# Changelog

## [next] — unreleased

- Documentation completeness pass: `QueryError`'s duplicate-column refusal
  documented in the README (exceptions table and a fourth honesty-contract
  bullet); the planner-statistics residual (`sqlite_stat1` row counts,
  STAT4 sampled key values) recorded in the threat model with its ACL
  remediation; the stopping-rule narrative corrected — the R4.6
  duplicate-name find was in the settled 0.1.0 core, not the new code;
  `CagePolicy` gained a class docstring; tag-pinned install example.

## [0.2.0] — 2026-08-20

Round 4: hardening from an independent external review. Two breaking-ish
changes to be aware of when upgrading:

- **Databases now open `mode=ro` (WAL-aware); `immutable` is opt-in** via
  `Cage(path, immutable=True)`. The old always-on `immutable=1` told SQLite
  the file could never change, so on a database with a live `-wal` it
  ignored committed transactions outright (verified: an uncheckpointed table
  was invisible). Pass `immutable=True` only for truly frozen files.
- **New defaults:** `max_columns` 64 → 256 (64 was prohibitive for real
  schemas), `max_result_bytes` 8 MiB → 64 MiB, `max_length` 1 MB → 512 KiB.
  The product `max_columns × max_length` (now 128 MiB) bounds the worst
  single row the engine can assemble before the byte budget applies.

Security/correctness fixes:

- Result width is now enforced by the engine (`SQLITE_LIMIT_COLUMN`) at
  **prepare** time. The old post-prepare check ran after Python's
  `execute()` had already stepped once — SQLite had fully materialised the
  first row in C memory no matter how wide (measured: 220 MB resident from
  a single no-fetch `execute()`). Each new connection warms the schema
  cache under SQLite's default limit, then lowers the limit to exactly
  `max_columns` — so narrow queries over wide tables keep working while a
  schema wider than the policy no longer raises the ceiling for
  wide-expression attacks (a second review pass caught the earlier
  max-of-schema sizing doing exactly that). "Too many columns" classifies
  as `ResultBudgetExceeded`.
- Live writers: every execution now reads `schema_version` (one header
  field) and, when it changed, rebuilds the ACL/FTS-shadow snapshots and
  re-warms the connection — a writer creating a new FTS index over a
  protected table after construction no longer hands callers a `MATCH`
  oracle (reproduced in review). If the new schema no longer matches
  `table_acl`, queries fail closed with instructions to rebuild the cage.
  Scope: this covers a *reasonable* writer evolving the schema between
  queries; an adversarial writer racing the check window is explicitly out
  of scope (see THREAT_MODEL).
- Policy collections (`deny_functions`, `deny_columns`) are normalised to
  frozensets at validation. A one-shot iterable (generator) previously
  validated as configured, was consumed doing so, and enforced as EMPTY —
  a denylist that protects nothing (reproduced in review).
- `Cage(..., immutable=)` requires a real bool: `immutable="false"` would
  have silently enabled the unsafe-for-live-databases mode.
- New `Cage.refresh()`: rebuild the ACL/FTS snapshots and retire existing
  connections on demand. Covers what the automatic per-execution check
  cannot see — an `immutable=True` cage whose file was atomically replaced
  (immutable connections never re-read the header) — and surfaces an ACL
  that no longer resolves as an eager `ValueError`. Connections now carry a
  snapshot-generation stamp, so ones that outlive a refresh are retired at
  their next touch instead of re-entering the pool with a stale schema
  cache.
- Rebuilds resolve the ACL from a deep-immutable spec captured at
  construction, never from the live policy: with the first refresh()
  implementation, `policy.table_acl.clear()` followed by any rebuild
  (explicit refresh() or a writer-triggered one) exposed the protected
  column, silently reopening round-3 BREAK 2 (caught in review,
  reproduced, regression-tested).
- A FAILED rebuild now taints the cage — connections retired, every query
  refused — until a rebuild succeeds (queries attempt the heal
  automatically). Previously a failed refresh() on an immutable cage whose
  file had been replaced left the old pool serving the replaced file's
  rows: the corpus-revocation case refresh() exists for (caught in
  review, reproduced).
- `table_acl` keys that name the same table under SQLite's case folding
  (`"docs"` and `"DOCS"`) are rejected; they previously resolved last-wins,
  silently trading a whole-table denial for a column mask.
- SQLite's busy wait is capped at `deadline_s` (it defaulted to a fixed
  5 s that the progress-handler deadline cannot interrupt — a 0.1 s-deadline
  query against a writer-locked database took 10.4 s, two stacked busy
  windows), and the deadline clock now starts before connection checkout
  and the schema-epoch check instead of after them. Under lock contention
  total wall-clock is bounded by a small multiple of `deadline_s`, not by
  a constant SQLite chose.
- Adopted the engine layers SQLite already offers: `PRAGMA query_only=ON`
  (a write barrier underneath the authorizer) and `PRAGMA
  trusted_schema=OFF` (schema-embedded functions/vtables run untrusted;
  silent no-op before SQLite 3.31) on every caged connection, neither
  revertible by the caller; plus three previously unused limits as policy
  fields — `max_like_pattern` (1000; long LIKE/GLOB patterns match in
  O(N×M)), `max_function_args` (64), and `max_bound_params` (999; `?NNN`
  allocates an NNN-slot vector). `SQLITE_LIMIT_VDBE_OP` is deliberately
  not used: SQLite reports exceeding it as out-of-memory, which Python
  raises as a bare MemoryError — enforcing it would leak a raw error or
  force mislabeling genuine OOMs.
- FTS shadow discovery rewritten: a real tokenizer over the `CREATE VIRTUAL
  TABLE` declaration replaces a regex over a lowercased copy. Handles
  `content=` in every quote style (`'…'`, `"…"`, `[…]`, `` `…` ``), comments,
  doubled-quote escapes, and ASCII case folding; covers FTS3/4 shadow
  layouts (`_segdir`, `_segments`, `_stat`) as well as FTS5; **fails closed**
  on anything it cannot conclusively parse. ACL'd virtual tables of any
  module get their shadow tables denied too.
- ACLs are validated against the real schema at construction: an unknown
  table or column now raises `ValueError` instead of silently protecting
  nothing. Names fold with SQLite's ASCII case rule; denying an INTEGER
  PRIMARY KEY alias also nulls `rowid`/`_rowid_`/`oid` reads of it.
- Type-strict policy validation: `True`, `inf`, `nan`, floats for integer
  fields, non-callable `slow_log`, and bare strings for `deny_functions` /
  `deny_columns` (which would deny per *character*) all raise `ValueError`.
- The database path is resolved at construction and turned into a URI with
  `as_uri()` — filenames containing `?`, `#`, or `%` no longer change the
  URI's meaning, later `chdir()` cannot redirect new pool connections, and
  non-regular files are refused.
- Lifecycle: `Cage` is a context manager; `close()` is terminal and
  idempotent (in-flight queries finish, their connections close at
  check-in). The fuzz harness keeps a bounded LRU of cages and closes
  evicted ones — it previously leaked file descriptors across hundreds of
  generated policies.
- Import-time floor: SQLite ≥ 3.37.0 (raised from the initial 3.26 during
  review). 3.37 buys `PRAGMA table_list`, whose engine-typed
  `virtual`/`shadow` classification now drives FTS shadow discovery —
  ground truth instead of name heuristics, with two new fail-closed rules:
  an engine-typed virtual table whose declaration will not parse, and a
  shadow attributable to no virtual table, are denied outright. The
  declaration tokenizer remains for what `table_list` cannot report
  (module and `content=`). The floor also makes `trusted_schema` real
  everywhere (3.31) and inherits SQLite's 2021+ corruption hardening. The
  floor concerns the *interpreter's* SQLite, not the OS: uv-managed
  Pythons bundle a current SQLite even on distros shipping an old
  `libsqlite3`.
- `PRAGMA cell_size_check=ON` on every caged connection: b-tree cells are
  validated as pages are read, so a malformed page surfaces as a clean
  `SQLITE_CORRUPT` error instead of undefined behavior.
- Duplicate result-column names are rejected with an aliasing hint. Rows
  are dicts, so `SELECT a.id, b.id FROM a JOIN b` silently kept one `id`
  and dropped the other — the exact silent data loss the honesty contract
  forbids (caught in review, reproduced).
- Python floor 3.11 → 3.12, so `Connection.setconfig` — and with it
  `SQLITE_DBCONFIG_DEFENSIVE` — is universal instead of best-effort on
  3.11 (the docs claimed DEFENSIVE unconditionally; now the code matches).
  An import-time check also refuses a Python whose `sqlite3` was built
  without the constant. Same reasoning as the SQLite floor: uv makes a
  current interpreter cheap everywhere.
- Documentation honesty pass from the final review: the two read-only
  pragma counters (`data_version`/`schema_version`) are documented as
  deliberate authorizer exceptions; `deadline_s` is documented as an
  approximate bound (a small multiple under lock contention — exactness
  would need `sqlite3_busy_handler`, which CPython does not expose); and
  two stale README claims (the old 3.26 floor, the old schema-sized
  column limit) are corrected.

## [0.1.0] — 2026-08-19

Initial release.

- Deny-by-default authorizer (engine-level, not text-based): read-only, no
  PRAGMA/ATTACH/writes/extension-loads; the `pragma_*()` function-form bypass
  is closed.
- Resource bounds: wall-clock deadline (op-interval scaled to it), row cap,
  byte budget counted while fetching, and a pre-fetch column-count ceiling.
- Honesty contract: `query()` raises on truncation; `fetch()` returns a
  `Result` with a precise truncation signal and a JSON-safe `envelope()`; no
  error path returns `[]`.
- Per-table / per-column ACL, including denial of the FTS5 shadow tables and
  `MATCH` oracle that would otherwise recover a hidden column.
- Bounded connection pool + semaphore; optional async facade (`aquery`,
  `afetch`) that queues under burst instead of spuriously failing.
- Fail-closed policy validation; the ACL is snapshotted immutably.
- Developed against three adversarial red-team passes (13 findings fixed) and
  a property-based fuzzer.
