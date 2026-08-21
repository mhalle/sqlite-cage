# sqlite-cage

Run untrusted SQL against SQLite **safely** and **honestly** — the query
protections of [Datasette](https://datasette.io/), without Datasette.

`sqlite-cage` is a small, zero-dependency, stdlib-only library for the case
where something you don't fully trust — most often an LLM agent or an MCP
tool — composes SQL to run against a SQLite database, and you need that to be
safe for the host and truthful to the caller. It is **not** a Datasette
competitor: Datasette is a publishing platform and UI; this is the embeddable
enforcement primitive that a service like Datasette contains, extracted and
hardened, at ~10 MB of RSS instead of ~50 MB and with no HTTP hop.

```python
from sqlite_cage import Cage, CagePolicy

cage = Cage("library.sqlite", CagePolicy(deadline_s=1.0, max_rows=1000))

rows = cage.query("SELECT year, count(*) FROM books GROUP BY year")  # list[dict]
res  = cage.fetch("SELECT * FROM books")     # Result: rows + a truncation signal
async_rows = await cage.aquery("SELECT ...") # async facade, same guarantees
```

## Why it exists

Two safety properties, both easy to get wrong by hand:

**Safe for the host.** A single bad query — a typo'd cross join, a `SELECT *`
over a huge table, an attempted `PRAGMA` or write — must not pin the CPU,
exhaust memory, or mutate anything.

**Honest to the caller.** A *partial* result returned as if complete, or an
*error* returned as an empty result, is worse than a crash: it produces a
confident, wrong answer with no signal. `sqlite-cage` makes truncation and
errors impossible to miss.

## What it enforces

Protection is at the **SQLite engine**, via the authorizer callback, not by
inspecting query text. Text allowlists have to enumerate every dangerous
construct, and SQLite keeps adding them — e.g. `SELECT * FROM
pragma_table_info(...)` reads PRAGMA state through something that looks
exactly like a plain read, so a regex passes it. Deny-by-default at compile
time does not.

| layer | mechanism |
|---|---|
| read-only | `mode=ro` open — WAL-aware, safe alongside writers. `immutable=True` is **opt-in** for truly frozen files: it skips locking and ignores `-wal`/`-journal`, which on a changing database means stale or wrong reads |
| deny-by-default authorizer | only plain reads, functions, and `WITH RECURSIVE`; everything else (PRAGMA, ATTACH, writes, extension loads) denied at compile time. Two deliberate exceptions: the read-only `data_version` / `schema_version` counters stay readable (FTS5 and the cage's own schema-epoch check need them; they expose change *counters*, never contents) |
| single statement | multi-statement strings refused by construction |
| runaway CPU | a wall-clock deadline via the progress handler, interval scaled to the deadline; SQLite's busy wait on a locked database is capped at `deadline_s` too (its 5 s default is uninterruptible). The bound is approximate: under lock contention total wall-clock is a small multiple of `deadline_s`, not an exact cutoff |
| result memory | a row cap **and** a byte budget counted while fetching, plus a column-count ceiling enforced by the engine **at prepare time** — before SQLite materialises the first row, which Python's `execute()` otherwise does no matter how large it is |
| concurrency | a bounded connection pool and semaphore; the async facade queues rather than fails under burst |
| per-table / per-column ACL | hide a column (read as NULL) or a whole table — validated against the real schema, extended to the FTS3/4/5 shadow tables and `MATCH` oracle that would otherwise recover a hidden column's text (shadow/virtual relations enumerated by the engine itself via `PRAGMA table_list`, not name patterns), and refreshed per execution when a live writer changes the schema |
| defensive mode | `SQLITE_DBCONFIG_DEFENSIVE` (unconditional — the Python 3.12 floor guarantees it), plus `PRAGMA query_only` (an engine-level write barrier under the authorizer), `PRAGMA trusted_schema=OFF` (functions/vtables embedded in the schema run untrusted), and `PRAGMA cell_size_check=ON` (malformed pages surface as clean `SQLITE_CORRUPT`) — none revertible by the caged caller |

## The honesty contract

- **`query()` raises `TruncatedResult`** if the result exceeds `max_rows`.
  Use it when the caller treats the rows as complete (aggregation, joins,
  "the answer is X") — silently returning a partial there is a lie.
- **`fetch()` returns a `Result`** carrying the rows plus an explicit,
  hard-to-drop truncation signal — Datasette's `truncated` flag, but precise
  (it means *strictly more* rows exist, never a false alarm at the cap) and
  with an actionable note in the same `envelope()` as the rows.
- **No error is ever an empty result.** Every failure raises a typed
  `CageError` carrying the query as written; nothing returns `[]` on the
  error path.
- **No silent column loss.** Rows are dicts, so two result columns sharing a
  name could keep only one value — `SELECT a.id, b.id FROM a JOIN b` would
  quietly drop a column. The cage raises instead, with an aliasing hint.

```python
res = cage.fetch("SELECT * FROM books")
if res.truncated:
    print(res.note)   # "TRUNCATED: showing the first 1000 rows; more exist …"
client.send(res.envelope())   # {rows, returned, truncated, limit, note?} — JSON-safe
```

## Sync and async

The synchronous methods (`query`, `fetch`, `stream`, `explain`) are the core.
`aquery` / `afetch` are thin async facades over a bounded thread pool sized to
`max_concurrency`. SQLite is a blocking library — there is no native async —
but the naive `asyncio.to_thread(cage.query, …)` bridge parks threads on the
concurrency semaphore and spuriously fails *queued* queries under burst; the
facade queues them in the executor instead. (Measured: 5 of 20 concurrent
queries failing under the naive bridge, 0 with `aquery`.)

## Policy

Everything is a field on the frozen `CagePolicy`; construct different cages
for different trust levels (a tight one for an agent's raw-SQL tool, a looser
one for your own known-shaped queries):

```python
CagePolicy(
    deadline_s=1.0, max_rows=1000, max_result_bytes=64 << 20,
    max_concurrency=3, max_columns=256,
    deny_functions=frozenset({"randomblob", "zeroblob"}),
    table_acl={"users": {"deny_columns": {"email"}}},   # or {"users": None}
    slow_log=lambda secs, sql: log.warning("slow %.1fs %s", secs, sql),
)
```

Degenerate values are rejected at construction (fail-closed) with strict
types — `True`, `inf`, `nan`, floats for counts, or a bare string where a
collection of names belongs all raise instead of quietly weakening a guard —
and the collections are normalised to frozensets, so a one-shot iterable
cannot validate as configured and then enforce as empty. The ACL is
snapshotted immutably — mutating the policy afterward cannot loosen
enforcement — and it is validated against the actual schema when the `Cage`
is built: a typo'd table or column name raises `ValueError` rather than
silently protecting nothing.

One sizing relationship to know: `max_columns × max_length` bounds the worst
single row SQLite can assemble before the byte budget applies — 256 × 512 KiB
= 128 MiB with the defaults. On a memory-tight host shrink either; both are
plain policy fields.

## API reference

### `Cage(path, policy=None, *, immutable=False)`

Opens `path` read-only (the path is resolved once, so later `chdir()` cannot
redirect it, and awkward filenames — `?`, `#`, `%` — are escaped correctly).
Raises `FileNotFoundError` if it is missing, `ValueError` if it is not a
regular file, or a `CageError` if it cannot be opened. Construct one cage per
trust level and reuse it; it owns a small connection pool. Requires Python ≥
3.12 and SQLite ≥ 3.37.0 (both checked at import).

Pass `immutable=True` (a real bool — anything else raises) **only** when the
file truly cannot change while the cage lives *and* skipping locks buys you
something real: read-only media (a container image layer, a mounted ISO), or
a network filesystem where POSIX locking is broken or slow. On ordinary
local files the default's per-read locking is microseconds — and strictly
more robust, since a stray in-place write stays consistent under locking but
yields garbage under immutable. A static corpus on local disk should just
use the default.

Live writers are supported in the default mode: each execution checks the
database's `schema_version`, and when a writer has changed the schema the
cage rebuilds its ACL/FTS snapshots before running the query. If the new
schema no longer satisfies `table_acl` (a protected table was dropped),
queries fail closed until a new cage is built. This covers a *reasonable*
writer evolving the schema — an adversarial writer racing the cage is out of
scope (see the threat model).

`refresh()` triggers that same rebuild on demand. Its main job is the one
case the automatic check cannot see: a file that was atomically **replaced**
(`os.replace` / `mv`). Pooled connections hold open file descriptors, so in
*either* open mode they keep reading the old inode — the epoch check reads
the old file's header through the same descriptor and cannot notice the
swap. Republish the corpus file, call `refresh()`, and subsequent queries
read the new one. It also surfaces an ACL that no longer resolves as an
eager `ValueError` instead of at the next query. A **failed** rebuild taints
the cage: every query raises until a rebuild succeeds (queries retry the
rebuild themselves, so restoring a compatible file heals it) — never the old
data, which is the point when the replacement was a revocation.

A cage is a context manager; after `close()` (explicit or via `with`), every
call raises `CageError` — in-flight queries finish, and their connections are
closed at check-in rather than re-pooled.

| method | returns | notes |
|---|---|---|
| `query(sql, params=())` | `list[dict]` | **Raises `TruncatedResult`** past `max_rows`. Use when rows are treated as complete. |
| `fetch(sql, params=())` | `Result` | Never raises on truncation — carries an explicit signal instead. |
| `stream(sql, params=())` | `Iterator[dict]` | Lazy; holds a connection for the iterator's life. Raises `TruncatedResult` past `max_rows`. |
| `explain(sql, params=())` | `None` | Compile-only pre-flight: runs the authorizer and limits, executes nothing. Raises if the query would be denied or is malformed. |
| `aquery(sql, params=())` | `list[dict]` | async `query()` over a bounded executor. |
| `afetch(sql, params=())` | `Result` | async `fetch()`. |
| `refresh()` | `None` | Re-read the schema now: rebuild the ACL/FTS snapshots and retire existing connections. Raises `ValueError` if `table_acl` no longer resolves (queries then keep failing closed). |
| `close()` | `None` | Closes the cage (idempotent); also runs on `with`-exit. |

`params` is bound, never interpolated — pass a tuple for `?` placeholders or a
dict for `:name` placeholders.

### `Result`

Returned by `fetch()` / `afetch()`. Immutable.

| member | meaning |
|---|---|
| `rows` | `tuple[dict, ...]` — the rows, capped at `limit` |
| `truncated` | `True` iff **strictly more** than `limit` rows exist |
| `complete` | `not truncated` |
| `returned` | `len(rows)` |
| `limit` | the `max_rows` in force |
| `query` | the SQL as written |
| `note` | actionable caveat string when truncated, else `None` |
| `envelope()` | JSON-safe `dict` — `{rows, returned, truncated, limit, note?}`; BLOBs become `{"$blob": {"bytes", "base64"}}` |
| iteration | `for row in result` yields rows (never the flag) |

### `CagePolicy` fields

| field | default | bounds |
|---|---|---|
| `deadline_s` | `1.0` | wall-clock timeout per query (also caps SQLite's busy wait); approximate under lock contention — a small multiple, not exact |
| `max_rows` | `1000` | row cap → truncation |
| `max_result_bytes` | `64 MiB` | result byte budget, counted while fetching |
| `max_concurrency` | `3` | simultaneous queries (pool + semaphore) |
| `max_columns` | `256` | result-column ceiling, enforced by the engine at prepare time |
| `max_length` | `512 KiB` | largest single string/blob value (and, per SQLite semantics, one stored table row) |
| `max_sql_bytes` | `100_000` | max length of the SQL text |
| `max_expr_depth` | `200` | expression-tree depth |
| `max_compound_select` | `50` | terms in a compound SELECT |
| `max_like_pattern` | `1_000` | LIKE/GLOB pattern bytes (long patterns match in O(N×M)) |
| `max_function_args` | `64` | arguments to one SQL function |
| `max_bound_params` | `999` | highest `?NNN` parameter number (`?NNN` allocates an NNN-slot vector) |
| `progress_every_ops` | `5000` | VDBE ops between deadline checks |
| `deny_functions` | `{"randomblob","zeroblob"}` | SQL functions to deny (matched ASCII case-insensitively) |
| `table_acl` | `{}` | `{table: {"deny_columns": {...}}}` (NULL the column) or `{table: None}` (hide the table); names are validated against the schema and matched with SQLite's ASCII case-insensitivity |
| `slow_log` | `None` | `callable(elapsed_s, sql)` for queries over `slow_log_s` |
| `slow_log_s` | `1.5` | slow-query threshold |

Every field is validated at construction — range **and** type; an
out-of-range, wrong-typed, or non-finite value raises `ValueError` rather
than silently disabling a guard.

ACL fine print: denying an `INTEGER PRIMARY KEY` alias also nulls reads via
`rowid`/`_rowid_`/`oid` (SQLite reports those under the alias name). The
implicit ROWID of a table with no alias is a row address, not a data column,
and cannot be listed. A schema wider than `max_columns` still opens: each
connection parses the schema under SQLite's default limit first, then the
limit drops to exactly `max_columns` for the untrusted statements that
follow.

### Exceptions

All inherit `CageError`, which carries the offending query as `.query`. No
failure path ever returns an empty result.

| exception | raised when |
|---|---|
| `QueryDenied` | the authorizer refused an operation (write, PRAGMA other than the two documented read-only counters, ATTACH, denied function, ACL-hidden table) |
| `QueryTimeout` | the `deadline_s` wall-clock limit elapsed |
| `TruncatedResult` | `query()`/`stream()` hit `max_rows` (use `fetch()` to accept a partial) |
| `ResultBudgetExceeded` | the byte budget or column ceiling was crossed |
| `QueryError` | anything else SQLite raised (syntax, missing table, bad params) — plus the cage's own refusal of a result with duplicate column names, which dict rows cannot carry without silent loss |

## Assurance

The threat model and what is explicitly **out** of scope (a hostile operator,
host memory outside the result set, single-op CPU, C extensions, DoS by
valid-looking load) are in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). The
enforcement was developed against three independent adversarial passes (13
findings) and a fourth external review round, all findings fixed and captured
as regression tests, plus a property-based fuzzer that re-checks the
invariants against random policies and queries.

```
pytest                              # the full suite, incl. a fuzz budget
python -m tests.fuzz_cage 5000 42   # a longer fuzz run, seeded
```

### A note on Datasette

`sqlite-cage`'s byte-budget guard catches a case a plain row cap does not: a
one-row, many-column result (`SELECT huge, huge, huge, …`) sails past
`max_returned_rows` and can exhaust memory. Datasette's row cap has the same
shape; this is offered as an observation, not a criticism — the tool it
draws from is excellent, and this library exists to be *embeddable*, which is
a different job.

## Install

Not yet on PyPI. Install from GitHub:

```
pip install "sqlite-cage @ git+https://github.com/mhalle/sqlite-cage"
```

Or pin a released tag:

```
pip install "sqlite-cage @ git+https://github.com/mhalle/sqlite-cage@v0.2.0"
```

Or vendor it — it is a single stdlib-only module (`src/sqlite_cage/__init__.py`),
and copying that one file into a project is a supported, dependency-free way
to use it.

Floors, both checked at import: Python ≥ 3.12 (`Connection.setlimit` and
`setconfig`, so `DBCONFIG_DEFENSIVE` is universal) and SQLite ≥ 3.37.0
(read-only WAL opens, `DBCONFIG_DEFENSIVE`, `trusted_schema`, and
engine-typed shadow enumeration via `PRAGMA table_list`). Both floors are
about the *interpreter*, not the OS: a
[uv](https://docs.astral.sh/uv/)-managed Python is current and bundles a
current SQLite even where the distro ships an old `libsqlite3`, so on older
platforms install Python with uv rather than using the system interpreter.

## License

MIT.
