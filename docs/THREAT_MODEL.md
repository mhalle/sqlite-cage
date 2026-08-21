# sqlite-cage threat model

What the cage defends, against whom, and — as important — what it does not.
Three adversarial rounds (13 breaks, all fixed; see `the project's adversarial test history`)
plus a fourth, external review pass hardened it against the in-scope threat.
This document draws the boundary so a future change knows what it must not
regress, and so no one mistakes the cage for protection it does not offer.

## The adversary it is built for

**A cooperative-but-fallible SQL composer** — an LLM agent (or any caller)
that writes queries against your database and may write *wrong* ones at machine
speed: a typo'd cross join, a `SELECT *` over a 137k-row table, a query that
tries a PRAGMA or a write because the model guessed the schema. The intent is
not hostile; the failure modes are volume, mistakes, and confident
misreading of results.

This matters most where the host has a hard memory ceiling enforced by a
silent OOM killer (a shared host, a container limit), so a single bad query
is a process kill — and where a partial or empty result read as complete
becomes a confidently wrong answer with no signal.

## In scope — defended, and tested each round

| threat | defense | verified |
|---|---|---|
| any write / DDL / schema change | read-only open (WAL-honoring; `immutable` opt-in for frozen files), deny-by-default authorizer | R1, R3, R4 |
| PRAGMA / ATTACH / extension load / function-form pragmas | authorizer (engine-level, not text regex). Documented exceptions: the read-only `data_version`/`schema_version` counters stay readable — FTS5 and the schema-epoch check need them, and they expose change counters, never contents (the metadata side-channel exclusion, №5 below) | R1, R4.6 |
| runaway CPU / wall-clock overrun | progress-handler deadline, op-interval scaled to the deadline; SQLite's busy wait capped at `deadline_s` (the 5 s default is uninterruptible and ignored the policy); the clock starts before checkout and the epoch check. The bound is APPROXIMATE by design: each engine operation gets its own busy window, so under lock contention total wall-clock is a small multiple of `deadline_s` — an exact cutoff would need `sqlite3_busy_handler`, which CPython does not expose | R1, R3, R4.3 |
| result-memory blow-up (many rows) | row cap + byte budget, counted while fetching | R1 |
| result-memory blow-up (one wide row) | engine column limit at PREPARE time — Python's `execute()` steps once, so a post-prepare check runs after the first row already exists in C memory (measured 220 MB from one no-fetch execute). Connections warm the schema under SQLite's default limit, then lower it to exactly `max_columns`, so a wide schema does not raise the attack ceiling | R2, R4, R4.1 |
| unbounded concurrency / fd exhaustion | semaphore + bounded pool; explain() takes a slot; close() is terminal and `with`-scoped | R2, R4 |
| partial result read as complete | truncation RAISES (query) or a signalled Result (fetch) | R1, R2 |
| error read as empty result | every failure raises a typed CageError with query text | R1, R2 |
| a duplicate result-column name silently dropping a value (dict rows keep one per name; trivial to hit with joins) | duplicate result names rejected with an aliasing hint | R4.6 |
| ACL-hidden column recovered via FTS shadow/MATCH | fail-closed discovery of FTS3/4/5 shadows: virtual/shadow relations enumerated by the engine (`PRAGMA table_list`), module and `content=` read by a real tokenizer (any quote style, comments, ASCII case folding); engine-typed shadows attributable to no virtual table, and virtual tables whose declaration will not parse, are denied outright | R2, R4, R4.5 |
| ACL-hidden alias recovered via `rowid`/`_rowid_`/`oid` | SQLite reports alias reads under the alias name; denial covers them (verified) | R4 |
| ACL bypassed by schema objects created AFTER construction (a new FTS index over a protected table) | per-execution `schema_version` epoch check; on change the ACL/FTS snapshots rebuild and the connection re-warms; an ACL the new schema cannot satisfy fails closed | R4.1 |
| a security collection that validated but enforces empty (one-shot iterable) | policy collections normalised to frozensets during validation | R4.1 |
| a guard silently disabled by degenerate config | construction-time policy validation — range AND type (bool/inf/nan/bare-string all refused), fail-closed | R3, R4 |
| a write compiling despite the authorizer; schema-embedded functions running trusted; quadratic LIKE patterns; huge `?NNN` bind vectors | engine layers on every connection: `query_only`, `trusted_schema=OFF` (no-op pre-3.31), and limits on LIKE-pattern length, function arity, and bind-parameter numbers | R4.4 |
| security config that LOOKS active but is inert or self-conflicting (typo'd ACL; `"docs"`/`"DOCS"` duplicate keys resolving last-wins) | ACL resolved against the real schema at construction; unknown names and case-folded duplicate keys raise | R4, R4.3 |
| revoked data still served after a FAILED refresh (a replaced file whose schema the ACL cannot resolve — pooled fds pin the old inode in either open mode) | a failed rebuild taints the cage: connections retired, every query refused until a rebuild succeeds (queries attempt the heal) | R4.3 |
| path interpreted as URI syntax / chdir redirection | resolved absolute path, `as_uri()` percent-escaping, regular-file check | R4 |
| enforcement loosened after construction | ACL/denylist snapshotted immutably at construct; snapshot REBUILDS (refresh(), epoch) re-resolve from that frozen spec, never the mutable policy | R3, R4.2 |

The worst single row the engine can assemble before the byte budget applies
is `max_columns × max_length` (128 MiB with the defaults, 256 × 512 KiB).
Both are policy fields; shrink either on a memory-tight host. This is a
bound, not RSS accounting — a genuinely hard ceiling still needs process
isolation (see out-of-scope №2).

## Explicitly OUT of scope — do not assume protection

1. **A hostile operator.** The cage trusts whoever constructs it. Mutating a
   `Cage`'s private attributes, subclassing to defeat a check, or passing a
   `slow_log` that mounts an attack are all "you broke your own tool." The
   `CagePolicy` is validated but the process boundary is not a sandbox.
2. **Host memory outside the result set.** SQLite's own page cache and
   sort/temp allocations are not counted by the byte budget. `max_length`
   bounds the worst single value; a deadline bounds a runaway sort. If a
   deployment needs a hard cache ceiling, set `PRAGMA cache_size` at connect —
   but that is not this library's job and it is not claimed.
3. **CPU inside one progress-handler window.** A single VDBE step between
   callbacks is not interruptible. Bounded in practice by the op interval;
   residual, not zero.
4. **Malicious C extensions or a corrupted database file.** Extension loading
   is denied and DEFENSIVE mode is on, but a hostile `.so` already loaded into
   the process, or a deliberately corrupted immutable file, is outside the
   model.
5. **Timing / oracle side channels beyond the ones fixed.** The FTS MATCH
   oracle was closed because it directly recovered hidden text; subtler
   statistical side channels (row-count timing, planner behaviour) are not
   claimed to be eliminated. One concrete, nameable instance: SQLite's
   planner statistics are ordinary readable tables. `sqlite_stat1` (present
   after `ANALYZE`) reveals per-index row counts of tables the ACL hides,
   and `sqlite_stat4` (only in builds compiled with STAT4) stores *sampled
   key values* of indexed columns — including masked or hidden ones. The
   cage does not deny them automatically; a deployment whose database
   carries ANALYZE statistics alongside an ACL should hide them explicitly
   (`table_acl={"sqlite_stat1": None, ...}` — they validate like any
   table).
6. **Denial of service by legitimate-looking load.** The cage bounds one
   query and total concurrency, not an attacker issuing a flood of
   individually-valid slow queries. Rate limiting belongs one layer up.
7. **An unreasonable concurrent writer.** The cage supports a *reasonable*
   writer — one evolving the schema between queries: each execution checks
   `schema_version` and refreshes the ACL/FTS snapshots on change, failing
   closed if the ACL no longer resolves. It does not defend an open cage
   against a writer radically rewriting the database underneath it or
   adversarially racing the window between the epoch check and a
   statement's prepare — that would take a pinned read transaction per
   execution, and per the operator's scoping it is deliberately not built.
   If the writer is the adversary, the game is already lost (see №1).

## The stopping rule (and what round 4 was)

Rounds are aimed; break count tracks where they were aimed, not how close the
code is to correct (R1=6, R2=3, R3=4, on ever-newer surfaces). "No breaks in
a round" proves the agents found none, not that none exist — the same
absence-is-not-evidence rule. So the criterion is not zero
breaks; it is:

- the in-scope invariants above have survived multiple independent passes ✓
- new findings fall outside the threat model (R3's required mutating frozen
  internals or degenerate config) ✓
- every break is captured as a regression test (the pytest suite) ✓

Round 4 is exactly the "new surface" clause exercising itself: an
independent external review, not another aimed pass. Its material findings —
the width check ran after `execute()` had already materialised the first row;
FTS discovery was a regex that quote style, case, or FTS3/4 layouts could
slip; the always-on `immutable=1` silently ignored a live WAL; type-degenerate
policy values and typo'd ACLs validated as configured — are fixed and
captured as regression tests like every earlier break. A second pass (R4.1)
then broke the first pass's own fixes twice — the widest-schema column-limit
sizing re-opened the wide-expression attack, and switching to WAL-aware opens
made construction-time ACL snapshots stale under a live writer — plus two
fail-open validation gaps (one-shot iterables, non-bool `immutable`). All
four are fixed and regression-tested; the writer-concurrency *scope* that
R4.1 exposed is now drawn explicitly in out-of-scope №7. The stopping rule
stands: ongoing assurance comes from `tests/fuzz_cage.py` — a property-based
generator that re-checks the invariants against random policies and queries —
not from more hand-picked rounds. Re-open a targeted round only when a *new
surface in scope* appears (e.g. if the deployment adds the `sql` MCP tool and
with it a new input path). Follow-up passes over the round-4 work itself
(R4.2's mutable-policy resolve, R4.3's fail-open failed refresh, duplicate
ACL keys, and the uninterruptible busy wait) each broke the newest code, not
the settled core — the pattern the stopping rule predicts, and the reason
new surfaces get review before they get trusted. One find keeps that claim
honest by breaking it: the duplicate-result-name silent data loss (R4.6)
had sat in the dict-row core since 0.1.0, through every earlier round —
absence of findings in settled code is still not evidence of their absence.
