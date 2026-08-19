# sqlite-cage threat model

What the cage defends, against whom, and — as important — what it does not.
Three adversarial rounds (13 breaks, all fixed; see `the project's adversarial test history`)
hardened it against the in-scope threat. This document draws the boundary so
a future change knows what it must not regress, and so no one mistakes the
cage for protection it does not offer.

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
| any write / DDL / schema change | read-only+immutable open, deny-by-default authorizer | R1, R3 |
| PRAGMA / ATTACH / extension load / function-form pragmas | authorizer (engine-level, not text regex) | R1 |
| runaway CPU | progress-handler deadline, op-interval scaled to the deadline | R1, R3 |
| result-memory blow-up (many rows) | row cap + byte budget, counted while fetching | R1 |
| result-memory blow-up (one wide row) | pre-fetch column-count ceiling | R2 |
| unbounded concurrency / fd exhaustion | semaphore + bounded connection pool; explain() takes a slot | R2 |
| partial result read as complete | truncation RAISES (query) or a signalled Result (fetch) | R1, R2 |
| error read as empty result | every failure raises a typed CageError with query text | R1, R2 |
| ACL-hidden column recovered via FTS shadow/MATCH | schema-discovered shadow-table denial | R2 |
| a guard silently disabled by degenerate config | construction-time policy validation, fail-closed | R3 |
| enforcement loosened after construction | ACL/denylist snapshotted immutably at construct | R3 |

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
   claimed to be eliminated.
6. **Denial of service by legitimate-looking load.** The cage bounds one
   query and total concurrency, not an attacker issuing a flood of
   individually-valid slow queries. Rate limiting belongs one layer up.

## The stopping rule (why round 4 is not automatic)

Rounds are aimed; break count tracks where they were aimed, not how close the
code is to correct (R1=6, R2=3, R3=4, on ever-newer surfaces). "No breaks in
a round" proves the agents found none, not that none exist — the same
absence-is-not-evidence rule. So the criterion is not zero
breaks; it is:

- the in-scope invariants above have survived multiple independent passes ✓
- new findings fall outside the threat model (R3's required mutating frozen
  internals or degenerate config) ✓
- every break is captured as a regression test (the pytest suite) ✓

All three hold. Further hardening now risks introducing defects faster than
it removes them (R2's fix created the seam R3 flagged). Ongoing assurance
comes from `tests/fuzz_cage.py` — a property-based generator that re-checks the
invariants against random policies and queries — not from more hand-picked
rounds. Re-open a targeted round only when a *new surface in scope* appears
(e.g. if the deployment adds the `sql` MCP tool and with it a new input path).
