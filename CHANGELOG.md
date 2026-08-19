# Changelog

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
