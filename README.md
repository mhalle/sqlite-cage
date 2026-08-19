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
| read-only | `mode=ro&immutable=1` open — no writes, no locks |
| deny-by-default authorizer | only plain reads, functions, and `WITH RECURSIVE`; everything else (PRAGMA, ATTACH, writes, extension loads) denied at compile time |
| single statement | multi-statement strings refused by construction |
| runaway CPU | a wall-clock deadline via the progress handler, interval scaled to the deadline |
| result memory | a row cap **and** a byte budget counted while fetching, plus a pre-fetch column-count ceiling (a 1-row × 2000-column result can blow RAM past a row cap alone) |
| concurrency | a bounded connection pool and semaphore; the async facade queues rather than fails under burst |
| per-table / per-column ACL | hide a column (read as NULL) or a whole table — and the FTS5 shadow tables and `MATCH` oracle that would otherwise recover a hidden column's text |
| defensive mode | `SQLITE_DBCONFIG_DEFENSIVE` on 3.12+ |

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
    deadline_s=1.0, max_rows=1000, max_result_bytes=8 << 20,
    max_concurrency=3, max_columns=64,
    deny_functions=frozenset({"randomblob", "zeroblob"}),
    table_acl={"users": {"deny_columns": {"email"}}},   # or {"users": None}
    slow_log=lambda secs, sql: log.warning("slow %.1fs %s", secs, sql),
)
```

Degenerate values are rejected at construction (fail-closed), and the ACL is
snapshotted immutably — mutating the policy afterward cannot loosen
enforcement.

## API reference

### `Cage(path, policy=None)`

Opens `path` read-only and immutable. Raises `FileNotFoundError` if it is
missing, or a `CageError` if it cannot be opened. Construct one cage per trust
level and reuse it; it owns a small connection pool.

| method | returns | notes |
|---|---|---|
| `query(sql, params=())` | `list[dict]` | **Raises `TruncatedResult`** past `max_rows`. Use when rows are treated as complete. |
| `fetch(sql, params=())` | `Result` | Never raises on truncation — carries an explicit signal instead. |
| `stream(sql, params=())` | `Iterator[dict]` | Lazy; holds a connection for the iterator's life. Raises `TruncatedResult` past `max_rows`. |
| `explain(sql, params=())` | `None` | Compile-only pre-flight: runs the authorizer and limits, executes nothing. Raises if the query would be denied or is malformed. |
| `aquery(sql, params=())` | `list[dict]` | async `query()` over a bounded executor. |
| `afetch(sql, params=())` | `Result` | async `fetch()`. |
| `close()` | `None` | Releases pooled connections and the async executor. |

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
| `deadline_s` | `1.0` | wall-clock timeout per query |
| `max_rows` | `1000` | row cap → truncation |
| `max_result_bytes` | `8 MiB` | result byte budget, counted while fetching |
| `max_concurrency` | `3` | simultaneous queries (pool + semaphore) |
| `max_columns` | `64` | result-column ceiling (checked pre-fetch) |
| `max_length` | `1_000_000` | largest single string/blob value |
| `max_sql_bytes` | `100_000` | max length of the SQL text |
| `max_expr_depth` | `200` | expression-tree depth |
| `max_compound_select` | `50` | terms in a compound SELECT |
| `progress_every_ops` | `5000` | VDBE ops between deadline checks |
| `deny_functions` | `{"randomblob","zeroblob"}` | SQL functions to deny |
| `table_acl` | `{}` | `{table: {"deny_columns": {...}}}` (NULL the column) or `{table: None}` (hide the table) |
| `slow_log` | `None` | `callable(elapsed_s, sql)` for queries over `slow_log_s` |
| `slow_log_s` | `1.5` | slow-query threshold |

Every numeric field is validated at construction; an out-of-range value raises
`ValueError` rather than silently disabling a guard.

### Exceptions

All inherit `CageError`, which carries the offending query as `.query`. No
failure path ever returns an empty result.

| exception | raised when |
|---|---|
| `QueryDenied` | the authorizer refused an operation (write, PRAGMA, ATTACH, denied function, ACL-hidden table) |
| `QueryTimeout` | the `deadline_s` wall-clock limit elapsed |
| `TruncatedResult` | `query()`/`stream()` hit `max_rows` (use `fetch()` to accept a partial) |
| `ResultBudgetExceeded` | the byte budget or column ceiling was crossed |
| `QueryError` | anything else SQLite raised (syntax, missing table, bad params) |

## Assurance

The threat model and what is explicitly **out** of scope (a hostile operator,
host memory outside the result set, single-op CPU, C extensions, DoS by
valid-looking load) are in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). The
enforcement was developed against three independent adversarial passes (13
findings, all fixed and captured as regression tests) plus a property-based
fuzzer that re-checks the invariants against random policies and queries.

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

Or vendor it — it is a single stdlib-only module (`src/sqlite_cage/__init__.py`),
and copying that one file into a project is a supported, dependency-free way
to use it.

## License

MIT.
