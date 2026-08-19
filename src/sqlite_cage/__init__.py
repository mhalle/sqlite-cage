"""sqlite-cage — run untrusted SQL against SQLite, safely and honestly.

README.md is the guide; docs/THREAT_MODEL.md is the boundary. Layers, ordered
by when they act: read-only+immutable open; DEFENSIVE dbconfig; hard limits
(ATTACHED=0, value length, column count, expression depth); a deny-by-default
authorizer at compile time; single-statement by construction; a progress-
handler deadline; and a result budget counted in BYTES as well as rows while
fetching.

The honesty contract is not optional: truncation RAISES from query()/stream()
unless the caller uses fetch() to accept a signalled partial, and no failure
path ever returns an empty list.

Stdlib only — no dependencies. Python floor 3.11 (setlimit); 3.12+ adds
DEFENSIVE. Vendorable: copying this single file into a project is supported.
"""
from __future__ import annotations

import re
import sqlite3

__version__ = "0.1.0"
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info < (3, 11):  # noqa: UP036  (informative refusal, not silent degradation)
    raise ImportError(
        "sqlcage needs Python 3.11+ (Connection.setlimit); running with "
        "fewer protection layers silently is worse than refusing")

__all__ = [
    "Cage",
    "CageError",
    "CagePolicy",
    "QueryDenied",
    "QueryError",
    "QueryTimeout",
    "Result",
    "ResultBudgetExceeded",
    "TruncatedResult",
]


class CageError(Exception):
    """Base. Every failure carries the query as written; none return []."""

    def __init__(self, message: str, query: str = ""):
        self.query = query
        super().__init__(
            f"{message}\n  query: {query!r}" if query else message)


class QueryDenied(CageError):
    """The authorizer or limits refused an operation at compile time."""


class QueryTimeout(CageError):
    """The deadline elapsed; the statement was interrupted mid-run."""


class TruncatedResult(CageError):
    """More rows than max_rows and the caller did not opt into partials.

    A partial result returned as if complete produces confident lies —
    aggregate in SQL (GROUP BY / count) or narrow the filter instead.
    """


class ResultBudgetExceeded(CageError):
    """The result's cumulative bytes passed max_result_bytes."""


class QueryError(CageError):
    """Everything else SQLite raised (syntax, missing table, bad params)."""


# Authorizer opcodes allowed for a plain read. Everything else is DENY —
# including SQLITE_PRAGMA (which also covers pragma_table_info()),
# SQLITE_ATTACH, every write/DDL opcode, and SQLITE_TRANSACTION.
_ALLOWED_OPS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_RECURSIVE,          # WITH RECURSIVE
    getattr(sqlite3, "SQLITE_FUNCTION", 31),
}


@dataclass(frozen=True)
class CagePolicy:
    deadline_s: float = 1.0
    max_rows: int = 1_000
    max_result_bytes: int = 8 << 20            # 8 MiB
    max_concurrency: int = 3
    progress_every_ops: int = 5_000
    max_sql_bytes: int = 100_000
    max_length: int = 1_000_000                # largest single string/blob
    max_columns: int = 64                      # result-column count ceiling
    max_expr_depth: int = 200
    max_compound_select: int = 50
    deny_functions: frozenset[str] = frozenset({"randomblob", "zeroblob"})
    # {"table": {"deny_columns": {"col", ...}}} or {"table": None} to hide it
    table_acl: dict = field(default_factory=dict, hash=False)
    slow_log_s: float = 1.5
    slow_log: object = None                    # callable(elapsed_s, sql) | None

    def __post_init__(self):
        # A degenerate policy value must fail LOUDLY at construction, not
        # silently disable a guard at query time or surface as a raw
        # sqlite3/ValueError from deep inside setlimit (round-3 BREAK 1 & 4).
        bad = [name for name, okay in {
            "deadline_s": self.deadline_s > 0,
            "max_rows": self.max_rows >= 0,
            "max_result_bytes": self.max_result_bytes > 0,
            "max_concurrency": self.max_concurrency >= 1,
            "progress_every_ops": self.progress_every_ops >= 1,
            "max_sql_bytes": self.max_sql_bytes > 0,
            "max_length": self.max_length > 0,
            "max_columns": self.max_columns >= 1,
            "max_expr_depth": self.max_expr_depth >= 1,
            "max_compound_select": self.max_compound_select >= 1,
            "slow_log_s": self.slow_log_s >= 0,
        }.items() if not okay]
        if bad:
            raise ValueError(
                "CagePolicy: value(s) out of range: " + ", ".join(bad)
                + " (a guard cannot be disabled by a degenerate setting)")


@dataclass
class _CagedConn:
    """One connection plus its private authorizer-denial holder."""
    conn: sqlite3.Connection
    denied: tuple | None = None


def _json_safe(value):
    """A JSON-serialisable stand-in for one SQLite scalar.

    SQLite hands BLOB columns back as Python `bytes`, which `json.dumps`
    cannot encode. Silently dropping them would hide data; letting them
    through makes `envelope()` detonate in the caller's serialiser with a
    raw TypeError bearing no query text — the error-as-surprise this library
    exists to prevent. So a blob becomes an explicit, reversible tagged
    object carrying its length, never a silent omission.
    """
    if isinstance(value, (bytes, bytearray)):
        import base64
        return {"$blob": {"bytes": len(value),
                          "base64": base64.b64encode(bytes(value)).decode()}}
    return value


@dataclass(frozen=True)
class Result:
    """A completed read, with an explicit truncation signal for the client.

    Like Datasette's `truncated` flag, but built so the signal is hard to
    drop: `complete` must be read to know the answer is whole, `envelope()`
    puts the flag and an actionable note in the same dict as the rows, and
    `truncated` is PRECISE — because truncation is detected by fetching one
    row past the cap, `truncated=True` always means strictly more than
    `limit` rows exist, never a false alarm at exactly the cap.

    `rows` is a tuple so `returned`/`truncated`/`note` cannot desync from it
    via an in-place append on a frozen object.
    """
    rows: tuple
    truncated: bool
    limit: int
    query: str

    @property
    def returned(self) -> int:
        return len(self.rows)

    @property
    def complete(self) -> bool:
        """True iff these rows are the whole result."""
        return not self.truncated

    @property
    def note(self) -> str | None:
        """Human/agent-facing caveat, or None when the result is whole."""
        if not self.truncated:
            return None
        return (f"TRUNCATED: showing the first {self.returned} rows; more "
                f"exist beyond the {self.limit}-row cap. This is a partial "
                "view — for a complete answer aggregate in SQL (COUNT, SUM, "
                "GROUP BY) or narrow the filter. Do not treat these rows as "
                "the full result.")

    def envelope(self) -> dict:
        """JSON-serialisable result for an MCP/HTTP client. The truncation
        signal travels in the SAME payload as the rows, with a natural-language
        note — a JSON `truncated: true` an agent might skip, plus a sentence it
        won't. BLOB values become tagged `$blob` objects so `json.dumps` of the
        envelope never raises (verified: round-2 break)."""
        rows = [{k: _json_safe(v) for k, v in row.items()} for row in self.rows]
        env = {"rows": rows, "returned": self.returned,
               "truncated": self.truncated, "limit": self.limit}
        if self.truncated:
            env["note"] = self.note
        return env

    def __iter__(self):
        """Iterating yields rows, so a caller that forgets `.rows` still gets
        rows — never silently gets the flag instead."""
        return iter(self.rows)

    def __repr__(self) -> str:
        tag = f", TRUNCATED at {self.limit}" if self.truncated else ""
        return f"Result({self.returned} rows{tag})"


def _row_bytes(row: tuple) -> int:
    n = 0
    for v in row:
        if v is None:
            n += 8
        elif isinstance(v, (bytes, bytearray)):
            n += len(v)
        elif isinstance(v, str):
            n += len(v.encode("utf-8", "replace"))
        else:
            n += 8
    return n


class Cage:
    """A pool of caged read-only connections over one database file."""

    def __init__(self, path: str | Path, policy: CagePolicy | None = None):
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        self.policy = policy or CagePolicy()
        self._sem = threading.BoundedSemaphore(self.policy.max_concurrency)
        # A pool of ready connections, at most max_concurrency live at once
        # (the semaphore guarantees it). Each EXECUTION checks one out for its
        # whole lifetime — including a suspended stream() — so its progress
        # handler and authorizer state are private. Sharing one connection was
        # the bug: an interleaved query on the same thread tore down a parked
        # stream's deadline (red-team finding #19), and _denied raced across
        # concurrent queries (R1).
        self._pool: list[_CagedConn] = []
        self._pool_lock = threading.Lock()
        # Bounded executor for the OPTIONAL async facade (aquery/afetch),
        # created lazily so a purely-sync process never allocates it. Sized to
        # max_concurrency: excess coroutines queue in the executor rather than
        # blocking a thread on the semaphore and spuriously timing out (the
        # naive asyncio.to_thread bridge loses 5/20 under burst — measured).
        self._executor = None
        self._executor_lock = threading.Lock()
        # Snapshot the ACL and function denylist into immutable form at
        # construction. The policy is frozen against REBINDING but not against
        # in-place mutation of its dict/set members, and FTS-shadow discovery
        # runs only once — so an authorizer that read the live policy could be
        # loosened after construction while the shadow denials stayed fixed,
        # silently reopening the confidentiality hole (round-3 BREAK 2).
        # Enforcement now reads these snapshots, never self.policy.
        self._acl: dict[str, frozenset | None] = {
            t: (None if v is None
                else frozenset((v or {}).get("deny_columns", ())))
            for t, v in self.policy.table_acl.items()}
        self._deny_functions = frozenset(
            f.lower() for f in self.policy.deny_functions)
        # Discover FTS indexes over ACL-protected tables before any caged
        # connection exists, so the authorizer can deny their shadow tables.
        self._acl_denied_tables = self._discover_fts_shadows()
        # Fail at construction, not first query, if the file is unusable.
        c = self._checkout()
        try:
            c.conn.execute("SELECT 1").fetchone()
        finally:
            self._checkin(c)

    # -- connection pool ----------------------------------------------------

    def _new_conn(self) -> _CagedConn:
        p = self.policy
        conn = sqlite3.connect(
            f"file:{self.path}?mode=ro&immutable=1", uri=True,
            check_same_thread=False)   # ownership is enforced by the pool
        try:
            conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        except AttributeError:                # 3.11: six layers, documented
            pass
        conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, p.max_length)
        conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, p.max_sql_bytes)
        conn.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, p.max_expr_depth)
        conn.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT,
                      p.max_compound_select)
        conn.setlimit(sqlite3.SQLITE_LIMIT_TRIGGER_DEPTH, 0)
        caged = _CagedConn(conn)
        # Each connection's authorizer writes its OWN denial holder — no
        # cross-execution contamination of the QueryDenied message.
        conn.set_authorizer(
            lambda op, a1, a2, db, tr: self._authorize(caged, op, a1, a2))
        return caged

    def _checkout(self) -> _CagedConn:
        with self._pool_lock:
            if self._pool:
                return self._pool.pop()
        return self._new_conn()

    def _checkin(self, c: _CagedConn) -> None:
        c.denied = None
        c.conn.set_progress_handler(None, 0)
        with self._pool_lock:
            # The semaphore already bounds live connections to max_concurrency,
            # so the pool should never exceed it. Cap defensively anyway: a
            # surplus connection is closed rather than hoarded, so no code path
            # can grow the pool (and its file descriptors) without bound.
            if len(self._pool) >= self.policy.max_concurrency:
                c.conn.close()
            else:
                self._pool.append(c)

    def _acl_shadow_denied(self, table: str) -> bool:
        """True if `table` is an FTS index or shadow of an ACL-protected base.

        The relationship base→index is not a naming rule (SQLite lets an FTS5
        table be named anything and point at any content table via
        `content='…'`), so it is discovered from the schema at construction,
        not guessed from prefixes.
        """
        return table in self._acl_denied_tables

    def _discover_fts_shadows(self) -> frozenset[str]:
        """Names to deny outright because they expose an ACL-protected table.

        Runs once, with a plain connection and NO authorizer, before the caged
        connections are built. For every FTS5 vtable whose `content=` names an
        ACL-protected table (or which has any column ACL of its own), deny the
        vtable and all five shadow tables — otherwise `hex(block) FROM
        x_fts_data` and `MATCH` recover the hidden text.
        """
        if not self._acl:
            return frozenset()
        protected = set(self._acl)
        denied: set[str] = set()
        raw = sqlite3.connect(f"file:{self.path}?mode=ro&immutable=1", uri=True)
        try:
            rows = raw.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table'"
            ).fetchall()
        finally:
            raw.close()
        for name, sql in rows:
            s = (sql or "").lower()
            if "using fts" not in s:
                continue
            m = re.search(r"content\s*=\s*'([^']+)'", s)
            content = m.group(1) if m else name
            if content in protected or name in protected:
                denied.add(name)
                denied.update(f"{name}_{suf}" for suf in
                              ("data", "idx", "docsize", "content", "config"))
        return frozenset(denied)

    def _authorize(self, caged: _CagedConn, op, a1, a2) -> int:
        if op == sqlite3.SQLITE_PRAGMA:
            # FTS5 reads `PRAGMA data_version` internally to detect database
            # changes; the READ form (no value argument) is harmless. Every
            # other pragma stays denied — including this one's WRITE form.
            if a1 == "data_version" and a2 is None:
                return sqlite3.SQLITE_OK
            caged.denied = (op, a1)
            return sqlite3.SQLITE_DENY
        if op not in _ALLOWED_OPS:
            caged.denied = (op, a1)
            return sqlite3.SQLITE_DENY
        if op == getattr(sqlite3, "SQLITE_FUNCTION", 31):
            # For SQLITE_FUNCTION the function name arrives as the SECOND
            # argument (a1 is NULL).
            name = (a2 or a1 or "")
            if isinstance(name, str) and name.lower() in self._deny_functions:
                caged.denied = (op, name)
                return sqlite3.SQLITE_DENY
        if op == sqlite3.SQLITE_READ and self._acl:
            table = a1
            # A hidden column is worthless if its FTS shadow tables remain
            # readable: `hex(block) FROM pages_fts_data` recovers the tokenised
            # text, and `MATCH` on the vtable is a per-term presence oracle
            # (red-team BREAK 1). Deny every FTS shadow/vtable belonging to a
            # protected base table (discovered from the schema), and hide
            # sqlite_master DDL for fully-hidden tables (schema leak, BREAK 2).
            if table == "sqlite_master" and a2 in ("sql", "rootpage"):
                # We cannot see which row is being read, so when any table is
                # fully hidden, blank DDL/rootpage wholesale. Names stay
                # visible (harmless, and the query planner needs them).
                if any(v is None for v in self._acl.values()):
                    return sqlite3.SQLITE_IGNORE
            if self._acl_shadow_denied(table):
                caged.denied = (op, table)
                return sqlite3.SQLITE_DENY
            acl = self._acl.get(table)
            if acl is None and table in self._acl:
                caged.denied = (op, table)
                return sqlite3.SQLITE_DENY          # whole table hidden
            if acl and a2 in acl:               # acl is a frozenset of columns
                # SQLITE_IGNORE reads the column as NULL: the row shape
                # survives, the value does not.
                return sqlite3.SQLITE_IGNORE
        return sqlite3.SQLITE_OK

    # -- the public surface -------------------------------------------------

    def query(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        """Run one read-only statement; return all rows as list[dict].

        RAISES TruncatedResult if the result exceeds max_rows. Use this when
        the caller will treat the rows as complete (aggregation, joins, any
        "the answer is X" claim) — silently returning a partial there is the
        confident-lie failure this library exists to prevent. When a partial
        view is acceptable, use `fetch()`, which returns a Result carrying an
        explicit truncation signal instead of raising.
        """
        rows: list[dict] = []
        for kind, payload in self._run(sql, params):
            if kind == "row":
                rows.append(payload)
            else:                               # "truncated"
                raise TruncatedResult(
                    f"result exceeds max_rows={self.policy.max_rows}; "
                    "returning it as if complete produces confident lies — "
                    "aggregate in SQL, or use fetch() to accept a partial "
                    "view with a truncation flag", sql)
        return rows

    def fetch(self, sql: str, params: tuple | dict = ()) -> Result:
        """Run one read-only statement; return a Result that never hides
        truncation. The rows are capped at max_rows and `result.truncated`
        tells the client whether more exist — the Datasette-style contract,
        but with the flag carried in the same envelope as the rows and an
        actionable note attached (see Result.envelope)."""
        rows: list[dict] = []
        truncated = False
        for kind, payload in self._run(sql, params):
            if kind == "row":
                rows.append(payload)
            else:
                truncated = True
        return Result(tuple(rows), truncated, self.policy.max_rows, sql)

    def stream(self, sql: str, params: tuple | dict = ()) -> Iterator[dict]:
        """Iterate rows under the same budgets. Raises on truncation."""
        for kind, payload in self._run(sql, params):
            if kind == "row":
                yield payload
            else:
                raise TruncatedResult(
                    f"result exceeds max_rows={self.policy.max_rows}", sql)

    def explain(self, sql: str, params: tuple | dict = ()) -> None:
        """Compile-only pre-flight: authorizer + limits, no execution.

        Takes a concurrency slot and arms the deadline like any other
        execution — round 2 found it did neither, so an explain() flood grew
        the pool past max_concurrency and could exhaust file descriptors.
        """
        with self._slot(sql):
            caged, t0 = self._begin(sql)
            try:
                # EXPLAIN compiles the inner statement (authorizer runs) but
                # executes only the opcode listing.
                cur = caged.conn.execute(f"EXPLAIN {sql}", params or ())
                cur.fetchone()
                cur.close()
            except sqlite3.Error as exc:
                raise self._classify(exc, sql, t0, caged) from exc
            finally:
                self._checkin(caged)

    # -- optional async facade ---------------------------------------------
    #
    # SQLite is a blocking library — there is no native async. These wrap the
    # SYNC methods (the tested core) in a bounded thread pool; they add a
    # thread hop and queue-based backpressure, nothing else. The sync methods
    # remain the default and the reference implementation.

    def _get_executor(self):
        if self._executor is None:
            with self._executor_lock:
                if self._executor is None:
                    from concurrent.futures import ThreadPoolExecutor
                    self._executor = ThreadPoolExecutor(
                        max_workers=self.policy.max_concurrency,
                        thread_name_prefix="cage")
        return self._executor

    async def aquery(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        """Async `query()`. Excess concurrent calls queue in the executor
        (bounded to max_concurrency) instead of failing the semaphore."""
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._get_executor(), self.query, sql, params)

    async def afetch(self, sql: str, params: tuple | dict = ()) -> Result:
        """Async `fetch()` — same bounded-executor bridge."""
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._get_executor(), self.fetch, sql, params)

    def close(self) -> None:
        """Release pooled connections and the async executor, if any."""
        with self._pool_lock:
            for c in self._pool:
                c.conn.close()
            self._pool.clear()
        if self._executor is not None:
            self._executor.shutdown(wait=False)
            self._executor = None

    # -- internals ----------------------------------------------------------

    @contextmanager
    def _slot(self, sql: str):
        """Hold one concurrency slot for the whole body, always released."""
        if not self._sem.acquire(timeout=self.policy.deadline_s * 2):
            raise QueryTimeout(
                f"no execution slot within {self.policy.deadline_s * 2:.1f}s "
                f"(max_concurrency={self.policy.max_concurrency})", sql)
        try:
            yield
        finally:
            self._sem.release()

    def _begin(self, sql: str) -> tuple[_CagedConn, float]:
        """Check out a connection and arm its deadline.

        Checkout can fail on I/O (an empty pool must open a new file); round 2
        found that failure escaping raw and leaking the slot because checkout
        sat outside the guarded region. Here it is classified to a CageError,
        and callers run under `_slot`, so the slot is released regardless.
        """
        caged = None
        try:
            caged = self._checkout()
            p = self.policy
            t0 = time.monotonic()
            deadline = t0 + p.deadline_s
            # The progress handler only fires every N VDBE ops, so a query that
            # does heavy work in FEWER than N ops can blow past the deadline
            # between checks (red-team BREAK 4). Scale the interval to the
            # deadline: a short deadline gets a finer check.
            ops = min(p.progress_every_ops, 500) if p.deadline_s <= 0.5 \
                else p.progress_every_ops
            # set_progress_handler DISABLES the handler when the interval is
            # <= 0, silently removing the deadline (round-3 BREAK 1). The policy
            # rejects progress_every_ops < 1, but floor here too so the guard
            # cannot vanish even if the arithmetic ever produces 0.
            caged.conn.set_progress_handler(
                lambda: 1 if time.monotonic() > deadline else 0, max(1, ops))
            return caged, t0
        except sqlite3.Error as exc:
            # Everything from checkout through arming the deadline is guarded:
            # if set_progress_handler (or checkout) ever raises, the connection
            # is returned to the pool and the error is classified, never
            # escaping raw or leaking the connection (round-3 refactor seam).
            if caged is not None:
                self._checkin(caged)
            raise self._classify(exc, sql) from exc

    def _run(self, sql: str, params: tuple | dict):
        p = self.policy
        with self._slot(sql):
            # A dedicated connection for THIS execution's whole lifetime, held
            # even while a stream() is suspended, so its progress handler and
            # denial holder cannot be torn down by another call (finding #19).
            caged, t0 = self._begin(sql)
            try:
                conn = caged.conn
                cur = conn.execute(sql, params or ())
                cols = [d[0] for d in cur.description or ()]
                # Bound row WIDTH before fetching anything. The per-row byte
                # budget is checked post-fetch, so the very first row is fully
                # materialised no matter how large — a 2000-column × 1 MB row
                # allocates gigabytes before the budget is ever consulted
                # (red-team BREAK 1). A column-count ceiling is the only guard
                # that acts before materialisation; combined with per-value
                # max_length it bounds the worst first row at
                # max_columns × max_length.
                if len(cols) > p.max_columns:
                    cur.close()
                    raise ResultBudgetExceeded(
                        f"result has {len(cols)} columns (max "
                        f"{p.max_columns}); a wide row can exhaust memory "
                        "before the byte budget is checked — select fewer "
                        "columns", sql)
                budget = p.max_result_bytes
                n = 0
                while True:
                    row = cur.fetchone()
                    if row is None:
                        break
                    n += 1
                    if n > p.max_rows:
                        cur.close()
                        yield ("truncated", n)
                        return
                    # Per-value guard as well: max_length bounds one value,
                    # but the sum across even a few columns can still be large.
                    rb = _row_bytes(row)
                    budget -= rb
                    if budget < 0:
                        cur.close()
                        raise ResultBudgetExceeded(
                            f"result passed {p.max_result_bytes} bytes at "
                            f"row {n} ({rb} in that row); select fewer/"
                            "narrower columns", sql)
                    yield ("row", dict(zip(cols, row)))
                cur.close()
            except sqlite3.Error as exc:
                raise self._classify(exc, sql, t0, caged) from exc
            finally:
                # Return the connection (clears its handler + denial holder)
                # on normal completion, exception, or generator close — an
                # early break out of stream() runs this too. The slot is
                # released by the enclosing _slot() context.
                self._checkin(caged)
                elapsed = time.monotonic() - t0
                if p.slow_log and elapsed >= p.slow_log_s:
                    # A diagnostic hook must never mask the real result or
                    # error: this runs in `finally`, so an exception here would
                    # overwrite an in-flight QueryTimeout/Denied/Budget with a
                    # bare, query-less error (round-3 BREAK 3). Swallow it.
                    try:
                        p.slow_log(elapsed, sql)
                    except Exception:  # noqa: BLE001, S110  (must never mask the real error)
                        pass

    def _classify(self, exc: sqlite3.Error, sql: str,
                  t0: float | None = None,
                  caged: _CagedConn | None = None) -> CageError:
        msg = str(exc)
        if "interrupted" in msg:
            took = f" after {time.monotonic() - t0:.2f}s" if t0 else ""
            return QueryTimeout(
                f"deadline {self.policy.deadline_s}s exceeded{took}", sql)
        # SQLite phrases an authorizer DENY several ways depending on where it
        # fired: "not authorized" for a plain read, "access to X.Y is
        # prohibited" for a denied column/table, and a vtable "constructor
        # failed" when the denied table is an FTS vtable. All are our denial.
        if ("not authorized" in msg or "authorization denied" in msg
                or "authorizer" in msg or "is prohibited" in msg
                or ("vtable constructor failed" in msg and caged
                    and caged.denied)):
            denied = caged.denied if caged else None
            what = (f"operation {denied[0]} on {denied[1]!r}" if denied
                    else "an operation")
            return QueryDenied(
                f"denied: {what}. This interface is read-only SELECT; "
                "no PRAGMA/ATTACH/writes, and some functions are blocked",
                sql)
        if "too many terms in compound SELECT" in msg or \
           "Expression tree is too large" in msg or \
           "statement too long" in msg or "string or blob too big" in msg:
            return QueryDenied(f"limit exceeded: {msg}", sql)
        return QueryError(msg, sql)
