"""sqlite-cage — run untrusted SQL against SQLite, safely and honestly.

README.md is the guide; docs/THREAT_MODEL.md is the boundary. Layers, ordered
by when they act: read-only open (WAL-aware; `immutable` is opt-in for truly
frozen files); DEFENSIVE dbconfig; hard limits enforced by the engine at
prepare time (ATTACHED=0, value length, result-column count, expression
depth); a deny-by-default authorizer at compile time; single-statement by
construction; a progress-handler deadline; and a result budget counted in
BYTES as well as rows while fetching.

The honesty contract is not optional: truncation RAISES from query()/stream()
unless the caller uses fetch() to accept a signalled partial, and no failure
path ever returns an empty list.

Stdlib only — no dependencies. Python floor 3.12 (Connection.setlimit and
setconfig, so DBCONFIG_DEFENSIVE is universal, never best-effort). SQLite
floor 3.37.0: read-only WAL opens (3.22), DEFENSIVE (3.26), a real
trusted_schema pragma (3.31), and engine-typed shadow-table enumeration via
PRAGMA table_list (3.37) — plus the corruption-hardening years between. A
uv-managed Python bundles a current SQLite regardless of the distro's
libsqlite3, so both floors are about the interpreter, not the OS.
Vendorable: copying this single file into a project is supported.
"""
from __future__ import annotations

import math
import sqlite3

__version__ = "0.2.0"
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

if sys.version_info < (3, 12):  # noqa: UP036  (informative refusal, not silent degradation)
    raise ImportError(
        "sqlcage needs Python 3.12+ (Connection.setlimit and setconfig for "
        "SQLITE_DBCONFIG_DEFENSIVE); running with fewer protection layers "
        "silently is worse than refusing")

if not hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE"):
    raise ImportError(
        "this Python's sqlite3 module lacks SQLITE_DBCONFIG_DEFENSIVE "
        "(built against pre-3.26 SQLite headers); running with fewer "
        "protection layers silently is worse than refusing")

if sqlite3.sqlite_version_info < (3, 37, 0):
    raise ImportError(
        f"sqlcage needs SQLite >= 3.37.0, found {sqlite3.sqlite_version}: "
        "the cage relies on read-only WAL opens (3.22), DBCONFIG_DEFENSIVE "
        "(3.26), trusted_schema (3.31), and engine-typed shadow-table "
        "enumeration via PRAGMA table_list (3.37); running with fewer "
        "protection layers silently is worse than refusing. A uv-managed "
        "Python bundles a current SQLite even where the OS ships an old "
        "libsqlite3")

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
    """Everything else SQLite raised (syntax, missing table, bad params) —
    plus the cage's own refusal of a result shape it cannot return honestly
    (duplicate result-column names)."""


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
    max_result_bytes: int = 64 << 20           # 64 MiB result budget
    max_concurrency: int = 3
    progress_every_ops: int = 5_000
    max_sql_bytes: int = 100_000
    # max_length bounds ONE string/blob value (and, per SQLite's LIMIT_LENGTH
    # semantics, one stored table row). max_columns bounds the result WIDTH at
    # prepare time. Their PRODUCT bounds the worst first row SQLite can
    # materialise before the byte budget is ever consulted: 256 × 512 KiB =
    # 128 MiB by default. Tighten either on memory-constrained hosts.
    max_length: int = 512 * 1024               # largest single string/blob
    max_columns: int = 256                     # result-column count ceiling
    max_expr_depth: int = 200
    max_compound_select: int = 50
    max_like_pattern: int = 1_000              # LIKE/GLOB pattern bytes
    max_function_args: int = 64                # args to one SQL function
    max_bound_params: int = 999                # highest ?NNN parameter
    deny_functions: frozenset[str] = frozenset({"randomblob", "zeroblob"})
    # {"table": {"deny_columns": {"col", ...}}} or {"table": None} to hide it
    table_acl: dict = field(default_factory=dict, hash=False)
    slow_log_s: float = 1.5
    slow_log: object = None                    # callable(elapsed_s, sql) | None

    def __post_init__(self):
        # A degenerate policy value must fail LOUDLY at construction, not
        # silently disable a guard at query time or surface as a raw
        # sqlite3/ValueError from deep inside setlimit (round-3 BREAK 1 & 4).
        # Round 4 (external review) added type strictness: bool is an int
        # subclass, inf passes a `> 0` check while disabling the deadline,
        # and a bare-string deny list iterates per CHARACTER — each would
        # quietly weaken a guard while looking configured.
        problems: list[str] = []

        def num(name: str, minimum, *, integer=True, exclusive=False):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(
                    v, int if integer else (int, float)):
                problems.append(
                    f"{name} must be {'an int' if integer else 'a finite number'}")
            elif not integer and not math.isfinite(v):
                problems.append(f"{name} must be a finite number")
            elif (v <= minimum) if exclusive else (v < minimum):
                problems.append(f"{name} out of range")

        num("deadline_s", 0, integer=False, exclusive=True)
        num("slow_log_s", 0, integer=False)
        num("max_rows", 0)
        num("max_result_bytes", 1)
        num("max_concurrency", 1)
        num("progress_every_ops", 1)
        num("max_sql_bytes", 1)
        num("max_length", 1)
        num("max_columns", 1)
        num("max_expr_depth", 1)
        num("max_compound_select", 1)
        num("max_like_pattern", 1)
        num("max_function_args", 1)
        num("max_bound_params", 1)

        # Deliberately NO cross-field invariant tying max_columns/max_length
        # to max_result_bytes (twice proposed in review): no combination of
        # them disables a guard — a row that overruns the budget raises,
        # loudly — and the budget is checked per fetched row regardless, so
        # the invariant would not prevent first-row materialisation either.
        # The real pre-budget bound is the max_columns × max_length product,
        # documented in the README and THREAT_MODEL; small budgets with
        # default value caps are legitimate configurations.

        if self.slow_log is not None and not callable(self.slow_log):
            problems.append("slow_log must be callable or None")

        # The collections are NORMALISED to frozensets below, not merely
        # validated: a one-shot iterable (a generator) would satisfy every
        # check here, be consumed doing so, and then iterate as EMPTY at
        # enforcement time — a denylist/ACL that validated as configured and
        # protects nothing (round-4.1 finding, reproduced).
        fns = None
        if isinstance(self.deny_functions, (str, bytes)):
            problems.append("deny_functions must be a collection of function "
                            "names, not a bare string")
        else:
            try:
                fns = list(self.deny_functions)
            except TypeError:
                problems.append("deny_functions must be iterable")
            if fns and any(not isinstance(f, str) or not f for f in fns):
                fns = None
                problems.append(
                    "deny_functions entries must be nonempty strings")

        acl_norm: dict[str, dict | None] | None = {}
        if not isinstance(self.table_acl, dict):
            acl_norm = None
            problems.append("table_acl must be a dict")
        else:
            folded_seen: dict[str, str] = {}
            for t, v in self.table_acl.items():
                where = f"table_acl[{t!r}]"
                if not isinstance(t, str) or not t:
                    acl_norm = None
                    problems.append(f"{where}: key must be a nonempty string")
                    continue
                # SQLite folds identifier case, so "docs" and "DOCS" are ONE
                # table; two dict keys folding together would resolve
                # last-wins — {"docs": None, "DOCS": {...}} silently trading
                # a whole-table denial for a column mask (round 4.3).
                folded = _ident_lower(t)
                if folded in folded_seen:
                    acl_norm = None
                    problems.append(
                        f"table_acl keys {folded_seen[folded]!r} and {t!r} "
                        "name the same table under SQLite's case folding")
                    continue
                folded_seen[folded] = t
                if v is None:
                    if acl_norm is not None:
                        acl_norm[t] = None
                    continue
                if not isinstance(v, dict) or set(v) - {"deny_columns"}:
                    acl_norm = None
                    problems.append(
                        f"{where} must be None or {{'deny_columns': ...}}")
                    continue
                dc = v.get("deny_columns", ())
                if isinstance(dc, (str, bytes)):
                    acl_norm = None
                    problems.append(
                        f"{where}['deny_columns'] must be a collection of "
                        "column names, not a bare string (a string would "
                        "deny per-character)")
                    continue
                try:
                    dcols = list(dc)
                except TypeError:
                    acl_norm = None
                    problems.append(f"{where}['deny_columns'] must be iterable")
                    continue
                if any(not isinstance(c, str) or not c for c in dcols):
                    acl_norm = None
                    problems.append(
                        f"{where} deny_columns entries must be nonempty strings")
                    continue
                if acl_norm is not None:
                    acl_norm[t] = {"deny_columns": frozenset(dcols)}

        if problems:
            raise ValueError(
                "CagePolicy: " + "; ".join(problems)
                + " (a guard cannot be disabled by a degenerate setting)")

        object.__setattr__(self, "deny_functions", frozenset(fns or ()))
        object.__setattr__(self, "table_acl", acl_norm)


@dataclass
class _CagedConn:
    """One connection plus its private authorizer-denial holder.

    `gen` is the cage's snapshot generation this connection was built under;
    a connection from an older generation has a stale schema-parse cache (and,
    on an immutable cage, possibly a whole stale FILE via its open fd), so it
    is retired at its next touch instead of being reused.
    """
    conn: sqlite3.Connection
    gen: int = 0
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


# SQLite folds identifier case for ASCII only; str.lower() folds all of
# Unicode (e.g. 'İ' → 'i̇'), which could make two names compare equal here
# that SQLite treats as distinct. Every name comparison in the cage goes
# through this.
_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def _ident_lower(s: str) -> str:
    return s.translate(_ASCII_LOWER)


def _sql_tokens(sql: str) -> list[tuple[str, str]]:
    """Tokenise a CREATE statement well enough to read a vtable declaration.

    Kinds: 'name' (bare word), 'str' (single-quoted literal), 'qname'
    (identifier quoted with double quotes, backticks, or [brackets]) and
    'punct'. Quote-doubling escapes and both comment forms are handled.
    Raises ValueError on an unterminated construct — the caller fails closed.
    """
    out: list[tuple[str, str]] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c.isspace():
            i += 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            if j < 0:
                raise ValueError("unterminated comment")
            i = j + 2
        elif c in ("'", '"', "`"):
            j, buf = i + 1, []
            while True:
                k = sql.find(c, j)
                if k < 0:
                    raise ValueError("unterminated quote")
                if k + 1 < n and sql[k + 1] == c:      # doubled-quote escape
                    buf.append(sql[j:k + 1])
                    j = k + 2
                else:
                    buf.append(sql[j:k])
                    j = k + 1
                    break
            out.append(("str" if c == "'" else "qname", "".join(buf)))
            i = j
        elif c == "[":
            k = sql.find("]", i + 1)
            if k < 0:
                raise ValueError("unterminated [identifier")
            out.append(("qname", sql[i + 1:k]))
            i = k + 1
        elif c.isalnum() or c in "_$":
            j = i
            while j < n and (sql[j].isalnum() or sql[j] in "_$"):
                j += 1
            out.append(("name", sql[i:j]))
            i = j
        else:
            out.append(("punct", c))
            i += 1
    return out


def _parse_vtable_decl(sql: str) -> tuple[str, str | None] | None:
    """Understand one sqlite_master `CREATE VIRTUAL TABLE` entry.

    Returns None when `sql` is not a CREATE VIRTUAL TABLE statement at all.
    Otherwise `(module, content)` where content is the value of a `content=`
    option: a table name, '' for a contentless index, or None when the option
    is absent. Raises ValueError when the declaration cannot be conclusively
    understood — the caller must treat that as protected (fail closed), never
    as unrelated. Built on a real tokenizer because the previous regex over a
    lowercased copy missed content="docs", content=[docs], comments, and
    case-folded quoted literals (external review, round 4).
    """
    toks = _sql_tokens(sql)

    def word(idx: int, w: str) -> bool:
        return (idx < len(toks) and toks[idx][0] == "name"
                and _ident_lower(toks[idx][1]) == w)

    if not (word(0, "create") and word(1, "virtual") and word(2, "table")):
        return None
    i = 3
    if word(i, "if") and word(i + 1, "not") and word(i + 2, "exists"):
        i += 3
    if i >= len(toks) or toks[i][0] not in ("name", "qname"):
        raise ValueError("no table name")
    i += 1
    if i < len(toks) and toks[i] == ("punct", "."):        # schema-qualified
        i += 2
    if not word(i, "using"):
        raise ValueError("no USING clause")
    i += 1
    if i >= len(toks) or toks[i][0] not in ("name", "qname"):
        raise ValueError("no module name")
    module = toks[i][1]
    i += 1
    if i == len(toks):
        return module, None                    # argument-less (fts3/4 style)
    if toks[i] != ("punct", "("):
        raise ValueError("junk after module name")
    depth, groups, cur = 1, [], []
    i += 1
    while i < len(toks):
        kind, val = toks[i]
        if kind == "punct" and val == "(":
            depth += 1
        elif kind == "punct" and val == ")":
            depth -= 1
            if depth == 0:
                break
        if kind == "punct" and val == "," and depth == 1:
            groups.append(cur)
            cur = []
        else:
            cur.append(toks[i])
        i += 1
    if depth != 0:
        raise ValueError("unbalanced parentheses")
    if i != len(toks) - 1:
        raise ValueError("junk after argument list")
    groups.append(cur)

    content, seen = None, 0
    for g in groups:
        if (len(g) >= 2 and g[0][0] in ("name", "qname", "str")
                and _ident_lower(g[0][1]) == "content"
                and g[1] == ("punct", "=")):
            if len(g) != 3 or g[2][0] not in ("name", "qname", "str"):
                raise ValueError("unreadable content= option")
            content = g[2][1]
            seen += 1
    if seen > 1:
        raise ValueError("multiple content= options")
    return module, content


_FTS_MODULES = frozenset({"fts3", "fts4", "fts5"})
# Union of the FTS5 (…_data/_idx/_content/_docsize/_config) and FTS3/4
# (…_content/_segments/_segdir/_docsize/_stat) shadow layouts. Actual schema
# names with the vtable's prefix are denied as well, so a layout this list
# does not know still cannot leak.
_FTS_SHADOW_SUFFIXES = ("data", "idx", "content", "docsize", "config",
                        "segments", "segdir", "stat")


class Cage:
    """A pool of caged read-only connections over one database file.

    `immutable=True` additionally promises SQLite that the file cannot change
    by ANY means while the cage lives: SQLite then takes no locks and ignores
    `-wal`/`-journal` files entirely. That is only safe for a truly frozen
    file — on a database with a live WAL it produces stale reads or spurious
    errors (verified: a committed-but-uncheckpointed table is simply invisible).
    The default `mode=ro` open honors WAL and locking and is safe alongside
    writers.
    """

    def __init__(self, path: str | Path, policy: CagePolicy | None = None,
                 *, immutable: bool = False):
        # Resolve NOW: a relative path kept around would silently point new
        # pool connections somewhere else after a chdir(); and the raw path
        # was previously spliced into the URI unescaped, so '?' or '#' in a
        # filename changed the URI's meaning (round 4). as_uri() percent-
        # escapes; resolve(strict=True) raises FileNotFoundError if missing.
        self.path = Path(path).resolve(strict=True)
        if not self.path.is_file():
            raise ValueError(f"not a regular file: {self.path}")
        if not isinstance(immutable, bool):
            # bool("false") is True: a truthy non-bool would silently turn on
            # the unsafe-for-live-databases mode (round-4.1 finding).
            raise TypeError(
                f"immutable must be True or False, not {immutable!r}")
        self.immutable = immutable
        self._uri = (self.path.as_uri() + "?mode=ro"
                     + ("&immutable=1" if self.immutable else ""))
        self.policy = policy or CagePolicy()
        self._closed = False
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
        self._deny_functions = frozenset(
            _ident_lower(f) for f in self.policy.deny_functions)
        # The ACL SPECIFICATION, captured deep-immutably before anything else
        # reads it. The policy is frozen against REBINDING but its table_acl
        # dict is not frozen against in-place mutation (round-3 BREAK 2), and
        # every snapshot REBUILD — refresh() or a writer-triggered epoch
        # rebuild — re-resolves the ACL; resolving from the live policy would
        # let `policy.table_acl.clear()` plus any rebuild loosen enforcement
        # that construction froze (round-4.2 regression, caught in review).
        # The per-table frozensets are already normalised by CagePolicy.
        self._acl_spec: tuple[tuple[str, frozenset | None], ...] = tuple(
            (t, None if v is None else v["deny_columns"])
            for t, v in self.policy.table_acl.items())
        # One schema snapshot drives the construction-time jobs: validating
        # the ACL against real tables/columns and discovering FTS shadows to
        # deny. Snapshotting into immutable form matters: enforcement reads
        # these snapshots, never self.policy. The snapshot is keyed to
        # schema_version and refreshed per execution when a live writer
        # changes the schema (round 4.1) — see _verify_schema_epoch.
        self._schema_lock = threading.Lock()
        self._generation = 0
        # Set when a snapshot REBUILD failed (schema no longer satisfies the
        # ACL, or could not be read): the cage fails closed — every query
        # raises — until a later rebuild succeeds. Without it, a failed
        # refresh() on an immutable cage whose file was replaced left the old
        # pool serving the REPLACED file's data (round 4.3, reproduced) —
        # exactly the corpus-revocation case refresh() exists for.
        self._schema_tainted: str | None = None
        schema, columns, kinds, self._schema_version = self._load_schema()
        self._acl = self._resolve_acl(columns)
        self._acl_denied_tables = self._discover_fts_shadows(
            schema, self._acl, kinds)
        # Fail at construction, not first query, if the file is unusable.
        c = self._checkout()
        try:
            c.conn.execute("SELECT 1").fetchone()
        finally:
            self._checkin(c)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- connection pool ----------------------------------------------------

    def _new_conn(self) -> _CagedConn:
        p = self.policy
        # timeout= caps SQLite's BUSY wait (a locked database retries inside
        # sqlite3_step, where the progress handler never runs). The default
        # is a fixed 5 s that ignores the policy entirely: a deadline_s=0.1
        # query against a writer-locked database took 10.4 s — two stacked
        # busy windows (round 4.3, measured). Scaling it to deadline_s keeps
        # the whole execution bounded by a small multiple of the deadline.
        conn = sqlite3.connect(
            self._uri, uri=True, timeout=p.deadline_s,
            check_same_thread=False)   # ownership is enforced by the pool
        # Unconditional: the 3.12 Python floor guarantees setconfig, and the
        # import-time check guarantees the constant (round 4.6 — DEFENSIVE
        # was documented as always-on but was best-effort on Python 3.11).
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        # Three engine-level pragmas the caged caller can never revert (the
        # authorizer denies every pragma WRITE form): query_only refuses
        # writes inside the engine even if some future authorizer bug let
        # one compile; trusted_schema=OFF stops functions/vtables embedded
        # in the SCHEMA (views, expression indexes) from running with
        # elevated trust (guaranteed real by the 3.37 floor); and
        # cell_size_check=ON validates b-tree cells as pages are read, so a
        # malformed page surfaces as a clean SQLITE_CORRUPT error instead
        # of undefined nonsense (round 4.4/4.5).
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA cell_size_check=ON")
        conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, p.max_length)
        conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, p.max_sql_bytes)
        conn.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, p.max_expr_depth)
        conn.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT,
                      p.max_compound_select)
        conn.setlimit(sqlite3.SQLITE_LIMIT_TRIGGER_DEPTH, 0)
        conn.setlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH,
                      p.max_like_pattern)   # long patterns match in O(N×M)
        conn.setlimit(sqlite3.SQLITE_LIMIT_FUNCTION_ARG, p.max_function_args)
        conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER,
                      p.max_bound_params)   # ?NNN allocates an NNN-slot vector
        # SQLITE_LIMIT_VDBE_OP is deliberately NOT set: SQLite reports
        # exceeding it as an out-of-memory condition, which Python raises as
        # a bare MemoryError — indistinguishable from real OOM, so enforcing
        # it would either leak a raw error (the honesty contract forbids
        # that) or force catching MemoryError and mislabeling genuine ones.
        # Program size stays indirectly bounded by max_sql_bytes,
        # max_expr_depth and max_compound_select.
        # The engine-level width limit rejects an over-wide SELECT at PREPARE
        # time. This is the load-bearing width defense: Python's execute()
        # advances the statement one step, so SQLite has fully materialised
        # the first row in C memory before any Python-side check can run
        # (round 4; measured 220 MB resident from a 10 × 20 MB-expression
        # SELECT with no fetch). But the same limit governs PARSING every
        # CREATE in sqlite_master, so it cannot simply be set low on a fresh
        # connection — a database containing one wide table would fail every
        # query. Order matters instead (round 4.1): warm the schema cache
        # NOW, under SQLite's default limit, then drop the limit to exactly
        # max_columns for everything untrusted that follows. Narrow queries
        # over wide tables keep working; a 257-expression SELECT does not
        # (the earlier max(max_columns, widest-table) sizing let a wide
        # schema raise the ceiling for wide-expression attacks too).
        try:
            row = conn.execute("SELECT name FROM sqlite_master "
                               "WHERE type='table' LIMIT 1").fetchone()
            if row:
                quoted = row[0].replace('"', '""')
                conn.execute(f'SELECT * FROM "{quoted}" LIMIT 0').fetchone()
        except sqlite3.Error:
            # An unwarmable schema (e.g. first table is a vtable whose module
            # is unavailable) stays cold; queries still run, and on a wide
            # schema they fail closed at prepare rather than open.
            pass
        conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, self.policy.max_columns)
        caged = _CagedConn(conn, gen=self._generation)
        # Each connection's authorizer writes its OWN denial holder — no
        # cross-execution contamination of the QueryDenied message.
        conn.set_authorizer(
            lambda op, a1, a2, db, tr: self._authorize(caged, op, a1, a2))
        return caged

    def _checkout(self) -> _CagedConn:
        with self._pool_lock:
            if self._closed:
                raise CageError("cage is closed")
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
            # can grow the pool (and its file descriptors) without bound. A
            # connection finishing after close() is likewise closed, not
            # re-pooled — close() means closed, not "closed except stragglers" —
            # and one that outlived a snapshot refresh is retired rather than
            # re-pooled with a stale parse cache.
            if self._closed or c.gen != self._generation \
                    or len(self._pool) >= self.policy.max_concurrency:
                c.conn.close()
            else:
                self._pool.append(c)

    # -- construction-time schema discovery ---------------------------------

    def _load_schema(self) -> tuple[list[tuple], dict, dict, int]:
        """One un-caged snapshot: sqlite_master rows, columns, kinds, version.

        Runs with a plain connection and NO authorizer. Returns
        ([(name, type, sql), ...] for tables and views,
        {folded_name: [column, ...] | None},
        {folded_name: 'table'|'view'|'virtual'|'shadow'}, schema_version) —
        a None column list marks an object whose columns could not be read
        (e.g. a vtable whose module is not loadable here). `kinds` comes
        from PRAGMA table_list (the 3.37 floor guarantees it): the engine's
        OWN typing of every relation, which is what lets shadow discovery
        work from ground truth instead of name heuristics. The reads share
        one read transaction so the version tags a CONSISTENT snapshot: a
        writer changing the schema mid-read bumps the version and the next
        execution refreshes.
        """
        raw = sqlite3.connect(self._uri, uri=True,
                              timeout=self.policy.deadline_s)
        try:
            if not self.immutable:
                raw.execute("BEGIN")
            version = raw.execute("PRAGMA schema_version").fetchone()[0]
            rows = raw.execute(
                "SELECT name, type, sql FROM sqlite_master "
                "WHERE type IN ('table', 'view')").fetchall()
            kinds = {
                _ident_lower(r[1]): r[2]
                for r in raw.execute("PRAGMA table_list")
                if r[0] == "main" and not r[1].startswith("sqlite_")}
            columns: dict[str, list[str] | None] = {}
            for name, _typ, _sql in rows:
                quoted = name.replace('"', '""')
                try:
                    columns[_ident_lower(name)] = [
                        r[1] for r in
                        raw.execute(f'PRAGMA table_xinfo("{quoted}")')]
                except sqlite3.Error:
                    columns[_ident_lower(name)] = None
        finally:
            raw.close()
        return rows, columns, kinds, version

    def _resolve_acl(self, columns: dict) -> dict[str, frozenset | None]:
        """Resolve the construction-time ACL spec against a schema, loudly.

        Reads self._acl_spec, NEVER self.policy: rebuilds re-run this, and
        the policy's table_acl dict is mutable — resolving from it would let
        `policy.table_acl.clear()` plus any rebuild loosen enforcement that
        round 3 froze (round-4.2 regression). A typo'd table or column name
        would otherwise sit in the ACL "protecting" nothing — a security
        config that LOOKS active and is silently inert (round 4). Names fold
        with SQLite's ASCII case rule and are stored folded, matching what
        the authorizer reports.

        ROWID note: an INTEGER PRIMARY KEY alias is a declared column, and
        SQLite reports reads via rowid/_rowid_/oid under the ALIAS name — so
        denying the alias covers them (verified). The implicit ROWID of an
        alias-less table is not a declared column and cannot be named here.
        """
        acl: dict[str, frozenset | None] = {}
        for t, denied in self._acl_spec:
            lt = _ident_lower(t)
            if lt not in columns:
                raise ValueError(
                    f"table_acl names a table that does not exist: {t!r} "
                    "(an ACL that silently protects nothing is worse than "
                    "an error)")
            if denied is None:
                acl[lt] = None
                continue
            wanted = {_ident_lower(c) for c in denied}
            declared = columns[lt]
            if declared is None:
                if wanted:
                    raise ValueError(
                        f"table_acl: cannot resolve the columns of {t!r} "
                        "to validate deny_columns; hide the whole table "
                        f"instead ({{{t!r}: None}})")
                acl[lt] = frozenset()
                continue
            unknown = wanted - {_ident_lower(c) for c in declared}
            if unknown:
                raise ValueError(
                    f"table_acl: {t!r} has no column(s) {sorted(unknown)}")
            acl[lt] = frozenset(wanted)
        return acl

    def _acl_shadow_denied(self, table: str) -> bool:
        """True if folded `table` is an FTS index/shadow of a protected base.

        The relationship base→index is not a naming rule (SQLite lets an FTS5
        table be named anything and point at any content table via
        `content='…'`), so it is discovered from the schema at construction,
        not guessed from prefixes.
        """
        return table in self._acl_denied_tables

    def _discover_fts_shadows(self, schema: list[tuple], acl: dict,
                              kinds: dict) -> frozenset[str]:
        """Names to deny outright because they expose an ACL-protected table.

        For every FTS vtable whose `content=` names a protected table (or
        which is protected itself), deny the vtable and its shadow tables —
        otherwise `hex(block) FROM x_fts_data` (FTS5), `x_segdir` (FTS3/4),
        and `MATCH` recover the hidden text. Fail closed: a declaration that
        cannot be conclusively parsed, or a `content=` target that cannot be
        resolved, is treated as protected. An FTS table with no `content=`
        (or `content=''`) stores its own data and is ACL'd directly like any
        table; a base table synced into it by application triggers cannot be
        inferred from schema and is the operator's call to protect.

        Which relations are virtual and which are shadows comes from
        `kinds` — the engine's own typing via PRAGMA table_list — not from
        parsing or name patterns (round 4.5; the declaration parser is
        still needed for module and `content=`, which table_list does not
        report). Two extra fail-closed rules that typing enables: an
        engine-typed VIRTUAL table whose declaration does not parse as one
        is denied, and an engine-typed SHADOW that prefix-matches no
        virtual table (impossible in a healthy schema) is denied.
        """
        if not acl:
            return frozenset()
        protected = set(acl)
        virtuals = {n for n, k in kinds.items() if k == "virtual"}
        shadows = {n for n, k in kinds.items() if k == "shadow"}
        decls = {_ident_lower(name): sql for name, typ, sql in schema
                 if typ == "table"}
        denied: set[str] = set()
        for lname in virtuals:
            deny = False
            try:
                parsed = _parse_vtable_decl(decls.get(lname) or "")
                if parsed is None:
                    deny = True     # engine says virtual, decl disagrees
                else:
                    module, content = parsed
                    if lname in protected:
                        # A protected vtable of ANY module keeps its data in
                        # its shadows (FTS, rtree, ...): hide those too.
                        deny = True
                    elif _ident_lower(module) in _FTS_MODULES:
                        if content:            # external-content index
                            target = _ident_lower(content)
                            deny = (target in protected
                                    or target not in kinds)
            except ValueError:
                deny = True                    # unreadable decl: closed
            if deny:
                denied.add(lname)
                denied.update(s for s in shadows
                              if s.startswith(lname + "_"))
                # Belts: the known FTS layouts even if absent, and ordinary
                # tables squatting on the shadow namespace of a denied
                # vtable.
                denied.update(f"{lname}_{suffix}"
                              for suffix in _FTS_SHADOW_SUFFIXES)
                denied.update(n for n in kinds
                              if n.startswith(lname + "_"))
        denied.update(s for s in shadows
                      if not any(s.startswith(v + "_") for v in virtuals))
        return frozenset(denied)

    def _flush_pool(self) -> None:
        """Discard every idle connection; the next checkouts open fresh."""
        with self._pool_lock:
            stale, self._pool[:] = self._pool[:], []
        for c in stale:
            c.conn.close()

    def _rebuild_snapshots(self, *, unless_version: int | None = None) -> None:
        """Re-read the schema and swap in fresh enforcement snapshots.

        With `unless_version` set, skip the reload when the stored snapshot
        already carries that version (another execution refreshed first) —
        unless the cage is tainted, which only a SUCCESSFUL rebuild clears.
        Bumps the connection generation and flushes the idle pool, so every
        connection built before this refresh is retired at its next touch —
        SQLite would silently re-parse a stale cache under our LOWERED column
        limit, which on a schema with wide tables fails, and an immutable
        connection's open fd could pin an entire replaced file.

        May raise ValueError (ACL no longer resolves) or sqlite3.Error — and
        then the cage is TAINTED: generation bumped, pool flushed, every
        query refused until a rebuild succeeds. Failing open here served a
        replaced immutable file's old data after its revocation failed
        (round 4.3); failing closed costs re-raising until the operator
        restores a schema the ACL resolves against.
        """
        try:
            with self._schema_lock:
                if unless_version is not None \
                        and self._schema_version == unless_version \
                        and self._schema_tainted is None:
                    return
                schema, columns, kinds, version = self._load_schema()
                acl = self._resolve_acl(columns)
                self._acl_denied_tables = self._discover_fts_shadows(
                    schema, acl, kinds)
                self._acl = acl
                self._schema_version = version
                self._schema_tainted = None
                self._generation += 1
        except (ValueError, sqlite3.Error) as exc:
            with self._schema_lock:
                self._schema_tainted = str(exc)
                self._generation += 1
            self._flush_pool()
            raise
        self._flush_pool()

    def _verify_schema_epoch(self, caged: _CagedConn, sql: str) -> _CagedConn:
        """Keep the enforcement snapshots honest under a live writer.

        The default open supports concurrent writers, but the ACL/FTS-shadow
        snapshots are built at construction — a writer creating a NEW FTS
        index over a protected table afterwards would hand callers a
        MATCH oracle the snapshot never heard of (round 4.1, reproduced).
        So every execution reads schema_version (one header field, no schema
        parse) and on change rebuilds the snapshots and swaps in a fresh
        connection (whose schema cache re-warms under the default column
        limit). Scope, per the operator: this handles a REASONABLE writer —
        schema evolution between queries. An adversarial writer racing the
        window between this check and the statement's prepare is explicitly
        out of scope (see THREAT_MODEL); protecting against it would take a
        pinned read transaction per execution.
        """
        if self._schema_tainted is not None:
            # A previous rebuild failed; the cage is failing closed. Attempt
            # to heal — the operator may have restored a schema the ACL
            # resolves against (or swapped a good file back in) — and refuse
            # the query if the schema is still incompatible.
            caged.conn.close()
            try:
                self._rebuild_snapshots()
            except ValueError as exc:
                raise QueryDenied(
                    "the cage is failing closed: the schema no longer "
                    f"matches table_acl ({exc}); restore a compatible "
                    "schema (a refresh then heals) or rebuild the Cage",
                    sql) from exc
            except sqlite3.Error as exc:
                raise self._classify(exc, sql) from exc
        elif caged.gen == self._generation:
            try:
                ver = caged.conn.execute(
                    "PRAGMA schema_version").fetchone()[0]
            except sqlite3.Error:
                return caged  # header unreadable: the query itself classifies
            if ver == self._schema_version:
                return caged
            caged.conn.close()   # stale parse cache
            try:
                self._rebuild_snapshots(unless_version=ver)
            except ValueError as exc:
                # The deployment's promise broke, not the query; fail
                # closed and say what to do.
                raise QueryDenied(
                    "the database schema changed under the cage and no "
                    f"longer matches table_acl: {exc}; rebuild the Cage "
                    "against the new schema", sql) from exc
            except sqlite3.Error as exc:
                raise self._classify(exc, sql) from exc
        else:
            # Built before the last refresh() — retire it unconditionally.
            caged.conn.close()
        try:
            return self._new_conn()
        except sqlite3.Error as exc:
            raise self._classify(exc, sql) from exc

    def _authorize(self, caged: _CagedConn, op, a1, a2) -> int:
        if op == sqlite3.SQLITE_PRAGMA:
            # FTS5 reads `PRAGMA data_version` internally to detect database
            # changes, and the cage itself reads `PRAGMA schema_version` per
            # execution to detect schema changes; the READ forms (no value
            # argument) are harmless counters. Every other pragma stays
            # denied — including these two's WRITE forms.
            if a1 in ("data_version", "schema_version") and a2 is None:
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
            if isinstance(name, str) \
                    and _ident_lower(name) in self._deny_functions:
                caged.denied = (op, name)
                return sqlite3.SQLITE_DENY
        if op == sqlite3.SQLITE_READ and self._acl:
            # Fold with SQLite's ASCII case rule: the authorizer reports
            # schema-stored spellings, the snapshots store folded ones.
            table = _ident_lower(a1) if isinstance(a1, str) else a1
            column = _ident_lower(a2) if isinstance(a2, str) else a2
            # A hidden column is worthless if its FTS shadow tables remain
            # readable: `hex(block) FROM pages_fts_data` recovers the tokenised
            # text, and `MATCH` on the vtable is a per-term presence oracle
            # (red-team BREAK 1). Deny every FTS shadow/vtable belonging to a
            # protected base table (discovered from the schema), and hide
            # sqlite_master DDL for fully-hidden tables (schema leak, BREAK 2).
            if table in ("sqlite_master", "sqlite_schema") \
                    and column in ("sql", "rootpage"):
                # We cannot see which row is being read, so when any table is
                # fully hidden, blank DDL/rootpage wholesale. Names stay
                # visible (harmless, and the query planner needs them).
                if any(v is None for v in self._acl.values()):
                    return sqlite3.SQLITE_IGNORE
            if self._acl_shadow_denied(table):
                caged.denied = (op, a1)
                return sqlite3.SQLITE_DENY
            acl = self._acl.get(table)
            if acl is None and table in self._acl:
                caged.denied = (op, a1)
                return sqlite3.SQLITE_DENY          # whole table hidden
            if acl and column in acl:           # acl is a frozenset of columns
                # SQLITE_IGNORE reads the column as NULL: the row shape
                # survives, the value does not. Reads of an INTEGER PRIMARY
                # KEY alias via rowid/_rowid_/oid arrive under the alias
                # name, so a denied alias is nulled on that path too.
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

    def refresh(self) -> None:
        """Re-read the schema NOW and rebuild the enforcement snapshots.

        Unconditional: after this returns, the ACL/FTS-shadow snapshots
        match the file's current schema, idle pooled connections are
        discarded, and connections still out on in-flight executions are
        retired at their next touch instead of being reused.

        Queries already do this automatically when a live writer bumps
        `schema_version`, so most deployments never need to call it. It
        exists for what the automatic check cannot see or should not wait
        for: an `immutable=True` cage whose file was atomically REPLACED
        (an immutable connection never re-reads the header, so the swap is
        invisible until the pool is rebuilt — the republish-a-corpus
        pattern; queries in flight during the swap are the operator's
        timing to manage), and surfacing an ACL that no longer resolves as
        an eager ValueError here rather than as QueryDenied at the next
        query. On failure (ValueError, or the schema being unreadable) the
        cage is left TAINTED and fails closed: existing connections are
        retired and every query raises until a rebuild succeeds — either an
        explicit refresh() after restoring a compatible schema/file, or the
        automatic heal a query attempts when it finds the cage tainted.
        Failing open here would keep serving a replaced immutable file's
        old data after its revocation failed. Raises CageError on a closed
        cage.

        refresh() re-reads the SCHEMA, never the policy: the ACL
        specification was captured immutably at construction, so mutating
        policy.table_acl and refreshing cannot loosen enforcement (the
        round-3 contract holds across rebuilds).
        """
        if self._closed:
            raise CageError("cage is closed")
        self._rebuild_snapshots()

    # -- optional async facade ---------------------------------------------
    #
    # SQLite is a blocking library — there is no native async. These wrap the
    # SYNC methods (the tested core) in a bounded thread pool; they add a
    # thread hop and queue-based backpressure, nothing else. The sync methods
    # remain the default and the reference implementation.

    def _get_executor(self):
        if self._executor is None:
            with self._executor_lock:
                if self._closed:
                    raise CageError("cage is closed")
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
        """Close the cage: idle connections now, in-flight ones at check-in.

        Idempotent, and usable as `with Cage(path) as cage:`. After close()
        every query/fetch/stream/explain raises CageError — a closed cage
        never silently reopens connections (its callbacks and pool die with
        it), which is what lets a caller hold many cages over their lifetime
        without leaking file descriptors (round 4, fuzz-harness finding).
        """
        with self._pool_lock:
            self._closed = True
            for c in self._pool:
                c.conn.close()
            self._pool.clear()
        with self._executor_lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False)

    # -- internals ----------------------------------------------------------

    @contextmanager
    def _slot(self, sql: str):
        """Hold one concurrency slot for the whole body, always released."""
        if self._closed:
            raise CageError("cage is closed", sql)
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
        # The clock starts BEFORE checkout and the schema-epoch check, so
        # their cost (a pragma, rarely a rebuild, a busy wait on a locked
        # database) counts against the deadline instead of silently
        # extending it (round 4.3).
        t0 = time.monotonic()
        caged = None
        try:
            caged = self._checkout()
            caged = self._verify_schema_epoch(caged, sql)
            p = self.policy
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
                # Enforce the POLICY's width exactly. The engine-level
                # SQLITE_LIMIT_COLUMN (set per connection) already rejected
                # anything wider than the limit at prepare time — before the
                # first row could materialise (red-team BREAK 1, tightened in
                # round 4) — but that limit may sit above max_columns when the
                # schema itself contains wider objects, so this check keeps
                # the policy precise. Together with per-value max_length the
                # worst first row is bounded at max_columns × max_length.
                if len(cols) > p.max_columns:
                    cur.close()
                    raise ResultBudgetExceeded(
                        f"result has {len(cols)} columns (max "
                        f"{p.max_columns}); a wide row can exhaust memory "
                        "before the byte budget is checked — select fewer "
                        "columns", sql)
                # Rows are dicts, so two result columns sharing a name would
                # keep ONE value and silently drop the rest — exactly the
                # silent data loss the honesty contract forbids, and easy to
                # hit with joins (a.id, b.id) or a JOIN's SELECT *
                # (round 4.6, external review). Refuse loudly instead.
                if len(set(cols)) != len(cols):
                    dupes = sorted({c for c in cols if cols.count(c) > 1})
                    cur.close()
                    raise QueryError(
                        f"result has duplicate column name(s) {dupes}; "
                        "dict rows would silently drop all but one value "
                        "per name — give each column a unique alias "
                        "(SELECT a.id AS a_id, b.id AS b_id, ...)", sql)
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
        if "too many columns" in msg:
            # The engine width limit fired at prepare time — same guard as
            # the Python-side max_columns check, caught one layer earlier
            # (before the first row can materialise).
            return ResultBudgetExceeded(
                f"result is wider than max_columns="
                f"{self.policy.max_columns}; a wide row can exhaust memory "
                "before the byte budget is checked — select fewer columns",
                sql)
        if "too many terms in compound SELECT" in msg or \
           "Expression tree is too large" in msg or \
           "statement too long" in msg or "string or blob too big" in msg or \
           "pattern too complex" in msg or \
           "too many arguments on function" in msg or \
           "variable number must be between" in msg:
            return QueryDenied(f"limit exceeded: {msg}", sql)
        return QueryError(msg, sql)
