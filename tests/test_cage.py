"""Adversarial test suite — every red-team break across three rounds plus the
honesty and async contracts, against a self-contained fixture. Round 4 is the
external review: prepare-time width enforcement, fail-closed FTS discovery,
URI/path safety, type-strict policy, schema-validated ACLs, and lifecycle."""
import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from sqlite_cage import (
    Cage,
    CageError,
    CagePolicy,
    QueryDenied,
    QueryError,
    QueryTimeout,
    Result,
    ResultBudgetExceeded,
    TruncatedResult,
)

# --- authorizer / read-only wall (round 1) --------------------------------

@pytest.mark.parametrize("sql", [
    "PRAGMA journal_mode",
    "PRAGMA data_version = 5",
    "ATTACH ':memory:' AS x",
    "SELECT * FROM pragma_table_info('docs')",
    "INSERT INTO docs_fts(docs_fts) VALUES('rebuild')",
    "INSERT INTO docs(id) VALUES(1)",
    "UPDATE docs SET title='x'",
    "DELETE FROM docs",
    "CREATE TABLE evil(x)",
    "SELECT load_extension('x')",
    "SELECT randomblob(1000000000)",
])
def test_denied(db, sql):
    with pytest.raises(QueryDenied):
        Cage(db).query(sql)


def test_multi_statement_refused(db):
    with pytest.raises(QueryError):
        Cage(db).query("SELECT 1; DROP TABLE docs")


@pytest.mark.parametrize("sql,params", [
    ("SELECT count(*) FROM docs", ()),
    ("SELECT d.id FROM docs_fts f JOIN docs d ON d.id=f.rowid "
     "WHERE f.body MATCH ? LIMIT 5", ('"cherry place"',)),
    ("SELECT snippet(docs_fts,0,'>','<','…',6) FROM docs_fts "
     "WHERE docs_fts MATCH 'NEAR(mill river, 10)' ORDER BY bm25(docs_fts) "
     "LIMIT 3", ()),
    ("WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<10)"
     " SELECT max(n) FROM c", ()),
])
def test_legitimate_queries(db, sql, params):
    Cage(db).query(sql, params)                # must not raise


# --- resources (rounds 1 & 2) ---------------------------------------------

def test_wide_row_refused_prefetch(db):
    cols = ",".join(f"s AS c{i}" for i in range(1990))
    with pytest.raises(ResultBudgetExceeded):
        Cage(db).query(
            f"WITH b(s) AS (SELECT printf('%999999d',1)) SELECT {cols} FROM b")


def test_deadline_holds_on_op_heavy_query(db):
    counter = ("WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c "
               "WHERE n < 50000000) SELECT count(*) FROM c")
    with pytest.raises(QueryTimeout):
        Cage(db, CagePolicy(deadline_s=0.5)).query(counter)


def test_byte_budget(db):
    with pytest.raises(ResultBudgetExceeded):
        Cage(db, CagePolicy(max_result_bytes=50_000)).query(
            "SELECT body FROM docs WHERE length(body) > 10000 LIMIT 20")


# --- honesty contract (rounds 1 & 2) --------------------------------------

def test_exactly_max_rows_ok(db):
    assert len(Cage(db, CagePolicy(max_rows=1000)).query(
        "SELECT id FROM docs LIMIT 1000")) == 1000


def test_over_cap_raises(db):
    with pytest.raises(TruncatedResult):
        Cage(db, CagePolicy(max_rows=1000)).query("SELECT id FROM docs LIMIT 1001")


def test_syntax_error_raises_not_empty(db):
    with pytest.raises(QueryError):
        Cage(db).query("SELEC nonsense")


def test_missing_param_is_cage_error(db):
    with pytest.raises(CageError):
        Cage(db).query("SELECT :missing")


def test_fetch_complete(db):
    r = Cage(db).fetch("SELECT id FROM docs LIMIT 5")
    assert r.complete and not r.truncated and r.returned == 5
    assert r.note is None and "note" not in r.envelope()


def test_fetch_truncated_signal(db):
    r = Cage(db, CagePolicy(max_rows=1000)).fetch("SELECT id FROM docs")
    assert r.truncated and r.returned == 1000
    env = r.envelope()
    assert env["truncated"] and env["limit"] == 1000 and "TRUNCATED" in env["note"]


def test_result_iterates_rows_not_flag(db):
    r = Cage(db).fetch("SELECT id FROM docs LIMIT 3")
    assert list(r)[:1] == list(r.rows[:1])


def test_envelope_serialises_blobs(db):
    r = Cage(db).fetch("SELECT id, tag FROM docs LIMIT 2")
    s = json.dumps(r.envelope())                      # must not raise
    tag = r.envelope()["rows"][0]["tag"]
    assert "$blob" in s and tag["$blob"]["bytes"] == 2


def test_rows_immutable(db):
    r = Cage(db).fetch("SELECT id FROM docs LIMIT 2")
    assert isinstance(r.rows, tuple) and not hasattr(r.rows, "append")


# --- ACL confidentiality (round 2) ----------------------------------------

def test_acl_nulls_column(db):
    r = Cage(db, CagePolicy(table_acl={"docs": {"deny_columns": {"body"}}})
             ).query("SELECT id, body FROM docs WHERE id=5")
    assert r[0]["body"] is None and r[0]["id"] == 5


def test_acl_denies_fts_shadow(db):
    acl = Cage(db, CagePolicy(table_acl={"docs": {"deny_columns": {"body"}}}))
    with pytest.raises(QueryDenied):
        acl.query("SELECT hex(block) FROM docs_fts_data")
    with pytest.raises(QueryDenied):
        acl.query("SELECT count(*) FROM docs_fts WHERE docs_fts MATCH 'newton'")


def test_acl_hides_ddl(db):
    r = Cage(db, CagePolicy(table_acl={"secrets": None})).query(
        "SELECT sql FROM sqlite_master WHERE name='secrets'")
    assert not r or r[0]["sql"] is None


def test_acl_immutable_after_construction(db):
    """Round-3 BREAK 2: mutating policy.table_acl must not loosen enforcement."""
    c = Cage(db, CagePolicy(table_acl={"docs": {"deny_columns": {"body"}}}))
    c.policy.table_acl.clear()
    r = c.query("SELECT body FROM docs WHERE id=5")
    assert r[0]["body"] is None
    with pytest.raises(QueryDenied):
        c.query("SELECT hex(block) FROM docs_fts_data")


# --- policy validation (round 3) ------------------------------------------

@pytest.mark.parametrize("kw", [
    {"progress_every_ops": 0}, {"max_length": 0}, {"max_concurrency": 0},
    {"deadline_s": 0}, {"max_result_bytes": 0}, {"max_columns": 0},
])
def test_invalid_policy_rejected(kw):
    with pytest.raises(ValueError):
        CagePolicy(**kw)


def test_raising_slow_log_does_not_mask(db):
    def boom(elapsed, sql):
        raise RuntimeError("slow_log blew up")
    c = Cage(db, CagePolicy(deadline_s=0.5, slow_log_s=0.0, slow_log=boom))
    with pytest.raises(QueryTimeout):
        c.query("WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c "
                "WHERE n<50000000) SELECT count(*) FROM c")
    assert c.query("SELECT 1 AS x")            # cage still usable


# --- pool discipline (round 2) --------------------------------------------

def test_explain_flood_bounded(db):
    c = Cage(db, CagePolicy(max_concurrency=3))

    def explainer():
        try:
            c.explain("SELECT count(*) FROM docs a, docs b")
        except CageError:
            pass
    ts = [threading.Thread(target=explainer) for _ in range(20)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(c._pool) <= 3
    assert c.query("SELECT 1 AS x")


def test_connect_failure_classified_no_slot_leak(db):
    c = Cage(db, CagePolicy(max_concurrency=2))
    orig = c._new_conn
    c._pool.clear()
    c._new_conn = lambda: (_ for _ in ()).throw(
        sqlite3.OperationalError("unable to open database file"))
    with pytest.raises(CageError):
        c.query("SELECT 1")
    c._new_conn = orig
    assert c.query("SELECT 1 AS x")            # not starved


def test_concurrency_storm(db):
    c = Cage(db, CagePolicy(deadline_s=0.5, max_concurrency=3))
    errs = []

    def worker():
        try:
            c.query("SELECT count(*) FROM docs a, docs b, docs c")
        except QueryTimeout:
            pass
        except Exception as e:
            errs.append(e)
    ts = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs
    assert c.query("SELECT 1 AS x")


# --- async facade ---------------------------------------------------------

def test_aquery_agrees_with_query(db):
    async def go():
        c = Cage(db)
        r = await c.aquery("SELECT count(*) AS n FROM docs")
        assert r[0]["n"] == c.query("SELECT count(*) AS n FROM docs")[0]["n"]
        c.close()
    asyncio.run(go())


def test_async_burst_no_spurious_slot_timeout(db):
    async def go():
        c = Cage(db, CagePolicy(deadline_s=0.5, max_concurrency=3))
        slow = "SELECT count(*) FROM docs a, docs b WHERE b.body LIKE '%zqxj%'"

        async def one():
            try:
                await c.aquery(slow)
                return "ok"
            except QueryTimeout as e:
                return "slot" if "no execution slot" in str(e) else "deadline"
            except CageError:
                return "err"
        kinds = await asyncio.gather(*[one() for _ in range(20)])
        assert kinds.count("slot") == 0
        c.close()
    asyncio.run(go())


def test_afetch_returns_result(db):
    async def go():
        c = Cage(db, CagePolicy(max_rows=1000))
        r = await c.afetch("SELECT id FROM docs")
        assert isinstance(r, Result) and r.truncated and r.returned == 1000
        c.close()
    asyncio.run(go())


# --- round 4: external review — width before execution ---------------------

def test_expression_width_rejected_at_prepare(db):
    """More columns than max_columns must fail at PREPARE, not after the
    first row has been materialised by execute()'s implicit step."""
    sql = "SELECT " + ", ".join(str(i) for i in range(400))
    with pytest.raises(ResultBudgetExceeded):
        Cage(db).query(sql)


def test_wide_schema_database_still_opens(tmp_path):
    """A database whose own tables are wider than max_columns must still
    open (the engine limit sizes up to the schema); the POLICY width is then
    enforced by the post-prepare check."""
    path = tmp_path / "wide.sqlite"
    conn = sqlite3.connect(path)
    wide_cols = ", ".join(f"c{i}" for i in range(300))
    conn.execute(f"CREATE TABLE wide({wide_cols})")
    conn.execute("INSERT INTO wide DEFAULT VALUES")
    conn.commit()
    conn.close()
    cage = Cage(path)                          # default max_columns=256 < 300
    assert cage.query("SELECT c0, c299 FROM wide") == [{"c0": None,
                                                        "c299": None}]
    with pytest.raises(ResultBudgetExceeded):
        cage.query("SELECT * FROM wide")
    cage.close()


_WIDTH_PROBE = """
import resource, sys
sys.path.insert(0, sys.argv[1])
from sqlite_cage import Cage, CagePolicy, ResultBudgetExceeded
cage = Cage(sys.argv[2])
cage.query("SELECT id FROM docs LIMIT 1")            # warm up
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
big = "(" + "||".join(["body"] * 20) + ")"           # ~480 KB per value
wide = ", ".join("%s AS c%d" % (big, i) for i in range(400))
try:
    cage.query("SELECT " + wide + " FROM docs WHERE length(body) > 20000")
    print("NOT-REJECTED")
except ResultBudgetExceeded:
    grew = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - base
    if sys.platform != "darwin":
        grew *= 1024                                 # ru_maxrss is KB there
    print("REJECTED", grew)
"""


def test_wide_row_rejected_before_materialisation(db):
    """The round-4 exploit, re-run: a 400-column × ~480 KB-expression SELECT
    (~190 MB if the first row materialises) must be rejected with FLAT
    memory — proving the width check now acts before execution."""
    src = str(Path(__file__).resolve().parents[1] / "src")
    out = subprocess.run(
        [sys.executable, "-c", _WIDTH_PROBE, src, str(db)],
        capture_output=True, text=True, check=True, timeout=60,
    ).stdout.split()
    assert out[0] == "REJECTED", "wide row was not rejected at prepare"
    assert int(out[1]) < 64 << 20, f"RSS grew {out[1]} bytes: row materialised"


# --- round 4: FTS discovery is parsed, case-folded, fail-closed ------------

def test_vtable_decl_parser_variants():
    from sqlite_cage import _parse_vtable_decl as parse
    assert parse("CREATE TABLE t(x)") is None
    same = ("fts5", "docs")
    assert parse("CREATE VIRTUAL TABLE f USING fts5(b, content='docs')") == same
    assert parse('CREATE VIRTUAL TABLE f USING fts5(b, content="docs")') == same
    assert parse("CREATE VIRTUAL TABLE f USING fts5(b, content=[docs])") == same
    assert parse("CREATE VIRTUAL TABLE f USING fts5(b, content=`docs`)") == same
    assert parse("CREATE VIRTUAL TABLE f USING fts5(b, content = /*c*/ 'docs')") == same
    assert parse("CREATE VIRTUAL TABLE F USING FTS4(CONTENT='Docs', b)") == ("FTS4", "Docs")
    assert parse("CREATE VIRTUAL TABLE f USING fts3") == ("fts3", None)
    assert parse("CREATE VIRTUAL TABLE f USING fts5(b, content='do''cs')") == ("fts5", "do'cs")
    for unreadable in [
        "CREATE VIRTUAL TABLE f USING fts5(b, content=)",
        "CREATE VIRTUAL TABLE f USING fts5(content='a', content='b')",
        "CREATE VIRTUAL TABLE f USING fts5(b /* unterminated",
        "CREATE VIRTUAL TABLE f USING fts5(b, 'unterminated",
    ]:
        with pytest.raises(ValueError):
            parse(unreadable)


def _build_db(tmp_path, script):
    path = tmp_path / "case.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(script)
    conn.commit()
    conn.close()
    return str(path)


@pytest.mark.parametrize("decl", [
    'CREATE VIRTUAL TABLE fx USING fts5(body, content="docs", content_rowid=\'id\')',
    "CREATE VIRTUAL TABLE fx USING fts5(body, content=[docs], content_rowid='id')",
    "CREATE VIRTUAL TABLE FX USING FTS5(body, CONTENT='DOCS', content_rowid='id')",
])
def test_fts5_quote_and_case_variants_denied(tmp_path, decl):
    """content="docs", content=[docs], and case-folded spellings all slipped
    the old single-quote regex; every one must now deny the index+shadows."""
    path = _build_db(tmp_path, f"""
        CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT);
        INSERT INTO docs VALUES (1, 'squeamish ossifrage');
        {decl};
        INSERT INTO fx(fx) VALUES('rebuild');
    """)
    cage = Cage(path, CagePolicy(table_acl={"docs": {"deny_columns": {"body"}}}))
    with pytest.raises(QueryDenied):
        cage.query("SELECT hex(block) FROM fx_data")
    with pytest.raises(QueryDenied):
        cage.query("SELECT count(*) FROM fx WHERE fx MATCH 'squeamish'")
    cage.close()


def test_fts4_external_content_shadows_denied(tmp_path):
    """FTS3/4 keep their text in _segdir/_segments, which the FTS5-only
    suffix list left readable."""
    path = _build_db(tmp_path, """
        CREATE TABLE src(a, b);
        INSERT INTO src(rowid, a, b) VALUES (1, 'hidden alpha', 'hidden beta');
        CREATE VIRTUAL TABLE f4 USING fts4(content="src", a, b);
        INSERT INTO f4(f4) VALUES('rebuild');
    """)
    cage = Cage(path, CagePolicy(table_acl={"src": None}))
    for sql in ["SELECT * FROM f4_segdir", "SELECT * FROM f4_segments",
                "SELECT * FROM f4_docsize", "SELECT * FROM f4",
                "SELECT count(*) FROM f4 WHERE f4 MATCH 'hidden'"]:
        with pytest.raises(QueryDenied):
            cage.query(sql)
    cage.close()


def test_self_stored_fts_unaffected_by_unrelated_acl(tmp_path):
    """An FTS index with no content= stores its own data; an ACL on an
    unrelated table must not collateral-deny it."""
    path = _build_db(tmp_path, """
        CREATE TABLE private(x);
        CREATE VIRTUAL TABLE notes USING fts5(body);
        INSERT INTO notes VALUES ('public words');
    """)
    cage = Cage(path, CagePolicy(table_acl={"private": None}))
    got = cage.query("SELECT count(*) AS n FROM notes WHERE notes MATCH 'public'")
    assert got == [{"n": 1}]
    cage.close()


def test_fts_content_target_unresolvable_fails_closed(tmp_path):
    """content= naming a table we cannot resolve is treated as protected."""
    path = _build_db(tmp_path, """
        CREATE TABLE private(x);
        CREATE VIRTUAL TABLE ghost USING fts5(body, content='vanished');
    """)
    cage = Cage(path, CagePolicy(table_acl={"private": None}))
    with pytest.raises(QueryDenied):
        cage.query("SELECT * FROM ghost_data")
    cage.close()


# --- round 4: ACL validated against the schema -----------------------------

def test_acl_unknown_table_rejected_at_construction(db):
    with pytest.raises(ValueError):
        Cage(db, CagePolicy(table_acl={"docz": None}))


def test_acl_unknown_column_rejected_at_construction(db):
    with pytest.raises(ValueError):
        Cage(db, CagePolicy(table_acl={"docs": {"deny_columns": {"bod"}}}))


def test_acl_names_fold_ascii_case(db):
    c = Cage(db, CagePolicy(table_acl={"DOCS": {"deny_columns": {"BODY"}}}))
    r = c.query("SELECT id, body FROM docs WHERE id=5")
    assert r[0]["body"] is None and r[0]["id"] == 5
    with pytest.raises(QueryDenied):
        c.query("SELECT hex(block) FROM docs_fts_data")
    c.close()


def test_denied_ipk_alias_not_recoverable_via_rowid(db):
    """SQLite reports rowid/_rowid_/oid reads of an INTEGER PRIMARY KEY
    alias under the alias name, so denying the alias must null them all."""
    c = Cage(db, CagePolicy(table_acl={"docs": {"deny_columns": {"id"}}}))
    for sql in ["SELECT id FROM docs LIMIT 3", "SELECT rowid FROM docs LIMIT 3",
                "SELECT _rowid_ FROM docs LIMIT 3", "SELECT oid FROM docs LIMIT 3"]:
        rows = c.query(sql)
        assert rows and all(v is None for row in rows for v in row.values()), sql
    c.close()


# --- round 4: type-strict policy -------------------------------------------

@pytest.mark.parametrize("kw", [
    {"deadline_s": float("inf")}, {"deadline_s": float("nan")},
    {"deadline_s": True}, {"max_rows": 10.5}, {"max_rows": True},
    {"max_result_bytes": "8388608"}, {"slow_log": "not-callable"},
    {"deny_functions": "hex"}, {"deny_functions": frozenset({""})},
    {"table_acl": {"docs": {"deny_columns": "body"}}},
    {"table_acl": {"docs": {"deny_cols": {"body"}}}},
    {"table_acl": [("docs", None)]},
])
def test_degenerate_policy_types_rejected(kw):
    """inf disables the deadline, bool/float pass int range checks, and a
    bare string ACL denies per CHARACTER — all must fail loudly instead."""
    with pytest.raises(ValueError):
        CagePolicy(**kw)


# --- round 4: path/URI safety and open mode --------------------------------

def test_awkward_filename_opens(tmp_path):
    from fixture import build
    path = tmp_path / "we?ird #1%.sqlite"
    build(path)
    cage = Cage(path)
    assert cage.query("SELECT count(*) AS n FROM docs")[0]["n"] == 3000
    cage.close()


def test_directory_path_rejected(tmp_path):
    with pytest.raises(ValueError):
        Cage(tmp_path)


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        Cage(tmp_path / "absent.sqlite")


def test_relative_path_survives_chdir(db, tmp_path, monkeypatch):
    try:
        rel = os.path.relpath(db)
    except ValueError:                    # not relativizable (other drive)
        pytest.skip("path not relativizable on this platform")
    cage = Cage(rel)
    monkeypatch.chdir(tmp_path)
    with cage._pool_lock:                 # force a FRESH connection post-chdir
        for c in cage._pool:
            c.conn.close()
        cage._pool.clear()
    assert cage.query("SELECT count(*) AS n FROM docs")[0]["n"] == 3000
    cage.close()


def test_wal_database_default_mode_sees_committed_rows(tmp_path):
    """mode=ro honors a live -wal; the old always-immutable open ignored it
    (committed-but-uncheckpointed tables were simply invisible)."""
    path = tmp_path / "wal.sqlite"
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE t(x)")
    writer.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(5)])
    writer.commit()                       # stays in -wal while writer is open
    try:
        assert (tmp_path / "wal.sqlite-wal").exists()
        with Cage(path) as cage:
            assert cage.query("SELECT count(*) AS n FROM t")[0]["n"] == 5
    finally:
        writer.close()


def test_immutable_optin_on_frozen_file(db):
    with Cage(db, immutable=True) as cage:
        assert cage.query("SELECT count(*) AS n FROM docs")[0]["n"] == 3000


# --- round 4: lifecycle ----------------------------------------------------

def test_context_manager_close_semantics(db):
    with Cage(db) as c:
        assert c.query("SELECT 1 AS x") == [{"x": 1}]
    with pytest.raises(CageError):
        c.query("SELECT 1")
    with pytest.raises(CageError):
        c.explain("SELECT 1")
    c.close()                             # idempotent
    with pytest.raises(CageError):
        asyncio.run(c.aquery("SELECT 1"))


def test_fd_ceiling_many_cages(db):
    """Constructing and closing many cages under a low file-descriptor
    ceiling must not leak (round-4 fuzz-harness finding)."""
    resource = pytest.importorskip("resource")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    cap = 128 if hard == resource.RLIM_INFINITY else min(hard, 128)
    cap = min(cap, soft)
    resource.setrlimit(resource.RLIMIT_NOFILE, (cap, hard))
    try:
        for _ in range(80):
            with Cage(db) as cage:
                cage.query("SELECT 1 AS x")
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


# --- round 4.1: second review pass -----------------------------------------

def _live_db(tmp_path):
    """A db with a writer connection kept open, for live-schema tests."""
    path = tmp_path / "live.sqlite"
    writer = sqlite3.connect(path)
    writer.execute("CREATE TABLE docs(id INTEGER PRIMARY KEY, body TEXT)")
    writer.execute("INSERT INTO docs VALUES (1, 'squeamish ossifrage')")
    writer.commit()
    return str(path), writer


def test_fts_index_created_after_construction_denied(tmp_path):
    """Round-4.1 exploit: a writer creating an external-content FTS index
    AFTER the cage exists must not hand callers a MATCH oracle over a
    protected column — the per-execution epoch check rebuilds the denial
    set."""
    path, writer = _live_db(tmp_path)
    try:
        cage = Cage(path, CagePolicy(
            table_acl={"docs": {"deny_columns": {"body"}}}))
        writer.execute("CREATE VIRTUAL TABLE spy USING fts5("
                       "body, content='docs', content_rowid='id')")
        writer.execute("INSERT INTO spy(spy) VALUES('rebuild')")
        writer.commit()
        with pytest.raises(QueryDenied):
            cage.query("SELECT count(*) FROM spy WHERE spy MATCH 'squeamish'")
        with pytest.raises(QueryDenied):
            cage.query("SELECT hex(block) FROM spy_data")
        assert cage.query("SELECT body FROM docs")[0]["body"] is None
        cage.close()
    finally:
        writer.close()


def test_schema_evolution_tolerated(tmp_path):
    """A reasonable writer adding unrelated objects must not break an open
    cage; the ACL keeps holding across the refresh."""
    path, writer = _live_db(tmp_path)
    try:
        cage = Cage(path, CagePolicy(
            table_acl={"docs": {"deny_columns": {"body"}}}))
        assert cage.query("SELECT body FROM docs")[0]["body"] is None
        writer.execute("CREATE TABLE extra(x)")
        writer.execute("INSERT INTO extra VALUES (42)")
        writer.commit()
        assert cage.query("SELECT x FROM extra") == [{"x": 42}]
        assert cage.query("SELECT body FROM docs")[0]["body"] is None
        cage.close()
    finally:
        writer.close()


def test_protected_table_dropped_fails_closed(tmp_path):
    """If the schema changes so the ACL no longer resolves, queries raise
    rather than continuing with a silently weaker ACL."""
    path, writer = _live_db(tmp_path)
    try:
        cage = Cage(path, CagePolicy(table_acl={"docs": None}))
        writer.execute("DROP TABLE docs")
        writer.commit()
        with pytest.raises(QueryDenied):
            cage.query("SELECT 1 AS x")
        cage.close()
    finally:
        writer.close()


def test_generator_policy_iterables_still_enforce(db):
    """Round-4.1 exploit: a one-shot iterable was consumed by validation and
    enforced as EMPTY. Policies now normalise to frozensets."""
    c = Cage(db, CagePolicy(deny_functions=(f for f in ["hex"])))
    with pytest.raises(QueryDenied):
        c.query("SELECT hex(1)")
    c.close()
    c = Cage(db, CagePolicy(
        table_acl={"docs": {"deny_columns": (col for col in ["body"])}}))
    assert c.query("SELECT body FROM docs WHERE id=5")[0]["body"] is None
    c.close()


def test_wide_schema_does_not_raise_width_ceiling(tmp_path):
    """Round-4.1 exploit: the engine limit must stay at max_columns even
    when the schema contains wider tables — a 300-column table must not
    re-open the wide-expression attack for 257..300 columns."""
    path = tmp_path / "wide.sqlite"
    conn = sqlite3.connect(path)
    cols = ", ".join(f"c{i}" for i in range(300))
    conn.execute(f"CREATE TABLE wide({cols})")
    conn.execute("INSERT INTO wide DEFAULT VALUES")
    conn.commit()
    conn.close()
    cage = Cage(path)                          # max_columns=256
    with pytest.raises(ResultBudgetExceeded):
        cage.query("SELECT " + ", ".join(str(i) for i in range(257)))
    assert cage.query("SELECT c0 FROM wide") == [{"c0": None}]
    cage.close()


def test_immutable_requires_real_bool(db):
    with pytest.raises(TypeError):
        Cage(db, immutable="false")


# --- refresh() -------------------------------------------------------------

def test_refresh_updates_snapshots_and_flushes_pool(tmp_path):
    path, writer = _live_db(tmp_path)
    try:
        cage = Cage(path, CagePolicy(
            table_acl={"docs": {"deny_columns": {"body"}}}))
        assert cage._pool                       # construction probe pooled one
        writer.execute("CREATE VIRTUAL TABLE spy USING fts5("
                       "body, content='docs', content_rowid='id')")
        writer.execute("INSERT INTO spy(spy) VALUES('rebuild')")
        writer.commit()
        cage.refresh()
        assert not cage._pool                   # idle connections retired
        with pytest.raises(QueryDenied):
            cage.query("SELECT count(*) FROM spy WHERE spy MATCH 'squeamish'")
        assert cage.query("SELECT body FROM docs")[0]["body"] is None
        cage.close()
    finally:
        writer.close()


def test_refresh_surfaces_acl_mismatch_eagerly(tmp_path):
    path, writer = _live_db(tmp_path)
    try:
        cage = Cage(path, CagePolicy(table_acl={"docs": None}))
        writer.execute("DROP TABLE docs")
        writer.commit()
        with pytest.raises(ValueError):
            cage.refresh()
        with pytest.raises(QueryDenied):        # still failing closed
            cage.query("SELECT 1 AS x")
        cage.close()
    finally:
        writer.close()


def test_refresh_catches_replaced_immutable_file(tmp_path):
    """The case the automatic check CANNOT see: an immutable connection
    never re-reads the header, so an atomic file replacement is invisible
    until refresh() rebuilds the pool."""
    old = tmp_path / "corpus.sqlite"
    conn = sqlite3.connect(old)
    conn.execute("CREATE TABLE docs(id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO docs VALUES (1)")
    conn.commit()
    conn.close()
    cage = Cage(old, immutable=True)
    assert cage.query("SELECT count(*) AS n FROM docs")[0]["n"] == 1

    new = tmp_path / "corpus-v2.sqlite"
    conn = sqlite3.connect(new)
    conn.execute("CREATE TABLE docs(id INTEGER PRIMARY KEY)")
    conn.executemany("INSERT INTO docs VALUES (?)", [(i,) for i in range(7)])
    conn.commit()
    conn.close()
    os.replace(new, old)

    assert cage.query("SELECT count(*) AS n FROM docs")[0]["n"] == 1  # stale
    cage.refresh()
    assert cage.query("SELECT count(*) AS n FROM docs")[0]["n"] == 7
    cage.close()


def test_refresh_on_closed_cage_raises(db):
    c = Cage(db)
    c.close()
    with pytest.raises(CageError):
        c.refresh()


def _corpus(path, table, rows):
    conn = sqlite3.connect(path)
    conn.execute(f"CREATE TABLE {table}(id INTEGER PRIMARY KEY, body TEXT)")
    conn.executemany(f"INSERT INTO {table} VALUES (?, ?)", rows)
    conn.commit()
    conn.close()


def test_failed_immutable_refresh_fails_closed(tmp_path):
    """Round-4.3 exploit: when a replaced immutable file no longer satisfies
    the ACL, refresh() raised — but the old pool kept serving the REPLACED
    file's rows, defeating the revocation the swap was for. A failed rebuild
    must taint the cage: every query refuses until a rebuild succeeds."""
    live = tmp_path / "corpus.sqlite"
    _corpus(live, "docs", [(1, "revoked-secret")])
    cage = Cage(live, CagePolicy(table_acl={"docs": {"deny_columns": {"body"}}}),
                immutable=True)
    assert cage.query("SELECT id FROM docs")[0]["id"] == 1

    bad = tmp_path / "v2.sqlite"
    _corpus(bad, "documents", [(1, "moved")])          # docs is GONE
    os.replace(bad, live)
    with pytest.raises(ValueError):
        cage.refresh()
    with pytest.raises(QueryDenied):                   # NOT the stale row
        cage.query("SELECT id FROM docs")
    with pytest.raises(QueryDenied):                   # everything refuses
        cage.query("SELECT 1 AS x")

    good = tmp_path / "v3.sqlite"
    _corpus(good, "docs", [(7, "fresh")])              # compatible again
    os.replace(good, live)
    # a plain query self-heals — no explicit refresh() needed
    assert cage.query("SELECT id FROM docs")[0]["id"] == 7
    assert cage.query("SELECT body FROM docs")[0]["body"] is None
    cage.close()


def test_case_folded_duplicate_acl_keys_rejected():
    """Round-4.3: "docs" and "DOCS" are ONE table to SQLite; letting both
    keys through resolved last-wins — a whole-table denial silently traded
    for a column mask."""
    with pytest.raises(ValueError):
        CagePolicy(table_acl={"docs": None,
                              "DOCS": {"deny_columns": {"body"}}})


def test_busy_writer_does_not_blow_deadline(tmp_path):
    """Round-4.3: SQLite's default 5 s busy timeout ignored deadline_s (a
    0.1 s-deadline query against a locked database took 10.4 s — two stacked
    busy windows). The busy wait now scales with the deadline."""
    path = tmp_path / "busy.sqlite"
    _corpus(path, "t", [(1, "x")])
    cage = Cage(path, CagePolicy(deadline_s=0.3))
    assert cage.query("SELECT id FROM t")[0]["id"] == 1
    writer = sqlite3.connect(path)
    writer.execute("BEGIN EXCLUSIVE")
    try:
        t0 = time.monotonic()
        with pytest.raises(CageError):
            cage.query("SELECT id FROM t")
        elapsed = time.monotonic() - t0
        assert elapsed < 3.0, f"busy wait ignored the deadline: {elapsed:.2f}s"
    finally:
        writer.rollback()
        writer.close()
        cage.close()


# --- round 4.4: engine layers adopted --------------------------------------

def test_engine_pragma_layers_set(db):
    """query_only, trusted_schema and cell_size_check are applied to every
    caged connection before its authorizer exists, and the caller can never
    revert them (pragma writes are denied). The 3.37 floor makes all three
    real, never a silently-ignored unknown pragma."""
    cage = Cage(db)
    caged = cage._new_conn()
    caged.conn.set_authorizer(None)        # white-box: peek past the cage
    assert caged.conn.execute("PRAGMA query_only").fetchone()[0] == 1
    assert caged.conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
    assert caged.conn.execute("PRAGMA cell_size_check").fetchone()[0] == 1
    caged.conn.close()
    with pytest.raises(QueryDenied):
        cage.query("PRAGMA query_only=OFF")
    cage.close()


@pytest.mark.parametrize("policy_kw,sql", [
    ({"max_like_pattern": 8}, "SELECT 'x' LIKE '%aaaaaaaaaaaaaaaa%'"),
    ({"max_function_args": 4}, "SELECT max(1,2,3,4,5,6)"),
    ({"max_bound_params": 8}, "SELECT ?20"),
])
def test_new_engine_limits_deny(db, policy_kw, sql):
    with Cage(db, CagePolicy(**policy_kw)) as cage:
        with pytest.raises(QueryDenied):
            cage.query(sql)


def test_new_engine_limit_defaults_allow_normal_queries(db):
    with Cage(db) as cage:
        got = cage.query("SELECT count(*) AS n FROM docs "
                         "WHERE title LIKE '%doc 1%' AND id = max(1, ?)", (1,))
        assert got[0]["n"] >= 1


def test_duplicate_result_columns_rejected(db):
    """Round-4.6: dict rows keep ONE value per name, so duplicate result
    names silently dropped data — the honesty contract's forbidden failure.
    Both the aliased and the join-collision spellings must refuse loudly,
    and unique aliases must keep working."""
    with Cage(db) as cage:
        with pytest.raises(QueryError):
            cage.query("SELECT id AS x, title AS x FROM docs LIMIT 1")
        with pytest.raises(QueryError):
            cage.query("SELECT d.id, f.id FROM docs d "
                       "JOIN docs f ON d.id = f.id LIMIT 1")
        with pytest.raises(QueryError):
            cage.fetch("SELECT d.id, f.id FROM docs d "
                       "JOIN docs f ON d.id = f.id LIMIT 1")
        ok = cage.query("SELECT d.id AS d_id, f.id AS f_id FROM docs d "
                        "JOIN docs f ON d.id = f.id LIMIT 1")
        assert ok == [{"d_id": 1, "f_id": 1}]


def test_rebuilds_cannot_loosen_mutated_acl(tmp_path):
    """Round-4.2 regression: rebuilds re-resolve the ACL, and resolving from
    the live (mutable) policy let `policy.table_acl.clear()` plus EITHER an
    explicit refresh() or a writer-triggered epoch rebuild expose the
    protected column — breaking the round-3 immutability contract."""
    path, writer = _live_db(tmp_path)
    try:
        cage = Cage(path, CagePolicy(
            table_acl={"docs": {"deny_columns": {"body"}}}))
        cage.policy.table_acl.clear()
        cage.refresh()                                  # variant 1: explicit
        assert cage.query("SELECT body FROM docs")[0]["body"] is None
        writer.execute("CREATE TABLE unrelated(x)")     # variant 2: epoch
        writer.commit()
        assert cage.query("SELECT body FROM docs")[0]["body"] is None
        # and the refreshed FTS discovery still uses the frozen spec
        writer.execute("CREATE VIRTUAL TABLE spy USING fts5("
                       "body, content='docs', content_rowid='id')")
        writer.execute("INSERT INTO spy(spy) VALUES('rebuild')")
        writer.commit()
        with pytest.raises(QueryDenied):
            cage.query("SELECT count(*) FROM spy WHERE spy MATCH 'squeamish'")
        cage.close()
    finally:
        writer.close()


def test_small_budget_with_default_value_cap_is_legal():
    """max_result_bytes < max_length is a LEGITIMATE config (oversized rows
    raise the budget error, loudly); no cross-field invariant may reject it."""
    CagePolicy(max_result_bytes=50_000)        # must not raise
