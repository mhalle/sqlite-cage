"""Adversarial test suite — every red-team break across three rounds plus the
honesty and async contracts, against a self-contained fixture."""
import asyncio
import json
import sqlite3
import threading

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
