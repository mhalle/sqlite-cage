#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["sqlite-cage"]
# ///
"""Property-based adversarial fuzzer for sqlite-cage.

Generates random policies and queries (legitimate + adversarial) and asserts
the invariants that must hold for EVERY input — never a specific value. A
violation prints the seed, policy, and query to reproduce.

  python -m tests.fuzz_cage            # 2000 cases, random seed
  python -m tests.fuzz_cage 5000 42    # N cases, fixed seed

Also importable: fuzz(db_path, n, seed) -> list of violations, so CI can run
it as a normal test with a small budget.
"""
import json
import random
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sqlite_cage import (
    Cage,
    CagePolicy,
    QueryDenied,
    QueryError,
    QueryTimeout,
    ResultBudgetExceeded,
    TruncatedResult,
)

try:
    from .fixture import build  # package-relative (pytest)
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fixture import build  # script

WRITES = [
    "INSERT INTO docs(id) VALUES(1)", "UPDATE docs SET title='x'",
    "DELETE FROM docs", "CREATE TABLE t(x)", "DROP TABLE docs",
    "INSERT INTO docs_fts(docs_fts) VALUES('rebuild')",
]
META = ["PRAGMA journal_mode", "PRAGMA table_info(docs)",
        "SELECT * FROM pragma_table_info('docs')", "ATTACH ':memory:' AS x",
        "SELECT load_extension('x')", "PRAGMA data_version = 9"]
BAD = ["SELEC 1", "SELECT FROM", "SELECT * FROM", "((("]
DENIABLE = ["randomblob", "zeroblob", "hex", "quote", "char"]


def _schema(path):
    c = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    t = {}
    for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        try:
            t[name] = [r[1] for r in c.execute(f"PRAGMA table_info('{name}')")]
        except sqlite3.Error:
            pass
    c.close()
    return t


def gen_policy(rng, tables):
    p = dict(deadline_s=rng.choice([0.3, 0.5, 1.0, 2.0]),
             max_rows=rng.choice([0, 1, 5, 100, 1000]),
             max_result_bytes=rng.choice([50_000, 1 << 20, 8 << 20]),
             max_concurrency=rng.choice([1, 2, 3, 5]),
             max_columns=rng.choice([4, 16, 64]))
    if rng.random() < 0.3:
        p["deny_functions"] = frozenset(rng.sample(DENIABLE, rng.randint(1, 3)))
    base = [t for t in tables if not t.startswith("docs_fts")]
    if rng.random() < 0.3 and base:
        t = rng.choice(base)
        cols = tables[t]
        p["table_acl"] = ({t: {"deny_columns": {rng.choice(cols)}}}
                          if cols and rng.random() < 0.7 else {t: None})
    invalid = rng.random() < 0.12
    if invalid:
        p[rng.choice(["deadline_s", "max_concurrency", "progress_every_ops",
                      "max_length", "max_columns"])] = rng.choice([0, -1])
    return p, invalid


def gen_query(rng, tables):
    base = [t for t in tables if not t.startswith("docs_fts")]
    r = rng.random()
    if r < 0.45:
        t = rng.choice(base)
        cols = tables[t]
        sel = rng.choice(["*", ", ".join(rng.sample(cols, min(3, len(cols)))),
                          "count(*)"])
        lim = rng.choice(["", " LIMIT 5", " LIMIT 2000",
                          f" LIMIT {rng.randint(1, 5000)}"])
        return f"SELECT {sel} FROM {t}{lim}", "any"
    if r < 0.60:
        term = rng.choice(['"cherry place"', "newton", "school*",
                           "NEAR(mill river, 10)", "meeting-house"])
        return (f"SELECT d.id FROM docs_fts f JOIN docs d ON d.id=f.rowid "
                f"WHERE f.body MATCH '{term}' LIMIT 50"), "any"
    if r < 0.72:
        return rng.choice(WRITES), "deny"
    if r < 0.84:
        return rng.choice(META), "deny"
    if r < 0.90:
        return rng.choice(BAD), "bad"
    return rng.choice([
        "SELECT count(*) FROM docs a, docs b, docs c, docs d",
        "SELECT body FROM docs",
        "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c "
        "WHERE n<50000000) SELECT count(*) FROM c"]), "any"


CAGE_ERRS = (QueryDenied, QueryTimeout, QueryError, TruncatedResult,
             ResultBudgetExceeded)


def _call(fn):
    try:
        return "ok", fn()
    except CAGE_ERRS as e:
        return "cage", e
    except sqlite3.Error as e:
        return "raw", e
    except Exception as e:
        return "raw", e


def check_case(cage, sql, category):
    t0 = time.monotonic()
    limit = cage.policy.max_rows
    fk, fv = _call(lambda: cage.fetch(sql))
    if fk == "raw":
        return f"I1 raw error from fetch(): {type(fv).__name__}: {fv}"
    qk, qv = _call(lambda: cage.query(sql))
    if time.monotonic() - t0 > max(3 * cage.policy.deadline_s, 1.5):
        return f"I6 timeout overrun vs deadline {cage.policy.deadline_s}s"
    if qk == "raw":
        return f"I1 raw error from query(): {type(qv).__name__}: {qv}"
    if fk == "cage" and qk == "cage":
        if category == "deny" and not isinstance(qv, QueryDenied):
            return f"I5 write/meta not denied: {type(qv).__name__}"
        if category == "bad" and not isinstance(qv, (QueryError, QueryDenied)):
            return f"I7 bad-syntax wrong type: {type(qv).__name__}"
        if not getattr(qv, "query", None) and not isinstance(qv, TruncatedResult):
            return "I1 CageError missing .query"
        return None
    if fk == "cage" and qk == "ok":
        return f"disagree: fetch raised {type(fv).__name__}, query returned rows"
    if fk == "ok" and qk == "cage":
        if not isinstance(qv, TruncatedResult):
            return f"disagree: query raised {type(qv).__name__}, fetch ok"
        if not fv.truncated:
            return "I3 query raised Truncated but fetch says complete"
    res = fv
    if res.returned > res.limit:
        return f"I3 fetch returned {res.returned} > limit {res.limit}"
    if res.truncated and res.returned != res.limit:
        return f"I3 truncated but returned {res.returned} != limit {res.limit}"
    if res.complete and res.truncated:
        return "I3 complete and truncated both true"
    if qk == "ok":
        if res.truncated:
            return "I2 SILENT TRUNCATION: query returned rows but truncated"
        if len(qv) != res.returned:
            return f"disagree: query {len(qv)} vs fetch {res.returned} rows"
        if len(qv) > limit:
            return f"I2 query returned {len(qv)} > max_rows {limit}"
        if category == "deny":
            return "I5 write/meta returned rows"
    try:
        json.dumps(res.envelope())
    except (TypeError, ValueError) as e:
        return f"I4 envelope not JSON-serialisable: {e}"
    return None


def fuzz(db_path, n=2000, seed=None):
    seed = random.randrange(1 << 30) if seed is None else seed
    rng = random.Random(seed)
    tables = _schema(db_path)
    cages, viols = {}, []
    for _ in range(n):
        pol, reject = gen_policy(rng, tables)
        key = json.dumps(pol, default=list, sort_keys=True)
        if reject:
            try:
                CagePolicy(**pol)
                viols.append(("I8 invalid policy accepted", pol, None, seed))
            except ValueError:
                pass
            continue
        if key not in cages:
            try:
                cages[key] = Cage(db_path, CagePolicy(**pol))
            except Exception as e:
                viols.append((f"valid policy rejected: {e}", pol, None, seed))
                cages[key] = None
        cage = cages[key]
        if cage is None:
            continue
        sql, cat = gen_query(rng, tables)
        try:
            v = check_case(cage, sql, cat)
        except Exception as e:
            v = f"HARNESS: {type(e).__name__}: {e}"
        if v:
            viols.append((v, pol, sql, seed))
            if len(viols) >= 20:
                break
    return seed, len(cages), viols


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else None
    with tempfile.TemporaryDirectory() as d:
        path = build(Path(d) / "fixture.sqlite")
        seed, ncages, viols = fuzz(path, n, seed)
    print(f"fuzz: {n} cases, seed={seed}, {ncages} distinct policies")
    if not viols:
        print(f"PASS — no invariant violations (seed {seed})")
        return 0
    print(f"FAIL — {len(viols)} violation(s):")
    for msg, pol, sql, sd in viols[:20]:
        print(f"  [{msg}]\n    policy: {pol}\n    query:  {sql!r}\n"
              f"    repro:  python -m tests.fuzz_cage {n} {sd}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
