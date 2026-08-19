"""A small self-contained SQLite fixture that exercises every cage surface.

Deliberately not tied to any corpus: a docs table with an external-content
FTS5 index (for MATCH and shadow-table ACL tests), a blob column (for the
envelope round-trip), some large rows (for the byte budget), and enough rows
that the default 1000-row cap truncates.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

N_ROWS = 3000
WORDS = ["cherry", "place", "newton", "school", "river", "mill", "bridge", "charles", "nonantum", "auburndale", "waban", "directory", "poll", "book", "edition"]


def build(path: str | Path) -> str:
    path = str(path)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE docs (
            id INTEGER PRIMARY KEY, title TEXT, body TEXT, tag BLOB);
        CREATE VIRTUAL TABLE docs_fts USING fts5(
            body, content='docs', content_rowid='id',
            tokenize='porter unicode61');
        CREATE TABLE secrets (id INTEGER PRIMARY KEY, value TEXT);
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    """)
    rows = []
    for i in range(1, N_ROWS + 1):
        # every ~250th row is large, to exercise the byte budget
        body = " ".join(WORDS[(i + j) % len(WORDS)] for j in range(6))
        if i % 250 == 0:
            body = ("large " * 4000)
        rows.append((i, f"doc {i}", body, bytes([i % 256, (i * 7) % 256])))
    db.executemany("INSERT INTO docs VALUES (?,?,?,?)", rows)
    db.execute("INSERT INTO docs_fts(docs_fts) VALUES('rebuild')")
    db.executemany("INSERT INTO secrets VALUES (?,?)",
                   [(i, f"secret-{i}") for i in range(1, 11)])
    db.execute("INSERT INTO meta VALUES ('corpus_id', 'fixture-v1')")
    db.commit()
    db.close()
    return path


if __name__ == "__main__":       # build one for manual poking
    import sys
    print(build(sys.argv[1] if len(sys.argv) > 1 else "fixture.sqlite"))
