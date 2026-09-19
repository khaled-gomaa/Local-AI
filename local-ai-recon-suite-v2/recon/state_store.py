from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = Path(os.getenv("RECON_DB_PATH", str(DATA / "recon.db")))

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS documents (
    url TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    record_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    published TEXT,
    category TEXT NOT NULL DEFAULT '',
    score REAL NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(content_hash);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);

CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    mode TEXT NOT NULL,
    items_seen INTEGER NOT NULL DEFAULT 0,
    items_added INTEGER NOT NULL DEFAULT 0,
    items_updated INTEGER NOT NULL DEFAULT 0,
    items_unchanged INTEGER NOT NULL DEFAULT 0,
    items_failed INTEGER NOT NULL DEFAULT 0
);
"""

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

class ReconStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def __enter__(self) -> "ReconStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type:
            self.conn.rollback()
        self.close()

    def close(self) -> None:
        self.conn.close()

    def get(self, url: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM documents WHERE url = ?",
            (url,),
        ).fetchone()

    def touch(self, url: str) -> None:
        self.conn.execute(
            "UPDATE documents SET last_seen_at = ? WHERE url = ?",
            (_now(), url),
        )
        self.conn.commit()

    def begin_run(self, mode: str) -> int:
        cursor = self.conn.execute(
            "INSERT INTO sync_runs(started_at, mode) VALUES(?, ?)",
            (_now(), mode),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def finish_run(
        self,
        run_id: int,
        *,
        items_seen: int,
        items_added: int,
        items_updated: int,
        items_unchanged: int,
        items_failed: int,
    ) -> None:
        self.conn.execute(
            """
            UPDATE sync_runs
            SET finished_at = ?, items_seen = ?, items_added = ?,
                items_updated = ?, items_unchanged = ?, items_failed = ?
            WHERE id = ?
            """,
            (
                _now(),
                items_seen,
                items_added,
                items_updated,
                items_unchanged,
                items_failed,
                run_id,
            ),
        )
        self.conn.commit()

    def upsert_document(
        self,
        *,
        url: str,
        content_hash: str,
        record_id: str,
        title: str,
        source: str,
        published: str | None,
        category: str,
        score: float,
    ) -> str:
        now = _now()
        current = self.get(url)

        if current is None:
            self.conn.execute(
                """
                INSERT INTO documents(
                    url, content_hash, record_id, title, source, published,
                    category, score, first_seen_at, last_seen_at, version
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    url, content_hash, record_id, title, source, published,
                    category, score, now, now,
                ),
            )
            self.conn.commit()
            return "added"

        if current["content_hash"] == content_hash:
            self.touch(url)
            return "unchanged"

        self.conn.execute(
            """
            UPDATE documents
            SET content_hash = ?, record_id = ?, title = ?, source = ?,
                published = ?, category = ?, score = ?,
                last_seen_at = ?, version = version + 1
            WHERE url = ?
            """,
            (
                content_hash, record_id, title, source, published,
                category, score, now, url,
            ),
        )
        self.conn.commit()
        return "updated"

    def count_documents(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM documents"
        ).fetchone()
        return int(row["n"])
