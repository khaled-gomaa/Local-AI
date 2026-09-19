from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
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
    version INTEGER NOT NULL DEFAULT 1,
    indexed_hash TEXT,
    indexed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(content_hash);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_record_id ON documents(record_id);

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

CREATE TABLE IF NOT EXISTS index_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    record_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    category TEXT NOT NULL,
    previous_record_id TEXT,
    previous_category TEXT,
    action TEXT NOT NULL DEFAULT 'upsert',
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_index_queue_status
    ON index_queue(status, id);

CREATE INDEX IF NOT EXISTS idx_index_queue_record
    ON index_queue(record_id);

CREATE TABLE IF NOT EXISTS index_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    items_claimed INTEGER NOT NULL DEFAULT 0,
    items_done INTEGER NOT NULL DEFAULT 0,
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

    def _enqueue_index(
        self,
        *,
        url: str,
        record_id: str,
        content_hash: str,
        category: str,
        previous_record_id: str | None,
        previous_category: str | None,
    ) -> None:
        now = _now()
        self.conn.execute(
            """
            INSERT INTO index_queue(
                url, record_id, content_hash, category,
                previous_record_id, previous_category,
                action, status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'upsert', 'pending', ?, ?)
            """,
            (
                url,
                record_id,
                content_hash,
                category,
                previous_record_id,
                previous_category,
                now,
                now,
            ),
        )

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
                    category, score, first_seen_at, last_seen_at, version,
                    indexed_hash, indexed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL)
                """,
                (
                    url, content_hash, record_id, title, source, published,
                    category, score, now, now,
                ),
            )
            self._enqueue_index(
                url=url,
                record_id=record_id,
                content_hash=content_hash,
                category=category,
                previous_record_id=None,
                previous_category=None,
            )
            self.conn.commit()
            return "added"

        if current["content_hash"] == content_hash:
            self.conn.execute(
                "UPDATE documents SET last_seen_at = ? WHERE url = ?",
                (now, url),
            )
            self.conn.commit()
            return "unchanged"

        self.conn.execute(
            """
            UPDATE documents
            SET content_hash = ?, record_id = ?, title = ?, source = ?,
                published = ?, category = ?, score = ?,
                last_seen_at = ?, version = version + 1,
                indexed_hash = NULL, indexed_at = NULL
            WHERE url = ?
            """,
            (
                content_hash, record_id, title, source, published,
                category, score, now, url,
            ),
        )
        self._enqueue_index(
            url=url,
            record_id=record_id,
            content_hash=content_hash,
            category=category,
            previous_record_id=current["record_id"],
            previous_category=current["category"],
        )
        self.conn.commit()
        return "updated"

    def insert_legacy_placeholder(self, url: str, record_id: str) -> None:
        now = _now()
        self.conn.execute(
            """
            INSERT OR IGNORE INTO documents(
                url, content_hash, record_id, first_seen_at, last_seen_at, version
            )
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (url, "legacy:" + record_id, record_id, now, now),
        )
        self.conn.commit()

    def count_documents(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM documents"
        ).fetchone()
        return int(row["n"])

    def reset_stale_index_jobs(self, older_than_minutes: int = 30) -> int:
        threshold = (
            datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)
        ).isoformat()
        cur = self.conn.execute(
            """
            UPDATE index_queue
            SET status = 'pending', updated_at = ?, last_error = 'reclaimed'
            WHERE status = 'running' AND updated_at < ?
            """,
            (_now(), threshold),
        )
        self.conn.commit()
        return cur.rowcount

    def begin_index_run(self) -> int:
        cur = self.conn.execute(
            "INSERT INTO index_runs(started_at) VALUES(?)",
            (_now(),),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def claim_index_jobs(self, limit: int = 32) -> list[sqlite3.Row]:
        limit = max(1, min(limit, 500))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                """
                SELECT *
                FROM index_queue
                WHERE status IN ('pending', 'failed')
                ORDER BY id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                self.conn.execute(
                    f"""
                    UPDATE index_queue
                    SET status = 'running', attempts = attempts + 1, updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    [_now(), *ids],
                )
            self.conn.commit()
            return rows
        except Exception:
            self.conn.rollback()
            raise

    def mark_index_done(self, job_id: int, content_hash: str) -> None:
        now = _now()
        self.conn.execute(
            """
            UPDATE index_queue
            SET status = 'done', updated_at = ?, last_error = NULL
            WHERE id = ?
            """,
            (now, job_id),
        )
        self.conn.execute(
            """
            UPDATE documents
            SET indexed_hash = ?, indexed_at = ?
            WHERE record_id = ?
            """,
            (
                content_hash,
                now,
                self.conn.execute(
                    "SELECT record_id FROM index_queue WHERE id = ?",
                    (job_id,),
                ).fetchone()["record_id"],
            ),
        )
        self.conn.commit()

    def mark_index_failed(self, job_id: int, error: str) -> None:
        self.conn.execute(
            """
            UPDATE index_queue
            SET status = 'failed', updated_at = ?, last_error = ?
            WHERE id = ?
            """,
            (_now(), error[:1000], job_id),
        )
        self.conn.commit()

    def finish_index_run(
        self,
        run_id: int,
        *,
        claimed: int,
        done: int,
        failed: int,
    ) -> None:
        self.conn.execute(
            """
            UPDATE index_runs
            SET finished_at = ?, items_claimed = ?, items_done = ?, items_failed = ?
            WHERE id = ?
            """,
            (_now(), claimed, done, failed, run_id),
        )
        self.conn.commit()

    def pending_index_count(self) -> int:
        row = self.conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM index_queue
            WHERE status IN ('pending', 'failed')
            """
        ).fetchone()
        return int(row["n"])
