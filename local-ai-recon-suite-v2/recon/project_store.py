from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PROJECT_ROOT = DATA / "projects"
DB_PATH = Path(os.getenv("RECON_DB_PATH", str(DATA / "recon.db")))

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    session_date TEXT NOT NULL,
    folder TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    notes TEXT NOT NULL DEFAULT '',
    UNIQUE(program_id, session_date),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS program_hosts (
    program_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY(program_id, host),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    session_id INTEGER,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE SET NULL
);
"""

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "program"

class ProjectStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def _program_row(self, program: str):
        slug = slugify(program)
        row = self.conn.execute(
            "SELECT * FROM programs WHERE slug = ?",
            (slug,),
        ).fetchone()
        return row

    def ensure_program(self, program: str) -> sqlite3.Row:
        name = program.strip()
        if not name:
            raise ValueError("Program name is required")

        slug = slugify(name)
        now = _now()
        row = self.conn.execute(
            "SELECT * FROM programs WHERE slug = ?",
            (slug,),
        ).fetchone()

        if row is None:
            self.conn.execute(
                """
                INSERT INTO programs(slug, name, created_at, last_seen_at)
                VALUES (?, ?, ?, ?)
                """,
                (slug, name, now, now),
            )
            self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM programs WHERE slug = ?",
                (slug,),
            ).fetchone()
        else:
            self.conn.execute(
                "UPDATE programs SET name = ?, last_seen_at = ? WHERE id = ?",
                (name, now, row["id"]),
            )
            self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM programs WHERE id = ?",
                (row["id"],),
            ).fetchone()

        return row

    def ensure_session(
        self,
        program: str,
        session_day: str | None = None,
    ) -> sqlite3.Row:
        row = self.ensure_program(program)
        day = session_day or date.today().isoformat()

        try:
            date.fromisoformat(day)
        except ValueError as exc:
            raise ValueError("session_date must be YYYY-MM-DD") from exc

        existing = self.conn.execute(
            """
            SELECT * FROM sessions
            WHERE program_id = ? AND session_date = ?
            """,
            (row["id"], day),
        ).fetchone()

        if existing:
            return existing

        folder = PROJECT_ROOT / day / row["slug"]
        folder.mkdir(parents=True, exist_ok=True)

        created = _now()
        self.conn.execute(
            """
            INSERT INTO sessions(
                program_id, session_date, folder, started_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (row["id"], day, str(folder), created),
        )
        self.conn.commit()

        # Human-readable session metadata next to the DB.
        metadata = {
            "program": row["name"],
            "program_slug": row["slug"],
            "session_date": day,
            "started_at": created,
        }
        (folder / "session.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "
",
            encoding="utf-8",
        )

        return self.conn.execute(
            "SELECT * FROM sessions WHERE program_id = ? AND session_date = ?",
            (row["id"], day),
        ).fetchone()

    def touch_host(self, program_id: int, host: str) -> None:
        now = _now()
        self.conn.execute(
            """
            INSERT INTO program_hosts(program_id, host, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(program_id, host)
            DO UPDATE SET last_seen_at = excluded.last_seen_at
            """,
            (program_id, host.lower(), now, now),
        )
        self.conn.commit()

    def list_programs(self) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT p.*,
                   COUNT(DISTINCT s.id) AS sessions,
                   COUNT(DISTINCT h.host) AS hosts
            FROM programs p
            LEFT JOIN sessions s ON s.program_id = p.id
            LEFT JOIN program_hosts h ON h.program_id = p.id
            GROUP BY p.id
            ORDER BY p.last_seen_at DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def list_sessions(self, program: str) -> list[dict]:
        row = self._program_row(program)
        if not row:
            return []
        rows = self.conn.execute(
            """
            SELECT * FROM sessions
            WHERE program_id = ?
            ORDER BY session_date DESC
            """,
            (row["id"],),
        ).fetchall()
        return [dict(item) for item in rows]

    def add_note(
        self,
        program: str,
        title: str,
        body: str,
        kind: str = "operator",
        session_date: str | None = None,
    ) -> None:
        program_row = self.ensure_program(program)
        session = None
        if session_date:
            session = self.ensure_session(program, session_date)

        self.conn.execute(
            """
            INSERT INTO project_notes(
                program_id, session_id, kind, title, body, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                program_row["id"],
                session["id"] if session else None,
                kind,
                title,
                body,
                _now(),
            ),
        )
        self.conn.commit()

    def program_context(self, program: str) -> dict:
        row = self._program_row(program)
        if not row:
            return {"program": program, "sessions": [], "hosts": [], "notes": []}

        sessions = self.conn.execute(
            "SELECT * FROM sessions WHERE program_id = ? ORDER BY session_date DESC LIMIT 30",
            (row["id"],),
        ).fetchall()
        hosts = self.conn.execute(
            "SELECT * FROM program_hosts WHERE program_id = ? ORDER BY last_seen_at DESC",
            (row["id"],),
        ).fetchall()
        notes = self.conn.execute(
            """
            SELECT * FROM project_notes
            WHERE program_id = ?
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (row["id"],),
        ).fetchall()

        return {
            "program": dict(row),
            "sessions": [dict(item) for item in sessions],
            "hosts": [dict(item) for item in hosts],
            "notes": [dict(item) for item in notes],
        }
