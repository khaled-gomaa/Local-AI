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

CREATE TABLE IF NOT EXISTS shadow_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    session_id INTEGER,
    agent TEXT NOT NULL,
    host TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(program_id, session_id, agent, host),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_shadow_findings_program
    ON shadow_findings(program_id, host, updated_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    session_id INTEGER,
    agent TEXT NOT NULL,
    host TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    statement TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.0,
    state TEXT NOT NULL DEFAULT 'needs_review',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    reviewed_at TEXT,
    operator_note TEXT NOT NULL DEFAULT '',
    UNIQUE(program_id, fingerprint),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_program
    ON findings(program_id, host, state, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS session_handoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL UNIQUE,
    summary_json TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_handoffs_session
    ON session_handoffs(session_id, generated_at DESC);

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
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
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


    def get_or_create_active_session(self, program: str) -> tuple[sqlite3.Row, sqlite3.Row]:
        program_row = self.ensure_program(program)
        session_row = self.ensure_session(program, date.today().isoformat())
        return program_row, session_row

    def save_shadow_finding(
        self,
        program_id: int,
        session_id: int,
        agent: str,
        host: str,
        result: dict,
    ) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True)
        now = _now()
        self.conn.execute(
            """
            INSERT INTO shadow_findings(
                program_id, session_id, agent, host, result_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(program_id, session_id, agent, host)
            DO UPDATE SET result_json = excluded.result_json,
                          updated_at = excluded.updated_at
            """,
            (program_id, session_id, agent, host.lower(), payload, now, now),
        )
        self.conn.commit()

        session_row = self.conn.execute(
            "SELECT folder FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if session_row:
            folder = Path(session_row["folder"]) / "shadow"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{slugify(agent)}.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

    def shadow_context(
        self,
        program_id: int,
        host: str | None = None,
    ) -> list[dict]:
        params: list = [program_id]
        sql = """
            SELECT agent, host, result_json, updated_at
            FROM shadow_findings
            WHERE program_id = ?
        """
        if host:
            sql += " AND host = ?"
            params.append(host.lower())
        sql += " ORDER BY updated_at DESC LIMIT 100"

        rows = self.conn.execute(sql, params).fetchall()
        return [
            {
                "agent": row["agent"],
                "host": row["host"],
                "updated_at": row["updated_at"],
                "result": json.loads(row["result_json"]),
            }
            for row in rows
        ]

    def program_by_id(self, program_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM programs WHERE id = ?",
            (program_id,),
        ).fetchone()

    def hosts_for_program(self, program_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT host, first_seen_at, last_seen_at
            FROM program_hosts
            WHERE program_id = ?
            ORDER BY last_seen_at DESC
            """,
            (program_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def upsert_finding(
        self,
        *,
        program_id: int,
        session_id: int,
        agent: str,
        host: str,
        category: str,
        target: str,
        title: str,
        statement: str,
        evidence: list[str],
        confidence: float = 0.0,
    ) -> int:
        from hashlib import sha256

        normalized = "|".join([
            agent.strip().lower(),
            host.strip().lower(),
            category.strip().lower(),
            target.strip().lower(),
        ])
        fingerprint = sha256(normalized.encode("utf-8", "ignore")).hexdigest()[:24]
        now = _now()
        confidence = max(0.0, min(float(confidence or 0.0), 1.0))
        row = self.conn.execute(
            """
            SELECT id, state, operator_note
            FROM findings
            WHERE program_id = ? AND fingerprint = ?
            """,
            (program_id, fingerprint),
        ).fetchone()

        if row is None:
            self.conn.execute(
                """
                INSERT INTO findings(
                    program_id, session_id, agent, host, fingerprint,
                    category, target, title, statement, evidence_json,
                    confidence, first_seen_at, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    program_id, session_id, agent, host.lower(), fingerprint,
                    category, target, title, statement,
                    json.dumps(evidence[:20], ensure_ascii=False),
                    confidence, now, now,
                ),
            )
            self.conn.commit()
            return int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])

        self.conn.execute(
            """
            UPDATE findings
            SET session_id = ?,
                agent = ?,
                title = ?,
                statement = ?,
                evidence_json = ?,
                confidence = MAX(confidence, ?),
                last_seen_at = ?
            WHERE id = ?
            """,
            (
                session_id, agent, title, statement,
                json.dumps(evidence[:20], ensure_ascii=False),
                confidence, now, row["id"],
            ),
        )
        self.conn.commit()
        return int(row["id"])

    def record_shadow_findings(
        self,
        *,
        program_id: int,
        session_id: int,
        host: str,
        agent_result: dict,
    ) -> list[int]:
        agent = str(agent_result.get("agent") or "shadow-agent")
        ids: list[int] = []
        for item in agent_result.get("missed_items") or []:
            target = str(item.get("target") or "").strip()
            reason = str(item.get("reason") or "").strip()
            if not target or not reason:
                continue
            ids.append(
                self.upsert_finding(
                    program_id=program_id,
                    session_id=session_id,
                    agent=agent,
                    host=host,
                    category="missed_review",
                    target=target,
                    title=f"Manual review suggested: {target}",
                    statement=reason,
                    evidence=[str(x) for x in item.get("evidence") or []],
                    confidence=float(item.get("confidence") or 0.0),
                )
            )
        return ids

    def list_findings(
        self,
        program: str,
        host: str | None = None,
        state: str | None = None,
        limit: int = 200,
    ) -> list[dict]:
        program_row = self._program_row(program)
        if not program_row:
            return []

        where = ["program_id = ?"]
        params: list = [program_row["id"]]
        if host:
            where.append("host = ?")
            params.append(host.lower())
        allowed_states = {
            "observed", "hypothesis", "needs_review",
            "tested", "confirmed", "rejected", "not_interesting",
        }
        if state and state in allowed_states:
            where.append("state = ?")
            params.append(state)

        params.append(max(1, min(int(limit), 500)))
        rows = self.conn.execute(
            f"""
            SELECT *
            FROM findings
            WHERE {" AND ".join(where)}
            ORDER BY
                CASE state
                    WHEN 'needs_review' THEN 0
                    WHEN 'hypothesis' THEN 1
                    WHEN 'observed' THEN 2
                    WHEN 'tested' THEN 3
                    WHEN 'confirmed' THEN 4
                    WHEN 'rejected' THEN 5
                    WHEN 'not_interesting' THEN 6
                    ELSE 7
                END,
                confidence DESC,
                last_seen_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

        return [
            {
                **dict(row),
                "evidence": json.loads(row["evidence_json"] or "[]"),
            }
            for row in rows
        ]

    def update_finding_state(
        self,
        *,
        program: str,
        finding_id: int,
        state: str,
        operator_note: str = "",
    ) -> dict | None:
        allowed = {
            "observed", "hypothesis", "needs_review",
            "tested", "confirmed", "rejected", "not_interesting",
        }
        if state not in allowed:
            raise ValueError("invalid finding state")

        program_row = self._program_row(program)
        if not program_row:
            return None

        reviewed_at = _now() if state in {
            "tested", "confirmed", "rejected", "not_interesting"
        } else None

        row = self.conn.execute(
            """
            SELECT * FROM findings
            WHERE id = ? AND program_id = ?
            """,
            (finding_id, program_row["id"]),
        ).fetchone()

        if not row:
            return None

        self.conn.execute(
            """
            UPDATE findings
            SET state = ?, operator_note = ?, reviewed_at = ?
            WHERE id = ? AND program_id = ?
            """,
            (
                state, operator_note.strip(), reviewed_at,
                finding_id, program_row["id"],
            ),
        )
        self.conn.commit()

        updated = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        return {
            **dict(updated),
            "evidence": json.loads(updated["evidence_json"] or "[]"),
        }

    def finding_learning_context(
        self,
        program_id: int,
        host: str,
        limit: int = 80,
    ) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT agent, host, category, target, title, statement,
                   confidence, state, operator_note, last_seen_at
            FROM findings
            WHERE program_id = ? AND host = ?
            ORDER BY last_seen_at DESC
            LIMIT ?
            """,
            (program_id, host.lower(), max(1, min(limit, 200))),
        ).fetchall()
        return [dict(row) for row in rows]

    def previous_session(self, program_id: int, session_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT *
            FROM sessions
            WHERE program_id = ? AND id != ?
            ORDER BY session_date DESC, id DESC
            LIMIT 1
            """,
            (program_id, session_id),
        ).fetchone()

    def session_stats(self, program_id: int, session_id: int) -> dict:
        row = self.conn.execute(
            """
            SELECT
                COUNT(*) AS requests,
                COUNT(DISTINCT host) AS hosts,
                COUNT(DISTINCT path) AS endpoints
            FROM (
                SELECT host, path
                FROM program_requests
                WHERE program_id = ? AND session_id = ?
            )
            """,
            (program_id, session_id),
        ).fetchone()

        param_rows = self.conn.execute(
            """
            SELECT params_json
            FROM program_requests
            WHERE program_id = ? AND session_id = ?
            """,
            (program_id, session_id),
        ).fetchall()
        params = set()
        for item in param_rows:
            params.update(json.loads(item["params_json"] or "[]"))

        states = self.conn.execute(
            """
            SELECT state, COUNT(*) AS n
            FROM findings
            WHERE program_id = ? AND session_id = ?
            GROUP BY state
            """,
            (program_id, session_id),
        ).fetchall()

        return {
            "requests": int(row["requests"]),
            "hosts": int(row["hosts"]),
            "endpoints": int(row["endpoints"]),
            "parameters": len(params),
            "finding_states": {
                item["state"]: int(item["n"])
                for item in states
            },
        }

    def session_handoff(
        self,
        program_id: int,
        session_id: int,
        traffic_summary: dict,
    ) -> dict:
        current = self.conn.execute(
            "SELECT * FROM sessions WHERE id = ? AND program_id = ?",
            (session_id, program_id),
        ).fetchone()
        previous = self.previous_session(program_id, session_id)

        current_stats = self.session_stats(program_id, session_id)
        previous_stats = (
            self.session_stats(program_id, previous["id"])
            if previous
            else None
        )

        current_hosts = {
            item["host"]
            for item in self.conn.execute(
                "SELECT DISTINCT host FROM program_requests WHERE program_id = ? AND session_id = ?",
                (program_id, session_id),
            ).fetchall()
        }
        previous_hosts = {
            item["host"]
            for item in self.conn.execute(
                "SELECT DISTINCT host FROM program_requests WHERE program_id = ? AND session_id = ?",
                (program_id, previous["id"]),
            ).fetchall()
        } if previous else set()

        current_paths = {
            item["path"]
            for item in self.conn.execute(
                "SELECT DISTINCT path FROM program_requests WHERE program_id = ? AND session_id = ?",
                (program_id, session_id),
            ).fetchall()
        }
        previous_paths = {
            item["path"]
            for item in self.conn.execute(
                "SELECT DISTINCT path FROM program_requests WHERE program_id = ? AND session_id = ?",
                (program_id, previous["id"]),
            ).fetchall()
        } if previous else set()

        open_findings = self.list_findings(
            self.program_by_id(program_id)["name"],
            state="needs_review",
            limit=100,
        )

        previous_handoff = None
        if previous:
            row = self.conn.execute(
                """
                SELECT summary_json, generated_at
                FROM session_handoffs
                WHERE session_id = ?
                """,
                (previous["id"],),
            ).fetchone()
            if row:
                previous_handoff = {
                    "generated_at": row["generated_at"],
                    "summary": json.loads(row["summary_json"]),
                }

        program_row = self.program_by_id(program_id)
        handoff = {
            "program": dict(program_row) if program_row else {"id": program_id},
            "session": dict(current) if current else None,
            "previous_session": dict(previous) if previous else None,
            "current_stats": current_stats,
            "previous_stats": previous_stats,
            "previous_handoff": previous_handoff,
            "delta": {
                "new_hosts": sorted(current_hosts - previous_hosts),
                "new_endpoints": sorted(current_paths - previous_paths),
                "requests_delta": (
                    current_stats["requests"] - previous_stats["requests"]
                    if previous_stats else current_stats["requests"]
                ),
                "endpoint_delta": (
                    current_stats["endpoints"] - previous_stats["endpoints"]
                    if previous_stats else current_stats["endpoints"]
                ),
                "parameter_delta": (
                    current_stats["parameters"] - previous_stats["parameters"]
                    if previous_stats else current_stats["parameters"]
                ),
            },
            "open_review_items": open_findings[:30],
            "traffic": traffic_summary,
        }
        return handoff

    def save_session_handoff(self, session_id: int, summary: dict) -> None:
        now = _now()
        self.conn.execute(
            """
            INSERT INTO session_handoffs(session_id, summary_json, generated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(session_id)
            DO UPDATE SET summary_json = excluded.summary_json,
                          generated_at = excluded.generated_at
            """,
            (
                session_id,
                json.dumps(summary, ensure_ascii=False),
                now,
            ),
        )
        self.conn.commit()

        row = self.conn.execute(
            "SELECT folder FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row:
            folder = Path(row["folder"])
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "handoff.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

    def latest_session_handoff(self, session_id: int) -> dict | None:
        row = self.conn.execute(
            """
            SELECT summary_json, generated_at
            FROM session_handoffs
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "generated_at": row["generated_at"],
            "summary": json.loads(row["summary_json"]),
        }

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

        findings = self.conn.execute(
            """
            SELECT id, agent, host, category, target, title,
                   confidence, state, operator_note, last_seen_at
            FROM findings
            WHERE program_id = ?
            ORDER BY last_seen_at DESC
            LIMIT 100
            """,
            (row["id"],),
        ).fetchall()

        return {
            "program": dict(row),
            "sessions": [dict(item) for item in sessions],
            "hosts": [dict(item) for item in hosts],
            "notes": [dict(item) for item in notes],
            "findings": [dict(item) for item in findings],
        }
