from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from recon.traffic import (
    EXPOSURE_PATH,
    ID_NAMES,
    SENSITIVE_NAMES,
    URLISH_NAMES,
    _body_param_names,
    _content_type,
    _extract_links,
    _header,
    _endpoint_path,
    _request_parts,
    _response_parts,
    _security_signals,
    _parameter_signals,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = Path(os.getenv("RECON_DB_PATH", str(DATA / "recon.db")))

SCHEMA = """
CREATE TABLE IF NOT EXISTS program_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL,
    program_id INTEGER NOT NULL,
    session_id INTEGER,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    request_content_type TEXT,
    response_content_type TEXT,
    params_json TEXT NOT NULL DEFAULT '[]',
    signals_json TEXT NOT NULL DEFAULT '[]',
    title TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    UNIQUE(program_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_program_requests
    ON program_requests(program_id, host, observed_at DESC);

CREATE TABLE IF NOT EXISTS program_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    source_url TEXT NOT NULL,
    target_url TEXT NOT NULL,
    relation TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(program_id, host, source_url, target_url, relation)
);

CREATE INDEX IF NOT EXISTS idx_program_edges
    ON program_edges(program_id, host, last_seen DESC);

CREATE TABLE IF NOT EXISTS program_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    param TEXT,
    vuln_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    UNIQUE(program_id, host, url, param, vuln_class)
);

CREATE INDEX IF NOT EXISTS idx_program_candidates
    ON program_candidates(program_id, host, state, confidence DESC);
"""

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

class ProgramTrafficStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def observe(
        self,
        *,
        program_id: int,
        session_id: int,
        event: dict,
    ) -> str:
        request_raw = str(event.get("request") or "")
        response_raw = str(event.get("response") or "")
        message_id = str(
            event.get("message_id")
            or sha256((request_raw + response_raw).encode("utf-8", "ignore")).hexdigest()[:24]
        )

        method, url, request_headers, request_body = _request_parts(request_raw)
        explicit_url = str(event.get("url") or "")
        if explicit_url:
            url = explicit_url

        host = (urlparse(url).hostname or "").lower()
        if not host:
            raise ValueError("Cannot determine request host")

        request_type = _content_type(request_headers)
        status_code, response_headers, response_body = _response_parts(response_raw)
        response_type = _content_type(response_headers)

        params = list(dict.fromkeys(
            [key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
            + _body_param_names(request_body, request_type)
        ))

        signals = (
            _parameter_signals(params, _endpoint_path(url))
            + _security_signals(url, request_headers, response_headers, response_body, params)
        )

        title = ""
        if "html" in response_type:
            match = re.search(
                r"(?is)<title[^>]*>(.*?)</title>",
                response_body[:65536],
            )
            if match:
                title = re.sub(r"\s+", " ", match.group(1)).strip()[:300]

        now = _now()
        self.conn.execute(
            """
            INSERT INTO program_requests(
                message_id, program_id, session_id, host, method, url, path,
                status_code, request_content_type, response_content_type,
                params_json, signals_json, title, observed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(program_id, message_id)
            DO UPDATE SET
                session_id = excluded.session_id,
                host = excluded.host,
                method = excluded.method,
                url = excluded.url,
                path = excluded.path,
                status_code = excluded.status_code,
                request_content_type = excluded.request_content_type,
                response_content_type = excluded.response_content_type,
                params_json = excluded.params_json,
                signals_json = excluded.signals_json,
                title = excluded.title,
                observed_at = excluded.observed_at
            """,
            (
                message_id, program_id, session_id, host, method, url,
                _endpoint_path(url), status_code, request_type, response_type,
                json.dumps(params, ensure_ascii=False),
                json.dumps(signals, ensure_ascii=False),
                title, now,
            ),
        )

        for target, relation in _extract_links(
            url,
            response_headers + "\n\n" + response_body,
            response_type,
        ):
            target_host = (urlparse(target).hostname or "").lower()
            if not target_host:
                continue

            target_value = (
                _endpoint_path(target)
                if target_host == host
                else target
            )
            edge_relation = (
                relation
                if target_host == host
                else "cross_host_reference"
            )

            self._edge(
                program_id,
                host,
                url,
                target_value,
                edge_relation,
                f"Observed in {method} {url}",
                now,
            )

        for signal in signals:
            self.conn.execute(
                """
                INSERT INTO program_candidates(
                    program_id, host, url, param, vuln_class, confidence,
                    reason, evidence_json, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(program_id, host, url, param, vuln_class)
                DO UPDATE SET
                    confidence = MAX(program_candidates.confidence, excluded.confidence),
                    reason = excluded.reason,
                    evidence_json = excluded.evidence_json,
                    last_seen = excluded.last_seen,
                    state = 'open'
                """,
                (
                    program_id,
                    host,
                    url,
                    signal.get("param"),
                    signal["class"],
                    float(signal["confidence"]),
                    signal["reason"],
                    json.dumps(
                        [f"{method} {url}", f"status={status_code}"],
                        ensure_ascii=False,
                    ),
                    now,
                    now,
                ),
            )

        self.conn.commit()
        return host

    def _edge(
        self,
        program_id: int,
        host: str,
        source: str,
        target: str,
        relation: str,
        evidence: str,
        now: str,
    ) -> None:
        source_path = _endpoint_path(source)
        target_path = _endpoint_path(target)
        self.conn.execute(
            """
            INSERT INTO program_edges(
                program_id, host, source_url, target_url,
                relation, evidence, first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(program_id, host, source_url, target_url, relation)
            DO UPDATE SET last_seen = excluded.last_seen,
                          evidence = excluded.evidence
            """,
            (
                program_id, host, source_path, target_path,
                relation, evidence[:500], now, now,
            ),
        )

    def snapshot(
        self,
        program_id: int,
        host: str,
    ) -> dict:
        host = host.lower()
        rows = self.conn.execute(
            """
            SELECT *
            FROM program_requests
            WHERE program_id = ? AND host = ?
            ORDER BY observed_at DESC
            LIMIT 1000
            """,
            (program_id, host),
        ).fetchall()

        pages: dict[str, dict] = {}
        for row in rows:
            key = row["path"]
            item = pages.setdefault(
                key,
                {
                    "path": key,
                    "url": row["url"],
                    "methods": set(),
                    "params": set(),
                    "statuses": set(),
                    "titles": set(),
                    "content_types": set(),
                    "observations": 0,
                    "sessions": set(),
                },
            )
            item["methods"].add(row["method"])
            item["params"].update(json.loads(row["params_json"] or "[]"))
            if row["status_code"] is not None:
                item["statuses"].add(row["status_code"])
            if row["title"]:
                item["titles"].add(row["title"])
            if row["response_content_type"]:
                item["content_types"].add(row["response_content_type"])
            if row["session_id"] is not None:
                item["sessions"].add(int(row["session_id"]))
            item["observations"] += 1

        for item in pages.values():
            item["methods"] = sorted(item["methods"])
            item["params"] = sorted(item["params"])
            item["statuses"] = sorted(item["statuses"])
            item["titles"] = sorted(item["titles"])
            item["content_types"] = sorted(item["content_types"])
            item["sessions"] = sorted(item["sessions"])

        edges = self.conn.execute(
            """
            SELECT source_url, target_url, relation, evidence
            FROM program_edges
            WHERE program_id = ? AND host = ?
            ORDER BY last_seen DESC
            LIMIT 1000
            """,
            (program_id, host),
        ).fetchall()

        candidates = self.conn.execute(
            """
            SELECT vuln_class, url, param, confidence, reason, evidence_json
            FROM program_candidates
            WHERE program_id = ? AND host = ? AND state = 'open'
            ORDER BY confidence DESC, last_seen DESC
            LIMIT 200
            """,
            (program_id, host),
        ).fetchall()

        resource_groups: dict[str, list[str]] = {}
        for item in pages.values():
            parts = [p for p in item["path"].split("/") if p]
            if parts:
                resource_groups.setdefault("/" + parts[0], []).append(item["path"])

        relationships = [dict(row) for row in edges]

        # Shared-parameter relationships are derived from the already loaded
        # snapshot instead of rescanning the whole request table on every event.
        parameter_endpoints: dict[str, set[str]] = {}
        for row in rows:
            for param in json.loads(row["params_json"] or "[]"):
                if str(param).lower() in SENSITIVE_NAMES:
                    continue
                parameter_endpoints.setdefault(str(param), set()).add(row["url"])

        existing_shared = {
            (
                item["source_url"],
                item["target_url"],
                item["relation"],
            )
            for item in relationships
            if item.get("relation") == "shared_parameter"
        }
        for param, endpoints in parameter_endpoints.items():
            if len(endpoints) < 2:
                continue
            ordered = sorted(endpoints)
            anchor = _endpoint_path(ordered[0])
            for target in ordered[1:]:
                target_path = _endpoint_path(target)
                key = (anchor, target_path, "shared_parameter")
                if key in existing_shared:
                    continue
                relationships.append({
                    "source_url": anchor,
                    "target_url": target_path,
                    "relation": "shared_parameter",
                    "evidence": param,
                })
                existing_shared.add(key)

        return {
            "program_id": program_id,
            "host": host,
            "pages": sorted(
                pages.values(),
                key=lambda x: -x["observations"],
            ),
            "resource_groups": {
                key: sorted(set(values))
                for key, values in sorted(resource_groups.items())
            },
            "relationships": relationships,
            "candidates": [
                {
                    "class": row["vuln_class"],
                    "url": row["url"],
                    "param": row["param"],
                    "confidence": float(row["confidence"]),
                    "reason": row["reason"],
                    "evidence": json.loads(row["evidence_json"] or "[]"),
                }
                for row in candidates
            ],
        }

    def program_summary(self, program_id: int) -> dict:
        hosts = self.conn.execute(
            """
            SELECT host,
                   COUNT(*) AS requests,
                   COUNT(DISTINCT path) AS pages,
                   MAX(observed_at) AS last_seen
            FROM program_requests
            WHERE program_id = ?
            GROUP BY host
            ORDER BY last_seen DESC
            """,
            (program_id,),
        ).fetchall()

        recent = self.conn.execute(
            """
            SELECT host, method, path, status_code, observed_at
            FROM program_requests
            WHERE program_id = ?
            ORDER BY observed_at DESC
            LIMIT 150
            """,
            (program_id,),
        ).fetchall()

        return {
            "hosts": [dict(row) for row in hosts],
            "recent_requests": [dict(row) for row in recent],
        }

    def request_count(self, program_id: int, host: str) -> int:
        row = self.conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM program_requests
            WHERE program_id = ? AND host = ?
            """,
            (program_id, host.lower()),
        ).fetchone()
        return int(row["n"])

    def has_open_candidates(self, program_id: int, host: str) -> bool:
        row = self.conn.execute(
            """
            SELECT 1
            FROM program_candidates
            WHERE program_id = ? AND host = ? AND state = 'open'
            LIMIT 1
            """,
            (program_id, host.lower()),
        ).fetchone()
        return row is not None

    def host_summary(self, program_id: int, host: str) -> dict:
        host = host.lower()
        counts = self.conn.execute(
            """
            SELECT COUNT(*) AS requests,
                   COUNT(DISTINCT path) AS pages
            FROM program_requests
            WHERE program_id = ? AND host = ?
            """,
            (program_id, host),
        ).fetchone()
        relationship_count = self.conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM program_edges
            WHERE program_id = ? AND host = ?
            """,
            (program_id, host),
        ).fetchone()["n"]
        candidates = self.conn.execute(
            """
            SELECT vuln_class, url, param, confidence, reason, evidence_json
            FROM program_candidates
            WHERE program_id = ? AND host = ? AND state = 'open'
            ORDER BY confidence DESC, last_seen DESC
            LIMIT 10
            """,
            (program_id, host),
        ).fetchall()

        return {
            "requests": int(counts["requests"] or 0),
            "pages": int(counts["pages"] or 0),
            "relationships": int(relationship_count or 0),
            "candidates": [
                {
                    "class": row["vuln_class"],
                    "url": row["url"],
                    "param": row["param"],
                    "confidence": float(row["confidence"]),
                    "reason": row["reason"],
                    "evidence": json.loads(row["evidence_json"] or "[]"),
                }
                for row in candidates
            ],
        }

    def hosts(self, program_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT host, COUNT(*) AS requests, MAX(observed_at) AS last_seen
            FROM program_requests
            WHERE program_id = ?
            GROUP BY host
            ORDER BY last_seen DESC
            """,
            (program_id,),
        ).fetchall()

        result = []
        seen_hosts = set()

        for row in rows:
            seen_hosts.add(row["host"])
            candidates = self.conn.execute(
                """
                SELECT COUNT(*) AS n
                FROM program_candidates
                WHERE program_id = ? AND host = ? AND state = 'open'
                """,
                (program_id, row["host"]),
            ).fetchone()["n"]
            pages = self.conn.execute(
                """
                SELECT COUNT(DISTINCT path) AS n
                FROM program_requests
                WHERE program_id = ? AND host = ?
                """,
                (program_id, row["host"]),
            ).fetchone()["n"]
            result.append({
                "host": row["host"],
                "requests": int(row["requests"]),
                "pages": int(pages),
                "candidates": int(candidates),
                "last_seen": row["last_seen"],
                "source": "observed_traffic",
            })

        edge_rows = self.conn.execute(
            """
            SELECT target_url, MAX(last_seen) AS last_seen
            FROM program_edges
            WHERE program_id = ?
              AND relation = 'cross_host_reference'
            GROUP BY target_url
            ORDER BY last_seen DESC
            """,
            (program_id,),
        ).fetchall()

        for edge in edge_rows:
            target_host = (urlparse(edge["target_url"]).hostname or "").lower()
            if not target_host or target_host in seen_hosts:
                continue

            seen_hosts.add(target_host)
            result.append({
                "host": target_host,
                "requests": 0,
                "pages": 0,
                "candidates": 0,
                "last_seen": edge["last_seen"],
                "source": "cross_host_reference",
            })

        return result
