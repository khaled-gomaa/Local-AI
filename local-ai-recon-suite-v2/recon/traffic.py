from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from html import unescape
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = Path(os.getenv("RECON_DB_PATH", str(DATA / "recon.db")))

SENSITIVE_NAMES = {
    "password", "passwd", "pwd", "secret", "token", "access_token",
    "refresh_token", "id_token", "authorization", "cookie", "api_key",
    "apikey", "client_secret", "private_key",
}

ID_NAMES = re.compile(
    r"(^|[_-])(id|uid|user|account|profile|order|invoice|tenant|org|project)"
    r"([_-]|$)",
    re.I,
)
URLISH_NAMES = re.compile(
    r"(^|[_-])(url|uri|uri_base|redirect|return|next|continue|dest|destination|"
    r"callback|webhook|link|target|host|endpoint)([_-]|$)",
    re.I,
)
EXPOSURE_PATH = re.compile(
    r"/(?:debug|actuator|swagger|openapi|graphql|graphiql|admin|internal|"
    r"health|metrics|server-status|\.git|\.env|[^/]+\.map)(?:/|$)",
    re.I,
)

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS burp_requests (
    message_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    request_content_type TEXT,
    response_content_type TEXT,
    params_json TEXT NOT NULL DEFAULT '[]',
    signals_json TEXT NOT NULL DEFAULT '[]',
    title TEXT,
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_burp_requests_host ON burp_requests(host, observed_at);
CREATE INDEX IF NOT EXISTS idx_burp_requests_path ON burp_requests(host, path);

CREATE TABLE IF NOT EXISTS burp_edges (
    host TEXT NOT NULL,
    source_url TEXT NOT NULL,
    target_url TEXT NOT NULL,
    relation TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY(host, source_url, target_url, relation)
);
CREATE INDEX IF NOT EXISTS idx_burp_edges_host ON burp_edges(host);

CREATE TABLE IF NOT EXISTS burp_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    UNIQUE(host, url, param, vuln_class)
);
CREATE INDEX IF NOT EXISTS idx_burp_candidates_host ON burp_candidates(host, state);

CREATE TABLE IF NOT EXISTS burp_insights (
    host TEXT PRIMARY KEY,
    snapshot_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    generated_at TEXT NOT NULL
);
"""

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _hash(value: str) -> str:
    return sha256(value.encode("utf-8", "ignore")).hexdigest()

def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()

def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _endpoint_path(url: str) -> str:
    p = urlparse(url)
    return p.path or "/"

def _content_type(headers: str | None) -> str:
    if not headers:
        return ""
    match = re.search(r"(?im)^content-type:\s*([^;\r\n]+)", headers)
    return match.group(1).strip().lower() if match else ""

def _header(headers: str | None, name: str) -> str:
    if not headers:
        return ""
    match = re.search(rf"(?im)^{re.escape(name)}:\s*([^\r\n]+)", headers)
    return match.group(1).strip() if match else ""

def _request_parts(raw: str) -> tuple[str, str, str, str]:
    lines = raw.replace("\r\n", "\n").split("\n")
    first = lines[0] if lines else ""
    m = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?", first, re.I)
    method = m.group(1).upper() if m else "GET"
    target = m.group(2) if m else "/"
    headers_end = next((i for i, line in enumerate(lines) if line == ""), len(lines))
    headers = "\n".join(lines[1:headers_end])
    body = "\n".join(lines[headers_end + 1:]) if headers_end < len(lines) else ""
    host = _header(headers, "Host")
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        scheme = "https" if _header(headers, "X-Forwarded-Proto").lower() == "https" else "https"
        url = f"{scheme}://{host}{target}" if host else target
    return method, url, headers, body

def _response_parts(raw: str) -> tuple[int | None, str, str]:
    lines = raw.replace("\r\n", "\n").split("\n")
    first = lines[0] if lines else ""
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first, re.I)
    status = int(m.group(1)) if m else None
    headers_end = next((i for i, line in enumerate(lines) if line == ""), len(lines))
    headers = "\n".join(lines[1:headers_end])
    body = "\n".join(lines[headers_end + 1:]) if headers_end < len(lines) else ""
    return status, headers, body

def _body_param_names(body: str, content_type: str) -> list[str]:
    if not body:
        return []
    names: list[str] = []
    if "application/x-www-form-urlencoded" in content_type:
        names = [k for k, _ in parse_qsl(body[:65536], keep_blank_values=True)]
    elif "application/json" in content_type:
        try:
            obj = json.loads(body[:65536])
            def walk(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        names.append(str(key))
                        walk(child)
                elif isinstance(value, list):
                    for child in value:
                        walk(child)
            walk(obj)
        except (ValueError, TypeError):
            pass
    return names

def _extract_links(base_url: str, body: str, content_type: str) -> list[tuple[str, str]]:
    if not body:
        return []
    text = body[:131072]
    links: list[tuple[str, str]] = []

    if "html" in content_type:
        soup = BeautifulSoup(text, "html.parser")
        for tag, attr, relation in (
            ("a", "href", "link"),
            ("script", "src", "script"),
            ("link", "href", "resource"),
            ("form", "action", "form"),
        ):
            for node in soup.find_all(tag, **{"attrs": {attr: True}}):
                value = str(node.get(attr, "")).strip()
                if value:
                    links.append((urljoin(base_url, unescape(value)), relation))
    else:
        for match in re.finditer(r"""["']((?:/|https?://)[^"'\s]{1,300})["']""", text):
            links.append((urljoin(base_url, match.group(1)), "discovered"))

    location = re.search(r"(?im)^location:\s*([^\r\n]+)", text)
    if location:
        links.append((urljoin(base_url, location.group(1).strip()), "redirect"))

    return links

def _parameter_signals(params: list[str], path: str) -> list[dict]:
    results = []
    unique = sorted({p for p in params if p})
    for param in unique:
        low = param.lower()
        if low in SENSITIVE_NAMES:
            continue
        if URLISH_NAMES.search(low):
            results.append({
                "class": "open-redirect_or_ssrf_candidate",
                "param": param,
                "confidence": 0.58,
                "reason": "URL/redirect-like parameter observed",
            })
        if ID_NAMES.search(low):
            results.append({
                "class": "idor_candidate",
                "param": param,
                "confidence": 0.52,
                "reason": "Object/user/tenant-like identifier observed",
            })
    if EXPOSURE_PATH.search(path):
        results.append({
            "class": "sensitive_endpoint_candidate",
            "param": None,
            "confidence": 0.68,
            "reason": "Path resembles a debug/schema/admin/internal or source-map endpoint",
        })
    return results

def _security_signals(request_headers: str, response_headers: str, response_body: str, params: list[str]) -> list[dict]:
    results = []
    acao = _header(response_headers, "Access-Control-Allow-Origin")
    acac = _header(response_headers, "Access-Control-Allow-Credentials")
    if acao == "*" and acac.lower() == "true":
        results.append({
            "class": "cors_candidate",
            "confidence": 0.72,
            "reason": "Wildcard ACAO observed together with credentialed CORS",
        })

    for param in params:
        low = param.lower()
        if low in SENSITIVE_NAMES:
            continue
        # Passive reflection signal only; values are not persisted.
        token_pattern = re.compile(rf"[?&]{re.escape(param)}=([^&#\s]+)", re.I)
        match = token_pattern.search(request_headers)
        if match:
            value = match.group(1)
            if 3 <= len(value) <= 80 and value.lower() in response_body.lower():
                results.append({
                    "class": "reflection_xss_candidate",
                    "param": param,
                    "confidence": 0.45,
                    "reason": "A non-sensitive parameter value appears reflected in the response",
                })
    return results

class TrafficStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def observe(self, event: dict) -> str:
        request_raw = str(event.get("request") or "")
        response_raw = str(event.get("response") or "")
        message_id = str(event.get("message_id") or _hash(request_raw + response_raw)[:24])

        method, url, request_headers, request_body = _request_parts(request_raw)
        explicit_url = str(event.get("url") or "")
        if explicit_url:
            url = explicit_url

        host = _host(url)
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
            + _security_signals(request_headers, response_headers, response_body, params)
        )

        title = ""
        if "html" in response_type:
            match = re.search(r"(?is)<title[^>]*>(.*?)</title>", response_body[:65536])
            if match:
                title = BeautifulSoup(match.group(1), "html.parser").get_text(" ", strip=True)[:300]

        now = _now()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO burp_requests(
                message_id, host, method, url, path, status_code,
                request_content_type, response_content_type,
                params_json, signals_json, title, observed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id, host, method, url, _endpoint_path(url), status_code,
                request_type, response_type, json.dumps(params, ensure_ascii=False),
                json.dumps(signals, ensure_ascii=False), title, now,
            ),
        )

        source_url = url
        for target, relation in _extract_links(url, response_body, response_type):
            target_host = _host(target)
            if target_host != host:
                continue
            target = _origin(target) + (_endpoint_path(target) or "/")
            source = _origin(source_url) + (_endpoint_path(source_url) or "/")
            self.conn.execute(
                """
                INSERT INTO burp_edges(host, source_url, target_url, relation, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host, source_url, target_url, relation)
                DO UPDATE SET last_seen = excluded.last_seen
                """,
                (host, source, target, relation, now, now),
            )

        # Infer relationships between endpoints that reuse the same parameter names.
        # This is passive graph enrichment; no additional requests are sent.
        parameter_endpoints: dict[str, set[str]] = {}
        for row in self.conn.execute(
            "SELECT url, params_json FROM burp_requests WHERE host = ?",
            (host,),
        ).fetchall():
            for param in json.loads(row["params_json"] or "[]"):
                parameter_endpoints.setdefault(str(param), set()).add(row["url"])

        for param, urls in parameter_endpoints.items():
            if len(urls) < 2 or param in SENSITIVE_NAMES:
                continue
            ordered = sorted(urls)
            anchor = ordered[0]
            for target in ordered[1:]:
                self.conn.execute(
                    """
                    INSERT INTO burp_edges(
                        host, source_url, target_url, relation, first_seen, last_seen
                    )
                    VALUES (?, ?, ?, 'shared_parameter:' || ?, ?, ?)
                    ON CONFLICT(host, source_url, target_url, relation)
                    DO UPDATE SET last_seen = excluded.last_seen
                    """,
                    (host, anchor, target, param, now, now),
                )

        for signal in signals:
            self.conn.execute(
                """
                INSERT INTO burp_candidates(
                    host, url, param, vuln_class, confidence,
                    reason, evidence_json, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host, url, param, vuln_class)
                DO UPDATE SET
                    confidence = MAX(burp_candidates.confidence, excluded.confidence),
                    reason = excluded.reason,
                    evidence_json = excluded.evidence_json,
                    last_seen = excluded.last_seen
                """,
                (
                    host, url, signal.get("param"), signal["class"],
                    float(signal["confidence"]), signal["reason"],
                    json.dumps([f"{method} {url}", f"status={status_code}"], ensure_ascii=False),
                    now, now,
                ),
            )

        self.conn.commit()
        return host

    def snapshot(self, host: str) -> dict:
        host = host.lower()
        rows = self.conn.execute(
            """
            SELECT * FROM burp_requests
            WHERE host = ?
            ORDER BY observed_at DESC
            LIMIT 500
            """,
            (host,),
        ).fetchall()

        pages = {}
        for row in rows:
            key = row["path"]
            item = pages.setdefault(key, {
                "path": key,
                "url": row["url"],
                "methods": set(),
                "params": set(),
                "statuses": set(),
                "titles": set(),
                "content_types": set(),
                "observations": 0,
            })
            item["methods"].add(row["method"])
            item["params"].update(json.loads(row["params_json"] or "[]"))
            if row["status_code"] is not None:
                item["statuses"].add(row["status_code"])
            if row["title"]:
                item["titles"].add(row["title"])
            if row["response_content_type"]:
                item["content_types"].add(row["response_content_type"])
            item["observations"] += 1

        for item in pages.values():
            for key in ("methods", "params", "statuses", "titles", "content_types"):
                item[key] = sorted(item[key])

        edge_rows = self.conn.execute(
            """
            SELECT source_url, target_url, relation
            FROM burp_edges WHERE host = ?
            ORDER BY last_seen DESC LIMIT 500
            """,
            (host,),
        ).fetchall()

        candidates = self.conn.execute(
            """
            SELECT vuln_class, url, param, confidence, reason, evidence_json
            FROM burp_candidates
            WHERE host = ? AND state = 'open'
            ORDER BY confidence DESC, last_seen DESC
            LIMIT 100
            """,
            (host,),
        ).fetchall()

        # Resource hints from path structure, useful to the explainer when several
        # endpoints belong to the same resource family.
        resource_groups: dict[str, list[str]] = {}
        for item in pages.values():
            parts = [p for p in item["path"].split("/") if p]
            if parts:
                family = "/" + parts[0]
                resource_groups.setdefault(family, []).append(item["path"])

        return {
            "host": host,
            "pages": sorted(pages.values(), key=lambda x: -x["observations"]),
            "resource_groups": {
                key: sorted(set(values))
                for key, values in sorted(resource_groups.items())
            },
            "relationships": [dict(row) for row in edge_rows],
            "candidates": [
                {
                    "class": row["vuln_class"],
                    "url": row["url"],
                    "param": row["param"],
                    "confidence": row["confidence"],
                    "reason": row["reason"],
                    "evidence": json.loads(row["evidence_json"] or "[]"),
                }
                for row in candidates
            ],
        }

    def hosts(self) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT host, COUNT(*) AS requests, MAX(observed_at) AS last_seen
            FROM burp_requests
            GROUP BY host
            ORDER BY last_seen DESC
            LIMIT 50
            """
        ).fetchall()

        out = []
        for row in rows:
            candidate_count = self.conn.execute(
                "SELECT COUNT(*) FROM burp_candidates WHERE host = ? AND state = 'open'",
                (row["host"],),
            ).fetchone()[0]
            page_count = self.conn.execute(
                "SELECT COUNT(DISTINCT path) FROM burp_requests WHERE host = ?",
                (row["host"],),
            ).fetchone()[0]
            out.append({
                "host": row["host"],
                "requests": int(row["requests"]),
                "pages": int(page_count),
                "candidates": int(candidate_count),
                "last_seen": row["last_seen"],
            })
        return out

    def save_insight(self, host: str, snapshot: dict, result: dict) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True)
        fingerprint = _hash(json.dumps(snapshot, ensure_ascii=False, sort_keys=True))
        self.conn.execute(
            """
            INSERT INTO burp_insights(host, snapshot_hash, result_json, generated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                snapshot_hash = excluded.snapshot_hash,
                result_json = excluded.result_json,
                generated_at = excluded.generated_at
            """,
            (host, fingerprint, payload, _now()),
        )
        self.conn.commit()

    def latest_insight(self, host: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM burp_insights WHERE host = ?",
            (host,),
        ).fetchone()
        if not row:
            return None
        result = json.loads(row["result_json"])
        result["generated_at"] = row["generated_at"]
        return result
