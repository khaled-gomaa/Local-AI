from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import trafilatura
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DOCS = DATA / "recon_documents.jsonl"
CHUNKS = DATA / "recon_chunks.jsonl"
STATE = DATA / "state.json"

TIMEOUT = int(os.getenv("RECON_TIMEOUT", "25"))
DELAY = float(os.getenv("RECON_DELAY", "0.7"))
MIN_SCORE = int(os.getenv("RECON_MIN_SCORE", "8"))
MIN_TEXT_CHARS = int(os.getenv("RECON_MIN_TEXT_CHARS", "400"))

session = requests.Session()
_retry = Retry(
    total=int(os.getenv("RECON_HTTP_RETRIES", "3")),
    connect=int(os.getenv("RECON_HTTP_CONNECT_RETRIES", "3")),
    read=int(os.getenv("RECON_HTTP_READ_RETRIES", "2")),
    status=int(os.getenv("RECON_HTTP_STATUS_RETRIES", "3")),
    backoff_factor=float(os.getenv("RECON_HTTP_BACKOFF", "0.8")),
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset({"GET", "HEAD"}),
    respect_retry_after_header=True,
)
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=8, pool_maxsize=16)
session.mount("http://", _adapter)
session.mount("https://", _adapter)
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
})

TERMS = {
    "recon": 10, "reconnaissance": 10, "passive reconnaissance": 12,
    "active reconnaissance": 10, "attack surface": 12,
    "attack surface mapping": 14, "asset discovery": 14,
    "asset inventory": 10, "external attack surface": 14,
    "subdomain": 9, "subdomain enumeration": 14, "subdomain takeover": 12,
    "dns enumeration": 12, "certificate transparency": 12, "ct logs": 10,
    "host discovery": 10, "service discovery": 10, "port discovery": 10,
    "port scanning": 8, "endpoint discovery": 12, "endpoint enumeration": 12,
    "content discovery": 10, "directory discovery": 10, "url discovery": 12,
    "parameter discovery": 10, "javascript reconnaissance": 12,
    "technology fingerprinting": 10, "web fingerprinting": 10,
    "virtual host discovery": 12, "cloud asset discovery": 12,
    "cloud enumeration": 10, "osint": 8, "github reconnaissance": 10,
    "dorking": 7, "wayback": 7, "httpx": 8, "subfinder": 10, "naabu": 8,
    "nuclei": 7, "amass": 9, "assetfinder": 8, "katana": 8, "dnsx": 8,
    "gau": 7, "ffuf": 7, "feroxbuster": 7, "hakrawler": 8,
    "crawler": 5, "security automation": 7, "recon automation": 12,
    "scanner development": 10, "crawler development": 10, "burp extension": 8,
    "burp montoya": 10, "burp api": 8, "python security": 6,
    "go security": 6, "api discovery": 12, "api enumeration": 12,
    "graphql discovery": 8, "web application testing": 5,
}

NEGATIVE = {
    "company culture": 18, "company values": 18, "hiring": 15,
    "career": 15, "funding": 15, "partnership": 15, "press release": 18,
    "webinar": 12, "conference": 10, "event": 9, "award": 12,
    "winner": 12, "milestone": 12, "thanksgiving": 15, "hall of fame": 12,
    "community spotlight": 12, "program launch": 12, "bug bounty program": 8,
    "customer story": 15, "quarterly": 10, "year in review": 10,
}

def clean(s: str) -> str:
    return re.sub(r"\s+", " ", BeautifulSoup(s or "", "html.parser").get_text(" ", strip=True)).strip()

def canonical(url: str) -> str:
    p = urlparse(url)
    return p._replace(query="", fragment="").geturl().rstrip("/")

def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

def has_term(text: str, term: str) -> bool:
    pattern = rf"(?<!\w){re.escape(term)}(?!\w)"
    return re.search(pattern, text, re.IGNORECASE) is not None

def score_text(title: str, summary: str = "", text: str = ""):
    hay = f"{title}\n{summary}\n{text[:30000]}"
    positives = {k: v for k, v in TERMS.items() if has_term(hay, k)}
    negatives = {k: v for k, v in NEGATIVE.items() if has_term(hay, k)}
    score = sum(positives.values()) - sum(negatives.values()) * 0.55
    categories = []
    if any(has_term(hay, k) for k in ("recon", "reconnaissance", "attack surface", "asset discovery", "subdomain")):
        categories.append("recon")
    if any(has_term(hay, k) for k in ("endpoint discovery", "api discovery", "parameter discovery", "web application testing")):
        categories.append("web_security")
    if any(has_term(hay, k) for k in ("security automation", "scanner development", "crawler development", "burp extension", "burp montoya")):
        categories.append("tooling_development")
    if any(has_term(hay, k) for k in ("hackerone", "bugcrowd", "disclosure")):
        categories.append("public_disclosures")
    return round(score, 2), sorted(set(categories)), list(positives)

def classify(title, summary="", text=""):
    score, cats, keywords = score_text(title, summary, text)
    if score < MIN_SCORE:
        return "ignore", score, cats, keywords
    if "public_disclosures" in cats and score >= 6:
        category = "public_disclosures"
    elif "recon" in cats:
        category = "recon"
    elif "tooling_development" in cats:
        category = "tooling_development"
    elif "web_security" in cats:
        category = "web_security"
    else:
        category = "ignore"
    return category, score, cats, keywords

def load_state():
    if not STATE.exists():
        return {"urls": {}, "hashes": {}, "updated_at": None}
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("state root must be an object")
        data.setdefault("urls", {})
        data.setdefault("hashes", {})
        data.setdefault("updated_at", None)
        return data
    except Exception:
        return {"urls": {}, "hashes": {}, "updated_at": None}

def save_state(state):
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(STATE)

def extract(url: str) -> str | None:
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as exc:
        print(f"[!] fetch failed: {url}: {exc}")
        return None

    if r.status_code >= 400:
        print(f"[!] fetch HTTP {r.status_code}: {url}")
        return None

    try:
        text = trafilatura.extract(
            r.text,
            url=url,
            include_comments=False,
            include_tables=True,
            favor_precision=True,
            deduplicate=True,
        )
    except Exception as exc:
        print(f"[!] trafilatura error: {url}: {exc}")
        return None

    if not text:
        print(f"[~] extract empty: {url}")
        return None
    if len(text) < MIN_TEXT_CHARS:
        print(f"[~] extract short ({len(text)}): {url}")
        return None
    return text.strip()

def chunks(text, size=1200, overlap=180):
    words = text.split()
    i = 0
    while i < len(words):
        j = min(len(words), i + size)
        yield " ".join(words[i:j])
        if j >= len(words):
            break
        i = max(0, j - overlap)

def append_record(title, url, source, published, text, extra=None):
    category, score, cats, keywords = classify(title, "", text)
    if category == "ignore":
        return None

    canon_url = canonical(url)
    content_hash = sha(text)
    # Versioned, URL-scoped record ID. This avoids cross-URL chunk collisions
    # when two pages contain identical text.
    doc_id = f"{sha(canon_url)[:16]}-{content_hash[:16]}"
    rec = {
        "id": doc_id,
        "content_hash": content_hash,
        "title": title,
        "url": canon_url,
        "source": source,
        "published": published or datetime.now(timezone.utc).isoformat(),
        "category": category,
        "score": score,
        "topics": cats,
        "keywords": keywords,
        "word_count": len(text.split()),
        "text": text,
    }
    if extra:
        rec.update(extra)

    with DOCS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    with CHUNKS.open("a", encoding="utf-8") as f:
        for i, chunk in enumerate(chunks(text), 1):
            row = {
                "id": f"{doc_id}-{i}",
                "doc_id": doc_id,
                "rank": i,
                "title": title,
                "url": canon_url,
                "source": source,
                "published": rec["published"],
                "category": category,
                "score": score,
                "keywords": keywords,
                "text": chunk,
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rec
