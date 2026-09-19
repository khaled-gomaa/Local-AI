from __future__ import annotations
import hashlib, json, os, re, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests, trafilatura
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
DOCS = DATA / "recon_documents.jsonl"
CHUNKS = DATA / "recon_chunks.jsonl"
STATE = DATA / "state.json"

UA = "LocalAIReconSuite/2.0 (public technical content collector)"
TIMEOUT = int(os.getenv("RECON_TIMEOUT", "25"))
DELAY = float(os.getenv("RECON_DELAY", "0.7"))
MIN_SCORE = int(os.getenv("RECON_MIN_SCORE", "12"))

session = requests.Session()
session.headers.update({"User-Agent": UA})

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
    "graphql discovery": 8, "web application testing": 5
}

NEGATIVE = {
    "company culture": 18, "company values": 18, "hiring": 15,
    "career": 15, "funding": 15, "partnership": 15, "press release": 18,
    "webinar": 12, "conference": 10, "event": 9, "award": 12,
    "winner": 12, "milestone": 12, "thanksgiving": 15, "hall of fame": 12,
    "community spotlight": 12, "program launch": 12, "bug bounty program": 8,
    "customer story": 15, "quarterly": 10, "year in review": 10
}

def clean(s: str) -> str:
    return re.sub(r"\s+", " ", BeautifulSoup(s or "", "html.parser").get_text(" ", strip=True)).strip()

def canonical(url: str) -> str:
    p = urlparse(url)
    return p._replace(query="", fragment="").geturl().rstrip("/")

def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

def score_text(title: str, summary: str = "", text: str = ""):
    hay = f"{title}\n{summary}\n{text[:30000]}".lower()
    positives = {k:v for k,v in TERMS.items() if k in hay}
    negatives = {k:v for k,v in NEGATIVE.items() if k in hay}
    score = sum(positives.values()) - sum(negatives.values()) * 0.55
    categories = []
    if any(k in hay for k in ("recon","reconnaissance","attack surface","asset discovery","subdomain")):
        categories.append("recon")
    if any(k in hay for k in ("endpoint discovery","api discovery","parameter discovery","web application testing")):
        categories.append("web_security")
    if any(k in hay for k in ("security automation","scanner development","crawler development","burp extension","burp montoya")):
        categories.append("tooling_development")
    if "hackerone" in hay or "bugcrowd" in hay or "disclosure" in hay:
        categories.append("public_disclosures")
    return round(score, 2), sorted(set(categories)), list(positives)

def classify(title, summary="", text=""):
    score, cats, keywords = score_text(title, summary, text)
    if score < MIN_SCORE:
        return "ignore", score, cats, keywords
    # Priority: disclosures keep their own collection; multi-category content goes to primary category.
    if "public_disclosures" in cats and score >= 8:
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
        return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"urls": {}, "hashes": {}, "updated_at": None}

def save_state(state):
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def extract(url):
    try:
        raw = trafilatura.fetch_url(url, no_ssl=False)
        if not raw:
            return None
        text = trafilatura.extract(raw, include_comments=False, include_tables=True,
                                   favor_precision=True, deduplicate=True)
        if text and len(text) >= 1000:
            return text.strip()
    except Exception as exc:
        print(f"[!] extract failed: {url}: {exc}")
    return None

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
    doc_id = sha(text)
    if any(rec.get("id") == doc_id for rec in []):
        return None
    rec = {
        "id": doc_id, "title": title, "url": canonical(url), "source": source,
        "published": published or datetime.now(timezone.utc).isoformat(),
        "category": category, "score": score, "topics": cats, "keywords": keywords,
        "word_count": len(text.split()), "text": text
    }
    if extra:
        rec.update(extra)
    with DOCS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with CHUNKS.open("a", encoding="utf-8") as f:
        for i, chunk in enumerate(chunks(text), 1):
            row = {
                "id": f"{doc_id[:16]}-{i}", "doc_id": doc_id, "rank": 0,
                "title": title, "url": canonical(url), "source": source,
                "published": rec["published"], "category": category,
                "score": score, "topics": cats, "keywords": keywords, "text": chunk
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rec
