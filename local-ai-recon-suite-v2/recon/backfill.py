from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import feedparser
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon.state_store import ReconStore\nfrom recon.common import (
    DATA,
    DELAY,
    TIMEOUT,
    append_record,
    canonical,
    classify,
    clean,
    extract,
    load_state,
    save_state,
    session,
    sha,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8"))
MAX_DOCS = int(os.getenv("RECON_BACKFILL_MAX_DOCS", "10000"))
MAX_PAGES = int(os.getenv("RECON_BACKFILL_MAX_PAGES", "200"))
H1_MAX_PAGES = int(os.getenv("H1_MAX_PAGES", "100"))
H1_PAGE_SIZE = min(int(os.getenv("H1_PAGE_SIZE", "100")), 100)

_BLOCK = (
    "/legal", "/privacy", "/terms", "/cookie", "/careers", "/jobs",
    "/pricing", "/contact", "/about", "/login", "/signup",
    "/tag/", "/author/", "/category/", "/page/",
)
_HINTS = (
    "blog", "research", "disclosure", "report", "writeup", "advisory",
    "security", "recon", "subdomain", "api", "vulnerability", "cve",
    "bug-bounty", "hacktivity", "case-study", "attack-surface", "exploit",
)

def _useful_url(url: str) -> bool:
    low = url.lower()
    if any(b in low for b in _BLOCK):
        return False
def ingest(store, title, url, source, published=None, summary="", extra=None):
    url = canonical(url)
    if not url:
        return "failed"

    if len(summary) >= 200:
        quick_cat, quick_score, _, _ = classify(title, summary, "")
        if quick_cat == "ignore" and quick_score < 0:
            return "ignored"

    text = extract(url)
    time.sleep(DELAY)
    if not text:
        return "failed"

    current_id = sha(text)
    rec = append_record(title, url, source, published, text, extra)
    if not rec:
        return "ignored"

    outcome = store.upsert_document(
        url=url,
        content_hash=current_id,
        record_id=rec["id"],
        title=title,
        source=source,
        published=rec.get("published"),
        category=rec["category"],
        score=float(rec.get("score", 0)),
    )

    if outcome == "unchanged":
        print(f"[=] unchanged: {title[:70]}")
    elif outcome == "updated":
        print(f"[~] updated {rec['category']:<20} {source}: {title[:70]}")
    else:
        print(f"[+] {rec['category']:<20} {source}: {title[:70]}")
    return outcome
def main():
    DATA.mkdir(exist_ok=True)
    with ReconStore() as store:
        run_id = store.begin_run("backfill")
        counters = {"seen": 0, "added": 0, "updated": 0, "unchanged": 0, "failed": 0}
        try:
            for sync in (sync_hackerone, sync_rss, sync_html_indexes, sync_sitemaps):
                # Sync functions return the number of successfully written records.
                counters["added"] += sync(store)
            store.finish_run(run_id, **{
                "items_seen": counters["seen"],
                "items_added": counters["added"],
                "items_updated": counters["updated"],
                "items_unchanged": counters["unchanged"],
                "items_failed": counters["failed"],
            })
            print(f"[+] Backfill finished. Documents={store.count_documents()}")
        except Exception:
            store.finish_run(run_id, **{
                "items_seen": counters["seen"],
                "items_added": counters["added"],
                "items_updated": counters["updated"],
                "items_unchanged": counters["unchanged"],
                "items_failed": counters["failed"] + 1,
            })
            raise

if __name__ == "__main__":
    main()
