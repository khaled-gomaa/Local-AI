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
from recon.common import (
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
    return any(h in low for h in _HINTS)

def ingest(state, title, url, source, published=None, summary="", extra=None):
    url = canonical(url)
    if not url:
        return 0

    previous_id = state["urls"].get(url)
    if previous_id is None and len(state["urls"]) >= MAX_DOCS:
        return 0

    if len(summary) >= 200:
        quick_cat, quick_score, _, _ = classify(title, summary, "")
        if quick_cat == "ignore" and quick_score < 0:
            return 0

    text = extract(url)
    time.sleep(DELAY)
    if not text:
        return 0

    current_id = sha(text)
    if previous_id == current_id:
        print(f"[=] unchanged: {title[:70]}")
        return 0

    record_extra = dict(extra or {})
    if previous_id:
        record_extra["previous_id"] = previous_id
        record_extra["updated"] = True

    rec = append_record(title, url, source, published, text, record_extra)
    if not rec:
        print(f"[~] classified ignore: {title[:70]}")
        return 0

    state["urls"][url] = rec["id"]
    state["hashes"][rec["id"]] = url

    if previous_id:
        print(f"[~] updated {rec['category']:<20} {source}: {title[:70]}")
    else:
        print(f"[+] {rec['category']:<20} {source}: {title[:70]}")
    return 1

def sync_rss(state):
    added = 0
    for source, feed_url in CONFIG["rss"].items():
        try:
            r = session.get(feed_url, timeout=TIMEOUT)
            r.raise_for_status()
            feed = feedparser.parse(r.content)
            print(f"[*] RSS {source}: {len(feed.entries)} entries visible")
            for entry in feed.entries:
                if len(state["urls"]) >= MAX_DOCS and canonical(entry.get("link", "")) not in state["urls"]:
                    break
                title = clean(entry.get("title", ""))
                url = entry.get("link", "")
                summary = clean(entry.get("summary", ""))
                published = entry.get("published", entry.get("updated", ""))
                added += ingest(state, title, url, source, published, summary)
        except Exception as exc:
            print(f"[!] RSS failed {source}: {exc}")
    return added

def discover_sitemaps(home):
    paths = []
    try:
        robots = session.get(urljoin(home, "/robots.txt"), timeout=TIMEOUT)
        if robots.ok:
            for line in robots.text.splitlines():
                if line.lower().startswith("sitemap:"):
                    paths.append(line.split(":", 1)[1].strip())
    except Exception:
        pass

    if not paths:
        paths.append(urljoin(home, "/sitemap.xml"))

    return list(dict.fromkeys(paths))

def sitemap_urls(xml_url, seen_xml=None):
    seen_xml = seen_xml or set()
    if xml_url in seen_xml or len(seen_xml) > MAX_PAGES:
        return []
    seen_xml.add(xml_url)
    try:
        r = session.get(xml_url, timeout=TIMEOUT)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "xml")
        if soup.find("sitemap"):
            urls = []
            for sm in soup.find_all("sitemap"):
                loc = sm.find("loc")
                if loc:
                    urls.extend(sitemap_urls(loc.text.strip(), seen_xml))
            return urls
        return [loc.text.strip() for loc in soup.find_all("loc") if loc.text.strip()]
    except Exception as exc:
        print(f"[!] GET {xml_url}: {exc}")
        return []

def sync_sitemaps(state):
    added = 0
    homes = [x for values in CONFIG["html_indexes"].values() for x in values]
    homes = list(dict.fromkeys(homes))

    for home in homes:
        parsed = urlparse(home)
        if not parsed.scheme or not parsed.netloc:
            print(f"[!] skipping malformed home: {home}")
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"

        for sm in discover_sitemaps(base):
            urls = sitemap_urls(sm)
            print(f"[*] sitemap {sm}: {len(urls)} URLs")
            matched = 0
            for url in urls:
                if not _useful_url(url):
                    continue
                matched += 1
                title = url.rstrip("/").rsplit("/", 1)[-1].replace("-", " ").replace("_", " ")
                added += ingest(state, title, url, "Sitemap archive")
                if len(state["urls"]) >= MAX_DOCS:
                    break
            print(f"[*]   → {matched} passed URL filter")
    return added

def sync_html_indexes(state):
    added = 0
    for source, indexes in CONFIG["html_indexes"].items():
        for index_url in indexes:
            try:
                r = session.get(index_url, timeout=TIMEOUT)
                r.raise_for_status()
                soup = BeautifulSoup(r.text, "html.parser")
                parsed = urlparse(r.url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                seen = set()
                for a in soup.find_all("a", href=True):
                    href = canonical(urljoin(base, a["href"]))
                    if href in seen or not href.startswith(base):
                        continue
                    seen.add(href)
                    anchor = clean(a.get_text(" ", strip=True))
                    if source == "Bugcrowd CrowdStream" and "/disclosures/" not in href:
                        continue
                    if source == "HackerOne Blog" and "/blog/" not in href:
                        continue
                    if source == "Bugcrowd Blog" and "/blog/" not in href:
                        continue
                    if anchor:
                        added += ingest(state, anchor, href, source)
                    if len(state["urls"]) >= MAX_DOCS:
                        break
            except Exception as exc:
                print(f"[!] index failed {source} {index_url}: {exc}")
    return added

def sync_hackerone(state):
    user, token = os.getenv("H1_API_USERNAME"), os.getenv("H1_API_TOKEN")
    if not user or not token:
        print("[*] HackerOne Hacktivity skipped: credentials not set")
        return 0

    endpoint = "https://api.hackerone.com/v1/hackers/hacktivity"
    added = 0

    for page in range(1, H1_MAX_PAGES + 1):
        if len(state["urls"]) >= MAX_DOCS:
            break
        params = {
            "page[number]": page,
            "page[size]": H1_PAGE_SIZE,
            "sort": "-disclosed_at",
            "queryString": "disclosed:true",
        }

        try:
            r = session.get(
                endpoint,
                params=params,
                auth=(user, token),
                headers={"Accept": "application/json"},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            payload = r.json()
        except Exception as exc:
            print(f"[!] HackerOne page {page} failed: {exc}")
            break

        data = payload.get("data", [])
        if not data:
            break

        print(f"[*] HackerOne Hacktivity page {page}: {len(data)} reports")

        for item in data:
            attrs = item.get("attributes", {})
            title, url = attrs.get("title", ""), attrs.get("url")
            if not title or not url:
                continue

            reporter = (
                (item.get("relationships", {}).get("reporter") or {}).get("data") or {}
            ).get("attributes", {}).get("username")
            program = (
                (item.get("relationships", {}).get("program") or {}).get("data") or {}
            ).get("attributes", {}).get("handle")

            extra = {
                "hackerone_id": item.get("id"),
                "severity": attrs.get("severity_rating"),
                "cwe": attrs.get("cwe"),
                "votes": attrs.get("votes"),
                "awarded": attrs.get("total_awarded_amount"),
                "reporter": reporter,
                "program": program,
                "disclosed": attrs.get("disclosed", False),
            }

            summary = attrs.get("vulnerability_information") or (
                f"{title} {program or ''} {attrs.get('cwe') or ''}"
            )
            added += ingest(
                state,
                title,
                url,
                "HackerOne Hacktivity",
                attrs.get("disclosed_at"),
                summary,
                extra,
            )

        if len(data) < H1_PAGE_SIZE:
            break
        time.sleep(1.5)

    return added

def main():
    DATA.mkdir(exist_ok=True)
    state = load_state()
    before = len(state["urls"])

    added = 0
    added += sync_hackerone(state)
    added += sync_rss(state)
    added += sync_html_indexes(state)
    added += sync_sitemaps(state)

    save_state(state)
    print(
        f"[+] Backfill finished. Existing={before}, "
        f"new/updated={added}, total={len(state['urls'])}"
    )

if __name__ == "__main__":
    main()
