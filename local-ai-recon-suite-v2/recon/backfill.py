from __future__ import annotations
import json, os, re, sys, time
from pathlib import Path
from urllib.parse import urljoin
import feedparser
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon.common import (
    session, TIMEOUT, DELAY, DATA, load_state, save_state, canonical,
    clean, extract, append_record, classify
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8"))
MAX_DOCS = int(os.getenv("RECON_BACKFILL_MAX_DOCS", "10000"))
MAX_PAGES = int(os.getenv("RECON_BACKFILL_MAX_PAGES", "200"))
H1_MAX_PAGES = int(os.getenv("H1_MAX_PAGES", "100"))
H1_PAGE_SIZE = min(int(os.getenv("H1_PAGE_SIZE", "100")), 100)

def already(state, url):
    return canonical(url) in state["urls"]

def ingest(state, title, url, source, published=None, summary="", extra=None):
    url = canonical(url)
    if not url or already(state, url) or len(state["urls"]) >= MAX_DOCS:
        return 0
    quick_cat, quick_score, _, _ = classify(title, summary, "")
    # Public disclosure sources are allowed through to full extraction.
    if quick_cat == "ignore" and source not in ("HackerOne Hacktivity", "Bugcrowd Public Disclosure"):
        return 0
    text = extract(url)
    time.sleep(DELAY)
    if not text:
        return 0
    rec = append_record(title, url, source, published, text, extra)
    if rec:
        state["urls"][url] = rec["id"]
        state["hashes"][rec["id"]] = url
        print(f"[+] {rec['category']:<20} {source}: {title}")
        return 1
    return 0

def sync_rss(state):
    added = 0
    for source, feed_url in CONFIG["rss"].items():
        try:
            r = session.get(feed_url, timeout=TIMEOUT)
            r.raise_for_status()
            feed = feedparser.parse(r.content)
            print(f"[*] RSS {source}: {len(feed.entries)} entries visible")
            for entry in feed.entries:
                if len(state["urls"]) >= MAX_DOCS:
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
    for p in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"):
        paths.append(urljoin(home, p))
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
    for home in homes:
        parsed = urlparse(home)
        if not parsed.scheme or not parsed.netloc:
            print(f"[!] skipping malformed home: {home}")
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        for sm in discover_sitemaps(base):
            urls = sitemap_urls(sm)
            print(f"[*] sitemap {sm}: {len(urls)} URLs")
            for url in urls:
                if len(state["urls"]) >= MAX_DOCS:
                    break
                # Avoid blindly ingesting every page; require URL hints first.
                low = url.lower()
                hints = ("blog", "research", "disclosure", "report", "security", "recon",
                         "subdomain", "api", "web", "vulnerability")
                if not any(h in low for h in hints):
                    continue
                title = low.rsplit("/", 1)[-1].replace("-", " ").replace("_", " ")
                added += ingest(state, title, url, "Sitemap archive")
    return added

def sync_html_indexes(state):
    added = 0
    for source, indexes in CONFIG["html_indexes"].items():
        for index_url in indexes:
            try:
                r = session.get(index_url, timeout=TIMEOUT)
                r.raise_for_status()
                soup = BeautifulSoup(r.text, "html.parser")
                base = f"{r.url.split('/')[0]}//{r.url.split('/')[2]}"
                seen = set()
                for a in soup.find_all("a", href=True):
                    href = canonical(urljoin(base, a["href"]))
                    if href in seen:
                        continue
                    seen.add(href)
                    anchor = clean(a.get_text(" ", strip=True))
                    if not href.startswith(base):
                        continue
                    if source == "Bugcrowd CrowdStream" and "/disclosures/" not in href:
                        continue
                    if source == "HackerOne Blog" and "/blog/" not in href:
                        continue
                    if source == "Bugcrowd Blog" and "/blog/" not in href:
                        continue
                    if anchor:
                        added += ingest(state, anchor, href, source)
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
            "queryString": "disclosed:true"
        }
        try:
            r = session.get(endpoint, params=params, auth=(user, token),
                            headers={"Accept":"application/json"}, timeout=TIMEOUT)
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
            title, url = attrs.get("title",""), attrs.get("url")
            if not title or not url:
                continue
            reporter = ((item.get("relationships", {}).get("reporter") or {}).get("data") or {}).get("attributes", {}).get("username")
            program = ((item.get("relationships", {}).get("program") or {}).get("data") or {}).get("attributes", {}).get("handle")
            extra = {
                "hackerone_id": item.get("id"),
                "severity": attrs.get("severity_rating"),
                "cwe": attrs.get("cwe"),
                "votes": attrs.get("votes"),
                "awarded": attrs.get("total_awarded_amount"),
                "reporter": reporter,
                "program": program,
                "disclosed": attrs.get("disclosed", False)
            }
            # Local classifier decides whether the report is useful to Recon / web security.
            summary = attrs.get("vulnerability_information") or title
            added += ingest(state, title, url, "HackerOne Hacktivity",
                            attrs.get("disclosed_at"), summary, extra)
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
    print(f"[+] Backfill finished. Existing={before}, new={added}, total={len(state['urls'])}")

if __name__ == "__main__":
    main()
