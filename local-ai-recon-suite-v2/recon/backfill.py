from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
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
    session,
    sha,
)
from recon.state_store import ReconStore

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8"))
MAX_DOCS = int(os.getenv("RECON_BACKFILL_MAX_DOCS", "10000"))
MAX_PAGES = int(os.getenv("RECON_BACKFILL_MAX_PAGES", "200"))
H1_MAX_PAGES = int(os.getenv("H1_MAX_PAGES", "100"))
H1_PAGE_SIZE = min(int(os.getenv("H1_PAGE_SIZE", "100")), 100)
BACKFILL_WORKERS = max(1, int(os.getenv("RECON_BACKFILL_WORKERS", "6")))

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
    if any(block in low for block in _BLOCK):
        return False
    return any(hint in low for hint in _HINTS)

def _fetch_item(item: tuple) -> tuple[tuple, str | None]:
    """
    Fetch/extract content concurrently. Database and append-only file writes remain
    on the caller thread so SQLite/JSONL state stays serialized and deterministic.
    """
    try:
        text = extract(item[1])
        if DELAY > 0:
            time.sleep(DELAY)
        return item, text
    except Exception as exc:
        print(f"[!] fetch failed: {item[1]}: {exc}")
        return item, None


def ingest_batch(
    store: ReconStore,
    items: list[tuple],
) -> dict[str, int]:
    stats = {k: 0 for k in ("seen", "added", "updated", "unchanged", "failed")}
    if not items:
        return stats

    with ThreadPoolExecutor(
        max_workers=BACKFILL_WORKERS,
        thread_name_prefix="backfill-fetch",
    ) as pool:
        fetched = pool.map(_fetch_item, items)

        for item, text in fetched:
            title, url, source, published, summary, extra = item
            stats["seen"] += 1
            outcome = ingest(
                store,
                title,
                url,
                source,
                published,
                summary,
                extra,
                text=text,
            )
            if outcome in stats:
                stats[outcome] += 1

    return stats


def ingest(
    store: ReconStore,
    title: str,
    url: str,
    source: str,
    published: str | None = None,
    summary: str = "",
    extra: dict | None = None,
    text: str | None = None,
) -> str:
    url = canonical(url)
    if not url:
        return "failed"

    current = store.get(url)
    is_new = current is None
    if is_new and store.count_documents() >= MAX_DOCS:
        return "ignored"

    if len(summary) >= 200:
        quick_cat, quick_score, _, _ = classify(title, summary, "")
        if quick_cat == "ignore" and quick_score < 0:
            return "ignored"

    if text is None:
        text = extract(url)
        if DELAY > 0:
            time.sleep(DELAY)
    if not text:
        return "failed"

    current_id = sha(text)

    if current is not None and current["content_hash"] == current_id:
        print(f"[=] unchanged: {title[:70]}")
        store.touch(url)
        return "unchanged"

    record_extra = dict(extra or {})
    if current is not None:
        record_extra["previous_id"] = current["record_id"]
        record_extra["updated"] = True

    rec = append_record(title, url, source, published, text, record_extra)
    if not rec:
        print(f"[~] classified ignore: {title[:70]}")
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

    if outcome == "updated":
        print(f"[~] updated {rec['category']:<20} {source}: {title[:70]}")
    else:
        print(f"[+] {rec['category']:<20} {source}: {title[:70]}")
    return outcome

def sync_rss(store: ReconStore) -> dict[str, int]:
    stats = {k: 0 for k in ("seen", "added", "updated", "unchanged", "failed")}
    for source, feed_url in CONFIG["rss"].items():
        try:
            response = session.get(feed_url, timeout=TIMEOUT)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            print(f"[*] RSS {source}: {len(feed.entries)} entries visible")

            items = []
            for entry in feed.entries:
                url = entry.get("link", "")
                if not url:
                    continue
                title = clean(entry.get("title", ""))
                summary = clean(entry.get("summary", ""))
                published = entry.get("published", entry.get("updated", ""))
                items.append((title, url, source, published, summary, None))

            part = ingest_batch(store, items)
            _merge_stats(stats, part)
        except Exception as exc:
            print(f"[!] RSS failed {source}: {exc}")
            stats["failed"] += 1
    return stats

def discover_sitemaps(home: str) -> list[str]:
    paths: list[str] = []
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

def sitemap_urls(xml_url: str, seen_xml: set[str] | None = None) -> list[str]:
    seen_xml = seen_xml or set()
    if xml_url in seen_xml or len(seen_xml) >= MAX_PAGES:
        return []
    seen_xml.add(xml_url)

    try:
        response = session.get(xml_url, timeout=TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "xml")

        if soup.find("sitemap"):
            urls: list[str] = []
            for sitemap in soup.find_all("sitemap"):
                loc = sitemap.find("loc")
                if loc and loc.text.strip():
                    urls.extend(sitemap_urls(loc.text.strip(), seen_xml))
            return urls

        return [
            loc.text.strip()
            for loc in soup.find_all("loc")
            if loc.text.strip()
        ]
    except Exception as exc:
        print(f"[!] GET {xml_url}: {exc}")
        return []

def sync_sitemaps(store: ReconStore) -> dict[str, int]:
    stats = {k: 0 for k in ("seen", "added", "updated", "unchanged", "failed")}
    homes = list(dict.fromkeys(
        x for values in CONFIG["html_indexes"].values() for x in values
    ))

    for home in homes:
        parsed = urlparse(home)
        if not parsed.scheme or not parsed.netloc:
            print(f"[!] skipping malformed home: {home}")
            stats["failed"] += 1
            continue

        base = f"{parsed.scheme}://{parsed.netloc}"
        for sitemap in discover_sitemaps(base):
            urls = sitemap_urls(sitemap)
            print(f"[*] sitemap {sitemap}: {len(urls)} URLs")
            matched = 0
            items = []

            for url in urls:
                if not _useful_url(url):
                    continue
                matched += 1
                title = (
                    url.rstrip("/")
                    .rsplit("/", 1)[-1]
                    .replace("-", " ")
                    .replace("_", " ")
                )
                items.append((title, url, "Sitemap archive", None, "", None))
                if len(items) >= max(1, MAX_DOCS - store.count_documents()):
                    break

            print(f"[*]   → {matched} passed URL filter")
            part = ingest_batch(store, items)
            _merge_stats(stats, part)
            if store.count_documents() >= MAX_DOCS:
                break
    return stats

def sync_html_indexes(store: ReconStore) -> dict[str, int]:
    stats = {k: 0 for k in ("seen", "added", "updated", "unchanged", "failed")}

    for source, indexes in CONFIG["html_indexes"].items():
        for index_url in indexes:
            try:
                response = session.get(index_url, timeout=TIMEOUT)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                parsed = urlparse(response.url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                seen: set[str] = set()
                items = []

                for anchor_tag in soup.find_all("a", href=True):
                    href = canonical(urljoin(base, anchor_tag["href"]))
                    if href in seen or not href.startswith(base):
                        continue
                    seen.add(href)

                    anchor = clean(anchor_tag.get_text(" ", strip=True))
                    if source == "Bugcrowd CrowdStream" and "/disclosures/" not in href:
                        continue
                    if source == "HackerOne Blog" and "/blog/" not in href:
                        continue
                    if source == "Bugcrowd Blog" and "/blog/" not in href:
                        continue
                    if not anchor:
                        continue

                    items.append((anchor, href, source, None, "", None))
                    if len(items) >= max(1, MAX_DOCS - store.count_documents()):
                        break

                part = ingest_batch(store, items)
                _merge_stats(stats, part)
                if store.count_documents() >= MAX_DOCS:
                    return stats
            except Exception as exc:
                print(f"[!] index failed {source} {index_url}: {exc}")
                stats["failed"] += 1

    return stats

def sync_hackerone(store: ReconStore) -> dict[str, int]:
    stats = {k: 0 for k in ("seen", "added", "updated", "unchanged", "failed")}
    user = os.getenv("H1_API_USERNAME")
    token = os.getenv("H1_API_TOKEN")

    if not user or not token:
        print("[*] HackerOne Hacktivity skipped: credentials not set")
        return stats

    endpoint = "https://api.hackerone.com/v1/hackers/hacktivity"

    for page in range(1, H1_MAX_PAGES + 1):
        if store.count_documents() >= MAX_DOCS:
            break

        params = {
            "page[number]": page,
            "page[size]": H1_PAGE_SIZE,
            "sort": "-disclosed_at",
            "queryString": "disclosed:true",
        }

        try:
            response = session.get(
                endpoint,
                params=params,
                auth=(user, token),
                headers={"Accept": "application/json"},
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            print(f"[!] HackerOne page {page} failed: {exc}")
            stats["failed"] += 1
            break

        data = payload.get("data", [])
        if not data:
            break

        print(f"[*] HackerOne Hacktivity page {page}: {len(data)} reports")

        items = []
        for item in data:
            attrs = item.get("attributes", {})
            title = attrs.get("title", "")
            url = attrs.get("url")
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
            items.append((
                title,
                url,
                "HackerOne Hacktivity",
                attrs.get("disclosed_at"),
                summary,
                extra,
            ))

        part = ingest_batch(store, items)
        _merge_stats(stats, part)

        if len(data) < H1_PAGE_SIZE:
            break
        time.sleep(1.5)

    return stats

def _merge_stats(total: dict[str, int], part: dict[str, int]) -> None:
    for key in total:
        total[key] += part.get(key, 0)

def run_sync(mode: str, include_sitemap: bool) -> dict[str, int]:
    totals = {k: 0 for k in ("seen", "added", "updated", "unchanged", "failed")}
    with ReconStore() as store:
        run_id = store.begin_run(mode)
        try:
            for sync in (sync_hackerone, sync_rss, sync_html_indexes):
                _merge_stats(totals, sync(store))
            if include_sitemap:
                _merge_stats(totals, sync_sitemaps(store))

            store.finish_run(
                run_id,
                items_seen=totals["seen"],
                items_added=totals["added"],
                items_updated=totals["updated"],
                items_unchanged=totals["unchanged"],
                items_failed=totals["failed"],
            )
            print(
                f"[+] {mode} finished: "
                f"seen={totals['seen']} added={totals['added']} "
                f"updated={totals['updated']} unchanged={totals['unchanged']} "
                f"failed={totals['failed']} documents={store.count_documents()}"
            )
        except Exception:
            store.finish_run(
                run_id,
                items_seen=totals["seen"],
                items_added=totals["added"],
                items_updated=totals["updated"],
                items_unchanged=totals["unchanged"],
                items_failed=totals["failed"] + 1,
            )
            raise
    return totals

def main():
    DATA.mkdir(exist_ok=True)
    run_sync("backfill", include_sitemap=True)

if __name__ == "__main__":
    main()
