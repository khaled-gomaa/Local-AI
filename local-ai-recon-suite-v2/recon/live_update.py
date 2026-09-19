from __future__ import annotations
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon.backfill import sync_hackerone, sync_rss, sync_html_indexes, load_state, save_state, DATA

def main():
    state = load_state()
    added = 0
    # Live mode intentionally uses the same dedupe state, but each source is only
    # queried for currently visible items. Historical backfill is a separate job.
    added += sync_hackerone(state)
    added += sync_rss(state)
    added += sync_html_indexes(state)
    save_state(state)
    print(f"[+] Live update: +{added} documents")

if __name__ == "__main__":
    main()
