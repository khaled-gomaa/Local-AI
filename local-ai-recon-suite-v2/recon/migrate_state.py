from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.common import canonical
from recon.state_store import ReconStore

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "data" / "state.json"

def main():
    if not STATE.exists():
        print("[=] No legacy state.json found; nothing to migrate.")
        return

    payload = json.loads(STATE.read_text(encoding="utf-8"))
    urls = payload.get("urls", {})
    if not isinstance(urls, dict):
        raise ValueError("Legacy state.json has an invalid 'urls' object.")

    imported = skipped = 0
    with ReconStore() as store:
        for raw_url, record_id in urls.items():
            url = canonical(raw_url)
            if not url or not record_id or store.get(url) is not None:
                skipped += 1
                continue
            store.insert_legacy_placeholder(url, str(record_id))
            imported += 1

    print(f"[+] Migrated legacy URLs: imported={imported} skipped={skipped}")

if __name__ == "__main__":
    main()
