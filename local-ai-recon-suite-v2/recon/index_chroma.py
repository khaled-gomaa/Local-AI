from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

try:
    import chromadb
except ImportError as exc:
    raise SystemExit("Install requirements.txt first") from exc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon.common import CHUNKS, DOCS, DATA

OLLAMA = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
DB = DATA / "chroma"

COLLECTIONS = {
    "recon": "recon",
    "web_security": "web_security",
    "tooling_development": "tooling_development",
    "public_disclosures": "public_disclosures",
}

def embed(texts):
    r = requests.post(
        f"{OLLAMA}/api/embed",
        json={"model": EMBED_MODEL, "input": texts},
        timeout=120,
    )
    if r.status_code == 404:
        raise RuntimeError(
            f"Ollama embedding model '{EMBED_MODEL}' is unavailable. "
            f"Run: ollama pull {EMBED_MODEL}"
        )
    r.raise_for_status()
    data = r.json()
    return data.get("embeddings", [])

def load_latest_doc_ids():
    latest: dict[str, str] = {}
    if not DOCS.exists():
        return latest

    with DOCS.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            url = row.get("url")
            doc_id = row.get("id")
            if url and doc_id:
                latest[url] = doc_id
    return latest

def load_rows():
    if not CHUNKS.exists():
        return []

    latest_docs = load_latest_doc_ids()
    rows_by_id: dict[str, dict] = {}

    with CHUNKS.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            url = row.get("url")
            doc_id = row.get("doc_id")
            chunk_id = row.get("id")
            if not url or not doc_id or not chunk_id:
                continue
            if latest_docs.get(url) != doc_id:
                continue
            rows_by_id[chunk_id] = row

    return list(rows_by_id.values())

def main():
    DB.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(DB))
    collections = {
        category: client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )
        for category, name in COLLECTIONS.items()
    }

    rows = load_rows()
    pending = {k: [] for k in collections}
    desired_ids = {k: set() for k in collections}

    for row in rows:
        cat = row.get("category")
        if cat not in pending:
            continue
        pending[cat].append(row)
        desired_ids[cat].add(row["id"])

    total = 0
    prune = os.getenv("CHROMA_PRUNE_STALE", "1").lower() not in {"0", "false", "no"}
    batch_size = max(1, int(os.getenv("EMBED_BATCH", "16")))

    for cat, data in pending.items():
        col = collections[cat]
        existing_ids = set(col.get(include=[])["ids"]) if col.count() else set()

        if prune:
            stale = existing_ids - desired_ids[cat]
            if stale:
                col.delete(ids=list(stale))
                print(f"[-] pruned {cat}: {len(stale)} stale chunks")
                existing_ids -= stale

        for i in range(0, len(data), batch_size):
            batch = [x for x in data[i:i + batch_size] if x["id"] not in existing_ids]
            if not batch:
                continue

            vectors = embed([x["text"] for x in batch])
            if len(vectors) != len(batch):
                raise RuntimeError("Ollama returned a different number of embeddings")

            col.upsert(
                ids=[x["id"] for x in batch],
                embeddings=vectors,
                documents=[x["text"] for x in batch],
                metadatas=[{
                    "doc_id": x["doc_id"],
                    "title": x["title"],
                    "url": x["url"],
                    "source": x["source"],
                    "published": x["published"],
                    "category": x["category"],
                    "score": float(x.get("score", 0)),
                    "keywords": ",".join(x.get("keywords", [])),
                } for x in batch],
            )
            total += len(batch)
            existing_ids.update(x["id"] for x in batch)
            print(f"[+] indexed {cat}: {len(batch)}")

    print(f"[+] New chunks indexed: {total}")
    print("[+] Collection counts:")
    for cat, col in collections.items():
        print(f"    {cat}: {col.count()}")

if __name__ == "__main__":
    main()
