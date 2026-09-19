from __future__ import annotations
import json, os, sys, time
from pathlib import Path
import requests

try:
    import chromadb
except ImportError as exc:
    raise SystemExit("Install requirements.txt first") from exc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon.common import CHUNKS, DATA

OLLAMA = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
DB = DATA / "chroma"

COLLECTIONS = {
    "recon": "recon",
    "web_security": "web_security",
    "tooling_development": "tooling_development",
    "public_disclosures": "public_disclosures"
}

def embed(texts):
    r = requests.post(f"{OLLAMA}/api/embed",
                      json={"model": EMBED_MODEL, "input": texts},
                      timeout=120)
    if r.status_code == 404:
        raise RuntimeError(
            f"Ollama embedding model '{EMBED_MODEL}' is unavailable. "
            f"Run: ollama pull {EMBED_MODEL}"
        )
    r.raise_for_status()
    data = r.json()
    return data.get("embeddings", [])

def load_rows():
    if not CHUNKS.exists():
        return []
    rows = []
    with CHUNKS.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def main():
    DB.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(DB))
    collections = {
        category: client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space":"cosine"}
        )
        for category, name in COLLECTIONS.items()
    }
    rows = load_rows()
    pending = {k: [] for k in collections}
    for row in rows:
        cat = row.get("category")
        if cat not in pending:
            continue
        pending[cat].append(row)

    total = 0
    batch_size = int(os.getenv("EMBED_BATCH", "16"))
    for cat, data in pending.items():
        col = collections[cat]
        existing = set()
        # count() is fast; get() without ids can be expensive on very large collections.
        if col.count():
            existing = set(col.get(include=[])["ids"])
        for i in range(0, len(data), batch_size):
            batch = [x for x in data[i:i+batch_size] if x["id"] not in existing]
            if not batch:
                continue
            vectors = embed([x["text"] for x in batch])
            if len(vectors) != len(batch):
                raise RuntimeError("Ollama returned a different number of embeddings")
            col.add(
                ids=[x["id"] for x in batch],
                embeddings=vectors,
                documents=[x["text"] for x in batch],
                metadatas=[{
                    "doc_id":x["doc_id"], "title":x["title"], "url":x["url"],
                    "source":x["source"], "published":x["published"],
                    "category":x["category"], "score":float(x.get("score",0)),
                    "keywords":",".join(x.get("keywords",[]))
                } for x in batch]
            )
            total += len(batch)
            print(f"[+] indexed {cat}: {len(batch)}")
    print(f"[+] New chunks indexed: {total}")
    print("[+] Collection counts:")
    for cat, col in collections.items():
        print(f"    {cat}: {col.count()}")

if __name__ == "__main__":
    main()
