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

from recon.common import CHUNKS, DATA
from recon.state_store import ReconStore

OLLAMA = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
DB = DATA / "chroma"

COLLECTIONS = {
    "recon": "recon",
    "web_security": "web_security",
    "tooling_development": "tooling_development",
    "public_disclosures": "public_disclosures",
}

def embed(texts: list[str]) -> list[list[float]]:
    response = requests.post(
        f"{OLLAMA}/api/embed",
        json={"model": EMBED_MODEL, "input": texts},
        timeout=120,
    )
    if response.status_code == 404:
        raise RuntimeError(
            f"Ollama embedding model '{EMBED_MODEL}' is unavailable. "
            f"Run: ollama pull {EMBED_MODEL}"
        )
    response.raise_for_status()
    vectors = response.json().get("embeddings", [])
    if len(vectors) != len(texts):
        raise RuntimeError(
            f"Ollama returned {len(vectors)} embeddings for {len(texts)} texts"
        )
    return vectors

def load_chunks_for_records(record_ids: set[str]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {record_id: [] for record_id in record_ids}
    if not record_ids or not CHUNKS.exists():
        return grouped

    with CHUNKS.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            record_id = row.get("doc_id")
            if record_id in grouped:
                grouped[record_id].append(row)

    for rows in grouped.values():
        rows.sort(key=lambda row: int(row.get("rank", 0)))
    return grouped

def delete_document_chunks(collection, record_id: str) -> int:
    result = collection.get(
        where={"doc_id": record_id},
        include=[],
    )
    ids = result.get("ids") or []
    if ids:
        collection.delete(ids=ids)
    return len(ids)

def index_job(job, chunks_by_record, collections) -> None:
    record_id = job["record_id"]
    category = job["category"]
    previous_record_id = job["previous_record_id"]
    previous_category = job["previous_category"]

    if previous_record_id and previous_category in collections:
        removed = delete_document_chunks(
            collections[previous_category],
            previous_record_id,
        )
        if removed:
            print(
                f"[-] removed old chunks: "
                f"{previous_category}/{previous_record_id} ({removed})"
            )

    rows = chunks_by_record.get(record_id, [])
    if not rows:
        raise RuntimeError(f"No chunks found for record_id={record_id}")

    collection = collections[category]
    texts = [row["text"] for row in rows]
    vectors = embed(texts)

    collection.upsert(
        ids=[row["id"] for row in rows],
        embeddings=vectors,
        documents=texts,
        metadatas=[{
            "doc_id": row["doc_id"],
            "title": row["title"],
            "url": row["url"],
            "source": row["source"],
            "published": row["published"],
            "category": row["category"],
            "score": float(row.get("score", 0)),
            "keywords": ",".join(row.get("keywords", [])),
            "rank": int(row.get("rank", 0)),
        } for row in rows],
    )

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

    batch_size = max(1, min(int(os.getenv("INDEX_BATCH_JOBS", "8")), 100))
    stale_minutes = max(5, int(os.getenv("INDEX_RECLAIM_MINUTES", "30")))

    with ReconStore() as store:
        reclaimed = store.reset_stale_index_jobs(stale_minutes)
        if reclaimed:
            print(f"[*] reclaimed stale index jobs: {reclaimed}")

        pending = store.pending_index_count()
        print(f"[*] pending index jobs: {pending}")

        run_id = store.begin_index_run()
        claimed_total = done_total = failed_total = 0

        try:
            while True:
                jobs = store.claim_index_jobs(batch_size)
                if not jobs:
                    break

                claimed_total += len(jobs)
                record_ids = {job["record_id"] for job in jobs}
                chunks_by_record = load_chunks_for_records(record_ids)

                for job in jobs:
                    try:
                        current = store.get(job["url"])

                        # A newer version superseded this job while it was pending.
                        if current is None or current["record_id"] != job["record_id"]:
                            store.mark_index_done(job["id"], job["content_hash"])
                            done_total += 1
                            print(
                                f"[=] superseded index job skipped: {job['url']}"
                            )
                            continue

                        index_job(job, chunks_by_record, collections)
                        store.mark_index_done(job["id"], job["content_hash"])
                        done_total += 1
                        print(
                            f"[+] indexed {job['category']}: "
                            f"{job['url']} ({len(chunks_by_record[job['record_id']])} chunks)"
                        )
                    except Exception as exc:
                        failed_total += 1
                        store.mark_index_failed(job["id"], str(exc))
                        print(f"[!] index job {job['id']} failed: {exc}")

            store.finish_index_run(
                run_id,
                claimed=claimed_total,
                done=done_total,
                failed=failed_total,
            )

            print(
                f"[+] Index run finished: claimed={claimed_total} "
                f"done={done_total} failed={failed_total} "
                f"pending={store.pending_index_count()}"
            )
            print("[+] Collection counts:")
            for category, collection in collections.items():
                print(f"    {category}: {collection.count()}")
        except Exception:
            store.finish_index_run(
                run_id,
                claimed=claimed_total,
                done=done_total,
                failed=failed_total + 1,
            )
            raise

if __name__ == "__main__":
    main()
