"""Hybrid reranker: cosine distance + lightweight BM25."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]

def _bm25_scores(
    query: str,
    docs: list[str],
    k1: float = 1.5,
    b: float = 0.75,
) -> list[float]:
    q_terms = list(dict.fromkeys(_tokens(query)))
    doc_tokens = [_tokens(d) for d in docs]
    doc_lens = [len(d) for d in doc_tokens]
    avg_len = sum(doc_lens) / max(len(doc_lens), 1)

    df: Counter[str] = Counter()
    for toks in doc_tokens:
        for token in set(toks):
            df[token] += 1

    N = len(docs)
    scores: list[float] = []

    for toks, dl in zip(doc_tokens, doc_lens):
        tf = Counter(toks)
        score = 0.0

        for q in q_terms:
            if q not in tf:
                continue
            idf = math.log(1 + (N - df[q] + 0.5) / (df[q] + 0.5))
            numerator = tf[q] * (k1 + 1)
            denominator = tf[q] + k1 * (1 - b + b * dl / max(avg_len, 1))
            score += idf * numerator / denominator

        scores.append(score)

    return scores

def rerank(
    query: str,
    candidates: Iterable[dict],
    top_k: int = 5,
    vector_weight: float = 0.6,
    bm25_weight: float = 0.4,
) -> list[dict]:
    cands = list(candidates)
    if not cands:
        return []

    docs = [c.get("text", "") for c in cands]
    bm25 = _bm25_scores(query, docs)
    max_bm25 = max(bm25) or 1.0

    distances = [float(c.get("distance", 1.0)) for c in cands]
    d_min = min(distances)
    d_max = max(distances)

    for c, b_score, distance in zip(cands, bm25, distances):
        if d_max == d_min:
            vec_score = 1.0
        else:
            vec_score = 1.0 - ((distance - d_min) / (d_max - d_min))

        c["_bm25"] = b_score / max_bm25
        c["_vec"] = max(0.0, min(1.0, vec_score))
        c["final_score"] = (
            vector_weight * c["_vec"] + bm25_weight * c["_bm25"]
        )

    cands.sort(key=lambda x: x["final_score"], reverse=True)
    return cands[:top_k]
