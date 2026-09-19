"""Reranker بسيط (BM25 + cosine) بدون أي نموذج خارجي."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

_TOKEN_RE = re.compile(r"\w+")


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


def _bm25_scores(query: str, docs: list[str], k1: float = 1.5, b: float = 0.75) -> list[float]:
    q_terms = _tokens(query)
    doc_tokens = [_tokens(d) for d in docs]
    doc_lens = [len(d) for d in doc_tokens]
    avg_len = sum(doc_lens) / max(len(doc_lens), 1)

    df: Counter[str] = Counter()
    for toks in doc_tokens:
        for t in set(toks):
            df[t] += 1
    N = len(docs)

    scores: list[float] = []
    for toks, dl in zip(doc_tokens, doc_lens):
        tf = Counter(toks)
        s = 0.0
        for q in q_terms:
            if q not in tf:
                continue
            idf = math.log(1 + (N - df[q] + 0.5) / (df[q] + 0.5))
            num = tf[q] * (k1 + 1)
            den = tf[q] + k1 * (1 - b + b * dl / max(avg_len, 1))
            s += idf * num / den
        scores.append(s)
    return scores


def rerank(
    query: str,
    candidates: Iterable[dict],
    top_k: int = 5,
    vector_weight: float = 0.6,
    bm25_weight: float = 0.4,
) -> list[dict]:
    """يرتّب المرشحين بدمج cosine من Chroma مع BM25 النصي."""
    cands = list(candidates)
    if not cands:
        return []

    docs = [c.get("text", "") for c in cands]
    bm25 = _bm25_scores(query, docs)
    max_bm25 = max(bm25) or 1.0
    max_vec = max((c.get("distance", 0.0) for c in cands), default=1.0) or 1.0

    for c, b in zip(cands, bm25):
        # distance أصغر = أفضل → نعكس
        vec_score = 1.0 - (c.get("distance", 0.0) / max_vec)
        c["_bm25"] = b / max_bm25
        c["_vec"] = max(vec_score, 0.0)
        c["final_score"] = vector_weight * c["_vec"] + bm25_weight * c["_bm25"]

    cands.sort(key=lambda x: x["final_score"], reverse=True)
    return cands[:top_k]