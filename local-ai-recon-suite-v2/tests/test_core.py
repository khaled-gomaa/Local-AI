from ai.rerank import rerank
from ai.agent_router import route
from recon.common import canonical, classify, has_term


def test_canonical_removes_query_and_fragment():
    assert canonical("https://example.com/a/?x=1#frag") == "https://example.com/a"


def test_has_term_uses_word_boundaries():
    assert has_term("the api endpoint is here", "api")
    assert not has_term("rapidapi is here", "api")


def test_recon_classification():
    category, score, _, keywords = classify(
        "Subdomain enumeration",
        "",
        "Passive reconnaissance and attack surface mapping",
    )
    assert category == "recon"
    assert score > 20
    assert "subdomain enumeration" in keywords


def test_router_prefers_llm_specific_signals():
    assert route("POST /chat - prompt injection test") == "llm_redteam"


def test_hybrid_rerank_returns_top_k_and_scores():
    candidates = [
        {"id": "a", "text": "subdomain enumeration attack surface", "distance": 0.2},
        {"id": "b", "text": "database backup", "distance": 0.1},
        {"id": "c", "text": "subdomain discovery", "distance": 0.6},
    ]
    results = rerank("subdomain discovery", candidates, top_k=2)
    assert len(results) == 2
    assert all("final_score" in item for item in results)
    assert results[0]["id"] in {"a", "c"}
