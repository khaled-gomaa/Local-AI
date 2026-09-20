from __future__ import annotations

from typing import Iterable


def build_attention_queue(
    *,
    findings: Iterable[dict],
    new_endpoints: Iterable[str],
    new_hosts: Iterable[str],
    agent_items: Iterable[dict] = (),
) -> list[dict]:
    items: list[dict] = []

    for host in new_hosts:
        items.append({
            "type": "new_host",
            "target": host,
            "reason": "A host was not present in the previous session.",
            "source": "session_delta",
        })

    for endpoint in new_endpoints:
        items.append({
            "type": "new_endpoint",
            "target": endpoint,
            "reason": "An endpoint was not present in the previous session.",
            "source": "session_delta",
        })

    state_weight = {
        "needs_review": 0,
        "hypothesis": 1,
        "observed": 2,
        "tested": 3,
        "confirmed": 4,
        "rejected": 5,
        "not_interesting": 6,
    }

    for finding in findings:
        state = str(finding.get("state") or "needs_review")
        if state in {"rejected", "not_interesting"}:
            continue
        items.append({
            "type": "finding",
            "target": finding.get("target", ""),
            "reason": finding.get("statement", finding.get("title", "")),
            "source": finding.get("agent", "ledger"),
            "state": state,
            "confidence": float(finding.get("confidence") or 0.0),
            "_state_weight": state_weight.get(state, 0),
        })

    for item in agent_items:
        target = str(item.get("target") or "").strip()
        reason = str(item.get("reason") or "").strip()
        if not target or not reason:
            continue
        items.append({
            "type": "agent_review",
            "target": target,
            "reason": reason,
            "source": item.get("agent", "shadow-agent"),
            "confidence": float(item.get("confidence") or 0.0),
        })

    def score(item: dict) -> tuple[int, float]:
        if item["type"] == "finding":
            return (item.get("_state_weight", 0), item.get("confidence", 0.0))
        return (0, item.get("confidence", 0.0))

    items.sort(key=score)
    for item in items:
        item.pop("_state_weight", None)

    # Deduplicate while preserving the most useful reason/source.
    seen: set[tuple[str, str]] = set()
    result: list[dict] = []
    for item in items:
        key = (str(item["type"]), str(item["target"]).lower())
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result[:40]


def render_briefing(handoff: dict) -> str:
    current = handoff.get("current_stats") or {}
    previous = handoff.get("previous_stats") or {}
    delta = handoff.get("delta") or {}
    program = (handoff.get("program") or {}).get("name", "unknown")
    session = (handoff.get("session") or {}).get("session_date", "today")

    lines = [
        f"Assessment Briefing — Program {program}",
        f"Session: {session}",
        "",
        "CURRENT COVERAGE",
        f"- Requests: {current.get('requests', 0)}",
        f"- Hosts: {current.get('hosts', 0)}",
        f"- Endpoints: {current.get('endpoints', 0)}",
        f"- Parameters: {current.get('parameters', 0)}",
    ]

    if previous:
        lines += [
            "",
            "SINCE PREVIOUS SESSION",
            f"- New hosts: {', '.join(delta.get('new_hosts') or []) or 'None'}",
            f"- New endpoints: {', '.join(delta.get('new_endpoints') or []) or 'None'}",
            f"- Request delta: {delta.get('requests_delta', 0)}",
            f"- Endpoint delta: {delta.get('endpoint_delta', 0)}",
            f"- Parameter delta: {delta.get('parameter_delta', 0)}",
        ]

    open_items = handoff.get("open_review_items") or []
    if open_items:
        lines += ["", "OPEN REVIEW ITEMS"]
        for item in open_items[:12]:
            lines.append(
                f"- [{item.get('state', 'needs_review')}] "
                f"{item.get('target', '')} — {item.get('statement', item.get('title', ''))}"
            )

    queue = handoff.get("attention_queue") or []
    if queue:
        lines += ["", "ATTENTION QUEUE"]
        for item in queue[:12]:
            lines.append(
                f"- {item.get('target', '')}: {item.get('reason', '')}"
            )

    lines += [
        "",
        "OPERATOR CONTROL",
        "- AI is observing and reviewing accumulated evidence only.",
        "- Active testing remains a manual operator decision.",
    ]

    return "\n".join(lines)
