from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# كل قاعدة: (اسم الوكيل، قائمة كلمات، وزن)
# نستخدم word boundary عشان نتجنب مطابقات خاطئة زي "llm" داخل "illuminate"
_RULES: list[tuple[str, list[re.Pattern[str]]]] = [
    ("llm_redteam", [
        re.compile(r"\bprompt\s+injection\b", re.I),
        re.compile(r"\bjailbreak\b", re.I),
        re.compile(r"\bsystem\s+prompt\b", re.I),
        re.compile(r"\bllm\b", re.I),
        re.compile(r"\brag\s+poisoning\b", re.I),
        re.compile(r"\btool\s+abuse\b", re.I),
    ]),
    ("api_security", [
        re.compile(r"/api/", re.I),
        re.compile(r"\bgraphql\b", re.I),
        re.compile(r"\bswagger\b", re.I),
        re.compile(r"\bopenapi\b", re.I),
        re.compile(r"\bauthorization\b", re.I),
        re.compile(r"\bbearer\s", re.I),
    ]),
    ("recon", [
        re.compile(r"\bhost:", re.I),
        re.compile(r"\bhttp/", re.I),
        re.compile(r"https?://", re.I),
        re.compile(r"\bsubdomain\b", re.I),
        re.compile(r"\borigin:", re.I),
        re.compile(r"\breferer:", re.I),
        re.compile(r"\buser-agent:", re.I),
    ]),
]

AGENT_SKILLS: dict[str, list[str]] = {
    "recon": ["web-security-testing", "scanning-tools"],
    "api_security": ["api-security-testing", "web-security-testing"],
    "llm_redteam": ["llm-redteam"],
    "subdomain": ["subdomain-intelligence", "web-security-testing"],
    "content": ["content-discovery-intelligence", "web-security-testing"],
    "parameter": ["parameter-intelligence", "api-security-testing"],
    "history": ["history-review", "web-security-testing"],
    "lead_review": ["history-review", "web-security-testing"],
}

_AGENT_FILES: dict[str, str] = {
    "recon": "agents/recon-orchestrator.md",
    "api_security": "agents/api-security.md",
    "llm_redteam": "agents/llm-redteam-specialist.md",
    "subdomain": "agents/subdomain-agent.md",
    "content": "agents/content-agent.md",
    "parameter": "agents/parameter-agent.md",
    "history": "agents/history-reviewer.md",
    "lead_review": "agents/lead-reviewer.md",
}


def route(request_text: str) -> str:
    for agent, patterns in _RULES:
        if any(p.search(request_text) for p in patterns):
            return agent
    return "recon"


@lru_cache(maxsize=32)
def _read_file(rel_path: str) -> str:
    p = ROOT / rel_path
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def load_agent(name: str) -> str:
    return _read_file(_AGENT_FILES.get(name, "agents/recon-orchestrator.md"))


def load_skill(name: str) -> str:
    return _read_file(f"skills/{name}/SKILL.md")


def plan(request_text: str) -> dict:
    agent = route(request_text)
    skills = AGENT_SKILLS[agent]
    return {
        "agent": agent,
        "skills": skills,
        "agent_prompt": load_agent(agent),
        "skill_prompts": {s: load_skill(s) for s in skills},
    }
