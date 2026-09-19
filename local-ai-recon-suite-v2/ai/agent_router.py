from __future__ import annotations
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RULES = [
    ("llm_redteam", ("prompt injection","jailbreak","system prompt","llm","rag poisoning","tool abuse")),
    ("api_security", ("/api/","graphql","swagger","openapi","authorization","bearer ")),
    ("recon", ("host:","http/","https://","subdomain","origin:","referer:","user-agent:")),
]

def route(request_text: str):
    low = request_text.lower()
    for agent, terms in RULES:
        if any(t in low for t in terms):
            return agent
    return "recon"

AGENT_SKILLS = {
    "recon": ["web-security-testing", "scanning-tools"],
    "api_security": ["api-security-testing", "web-security-testing"],
    "llm_redteam": ["llm-redteam"],
}

def load_agent(name):
    mapping = {
        "recon": "agents/recon-orchestrator.md",
        "api_security": "agents/api-security.md",
        "llm_redteam": "agents/llm-redteam-specialist.md",
    }
    p = ROOT / mapping.get(name, "agents/recon-orchestrator.md")
    return p.read_text(encoding="utf-8") if p.exists() else ""

def load_skill(name):
    p = ROOT / "skills" / name / "SKILL.md"
    return p.read_text(encoding="utf-8") if p.exists() else ""

def plan(request_text):
    agent = route(request_text)
    skills = AGENT_SKILLS[agent]
    return {
        "agent": agent,
        "skills": skills,
        "agent_prompt": load_agent(agent),
        "skill_prompts": {s: load_skill(s) for s in skills}
    }
