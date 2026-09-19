from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read_component(path: str):
    return Path(path).read_text(encoding="utf-8")

def strip_claude_tool_instructions(text: str):
    replacements = {
        "Read": "local.read_file",
        "Grep": "local.search_files",
        "Glob": "local.list_files",
        "Bash": "local.safe_command"
    }
    out = text
    for old, new in replacements.items():
        out = re.sub(rf"\b{re.escape(old)}\b", new, out)
    return out

def normalize(text: str):
    text = strip_claude_tool_instructions(text)
    return (
        "LOCAL AI ADAPTER POLICY\n"
        "Do not assume Claude Code tools exist. Use only tools registered by the Local AI runtime.\n"
        "Do not execute destructive actions. Require explicit local authorization for active testing.\n\n"
        + text
    )
