from __future__ import annotations
import argparse, json, re
from pathlib import Path
from component_loader import normalize

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=["agent","skill"], required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--file", required=True)
    args = ap.parse_args()

    content = normalize(Path(args.file).read_text(encoding="utf-8"))
    if args.kind == "agent":
        out = ROOT / "agents" / f"{args.name}.md"
        out.parent.mkdir(exist_ok=True)
    else:
        out = ROOT / "skills" / args.name / "SKILL.md"
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    print(out)

if __name__ == "__main__":
    main()
