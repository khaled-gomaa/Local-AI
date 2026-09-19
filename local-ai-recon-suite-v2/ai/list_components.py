from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

print("Agents:")
for p in sorted((ROOT/"agents").glob("*.md")):
    print("  -", p.stem)

print("Skills:")
for p in sorted((ROOT/"skills").glob("*/SKILL.md")):
    print("  -", p.parent.name)
