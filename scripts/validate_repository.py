from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate() -> list[str]:
    errors: list[str] = []
    required = [
        "README.md", "BRD.md", "CLAUDE.md", "BOOTSTRAP.md", "ONE_PROMPT.md",
        ".claude-plugin/plugin.json", "skills/build-app/SKILL.md",
        ".nornyx/contracts/forge_control.nyx", ".nornyx/contracts/runtime_network.nyx",
        "src/nornyx_forge/cli.py", "src/demo_app/main.py", "docker-compose.yml",
        "docs/VALIDATION.md", "docs/CLAUDE_CODE_AND_CREWAI.md", "PUBLISH.md",
        "scripts/smoke_http.py", "schemas/in-session-reviews.schema.json",
    ]
    for name in required:
        if not (ROOT / name).exists():
            errors.append(f"missing required file: {name}")
    try:
        json.loads((ROOT / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
        json.loads((ROOT / "hooks/hooks.json").read_text(encoding="utf-8"))
        json.loads((ROOT / "schemas/in-session-reviews.schema.json").read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"invalid JSON: {exc}")
    tracked_text = []
    for path in ROOT.rglob("*"):
        if path.is_file() and ".git" not in path.parts and ".venv" not in path.parts:
            try:
                tracked_text.append((path, path.read_text(encoding="utf-8")))
            except UnicodeDecodeError:
                pass
    secret_patterns = [
        re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        re.compile(r"sk-[A-Za-z0-9]{32,}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    ]
    for path, text in tracked_text:
        for pattern in secret_patterns:
            if pattern.search(text):
                errors.append(f"possible committed secret in {path.relative_to(ROOT)}")
    if "human_review: not_performed" not in (ROOT / "BOOTSTRAP.md").read_text(encoding="utf-8"):
        errors.append("bootstrap does not disclose absent human review")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--internal", action="store_true")
    parser.parse_args()
    errors = validate()
    print(json.dumps({"status": "pass" if not errors else "fail", "errors": errors}, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
