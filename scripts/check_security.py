from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / ".nornyx/security/report.json"
findings: list[str] = []
patterns = {
    "hardcoded_anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "hardcoded_openai_key": re.compile(r"sk-[A-Za-z0-9]{32,}"),
    "hardcoded_github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "shell_true": re.compile(r"shell\s*=\s*True"),
    "python_eval": re.compile(r"\beval\s*\("),
    "python_exec": re.compile(r"\bexec\s*\("),
}
ignored_parts = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".nornyx",
    "evidence",
    "dist",
    "build",
    "__pycache__",
}
ignored_suffixes = {".pyc", ".whl", ".gz", ".zip"}
for path in ROOT.rglob("*"):
    if (
        not path.is_file()
        or any(part in ignored_parts or part.endswith(".egg-info") for part in path.parts)
        or path.suffix in ignored_suffixes
    ):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    relative = path.relative_to(ROOT)
    # KNOWN BOUND, stated rather than left implicit. This exempts the WHOLE
    # scanner file, not merely its pattern literals, so a real secret added to
    # this file would not be reported by it. `.nornyx` is also excluded from
    # the scan entirely, and the Dockerfile copies that directory into the
    # image -- so contract-embedded material is outside this gate's reach.
    # Both are deliberate today; neither is claimed as covered.
    if relative == Path("scripts/check_security.py"):
        continue
    for name, pattern in patterns.items():
        if pattern.search(text):
            findings.append(f"{name}: {relative}")
result = {
    "schema": "nornyx.forge.security_report.v1",
    "status": "pass" if not findings else "fail",
    "checks": ["secret_patterns", "shell_true", "dynamic_python_execution"],
    "findings": findings,
}
REPORT.parent.mkdir(parents=True, exist_ok=True)
# newline="" keeps this report canonical-LF on every platform, matching the
# canonical form the subject observer enforces when it hashes governed text.
REPORT.write_text(
    json.dumps(result, indent=2) + "\n", encoding="utf-8", newline=""
)
print(json.dumps(result, indent=2))
raise SystemExit(0 if not findings else 2)
