from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / ".nornyx/architecture/conformance.json"
violations: list[str] = []

rules = {
    "src/demo_app/store.py": {"fastapi", "crewai", "subprocess"},
    "src/nornyx_forge/evidence.py": {"fastapi", "crewai", "demo_app"},
    "src/nornyx_forge/policy.py": {"fastapi", "demo_app"},
    "src/nornyx_forge/nornyx_runtime.py": {"fastapi", "demo_app"},
}
for relative, forbidden in rules.items():
    path = ROOT / relative
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    for name in sorted(imports & forbidden):
        violations.append(f"{relative} imports forbidden dependency {name}")

main_text = (ROOT / "src/demo_app/main.py").read_text(encoding="utf-8")
if "subprocess" in main_text or "os.system" in main_text:
    violations.append("API layer contains direct command execution")
agentic_text = (ROOT / "src/demo_app/agentic.py").read_text(encoding="utf-8")
if "NornyxActionBoundary" not in agentic_text:
    violations.append("runtime orchestration does not use the declared Nornyx action boundary")
if "action()" in main_text:
    violations.append("API layer appears to invoke a consequential action directly")

result = {
    "schema": "nornyx.forge.architecture_report.v1",
    "status": "pass" if not violations else "fail",
    "subject": "nornyx-forge-live-demo",
    "checks": [
        "dependency_direction",
        "api_command_isolation",
        "governed_action_boundary",
        "persistence_isolation",
    ],
    "violations": violations,
}
REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
raise SystemExit(0 if not violations else 2)
