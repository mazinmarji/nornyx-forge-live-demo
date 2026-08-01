import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = Path(".nornyx/contracts/architecture_governance.nyx")


def test_architecture_gate():
    assert subprocess.run([sys.executable, "scripts/check_architecture.py"], cwd=ROOT).returncode == 0


def test_security_gate():
    assert subprocess.run([sys.executable, "scripts/check_security.py"], cwd=ROOT).returncode == 0


def _forge_tree(tmp_path: Path) -> Path:
    """Copy the parts of the repository the architecture gate reads."""
    workspace = tmp_path / "repo"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/check_architecture.py", workspace / "scripts")
    shutil.copytree(ROOT / "src", workspace / "src")
    (workspace / CONTRACT.parent).mkdir(parents=True)
    shutil.copy2(ROOT / CONTRACT, workspace / CONTRACT)
    return workspace


def test_architecture_gate_detects_undeclared_dependency(tmp_path: Path):
    """The gate must fail when a real import is absent from depends_on.

    demo_app.agentic genuinely imports nornyx_forge.claude_worker. Removing that
    edge from the contract has to be caught, otherwise the check is vacuous.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    for module in document["architecture"]["modules"]:
        if module["id"] == "module.runtime":
            module["depends_on"] = [
                item for item in module["depends_on"] if item != "module.worker_adapter"
            ]
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["status"] == "fail"
    assert any(
        "undeclared dependency nornyx_forge.claude_worker" in violation
        for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_unmodelled_first_party_import(tmp_path: Path):
    """An import of a real but unmodelled first-party module is a violation.

    Checking only edges between already-declared modules would let a brand-new
    dependency on an unmodelled module (nornyx_forge.gates, which itself shells
    out) pass silently.
    """
    workspace = _forge_tree(tmp_path)
    runtime = workspace / "src/demo_app/agentic.py"
    runtime.write_text(
        runtime.read_text(encoding="utf-8") + "\nfrom nornyx_forge.gates import default_gates\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "first-party module nornyx_forge.gates" in violation
        for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_process_execution_outside_adapter(tmp_path: Path):
    """Interface/application modules must not start processes directly.

    Guards the bounded_external_adapter constraint against os.system as well as
    subprocess, since detecting only `import subprocess` would miss it.
    """
    workspace = _forge_tree(tmp_path)
    api = workspace / "src/demo_app/main.py"
    api.write_text(
        api.read_text(encoding="utf-8") + "\n\nimport os\n\n\ndef _bad():\n    os.system('echo hi')\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "process execution (os.system)" in violation for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_layer_violation(tmp_path: Path):
    """A module may not depend on a layer its own layer does not permit."""
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    for layer in document["architecture"]["layers"]:
        if layer["id"] == "layer.application":
            layer["may_depend_on"] = ["layer.domain"]
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "which layer.application may not depend on" in violation
        for violation in report["violations"]
    ), report["violations"]
