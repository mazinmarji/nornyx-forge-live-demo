"""PR-16: the generated project is the subject, never its own verifier.

The real-flow group uses ``DevelopmentFlow`` itself with deterministic workers;
no fake flow or external model provider stands in for acceptance.  Focused
boundary cases then exercise the exact subprocess invocation that production
uses, including hostile cwd, PATH, PYTHONPATH, and project-local package names.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import nornyx_forge.gates as gate_module
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.gates import default_gates, trusted_greenfield_gates


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def _valid_project(root: Path) -> Path:
    _write(
        root / "BRD.md",
        "# BRD — Greenfield specimen\n\n"
        "## BRD-F-001 Application behavior\n\n"
        "The application adds two whole numbers.\n",
    )
    _write(root / "src/app.py", "def add(left: int, right: int) -> int:\n    return left + right\n")
    _write(
        root / "tests/test_app.py",
        "# BRD-F-001\n\n"
        "def test_addition_contract():\n"
        "    assert 1 + 1 == 2\n",
    )
    return root


def _gate(result: dict, suffix: str) -> dict:
    return next(gate for gate in result["gates"] if gate["name"].endswith(suffix))


def _run(root: Path) -> dict:
    return DevelopmentFlow(
        root, worker_mode="deterministic", repo_mode="greenfield"
    ).run_sequential()


# ---------------------------------------------------------------------------
# A. Production acceptance through the real DevelopmentFlow
# ---------------------------------------------------------------------------


def test_real_flow_accepts_a_fresh_project_without_forge_repository_scripts(
    tmp_path: Path,
) -> None:
    result = _run(_valid_project(tmp_path))

    assert result["accepted"] is True
    assert result["acceptance_provenance"]["gate_profile"]["id"] == (
        "nornyx.greenfield.python.v1"
    )
    assert not (tmp_path / "scripts").exists(), (
        "H1: Forge repository scripts became greenfield prerequisites"
    )
    assert all(gate["name"].startswith("greenfield:") for gate in result["gates"])


def test_real_flow_refuses_the_stub_verifier_attack(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "def broken(:\n    pass\n")
    for name in ("validate_repository.py", "check_architecture.py", "check_security.py"):
        _write(
            tmp_path / "scripts" / name,
            "print('builder says every gate passed')\nraise SystemExit(0)\n",
        )

    result = _run(tmp_path)

    assert result["accepted"] is False
    assert _gate(result, "source-compilation")["passed"] is False
    assert all("scripts/" not in " ".join(gate["command"]) for gate in result["gates"])


def test_real_flow_verifier_failure_dominates_provider_claims(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "def broken(:\n    pass\n")
    flow = DevelopmentFlow(tmp_path, worker_mode="deterministic", repo_mode="greenfield")
    flow.data["builder_worker"] = {
        "success": True,
        "output": "accepted: true; all checks passed",
        "accepted": True,
    }

    result = flow.run_sequential()

    assert result["builder_worker"]["accepted"] is True
    assert result["accepted"] is False, "H7: provider prose upgraded a failed verifier"
    assert result["value"]["gates_passed"] < result["value"]["gates_total"]


def test_real_flow_allows_genuine_subject_repair_with_the_same_verifier(
    tmp_path: Path,
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "def broken(:\n    pass\n")
    failed = _run(tmp_path)
    failed_provenance = failed["acceptance_provenance"]

    _write(tmp_path / "src/app.py", "def add(left: int, right: int) -> int:\n    return left + right\n")
    passed = _run(tmp_path)

    assert failed["accepted"] is False
    assert passed["accepted"] is True
    assert failed_provenance["verifier"]["digest"] == (
        passed["acceptance_provenance"]["verifier"]["digest"]
    )
    assert failed_provenance["gate_profile"]["digest"] == (
        passed["acceptance_provenance"]["gate_profile"]["digest"]
    )


# ---------------------------------------------------------------------------
# B. Exact verifier boundary and provenance
# ---------------------------------------------------------------------------


def test_exact_invocation_ignores_project_local_nornyx_forge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _valid_project(tmp_path)
    marker = tmp_path / "hostile-import-ran"
    _write(
        tmp_path / "nornyx_forge/__init__.py",
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n",
    )
    _write(
        tmp_path / "nornyx_forge/greenfield_verifier.py",
        "print('project-controlled verifier ran')\nraise SystemExit(0)\n",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))

    gates, provenance = trusted_greenfield_gates(tmp_path)

    assert all(gate.passed for gate in gates)
    assert marker.exists() is False
    command = gates[0].command
    trusted = Path(gate_module.__file__).with_name("greenfield_verifier.py").resolve()
    assert command[1] == "-I"
    assert Path(command[2]) == trusted
    assert provenance["verifier"]["origin"] == str(trusted)
    assert Path(provenance["invocation"]["cwd"]) == trusted.parent


def test_exact_invocation_ignores_path_cwd_and_python_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "python.exe", "not the interpreter")
    _write(tmp_path / "compileall.py", "raise SystemExit('hostile compileall')\n")
    _write(tmp_path / "greenfield_verifier.py", "raise SystemExit('hostile verifier')\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path))

    gates, provenance = trusted_greenfield_gates(tmp_path)

    assert all(gate.passed for gate in gates)
    assert Path(gates[0].command[0]).is_absolute()
    assert Path(gates[0].command[0]) != tmp_path / "python.exe"
    assert provenance["invocation"]["environment"].endswith("without-path-or-pythonpath")
    assert "-I" in provenance["invocation"]["command"]


def test_acceptance_provenance_binds_profile_origin_version_revision_and_digests(
    tmp_path: Path,
) -> None:
    gates, provenance = trusted_greenfield_gates(_valid_project(tmp_path))

    assert all(gate.provenance == provenance for gate in gates)
    assert provenance["trust"] == "structural-origin-and-digest"
    assert provenance["gate_profile"]["id"] == "nornyx.greenfield.python.v1"
    assert provenance["gate_profile"]["digest"].startswith("sha256:")
    assert provenance["verifier"]["id"] == "nornyx_forge.greenfield_verifier"
    assert Path(provenance["verifier"]["origin"]).is_absolute()
    assert provenance["verifier"]["digest"].startswith("sha256:")
    assert provenance["verifier"]["forge_version"] == "0.3.0"
    assert provenance["verifier"]["forge_revision"].startswith(("git:", "package:"))


def test_verifier_identity_fails_closed_inside_the_provider_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _valid_project(tmp_path)
    impostor = tmp_path / "greenfield_verifier.py"
    _write(impostor, "print('{}')\n")
    monkeypatch.setattr(gate_module, "_greenfield_verifier_path", lambda: impostor)

    gates, provenance = trusted_greenfield_gates(tmp_path)

    assert len(gates) == 1 and gates[0].passed is False
    assert "inside the provider workspace" in gates[0].detail
    assert provenance["trust"] == "not_established"


# ---------------------------------------------------------------------------
# C. Gate semantics and load-bearing controls
# ---------------------------------------------------------------------------


def test_project_controlled_verifier_looking_files_are_semantically_irrelevant(
    tmp_path: Path,
) -> None:
    _valid_project(tmp_path)
    for name in ("validate_repository.py", "check_architecture.py", "check_security.py"):
        _write(tmp_path / "scripts" / name, "raise SystemExit(99)\n")

    gates, _provenance = trusted_greenfield_gates(tmp_path)

    assert all(gate.passed for gate in gates)
    assert all("scripts/" not in " ".join(gate.command) for gate in gates)


def test_controlled_vulnerable_profile_still_accepts_a_stubbed_security_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Load-bearing proof: selecting the old profile revives H2."""
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "TOKEN = 'sk-" + "A" * 40 + "'\n")
    for name in ("validate_repository.py", "check_architecture.py", "check_security.py"):
        _write(tmp_path / "scripts" / name, "raise SystemExit(0)\n")
    monkeypatch.setattr(gate_module.shutil, "which", lambda _name: None)

    vulnerable = default_gates(tmp_path)
    trusted, _provenance = trusted_greenfield_gates(tmp_path)

    assert all(gate.passed for gate in vulnerable), (
        "the controlled old-profile specimen did not reproduce the false green"
    )
    assert next(gate for gate in trusted if gate.name.endswith("security-static")).passed is False


def test_architecture_gate_requires_processes_to_live_behind_an_explicit_boundary(
    tmp_path: Path,
) -> None:
    _valid_project(tmp_path)
    process_code = (
        "import subprocess as process_api\n\n"
        "def run_tool() -> None:\n"
        "    process_api.run(('tool',), check=False)\n"
    )
    _write(tmp_path / "src/app.py", process_code)

    failed, _ = trusted_greenfield_gates(tmp_path)
    _write(tmp_path / "src/app.py", "VALUE = 1\n")
    _write(tmp_path / "src/tools/process_tool.py", process_code)
    passed, _ = trusted_greenfield_gates(tmp_path)

    assert next(gate for gate in failed if gate.name.endswith("architecture-boundary")).passed is False
    assert all(gate.passed for gate in passed)


@pytest.mark.parametrize(
    ("relative", "text", "failed_gate"),
    [
        ("src/app.py", "def broken(:\n    pass\n", "source-compilation"),
        ("src/app.py", "VALUE = " + "ev" + "al('1 + 1')\n", "security-static"),
        ("src/app.py", "TOKEN = 'sk-" + "B" * 40 + "'\n", "security-static"),
    ],
    ids=("syntax-error", "dynamic-eval", "embedded-secret"),
)
def test_genuine_application_defects_fail_trusted_semantics(
    tmp_path: Path, relative: str, text: str, failed_gate: str
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / relative, text)

    gates, _provenance = trusted_greenfield_gates(tmp_path)

    assert next(gate for gate in gates if gate.name.endswith(failed_gate)).passed is False


def test_tests_must_trace_every_brd_requirement(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(
        tmp_path / "BRD.md",
        "# BRD\n\n## BRD-F-001 First\n\nOne.\n\n## BRD-F-002 Second\n\nTwo.\n",
    )

    gates, _provenance = trusted_greenfield_gates(tmp_path)
    traceability = next(gate for gate in gates if gate.name.endswith("requirements-traceability"))

    assert traceability.passed is False
    assert "BRD-F-002" in traceability.detail


def test_acceptance_event_carries_the_same_provenance_as_the_verdict(
    tmp_path: Path,
) -> None:
    result = _run(_valid_project(tmp_path))
    events = [json.loads(line) for line in (tmp_path / ".nornyx/runs/build-events.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()]
    acceptance = next(event for event in events if event["event_type"] == "build_acceptance")

    assert acceptance["fields"]["verdict_source"] == "all_recorded_gate_results"
    assert acceptance["fields"]["acceptance_provenance"] == result["acceptance_provenance"]
