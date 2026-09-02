"""PR-16: the generated project is the subject, never its own verifier.

The real-flow group uses ``DevelopmentFlow`` itself with deterministic workers;
no fake flow or external model provider stands in for acceptance.  Focused
boundary cases then exercise the exact subprocess invocation that production
uses, including hostile cwd, PATH, PYTHONPATH, and project-local package names.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

import pytest

import nornyx_forge.gates as gate_module
import nornyx_forge.greenfield_verifier as verifier_module
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.gates import default_gates, trusted_greenfield_gates
from nornyx_forge.models import WorkerResult


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


class _LocalWorker:
    """Deterministic stand-in at the real DevelopmentFlow worker seam."""

    def __init__(self, action: Callable[[str, str, Path], None] | None = None) -> None:
        self.action = action
        self.calls: list[dict[str, Any]] = []

    def run(self, **request: Any) -> WorkerResult:
        self.calls.append(dict(request))
        role = str(request["role"])
        goal = str(request["goal"])
        workspace = Path(request["workspace"])
        if self.action is not None:
            self.action(role, goal, workspace)
        return WorkerResult(
            role=role,
            goal=goal,
            success=True,
            output="accepted: true; all checks passed",
            command=("deterministic-local-worker", role),
        )


def _claude_flow(root: Path, worker: _LocalWorker) -> dict:
    flow = DevelopmentFlow(root, worker_mode="claude-code", repo_mode="greenfield")
    flow.worker = worker
    return flow.run_sequential()


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
    assert all(
        gate["name"].startswith("greenfield:")
        or gate["name"] == "build-evidence-ledger-valid-before-verdict"
        for gate in result["gates"]
    )


def test_standing_real_development_flow_uses_the_trusted_profile(tmp_path: Path) -> None:
    result = _run(_valid_project(tmp_path))

    assert result["accepted"] is True
    assert result["value"]["acceptance_profile"] == "nornyx.greenfield.python.v1"
    assert any(gate["name"] == "greenfield:test-execution" for gate in result["gates"])


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


def test_real_flow_verifier_failure_dominates_provider_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "def broken(:\n    pass\n")
    monkeypatch.setenv("FORGE_MAX_REPAIR_ATTEMPTS", "1")

    def write_false_green(_role: str, goal: str, workspace: Path) -> None:
        if goal.startswith("Repair only"):
            for name in (
                "validate_repository.py",
                "check_architecture.py",
                "check_security.py",
            ):
                _write(workspace / "scripts" / name, "raise SystemExit(0)\n")

    worker = _LocalWorker(write_false_green)
    result = _claude_flow(tmp_path, worker)

    assert result["builder_worker"]["output"].startswith("accepted: true")
    assert result["repair_attempts"] == 1
    assert any(call["goal"].startswith("Repair only") for call in worker.calls)
    assert result["accepted"] is False, "H7: provider prose upgraded a failed verifier"
    assert result["value"]["gates_passed"] < result["value"]["gates_total"]


def test_real_flow_allows_genuine_subject_repair_with_the_same_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "def add(left: int, right: int) -> int:\n    return 0\n")
    _write(
        tmp_path / "tests/test_app.py",
        "# BRD-F-001\nfrom src.app import add\n\n"
        "def test_addition_contract():\n    assert add(1, 1) == 2\n",
    )
    failed_gates, failed_provenance = trusted_greenfield_gates(tmp_path)
    assert next(g for g in failed_gates if g.name.endswith("test-execution")).passed is False
    monkeypatch.setenv("FORGE_MAX_REPAIR_ATTEMPTS", "1")

    def repair_subject(_role: str, goal: str, workspace: Path) -> None:
        if goal.startswith("Repair only"):
            _write(
                workspace / "src/app.py",
                "def add(left: int, right: int) -> int:\n    return left + right\n",
            )

    passed = _claude_flow(tmp_path, _LocalWorker(repair_subject))

    assert passed["accepted"] is True
    assert passed["repair_attempts"] == 1
    assert failed_provenance["verifier"]["digest"] == (
        passed["acceptance_provenance"]["verifier"]["digest"]
    )
    assert failed_provenance["gate_profile"]["digest"] == (
        passed["acceptance_provenance"]["gate_profile"]["digest"]
    )
    assert failed_provenance["subject"]["digest"] != (
        passed["acceptance_provenance"]["subject"]["digest"]
    )


def test_real_flow_reverifies_after_read_only_reviewers(
    tmp_path: Path,
) -> None:
    _valid_project(tmp_path)

    def mutate_despite_policy(role: str, _goal: str, workspace: Path) -> None:
        if role == "security-inspector":
            _write(workspace / "src/app.py", "def broken(:\n    pass\n")

    worker = _LocalWorker(mutate_despite_policy)
    result = _claude_flow(tmp_path, worker)

    reviewer_calls = [
        call for call in worker.calls if str(call["role"]).endswith("-inspector")
    ]
    assert reviewer_calls
    assert all(call["allowed_tools"] == ("Read", "Glob", "Grep") for call in reviewer_calls)
    assert result["accepted"] is False
    assert _gate(result, "source-compilation")["passed"] is False


def test_real_flow_refuses_a_corrupt_preexisting_evidence_ledger(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / ".nornyx/runs/build-events.jsonl", "not-json\n")

    result = _run(tmp_path)

    assert result["accepted"] is False
    assert result["evidence"]["status"] == "fail"
    assert _gate(result, "build-evidence-ledger-valid-before-verdict")["passed"] is False


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
    assert command[2] == "-c"
    assert Path(command[4]).is_absolute()
    assert Path(command[4]) != trusted
    assert command[command.index("--trusted-origin") + 1] == str(trusted)
    assert provenance["verifier"]["origin"] == str(trusted)
    assert provenance["invocation"]["verifier_execution"] == (
        "digest-verified-in-memory-byte-snapshot"
    )
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
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))
    observed: dict[str, Any] = {}
    real_run = gate_module.subprocess.run

    def capture_run(command: tuple[str, ...], **kwargs: Any):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return real_run(command, **kwargs)

    monkeypatch.setattr(gate_module.subprocess, "run", capture_run)

    gates, provenance = trusted_greenfield_gates(tmp_path)

    assert all(gate.passed for gate in gates)
    assert Path(gates[0].command[0]).is_absolute()
    assert gates[0].command[0] == os.path.abspath(gate_module.sys.executable)
    assert Path(gates[0].command[0]) != tmp_path / "python.exe"
    assert provenance["invocation"]["python_resolved_target"] == str(
        Path(gate_module.sys.executable).resolve(strict=True)
    )
    assert provenance["invocation"]["environment"].endswith("without-path-or-pythonpath")
    assert "-I" in provenance["invocation"]["command"]
    assert Path(observed["kwargs"]["cwd"]) == Path(provenance["invocation"]["cwd"])
    assert {"PATH", "PYTHONPATH", "PYTHONHOME"}.isdisjoint(observed["kwargs"]["env"])
    assert observed["kwargs"]["env"].get("LD_LIBRARY_PATH") != str(tmp_path)
    assert provenance["invocation"]["trusted_loader_path"] == observed["kwargs"][
        "env"
    ].get("LD_LIBRARY_PATH")


def test_linux_loader_path_is_derived_from_trusted_python_not_inherited_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "subject"
    project.mkdir()
    runtime = tmp_path / "trusted-python"
    library = runtime / "lib"
    library.mkdir(parents=True)
    hostile = project / "native-libraries"
    hostile.mkdir()
    monkeypatch.setattr(gate_module.sys, "platform", "linux")
    monkeypatch.setattr(gate_module.sys, "base_prefix", str(runtime))
    monkeypatch.setenv("LD_LIBRARY_PATH", str(hostile))

    loader = gate_module._trusted_loader_path(project.resolve())
    environment = gate_module._verifier_environment(loader)

    assert loader == library.resolve()
    assert environment["LD_LIBRARY_PATH"] == str(library.resolve())
    assert str(hostile) not in environment["LD_LIBRARY_PATH"]


def test_verifier_refuses_a_loader_directory_inside_the_provider_workspace(
    tmp_path: Path,
) -> None:
    project = _valid_project(tmp_path)

    payload = verifier_module.verify(project, trusted_loader_path=project)
    structure = next(
        gate for gate in payload["gates"] if gate["id"] == "project-structure"
    )

    assert structure["passed"] is False
    assert "loader directory is not an external directory" in structure["detail"]


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
    assert provenance["subject"]["digest"].startswith("sha256:")
    assert provenance["resource_limits"]["enforced"] is True
    assert provenance["test_execution"]["subject"] == "private-temporary-copy"
    assert provenance["test_execution"]["runner_execution"] == (
        "digest-verified-in-memory-byte-snapshot"
    )
    assert provenance["test_execution"]["executor_execution"] == (
        "digest-verified-in-memory-byte-snapshot"
    )
    assert provenance["test_execution"]["executor_digest"] == (
        gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST
    )
    assert provenance["test_execution"]["trusted_loader_path"] == provenance[
        "invocation"
    ]["trusted_loader_path"]
    assert provenance["test_execution"]["completion"]["executor_returncode"] == 73
    assert provenance["test_execution"]["completion"]["executor_command"][:4] == [
        os.path.abspath(gate_module.sys.executable),
        "-I",
        "-c",
        gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP,
    ]


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


def _valid_child_payload(command: tuple[str, ...]) -> dict[str, Any]:
    project = command[command.index("--project-root") + 1]
    origin = command[command.index("--trusted-origin") + 1]
    digest = command[command.index("--trusted-digest") + 1]
    version = command[command.index("--forge-version") + 1]
    revision = command[command.index("--forge-revision") + 1]
    subject_digest = "sha256:" + "1" * 64
    test_runner = str(Path(command[4]).with_name("greenfield_test_runner.py"))
    test_subject = str(Path(command[4]).with_name("subject-snapshot"))
    test_executor = str(Path(command[4]).with_name("greenfield_pytest_executor.py"))
    test_inner_result = str(Path(command[4]).with_name("greenfield_pytest_inner.json"))
    test_config = str(Path(command[4]).with_name("greenfield_pytest.ini"))
    return {
        "schema": "nornyx.forge.greenfield_verification.v1",
        "status": "pass",
        "gate_profile": {
            **gate_module.GREENFIELD_PROFILE_DEFINITION,
            "digest": gate_module.GREENFIELD_PROFILE_DIGEST,
        },
        "verifier": {
            "id": gate_module.GREENFIELD_VERIFIER_ID,
            "origin": origin,
            "digest": digest,
            "execution_origin": command[4],
            "execution_digest": digest,
            "forge_version": version,
            "forge_revision": revision,
        },
        "subject": {"root": project, "digest": subject_digest, "file_count": 3},
        "resource_limits": dict(gate_module.GREENFIELD_RESOURCE_LIMITS),
        "test_execution": {
            "python": command[0],
            "isolated_python": True,
            "cwd": str(Path(origin).parent),
            "environment": "constructed-host-allowlist-without-path-or-pythonpath",
            "subject": "private-temporary-copy",
            "subject_digest": subject_digest,
            "runner": "private-readonly-trusted-runner",
            "runner_digest": gate_module.GREENFIELD_TEST_RUNNER_DIGEST,
            "runner_execution": "digest-verified-in-memory-byte-snapshot",
            "executor_digest": gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
            "executor_execution": "digest-verified-in-memory-byte-snapshot",
            "command": [
                command[0],
                "-I",
                "-c",
                gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP,
                test_runner,
                gate_module.GREENFIELD_TEST_RUNNER_DIGEST,
                test_subject,
            ],
            "output_capture": "bounded-20000-byte-tail-no-disk-spool",
            "output_bytes": 100,
            "result_protocol": "nornyx.greenfield.pytest_result.v1",
            "completion": {
                "schema": "nornyx.greenfield.pytest_result.v1",
                "returncode": 0,
                "collected": 1,
                "executed": 1,
                "failed": 0,
                "skipped": 0,
                "executor_digest": gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
                "executor_command": [
                    command[0],
                    "-I",
                    "-c",
                    gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP,
                    test_executor,
                    gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
                    test_subject,
                    test_inner_result,
                    test_config,
                    gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
                ],
                "executor_cwd": test_subject,
                "executor_returncode": 73,
            },
            "final_subject_digest": subject_digest,
        },
        "gates": [
            {"id": identifier, "passed": True, "detail": "passed"}
            for identifier in gate_module.GREENFIELD_GATE_IDS
        ],
    }


_INVALID_CHILD_PAYLOADS = [
    ("schema", lambda value: value.__setitem__("schema", "wrong")),
    ("profile-absent", lambda value: value.pop("gate_profile")),
    ("profile-version", lambda value: value["gate_profile"].__setitem__("version", 999)),
    ("profile-checks", lambda value: value["gate_profile"].__setitem__("checks", ["accept-all"])),
    ("profile-digest", lambda value: value["gate_profile"].__setitem__("digest", "sha256:" + "0" * 64)),
    ("verifier-absent", lambda value: value.pop("verifier")),
    ("verifier-id", lambda value: value["verifier"].__setitem__("id", "project.verifier")),
    ("verifier-origin", lambda value: value["verifier"].__setitem__("origin", "project.py")),
    ("verifier-digest", lambda value: value["verifier"].__setitem__("digest", "sha256:" + "0" * 64)),
    ("execution-origin", lambda value: value["verifier"].__setitem__("execution_origin", "other.py")),
    ("execution-digest", lambda value: value["verifier"].__setitem__("execution_digest", "sha256:" + "0" * 64)),
    ("forge-version", lambda value: value["verifier"].__setitem__("forge_version", "999")),
    ("forge-revision", lambda value: value["verifier"].__setitem__("forge_revision", "git:" + "0" * 40)),
    ("subject-absent", lambda value: value.pop("subject")),
    ("subject-root", lambda value: value["subject"].__setitem__("root", "elsewhere")),
    ("subject-digest", lambda value: value["subject"].__setitem__("digest", "not-a-digest")),
    ("subject-count", lambda value: value["subject"].__setitem__("file_count", 0)),
    ("resource-limits", lambda value: value["resource_limits"].__setitem__("enforced", False)),
    ("test-provenance-absent", lambda value: value.pop("test_execution")),
    ("gates-absent", lambda value: value.pop("gates")),
    ("gate-order", lambda value: value.__setitem__("gates", list(reversed(value["gates"])))),
    ("gate-duplicate", lambda value: value["gates"].__setitem__(1, dict(value["gates"][0]))),
    ("gate-extra", lambda value: value["gates"].append({"id": "accept-all", "passed": True, "detail": "passed"})),
    ("gate-shape", lambda value: value["gates"][0].__setitem__("extra", True)),
    ("gate-passed-type", lambda value: value["gates"][0].__setitem__("passed", "yes")),
    ("gate-detail-type", lambda value: value["gates"][0].__setitem__("detail", 1)),
    ("test-provenance", lambda value: value["test_execution"].__setitem__("subject_digest", "sha256:" + "0" * 64)),
    (
        "runner-execution",
        lambda value: value["test_execution"].__setitem__("runner_execution", "by-path"),
    ),
    (
        "executor-digest",
        lambda value: value["test_execution"].__setitem__(
            "executor_digest", "sha256:" + "0" * 64
        ),
    ),
    (
        "executor-command",
        lambda value: value["test_execution"]["completion"]["executor_command"].__setitem__(
            3, "exec-by-path"
        ),
    ),
    ("status", lambda value: value.__setitem__("status", "fail")),
]


@pytest.mark.parametrize(
    ("label", "mutate"),
    _INVALID_CHILD_PAYLOADS,
    ids=[case[0] for case in _INVALID_CHILD_PAYLOADS],
)
def test_every_malformed_verifier_result_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    _valid_project(tmp_path)

    def fake_run(command: tuple[str, ...], **_kwargs: Any):
        payload = _valid_child_payload(command)
        mutate(payload)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(gate_module.subprocess, "run", fake_run)
    gates, provenance = trusted_greenfield_gates(tmp_path)

    assert label
    assert len(gates) == 1 and gates[0].passed is False
    assert gates[0].name == "greenfield:trusted-verifier-identity"
    assert provenance["trust"] in {"not_established", "structural-origin-and-digest"}


@pytest.mark.parametrize(
    "failure",
    ("oserror", "timeout", "invalid-json", "non-object", "stderr", "returncode"),
)
def test_verifier_process_and_protocol_failures_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    _valid_project(tmp_path)

    def fake_run(command: tuple[str, ...], **_kwargs: Any):
        if failure == "oserror":
            raise OSError("cannot execute")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 120)
        if failure == "invalid-json":
            return subprocess.CompletedProcess(command, 0, "not-json", "")
        if failure == "non-object":
            return subprocess.CompletedProcess(command, 0, "[]", "")
        payload = _valid_child_payload(command)
        return subprocess.CompletedProcess(
            command,
            2 if failure == "returncode" else 0,
            json.dumps(payload),
            "unexpected" if failure == "stderr" else "",
        )

    monkeypatch.setattr(gate_module.subprocess, "run", fake_run)
    gates, _provenance = trusted_greenfield_gates(tmp_path)

    assert len(gates) == 1 and gates[0].passed is False
    assert gates[0].name == "greenfield:trusted-verifier-identity"


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


_PROCESS_CAPABILITY_SPELLINGS = [
    ("os-attribute", "import os\ndef probe(c):\n    os.system(c)\n"),
    ("os-from-import", "from os import system\ndef probe(c):\n    system(c)\n"),
    ("os-alias", "from os import system as run\ndef probe(c):\n    run(c)\n"),
    ("popen-alias", "from os import popen as run\ndef probe(c):\n    return run(c)\n"),
    ("subprocess-import", "import subprocess\ndef probe(c):\n    subprocess.run(c)\n"),
    ("subprocess-from", "from subprocess import run\ndef probe(c):\n    run(c)\n"),
    ("startfile", "import os\ndef probe(p):\n    os.startfile(p)\n"),
    ("execvp", "from os import execvp\ndef probe(a,b):\n    execvp(a,b)\n"),
    ("multiprocessing", "import multiprocessing\nHANDLE=multiprocessing.Process\n"),
    ("retained-handle", "from os import system\nHANDLE=system\n"),
    ("modules-subscript", "import sys\nHANDLE=sys.modules['sub'+'process']\n"),
    ("modules-get", "import sys\nHANDLE=sys.modules.get('sub'+'process')\n"),
    ("modules-pop", "import sys\nHANDLE=sys.modules.pop('sub'+'process')\n"),
    ("builtins-import", "import builtins\nHANDLE=builtins.__import__('sub'+'process')\n"),
    (
        "computed-importer",
        "import builtins\nIMPORT=getattr(builtins,'__imp'+'ort__')\n"
        "HANDLE=IMPORT('sub'+'process')\n",
    ),
    ("aliased-sys", "import sys as runtime\nHANDLE=runtime.modules.get('sub'+'process')\n"),
]


@pytest.mark.parametrize(
    ("label", "source"),
    _PROCESS_CAPABILITY_SPELLINGS,
    ids=[case[0] for case in _PROCESS_CAPABILITY_SPELLINGS],
)
def test_greenfield_profile_matches_the_hardened_process_capability_corpus(
    tmp_path: Path, label: str, source: str
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", source)

    gates, _provenance = trusted_greenfield_gates(tmp_path)
    architecture = next(g for g in gates if g.name.endswith("architecture-boundary"))

    assert label
    assert architecture.passed is False
    assert "process capability" in architecture.detail


@pytest.mark.parametrize(
    ("relative", "source"),
    [
        (
            "src/app.py",
            "import builtins\nVALUE=getattr(builtins,'ev'+'al')('1 + 1')\n",
        ),
        (
            "src/tools/process_tool.py",
            "import subprocess\ndef run(c):\n    subprocess.run(c, shell=1)\n",
        ),
        ("src/app.py", "TOKEN = 'sk-' + 'C' * 40\n"),
        ("src/app.py", "import importlib\nMOD=importlib.import_module('json')\n"),
    ],
    ids=("indirect-eval", "truthy-shell", "split-secret", "dynamic-import"),
)
def test_security_static_rejects_resolved_and_constant_folded_bypasses(
    tmp_path: Path, relative: str, source: str
) -> None:
    _valid_project(tmp_path)
    if relative != "src/app.py":
        _write(tmp_path / "src/app.py", "VALUE = 1\n")
    _write(tmp_path / relative, source)

    gates, _provenance = trusted_greenfield_gates(tmp_path)

    assert next(g for g in gates if g.name.endswith("security-static")).passed is False


@pytest.mark.parametrize(
    "source",
    (
        "import os\nEXIT=getattr(os, '_' + 'exit')\n",
        "def subject():\n    return None\nGLOBALS=getattr(subject, '__glo' + 'bals__')\n",
        "import sys\nORIGINAL=sys.orig_argv\n",
        "def reflected(subject, member):\n    return getattr(subject, member)\n",
    ),
    ids=("reflected-hard-exit", "reflected-globals", "original-argv", "opaque-getattr"),
)
def test_security_static_rejects_reflected_executor_control(
    tmp_path: Path, source: str
) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", source)

    gates, _provenance = trusted_greenfield_gates(tmp_path)

    security = next(g for g in gates if g.name.endswith("security-static"))
    assert security.passed is False
    assert "interpreter-control" in security.detail or "reflected" in security.detail


def test_failing_project_tests_are_a_real_acceptance_failure(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "src/app.py", "def add(left: int, right: int) -> int:\n    return 0\n")
    _write(
        tmp_path / "tests/test_app.py",
        "# BRD-F-001\nfrom src.app import add\n\n"
        "def test_addition_contract():\n    assert add(1, 1) == 2\n",
    )

    result = _run(tmp_path)

    assert result["accepted"] is False
    assert _gate(result, "test-execution")["passed"] is False


def test_project_conftest_cannot_rewrite_a_failing_pytest_exit_status(
    tmp_path: Path,
) -> None:
    _valid_project(tmp_path)
    _write(
        tmp_path / "tests/conftest.py",
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    session.exitstatus = 0\n",
    )
    _write(
        tmp_path / "tests/test_app.py",
        "# BRD-F-001\n\ndef test_real_failure():\n    assert False\n",
    )

    result = _run(tmp_path)

    assert result["accepted"] is False
    assert _gate(result, "test-execution")["passed"] is False


def test_project_pytest_configuration_cannot_hide_a_failing_test(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "pytest.ini", "[pytest]\npython_files = never_collect_*.py\n")
    _write(
        tmp_path / "tests/test_app.py",
        "# BRD-F-001\n\ndef test_real_failure():\n    assert False\n",
    )

    result = _run(tmp_path)

    assert result["accepted"] is False
    assert _gate(result, "test-execution")["passed"] is False


def test_project_tests_cannot_force_a_successful_runner_exit(tmp_path: Path) -> None:
    specimens = (
        "import os\n\ndef test_forced_exit():\n    os._exit(0)\n    assert False\n",
        "import pytest\npytest.exit('forced', returncode=0)\n\n"
        "def test_never_runs():\n    assert False\n",
        "import __main__\nimport json\nimport os\nfrom pathlib import Path\n\n"
        "def test_forged_completion():\n"
        "    payload = {'schema': 'nornyx.greenfield.pytest_result.v1', "
        "'returncode': 0, 'collected': 1, 'executed': 1, 'failed': 0, 'skipped': 0}\n"
        "    Path(__main__.result_path).write_text(json.dumps(payload), encoding='utf-8')\n"
        "    os._exit(0)\n"
        "    assert False\n",
        "import __main__\nimport pytest\n\n"
        "__main__.trusted_dumps = lambda value, **kwargs: "
        "\"{\\\"schema\\\":\\\"nornyx.greenfield.pytest_result.v1\\\","
        "\\\"returncode\\\":0,\\\"collected\\\":1,\\\"executed\\\":1,"
        "\\\"failed\\\":0,\\\"skipped\\\":0}\"\n"
        "pytest.exit('forged completion', returncode=0)\n\n"
        "def test_never_runs():\n    assert False\n",
        "import pytest\n\n"
        "class ExitRewriter:\n"
        "    def pytest_sessionfinish(self, session):\n"
        "        session.exitstatus = 0\n\n"
        "def test_registers_runtime_plugin(request):\n"
        "    request.config.pluginmanager.register(ExitRewriter())\n"
        "    assert False\n",
    )
    for index, source in enumerate(specimens):
        project = _valid_project(tmp_path / str(index))
        _write(project / "tests/test_app.py", f"# BRD-F-001\n{source}")

        result = _run(project)

        assert result["accepted"] is False
        assert _gate(result, "test-execution")["passed"] is False
        assert (
            _gate(result, "security-static")["passed"] is False
            or "completion record" in _gate(result, "test-execution")["detail"]
        )


def test_runner_and_executor_use_digest_verified_in_memory_snapshots() -> None:
    assert gate_module.GREENFIELD_TEST_RUNNER_SOURCE == (
        verifier_module.TEST_RUNNER_SOURCE
    )
    assert gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE == (
        verifier_module.TEST_EXECUTOR_SOURCE
    )
    assert "executor_command = [" in gate_module.GREENFIELD_TEST_RUNNER_SOURCE
    assert '"-I", "-c", DIGEST_BOOTSTRAP' in gate_module.GREENFIELD_TEST_RUNNER_SOURCE
    assert "completed.returncode == 73" in gate_module.GREENFIELD_TEST_RUNNER_SOURCE
    assert '_sys.orig_argv[:] = [str(_subject)]' in gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE
    assert '_event == "os.link"' in gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE
    assert '_write_is_allowed(_item) for _item in _args[:2]' in (
        gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE
    )


def test_executor_rejects_a_hard_link_to_its_completion_record(tmp_path: Path) -> None:
    subject = _valid_project(tmp_path / "subject")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    executor = scratch / "greenfield_pytest_executor.py"
    result = scratch / "greenfield_pytest_inner.json"
    config = scratch / "greenfield_pytest.ini"
    _write(executor, gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE)
    _write(config, "[pytest]\n")
    forged = {
        "schema": "nornyx.greenfield.pytest_result.v1",
        "returncode": 0,
        "collected": 1,
        "executed": 1,
        "failed": 0,
        "skipped": 0,
        "executor_digest": gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
    }
    _write(
        subject / "tests/test_app.py",
        "# BRD-F-001\n"
        "import json\n"
        "import os\n"
        "from pathlib import Path\n\n"
        "def test_forges_completion_with_a_hard_link():\n"
        "    source = Path('.nornyx-test-tmp/forged.json')\n"
        f"    source.write_text({json.dumps(json.dumps(forged))}, encoding='utf-8')\n"
        f"    os.link(source, Path({json.dumps(str(result))}))\n"
        "    os._exit(73)\n",
    )

    completed = subprocess.run(
        [
            os.fspath(Path(sys.executable)),
            "-I",
            "-c",
            gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP,
            os.fspath(executor),
            gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
            os.fspath(subject),
            os.fspath(result),
            os.fspath(config),
            gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
        ],
        cwd=subject,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 73, completed.stdout + completed.stderr
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["returncode"] != 0
    assert payload["failed"] == 1

    interpreter_controls = (
        "import sys\nsys.addaudithook(lambda *_args: None)\n",
        "import sys\nsys.call_tracing(lambda: None, ())\n",
        "import sys\nsys.set_asyncgen_hooks(firstiter=lambda _item: None)\n",
        "import sys\nsys.setprofile(lambda *_args: None)\n",
        "import sys\nsys.settrace(lambda *_args: None)\n",
        "import sys\nCONTROL=sys.monitoring\n",
    )
    for index, source in enumerate(interpreter_controls):
        project = _valid_project(tmp_path / f"static-control-{index}")
        _write(project / "src/app.py", source)
        gates, _provenance = trusted_greenfield_gates(project)
        security = next(g for g in gates if g.name.endswith("security-static"))
        assert security.passed is False, source

    callback_subject = _valid_project(tmp_path / "callback-subject")
    callback_scratch = tmp_path / "callback-scratch"
    callback_scratch.mkdir()
    callback_executor = callback_scratch / "greenfield_pytest_executor.py"
    callback_result = callback_scratch / "greenfield_pytest_inner.json"
    callback_config = callback_scratch / "greenfield_pytest.ini"
    _write(callback_executor, gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE)
    _write(callback_config, "[pytest]\n")
    _write(
        callback_subject / "tests/test_app.py",
        "# BRD-F-001\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        f"RESULT = Path({json.dumps(str(callback_result))})\n"
        "SOURCE = Path('.nornyx-test-tmp/forged.json')\n\n"
        "def completion_hook(event, args):\n"
        "    if event == 'open' and args and Path(args[0]).resolve() == RESULT:\n"
        "        os.link(SOURCE, RESULT)\n"
        "        os._exit(73)\n\n"
        "def test_registers_a_completion_callback():\n"
        f"    SOURCE.write_text({json.dumps(json.dumps(forged))}, encoding='utf-8')\n"
        "    sys.addaudithook(completion_hook)\n"
        "    assert True\n",
    )

    callback_completed = subprocess.run(
        [
            os.fspath(Path(sys.executable)),
            "-I",
            "-c",
            gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP,
            os.fspath(callback_executor),
            gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
            os.fspath(callback_subject),
            os.fspath(callback_result),
            os.fspath(callback_config),
            gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
        ],
        cwd=callback_subject,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert callback_completed.returncode == 73, (
        callback_completed.stdout + callback_completed.stderr
    )
    callback_payload = json.loads(callback_result.read_text(encoding="utf-8"))
    assert callback_payload["returncode"] != 0
    assert callback_payload["failed"] == 1


def test_project_test_output_is_drained_without_an_unbounded_spool(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(
        tmp_path / "tests/test_app.py",
        "# BRD-F-001\n\ndef test_chatty():\n"
        "    print('x' * 100_000)\n"
        "    assert True\n",
    )

    gates, provenance = trusted_greenfield_gates(tmp_path)

    assert all(gate.passed for gate in gates)
    assert provenance["test_execution"]["output_capture"] == (
        "bounded-20000-byte-tail-no-disk-spool"
    )
    assert provenance["test_execution"]["output_bytes"] >= 100_000


_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "RLIMIT_NPROC is a POSIX per-user-id limit; Windows confines the "
        "verifier with a Job Object whose active-process cap is per job"
    ),
)


@_POSIX_ONLY
def test_posix_process_budget_survives_a_busy_real_uid(tmp_path: Path) -> None:
    """The CI red: an absolute RLIMIT_NPROC ceiling refused the verifier's own runner.

    ``RLIMIT_NPROC`` is charged to every task the real user id holds host-wide,
    not to this process tree. The GitHub runner service user already held more
    than the verifier's ceiling of 64, so the trusted runner, the executor, or
    the output drain thread failed with EAGAIN on every interpreter of the
    matrix -- at whichever point the ceiling happened to bite. Holding 96
    sleeping threads reproduces that host without depending on it. Under the
    old ceiling this test fails; the budget must sit above the ambient count.
    """
    release = threading.Event()
    threads = [threading.Thread(target=release.wait, daemon=True) for _ in range(96)]
    for thread in threads:
        thread.start()
    try:
        gates, provenance = trusted_greenfield_gates(_valid_project(tmp_path))
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=10)

    assert provenance["trust"] == "structural-origin-and-digest"
    assert [gate.name for gate in gates if not gate.passed] == []
    assert provenance["resource_limits"] == gate_module.GREENFIELD_RESOURCE_LIMITS
    assert provenance["test_execution"]["completion"]["executor_returncode"] == 73


@_POSIX_ONLY
def test_posix_process_budget_is_applied_above_the_ambient_task_count() -> None:
    """The budget still bounds what the subject may add; it was not merely lifted.

    Probed in a child so the limits never land on the pytest interpreter. The
    child measures the ambient count the way the verifier does, applies the
    limits, and reads back what the kernel now holds: room for the verifier's
    own three tasks, at most the declared budget above the ambient count, a
    hard limit the subject cannot raise, and the memory/CPU limits unchanged.
    """
    probe = (
        "import json, resource, subprocess, sys, threading\n"
        "from nornyx_forge import greenfield_verifier as verifier\n"
        "ambient = verifier._real_uid_task_count()\n"
        "limits = verifier._apply_resource_limits()\n"
        "soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)\n"
        "memory = resource.getrlimit(resource.RLIMIT_AS)\n"
        "cpu = resource.getrlimit(resource.RLIMIT_CPU)\n"
        "thread = threading.Thread(target=lambda: None)\n"
        "thread.start()\n"
        "thread.join()\n"
        "child = subprocess.run([sys.executable, '-c', 'pass'], check=False)\n"
        "print(json.dumps({'ambient': ambient, 'limits': limits, 'soft': soft, "
        "'hard': hard, 'memory': memory, 'cpu': cpu, 'child': child.returncode}))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    observed = json.loads(completed.stdout.strip().splitlines()[-1])
    budget = gate_module.GREENFIELD_RESOURCE_LIMITS["active_processes"]
    assert observed["limits"] == gate_module.GREENFIELD_RESOURCE_LIMITS
    assert observed["memory"] == [768 * 1024 * 1024, 768 * 1024 * 1024]
    assert observed["cpu"] == [120, 120]
    assert observed["ambient"] >= 1
    assert observed["soft"] >= observed["ambient"] + 3, "no room for the verifier's own tasks"
    assert observed["soft"] <= observed["ambient"] + budget + 2, "the budget was lifted, not bounded"
    assert observed["soft"] == observed["hard"], "the subject could raise the budget back"
    assert observed["child"] == 0


@pytest.mark.parametrize("missing", ("BRD.md", "src", "tests"))
def test_required_greenfield_structure_fails_closed(tmp_path: Path, missing: str) -> None:
    _valid_project(tmp_path)
    target = tmp_path / missing
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()

    gates, _provenance = trusted_greenfield_gates(tmp_path)

    assert next(g for g in gates if g.name.endswith("project-structure")).passed is False


def test_greenfield_file_size_limit_is_a_refusal(tmp_path: Path) -> None:
    _valid_project(tmp_path)
    _write(tmp_path / "notes.txt", "x" * 500_001)

    gates, _provenance = trusted_greenfield_gates(tmp_path)

    structure = next(g for g in gates if g.name.endswith("project-structure"))
    assert structure.passed is False
    assert "inspection limit" in structure.detail


def test_links_and_windows_junctions_cannot_escape_the_subject(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    _valid_project(project)
    _valid_project(outside)
    shutil.rmtree(project / "src")
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(project / "src"), str(outside / "src")],
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert (project / "src").is_symlink() is False
    else:
        os.symlink(outside / "src", project / "src", target_is_directory=True)

    gates, _provenance = trusted_greenfield_gates(project)

    structure = next(g for g in gates if g.name.endswith("project-structure"))
    assert structure.passed is False
    assert "reparse" in structure.detail or "linked" in structure.detail


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
