from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .models import GateResult

GREENFIELD_PROFILE_ID = "nornyx.greenfield.python.v1"
GREENFIELD_VERIFIER_ID = "nornyx_forge.greenfield_verifier"
GREENFIELD_PROFILE_DEFINITION = {
    "id": GREENFIELD_PROFILE_ID,
    "version": 2,
    "checks": [
        "project-structure",
        "requirements-traceability",
        "source-compilation",
        "test-semantics",
        "architecture-boundary",
        "security-static",
        "test-execution",
    ],
    "execution": "bounded-static-inspection-and-isolated-tests",
}
GREENFIELD_GATE_IDS = tuple(GREENFIELD_PROFILE_DEFINITION["checks"])
GREENFIELD_TEST_RUNNER_SOURCE = """from __future__ import annotations
import sys
from pathlib import Path
import pytest

subject = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(subject / "src"))
sys.path.insert(0, str(subject))
raise SystemExit(pytest.main([
    "-q", "--capture=no", "--disable-warnings", "--maxfail=1",
    "-o", "addopts=", "--rootdir", str(subject), str(subject / "tests"),
]))
"""


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


GREENFIELD_PROFILE_DIGEST = _canonical_digest(GREENFIELD_PROFILE_DEFINITION)
GREENFIELD_TEST_RUNNER_DIGEST = (
    "sha256:" + hashlib.sha256(GREENFIELD_TEST_RUNNER_SOURCE.encode("utf-8")).hexdigest()
)
GREENFIELD_RESOURCE_LIMITS = (
    {
        "enforced": True,
        "platform": "windows-job-object",
        "process_memory_bytes": 768 * 1024 * 1024,
        "job_memory_bytes": 1024 * 1024 * 1024,
        "active_processes": 4,
    }
    if os.name == "nt"
    else {
        "enforced": True,
        "platform": "posix-rlimit",
        "process_memory_bytes": 768 * 1024 * 1024,
        "active_processes": 64,
        "cpu_seconds": 120,
    }
)


def _digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _greenfield_verifier_path() -> Path:
    return Path(__file__).with_name("greenfield_verifier.py").resolve(strict=True)


def _git_directory(marker: Path) -> Path | None:
    if marker.is_dir():
        return marker
    if not marker.is_file():
        return None
    try:
        line = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not line.startswith("gitdir: "):
        return None
    candidate = Path(line.removeprefix("gitdir: "))
    if not candidate.is_absolute():
        candidate = marker.parent / candidate
    try:
        return candidate.resolve(strict=True)
    except OSError:
        return None


def _forge_revision(origin: Path, version: str) -> str:
    for ancestor in origin.parents:
        git_dir = _git_directory(ancestor / ".git")
        if git_dir is None:
            continue
        try:
            head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
            if re.fullmatch(r"[0-9a-fA-F]{40}", head):
                return "git:" + head.lower()
            if head.startswith("ref: "):
                ref = head.removeprefix("ref: ")
                loose = git_dir / ref
                if loose.is_file():
                    value = loose.read_text(encoding="utf-8").strip()
                    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
                        return "git:" + value.lower()
                packed = git_dir / "packed-refs"
                if packed.is_file():
                    for line in packed.read_text(encoding="utf-8").splitlines():
                        if line.startswith(("#", "^")):
                            continue
                        parts = line.split(" ", 1)
                        if len(parts) == 2 and parts[1] == ref:
                            return "git:" + parts[0].lower()
        except OSError:
            break
    return "package:" + version


def _forge_version() -> str:
    try:
        return importlib.metadata.version("nornyx-forge-live-demo")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _verifier_environment() -> dict[str, str]:
    """A small host allowlist; project PATH/PYTHON* state is not inherited."""
    allowed = ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _closed_failure(
    detail: str,
    *,
    command: tuple[str, ...] = (),
    returncode: int = 2,
    provenance: dict[str, Any] | None = None,
) -> tuple[list[GateResult], dict[str, Any]]:
    record = provenance or {
        "schema": "nornyx.forge.verifier_provenance.v1",
        "trust": "not_established",
        "gate_profile": {"id": GREENFIELD_PROFILE_ID},
        "verifier": {"id": GREENFIELD_VERIFIER_ID},
    }
    return (
        [
            GateResult(
                "greenfield:trusted-verifier-identity",
                False,
                detail,
                command,
                returncode,
                record,
            )
        ],
        record,
    )


def trusted_greenfield_gates(root: Path) -> tuple[list[GateResult], dict[str, Any]]:
    """Run the Forge-owned greenfield profile without trusting project state.

    The project is an argument, never the verifier working directory. Both
    executable paths are absolute, ``-I`` ignores project import/environment
    precedence, and the child receives a constructed environment with no PATH,
    PYTHONPATH, or PYTHONHOME. The already-digested verifier bytes execute from
    a private read-only snapshot and run project tests from a second private
    snapshot under OS resource limits.
    """
    try:
        project = Path(root).resolve(strict=True)
        verifier = _greenfield_verifier_path()
        interpreter = Path(sys.executable).resolve(strict=True)
    except OSError as exc:
        return _closed_failure(f"trusted verifier identity cannot be resolved: {exc}")
    if not project.is_dir():
        return _closed_failure(f"greenfield project root is not a directory: {project}")
    if _inside(verifier, project):
        return _closed_failure(
            "trusted verifier is inside the provider workspace; structural trust is absent"
        )
    if _inside(interpreter, project):
        return _closed_failure(
            "Python interpreter is inside the provider workspace; executable trust is absent"
        )

    try:
        verifier_bytes = verifier.read_bytes()
    except OSError as exc:
        return _closed_failure(f"trusted verifier bytes cannot be read: {exc}")
    before_digest = "sha256:" + hashlib.sha256(verifier_bytes).hexdigest()
    forge_version = _forge_version()
    forge_revision = _forge_revision(verifier, forge_version)
    command: tuple[str, ...] = ()
    try:
        with tempfile.TemporaryDirectory(prefix="nornyx-forge-verifier-") as scratch:
            snapshot = Path(scratch) / "greenfield_verifier.py"
            snapshot.write_bytes(verifier_bytes)
            snapshot.chmod(0o444)
            command = (
                str(interpreter),
                "-I",
                str(snapshot),
                "--project-root",
                str(project),
                "--trusted-origin",
                str(verifier),
                "--trusted-digest",
                before_digest,
                "--forge-version",
                forge_version,
                "--forge-revision",
                forge_revision,
            )
            invocation = {
                "python": str(interpreter),
                "isolated_python": True,
                "cwd": str(verifier.parent),
                "environment": "constructed-host-allowlist-without-path-or-pythonpath",
                "verifier_execution": "private-readonly-byte-snapshot",
                "command": list(command),
            }
            completed = subprocess.run(
                command,
                cwd=verifier.parent,
                env=_verifier_environment(),
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )
            snapshot_digest = _digest_file(snapshot)
            execution_origin = str(snapshot.resolve(strict=True))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _closed_failure(
            f"trusted verifier could not run: {type(exc).__name__}: {exc}",
            command=command,
            returncode=124 if isinstance(exc, subprocess.TimeoutExpired) else 2,
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        return _closed_failure(
            f"trusted verifier returned invalid JSON: {exc}; stderr={completed.stderr.strip()!r}",
            command=command,
            returncode=completed.returncode,
        )
    if not isinstance(payload, dict):
        return _closed_failure(
            "trusted verifier result is not an object",
            command=command,
            returncode=completed.returncode,
        )

    profile = payload.get("gate_profile")
    verifier_claim = payload.get("verifier")
    raw_gates = payload.get("gates")
    subject_claim = payload.get("subject")
    resource_limits = payload.get("resource_limits")
    test_execution = payload.get("test_execution")
    after_digest = _digest_file(verifier)
    identity_problems: list[str] = []
    if payload.get("schema") != "nornyx.forge.greenfield_verification.v1":
        identity_problems.append("unexpected verifier result schema")
    expected_profile = {
        **GREENFIELD_PROFILE_DEFINITION,
        "digest": GREENFIELD_PROFILE_DIGEST,
    }
    if profile != expected_profile:
        identity_problems.append("gate profile does not match the parent-owned definition")
    if not isinstance(verifier_claim, dict):
        identity_problems.append("verifier provenance is absent")
    else:
        if verifier_claim.get("id") != GREENFIELD_VERIFIER_ID:
            identity_problems.append("unexpected verifier identity")
        if verifier_claim.get("origin") != str(verifier):
            identity_problems.append("verifier origin does not match the trusted installation")
        if verifier_claim.get("execution_origin") != execution_origin:
            identity_problems.append("verifier execution origin is not the private snapshot")
        if (
            verifier_claim.get("digest") != before_digest
            or verifier_claim.get("execution_digest") != snapshot_digest
            or snapshot_digest != before_digest
            or after_digest != before_digest
        ):
            identity_problems.append("installed or snapshotted verifier digest changed or disagrees")
        if forge_version == "unknown" or verifier_claim.get("forge_version") != forge_version:
            identity_problems.append("Forge version does not match the trusted installation")
        if verifier_claim.get("forge_revision") != forge_revision:
            identity_problems.append("Forge revision does not match the trusted installation")
    if not isinstance(subject_claim, dict):
        identity_problems.append("subject provenance is absent")
    else:
        if subject_claim.get("root") != str(project):
            identity_problems.append("subject root does not match the inspected project")
        if not re_full_digest(subject_claim.get("digest")):
            identity_problems.append("subject digest is absent or malformed")
        file_count = subject_claim.get("file_count")
        if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count < 1:
            identity_problems.append("subject file count is absent or invalid")
    if resource_limits != GREENFIELD_RESOURCE_LIMITS:
        identity_problems.append("OS resource limits do not match the parent-owned policy")
    if not isinstance(test_execution, dict):
        identity_problems.append("test-execution provenance is absent")
    if not isinstance(raw_gates, list):
        identity_problems.append("verifier returned no gate list")
    else:
        raw_ids = [raw.get("id") if isinstance(raw, dict) else None for raw in raw_gates]
        if raw_ids != list(GREENFIELD_GATE_IDS):
            identity_problems.append("verifier gate identifiers do not exactly match the profile")
    if completed.stderr.strip():
        identity_problems.append("trusted verifier wrote unexpected stderr")
    if identity_problems:
        return _closed_failure(
            "; ".join(identity_problems),
            command=command,
            returncode=completed.returncode,
        )

    assert isinstance(profile, dict) and isinstance(verifier_claim, dict)
    provenance = {
        "schema": "nornyx.forge.verifier_provenance.v1",
        "trust": "structural-origin-and-digest",
        "gate_profile": profile,
        "verifier": verifier_claim,
        "subject": subject_claim,
        "resource_limits": resource_limits,
        "test_execution": test_execution,
        "invocation": invocation,
    }
    results: list[GateResult] = []
    identifiers: set[str] = set()
    for raw in raw_gates:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"id", "passed", "detail"}
            or not isinstance(raw.get("id"), str)
            or not isinstance(raw.get("passed"), bool)
            or not isinstance(raw.get("detail"), str)
            or raw["id"] in identifiers
        ):
            return _closed_failure(
                "trusted verifier returned a malformed or duplicate gate record",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
        identifiers.add(raw["id"])
        results.append(
            GateResult(
                f"greenfield:{raw['id']}",
                raw["passed"],
                raw["detail"],
                command,
                0 if raw["passed"] else 2,
                provenance,
            )
        )
    passed = all(result.passed for result in results)
    test_gate = next(result for result in results if result.name == "greenfield:test-execution")
    if test_gate.passed:
        test_command = test_execution.get("command") if isinstance(test_execution, dict) else None
        test_subject = test_execution.get("subject_digest") if isinstance(test_execution, dict) else None
        test_cwd = test_execution.get("cwd") if isinstance(test_execution, dict) else None
        if (
            not isinstance(test_command, list)
            or len(test_command) != 4
            or test_command[:2] != [str(interpreter), "-I"]
            or not Path(test_command[2]).is_absolute()
            or not Path(test_command[3]).is_absolute()
            or _inside(Path(test_command[2]), project)
            or _inside(Path(test_command[3]), project)
            or test_execution.get("isolated_python") is not True
            or test_execution.get("python") != str(interpreter)
            or test_execution.get("environment")
            != "constructed-host-allowlist-without-path-or-pythonpath"
            or test_execution.get("subject") != "private-temporary-copy"
            or test_subject != subject_claim.get("digest")
            or test_cwd != str(verifier.parent)
            or test_execution.get("runner") != "private-readonly-trusted-runner"
            or test_execution.get("runner_digest") != GREENFIELD_TEST_RUNNER_DIGEST
        ):
            return _closed_failure(
                "test-execution provenance does not match the trusted invocation",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
    elif test_execution.get("status") != "not_run":
        # A failing pytest run still has a real invocation record; only a
        # preceding static refusal is represented as not_run.
        test_command = test_execution.get("command")
        if (
            not isinstance(test_command, list)
            or len(test_command) != 4
            or test_command[:2] != [str(interpreter), "-I"]
            or test_execution.get("runner_digest") != GREENFIELD_TEST_RUNNER_DIGEST
        ):
            return _closed_failure(
                "failed test-execution provenance is absent or malformed",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
    expected_status = "pass" if passed else "fail"
    expected_returncode = 0 if passed else 2
    if payload.get("status") != expected_status or completed.returncode != expected_returncode:
        return _closed_failure(
            "verifier status, gate outcomes, and process return code disagree",
            command=command,
            returncode=completed.returncode,
            provenance=provenance,
        )
    return results, provenance


def re_full_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def run(command: tuple[str, ...], *, cwd: Path) -> GateResult:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    detail = (result.stdout + result.stderr).strip()
    return GateResult(" ".join(command), result.returncode == 0, detail, command, result.returncode)


def default_gates(root: Path, *, quick: bool = False) -> list[GateResult]:
    commands: list[tuple[str, ...]] = [
        (sys.executable, "-m", "compileall", "-q", "src", "scripts"),
        (sys.executable, "scripts/validate_repository.py", "--internal"),
        (sys.executable, "scripts/check_architecture.py"),
        (sys.executable, "scripts/check_security.py"),
    ]
    if not quick and shutil.which("pytest"):
        commands.append((sys.executable, "-m", "pytest", "-q"))
    if shutil.which("ruff"):
        commands.append(("ruff", "check", "src", "scripts", "tests"))
    if shutil.which("nornyx"):
        commands.extend(
            [
                ("nornyx", "check", ".nornyx/contracts/forge_control.nyx"),
                ("nornyx", "check", ".nornyx/contracts/architecture_governance.nyx"),
                ("nornyx", "check", ".nornyx/contracts/runtime_network.nyx"),
                ("nornyx", "check", ".nornyx/generated/brd_contract.nyx"),
                (sys.executable, "scripts/prepare_runtime.py"),
            ]
        )
    return [run(command, cwd=root) for command in commands]
