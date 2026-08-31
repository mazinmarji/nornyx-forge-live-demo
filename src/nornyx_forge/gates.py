from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .models import GateResult

GREENFIELD_PROFILE_ID = "nornyx.greenfield.python.v1"
GREENFIELD_VERIFIER_ID = "nornyx_forge.greenfield_verifier"


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

    The project is an argument, never the verifier working directory.  Both
    executable paths are absolute, ``-I`` ignores project import/environment
    precedence, and the child receives a constructed environment with no PATH,
    PYTHONPATH, or PYTHONHOME.  The verifier itself executes no external tool.
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

    before_digest = _digest_file(verifier)
    command = (
        str(interpreter),
        "-I",
        str(verifier),
        "--project-root",
        str(project),
    )
    invocation = {
        "python": str(interpreter),
        "isolated_python": True,
        "cwd": str(verifier.parent),
        "environment": "constructed-host-allowlist-without-path-or-pythonpath",
        "command": list(command),
    }
    try:
        completed = subprocess.run(
            command,
            cwd=verifier.parent,
            env=_verifier_environment(),
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
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
    after_digest = _digest_file(verifier)
    identity_problems: list[str] = []
    if payload.get("schema") != "nornyx.forge.greenfield_verification.v1":
        identity_problems.append("unexpected verifier result schema")
    if not isinstance(profile, dict) or profile.get("id") != GREENFIELD_PROFILE_ID:
        identity_problems.append("unexpected gate profile identity")
    if not isinstance(profile, dict) or not re_full_digest(profile.get("digest")):
        identity_problems.append("gate profile digest is absent or malformed")
    if not isinstance(verifier_claim, dict):
        identity_problems.append("verifier provenance is absent")
    else:
        if verifier_claim.get("id") != GREENFIELD_VERIFIER_ID:
            identity_problems.append("unexpected verifier identity")
        if verifier_claim.get("origin") != str(verifier):
            identity_problems.append("verifier origin does not match the invoked file")
        if verifier_claim.get("digest") != before_digest or after_digest != before_digest:
            identity_problems.append("verifier digest changed or does not match the invoked file")
        if verifier_claim.get("forge_version") in {None, "", "unknown"}:
            identity_problems.append("Forge version is unavailable")
        if not isinstance(verifier_claim.get("forge_revision"), str):
            identity_problems.append("Forge revision provenance is unavailable")
    if not isinstance(raw_gates, list) or not raw_gates:
        identity_problems.append("verifier returned no gates")
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
        "invocation": invocation,
    }
    results: list[GateResult] = []
    identifiers: set[str] = set()
    for raw in raw_gates:
        if (
            not isinstance(raw, dict)
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
