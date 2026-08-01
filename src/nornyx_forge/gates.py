from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .models import GateResult


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
