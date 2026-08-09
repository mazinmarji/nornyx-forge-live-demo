"""Prepare and verify the Nornyx runtime contract. Application, not domain.

This lived in `nornyx_runtime`, a `layer.domain` module, and shelled out to the
Nornyx CLI from there. Moving the subprocess into an adapter exposed the real
misplacement rather than fixing it: domain may not depend on an adapter, and
this function is not domain logic. It sequences CLI invocations and interprets
their results, which is application work.

The layering now reads: this module decides that preparation is required and
what the outcome means; `nornyx_cli_adapter` starts the process and reports what
happened; neither judges whether a consequential effect may be released.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .models import GateResult
from .nornyx_cli_adapter import run_nornyx
from .nornyx_runtime import (
    RUNTIME_CONTRACT,
    runtime_as_of,
)
from .util import write_json


def prepare_runtime_contract(root: Path, *, as_of: str | None = None) -> list[GateResult]:
    """Validate, generate, lock, and verify the runtime contract with Nornyx.

    Every step receives the same explicit evaluation instant, including the
    initial ``check``. Leaving ``check`` on the live clock while the lock steps
    used a pinned instant meant the two could disagree about whether an approval
    was still valid.

    The generated artifacts are intentionally outside tracked source. When the
    CLI is unavailable the caller receives a failed gate rather than a fabricated
    success.
    """

    executable = shutil.which("nornyx")
    if not executable:
        return [GateResult("nornyx runtime preparation", False, "nornyx CLI not installed", (), 127)]
    moment = runtime_as_of(as_of)
    contract = root / RUNTIME_CONTRACT
    out = root / ".nornyx/runtime"
    artifacts = out / "control_artifacts"
    lock = out / "nornyx.agentic_network.lock"
    out.mkdir(parents=True, exist_ok=True)
    commands = [
        (executable, "check", str(contract), "--as-of", moment),
        (
            executable,
            "agentic-network",
            "generate",
            str(contract),
            "--out",
            str(artifacts),
            "--as-of",
            moment,
        ),
        (
            executable,
            "agentic-network",
            "lock",
            str(contract),
            "--artifacts",
            str(artifacts),
            "--out",
            str(lock),
            "--as-of",
            moment,
        ),
        (
            executable,
            "agentic-network",
            "lock-check",
            str(contract),
            "--lock",
            str(lock),
            "--artifacts",
            str(artifacts),
            "--as-of",
            moment,
        ),
    ]
    results: list[GateResult] = []
    for command in commands:
        # Process execution belongs to the adapter; deciding what the outcome
        # means stays here. The adapter reports an exit code and streams and
        # judges nothing.
        outcome = run_nornyx(tuple(command), cwd=root)
        result = GateResult(
            name=" ".join(command[1:3]),
            passed=outcome.exit_code == 0,
            detail=outcome.detail,
            command=outcome.command,
            returncode=outcome.exit_code,
        )
        results.append(result)
        if not result.passed:
            break
    write_json(out / "preparation-report.json", [item.__dict__ for item in results])
    return results
