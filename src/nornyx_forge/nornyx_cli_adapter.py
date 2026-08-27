"""Run the Nornyx CLI. Process execution, and nothing else.

A declared adapter because starting a process is an external effect, and the
domain has no business doing it — `prepare_runtime_contract` shelled out from
`layer.domain`, which the domain process-execution prohibition now refuses.

The split is deliberate and narrow. This module decides *nothing*: it does not
mint an approval, judge risk, interpret whether a governance decision passed, or
determine whether a consequential effect is permitted. It invokes a command and
reports what happened. Deciding that runtime-contract preparation is required,
and interpreting the structured result, stay where they belong — moving the
governance decision here merely because the subprocess lives here would relocate
the thing the layering exists to keep separate.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NornyxCheckResult:
    """What a Nornyx CLI invocation did. An observation, not a verdict."""

    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str

    @property
    def detail(self) -> str:
        return (self.stdout + self.stderr).strip()


def run_nornyx(command: tuple[str, ...], *, cwd: Path) -> NornyxCheckResult:
    """Invoke the Nornyx CLI and report the outcome.

    `encoding` is stated rather than inherited. Without it the locale codec
    decodes the output — cp1252 on a Windows workstation — and UTF-8 diagnostics
    raise `UnicodeDecodeError` instead of being read, turning a governed refusal
    into a crash on one platform and not another.
    """
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return NornyxCheckResult(
        command=tuple(command),
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
