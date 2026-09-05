"""Bounded bridge to an authenticated local Codex CLI installation.

The Codex sibling of `claude_worker`, deliberately the same shape: construct
with an executable name, `available()` answers whether it can be invoked at
all, `run()` executes one bounded task and reports a `WorkerResult` with the
same failure conventions — 127 when the executable is absent, 124 on timeout,
success exactly when the process exited 0, output passed through verbatim.
Keeping the shape identical is what lets one Provider Contract wrap both
without either adapter carrying translation logic of its own.

THE INVOCATION IS VALIDATED, NOT GUESSED. Flags here were checked against a
real `codex` CLI (codex-cli 0.128.0): `codex exec` is the non-interactive
mode, `--cd` sets the working root, `--json` streams JSONL events to stdout,
`--skip-git-repo-check` permits arbitrary workspaces, and `--sandbox`
selects the execution policy.

TWO MAPPING LIMITS, stated because pretending otherwise would be the exact
dishonesty the contract exists to prevent:

  * `max_turns` has no Codex CLI equivalent. It is accepted for interface
    symmetry and NOT enforced here; the enforced bound is `timeout_seconds`,
    exactly as the subprocess timeout enforces it for the Claude path too.
  * `allowed_tools` has no per-tool equivalent; Codex's real control is the
    sandbox policy, and this worker always passes `--sandbox workspace-write`
    — the bounded default matching what Forge asks of a build worker. The
    tool names are recorded in the prompt so the model sees the intent, but
    the MECHANISM is the sandbox, and this docstring is the disclosure.

THE STREAM IS UTF-8, AND IS DECODED AS UTF-8. Not a detail: `text=True` on its
own decodes with the locale encoding, and PA-01 measured that going wrong two
ways on this adapter's real output under cp1252 -- silent mojibake carried
verbatim into evidence, and an unmapped byte raising out of `run()` where the
contract requires a WorkerResult. See the comment at the call.

The session identifier is parsed from the JSONL event stream when one appears
(`session_id` or `thread_id` keys); absence is recorded as None, never
invented.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import WorkerResult


class CodexWorker:
    """Bounded bridge to an authenticated local Codex CLI installation."""

    def __init__(self, executable: str = "codex") -> None:
        self.executable = executable

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def run(
        self,
        *,
        role: str,
        goal: str,
        workspace: Path,
        allowed_tools: tuple[str, ...],
        max_turns: int = 30,
        timeout_seconds: int = 900,
    ) -> WorkerResult:
        del max_turns  # no Codex CLI equivalent; the enforced bound is the timeout
        if not self.available():
            return WorkerResult(
                role,
                goal,
                False,
                "Codex CLI executable not found",
                returncode=127,
            )
        prompt = (
            f"You are the {role} worker in Nornyx Forge. Execute only this bounded goal:\n"
            f"{goal}\n\n"
            "Read the repository instructions and the relevant Nornyx contracts. "
            "Do not weaken gates, do not claim human approval, and do not perform "
            f"production operations. Intended tools: {', '.join(allowed_tools)}. "
            "Return a concise JSON-compatible result with changed files, checks, "
            "findings, assumptions, and limitations."
        )
        read_only_tools = {"Read", "Glob", "Grep"}
        sandbox = (
            "read-only"
            if set(allowed_tools).issubset(read_only_tools)
            else "workspace-write"
        )
        command = (
            self.executable,
            "exec",
            "--json",
            "--cd",
            str(workspace),
            "--skip-git-repo-check",
            "--sandbox",
            sandbox,
            "--color",
            "never",
            prompt,
        )
        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                text=True,
                # The CLI emits UTF-8. `text=True` alone decodes with the
                # locale encoding, which on a Windows basic-user host is
                # cp1252, and the PA-01 measurement caught both ways that
                # goes wrong on this adapter's REAL output: a right single
                # quote decoded to mojibake and was passed through verbatim
                # into evidence, and a right double quote (byte 0x9d, unmapped
                # in cp1252) raised UnicodeDecodeError on the reader thread,
                # left `stdout` as None, and turned the `result.stdout.strip()`
                # below into an AttributeError escaping `run()` -- which the
                # Provider Contract forbids outright, failure being a
                # WorkerResult and never an exception. Naming the encoding
                # fixes both; `replace` keeps a stray byte from resurrecting
                # the raise.
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=f"Codex worker timed out after {timeout_seconds}s.\n{output}",
                command=command,
                returncode=124,
            )
        output = result.stdout.strip() or result.stderr.strip()
        session_id = _session_from_jsonl(result.stdout)
        return WorkerResult(
            role=role,
            goal=goal,
            success=result.returncode == 0,
            output=output,
            session_id=session_id,
            command=command,
            returncode=result.returncode,
        )


def _session_from_jsonl(stdout: str) -> str | None:
    """The first session/thread identifier the event stream carries, or None.

    `codex exec --json` emits one JSON event per line. Nothing here depends on
    a specific event vocabulary: any event carrying a string `session_id` or
    `thread_id` identifies the session, and a stream carrying neither yields
    None — recorded as absent, never synthesized.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        for key in ("session_id", "thread_id"):
            value = event.get(key)
            if isinstance(value, str) and value:
                return value
    return None
