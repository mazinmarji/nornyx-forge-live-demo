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

THE STREAM IS UTF-8, AND IS DECODED AS UTF-8, STRICTLY. Not a detail:
`text=True` on its own decodes with the locale encoding, and PA-01 measured
that going wrong two ways on this adapter's real output under cp1252 -- silent
mojibake carried verbatim into evidence, and an unmapped byte raising out of
`run()` where the contract requires a WorkerResult.

AND NOT `errors="replace"` EITHER, which is the repair that looks right and
is not. Replacement turns malformed bytes into U+FFFD and hands them on as
ordinary text, so a run whose output could not be read reports success and
prose. Both failures are the same failure -- evidence that is not what the
provider actually emitted -- and one of them is harder to notice. So decoding
is strict, a stream that fails it yields a WorkerResult that RECORDS the
integrity failure with the payload's length and digest, and the run is not
successful whatever the process exited with. Valid UTF-8 is preserved exactly.

The session identifier is parsed from the JSONL event stream when one appears
(`session_id` or `thread_id` keys); absence is recorded as None, never
invented.
"""

from __future__ import annotations

import hashlib
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
            # BYTES, DECODED HERE RATHER THAN BY subprocess. `text=True` alone
            # decodes with the locale encoding -- cp1252 on a Windows
            # basic-user host -- and PA-01 caught both ways that goes wrong on
            # this adapter's REAL output: a right single quote became mojibake
            # carried verbatim into evidence, and a right double quote (byte
            # 0x9d, unmapped in cp1252) raised on the reader thread, left
            # `stdout` as None, and became an AttributeError escaping `run()`.
            # Decoding here makes the encoding explicit AND keeps the failure
            # a WorkerResult, which is what the Provider Contract requires.
            result = subprocess.run(
                command,
                cwd=workspace,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            out, out_problem = _decode(exc.stdout, "stdout")
            err, err_problem = _decode(exc.stderr, "stderr")
            note = "".join(f"\n{p}" for p in (out_problem, err_problem) if p)
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=f"Codex worker timed out after {timeout_seconds}s.{note}\n"
                       + out + err,
                command=command,
                returncode=124,
            )

        stdout, stdout_problem = _decode(result.stdout, "stdout")
        stderr, stderr_problem = _decode(result.stderr, "stderr")
        problems = [p for p in (stdout_problem, stderr_problem) if p]
        if problems:
            # NOT `errors="replace"`. Substituting U+FFFD would let malformed
            # bytes enter the WorkerResult as ordinary text, and evidence that
            # reads as text the provider wrote is worse than evidence that
            # says it could not be read: the run would look successful and its
            # output would look like prose. So the decode failure IS the
            # result, the run is not successful whatever the process exited
            # with, and the undecodable payload is described -- length and
            # digest, for forensics -- rather than rendered.
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output="Codex worker output failed UTF-8 integrity and was NOT "
                       "decoded with replacement: " + "; ".join(problems)
                       + f". Process exited {result.returncode}. "
                       + _fingerprint("stdout", result.stdout) + " "
                       + _fingerprint("stderr", result.stderr),
                command=command,
                returncode=result.returncode,
            )

        output = stdout.strip() or stderr.strip()
        session_id = _session_from_jsonl(stdout)
        return WorkerResult(
            role=role,
            goal=goal,
            success=result.returncode == 0,
            output=output,
            session_id=session_id,
            command=command,
            returncode=result.returncode,
        )


def _decode(raw: bytes | str | None, stream: str) -> tuple[str, str | None]:
    """Decode one captured stream as UTF-8, STRICTLY, and say so when it fails.

    Returns the text and `None` when the bytes are valid UTF-8 -- preserved
    exactly, so a typographic quote survives as itself. Returns empty text and
    a description when they are not. Never raises and never substitutes: the
    caller decides what a failed stream means, and the one thing it must not
    mean is "here is some text".
    """
    if raw is None:
        return "", None
    if isinstance(raw, str):  # a caller that already decoded; nothing to check
        return raw, None
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return "", (
            f"{stream} is not valid UTF-8 ({exc.reason} at byte {exc.start})"
        )


def _fingerprint(stream: str, raw: bytes | str | None) -> str:
    """Identify an undecodable payload without pretending it is text."""
    if raw is None:
        return f"{stream}: absent."
    data = raw.encode("utf-8", "surrogatepass") if isinstance(raw, str) else raw
    return (
        f"{stream}: {len(data)} bytes, "
        f"sha256:{hashlib.sha256(data).hexdigest()}."
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
