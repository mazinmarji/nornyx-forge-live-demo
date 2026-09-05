"""Bounded bridge to an authenticated local Claude Code installation.

THE STREAM IS UTF-8, AND IS DECODED AS UTF-8, STRICTLY. Not a detail, and not
a theoretical one: the sibling Codex adapter was measured failing this two
ways on real CLI output under a Windows basic-user host, where the locale
encoding is cp1252. `subprocess.run(..., text=True)` with no encoding named
decodes with that locale codec, and a provider that emits typographic
characters -- both CLIs do -- then produces either silent corruption or a
crash, depending on which byte arrives first:

  * a right single quote (U+2019) has a cp1252 mapping, so it decodes to
    MOJIBAKE and is passed through verbatim into the WorkerResult and onward
    into evidence, while the run reports success and everything looks healthy;
  * a right double quote (U+201D) carries byte 0x9d, which is unmapped in
    cp1252, so the reader thread raises, `stdout` comes back None, and
    `result.stdout.strip()` becomes an AttributeError escaping `run()` --
    which the Provider Contract forbids outright, failure being a
    WorkerResult and never an exception.

AND NOT `errors="replace"` EITHER, which is the repair that looks right and
is not. Replacement turns malformed bytes into U+FFFD and hands them on as
ordinary text, so a run whose output could not be read reports success and
prose. Both failures are the same failure -- evidence that is not what the
provider actually emitted -- and one of them is much harder to notice. So
decoding is strict, a stream that fails it yields a WorkerResult that RECORDS
the integrity failure with the payload's length and digest, and the run is
not successful whatever the process exited with. Valid UTF-8 is preserved
exactly.

This repair is the Claude half of a defect found while measuring the Codex
adapter; the Codex half is a separate bounded change, and neither adapter's
confinement or eligibility is touched by either.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from .models import WorkerResult


class ClaudeCodeWorker:
    """Bounded bridge to an authenticated local Claude Code installation."""

    def __init__(self, executable: str = "claude") -> None:
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
        if not self.available():
            return WorkerResult(
                role,
                goal,
                False,
                "Claude Code executable not found",
                returncode=127,
            )
        prompt = (
            f"You are the {role} worker in Nornyx Forge. Execute only this bounded goal:\n"
            f"{goal}\n\n"
            "Read CLAUDE.md and the relevant Nornyx contracts. Do not weaken gates, "
            "do not claim human approval, and do not perform production operations. "
            "Return a concise JSON-compatible result with changed files, checks, "
            "findings, assumptions, and limitations."
        )
        command = (
            self.executable,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--max-turns",
            str(max_turns),
            "--allowedTools",
            ",".join(allowed_tools),
        )
        try:
            # BYTES, DECODED BELOW RATHER THAN BY subprocess. See the module
            # docstring: `text=True` alone decodes with the locale encoding,
            # and the sibling adapter was measured corrupting and then
            # crashing on real CLI output because of it.
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
                output=f"Claude Code worker timed out after {timeout_seconds}s.{note}\n"
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
                output="Claude Code worker output failed UTF-8 integrity and was "
                       "NOT decoded with replacement: " + "; ".join(problems)
                       + f". Process exited {result.returncode}. "
                       + _fingerprint("stdout", result.stdout) + " "
                       + _fingerprint("stderr", result.stderr),
                command=command,
                returncode=result.returncode,
            )

        output = stdout.strip() or stderr.strip()
        session_id = None
        try:
            parsed = json.loads(stdout)
            session_id = parsed.get("session_id") if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, TypeError):
            pass
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
