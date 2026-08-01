from __future__ import annotations

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
            result = subprocess.run(
                command,
                cwd=workspace,
                text=True,
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
                output=f"Claude Code worker timed out after {timeout_seconds}s.\n{output}",
                command=command,
                returncode=124,
            )
        output = result.stdout.strip() or result.stderr.strip()
        session_id = None
        try:
            parsed = json.loads(result.stdout)
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
