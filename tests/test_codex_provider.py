"""The Codex adapter's conformance to the Provider Contract.

SAME HARNESS TECHNIQUE, SEPARATE PROOF. These tests exercise the real
`CodexWorker` and real `CodexProviderAdapter` against a controlled fake
executable — real subprocess handling, real timeout, the real 127/124
conventions — exactly as the Claude conformance suite does. What they prove is
that the CODEX adapter satisfies the contract; not one assertion here compares
Codex to Claude, because per-adapter conformance and cross-adapter equivalence
are different properties and the second is pre-registered work.

The two honest mapping limits are pinned rather than hidden:

  * `max_turns` has no Codex CLI equivalent — the adapter accepts it for
    interface symmetry and the enforced bound is the timeout; a test proves
    the parameter does not leak into the command line as an invented flag;
  * `allowed_tools` maps to the sandbox policy, not per-tool allowlists — a
    test pins that the command carries `--sandbox workspace-write` and no
    fabricated tool flag.

The invocation surface itself (exec, --cd, --json, --skip-git-repo-check,
--sandbox) was validated against a real codex-cli 0.128.0 installation; the
fake executable exists so the failure semantics are exercised hermetically,
not to stand in for that validation.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nornyx_forge.codex_worker import CodexWorker, _session_from_jsonl
from nornyx_forge.provider_contract import (
    TIMEOUT_RETURNCODE,
    UNAVAILABLE_RETURNCODE,
    ProviderTask,
)
from nornyx_forge.providers import CodexProviderAdapter

JSONL_EVENT = '{"type": "thread.started", "thread_id": "codex-conf-1"}'


def _fake_cli(tmp_path: Path, *, exit_code: int = 0, sleep_seconds: int = 0,
              stdout: str = JSONL_EVENT) -> str:
    """A controlled executable the real worker can actually run."""
    if os.name == "nt":
        path = tmp_path / "fake-codex.bat"
        lines = ["@echo off"]
        if sleep_seconds:
            lines.append(f"ping -n {sleep_seconds + 1} 127.0.0.1 >nul")
        if stdout:
            lines.append(f"echo {stdout}")
        lines.append(f"exit /b {exit_code}")
        path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8", newline="")
    else:
        path = tmp_path / "fake-codex.sh"
        lines = ["#!/bin/sh"]
        if sleep_seconds:
            lines.append(f"sleep {sleep_seconds}")
        if stdout:
            lines.append(f"printf '%s\\n' '{stdout}'")
        lines.append(f"exit {exit_code}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


def _task(workspace: Path, timeout_seconds: int = 30) -> ProviderTask:
    return ProviderTask(
        role="builder",
        goal="conformance probe: report and exit",
        workspace=str(workspace),
        allowed_tools=("Read", "Write"),
        max_turns=1,
        timeout_seconds=timeout_seconds,
    )


# ---------------------------------------------------------------------------
# Conformance: every ending lands in the vocabulary, through the real worker
# ---------------------------------------------------------------------------

def test_a_successful_run_reports_ok_and_parses_the_thread_id(tmp_path: Path):
    adapter = CodexProviderAdapter(CodexWorker(_fake_cli(tmp_path)))
    result = adapter.run_task(_task(tmp_path))
    assert result.success is True
    assert result.failure_class == "ok"
    assert result.provider == "codex"
    assert result.session_id == "codex-conf-1"
    result.validate()


def test_a_missing_codex_cli_is_unavailable_not_an_error(tmp_path: Path):
    adapter = CodexProviderAdapter(CodexWorker(str(tmp_path / "absent-codex")))
    assert adapter.available() is False
    result = adapter.run_task(_task(tmp_path))
    assert result.failure_class == "unavailable"
    assert result.returncode == UNAVAILABLE_RETURNCODE


def test_a_nonzero_exit_is_an_error_with_output_passed_through(tmp_path: Path):
    adapter = CodexProviderAdapter(
        CodexWorker(_fake_cli(tmp_path, exit_code=2, stdout="auth required"))
    )
    result = adapter.run_task(_task(tmp_path))
    assert result.failure_class == "error"
    assert result.returncode == 2
    assert "auth required" in result.output


def test_a_real_timeout_lands_in_the_timeout_class(tmp_path: Path):
    adapter = CodexProviderAdapter(
        CodexWorker(_fake_cli(tmp_path, sleep_seconds=3))
    )
    result = adapter.run_task(_task(tmp_path, timeout_seconds=1))
    assert result.failure_class == "timeout"
    assert result.returncode == TIMEOUT_RETURNCODE


# ---------------------------------------------------------------------------
# The command line: validated conventions, and no invented flags
# ---------------------------------------------------------------------------

def test_the_command_uses_the_validated_codex_conventions(tmp_path: Path):
    """The invocation is exec/--cd/--json/--skip-git-repo-check/--sandbox —
    the surface checked against a real codex-cli 0.128.0 — with the workspace
    where --cd points and the goal inside the prompt argument."""
    result = CodexWorker(_fake_cli(tmp_path)).run(
        role="builder", goal="probe goal", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    command = result.command
    assert command[1] == "exec"
    assert "--json" in command
    assert "--skip-git-repo-check" in command
    cd_index = command.index("--cd")
    assert command[cd_index + 1] == str(tmp_path)
    assert "probe goal" in command[-1]


def test_max_turns_does_not_leak_into_the_command_as_an_invented_flag(tmp_path: Path):
    """The disclosed mapping limit, pinned: max_turns has no Codex equivalent,
    so no flag spelling it may appear — an invented --max-turns would be the
    adapter pretending a control it does not have."""
    result = CodexWorker(_fake_cli(tmp_path)).run(
        role="builder", goal="g", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=7, timeout_seconds=30,
    )
    # Only FLAG-shaped elements are inspected: a first draft scanned every
    # element and caught the --cd path, because pytest embeds this test's own
    # name (containing "turns") in the tmp directory — a spelling scan
    # colliding with its own scaffolding. The property is about flags.
    flags = [part for part in result.command if part.startswith("-")]
    assert not any("turn" in flag.lower() for flag in flags), (
        f"a max-turns flag was invented for a CLI that has none: {flags}"
    )
    assert "7" not in result.command, "the unmappable max_turns value leaked into the command"


def test_allowed_tools_map_to_the_sandbox_not_to_fabricated_flags(tmp_path: Path):
    """The other disclosed limit: the mechanism is the sandbox policy."""
    result = CodexWorker(_fake_cli(tmp_path)).run(
        role="builder", goal="g", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    sandbox_index = result.command.index("--sandbox")
    assert result.command[sandbox_index + 1] == "workspace-write"
    assert not any("allowedTools" in part for part in result.command), (
        "a Claude-shaped tool flag was fabricated for the Codex CLI"
    )


# ---------------------------------------------------------------------------
# Session parsing: recorded when present, absent when absent
# ---------------------------------------------------------------------------

def test_session_parsing_reads_jsonl_and_never_invents():
    assert _session_from_jsonl('{"session_id": "s-1"}\n{"type": "x"}') == "s-1"
    assert _session_from_jsonl('{"type": "thread.started", "thread_id": "t-9"}') == "t-9"
    assert _session_from_jsonl("not json at all\n{}") is None
    assert _session_from_jsonl('{"session_id": ""}') is None
    assert _session_from_jsonl("") is None


def test_a_stream_without_identifiers_records_none(tmp_path: Path):
    adapter = CodexProviderAdapter(
        CodexWorker(_fake_cli(tmp_path, stdout='{"type": "turn.completed"}'))
    )
    result = adapter.run_task(_task(tmp_path))
    assert result.success is True
    assert result.session_id is None, "a session identifier was invented"


# ---------------------------------------------------------------------------
# Contract discipline carried over
# ---------------------------------------------------------------------------

def test_an_invalid_task_is_refused_before_any_execution(tmp_path: Path):
    """run_task validates first; a bad task must not reach the executable.
    The sentinel is the fake CLI writing its marker only when invoked."""
    marker = tmp_path / "invoked.txt"
    if os.name == "nt":
        cli = tmp_path / "marking-codex.bat"
        cli.write_text(f"@echo off\r\necho ran> \"{marker}\"\r\nexit /b 0\r\n",
                       encoding="utf-8", newline="")
    else:
        cli = tmp_path / "marking-codex.sh"
        cli.write_text(f"#!/bin/sh\necho ran > '{marker}'\nexit 0\n",
                       encoding="utf-8", newline="")
        cli.chmod(0o755)

    adapter = CodexProviderAdapter(CodexWorker(str(cli)))
    bad = ProviderTask(role="builder", goal=" ", workspace=str(tmp_path),
                       allowed_tools=("Read",))
    with pytest.raises(Exception, match="goal"):
        adapter.run_task(bad)
    assert not marker.exists(), "an invalid task reached the executable"
