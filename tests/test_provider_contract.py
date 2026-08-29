"""The Provider Contract, and the Claude path's observable behaviour preserved.

TWO PROPERTIES, held separately because they fail differently:

  * CONFORMANCE — the adapter satisfies the contract: availability is honest,
    every ending lands in the closed failure vocabulary via the one mapping,
    results validate, and the registry refuses what it cannot serve. These run
    the REAL adapter and the REAL worker against a controlled fake executable,
    so the code under test is the shipping path, not a reimplementation.

  * PRESERVATION — wrapping changed nothing observable: for identical inputs,
    the adapter's result fields EQUAL the raw `ClaudeCodeWorker` result's,
    field by field. This is the founder's invariance rule made mechanical —
    any drift between the wrapped and unwrapped path is a red test here, and
    `claude_worker` itself is untouched at its pinned import path.

The fake executable exists so failure semantics are EXERCISED, not simulated:
exit 0 with JSON, a chosen nonzero exit, and a real timeout all pass through
the worker's actual subprocess handling, including the 127/124 conventions.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nornyx_forge.capsule import PROVIDERS
from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.provider_contract import (
    FAILURE_CLASSES,
    TIMEOUT_RETURNCODE,
    UNAVAILABLE_RETURNCODE,
    ProviderError,
    ProviderResult,
    ProviderTask,
    classify_result,
    result_from_worker,
    validate_adapter_identity,
)
from nornyx_forge.providers import ClaudeProviderAdapter, get_provider


def _fake_cli(tmp_path: Path, *, exit_code: int = 0, sleep_seconds: int = 0,
              stdout: str = '{"session_id": "conf-1"}') -> str:
    """A controlled executable the real worker can actually run.

    Platform-appropriate: a .bat on Windows, a shebang script elsewhere —
    because the property under test includes the worker's real subprocess
    handling, which a monkeypatched `subprocess.run` would bypass.
    """
    if os.name == "nt":
        path = tmp_path / "fake-provider.bat"
        lines = ["@echo off"]
        if sleep_seconds:
            lines.append(f"ping -n {sleep_seconds + 1} 127.0.0.1 >nul")
        if stdout:
            lines.append(f"echo {stdout}")
        lines.append(f"exit /b {exit_code}")
        path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8", newline="")
    else:
        path = tmp_path / "fake-provider.sh"
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
# Conformance: the real adapter over the real worker, endings exercised
# ---------------------------------------------------------------------------

def test_a_successful_run_reports_ok_and_parses_the_session(tmp_path: Path):
    adapter = ClaudeProviderAdapter(ClaudeCodeWorker(_fake_cli(tmp_path)))
    result = adapter.run_task(_task(tmp_path))
    assert result.success is True
    assert result.failure_class == "ok"
    assert result.returncode == 0
    assert result.session_id == "conf-1"
    assert result.provider == "claude"
    result.validate()


def test_a_missing_executable_is_unavailable_not_an_error(tmp_path: Path):
    """The 127 convention survives the wrapping, and availability is honest."""
    adapter = ClaudeProviderAdapter(ClaudeCodeWorker(str(tmp_path / "does-not-exist")))
    assert adapter.available() is False
    result = adapter.run_task(_task(tmp_path))
    assert result.failure_class == "unavailable"
    assert result.returncode == UNAVAILABLE_RETURNCODE
    assert result.success is False


def test_a_nonzero_exit_is_an_error_with_output_passed_through(tmp_path: Path):
    adapter = ClaudeProviderAdapter(
        ClaudeCodeWorker(_fake_cli(tmp_path, exit_code=3, stdout="it broke"))
    )
    result = adapter.run_task(_task(tmp_path))
    assert result.failure_class == "error"
    assert result.returncode == 3
    assert "it broke" in result.output, "the provider's own words were not passed through"


def test_a_real_timeout_lands_in_the_timeout_class(tmp_path: Path):
    """Exercised, not simulated: the fake CLI genuinely outlives the budget."""
    adapter = ClaudeProviderAdapter(
        ClaudeCodeWorker(_fake_cli(tmp_path, sleep_seconds=3))
    )
    result = adapter.run_task(_task(tmp_path, timeout_seconds=1))
    assert result.failure_class == "timeout"
    assert result.returncode == TIMEOUT_RETURNCODE
    assert result.success is False


# ---------------------------------------------------------------------------
# Preservation: wrapping changed nothing observable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ending", ["success", "error", "unavailable"])
def test_the_adapter_equals_the_raw_worker_field_for_field(tmp_path: Path, ending: str):
    """THE INVARIANCE PROOF. Same inputs, wrapped and unwrapped; the shared
    fields must be EQUAL — success, output, returncode, session_id, command.
    The adapter adds vocabulary (provider, failure_class); it may change
    nothing it inherited."""
    if ending == "success":
        executable = _fake_cli(tmp_path)
    elif ending == "error":
        executable = _fake_cli(tmp_path, exit_code=5, stdout="boom")
    else:
        executable = str(tmp_path / "absent-cli")

    task = _task(tmp_path)
    raw = ClaudeCodeWorker(executable).run(
        role=task.role, goal=task.goal, workspace=tmp_path,
        allowed_tools=task.allowed_tools, max_turns=task.max_turns,
        timeout_seconds=task.timeout_seconds,
    )
    wrapped = ClaudeProviderAdapter(ClaudeCodeWorker(executable)).run_task(task)

    assert wrapped.success == raw.success
    assert wrapped.output == raw.output
    assert wrapped.returncode == raw.returncode
    assert wrapped.session_id == raw.session_id
    assert wrapped.command == raw.command
    assert wrapped.role == raw.role and wrapped.goal == raw.goal


def test_claude_worker_is_untouched_at_its_pinned_path():
    """The module architecture guards pin must still be exactly itself:
    importable at its path, with subprocess in run's globals — the anchor
    tests/test_module_acquisition_limits.py reaches through."""
    import nornyx_forge.claude_worker as worker_module

    assert worker_module.ClaudeCodeWorker is ClaudeCodeWorker
    assert "subprocess" in ClaudeCodeWorker.run.__globals__


# ---------------------------------------------------------------------------
# The vocabulary and its one mapping
# ---------------------------------------------------------------------------

def test_the_classification_mapping_is_total_and_exact():
    assert classify_result(True, 0) == "ok"
    assert classify_result(False, UNAVAILABLE_RETURNCODE) == "unavailable"
    assert classify_result(False, TIMEOUT_RETURNCODE) == "timeout"
    for code in (1, 2, 3, 5, 99, -1):
        assert classify_result(False, code) == "error"
    assert set(FAILURE_CLASSES) == {"ok", "unavailable", "timeout", "error"}


def test_a_result_cannot_claim_success_with_a_failing_class():
    """success and failure_class are one fact in two spellings; disagreement
    is refused so no adapter can report a green word over a red code."""
    with pytest.raises(ProviderError, match="disagree"):
        ProviderResult(
            provider="claude", role="builder", goal="g", success=True,
            output="", failure_class="error", returncode=1,
        ).validate()
    with pytest.raises(ProviderError, match="disagree"):
        ProviderResult(
            provider="claude", role="builder", goal="g", success=False,
            output="", failure_class="ok", returncode=0,
        ).validate()


def test_task_validation_refuses_bad_shapes(tmp_path: Path):
    good = _task(tmp_path)
    for bad in (
        {"role": ""}, {"goal": " "}, {"workspace": ""},
        {"allowed_tools": ()}, {"allowed_tools": ("Read,Write",)},
        {"max_turns": 0}, {"timeout_seconds": 0}, {"timeout_seconds": 10**6},
    ):
        fields = {**good.__dict__, **bad}
        with pytest.raises(ProviderError):
            ProviderTask(**fields).validate()


# ---------------------------------------------------------------------------
# The registry: names are not capabilities
# ---------------------------------------------------------------------------

def test_the_registry_serves_claude_and_validates_its_identity():
    adapter = get_provider("claude")
    assert adapter.name == "claude"
    validate_adapter_identity(adapter)


def test_codex_is_declared_and_served_with_validated_identity():
    """The refusal guard's successor, changed ON PURPOSE in the Codex slice.

    Until the Codex adapter existed, this test held the registry to an honest
    refusal — a declared name is not a capability. The adapter now exists, so
    the same site holds the successor property: codex is served, its identity
    validates, and it is a DIFFERENT adapter from Claude's — served does not
    mean merged, and nothing about equivalence is asserted by either."""
    assert "codex" in PROVIDERS
    adapter = get_provider("codex")
    assert adapter.name == "codex"
    validate_adapter_identity(adapter)
    assert type(adapter) is not type(get_provider("claude"))


def test_an_undeclared_provider_is_refused_as_undeclared():
    with pytest.raises(ProviderError, match="not a declared provider name"):
        get_provider("gemini")


def test_an_impostor_adapter_is_refused_by_identity_validation():
    class Impostor:
        name = "gemini"

        def available(self) -> bool:
            return True

        def run_task(self, task):
            raise AssertionError("must never be reached")

    with pytest.raises(ProviderError, match="not a declared provider"):
        validate_adapter_identity(Impostor())

    class WrongSurface:
        name = "claude"

    with pytest.raises(ProviderError, match="does not implement"):
        validate_adapter_identity(WrongSurface())


def test_normalization_never_improves_the_news():
    """result_from_worker passes observations through and derives the class;
    it must refuse shapes it cannot read rather than defaulting them."""
    normalized = result_from_worker("claude", {
        "role": "builder", "goal": "g", "success": False, "output": "raw words",
        "returncode": 3, "session_id": None, "command": ("x",),
    })
    assert normalized.failure_class == "error"
    assert normalized.output == "raw words"

    with pytest.raises(ProviderError, match="boolean success"):
        result_from_worker("claude", {"success": "yes", "returncode": 0})
