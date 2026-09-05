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
import sys
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


# ---------------------------------------------------------------------------
# Non-ASCII provider output: preserved exactly, or refused as an integrity
# failure -- never silently replaced
# ---------------------------------------------------------------------------

def _emitting_cli(tmp_path: Path, name: str, payload: bytes) -> str:
    """A controlled executable that writes exact BYTES to stdout.

    `_fake_cli` echoes through the shell, which cannot express an arbitrary
    byte; these specimens are about bytes, so the payload is written by a
    Python one-liner through `sys.stdout.buffer`.
    """
    emitter = tmp_path / f"emit_{name}.py"
    emitter.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(b'before ' + " + repr(payload) + " + b' after')\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        path = tmp_path / f"bytes-provider-{name}.bat"
        path.write_text(f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n',
                        encoding="utf-8", newline="")
    else:
        path = tmp_path / f"bytes-provider-{name}.sh"
        path.write_text(f'#!/bin/sh\n"{sys.executable}" "{emitter}"\n',
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("right_single_quote", b"\xe2\x80\x99"),
        ("right_double_quote", b"\xe2\x80\x9d"),
        ("box_drawing", b"\xe2\x94\x80"),
    ],
)
def test_utf8_provider_output_neither_raises_nor_is_corrupted(
    tmp_path: Path, name: str, payload: bytes
):
    """Valid UTF-8 must reach the result as itself.

    The CLI emits UTF-8 and its prose carries typographic characters.
    `subprocess.run(..., text=True)` with no encoding named decodes with the
    LOCALE codec, which on a Windows basic-user host is cp1252: a right single
    quote then decodes to mojibake and is passed through verbatim into
    evidence, while a right double quote (byte 0x9d, unmapped in cp1252)
    raises on the reader thread, leaves `stdout` as None, and turns the next
    line into an AttributeError escaping `run()` -- an exception where the
    Provider Contract requires a WorkerResult.

    Asserted on the exact text, not merely on "did not raise": an adapter that
    silently mangled every quotation mark would satisfy the weaker check.
    """
    worker = ClaudeCodeWorker(_emitting_cli(tmp_path, name, payload))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is True
    assert result.output == "before " + payload.decode("utf-8") + " after", (
        f"the provider's own bytes must reach the result undamaged; "
        f"got {result.output!r}"
    )


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("lone_continuation", b"\x80"),
        ("truncated_sequence", b"\xe2\x80"),
        ("invalid_start_byte", b"\xff\xfe"),
    ],
)
def test_malformed_output_is_recorded_as_an_integrity_failure_not_replaced(
    tmp_path: Path, name: str, payload: bytes
):
    """Bytes that are not UTF-8 must not become text that looks like prose.

    `errors="replace"` is the repair that looks right: it stops the crash, and
    it converts every malformed byte into U+FFFD, which then travels into the
    WorkerResult and onward into evidence as ordinary characters. The run
    reports SUCCESS and its output reads as something the provider wrote. That
    is a worse failure than the crash it replaces, because nothing about it
    looks wrong.

    Three properties, separate on purpose:

      * `run()` does not raise -- the Provider Contract requires a
        WorkerResult, and an exception for task failure is a contract
        violation;
      * the result is NOT successful, whatever the process exited with, so a
        clean exit cannot launder unreadable output;
      * the output NAMES the decode failure and carries no U+FFFD, so no
        substituted character can be mistaken for provider text.
    """
    worker = ClaudeCodeWorker(_emitting_cli(tmp_path, name, payload))
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )

    assert result.success is False, (
        "output that could not be decoded must not be reported as a successful "
        f"run; got {result.output!r}"
    )
    assert "\ufffd" not in result.output, (
        "the replacement character reached the result, so malformed bytes are "
        "being carried as though they were text the provider wrote"
    )
    assert "UTF-8" in result.output and "integrity" in result.output, (
        f"the failure does not say what went wrong: {result.output!r}"
    )
    assert "sha256:" in result.output, (
        "the undecodable payload is neither rendered nor identified, so the "
        "evidence cannot be traced back to what was actually emitted"
    )


def test_a_malformed_run_still_lands_in_the_failure_vocabulary(tmp_path: Path):
    """The contract's own view: a decode failure is an `error`, never `ok`.

    Held through `result_from_worker`, the one mapping, because an adapter
    that returned a not-successful result with a zero returncode would
    otherwise be free to normalize back into the success class.
    """
    worker = ClaudeCodeWorker(_emitting_cli(tmp_path, "vocab", b"\xff\xfe"))
    raw = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    normalized = result_from_worker("claude", raw)
    assert normalized.failure_class == "error"
    assert normalized.success is False
    normalized.validate()
