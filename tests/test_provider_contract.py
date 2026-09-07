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

import errno
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from nornyx_forge import codex_worker as _codex_worker_module
from nornyx_forge.capsule import PROVIDERS
from nornyx_forge.claude_worker import (
    MALFORMED_INVOCATION_RETURNCODE,
    PROVIDER_TEXT_DELIMITER,
    SESSION_ID_MAX_LENGTH,
    WINDOWS_COMMAND_LINE_LIMIT,
    ClaudeCodeWorker,
)
from nornyx_forge.claude_worker import (
    _argument_list_too_long as _claude_argument_list_too_long,
)
from nornyx_forge.claude_worker import _command_line_length as _claude_command_line_length
from nornyx_forge.claude_worker import _decode as _claude_decode
from nornyx_forge.claude_worker import _fingerprint as _claude_fingerprint
from nornyx_forge.claude_worker import _validated_session_id as _claude_validated_session_id
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
from nornyx_forge.util import digest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from provider_specimens import PREFIX as _PREFIX  # noqa: E402
from provider_specimens import RENDERINGS as _RENDERINGS  # noqa: E402
from provider_specimens import SESSION_ID_SPECIMENS as _SESSION_ID_SPECIMENS  # noqa: E402
from provider_specimens import (  # noqa: E402
    assert_forge_account_precedes_provider_text as _assert_forge_account_precedes_provider_text,
)
from provider_specimens import (  # noqa: E402
    assert_identified_not_rendered as _assert_identified_not_rendered,
)
from provider_specimens import deep_nested_json as _deep_nested_json  # noqa: E402
from provider_specimens import emitted as _emitted  # noqa: E402
from provider_specimens import emitting_cli as _emitting_cli  # noqa: E402
from provider_specimens import emitting_cli_mixed as _emitting_cli_mixed  # noqa: E402
from provider_specimens import (  # noqa: E402
    expected_command_line_length as _expected_command_line_length,
)
from provider_specimens import raw_stdout_cli as _raw_stdout_cli  # noqa: E402
from provider_specimens import segment as _segment  # noqa: E402


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

#: The four specimen-building helpers above this section used to be defined
#: here, duplicated near-verbatim in tests/test_codex_provider.py. They now
#: live in tests/provider_specimens.py, imported above, so a fix to what
#: "identified, not rendered" means reaches both adapters' proofs from one
#: place instead of two copies that can drift.


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


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("lone_continuation", b"\x80"),
        ("truncated_sequence", b"\xe2\x80"),
        ("invalid_start_byte", b"\xff\xfe"),
    ],
)
def test_malformed_output_is_recorded_as_an_integrity_failure_not_replaced(
    tmp_path: Path, name: str, payload: bytes, stream: str
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

    On BOTH streams. The adapter decodes stdout and stderr and refuses the
    run if either fails; a specimen set that only ever wrote to stdout left
    the stderr half unmeasured, and a mutant that dropped it reported
    `success=True` with an empty output for a run whose stderr could not be
    read -- the exact failure this change exists to abolish, alive in the
    half nobody looked at.
    """
    worker = ClaudeCodeWorker(_emitting_cli(tmp_path, name, payload, stream=stream))
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )

    assert result.success is False, (
        "output that could not be decoded must not be reported as a successful "
        f"run; got {result.output!r}"
    )
    assert "UTF-8" in result.output and "integrity" in result.output, (
        f"the failure does not say what went wrong: {result.output!r}"
    )
    _assert_identified_not_rendered(result.output, payload, stream, other_stream_empty=True)


def test_a_carriage_return_survives_exactly_as_emitted(tmp_path: Path):
    """Bytes mode does no newline translation, and that is the rule.

    `text=True` also performed universal-newline translation on the way in,
    so a carriage return the provider wrote used to arrive as a line feed.
    A-025 states the change; this pins it, because a documented behaviour
    change with no specimen is prose standing in for a measurement: the
    result is what the provider wrote, byte for byte, with only the ends
    stripped.
    """
    payload = b"\r\n"
    worker = ClaudeCodeWorker(_emitting_cli(tmp_path, "cr", payload))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is True
    assert result.output == "before \r\n after", result.output


def test_a_timed_out_run_with_malformed_output_is_still_fingerprinted(tmp_path: Path):
    """The timeout branch identifies an undecodable payload too.

    Found in review of this change: the completed-process branch recorded a
    failed stream's length and SHA-256, while the timeout branch recorded only
    the decode reason and byte offset -- so unreadable output from a run that
    outlived its budget could not be correlated with the bytes actually
    emitted. Here the provider writes malformed bytes, flushes them, and then
    outlives the budget. The result must be the timeout class AND carry the
    fingerprint, with no replacement character standing in for the bytes.
    """
    # The budget and the linger are apart on purpose. On Windows `run()`
    # re-collects after the kill and blocks until the lingering grandchild
    # closes the pipe, so the bytes arrive whenever they were written and the
    # test costs the whole linger; on POSIX only bytes READ before the budget
    # expires are in the exception, so the emitter's write must land inside
    # the budget. The write was measured ~0.2 s from launch on the Windows
    # host this was developed on (spawn, .bat, interpreter, write); no POSIX
    # latency was measured. If it ever misses, the failure is RED (no
    # UTF-8 note in the result), never a false green.
    payload = b"\xff\xfe"
    worker = ClaudeCodeWorker(
        _emitting_cli(tmp_path, "linger", payload, linger_seconds=5)
    )
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=3,
    )
    assert result.success is False
    assert result.returncode == TIMEOUT_RETURNCODE, result.output
    assert "UTF-8" in result.output, (
        f"the timed-out run does not say its output was unreadable: {result.output!r}"
    )
    _assert_identified_not_rendered(result.output, payload, "stdout", other_stream_empty=False)


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


# ---------------------------------------------------------------------------
# Valid UTF-8 on stderr alone: the success path's `stdout.strip() or
# stderr.strip()` fallback, exercised rather than assumed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_valid_utf8_reaches_the_result_from_either_stream(tmp_path: Path, stream: str):
    """The success path is `output = stdout.strip() or stderr.strip()`.

    Every specimen above wrote its valid-UTF-8 payload to stdout, so the
    `or stderr.strip()` half of that line had never been exercised by a
    specimen carrying real non-ASCII bytes: a mutant that dropped the stderr
    fallback entirely, or one that decoded stderr with a different codec,
    would still pass every existing test here. Parametrized over the stream
    that carries the payload, with the other left completely silent, so
    stdout-empty-stderr-full is measured as a real run rather than assumed
    from the stdout case.
    """
    payload = b"\xe2\x80\x99"  # right single quote -- valid UTF-8, non-ASCII
    worker = ClaudeCodeWorker(_emitting_cli(tmp_path, f"fallback-{stream}", payload, stream=stream))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is True
    assert result.output == "before " + payload.decode("utf-8") + " after", (
        f"valid UTF-8 emitted on {stream} alone must reach the result byte-exact "
        f"through the stdout.strip() or stderr.strip() fallback; got {result.output!r}"
    )


# ---------------------------------------------------------------------------
# `_decode`/`_fingerprint` accept bytes or None only; a `str` is a defect
# ---------------------------------------------------------------------------

def test_decode_refuses_a_str_instead_of_silently_skipping_the_check():
    """The dead `str` branch used to return `problem=None` unconditionally --
    a caller handing already-decoded text would have it reported as verified
    UTF-8 without the check ever running. It is annotated `bytes | None` now
    and a `str` argument raises."""
    with pytest.raises(TypeError, match="bytes or None"):
        _claude_decode("already decoded", "stdout")


def test_fingerprint_refuses_a_str_instead_of_silently_accepting_it():
    with pytest.raises(TypeError, match="bytes or None"):
        _claude_fingerprint("stdout", "already decoded")


def test_decode_and_fingerprint_still_accept_the_two_real_shapes():
    """The positive control: bytes and None are not merely tolerated by
    accident of the type check, they still behave exactly as before."""
    assert _claude_decode(None, "stdout") == ("", None)
    assert _claude_decode(b"hello", "stdout") == ("hello", None)
    assert _claude_fingerprint("stdout", None) == "stdout: absent."
    assert "0 bytes" in _claude_fingerprint("stdout", b"")


# ---------------------------------------------------------------------------
# Readable-sibling asymmetry: a decoded stream's text is kept beside a failed
# sibling's fingerprint, on the completed-process branch too
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_stream", ["stdout", "stderr"])
def test_a_readable_sibling_streams_text_survives_beside_a_failed_ones_fingerprint(
    tmp_path: Path, bad_stream: str
):
    """The timeout branch already keeps a decoded sibling's text. The
    completed-process branch used to drop it: when one stream failed to
    decode and the other decoded perfectly good UTF-8, the good stream's text
    never reached the result at all -- only the two fingerprints and the
    decode-failure sentence. Both branches now behave the same way, and both
    put the sibling's text AFTER `PROVIDER_TEXT_DELIMITER`, so the adapter's
    own account (fingerprints first) is separable from text the provider
    wrote -- which could otherwise append a forged second integrity sentence
    that a reader had no way to tell from the adapter's.
    """
    good_stream = "stderr" if bad_stream == "stdout" else "stdout"
    good_payload = b"\xe2\x80\x99"
    bad_payload = b"\xff\xfe"
    cli = _emitting_cli_mixed(
        tmp_path, f"asym-{bad_stream}", good_stream=good_stream,
        good_payload=good_payload, bad_payload=bad_payload,
    )
    worker = ClaudeCodeWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is False

    readable_text = _emitted(good_payload).decode("utf-8")
    assert readable_text in result.output, (
        f"the {good_stream} stream decoded cleanly but its text was dropped once "
        f"{bad_stream} failed to decode: {result.output!r}"
    )
    assert _segment(bad_stream, _emitted(bad_payload)) in result.output, (
        f"the failed {bad_stream} stream's fingerprint is missing: {result.output!r}"
    )
    _assert_forge_account_precedes_provider_text(
        result.output, delimiter=PROVIDER_TEXT_DELIMITER,
        forge_account=_segment(bad_stream, _emitted(bad_payload)),
        provider_text=readable_text,
    )
    for codec in _RENDERINGS:
        rendered = bad_payload.decode(codec, "replace")
        assert rendered not in result.output, (
            f"the failed stream's payload reached the result rendered under {codec}: "
            f"{result.output!r}"
        )
    assert "�" not in result.output, (
        "the replacement character reached the result for the failed stream"
    )


# ---------------------------------------------------------------------------
# session_id validation: bounded str, no surrogate code points, or None
# ---------------------------------------------------------------------------

def _json_stdout_cli(tmp_path: Path, name: str, payload: object) -> str:
    """A controlled executable that writes `payload` as JSON to stdout.

    `_fake_cli` echoes its stdout argument through the shell, which breaks
    down for a 200,000-character line (a genuine "the batch file crashed"
    failure was measured trying it, not a defect in the adapter). Writing
    through a Python one-liner, as `provider_specimens.emitting_cli` already
    does for byte specimens, sidesteps every shell length and escaping limit.
    """
    import json as _json

    tag = hashlib.sha256(name.encode("utf-8")).hexdigest()[:6]
    emitter = tmp_path / f"j{tag}.py"
    emitter.write_text(
        "import sys\n"
        "sys.stdout.write(" + repr(_json.dumps(payload)) + ")\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        path = tmp_path / f"jp{tag}.bat"
        path.write_text(f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n',
                        encoding="utf-8", newline="")
    else:
        path = tmp_path / f"jp{tag}.sh"
        path.write_text(f'#!/bin/sh\n"{sys.executable}" "{emitter}"\n',
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize(
    ("name", "session_id_value"),
    [
        ("a_dict", {"nested": True}),
        ("an_oversized_string", "x" * 200_000),
        ("a_lone_surrogate_escape", "\ud800"),
        ("a_nul_character", "s-\x00-1"),
        ("an_embedded_newline", "s-1\ns-2"),
        ("a_bidi_override", "s-\u202e-1"),
        ("a_strong_rtl_letter", "s-\u05d0-1"),
    ],
    # EXPLICIT IDS. Without them pytest derives the id from the parameter
    # value, and the 200,000-character string became the id verbatim -- which
    # pytest's tmp_path fixture then folds into the per-test directory name,
    # pushing it past MAX_PATH on Windows and erroring the fixture before the
    # test body ever ran (an ERROR, not a FAILED, and not this test's own
    # assertion). The id is a label, not the specimen.
    ids=[
        "a_dict", "an_oversized_string", "a_lone_surrogate_escape",
        "a_nul_character", "an_embedded_newline", "a_bidi_override",
        "a_strong_rtl_letter",
    ],
)
def test_an_invalid_session_id_becomes_none_not_a_forged_value(
    tmp_path: Path, name: str, session_id_value: object
):
    """`session_id` is accepted only as a bounded ASCII identifier: printable
    ASCII, no whitespace. A dict, an oversized string, a lone surrogate code
    point (the shape a JSON `\\ud800` escape decodes to), a NUL byte, an
    embedded newline, a bidi override character (U+202E, which can make a
    rendered string display in an order its characters do not actually
    hold), and a strong right-to-left LETTER (U+05D0, printable by every
    category rule and reordering its neighbours when rendered all the same)
    are seven different ways the raw parsed value is NOT that, and all seven
    must become `None` -- the same absence a stream that never mentioned a
    session already records -- rather than being carried through as whatever
    `json.loads` happened to produce.
    """
    cli = _json_stdout_cli(tmp_path, name, {"session_id": session_id_value})
    worker = ClaudeCodeWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    assert result.success is True
    assert result.session_id is None, (
        f"an invalid session_id ({name}) was recorded rather than treated as absent: "
        f"{result.session_id!r}"
    )


def test_digest_raises_on_a_lone_surrogate_which_is_why_session_id_is_validated():
    """WHY the surrogate case matters, pinned where it can fail. An earlier
    form of the run-level test above ended with `digest(asdict(result))`,
    which cannot fail once `session_id` is `None` and so discriminated
    nothing. This is the discriminating half: `canonical_json` serialises a
    lone surrogate without complaint, and it is `digest`'s `.encode("utf-8")`
    that raises `UnicodeEncodeError` -- deep inside evidence serialisation,
    which is exactly where an unvalidated `session_id` would have taken it.
    """
    from nornyx_forge.util import canonical_json  # noqa: PLC0415

    canonical_json({"session_id": "\ud800"})  # serialises; nothing refuses it here
    with pytest.raises(UnicodeEncodeError):
        digest({"session_id": "\ud800"})


def test_validated_session_id_accepts_only_a_bounded_surrogate_free_str():
    """The helper directly, since the run-level tests above only prove the
    named shapes; this pins the bound and the surrogate range exactly."""
    assert _claude_validated_session_id("s-1") == "s-1"
    assert _claude_validated_session_id("") is None
    assert _claude_validated_session_id(None) is None
    assert _claude_validated_session_id(42) is None
    assert _claude_validated_session_id({"a": 1}) is None
    assert _claude_validated_session_id("x" * SESSION_ID_MAX_LENGTH) == "x" * SESSION_ID_MAX_LENGTH
    assert _claude_validated_session_id("x" * (SESSION_ID_MAX_LENGTH + 1)) is None
    assert SESSION_ID_MAX_LENGTH == 200
    assert _claude_validated_session_id("\ud800") is None
    assert _claude_validated_session_id("\udfff") is None


def test_validated_session_id_is_an_ascii_identifier():
    """The rule is ASCII, not merely printable: every character between `!`
    and `~` inclusive is accepted (in one 94-character run, which is also
    inside the bound), and any character outside ASCII is refused however
    printable -- a Hebrew letter, an accented Latin letter, a non-breaking
    space (which `isspace()` would also catch) and an emoji. DEL (0x7F) is
    ASCII but not printable and is refused by the second check. The
    round-2 security question this answers: a character-category rule
    admitted strong right-to-left LETTERS, which reorder a rendering just as
    an override does, and no category rule can tell such a letter from an
    ordinary one -- an ASCII rule can.
    """
    printable_ascii = "".join(chr(code) for code in range(0x21, 0x7F))
    assert len(printable_ascii) == 94
    assert _claude_validated_session_id(printable_ascii) == printable_ascii
    assert _claude_validated_session_id("s-\u05d0-1") is None, "a strong RTL letter"
    assert _claude_validated_session_id("s-\u00e9-1") is None, "an accented letter"
    assert _claude_validated_session_id("s-\u00a0-1") is None, "a non-breaking space"
    assert _claude_validated_session_id("s-\U0001f600-1") is None, "an emoji"
    assert _claude_validated_session_id("s-\x7f-1") is None, "DEL is ASCII, not printable"
    assert _claude_validated_session_id(" ") is None, "a space is printable, not an identifier"


def test_validated_session_id_refuses_unprintable_and_whitespace_characters():
    """The character-class rule, pinned directly: printable and whitespace-
    free, beyond the bound and the surrogate range the test above already
    covers.

    A plain ASCII space is deliberately its own case: `str.isprintable()`
    accepts U+0020 (it excludes only non-space separators and "Other"
    category characters), so `isprintable()` ALONE would let `"a b"` through.
    The explicit `any(ch.isspace() ...)` check is what actually closes that
    gap; asserting only the NUL/newline/bidi cases below would leave a
    mutant that dropped the whitespace check (but kept `isprintable()`)
    alive, because none of them is a plain space.
    """
    assert _claude_validated_session_id("s-\x00-1") is None, "NUL is not printable"
    assert _claude_validated_session_id("s-1\ns-2") is None, "a newline is not printable"
    assert _claude_validated_session_id("s-\t-1") is None, "a tab is not printable"
    assert _claude_validated_session_id("s-\u202e-1") is None, (
        "U+202E (right-to-left override) is not printable"
    )
    assert _claude_validated_session_id("a b") is None, (
        "an ASCII space is printable by isprintable() alone, so a value "
        "containing one must be refused by the explicit whitespace check"
    )
    assert _claude_validated_session_id("a-b_c.d:9") == "a-b_c.d:9", (
        "an ordinary printable, whitespace-free identifier is still accepted"
    )


# ---------------------------------------------------------------------------
# Renderings: an offset that is not hardcoded, and the real exit code on a
# malformed run
# ---------------------------------------------------------------------------

def test_the_byte_offset_is_recomputed_not_a_hardcoded_seven(tmp_path: Path):
    """Every other specimen in this module uses the default `PREFIX` (7
    bytes), so `at byte 7)` would pass even against an adapter that hardcoded
    the number 7 instead of computing `exc.start`. A prefix of a different
    length proves the offset is recomputed from the real bytes.
    """
    long_prefix = b"a substantially longer prefix than usual, "
    assert len(long_prefix) != len(_PREFIX)
    payload = b"\xff\xfe"
    cli = _emitting_cli(tmp_path, "offset", payload, prefix=long_prefix)
    worker = ClaudeCodeWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is False
    assert f"at byte {len(long_prefix)})" in result.output, result.output
    assert f"at byte {len(_PREFIX)})" not in result.output, (
        f"the default prefix's offset appeared even though this specimen used a "
        f"different prefix length: {result.output!r}"
    )
    _assert_identified_not_rendered(
        result.output, payload, "stdout", other_stream_empty=True, prefix=long_prefix
    )


def test_a_malformed_run_names_its_real_nonzero_exit_code(tmp_path: Path):
    """Every other malformed specimen exits 0 (the emitter never calls
    `sys.exit`), so `Process exited 0.` would pass even against an adapter
    that hardcoded that sentence. A specimen that also exits nonzero pins the
    real `result.returncode` is what gets named."""
    payload = b"\xff\xfe"
    cli = _emitting_cli(tmp_path, "nonzero-exit", payload, exit_code=17)
    worker = ClaudeCodeWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is False
    assert result.returncode == 17
    assert "Process exited 17." in result.output, result.output


# ---------------------------------------------------------------------------
# `run()` never raises: pathological JSON on stdout, an unusable executable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shape", ["array", "object"])
@pytest.mark.parametrize("exit_code", [0, 9])
def test_deeply_nested_json_stdout_does_not_escape_run_as_a_recursionerror(
    tmp_path: Path, shape: str, exit_code: int
):
    """`json.loads(stdout)` over deeply enough nested JSON raises
    `RecursionError`, not `json.JSONDecodeError` -- measured directly, not
    assumed, against `provider_specimens.deep_nested_json`. The Provider
    Contract requires a `WorkerResult` for every ending; an uncaught
    `RecursionError` escaping `run()` is exactly as much a contract violation
    as the `AttributeError` A-025 already closed. `exit_code` is
    parametrized, not fixed at 0, so `success` is proven to REFLECT the real
    exit code rather than being hardcoded True by whatever handles the catch.
    """
    text = _deep_nested_json(shape)
    # THE SPECIMEN'S POWER, PINNED ON THE RUNNING INTERPRETER. Without this
    # line a depth that no longer exhausts the guard on some future CPython
    # would leave the test below green over a specimen that merely fails to
    # parse -- the ordinary `JSONDecodeError` path, which was never in doubt.
    with pytest.raises(RecursionError):
        json.loads(text)
    cli = _raw_stdout_cli(tmp_path, f"deep-{shape}-{exit_code}", text, exit_code=exit_code)
    worker = ClaudeCodeWorker(cli)
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    assert result.success == (exit_code == 0), result.output
    assert result.returncode == exit_code
    assert result.session_id is None, (
        "a session identifier was invented out of pathological JSON that "
        f"was never actually parsed: {result.session_id!r}"
    )


# ---------------------------------------------------------------------------
# An invocation that cannot be formed: a NUL the OS refuses, or a workspace
# that is not a directory. Neither is `unavailable` (127) nor `timeout` (124)
# ---------------------------------------------------------------------------

def _assert_malformed_invocation(result, *, sentence: str) -> None:
    assert result.success is False
    assert result.returncode == MALFORMED_INVOCATION_RETURNCODE
    assert result.returncode not in (0, TIMEOUT_RETURNCODE, UNAVAILABLE_RETURNCODE)
    assert classify_result(result.success, result.returncode) == "error"
    assert sentence in result.output, result.output


def test_a_nul_in_the_goal_is_reported_not_raised(tmp_path: Path):
    """`subprocess.run` refuses an argument carrying a NUL with `ValueError`
    before any process exists -- measured: `embedded null character` on
    Windows, `embedded null byte` on POSIX. The goal is the one argument a
    caller composes, and a provider's own output can put a NUL there (see
    tests/test_provider_execution.py for the composition path). The adapter
    must report it, in the `error` class, rather than let the `ValueError`
    escape `run()`. The fake CLI never runs, so `ok.bat` exiting 0 cannot
    make this pass.
    """
    worker = ClaudeCodeWorker(_fake_cli(tmp_path))
    result = worker.run(  # must not raise
        role="builder", goal="repair a\x00b", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    _assert_malformed_invocation(result, sentence="could not be formed")


def test_a_nul_in_the_executable_name_is_unavailable_not_raised(tmp_path: Path):
    """ON WINDOWS `shutil.which("a\\x00b")` raises `ValueError` (measured on
    CPython 3.12 for a bare name; a name WITH a directory part returns None
    instead). On POSIX the same lookup returns None, so there the adapter's
    catch is never entered and this test exercises only the None path; the
    catch itself is a Windows-host fact. On every host `available()` must
    answer False rather than raise -- the contract says it never raises --
    and `run()` then reports the ordinary `unavailable` class, because a
    name the OS cannot even look up is not available.
    """
    worker = ClaudeCodeWorker("claude\x00fake")
    assert worker.available() is False
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE


def test_an_over_long_argument_list_is_an_error_naming_its_length_not_unavailable(
    tmp_path: Path,
):
    """Round-3 security P3-1. A 1 MB goal makes a command line no operating
    system accepts. Windows refuses it at `CreateProcess` with error 206,
    which CPython raises as `FileNotFoundError` with errno 2 -- the ABSENT-
    EXECUTABLE errno, which is how this used to be reported as `unavailable`
    (127) under a sentence blaming the executable (measured: a 33000-
    character argument fails this way on the Windows host, 32000 runs);
    POSIX `execve` refuses with `E2BIG` (a single argument above the kernel's
    per-argument limit). Both must land in the `error` class with the sizes
    in the sentence, and the fake CLI never runs. Reached through the DIRECT
    worker because the specimen is the GOAL: the routed path refuses a goal
    above 8000 characters at `ProviderTask.validate` before any adapter sees
    it. The routed path still reaches this branch through the tool list,
    which `validate` does not bound -- pinned in
    tests/test_provider_execution.py (round-5 security P2-NEW-1).
    """
    worker = ClaudeCodeWorker(_fake_cli(tmp_path))
    goal = "x" * 1_000_000
    result = worker.run(  # must not raise
        role="builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    _assert_malformed_invocation(
        result, sentence="exceeds the operating system's command-line length"
    )
    assert str(len(goal)) in result.output, result.output
    assert "could not be started" not in result.output, (
        "the argument length was blamed on the executable"
    )


class _WindowsLengthRefusal(OSError):
    """The shape `CreateProcess`'s error 206 takes in CPython: an `OSError`
    whose `winerror` is 206 and whose `errno` is 2. A subclass carrying the
    attribute so the classifier can be exercised on POSIX hosts too, where
    a real `OSError` has no `winerror` at all."""

    winerror = 206


def test_the_argument_length_classifier_knows_both_platforms_refusals():
    """Both spellings, on every host: `E2BIG` (POSIX) and Windows error 206
    -- which arrives with errno 2, so a classifier reading errno alone would
    call it an absent executable -- while a plain ENOENT stays about the
    executable. The two adapters' classifiers are duplicated, not shared, and
    must agree on every specimen.

    ROUND SIX (security F-1): 206 IS SHARED. `CreateProcess` answers the
    same 206 for an executable whose PATH is too long -- measured on the
    Windows host, an existing 333-character `.cmd` shim under a
    343-character line -- and the round-five rule took every 206 as the
    length refusal, so that executable came back as an over-long invocation
    of 343 characters against a bound of 32767. The classifier now reads
    the command too, and the 206 arm holds only when
    `_command_line_length(command)` EXCEEDS `WINDOWS_COMMAND_LINE_LIMIT`:
    the specimens sit exactly on either side of it (a count equal to the
    bound is False, one above it True), and a 206 under a short line
    answers False so the caller reports the executable. `E2BIG` is
    unambiguous and stays True under any line; ENOENT stays False under any
    line. Synthesised, so the rule runs on every host; the real spawns are
    the two Windows-only specimens below.
    """
    short = ("claude", "-p", "probe")
    at_the_bound = ("x" * (WINDOWS_COMMAND_LINE_LIMIT - 1),)
    past_the_bound = ("x" * WINDOWS_COMMAND_LINE_LIMIT,)
    assert _claude_command_line_length(at_the_bound) == WINDOWS_COMMAND_LINE_LIMIT
    assert _claude_command_line_length(past_the_bound) == WINDOWS_COMMAND_LINE_LIMIT + 1
    too_long = "The filename or extension is too long"
    specimens = (
        (OSError(errno.E2BIG, "Argument list too long"), short, True),
        (OSError(errno.E2BIG, "Argument list too long"), past_the_bound, True),
        (_WindowsLengthRefusal(2, too_long), past_the_bound, True),
        (_WindowsLengthRefusal(2, too_long), at_the_bound, False),
        (_WindowsLengthRefusal(2, too_long), short, False),
        (OSError(errno.ENOENT, "No such file or directory"), short, False),
        (OSError(errno.ENOENT, "No such file or directory"), past_the_bound, False),
        (OSError(errno.EACCES, "Permission denied"), short, False),
        (PermissionError(errno.EACCES, "Permission denied"), short, False),
    )
    codex_rule = _codex_worker_module._argument_list_too_long
    assert codex_rule is not _claude_argument_list_too_long
    assert WINDOWS_COMMAND_LINE_LIMIT == _codex_worker_module.WINDOWS_COMMAND_LINE_LIMIT
    for exc, command, expected in specimens:
        specimen = (exc, len(command), len(command[0]))
        assert _claude_argument_list_too_long(exc, command) is expected, specimen
        assert codex_rule(exc, command) is expected, specimen


def _over_long_executable_shim(tmp_path: Path) -> str:
    """An EXISTING `.cmd` shim at a path of at least 300 characters: long
    enough for `CreateProcess` to refuse the PATH with error 206 while the
    whole line stays far below the 32767-character bound. A chain of
    40-character directories under `tmp_path`; `os.makedirs` needs
    long-path support past 260 characters, and the caller skips, with the
    reason declared in the census, when the volume refuses to build it.
    Duplicated in tests/test_codex_provider.py, like `_fake_cli`."""
    chain = tmp_path
    while len(str(chain)) < 300:
        chain = chain / ("d" * 40)
    os.makedirs(chain, exist_ok=True)
    shim = chain / "provider.cmd"
    shim.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii", newline="")
    return str(shim)


def test_an_over_long_executable_path_is_unavailable_not_a_length_refusal(tmp_path: Path):
    """Round-6 security F-1. `CreateProcess` answers error 206 for an
    executable whose PATH is too long, exactly as it does for a command line
    past 32767 characters -- and the round-five classifier read only the
    number, so an existing `.cmd` shim at a 333-character path with a
    10-character goal came back as `error` (2) under "exceeds the operating
    system's command-line length: 343 characters": a false quantity, and
    the round-four class split inverted, because an executable that cannot
    be started is the `unavailable` class (127). The classifier now gates
    the 206 arm on the computed line exceeding `WINDOWS_COMMAND_LINE_LIMIT`,
    so this specimen lands in the executable arm.

    The premise is measured, not assumed: the shim exists, passes
    `available()` unmodified, its line is below the bound, and a direct
    spawn of it raises 206 -- with long paths enabled on this host; a host
    that refuses the path with another number is not exercising the shared
    206, and this test says so rather than passing on the class alone.
    Then the real worker runs it with a short goal and must report the
    executable, in the `unavailable` class, and NOT the length sentence.
    Windows only, by a skip declared in the census: only `CreateProcess`
    answers 206 for a path, and the synthesised half of the proof runs on
    every host in the classifier test above.
    """
    if os.name != "nt":
        pytest.skip(
            "only CreateProcess answers error 206 for an over-long executable "
            "path; the classifier's rule is held on every host by the "
            "synthesised specimens above"
        )
    try:
        shim = _over_long_executable_shim(tmp_path)
    except OSError as exc:  # long paths disabled on this volume
        pytest.skip(f"this volume cannot hold a 300-character path: {exc}")
    assert len(shim) >= 300 and os.path.isfile(shim)
    worker = ClaudeCodeWorker(shim)
    assert worker.available() is True, "the specimen must pass available() unmodified"
    with pytest.raises(OSError) as raised:
        subprocess.run([shim], capture_output=True, timeout=30)
    measured = getattr(raised.value, "winerror", None)
    assert measured == 206, (
        f"this host refused the {len(shim)}-character path with winerror "
        f"{measured}, not the 206 it shares with the length refusal, so the "
        "specimen does not reach the arm under test here"
    )

    result = worker.run(  # must not raise
        role="builder", goal="ten chars.", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    assert _claude_command_line_length(result.command) <= WINDOWS_COMMAND_LINE_LIMIT, (
        "the premise is a SUB-bound line; this one is not"
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE, (result.returncode, result.output[:300])
    assert classify_result(result.success, result.returncode) == "unavailable"
    assert "could not be started" in result.output, result.output[:300]
    assert "[WinError 206]" in result.output, result.output[:300]
    assert "command-line length" not in result.output, (
        "an over-long executable path was reported as an over-long invocation"
    )


def test_the_windows_command_line_limit_is_the_operating_systems_not_a_copy_of_the_rule():
    """Round-6 security F-2. `WINDOWS_COMMAND_LINE_LIMIT` is the number the
    classifier compares the computed line against; a test comparing the
    constant with 32767 would hold a copy of the rule against itself. This
    holds it against `CreateProcess`: two real spawns of the base
    interpreter with `-c pass` and one padding argument, the quoted line
    `subprocess.list2cmdline` builds sized to exactly 32766 characters and
    then 32767. Measured on the Windows host this was written on: 32766
    spawns (exit 0), 32767 is refused with error 206. In the adapters'
    count -- the line plus its terminating NUL -- those are 32767 and
    32768, so the accepted line's count EQUALS the constant and the refused
    line's is the first to EXCEED it, which is exactly the classifier's
    test for a 206. Both adapters' constants and counts are held, and both
    classifiers are run over the real refusal and over a synthesised 206 on
    the accepted line.

    The BASE interpreter (`sys._base_executable`), because the venv
    launcher re-executes it with a longer path in front of the same
    arguments and fails on its own re-composed line (measured: exit 101,
    "Unable to create process") -- a spawn that succeeded and a child that
    failed, which is not the operating-system verdict this test is about.
    Windows only, by a skip declared in the census; two spawns, bounded.
    """
    if os.name != "nt":
        pytest.skip("the bound under test is CreateProcess's; nothing on POSIX answers it")
    python = getattr(sys, "_base_executable", sys.executable)
    assert WINDOWS_COMMAND_LINE_LIMIT == _codex_worker_module.WINDOWS_COMMAND_LINE_LIMIT

    def line_of(length: int) -> tuple[str, ...]:
        head = (python, "-c", "pass")
        fixed = len(subprocess.list2cmdline(head)) + 1  # the space before the pad
        command = head + ("x" * (length - fixed),)
        assert len(subprocess.list2cmdline(command)) == length
        return command

    accepted = line_of(WINDOWS_COMMAND_LINE_LIMIT - 1)
    refused = line_of(WINDOWS_COMMAND_LINE_LIMIT)
    for count in (_claude_command_line_length, _codex_worker_module._command_line_length):
        assert count(accepted) == WINDOWS_COMMAND_LINE_LIMIT
        assert count(refused) == WINDOWS_COMMAND_LINE_LIMIT + 1

    ran = subprocess.run(accepted, capture_output=True, timeout=120)  # must not raise
    assert ran.returncode == 0, (ran.returncode, ran.stderr[:200])
    with pytest.raises(OSError) as raised:
        subprocess.run(refused, capture_output=True, timeout=120)
    assert getattr(raised.value, "winerror", None) == 206, raised.value

    for rule in (_claude_argument_list_too_long, _codex_worker_module._argument_list_too_long):
        assert rule(raised.value, refused) is True
        assert rule(_WindowsLengthRefusal(2, "synthesised on the accepted line"), accepted) is False


def test_the_reported_command_line_length_is_the_line_the_platform_counts(
    tmp_path: Path,
):
    """Round-5 security P3-NEW-1. The number in the refusal sentence was a
    sum over the raw arguments; Windows counts the ONE quoted line
    `CreateProcess` receives -- `subprocess.list2cmdline(command)`, exactly
    what `Popen` builds -- against 32767, terminator included. Quoting is
    not free (every quote inside an argument gains a backslash, the argument
    gains surrounding quotes), so the raw sum could name a number BELOW the
    bound it was explaining: measured on the Windows host, a goal of 17000
    double quotes summed to 17590 while the line was 34591.

    The rule is computed HERE, independently of the adapter, for the
    platform this test runs on -- the quoted line plus its terminating NUL
    on Windows, the arguments plus one terminator each elsewhere -- so the
    assertion holds on every host without a skip. First against the
    function over a quote-heavy vector; then against the sentence of a real
    refusal through the real worker: 140000 double quotes as the goal, one
    argument above Linux's `MAX_ARG_STRLEN` and a quoted line far above
    Windows's 32767, whose sentence must name the rule's number for the
    command the result carries. The fake CLI never runs.
    """
    quote_heavy = ("claude", "-p", 'say "hi" then "bye"', "--allowedTools", 'Read,"Write"')
    expected = _expected_command_line_length(quote_heavy)
    assert _claude_command_line_length(quote_heavy) == expected
    raw_sum = sum(len(argument) + 1 for argument in quote_heavy)
    assert expected >= raw_sum
    if os.name == "nt":
        assert expected > raw_sum, "the quoted line is longer than the raw sum here"

    worker = ClaudeCodeWorker(_fake_cli(tmp_path))
    goal = '"' * 140_000
    result = worker.run(  # must not raise
        role="builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    _assert_malformed_invocation(
        result, sentence="exceeds the operating system's command-line length"
    )
    reported = _expected_command_line_length(result.command)
    assert (
        f"command-line length: {reported} characters across "
        f"{len(result.command)} arguments, the goal alone {len(goal)} characters"
    ) in result.output, result.output[:300]


def test_both_adapters_apply_the_same_session_identifier_rule():
    """Cross-module identity (round-3 architecture P4-2). The two
    `_validated_session_id` functions are duplicated rather than imported --
    the adapters do not import each other -- so their agreement is a fact to
    hold by test, over ONE shared table of accepted and refused values, and
    not something each adapter's own suite can see. The bound they share is
    held equal the same way.
    """
    assert SESSION_ID_MAX_LENGTH == _codex_worker_module.SESSION_ID_MAX_LENGTH
    assert any(accepted for _, accepted in _SESSION_ID_SPECIMENS)
    assert any(not accepted for _, accepted in _SESSION_ID_SPECIMENS)
    for value, accepted in _SESSION_ID_SPECIMENS:
        claude = _claude_validated_session_id(value)
        codex = _codex_worker_module._validated_session_id(value)
        assert claude == codex, (value, claude, codex)
        assert (claude is not None) is accepted, (value, claude)
        if accepted:
            assert claude == value


@pytest.mark.parametrize("shape", ["missing", "file", "nul"])
def test_a_workspace_that_is_not_a_directory_is_an_error_naming_the_workspace(
    tmp_path: Path, shape: str
):
    """The round-2 finding: a missing or non-directory workspace raised
    `NotADirectoryError` out of `subprocess.run(cwd=...)` -- an `OSError`
    the adapter caught and reported as `unavailable` (127) under a sentence
    blaming the EXECUTABLE. The workspace is checked before spawning, so the
    result names the workspace, lands in the `error` class, and the fake CLI
    (which exits 0) never runs. Three shapes: a path that does not exist, a
    path that is a file, and a path carrying a NUL (`os.path.isdir` answers
    False for it without raising, so it never reaches `subprocess.run`).
    """
    if shape == "missing":
        workspace = tmp_path / "no-such-workspace"
    elif shape == "file":
        workspace = tmp_path / "a-file-not-a-directory"
        workspace.write_text("", encoding="utf-8")
    else:
        workspace = Path(str(tmp_path / "with-nul") + "\x00x")
    worker = ClaudeCodeWorker(_fake_cli(tmp_path))
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=workspace,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    _assert_malformed_invocation(result, sentence="workspace is not an existing directory")
    assert str(workspace) in result.output, result.output
    assert "could not be started" not in result.output, (
        "the workspace was blamed on the executable"
    )


def test_both_adapters_share_the_malformed_invocation_code_and_the_delimiter():
    """The two constants are duplicated in `codex_worker.py` rather than
    imported (the adapters do not import each other), so their equality is a
    fact to hold by test, not by construction. The code must also be neither
    of the two the contract already gives a meaning to.
    """
    assert MALFORMED_INVOCATION_RETURNCODE == _codex_worker_module.MALFORMED_INVOCATION_RETURNCODE
    assert MALFORMED_INVOCATION_RETURNCODE not in (0, TIMEOUT_RETURNCODE, UNAVAILABLE_RETURNCODE)
    assert classify_result(False, MALFORMED_INVOCATION_RETURNCODE) == "error"
    assert PROVIDER_TEXT_DELIMITER == _codex_worker_module.PROVIDER_TEXT_DELIMITER
    assert PROVIDER_TEXT_DELIMITER.isascii() and "\n" not in PROVIDER_TEXT_DELIMITER


def test_a_directory_as_the_executable_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """`subprocess.run` raises `PermissionError` (an `OSError`) when the
    executable it is handed is a directory. `available()` already refuses a
    directory -- `shutil.which`'s own `_access_check` excludes anything
    `os.path.isdir` reports true, on every platform -- so `run()` can never
    reach `subprocess.run` with a directory through its own public surface.
    `available` is monkeypatched True here specifically to reach the second,
    independent guard this repair adds: even if that first gate were ever
    bypassed (a TOCTOU replacement, a future caller that skips `available()`),
    `subprocess.run`'s own failure must still come back as a `WorkerResult`,
    not an exception -- defense in depth proven by actually removing the
    first line of defense for this one test.
    """
    directory = tmp_path / "not-a-real-cli"
    directory.mkdir()
    worker = ClaudeCodeWorker(str(directory))
    monkeypatch.setattr(worker, "available", lambda: True)
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE
    assert "could not be started" in result.output, result.output


def test_a_non_executable_file_as_the_executable_is_reported_not_raised(tmp_path: Path):
    """A zero-byte file passes `available()` and then fails to execute --
    reached WITHOUT monkeypatching, unlike the directory case above.

    On Windows, `shutil.which` treats a path ending in a recognised
    executable extension as available purely by extension and existence; it
    does not open the file. Measured directly: a zero-byte `.exe` passes
    `shutil.which` and then `subprocess.run` raises
    `OSError: [WinError 193] %1 is not a valid Win32 application`. On other
    platforms the equivalent is a file WITH the execute bit set but no valid
    executable format (no shebang, not a binary), which `os.access(...,
    os.X_OK)` -- what `shutil.which` actually checks -- accepts on
    permission bits alone, and which `subprocess.run` then refuses at exec
    time with `OSError: [Errno 8] Exec format error`.
    """
    if os.name == "nt":
        broken = tmp_path / "broken.exe"
        broken.write_bytes(b"")
    else:
        broken = tmp_path / "broken"
        broken.write_bytes(b"")
        broken.chmod(0o755)
    worker = ClaudeCodeWorker(str(broken))
    assert worker.available() is True, (
        "the specimen must pass available() unmodified, or this test proves "
        "nothing about the OSError branch inside run() itself"
    )
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE
    assert "could not be started" in result.output, result.output


# ---------------------------------------------------------------------------
# Lingering readable sibling: the timeout branch's `+ out + err` is reached
# with a genuinely readable sibling live, not merely a silent one
# ---------------------------------------------------------------------------

def test_a_timed_out_run_keeps_its_readable_siblings_text(tmp_path: Path):
    """Every existing timeout specimen (`test_a_timed_out_run_with_malformed_
    output_is_still_fingerprinted`) leaves the OTHER stream completely
    silent, so `+ out + err` on the timeout branch contributes nothing
    observable there: deleting it survived every test until this specimen
    existed. Here one stream carries valid, non-ASCII UTF-8 text and the
    other carries malformed bytes, and BOTH outlive the budget.
    """
    good_payload = b"\xe2\x80\x99"
    bad_payload = b"\xff\xfe"
    cli = _emitting_cli_mixed(
        tmp_path, "linger-mixed", good_stream="stdout",
        good_payload=good_payload, bad_payload=bad_payload, linger_seconds=5,
    )
    worker = ClaudeCodeWorker(cli)
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=3,
    )
    assert result.success is False
    assert result.returncode == TIMEOUT_RETURNCODE

    readable_text = _emitted(good_payload).decode("utf-8")
    assert readable_text in result.output, (
        f"the readable stdout sibling's text was dropped on the timeout "
        f"branch even though it decoded cleanly: {result.output!r}"
    )
    assert _segment("stderr", _emitted(bad_payload)) in result.output, (
        f"the failed stderr stream's fingerprint is missing: {result.output!r}"
    )
    _assert_forge_account_precedes_provider_text(
        result.output, delimiter=PROVIDER_TEXT_DELIMITER,
        forge_account=_segment("stderr", _emitted(bad_payload)),
        provider_text=readable_text,
    )
    for codec in _RENDERINGS:
        rendered = bad_payload.decode(codec, "replace")
        assert rendered not in result.output, (
            f"the failed stream's payload reached the result rendered under "
            f"{codec}: {result.output!r}"
        )
    assert "�" not in result.output


def test_a_timed_out_run_with_nothing_readable_carries_no_delimiter(tmp_path: Path):
    """The delimiter marks provider text; when a timed-out run decoded no
    text at all (the only stream that spoke failed to decode, the other was
    silent), there is nothing to mark, and neither the delimiter nor a
    trailing newline is added -- the same rule the completed-process branch
    applies when both streams fail. Pinned so the delimiter cannot become an
    unconditional suffix that reads as "provider text follows" over nothing.
    """
    payload = b"\xff\xfe"
    worker = ClaudeCodeWorker(
        _emitting_cli(tmp_path, "linger-silent", payload, linger_seconds=5)
    )
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=3,
    )
    assert result.returncode == TIMEOUT_RETURNCODE, result.output
    # The failed stream was SEEN, not missed: its fingerprint segment is in
    # the account. Without this, a host where the bytes never reached the
    # adapter before the kill (a POSIX pipe timing miss) would satisfy the
    # two negatives below over an output that says nothing at all.
    assert _segment("stdout", _emitted(payload)) in result.output, result.output
    assert PROVIDER_TEXT_DELIMITER not in result.output, result.output
    assert not result.output.endswith("\n"), result.output


# ---------------------------------------------------------------------------
# No trailing newline when BOTH streams fail to decode: the readable-sibling
# concatenation must contribute nothing, not a bare newline, when there is no
# readable sibling at all
# ---------------------------------------------------------------------------

def test_both_streams_malformed_leaves_no_trailing_newline(tmp_path: Path):
    """When only one stream failed, `"\\n" + stdout + stderr` appends a real
    sibling's text after the newline. When BOTH streams fail, `stdout` and
    `stderr` are both `""`, and appending unconditionally left a bare
    trailing newline that nothing in the provider's actual output produced --
    a small version of the exact mistake this module exists to prevent:
    something in the result the provider did not emit.
    """
    # A single-stream helper leaves the other stream silent (valid empty
    # UTF-8), which is not "both malformed" -- build a specimen that fails
    # BOTH streams by running two single-stream emitters is not possible
    # through `emitting_cli` (one process, one stream), so a small emitter is
    # built directly, mirroring the internals of `emitting_cli_mixed`.
    tag = "both-malformed"
    emitter = tmp_path / f"{tag}.py"
    emitter.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(" + repr(b"\xff\xfe") + ")\n"
        "sys.stderr.buffer.write(" + repr(b"\x80") + ")\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        cli_path = tmp_path / f"{tag}.bat"
        cli_path.write_text(
            f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n',
            encoding="utf-8", newline="",
        )
    else:
        cli_path = tmp_path / f"{tag}.sh"
        cli_path.write_text(f'#!/bin/sh\n"{sys.executable}" "{emitter}"\n',
                             encoding="utf-8", newline="")
        cli_path.chmod(0o755)

    result = ClaudeCodeWorker(str(cli_path)).run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=60,
    )
    assert result.success is False
    assert not result.output.endswith("\n"), (
        f"a trailing newline survived even though neither stream decoded, so "
        f"nothing readable was appended: {result.output!r}"
    )
    # Both streams' fingerprints must still be present and bound to the
    # right stream -- `_assert_identified_not_rendered` is not reusable here
    # (it asserts the OTHER stream did NOT fail, which is false when both
    # did), so both halves are checked directly instead.
    assert _segment("stdout", b"\xff\xfe") in result.output, result.output
    assert _segment("stderr", b"\x80") in result.output, result.output
    assert "stdout is not valid UTF-8 (" in result.output, result.output
    assert "stderr is not valid UTF-8 (" in result.output, result.output
    assert result.output.isascii(), result.output
    assert "�" not in result.output
