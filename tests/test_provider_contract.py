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

import hashlib
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

_PREFIX = b"before "
_SUFFIX = b" after"
#: Renderings a maintainer could plausibly substitute for strict decoding on
#: the hosts this defect was measured on: the eight-bit identity and the
#: Windows locale codec. Not "every codec": an enumerated denylist, checked
#: alongside the backslash-escape and surrogateescape shapes below.
_RENDERINGS = ("latin-1", "cp1252")


def _emitted(payload: bytes) -> bytes:
    """The exact bytes `_emitting_cli` puts on the pipe for a payload."""
    return _PREFIX + payload + _SUFFIX


def _emitting_cli(tmp_path: Path, name: str, payload: bytes,
                  linger_seconds: int = 0, stream: str = "stdout") -> str:
    """A controlled executable that writes exact BYTES to one stream.

    `_fake_cli` echoes through the shell, which cannot express an arbitrary
    byte; these specimens are about bytes, so the payload is written by a
    Python one-liner through `sys.stdout.buffer` or `sys.stderr.buffer` --
    the adapter decodes BOTH, and a specimen set that only ever wrote to
    stdout left the stderr half of the branch unmeasured. With
    `linger_seconds` the emitter flushes the payload and then outlives the
    caller's budget, which is how the timeout branch is reached with real
    bytes already on the pipe.
    """
    assert stream in ("stdout", "stderr"), stream
    # Short file names on purpose: `tmp_path` can sit under a long basetemp,
    # and a specimen name spelled out in two file names pushed a Windows
    # path past MAX_PATH under review, failing `CreateProcess` for the
    # long-named parameters only -- a failure that reads like a defect.
    tag = hashlib.sha256(f"{name}:{stream}".encode("utf-8")).hexdigest()[:6]
    emitter = tmp_path / f"e{tag}.py"
    emitter.write_text(
        "import sys, time\n"
        f"out = sys.{stream}.buffer\n"
        "out.write(" + repr(_emitted(payload)) + ")\n"
        "out.flush()\n"
        f"time.sleep({linger_seconds})\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        path = tmp_path / f"p{tag}.bat"
        path.write_text(f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n',
                        encoding="utf-8", newline="")
    else:
        path = tmp_path / f"p{tag}.sh"
        path.write_text(f'#!/bin/sh\n"{sys.executable}" "{emitter}"\n',
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


def _segment(stream: str, data: bytes) -> str:
    """The fingerprint the adapter must write for ONE stream, as one string:
    the stream name, the byte length and the SHA-256 together, so a digest
    cannot be credited to the wrong stream and a length cannot be matched as
    a substring of a larger number ("14 bytes" inside "114 bytes")."""
    return f"{stream}: {len(data)} bytes, sha256:{hashlib.sha256(data).hexdigest()}."


def _assert_identified_not_rendered(output: str, payload: bytes, stream: str, *,
                                    other_stream_empty: bool) -> None:
    """The undecodable payload is IDENTIFIED, BOUND TO ITS STREAM, and NOT RENDERED.

    Identified means the exact byte length and SHA-256 of what the provider
    emitted on THAT stream, and the offset of the first byte that is not
    UTF-8 -- recomputed here from the bytes and compared, because review
    showed the earlier `"sha256:" in output` satisfied by a CONSTANT digest,
    by a digest of the empty string, and by a fingerprint with the length
    dropped: a marker that identifies nothing is not a fingerprint. Bound
    means the name, length and digest sit in one segment and the decode
    message names the same stream, because a second review showed the
    fingerprint sources swapped between streams, a stdout digest credited to
    stderr, and a stdout failure labelled stderr all passing when each fact
    only had to appear SOMEWHERE in the output. When the sibling stream was
    silent, its segment must say so (zero bytes, the digest of nothing).

    Not rendered is held as a POSITIVE property first: the adapter's own
    account of an unreadable stream is pure ASCII (the banner, the codec's
    reason, a decimal offset and length, a hex digest), and every specimen
    payload here holds bytes above 0x7F that decode to a non-ASCII character
    under every single-byte codec and to non-ASCII noise under the wide
    ones, so `output.isascii()` refuses any rendering under any codec -- a
    review showed a cp437 rendering slipping past a list of named codecs.
    The named renderings a maintainer could plausibly substitute on the
    measured hosts (`_RENDERINGS`, the backslash-escape shape, the
    surrogateescape range, U+FFFD) stay as diagnostics that say WHICH
    mistake was made: `"\ufffd" not in output` alone catches
    `errors="replace"` and nothing else, and an earlier review showed a
    latin-1 rendering -- the exact mojibake this adapter exists to keep out
    of evidence -- passing every test before the list existed.
    """
    other = "stderr" if stream == "stdout" else "stdout"
    emitted = _emitted(payload)
    assert _segment(stream, emitted) in output, (
        f"the {stream} segment (name, {len(emitted)} bytes, digest of the bytes actually "
        f"emitted) is not in the result, so whatever fingerprint it carries identifies "
        f"something else or credits it to another stream: {output!r}"
    )
    if other_stream_empty:
        assert _segment(other, b"") in output, (
            f"the silent {other} stream must be recorded as zero bytes with the digest "
            f"of nothing; got {output!r}"
        )
    assert f"{stream} is not valid UTF-8 (" in output, (
        f"the decode failure does not name {stream}: {output!r}"
    )
    assert f"{other} is not valid UTF-8" not in output, (
        f"a decode failure was attributed to {other}, which decoded: {output!r}"
    )
    # The first byte that is not UTF-8 sits right after the prefix for every
    # malformed specimen; the closing parenthesis anchors the exact number.
    assert f"at byte {len(_PREFIX)})" in output, (
        f"the byte offset is not recorded: {output!r}"
    )
    assert any(byte > 0x7F for byte in payload), "specimen payloads must carry non-ASCII bytes"
    assert output.isascii(), (
        "the account of an unreadable stream is pure ASCII by construction, so a "
        f"non-ASCII character in it is the payload rendered under SOME codec: {output!r}"
    )
    for codec in _RENDERINGS:
        rendered = payload.decode(codec, "replace")
        assert rendered not in output, (
            f"the payload rendered under {codec} ({rendered!r}) reached the result: "
            "malformed bytes are being carried as text again"
        )
    assert payload.decode("utf-8", "backslashreplace") not in output, (
        "the payload rendered with backslash escapes reached the result"
    )
    assert not any("\udc80" <= ch <= "\udcff" for ch in output), (
        "surrogateescape code points reached the result"
    )
    assert "\ufffd" not in output, (
        "the replacement character reached the result, so malformed bytes are "
        "being carried as though they were text the provider wrote"
    )


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
