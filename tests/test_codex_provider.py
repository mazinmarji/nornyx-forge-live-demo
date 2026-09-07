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
    test pins mutation-capable tasks to `workspace-write`, read-only reviewer
    tasks to `read-only`, and both to no fabricated tool flag.

The invocation surface itself (exec, --cd, --json, --skip-git-repo-check,
--sandbox) was validated against a real codex-cli 0.128.0 installation; the
fake executable exists so the failure semantics are exercised hermetically,
not to stand in for that validation.
"""

from __future__ import annotations

import errno
import hashlib
import json as _json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from nornyx_forge.codex_worker import (
    MALFORMED_INVOCATION_RETURNCODE,
    PROVIDER_TEXT_DELIMITER,
    SESSION_ID_MAX_LENGTH,
    WINDOWS_COMMAND_LINE_LIMIT,
    CodexWorker,
    _session_from_jsonl,
)
from nornyx_forge.codex_worker import _argument_list_too_long as _codex_argument_list_too_long
from nornyx_forge.codex_worker import _command_line_length as _codex_command_line_length
from nornyx_forge.codex_worker import _decode as _codex_decode
from nornyx_forge.codex_worker import _fingerprint as _codex_fingerprint
from nornyx_forge.codex_worker import _validated_session_id as _codex_validated_session_id
from nornyx_forge.provider_contract import (
    TIMEOUT_RETURNCODE,
    UNAVAILABLE_RETURNCODE,
    ProviderTask,
    classify_result,
    result_from_worker,
)
from nornyx_forge.providers import CodexProviderAdapter
from nornyx_forge.util import digest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from provider_specimens import PREFIX as _PREFIX  # noqa: E402
from provider_specimens import RENDERINGS as _RENDERINGS  # noqa: E402
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
    worker = CodexWorker(_fake_cli(tmp_path))
    result = worker.run(
        role="builder", goal="g", workspace=tmp_path,
        allowed_tools=("Read", "Write"), max_turns=1, timeout_seconds=30,
    )
    sandbox_index = result.command.index("--sandbox")
    assert result.command[sandbox_index + 1] == "workspace-write"
    review = worker.run(
        role="security-inspector", goal="review", workspace=tmp_path,
        allowed_tools=("Read", "Glob", "Grep"), max_turns=1, timeout_seconds=30,
    )
    review_sandbox = review.command.index("--sandbox")
    assert review.command[review_sandbox + 1] == "read-only"
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


# ---------------------------------------------------------------------------
# Non-ASCII provider output (PA-01)
# ---------------------------------------------------------------------------

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
    """The real CLI's output is UTF-8 and carries typographic characters.

    Measured under PA-01 against the shipped adapter, `text=True` with no
    encoding named decoded with the locale codec -- cp1252 on the Windows
    basic-user host -- and failed two different ways on real Codex output.
    A right single quote became mojibake and was passed through verbatim into
    the WorkerResult, so corrupted text reached evidence while everything
    looked healthy. A right double quote carries byte 0x9d, unmapped in
    cp1252, so the reader thread raised, `stdout` came back None, and the
    adapter turned that into an AttributeError escaping `run()` -- an
    exception where the Provider Contract requires a WorkerResult.

    Both directions are asserted: the text must survive intact, AND the call
    must return rather than raise. Asserting only the second would pass on an
    adapter that silently mangled every quotation mark.
    """
    worker = CodexWorker(_emitting_cli(tmp_path, name, payload))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
    )
    assert result.success is True
    assert result.output == "before " + payload.decode("utf-8") + " after", (
        "the provider's own bytes must reach the result undamaged; "
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

    `errors="replace"` was the first repair and it is the one that looks
    right: it stops the crash, and it converts every malformed byte into
    U+FFFD, which then travels into the WorkerResult and onward into evidence
    as ordinary characters. The run reports SUCCESS and its output reads as
    something the provider wrote. That is a worse failure than the crash it
    replaced, because nothing about it looks wrong.

    So the three properties asserted here are separate on purpose:

      * `run()` does not raise -- the Provider Contract requires a
        WorkerResult, and an exception for task failure is a contract
        violation;
      * the result is NOT successful, whatever the process exited with, so a
        clean exit cannot launder unreadable output;
      * the output NAMES the decode failure and does not carry U+FFFD, so no
        substituted character can be mistaken for provider text.

    On BOTH streams, mirroring the Claude adapter's suite exactly (via the
    shared tests/provider_specimens.py): a specimen set that only ever wrote
    to stdout would leave the stderr half of the branch unmeasured.
    """
    worker = CodexWorker(_emitting_cli(tmp_path, name, payload, stream=stream))
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
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
    A-025 (docs/requirements/ASSUMPTIONS.md) states the change for both
    adapters; this pins it for Codex, mirroring the Claude specimen, because a
    documented behaviour change with no specimen is prose standing in for a
    measurement: the result is the provider's bytes, with only the ends
    stripped.
    """
    payload = b"\r\n"
    worker = CodexWorker(_emitting_cli(tmp_path, "cr", payload))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
    )
    assert result.success is True
    assert result.output == "before \r\n after", result.output


def test_a_timed_out_run_with_malformed_output_is_still_fingerprinted(tmp_path: Path):
    """The timeout branch identifies an undecodable payload too.

    This branch used to record only the decode reason and byte offset here --
    the open item A-025 carried against this module -- while the
    completed-process branch (and the Claude adapter's timeout branch)
    recorded length and SHA-256. Closed in the provider-adapter parity slice:
    the provider writes malformed bytes, flushes them, and then outlives the
    budget. The result must be the timeout class AND carry the fingerprint,
    with no replacement character standing in for the bytes.
    """
    # See the identical timing note on the Claude specimen
    # (tests/test_provider_contract.py): budget and linger are apart so the
    # write lands inside the budget on POSIX while Windows re-collects after
    # the kill regardless.
    payload = b"\xff\xfe"
    worker = CodexWorker(_emitting_cli(tmp_path, "linger", payload, linger_seconds=5))
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=3,
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
    worker = CodexWorker(_emitting_cli(tmp_path, "vocab", b"\xff\xfe"))
    raw = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
    )
    normalized = result_from_worker("codex", raw)
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
    specimen carrying real non-ASCII bytes. Parametrized over the stream that
    carries the payload, with the other left completely silent, mirroring the
    Claude adapter's equivalent test exactly.
    """
    payload = b"\xe2\x80\x99"  # right single quote -- valid UTF-8, non-ASCII
    worker = CodexWorker(_emitting_cli(tmp_path, f"fallback-{stream}", payload, stream=stream))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
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
        _codex_decode("already decoded", "stdout")


def test_fingerprint_refuses_a_str_instead_of_silently_accepting_it():
    with pytest.raises(TypeError, match="bytes or None"):
        _codex_fingerprint("stdout", "already decoded")


def test_decode_and_fingerprint_still_accept_the_two_real_shapes():
    """The positive control: bytes and None are not merely tolerated by
    accident of the type check, they still behave exactly as before."""
    assert _codex_decode(None, "stdout") == ("", None)
    assert _codex_decode(b"hello", "stdout") == ("hello", None)
    assert _codex_fingerprint("stdout", None) == "stdout: absent."
    assert "0 bytes" in _codex_fingerprint("stdout", b"")


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
    decode-failure sentence. Both branches now behave the same way, mirroring
    the Claude adapter exactly, and both put the sibling's text AFTER
    `PROVIDER_TEXT_DELIMITER`, so the adapter's own account (fingerprints
    first) is separable from text the provider wrote -- which could otherwise
    append a forged second integrity sentence a reader had no way to tell
    from the adapter's.
    """
    good_stream = "stderr" if bad_stream == "stdout" else "stdout"
    good_payload = b"\xe2\x80\x99"
    bad_payload = b"\xff\xfe"
    cli = _emitting_cli_mixed(
        tmp_path, f"asym-{bad_stream}", good_stream=good_stream,
        good_payload=good_payload, bad_payload=bad_payload,
    )
    worker = CodexWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
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

def _jsonl_cli(tmp_path: Path, name: str, event: dict) -> str:
    """A controlled executable that writes one JSONL event to stdout.

    Writing through Python rather than through a shell `echo` -- as
    `provider_specimens.emitting_cli` already does for byte specimens --
    because one specimen below carries a 200,000-character value, and a
    single `echo` line that long was measured crashing the batch shell on
    Windows rather than exercising the adapter.
    """
    tag = hashlib.sha256(name.encode("utf-8")).hexdigest()[:6]
    emitter = tmp_path / f"j{tag}.py"
    emitter.write_text(
        "import sys\n"
        "sys.stdout.write(" + repr(_json.dumps(event)) + ")\n",
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
    # EXPLICIT IDS -- see the identical note on the Claude specimen. Without
    # them the 200,000-character value becomes the id verbatim and pytest's
    # tmp_path fixture folds it into a directory name past MAX_PATH on
    # Windows, erroring the fixture before the test body runs.
    ids=[
        "a_dict", "an_oversized_string", "a_lone_surrogate_escape",
        "a_nul_character", "an_embedded_newline", "a_bidi_override",
        "a_strong_rtl_letter",
    ],
)
def test_an_invalid_session_id_becomes_none_not_a_forged_value(
    tmp_path: Path, name: str, session_id_value: object
):
    """`session_id`/`thread_id` are accepted only as a bounded ASCII
    identifier: printable ASCII, no whitespace. A dict, an oversized string,
    a lone surrogate code point (the shape a JSON `\\ud800` escape decodes
    to), a NUL byte, an embedded newline, a bidi override character (U+202E,
    which can make a rendered string display in an order its characters do
    not actually hold), and a strong right-to-left LETTER (U+05D0, printable
    by every category rule and reordering its neighbours when rendered all
    the same) are seven different ways the raw parsed value is NOT that, and
    all seven must become `None` -- the same absence a stream carrying
    neither key already records -- rather than being carried through as
    whatever `json.loads` happened to produce.
    """
    cli = _jsonl_cli(tmp_path, name, {"type": "thread.started", "thread_id": session_id_value})
    worker = CodexWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    assert result.success is True
    assert result.session_id is None, (
        f"an invalid session_id ({name}) was recorded rather than treated as absent: "
        f"{result.session_id!r}"
    )


def test_digest_raises_on_a_lone_surrogate_which_is_why_session_id_is_validated():
    """WHY the surrogate case matters, pinned where it can fail -- mirrors the
    identical Claude specimen. `canonical_json` serialises a lone surrogate
    without complaint; it is `digest`'s `.encode("utf-8")` that raises
    `UnicodeEncodeError`, deep inside evidence serialisation, which is where
    an unvalidated `thread_id` would have taken it.
    """
    from nornyx_forge.util import canonical_json  # noqa: PLC0415

    canonical_json({"session_id": "\ud800"})
    with pytest.raises(UnicodeEncodeError):
        digest({"session_id": "\ud800"})


def test_validated_session_id_accepts_only_a_bounded_surrogate_free_str():
    """The helper directly, since the run-level tests above only prove the
    named shapes; this pins the bound and the surrogate range exactly."""
    assert _codex_validated_session_id("s-1") == "s-1"
    assert _codex_validated_session_id("") is None
    assert _codex_validated_session_id(None) is None
    assert _codex_validated_session_id(42) is None
    assert _codex_validated_session_id({"a": 1}) is None
    assert _codex_validated_session_id("x" * SESSION_ID_MAX_LENGTH) == "x" * SESSION_ID_MAX_LENGTH
    assert _codex_validated_session_id("x" * (SESSION_ID_MAX_LENGTH + 1)) is None
    assert SESSION_ID_MAX_LENGTH == 200
    assert _codex_validated_session_id("\ud800") is None
    assert _codex_validated_session_id("\udfff") is None


def test_validated_session_id_is_an_ascii_identifier():
    """The rule is ASCII, not merely printable -- identical to the Claude
    adapter's, and pinned identically: every character between `!` and `~`
    inclusive is accepted, and any character outside ASCII is refused however
    printable (a Hebrew letter, an accented Latin letter, a non-breaking
    space, an emoji); DEL is ASCII but not printable and is refused too.
    """
    printable_ascii = "".join(chr(code) for code in range(0x21, 0x7F))
    assert len(printable_ascii) == 94
    assert _codex_validated_session_id(printable_ascii) == printable_ascii
    assert _codex_validated_session_id("s-\u05d0-1") is None, "a strong RTL letter"
    assert _codex_validated_session_id("s-\u00e9-1") is None, "an accented letter"
    assert _codex_validated_session_id("s-\u00a0-1") is None, "a non-breaking space"
    assert _codex_validated_session_id("s-\U0001f600-1") is None, "an emoji"
    assert _codex_validated_session_id("s-\x7f-1") is None, "DEL is ASCII, not printable"
    assert _codex_validated_session_id(" ") is None, "a space is printable, not an identifier"


def test_validated_session_id_refuses_unprintable_and_whitespace_characters():
    """The character-class rule, pinned directly -- mirrors the identical
    Claude specimen exactly.

    A plain ASCII space is deliberately its own case: `str.isprintable()`
    accepts U+0020 (it excludes only non-space separators and "Other"
    category characters), so `isprintable()` ALONE would let `"a b"` through.
    The explicit `any(ch.isspace() ...)` check is what actually closes that
    gap; asserting only the NUL/newline/bidi cases below would leave a
    mutant that dropped the whitespace check (but kept `isprintable()`)
    alive, because none of them is a plain space.
    """
    assert _codex_validated_session_id("s-\x00-1") is None, "NUL is not printable"
    assert _codex_validated_session_id("s-1\ns-2") is None, "a newline is not printable"
    assert _codex_validated_session_id("s-\t-1") is None, "a tab is not printable"
    assert _codex_validated_session_id("s-\u202e-1") is None, (
        "U+202E (right-to-left override) is not printable"
    )
    assert _codex_validated_session_id("a b") is None, (
        "an ASCII space is printable by isprintable() alone, so a value "
        "containing one must be refused by the explicit whitespace check"
    )
    assert _codex_validated_session_id("a-b_c.d:9") == "a-b_c.d:9", (
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
    worker = CodexWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
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
    worker = CodexWorker(cli)
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
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
    """`_session_from_jsonl` calls `json.loads` per line, and a line deep
    enough (nested arrays or objects, no closing bracket required) raises
    `RecursionError`, not `json.JSONDecodeError` -- measured directly against
    `provider_specimens.deep_nested_json`, mirroring the identical Claude
    specimen. The Provider Contract requires a `WorkerResult` for every
    ending; an uncaught `RecursionError` escaping `run()` is exactly as much
    a contract violation as the `AttributeError` A-025 already closed.
    `exit_code` is parametrized, not fixed at 0, so `success` is proven to
    REFLECT the real exit code rather than being hardcoded True by whatever
    handles the catch.
    """
    text = _deep_nested_json(shape)
    # THE SPECIMEN'S POWER, PINNED ON THE RUNNING INTERPRETER -- see the
    # identical line on the Claude specimen: a depth that no longer exhausts
    # the guard would otherwise leave this green over an ordinary parse
    # failure, which was never in doubt.
    with pytest.raises(RecursionError):
        _json.loads(text)
    cli = _raw_stdout_cli(tmp_path, f"deep-{shape}-{exit_code}", text, exit_code=exit_code)
    worker = CodexWorker(cli)
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
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
    before any process exists -- mirrors the identical Claude specimen; here
    the goal sits inside the prompt, the LAST element of the Codex command
    vector. The adapter must report it, in the `error` class, rather than
    let the `ValueError` escape `run()`. The fake CLI never runs.
    """
    worker = CodexWorker(_fake_cli(tmp_path))
    result = worker.run(  # must not raise
        role="builder", goal="repair a\x00b", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    _assert_malformed_invocation(result, sentence="could not be formed")


def test_a_nul_in_the_executable_name_is_unavailable_not_raised(tmp_path: Path):
    """ON WINDOWS `shutil.which` raises `ValueError` for a bare name carrying
    a NUL (measured on CPython 3.12); on POSIX the same lookup returns None,
    so there the adapter's catch is never entered and only the None path is
    exercised. On every host `available()` answers False rather than raising,
    and `run()` reports the ordinary `unavailable` class. Mirrors the
    identical Claude specimen.
    """
    worker = CodexWorker("codex\x00fake")
    assert worker.available() is False
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE


def test_an_over_long_argument_list_is_an_error_naming_its_length_not_unavailable(
    tmp_path: Path,
):
    """Mirrors the identical Claude specimen (round-3 security P3-1): a 1 MB
    goal, which here sits inside the prompt -- the LAST element of the Codex
    command vector -- makes a command line the operating system refuses
    (Windows error 206 raised as `FileNotFoundError` errno 2; POSIX `E2BIG`).
    The adapter must report it in the `error` class with the sizes in the
    sentence, not as `unavailable` under the executable's sentence; the fake
    CLI never runs. Through the DIRECT worker because the specimen is the
    GOAL: the routed path refuses such a goal at `ProviderTask.validate`
    before any adapter sees it, and still reaches this branch through the
    tool list, which `validate` does not bound -- pinned in
    tests/test_provider_execution.py (round-5 security P2-NEW-1).
    """
    worker = CodexWorker(_fake_cli(tmp_path))
    goal = "x" * 1_000_000
    result = worker.run(  # must not raise
        role="builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
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
    attribute so the classifier can be exercised on POSIX hosts too, where a
    real `OSError` has no `winerror` at all."""

    winerror = 206


def test_the_argument_length_classifier_knows_both_platforms_refusals():
    """THIS adapter's classifier, held by THIS suite: the round-4 mutation
    matrix found the Codex `E2BIG` arm unpinned here -- the 1 MB specimen
    above goes through Windows error 206 on the Windows host, and the
    classifier test in the contract module is not run against a Codex
    mutant -- so a Codex classifier that ignored `E2BIG` survived on every
    host but Linux. Both spellings on every host: `E2BIG` (POSIX) and
    Windows error 206 (which arrives with errno 2, so a classifier reading
    errno alone would call it an absent executable), while a plain ENOENT
    or EACCES stays about the executable.

    ROUND SIX (security F-1): 206 IS SHARED. `CreateProcess` answers the
    same 206 for an executable whose PATH is too long -- measured on the
    Windows host, an existing 333-character `.cmd` shim under a
    343-character line -- and the round-five rule took every 206 as the
    length refusal. THIS adapter's classifier now reads the command too,
    and the 206 arm holds only when `_command_line_length(command)` EXCEEDS
    `WINDOWS_COMMAND_LINE_LIMIT`: the specimens sit exactly on either side
    of it (a count equal to the bound is False, one above it True), and a
    206 under a short line answers False. `E2BIG` stays True under any
    line; ENOENT stays False under any line. Synthesised, so the rule runs
    on every host; the real spawn is the Windows-only specimen below, and
    the bound itself is held against the operating system in
    tests/test_provider_contract.py.
    """
    short = ("codex", "exec", "probe")
    at_the_bound = ("x" * (WINDOWS_COMMAND_LINE_LIMIT - 1),)
    past_the_bound = ("x" * WINDOWS_COMMAND_LINE_LIMIT,)
    assert _codex_command_line_length(at_the_bound) == WINDOWS_COMMAND_LINE_LIMIT
    assert _codex_command_line_length(past_the_bound) == WINDOWS_COMMAND_LINE_LIMIT + 1
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
    for exc, command, expected in specimens:
        specimen = (exc, len(command), len(command[0]))
        assert _codex_argument_list_too_long(exc, command) is expected, specimen


def _over_long_executable_shim(tmp_path: Path) -> str:
    """An EXISTING `.cmd` shim at a path of at least 300 characters: long
    enough for `CreateProcess` to refuse the PATH with error 206 while the
    whole line stays far below the 32767-character bound. A chain of
    40-character directories under `tmp_path`; `os.makedirs` needs
    long-path support past 260 characters, and the caller skips, with the
    reason declared in the census, when the volume refuses to build it.
    Duplicated from tests/test_provider_contract.py, like `_fake_cli`."""
    chain = tmp_path
    while len(str(chain)) < 300:
        chain = chain / ("d" * 40)
    os.makedirs(chain, exist_ok=True)
    shim = chain / "provider.cmd"
    shim.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii", newline="")
    return str(shim)


def test_an_over_long_executable_path_is_unavailable_not_a_length_refusal(tmp_path: Path):
    """Mirrors the identical Claude specimen (round-6 security F-1) for
    THIS adapter. `CreateProcess` answers error 206 for an executable whose
    PATH is too long, exactly as it does for a command line past 32767
    characters; the round-five classifier read only the number, so an
    existing `.cmd` shim at a 333-character path with a 10-character goal
    came back as `error` (2) under a length sentence naming 343 characters
    -- a false quantity, and the round-four class split inverted. The
    classifier now gates the 206 arm on the computed line exceeding
    `WINDOWS_COMMAND_LINE_LIMIT`, so this specimen lands in the executable
    arm: `unavailable` (127), the executable's sentence, NOT the length
    sentence. The premise is measured (the shim exists, passes
    `available()` unmodified, its line is sub-bound, a direct spawn raises
    206). Windows only, by a skip declared in the census; the synthesised
    half of the proof runs on every host in the classifier test above.
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
    worker = CodexWorker(shim)
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
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    assert _codex_command_line_length(result.command) <= WINDOWS_COMMAND_LINE_LIMIT, (
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


def test_the_reported_command_line_length_is_the_line_the_platform_counts(
    tmp_path: Path,
):
    """Mirrors the identical Claude specimen (round-5 security P3-NEW-1),
    for THIS adapter's own `_command_line_length`: the number in the
    refusal sentence must be the length the refusing platform counts -- on
    Windows the ONE quoted line `CreateProcess` receives (exactly
    `subprocess.list2cmdline`, which is what `Popen` builds) plus its
    terminating NUL, elsewhere the arguments plus one terminator each. The
    raw sum named a number below the bound it explained (measured on the
    Windows host: 17000 double quotes summed to 17840 while the line was
    34841). The rule is computed in the shared specimens module, held here
    against the function over a quote-heavy vector, then against the
    sentence of a real refusal -- 140000 double quotes as the goal, which
    sits inside the prompt, the LAST element of the Codex command vector --
    over the command the result carries. No skip on any host; the fake CLI
    never runs.
    """
    quote_heavy = ("codex", "exec", "--json", "--sandbox", "read-only", 'say "hi" then "bye"')
    expected = _expected_command_line_length(quote_heavy)
    assert _codex_command_line_length(quote_heavy) == expected
    raw_sum = sum(len(argument) + 1 for argument in quote_heavy)
    assert expected >= raw_sum
    if os.name == "nt":
        assert expected > raw_sum, "the quoted line is longer than the raw sum here"

    worker = CodexWorker(_fake_cli(tmp_path))
    goal = '"' * 140_000
    result = worker.run(  # must not raise
        role="builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    _assert_malformed_invocation(
        result, sentence="exceeds the operating system's command-line length"
    )
    reported = _expected_command_line_length(result.command)
    assert (
        f"command-line length: {reported} characters across "
        f"{len(result.command)} arguments, the goal alone {len(goal)} characters"
    ) in result.output, result.output[:300]


@pytest.mark.parametrize("shape", ["missing", "file", "nul"])
def test_a_workspace_that_is_not_a_directory_is_an_error_naming_the_workspace(
    tmp_path: Path, shape: str
):
    """Mirrors the identical Claude specimen. The Codex command ALSO carries
    the workspace as `--cd <workspace>`, so before the pre-check a NUL in the
    workspace would have reached `subprocess.run` twice over -- as `cwd` and
    as an argument; the pre-check answers before either.
    """
    if shape == "missing":
        workspace = tmp_path / "no-such-workspace"
    elif shape == "file":
        workspace = tmp_path / "a-file-not-a-directory"
        workspace.write_text("", encoding="utf-8")
    else:
        workspace = Path(str(tmp_path / "with-nul") + "\x00x")
    worker = CodexWorker(_fake_cli(tmp_path))
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=workspace,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    _assert_malformed_invocation(result, sentence="workspace is not an existing directory")
    assert str(workspace) in result.output, result.output
    assert "could not be started" not in result.output, (
        "the workspace was blamed on the executable"
    )


def test_a_directory_as_the_executable_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """`subprocess.run` raises `PermissionError` (an `OSError`) when the
    executable it is handed is a directory. `available()` already refuses a
    directory -- `shutil.which`'s own `_access_check` excludes anything
    `os.path.isdir` reports true, on every platform -- so `run()` can never
    reach `subprocess.run` with a directory through its own public surface.
    `available` is monkeypatched True here, mirroring the identical Claude
    specimen, specifically to reach the second, independent guard this
    repair adds: even if that first gate were ever bypassed, `subprocess.
    run`'s own failure must still come back as a `WorkerResult`, not an
    exception.
    """
    directory = tmp_path / "not-a-real-cli"
    directory.mkdir()
    worker = CodexWorker(str(directory))
    monkeypatch.setattr(worker, "available", lambda: True)
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE
    assert "could not be started" in result.output, result.output


def test_a_non_executable_file_as_the_executable_is_reported_not_raised(tmp_path: Path):
    """A zero-byte file passes `available()` and then fails to execute --
    reached WITHOUT monkeypatching, unlike the directory case above. Mirrors
    the identical Claude specimen exactly; see its docstring for the
    platform-specific mechanism (`shutil.which` checking extension/execute
    bit, not file contents).
    """
    if os.name == "nt":
        broken = tmp_path / "broken.exe"
        broken.write_bytes(b"")
    else:
        broken = tmp_path / "broken"
        broken.write_bytes(b"")
        broken.chmod(0o755)
    worker = CodexWorker(str(broken))
    assert worker.available() is True, (
        "the specimen must pass available() unmodified, or this test proves "
        "nothing about the OSError branch inside run() itself"
    )
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=30,
    )
    assert result.success is False
    assert result.returncode == UNAVAILABLE_RETURNCODE
    assert "could not be started" in result.output, result.output


# ---------------------------------------------------------------------------
# Lingering readable sibling: the timeout branch's `+ out + err` is reached
# with a genuinely readable sibling live, not merely a silent one
# ---------------------------------------------------------------------------

def test_a_timed_out_run_keeps_its_readable_siblings_text(tmp_path: Path):
    """Every existing timeout specimen leaves the OTHER stream completely
    silent, so `+ out + err` on the timeout branch contributes nothing
    observable there: deleting it survived every test until this specimen
    existed. Mirrors the identical Claude specimen: one stream carries valid,
    non-ASCII UTF-8 text, the other carries malformed bytes, and BOTH
    outlive the budget.
    """
    good_payload = b"\xe2\x80\x99"
    bad_payload = b"\xff\xfe"
    cli = _emitting_cli_mixed(
        tmp_path, "linger-mixed", good_stream="stdout",
        good_payload=good_payload, bad_payload=bad_payload, linger_seconds=5,
    )
    worker = CodexWorker(cli)
    result = worker.run(  # must not raise
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=3,
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
    """Mirrors the identical Claude specimen: when a timed-out run decoded no
    text at all, neither the delimiter nor a trailing newline is added.
    """
    payload = b"\xff\xfe"
    worker = CodexWorker(_emitting_cli(tmp_path, "linger-silent", payload, linger_seconds=5))
    result = worker.run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=3,
    )
    assert result.returncode == TIMEOUT_RETURNCODE, result.output
    # The failed stream was SEEN, not missed: its fingerprint segment is in
    # the account, so a POSIX pipe-timing miss (bytes never reaching the
    # adapter before the kill) cannot satisfy the two negatives below over
    # an output that says nothing at all.
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
    trailing newline that nothing in the provider's actual output produced.
    Mirrors the identical Claude specimen.
    """
    tag = "both-malformed-codex"
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

    result = CodexWorker(str(cli_path)).run(
        role="builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read", "Write"), timeout_seconds=60,
    )
    assert result.success is False
    assert not result.output.endswith("\n"), (
        f"a trailing newline survived even though neither stream decoded, so "
        f"nothing readable was appended: {result.output!r}"
    )
    assert _segment("stdout", b"\xff\xfe") in result.output, result.output
    assert _segment("stderr", b"\x80") in result.output, result.output
    assert "stdout is not valid UTF-8 (" in result.output, result.output
    assert "stderr is not valid UTF-8 (" in result.output, result.output
    assert result.output.isascii(), result.output
    assert "�" not in result.output
