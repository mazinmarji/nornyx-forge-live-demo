"""Shared specimens for the two provider adapters: UTF-8 decode failures, and
the session-identifier rule's accepted and refused values.

NOT A TEST MODULE. `tests/test_provider_contract.py` (Claude) and
`tests/test_codex_provider.py` (Codex) both import from here so the two
adapters are held to the SAME criterion for "the undecodable payload is
identified, bound to its stream, and not rendered" -- see claude_worker.py's
and codex_worker.py's module docstrings, and A-025 in
docs/requirements/ASSUMPTIONS.md. BEFORE THIS MODULE EXISTED, only
`tests/test_provider_contract.py` carried these hardened helpers at all;
`tests/test_codex_provider.py` inlined its own, separately written, weaker
per-test emitter, so a review finding fixed against the Claude suite's
assertions never reached the Codex one -- hardening did not reach Codex,
full stop, not merely drift between two copies of the same design. This
module is what closed that: one set of helpers, imported by both.

Deliberately excluded from `scripts/check_test_coverage.py`'s
`REQUIRED_MODULES`: this module collects no tests of its own (it is not named
`test_*.py`, so pytest does not collect it), and requiring it there would
assert something false. Its coverage is exercised transitively, through every
test in the two modules that import it.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

#: The default wrapper bytes around a specimen payload. Kept short and fixed
#: on purpose: most specimens compare against `at byte {len(PREFIX)})`, which
#: only pins a real, dynamically-computed offset if the prefix used to build
#: the specimen and the prefix used to check the assertion are THE SAME value
#: -- see `assert_identified_not_rendered`'s `prefix`/`suffix` parameters,
#: which let a test deliberately use a DIFFERENT length to prove the offset is
#: not hardcoded anywhere in the adapter.
PREFIX = b"before "
SUFFIX = b" after"

#: Renderings a maintainer could plausibly substitute for strict decoding on
#: the hosts this defect was measured on: the eight-bit identity and the
#: Windows locale codec. Not "every codec" -- an enumerated denylist, checked
#: alongside the backslash-escape, surrogateescape and ascii-ignore shapes
#: below, each of which names the ONE mistake it catches rather than standing
#: in for decoding failures in general.
RENDERINGS = ("latin-1", "cp1252")

#: The session-identifier rule's specimen table, shared so that BOTH adapters'
#: `_validated_session_id` are held to it side by side: `(value, accepted)`.
#: The two functions are duplicated rather than imported (the adapters do not
#: import each other), so their agreement is a fact to hold by test, and the
#: per-adapter suites' own assertions cannot hold it -- each sees one adapter.
#: Accepted values are ASCII identifiers (printable ASCII, no whitespace, at
#: most 200 characters); refused values cover each clause of the rule once:
#: not a `str`, empty, over-long, a lone surrogate, a non-ASCII letter (a
#: strong right-to-left one and an accented one), a non-breaking space, an
#: emoji, DEL, NUL, a newline, a tab, a bidi override, and an ordinary space.
SESSION_ID_SPECIMENS: tuple[tuple[object, bool], ...] = (
    ("s-1", True),
    ("a-b_c.d:9", True),
    ("".join(chr(code) for code in range(0x21, 0x7F)), True),
    ("x" * 200, True),
    ("x" * 201, False),
    ("", False),
    (None, False),
    (42, False),
    ({"a": 1}, False),
    (["s-1"], False),
    (chr(0xD800), False),  # a lone high surrogate, as json.loads yields it
    (chr(0xDFFF), False),  # a lone low surrogate
    ("s-" + chr(0x05D0) + "-1", False),  # a strong right-to-left letter
    ("s-" + chr(0x00E9) + "-1", False),  # an accented letter
    ("s-" + chr(0x00A0) + "-1", False),  # a non-breaking space
    ("s-" + chr(0x1F600) + "-1", False),  # an emoji
    ("s-" + chr(0x7F) + "-1", False),  # DEL: ASCII, not printable
    ("s-" + chr(0x00) + "-1", False),  # NUL
    ("s-1" + chr(0x0A) + "s-2", False),  # a newline
    ("s-" + chr(0x09) + "-1", False),  # a tab
    ("s-" + chr(0x202E) + "-1", False),  # a bidi override
    ("a b", False),
    (" ", False),
)


def emitted(payload: bytes, *, prefix: bytes = PREFIX, suffix: bytes = SUFFIX) -> bytes:
    """The exact bytes `emitting_cli` puts on the pipe for a payload."""
    return prefix + payload + suffix


def emitting_cli(
    tmp_path: Path,
    name: str,
    payload: bytes,
    linger_seconds: int = 0,
    stream: str = "stdout",
    *,
    prefix: bytes = PREFIX,
    suffix: bytes = SUFFIX,
    exit_code: int = 0,
) -> str:
    """A controlled executable that writes exact BYTES to one stream.

    A shell-echo fake CLI cannot express an arbitrary byte, so these specimens
    are written by a Python one-liner through `sys.stdout.buffer` or
    `sys.stderr.buffer` -- both adapters decode both streams, and a specimen
    set that only ever wrote to stdout would leave the stderr half of either
    branch unmeasured. `linger_seconds` flushes the payload and then outlives
    the caller's budget, which is how a timeout branch is reached with real
    bytes already on the pipe. `prefix`/`suffix` default to the module
    constants but can be overridden so a test can prove an offset assertion is
    computed from the real bytes rather than hardcoded to this module's
    default length. `exit_code` lets a specimen combine malformed output with
    a chosen nonzero process exit, so "Process exited N" can be pinned against
    a real N rather than the 0 every other specimen here happens to produce.
    """
    assert stream in ("stdout", "stderr"), stream
    # Short file names on purpose: `tmp_path` can sit under a long basetemp,
    # and a specimen name spelled out in two file names pushed a Windows path
    # past MAX_PATH under review, failing `CreateProcess` for the long-named
    # parameters only -- a failure that reads like a defect.
    tag = hashlib.sha256(f"{name}:{stream}:{prefix!r}:{exit_code}".encode("utf-8")).hexdigest()[:6]
    emitter = tmp_path / f"e{tag}.py"
    emitter.write_text(
        "import sys, time\n"
        f"out = sys.{stream}.buffer\n"
        "out.write(" + repr(emitted(payload, prefix=prefix, suffix=suffix)) + ")\n"
        "out.flush()\n"
        f"time.sleep({linger_seconds})\n"
        f"sys.exit({exit_code})\n",
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


def emitting_cli_mixed(
    tmp_path: Path,
    name: str,
    *,
    good_stream: str,
    good_payload: bytes,
    bad_payload: bytes,
    linger_seconds: int = 0,
) -> str:
    """A controlled executable that writes a WELL-FORMED payload to one stream
    and a MALFORMED one to the other, both live in the same run.

    `emitting_cli` writes to exactly one stream, leaving the other silent --
    which measures a stream failing alone, not a stream failing BESIDE a
    sibling that decoded cleanly. The readable-sibling asymmetry (both
    adapters' completed-process branch keeping a decoded sibling's text
    alongside a failed stream's fingerprint, as the timeout branch already
    does) needs both halves live at once, so this is a separate helper rather
    than a mode of `emitting_cli`.

    `linger_seconds` flushes both payloads and then outlives the caller's
    budget, mirroring `emitting_cli`'s own parameter of the same name --
    without it, the timeout branch's readable-sibling handling (the same
    `+ out + err` appended after `note` on both adapters) had no mixed-stream
    specimen at all: `test_a_timed_out_run_with_malformed_output_is_still_
    fingerprinted` uses `emitting_cli`, which leaves one stream completely
    silent rather than carrying a genuinely readable sibling, so a mutant
    deleting `+ out + err` on the timeout branch specifically survived every
    existing test.
    """
    assert good_stream in ("stdout", "stderr"), good_stream
    bad_stream = "stderr" if good_stream == "stdout" else "stdout"
    tag = hashlib.sha256(
        f"{name}:mixed:{good_stream}:{linger_seconds}".encode("utf-8")
    ).hexdigest()[:6]
    emitter = tmp_path / f"m{tag}.py"
    emitter.write_text(
        "import sys, time\n"
        f"good = sys.{good_stream}.buffer\n"
        f"bad = sys.{bad_stream}.buffer\n"
        "good.write(" + repr(emitted(good_payload)) + ")\n"
        "bad.write(" + repr(emitted(bad_payload)) + ")\n"
        "good.flush()\n"
        "bad.flush()\n"
        f"time.sleep({linger_seconds})\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        path = tmp_path / f"q{tag}.bat"
        path.write_text(f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n',
                        encoding="utf-8", newline="")
    else:
        path = tmp_path / f"q{tag}.sh"
        path.write_text(f'#!/bin/sh\n"{sys.executable}" "{emitter}"\n',
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


#: Chosen far above the guard that actually fires. THE OPERATIVE GUARD IS NOT
#: `sys.getrecursionlimit()`: CPython's json scanner is the C accelerator
#: (`_json.scanner`), and its nested-container recursion is checked by the
#: interpreter's C-level recursion check, whose limit is set independently of
#: the Python-level one. Measured on CPython 3.12.10 by bisection: with
#: `sys.getrecursionlimit()` at its default 1000, `json.loads` first raised
#: `RecursionError` at depth 2997 for the array shape and 2998 for the object
#: shape -- roughly three times the Python limit, which is why a rationale
#: written in terms of that limit was wrong even though the number it chose
#: happened to work. The limit differs by interpreter version (3.10 and 3.11
#: share the Python limit for C calls; 3.12 and 3.13 keep a separate C one),
#: so this constant is not derived from any of them: it sits so far above
#: every measured or documented value that the specimen raises on each
#: interpreter in the CI matrix, and the parametrised test in both adapter
#: modules asserts `json.loads(deep_nested_json(shape))` raises
#: `RecursionError` on the running interpreter BEFORE handing the text to an
#: adapter -- so the specimen's power is pinned, not assumed, and a future
#: interpreter that parsed 100,000 levels would turn the test red rather
#: than leaving it green over a specimen that no longer tests anything.
DEEP_NESTING_DEPTH = 100_000


def deep_nested_json(shape: str) -> str:
    """Text that makes `json.loads` raise `RecursionError`, not merely fail
    to parse.

    The two shapes differ in whether they close. The `"array"` string is
    `[` repeated and never closed; the `"object"` string is a COMPLETE
    document, `{"a":` repeated, a `1`, and the matching run of `}`. Both
    raise the same way because CPython's json scanner recurses into each
    nested `[` or `{` as it meets it, so the recursion guard fires while the
    scanner is still descending -- before it could ever reach the point of
    noticing whether the document closes. Closing brackets are therefore
    irrelevant to the specimen's power; the object shape carries them only
    so that the two shapes are not the same specimen twice.
    Both adapters call `json.loads` on unbounded provider stdout --
    `claude_worker.py` on the whole payload, `codex_worker.py` per JSONL
    line -- and the Provider Contract requires a `WorkerResult` for either
    outcome, never an exception escaping `run()`.

    `"array"` and `"object"` are the two container shapes `json.loads`
    recurses through; both are specimens rather than one generalized to the
    other, because review of this exact module found a fix proven against
    one shape assumed, not measured, to cover its sibling.
    """
    if shape == "array":
        return "[" * DEEP_NESTING_DEPTH
    if shape == "object":
        return ('{"a":' * DEEP_NESTING_DEPTH) + "1" + ("}" * DEEP_NESTING_DEPTH)
    raise ValueError(f"unknown deep_nested_json shape: {shape!r}")


def expected_command_line_length(command: tuple[str, ...]) -> int:
    """The length the platform that refuses an over-long invocation counts,
    computed here independently of either adapter's `_command_line_length`
    so both suites hold both adapters to ONE rule (round-5 security
    P3-NEW-1). Windows: the ONE quoted line `CreateProcess` receives --
    `subprocess.list2cmdline`, exactly what `Popen` builds from the vector
    -- plus its terminating NUL, which the 32767-character bound includes.
    POSIX: each argument plus one terminator, in characters."""
    if os.name == "nt":
        return len(subprocess.list2cmdline(command)) + 1
    return sum(len(argument) + 1 for argument in command)


def raw_stdout_cli(tmp_path: Path, name: str, text: str, *, exit_code: int = 0) -> str:
    """A controlled executable that writes `text` to stdout LITERALLY.

    Not JSON-encoded (`json.dumps` would escape the unclosed brackets
    `deep_nested_json` needs to reach `json.loads` unmodified) and not
    wrapped in `PREFIX`/`SUFFIX` (this specimen is not a decode-integrity
    proof; the text is always valid ASCII UTF-8 -- LONG, not short: the deep
    nesting specimens are 100,000 to 600,000 characters -- and what is under
    test is `json.loads` itself, not `_decode`). Kept as a Python one-liner
    emitter for the same reason `emitting_cli` is: a shell `echo` cannot
    express 100,000 repeated bracket characters reliably across platforms,
    and a first attempt at exactly that was measured crashing the Windows
    batch shell rather than exercising either adapter.
    """
    tag = hashlib.sha256(f"{name}:{exit_code}".encode("utf-8")).hexdigest()[:6]
    emitter = tmp_path / f"d{tag}.py"
    emitter.write_text(
        "import sys\n"
        "sys.stdout.write(" + repr(text) + ")\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        path = tmp_path / f"dp{tag}.bat"
        path.write_text(f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n',
                        encoding="utf-8", newline="")
    else:
        path = tmp_path / f"dp{tag}.sh"
        path.write_text(f'#!/bin/sh\n"{sys.executable}" "{emitter}"\n',
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


def assert_forge_account_precedes_provider_text(
    output: str, *, delimiter: str, forge_account: str, provider_text: str
) -> None:
    """Forge's own account of a run sits BEFORE the first delimiter line, and
    the decoded provider text sits AFTER it.

    Both adapters keep a decoded stream's text beside their own account on
    two branches (a timeout, and a sibling stream that failed to decode).
    Before the delimiter existed the two were simply concatenated, so a
    provider could append a forged second integrity sentence and a reader
    had no way to tell where the adapter stopped speaking. The delimiter is
    the adapter's fixed line; `forge_account` (a fingerprint segment, say)
    must appear before its FIRST occurrence and `provider_text` after it.
    Nothing in Forge parses the provider's part, and the provider may forge
    a copy of the delimiter inside its own text -- which is why this
    partitions at the FIRST occurrence, the one Forge wrote.

    `delimiter` is passed in by the calling test module from the adapter
    under test, rather than imported here, so this helper cannot quietly
    pin both adapters to whichever constant this shared module imported;
    the two constants are held equal by a separate test.
    """
    assert delimiter in output, (
        f"no delimiter separates the adapter's account from the provider's text: "
        f"{output!r}"
    )
    forge_part, _, provider_part = output.partition(delimiter)
    assert forge_account in forge_part, (
        f"the adapter's own account ({forge_account!r}) does not precede the "
        f"first delimiter: {output!r}"
    )
    assert forge_part.endswith("\n"), (
        f"the delimiter must start its own line: {output!r}"
    )
    assert provider_part.startswith("\n"), (
        f"the provider's text must start on the line after the delimiter: {output!r}"
    )
    assert provider_text in provider_part, (
        f"the decoded provider text ({provider_text!r}) does not follow the "
        f"delimiter: {output!r}"
    )
    assert provider_text not in forge_part, (
        f"the provider's text leaked into the adapter's own account, before "
        f"the delimiter: {output!r}"
    )


def segment(stream: str, data: bytes) -> str:
    """One stream's fingerprint as ONE string: name, byte length and SHA-256
    together. An assertion built on this has to match all three joined, rather
    than any one of them appearing somewhere in the output on its own -- which
    is what let a constant digest, a digest of the empty string, and a length
    dropped from the string each satisfy a looser `"sha256:" in output`
    check."""
    return f"{stream}: {len(data)} bytes, sha256:{hashlib.sha256(data).hexdigest()}."


def assert_identified_not_rendered(
    output: str,
    payload: bytes,
    stream: str,
    *,
    other_stream_empty: bool,
    prefix: bytes = PREFIX,
    suffix: bytes = SUFFIX,
) -> None:
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

    `prefix`/`suffix` default to this module's constants; passing different
    ones lets a test build a specimen whose malformed byte sits at a different
    offset, so the `at byte N)` check pins a real, recomputed offset rather
    than one that happens to match this module's default prefix length.

    Not rendered is held as a POSITIVE property first: the adapter's own
    account of an unreadable stream is pure ASCII (the banner, the codec's
    reason, a decimal offset and length, a hex digest) -- THIS HOLDS ONLY
    WHEN THE SIBLING STREAM IS SILENT. Both adapters now keep a genuinely
    readable sibling's decoded TEXT beside a failed stream's fingerprint (the
    readable-sibling-kept behaviour), and that text can itself carry real
    non-ASCII UTF-8 -- a right single quote, say -- which is exactly what a
    decoded sibling is SUPPOSED to preserve, not a rendering of the failed
    stream's bytes. `assert_identified_not_rendered` is therefore called only
    with `other_stream_empty` cases where the sibling contributes no text of
    its own; the readable-sibling proof
    (`test_a_readable_sibling_streams_text_survives_beside_a_failed_ones_
    fingerprint` in both adapters' test modules) asserts its own, narrower
    set of properties instead rather than reusing this ASCII-only check
    against text it would correctly reject. Every specimen payload used
    against THIS function holds bytes above 0x7F, and under the two
    codecs actually checked below (`RENDERINGS`: latin-1 and cp1252) those
    bytes decode to a visible non-ASCII character rather than vanishing --
    `output.isascii()` is therefore a POSITIVE sanity check that the account
    contains no such byte at all, not a claim that no codec anywhere could
    ever map these particular bytes to ASCII. A review showed a cp437
    rendering slipping past a list of named codecs, which is why the ASCII
    check exists as a backstop beside the named list rather than instead of
    it. The named renderings, the backslash-escape shape, the surrogateescape
    range, the ascii-ignore shape (silently dropping the bad bytes rather than
    substituting for them) and U+FFFD stay as diagnostics that say WHICH
    mistake was made: `"�" not in output` alone catches
    `errors="replace"` and nothing else, and an earlier review showed a
    latin-1 rendering -- the exact mojibake this adapter exists to keep out of
    evidence -- passing every test before the list existed.
    """
    other = "stderr" if stream == "stdout" else "stdout"
    emitted_bytes = emitted(payload, prefix=prefix, suffix=suffix)
    assert segment(stream, emitted_bytes) in output, (
        f"the {stream} segment (name, {len(emitted_bytes)} bytes, digest of the bytes "
        f"actually emitted) is not in the result, so whatever fingerprint it carries "
        f"identifies something else or credits it to another stream: {output!r}"
    )
    if other_stream_empty:
        assert segment(other, b"") in output, (
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
    # malformed specimen; the closing parenthesis anchors the exact number,
    # computed from the PREFIX ACTUALLY USED rather than assumed.
    assert f"at byte {len(prefix)})" in output, (
        f"the byte offset is not recorded: {output!r}"
    )
    assert any(byte > 0x7F for byte in payload), "specimen payloads must carry non-ASCII bytes"
    assert output.isascii(), (
        "the account of an unreadable stream is pure ASCII by construction, so a "
        f"non-ASCII character in it is the payload rendered under SOME codec: {output!r}"
    )
    for codec in RENDERINGS:
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
    assert "�" not in output, (
        "the replacement character reached the result, so malformed bytes are "
        "being carried as though they were text the provider wrote"
    )
    ignored = emitted_bytes.decode("ascii", "ignore")
    assert ignored not in output, (
        f"the payload rendered with the bad bytes silently DROPPED ({ignored!r}) "
        f"reached the result: malformed bytes are being carried as text again, just "
        f"quietly rather than as mojibake: {output!r}"
    )
