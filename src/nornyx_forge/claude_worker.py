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
adapter under PA-01; the Codex half landed first, in `codex_worker.py`, and
this module applies the same rule. On the timeout branch this module
fingerprints a stream that failed to decode, exactly as its own
completed-process branch already does. The Codex adapter's timeout branch was
brought to the same point in the provider-adapter parity slice that closed the
open item A-025 used to carry here -- mirrored test for test in
tests/test_codex_provider.py via the shared tests/provider_specimens.py -- so
the two adapters agree on this point now.
Neither adapter's confinement or eligibility is touched by either
half: `PROVIDER_CONFINEMENT["claude"]` stays `none`, and reading a provider's
bytes correctly says nothing about what that provider may reach.

WHERE FORGE'S ACCOUNT ENDS AND THE PROVIDER'S TEXT BEGINS IS MARKED. On the
two branches that keep a decoded stream's text beside Forge's own account of
the run (a timeout, or a sibling stream that failed to decode), that text is
appended after `PROVIDER_TEXT_DELIMITER`, a fixed line Forge writes. Everything
AFTER the first occurrence of that line is provider-authored: it may contain
anything, including a forged second integrity banner or a forged copy of the
delimiter itself. Nothing in Forge parses this prose -- the failure class is
derived from `success` and `returncode` by `provider_contract.classify_result`,
never from output text -- so a forgery there can mislead a human reader and
nothing else; the delimiter exists so that the reader knows where Forge stopped
speaking. On those two branches, Forge's own account is the part BEFORE the
first delimiter. The success path is different by design: there `output` is
the provider's text from its first character, with no delimiter and no
sentence of Forge's in front of it, so a delimiter-shaped line inside it is
the provider's own and marks nothing.

A LITERAL NUL IS VALID UTF-8, and a provider may emit one. It decodes and is
carried in `output` exactly as emitted (the rule above: the result is what the
provider wrote). What a NUL may NOT do is reach an operating-system call as
part of an argument, a working directory or an executable name.
`subprocess.run` refuses it with `ValueError` on every platform, before a
process exists. `shutil.which` refuses it the same way ON WINDOWS ONLY
(measured on CPython 3.12); on POSIX the same lookup returns None, because
`os.path.exists` swallows the `ValueError` there. The Provider Contract
requires a WorkerResult for that ending too, so both are caught here, and the
catch in `available()` is exercised only on Windows. Composing provider text
into a NEW invocation is the caller's act, and `development_flow` sanitises
control characters -- and bounds the length -- at that composition.

AN ARGUMENT LIST CAN ALSO BE TOO LONG for the operating system, and that is
reported as what it is. Windows bounds a command line at 32767 characters and
`CreateProcess` refuses a longer one with `ERROR_FILENAME_EXCED_RANGE` (206),
which CPython raises as `FileNotFoundError` with errno 2 -- the same
exception and errno an absent executable produces, told apart only by
`winerror`; a POSIX `execve` refuses with `E2BIG`. Both are recognised at the
`OSError` catch below and reported in the `error` class with the command
line's length in the sentence, rather than as `unavailable` (127) under a
sentence blaming the executable. Measured on the Windows host this was written
on: a 33000-character argument fails that way and a 32000-character one runs.
The length the sentence names is the one the refusing platform counts: on
Windows the ONE quoted line `CreateProcess` receives plus its terminating NUL,
elsewhere the arguments plus one terminator each (`_command_line_length`).
The routed path reaches this too. `ProviderTask.validate` bounds the GOAL
(8000 characters) but neither the tool list nor the workspace path, so a
routed caller with a short goal and a long `allowed_tools` arrives here
through the joined list -- measured through the real routed worker on this
host: a 12-character goal and 90 tools joined to 36449 characters ended here
on both adapters. An earlier form of this paragraph said the routed path
never reaches it; that was true of the goal and false of the invocation.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from .models import WorkerResult


class ClaudeCodeWorker:
    """Bounded bridge to an authenticated local Claude Code installation."""

    def __init__(self, executable: str = "claude") -> None:
        self.executable = executable

    def available(self) -> bool:
        # ON WINDOWS `shutil.which` raises `ValueError: embedded null
        # character` for a bare name carrying a NUL (measured on CPython
        # 3.12; a NUL inside a path WITH a directory part returns None
        # instead, because that branch's existence check swallows it). On
        # POSIX the same lookup returns None, and this catch is never
        # entered there. The contract says `available()` never raises, and
        # a name the OS cannot look up is not available either way.
        try:
            return shutil.which(self.executable) is not None
        except ValueError:
            return False

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
        if not os.path.isdir(workspace):
            # Checked BEFORE spawning, so a missing or non-directory workspace
            # gets its own sentence and the `error` class rather than the
            # `OSError` branch below, which can only speak about the
            # executable. Measured: a file, or a path that does not exist,
            # handed to `subprocess.run(cwd=...)` raises `NotADirectoryError`
            # (`[WinError 267] The directory name is invalid` on Windows) --
            # an `OSError` indistinguishable at the catch site from one the
            # executable raised, so it used to be reported as `unavailable`
            # (127) with a sentence blaming the executable. `os.path.isdir`
            # answers False, never raises, for a NUL in the path as well. The
            # gap between this check and the spawn is not closed: a workspace
            # removed in that window still lands in the `OSError` branch and
            # is reported under the executable's sentence.
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=(
                    "Claude Code worker workspace is not an existing directory: "
                    f"{workspace}"
                ),
                returncode=MALFORMED_INVOCATION_RETURNCODE,
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
            # A stream that failed to decode is identified the same way the
            # completed-process branch identifies one -- length and digest --
            # so a timed-out run's unreadable output can still be correlated
            # with the bytes actually emitted instead of vanishing behind the
            # timeout. Both branches DESCRIBE an undecodable payload; neither
            # renders it.
            note = "".join(
                f"\n{problem} {_fingerprint(stream, raw)}"
                for stream, raw, problem in (
                    ("stdout", exc.stdout, out_problem),
                    ("stderr", exc.stderr, err_problem),
                )
                if problem
            )
            # The decoded text, when there is any, follows the delimiter: see
            # the module docstring -- everything after that line is the
            # provider's, and Forge's account is everything before it. When
            # neither stream decoded to anything, nothing is appended, so the
            # account does not end in a newline nobody wrote.
            readable = out + err
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=f"Claude Code worker timed out after {timeout_seconds}s.{note}"
                       + (f"\n{PROVIDER_TEXT_DELIMITER}\n{readable}" if readable else ""),
                command=command,
                returncode=124,
            )
        except ValueError as exc:
            # `subprocess.run` refuses an argument, a working directory or an
            # executable name that carries a NUL -- `ValueError: embedded
            # null character` on Windows, `embedded null byte` on POSIX --
            # BEFORE any process exists. Measured directly for all three
            # positions. The only way a NUL reaches this call site is through
            # `goal` or `role`, which a caller composed; the adapter's own
            # arguments are literals. Reported in the `error` class, because
            # this is neither an absent executable nor a timeout: it is an
            # invocation that could not be formed, and the sentence says so.
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=f"Claude Code worker invocation could not be formed: {exc}",
                command=command,
                returncode=MALFORMED_INVOCATION_RETURNCODE,
            )
        except OSError as exc:
            if _argument_list_too_long(exc):
                # The operating system refused the INVOCATION for its length,
                # not the executable. Windows bounds a command line at 32767
                # characters and `CreateProcess` answers error 206, which
                # CPython raises as `FileNotFoundError` with errno 2 -- the
                # absent-executable errno -- so only `winerror` tells the two
                # apart; a POSIX `execve` answers `E2BIG`. Reported in the
                # `error` class with the length in the sentence, because a
                # caller that composed an argument this long has a defect in
                # the composition, and "executable could not be started"
                # would send it looking in the wrong place. The routed path
                # reaches this line too: `ProviderTask.validate` bounds the
                # goal (8000 characters) but neither the tool list nor the
                # workspace path, so a short goal beside a long
                # `allowed_tools` arrives here through the joined list
                # (pinned in tests/test_provider_execution.py).
                return WorkerResult(
                    role=role,
                    goal=goal,
                    success=False,
                    output=(
                        "Claude Code worker invocation exceeds the operating "
                        "system's command-line length: "
                        f"{_command_line_length(command)} characters across "
                        f"{len(command)} arguments, the goal alone "
                        f"{len(goal)} characters: {exc}"
                    ),
                    command=command,
                    returncode=MALFORMED_INVOCATION_RETURNCODE,
                )
            # `available()` already refuses an absent executable and, via
            # `shutil.which`'s own `not os.path.isdir` check, a directory --
            # but nothing about that check survives to this line: the
            # executable can be replaced or become unusable in the gap
            # between the two, and some unusable paths reach `available()`
            # as "found" in the first place. Measured directly: a zero-byte
            # file carrying an executable extension passes `shutil.which`
            # (Windows does not check file CONTENTS, only that something
            # exists at a recognised extension) and then
            # `subprocess.run` raises `OSError: [WinError 193] %1 is not a
            # valid Win32 application` when the loader actually tries it.
            # The Provider Contract still requires a WorkerResult, not an
            # exception, for this: it is the SAME unavailable class
            # `available()` already reports for an absent executable,
            # because a path that cannot be executed is not meaningfully
            # different from one that was never there.
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=f"Claude Code worker executable could not be started: {exc}",
                command=command,
                returncode=127,
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
            # THE READABLE SIBLING IS KEPT, not dropped. When only one stream
            # failed, the other decoded cleanly and has text worth keeping
            # beside the failure -- exactly what the timeout branch above
            # already does. `stdout`/`stderr` here are `""` for whichever
            # stream failed (see `_decode`), so concatenating both keeps the
            # readable sibling's text -- AFTER `PROVIDER_TEXT_DELIMITER`, so
            # a reader can tell Forge's account (the sentence, the exit code,
            # the two fingerprints: all ASCII the adapter composed) from text
            # the provider wrote, which may say anything, including a second
            # "integrity" sentence of its own. APPENDED ONLY WHEN NON-EMPTY:
            # when BOTH streams failed to decode, `stdout` and `stderr` are
            # both `""`, and an unconditional append would still add a bare
            # delimiter and newline that nothing in the provider's output
            # produced -- a smaller version of the same mistake this module
            # exists to prevent: something in the result that the provider
            # did not actually emit.
            readable = stdout + stderr
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output="Claude Code worker output failed UTF-8 integrity and was "
                       "NOT decoded with replacement: " + "; ".join(problems)
                       + f". Process exited {result.returncode}. "
                       + _fingerprint("stdout", result.stdout) + " "
                       + _fingerprint("stderr", result.stderr)
                       + (f"\n{PROVIDER_TEXT_DELIMITER}\n{readable}" if readable else ""),
                command=command,
                returncode=result.returncode,
            )

        output = stdout.strip() or stderr.strip()
        session_id = None
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                session_id = _validated_session_id(parsed.get("session_id"))
        except (TypeError, ValueError, RecursionError):
            # ValueError covers `json.JSONDecodeError` (a subclass) for
            # ordinary malformed JSON. RecursionError is the one that is not
            # obvious: `json.loads` over stdout deep enough (nested arrays or
            # objects, no closing bracket required to trigger it) exhausts
            # CPython's own recursion guard before it ever notices the
            # document is incomplete -- measured directly, not assumed --
            # and the Provider Contract requires a WorkerResult here too,
            # never an exception escaping over provider-controlled stdout.
            # session_id stays None either way, the same absence a stream
            # that never mentioned one already records.
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


def _decode(raw: bytes | None, stream: str) -> tuple[str, str | None]:
    """Decode one captured stream as UTF-8, STRICTLY, and say so when it fails.

    Returns the text and `None` when the bytes are valid UTF-8 -- preserved
    exactly, so a typographic quote survives as itself. Returns empty text and
    a description when they are not. Never raises for a byte-decode failure,
    and never substitutes: the caller decides what a failed stream means, and
    the one thing it must not mean is "here is some text".

    `raw` is bytes or `None` -- the two shapes `subprocess.run(...,
    capture_output=True)` with no `text=True` and no `encoding=` ever produces
    on this adapter's real call sites, and the two this function is annotated
    for. A `str` used to be accepted too, treated as "a caller that already
    decoded; nothing to check" and returned as `problem=None` unconditionally
    -- a dead branch on every real call site, and a live one for anything that
    called this function directly with text: it would report a `str` payload
    as successfully verified UTF-8 without ever running the check this
    function exists to run. That is the exact substitution this module's
    docstring forbids, so a `str` argument now raises rather than silently
    skipping the check.
    """
    if raw is None:
        return "", None
    if not isinstance(raw, bytes):
        raise TypeError(
            f"_decode expects bytes or None, got {type(raw).__name__}; a caller "
            "handing this function already-decoded text would let that text "
            "skip strict UTF-8 decoding entirely"
        )
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return "", (
            f"{stream} is not valid UTF-8 ({exc.reason} at byte {exc.start})"
        )


def _fingerprint(stream: str, raw: bytes | None) -> str:
    """Identify an undecodable payload without pretending it is text.

    `raw` is bytes or `None`, the same two shapes `_decode` accepts and for
    the same reason: this adapter always captures bytes, and a `str` reaching
    a fingerprint function would mean something already decoded the payload
    this function exists to identify undecoded.
    """
    if raw is None:
        return f"{stream}: absent."
    if not isinstance(raw, bytes):
        raise TypeError(
            f"_fingerprint expects bytes or None, got {type(raw).__name__}"
        )
    return (
        f"{stream}: {len(raw)} bytes, "
        f"sha256:{hashlib.sha256(raw).hexdigest()}."
    )


#: The bound `_validated_session_id` enforces. Chosen, not derived: no
#: provider CLI documents a maximum session-identifier length, so this is
#: Forge's own ceiling on what it will RECORD, generous enough for any
#: identifier either CLI has been observed to emit and small enough that a
#: pathological value cannot bloat evidence.
SESSION_ID_MAX_LENGTH = 200

#: Returned when Forge could not hand the provider a well-formed invocation at
#: all: the workspace is not an existing directory, an argument carries a
#: NUL the operating system refuses, or the argument list is longer than the
#: operating system accepts. None of these is an absent executable (127) or
#: a timeout (124), so the value is deliberately neither -- it lands in the
#: Provider Contract's `error` class, and the output sentence, not the
#: number, says which it was. 2 follows the shell's usage-error tradition; it
#: is Forge's own code, and a real CLI exiting 2 for its own reasons is
#: distinguishable only by the sentence. Duplicated in `codex_worker.py`
#: rather than imported, like `SESSION_ID_MAX_LENGTH`, so the two adapters
#: stay independent modules; a test holds the two equal.
MALFORMED_INVOCATION_RETURNCODE = 2

#: The Windows system error `CreateProcess` answers when the command line
#: exceeds its 32767-character bound: ERROR_FILENAME_EXCED_RANGE. CPython maps
#: it to errno ENOENT (2), so `OSError.errno` cannot tell it from an absent
#: executable; `OSError.winerror` can. Duplicated in `codex_worker.py`.
_ARGUMENT_TOO_LONG_WINERROR = 206


def _argument_list_too_long(exc: OSError) -> bool:
    """Whether the operating system refused the spawn for the LENGTH of its
    arguments: `E2BIG` from a POSIX `execve`, or Windows error 206 from
    `CreateProcess` (measured: a 33000-character argument on the Windows host
    this was written on). Any other `OSError` is about the executable."""
    return (
        getattr(exc, "winerror", None) == _ARGUMENT_TOO_LONG_WINERROR
        or exc.errno == errno.E2BIG
    )


def _command_line_length(command: tuple[str, ...]) -> int:
    """How many characters the invocation occupies, counted the way the
    platform that refused it counts -- so the sentence that reports the
    refusal names a size the bound can be compared with, not only the fact.

    ON WINDOWS (`os.name == "nt"`): the length of the ONE quoted line
    `CreateProcess` receives -- `subprocess.list2cmdline(command)`, which is
    exactly what `Popen` builds from the argument vector -- plus its
    terminating NUL, because the 32767-character bound includes that
    terminator. Quoting is not free: an argument with a space or a quote
    gains surrounding quotes and every quote inside it a backslash, so a sum
    over the raw arguments can name a number BELOW the bound it is
    explaining. Measured on the Windows host: a goal of 17000 double quotes
    summed to 17590 while the line handed to `CreateProcess` was 34591.

    ON POSIX: each argument plus one terminator, in CHARACTERS. The kernel
    counts bytes, so for non-ASCII text this is a lower bound on what
    `execve` saw; no quoting happens there, the vector is passed as it is.
    Duplicated in `codex_worker.py`; a test in each adapter suite holds it
    to the same rule."""
    if os.name == "nt":
        return len(subprocess.list2cmdline(command)) + 1
    return sum(len(argument) + 1 for argument in command)

#: The line Forge writes between its own account of a run and any decoded
#: provider text it keeps beside that account. See the module docstring:
#: everything after the FIRST occurrence is provider-authored, and nothing in
#: Forge parses it. Duplicated in `codex_worker.py`; a test holds them equal.
PROVIDER_TEXT_DELIMITER = (
    "--- provider text (decoded, provider-authored; anything after this line "
    "is the provider's) ---"
)


def _validated_session_id(value: object) -> str | None:
    """A session identifier Forge will RECORD, never one it invents.

    Accepted only as a `str`, non-empty, at most `SESSION_ID_MAX_LENGTH`
    characters, and an ASCII IDENTIFIER: every character printable ASCII and
    none of them whitespace, i.e. each in the range `!` (0x21) to `~` (0x7E).
    Anything else -- a dict, a number, an oversized string, a JSON `\\ud800`
    escape that `json.loads` happily turns into a Python string holding a
    lone surrogate, a NUL or newline, a bidi control character like U+202E
    that can make a rendered string display in an order its characters do
    not actually hold, or a strong right-to-left LETTER such as U+05D0 (which
    `isprintable()` accepts, and which reorders its neighbours when rendered
    just as an override does) -- becomes `None`, the same absence a stream
    that never mentioned a session already records. The ASCII rule is what
    closes the last of those: a character-category rule cannot, because the
    letters that reorder a rendering are ordinary printable letters.

    Three checks, in order. `isascii()` refuses every non-ASCII code point,
    surrogates included. `isprintable()` then refuses the ASCII controls
    (NUL, newline, tab, DEL). The explicit whitespace check refuses the one
    printable ASCII character that is not an identifier character, the space
    (U+0020) -- `isprintable()` alone accepts it, so `"a b"` would pass
    without the third check. Every session identifier either provider CLI
    has been observed to emit is a UUID-shaped run of ASCII letters, digits
    and hyphens, well inside this rule.

    The surrogate refusal matters beyond shape: `nornyx_forge.util.digest`
    calls `.encode("utf-8")` on the canonical JSON text built from
    `WorkerResult` fields (`canonical_json`'s own `json.dumps` accepts a lone
    surrogate without complaint, so it would not catch this), and a lone
    surrogate surviving into that text raises `UnicodeEncodeError` deep
    inside evidence serialization rather than being refused at the one place
    that actually parsed untrusted provider output.
    """
    if not isinstance(value, str):
        return None
    if not value or len(value) > SESSION_ID_MAX_LENGTH:
        return None
    if not value.isascii():
        return None
    if not value.isprintable() or any(ch.isspace() for ch in value):
        return None
    return value
