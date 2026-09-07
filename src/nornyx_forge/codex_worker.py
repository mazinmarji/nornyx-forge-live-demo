"""Bounded bridge to an authenticated local Codex CLI installation.

The Codex sibling of `claude_worker`, deliberately the same shape: construct
with an executable name, `available()` answers whether it can be invoked at
all, `run()` executes one bounded task and reports a `WorkerResult` with the
same failure conventions — 127 when the executable is absent, 124 on timeout,
success exactly when the process exited 0, output passed through verbatim.
Keeping the shape identical is what lets one Provider Contract wrap both
without either adapter carrying translation logic of its own.

THE INVOCATION IS VALIDATED, NOT GUESSED. Flags here were checked against a
real `codex` CLI (codex-cli 0.128.0): `codex exec` is the non-interactive
mode, `--cd` sets the working root, `--json` streams JSONL events to stdout,
`--skip-git-repo-check` permits arbitrary workspaces, and `--sandbox`
selects the execution policy.

TWO MAPPING LIMITS, stated because pretending otherwise would be the exact
dishonesty the contract exists to prevent:

  * `max_turns` has no Codex CLI equivalent. It is accepted for interface
    symmetry and NOT enforced here; the enforced bound is `timeout_seconds`,
    exactly as the subprocess timeout enforces it for the Claude path too.
  * `allowed_tools` has no per-tool equivalent; Codex's real control is the
    sandbox policy, and this worker always passes `--sandbox workspace-write`
    — the bounded default matching what Forge asks of a build worker. The
    tool names are recorded in the prompt so the model sees the intent, but
    the MECHANISM is the sandbox, and this docstring is the disclosure.

THE STREAM IS UTF-8, AND IS DECODED AS UTF-8, STRICTLY. Not a detail:
`text=True` on its own decodes with the locale encoding, and PA-01 measured
that going wrong two ways on this adapter's real output under cp1252 -- silent
mojibake carried verbatim into evidence, and an unmapped byte raising out of
`run()` where the contract requires a WorkerResult.

AND NOT `errors="replace"` EITHER, which is the repair that looks right and
is not. Replacement turns malformed bytes into U+FFFD and hands them on as
ordinary text, so a run whose output could not be read reports success and
prose. Both failures are the same failure -- evidence that is not what the
provider actually emitted -- and one of them is harder to notice. So decoding
is strict, a stream that fails it yields a WorkerResult that RECORDS the
integrity failure with the payload's length and digest, and the run is not
successful whatever the process exited with. Valid UTF-8 is preserved exactly.

The session identifier is parsed from the JSONL event stream when one appears
(`session_id` or `thread_id` keys); absence is recorded as None, never
invented.

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
The routed path never reaches this -- `ProviderTask.validate` refuses a goal
above 8000 characters first -- so it guards the direct worker's callers.
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


class CodexWorker:
    """Bounded bridge to an authenticated local Codex CLI installation."""

    def __init__(self, executable: str = "codex") -> None:
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
        del max_turns  # no Codex CLI equivalent; the enforced bound is the timeout
        if not self.available():
            return WorkerResult(
                role,
                goal,
                False,
                "Codex CLI executable not found",
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
                    "Codex worker workspace is not an existing directory: "
                    f"{workspace}"
                ),
                returncode=MALFORMED_INVOCATION_RETURNCODE,
            )
        prompt = (
            f"You are the {role} worker in Nornyx Forge. Execute only this bounded goal:\n"
            f"{goal}\n\n"
            "Read the repository instructions and the relevant Nornyx contracts. "
            "Do not weaken gates, do not claim human approval, and do not perform "
            f"production operations. Intended tools: {', '.join(allowed_tools)}. "
            "Return a concise JSON-compatible result with changed files, checks, "
            "findings, assumptions, and limitations."
        )
        read_only_tools = {"Read", "Glob", "Grep"}
        sandbox = (
            "read-only"
            if set(allowed_tools).issubset(read_only_tools)
            else "workspace-write"
        )
        command = (
            self.executable,
            "exec",
            "--json",
            "--cd",
            str(workspace),
            "--skip-git-repo-check",
            "--sandbox",
            sandbox,
            "--color",
            "never",
            prompt,
        )
        try:
            # BYTES, DECODED HERE RATHER THAN BY subprocess. `text=True` alone
            # decodes with the locale encoding -- cp1252 on a Windows
            # basic-user host -- and PA-01 caught both ways that goes wrong on
            # this adapter's REAL output: a right single quote became mojibake
            # carried verbatim into evidence, and a right double quote (byte
            # 0x9d, unmapped in cp1252) raised on the reader thread, left
            # `stdout` as None, and became an AttributeError escaping `run()`.
            # Decoding here makes the encoding explicit AND keeps the failure
            # a WorkerResult, which is what the Provider Contract requires.
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
            # timeout. Brought level with the Claude adapter's timeout branch
            # in the provider-adapter parity slice: this branch used to record
            # only the decode reason and byte offset here, which A-025
            # (docs/requirements/ASSUMPTIONS.md) carried as an open item.
            # Both branches DESCRIBE an undecodable payload; neither renders it.
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
                output=f"Codex worker timed out after {timeout_seconds}s.{note}"
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
                output=f"Codex worker invocation could not be formed: {exc}",
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
                # would send it looking in the wrong place. Here the goal
                # sits inside the prompt, the LAST element of the command
                # vector. The routed path cannot reach this line:
                # `ProviderTask.validate` refuses a goal above 8000
                # characters before any adapter runs.
                return WorkerResult(
                    role=role,
                    goal=goal,
                    success=False,
                    output=(
                        "Codex worker invocation exceeds the operating "
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
            # as "found" in the first place. Measured directly, mirroring
            # the identical repair on the Claude adapter: a zero-byte file
            # carrying an executable extension passes `shutil.which`
            # (Windows does not check file CONTENTS, only that something
            # exists at a recognised extension) and then `subprocess.run`
            # raises `OSError: [WinError 193] %1 is not a valid Win32
            # application` when the loader actually tries it. The Provider
            # Contract still requires a WorkerResult, not an exception, for
            # this: it is the SAME unavailable class `available()` already
            # reports for an absent executable, because a path that cannot
            # be executed is not meaningfully different from one that was
            # never there.
            return WorkerResult(
                role=role,
                goal=goal,
                success=False,
                output=f"Codex worker executable could not be started: {exc}",
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
                output="Codex worker output failed UTF-8 integrity and was NOT "
                       "decoded with replacement: " + "; ".join(problems)
                       + f". Process exited {result.returncode}. "
                       + _fingerprint("stdout", result.stdout) + " "
                       + _fingerprint("stderr", result.stderr)
                       + (f"\n{PROVIDER_TEXT_DELIMITER}\n{readable}" if readable else ""),
                command=command,
                returncode=result.returncode,
            )

        output = stdout.strip() or stderr.strip()
        session_id = _session_from_jsonl(stdout)
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


#: The bound `_validated_session_id` enforces. See the identical constant and
#: rationale in `claude_worker.py`; duplicated rather than imported so the two
#: adapters stay independent modules with no cross-import between them.
SESSION_ID_MAX_LENGTH = 200

#: Returned when Forge could not hand the provider a well-formed invocation at
#: all: the workspace is not an existing directory, an argument carries a NUL
#: the operating system refuses, or the argument list is longer than the
#: operating system accepts. See the identical constant and rationale in
#: `claude_worker.py`; duplicated for the same reason, and a test holds the
#: two equal.
MALFORMED_INVOCATION_RETURNCODE = 2

#: The Windows system error `CreateProcess` answers when the command line
#: exceeds its 32767-character bound: ERROR_FILENAME_EXCED_RANGE. CPython maps
#: it to errno ENOENT (2), so `OSError.errno` cannot tell it from an absent
#: executable; `OSError.winerror` can. Identical in `claude_worker.py`.
_ARGUMENT_TOO_LONG_WINERROR = 206


def _argument_list_too_long(exc: OSError) -> bool:
    """Whether the operating system refused the spawn for the LENGTH of its
    arguments: `E2BIG` from a POSIX `execve`, or Windows error 206 from
    `CreateProcess` (measured: a 33000-character argument on the Windows host
    this was written on). Any other `OSError` is about the executable.
    Identical to `claude_worker.py`'s rule."""
    return (
        getattr(exc, "winerror", None) == _ARGUMENT_TOO_LONG_WINERROR
        or exc.errno == errno.E2BIG
    )


def _command_line_length(command: tuple[str, ...]) -> int:
    """How many characters the argument vector occupies: the arguments plus
    one separator each. A platform-neutral count of what was handed to the
    operating system (Windows quotes some arguments and counts the result
    against 32767; POSIX counts bytes with terminators), so the sentence that
    reports the refusal names a size and not only the fact."""
    return sum(len(argument) + 1 for argument in command)

#: The line Forge writes between its own account of a run and any decoded
#: provider text it keeps beside that account. See the module docstring and
#: the identical constant in `claude_worker.py`; a test holds them equal.
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
    that carries neither `session_id` nor `thread_id` already records. The
    ASCII rule is what closes the last of those: a character-category rule
    cannot, because the letters that reorder a rendering are ordinary
    printable letters.

    Three checks, in order. `isascii()` refuses every non-ASCII code point,
    surrogates included. `isprintable()` then refuses the ASCII controls
    (NUL, newline, tab, DEL). The explicit whitespace check refuses the one
    printable ASCII character that is not an identifier character, the space
    (U+0020) -- `isprintable()` alone accepts it, so `"a b"` would pass
    without the third check. Every session identifier either provider CLI
    has been observed to emit is a UUID-shaped run of ASCII letters, digits
    and hyphens, well inside this rule. Identical to `claude_worker.py`'s
    rule, character for character.

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


def _session_from_jsonl(stdout: str) -> str | None:
    """The first session/thread identifier the event stream carries, or None.

    `codex exec --json` emits one JSON event per line. Nothing here depends on
    a specific event vocabulary: any event carrying a string `session_id` or
    `thread_id` identifies the session, and a stream carrying neither, or
    carrying only a value `_validated_session_id` refuses, yields None —
    recorded as absent, never synthesized.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            # ValueError covers `json.JSONDecodeError` (a subclass) for an
            # ordinary malformed line. RecursionError is the one that is not
            # obvious: a single JSONL line deep enough (nested arrays or
            # objects, no closing bracket required to trigger it) exhausts
            # CPython's own recursion guard before it ever notices the line
            # is malformed -- measured directly, not assumed -- and the
            # Provider Contract requires a WorkerResult here too, never an
            # exception escaping over provider-controlled stdout. Skipping
            # the line and continuing the scan is the same response either
            # way: this line names no session, exactly like one that failed
            # to parse for an ordinary reason.
            continue
        if not isinstance(event, dict):
            continue
        for key in ("session_id", "thread_id"):
            value = _validated_session_id(event.get(key))
            if value is not None:
                return value
    return None
