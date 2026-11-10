"""The verdict a review worker must end with, and the parser that reads it.

WHY THIS EXISTS. A review gate used to pass when the reviewer's PROCESS
finished. A reviewer that concluded `NOT_VERIFIED`, or reported a defect, still
produced a passing gate, because nothing read what it concluded -- and nothing
could, since reviewers had no verdict contract and each invented its own words.

THE CONTRACT. A reviewer ends its reply with a line that reads exactly
`NORNYX-REVIEW-VERDICT`, followed by exactly one JSON object -- alone, or alone
inside one fenced code block -- and nothing after it:

    NORNYX-REVIEW-VERDICT
    {"schema": "nornyx.forge.review_verdict.v1",
     "role": "<the reviewer's role>",
     "verdict": "PASS" | "FAIL" | "NOT_VERIFIED",
     "blocking_findings": ["<non-empty text>", ...],
     "evidence_relied_on": ["<text>", ...]}

Exactly those five keys. `PASS` with any blocking finding is invalid.

WHY A MARKER LINE, and not a search for the last object. Earlier heads found
the verdict by scanning the reply's free text for JSON, and each review of
them found a reply shape that scan misread: a verdict nested in an example, in
an object or array never closed, or behind a stray quote that shifted where
strings were taken to begin. Inferring structure from text that need not be
JSON keeps leaving such gaps. A JSON string cannot hold a raw line break and a
bare word is not a JSON token, so no JSON value written before the marker
line can extend past it. The text before the marker is therefore never parsed
or counted; the text after it must decode, strictly and entirely, as one
object. The marker occurs exactly once, and the schema identifier, however it
is spelled -- a JSON escape such as `\\u006e` is the same text -- does not
appear before it, so a second or draft verdict is refused as well.

THE PARSER FAILS CLOSED. `parse_review` reads a worker's recorded output
exactly as `WorkerResult.output` holds it, and returns `PASS`, `FAIL`,
`NOT_VERIFIED` or `INVALID`, each with a reason. Everything that is not one
well-formed verdict object for the expected role, from a worker that
succeeded, is `INVALID`. Only a valid `PASS` passes a verdict gate.

WHAT THE ADAPTERS RECORD, read from them rather than assumed:

  * `claude_worker` records `claude -p --output-format json` stdout: one JSON
    envelope whose `result` field holds the reply text.
  * `codex_worker` records `codex exec --json` stdout: JSON events, one per
    line. The reply text is the `text` of the last `item.completed` event
    whose `item.type` is `agent_message`. No recorded sample of that
    vocabulary is pinned in this repository; a stream that does not carry it
    yields no reply text and so `INVALID`, never a guessed verdict.

A verdict here is an INTERNAL AI review verdict: the reviewer is a worker the
same build launched. It is not independent review and not human approval,
and nothing in this module records or implies either.

`layer.domain`: strings in, values out. No filesystem, clock or process.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

#: The verdict object's schema identifier.
REVIEW_VERDICT_SCHEMA = "nornyx.forge.review_verdict.v1"

#: The verdicts a reviewer may give, closed.
VERDICTS = ("PASS", "FAIL", "NOT_VERIFIED")

#: What the parser can return: a reviewer's verdict, or INVALID.
PARSED_VERDICTS = (*VERDICTS, "INVALID")

#: The verdict object's keys, exactly.
VERDICT_KEYS = frozenset(
    {"schema", "role", "verdict", "blocking_findings", "evidence_relied_on"}
)

#: The longest reply text read, in characters. Beyond it the output is
#: INVALID: a verdict is a short object at the end of a review, and an
#: unbounded text would make the object scan quadratic in provider output.
MAX_RESULT_TEXT = 200_000


@dataclass(frozen=True)
class ParsedVerdict:
    """One reviewer's verdict as the parser read it."""

    verdict: str
    reason: str
    role: str
    blocking_findings: tuple[str, ...] = field(default=())
    evidence_relied_on: tuple[str, ...] = field(default=())

    @property
    def passed(self) -> bool:
        """True only for a valid PASS."""
        return self.verdict == "PASS"

    def as_dict(self) -> dict[str, Any]:
        """The parsed record. It carries no `schema` key, so a record can
        never itself be read back as a verdict object."""
        return {
            "role": self.role,
            "verdict": self.verdict,
            "reason": self.reason,
            "blocking_findings": list(self.blocking_findings),
            "evidence_relied_on": list(self.evidence_relied_on),
        }


def _invalid(role: str, reason: str) -> ParsedVerdict:
    return ParsedVerdict("INVALID", reason, role)


class _DuplicateKey(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """`json` keeps the LAST of a repeated key, so `{"verdict": "FAIL",
    "verdict": "PASS"}` would read as a PASS. A repeated key is refused."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate key {key!r}")
        result[key] = value
    return result


_DECODER = json.JSONDecoder(object_pairs_hook=_no_duplicate_keys)


def _loads(text: str) -> Any:
    return _DECODER.decode(text)


#: Event types by which a Codex stream reports a run that did not complete.
#: A stream carrying one yields no reply, whatever message precedes it.
_FAILED_EVENTS = frozenset({"error", "turn.failed"})


def reply_text(output: Any) -> tuple[str | None, str]:
    """The reviewer's reply text inside a recorded worker output.

    Returns `(text, how)` where `how` names the envelope read, or
    `(None, reason)` when no reply text can be read.
    """
    if not isinstance(output, str):
        return None, "the recorded output is not text"
    stripped = output.strip()
    if not stripped:
        return None, "the recorded output is empty"
    try:
        envelope = _loads(stripped)
    except (ValueError, RecursionError):
        envelope = None
    if envelope is not None:
        if not isinstance(envelope, dict):
            return None, "the recorded output is JSON but not an envelope object"
        if envelope.get("is_error") is True:
            return None, "the worker envelope reports an error"
        # The Claude CLI marks a run that did not finish normally -- a turn
        # limit, an execution error -- by its subtype, so anything other than
        # a successful result is not a reply to read a verdict from.
        if "type" in envelope and envelope["type"] != "result":
            return None, "the worker envelope is not a result"
        if "subtype" in envelope and envelope["subtype"] != "success":
            return None, "the worker envelope reports a run that did not succeed"
        if "result" not in envelope:
            return None, "the worker envelope carries no result text"
        if not isinstance(envelope["result"], str):
            return None, "the worker envelope's result is not text"
        return envelope["result"], "worker JSON envelope"
    events: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = _loads(line)
        except (ValueError, RecursionError):
            return None, "the recorded output is not a decodable worker envelope"
        if not isinstance(event, dict):
            return None, "the recorded output is not a decodable worker envelope"
        events.append(event)
    if any(event.get("type") in _FAILED_EVENTS for event in events):
        return None, "the worker event stream reports an error"
    reply: str | None = None
    for event in events:
        item = event.get("item")
        if (
            event.get("type") == "item.completed"
            and isinstance(item, dict)
            and item.get("type") == "agent_message"
            and isinstance(item.get("text"), str)
        ):
            reply = item["text"]
    if reply is None:
        return None, "the worker event stream carries no completed agent message"
    return reply, "worker JSON event stream"


#: The lenient decoder used only to find WHERE a JSON object ends. A repeated
#: key does not stop it, so a malformed candidate is still located and then
#: refused by the strict decoder rather than skipped as if it were prose.
_LOCATOR = json.JSONDecoder()

#: A JSON escape that can spell a character of the schema identifier.
_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\(/)")

#: How many rounds of escape decoding are applied; each round can only make
#: more of the text literal, and the identifier is ASCII, so a few suffice.
_ESCAPE_ROUNDS = 8


def _unescaped(text: str) -> str:
    """`text` with every JSON escape decoded, wherever it occurs.

    No string literal is parsed, so no pairing of quotes is relied on: a
    stray quote in prose cannot shift where an escaped spelling is found.
    Decoding is repeated so a doubly escaped spelling is decoded as well;
    over-decoding can only find MORE mentions, which fails closed.
    """
    for _ in range(_ESCAPE_ROUNDS):
        decoded = _JSON_ESCAPE.sub(
            lambda hit: chr(int(hit.group(1), 16)) if hit.group(1) else hit.group(2), text
        )
        if decoded == text:
            break
        text = decoded
    return text


def _names_the_schema(text: str) -> bool:
    """Whether `text` contains the schema identifier, spelled any way."""
    return REVIEW_VERDICT_SCHEMA in text or REVIEW_VERDICT_SCHEMA in _unescaped(text)


#: The line that introduces the verdict. A JSON string cannot hold a raw line
#: break and a bare word is not a JSON token, so no JSON value written before
#: this line can extend past it: the object after it is never inside one.
VERDICT_MARKER = "NORNYX-REVIEW-VERDICT"

#: The Markdown fence lines a verdict object may be wrapped in after the marker.
_FENCE_OPENERS = ("```", "```json")
_FENCE = "```"


def _verdict_block(text: str) -> tuple[str, str] | str:
    """The text before the marker line and the verdict text after it.

    Returns `(before, verdict_text)`, or the reason no block can be read.
    The marker must stand alone on exactly one line and occur nowhere else.
    After it comes the object, alone, or the object alone inside one fenced
    block; anything else after the marker is not a verdict block.
    """
    if VERDICT_MARKER not in text:
        return "the reply has no verdict marker line"
    lines = text.split("\n")
    marked = [index for index, line in enumerate(lines) if line.strip() == VERDICT_MARKER]
    if not marked:
        return "the verdict marker is not on a line of its own"
    if len(marked) > 1 or text.count(VERDICT_MARKER) > 1:
        return "the verdict marker appears more than once"
    index = marked[0]
    before = "\n".join(lines[:index])
    after = "\n".join(lines[index + 1:]).strip()
    if after.startswith(_FENCE):
        newline = after.find("\n")
        if newline == -1:
            return "the text after the verdict marker is not exactly one verdict object"
        opener = after[:newline].strip()
        body = after[newline + 1:].rstrip()
        if opener not in _FENCE_OPENERS or not body.endswith(_FENCE):
            return "the text after the verdict marker is not exactly one verdict object"
        after = body[: -len(_FENCE)].strip()
    return before, after


def validate_verdict_object(value: Any, expected_role: str) -> ParsedVerdict:
    """One candidate object judged against the contract, closed."""
    if not isinstance(value, dict):
        return _invalid(expected_role, "the verdict is not a JSON object")
    keys = set(value)
    if keys != VERDICT_KEYS:
        missing = sorted(VERDICT_KEYS - keys)
        unknown = sorted(keys - VERDICT_KEYS)
        parts = []
        if missing:
            parts.append(f"missing keys {missing}")
        if unknown:
            parts.append(f"unknown keys {unknown}")
        return _invalid(expected_role, "the verdict object has " + " and ".join(parts))
    if value["schema"] != REVIEW_VERDICT_SCHEMA:
        return _invalid(expected_role, "the verdict object names another schema")
    role = value["role"]
    if not isinstance(role, str):
        return _invalid(expected_role, "the verdict's role is not text")
    if role != expected_role:
        return _invalid(expected_role, f"the verdict is for role {role!r}, not {expected_role!r}")
    verdict = value["verdict"]
    if not isinstance(verdict, str):
        return _invalid(expected_role, "the verdict is not text")
    if verdict not in VERDICTS:
        return _invalid(expected_role, f"the verdict {verdict!r} is not one of {list(VERDICTS)}")
    findings = value["blocking_findings"]
    if not isinstance(findings, list) or not all(
        isinstance(item, str) and item.strip() for item in findings
    ):
        return _invalid(expected_role, "blocking_findings is not a list of non-empty text")
    evidence = value["evidence_relied_on"]
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        return _invalid(expected_role, "evidence_relied_on is not a list of text")
    if verdict == "PASS" and findings:
        return _invalid(expected_role, "a PASS verdict lists blocking findings")
    reason = {
        "PASS": "the reviewer gave a valid PASS verdict",
        "FAIL": "the reviewer gave a FAIL verdict",
        "NOT_VERIFIED": "the reviewer could not verify, and said so",
    }[verdict]
    return ParsedVerdict(verdict, reason, expected_role, tuple(findings), tuple(evidence))


def parse_review(output: Any, *, expected_role: str, worker_success: bool) -> ParsedVerdict:
    """A reviewer's recorded output read as a verdict, failing closed."""
    if worker_success is not True:
        return _invalid(expected_role, "the review worker did not succeed")
    text, how = reply_text(output)
    if text is None:
        return _invalid(expected_role, how)
    if len(text) > MAX_RESULT_TEXT:
        return _invalid(expected_role, f"the reply text exceeds {MAX_RESULT_TEXT} characters")
    block = _verdict_block(text)
    if isinstance(block, str):
        return _invalid(expected_role, block)
    before, verdict_text = block
    if _names_the_schema(before):
        return _invalid(
            expected_role,
            "the schema identifier appears before the verdict marker, so the reply "
            "holds another or a partial verdict",
        )
    try:
        located, stop = _LOCATOR.raw_decode(verdict_text) if verdict_text.startswith("{") else (None, -1)
    except (ValueError, RecursionError):
        located, stop = None, -1
    if not isinstance(located, dict) or stop != len(verdict_text):
        return _invalid(
            expected_role, "the text after the verdict marker is not exactly one verdict object"
        )
    try:
        value = _loads(verdict_text)
    except (ValueError, RecursionError):
        return _invalid(expected_role, "the verdict object is malformed JSON")
    return validate_verdict_object(value, expected_role)


def verdict_counts(parsed: list[ParsedVerdict]) -> dict[str, int]:
    """How many parsed verdicts of each kind, every kind present."""
    counts = {verdict: 0 for verdict in PARSED_VERDICTS}
    for item in parsed:
        counts[item.verdict] += 1
    return counts


def verdict_requirement(role: str) -> str:
    """The sentence a review goal ends with: the exact object, and the rule.

    The template's verdict is a placeholder that is not a valid verdict, so
    an echoed template can never read as a PASS.
    """
    template = (
        '{"schema": "' + REVIEW_VERDICT_SCHEMA + '", "role": "' + role + '", '
        '"verdict": "PASS or FAIL or NOT_VERIFIED", '
        '"blocking_findings": ["..."], "evidence_relied_on": ["..."]}'
    )
    return (
        "End your reply with a line containing exactly " + VERDICT_MARKER + ", "
        "followed by exactly one JSON object, alone or alone inside one fenced "
        "code block, with exactly these five keys: " + template + ". "
        "Nothing may follow that object except the closing fence of that block. "
        "Set verdict to exactly one of PASS, FAIL or NOT_VERIFIED. "
        "blocking_findings lists each blocking finding as non-empty text; PASS "
        "requires an empty list. evidence_relied_on lists what you relied on. "
        "Write the marker and the schema identifier nowhere else. A missing "
        "marker, a missing, malformed or additional verdict object, any other "
        "verdict, or any other role is treated as a failure, and anything other "
        "than a valid PASS rejects the build."
    )
