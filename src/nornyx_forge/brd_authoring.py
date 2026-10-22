"""Derive a BRD from the capsule's CONFIRMED region. Authority in, BRD out.

WHAT THIS IS FOR. The build flow reads requirements from a BRD; the basic
user writes plain language into the capsule. This module is the bridge,
and it carries the authority line across: the BRD is derived from the
AUTHORITATIVE region only -- the intent and requirements a human
confirmed -- rendered by a fixed template with no free-text parameter of
its own. The user's words appear in the BRD because the user confirmed
them, which is precisely the provenance a requirements document should
have; an open proposal, whoever made it, authors nothing here.

The output is shaped for `parse_brd` and the derivation is verified
against it: every confirmed requirement becomes a leaf heading the parser
reads back, so what the flow will build from is provably what the human
confirmed -- not a paraphrase, not a superset.

THE IDENTITIES ARE CHECKED, NOT ASSUMED (A-045). Before it returns, the
derivation reads its own rendering through `brd_requirement_identity`, the
one rule the parser and the acceptance verifier also apply, and refuses a
rendering whose requirements are not exactly `BRD-001` and one `BRD-F-NNN`
per confirmed row, whose only section is the `BRD-002` heading above those
rows, or that holds any malformed identifier heading. So the BRD a basic
user's confirmation produces is one the verifier can accept, and a confirmed
text that would change what a reader takes as a requirement -- a line
separator `str.splitlines` honours, say -- is refused here rather than
built from.

`layer.domain`: mappings and strings in, one string out. Writing the file
is the caller's act.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .capsule import AUTHORITATIVE_FIELDS, REQUIREMENT_NUMBER_LIMIT, CapsuleValidationError
from .requirements import brd_requirement_identity


class BrdAuthoringError(Exception):
    """A capsule state this derivation refuses."""


#: The characters `str.splitlines()` ends a line at -- the reader's rule, as a
#: set, so a text is tested for them directly rather than by counting the lines
#: a split makes: one boundary at the end of a text leaves one line, and the
#: count missed it (Codex P2 4338765174). Built from
#: code points; the test enumerates every code point against splitlines().
#: The page holds no copy: it sends what the person typed, and only the
#: server judges a text.
LINE_BOUNDARIES = frozenset(chr(code) for code in (
    0x0A, 0x0D, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029))


def holds_line_boundary(text: str) -> bool:
    """Whether `text` holds any character `str.splitlines()` ends a line at."""
    return any(character in LINE_BOUNDARIES for character in text)


def _shown(text: str, limit: int = 60) -> str:
    return repr(text) if len(text) <= limit else repr(text[:limit]) + f"... ({len(text)} characters)"


def _confirmed(document: Mapping[str, Any], field: str) -> Any:
    if not isinstance(document, Mapping):
        raise BrdAuthoringError("a BRD is derived from a capsule document")
    return document.get("authoritative", {}).get(field)


def _refuse_heading_collisions(value: str, where: str) -> str:
    if "\n" in value or "\r" in value or value.lstrip().startswith("#"):
        raise BrdAuthoringError(
            f"{where} collides with the BRD's heading grammar and cannot be "
            "rendered without changing what a parser would read back"
        )
    return value


def brd_from_capsule(document: Mapping[str, Any]) -> str:
    """The confirmed intent and requirements, as a parseable BRD.

    Refuses a capsule with no CONFIRMED intent: a project whose need was
    only proposed has not decided what to build, and deriving a BRD from a
    proposal would put unconfirmed words in front of the build flow.
    """
    project_name = _confirmed(document, "project_name")
    intent = _confirmed(document, "intent")
    if not isinstance(intent, str) or not intent.strip():
        raise BrdAuthoringError(
            "the capsule has no confirmed intent; confirm one through "
            "onboarding before deriving a BRD"
        )
    requirements = _confirmed(document, "requirements") or []

    lines: list[str] = [
        f"# BRD — {_refuse_heading_collisions(str(project_name), 'the project name')}",
        "",
        "This document is DERIVED from the project capsule's confirmed",
        "region. The capsule is the authority; regenerate this file after",
        "new confirmations rather than editing it in place.",
        "",
        "## BRD-001 Purpose",
        "",
        _refuse_heading_collisions(intent, "the confirmed intent"),
        "",
    ]
    if requirements:
        lines.extend(["## BRD-002 Functional requirements", ""])
        for index, row in enumerate(requirements, start=1):
            lines.extend([
                f"### BRD-F-{index:03d} {row['id']}",
                "",
                _refuse_heading_collisions(
                    row["text"], f"requirement {row['id']}"
                ),
                "",
            ])
    rendered = "\n".join(lines)
    identity = brd_requirement_identity(rendered)
    expected = ["BRD-001", *(f"BRD-F-{index:03d}" for index in range(1, len(requirements) + 1))]
    if (
        [entry["id"] for entry in identity["requirements"]] != expected
        or identity["sections"] != (["BRD-002"] if requirements else [])
        or identity["malformed"]
    ):
        raise BrdAuthoringError(
            "the derived BRD does not read back, under the requirement-identity "
            "rule, as exactly the confirmed intent and requirements; a confirmed "
            "text changes which headings a reader takes as requirements, so it is "
            "refused rather than rendered"
        )
    # THE STATEMENTS, NOT ONLY THE IDENTITIES. The reader strips each line,
    # joins lines, and drops a leading list mark, so a confirmed text with a
    # trailing line boundary, padding or a "- " in front was read back as other
    # words than the human confirmed -- and the identity check above, which
    # compares only ids, passed it (Codex P2 4338765174). Each statement is
    # now compared with the confirmed text it renders.
    confirmed = [intent, *(row["text"] for row in requirements)]
    read_back = [entry["statement"] for entry in identity["requirements"]]
    for index, (wanted, got) in enumerate(zip(confirmed, read_back)):
        if wanted != got:
            label = "the confirmed intent" if index == 0 else f"requirement {requirements[index - 1]['id']}"
            raise BrdAuthoringError(
                f"the derived BRD reads {label} back as {_shown(got)}, not as confirmed "
                f"({_shown(wanted)}); a document that builds from other words than the "
                "human confirmed is refused rather than rendered"
            )
    return rendered


def confirmed_requirement_texts(document: Mapping[str, Any]) -> tuple[str, ...]:
    """What a parser must read back: the confirmed statements, in order."""
    intent = _confirmed(document, "intent")
    rows = _confirmed(document, "requirements") or []
    statements = [intent] if isinstance(intent, str) else []
    statements.extend(row["text"] for row in rows)
    return tuple(statements)


# ---------------------------------------------------------------------------
# The same rules, asked when a basic user proposes (A-048)
# ---------------------------------------------------------------------------
#
# WHY HERE. The derivation above is the rule a confirmed intent and confirmed
# requirement rows must satisfy; asking it only at `POST /api/brd` meant a
# multi-line need was proposed, confirmed into authority, and only then
# refused, in the parser's terms. `proposal_entry_refusal` asks the same
# derivation, and the capsule's own field schema, at the door -- before
# anything is stored -- and says what to change in plain words, with the
# technical reason beneath, quoting the derivation's own words. It refuses
# nothing the derivation or the capsule would accept, with two exceptions it
# names: a row that repeats another, which would be built and tested as two
# requirements; and a line boundary `str.splitlines` honours that the
# derivation does not spell, which a reader of the rendered document would
# read as a second line. It authorizes nothing: a value that passes is still
# only a proposal, and only a human confirmation moves it.

#: The fields a basic user enters as text; every other field passes untouched.
ENTRY_FIELDS = ("intent", "requirements")
#: Neutral stand-ins for the parts of a BRD a proposal does not supply, so the
#: derivation judges the proposed value alone and not the confirmed state.
_PROBE_NAME = "Project"
_PROBE_INTENT = "Purpose."


@dataclass(frozen=True)
class EntryRefusal:
    """Why a proposed intent or requirement set is refused, twice over.

    `explanation` is for the person at the page: what is wrong and what to
    change, without the parser's vocabulary. `reason` is the technical
    refusal: the capsule's own words where its schema refuses the value; the
    derivation's own words, quoted verbatim after `DERIVATION_WOULD_REFUSE`,
    where it would refuse the value once confirmed; this module's where it
    refuses on its own account. `row` names the requirement
    at fault (its id, or "row <n>" when the row has no usable id), or is
    None when the fault is the whole value."""

    field: str
    explanation: str
    reason: str
    row: str | None = None

    def as_body(self) -> dict[str, Any]:
        """The refusal as the onboarding surface returns it. `refused` stays
        the technical reason, where every existing client already reads one."""
        return {"refused": self.reason, "explanation": self.explanation,
                "field": self.field, "row": self.row}


#: What the derivation's own words are quoted after. They are written for a
#: CONFIRMED capsule ("the confirmed intent collides ..."), and at a proposal
#: nothing is confirmed, so they are not returned bare: bare, they would state
#: something the record does not hold.
DERIVATION_WOULD_REFUSE = "once confirmed, the BRD derivation would refuse this: "


def _derivation_refusal(intent: str, rows: list[dict[str, Any]]) -> str | None:
    """The derivation's own refusal of this content, quoted verbatim after
    `DERIVATION_WOULD_REFUSE`, or None."""
    probe = {"authoritative": {"project_name": _PROBE_NAME, "intent": intent,
                               "requirements": rows}}
    try:
        brd_from_capsule(probe)
    except BrdAuthoringError as error:
        return DERIVATION_WOULD_REFUSE + str(error)
    return None


_LINE_FAULT = ("{who} is written over more than one line. Write it as one line;"
               " a line break you cannot see counts too.")


def _text_fault(text: str, who: str, grammar_reason: str | None) -> str | None:
    """A plain explanation of why `text` cannot be rendered, or would not read
    back as written, or None. Each property is tested directly."""
    if holds_line_boundary(text):
        return _LINE_FAULT.format(who=who)
    if text.lstrip().startswith("#"):
        return (f"{who} starts with “#”, which the requirements document keeps for"
                " its own section titles. Remove the “#” at the start.")
    if text != text.strip():
        return (f"{who} begins or ends with a space or another blank character, which"
                " the requirements document does not keep. Remove it.")
    if text[:1] in ("-", "*") and text[1:2].isspace():
        return (f"{who} starts with “{text[0]}” and a space, which the requirements"
                " document reads as a list mark and drops. Remove the mark, or start"
                " the sentence differently.")
    if grammar_reason is not None:
        return (f"{who} cannot be written into the requirements document as it"
                " stands. Rephrase it as one plain sentence.")
    return None


def _schema_explanation(reason: str, who: str, limit: int, text: Any = None) -> str:
    """The capsule's field-schema refusal, in plain words. A control character
    that is also a line boundary is explained as the line break it is."""
    if "control characters" in reason and isinstance(text, str) and holds_line_boundary(text):
        return _LINE_FAULT.format(who=who)
    if "must be a string" in reason:
        return f"{who} could not be read as text. Enter it as words."
    if "must not be empty" in reason:
        return f"{who} is empty. Write it, or remove it."
    if "exceeds" in reason:
        return (f"{who} is longer than {limit} characters. Shorten it, or split it"
                " into more than one requirement.")
    if "control characters" in reason:
        return (f"{who} contains a control character that cannot be stored. Retype"
                " it without special characters.")
    return f"{who} cannot be stored as entered. Retype it as plain words."


def _intent_refusal(value: Any) -> EntryRefusal | None:
    who = "Your description of what you need"
    try:
        AUTHORITATIVE_FIELDS["intent"](value)
    except CapsuleValidationError as error:
        reason = str(error)
        explanation = _schema_explanation(reason, who, 4000, value)
        if "must not be empty" in reason:
            explanation = f"{who} is empty. Write what you need, in one line."
        return EntryRefusal("intent", explanation, reason)
    grammar = _derivation_refusal(value, [])
    fault = _text_fault(value, who, grammar)
    if fault is None:
        return None
    if "more than one line" in fault:
        fault += (" Put each separate thing the application must do in its own"
                  " requirement row instead.")
    reason = grammar or (
        "the intent holds a line boundary str.splitlines honours, so a reader of "
        "the derived BRD would read it as more than one line")
    return EntryRefusal("intent", fault, reason)


#: The shape of a requirement number the rule counts: one to six ASCII digits,
#: the schema's own width. Any other suffix -- longer, empty, signed, spaced or
#: non-ASCII -- holds no number here, as it holds none on the page, and is never
#: converted with int(), so a suffix of thousands of digits cannot raise
#: (Codex P2 4337040952).
_REQUIREMENT_NUMBER = re.compile(r"RQ-([0-9]{1,6})")


def smallest_unused_requirement_id(used: Any) -> str | None:
    """The id a new requirement row takes: `RQ-<n>` for the smallest n from 1 to
    `REQUIREMENT_NUMBER_LIMIT` that no id in `used` holds, compared by number so
    a number held under another spelling (RQ-01) is taken; or None when every
    number in that range is held. Never an id the capsule's schema refuses.

    The onboarding page applies the same rule to its rows (A-048); this is the
    rule as the domain states it, and the refusal of an out-of-range id names
    the number it gives."""
    taken: set[int] = set()
    for ident in used or ():
        held = _REQUIREMENT_NUMBER.fullmatch(ident) if isinstance(ident, str) else None
        if held is not None:
            taken.add(int(held.group(1)))
    for number in range(1, REQUIREMENT_NUMBER_LIMIT + 1):
        if number not in taken:
            return f"RQ-{number}"
    return None


def _normalised(text: str) -> str:
    return " ".join(text.split()).casefold()


def _schema_row_refusal(value: list[Any]) -> EntryRefusal | None:
    """The capsule's schema, so a refusal names the row it is about, in the
    schema's own words. The schema refuses a prefix of the rows exactly when the
    prefix holds the faulty row, so the shortest refused prefix ends at it; it
    is found by bisection, about n log n rows checked for n rows, where trying
    every prefix checked n(n+1)/2 -- and a request sets the n."""
    validate = AUTHORITATIVE_FIELDS["requirements"]
    try:
        validate(value)
        return None
    except CapsuleValidationError:
        pass
    low, high = 1, len(value)
    while low < high:
        middle = (low + high) // 2
        try:
            validate(value[:middle])
            low = middle + 1
        except CapsuleValidationError:
            high = middle
    index = high
    try:
        validate(value[:index])
    except CapsuleValidationError as error:
        reason = str(error)
        row = value[index - 1]
        ident = row.get("id") if isinstance(row, dict) else None
        usable = (isinstance(ident, str) and ident in reason
                  and "must match RQ-" not in reason)
        named = ident if usable else f"row {index}"
        who = f"Requirement {named}" if named == ident else f"Requirement row {index}"
        if "exactly {id, text}" in reason:
            explanation = f"{who} could not be read: each row needs exactly an id and a text."
        elif "must match RQ-" in reason:
            free = smallest_unused_requirement_id(
                [row.get("id") for row in value if isinstance(row, dict)])
            shown = (repr(ident) if not isinstance(ident, str) or len(ident) <= 24
                     else f"'{ident[:12]}...' ({len(ident)} characters)")
            explanation = (f"{who} is numbered {shown}, outside the numbers a requirement"
                           f" can have (RQ-1 to RQ-{REQUIREMENT_NUMBER_LIMIT}). "
                           + (f"Number it {free}, the smallest number not in use."
                              if free is not None else
                              "Every number is in use; remove a requirement first."))
        elif "is duplicated" in reason:
            explanation = (f"Two rows have the same number, {ident}. Give each row its"
                           " own number.")
        elif "must not be empty" in reason:
            explanation = (f"{who} is empty. Write what the application must do, or"
                           " remove the row.")
        else:
            explanation = _schema_explanation(
                reason, who, 2000, row.get("text") if isinstance(row, dict) else None)
        return EntryRefusal("requirements", explanation, reason, named)
    return None


def _requirements_refusal(value: Any) -> EntryRefusal | None:
    if not isinstance(value, list):
        try:
            AUTHORITATIVE_FIELDS["requirements"](value)
        except CapsuleValidationError as error:
            return EntryRefusal(
                "requirements",
                "The requirements could not be read as a list of rows. Enter each"
                " requirement in its own row.", str(error))
        return None
    schema = _schema_row_refusal(value)
    if schema is not None:
        return schema
    seen: dict[str, str] = {}
    for row in value:
        key = _normalised(row["text"])
        if key in seen:
            return EntryRefusal(
                "requirements",
                f"Requirement {row['id']} says the same as requirement {seen[key]}."
                " Remove one of them, or change one so each says something different.",
                f"requirement {row['id']} repeats requirement {seen[key]}: one statement"
                " twice would be built and tested as two requirements",
                row["id"])
        seen[key] = row["id"]
    for row in value:
        grammar = _derivation_refusal(_PROBE_INTENT, [row])
        fault = _text_fault(row["text"], f"Requirement {row['id']}", grammar)
        if fault is not None:
            if "more than one line" in fault:
                fault += " If it says two things, split it into two rows."
            reason = grammar or (
                f"requirement {row['id']} holds a line boundary str.splitlines honours,"
                " so a reader of the derived BRD would read it as more than one line")
            return EntryRefusal("requirements", fault, reason, row["id"])
    # The rows one by one are not the rows together: the derivation also reads
    # the whole rendering back under the requirement-identity rule.
    together = _derivation_refusal(_PROBE_INTENT, list(value))
    if together is not None:
        return EntryRefusal(
            "requirements",
            "These requirements cannot be written into the requirements document"
            " together. Check that each row is one plain sentence.", together)
    return None


def proposal_entry_refusal(field: str, value: Any) -> EntryRefusal | None:
    """Why a proposed `intent` or `requirements` value would be refused --
    by the capsule's field schema now, or by the BRD derivation once it was
    confirmed -- or None. Every other field returns None: its rules are the
    capsule's, unchanged."""
    if field == "intent":
        return _intent_refusal(value)
    if field == "requirements":
        return _requirements_refusal(value)
    return None
