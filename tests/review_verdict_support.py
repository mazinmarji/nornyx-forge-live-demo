"""Recorded reviewer outputs that carry a review verdict, for stub workers.

A review gate passes only on a valid PASS verdict (`nornyx_forge.review_verdict`),
so a stub worker standing in for a reviewer at the flow's worker seam must end
its reply with the verdict marker line and one verdict object, in the envelope
the Claude adapter records. These helpers build that output; they decide
nothing about what a gate does with it.
"""

from __future__ import annotations

import json
from typing import Any

from nornyx_forge.review_verdict import REVIEW_VERDICT_SCHEMA, VERDICT_MARKER

#: The three review workers the flow runs after its gates pass, in order.
REVIEW_ROLES = ("test-inspector", "architecture-inspector", "security-inspector")


def verdict_object(role: str, verdict: str = "PASS", findings: tuple[str, ...] = (),
                   evidence: tuple[str, ...] = ("stub reviewer at the test seam",)) -> dict[str, Any]:
    return {"schema": REVIEW_VERDICT_SCHEMA, "role": role, "verdict": verdict,
            "blocking_findings": list(findings), "evidence_relied_on": list(evidence)}


def marked(verdict_text: str, before: str = "") -> str:
    """A reply: `before`, then the marker line, then `verdict_text`."""
    return before + ("\n" if before and not before.endswith("\n") else "") + (
        VERDICT_MARKER + "\n" + verdict_text)


def envelope(result_text: str, **fields: Any) -> str:
    """The Claude adapter's recorded output: one JSON envelope."""
    return json.dumps({"type": "result", "subtype": "success", "is_error": False,
                       "result": result_text, **fields})


def review_output(role: str, verdict: str = "PASS", findings: tuple[str, ...] = (),
                  prefix: str = "") -> str:
    """A reviewer's recorded output ending with the marker and one verdict."""
    return envelope(marked(json.dumps(verdict_object(role, verdict, findings)), prefix))


def _with(expected_role: str, /, **changes: Any) -> dict[str, Any]:
    value = verdict_object(expected_role)
    value.update(changes)
    return value


def _without(role: str, key: str) -> dict[str, Any]:
    value = verdict_object(role)
    del value[key]
    return value


def _escaped_duplicate(role: str) -> str:
    """A verdict object whose schema is spelled with a JSON escape and whose
    `verdict` key is repeated: FAIL, then PASS, which `json` would keep."""
    return ('{"schema": "\\u006e' + REVIEW_VERDICT_SCHEMA[1:] + '", "role": "' + role
            + '", "verdict": "FAIL", "verdict": "PASS", "blocking_findings": [], '
            '"evidence_relied_on": []}')


def _escaped(role: str, escape: str) -> str:
    """A valid verdict object whose schema's first letter is spelled `escape`."""
    return json.dumps(verdict_object(role)).replace(
        REVIEW_VERDICT_SCHEMA, escape + REVIEW_VERDICT_SCHEMA[1:])


def _ok(role: str) -> str:
    return json.dumps(verdict_object(role))


def _codex_stream(*events: dict[str, Any]) -> str:
    return "\n".join(json.dumps(event) for event in events)


#: Reasons the parser gives, as fragments the cases below expect.
NO_MARKER = "no verdict marker line"
AFTER = "not exactly one verdict object"
BEFORE = "appears before the verdict marker"

#: Every recorded output a reviewer of `role` might return that must read as
#: INVALID, keyed by case. Each builder takes the expected role; the second
#: element is a fragment of the reason the parser must give.
INVALID_CASES: dict[str, tuple[Any, str]] = {
    # The marker line.
    "no verdict marker": (
        lambda role: envelope("Review complete. No blocking issues were found."),
        NO_MARKER),
    "a verdict object without the marker": (
        lambda role: envelope(_ok(role)),
        NO_MARKER),
    "marker not on a line of its own": (
        lambda role: envelope("Verdict: " + marked(_ok(role)).replace("\n", " ", 1)),
        "not on a line of its own"),
    "two marker lines": (
        lambda role: envelope(marked(_ok(role), marked(_ok(role)))),
        "more than once"),
    "marker named again in the text": (
        lambda role: envelope(marked(json.dumps(_with(
            role, evidence_relied_on=["the " + "NORNYX-REVIEW-VERDICT" + " line"])))),
        "more than once"),
    # What follows the marker.
    "marker with nothing after it": (
        lambda role: envelope(marked("")),
        AFTER),
    "two identical verdict objects after the marker": (
        lambda role: envelope(marked(_ok(role) + "\n" + _ok(role))),
        AFTER),
    "two conflicting verdict objects after the marker": (
        lambda role: envelope(marked(json.dumps(verdict_object(role, "FAIL", ("a defect",)))
                                     + "\n" + _ok(role))),
        AFTER),
    "malformed verdict JSON": (
        lambda role: envelope(marked('{"schema": "' + REVIEW_VERDICT_SCHEMA + '", "role": "'
                                     + role + '", "verdict": "PASS", "blocking_findings": [')),
        AFTER),
    "PASS nested inside another object": (
        lambda role: envelope(marked('{"verdict": "FAIL", "blocking_findings": ["a defect"], '
                                     '"example": ' + _ok(role) + "}")),
        "unknown keys"),
    "PASS inside an unfinished object after the marker": (
        lambda role: envelope(marked('{"verdict": "FAIL", "note": "}", "example": ' + _ok(role))),
        AFTER),
    "PASS inside an unfinished array after the marker": (
        lambda role: envelope(marked('[ "]", ' + _ok(role))),
        AFTER),
    "text after the verdict": (
        lambda role: envelope(marked(_ok(role) + "\nFinal conclusion: NOT_VERIFIED")),
        AFTER),
    "text after the closing fence": (
        lambda role: envelope(marked("```json\n" + _ok(role) + "\n```\nOn reflection, FAIL.")),
        AFTER),
    "a closing fence with no opening fence": (
        lambda role: envelope(marked(_ok(role) + "\n```")),
        AFTER),
    "an unclosed fence": (
        lambda role: envelope(marked("```json\n" + _ok(role))),
        AFTER),
    "a fence of another language": (
        lambda role: envelope(marked("```python\n" + _ok(role) + "\n```")),
        AFTER),
    "escaped schema in a malformed final object": (
        lambda role: envelope(marked(_escaped_duplicate(role))),
        "malformed"),
    "duplicate key": (
        lambda role: envelope(marked('{"schema": "' + REVIEW_VERDICT_SCHEMA + '", "role": "' + role
                                     + '", "verdict": "FAIL", "verdict": "PASS", '
                                     '"blocking_findings": [], "evidence_relied_on": []}')),
        "malformed"),
    # What comes before the marker.
    "an earlier verdict before the marker": (
        lambda role: envelope(marked(_ok(role), _ok(role))),
        BEFORE),
    "schema named before the marker": (
        lambda role: envelope(marked(_ok(role), "I return a " + REVIEW_VERDICT_SCHEMA + " object.")),
        BEFORE),
    "escaped schema in a malformed object before the marker": (
        lambda role: envelope(marked(_ok(role), _escaped_duplicate(role))),
        BEFORE),
    "escaped schema in another valid object before the marker": (
        lambda role: envelope(marked(_ok(role), _escaped(role, "\\u006e"))),
        BEFORE),
    "escaped schema after a stray quote before the marker": (
        lambda role: envelope(marked(_ok(role), 'A stray " before ' + _escaped_duplicate(role))),
        BEFORE),
    "doubly escaped schema before the marker": (
        lambda role: envelope(marked(_ok(role), _escaped(role, "\\\\u005cu006e"))),
        BEFORE),
    # The object itself.
    "unknown key": (
        lambda role: envelope(marked(json.dumps(_with(role, notes="extra")))),
        "unknown keys"),
    "missing key": (
        lambda role: envelope(marked(json.dumps(_without(role, "evidence_relied_on")))),
        "missing keys"),
    "findings not a list": (
        lambda role: envelope(marked(json.dumps(_with(role, blocking_findings="none")))),
        "blocking_findings"),
    "empty finding text": (
        lambda role: envelope(marked(json.dumps(_with(role, verdict="FAIL", blocking_findings=[" "])))),
        "blocking_findings"),
    "evidence not text": (
        lambda role: envelope(marked(json.dumps(_with(role, evidence_relied_on=[1])))),
        "evidence_relied_on"),
    "verdict not text": (
        lambda role: envelope(marked(json.dumps(_with(role, verdict=True)))),
        "verdict is not text"),
    "unknown verdict": (
        lambda role: envelope(marked(json.dumps(_with(role, verdict="APPROVED")))),
        "is not one of"),
    "verdict in another case": (
        lambda role: envelope(marked(json.dumps(_with(role, verdict="pass")))),
        "is not one of"),
    "another role": (
        lambda role: envelope(marked(json.dumps(_with(role, role="another-inspector")))),
        "is for role"),
    "role not text": (
        lambda role: envelope(marked(json.dumps(_with(role, role=None)))),
        "role is not text"),
    "PASS with blocking findings": (
        lambda role: envelope(marked(json.dumps(_with(role, blocking_findings=["a defect"])))),
        "PASS verdict lists blocking findings"),
    # The envelope and the event stream.
    "undecodable envelope": (
        lambda role: "not a worker envelope { " + marked(_ok(role)),
        "not a decodable worker envelope"),
    "envelope reports an error": (
        lambda role: envelope(marked(_ok(role)), is_error=True),
        "reports an error"),
    "envelope without result text": (
        lambda role: json.dumps({"type": "result", "subtype": "success", "is_error": False}),
        "no result text"),
    "envelope result not text": (
        lambda role: json.dumps({"type": "result", "is_error": False,
                                 "result": verdict_object(role)}),
        "result is not text"),
    "envelope reports another subtype": (
        lambda role: envelope(marked(_ok(role)), subtype="error_max_turns"),
        "did not succeed"),
    "envelope of another type": (
        lambda role: envelope(marked(_ok(role)), type="assistant"),
        "not a result"),
    "event stream reporting a failed turn": (
        lambda role: codex_review_output(role)[: codex_review_output(role).rindex("\n")]
        + "\n" + json.dumps({"type": "turn.failed", "error": {"message": "stopped"}}),
        "reports an error"),
    "empty output": (
        lambda role: "",
        "empty"),
    "event stream without an agent message": (
        lambda role: _codex_stream({"type": "thread.started", "thread_id": "t-1"},
                                   {"type": "turn.completed"}),
        "no completed agent message"),
}


def codex_review_output(role: str, verdict: str = "PASS",
                        findings: tuple[str, ...] = ()) -> str:
    """A reviewer's output as the Codex adapter records it: JSON events."""
    return _codex_stream(
        {"type": "thread.started", "thread_id": "t-1"},
        {"type": "item.completed",
         "item": {"id": "i-1", "type": "agent_message", "text": "draft"}},
        {"type": "item.completed",
         "item": {"id": "i-2", "type": "agent_message",
                  "text": marked(json.dumps(verdict_object(role, verdict, findings)))}},
        {"type": "turn.completed"},
    )
