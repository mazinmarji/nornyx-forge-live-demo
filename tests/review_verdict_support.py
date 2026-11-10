"""Recorded reviewer outputs that carry a review verdict, for stub workers.

A review gate passes only on a valid PASS verdict (`nornyx_forge.review_verdict`),
so a stub worker standing in for a reviewer at the flow's worker seam must end
its reply with one, in the envelope the Claude adapter records. These helpers
build that output; they decide nothing about what a gate does with it.
"""

from __future__ import annotations

import json
from typing import Any

from nornyx_forge.review_verdict import REVIEW_VERDICT_SCHEMA

#: The three review workers the flow runs after its gates pass, in order.
REVIEW_ROLES = ("test-inspector", "architecture-inspector", "security-inspector")


def verdict_object(role: str, verdict: str = "PASS", findings: tuple[str, ...] = (),
                   evidence: tuple[str, ...] = ("stub reviewer at the test seam",)) -> dict[str, Any]:
    return {"schema": REVIEW_VERDICT_SCHEMA, "role": role, "verdict": verdict,
            "blocking_findings": list(findings), "evidence_relied_on": list(evidence)}


def envelope(result_text: str, **fields: Any) -> str:
    """The Claude adapter's recorded output: one JSON envelope."""
    return json.dumps({"type": "result", "subtype": "success", "is_error": False,
                       "result": result_text, **fields})


def review_output(role: str, verdict: str = "PASS", findings: tuple[str, ...] = (),
                  prefix: str = "") -> str:
    """A reviewer's recorded output ending with one verdict object."""
    return envelope(prefix + json.dumps(verdict_object(role, verdict, findings)))


def _with(expected_role: str, /, **changes: Any) -> dict[str, Any]:
    value = verdict_object(expected_role)
    value.update(changes)
    return value


def _without(role: str, key: str) -> dict[str, Any]:
    value = verdict_object(role)
    del value[key]
    return value


def _codex_stream(*events: dict[str, Any]) -> str:
    return "\n".join(json.dumps(event) for event in events)


#: Every recorded output a reviewer of `role` might return that must read as
#: INVALID, keyed by case. Each builder takes the expected role; the second
#: element is a fragment of the reason the parser must give.
INVALID_CASES: dict[str, tuple[Any, str]] = {
    "no verdict object": (
        lambda role: envelope("Review complete. No blocking issues were found."),
        "no verdict object"),
    "two identical verdict objects": (
        lambda role: envelope(json.dumps(verdict_object(role)) + "\n"
                              + json.dumps(verdict_object(role))),
        "2 verdict objects"),
    "two conflicting verdict objects": (
        lambda role: envelope(json.dumps(verdict_object(role, "FAIL", ("a defect",))) + "\n"
                              + json.dumps(verdict_object(role))),
        "2 verdict objects"),
    "malformed verdict JSON": (
        lambda role: envelope('{"schema": "' + REVIEW_VERDICT_SCHEMA + '", "role": "'
                              + role + '", "verdict": "PASS", "blocking_findings": ['),
        "malformed"),
    "schema named outside the object": (
        lambda role: envelope("I return a " + REVIEW_VERDICT_SCHEMA + " object below.\n"
                              + json.dumps(verdict_object(role))),
        "outside the one decodable verdict object"),
    "unknown key": (
        lambda role: envelope(json.dumps(_with(role, notes="extra"))),
        "unknown keys"),
    "missing key": (
        lambda role: envelope(json.dumps(_without(role, "evidence_relied_on"))),
        "missing keys"),
    "duplicate key": (
        lambda role: envelope('{"schema": "' + REVIEW_VERDICT_SCHEMA + '", "role": "' + role
                              + '", "verdict": "FAIL", "verdict": "PASS", '
                              '"blocking_findings": [], "evidence_relied_on": []}'),
        "malformed"),
    "findings not a list": (
        lambda role: envelope(json.dumps(_with(role, blocking_findings="none"))),
        "blocking_findings"),
    "empty finding text": (
        lambda role: envelope(json.dumps(_with(role, verdict="FAIL", blocking_findings=[" "]))),
        "blocking_findings"),
    "evidence not text": (
        lambda role: envelope(json.dumps(_with(role, evidence_relied_on=[1]))),
        "evidence_relied_on"),
    "verdict not text": (
        lambda role: envelope(json.dumps(_with(role, verdict=True))),
        "verdict is not text"),
    "unknown verdict": (
        lambda role: envelope(json.dumps(_with(role, verdict="APPROVED"))),
        "is not one of"),
    "verdict in another case": (
        lambda role: envelope(json.dumps(_with(role, verdict="pass"))),
        "is not one of"),
    "another role": (
        lambda role: envelope(json.dumps(_with(role, role="another-inspector"))),
        "is for role"),
    "role not text": (
        lambda role: envelope(json.dumps(_with(role, role=None))),
        "role is not text"),
    "PASS with blocking findings": (
        lambda role: envelope(json.dumps(_with(role, blocking_findings=["a defect"]))),
        "PASS verdict lists blocking findings"),
    "undecodable envelope": (
        lambda role: "not a worker envelope { " + json.dumps(verdict_object(role)),
        "not a decodable worker envelope"),
    "envelope reports an error": (
        lambda role: envelope(json.dumps(verdict_object(role)), is_error=True),
        "reports an error"),
    "envelope without result text": (
        lambda role: json.dumps({"type": "result", "subtype": "success", "is_error": False}),
        "no result text"),
    "envelope result not text": (
        lambda role: json.dumps({"type": "result", "is_error": False,
                                 "result": verdict_object(role)}),
        "result is not text"),
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
                  "text": json.dumps(verdict_object(role, verdict, findings))}},
        {"type": "turn.completed"},
    )
