"""The review-worker verdict contract and its fail-closed parser.

A review gate used to pass when the reviewer's process finished, whatever the
reviewer concluded. `nornyx_forge.review_verdict` gives reviewers one exact
object to end with and reads it closed: only a valid PASS passes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from review_verdict_support import (
    INVALID_CASES,
    REVIEW_ROLES,
    codex_review_output,
    envelope,
    review_output,
    verdict_object,
)

from nornyx_forge.review_verdict import (
    MAX_RESULT_TEXT,
    PARSED_VERDICTS,
    REVIEW_VERDICT_SCHEMA,
    VERDICT_KEYS,
    VERDICTS,
    ParsedVerdict,
    parse_review,
    reply_text,
    verdict_counts,
    verdict_requirement,
)

#: Three reviewer outputs recorded from one greenfield run that Forge accepted
#: under the old rule, replayed against the verdict gate.
#: Stored as `.json.txt`, as every specimen under tests/specimens/ keeps its
#: native extension plus `.txt`: recorded provider output, not an authored
#: surface, and its bytes are exactly the recorded JSON.
FIXTURE = (Path(__file__).parent / "specimens" / "review_verdicts"
           / "recorded_reviewer_outputs.json.txt")
#: The fixture is evidence and is held to its recorded bytes.
FIXTURE_SHA256 = "99351b283cccdbc7424e23e825b12a5dc36ab72b3084d98eb67acffd8ddc6341"


def _parse(output: str, role: str = "test-inspector", success: bool = True) -> ParsedVerdict:
    return parse_review(output, expected_role=role, worker_success=success)


def test_the_contract_is_closed():
    assert REVIEW_VERDICT_SCHEMA == "nornyx.forge.review_verdict.v1"
    assert VERDICTS == ("PASS", "FAIL", "NOT_VERIFIED")
    assert PARSED_VERDICTS == ("PASS", "FAIL", "NOT_VERIFIED", "INVALID")
    assert VERDICT_KEYS == {"schema", "role", "verdict", "blocking_findings", "evidence_relied_on"}


@pytest.mark.parametrize("role", REVIEW_ROLES)
def test_a_valid_pass_is_the_only_passing_result(role):
    parsed = _parse(review_output(role), role)
    assert parsed.verdict == "PASS" and parsed.passed is True
    assert parsed.blocking_findings == () and parsed.role == role


def test_a_pass_inside_surrounding_review_text_is_read():
    text = "Checked every module.\n```json\n" + json.dumps(verdict_object("test-inspector")) + "\n```"
    assert _parse(envelope(text)).verdict == "PASS"


def test_only_whitespace_and_one_closing_fence_may_follow_the_verdict():
    body = json.dumps(verdict_object("test-inspector"))
    for text in (body + "\n\n  ", "```json\n" + body + "\n```", "```\n" + body + "\n```\n\n"):
        assert _parse(envelope(text)).verdict == "PASS", text
    for text in (body + "\n```\n```", body + " ok", body + "\n```json"):
        assert _parse(envelope(text)).verdict == "INVALID", text


def test_a_fail_carries_its_findings_and_does_not_pass():
    parsed = _parse(review_output("test-inspector", "FAIL", ("no test covers BRD-F-002",)))
    assert parsed.verdict == "FAIL" and parsed.passed is False
    assert parsed.blocking_findings == ("no test covers BRD-F-002",)


@pytest.mark.parametrize("findings", [(), ("the suite was not run",)])
def test_not_verified_is_a_verdict_and_does_not_pass(findings):
    parsed = _parse(review_output("test-inspector", "NOT_VERIFIED", findings))
    assert parsed.verdict == "NOT_VERIFIED" and parsed.passed is False


@pytest.mark.parametrize("case", sorted(INVALID_CASES))
def test_each_malformed_output_is_invalid_with_its_reason(case):
    build, fragment = INVALID_CASES[case]
    parsed = _parse(build("test-inspector"))
    assert parsed.verdict == "INVALID", (case, parsed)
    assert parsed.passed is False
    assert fragment in parsed.reason, (case, parsed.reason)


def test_a_worker_that_did_not_succeed_is_invalid_even_with_a_pass_text():
    parsed = _parse(review_output("test-inspector"), success=False)
    assert parsed.verdict == "INVALID" and "did not succeed" in parsed.reason


@pytest.mark.parametrize("output", [None, 7, b"bytes", ["list"]])
def test_output_that_is_not_text_is_invalid(output):
    assert _parse(output).verdict == "INVALID"


def test_a_reply_beyond_the_bound_is_invalid():
    text = "x" * (MAX_RESULT_TEXT + 1) + json.dumps(verdict_object("test-inspector"))
    parsed = _parse(envelope(text))
    assert parsed.verdict == "INVALID" and "exceeds" in parsed.reason


def test_the_codex_event_stream_is_read_from_its_last_agent_message():
    assert _parse(codex_review_output("test-inspector")).verdict == "PASS"
    assert _parse(codex_review_output("test-inspector", "FAIL", ("a defect",))).verdict == "FAIL"
    text, how = reply_text(codex_review_output("test-inspector"))
    assert how == "worker JSON event stream"
    assert json.loads(text)["role"] == "test-inspector"


def test_the_record_cannot_be_read_back_as_a_verdict():
    record = _parse(review_output("test-inspector")).as_dict()
    assert "schema" not in record
    assert _parse(envelope(json.dumps(record))).verdict == "INVALID"


def test_verdict_counts_name_every_kind():
    parsed = [_parse(review_output("test-inspector")),
              _parse(review_output("test-inspector", "FAIL", ("f",))),
              _parse(envelope("no verdict"))]
    assert verdict_counts(parsed) == {"PASS": 1, "FAIL": 1, "NOT_VERIFIED": 0, "INVALID": 1}
    assert verdict_counts([]) == {"PASS": 0, "FAIL": 0, "NOT_VERIFIED": 0, "INVALID": 0}


@pytest.mark.parametrize("role", REVIEW_ROLES)
def test_the_required_object_is_stated_and_an_echoed_template_never_passes(role):
    requirement = verdict_requirement(role)
    assert REVIEW_VERDICT_SCHEMA in requirement and f'"role": "{role}"' in requirement
    assert "treated as a failure" in requirement
    assert "anything other than a valid PASS rejects the build" in requirement
    echoed = _parse(envelope(requirement), role)
    assert echoed.verdict == "INVALID", echoed


def test_the_replay_fixture_holds_its_recorded_bytes():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert set(recorded["reviews"]) == set(REVIEW_ROLES)


@pytest.mark.parametrize("role", REVIEW_ROLES)
def test_each_recorded_reviewer_output_from_an_accepted_run_is_rejected(role):
    """These three outputs passed the old review gate because each process
    finished. None ends with a verdict object, so none passes now."""
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))["reviews"][role]
    assert recorded["worker_success"] is True and recorded["returncode"] == 0
    parsed = parse_review(json.dumps(recorded["envelope"]), expected_role=role,
                          worker_success=recorded["worker_success"])
    assert parsed.verdict == "INVALID", parsed
    assert parsed.passed is False
