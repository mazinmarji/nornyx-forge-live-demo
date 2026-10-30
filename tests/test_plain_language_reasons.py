"""Refusals and failures carry a plain-language summary and the failing
check's name, above the verbatim reason, rendered from the same data.

WHAT WOULD FALSIFY IT: an eligibility refusal shown to a basic user with no
plain summary, or with its verbatim reason altered; a build failure whose
journey view does not name, in plain terms, which check stopped it; or the
plain classifier drifting from the failure text Forge actually writes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from session_client import authed_client

from nornyx_forge import experience_journey as journey
from nornyx_forge.brd_authoring import brd_from_capsule
from nornyx_forge.capsule import Actor, confirm, create_document, propose
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.experience import EvidenceRef, ExperienceError, advance, start_experience
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.plain_reasons import (
    ELIGIBILITY_CHECK,
    build_failure_headline,
    eligibility_summary,
)
from nornyx_forge.provider_contract import GovernedEligibility

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
T0 = "2026-08-30T12:00:00Z"
T1 = "2026-08-30T12:01:00Z"
T2 = "2026-08-30T12:02:00Z"
T3 = "2026-08-30T12:03:00Z"
T4 = "2026-08-30T12:04:00Z"
T5 = "2026-08-30T12:05:00Z"


# -- unit: eligibility_summary ------------------------------------------------

def test_eligibility_summary_is_plain_and_does_not_leak_the_verbatim_reason():
    verdict = {
        "provider": "claude", "platform": "windows", "eligible": False,
        "confinement": "none",
        "reason": ("claude is not eligible on windows: commit 1a2b3c4 ... see "
                   "CLAUDE_CONFINEMENT_MEASUREMENT.md; no other provider is tried"),
    }
    summary = eligibility_summary(verdict)
    assert "claude" in summary and "windows" in summary
    assert ELIGIBILITY_CHECK in summary
    assert "1a2b3c4" not in summary and "CLAUDE_CONFINEMENT_MEASUREMENT" not in summary
    assert summary != verdict["reason"]


def test_eligibility_summary_has_safe_defaults_for_missing_fields():
    summary = eligibility_summary({})
    assert "the chosen" in summary and "this platform" in summary


# -- unit: build_failure_headline ---------------------------------------------

def test_no_failure_yields_no_headline():
    assert build_failure_headline(None) == {"summary": None, "check": None}
    assert build_failure_headline("") == {"summary": None, "check": None}


def test_headline_names_the_check_for_each_kind():
    assert build_failure_headline(
        "refused: the presented 'flow_run' evidence (x) reports failure; ..."
    )["check"] == "test results (flow_run)"
    assert build_failure_headline(
        "refused: advancing into GOVERN requires evidence of kind 'gate_results', which was not presented"
    )["check"] == "governance gates (gate_results)"
    assert build_failure_headline("the build did not complete: boom")["check"] == "the build run"
    assert build_failure_headline(
        "the build produced no usable evidence: bad"
    )["check"] == "the build's evidence"
    assert build_failure_headline("refused: something unexpected")["check"] == "the build's governance checks"
    assert build_failure_headline("a shape nobody wrote")["check"] == "the build"
    for detail in ["x flow_run x", "x gate_results x", "the build did not complete: y",
                   "the build produced no usable evidence: y", "refused: z", "weird"]:
        assert build_failure_headline(detail)["summary"], detail


# -- pin: the classifier keys on the text Forge actually writes ---------------

def _state_at_build():
    s = start_experience(Actor("human", "casey"), T0)
    binding = EvidenceRef(kind="brd_requirements", ref="brd-ref-1", passed=True)
    s = advance(s, "CONFIRM", Actor("human", "casey"), T1, (binding,))
    s = advance(s, "BUILD", Actor("human", "casey"), T2, ())
    return s


def test_the_flow_run_refusal_forge_writes_classifies_to_the_test_check():
    s = _state_at_build()
    try:
        advance(s, "TEST", journey.SYSTEM_ACTOR, T3, (EvidenceRef("flow_run", "flow-ref-1", False),))
    except ExperienceError as error:
        detail = f"refused: {error}"
    else:
        raise AssertionError("a failing flow_run must refuse the advance into TEST")
    assert "flow_run" in detail
    assert build_failure_headline(detail)["check"] == "test results (flow_run)"


def test_the_gate_results_refusal_forge_writes_classifies_to_the_gate_check():
    s = _state_at_build()
    s = advance(s, "TEST", journey.SYSTEM_ACTOR, T3, (EvidenceRef("flow_run", "flow-ref-1", True),))
    try:
        advance(s, "GOVERN", journey.SYSTEM_ACTOR, T4, ())
    except ExperienceError as error:
        detail = f"refused: {error}"
    else:
        raise AssertionError("GOVERN without gate_results must refuse")
    assert "gate_results" in detail
    assert build_failure_headline(detail)["check"] == "governance gates (gate_results)"


def test_build_error_detail_classifies_to_the_build_run():
    failed = journey.build_error(_state_at_build(), "the worker process exploded", T3)
    detail = failed["history"][-1]["detail"]
    assert detail.startswith("the build did not complete")
    assert build_failure_headline(detail)["check"] == "the build run"


# -- integration: the basic-user surfaces carry the plain line ----------------

def _intent_document():
    document = create_document("proj-1", "Test Project", Actor("human", "casey"), T0)
    document, intent_id = propose(document, "intent", "Build a portal.", Actor("model", "m"), T1)
    document = confirm(document, intent_id, Actor("human", "casey"), T2)
    return document


def _brd_and_binding(document):
    rendered = brd_from_capsule(document)
    brd = journey.BrdState.matching(hashlib.sha256(rendered.encode("utf-8")).hexdigest())
    binding = EvidenceRef(kind="brd_requirements", ref=journey.scope_ref(document, brd), passed=True)
    return rendered, brd, binding


def _confirmed_project(tmp_path: Path) -> Path:
    document = _intent_document()
    document, provider_id = propose(document, "provider", {"name": "codex"}, Actor("human", "casey"), T3)
    document = confirm(document, provider_id, Actor("human", "casey"), T4)
    rendered, _brd, binding = _brd_and_binding(document)
    lifecycle = start_experience(Actor("human", "casey"), T0)
    lifecycle = advance(lifecycle, "CONFIRM", Actor("human", "casey"), T5, (binding,))
    CapsuleStore(tmp_path / "capsule").initialize(document, experience=lifecycle)
    (tmp_path / "BRD.md").write_text(rendered, encoding="utf-8", newline="")
    return tmp_path


def _ineligible(provider: str, platform: str) -> GovernedEligibility:
    return GovernedEligibility(
        provider=provider, platform=platform, eligible=False, confinement="none",
        reason=(f"{provider} is not eligible on {platform}: see commit 1a2b3c4 and "
                "CLAUDE_CONFINEMENT_MEASUREMENT.md; no other provider is tried"))


def test_build_refusal_adds_a_plain_explanation_and_keeps_the_verbatim_reason(tmp_path: Path):
    _confirmed_project(tmp_path)
    client = authed_client(create_app(tmp_path / "capsule", CONTRACTS,
                                      seal_dir=tmp_path / "seals", eligibility=_ineligible))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    body = response.json()
    verbatim = _ineligible("codex", body["eligibility"]["platform"]).reason
    assert body["refused"] == verbatim
    assert body["explanation"] and body["explanation"] != body["refused"]
    assert ELIGIBILITY_CHECK in body["explanation"]
    assert "1a2b3c4" not in body["explanation"]


def test_a_failed_builds_journey_names_the_check_in_plain_terms():
    document = _intent_document()
    _rendered, brd, binding = _brd_and_binding(document)
    s = start_experience(Actor("human", "casey"), T0)
    s = advance(s, "CONFIRM", Actor("human", "casey"), T3, (binding,))
    s = advance(s, "BUILD", Actor("human", "casey"), T4, ())
    failed = journey.build_error(s, "the worker process exploded", T5)
    view = journey.journey_view(failed, document, brd, build_running=False)
    assert view["status"] == "failed"
    assert view["failure_check"] == "the build run"
    assert view["failure_summary"]
    assert "the build did not complete" in view["failure"]


def test_every_journey_shape_carries_the_failure_fields():
    document = _intent_document()
    _rendered, brd, binding = _brd_and_binding(document)
    s = start_experience(Actor("human", "casey"), T0)
    s = advance(s, "CONFIRM", Actor("human", "casey"), T3, (binding,))
    view = journey.journey_view(s, document, brd, build_running=False)
    assert view["status"] != "failed"
    assert view["failure"] is None
    assert view["failure_summary"] is None and view["failure_check"] is None
