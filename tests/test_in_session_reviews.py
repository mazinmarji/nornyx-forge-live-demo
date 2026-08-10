import json
from pathlib import Path

from nornyx_forge.development_flow import DevelopmentFlow

REQUIRED_REVIEWS = [
    {"role": "test-inspector", "status": "pass", "findings": []},
    {"role": "architecture-inspector", "status": "pass", "findings": []},
    {"role": "security-inspector", "status": "pass", "findings": []},
]


def _write_review(root: Path, reviews: list[dict[str, object]]) -> None:
    target = root / ".nornyx/in-session/reviews.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.in_session_reviews.v1",
                "human_review": "not_performed",
                "builder_self_approval": False,
                "reviews": reviews,
            }
        ),
        encoding="utf-8",
    )


def test_in_session_review_artifact_is_accepted(tmp_path: Path, monkeypatch) -> None:
    _write_review(tmp_path, REQUIRED_REVIEWS)
    flow = DevelopmentFlow(tmp_path, worker_mode="in-session")
    monkeypatch.setattr("nornyx_forge.development_flow.default_gates", lambda _root: [])
    flow.data["foundation"] = {"verdict": "GO", "overall_score": 90}
    result = flow.acceptance()
    assert result["accepted"] is True
    # Completeness, which this artifact can establish, reported as a count.
    assert result["assurance"]["review_workers_executed"] == len(REQUIRED_REVIEWS)
    # Independence, which it cannot establish, reported as unestablished. It
    # previously read `True` here, derived from the list being non-empty — so
    # running three reviewers was indistinguishable from three reviewers
    # agreeing, and neither was independent of the builder that ran them.
    assert result["assurance"]["independent_ai_review"] == "not_established"


def test_in_session_review_artifact_fails_closed(tmp_path: Path, monkeypatch) -> None:
    _write_review(tmp_path, REQUIRED_REVIEWS[:1])
    flow = DevelopmentFlow(tmp_path, worker_mode="in-session")
    monkeypatch.setattr("nornyx_forge.development_flow.default_gates", lambda _root: [])
    result = flow.acceptance()
    assert result["accepted"] is False


def test_a_self_certified_artifact_cannot_claim_independence(
    tmp_path: Path, monkeypatch
) -> None:
    """The file may say whatever it likes about its own provenance.

    `builder_self_approval: false` used to be a term in the acceptance
    expression: the builder certifying their own independence, in a gitignored
    file the builder writes. The same defect was removed from the evidence tool
    while this copy went on gating acceptance.

    Asserted in the exploitable direction. The artifact here claims the *worst*
    case — that the builder did approve their own work — and acceptance is
    unchanged, because nothing the file says about how it was produced is read.
    """
    target = tmp_path / ".nornyx/in-session/reviews.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.in_session_reviews.v1",
                "human_review": "not_performed",
                "builder_self_approval": True,
                "reviews": REQUIRED_REVIEWS,
            }
        ),
        encoding="utf-8",
    )
    flow = DevelopmentFlow(tmp_path, worker_mode="in-session")
    monkeypatch.setattr("nornyx_forge.development_flow.default_gates", lambda _root: [])
    flow.data["foundation"] = {"verdict": "GO", "overall_score": 90}
    result = flow.acceptance()

    assert result["accepted"] is True, (
        "a field the artifact asserts about itself still changes acceptance"
    )
    assert result["assurance"]["independent_ai_review"] == "not_established"
