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
    assert result["assurance"]["independent_ai_review"] is True


def test_in_session_review_artifact_fails_closed(tmp_path: Path, monkeypatch) -> None:
    _write_review(tmp_path, REQUIRED_REVIEWS[:1])
    flow = DevelopmentFlow(tmp_path, worker_mode="in-session")
    monkeypatch.setattr("nornyx_forge.development_flow.default_gates", lambda _root: [])
    result = flow.acceptance()
    assert result["accepted"] is False
