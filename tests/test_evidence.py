from pathlib import Path

from nornyx_forge.evidence import EvidenceLedger


def test_evidence_is_append_only_and_valid(tmp_path: Path):
    ledger = EvidenceLedger(tmp_path / "events.jsonl", subject_revision="git:test")
    ledger.append("started", mission_id="M1", actor="agent.test")
    ledger.append("completed", mission_id="M1", actor="agent.test", decision="ALLOW")
    report = ledger.validate()
    assert report["status"] == "pass"
    assert report["event_count"] == 2
    assert report["human_review"] == "not_performed"
