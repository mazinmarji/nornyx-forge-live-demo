"""What the demo evidence report certifies, and about which stream.

`validate()` used to compute its verdict over `self._events` -- the list one
instance happened to append -- while the report it wrote named a FILE it never
read back. The two are not the same object whenever more than one ledger shares
a path, and `src/demo_app/main.py` builds one per request over one shared
`evidence/runtime/events.jsonl`, with FastAPI running the sync handler in a
threadpool.

Measured on that shape before the repair: three concurrent `run_case` calls each
returned `status: pass, event_count: 6, diagnostics: []`, and the file they
described held twenty-one records in which every sequence number 1..7 appeared
three times.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from nornyx_forge.evidence import EvidenceLedger


def _stream(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_evidence_is_append_only_and_valid(tmp_path: Path):
    ledger = EvidenceLedger(tmp_path / "events.jsonl", subject_revision="git:test")
    ledger.append("started", mission_id="M1", actor="agent.test")
    ledger.append("completed", mission_id="M1", actor="agent.test", decision="ALLOW")
    report = ledger.validate()
    assert report["status"] == "pass"
    assert report["event_count"] == 2
    assert report["human_review"] == "not_performed"


def test_concurrent_ledgers_over_one_file_do_not_reuse_a_sequence(tmp_path: Path):
    """The production shape: one ledger per request, one shared file.

    `sequence = len(self._events) + 1` is only correct when nothing else writes
    to the same path, and something does. The lock that was supposed to make
    this safe was held per INSTANCE, so four writers held four different locks
    and guarded nothing from each other.
    """
    path = tmp_path / "events.jsonl"
    writers, each = 4, 5

    def worker(n: int) -> None:
        ledger = EvidenceLedger(path, subject_revision="git:test")
        for _ in range(each):
            ledger.append("event", mission_id=f"M{n}", actor="agent.test")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    sequences = [record["sequence"] for record in _stream(path)]
    assert len(sequences) == writers * each
    assert sorted(sequences) == list(range(1, writers * each + 1)), (
        "two writers were given the same sequence number, so the only "
        f"continuity control this stream has cannot hold: {sequences}"
    )
    report = EvidenceLedger(path).validate()
    assert report["status"] == "pass", report["diagnostics"]
    assert report["event_count"] == writers * each


def test_the_report_describes_the_file_and_not_the_instance(tmp_path: Path):
    """A ledger that appended two records certifies the stream, not its own list.

    This is the P1 itself, in the smallest form that shows it: the instance
    knows about two events and the file holds four.
    """
    path = tmp_path / "events.jsonl"
    first = EvidenceLedger(path, subject_revision="git:test")
    second = EvidenceLedger(path, subject_revision="git:test")
    first.append("a", mission_id="M", actor="agent.test")
    second.append("b", mission_id="M", actor="agent.test")
    first.append("c", mission_id="M", actor="agent.test")
    second.append("d", mission_id="M", actor="agent.test")

    report = first.validate()
    assert report["event_count"] == 4, (
        "the report counted the events this instance appended, not the ones "
        f"the file it names holds: {report}"
    )
    assert report["status"] == "pass", report["diagnostics"]


def test_removing_the_last_record_is_reported(tmp_path: Path):
    """Truncation is the one tamper a self-consistent chain cannot see.

    Lopping the tail off leaves a shorter chain that links perfectly, so the
    high-water mark is held BESIDE the stream -- the same reasoning as the
    approval ledger's sidecar. Before the repair, dropping the record of a
    released high-risk effect still returned `status: pass`.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for event_type in ("intake", "decided", "high_risk_effect_released"):
        ledger.append(event_type, mission_id="M", actor="agent.test")
    assert ledger.validate()["status"] == "pass"

    kept = path.read_text(encoding="utf-8").splitlines()[:-1]
    path.write_text(chr(10).join(kept) + chr(10), encoding="utf-8", newline="")

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("removed from the end" in item for item in report["diagnostics"]), (
        "the release record was deleted and the report did not say so: "
        f"{report['diagnostics']}"
    )


def test_rewriting_a_field_breaks_the_chain(tmp_path: Path):
    """Every verdict in the stream flipped, and the old check called it pass."""
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for event_type in ("a", "b", "c"):
        ledger.append(
            event_type, mission_id="M", actor="agent.test", decision="ALLOW",
        )
    assert ledger.validate()["status"] == "pass"

    path.write_text(
        path.read_text(encoding="utf-8").replace('"ALLOW"', '"DENY"'),
        encoding="utf-8", newline="",
    )
    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any(
        "does not follow the record before it" in item
        for item in report["diagnostics"]
    ), report["diagnostics"]


def test_removing_a_record_from_the_middle_breaks_the_chain(tmp_path: Path):
    """Caught twice over -- by the gap and by the broken link.

    The gap check alone could not tell a deletion from two writers racing,
    which is what made it useless as tamper-evidence: an operator seeing it had
    no way to know which had happened.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for event_type in ("a", "b", "c"):
        ledger.append(event_type, mission_id="M", actor="agent.test")

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(
        chr(10).join([lines[0], lines[2]]) + chr(10), encoding="utf-8", newline="",
    )
    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("sequence gap" in item for item in report["diagnostics"])
    assert any(
        "does not follow the record before it" in item
        for item in report["diagnostics"]
    ), report["diagnostics"]


def test_a_stream_with_no_high_water_mark_is_unconfirmed_not_clean(tmp_path: Path):
    """Absence of the mark is not a pass.

    Deleting the sidecar is the obvious way to defeat a completeness check, so
    a missing one must read as "nobody can confirm this" rather than as
    silence. `except: return []` reporting a clean tree when git could not run
    is the failure this repository was built around.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    ledger.append("a", mission_id="M", actor="agent.test")
    assert ledger.validate()["status"] == "pass"

    ledger.watermark_path.unlink()
    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("is unknown, not confirmed" in item for item in report["diagnostics"])


def test_an_untouched_stream_still_validates(tmp_path: Path):
    """The over-reach control, and the reason it is stated separately.

    Every check above is satisfied by a validator that refuses everything. A
    stream nobody touched has to pass, or none of the refusals above mean
    anything.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(12):
        ledger.append(
            "event", mission_id=f"M{index % 3}", actor="agent.test",
            capability="execute_low_risk_action", decision="ALLOW",
        )
    report = ledger.validate()
    assert report["status"] == "pass", report["diagnostics"]
    assert report["event_count"] == 12
    assert report["diagnostics"] == []
    # And re-read from disk by a ledger that appended nothing.
    assert EvidenceLedger(path).validate()["status"] == "pass"
