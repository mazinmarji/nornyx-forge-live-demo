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

import pytest

from nornyx_forge.evidence import EvidenceLedger
from nornyx_forge.util import digest

#: A record cut off mid-write, as an interrupted append leaves it.
TORN_RECORD = (
    chr(123) + chr(34) + "sequence" + chr(34) + ": 5, "
    + chr(34) + "timestam"
)

#: A high-water mark left behind by a previous run.
STALE_MARK = json.dumps({"sequence": 99, "digest": "sha256:dead"})


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


def test_emptying_the_stream_entirely_is_reported(tmp_path: Path):
    """Removing HALF was caught; removing ALL was not.

    `_completeness_diagnostics` began `if not durable: return []`, so the
    completeness control was inverted on the one case an adversary who wants no
    record at all would choose. The mark beside the stream still recorded that
    six had been written.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(6):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test")
    assert ledger.validate()["status"] == "pass"

    path.write_text("", encoding="utf-8", newline="")
    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert report["event_count"] == 0
    assert any("the stream was removed or emptied" in item
               for item in report["diagnostics"]), report["diagnostics"]


def test_deleting_the_stream_file_is_reported(tmp_path: Path):
    """The same fact, one syscall further."""
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    ledger.append("only", mission_id="M", actor="agent.test")
    path.unlink()
    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("removed or emptied" in item for item in report["diagnostics"])


def test_a_stream_that_was_never_written_is_not_an_alarm(tmp_path: Path):
    """The over-reach control for the two above.

    Both are satisfied by a validator that refuses every empty stream, and a
    ledger nobody has appended to yet is empty for an innocent reason. With no
    mark and no records, nothing was written and nothing is claimed.
    """
    report = EvidenceLedger(tmp_path / "events.jsonl").validate()
    assert report["status"] == "pass", report
    assert report["event_count"] == 0
    assert report["diagnostics"] == []


def test_a_torn_line_is_reported_rather_than_raised(tmp_path: Path):
    """One partial write must not take the whole application down.

    The re-read happens on every APPEND as well as every validate, so letting
    `json.loads` escape turned one damaged line into an unhandled 500 for every
    later governed request in the process -- from `CustomerCaseFlow._stage` at
    intake, before anything had been decided. The class docstring already
    promised the other outcome: it "would then REPORT that rather than certify
    it".
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(4):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test")
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(TORN_RECORD)

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("is not a record" in item for item in report["diagnostics"]), (
        report["diagnostics"]
    )
    # And the ledger still accepts records, so the damage is visible rather
    # than terminal.
    EvidenceLedger(path, subject_revision="git:test").append(
        "after", mission_id="M", actor="agent.test",
    )


def test_a_correctly_chained_append_past_the_mark_is_caught(tmp_path: Path):
    """The forgery only the mark can see, and the direction it is named by.

    A record added with a correctly computed `previous_digest` leaves the chain
    intact -- linkage cannot help. The mark can, and the diagnostic used to say
    "records were removed from the end" for a record that had been ADDED,
    because one equality test served both directions.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(3):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test",
                      decision="DENY")

    records = _stream(path)
    mark_text = ledger.watermark_path.read_text(encoding="utf-8")
    forged = dict(records[-1])
    forged["sequence"] = 4
    forged["decision"] = "ALLOW"
    forged["event_type"] = "action_executed"
    forged["previous_digest"] = digest(records[-1])
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(forged, sort_keys=True) + chr(10))
    ledger.watermark_path.write_text(mark_text, encoding="utf-8", newline="")

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("APPENDED after the mark" in item
               for item in report["diagnostics"]), report["diagnostics"]
    assert not any("removed from the end" in item
                   for item in report["diagnostics"]), (
        "a record was added and the report says records were removed"
    )


def test_validating_while_writers_run_never_reports_a_sound_stream_as_tampered(
    tmp_path: Path,
):
    """`append` took the lock and `validate` took nothing.

    The reader saw the stream and the mark at two different instants with the
    whole validation loop in between, and the mark's write truncated before it
    wrote. Measured before the repair: 89 false `fail` verdicts in 1516
    validations of a stream that was in fact sound.
    """
    path = tmp_path / "events.jsonl"
    verdicts: list[str] = []

    def writer() -> None:
        ledger = EvidenceLedger(path, subject_revision="git:test")
        for _ in range(40):
            ledger.append("event", mission_id="M", actor="agent.test")

    def reader() -> None:
        ledger = EvidenceLedger(path)
        for _ in range(120):
            verdicts.append(ledger.validate()["status"])

    threads = [threading.Thread(target=writer) for _ in range(4)]
    threads += [threading.Thread(target=reader) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert set(verdicts) == {"pass"}, (
        "a sound stream was reported as tampered while it was being written: "
        + repr({verdict: verdicts.count(verdict) for verdict in set(verdicts)})
    )
    assert EvidenceLedger(path).validate()["status"] == "pass"


def test_the_demonstration_removes_the_mark_with_the_stream(tmp_path: Path):
    """The application decoupled its own completeness control.

    `run_demo_scenarios` unlinked `events.jsonl` and `report.json` and left the
    `.highwater` file behind, so the next run began beside a mark recording
    records that no longer existed.
    """
    from demo_app.agentic import run_demo_scenarios  # noqa: PLC0415
    from nornyx_forge.evidence import WATERMARK_SUFFIX  # noqa: PLC0415
    from nornyx_forge.governed_subject import RuntimeAuthorityConfig  # noqa: PLC0415

    runtime = tmp_path / "evidence" / "runtime"
    runtime.mkdir(parents=True)
    stale = runtime / ("events.jsonl" + WATERMARK_SUFFIX)
    stale.write_text(STALE_MARK, encoding="utf-8", newline="")

    result = run_demo_scenarios(
        tmp_path, worker_mode="deterministic",
        config=RuntimeAuthorityConfig(
            policy_backend="deterministic_demo", execution_backend="sequential",
        ),
    )
    assert result["evidence"]["status"] == "pass", (
        "a stale mark from a previous run survived into this one: "
        + repr(result["evidence"]["diagnostics"])
    )


def test_the_lock_key_does_not_change_when_the_file_appears(tmp_path: Path):
    """A "per-path" lock that was two locks.

    `Path.resolve()` looks at the filesystem, and on Windows it expands an 8.3
    short name only when the path EXISTS. The temporary directories these tests
    and the demo run in are short-named, so the same stream produced one key
    before its first append and another afterwards -- and appends that were
    supposed to serialise took different locks.
    """
    from nornyx_forge.evidence import _lock_key, _path_lock  # noqa: PLC0415

    path = tmp_path / "nested" / "events.jsonl"
    before_key = _lock_key(path)
    before_lock = _path_lock(path)

    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8", newline="")
    after_key = _lock_key(path)

    assert after_key == before_key, (
        "the lock key changed when the file was created, so writers before and "
        f"after the first append hold different locks: {before_key} then "
        f"{after_key}"
    )
    assert _path_lock(path) is before_lock
    # And it survives the file going away again, which is the whole lifetime a
    # reset walks through.
    path.unlink()
    assert _lock_key(path) == before_key
    assert _path_lock(path) is before_lock


def test_resetting_while_another_case_is_running_stays_consistent(tmp_path: Path):
    """The application reset its own ledger outside the lock.

    `run_demo_scenarios` unlinked the stream, the mark and the report with bare
    `unlink()` calls while `CustomerCaseFlow._stage` appended in the threadpool
    FastAPI dispatches its handlers into. Measured over 300 iterations before
    the repair: 5 legitimate runs reported `fail`, and 172 OSErrors escaped
    `append` as unhandled 500s.

    Both are gone only because BOTH halves were wrong: the reset had to take the
    lock, and the lock had to be one lock.
    """
    runtime = tmp_path / "evidence" / "runtime"
    runtime.mkdir(parents=True)
    path = runtime / "events.jsonl"
    rounds = 60
    verdicts: list[str] = []
    escaped: list[str] = []

    def resetter() -> None:
        for _ in range(rounds):
            try:
                EvidenceLedger(path).reset(runtime / "report.json")
                ledger = EvidenceLedger(path, subject_revision="git:test")
                for index in range(3):
                    ledger.append(f"r{index}", mission_id="R", actor="agent.test")
                verdicts.append(EvidenceLedger(path).validate()["status"])
            except Exception as exc:  # noqa: BLE001 - the point of the test
                escaped.append(type(exc).__name__)

    def writer() -> None:
        for _ in range(rounds):
            try:
                ledger = EvidenceLedger(path, subject_revision="git:test")
                for index in range(6):
                    ledger.append(f"w{index}", mission_id="W", actor="agent.test")
            except Exception as exc:  # noqa: BLE001 - the point of the test
                escaped.append(type(exc).__name__)

    threads = [threading.Thread(target=resetter), threading.Thread(target=writer)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert escaped == [], (
        "the reset raced a concurrent append and the exception escaped to the "
        f"caller, which is an unhandled 500 from `_stage`: {escaped[:5]}"
    )
    assert set(verdicts) == {"pass"}, (
        "a run that nothing tampered with was reported as tampered: "
        + repr({verdict: verdicts.count(verdict) for verdict in set(verdicts)})
    )


def test_removing_the_stream_and_its_mark_together_is_the_disclosed_limit(
    tmp_path: Path,
):
    """Stated rather than implied, because the docstring once implied otherwise.

    With both files gone there is nothing local left to disagree with. That is
    a real limit of a sidecar held beside the thing it marks, and the class
    says so in the same words the approval ledger uses about an adversary with
    write access. This test exists so the limit is a MEASURED, named fact
    rather than a gap someone later mistakes for a control.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(6):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test")

    path.unlink()
    ledger.watermark_path.unlink()
    report = EvidenceLedger(path).validate()
    assert report["status"] == "pass", report
    assert report["event_count"] == 0
    # And each half ALONE is still caught, which is what makes this a limit
    # rather than an absence of control.
    for keep in ("stream", "mark"):
        again = tmp_path / (keep + ".jsonl")
        second = EvidenceLedger(again, subject_revision="git:test")
        second.append("only", mission_id="M", actor="agent.test")
        (again if keep == "mark" else second.watermark_path).unlink()
        assert EvidenceLedger(again).validate()["status"] == "fail", keep


def test_a_line_that_parses_but_is_not_an_event_is_reported(tmp_path: Path):
    """Valid JSON, wrong shape: `__init__` and `validate` tolerated it, `append`
    subscripted it and raised `KeyError` from `_stage` at intake."""
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    ledger.append("first", mission_id="M", actor="agent.test")
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps({"not": "an event"}) + chr(10))

    EvidenceLedger(path, subject_revision="git:test").append(
        "after", mission_id="M", actor="agent.test",
    )
    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("missing required identity fields" in item
               for item in report["diagnostics"]), report["diagnostics"]


def test_a_torn_line_does_not_make_the_report_name_a_direction(tmp_path: Path):
    """The sequence jumps because a record could not be read, not because one
    was removed, and telling an operator otherwise sends them somewhere else."""
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(3):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test")
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(TORN_RECORD)
    EvidenceLedger(path, subject_revision="git:test").append(
        "after", mission_id="M", actor="agent.test",
    )

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert not any("removed from the end" in item
                   for item in report["diagnostics"]), report["diagnostics"]
    assert any("cannot be attributed" in item
               for item in report["diagnostics"]), report["diagnostics"]


def test_the_report_describes_the_whole_case(tmp_path: Path):
    """`report.json` was permanently one record behind on the single-case path.

    `audit` validated and then appended its own `stage_completed`, so the
    artifact and the stream it names disagreed about how long the evidence was
    for every `POST /api/cases`.
    """
    from demo_app.agentic import CustomerCaseFlow, application_security_context  # noqa: PLC0415

    flow = CustomerCaseFlow(
        {"id": "CASE-SEAL", "customer": "Amina", "risk": "low",
         "summary": "Update delivery instructions",
         "requested_action": "send guidance"},
        root=tmp_path, worker_mode="deterministic", allow_policy_fallback=True,
        security_context=application_security_context(),
    )
    case = flow.run_sequential()
    stream = _stream(tmp_path / "evidence" / "runtime" / "events.jsonl")
    assert case["evidence"]["event_count"] == len(stream), (
        "the report names " + str(case["evidence"]["event_count"])
        + " events and the stream it describes holds " + str(len(stream))
    )
    assert case["evidence"]["status"] == "pass", case["evidence"]["diagnostics"]
    assert any(entry["stage"] == "audit" for entry in case["timeline"])


def test_a_sequence_that_is_not_a_number_is_reported_not_raised(tmp_path: Path):
    """`validate` is the only one of the three that is a GATE, and the only one
    that did not check the type it does arithmetic on.

    `append` guards it with `isinstance(last_sequence, int)` and `__init__`
    tolerates a wrong-shaped record by design. `validate` ran
    `(sequence or expected) + 1`, which CONCATENATES when a record carries
    `"sequence": "3"`. Measured on the shipped path: TypeError out of
    `CustomerCaseFlow.audit`, so the records were appended, the low-risk effect
    was released, and the report was never written -- leaving the previous
    `pass` artifact on disk describing 7 events beside a file holding 14.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(3):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test")

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["sequence"] = str(record["sequence"])
    lines[1] = json.dumps(record, sort_keys=True)
    path.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline="")

    report = tmp_path / "report.json"
    verdict = EvidenceLedger(path).validate(report_path=report)
    assert verdict["status"] == "fail", verdict
    assert any("not a whole number" in item for item in verdict["diagnostics"]), (
        verdict["diagnostics"]
    )
    assert report.exists(), (
        "validate died before writing the report, so the artifact an operator "
        "reads is the previous run's verdict"
    )
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "fail"


def test_a_stream_that_cannot_be_decoded_is_reported(tmp_path: Path):
    """The read boundary guarded one exception class.

    `read_text` sat OUTSIDE the try and the try named `ValueError`, so an
    invalid UTF-8 byte raised `UnicodeDecodeError` and 60000 nested arrays
    raised `RecursionError` -- both straight out of `_stage` at intake, leaving
    the previous `pass` report on disk beside a longer stream. The repair was
    being made one exception class at a time; a reader cannot enumerate the
    ways bytes go wrong, which is why the guard belongs at the boundary.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    ledger.append("first", mission_id="M", actor="agent.test")
    with path.open("ab") as handle:
        handle.write(bytes([0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D, 0x0A]))

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("could not be read" in item for item in report["diagnostics"]), (
        report["diagnostics"]
    )


def test_a_deeply_nested_line_is_reported(tmp_path: Path):
    """Valid JSON that `json.loads` cannot finish is still a damaged line."""
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    ledger.append("first", mission_id="M", actor="agent.test")
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write("[" * 60000 + "]" * 60000 + chr(10))

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("is not a record" in item for item in report["diagnostics"]), (
        report["diagnostics"]
    )


def test_a_record_that_cannot_be_digested_never_reaches_the_stream(tmp_path: Path):
    """The digest was computed AFTER the write, and that ordering was the bug.

    A lone surrogate in a summary -- the shape `resolution` builds straight from
    `requested_action` -- left the stream one line ahead of the mark
    permanently, and poisoned every later append IN EVERY PROCESS, because the
    next `digest(previous)` re-reads it. `validate` then raised too, so the gate
    could no longer report anything at all.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    ledger.append("first", mission_id="M", actor="agent.test")
    before = len(_stream(path))

    with pytest.raises(ValueError, match="cannot be recorded"):
        EvidenceLedger(path, subject_revision="git:test").append(
            "stage_completed", mission_id="M", actor="agent.test",
            summary="Proposed action: ab" + chr(0xD800) + "cd.",
        )

    assert len(_stream(path)) == before, "the undigestable record reached the stream"
    mark = json.loads(ledger.watermark_path.read_text(encoding="utf-8"))
    assert mark["sequence"] == before, "the mark and the stream disagree"
    # And the ledger still works, so one bad input is not permanent poison.
    following = EvidenceLedger(path, subject_revision="git:test").append(
        "after", mission_id="M", actor="agent.test",
    )
    assert following.sequence == before + 1
    assert EvidenceLedger(path).validate()["status"] == "pass"


def test_a_mark_whose_sequence_is_not_a_number_names_no_direction(tmp_path: Path):
    """The record's sequence was type-checked and the mark's was not.

    A mark reading `"2"` beside a stream ending at 2 produced "the stream ends
    at event 2 and 2 were written: records were APPENDED after the mark was
    last written" -- self-contradictory, and an accusation of tampering where
    nothing had been appended. `isinstance(written, int)` was silently
    selecting APPENDED as the fallback for cannot-tell.
    """
    path = tmp_path / "events.jsonl"
    ledger = EvidenceLedger(path, subject_revision="git:test")
    for index in range(2):
        ledger.append(f"e{index}", mission_id="M", actor="agent.test")

    mark = json.loads(ledger.watermark_path.read_text(encoding="utf-8"))
    mark["sequence"] = str(mark["sequence"])
    ledger.watermark_path.write_text(
        json.dumps(mark), encoding="utf-8", newline="",
    )

    report = EvidenceLedger(path).validate()
    assert report["status"] == "fail", report
    assert any("cannot be compared" in item for item in report["diagnostics"]), (
        report["diagnostics"]
    )
    assert not any("APPENDED" in item for item in report["diagnostics"]), (
        "a direction was claimed from a mark that cannot be compared"
    )
