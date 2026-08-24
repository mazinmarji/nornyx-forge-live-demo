from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .util import digest, write_json

#: Sequencing is serialised per PATH, not per instance.
#:
#: `main.py` builds one `EvidenceLedger` per request over one shared
#: `events.jsonl`, and FastAPI runs the sync handler in a threadpool, so the
#: per-instance lock this class used to hold guarded nothing that mattered.
#: Measured with four writers and three events each: twelve lines on disk with
#: sequences 1, 2 and 3 each appearing three times over.
_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()

#: Where the highest sequence written is recorded, BESIDE the stream.
#:
#: A chain of digests catches rewriting and mid-stream deletion, because both
#: break a link. It cannot catch TRUNCATION: lopping the tail off leaves a
#: shorter chain that is perfectly consistent with itself. The one fact a
#: truncation cannot carry away is a count held somewhere else -- the same
#: reasoning, and the same shape, as the approval ledger high-water mark.
WATERMARK_SUFFIX = ".highwater"

#: One newline, spelled once. These records are evidence and their bytes are
#: digested, so the separator is not an incidental detail.
_RECORD_SEPARATOR = chr(10)


def _path_lock(path: Path) -> threading.Lock:
    """The lock every ledger over this file shares."""
    key = str(Path(path).resolve()).lower()
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.Lock())


@dataclass(frozen=True)
class EvidenceEvent:
    sequence: int
    timestamp: str
    mission_id: str
    event_type: str
    actor: str
    capability: str | None
    decision: str | None
    reason: str | None
    subject_revision: str
    fields: dict[str, Any]
    #: The digest of the record before this one, empty for the first.
    #:
    #: Defaulted so a stream written before this field existed still loads --
    #: `validate` reports such a stream as unchained rather than refusing to
    #: read it, which is the difference between "I cannot confirm this" and
    #: "this is fine".
    previous_digest: str = ""


class EvidenceLedger:
    """Small append-only ledger for the public demo.

    It is not a substitute for Nornyx runtime evidence validation. The ledger
    keeps the demo observable even when optional Nornyx/CrewAI dependencies are
    absent in CI.

    WHAT `validate()` CERTIFIES, and what it does not. It used to compute its
    verdict over `self._events` -- the list this instance happened to append --
    while the report it wrote named a FILE it never read back. Measured on the
    production shape, three concurrent `run_case` calls each certified a sound
    six-event stream while the file they shared held twenty-one records in
    which every sequence number appeared three times. It now reads the stream
    it names, and the three questions it answers are kept apart:

        contiguity    the sequence numbers present run 1..n without a gap
        linkage       each record carries the digest of the one before it
        completeness  the last record is the last one that was WRITTEN

    Cross-PROCESS concurrency is not defended and is not claimed: the lock is a
    `threading.Lock` held per resolved path, which covers the threadpool this
    application actually uses. Two processes appending to one file would still
    interleave -- and `validate()` would then REPORT that rather than certify
    it, which is the property that matters.
    """

    def __init__(self, path: Path, *, subject_revision: str = "git:unbound") -> None:
        self.path = path
        self.subject_revision = subject_revision
        self._lock = _path_lock(path)
        self._events: list[EvidenceEvent] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._events.append(EvidenceEvent(**json.loads(line)))

    @property
    def watermark_path(self) -> Path:
        return self.path.with_name(self.path.name + WATERMARK_SUFFIX)

    def _durable_events(self) -> list[dict[str, Any]]:
        """The records the FILE holds, which is what a report is about."""
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def append(
        self,
        event_type: str,
        *,
        mission_id: str,
        actor: str,
        capability: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        **fields: Any,
    ) -> EvidenceEvent:
        with self._lock:
            # THE SEQUENCE COMES FROM THE STREAM, not from this instance's idea
            # of how long it is. `len(self._events) + 1` is only correct when
            # nothing else writes to the same file, and something does.
            durable = self._durable_events()
            previous = durable[-1] if durable else None
            event = EvidenceEvent(
                sequence=(previous["sequence"] + 1) if previous else 1,
                timestamp=datetime.now(timezone.utc).isoformat(),
                mission_id=mission_id,
                event_type=event_type,
                actor=actor,
                capability=capability,
                decision=decision,
                reason=reason,
                subject_revision=self.subject_revision,
                fields=fields,
                previous_digest=digest(previous) if previous else "",
            )
            record = asdict(event)
            self._events.append(event)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # newline="" so a record is the bytes this line built. Text mode
            # translates on Windows, which would make one append produce a
            # different record than the same append on Linux -- and these lines
            # are evidence, read back and counted.
            with self.path.open("a", encoding="utf-8", newline="") as handle:
                handle.write(
                    json.dumps(record, sort_keys=True) + _RECORD_SEPARATOR
                )
            # BESIDE the stream, so a truncation cannot carry it away.
            write_json(
                self.watermark_path,
                {"sequence": event.sequence, "digest": digest(record)},
            )
            return event

    def events(self, mission_id: str | None = None) -> list[dict[str, Any]]:
        selected = self._events if mission_id is None else [e for e in self._events if e.mission_id == mission_id]
        return [asdict(e) for e in selected]

    def validate(self, *, report_path: Path | None = None) -> dict[str, Any]:
        diagnostics: list[str] = []
        durable = self._durable_events()

        expected = 1
        previous: dict[str, Any] | None = None
        for record in durable:
            sequence = record.get("sequence")
            if sequence != expected:
                diagnostics.append(
                    f"sequence gap: expected {expected}, got {sequence}"
                )
            expected = (sequence or expected) + 1
            if (not record.get("mission_id") or not record.get("actor")
                    or not record.get("event_type")):
                diagnostics.append(
                    f"event {sequence} missing required identity fields"
                )
            # LINKAGE. Rewriting any earlier field changes its digest, so the
            # next record no longer points at it. Every verdict in a stream was
            # flipped from ALLOW to DENY and the old check called it "pass".
            expected_link = digest(previous) if previous else ""
            if record.get("previous_digest", "") != expected_link:
                diagnostics.append(
                    f"event {sequence} does not follow the record before it: "
                    "the stream was rewritten, reordered, or a record was "
                    "removed from the middle"
                )
            previous = record

        diagnostics.extend(self._completeness_diagnostics(durable))

        payload = {
            "schema": "nornyx.forge.demo_evidence_report.v1",
            "status": "pass" if not diagnostics else "fail",
            "event_count": len(durable),
            "diagnostics": diagnostics,
            "stream_digest": digest(durable),
            "assurance_mode": "autonomous_demonstration",
            "human_review": "not_performed",
            "production_approval": "not_granted",
        }
        if report_path:
            write_json(report_path, payload)
        return payload

    def _completeness_diagnostics(self, durable: list) -> list[str]:
        """Is the last record on disk the last one that was written?

        ABSENCE OF THE MARK IS NOT A PASS. A stream with no watermark beside it
        is one whose completeness nobody can confirm, and saying so is the
        whole point -- `except: return []` reporting a clean tree when git
        could not run is the failure this repository was built around.
        """
        if not durable:
            return []
        if not self.watermark_path.exists():
            return [
                "no high-water mark beside this stream, so whether records "
                "were removed from the end of it is unknown, not confirmed"
            ]
        try:
            mark = json.loads(self.watermark_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [f"the high-water mark could not be read: {exc}"]
        last = durable[-1]
        if mark.get("sequence") != last.get("sequence"):
            return [
                "the stream ends at event " + str(last.get("sequence"))
                + " but " + str(mark.get("sequence")) + " were written: "
                "records were removed from the end"
            ]
        if mark.get("digest") != digest(last):
            return ["the last record is not the one that was written there"]
        return []
