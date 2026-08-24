from __future__ import annotations

import json
import os
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
#: Measured with four writers and three events each: twelve lines on disk, and
#: sequences 1, 2 and 3 each appearing four times over.
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
    verdict over `self._events` -- the list one instance happened to append --
    while the report it wrote named a FILE it never read back. Measured on the
    production shape, three concurrent `run_case` calls each certified a sound
    six-event stream while the file they shared held twenty-one records in
    which every sequence number appeared three times. It now reads the stream
    it names, under the same lock the writers hold, and the four questions it
    answers are kept apart:

        readability   every line on disk is a record that parses
        contiguity    the sequence numbers present run 1..n without a gap
        linkage       each record carries the digest of the one before it
        completeness  the last record is the last one that was WRITTEN, and
                      the stream has not been emptied out from under the mark

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
        for record in self._read_stream()[0]:
            try:
                self._events.append(EvidenceEvent(**record))
            except TypeError:
                # A record whose SHAPE is wrong is reported by `validate`, not
                # raised here. Construction that dies on a damaged stream takes
                # the diagnosis down with it.
                continue

    @property
    def watermark_path(self) -> Path:
        return self.path.with_name(self.path.name + WATERMARK_SUFFIX)

    def _read_stream(self) -> tuple[list[dict[str, Any]], list[str], int]:
        """(records, problems, lines) for the FILE, which is what a report is about.

        A TORN LINE IS REPORTED, NOT RAISED. This read happens on every append
        as well as on every validate, so letting `json.loads` escape meant one
        partial write turned every later governed request in the process into
        an unhandled 500 -- measured, from `CustomerCaseFlow._stage` at intake.
        The class docstring already promised the other outcome for the case it
        names: `validate()` "would then REPORT that rather than certify it".
        """
        if not self.path.exists():
            return [], [], 0
        records: list[dict[str, Any]] = []
        problems: list[str] = []
        lines = [
            line for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for number, line in enumerate(lines, start=1):
            try:
                parsed = json.loads(line)
            except ValueError as exc:
                problems.append(
                    f"line {number} of the stream is not a record: {exc}"
                )
                continue
            if not isinstance(parsed, dict):
                problems.append(f"line {number} of the stream is not an object")
                continue
            records.append(parsed)
        return records, problems, len(lines)

    def _write_watermark(self, sequence: int, record_digest: str) -> None:
        """Replace the mark atomically.

        `write_json` truncates and then writes, so every append left a window
        in which the mark was an empty file on disk. A concurrent `validate()`
        read it and reported "the high-water mark could not be read" against a
        stream that was perfectly sound -- measured, 89 false failures in 1516
        validations under load.
        """
        temporary = self.watermark_path.with_name(
            self.watermark_path.name + ".writing"
        )
        write_json(temporary, {"sequence": sequence, "digest": record_digest})
        os.replace(temporary, self.watermark_path)

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
            durable, problems, lines = self._read_stream()
            readable_tail = bool(durable) and not problems and len(durable) == lines
            previous = durable[-1] if readable_tail else None
            if previous is not None:
                sequence = previous["sequence"] + 1
            else:
                # A damaged stream still accepts records; the chain simply
                # shows where the damage is, which is what a reader needs.
                sequence = max(lines, len(durable)) + 1
            event = EvidenceEvent(
                sequence=sequence,
                timestamp=datetime.now(timezone.utc).isoformat(),
                mission_id=mission_id,
                event_type=event_type,
                actor=actor,
                capability=capability,
                decision=decision,
                reason=reason,
                subject_revision=self.subject_revision,
                fields=fields,
                previous_digest=digest(previous) if previous is not None else "",
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
            self._write_watermark(event.sequence, digest(record))
            return event

    def events(self, mission_id: str | None = None) -> list[dict[str, Any]]:
        selected = self._events if mission_id is None else [e for e in self._events if e.mission_id == mission_id]
        return [asdict(e) for e in selected]

    def validate(self, *, report_path: Path | None = None) -> dict[str, Any]:
        # UNDER THE SAME LOCK THE WRITERS HOLD. `append` took it and `validate`
        # took nothing, so a reader saw the stream and the mark at two
        # different instants with the whole validation loop in between, and
        # reported a sound stream as tampered.
        with self._lock:
            durable, diagnostics, _lines = self._read_stream()
            diagnostics = list(diagnostics)

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
                # LINKAGE. Rewriting any earlier field changes its digest, so
                # the next record no longer points at it. Every verdict in a
                # stream was flipped from ALLOW to DENY and the old check
                # called it "pass".
                expected_link = digest(previous) if previous else ""
                if record.get("previous_digest", "") != expected_link:
                    diagnostics.append(
                        f"event {sequence} does not follow the record before "
                        "it: the stream was rewritten, reordered, or a record "
                        "was removed from the middle"
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
        """Is the stream on disk the whole of what was written?

        ABSENCE OF THE MARK IS NOT A PASS. A stream with no watermark beside it
        is one whose completeness nobody can confirm, and saying so is the
        whole point -- `except: return []` reporting a clean tree when git
        could not run is the failure this repository was built around.

        AND ABSENCE OF THE STREAM IS NOT A PASS EITHER. This began
        `if not durable: return []`, so removing HALF the records was caught
        and removing ALL of them was not -- the completeness control inverted
        on the one case an adversary who wants no record at all would choose.
        An empty stream is fine only if nothing was ever written to it.
        """
        mark = self._read_watermark()
        if mark is None:
            if not durable:
                # Nothing written and nothing claimed: genuinely empty.
                return []
            return [
                "no high-water mark beside this stream, so whether records "
                "were removed from the end of it is unknown, not confirmed"
            ]
        if isinstance(mark, str):
            return [mark]
        written = mark.get("sequence")
        if not durable:
            return [
                "the stream is empty and the high-water mark beside it records "
                f"that {written} record(s) were written: the stream was removed "
                "or emptied"
            ]
        last = durable[-1]
        present = last.get("sequence")
        if written != present:
            direction = (
                "records were removed from the end"
                if isinstance(written, int) and isinstance(present, int)
                and present < written
                else "records were APPENDED after the mark was last written"
            )
            return [
                f"the stream ends at event {present} and {written} were "
                f"written: {direction}"
            ]
        if mark.get("digest") != digest(last):
            return ["the last record is not the one that was written there"]
        return []

    def _read_watermark(self) -> dict[str, Any] | str | None:
        """The mark, a diagnostic string if it is unreadable, or None if absent."""
        if not self.watermark_path.exists():
            return None
        try:
            mark = json.loads(self.watermark_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return f"the high-water mark could not be read: {exc}"
        if not isinstance(mark, dict):
            return "the high-water mark is not a record"
        return mark
