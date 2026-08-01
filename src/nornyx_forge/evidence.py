from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .util import digest, write_json


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


class EvidenceLedger:
    """Small append-only ledger for the public demo.

    It is not a substitute for Nornyx's runtime evidence validator. The ledger
    keeps the demo observable even when optional Nornyx/CrewAI dependencies are
    absent in CI.
    """

    def __init__(self, path: Path, *, subject_revision: str = "git:unbound") -> None:
        self.path = path
        self.subject_revision = subject_revision
        self._lock = threading.Lock()
        self._events: list[EvidenceEvent] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._events.append(EvidenceEvent(**json.loads(line)))

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
            event = EvidenceEvent(
                sequence=len(self._events) + 1,
                timestamp=datetime.now(timezone.utc).isoformat(),
                mission_id=mission_id,
                event_type=event_type,
                actor=actor,
                capability=capability,
                decision=decision,
                reason=reason,
                subject_revision=self.subject_revision,
                fields=fields,
            )
            self._events.append(event)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
            return event

    def events(self, mission_id: str | None = None) -> list[dict[str, Any]]:
        selected = self._events if mission_id is None else [e for e in self._events if e.mission_id == mission_id]
        return [asdict(e) for e in selected]

    def validate(self, *, report_path: Path | None = None) -> dict[str, Any]:
        diagnostics: list[str] = []
        expected = 1
        for event in self._events:
            if event.sequence != expected:
                diagnostics.append(f"sequence gap: expected {expected}, got {event.sequence}")
            expected = event.sequence + 1
            if not event.mission_id or not event.actor or not event.event_type:
                diagnostics.append(f"event {event.sequence} missing required identity fields")
        payload = {
            "schema": "nornyx.forge.demo_evidence_report.v1",
            "status": "pass" if not diagnostics else "fail",
            "event_count": len(self._events),
            "diagnostics": diagnostics,
            "stream_digest": digest(self.events()),
            "assurance_mode": "autonomous_demonstration",
            "human_review": "not_performed",
            "production_approval": "not_granted",
        }
        if report_path:
            write_json(report_path, payload)
        return payload
