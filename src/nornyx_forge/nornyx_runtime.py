from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .models import GateResult
from .util import write_json

#: Pin the evaluation instant for a reproducible run (CI, fixtures, demos).
RUNTIME_AS_OF_ENV = "FORGE_RUNTIME_AS_OF"
#: Override the governed subject revision when the contract cannot be read.
RUNTIME_REVISION_ENV = "FORGE_RUNTIME_REVISION"

RUNTIME_CONTRACT = ".nornyx/contracts/runtime_network.nyx"
_UNBOUND_REVISION = "git:unbound"
_REVISION_RE = re.compile(r"^(?:git:[0-9a-f]{40}|git:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
_SUBJECT_REVISION_RE = re.compile(
    r"^\s{2}subject_revision:\s*(\S+)\s*$", re.MULTILINE
)


def runtime_as_of(explicit: str | None = None) -> str:
    """Return the instant Nornyx must evaluate temporal validity against.

    Defaults to the real current time, so an approval issued now is judged
    against now and the seven-day expiry rule measures real elapsed time. A run
    that needs determinism pins the instant explicitly, either by argument or via
    ``FORGE_RUNTIME_AS_OF``.

    A supplied value must be an explicit timezone-aware timestamp. Anything else
    raises instead of silently falling back to the live clock, so a malformed pin
    can never widen a validity window by accident.
    """

    raw = explicit if explicit is not None else os.getenv(RUNTIME_AS_OF_ENV)
    if raw is not None and not raw.strip():
        # Set-but-blank is a configuration mistake, not a request for the live
        # clock. Falling back silently would hide a broken pin.
        raise ValueError(f"{RUNTIME_AS_OF_ENV} is set but empty")
    if raw is None:
        moment = datetime.now(timezone.utc)
    else:
        try:
            parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                f"{RUNTIME_AS_OF_ENV} must be an ISO-8601 timestamp, got {raw!r}"
            ) from exc
        if parsed.tzinfo is None:
            raise ValueError(
                f"{RUNTIME_AS_OF_ENV} must be timezone-aware, got {raw!r}"
            )
        moment = parsed
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def runtime_revision(root: Path | None = None) -> str:
    """Return the governed subject revision the runtime contract declares.

    The contract is the single source of truth, so the code can never disagree
    with the declaration Nornyx validates. Returns ``git:unbound`` when no
    contract is present, which keeps evidence honestly labelled rather than
    claiming a binding that does not exist.
    """

    override = os.getenv(RUNTIME_REVISION_ENV)
    if override and _REVISION_RE.fullmatch(override.strip()):
        return override.strip()
    contract = (root or Path.cwd()) / RUNTIME_CONTRACT
    try:
        text = contract.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # An unreadable or non-UTF-8 contract yields an honest "unbound" rather
        # than raising out of an evidence-labelling path.
        return _UNBOUND_REVISION
    for match in _SUBJECT_REVISION_RE.finditer(text):
        candidate = match.group(1).strip().strip("\"'")
        if _REVISION_RE.fullmatch(candidate):
            return candidate
    return _UNBOUND_REVISION


#: Risk levels that require an action-specific human approval, never merely a
#: contract approval, before a consequential effect may be released.
HIGH_RISK_LEVELS = frozenset({"high", "critical"})


#: A human action approval may not outlive this window, matching the P7D cap
#: Nornyx applies to agentic-network approval evidence.
ACTION_APPROVAL_MAX_AGE = timedelta(days=7)

#: Roles permitted to release a consequential effect, per high_risk_action_authority.
ACTION_APPROVER_ROLES = frozenset({"operations_owner", "network_governance_owner"})


def _canonical(value: Any) -> Any:
    """Normalize a value so equal operations always digest identically."""
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        # 100 and 100.0 are the same amount and must not digest differently.
        return int(value) if value.is_integer() else float(value)
    return str(value)


@dataclass(frozen=True)
class ActionDescriptor:
    """What the effect actually does, described independently of any callable.

    The approved thing must be the operation, not the Python object that happens
    to perform it. Two different refunds share a callable; they are not the same
    consequential act, and an approval for one must not release the other.
    """

    operation: str
    resource: str
    destination: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "resource": self.resource,
            "destination": self.destination,
            "parameters": _canonical(dict(self.parameters)),
        }

    @property
    def payload_digest(self) -> str:
        canonical = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ActionRequest:
    """One exact consequential request an approval may be bound to."""

    request_id: str
    mission_id: str
    subject_revision: str
    capability: str
    action: ActionDescriptor

    @property
    def destination(self) -> str:
        return self.action.destination

    @property
    def payload_digest(self) -> str:
        return self.action.payload_digest

    def canonical(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "mission_id": self.mission_id,
            "subject_revision": self.subject_revision,
            "capability": self.capability,
            "action": self.action.canonical(),
            "payload_digest": self.action.payload_digest,
        }

    @property
    def digest(self) -> str:
        """Digest over the whole request, so an approval cannot be re-aimed.

        Covers the complete action descriptor, so changing the operation, the
        target, the destination, or any parameter — an amount, an account —
        produces a different digest and voids the grant.
        """
        canonical = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: Where consumed action approvals are recorded. Generated runtime state, so it
#: lives under evidence/runtime/ and is never committed.
APPROVAL_LEDGER_ENV = "FORGE_APPROVAL_LEDGER"
DEFAULT_APPROVAL_LEDGER = "evidence/runtime/action_approvals.sqlite3"


class ApprovalLedger:
    """Durable, atomic, single-use consumption of action approvals.

    A process-local set forgets everything when the boundary is rebuilt or the
    process restarts, so the same grant could be replayed simply by starting
    again. Consumption is recorded in SQLite under a primary key, so a duplicate
    or concurrent claim loses to the unique constraint rather than to a
    check-then-act race.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS consumed_approvals ("
                " approval_id TEXT PRIMARY KEY,"
                " request_digest TEXT NOT NULL,"
                " consumed_at TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def consume(self, approval_id: str, request_digest: str, *, at: str) -> tuple[bool, str]:
        """Claim the approval, or refuse. The insert is the claim.

        Called before the effect runs, so a grant is spent even if the effect
        then fails. That is deliberate: at-most-once is the safe direction for a
        consequential act, and retrying requires a fresh human approval.
        """
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO consumed_approvals"
                    " (approval_id, request_digest, consumed_at) VALUES (?, ?, ?)",
                    (approval_id, request_digest, at),
                )
        except sqlite3.IntegrityError:
            previous = self.lookup(approval_id)
            when = previous[1] if previous else "an earlier run"
            if previous and previous[0] != request_digest:
                return False, (
                    f"approval {approval_id} was already consumed at {when} for a "
                    "different request"
                )
            return False, f"approval {approval_id} was already consumed at {when}"
        return True, f"approval {approval_id} consumed"

    def lookup(self, approval_id: str) -> tuple[str, str] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT request_digest, consumed_at FROM consumed_approvals"
                " WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        return (row[0], row[1]) if row else None


def approval_ledger_path(root: Path) -> Path:
    override = os.getenv(APPROVAL_LEDGER_ENV)
    return Path(override) if override else root / DEFAULT_APPROVAL_LEDGER


def validate_action_approval(
    approval: Mapping[str, Any] | None,
    request: ActionRequest,
    *,
    as_of: str,
) -> tuple[bool, str]:
    """Decide whether this approval releases *this* request, and only this one.

    Every check is a reason to refuse. A grant is bound to one request id, one
    subject revision, one capability, one destination, and one request digest,
    so an approval obtained for a harmless action cannot be replayed against a
    different or larger one. It is single-use and time-bounded.

    Returns (released, reason). The reason is recorded either way, so a refusal
    is always explainable.
    """

    if not isinstance(approval, Mapping):
        return False, "no action-specific approval was supplied"
    if approval.get("granted") is not True:
        return False, "approval does not carry an explicit granted decision"

    approval_id = approval.get("approval_id")
    if not isinstance(approval_id, str) or not approval_id.strip():
        return False, "approval has no identifier"

    approver = approval.get("approver")
    if not isinstance(approver, str) or not approver.strip():
        return False, "approval names no human approver"
    if str(approval.get("approver_type", "")).lower() != "human":
        return False, "approver is not declared human"
    role = str(approval.get("approver_role", ""))
    if role not in ACTION_APPROVER_ROLES:
        return False, f"approver role {role!r} may not release a high-risk effect"

    for name, expected in (
        ("request_id", request.request_id),
        ("subject_revision", request.subject_revision),
        ("capability", request.capability),
        ("destination", request.destination),
        ("payload_digest", request.payload_digest),
        ("request_digest", request.digest),
    ):
        actual = approval.get(name)
        if actual != expected:
            return False, (
                f"approval {name} does not match this request "
                f"({actual!r} != {expected!r})"
            )

    try:
        generated = datetime.fromisoformat(
            str(approval["generated_at"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(approval["expires_at"]).replace("Z", "+00:00")
        )
        moment = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False, "approval has no valid generated/expiry interval"
    if generated.tzinfo is None or expires.tzinfo is None:
        return False, "approval timestamps must be timezone-aware"
    if expires <= generated:
        return False, "approval expiry precedes its issue"
    if expires - generated > ACTION_APPROVAL_MAX_AGE:
        return False, "approval window exceeds the seven-day limit"
    if moment < generated:
        return False, "approval is not yet valid"
    if moment >= expires:
        return False, "approval has expired"

    return True, f"released by action approval {approval_id}"


def _action_approval_present(approval: Mapping[str, Any] | None) -> bool:
    """Return whether a usable action-specific human approval was supplied.

    Kept for the shape checks that do not depend on a specific request. Binding
    to an exact request is done by :func:`validate_action_approval`.
    """

    if not isinstance(approval, Mapping):
        return False
    approver = approval.get("approver")
    granted = approval.get("granted")
    return (
        granted is True
        and isinstance(approver, str)
        and approver.strip() != ""
        and str(approval.get("approver_type", "human")).lower() == "human"
    )


class NornyxRuntimeUnavailable(RuntimeError):
    """The official Nornyx authorization path could not be established.

    Raised only when the deterministic fallback is refused. Callers should treat
    this as a governed refusal to act, not as an unexpected crash: no capability
    was authorized, so no action may run.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True)
class RuntimeDecision:
    effect: str
    code: str
    reason: str
    source: str
    evidence: dict[str, Any] | None = None

    @property
    def allowed(self) -> bool:
        return self.effect == "ALLOW"


def prepare_runtime_contract(root: Path, *, as_of: str | None = None) -> list[GateResult]:
    """Validate, generate, lock, and verify the runtime contract with Nornyx.

    Every step receives the same explicit evaluation instant, including the
    initial ``check``. Leaving ``check`` on the live clock while the lock steps
    used a pinned instant meant the two could disagree about whether an approval
    was still valid.

    The generated artifacts are intentionally outside tracked source. When the
    CLI is unavailable the caller receives a failed gate rather than a fabricated
    success.
    """

    executable = shutil.which("nornyx")
    if not executable:
        return [GateResult("nornyx runtime preparation", False, "nornyx CLI not installed", (), 127)]
    moment = runtime_as_of(as_of)
    contract = root / RUNTIME_CONTRACT
    out = root / ".nornyx/runtime"
    artifacts = out / "control_artifacts"
    lock = out / "nornyx.agentic_network.lock"
    out.mkdir(parents=True, exist_ok=True)
    commands = [
        (executable, "check", str(contract), "--as-of", moment),
        (
            executable,
            "agentic-network",
            "generate",
            str(contract),
            "--out",
            str(artifacts),
            "--as-of",
            moment,
        ),
        (
            executable,
            "agentic-network",
            "lock",
            str(contract),
            "--artifacts",
            str(artifacts),
            "--out",
            str(lock),
            "--as-of",
            moment,
        ),
        (
            executable,
            "agentic-network",
            "lock-check",
            str(contract),
            "--lock",
            str(lock),
            "--artifacts",
            str(artifacts),
            "--as-of",
            moment,
        ),
    ]
    results: list[GateResult] = []
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        detail = (completed.stdout + completed.stderr).strip()
        result = GateResult(
            name=" ".join(command[1:3]),
            passed=completed.returncode == 0,
            detail=detail,
            command=tuple(command),
            returncode=completed.returncode,
        )
        results.append(result)
        if not result.passed:
            break
    write_json(out / "preparation-report.json", [item.__dict__ for item in results])
    return results


class NornyxActionBoundary:
    """Official Nornyx authorization path with an explicit fallback boundary.

    If the Nornyx package and a verified lock are present, decisions and evidence
    come from `nornyx.agentic`. A deterministic fallback is available only for
    offline CI and is always labelled as fallback evidence.
    """

    def __init__(
        self,
        root: Path,
        *,
        allow_fallback: bool = True,
        as_of: str | None = None,
    ) -> None:
        self.root = root
        self.allow_fallback = allow_fallback
        self.as_of = runtime_as_of(as_of)
        #: Durable single-use ledger. Survives boundary and process restarts.
        self.approval_ledger = ApprovalLedger(approval_ledger_path(root))
        self.authorizer: Any | None = None
        self.context: Any | None = None
        self._imports: dict[str, Any] = {}
        self.load_error: str | None = None
        try:
            from nornyx.agentic import (  # type: ignore[import-not-found]
                CapabilityRequest,
                EvaluationContext,
                EvidenceRecorder,
                ZoneCrossingRequest,
                load_authorizer,
            )

            contract = root / RUNTIME_CONTRACT
            lock = root / ".nornyx/runtime/nornyx.agentic_network.lock"
            if not lock.exists():
                prepared = prepare_runtime_contract(root, as_of=self.as_of)
                if not prepared or not all(item.passed for item in prepared):
                    detail = prepared[-1].detail if prepared else "no preparation result"
                    raise RuntimeError(detail)
            authorizer = load_authorizer(contract, lock, validation_as_of=self.as_of)
            context = EvaluationContext(
                decision_at=self.as_of,
                observed_subject_revision=authorizer.subject_revision,
            )
            self.authorizer = authorizer
            self.context = context
            self._imports = {
                "CapabilityRequest": CapabilityRequest,
                "EvidenceRecorder": EvidenceRecorder,
                "ZoneCrossingRequest": ZoneCrossingRequest,
            }
        except Exception as exc:  # optional dependency / contract preparation boundary
            self.load_error = f"{type(exc).__name__}: {exc}"
            if not allow_fallback:
                raise NornyxRuntimeUnavailable(self.load_error) from exc

    @property
    def mode(self) -> str:
        return "nornyx.agentic" if self.authorizer is not None else "deterministic_fallback"

    def _official(
        self,
        *,
        mission_id: str,
        risk: str,
        action: Callable[[], str],
        action_approval: Mapping[str, Any] | None = None,
        action_request: ActionRequest | None = None,
    ) -> RuntimeDecision:
        assert self.authorizer is not None and self.context is not None
        high_risk = risk.lower() in HIGH_RISK_LEVELS
        # Proposal and effect are separate capabilities. The agent may always
        # request; only the effect capability carries execution authority, so the
        # evidence never shows an `execute_*` capability allowed before the
        # authority for it exists.
        capability_name = (
            "execute_high_risk_effect" if high_risk else "execute_low_risk_action"
        )
        CapabilityRequest = self._imports["CapabilityRequest"]
        ZoneCrossingRequest = self._imports["ZoneCrossingRequest"]
        EvidenceRecorder = self._imports["EvidenceRecorder"]
        recorder = EvidenceRecorder(
            self.authorizer,
            self.context,
            producer_id="nornyx-forge-live-demo",
            producer_version="0.3.0",
            producer_type="external_runtime",
        )
        if high_risk:
            # Recorded so the stream distinguishes "may propose" from "may act".
            request = self.authorizer.evaluate(
                CapabilityRequest("identity.execution", "request_high_risk_action"),
                context=self.context,
            )
            recorder.record_decision(request, mission_id=mission_id)
        capability = self.authorizer.evaluate(
            CapabilityRequest("identity.execution", capability_name),
            context=self.context,
        )
        recorder.record_decision(capability, mission_id=mission_id)
        decision = capability
        if capability.allowed and high_risk:
            decision = self.authorizer.evaluate(
                ZoneCrossingRequest(
                    "identity.execution",
                    "zone.local_demo",
                    "zone.external_customer",
                    None,
                ),
                context=self.context,
            )
            recorder.record_decision(decision, mission_id=mission_id)

        nornyx_effect = getattr(decision.effect, "name", str(decision.effect))
        nornyx_code = decision.code.value
        nornyx_reason = decision.reason or nornyx_code

        # Approving the agentic-network contract is not approving an individual
        # consequential action. A high-risk effect additionally requires an
        # approval bound to this exact request, so a contract approval can never
        # on its own release an external effect, and an approval obtained for one
        # action can never release another. This only ever narrows the decision.
        release_reason = "not evaluated"
        if high_risk and decision.allowed:
            request = action_request or ActionRequest(
                request_id=f"REQ-{mission_id}",
                mission_id=mission_id,
                subject_revision=runtime_revision(self.root),
                capability=capability_name,
                action=ActionDescriptor(
                    operation="execute_high_risk_action",
                    resource=mission_id,
                    destination="zone.external_customer",
                ),
            )
            released, release_reason = validate_action_approval(
                action_approval, request, as_of=self.as_of
            )
            if released:
                # Consume before the effect runs. A claim that loses the race, or
                # that was already spent in an earlier process, withholds here.
                released, release_reason = self.approval_ledger.consume(
                    str(action_approval["approval_id"]),
                    request.digest,
                    at=self.as_of,
                )
            withheld = not released
        else:
            withheld = False
        if withheld:
            recorder.record_observation(
                "action_withheld",
                mission_id=mission_id,
                actor_ref="identity.execution",
                capability_ref=capability_name,
            )

        allowed = decision.allowed and not withheld
        if allowed:
            action()
            recorder.record_observation(
                "tool_invoked",
                mission_id=mission_id,
                actor_ref="identity.execution",
                capability_ref=capability_name,
            )
        stream = recorder.stream()
        report = recorder.validate()
        if isinstance(report, dict):
            report = {
                **report,
                "nornyx_decision": {
                    "effect": nornyx_effect,
                    "code": nornyx_code,
                    "reason": nornyx_reason,
                },
                "action_approval_present": _action_approval_present(action_approval),
                "action_binding": release_reason,
            }
        evidence_dir = self.root / "evidence/runtime/nornyx"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        write_json(evidence_dir / f"{mission_id}.events.json", stream)
        write_json(evidence_dir / f"{mission_id}.report.json", report)
        if withheld:
            return RuntimeDecision(
                effect="DENY",
                code="HUMAN_APPROVAL_REQUIRED",
                reason=(
                    "Nornyx authorized the declared capability, but this high-risk "
                    "effect was not released: " + release_reason + ". Contract "
                    "approval does not authorize an individual consequential action."
                ),
                source="nornyx.agentic",
                evidence=report,
            )
        return RuntimeDecision(
            effect=nornyx_effect,
            code=nornyx_code,
            reason=nornyx_reason,
            source="nornyx.agentic",
            evidence=report,
        )

    def evaluate_and_execute(
        self,
        *,
        mission_id: str,
        risk: str,
        action: Callable[[], str],
        action_approval: Mapping[str, Any] | None = None,
        action_request: ActionRequest | None = None,
    ) -> tuple[RuntimeDecision, str | None]:
        """Authorize and, only if authorized, run one consequential action.

        ``action_approval`` carries an approval for *this specific action*. It is
        deliberately separate from the agentic-network contract approval: the
        contract says the network may hold the capability, not that a particular
        high-risk effect may be released.
        """
        if self.authorizer is not None:
            result: str | None = None

            def capture() -> str:
                nonlocal result
                result = action()
                return result

            decision = self._official(
                mission_id=mission_id,
                risk=risk,
                action=capture,
                action_approval=action_approval,
                action_request=action_request,
            )
            return decision, result
        if not self.allow_fallback:
            raise NornyxRuntimeUnavailable(self.load_error or "Nornyx runtime unavailable")
        # The fallback denies every high-risk action unconditionally. An
        # action-specific approval is an additional requirement on top of Nornyx
        # authorization, never a substitute for it, so it cannot release an
        # action here where no authorization path was established at all.
        if risk.lower() in HIGH_RISK_LEVELS:
            decision = RuntimeDecision(
                "DENY",
                "HUMAN_APPROVAL_REQUIRED",
                "Autonomous demonstration mode cannot grant human production approval.",
                "deterministic_fallback",
                {"status": "fallback", "load_error": self.load_error},
            )
            return decision, None
        result = action()
        decision = RuntimeDecision(
            "ALLOW",
            "ALLOWED",
            "Declared low-risk demonstration capability.",
            "deterministic_fallback",
            {"status": "fallback", "load_error": self.load_error},
        )
        return decision, result
