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

from . import __version__
from .approval_trust import (
    ApprovalTrustStore,
    TrustStoreUnavailable,
    canonical_grant_payload,
    verify_signed_approval,
)
from .models import GateResult
from .util import write_json

RUNTIME_CONTRACT = ".nornyx/contracts/runtime_network.nyx"
_UNBOUND_REVISION = "git:unbound"
_REVISION_RE = re.compile(r"^(?:git:[0-9a-f]{40}|git:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
_SUBJECT_REVISION_RE = re.compile(
    r"^\s{2}subject_revision:\s*(\S+)\s*$", re.MULTILINE
)


def runtime_as_of(explicit: str | None = None) -> str:
    """Return the instant temporal validity is judged against.

    The trusted source is the real clock. There is deliberately no environment
    override: one existed, and it revived an expired approval and backdated the
    ledger record of its consumption. An environment variable is ambient
    authority — anything in the process can set it, nothing declares that it
    did, and the resulting evidence looks identical to an honest run.

    ``explicit`` is the injection point for deterministic tests. It is a real
    argument a caller must pass on purpose, so a governed path that does not
    pass one cannot be steered from outside.
    """

    if explicit is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not explicit.strip():
        raise ValueError("an explicit evaluation instant must not be blank")
    try:
        parsed = datetime.fromisoformat(explicit.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"evaluation instant must be an ISO-8601 timestamp, got {explicit!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError(f"evaluation instant must be timezone-aware, got {explicit!r}")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def runtime_revision(root: Path | None = None) -> str:
    """Return the governed subject revision the runtime contract declares.

    The contract is the only source. There is deliberately no environment
    override: one existed, and setting it re-aimed a human approval issued for
    one revision onto a different one — the contract said B, the approval said
    A, and the variable made the runtime agree with the approval.

    Returns ``git:unbound`` when no contract is present, which keeps evidence
    honestly labelled rather than claiming a binding that does not exist.
    """

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


def actual_revision(root: Path) -> str | None:
    """The revision actually checked out, read from git and nothing else.

    Returns None when git cannot answer — a deployed artifact has no ``.git``,
    and claiming a verified revision there would be worse than admitting the
    check could not run.
    """

    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return None
    candidate = "git:" + result.stdout.strip()
    return candidate if _REVISION_RE.fullmatch(candidate) else None


_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_evidence_name(value: str) -> str:
    """A filename that cannot escape the directory it is written into.

    Identifiers reach evidence paths, and an identifier is caller-supplied text.
    Everything outside a conservative set becomes an underscore, so no separator
    or parent reference survives into a path.
    """
    cleaned = _UNSAFE_NAME_RE.sub("_", value).strip("._") or "unnamed"
    return cleaned[:120]


#: Why a revision-bound consequential release was refused. Distinct codes,
#: because "I checked and it is wrong" and "I could not check" are different
#: facts and a reviewer must not have to guess which one happened.
GOVERNED_REVISION_MISMATCH = "GOVERNED_REVISION_MISMATCH"
GOVERNED_REVISION_UNVERIFIED = "GOVERNED_REVISION_UNVERIFIED"

#: The grant was not signed by a key the trust store vouches for. Distinct from
#: HUMAN_APPROVAL_REQUIRED: one says nobody approved, the other says someone
#: claimed to and could not be authenticated.
APPROVAL_NOT_AUTHENTICATED = "APPROVAL_NOT_AUTHENTICATED"


@dataclass(frozen=True)
class RuntimeContext:
    """The facts governed authority depends on, and where each one comes from.

    Three revision facts are kept deliberately apart, and never collapsed into
    one value:

    ``actual_revision``    what git says is checked out, or None if it cannot say
    ``declared_revision``  what the contract claims to govern
    ``revision_verified``  whether those were compared and agreed

    Collapsing them is how the earlier version failed open. It returned the
    contract's claim whenever git was unavailable, so a container with no
    ``.git`` reported a revision it had no way to confirm, and a stale contract
    could tell the runtime which revision to believe it was running.

    Time and revision were also readable from the process environment. They are
    not any more: production builds this from trusted sources, a test builds one
    with :meth:`for_test`, and the difference is visible where it is constructed.
    """

    root: Path
    pinned_at: str | None = None
    pinned_revision: str | None = None
    for_test_only: bool = False

    @classmethod
    def trusted(cls, root: Path) -> RuntimeContext:
        """The only context a governed run uses: real clock, verified revision."""
        return cls(root=root)

    @classmethod
    def for_test(
        cls, root: Path, *, at: str | None = None, revision: str | None = None
    ) -> RuntimeContext:
        """A deterministic context for tests. Never constructed by governed code.

        Named for what it is. ``fixed`` read like a supported runtime mode, which
        is exactly the rationalisation that lets a test seam drift into
        production.
        """
        if at is not None:
            runtime_as_of(at)  # validate now, so a bad pin fails at the seam
        if revision is not None and not _REVISION_RE.fullmatch(revision):
            raise ValueError(f"pinned revision is not a revision: {revision!r}")
        return cls(root=root, pinned_at=at, pinned_revision=revision, for_test_only=True)

    def now(self) -> str:
        return runtime_as_of(self.pinned_at)

    @property
    def actual_revision(self) -> str | None:
        """What is really checked out. None when git cannot answer."""
        if self.pinned_revision is not None:
            return self.pinned_revision
        return actual_revision(self.root)

    @property
    def declared_revision(self) -> str:
        """What the contract claims to govern. A claim, never a verification."""
        return runtime_revision(self.root)

    @property
    def revision_verified(self) -> bool:
        """True only when the checkout was derived AND agrees with the contract.

        A pinned test revision counts as verified: the test is the authority for
        its own fixture, and it had to say so explicitly at the seam.
        """
        if self.pinned_revision is not None:
            return True
        actual = self.actual_revision
        if actual is None:
            return False
        declared = self.declared_revision
        return declared == _UNBOUND_REVISION or declared == actual

    def revision_refusal(self) -> tuple[str, str] | None:
        """Why revision-bound authority cannot be exercised here, if it cannot.

        Returns ``(code, reason)`` or None. Called only on the approval-bound
        path: an unverifiable revision must not stop the application starting or
        a low-risk demo running, because neither borrows authority from it.
        """
        if self.revision_verified:
            return None
        actual = self.actual_revision
        if actual is None:
            return (
                GOVERNED_REVISION_UNVERIFIED,
                "the checked-out revision could not be derived independently "
                "(no git metadata, as in a built container), so the contract's "
                "claim about what it governs cannot be confirmed. The "
                "application runs; revision-bound consequential authority does "
                "not.",
            )
        return (
            GOVERNED_REVISION_MISMATCH,
            f"the contract declares it governs {self.declared_revision} but the "
            f"checkout is {actual}. Refusing to act on a revision the governed "
            "subject does not describe.",
        )


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
    """One exact consequential attempt an approval may be bound to.

    Three levels, because collapsing them costs something either way:

    ``mission_id``  the case being worked
    ``request_id``  the consequential request within that mission
    ``attempt_id``  this specific attempt at it

    Consumption is at-most-once per *attempt*. A failed effect leaves its
    attempt spent — that is what makes at-most-once meaningful — but a retry is
    a new attempt within the same mission, needing its own approval bound to it.
    Without the third level, single use would force an operator to invent a new
    mission to retry a refund that failed in transit.
    """

    request_id: str
    mission_id: str
    subject_revision: str
    capability: str
    action: ActionDescriptor
    attempt_id: str = ""

    @property
    def destination(self) -> str:
        return self.action.destination

    @property
    def payload_digest(self) -> str:
        return self.action.payload_digest

    def canonical(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "attempt_id": self.attempt_id,
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


#: The trust zone a released high-risk effect actually crosses into. Declared
#: once so the zone the runtime asks Nornyx about and the destination an approval
#: is bound to cannot drift apart.
EXTERNAL_TRUST_ZONE = "zone.external_customer"


def exercised_capability(risk: str) -> str:
    """The capability a given risk level actually exercises.

    The single derivation. Proposing an action and releasing its effect are
    different capabilities, and which one is in play follows from the risk of the
    act — never from a label a caller supplies.
    """
    return (
        "execute_high_risk_effect"
        if risk.lower() in HIGH_RISK_LEVELS
        else "execute_low_risk_action"
    )


def canonical_action_request(
    *,
    mission_id: str,
    risk: str,
    subject_revision: str,
    descriptor: ActionDescriptor | None = None,
    attempt: int = 1,
) -> ActionRequest:
    """The request the runtime will authorize for this execution context.

    Public so a caller can report or pre-compute exactly what the runtime will
    bind an approval to, without that computation being what the runtime trusts.
    """
    return _canonical_action_request(
        mission_id=mission_id,
        capability=exercised_capability(risk),
        subject_revision=subject_revision,
        descriptor=descriptor,
        attempt=attempt,
    )


def canonical_request_id(mission_id: str) -> str:
    """The only request id valid for a given mission.

    Deriving it from the mission is what makes a request id meaningless outside
    its own execution: the same id under a different mission is a different
    request, and cannot match an approval issued for either one.
    """
    return f"REQ-{mission_id}"


def canonical_attempt_id(mission_id: str, attempt: int) -> str:
    """The only attempt id valid for a given mission and attempt number.

    Derived, not caller-chosen, for the same reason the request id is: an
    attempt label a presenter picks freely would reintroduce exactly the
    replay hole that keying single use on ``approval_id`` created.
    """
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError(f"attempt must be a positive integer, got {attempt!r}")
    return f"{canonical_request_id(mission_id)}#attempt-{attempt}"


def _canonical_action_request(
    *,
    mission_id: str,
    capability: str,
    subject_revision: str,
    descriptor: ActionDescriptor | None,
    attempt: int = 1,
) -> ActionRequest:
    """Describe the act being executed, from the execution context itself.

    Everything that identifies *which* execution this is — mission, request id,
    capability, governed revision, destination — comes from the runtime. Only the
    descriptor's operation, resource and parameters come from the caller, because
    nothing else can know what the opaque callable is meant to do; that is why
    the approval binds to the descriptor rather than to the callable.
    """

    supplied = descriptor or ActionDescriptor(
        operation="execute_high_risk_action",
        resource=mission_id,
        destination=EXTERNAL_TRUST_ZONE,
    )
    return ActionRequest(
        request_id=canonical_request_id(mission_id),
        attempt_id=canonical_attempt_id(mission_id, attempt),
        mission_id=mission_id,
        subject_revision=subject_revision,
        capability=capability,
        action=ActionDescriptor(
            operation=supplied.operation,
            resource=supplied.resource,
            # Pinned to the zone actually crossed, never to a caller's label.
            destination=EXTERNAL_TRUST_ZONE,
            parameters=supplied.parameters,
        ),
    )


def _request_context_mismatch(
    supplied: ActionRequest, canonical: ActionRequest
) -> str | None:
    """Return why a supplied request does not describe this execution, or None.

    Compared field by field rather than by digest so the refusal can name what
    disagreed. A single digest comparison would be equally safe and completely
    unactionable in evidence.
    """

    for field_name, claimed, actual in (
        ("mission_id", supplied.mission_id, canonical.mission_id),
        ("request_id", supplied.request_id, canonical.request_id),
        ("attempt_id", supplied.attempt_id, canonical.attempt_id),
        ("capability", supplied.capability, canonical.capability),
        ("subject_revision", supplied.subject_revision, canonical.subject_revision),
        ("destination", supplied.destination, canonical.destination),
    ):
        if claimed != actual:
            return (
                f"action request {field_name} is {claimed!r} but this execution's "
                f"{field_name} is {actual!r}"
            )
    if supplied.action.canonical() != canonical.action.canonical():
        return (
            "action request describes a different operation than the one being "
            f"executed: {supplied.action.canonical()!r} against "
            f"{canonical.action.canonical()!r}"
        )
    if supplied.digest != canonical.digest:  # pragma: no cover - belt and braces
        return (
            f"action request digest {supplied.digest} does not match this "
            f"execution's {canonical.digest}"
        )
    return None


#: Where consumed action approvals are recorded. Generated runtime state, so it
#: lives under evidence/runtime/ and is never committed.
APPROVAL_LEDGER_ENV = "FORGE_APPROVAL_LEDGER"
DEFAULT_APPROVAL_LEDGER = "evidence/runtime/action_approvals.sqlite3"


def approval_fingerprint(approval: Mapping[str, Any], request: ActionRequest) -> str:
    """Digest the authority a validated grant actually carries.

    The canonical signed payload, which is exactly the material a trusted key
    committed to. Deliberately not ``approval_id``: keying single use on it made
    the control caller-selectable, and the same grant re-presented as ACT-0002
    released the effect again. An id is a label a presenter chooses; it is not
    part of what a human decided.

    Deliberately not the signature bytes either. Ed25519 is deterministic today,
    but keying replay protection on an encoding rather than on meaning is the
    kind of assumption that quietly stops holding.

    Only ever computed from a grant that has already passed authentication and
    ``validate_action_approval``.
    """

    material = canonical_grant_payload(approval)
    return "sha256:" + hashlib.sha256(material).hexdigest()


class ApprovalLedger:
    """Durable, atomic, single-use consumption of action approvals.

    A process-local set forgets everything when the boundary is rebuilt or the
    process restarts, so the same grant could be replayed simply by starting
    again. Consumption is recorded in SQLite under a primary key, so a duplicate
    or concurrent claim loses to the unique constraint rather than to a
    check-then-act race.

    Two constraints, because they answer different questions:

    ``fingerprint`` as primary key stops the same human decision being spent
    twice under different labels. ``request_digest`` as UNIQUE stops the same
    consequential act running twice under *any* decision — which is the promise
    the boundary actually makes to the outside world. A retry after a failed
    effect is a new act and needs a new request, not a second release of the old
    one.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS consumed_approvals ("
                    " fingerprint TEXT PRIMARY KEY,"
                    " request_digest TEXT NOT NULL UNIQUE,"
                    " approval_id TEXT NOT NULL,"
                    " consumed_at TEXT NOT NULL)"
                )
        except (sqlite3.Error, OSError) as exc:
            # A ledger we cannot read is a ledger we cannot trust to say whether
            # a grant was already spent, so refuse in the governed way the rest
            # of this boundary uses rather than crashing out as a raw 500.
            raise NornyxRuntimeUnavailable(
                f"action approval ledger at {self.path} is unusable: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def consume(
        self,
        fingerprint: str,
        request_digest: str,
        *,
        at: str,
        approval_id: str = "",
    ) -> tuple[bool, str]:
        """Claim the approval, or refuse. The insert is the claim.

        Called before the effect runs, so a grant is spent even if the effect
        then fails. That is deliberate: at-most-once is the safe direction for a
        consequential act, and retrying requires a fresh request.

        ``fingerprint`` must come from :func:`approval_fingerprint` over an
        already-validated grant. ``approval_id`` is recorded for provenance only
        and is never part of what makes the claim unique.
        """
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO consumed_approvals"
                    " (fingerprint, request_digest, approval_id, consumed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (fingerprint, request_digest, approval_id, at),
                )
        except sqlite3.IntegrityError:
            spent = self.lookup(fingerprint=fingerprint) or self.lookup(
                request_digest=request_digest
            )
            when = spent["consumed_at"] if spent else "an earlier run"
            if spent and spent["fingerprint"] != fingerprint:
                # Same act, different decision: a second grant cannot release an
                # effect that has already happened.
                return False, (
                    f"this action was already released at {when} under approval "
                    f"{spent['approval_id']!r}; a further approval cannot release "
                    "it again"
                )
            return False, f"this approval was already consumed at {when}"
        except (sqlite3.Error, OSError) as exc:
            # Cannot record the claim, so cannot promise single use. Withhold.
            return False, (
                f"action approval ledger is unusable, so single use cannot be "
                f"guaranteed: {type(exc).__name__}: {exc}"
            )
        return True, f"approval {approval_id or fingerprint} consumed"

    def lookup(
        self, *, fingerprint: str | None = None, request_digest: str | None = None
    ) -> dict[str, str] | None:
        if fingerprint is not None:
            column, value = "fingerprint", fingerprint
        elif request_digest is not None:
            column, value = "request_digest", request_digest
        else:  # pragma: no cover - programming error
            raise TypeError("lookup needs fingerprint or request_digest")
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT fingerprint, request_digest, approval_id, consumed_at"
                    f" FROM consumed_approvals WHERE {column} = ?",
                    (value,),
                ).fetchone()
        except (sqlite3.Error, OSError):
            return None
        if not row:
            return None
        return {
            "fingerprint": row[0],
            "request_digest": row[1],
            "approval_id": row[2],
            "consumed_at": row[3],
        }


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

    @property
    def public_detail(self) -> str:
        """The detail with local filesystem paths removed.

        The full text belongs in operator output; an unauthenticated caller of
        the demo API should not be told the server's directory layout.
        """
        redacted = re.sub(r"[A-Za-z]:\\[^\s'\"]+", "<path>", self.detail)
        redacted = re.sub(r"(?<![\w<])/[^\s'\":]+/[^\s'\":]*", "<path>", redacted)
        return redacted


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
        runtime_context: RuntimeContext | None = None,
        approver_trust_store: ApprovalTrustStore | None = None,
    ) -> None:
        self.root = root
        self.allow_fallback = allow_fallback
        # Trusted by default, and the only alternative is RuntimeContext.for_test,
        # which a caller must name at the construction site. There is no ambient
        # route to either value.
        self.runtime_context = runtime_context or RuntimeContext.trusted(root)
        self.as_of = self.runtime_context.now()
        #: Trusted approver keys, resolved once here rather than per decision.
        #: Looking the location up on every authorization would make the
        #: environment an ambient selector of the root of trust: set a variable
        #: between two calls and the second answers to a different authority.
        #: The store is never inside the governed repository, so editing this
        #: tree cannot add a trusted signer.
        if approver_trust_store is not None:
            self.approver_trust_store = approver_trust_store
        else:
            try:
                self.approver_trust_store = ApprovalTrustStore.load()
            except TrustStoreUnavailable as exc:
                # A store we cannot parse is not an empty store. Hold the
                # refusal rather than starting up as though none was configured.
                self.approver_trust_store = ApprovalTrustStore(source=str(exc))
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
        action_descriptor: ActionDescriptor | None = None,
        attempt: int = 1,
    ) -> RuntimeDecision:
        assert self.authorizer is not None and self.context is not None
        high_risk = risk.lower() in HIGH_RISK_LEVELS
        # Proposal and effect are separate capabilities. The agent may always
        # request; only the effect capability carries execution authority, so the
        # evidence never shows an `execute_*` capability allowed before the
        # authority for it exists.
        capability_name = exercised_capability(risk)
        CapabilityRequest = self._imports["CapabilityRequest"]
        ZoneCrossingRequest = self._imports["ZoneCrossingRequest"]
        EvidenceRecorder = self._imports["EvidenceRecorder"]
        recorder = EvidenceRecorder(
            self.authorizer,
            self.context,
            producer_id="nornyx-forge-live-demo",
            producer_version=__version__,
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
                    EXTERNAL_TRUST_ZONE,
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
        withheld_code = "HUMAN_APPROVAL_REQUIRED"
        authentication_evidence: dict[str, Any] = {}
        if high_risk and decision.allowed:
            # First: is the tree what it claims to be? Asked here and nowhere
            # else, because an unverifiable revision must not stop the
            # application starting or a low-risk demo running — neither borrows
            # authority from it. A consequential release does. Asked before
            # validation and before any ledger claim, so no grant is spent
            # discovering the tree cannot be confirmed.
            refusal = self.runtime_context.revision_refusal()
            if refusal is not None:
                withheld_code, detail = refusal
                release_reason = f"{withheld_code}: {detail}"
            governed_revision = (
                self.runtime_context.actual_revision if refusal is None else None
            )

            # Then: build the request from the execution context and validate the
            # approval against *that*. A caller-supplied request is a claim about
            # what is being executed, not evidence of it — trusting it let an
            # approval issued for one mission release another mission's callback,
            # because every field the approval was checked against came from the
            # same untrusted object.
            request = None if governed_revision is None else _canonical_action_request(
                mission_id=mission_id,
                capability=capability_name,
                subject_revision=governed_revision,
                descriptor=action_descriptor
                or (action_request.action if action_request is not None else None),
                attempt=attempt,
            )
            mismatch = (
                _request_context_mismatch(action_request, request)
                if action_request is not None and request is not None
                else None
            )
            if request is None:
                released = False
            elif mismatch is not None:
                # Refused before approval validation and before the ledger claim,
                # so a mismatched request can neither be judged releasable nor
                # spend a grant that belongs to the request it is imitating.
                released = False
                release_reason = mismatch
            else:
                # Authentication first. Everything after this asks what the grant
                # says; this asks whether anyone trusted actually said it. A
                # self-issued grant claiming `approver_type: human` released a
                # $10,000,000 transfer, because that field was treated as
                # evidence of the thing it merely asserted.
                authentic, authentication, authentication_evidence = verify_signed_approval(
                    action_approval, trust_store=self.approver_trust_store
                )
                if not authentic:
                    released = False
                    release_reason = authentication
                    # Nobody claiming anything is a different fact from someone
                    # claiming and failing to prove it. Collapsing them would
                    # tell an operator to go find a key when the real answer is
                    # that no approval was ever sought.
                    if action_approval is not None:
                        release_reason = f"{APPROVAL_NOT_AUTHENTICATED}: {authentication}"
                        withheld_code = APPROVAL_NOT_AUTHENTICATED
                else:
                    released, release_reason = validate_action_approval(
                        action_approval, request, as_of=self.as_of
                    )
            if released:
                # Consume before the effect runs. A claim that loses the race, or
                # that was already spent in an earlier process, withholds here.
                # Keyed on the validated grant's own authority, never on the
                # approval_id the presenter chose.
                assert action_approval is not None
                released, release_reason = self.approval_ledger.consume(
                    approval_fingerprint(action_approval, request),
                    request.digest,
                    at=self.as_of,
                    approval_id=str(action_approval.get("approval_id", "")),
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
                "approval_authentication": authentication_evidence,
                "revision_verified": self.runtime_context.revision_verified,
                "actual_revision": self.runtime_context.actual_revision,
                "declared_revision": self.runtime_context.declared_revision,
            }
        if withheld and request is not None:
            # Emit the exact request an approver would be signing. Without this
            # an operator has to reconstruct mission, attempt, capability and
            # digest by hand — a second implementation of canonicalization, and
            # the likeliest way to approve the wrong attempt.
            pending_dir = self.root / "evidence/runtime/pending"
            pending_dir.mkdir(parents=True, exist_ok=True)
            write_json(
                pending_dir / f"{_safe_evidence_name(request.attempt_id)}.request.json",
                {
                    "schema": "nornyx.forge.pending_action_request.v1",
                    "request": request.canonical(),
                    "request_digest": request.digest,
                    "attempt_id": request.attempt_id,
                    "withheld_reason": release_reason,
                    "note": (
                        "Sign this exact request_digest with "
                        "scripts/issue_action_approval.py. Approving a different "
                        "attempt releases nothing."
                    ),
                },
            )

        evidence_dir = self.root / "evidence/runtime/nornyx"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        write_json(evidence_dir / f"{mission_id}.events.json", stream)
        write_json(evidence_dir / f"{mission_id}.report.json", report)
        if withheld:
            return RuntimeDecision(
                effect="DENY",
                code=withheld_code,
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
        action_descriptor: ActionDescriptor | None = None,
        attempt: int = 1,
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
                action_descriptor=action_descriptor,
                attempt=attempt,
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
