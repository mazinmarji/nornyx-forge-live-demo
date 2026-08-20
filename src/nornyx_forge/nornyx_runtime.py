from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .approval_trust import (
    ACTION_TRUST_DOMAIN,
    ApprovalTrustStore,
    AuthorityDecision,
    TrustStoreUnavailable,
    authenticate_action_grant,
    canonical_grant_payload,
)
from .governed_subject import (
    GovernanceIntegrityState,
    RuntimeSubject,
    TrustConfiguration,
)
from .util import write_json

RUNTIME_CONTRACT = ".nornyx/contracts/runtime_network.nyx"
_REVISION_RE = re.compile(r"^(?:git:[0-9a-f]{40}|git:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")


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


_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

def evidence_storage_key(value: str) -> str:
    """A filesystem-safe, collision-resistant key for a caller-supplied id.

    Sanitising alone is not enough. Replacing separators maps ``a/b`` and ``a_b``
    onto the same name, so closing a traversal would open an overwrite: one
    mission could silently replace another mission's decision evidence,
    including the record of a refused high-risk effect.

    So the key is a readable slug plus a digest of the *original* identifier.
    The slug is for humans reading a directory listing; the digest is what makes
    it unique. The real identifier is kept inside the payload — a filename is
    storage identity, never governance identity.
    """
    slug = _UNSAFE_NAME_RE.sub("_", value).strip("._")[:64] or "unnamed"
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{slug}--{fingerprint}"


def _safe_evidence_name(value: str) -> str:
    """Deprecated alias; kept so existing call sites cannot regress silently."""
    return evidence_storage_key(value)


class UnknownRiskLevel(ValueError):
    """A risk label outside the declared vocabulary."""


#: The complete risk vocabulary. Closed, deliberately: a label this does not
#: recognise is not "probably low", it is a label nobody has classified.
RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})

#: Distinct from HUMAN_APPROVAL_REQUIRED. "I do not know what this act is" and
#: "I know it is consequential and nobody approved it" call for different fixes.
RISK_LEVEL_UNKNOWN = "RISK_LEVEL_UNKNOWN"


def normalize_risk(value: object) -> str:
    """Return a declared risk level, or refuse.

    Classification used to be membership-tested after ``.lower()``, so anything
    unrecognised fell through to the low-risk path: ``"HIGH-RISK"``, ``"severe"``,
    ``"urgent"`` and ``"High
"`` all skipped the trust-zone crossing and the
    approval requirement, and ran the callable.

    No aliases. If a friendlier vocabulary is wanted, it belongs upstream of this
    boundary, where a mistranslation is a display bug rather than a released
    effect.
    """

    if not isinstance(value, str):
        raise UnknownRiskLevel(
            f"risk must be a string from {sorted(RISK_LEVELS)}, got "
            f"{type(value).__name__}"
        )
    normalized = value.strip().lower()
    if normalized not in RISK_LEVELS:
        raise UnknownRiskLevel(
            f"risk level {value!r} is not one of {sorted(RISK_LEVELS)}. An "
            "unclassified act is not a low-risk act."
        )
    return normalized


#: Why a revision-bound consequential release was refused. Distinct codes,
#: because "I checked and it is wrong" and "I could not check" are different
#: facts and a reviewer must not have to guess which one happened.
#: The runtime cannot establish what it is, so nothing consequential may run.
SUBJECT_UNVERIFIED = "SUBJECT_UNVERIFIED"
#: The governance evidence a decision would rest on does not match what the
#: contracts record. Distinct from SUBJECT_UNVERIFIED: the runtime knows
#: exactly what it is, and what it is has been tampered with.
GOVERNANCE_INTEGRITY_COMPROMISED = "GOVERNANCE_INTEGRITY_COMPROMISED"
#: An authenticated grant describes a different subject than the one running.
#: Deliberately generic: distinguishing "stale assurance" from "different
#: subject" would require both identities as authenticated claims, and a falsely
#: precise diagnostic is worse than an honest broad one.
#:
#: NOT CURRENTLY EMITTED. A review found it defined here and referenced nowhere:
#: no emitter, no test, no documentation. Subject binding IS enforced -- the
#: signed `request_digest` covers `subject_revision`, so a grant for another
#: subject fails authentication before any subject comparison happens -- so this
#: names a refusal path that does not exist as a distinct outcome.
#:
#: Kept rather than deleted because the distinction it draws is the right one if
#: the boundary ever compares subjects directly. An operator grepping for it
#: will find this note instead of concluding the check is missing.
APPROVAL_SUBJECT_MISMATCH = "APPROVAL_SUBJECT_MISMATCH"

#: The grant was not signed by a key the trust store vouches for. Distinct from
#: HUMAN_APPROVAL_REQUIRED: one says nobody approved, the other says someone
#: claimed to and could not be authenticated.
APPROVAL_NOT_AUTHENTICATED = "APPROVAL_NOT_AUTHENTICATED"


@dataclass(frozen=True)
class RuntimeContext:
    """Evaluation time, and where it comes from.

    This carried three revision facts — what git said was checked out, what the
    contract claimed to govern, and whether those agreed. All three are gone.
    The comparison could not succeed: a contract cannot contain the hash of the
    commit that contains it, so `declared == actual` was false at every commit,
    and the only state where it passed was an uncommitted working tree — which
    is precisely the dirty tree the same system refuses.

    Identity is now content, carried by ``RuntimeSubject`` and established once
    at startup rather than rediscovered here. Git remains available as
    provenance through ``subject_observer.observe_source_commit``, and reaches
    no decision.

    Time is still a governed fact and still comes from trusted sources:
    production builds this with :meth:`trusted`, a test with :meth:`for_test`,
    and the difference is visible where it is constructed rather than readable
    from the environment.
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

    # The revision model is gone, not deprecated in place. `actual_revision`
    # shelled out to git from a domain module, and `revision_verified` compared
    # a contract's claim against it — a comparison that was false at every
    # commit, because a contract cannot contain the hash of the commit that
    # contains it. The only state where it passed was an uncommitted working
    # tree, which is precisely the dirty tree the same system refuses.
    #
    # Authority is now content: `RuntimeSubject.governed_subject_digest`,
    # established once at startup and injected here. Git provenance lives in
    # `subject_observer.observe_source_commit` and reaches no decision.


#: Risk levels that require an action-specific human approval, never merely a
#: contract approval, before a consequential effect may be released.
HIGH_RISK_LEVELS = frozenset({"high", "critical"})


#: A human action approval may not outlive this window, matching the P7D cap
#: Nornyx applies to agentic-network approval evidence.
ACTION_APPROVAL_MAX_AGE = timedelta(days=7)

#: Roles permitted to release a consequential effect, per high_risk_action_authority.
ACTION_APPROVER_ROLES = frozenset({"operations_owner", "network_governance_owner"})


def _canonical(value: Any) -> Any:
    """Normalize a value so equal operations always digest identically.

    And so UNEQUAL operations never do. The two halves are not the same
    requirement, and only the first was being met: `str(key)` mapped `{1: ...}`
    and `{"1": ...}` onto one canonical form, so two different requests shared a
    `payload_digest` and an approval bound to one released the other.

    Ambiguity is refused rather than resolved. Coercing the key silently picks
    a winner between two distinct requests; refusing says the descriptor cannot
    be canonicalized and lets the caller spell it unambiguously. JSON has only
    string keys, so no request arriving over the API is affected -- what this
    stops is an in-process caller constructing one that collides.

    `100` and `100.0` still normalize together, deliberately: they are the same
    amount, and that collapse is between two spellings of ONE value rather than
    between two different ones.
    """
    if isinstance(value, Mapping):
        offending = sorted(
            repr(key) for key in value if not isinstance(key, str)
        )
        if offending:
            raise NornyxRuntimeUnavailable(
                "an action descriptor cannot be canonicalized: these keys are "
                f"not strings {offending}. Coercing them would let {{1: ...}} "
                'and {"1": ...} -- two different requests -- share one digest, '
                "so an approval bound to either would release the other."
            )
        return {key: _canonical(value[key]) for key in sorted(value)}
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
    #: The authority subject this attempt is bound to. Named `subject_revision`
    #: for continuity with the field an approval already signs; it now holds a
    #: content digest rather than a git commit, because a commit could not
    #: identify what would execute.
    subject_revision: str
    capability: str
    action: ActionDescriptor
    attempt_id: str = ""
    #: Which authority surface the subject describes, and the revision anchor it
    #: was produced from. Carried for a reader; NEITHER is in `canonical()`, so
    #: neither is covered by the request digest and a caller may put anything
    #: here. An earlier version of this comment claimed both were covered, which
    #: an independent review measured and disproved: two requests differing only
    #: in these fields produce identical digests.
    #:
    #: The property the comment was reaching for does hold, by a different
    #: route. `subject_revision` IS signed and IS compared, and it is the
    #: `governed_subject_digest`, which embeds the scope id, the scope definition
    #: digest and the settled contract bytes. So a grant cannot be re-aimed at a
    #: different scope or assurance state -- because the subject digest differs,
    #: not because these two fields are checked. Stating the real mechanism
    #: matters: a reader who trusted the old comment might add a check here and
    #: believe they had tightened something.
    subject_scope_id: str = ""
    governed_revision_digest: str = ""

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

    The single derivation, over a validated level. Proposing an action and
    releasing its effect are different capabilities, and which one is in play
    follows from the risk of the act — never from a label a caller supplies.

    TWO CAPABILITIES, FOUR RISK LEVELS, and the gap is stated rather than
    implied. `RISK_LEVELS` accepts low, medium, high and critical; the HTTP
    surface accepts all four; `HIGH_RISK_LEVELS` is {high, critical}. So a
    request declaring `medium` exercises `execute_low_risk_action`, which the
    contract declares as `risk: low` with no required gates and no required
    approvals — the same treatment as `low`, despite a vocabulary that reads
    like three tiers.

    That is a deliberate two-tier authorization model, not an oversight in the
    mapping: the boundary distinguishes acts that need a human from acts that
    do not, and `medium` is on the "does not" side. What was misleading is a
    four-level vocabulary implying otherwise. Pinned by
    `test_medium_risk_exercises_the_low_risk_capability` so the mapping is a
    measured fact rather than something a reader has to infer, and so moving
    `medium` across the line is a deliberate diff.
    """
    return (
        "execute_high_risk_effect"
        if normalize_risk(risk) in HIGH_RISK_LEVELS
        else "execute_low_risk_action"
    )


def canonical_action_request(
    *,
    mission_id: str,
    risk: str,
    subject_revision: str,
    descriptor: ActionDescriptor | None = None,
    attempt: int = 1,
    subject_scope_id: str = "",
    governed_revision_digest: str = "",
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
        subject_scope_id=subject_scope_id,
        governed_revision_digest=governed_revision_digest,
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
    subject_scope_id: str = "",
    governed_revision_digest: str = "",
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
        subject_scope_id=subject_scope_id,
        governed_revision_digest=governed_revision_digest,
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


#: The ledger's own establishment record. One row, one column that matters.
#:
#: THE PROPERTY: previously established replay state cannot disappear and then
#: be silently interpreted as legitimate first provisioning.
#:
#: The disclosed residual was: consume G, delete the ledger, run the documented
#: provisioning command, present G again, and G releases. Correct SQL schema
#: does not touch this — the recreated table is right in every respect except
#: that it has forgotten. Distinguishing "first setup" from "setup after the
#: history was removed" needs something the deleted file cannot carry.
#:
#: The move is to stop trying to remember what was spent, and instead make
#: forgetting SELF-DEFEATING. The ledger records when it was established, and a
#: grant is consumable only if the human issued it AFTER that moment. Then:
#:
#:     ledger established T0, grant issued T1 > T0   -> consumable, once
#:     ledger deleted, re-provisioned at T2          -> every grant issued
#:                                                      before T2 is refused
#:     operator obtains a fresh approval at T3 > T2  -> works normally
#:
#: Deleting the replay history therefore makes outstanding grants UNUSABLE
#: rather than reusable. An attacker who removes the file to replay G finds G
#: refused, because G predates the ledger now being asked to vouch for it.
#:
#: What this does and does not defend, stated plainly rather than implied:
#:
#: - Operational loss — a redeploy on ephemeral storage, or an operator running
#:   the documented recovery on an ABSENT ledger — fails closed here, because a
#:   file that is gone is re-provisioned at a later epoch.
#: - A ledger RESTORED from a backup is NOT covered by this anchor, and the
#:   sentence that used to stand here said it was. `established_at` rides back
#:   in with the emptied rows, so the pair looks exactly like an unused ledger.
#:   Measured: one grant, five releases, zero refusals. That case is caught by
#:   the consumption high-water mark below, not by this anchor.
#: - An attacker who can WRITE the ledger can also set `established_at` back and
#:   delete rows. No local anchor survives an adversary with write access to the
#:   thing being anchored, and inventing a second local file would only move the
#:   same weakness. Defending that requires an externally anchored epoch — the
#:   operator's trust store is the natural home — and is recorded in
#:   docs/governance/RUNTIME_INPUT_AUDIT.md as the remaining exposure rather
#:   than papered over here.
LEDGER_METADATA_TABLE = "ledger_identity"

#: The high-water mark of consumptions, held BESIDE the ledger rather than in
#: it. The paragraph above claimed that "an operator 'restoring' a lost ledger
#: with the documented command now fails closed". A review measured otherwise,
#: and so did I when I reproduced it: ONE human approval released FIVE effects.
#:
#: The anchor defeats DELETION, because re-provisioning an absent file mints a
#: later epoch and every outstanding grant then predates it. It cannot defeat
#: RESTORATION, because `established_at` lives inside the file being rolled
#: back -- the old epoch returns alongside the emptied rows, and the pair is
#: indistinguishable from a ledger that was simply set up early and has not
#: been used yet. No adversary is required and the anchor is never set back.
#:
#: A count is the one fact a restore cannot carry back, PROVIDED it is not
#: stored in the thing being restored. Consumption rows only ever accumulate,
#: so a ledger holding fewer rows than were recorded here has lost history.
#:
#: WHAT THIS DOES NOT DEFEND, stated rather than implied: restoring the whole
#: directory carries the sidecar back too, and anyone who can delete the
#: sidecar disables the check. Both need write access to the runtime directory,
#: which is the exposure RUNTIME_INPUT_AUDIT.md already records. What changes
#: is that the ORDINARY operator action -- restore the ledger file from a
#: backup -- now fails closed, which is what the paragraph above claimed.
LEDGER_WATERMARK_SUFFIX = ".highwater"

#: Refusal codes for continuity, distinct because the operator response differs:
#: a grant older than the ledger needs a fresh approval, while a ledger with no
#: identity row at all needs re-provisioning.
GRANT_PREDATES_LEDGER = "GRANT_PREDATES_LEDGER"
LEDGER_CONTINUITY_UNKNOWN = "LEDGER_CONTINUITY_UNKNOWN"
GRANT_ISSUANCE_UNKNOWN = "GRANT_ISSUANCE_UNKNOWN"
#: Distinct from the three above because the operator response differs again:
#: a rolled-back ledger is not a stale grant and not an unreadable anchor. The
#: history is gone and cannot be recovered by re-reading anything.
LEDGER_ROLLED_BACK = "LEDGER_ROLLED_BACK"


def _instant(value: str | None) -> datetime | None:
    """Parse an ISO-8601 instant, or None if it is absent or unreadable.

    Continuity compares two timestamps, and comparing them as STRINGS was a
    real bypass rather than a style problem. `2026-08-10T23:00:00+02:00` is
    21:00Z — earlier than `2026-08-10T22:00:00Z` — but sorts after it, because
    `'2' > 'Z'` is false and the offset digits are compared as text. A grant
    issued before the ledger would have been read as issued after it, which is
    the exact direction the control exists to refuse.

    Both sides are therefore parsed to aware instants and compared as time.
    """
    if value is None or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # A naive stamp has no instant. Guessing a zone here would decide the
        # comparison by assumption, so it is treated as unreadable.
        return None
    return parsed.astimezone(timezone.utc)


#: Every object the ledger database may contain, by name. A CLOSED set: the
#: replay property is defeated not by a missing constraint but by an EXTRA
#: object -- a trigger that discards the insert, or a view that shadows the
#: table a later read consults. Both are engine metadata and both leave every
#: uniqueness check passing, so the question asked here is "what is in this
#: database" rather than "is what I expected present".
#: BY (KIND, NAME), not by name. Filtering on the name alone discarded the kind
#: it had just unpacked, and SQLite lets a TRIGGER share a TABLE's name -- so
#: `CREATE TRIGGER consumed_approvals BEFORE INSERT ON consumed_approvals BEGIN
#: SELECT RAISE(IGNORE); END` passed the guard whose docstring above names that
#: exact attack. Measured: one grant released five effects, wrote zero
#: consumption rows, and left `established_at` intact, so the continuity anchor
#: never fired either. The four hostile tests all named their trigger `t`, so
#: the control was never reached and 42 tests passed with it fully bypassed.
#:
#: Indexes are permitted BY KIND with any name, because a UNIQUE index is a
#: legitimate way to enforce the property and refusing it by name rejected
#: correctly-built ledgers -- the same defect in the safe direction.
PERMITTED_LEDGER_OBJECTS = frozenset(
    {("table", "consumed_approvals"), ("table", "ledger_identity")}
)

#: Object kinds that may appear under any name. An index cannot discard, rewrite
#: or shadow a row; a trigger and a view can, so neither is here.
PERMITTED_LEDGER_KINDS = frozenset({"index"})

#: SQLite's own statistics tables, which `ANALYZE` and `PRAGMA optimize` create.
#: They are DATA ABOUT the index, consulted by the query planner; they cannot
#: discard, rewrite or shadow a consumption row, which is the property this
#: closed set exists to protect.
#:
#: Refusing them made an ordinary maintenance command permanently fatal:
#: measured, one `PRAGMA optimize` left `ApprovalLedger(path)` raising forever,
#: so no effect could ever be released again -- and the refusal blamed "a
#: trigger or view", naming a hazard that was not present. Failing closed is
#: right; failing closed FOREVER for a statistics table, while misdescribing
#: what it found, is not.
PERMITTED_LEDGER_STATISTICS = frozenset(
    {"sqlite_stat1", "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"}
)

#: Columns the consumption record must carry. Names, because `consume` writes by
#: name: a table missing one accepts the INSERT nowhere or silently drops it.
REQUIRED_LEDGER_COLUMNS = frozenset(
    {"fingerprint", "request_digest", "approval_id", "consumed_at"}
)

#: Single-column uniqueness the authorization model depends on, and what each
#: one is actually promising.
#:
#: `fingerprint` stops one human decision being spent twice under different
#: labels. `request_digest` stops one consequential act running twice under ANY
#: decision. They answer different questions, so both are required and each is
#: checked separately.
REQUIRED_LEDGER_UNIQUE_COLUMNS = {
    "fingerprint": "one human decision could be spent twice under different labels",
    "request_digest": "one consequential act could run twice under different decisions",
}


def _read_established_at(conn: sqlite3.Connection) -> str | None:
    """When this replay history began, or None when it cannot say.

    Two rows is not "pick the first one". A ledger carrying two establishment
    instants cannot say when its history began, and reading it with `fetchone()`
    silently chose between them in whatever order SQLite happened to return --
    which made an extra row a way to move the anchor rather than an error. The
    table constrains itself to one row; this refuses to guess if it ever holds
    more, because the constraint is only present on ledgers this code created.
    """
    try:
        rows = conn.execute(
            f"SELECT established_at FROM {LEDGER_METADATA_TABLE}"
        ).fetchall()
    except sqlite3.Error:
        return None
    if len(rows) != 1:
        return None
    return str(rows[0][0]) if rows[0][0] else None


def _assert_ledger_structure(
    conn: sqlite3.Connection, path: Path, code: str
) -> None:
    """Refuse a ledger whose structure cannot enforce single use.

    THE PROPERTY: replay state is accepted only when the database itself
    enforces the uniqueness the authorization model assumes. Not when it claims
    to; when it does.

    This previously matched the strings "primary key" and "unique" against
    `sqlite_master.sql` — the original DDL *text*, comments included. An
    independent review put both words in comments over a constraint-free table
    and released one grant three times. The check was written because "checking
    that a table called consumed_approvals exists was checking the label on the
    box"; matching the DDL text read the label in a different font.

    SQLite's own metadata is the authority here, because it describes what the
    engine will ENFORCE rather than what someone wrote. `PRAGMA index_list`
    reports every index with its uniqueness and origin; `PRAGMA index_info`
    reports the columns each covers. A comment cannot appear in either, and
    neither can a constraint that was described but not created.

    Partial indexes are rejected: a `UNIQUE ... WHERE` index enforces uniqueness
    only over the rows matching its predicate, so rows outside it may repeat.
    """
    # THE SCHEMA IS CLOSED, not merely sufficient.
    #
    # `PRAGMA index_list` reports what the engine will CONSTRAIN. It says
    # nothing about what the engine will DO with the write. One statement --
    #
    #     CREATE TRIGGER t BEFORE INSERT ON consumed_approvals
    #     BEGIN SELECT RAISE(IGNORE); END
    #
    # -- makes every consumption a silent no-op: no IntegrityError, so `consume`
    # reports success forever, the table stays empty, and every uniqueness and
    # continuity check above still passes. Measured before this existed: five
    # callbacks from one grant, zero rows, `established_at` intact, the ledger
    # reporting itself sound. An `AFTER INSERT ... DELETE` trigger behaves
    # identically, and a view can shadow the name a later query reads.
    #
    # A trigger IS engine metadata and IS what the engine will do, so the fix is
    # to enumerate every object rather than to add "no triggers" to a list of
    # things checked. Anything not in the permitted set is refused, because the
    # next hostile object is the one nobody enumerated.
    # THE CANDIDATE SET IS ESTABLISHED BEFORE CLOSURE IS EVALUATED, and nothing
    # is excluded on the way in. That ordering is the property; the previous
    # query inverted it --
    #     SELECT ... WHERE name NOT LIKE 'sqlite_%'
    # -- so objects were filtered out BEFORE the closure check could consider
    # them, and a hostile member that fell in the excluded range was never a
    # candidate to reject. A set that calls itself closed cannot be filtered on
    # the way in.
    #
    # Two live bypasses came from that inversion, and they are different in
    # kind, which is why fixing the pattern would not have been fixing the
    # defect: `_` is a single-character LIKE wildcard, so `sqliteXshadow` was
    # discarded by ordinary CREATE TRIGGER, while `PRAGMA writable_schema`
    # reached the literal `sqlite_` prefix. Measured on both: one fingerprint
    # granted five times, zero consumption rows persisted.
    #
    # Ordinary SQLite structure is still accepted, because it is judged rather
    # than skipped: `sqlite_autoindex_*` arrives as kind `index`, which is in
    # PERMITTED_LEDGER_KINDS. Anything else in that namespace is unexpected and
    # must be refused -- which is what the excluding query made impossible.
    present = {
        (kind, name) for kind, name in conn.execute(
            "SELECT type, name FROM sqlite_master"
        )
    }
    unexpected = sorted(
        f"{kind} {name!r}"
        for kind, name in present
        if kind not in PERMITTED_LEDGER_KINDS
        and (kind, name) not in PERMITTED_LEDGER_OBJECTS
        and not (kind == "table" and name in PERMITTED_LEDGER_STATISTICS)
    )
    if unexpected:
        raise NornyxRuntimeUnavailable(
            f"action approval ledger at {path} is unusable: {code}, it carries "
            f"objects the replay model does not permit: {unexpected}. A trigger "
            "or view can silently discard, rewrite or shadow a consumption "
            "record while every uniqueness check still passes."
            + (
                ""
                if any(kind.startswith("trigger") or kind.startswith("view")
                       for kind in unexpected)
                else " Note that none of the objects listed is a trigger or a "
                "view; the refusal is that the set is CLOSED, not that this "
                "particular object was recognised as dangerous."
            )
        )
    # Deliberately NOT the mirror image. A ledger MISSING `ledger_identity` is
    # not an outage: `_read_established_at` returns None by design and `consume`
    # denies with LEDGER_CONTINUITY_UNKNOWN, which is a decision that names the
    # unanswered question. Requiring the table here would report that decision as
    # a broken database instead, merging two different security states -- and
    # absence, unavailability and invalidity are not the same thing. What is
    # closed here is the set of things that may be PRESENT.

    columns = {row[1] for row in conn.execute("PRAGMA table_info(consumed_approvals)")}
    if not columns:
        raise NornyxRuntimeUnavailable(
            f"action approval ledger at {path} is unusable: {code}, it holds no "
            "consumed_approvals table"
        )

    missing = REQUIRED_LEDGER_COLUMNS - columns
    if missing:
        raise NornyxRuntimeUnavailable(
            f"action approval ledger at {path} is unusable: {code}, "
            f"consumed_approvals is missing columns {sorted(missing)}"
        )

    # Every column covered by a full single-column unique index, whatever
    # syntax produced it: PRIMARY KEY, a UNIQUE constraint, or CREATE UNIQUE
    # INDEX all appear here identically, which is the point of asking the engine.
    enforced: set[str] = set()
    for _seq, name, unique, _origin, partial in conn.execute(
        "PRAGMA index_list(consumed_approvals)"
    ):
        if not unique or partial:
            continue
        covered = [row[2] for row in conn.execute(f"PRAGMA index_info({name!r})")]
        if len(covered) == 1:
            enforced.add(covered[0])

    for column, consequence in REQUIRED_LEDGER_UNIQUE_COLUMNS.items():
        if column not in enforced:
            raise NornyxRuntimeUnavailable(
                f"action approval ledger at {path} is unusable: {code}, nothing "
                f"enforces uniqueness on {column!r}, so {consequence}"
            )


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

    #: Emitted when the ledger cannot answer "was this grant already spent?".
    #: Distinct codes, because the operator response differs: a ledger that was
    #: never provisioned needs provisioning, and one that has gone missing needs
    #: investigating.
    MISSING = "APPROVAL_LEDGER_MISSING"
    UNREADABLE = "APPROVAL_LEDGER_UNREADABLE"
    UNWRITABLE = "APPROVAL_LEDGER_UNWRITABLE"

    @classmethod
    def provision(cls, path: Path, *, established_at: str | None = None) -> ApprovalLedger:
        """Create the ledger. Explicit, and never reached from the boundary.

        Separate from opening one because creation used to happen at the point
        of use: `CREATE TABLE IF NOT EXISTS` on every construction meant deleting
        the file produced an empty ledger in which nothing had been spent, and
        every previously consumed grant became replayable. Deleting a file is not
        an authorization decision, and it must not act like one.

        ``established_at`` follows :func:`runtime_as_of`: the trusted clock by
        default, with an explicit argument a caller must pass on purpose so a
        test can build a coherent time frame. It is deliberately not an
        environment variable — ambient authority over when a replay history
        began would let anything in the process decide which grants outlive it.
        Setting it back is not a new exposure: it needs the same write access
        that could edit the rows directly, which is the disclosed residual.

        Re-provisioning a live ledger preserves the original instant, so running
        the documented setup command on a healthy ledger does not invalidate
        every outstanding approval.
        """
        location = Path(path)
        location.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(location, timeout=30, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS consumed_approvals ("
                    " fingerprint TEXT PRIMARY KEY,"
                    " request_digest TEXT NOT NULL UNIQUE,"
                    " approval_id TEXT NOT NULL,"
                    " consumed_at TEXT NOT NULL)"
                )
                # When this replay history began. A grant issued before it
                # cannot be vouched for by it, so losing the history makes
                # outstanding grants unusable rather than reusable.
                connection.execute(
                    f"CREATE TABLE IF NOT EXISTS {LEDGER_METADATA_TABLE} ("
                    # Exactly one row, enforced by the database rather than by
                    # the care of whoever writes to it. Without the constraint
                    # a second INSERT simply appended, and the reader's
                    # `fetchone()` took whichever row SQLite returned first --
                    # so a ledger could carry two establishment instants and
                    # quietly choose between them. A mutation that made
                    # provisioning re-insert on every call survived the suite
                    # for exactly that reason.
                    " id INTEGER PRIMARY KEY CHECK (id = 1),"
                    " established_at TEXT NOT NULL)"
                )
                if not connection.execute(
                    f"SELECT established_at FROM {LEDGER_METADATA_TABLE}"
                ).fetchone():
                    connection.execute(
                        f"INSERT INTO {LEDGER_METADATA_TABLE} (id, established_at)"
                        " VALUES (1, ?)",
                        (runtime_as_of(established_at),),
                    )
        except (sqlite3.Error, OSError) as exc:
            raise NornyxRuntimeUnavailable(
                f"action approval ledger at {location} could not be provisioned: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        finally:
            connection.close()
        # Opened through the ordinary constructor, so what comes back has passed
        # exactly the checks any other caller's ledger passes. Building the
        # instance directly would hand back an object that had skipped them, and
        # a field added to `__init__` later would silently not exist here.
        return cls(location)

    def __init__(self, path: Path) -> None:
        """Open an existing ledger. Creates nothing.

        Absent and broken are different facts and get different treatment.

        A ledger that was never provisioned is a deployment that has not been
        set up yet. Recorded, not raised: constructing the boundary must not fail
        merely because replay state is absent, or a repository with no ledger
        could not answer read-only questions either. Consequential acts refuse
        at `consume`, which is the only place replay state is authority.

        A ledger that exists but cannot be read or written is a fault in a
        deployment that believes it *is* set up. That still raises, so it
        surfaces as unavailable rather than as a policy refusal — reporting a
        broken database as DENY would describe an outage as a decision.
        """
        self.path = Path(path)
        self.unavailable_reason = ""
        self.established_at: str | None = None

        if not self.path.is_file():
            self.unavailable_reason = (
                f"{self.MISSING}: no ledger at {self.path}. Replay protection "
                "cannot be asserted over state that does not exist; provision it "
                "explicitly rather than letting a consequential act create it."
            )
            return

        try:
            with self._session() as conn:
                _assert_ledger_structure(conn, self.path, self.UNREADABLE)
                self.established_at = _read_established_at(conn)

                # An INSERT that fails *after* the boundary has decided to
                # release an effect is the worst moment to discover the ledger is
                # read-only, so find out now.
                #
                # `BEGIN IMMEDIATE` was the whole pre-flight and it SUCCEEDS on a
                # read-only SQLite database -- measured, along with
                # `PRAGMA journal_mode=WAL` and `ROLLBACK`, all three fine. Only
                # the INSERT fails. So the check was a no-op for exactly the
                # state it names, `UNWRITABLE` was emitted by nothing anywhere in
                # the repository, and the refusal that did arrive carried no code
                # at all. A write is the only thing that proves writability.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "INSERT INTO consumed_approvals"
                        " (fingerprint, request_digest, approval_id, consumed_at)"
                        " VALUES (?, ?, ?, ?)",
                        ("__preflight__", "__preflight__", "", ""),
                    )
                finally:
                    # ALWAYS, so the probe row can never survive into the
                    # history it is checking. A ledger that recorded its own
                    # pre-flight would be a ledger that lies about what it spent.
                    conn.execute("ROLLBACK")
        except (sqlite3.Error, OSError) as exc:
            # A ledger we cannot read is a ledger we cannot trust to say whether
            # a grant was already spent, so refuse in the governed way the rest
            # of this boundary uses rather than crashing out as a raw 500.
            readonly = "readonly" in str(exc).lower() or "attempt to write" in str(exc).lower()
            raise NornyxRuntimeUnavailable(
                f"{self.UNWRITABLE if readonly else self.UNREADABLE}: action "
                f"approval ledger at {self.path} is unusable: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    @property
    def available(self) -> bool:
        return not self.unavailable_reason

    def _connect(self) -> sqlite3.Connection:
        # `mode=rw`, NOT the default. `sqlite3.connect(path)` CREATES the file,
        # so the point-of-use creation this class removed came back in a second
        # spelling: `consume` on a deleted ledger left a 0-byte file behind, and
        # the next NornyxActionBoundary raised on it -- so a missing ledger
        # stopped meaning "refuse consequential acts" and started meaning "serve
        # nothing at all, including low-risk read-only work". Two written claims
        # said otherwise: "Open an existing ledger. Creates nothing." and
        # A-014's "the boundary opens it and never creates it".
        connection = sqlite3.connect(
            f"file:{self.path.as_posix()}?mode=rw", uri=True,
            timeout=30, isolation_level=None,
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """A connection that is actually closed afterwards.

        `with sqlite3.connect(...) as conn` commits the transaction and leaves
        the connection open — a detail that reads exactly like a closing context
        manager and is not one. Every consumption and lookup leaked one, which
        on Windows holds a lock on the ledger file and elsewhere just exhausts
        descriptors slowly enough to look like something else.
        """
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def consume(
        self,
        fingerprint: str,
        request_digest: str,
        *,
        at: str,
        grant_issued_at: str,
        approval_id: str = "",
    ) -> tuple[bool, str]:
        """Claim the approval, or refuse. The insert is the claim.

        Called before the effect runs, so a grant is spent even if the effect
        then fails. That is deliberate: at-most-once is the safe direction for a
        consequential act, and retrying requires a fresh request.

        ``fingerprint`` must come from :func:`approval_fingerprint` over an
        already-validated grant. ``approval_id`` is recorded for provenance only
        and is never part of what makes the claim unique.

        A ledger that cannot answer refuses. "I do not know whether this grant
        was already spent" and "this grant has not been spent" are different
        answers, and only one of them may release an effect.
        """
        if not self.available:
            return False, self.unavailable_reason

        # RE-VALIDATED HERE, not only at construction. The structure check ran
        # once in __init__, and the ledger file lives in the directory the
        # governed process writes to on every request -- bind-mounted read-write
        # in docker-compose.yml, and excluded from review by .gitignore. A
        # hostile object installed after establishment was never seen again.
        #
        # This is the last moment before the claim, so it is the moment that
        # matters: everything after this line assumes the insert is the claim.
        # `closing`, not `with sqlite3.connect(...)`: the connection context
        # manager commits or rolls back the TRANSACTION and leaves the handle
        # open. On Windows that open handle makes the file undeletable, and four
        # tests that delete a ledger to prove a spent grant stays spent failed
        # with PermissionError -- the repair breaking the proofs around it.
        # THE ANCHOR IS READ HERE TOO, on the same connection and at the same
        # moment. It was read once in __init__ and cached, so a boundary object
        # that outlived the documented ledger restore kept vouching for a grant
        # the restore existed to invalidate: measured, a surviving object
        # granted a second consumption of one fingerprint while a freshly
        # constructed one refused it, the two differing only in WHEN the object
        # was built. No attacker required -- an operator running the documented
        # recovery while a request is in flight produces it.
        #
        # The structure check was already re-run here for exactly this reason
        # ('a hostile object installed after establishment was never seen
        # again'). The anchor lives in the same file, in the same directory,
        # with the same write exposure, and was not.
        established_now: str | None = self.established_at
        # THE MARK IS READ FIRST, THEN THE ROW COUNT, AND THE ORDER IS THE
        # WHOLE CORRECTNESS ARGUMENT. Rows only accumulate and the mark trails
        # them, so a mark read at T1 can never exceed rows read at T2 > T1 --
        # unless history was actually rolled back. Reading them the other way
        # round would let a concurrent consumption advance the mark between the
        # two reads and refuse a legitimate grant. Eight-process races are
        # already measured here; this must not regress them.
        recorded = self._recorded_consumptions()
        held = 0
        try:
            # `_connect()`, not a bare `sqlite3.connect`: the bare form CREATES
            # the file, and this line is reached precisely when the ledger may
            # be gone. It left a 0-byte residue that every later boundary then
            # raised on.
            with closing(self._connect()) as conn:
                _assert_ledger_structure(conn, self.path, self.UNREADABLE)
                established_now = _read_established_at(conn)
                held = int(
                    conn.execute(
                        "SELECT count(*) FROM consumed_approvals"
                    ).fetchone()[0]
                )
        except NornyxRuntimeUnavailable as exc:
            return (
                False,
                f"{self.UNREADABLE}: the ledger structure changed after it was "
                f"established, so a claim cannot be trusted: {exc}",
            )
        except sqlite3.Error as exc:
            # "unusable" is the established vocabulary for this refusal, and a
            # test asserts on it. Inventing a second phrase for the same state
            # would leave two ways to say one thing and one of them unchecked.
            return (
                False,
                f"{self.UNREADABLE}: the ledger at {self.path} is unusable — it "
                f"could not be re-read before the claim ({exc}), and an "
                "unanswerable question is not a free one",
            )

        # Continuity. A ledger cannot say whether a grant older than itself was
        # already spent, so it must not pretend the grant is fresh.
        #
        # `grant_issued_at` is a required argument rather than an optional one.
        # It was optional, defaulting to None, and the boundary passed
        # `str(approval.get("generated_at", "")) or None` — so an approval with
        # no issuance stamp produced None and skipped this check entirely. An
        # unanswered question was being read as a satisfied one.
        # `established_now`, not `self.established_at`: the cached value is the
        # one that let a spent grant through.
        established = _instant(established_now)
        if established is None:
            return (
                False,
                f"{LEDGER_CONTINUITY_UNKNOWN}: {self.path} carries no readable "
                f"establishment record ({established_now!r}), so it cannot "
                "say which grants it has seen. Re-provision it deliberately.",
            )
        issued = _instant(grant_issued_at)
        if issued is None:
            return (
                False,
                f"{GRANT_ISSUANCE_UNKNOWN}: the approval does not state a "
                f"readable issuance instant ({grant_issued_at!r}), so it cannot "
                "be placed against this replay history. An approval that will "
                "not say when it was issued is not evidence that it is unspent.",
            )
        if issued < established:
            return (
                False,
                f"{GRANT_PREDATES_LEDGER}: the approval was issued at "
                f"{grant_issued_at}, before this replay history began at "
                # `established_now`, NOT `self.established_at`. The decision two
                # lines up uses the anchor re-read at the claim; this message
                # used the cached one, so a refusal artifact written into
                # runtime evidence named the stale instant and asserted an
                # inequality that is false -- "2026-08-02 is before
                # 2026-08-01" -- while the decision itself was right. The
                # regression test asserted only that the CODE appeared, so the
                # value went unmeasured. A governance record that states a
                # falsehood is worse than one that says less.
                f"{established_now}. Replay state was lost or replaced, so "
                "whether this grant was already spent is unknown. A fresh human "
                "approval is required; the old one cannot regain usability.",
            )

        # ROLLBACK, checked AFTER continuity so the established diagnostic wins
        # wherever it applies. A DELETED ledger is re-provisioned at a later
        # epoch, so continuity already refuses it as GRANT_PREDATES_LEDGER and
        # two tests assert exactly that; firing here first would have renamed a
        # refusal that was already correct. This case is the one continuity
        # CANNOT see: the anchor rode back in with the restore, so it agrees
        # the grant is fresh, and only the count disagrees.
        #
        # `recorded is None` is not zero. A ledger from before this check, or
        # one whose sidecar was removed, has nothing to compare against, and
        # reading that as zero would refuse every ledger that has ever been
        # used. It bootstraps on the next successful consumption instead.
        if recorded is not None and held < recorded:
            return False, (
                f"{LEDGER_ROLLED_BACK}: this ledger holds {held} consumption "
                f"records but {recorded} were recorded against it. Replay "
                "history was rolled back, so a grant already spent would be "
                "released again. Re-provision the ledger and obtain a fresh "
                "approval; restoring a backup cannot restore what it forgot."
            )


        try:
            with self._session() as conn:
                conn.execute(
                    "INSERT INTO consumed_approvals"
                    " (fingerprint, request_digest, approval_id, consumed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (fingerprint, request_digest, approval_id, at),
                )
                # THE WRITE IS VERIFIED, not assumed. `INSERT` succeeding is
                # not the same fact as a row existing: a BEFORE INSERT trigger
                # running RAISE(IGNORE) discards it and reports success. The
                # structure check above refuses such a trigger, but it runs on
                # a different connection a moment earlier, and a review
                # measured 943 claims granted with no row by flapping a trigger
                # inside that window -- the original 'one grant, N effects,
                # zero rows' defeat, relocated from WHAT the check looks at to
                # WHEN it looks.
                #
                # Reading the row back ON THE SAME CONNECTION, immediately
                # after the INSERT, catches whatever discarded it.
                #
                # NOT "inside the same transaction", which is what this said and
                # is false: `_connect` sets `isolation_level=None`, so the
                # connection is in autocommit and the row is COMMITTED before
                # this SELECT runs -- a separate connection can already see it.
                # The enumerated attack is still caught, because a trigger fires
                # within the INSERT statement itself and its effect is visible
                # here; but "closes the window regardless of timing" claimed a
                # transactional guarantee that no transaction provides.
                landed = conn.execute(
                    "SELECT count(*) FROM consumed_approvals"
                    " WHERE fingerprint = ? AND request_digest = ?",
                    (fingerprint, request_digest),
                ).fetchone()
                if not landed or int(landed[0]) != 1:
                    return (
                        False,
                        f"{self.UNREADABLE}: the consumption row for this grant "
                        "was not written, so single use cannot be guaranteed. "
                        "The insert reported success and the ledger holds "
                        f"{0 if not landed else landed[0]} matching rows -- "
                        "something is discarding writes.",
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
        # AFTER the row is confirmed, never before: a mark advanced ahead of a
        # write that then failed would refuse the next legitimate grant.
        self._record_consumptions(held + 1)
        return True, f"approval {approval_id or fingerprint} consumed"

    @property
    def watermark_path(self) -> Path:
        """Beside the ledger, deliberately not inside it."""
        return Path(str(self.path) + LEDGER_WATERMARK_SUFFIX)

    def _recorded_consumptions(self) -> int | None:
        """The high-water mark, or None if this ledger has never written one.

        None is NOT zero. A ledger predating this check, or one whose sidecar
        was removed, has no mark to compare against; treating that as zero
        would refuse every legitimate ledger with rows in it.
        """
        try:
            text = self.watermark_path.read_bytes().decode("utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return None
        try:
            return int(text)
        except ValueError:
            return None

    def _record_consumptions(self, count: int) -> None:
        """Advance the mark, never lower it.

        `max` because two processes can consume concurrently: whichever writes
        second must not undo the other's advance. Lowering the mark would only
        ever weaken the check, so it is refused arithmetically rather than by
        locking.
        """
        standing = self._recorded_consumptions() or 0
        try:
            self.watermark_path.write_bytes(str(max(standing, count)).encode("utf-8"))
        except OSError:
            # A mark we cannot write is a weaker future check, not a reason to
            # refuse an effect whose row is already committed.
            pass

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
            with self._session() as conn:
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


def verify_action_approval(
    approval: Mapping[str, Any] | None,
    request: ActionRequest,
    *,
    trust_store: ApprovalTrustStore | None,
    as_of: str,
) -> AuthorityDecision:
    """Decide whether ACTION authority was granted to release exactly this request.

    THE ONLY entry point a consequential boundary may use. The clauses are
    joined here rather than at the call site, because a call site that composes
    them is a call site that can stop composing them -- and the composition was
    the whole property. Measured before this API existed, all three of these
    passed the repository's structural guard while defeating the control:

        authentic, _, _ = verify_signed_approval(...)   # discard the validator
        if False: validate_action_approval(...)         # unreachable branch
        released = authentic                            # authentication as authority

    Only the behavioural boundary test caught them. Now there is nothing to
    discard: authentication does not return a decision, and the decision cannot
    be reached without it.

        cryptographic authentication of a trusted human key
        AND membership in the ACTION trust domain
        AND a role valid for consequential release
        AND that domain trusting this key to claim that role
        AND binding to this exact request
        AND temporal validity

    Replay is NOT a clause here. It is a stateful claim on the ledger, taken by
    the boundary after this returns, so that a decision cannot be spent by a run
    that never starts.
    """
    signer = authenticate_action_grant(approval, trust_store=trust_store)
    evidence: dict[str, Any] = {
        **signer.as_evidence(),
        "signer_authenticated": signer.signer_authenticated,
        "role_verified": False,
    }

    def refuse(reason: str) -> AuthorityDecision:
        return AuthorityDecision(
            authority=ACTION_TRUST_DOMAIN,
            granted=False,
            reason=reason,
            evidence=evidence,
        )

    if not signer.signer_authenticated:
        return refuse(signer.reason)

    # BOTH clauses. `network_governance_owner` is deliberately present in the
    # governance vocabulary AND this one, so neither the role name nor the key
    # identity may bridge a domain it was not provisioned into: the second
    # clause asks the ACTION store, and only the action store.
    claimed_role = signer.claimed_role or ""
    if claimed_role not in ACTION_APPROVER_ROLES:
        return refuse(
            f"APPROVER_ROLE_UNAUTHORIZED: approver role {claimed_role!r} may not "
            "release a high-risk effect"
        )
    if claimed_role not in signer.trusted_roles:
        return refuse(
            f"APPROVER_ROLE_UNAUTHORIZED: {signer.signer_subject!r} may not "
            f"approve as {claimed_role!r} in the {ACTION_TRUST_DOMAIN} trust domain"
        )
    evidence["role_verified"] = True
    evidence["approver_role"] = claimed_role

    released, reason = _bind_action_approval(approval, request, as_of=as_of)
    evidence["binding_verified"] = released
    return AuthorityDecision(
        authority=ACTION_TRUST_DOMAIN,
        granted=released,
        reason=reason,
        evidence=evidence,
    )


def _bind_action_approval(
    approval: Mapping[str, Any] | None,
    request: ActionRequest,
    *,
    as_of: str,
) -> tuple[bool, str]:
    """Bind an ALREADY-AUTHENTICATED grant to *this* request, and only this one.

    Private, and named for what it does. It answers no question about who
    signed and none about trust, so on its own it is not an authority and must
    never be read as one -- the public entry point is
    :func:`verify_action_approval`.

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
        # DEFAULTS TO ABSENT, not to "human". This read
        # `approval.get("approver_type", "human")` while the VERIFIER reads
        # `approval.get("approver_type", "")` and refuses an absent producer as
        # APPROVAL_PRODUCER_NOT_HUMAN. Measured on the issuer's own output
        # before the producer field was emitted: this reported
        # `action_approval_present: True` into the evidence record while the
        # verifier refused the same artifact. Two defaults for one field, in
        # opposite directions, so the report and the decision disagreed.
        and str(approval.get("approver_type", "")).lower() == "human"
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
        runtime_subject: RuntimeSubject | None = None,
        governance_integrity: GovernanceIntegrityState | None = None,
        frozen_action_trust: ApprovalTrustStore | None = None,
        action_trust_store: ApprovalTrustStore | None = None,
        trust: TrustConfiguration | None = None,
        established_root: str = "",
    ) -> None:
        # ONE TREE. `root` selects the contract and the lock; the injected
        # subject and integrity verdict describe whatever tree the application
        # observed at startup. Nothing required those to be the same, so a
        # caller could have policy from tree A judged against an identity from
        # tree B -- reachable from `nornyx-forge demo --offline`, which passes a
        # root of its own. An authority conclusion that spans two trees
        # describes neither.
        # Scoped to the case that actually produces a cross-tree conclusion: a
        # root that CARRIES ITS OWN CONTRACT. `root` selects two different
        # things -- the governing contract and lock, and where evidence and the
        # ledger are written -- and that conflation is the real defect here.
        # Refusing every differing root would also refuse writing evidence to a
        # scratch directory, which supplies no policy from anywhere: with no
        # contract present the boundary falls back and denies high-risk outright,
        # so no authority conclusion spans two trees. What must not happen is
        # tree A's contract judging tree B's identity, and that requires tree A
        # to have a contract.
        if (
            established_root
            and Path(root).resolve() != Path(established_root)
            and (Path(root) / RUNTIME_CONTRACT).exists()
        ):
            raise NornyxRuntimeUnavailable(
                f"this boundary was built for {Path(root).resolve()} but the "
                f"security context describes {established_root}. The contract "
                "and lock would come from one tree while the governed subject "
                "and integrity verdict describe another, so the decision would "
                "belong to neither."
            )
        self.root = root
        self.allow_fallback = allow_fallback
        # Injected, never discovered. A boundary that established its own
        # subject would let the request influence the authority judging it.
        self.runtime_subject = runtime_subject
        #: Injected, never observed here. The domain does not reach a
        #: filesystem to decide its own trustworthiness; the application
        #: establishes this alongside the subject and hands both down.
        self.governance_integrity = governance_integrity
        # Trusted by default, and the only alternative is RuntimeContext.for_test,
        # which a caller must name at the construction site. There is no ambient
        # route to either value.
        self.runtime_context = runtime_context or RuntimeContext.trusted(root)
        #: Trusted approver keys, resolved once here rather than per decision.
        #: Looking the location up on every authorization would make the
        #: environment an ambient selector of the root of trust: set a variable
        #: between two calls and the second answers to a different authority.
        #: The store is never inside the governed repository, so editing this
        #: tree cannot add a trusted signer.
        #: The resolved trust anchors, when the caller established them at
        #: startup. Falling back to resolving them here is what a boundary built
        #: outside an application does — a test, or a script — and it is exactly
        #: the per-construction environment read that R3 removes from the
        #: serving path.
        self.trust = trust
        if action_trust_store is not None:
            self.action_trust_store = action_trust_store
        elif frozen_action_trust is not None:
            # The store the application parsed at startup. Preferred over the
            # path because a location is not authority: reopening the file per
            # boundary meant an edit between two requests changed who the second
            # one trusted, with the same context serving both.
            self.action_trust_store = frozen_action_trust
        else:
            try:
                self.action_trust_store = ApprovalTrustStore.load(
                    Path(trust.approver_store) if trust is not None else None,
                    domain=ACTION_TRUST_DOMAIN,
                )
            except TrustStoreUnavailable as exc:
                # A store we cannot parse is not an empty store. Hold the
                # refusal rather than starting up as though none was configured.
                self.action_trust_store = ApprovalTrustStore(
                    source=str(exc), domain=ACTION_TRUST_DOMAIN, unusable=True
                )
        #: Durable single-use ledger. Survives boundary and process restarts.
        #: Never provisioned here: a boundary that could create its own replay
        #: state could also reset it.
        self.approval_ledger = ApprovalLedger(
            Path(trust.approval_ledger)
            if trust is not None
            else approval_ledger_path(root)
        )
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
                # The boundary refuses; it does not repair. Preparing the
                # runtime contract here meant a consequential boundary could
                # invoke the Nornyx CLI to manufacture the very lock it was
                # about to rely on — self-healing its own preconditions, from a
                # domain module, at authorization time. Preparation is a
                # startup concern and lives in `runtime_preparation`.
                raise RuntimeError(
                    f"RUNTIME_LOCK_MISSING: {lock} does not exist. Run "
                    "`nornyx-forge prepare-runtime` before serving governed "
                    "traffic; the action boundary will not create the lock it "
                    "depends on."
                )
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
    def as_of(self) -> str:
        """The trusted instant, read WHEN A DECISION IS MADE.

        This was `self.as_of = self.runtime_context.now()` in `__init__`, so a
        boundary judged every approval window it ever saw at the instant it was
        CONSTRUCTED. The magnitude is bounded -- the boundary is per
        `CustomerCaseFlow`, and the one worker call between construction and
        the execution stage caps at `timeout_seconds=180` -- but the direction
        is wrong in principle: a grant that expired during the run was still
        judged against a stale clock.

        `RuntimeContext.now()` is a per-call method precisely so this can be
        asked repeatedly, and `RuntimeContext.for_test(at=...)` pins it, so
        deterministic tests are unaffected. The only test of the boundary's
        instant constructed it with `for_test` -- the declared pin -- so it
        could not observe that the production path pinned itself too. That is
        the ordering an independent review named: the object built the one way
        the property holds.
        """
        return self.runtime_context.now()

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
        high_risk = normalize_risk(risk) in HIGH_RISK_LEVELS
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
        # INTEGRITY IS ASKED FIRST, WHICH IS WHAT THIS COMMENT ALWAYS SAID.
        # The block below used to sit inside `if high_risk and
        # decision.allowed:`, AFTER three `authorizer.evaluate` calls, while
        # stating it ran "before the authorizer is consulted, because a
        # compromised contract is what the authorizer would be reading". A
        # review measured the authorizer reading it three times first.
        #
        # Worse, the guard made the refusal conditional on the compromised
        # material's own verdict. When tampering made the contract DENY, the
        # branch was never entered and the `refused_action_attempt.v1` record
        # -- added precisely so an operator could see a consequential act
        # attempted against a compromised runtime -- was never written.
        # Measured: contract allows -> 1 refusal record; contract denies -> 0.
        # Whether the operator learned of the compromise was decided BY the
        # compromised material.
        #
        # Now unconditional and first. `high_risk` is not a precondition
        # either: a compromised governance state is not more acceptable for a
        # low-risk act, it simply has less to release.
        # Integrity, immediately after subject and before any decision.
        #
        # Derived governance state -- an evidence record's `status`, a
        # recorded `content_hash` -- is deliberately outside the inspection
        # subject, because binding an inspection to values the tooling
        # rewrites made authenticated inspection unreachable. That exclusion
        # is only admissible while compromise of those values withdraws
        # every authority depending on them, and runtime authority did not:
        # mutating either changed the Nornyx verdict, left the subject
        # untouched, and this boundary released the effect and spent the
        # approval regardless.
        #
        #     derived status mutated   effect=ALLOW callbacks=1 spent=True
        #     content_hash mutated     effect=ALLOW callbacks=1 spent=True
        #
        # Asked before the request is built, so no grant is spent finding
        # out, and before the authorizer is consulted, because a compromised
        # contract is what the authorizer would be reading.
        integrity = self.governance_integrity
        if integrity is None or not integrity.authorizes_consequential_action:
            reason = (
                "the governance evidence this runtime would be judged "
                "under does not match what the contracts record: "
                + (
                    "; ".join(integrity.problems[:3])
                    if integrity is not None
                    else "no integrity observation was established"
                )
                + ". Consequential authority is unavailable until the "
                "evidence set is regenerated and re-approved."
            )
            # Recorded, not just returned. This refusal wrote nothing at
            # all: no event stream, no report, no case record -- so an
            # operator could not see that a consequential act had been
            # attempted against a runtime whose own governance state was
            # compromised. That is the attempt most worth being able to
            # find afterwards.
            #
            # A Nornyx event stream is not available here and is not
            # invented: this runs before the authorizer is consulted,
            # deliberately, because a compromised contract is what the
            # authorizer would be reading. What is written is a refusal
            # record in its own schema, which claims nothing about a
            # governance decision that was never made.
            record = {
                "schema": "nornyx.forge.refused_action_attempt.v1",
                "mission_id": mission_id,
                "risk": normalize_risk(risk),
                "attempt": attempt,
                "code": GOVERNANCE_INTEGRITY_COMPROMISED,
                "reason": reason,
                "integrity_status": (
                    integrity.status if integrity is not None else "unobserved"
                ),
                "integrity_problems": list(
                    integrity.problems if integrity is not None else ()
                ),
                "action_approval_present": _action_approval_present(action_approval),
                "approval_consumed": False,
                "effect_released": False,
                "refused_at": self.as_of,
            }
            refusals = self.root / "evidence/runtime/refused"
            refusals.mkdir(parents=True, exist_ok=True)
            write_json(
                refusals
                / (evidence_storage_key(mission_id + "#attempt-" + str(attempt))
                   + ".refused.json"),
                record,
            )
            return RuntimeDecision(
                effect="DENY",
                code=GOVERNANCE_INTEGRITY_COMPROMISED,
                reason=reason,
                source=self.mode,
                evidence=record,
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
        # AUTHORIZED WHERE CLAIMED. `canonical_action_request` pins
        # `destination=EXTERNAL_TRUST_ZONE` on EVERY request, whatever its risk
        # -- that is what an approver signs and what the digest binds. The
        # crossing was then evaluated only for high risk, so a low or medium
        # action asserted a crossing into the external zone that nothing ever
        # authorized, and the evidence stream carried no `trust_zone_crossed`
        # decision to show for the claim it had already made.
        #
        # Risk selects WHICH CAPABILITY is exercised. It does not decide whether
        # a boundary between trust zones is real.
        if capability.allowed:
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
            # The tree-identity question used to be asked here by comparing a
            # git checkout against a contract's claim. That comparison is gone:
            # it was false at every commit, and its only passing state was an
            # uncommitted working tree. Content identity replaces it, and the
            # subject carrying it is established once at startup and injected —
            # R1-D wires it in. Until then this path releases nothing on the
            # strength of a revision, because there is no revision concept left
            # to be wrong about.
            # First: is the subject established? A runtime that cannot say what
            # it is cannot release a consequential effect. Asked before anything
            # else, so no grant is spent discovering it.

            subject = self.runtime_subject
            if subject is None or not subject.subject_verified:
                release_reason = (
                    f"{SUBJECT_UNVERIFIED}: the governed subject is not "
                    "established, so consequential authority is unavailable. "
                    + (subject.unavailable_reason or "" if subject else
                       "no runtime subject was injected into this boundary.")
                )
                request = None
            else:
                # Then: build the request from the execution context. A
                # caller-supplied request is a claim about what is executing,
                # not evidence of it — trusting it let an approval issued for
                # one mission release another mission's callback.
                #
                # Subject identity comes from the established subject, never
                # from the caller, and is covered by the request digest.
                request = _canonical_action_request(
                    mission_id=mission_id,
                    capability=capability_name,
                    subject_revision=subject.governed_subject_digest,
                    subject_scope_id=subject.scope_id,
                    governed_revision_digest=subject.governed_revision_digest,
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
                # ONE authority call. Not authentication composed with a
                # validator: composing them here is what let a self-issued grant
                # claiming `approver_type: human` release a $10,000,000 transfer,
                # because a field was read as evidence of the thing it asserted.
                # The clauses now live behind the API, where a caller cannot
                # forget one.
                authority = verify_action_approval(
                    action_approval,
                    request,
                    trust_store=self.action_trust_store,
                    as_of=self.as_of,
                )
                released = authority.granted
                release_reason = authority.reason
                authentication_evidence = authority.evidence
                # Nobody claiming anything is a different fact from someone
                # claiming and failing to prove it. Collapsing them would tell an
                # operator to go find a key when the real answer is that no
                # approval was ever sought.
                if (
                    not released
                    and action_approval is not None
                    and not authority.evidence.get("signer_authenticated")
                ):
                    release_reason = f"{APPROVAL_NOT_AUTHENTICATED}: {authority.reason}"
                    withheld_code = APPROVAL_NOT_AUTHENTICATED
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
                    # No `or None`: an absent stamp must reach the ledger as an
                    # empty string and be refused, not vanish into a default
                    # that means "do not check".
                    grant_issued_at=str(action_approval.get("generated_at", "")),
                )
                # THE LEDGER'S OWN CODE SURVIVES TO THE DECISION. Every
                # high-risk non-release used to report `HUMAN_APPROVAL_REQUIRED`
                # -- no approval, an expired one, and a REPLAYED grant were
                # indistinguishable in `RuntimeDecision.code`, while
                # GRANT_PREDATES_LEDGER, LEDGER_CONTINUITY_UNKNOWN,
                # GRANT_ISSUANCE_UNKNOWN and LEDGER_ROLLED_BACK were defined
                # three hundred lines above with a comment saying they are
                # distinct "because the operator response differs".
                #
                # They differ a great deal: obtain a fresh approval, versus
                # re-provision a ledger, versus stop and investigate a rollback.
                # An operator reading the evidence could not tell which.
                if not released:
                    for ledger_code in (
                        LEDGER_ROLLED_BACK,
                        GRANT_PREDATES_LEDGER,
                        LEDGER_CONTINUITY_UNKNOWN,
                        GRANT_ISSUANCE_UNKNOWN,
                    ):
                        if release_reason.startswith(ledger_code):
                            withheld_code = ledger_code
                            break
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
        #: Set when the effect was released and then raised. Not a decision --
        #: the decision was ALLOW and it stands -- but the record has to say
        #: that what happened next is unknown.
        release_failure = ""
        if allowed:
            try:
                action()
            except BaseException as exc:  # noqa: BLE001 - re-raised below
                # THE GRANT IS ALREADY SPENT. `consume` runs before the effect,
                # deliberately, because at-most-once is the safe direction. But
                # the exception used to propagate straight out of here, past the
                # recorder and past both `write_json` calls -- so a consequential
                # act that may have partially happened left the ledger row and
                # NOTHING ELSE: no event stream, no report, no case record. The
                # one situation where an operator most needs to know what was
                # attempted produced the least evidence of any path through this
                # method.
                #
                # No `tool_invoked` observation: that is a SUCCESS terminal in
                # the evidence vocabulary and the tool did not complete. The
                # failure is carried in the report instead, because inventing an
                # event type the schema does not define would make the stream
                # unvalidatable -- and an unvalidatable stream is not evidence.
                release_failure = f"{type(exc).__name__}: {exc}"
                self._emit_evidence(
                    mission_id=mission_id,
                    attempt=attempt,
                    recorder=recorder,
                    nornyx_effect=nornyx_effect,
                    nornyx_code=nornyx_code,
                    nornyx_reason=nornyx_reason,
                    action_approval=action_approval,
                    release_reason=release_reason,
                    authentication_evidence=authentication_evidence,
                    release_failure=release_failure,
                )
                raise
            recorder.record_observation(
                "tool_invoked",
                mission_id=mission_id,
                actor_ref="identity.execution",
                capability_ref=capability_name,
            )
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

        report = self._emit_evidence(
            mission_id=mission_id,
            attempt=attempt,
            recorder=recorder,
            nornyx_effect=nornyx_effect,
            nornyx_code=nornyx_code,
            nornyx_reason=nornyx_reason,
            action_approval=action_approval,
            release_reason=release_reason,
            authentication_evidence=authentication_evidence,
        )
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

    def _emit_evidence(
        self,
        *,
        mission_id: str,
        attempt: int,
        recorder,
        nornyx_effect: str,
        nornyx_code: str,
        nornyx_reason: str,
        action_approval,
        release_reason: str,
        authentication_evidence,
        release_failure: str = "",
    ) -> dict:
        """Write the event stream and the report. The ONLY place either is written.

        Extracted because the effect-raises path used to write neither: the
        exception propagated out of `_official` before the recorder was drained,
        so a spent grant produced a ledger row and no other trace at all. Two
        copies of this would drift, and the copy on the failure path is the one
        nobody exercises.
        """
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
            }
            if release_failure:
                # SUCCESS and FAILURE-AFTER-RELEASE are different states, and
                # neither is a denial. The decision was ALLOW and it stands;
                # what the effect did is unknown, and saying so is the point.
                report["effect_release"] = {
                    "released": True,
                    "completed": False,
                    "outcome": "unknown",
                    "error": release_failure,
                    "note": (
                        "The approval was consumed before the effect ran, so it "
                        "is spent. Whether the effect took place, partially or "
                        "at all, cannot be determined from here. A fresh human "
                        "approval is required for any retry."
                    ),
                }
        evidence_dir = self.root / "evidence/runtime/nornyx"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        # The identifier is data in the payload, never a path component.
        #
        # KEYED ON THE ATTEMPT, not the mission. `evidence_storage_key`'s own
        # docstring says the digest exists because "one mission could silently
        # replace another mission's decision evidence, including the record of
        # a refused high-risk effect". The hazard survived one level down: the
        # same mission's ATTEMPTS collided, and the retry model this design
        # mandates is what produced them. Measured across three attempts at one
        # mission: one events file, one report, and attempts 1 and 2 left no
        # record of their own -- while the pending artifacts beside them were
        # already per-attempt.
        storage_key = evidence_storage_key(mission_id + "#attempt-" + str(attempt))
        write_json(evidence_dir / f"{storage_key}.events.json", stream)
        write_json(evidence_dir / f"{storage_key}.report.json", report)
        return report

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
        # Before anything: is this act classified at all? An unrecognised label
        # used to fall through to the low-risk path, skipping the trust-zone
        # crossing and the approval requirement entirely, and running the
        # callable. Refused here, ahead of both the official and fallback paths,
        # so no callback runs and no approval is consumed finding out.
        try:
            normalize_risk(risk)
        except UnknownRiskLevel as exc:
            return (
                RuntimeDecision(
                    effect="DENY",
                    code=RISK_LEVEL_UNKNOWN,
                    reason=str(exc),
                    source="nornyx.agentic" if self.authorizer else "deterministic_fallback",
                    evidence={
                        "status": "refused",
                        "risk_level_declared": risk if isinstance(risk, str) else repr(risk),
                        "risk_vocabulary": sorted(RISK_LEVELS),
                    },
                ),
                None,
            )

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
        if normalize_risk(risk) in HIGH_RISK_LEVELS:
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
