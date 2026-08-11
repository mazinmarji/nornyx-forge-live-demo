"""Authentication for action-specific consequential approvals.

A review minted its own grant for ``wire $10,000,000 to attacker``, wrote
``approver_type: "human"`` into it, and the boundary released the effect. That
field was never evidence of anything: a grant cannot authenticate itself, any
more than a letter is signed by the sentence "this letter is genuine".

Authority now comes from a detached Ed25519 signature over the complete
canonical grant, verified against a trust store that lives **outside** the
governed repository. The direction matters:

    the grant says      "I am Mazin, operations_owner"
    the trust store says "this key belongs to Mazin, and may act as
                          operations_owner"

Only the second establishes authority. ``approver_type`` is retained as a claim
to be checked against the trusted record, never as security evidence.

SCOPE. This authenticates the Forge *action-specific* consequential approval
boundary. Nornyx network and architecture approval evidence retain their own,
separate assurance model; nothing here should be read as authenticating those.

WHY NOT A SHARED SECRET. An HMAC verifier holds the same key that creates
approvals, so the application could mint its own authority. Ed25519 gives
asymmetric verification with no certificate machinery: the verifier can check a
signature and cannot produce one.

WHY THE TRUST STORE IS EXTERNAL. Committing ``trusted_approvers.json`` into the
governed tree would make root authority editable by whoever edits the
repository — add a key, sign a grant with it, and the boundary agrees. The store
is therefore a runtime dependency supplied from outside: a path outside the
working tree locally, a read-only mount in a container.

WHERE SIGNING LIVES. Not here. The issuer-side utility is
``scripts/issue_action_approval.py``, which the Dockerfile does not copy into the
image. The property being protected is not "this module has no signer" but that
the verifier *process* cannot mint the artifact it accepts — a signer kept in the
package with a comment saying not to call it would leave that resting on nobody
calling it.

WHEN TRUST IS RESOLVED. Once, at startup, into an immutable
:class:`ApprovalTrustStore` that is then injected. Resolving the location per
decision would make the environment an ambient selector of the root of trust:
set a variable between two authorization calls and the second answers to a
different authority. Loading once means an action request cannot alter trust,
and a variable changed after startup has no effect at all.

The environment variable therefore remains a *deployment-time bootstrap*
mechanism. Control of process startup configuration is part of the trusted
deployment boundary, which is a materially narrower claim than saying the
environment is trusted during runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

#: Where the trusted signer keys are read from. A location, never authority:
#: pointing this elsewhere selects a store, it cannot create a trusted key.
TRUST_STORE_ENV = "FORGE_APPROVER_TRUST_STORE"

#: Default location, deliberately outside any repository working tree.
DEFAULT_TRUST_STORE = Path.home() / ".nornyx-forge" / "trusted_approvers.json"

#: The fields a signature covers. Signing only the request digest would leave
#: the role, the window, the approver and the decision itself free to change
#: under a still-valid signature.
SIGNED_FIELDS = (
    "schema",
    "approval_id",
    "request_digest",
    "approver",
    "approver_role",
    "signer_key_id",
    "generated_at",
    "expires_at",
    "granted",
)

APPROVAL_SCHEMA = "nornyx.forge.action_approval.v1"

#: A governance approval is a different statement from an action approval, so it
#: is a different signed payload. An action approval says "this specific effect
#: may be released"; a governance approval says "this governed content is
#: approved". Signing one set of fields and checking the other would authenticate
#: nothing, which is how a verifier built for grants came to be pointed at
#: approval records during remediation — caught before it shipped, and the reason
#: these are separate rather than shared.
GOVERNANCE_APPROVAL_SCHEMA = "nornyx.forge.human_approval_record.v1"

#: Total and ordered, like SIGNED_FIELDS. `subject_revision` is here because an
#: approval of different content is a different approval; the window bounds are
#: here because an approval that can be re-dated is not bounded.
GOVERNANCE_SIGNED_FIELDS = (
    "schema",
    "approval",
    "status",
    "subject_revision",
    "generated_at",
    "expires_at",
    "producer_id",
    "signer_key_id",
)


def canonical_governance_payload(approval: "Mapping[str, Any]") -> bytes:
    """The exact bytes a human approver's signature covers.

    `producer_id` is flattened out of the nested `producer` object so the signed
    material is a flat, totally-ordered mapping — a nested structure invites two
    encoders that disagree, and a signature is only as good as the agreement
    about what was signed.
    """
    producer = approval.get("producer")
    material: dict[str, Any] = {}
    for field_name in GOVERNANCE_SIGNED_FIELDS:
        if field_name == "producer_id":
            material[field_name] = (
                producer.get("id") if isinstance(producer, Mapping) else None
            )
        else:
            material[field_name] = approval.get(field_name)
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Roles a key may hold to approve GOVERNED CONTENT. Closed, and separate from
#: ACTION_APPROVER_ROLES: approving "this content is fit to govern" is not the
#: same authority as approving "this effect may be released", and a vocabulary
#: shared between them would let one key do both by accident.
GOVERNANCE_APPROVER_ROLES = frozenset(
    {"network_governance_owner", "architecture_reviewer"}
)



#: Temporal refusals, distinct because the operator response differs: an expired
#: approval needs a new decision, an unreadable one needs a corrected artifact,
#: and an invalid window means the issuing tool is wrong.
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
APPROVAL_NOT_YET_VALID = "APPROVAL_NOT_YET_VALID"
APPROVAL_TIME_UNREADABLE = "APPROVAL_TIME_UNREADABLE"
APPROVAL_WINDOW_INVALID = "APPROVAL_WINDOW_INVALID"

#: The same seven-day cap the agentic-network module applies to action approvals.
#: A governance approval that outlived it would be a standing authorisation.
GOVERNANCE_APPROVAL_MAX_AGE = timedelta(days=7)


def _aware_instant(value: object) -> datetime | None:
    """Parse to an aware UTC instant, or None when it cannot be read.

    Never a string comparison. `2026-08-10T23:00:00+02:00` is 21:00Z -- earlier
    than `2026-08-10T22:00:00Z` -- but sorts after it as text, so lexical
    comparison gets the dangerous direction wrong. A naive stamp has no instant
    at all, and guessing a zone would decide validity by assumption.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def verify_signed_governance_approval(
    approval: "Mapping[str, Any] | None",
    *,
    trust_store: "ApprovalTrustStore | None" = None,
    as_of: str,
) -> "tuple[bool, str, dict[str, Any]]":
    """Authenticate a human governance approval.

    THE PROPERTY: a governance approval is authoritative only when an externally
    trusted HUMAN identity is cryptographically authenticated FOR THE EXACT ROLE
    it claims, over the EXACT governed subject it names.

    Every clause of that sentence is a separate refusal below, and each returns
    before any later evidence is recorded. The previous version failed three of
    them:

    - ``evidence["role_verified"] = True`` sat outside the ``if claimed_role:``
      guard, so an approval whose ``producer.id`` carried no role skipped the
      role check entirely AND reported that a role had been verified. The
      repository's own fixture used a role-less id, so that was the only path
      the suite ever executed.
    - There was no role vocabulary: any string a trusted key happened to list
      authenticated.
    - ``subject_type`` was never consulted, so a machine key signed an artifact
      saying ``producer.type: "human"`` and became a human approval. The sibling
      action verifier has that check, with a test. Verified where written,
      absent where copied.

    Evidence flags are set only on the line after the check they describe
    passes. A flag that can be true while its check was skipped is a false
    statement in an audit record, which is worse than a missing one.
    """
    evidence: dict[str, Any] = {
        "signature_verified": False,
        "identity_verified": False,
        "role_verified": False,
        "subject_type_verified": False,
    }
    if approval is None:
        return False, "no governance approval was supplied", evidence

    # Fail closed on absence: an empty store must never be the permissive case.
    store = trust_store if trust_store is not None else ApprovalTrustStore()
    evidence["trust_store_digest"] = store.digest
    if not store.signers:
        return (
            False,
            "APPROVER_TRUST_UNAVAILABLE: no approver trust store, so no human "
            f"approval can be authenticated ({store.source})",
            evidence,
        )

    if approval.get("schema") != GOVERNANCE_APPROVAL_SCHEMA:
        return False, f"APPROVAL_SCHEMA_UNKNOWN: {approval.get('schema')!r}", evidence

    key_id = str(approval.get("signer_key_id", ""))
    if not key_id:
        return False, "APPROVAL_UNSIGNED: names no signer key", evidence
    signer = store.signers.get(key_id)
    if signer is None:
        return (
            False,
            f"APPROVER_NOT_TRUSTED: signer key {key_id!r} is not in the approver "
            "trust store",
            evidence,
        )
    if signer.status != "active":
        return (
            False,
            f"APPROVER_NOT_TRUSTED: signer key {key_id!r} is {signer.status}",
            evidence,
        )
    evidence["signer_key_id"] = key_id

    # The trust store decides what a key IS; the artifact only claims. Checked
    # before the signature so a machine key is refused for being a machine.
    if signer.subject_type != "human":
        return (
            False,
            f"APPROVER_NOT_HUMAN: signer key {key_id!r} belongs to a "
            f"{signer.subject_type!r}, which cannot give a human approval "
            "however the artifact describes itself",
            evidence,
        )
    producer = approval.get("producer")
    claimed_type = producer.get("type") if isinstance(producer, Mapping) else None
    if claimed_type != "human":
        return (
            False,
            f"APPROVAL_PRODUCER_NOT_HUMAN: producer.type is {claimed_type!r}",
            evidence,
        )
    evidence["subject_type_verified"] = True

    signature = approval.get("signature")
    if not isinstance(signature, str) or not signature:
        return False, "APPROVAL_UNSIGNED: no signature present", evidence

    try:
        from base64 import b64decode

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        return False, "APPROVAL_VERIFIER_UNAVAILABLE", evidence

    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(signer.public_key))
        public_key.verify(b64decode(signature), canonical_governance_payload(approval))
    except InvalidSignature:
        return False, "APPROVAL_NOT_AUTHENTICATED: signature invalid", evidence
    except Exception as exc:
        return False, f"APPROVAL_NOT_AUTHENTICATED: {type(exc).__name__}", evidence
    evidence["signature_verified"] = True

    claimed = producer.get("id") if isinstance(producer, Mapping) else None
    if not isinstance(claimed, str) or not claimed:
        return False, "APPROVER_IDENTITY_MISSING: producer.id is absent", evidence
    claimed_subject, separator, claimed_role = claimed.partition(":")

    # An empty trusted subject must not silently disable the comparison.
    if not signer.subject:
        return (
            False,
            f"APPROVER_NOT_TRUSTED: key {key_id!r} names no subject, so no "
            "identity can be matched against it",
            evidence,
        )
    if claimed_subject != signer.subject:
        return (
            False,
            f"APPROVER_IDENTITY_MISMATCH: signed as {claimed_subject!r}, key "
            f"belongs to {signer.subject!r}",
            evidence,
        )
    evidence["identity_verified"] = True
    evidence["approver"] = claimed_subject

    # PRESENCE, then authorization. A missing role is a refusal, not a skip:
    # "approved by someone" is not an approval, and omitting the capacity was
    # exactly how the previous version was bypassed.
    if not separator or not claimed_role:
        return (
            False,
            "APPROVER_ROLE_MISSING: producer.id names no role. An approval must "
            "state the capacity it was given in, as 'subject:role'",
            evidence,
        )
    if claimed_role not in GOVERNANCE_APPROVER_ROLES:
        return (
            False,
            f"APPROVER_ROLE_UNAUTHORIZED: {claimed_role!r} is not a governance "
            f"approver role {sorted(GOVERNANCE_APPROVER_ROLES)}",
            evidence,
        )
    if claimed_role not in signer.roles:
        return (
            False,
            f"APPROVER_ROLE_UNAUTHORIZED: {signer.subject!r} may not approve as "
            f"{claimed_role!r}",
            evidence,
        )
    evidence["role_verified"] = True
    evidence["approver_role"] = claimed_role

    # Temporal validity, last and mandatory.
    #
    # The window was SIGNED and never evaluated. Signing the bounds stops them
    # being re-dated; it does not bound anything. Measured against this
    # repository's own fixtures before this clause existed:
    #
    #     generated 2020-01-01 / expires 2020-01-08  -> (True, "authenticated")
    #     expires BEFORE generated                   -> (True, "authenticated")
    #     generated "not-a-time", expires null       -> (True, "authenticated")
    #
    # and the evidence returned `signature_verified`, `identity_verified`,
    # `role_verified` and `subject_type_verified` all true with nothing about
    # time -- the same "a flag can be true while its check was skipped" defect
    # this function's docstring says it removed.
    #
    # The sibling action path enforces exactly this at
    # `nornyx_runtime.validate_action_approval`; the check was present in one
    # code path and absent in its twin.
    moment = _aware_instant(as_of)
    generated = _aware_instant(approval.get("generated_at"))
    expires = _aware_instant(approval.get("expires_at"))
    if moment is None:
        return (
            False,
            f"{APPROVAL_TIME_UNREADABLE}: the evaluation instant {as_of!r} is not "
            "a timezone-aware ISO-8601 timestamp, so validity cannot be judged",
            evidence,
        )
    if generated is None or expires is None:
        return (
            False,
            f"{APPROVAL_TIME_UNREADABLE}: the approval does not carry a readable "
            "timezone-aware validity interval, so it bounds nothing",
            evidence,
        )
    if expires <= generated:
        return (
            False,
            f"{APPROVAL_WINDOW_INVALID}: the approval expires at "
            f"{expires.isoformat()}, at or before it was issued at "
            f"{generated.isoformat()}",
            evidence,
        )
    if expires - generated > GOVERNANCE_APPROVAL_MAX_AGE:
        return (
            False,
            f"{APPROVAL_WINDOW_INVALID}: the approval claims a validity window "
            f"longer than {GOVERNANCE_APPROVAL_MAX_AGE.days} days",
            evidence,
        )
    # Half-open [generated, expires), stated rather than left to a reader of the
    # operators. The instant of issue is valid; the instant of expiry is not.
    if moment < generated:
        return (
            False,
            f"{APPROVAL_NOT_YET_VALID}: the approval becomes valid at "
            f"{generated.isoformat()}, which is after {moment.isoformat()}",
            evidence,
        )
    if moment >= expires:
        return (
            False,
            f"{APPROVAL_EXPIRED}: the approval expired at {expires.isoformat()}, "
            f"at or before {moment.isoformat()}",
            evidence,
        )
    evidence["validity_verified"] = True

    return True, "authenticated", evidence




class TrustStoreUnavailable(RuntimeError):
    """The trust store could not be read, so no signer can be trusted."""


@dataclass(frozen=True)
class TrustedSigner:
    key_id: str
    subject: str
    subject_type: str
    roles: frozenset[str]
    public_key: str
    status: str


def canonical_grant_payload(approval: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers.

    Deterministic and total over :data:`SIGNED_FIELDS`: a missing field is
    rendered explicitly rather than dropped, so removing one cannot produce the
    same bytes as a grant that never had it.
    """

    material = {field: approval.get(field) for field in SIGNED_FIELDS}
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def trust_store_path() -> Path:
    """Resolve the store location. Called once, at startup, never per decision."""
    override = os.getenv(TRUST_STORE_ENV)
    return Path(override) if override else DEFAULT_TRUST_STORE


def _parse_signers(payload: Any, location: Path) -> dict[str, TrustedSigner]:
    entries = payload.get("signers") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise TrustStoreUnavailable(
            f"approver trust store at {location} has no signers list"
        )
    signers: dict[str, TrustedSigner] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise TrustStoreUnavailable("each trusted signer must be an object")
        required = {"key_id", "algorithm", "subject", "subject_type", "roles", "public_key"}
        missing = required - set(entry)
        if missing:
            raise TrustStoreUnavailable(f"trusted signer is missing {sorted(missing)}")
        if entry["algorithm"] != "Ed25519":
            raise TrustStoreUnavailable(
                f"unsupported signature algorithm {entry['algorithm']!r}; only "
                "Ed25519 is accepted"
            )
        if not isinstance(entry["roles"], list) or not entry["roles"]:
            raise TrustStoreUnavailable("a trusted signer must list at least one role")
        signers[str(entry["key_id"])] = TrustedSigner(
            key_id=str(entry["key_id"]),
            subject=str(entry["subject"]),
            subject_type=str(entry["subject_type"]),
            roles=frozenset(str(role) for role in entry["roles"]),
            public_key=str(entry["public_key"]),
            status=str(entry.get("status", "active")),
        )
    return signers


@dataclass(frozen=True)
class ApprovalTrustStore:
    """The trusted signers, fixed at the moment they were loaded.

    Immutable and injected, so an authorization decision consults an object
    rather than the filesystem or the environment. Two decisions in one process
    answer to the same authority by construction, and a variable changed after
    startup cannot re-point the root of trust.
    """

    signers: Mapping[str, TrustedSigner] = field(default_factory=dict)
    digest: str = "sha256:" + hashlib.sha256(b"").hexdigest()
    source: str = "<none>"
    available: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> "ApprovalTrustStore":
        """Read and validate the store once, at startup.

        Absence and malformation are different facts. Absence means no
        consequential authority is available here, an ordinary deployment state.
        Malformation means the store cannot be understood, and must raise rather
        than degrade into an empty mapping that quietly means the same thing.
        """
        location = path or trust_store_path()
        if not location.exists():
            return cls(source=str(location))
        try:
            raw = location.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrustStoreUnavailable(
                f"approver trust store at {location} is unreadable: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return cls(
            signers=_parse_signers(payload, location),
            digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            source=str(location),
            available=True,
        )

    @classmethod
    def for_test(cls, entries: list[dict[str, Any]]) -> "ApprovalTrustStore":
        """An in-memory store for tests. Never constructed by governed code."""
        raw = json.dumps({"signers": entries}, sort_keys=True).encode("utf-8")
        return cls(
            signers=_parse_signers({"signers": entries}, Path("<test>")),
            digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            source="<test>",
            available=True,
        )


def load_trust_store(path: Path | None = None) -> dict[str, TrustedSigner]:
    """The signer mapping alone, for callers that only need to inspect it."""
    return dict(ApprovalTrustStore.load(path).signers)


def verify_signed_approval(
    approval: "Mapping[str, Any] | None",
    *,
    trust_store: "ApprovalTrustStore | None" = None,
) -> "tuple[bool, str, dict[str, Any]]":
    """Decide whether this grant was signed by a key trusted to make it.

    Returns ``(authenticated, reason, evidence)``. The evidence names which
    checks passed and which store answered, and deliberately carries no
    public-key material: a reader needs to know the decision was anchored, not
    to re-derive it.
    """

    store = trust_store if trust_store is not None else ApprovalTrustStore()
    evidence: dict[str, Any] = {
        "signer_key_id": None,
        "trust_store_digest": store.digest,
        "signature_verified": False,
        "identity_verified": False,
        "role_verified": False,
    }

    if not isinstance(approval, Mapping):
        return False, "no action approval was supplied", evidence

    signature = approval.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return (
            False,
            "action approval carries no signature. A self-declared "
            "'approver_type: human' is a claim, not authentication.",
            evidence,
        )

    key_id = approval.get("signer_key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        return False, "action approval names no signer key", evidence
    evidence["signer_key_id"] = key_id

    if not store.available or not store.signers:
        return (
            False,
            "no approver trust store is available, so no signer can be trusted. "
            "The application runs; consequential approval authority does not.",
            evidence,
        )

    signer = store.signers.get(key_id)
    if signer is None:
        return False, f"signer key {key_id!r} is not in the approver trust store", evidence
    if signer.status != "active":
        return False, f"signer key {key_id!r} is {signer.status}, not active", evidence

    # The trust store is the authority on who this key is and what it may do.
    # The grant's own claims are compared against it, never believed over it.
    if signer.subject_type != "human":
        return (
            False,
            f"signer key {key_id!r} belongs to a {signer.subject_type}, which may "
            "not release a consequential human approval",
            evidence,
        )
    claimed_approver = str(approval.get("approver", ""))
    if claimed_approver != signer.subject:
        return (
            False,
            f"approval claims approver {claimed_approver!r} but key {key_id!r} "
            f"belongs to {signer.subject!r}",
            evidence,
        )
    evidence["identity_verified"] = True

    claimed_role = str(approval.get("approver_role", ""))
    if claimed_role not in signer.roles:
        return (
            False,
            f"key {key_id!r} is not trusted to act as {claimed_role!r} "
            f"(trusted roles: {sorted(signer.roles)})",
            evidence,
        )
    evidence["role_verified"] = True

    if approval.get("schema") != APPROVAL_SCHEMA:
        return (
            False,
            f"action approval schema is {approval.get('schema')!r}, expected "
            f"{APPROVAL_SCHEMA!r}",
            evidence,
        )

    try:
        from base64 import b64decode

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - packaging boundary
        return False, f"signature verification is unavailable: {exc}", evidence

    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(signer.public_key))
        public_key.verify(b64decode(signature), canonical_grant_payload(approval))
    except InvalidSignature:
        return (
            False,
            "action approval signature does not match the grant it accompanies. "
            "Any change to the decision, approver, role, window, or bound request "
            "invalidates it.",
            evidence,
        )
    except (ValueError, TypeError) as exc:
        return False, f"action approval signature is malformed: {exc}", evidence

    evidence["signature_verified"] = True
    return True, f"signed by {signer.subject} using trusted key {key_id}", evidence
