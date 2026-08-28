"""Authenticate an independent inspection. Verification only; no signing here.

The artifact deciding whether an independent inspection happened was
unauthenticated. A ~120-line validator (`load_inspection_attestation`, since
deleted) checked shape exhaustively — required fields, one result per role,
subject digest, a producer that is not `type: human` — and authenticated
nothing. Independence was read straight off the file:

    state["independent"] = attested.get("builder_self_approval") is False

A builder asserting its own non-self-approval is the control defeating itself.
Writing one file flipped `assurance_state` from `not_independently_inspected` to
`independently_inspected` with `problems: []`.

Worse, no test could have caught it: the suite's positive fixture writes exactly
that artifact and asserts it must produce `independently_inspected`. The exploit
was encoded as required behaviour.

So independence stops being a claim and becomes a derivation:

    authenticated reviewer identity != authenticated builder identity
    AND that reviewer's key is authorized for the inspector role it reports

REVIEWER KEYS ARE NOT APPROVER KEYS

A separate store, separate roles, separate file. An action approver signs "this
effect may be released"; an inspector signs "I looked at this content and found
these things". Letting one key satisfy both would mean the party authorizing a
payment could also certify that the code releasing it had been independently
reviewed.

Like the approval trust store, this holds public keys only and lives outside the
governed tree — editing the repository cannot add a trusted reviewer, and the
runtime image ships no signing capability.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

REVIEWER_STORE_ENV = "FORGE_REVIEWER_TRUST_STORE"
DEFAULT_REVIEWER_STORE = Path.home() / ".nornyx" / "forge_reviewer_trust.json"

ATTESTATION_SCHEMA = "nornyx.forge.inspection_attestation.v2"

#: Everything a reviewer's signature covers. Total and ordered: a missing field
#: is rendered explicitly rather than dropped, so removing one cannot produce
#: the same bytes as an attestation that never had it.
#:
#: `findings_digest` is signed so findings cannot be edited after review;
#: `tool` and `tool_version` because "which model, at what version, looked at
#: this" is part of what an inspection claims; `inspection_subject_digest`
#: because an inspection of different content is a different inspection.
SIGNED_FIELDS = (
    "schema",
    "inspection_subject_digest",
    "reviewer",
    "reviewer_key_id",
    "inspector_role",
    "verdict",
    "findings_digest",
    "produced_at",
    "tool",
    "tool_version",
)

#: Roles an inspection must cover before it counts as complete.
REQUIRED_INSPECTOR_ROLES = frozenset(
    {"test-inspector", "architecture-inspector", "security-inspector"}
)

BUILDER_IDENTITY_ENV = "FORGE_BUILDER_IDENTITY"

#: Identities that can never count as an independent inspector, whatever the
#: environment says.
BUILDER_IDENTITIES = frozenset({"builder.nornyx_forge"})


def excluded_inspector_identities() -> frozenset[str]:
    """Who may not inspect. Ambient input adds to this set and never removes.

    The environment variable used to *replace* the builder identity, which meant
    setting it to an unrelated name removed the real builder from the set — and
    a builder who also held a trusted reviewer key would then authenticate as
    independent. The control was still running; it had just been aimed somewhere
    harmless.

    Union, so ambient state can only tighten. An operator naming an additional
    builder excludes one more identity; nobody can exclude fewer.
    """
    named = os.getenv(BUILDER_IDENTITY_ENV, "").strip()
    return BUILDER_IDENTITIES | ({named} if named else frozenset())


class ReviewerStoreUnavailable(RuntimeError):
    """The reviewer store could not be read, so no reviewer can be trusted."""


@dataclass(frozen=True)
class TrustedReviewer:
    key_id: str
    reviewer: str
    roles: frozenset[str]
    public_key: str
    status: str

    def may_inspect_as(self, role: str) -> bool:
        return self.status == "active" and role in self.roles


def canonical_attestation_payload(attestation: Mapping[str, Any]) -> bytes:
    """The exact bytes a reviewer's signature covers."""
    material = {field_name: attestation.get(field_name) for field_name in SIGNED_FIELDS}
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def findings_digest(findings: Any) -> str:
    """Bind the findings themselves, so they cannot be edited after signing."""
    canonical = json.dumps(findings, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def reviewer_store_path() -> Path:
    """Resolved once, at startup. Never per verification."""
    override = os.getenv(REVIEWER_STORE_ENV)
    return Path(override) if override else DEFAULT_REVIEWER_STORE


def _assert_loadable_public_key(key_id: str, material: str) -> None:
    """A key that cannot be loaded is not a key, and the store is not usable.

    Refused at PARSE time so the failure names the STORE. Deferred to the first
    signature check -- which is where it lived -- a reviewer store whose only
    `public_key` was the string "not a PEM key at all" loaded without raising,
    reported `available: True`, and then refused with
    `ATTESTATION_NOT_AUTHENTICATED: ValueError`, blaming the attestation for a
    fault entirely in the store.

    This is verbatim the defect `approval_trust._assert_loadable_public_key`
    records as closed for the approver store. It was closed there and never
    re-derived here.

    PEM, NOT RAW BASE64. `verify_inspection_attestation` loads these keys with
    `load_pem_public_key`; the approver store's equivalent uses
    `Ed25519PublicKey.from_public_bytes` over base64. A check must load a key
    the same way the verifier will, or it certifies a format nobody uses.
    """
    try:
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            load_pem_public_key,
        )
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        return
    try:
        load_pem_public_key(material.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any failure means unusable
        raise ReviewerStoreUnavailable(
            f"trusted reviewer {key_id!r} carries public key material that "
            f"cannot be loaded ({type(exc).__name__}), so this store cannot "
            "authenticate any independent inspection and must not report "
            "itself available"
        ) from exc


def _parse_reviewers(payload: Any, location: Path) -> Mapping[str, TrustedReviewer]:
    if not isinstance(payload, Mapping):
        raise ReviewerStoreUnavailable(f"{location} is not a reviewer trust store")
    if payload.get("schema") != "nornyx.forge.reviewer_trust_store.v1":
        raise ReviewerStoreUnavailable(
            f"{location} declares schema {payload.get('schema')!r}, which is not a "
            "reviewer trust store. An approver store is deliberately a different "
            "thing and must not be accepted here."
        )
    entries = payload.get("reviewers")
    if not isinstance(entries, list):
        raise ReviewerStoreUnavailable(f"{location} has no reviewers list")

    reviewers: dict[str, TrustedReviewer] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ReviewerStoreUnavailable(f"{location} holds a malformed reviewer")
        key_id = str(entry.get("key_id", ""))
        public_key = str(entry.get("public_key", ""))
        if not key_id or not public_key:
            raise ReviewerStoreUnavailable(f"{location} holds a reviewer without a key")
        if key_id in reviewers:
            raise ReviewerStoreUnavailable(
                f"{location} lists key_id {key_id!r} twice; which reviewer it means "
                "would depend on ordering"
            )
        roles = entry.get("roles")
        if not isinstance(roles, list) or not roles:
            raise ReviewerStoreUnavailable(
                f"{location}: reviewer {key_id!r} is authorized for no role"
            )
        _assert_loadable_public_key(key_id, public_key)
        reviewers[key_id] = TrustedReviewer(
            key_id=key_id,
            reviewer=str(entry.get("reviewer", "")),
            roles=frozenset(str(role) for role in roles),
            public_key=public_key,
            status=str(entry.get("status", "active")),
        )
    # READ-ONLY, because `frozen=True` on the store freezes the REFERENCE and
    # not what it points at. A review inserted an attacker key into the "frozen
    # startup snapshot" after load and authenticated a FORGED independent
    # inspection -- signed with a key present in no store on disk -- while
    # `store.digest`, the value an audit would compare, stayed unchanged.
    #
    # `approval_trust._parse_signers` already returns `MappingProxyType` for
    # exactly this reason, recorded there against exactly this demonstration.
    # The authority protected here is the one CLAUDE.md names as the only thing
    # that can clear SOD_EVIDENCE_PRODUCER_UNKNOWN, so the two stores being out
    # of step ran the dangerous way round.
    return MappingProxyType(reviewers)


@dataclass(frozen=True)
class ReviewerTrustStore:
    """Trusted reviewers, fixed at the moment they were loaded.

    "Fixed" is now true as measured rather than as intended: `_parse_reviewers`
    returns a `MappingProxyType`, so this word describes the type and not an
    aspiration. It did not, and a review demonstrated the difference.
    """

    reviewers: Mapping[str, TrustedReviewer] = field(default_factory=dict)
    digest: str = "sha256:" + hashlib.sha256(b"").hexdigest()
    source: str = "<none>"
    available: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> ReviewerTrustStore:
        """Read and validate once. Absence and malformation are different facts.

        Absence means no independent inspection can be authenticated here, an
        ordinary state. Malformation means the store cannot be understood, and
        raises rather than degrading into an empty mapping that quietly means
        the same thing.
        """
        location = path if path is not None else reviewer_store_path()
        if not location.is_file():
            return cls(source=f"{location} (absent)")
        raw = location.read_bytes()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReviewerStoreUnavailable(f"{location} is unreadable: {exc}") from exc
        return cls(
            reviewers=_parse_reviewers(payload, location),
            digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            source=str(location),
            available=True,
        )


def verify_signed_attestation(
    attestation: Mapping[str, Any],
    *,
    store: ReviewerTrustStore,
    builder_identity: str | frozenset[str] | set[str],
) -> tuple[bool, str, dict[str, Any]]:
    """Authenticate one inspection attestation.

    Returns ``(authenticated, reason, evidence)``. Independence is *derived*
    here from authenticated identities, never read from the artifact, and the
    builder is supplied by the caller rather than asserted by the file under
    examination.
    """
    evidence: dict[str, Any] = {
        "reviewer_store_digest": store.digest,
        "signature_verified": False,
        "identity_verified": False,
        "role_verified": False,
        "independent": False,
    }

    if not store.available:
        return False, "REVIEWER_TRUST_UNAVAILABLE: no reviewer trust store", evidence

    if attestation.get("schema") != ATTESTATION_SCHEMA:
        return (
            False,
            f"ATTESTATION_SCHEMA_UNKNOWN: {attestation.get('schema')!r}",
            evidence,
        )

    key_id = str(attestation.get("reviewer_key_id", ""))
    reviewer = store.reviewers.get(key_id)
    if reviewer is None:
        return False, f"REVIEWER_NOT_TRUSTED: unknown key {key_id!r}", evidence
    evidence["reviewer_key_id"] = key_id

    signature = attestation.get("signature")
    if not isinstance(signature, str) or not signature:
        return False, "ATTESTATION_UNSIGNED: no signature present", evidence

    try:
        from base64 import b64decode

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        return False, "REVIEWER_VERIFIER_UNAVAILABLE", evidence

    try:
        public_key = load_pem_public_key(reviewer.public_key.encode("utf-8"))
        public_key.verify(  # type: ignore[call-arg]
            b64decode(signature), canonical_attestation_payload(attestation)
        )
    except InvalidSignature:
        return False, "ATTESTATION_NOT_AUTHENTICATED: signature invalid", evidence
    except Exception as exc:  # malformed key or signature encoding
        return False, f"ATTESTATION_NOT_AUTHENTICATED: {type(exc).__name__}", evidence
    evidence["signature_verified"] = True

    # THE SIGNED DIGEST IS NOW COMPARED AGAINST THE FINDINGS IT COVERS.
    # `findings_digest` was computed at issue time, signed, and read by
    # nobody: a review measured `findings` scrubbed to `[]` and replaced
    # with "no issues found", and both returned authenticated=True. The
    # comment above SIGNED_FIELDS said findings 'cannot be edited after
    # review', and `test_findings_cannot_be_edited_after_review` passed
    # while they could -- it recomputed the digest ITSELF and compared two
    # values, which proves a property of this function rather than of the
    # verifier a consumer calls. Its own comment said 'which is what a
    # consumer checks'. No consumer checked it.
    #
    # Placed AFTER signature verification on purpose: an unauthenticated
    # digest is not a fact about anything, so comparing against it first
    # would let an unsigned artifact choose its own binding.
    signed_digest = attestation.get("findings_digest")
    carried = findings_digest(attestation.get("findings"))
    if carried != signed_digest:
        return (
            False,
            "ATTESTATION_FINDINGS_UNBOUND: the signed findings_digest "
            + str(signed_digest) + " does not cover the findings carried "
            "alongside it (" + carried + "), so the findings have been "
            "edited since the reviewer signed them",
            evidence,
        )
    evidence["findings_bound"] = True

    claimed = str(attestation.get("reviewer", ""))
    if claimed != reviewer.reviewer:
        return (
            False,
            f"REVIEWER_IDENTITY_MISMATCH: signed as {claimed!r}, key belongs to "
            f"{reviewer.reviewer!r}",
            evidence,
        )
    evidence["identity_verified"] = True
    evidence["reviewer"] = reviewer.reviewer

    role = str(attestation.get("inspector_role", ""))
    if not reviewer.may_inspect_as(role):
        return (
            False,
            f"REVIEWER_ROLE_UNAUTHORIZED: {reviewer.reviewer!r} may not inspect as "
            f"{role!r}",
            evidence,
        )
    evidence["role_verified"] = True
    evidence["inspector_role"] = role

    # Derived, never asserted. `builder_self_approval: false` used to live in the
    # artifact, which meant the builder certified their own independence.
    excluded = (
        {builder_identity}
        if isinstance(builder_identity, str)
        else set(builder_identity)
    )
    if reviewer.reviewer in excluded:
        return (
            False,
            f"REVIEWER_IS_THE_BUILDER: {reviewer.reviewer!r} cannot independently "
            "inspect their own work",
            evidence,
        )
    evidence["independent"] = True

    return True, "authenticated", evidence
