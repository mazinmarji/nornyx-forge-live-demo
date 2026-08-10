"""One place tests obtain a genuinely trusted signer.

Action approvals are authenticated against an Ed25519 trust store held outside
the governed tree, so a test that wants a *releasable* grant needs a real key
and a real signature. Hand-rolling that in every module would mean seventeen
copies of the same ceremony, each free to drift into signing something slightly
different from what the boundary verifies.

The split this exists to protect:

    a test whose subject is a successful release
        -> use signed_grant(), which is trusted and correct

    a test whose subject is a *refusal*
        -> keep the defect explicit and visible in the test itself

Never import this from ``src``. It holds a private key, and the whole point of
Ed25519 here is that the verifier cannot produce what it verifies.
"""

from __future__ import annotations

import sys
from base64 import b64encode
from functools import lru_cache
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from issue_action_approval import sign_grant  # noqa: E402

from nornyx_forge.approval_trust import APPROVAL_SCHEMA, ApprovalTrustStore  # noqa: E402

KEY_ID = "test-approval-01"
SUBJECT = "human.test_fixture"
#: Roles the session key may approve in. "architecture_reviewer" is here because
#: governance approvals name the capacity in producer.id (subject:role) and the
#: verifier checks it against the key's roles -- a key must not approve in a
#: capacity it does not hold. A fixture needing an unauthorized role should ask
#: for one explicitly rather than widening this.
ROLES = ("operations_owner", "network_governance_owner", "architecture_reviewer")


@lru_cache(maxsize=1)
def _keypair() -> tuple[bytes, str]:
    """One ephemeral keypair per test session. Never written to disk."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return raw, b64encode(public).decode("ascii")


def trust_store(*, roles: tuple[str, ...] = ROLES, status: str = "active",
                subject_type: str = "human") -> ApprovalTrustStore:
    """A trust store vouching for the session key."""
    _, public = _keypair()
    return ApprovalTrustStore.for_test(
        [
            {
                "key_id": KEY_ID,
                "algorithm": "Ed25519",
                "subject": SUBJECT,
                "subject_type": subject_type,
                "roles": list(roles),
                "public_key": public,
                "status": status,
            }
        ]
    )


def signed_grant(
    request: Any,
    *,
    approval_id: str = "ACT-0001",
    role: str = "operations_owner",
    generated_at: str = "2026-08-02T00:00:00Z",
    expires_at: str = "2026-08-05T00:00:00Z",
    **overrides: Any,
) -> dict[str, Any]:
    """A complete, correctly signed grant for exactly this request.

    The signature covers the canonical payload only. Fields outside that set —
    the per-request bindings ``validate_action_approval`` checks — are carried
    alongside, because they are already covered transitively by
    ``request_digest``.
    """

    private, _ = _keypair()
    signed = {
        "schema": APPROVAL_SCHEMA,
        "approval_id": approval_id,
        "request_digest": request.digest,
        "approver": SUBJECT,
        "approver_role": role,
        "signer_key_id": KEY_ID,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "granted": True,
    }
    grant = dict(signed)
    grant.update(
        {
            "signature": sign_grant(signed, private),
            "approver_type": "human",
            "request_id": request.request_id,
            "attempt_id": request.attempt_id,
            "subject_revision": request.subject_revision,
            "capability": request.capability,
            "destination": request.destination,
            "payload_digest": request.payload_digest,
        }
    )
    grant.update(overrides)
    return grant


def signed_governance_approval(
    *,
    subject_revision: str,
    status: str = "pass",
    approval: str = "granted",
    generated_at: str = "2026-08-02T00:00:00Z",
    expires_at: str = "2026-08-05T00:00:00Z",
    producer_id: str = SUBJECT,
    key_id: str = KEY_ID,
) -> dict:
    """A governance approval record signed by the session key.

    SYNTHETIC TEST FIXTURE. The key is ephemeral, generated per session, never
    written to disk, and vouched for only by a trust store built in-process. It
    cannot and does not constitute a human approval for this repository.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nornyx_forge.approval_trust import (
        GOVERNANCE_APPROVAL_SCHEMA,
        canonical_governance_payload,
    )

    record = {
        "schema": GOVERNANCE_APPROVAL_SCHEMA,
        "approval": approval,
        "producer": {"id": producer_id, "type": "human"},
        "status": status,
        "subject_revision": subject_revision,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "signer_key_id": key_id,
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    raw, _ = _keypair()
    private = Ed25519PrivateKey.from_private_bytes(raw)
    record["signature"] = b64encode(
        private.sign(canonical_governance_payload(record))
    ).decode("ascii")
    return record


def write_trust_store(path, *, roles: tuple[str, ...] = ROLES,
                      status: str = "active") -> "Path":
    """Write the session trust store to disk for subprocess runs.

    Public keys only, and the private half never leaves memory. A subprocess
    cannot be handed an in-process store, and building one by hand in each test
    would let the tests and the production loader drift apart.
    """
    import json as _json
    from pathlib import Path as _Path

    _, public = _keypair()
    location = _Path(path)
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_text(
        _json.dumps(
            {
                "signers": [
                    {
                        "key_id": KEY_ID,
                        "algorithm": "Ed25519",
                        "subject": SUBJECT,
                        "subject_type": "human",
                        "roles": list(roles),
                        "public_key": public,
                        "status": status,
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return location


def sign_governance_record(payload: dict) -> dict:
    """Sign an already-built governance approval payload in place.

    Takes the fixture's own dict rather than building one, so a test that varies
    a field keeps varying it and the signature still covers what it varied. The
    alternative — each fixture assembling its own signed material — is how a
    signature comes to cover something other than the record shipped.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nornyx_forge.approval_trust import canonical_governance_payload

    signed = dict(payload)
    signed.setdefault("signer_key_id", KEY_ID)
    raw, _ = _keypair()
    signed["signature"] = b64encode(
        Ed25519PrivateKey.from_private_bytes(raw).sign(
            canonical_governance_payload(signed)
        )
    ).decode("ascii")
    return signed
