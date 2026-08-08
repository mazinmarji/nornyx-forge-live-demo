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
ROLES = ("operations_owner", "network_governance_owner")


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
