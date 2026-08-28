"""A correctly signed governance approval, shared by tests and the probe.

Kept out of any test module so the subprocess probe can import it without
dragging a suite's fixtures along, and so the two cannot drift apart -- the
signed-field tuple is the thing under test, and two copies of it would be two
opinions about what a signature covers.
"""

from __future__ import annotations

import sys
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from signing import KEY_ID, SUBJECT, _keypair  # noqa: E402

from nornyx_forge.approval_trust import (  # noqa: E402
    GOVERNANCE_APPROVAL_SCHEMA,
    canonical_governance_payload,
)


def now_window(*, days: int = 2) -> tuple[str, str, str]:
    """A live window and an instant inside it.

    The governance verifier judges against a TRUSTED clock, so a fixture with
    hard-coded dates would be testing the clock rather than the authority.
    """
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (
        (now - timedelta(minutes=5)).strftime(fmt),
        (now + timedelta(days=days)).strftime(fmt),
        now.strftime(fmt),
    )


def governance_approval(role: str, generated: str, expires: str) -> dict:
    """A governance approval correctly signed by the session key, claiming `role`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PrivateKey,
    )

    record = {
        "schema": GOVERNANCE_APPROVAL_SCHEMA,
        "approval": "granted",
        "producer": {"id": f"{SUBJECT}:{role}", "type": "human"},
        "status": "pass",
        "subject_revision": "sha256:" + "a" * 64,
        "generated_at": generated,
        "expires_at": expires,
        "signer_key_id": KEY_ID,
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    raw, _ = _keypair()
    record["signature"] = b64encode(
        Ed25519PrivateKey.from_private_bytes(raw).sign(
            canonical_governance_payload(record)
        )
    ).decode("ascii")
    return record
