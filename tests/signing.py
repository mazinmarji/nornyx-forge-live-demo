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


#: The fixture time frame, stated once so every test shares one coherent world.
#:
#: The ledger's replay history begins, THEN the human issues the grant, THEN it
#: is consumed. A fixture that provisioned on the real clock while signing a
#: grant dated 2026-08-02 was describing a grant issued before the ledger
#: existed -- which continuity correctly refuses, and which is not the scenario
#: those tests meant to describe.
LEDGER_ESTABLISHED = "2026-08-01T00:00:00Z"
GRANT_ISSUED = "2026-08-02T00:00:00Z"


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


def signer_entry(*, roles: tuple[str, ...] = ROLES, status: str = "active",
                 subject_type: str = "human", key_id: str = KEY_ID,
                 subject: str = SUBJECT) -> dict:
    """One trusted-signer record for the session key."""
    _, public = _keypair()
    return {
        "key_id": key_id,
        "algorithm": "Ed25519",
        "subject": subject,
        "subject_type": subject_type,
        "roles": list(roles),
        "public_key": public,
        "status": status,
    }


def trust_store(*, roles: tuple[str, ...] = ROLES, status: str = "active",
                subject_type: str = "human",
                domain: str = "") -> ApprovalTrustStore:
    """A trust store vouching for the session key.

    `domain` defaults to unlabelled, which the authenticator treats as "asserts
    nothing about which authority this membership is for" and therefore does not
    refuse on the domain clause. A test that means to prove domain separation
    must say which domain it is building -- silence must not be mistaken for
    "trusted in whichever domain is asking".
    """
    return ApprovalTrustStore.for_test(
        [signer_entry(roles=roles, status=status, subject_type=subject_type)],
        domain=domain,
    )


def signed_grant(
    request: Any,
    *,
    approval_id: str = "ACT-0001",
    role: str = "operations_owner",
    # A window around the real clock, not a calendar date. The production
    # verifier now evaluates the signed window against a trusted instant, so a
    # pinned date is genuinely expired the day after it is written -- and every
    # fixture whose validity is a PREREQUISITE would start failing for a reason
    # that has nothing to do with what it asserts. Tests about temporal
    # semantics pass explicit instants instead.
    generated_at: str = "2026-08-02T00:00:00Z",
    expires_at: str = "2026-08-05T00:00:00Z",
    **overrides: Any,
) -> dict[str, Any]:
    """A complete, correctly signed grant for exactly this request.

    The signature covers the canonical payload only. Fields outside that set —
    the per-request bindings ``_bind_action_approval`` checks — are carried
    alongside, because they are already covered transitively by
    ``request_digest``.
    """
    # Fixed dates deliberately, unlike the governance builder. Action fixtures
    # run inside a SIMULATED frame -- the boundary is given an explicit
    # `as_of` of 2026-08-03 -- so a window around the real clock would be "not
    # yet valid" in the world those tests describe. The governance loader has no
    # such injection point and judges against the trusted clock, which is why
    # the two builders differ.

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
    generated_at: str | None = None,
    expires_at: str | None = None,
    # A realistic subject:role identity. This defaulted to a role-less SUBJECT,
    # so every governance fixture in the suite took the branch where the role
    # check was skipped -- the bypass was the only path the tests executed.
    producer_id: str = SUBJECT + ':network_governance_owner',
    key_id: str = KEY_ID,
) -> dict:
    """A governance approval record signed by the session key.

    SYNTHETIC TEST FIXTURE. The key is ephemeral, generated per session, never
    written to disk, and vouched for only by a trust store built in-process. It
    cannot and does not constitute a human approval for this repository.
    """
    # Defaults resolved here rather than in the signature: a default evaluated
    # at import would freeze the window at collection time, which is the same
    # calendar-pinning problem one step removed.
    if generated_at is None or expires_at is None:
        default_start, default_end = live_window()
        generated_at = generated_at or default_start
        expires_at = expires_at or default_end
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


def write_trust_store(
    path,
    *,
    roles: tuple[str, ...] | None = None,
    governance_roles: tuple[str, ...] | None = None,
    action_roles: tuple[str, ...] | None = None,
    governance_extra: tuple[dict, ...] = (),
    action_extra: tuple[dict, ...] = (),
    status: str = "active",
) -> "Path":
    """Write the session trust store to disk for subprocess runs.

    Public keys only, and the private half never leaves memory. A subprocess
    cannot be handed an in-process store, and building one by hand in each test
    would let the tests and the production loader drift apart.

    The two domains are provisioned SEPARATELY. `roles=` sets both, which is
    what a test asserting something other than domain separation wants; passing
    `governance_roles=` or `action_roles=` provisions one domain and leaves the
    other empty, which is what the directionality matrix needs. Omitting a
    domain entirely leaves it with no signers, and an empty domain authorizes
    nothing rather than everything.

    `governance_extra` / `action_extra` add UNRELATED principals. A negative
    directionality test needs them: against an empty domain the refusal is
    "this domain has no approvers", which proves the domain was unprovisioned
    rather than that this key was rejected by it. With another principal
    present, the refusal has to name the key.
    """
    import json as _json
    from pathlib import Path as _Path

    both = roles if roles is not None else ROLES
    if governance_roles is None and action_roles is None:
        governance, action = both, both
    else:
        governance = governance_roles or ()
        action = action_roles or ()

    def section(domain_roles: tuple[str, ...], extra: tuple[dict, ...]) -> dict:
        entries = list(extra)
        if domain_roles:
            entries.insert(0, signer_entry(roles=domain_roles, status=status))
        return {"signers": entries}

    location = _Path(path)
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_text(
        _json.dumps(
            {
                "domains": {
                    "governance": section(tuple(governance), tuple(governance_extra)),
                    "action": section(tuple(action), tuple(action_extra)),
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return location


def live_window(*, days: int = 3) -> tuple[str, str]:
    """A validity window around the real clock, for fixtures the loader judges.

    `verify_governance_approval` now evaluates the signed window against
    a trusted instant, so a fixture pinned to a fixed calendar date is genuinely
    expired the day after it was written -- and a test asserting adoption would
    start failing for a reason that has nothing to do with what it tests.

    Tests that exercise temporal semantics deliberately still pass explicit
    instants; this is for the ones where validity is a PREREQUISITE rather than
    the property under test.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    started = now - timedelta(minutes=5)
    return (
        started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        (started + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

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


#: A second, unrelated principal. Present so a domain a test means to leave
#: THIS key out of is still a provisioned domain, and a refusal there is about
#: the key rather than about the domain being empty.
OTHER_KEY_ID = "test-approval-other"
OTHER_SUBJECT = "human.other_principal"


def other_signer(roles: tuple[str, ...]) -> dict:
    """A trusted-signer record for a principal that is not the session key."""
    return signer_entry(roles=roles, key_id=OTHER_KEY_ID, subject=OTHER_SUBJECT)
