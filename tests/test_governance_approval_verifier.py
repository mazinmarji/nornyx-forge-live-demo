"""Direct control tests for `verify_signed_governance_approval`.

This verifier authenticates the artifact granting the strongest authority the
system recognises, and until now **no test called it**. It was reached only
through `load_canonical_approval`, whose negative cases all pointed
`FORGE_APPROVER_TRUST_STORE` at an absent file — so they refused at
`APPROVER_TRUST_UNAVAILABLE` and the signature was never verified. Both negative
tests proved "no trust store ⇒ refuse", never "bad signature ⇒ refuse".

An independent review removed the signature check, the identity check, the role
check, the `subject_revision` binding and the trust-store membership check, one
at a time, and the suite stayed green for every one.

THE PROPERTY under test:

    A governance approval is authoritative only when an externally trusted HUMAN
    identity is cryptographically authenticated FOR THE EXACT ROLE it claims,
    over the EXACT governed subject it names.

Each clause gets its own refusal case, asserted on the specific diagnostic —
because a test that accepts any refusal cannot tell "rejected for the reason I
named" from "rejected for an unrelated reason two checks earlier", which is
precisely how the previous suite passed while three clauses were missing.

Fixtures use a realistic `subject:role` identity. The old fixture's role-less id
meant the bypassing branch was the only one the suite executed.
"""

from __future__ import annotations

import sys
from base64 import b64encode
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from nornyx_forge.approval_trust import (  # noqa: E402
    GOVERNANCE_APPROVAL_SCHEMA,
    GOVERNANCE_APPROVER_ROLES,
    ApprovalTrustStore,
    canonical_governance_payload,
    verify_signed_governance_approval,
)

SUBJECT = "human.test_fixture"
ROLE = "network_governance_owner"
KEY_ID = "gov-key-01"
REVISION = "sha256:" + "a" * 64


def _keypair() -> tuple[bytes, str]:
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


@pytest.fixture(scope="module")
def keypair():
    return _keypair()


def _store(
    keypair,
    *,
    subject: str = SUBJECT,
    subject_type: str = "human",
    roles: tuple[str, ...] = (ROLE,),
    status: str = "active",
    key_id: str = KEY_ID,
) -> ApprovalTrustStore:
    _, public = keypair
    return ApprovalTrustStore.for_test(
        [
            {
                "key_id": key_id,
                "algorithm": "Ed25519",
                "subject": subject,
                "subject_type": subject_type,
                "roles": list(roles),
                "public_key": public,
                "status": status,
            }
        ]
    )


def _approval(keypair, *, sign: bool = True, **overrides) -> dict:
    """A correct governance approval, then optionally altered.

    Signed AFTER the overrides are applied, so a case that changes a signed
    field tests the field's meaning rather than testing a broken signature.
    Cases that want a broken signature say so explicitly.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    record = {
        "schema": GOVERNANCE_APPROVAL_SCHEMA,
        "approval": "granted",
        "producer": {"id": f"{SUBJECT}:{ROLE}", "type": "human"},
        "status": "pass",
        "subject_revision": REVISION,
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "signer_key_id": KEY_ID,
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    record.update(overrides)
    if sign:
        raw, _ = keypair
        record["signature"] = b64encode(
            Ed25519PrivateKey.from_private_bytes(raw).sign(
                canonical_governance_payload(record)
            )
        ).decode("ascii")
    return record


# --------------------------------------------------------------------------
# The benign case. Without it every refusal below could be "refuses everything".
# --------------------------------------------------------------------------


def test_a_trusted_human_in_an_authorized_role_authenticates(keypair):
    ok, reason, evidence = verify_signed_governance_approval(
        _approval(keypair), trust_store=_store(keypair)
    )
    assert ok is True, reason
    assert evidence["signature_verified"] is True
    assert evidence["identity_verified"] is True
    assert evidence["role_verified"] is True
    assert evidence["subject_type_verified"] is True
    assert evidence["approver"] == SUBJECT
    assert evidence["approver_role"] == ROLE


def test_the_other_authorized_role_also_authenticates(keypair):
    """The vocabulary is a set, not one blessed string."""
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:architecture_reviewer", "type": "human"}),
        trust_store=_store(keypair, roles=("architecture_reviewer",)),
    )
    assert ok is True, reason


# --------------------------------------------------------------------------
# Role: presence, then vocabulary, then this key's authorization
# --------------------------------------------------------------------------


def test_an_omitted_role_is_refused(keypair):
    """The live bypass. A missing role must not mean "no check needed".

    `evidence["role_verified"] = True` was set outside the `if claimed_role:`
    guard, so this case authenticated AND reported a verified role. The
    repository's own fixture used a role-less id, so this was the only path the
    suite executed.
    """
    ok, reason, evidence = verify_signed_governance_approval(
        _approval(keypair, producer={"id": SUBJECT, "type": "human"}),
        trust_store=_store(keypair),
    )
    assert ok is False
    assert "APPROVER_ROLE_MISSING" in reason
    assert evidence["role_verified"] is False


def test_an_empty_role_after_the_colon_is_refused(keypair):
    ok, reason, evidence = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:", "type": "human"}),
        trust_store=_store(keypair),
    )
    assert ok is False
    assert "APPROVER_ROLE_MISSING" in reason
    assert evidence["role_verified"] is False


def test_a_role_outside_the_governance_vocabulary_is_refused(keypair):
    """A key trusted for a role that is not a governance-approver role.

    There was no vocabulary at all: any string the key happened to list
    authenticated, so a `documentation_reader` key approved governed content.
    """
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:documentation_reader", "type": "human"}),
        trust_store=_store(keypair, roles=("documentation_reader",)),
    )
    assert ok is False
    assert "APPROVER_ROLE_UNAUTHORIZED" in reason
    assert "not a governance approver role" in reason


def test_an_authorized_role_this_key_does_not_hold_is_refused(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:architecture_reviewer", "type": "human"}),
        trust_store=_store(keypair, roles=(ROLE,)),
    )
    assert ok is False
    assert "may not approve as" in reason


def test_an_action_approver_role_cannot_approve_governance(keypair):
    """The two vocabularies are separate authorities, not one shared list."""
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:operations_owner", "type": "human"}),
        trust_store=_store(keypair, roles=("operations_owner",)),
    )
    assert ok is False
    assert "not a governance approver role" in reason


# --------------------------------------------------------------------------
# Identity and humanity
# --------------------------------------------------------------------------


def test_a_machine_key_cannot_give_a_human_approval(keypair):
    """The trust store decides what a key is; the artifact only claims.

    `subject_type` was never consulted, so a machine key signing an artifact
    that said `producer.type: "human"` became a human approval. The sibling
    action verifier has this check, with a test — verified where written,
    absent where copied.
    """
    ok, reason, evidence = verify_signed_governance_approval(
        _approval(keypair), trust_store=_store(keypair, subject_type="machine")
    )
    assert ok is False
    assert "APPROVER_NOT_HUMAN" in reason
    assert evidence["subject_type_verified"] is False


def test_an_artifact_declaring_a_non_human_producer_is_refused(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:{ROLE}", "type": "tool"}),
        trust_store=_store(keypair),
    )
    assert ok is False
    assert "APPROVAL_PRODUCER_NOT_HUMAN" in reason


def test_signing_as_someone_else_is_refused(keypair):
    ok, reason, evidence = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f"human.attacker:{ROLE}", "type": "human"}),
        trust_store=_store(keypair),
    )
    assert ok is False
    assert "APPROVER_IDENTITY_MISMATCH" in reason
    assert evidence["identity_verified"] is False


def test_a_trust_entry_with_an_empty_subject_cannot_match_anyone(keypair):
    """An empty trusted subject must not silently disable the comparison.

    `if signer.subject and claimed_subject != signer.subject` skipped the whole
    identity check when the store carried `subject: ""`.
    """
    ok, reason, evidence = verify_signed_governance_approval(
        _approval(keypair, producer={"id": f":{ROLE}", "type": "human"}),
        trust_store=_store(keypair, subject=""),
    )
    assert ok is False
    assert "names no subject" in reason
    assert evidence["identity_verified"] is False


# --------------------------------------------------------------------------
# Key trust
# --------------------------------------------------------------------------


def test_an_unknown_key_is_refused(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, signer_key_id="not-in-the-store"), trust_store=_store(keypair)
    )
    assert ok is False
    assert "APPROVER_NOT_TRUSTED" in reason


def test_a_revoked_key_is_refused(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair), trust_store=_store(keypair, status="revoked")
    )
    assert ok is False
    assert "APPROVER_NOT_TRUSTED" in reason


def test_an_absent_trust_store_is_not_permission(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair), trust_store=ApprovalTrustStore()
    )
    assert ok is False
    assert "APPROVER_TRUST_UNAVAILABLE" in reason


def test_the_default_trust_store_is_the_empty_one(keypair):
    """No store argument must fail closed, not read one ambiently.

    The sibling action verifier defaults to an empty store; this one defaulted
    to `ApprovalTrustStore.load()` — a filesystem read at verification time,
    which is the per-verification ambient trust resolution the module argues
    against everywhere else.
    """
    ok, reason, _ = verify_signed_governance_approval(_approval(keypair))
    assert ok is False
    assert "APPROVER_TRUST_UNAVAILABLE" in reason


# --------------------------------------------------------------------------
# Signature coverage: every authority-bearing field
# --------------------------------------------------------------------------


def test_an_unsigned_approval_is_refused(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, sign=False), trust_store=_store(keypair)
    )
    assert ok is False
    assert "APPROVAL_UNSIGNED" in reason


def test_a_corrupt_signature_is_refused(keypair):
    record = _approval(keypair)
    record["signature"] = b64encode(b"\x00" * 64).decode("ascii")
    ok, reason, evidence = verify_signed_governance_approval(
        record, trust_store=_store(keypair)
    )
    assert ok is False
    assert "APPROVAL_NOT_AUTHENTICATED" in reason
    assert evidence["signature_verified"] is False


@pytest.mark.parametrize(
    "field",
    ["approval", "status", "subject_revision", "generated_at", "expires_at"],
)
def test_every_authority_bearing_field_is_covered_by_the_signature(keypair, field: str):
    """Enumerated, not sampled.

    A field outside the signed set is one an attacker may rewrite freely.
    `subject_revision` matters most: dropping it from the signed set let a
    correctly signed approval be re-pointed at a different revision and still
    return `authenticated`.
    """
    record = _approval(keypair)
    record[field] = "tampered-after-signing"
    ok, reason, _ = verify_signed_governance_approval(
        record, trust_store=_store(keypair)
    )
    assert ok is False, f"{field} is not covered by the signature"
    assert "APPROVAL_NOT_AUTHENTICATED" in reason


def test_the_producer_identity_is_covered_by_the_signature(keypair):
    """`producer.id` is flattened into the signed payload as `producer_id`."""
    record = _approval(keypair)
    record["producer"] = {"id": f"{SUBJECT}:architecture_reviewer", "type": "human"}
    ok, reason, _ = verify_signed_governance_approval(
        record, trust_store=_store(keypair, roles=(ROLE, "architecture_reviewer"))
    )
    assert ok is False
    assert "APPROVAL_NOT_AUTHENTICATED" in reason


def test_an_approval_cannot_be_moved_to_another_subject(keypair):
    """Re-pointing a signed approval at different governed content must fail."""
    record = _approval(keypair)
    record["subject_revision"] = "sha256:" + "b" * 64
    ok, reason, _ = verify_signed_governance_approval(
        record, trust_store=_store(keypair)
    )
    assert ok is False
    assert "APPROVAL_NOT_AUTHENTICATED" in reason


def test_a_foreign_schema_is_refused(keypair):
    ok, reason, _ = verify_signed_governance_approval(
        _approval(keypair, schema="nornyx.forge.action_approval.v1"),
        trust_store=_store(keypair),
    )
    assert ok is False
    assert "APPROVAL_SCHEMA_UNKNOWN" in reason


def test_the_governance_role_vocabulary_is_stated_not_inferred():
    assert GOVERNANCE_APPROVER_ROLES == {
        "network_governance_owner",
        "architecture_reviewer",
    }
