"""Direct control tests for `verify_governance_approval`.

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
    GOVERNANCE_TRUST_DOMAIN,
    SUBJECT_BOUND_ELSEWHERE,
    ApprovalTrustStore,
    canonical_governance_payload,
    verify_governance_approval,
)

SUBJECT = "human.test_fixture"
ROLE = "network_governance_owner"
KEY_ID = "gov-key-01"
REVISION = "sha256:" + "a" * 64


#: An instant inside the fixture window (generated 2026-08-02, expires
#: 2026-08-05). Every non-temporal case is judged here, so a role or identity
#: refusal cannot be an expiry refusal wearing the wrong name.
VERIFY_AS_OF = "2026-08-03T00:00:00Z"


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
        ],
        # Declared, because the domain guard is total: a store that will not say
        # which authority it belongs to cannot answer a domain-scoped question.
        # Without this these fixtures refuse on the domain clause and the tests
        # never reach the expiry, timestamp and instant clauses they name --
        # failing for a true reason that is not the one under test.
        domain=GOVERNANCE_TRUST_DOMAIN,
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
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair)
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is True, reason
    assert evidence["signature_verified"] is True
    assert evidence["identity_verified"] is True
    assert evidence["role_verified"] is True
    assert evidence["subject_type_verified"] is True
    assert evidence["approver"] == SUBJECT
    assert evidence["approver_role"] == ROLE


def test_the_other_authorized_role_also_authenticates(keypair):
    """The vocabulary is a set, not one blessed string."""
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:architecture_reviewer", "type": "human"}),
        trust_store=_store(keypair, roles=("architecture_reviewer",)),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
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
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair, producer={"id": SUBJECT, "type": "human"}),
        trust_store=_store(keypair),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "APPROVER_ROLE_MISSING" in reason
    assert evidence["role_verified"] is False


def test_an_empty_role_after_the_colon_is_refused(keypair):
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:", "type": "human"}),
        trust_store=_store(keypair),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "APPROVER_ROLE_MISSING" in reason
    assert evidence["role_verified"] is False


def test_a_role_outside_the_governance_vocabulary_is_refused(keypair):
    """A key trusted for a role that is not a governance-approver role.

    There was no vocabulary at all: any string the key happened to list
    authenticated, so a `documentation_reader` key approved governed content.
    """
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:documentation_reader", "type": "human"}),
        trust_store=_store(keypair, roles=("documentation_reader",)),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "APPROVER_ROLE_UNAUTHORIZED" in reason
    assert "not a governance approver role" in reason


def test_an_authorized_role_this_key_does_not_hold_is_refused(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:architecture_reviewer", "type": "human"}),
        trust_store=_store(keypair, roles=(ROLE,)),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "may not approve as" in reason


def test_an_action_approver_role_cannot_approve_governance(keypair):
    """The two vocabularies are separate authorities, not one shared list."""
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:operations_owner", "type": "human"}),
        trust_store=_store(keypair, roles=("operations_owner",)),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
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
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair, subject_type="machine")
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVER_NOT_HUMAN" in reason
    assert evidence["subject_type_verified"] is False


def test_an_artifact_declaring_a_non_human_producer_is_refused(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, producer={"id": f"{SUBJECT}:{ROLE}", "type": "tool"}),
        trust_store=_store(keypair),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "APPROVAL_PRODUCER_NOT_HUMAN" in reason


def test_signing_as_someone_else_is_refused(keypair):
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair, producer={"id": f"human.attacker:{ROLE}", "type": "human"}),
        trust_store=_store(keypair),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "APPROVER_IDENTITY_MISMATCH" in reason
    assert evidence["identity_verified"] is False


def test_a_trust_entry_with_an_empty_subject_cannot_match_anyone(keypair):
    """An empty trusted subject must not silently disable the comparison.

    `if signer.subject and claimed_subject != signer.subject` skipped the whole
    identity check when the store carried `subject: ""`.
    """
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair, producer={"id": f":{ROLE}", "type": "human"}),
        trust_store=_store(keypair, subject=""),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "names no subject" in reason
    assert evidence["identity_verified"] is False


# --------------------------------------------------------------------------
# Key trust
# --------------------------------------------------------------------------


def test_an_unknown_key_is_refused(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, signer_key_id="not-in-the-store"), trust_store=_store(keypair)
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVER_NOT_TRUSTED" in reason


def test_a_revoked_key_is_refused(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair, status="revoked")
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVER_NOT_TRUSTED" in reason


def test_an_absent_trust_store_is_not_permission(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=ApprovalTrustStore()
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVER_TRUST_UNAVAILABLE" in reason


def test_the_default_trust_store_is_the_empty_one(keypair):
    """No store argument must fail closed, not read one ambiently.

    The sibling action verifier defaults to an empty store; this one defaulted
    to `ApprovalTrustStore.load()` — a filesystem read at verification time,
    which is the per-verification ambient trust resolution the module argues
    against everywhere else.
    """
    ok, reason, _ = verify_governance_approval(_approval(keypair), as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVER_TRUST_UNAVAILABLE" in reason


# --------------------------------------------------------------------------
# Signature coverage: every authority-bearing field
# --------------------------------------------------------------------------


def test_an_unsigned_approval_is_refused(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, sign=False), trust_store=_store(keypair)
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVAL_UNSIGNED" in reason


def test_a_corrupt_signature_is_refused(keypair):
    record = _approval(keypair)
    record["signature"] = b64encode(b"\x00" * 64).decode("ascii")
    ok, reason, evidence = verify_governance_approval(
        record, trust_store=_store(keypair)
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
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
    ok, reason, _ = verify_governance_approval(
        record, trust_store=_store(keypair)
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False, f"{field} is not covered by the signature"
    assert "APPROVAL_NOT_AUTHENTICATED" in reason


def test_the_producer_identity_is_covered_by_the_signature(keypair):
    """`producer.id` is flattened into the signed payload as `producer_id`."""
    record = _approval(keypair)
    record["producer"] = {"id": f"{SUBJECT}:architecture_reviewer", "type": "human"}
    ok, reason, _ = verify_governance_approval(
        record, trust_store=_store(keypair, roles=(ROLE, "architecture_reviewer"))
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVAL_NOT_AUTHENTICATED" in reason


def test_an_approval_cannot_be_moved_to_another_subject(keypair):
    """Re-pointing a signed approval at different governed content must fail."""
    record = _approval(keypair)
    record["subject_revision"] = "sha256:" + "b" * 64
    ok, reason, _ = verify_governance_approval(
        record, trust_store=_store(keypair)
    , as_of=VERIFY_AS_OF, expected_subject_revision=REVISION)
    assert ok is False
    assert "APPROVAL_NOT_AUTHENTICATED" in reason


def test_a_foreign_schema_is_refused(keypair):
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, schema="nornyx.forge.action_approval.v1"),
        trust_store=_store(keypair),
     as_of=VERIFY_AS_OF, expected_subject_revision=REVISION,)
    assert ok is False
    assert "APPROVAL_SCHEMA_UNKNOWN" in reason


def test_the_governance_role_vocabulary_is_stated_not_inferred():
    assert GOVERNANCE_APPROVER_ROLES == {
        "network_governance_owner",
        "architecture_reviewer",
    }


# --------------------------------------------------------------------------
# Temporal validity: an independent mandatory clause
# --------------------------------------------------------------------------
#
# The window was SIGNED and never evaluated. Signing the bounds prevents them
# being re-dated; it does not bound anything. Measured against this module's own
# fixtures before the clause existed:
#
#     generated 2020-01-01 / expires 2020-01-08  -> (True, "authenticated")
#     expires BEFORE generated                   -> (True, "authenticated")
#     generated "not-a-time", expires null       -> (True, "authenticated")
#
# and the evidence returned signature/identity/role/subject_type all verified
# with nothing about time -- a flag true while its check was skipped, which is
# the defect the verifier's own docstring says it removed.
#
# EVERY case below is otherwise completely valid: trusted key, human subject
# type, matching identity, authorized role, correct schema, correct subject,
# signature over the exact record. So whatever refuses can only be the clock.

#: Fixture window: [2026-08-02T00:00:00Z, 2026-08-05T00:00:00Z)
WINDOW_START = "2026-08-02T00:00:00Z"
WINDOW_END = "2026-08-05T00:00:00Z"


def test_an_approval_inside_its_window_authenticates(keypair):
    """The benign control for this whole section."""
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-03T12:00:00Z",
        expected_subject_revision=REVISION
    )
    assert ok is True, reason
    assert evidence["validity_verified"] is True


def test_an_expired_approval_is_refused(keypair):
    """One second past the end. Everything else about it is impeccable."""
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-05T00:00:01Z",
        expected_subject_revision=REVISION
    )
    assert ok is False
    assert "APPROVAL_EXPIRED" in reason
    assert evidence["signature_verified"] is True, (
        "the signature must still verify, or this tests the wrong clause"
    )
    assert evidence.get("validity_verified") is not True


def test_an_approval_not_yet_valid_is_refused(keypair):
    """One second before the start."""
    ok, reason, evidence = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-01T23:59:59Z",
        expected_subject_revision=REVISION
    )
    assert ok is False
    assert "APPROVAL_NOT_YET_VALID" in reason
    assert evidence["role_verified"] is True


def test_the_lower_boundary_instant_is_valid(keypair):
    """Half-open [start, end): the instant of issue is inside the window."""
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of=WINDOW_START,
        expected_subject_revision=REVISION
    )
    assert ok is True, reason


def test_the_upper_boundary_instant_is_not_valid(keypair):
    """Half-open [start, end): the instant of expiry is outside it.

    Stated as a test rather than left to a reader of `<` versus `<=`, because an
    off-by-one here is a whole extra second of authority nobody granted.
    """
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of=WINDOW_END,
        expected_subject_revision=REVISION
    )
    assert ok is False
    assert "APPROVAL_EXPIRED" in reason


def test_the_same_instant_in_a_different_offset_gives_the_same_answer(keypair):
    """Instants, not strings.

    `2026-08-05T02:00:00+02:00` IS `2026-08-05T00:00:00Z`. Compared as text the
    offset form sorts differently, and lexical comparison gets the dangerous
    direction wrong -- so both spellings must reach the same answer.
    """
    utc = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-05T00:00:00Z",
        expected_subject_revision=REVISION
    )
    offset = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-05T02:00:00+02:00",
        expected_subject_revision=REVISION
    )
    assert utc.granted is False and offset.granted is False
    assert "APPROVAL_EXPIRED" in utc.reason
    assert "APPROVAL_EXPIRED" in offset.reason

    inside_utc = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-03T00:00:00Z",
        expected_subject_revision=REVISION
    )
    inside_offset = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="2026-08-03T02:00:00+02:00",
        expected_subject_revision=REVISION
    )
    assert inside_utc.granted is True
    assert inside_offset.granted is True


TEMPORAL_DEFECTS = [
    ("expiry before issue", {"expires_at": "2026-08-01T00:00:00Z"},
     "APPROVAL_WINDOW_INVALID"),
    ("expiry equal to issue", {"expires_at": WINDOW_START},
     "APPROVAL_WINDOW_INVALID"),
    ("window longer than the cap", {"expires_at": "2026-09-30T00:00:00Z"},
     "APPROVAL_WINDOW_INVALID"),
    ("malformed issue stamp", {"generated_at": "not-a-time"},
     "APPROVAL_TIME_UNREADABLE"),
    ("missing expiry", {"expires_at": None},
     "APPROVAL_TIME_UNREADABLE"),
    ("naive issue stamp", {"generated_at": "2026-08-02T00:00:00"},
     "APPROVAL_TIME_UNREADABLE"),
]


@pytest.mark.parametrize(
    ("label", "override", "expected"),
    TEMPORAL_DEFECTS,
    ids=[case[0] for case in TEMPORAL_DEFECTS],
)
def test_a_defective_window_is_refused(keypair, label, override, expected):
    """Signed over the defect, so the signature is genuinely valid.

    `_approval` signs after applying overrides, so each of these is a correctly
    signed approval carrying a broken window -- not a broken signature, which
    would refuse one clause earlier and prove nothing about time.
    """
    ok, reason, _ = verify_governance_approval(
        _approval(keypair, **override),
        trust_store=_store(keypair),
        as_of="2026-08-03T00:00:00Z",
        # The subject matches, so the refusal below is about TIME. Supplying a
        # mismatched one would refuse a clause earlier and prove nothing about
        # the window -- the same reason this fixture signs after the override.
        expected_subject_revision=REVISION,
    )
    assert ok is False, label
    assert expected in reason, f"{label}: refused as {reason}"


def test_an_unreadable_evaluation_instant_is_refused(keypair):
    """The clock the verifier is handed must itself be readable.

    Fails closed rather than falling back to the real clock: a caller that
    cannot say when it is asking has not established the time, and quietly
    substituting `now` would answer a question nobody asked.
    """
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of="whenever",
        expected_subject_revision=REVISION
    )
    assert ok is False
    assert "APPROVAL_TIME_UNREADABLE" in reason


def test_temporal_validity_is_not_optional_at_the_call_site():
    """Structural: no caller can omit the instant and skip the clause.

    A default would let a caller that forgets it authenticate an expired
    approval, which is the shape of the original defect.
    """
    import inspect

    parameter = inspect.signature(verify_governance_approval).parameters["as_of"]
    assert parameter.default is inspect.Parameter.empty, (
        "as_of has a default, so a caller that omits it skips temporal validity"
    )


# --------------------------------------------------------------------------
# A13 -- the equation listed "AND subject binding" and there was no subject.
#
# `verify_governance_approval` took no subject argument and never compared
# `subject_revision`. Measured before the fix: an approval naming the real
# subject, a DIFFERENT subject, an obvious nonsense value and the empty string
# were ALL granted. The field was signed and never evaluated -- exactly the
# shape this function's own docstring records as fixed for the temporal window,
# where "signing the bounds stops them being re-dated; it does not bound
# anything".
#
# The binding did exist, as `require_approval_matches_head()` composed at seven
# call sites in `scripts/refresh_governance_evidence.py`. That is the
# architecture `verify_action_approval` exists to forbid: a call site that
# composes a clause is a call site that can stop composing it.
# --------------------------------------------------------------------------

SUBJECT_BINDING_CASES = [
    ("a different subject", "sha256:" + "b" * 64, False),
    ("obvious nonsense", "not-a-revision", False),
    ("the empty string", "", False),
]


@pytest.mark.parametrize(
    ("label", "expected_subject", "granted"),
    SUBJECT_BINDING_CASES,
    ids=[case[0] for case in SUBJECT_BINDING_CASES],
)
def test_a13_an_approval_for_another_subject_is_refused(
    keypair, label: str, expected_subject: str, granted: bool
):
    """Each of these was granted before the clause was evaluated."""
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of=VERIFY_AS_OF,
        expected_subject_revision=expected_subject,
    )
    assert ok is granted, f"{label}: {reason}"
    assert "SUBJECT" in reason, f"{label} was refused for some other reason: {reason}"


def test_a13_the_matching_subject_is_still_granted(keypair):
    """The positive control. Without it the clause could refuse everything,
    which would look identical to a working binding from the outside."""
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of=VERIFY_AS_OF,
        expected_subject_revision=REVISION,
    )
    assert ok is True, reason


def test_a13_the_subject_is_a_required_argument():
    """No default, deliberately.

    An optional subject defaulting to None would make "no expectation supplied"
    indistinguishable from "the expectation was met" -- the unanswered question
    read as a satisfied one, which is the defect this repository keeps finding.
    A caller with nothing to bind against has to say so, and saying so refuses.
    """
    import inspect  # noqa: PLC0415

    parameter = inspect.signature(
        verify_governance_approval
    ).parameters["expected_subject_revision"]
    assert parameter.default is inspect.Parameter.empty, (
        "expected_subject_revision has a default, so a caller can omit the "
        "subject clause and the verifier will not notice"
    )
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


# --------------------------------------------------------------------------
# The subject opt-out is a HOLE. These keep it one hole rather than a habit.
#
# `scripts/refresh_governance_evidence.py` must be able to LOAD an approval
# covering an older revision, because detecting exactly that is
# `require_approval_matches_head()`'s job. My first version of the subject
# clause passed HEAD there, which made a stale approval fail AUTHENTICATION --
# the wrong diagnostic, and it made the drift detector UNREACHABLE, because
# `_approved_revision()` could then never return anything but HEAD. The suite
# caught it; these two tests are what stop it coming back quietly.
# --------------------------------------------------------------------------


def test_the_subject_opt_out_is_used_in_exactly_one_place():
    """One production call site, found structurally.

    A sentinel that spreads is a parameter that has stopped meaning anything.
    AST rather than text, because the constant is DEFINED in `approval_trust`
    and DISCUSSED in comments, and neither is a use.
    """
    import ast  # noqa: PLC0415

    users = []
    for area in ("src", "scripts"):
        for path in sorted((ROOT / area).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if (
                        keyword.arg == "expected_subject_revision"
                        and isinstance(keyword.value, ast.Name)
                        and keyword.value.id == "SUBJECT_BOUND_ELSEWHERE"
                    ):
                        users.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert len(users) == 1, (
        "the subject opt-out is used at more than one production call site, so "
        f"it has stopped being a documented exception: {users}"
    )
    assert users[0].startswith("scripts\\refresh_governance_evidence.py") or users[
        0
    ].startswith("scripts/refresh_governance_evidence.py"), users


def test_a_stale_approval_still_authenticates_so_the_drift_detector_can_see_it(
    keypair,
):
    """The control the opt-out exists to preserve, asserted directly.

    If this ever refuses, `require_approval_matches_head()` can no longer be
    reached with a stale approval -- the approval would fail one clause
    earlier -- and the operator guidance it carries ("stop, and let a human
    re-approve the new revision") would be replaced by a bare authentication
    failure that says nothing about what to do.
    """
    ok, reason, _ = verify_governance_approval(
        _approval(keypair), trust_store=_store(keypair), as_of=VERIFY_AS_OF,
        expected_subject_revision=SUBJECT_BOUND_ELSEWHERE,
    )
    assert ok is True, (
        "an authentic approval could not be loaded for the drift check: "
        f"{reason}"
    )


def test_the_opt_out_does_not_leak_into_ordinary_calls(keypair):
    """A caller that supplies a real subject still gets the clause evaluated.

    The sentinel must not have widened into "any falsy or unusual value skips
    the check", which is how an exemption becomes a default.
    """
    for expected in ("sha256:" + "b" * 64, "not-a-revision", ""):
        ok, reason, _ = verify_governance_approval(
            _approval(keypair), trust_store=_store(keypair), as_of=VERIFY_AS_OF,
            expected_subject_revision=expected,
        )
        assert ok is False, f"{expected!r} was granted: {reason}"
        assert "SUBJECT" in reason, reason


def test_the_subject_opt_out_cannot_hide_in_another_spelling():
    """A26: the enumeration matched one syntactic shape out of six.

    The guard above requires `keyword.value` to be an `ast.Name` whose id is
    literally `SUBJECT_BOUND_ELSEWHERE`. A review measured five ordinary
    spellings invisible to it -- module-qualified, aliased on import, bound to a
    local first, the literal string, and passed through `**kwargs` -- and it is
    the only guard on the sentinel, so a second opt-out in any of them would
    leave the count at 1 and the guard silent.

    So this asks the opposite question, the same inversion the document guards
    needed: every `expected_subject_revision=` in production must be a value
    this test can SEE and judge -- a literal, a locally-defined name, or the
    declared sentinel. Anything opaque fails, whatever it is called.
    """
    import ast  # noqa: PLC0415

    opaque = []
    for area in ("src", "scripts"):
        for path in sorted((ROOT / area).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name != "verify_governance_approval":
                    continue
                if any(keyword.arg is None for keyword in node.keywords):
                    opaque.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} **kwargs"
                    )
                    continue
                supplied = {keyword.arg: keyword.value for keyword in node.keywords}
                value = supplied.get("expected_subject_revision")
                if value is None:
                    opaque.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} no subject"
                    )
                elif not isinstance(value, (ast.Constant, ast.Name, ast.Call)):
                    opaque.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} "
                        f"{type(value).__name__}"
                    )
    assert opaque == [], (
        "these calls pass a subject this guard cannot judge, so an opt-out "
        f"could hide in one of them: {opaque}"
    )
