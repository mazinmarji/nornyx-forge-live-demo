"""An independent inspection has to be authenticated, not asserted.

The artifact deciding whether an independent inspection happened was
unauthenticated. Shape was validated exhaustively; identity was not. Independence
came straight off the file:

    state["independent"] = attested.get("builder_self_approval") is False

A builder asserting their own non-self-approval. Writing one file flipped
`assurance_state` to `independently_inspected` with `problems: []`.

No test could have caught it, because the suite's positive fixture wrote exactly
that artifact and asserted it must succeed. The exploit was encoded as required
behaviour — which is why this file replaces that one rather than extending it.

Every positive case here signs with a real ephemeral key through the real
issuer, and every negative case goes through the production verifier. A fixture
that hand-rolled either side would prove something about the fixture.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from nornyx_forge.reviewer_trust import (
    ATTESTATION_SCHEMA,
    REQUIRED_INSPECTOR_ROLES,
    ReviewerStoreUnavailable,
    ReviewerTrustStore,
    verify_signed_attestation,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from issue_inspection_attestation import (  # noqa: E402
    build_attestation,
    sign_attestation,
)

BUILDER = "builder.nornyx_forge"
SUBJECT = "sha256:" + "a" * 64


def _keypair() -> tuple[bytes, str]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return private, public


def _store(*reviewers: dict) -> ReviewerTrustStore:
    path = Path(tempfile.mkdtemp()) / "reviewers.json"
    path.write_text(
        json.dumps(
            {"schema": "nornyx.forge.reviewer_trust_store.v1", "reviewers": list(reviewers)}
        ),
        encoding="utf-8",
    )
    return ReviewerTrustStore.load(path)


def _reviewer(key_id: str, name: str, roles: list[str], public: str, status="active") -> dict:
    return {
        "key_id": key_id,
        "reviewer": name,
        "roles": roles,
        "public_key": public,
        "status": status,
    }


def _attest(private: bytes, *, reviewer: str, key_id: str, role: str,
            verdict: str = "pass", findings=None, subject: str = SUBJECT) -> dict:
    return sign_attestation(
        build_attestation(
            inspection_subject_digest=subject,
            reviewer=reviewer,
            reviewer_key_id=key_id,
            inspector_role=role,
            verdict=verdict,
            findings=findings or [],
            tool="claude-opus",
            tool_version="5",
        ),
        private,
    )


# --------------------------------------------------------------------------
# The control that did not exist
# --------------------------------------------------------------------------


def test_an_unsigned_attestation_authenticates_nothing():
    """The original exploit, run against the production verifier.

    This is the whole file's reason for existing: the old model accepted this
    artifact and derived `independently_inspected` from it.
    """
    private, public = _keypair()
    store = _store(_reviewer("rev-1", "reviewer.security", ["security-inspector"], public))

    unsigned = build_attestation(
        inspection_subject_digest=SUBJECT,
        reviewer="reviewer.security",
        reviewer_key_id="rev-1",
        inspector_role="security-inspector",
        verdict="pass",
        findings=[],
        tool="claude-opus",
        tool_version="5",
    )
    # The field that used to decide independence, asserted as favourably as an
    # attacker would. It must change nothing.
    unsigned["builder_self_approval"] = False

    ok, reason, evidence = verify_signed_attestation(
        unsigned, store=store, builder_identity=BUILDER
    )
    assert ok is False
    assert "ATTESTATION_UNSIGNED" in reason
    assert evidence["independent"] is False


def test_builder_self_approval_is_not_consulted_anywhere():
    """The field is gone as an authority primitive, not merely ignored in one path.

    Whole file, not just the derivation: a second reader reintroducing it
    elsewhere would restore the defect. Comments naming it are what keep the
    history legible, so only executable lines are examined.
    """
    import ast

    for name in ("scripts/refresh_governance_evidence.py",
                 "src/nornyx_forge/reviewer_trust.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        tree = ast.parse(source)

        # Docstrings explaining the defect are exactly what keeps it from being
        # reintroduced. Excluded structurally, so prose can never be mistaken for
        # a live reference and a live reference can never hide as prose.
        prose: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
                body = getattr(node, "body", [])
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    prose.update(range(body[0].lineno, (body[0].end_lineno or 0) + 1))

        for number, line in enumerate(source.splitlines(), 1):
            if number in prose:
                continue
            assert "builder_self_approval" not in line.split("#", 1)[0], (
                f"{name}:{number} still consults a field the artifact asserts "
                "about itself"
            )


def test_a_correctly_signed_attestation_authenticates():
    """The control must permit the case it exists to recognise."""
    private, public = _keypair()
    store = _store(_reviewer("rev-1", "reviewer.security", ["security-inspector"], public))

    ok, reason, evidence = verify_signed_attestation(
        _attest(private, reviewer="reviewer.security", key_id="rev-1",
                role="security-inspector"),
        store=store,
        builder_identity=BUILDER,
    )
    assert ok is True, reason
    assert evidence["signature_verified"] and evidence["identity_verified"]
    assert evidence["role_verified"] and evidence["independent"]


# --------------------------------------------------------------------------
# Independence is derived, never claimed
# --------------------------------------------------------------------------


def test_the_builder_cannot_inspect_their_own_work():
    """Even holding a valid key for the role."""
    private, public = _keypair()
    store = _store(_reviewer("rev-1", BUILDER, ["security-inspector"], public))

    ok, reason, evidence = verify_signed_attestation(
        _attest(private, reviewer=BUILDER, key_id="rev-1", role="security-inspector"),
        store=store,
        builder_identity=BUILDER,
    )
    assert ok is False
    assert "REVIEWER_IS_THE_BUILDER" in reason
    assert evidence["independent"] is False


def test_naming_a_different_builder_cannot_excuse_the_real_one(monkeypatch):
    """Ambient state may tighten this control; it must not re-aim it.

    `FORGE_BUILDER_IDENTITY` used to replace the builder identity outright, so
    setting it to an unrelated name removed the real builder from the excluded
    set — and a builder who also held a trusted reviewer key would then
    authenticate as independent. The check would still be running, just pointed
    somewhere harmless. It is a union now.
    """
    from nornyx_forge.reviewer_trust import (
        BUILDER_IDENTITIES,
        excluded_inspector_identities,
    )

    monkeypatch.setenv("FORGE_BUILDER_IDENTITY", "someone.else")
    excluded = excluded_inspector_identities()
    assert BUILDER_IDENTITIES <= excluded, "naming another builder excused the real one"
    assert "someone.else" in excluded

    private, public = _keypair()
    store = _store(_reviewer("rev-1", BUILDER, ["security-inspector"], public))
    ok, reason, _ = verify_signed_attestation(
        _attest(private, reviewer=BUILDER, key_id="rev-1", role="security-inspector"),
        store=store,
        builder_identity=excluded,
    )
    assert ok is False
    assert "REVIEWER_IS_THE_BUILDER" in reason


def test_an_unset_builder_identity_still_excludes_the_builder(monkeypatch):
    """Absence of the variable must not empty the set."""
    from nornyx_forge.reviewer_trust import (
        BUILDER_IDENTITIES,
        excluded_inspector_identities,
    )

    monkeypatch.delenv("FORGE_BUILDER_IDENTITY", raising=False)
    assert excluded_inspector_identities() == BUILDER_IDENTITIES
    assert BUILDER in BUILDER_IDENTITIES


def test_a_reviewer_cannot_inspect_as_a_role_they_hold_no_key_for():
    private, public = _keypair()
    store = _store(_reviewer("rev-1", "reviewer.tests", ["test-inspector"], public))

    ok, reason, _ = verify_signed_attestation(
        _attest(private, reviewer="reviewer.tests", key_id="rev-1",
                role="security-inspector"),
        store=store,
        builder_identity=BUILDER,
    )
    assert ok is False
    assert "REVIEWER_ROLE_UNAUTHORIZED" in reason


def test_a_revoked_reviewer_cannot_authenticate():
    private, public = _keypair()
    store = _store(
        _reviewer("rev-1", "reviewer.security", ["security-inspector"], public,
                  status="revoked")
    )
    ok, reason, _ = verify_signed_attestation(
        _attest(private, reviewer="reviewer.security", key_id="rev-1",
                role="security-inspector"),
        store=store,
        builder_identity=BUILDER,
    )
    assert ok is False
    assert "REVIEWER_ROLE_UNAUTHORIZED" in reason


def test_signing_with_the_wrong_key_is_refused():
    """A real signature by the wrong reviewer is still the wrong reviewer."""
    _, public = _keypair()
    other_private, _ = _keypair()
    store = _store(_reviewer("rev-1", "reviewer.security", ["security-inspector"], public))

    ok, reason, _ = verify_signed_attestation(
        _attest(other_private, reviewer="reviewer.security", key_id="rev-1",
                role="security-inspector"),
        store=store,
        builder_identity=BUILDER,
    )
    assert ok is False
    assert "ATTESTATION_NOT_AUTHENTICATED" in reason


@pytest.mark.parametrize(
    "field", ["verdict", "inspection_subject_digest", "inspector_role",
              "findings_digest", "tool_version", "reviewer"]
)
def test_every_signed_field_is_covered(field: str):
    """Editing any of them after signing must break authentication.

    Enumerated rather than sampled: a field left out of the signature is a field
    an attacker may rewrite freely, and "we signed the important ones" is how
    that happens.
    """
    private, public = _keypair()
    store = _store(_reviewer("rev-1", "reviewer.security", ["security-inspector"], public))
    signed = _attest(private, reviewer="reviewer.security", key_id="rev-1",
                     role="security-inspector")

    tampered = {**signed, field: "tampered-value"}
    ok, reason, _ = verify_signed_attestation(
        tampered, store=store, builder_identity=BUILDER
    )
    assert ok is False, f"{field} is not covered by the signature"
    # Identity and role mismatches are named specifically; everything else fails
    # the signature itself. Both are refusals, neither is acceptance.
    assert any(
        code in reason
        for code in (
            "ATTESTATION_NOT_AUTHENTICATED",
            "REVIEWER_IDENTITY_MISMATCH",
            "REVIEWER_ROLE_UNAUTHORIZED",
        )
    ), reason


def test_findings_cannot_be_edited_after_review():
    """The digest is signed, so the findings it covers are fixed."""
    private, public = _keypair()
    store = _store(_reviewer("rev-1", "reviewer.security", ["security-inspector"], public))
    signed = _attest(
        private, reviewer="reviewer.security", key_id="rev-1",
        role="security-inspector",
        findings=[{"severity": "P1", "summary": "a real problem"}],
    )

    # The signature still validates: `findings` travels alongside it.
    ok, _, _ = verify_signed_attestation(signed, store=store, builder_identity=BUILDER)
    assert ok is True

    # But the digest no longer describes them, which is what a consumer checks.
    from nornyx_forge.reviewer_trust import findings_digest

    scrubbed = {**signed, "findings": []}
    assert findings_digest(scrubbed["findings"]) != scrubbed["findings_digest"]


# --------------------------------------------------------------------------
# Trust domains stay apart
# --------------------------------------------------------------------------


def test_an_approver_trust_store_is_not_a_reviewer_trust_store():
    """A CFO key must not satisfy `security-inspector`.

    Rejected by schema rather than by hoping the shapes differ: the two stores
    could drift into looking alike, and the point is that they are different
    authorities regardless of shape.
    """
    path = Path(tempfile.mkdtemp()) / "approvers.json"
    path.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.approval_trust_store.v1",
                "signers": [{"key_id": "cfo-1", "public_key": "x"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewerStoreUnavailable) as refusal:
        ReviewerTrustStore.load(path)
    assert "reviewer trust store" in str(refusal.value)


def test_an_absent_store_authenticates_nothing_and_does_not_raise():
    """Absence is an ordinary state; malformation is not. They differ."""
    store = ReviewerTrustStore.load(Path(tempfile.mkdtemp()) / "missing.json")
    assert store.available is False

    ok, reason, _ = verify_signed_attestation(
        {"schema": ATTESTATION_SCHEMA}, store=store, builder_identity=BUILDER
    )
    assert ok is False
    assert "REVIEWER_TRUST_UNAVAILABLE" in reason


def test_a_duplicate_key_id_is_refused():
    """Which reviewer a key means must not depend on ordering."""
    _, public = _keypair()
    path = Path(tempfile.mkdtemp()) / "reviewers.json"
    path.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.reviewer_trust_store.v1",
                "reviewers": [
                    _reviewer("rev-1", "reviewer.a", ["test-inspector"], public),
                    _reviewer("rev-1", "reviewer.b", ["security-inspector"], public),
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReviewerStoreUnavailable) as refusal:
        ReviewerTrustStore.load(path)
    assert "twice" in str(refusal.value)


def test_the_runtime_image_ships_no_reviewer_signing_capability():
    """Verification material only. The issuer stays outside the trust boundary."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copied = [
        line.split()[1]
        for line in dockerfile.splitlines()
        if line.startswith("COPY ") and len(line.split()) > 2
    ]
    assert "scripts" not in copied

    runtime = (ROOT / "src/nornyx_forge/reviewer_trust.py").read_text(encoding="utf-8")
    assert "load_pem_private_key" not in runtime
    assert "Ed25519PrivateKey" not in runtime
    assert ".sign(" not in runtime


def test_the_required_roles_are_stated_not_inferred():
    """Three distinct lenses; a shrinking set would quietly lower the bar."""
    assert REQUIRED_INSPECTOR_ROLES == {
        "test-inspector",
        "architecture-inspector",
        "security-inspector",
    }
