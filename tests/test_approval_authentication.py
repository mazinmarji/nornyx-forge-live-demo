"""A grant cannot authenticate itself.

An independent review computed the canonical request for
``wire $10,000,000 to attacker``, minted its own approval, wrote
``approver_type: "human"`` into it, and the boundary released the effect. That
field asserted the very thing it was being trusted to prove.

Authority now requires a detached Ed25519 signature over the complete canonical
grant, verified against a trust store held outside the governed repository. The
direction is what matters: the grant claims an identity and a role; the trust
store is what says a key belongs to that identity and may act in that role.

Every denial below asserts the same three things — DENY, the callback never ran,
and the ledger is untouched. A refusal that consumed the grant would destroy a
real approval; a refusal that ran the effect would not be a refusal.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from base64 import b64encode
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from issue_action_approval import sign_grant  # noqa: E402

from nornyx_forge.approval_trust import (  # noqa: E402
    APPROVAL_SCHEMA,
    ApprovalTrustStore,
    TrustStoreUnavailable,
    verify_signed_approval,
)
from nornyx_forge.nornyx_runtime import (
    APPROVAL_NOT_AUTHENTICATED,
    ActionDescriptor,
    ApprovalLedger,
    RuntimeContext,
    canonical_action_request,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: E402

NOW = "2026-08-03T00:00:00Z"
KEY_ID = "fixture-approval-01"
SUBJECT = "human.test_fixture"

DESCRIPTOR = ActionDescriptor(
    operation="issue refund",
    resource="customer:omar",
    destination="zone.external_customer",
    parameters={"amount": 5000, "currency": "USD"},
)


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, str]:
    """A signing key that exists only for this test module."""
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


@pytest.fixture
def trust_store(keypair):
    _, public = keypair
    return load_trust_store_from_entries(
        [
            {
                "key_id": KEY_ID,
                "algorithm": "Ed25519",
                "subject": SUBJECT,
                "subject_type": "human",
                "roles": ["operations_owner"],
                "public_key": public,
                "status": "active",
            }
        ]
    )


def load_trust_store_from_entries(entries: list[dict], tmp: Path | None = None):
    """Build a store the way a deployment would: a real file, loaded once."""
    import tempfile

    target = Path(tmp or tempfile.mkdtemp()) / "trusted_approvers.json"
    target.write_text(json.dumps({"signers": entries}, indent=2), encoding="utf-8")
    return ApprovalTrustStore.load(target)


def _repo(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for command in (["init", "-q"], ["config", "user.email", "f@x.invalid"],
                    ["config", "user.name", "f"]):
        subprocess.run(["git", "-C", str(work), *command], capture_output=True, check=True)
    return work


def _request(*, attempt: int = 1):
    return canonical_action_request(
        mission_id="CASE-1",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=DESCRIPTOR,
        attempt=attempt,
    )


def _grant(request, keypair, **overrides) -> dict:
    """A complete, correctly signed grant — then optionally tampered."""
    private, _ = keypair
    payload = {
        "schema": APPROVAL_SCHEMA,
        "approval_id": "ACT-0001",
        "request_digest": request.digest,
        "approver": SUBJECT,
        "approver_role": "operations_owner",
        "signer_key_id": KEY_ID,
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "granted": True,
    }
    sign_over = dict(payload)
    sign_over.update(overrides.pop("sign_over", {}))
    signature = sign_grant(sign_over, private)

    payload.update(overrides)
    # The fields validate_action_approval also needs, outside the signed set.
    payload.update(
        {
            "approver_type": "human",
            "request_id": request.request_id,
            "attempt_id": request.attempt_id,
            "subject_revision": request.subject_revision,
            "capability": request.capability,
            "destination": request.destination,
            "payload_digest": request.payload_digest,
            "signature": signature,
        }
    )
    for key, value in overrides.items():
        payload[key] = value
    return payload


def _release(work: Path, grant, store, *, request=None, attempt: int = 1):
    ledger_path = work / "ledger.sqlite3"
    boundary = _permissive_boundary(
        work,
        runtime_context=RuntimeContext.for_test(work, at=NOW, revision=TEST_REVISION),
    )
    boundary.approver_trust_store = store
    boundary.approval_ledger = ApprovalLedger(ledger_path)
    ran: list[int] = []
    decision, _ = boundary.evaluate_and_execute(
        mission_id="CASE-1",
        risk="high",
        action=lambda: ran.append(1) or "ran",
        action_approval=grant,
        action_request=request,
        action_descriptor=None if request is not None else DESCRIPTOR,
        attempt=attempt,
    )
    rows = sqlite3.connect(ledger_path).execute(
        "SELECT COUNT(*) FROM consumed_approvals"
    ).fetchone()[0]
    return decision, len(ran), rows


# --------------------------------------------------------------------------


def test_the_reported_exploit_is_refused(tmp_path: Path, trust_store):
    """The exact grant the reviewer minted, reproduced verbatim."""
    work = _repo(tmp_path)
    request = canonical_action_request(
        mission_id="CASE-1",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=ActionDescriptor(
            operation="wire $10,000,000 to attacker",
            resource="account:attacker",
            destination="zone.external_customer",
            parameters={"amount": 10_000_000, "currency": "USD"},
        ),
    )
    self_issued = {
        "granted": True,
        "approval_id": "ACT-SELF",
        "approver": "human:operations_owner",
        "approver_type": "human",
        "approver_role": "operations_owner",
        "request_id": request.request_id,
        "attempt_id": request.attempt_id,
        "subject_revision": request.subject_revision,
        "capability": request.capability,
        "destination": request.destination,
        "payload_digest": request.payload_digest,
        "request_digest": request.digest,
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
    }
    ledger = work / "ledger.sqlite3"
    boundary = _permissive_boundary(
        work, runtime_context=RuntimeContext.for_test(work, at=NOW, revision=TEST_REVISION)
    )
    boundary.approver_trust_store = trust_store
    boundary.approval_ledger = ApprovalLedger(ledger)
    ran: list[int] = []
    decision, _ = boundary.evaluate_and_execute(
        mission_id="CASE-1",
        risk="high",
        action=lambda: ran.append(1) or "ran",
        action_approval=self_issued,
        action_request=request,
    )
    assert decision.effect == "DENY"
    assert decision.code == APPROVAL_NOT_AUTHENTICATED
    assert ran == []
    assert sqlite3.connect(ledger).execute(
        "SELECT COUNT(*) FROM consumed_approvals"
    ).fetchone()[0] == 0


def test_a_correctly_signed_grant_releases_exactly_once(tmp_path: Path, keypair, trust_store):
    work = _repo(tmp_path)
    request = _request()
    grant = _grant(request, keypair)

    decision, ran, rows = _release(work, grant, trust_store, request=request)
    assert decision.effect == "ALLOW", decision.evidence.get("action_binding")
    assert ran == 1 and rows == 1

    decision, ran, rows = _release(work, grant, trust_store, request=request)
    assert decision.effect == "DENY", "a signed grant replayed"
    assert ran == 0 and rows == 1


@pytest.mark.parametrize(
    ("label", "mutation"),
    [
        ("no signature at all", {"signature": ""}),
        ("corrupt signature", {"signature": b64encode(b"x" * 64).decode("ascii")}),
        ("unknown key", {"signer_key_id": "not-in-the-store"}),
        ("role not trusted for this key", {"approver_role": "network_governance_owner"}),
        ("approver altered after signing", {"approver": "human.someone_else"}),
        ("expiry altered after signing", {"expires_at": "2026-08-09T00:00:00Z"}),
        ("decision flipped after signing", {"granted": True, "approval_id": "ACT-OTHER"}),
        ("request digest altered", {"request_digest": "sha256:" + "0" * 64}),
    ],
)
def test_a_tampered_or_untrusted_grant_is_refused(
    label: str, mutation: dict, tmp_path: Path, keypair, trust_store
):
    work = _repo(tmp_path)
    request = _request()
    grant = _grant(request, keypair, **mutation)

    decision, ran, rows = _release(work, grant, trust_store, request=request)
    assert decision.effect == "DENY", f"{label} was released"
    assert ran == 0, f"{label} reached the callback"
    assert rows == 0, f"{label} consumed the approval"


@pytest.mark.parametrize(
    ("label", "descriptor"),
    [
        ("amount altered", ActionDescriptor("issue refund", "customer:omar",
                                            "zone.external_customer",
                                            {"amount": 5_000_000, "currency": "USD"})),
        ("resource altered", ActionDescriptor("issue refund", "customer:attacker",
                                              "zone.external_customer",
                                              {"amount": 5000, "currency": "USD"})),
    ],
)
def test_altering_the_act_after_signing_is_refused(
    label: str, descriptor: ActionDescriptor, tmp_path: Path, keypair, trust_store
):
    """The signature covers the request digest, which covers the whole act."""
    work = _repo(tmp_path)
    signed_request = _request()
    grant = _grant(signed_request, keypair)

    altered = canonical_action_request(
        mission_id="CASE-1", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor,
    )
    decision, ran, rows = _release(work, grant, trust_store, request=altered)
    assert decision.effect == "DENY", f"{label} was released"
    assert ran == 0 and rows == 0


@pytest.mark.parametrize(
    ("label", "generated", "expires"),
    [
        ("expired", "2026-07-20T00:00:00Z", "2026-07-25T00:00:00Z"),
        ("not yet valid", "2026-09-01T00:00:00Z", "2026-09-05T00:00:00Z"),
    ],
)
def test_a_signed_grant_outside_its_window_is_refused(
    label: str, generated: str, expires: str, tmp_path: Path, keypair, trust_store
):
    """Correctly signed and genuinely trusted, but not now."""
    work = _repo(tmp_path)
    request = _request()
    grant = _grant(
        request,
        keypair,
        sign_over={"generated_at": generated, "expires_at": expires},
        generated_at=generated,
        expires_at=expires,
    )
    decision, ran, rows = _release(work, grant, trust_store, request=request)
    assert decision.effect == "DENY", f"{label} was released"
    assert ran == 0 and rows == 0


def test_an_attempt_one_signature_cannot_release_attempt_two(
    tmp_path: Path, keypair, trust_store
):
    work = _repo(tmp_path)
    first = _request(attempt=1)
    grant = _grant(first, keypair)
    second = _request(attempt=2)

    decision, ran, rows = _release(work, grant, trust_store, request=second, attempt=2)
    assert decision.effect == "DENY"
    assert ran == 0 and rows == 0


def test_no_trust_store_means_no_consequential_authority(tmp_path: Path, keypair):
    """The application still runs; the release does not.

    Same shape as the unverifiable-revision case: missing assurance removes
    consequential authority rather than stopping the application.
    """
    work = _repo(tmp_path)
    request = _request()
    grant = _grant(request, keypair)

    decision, ran, rows = _release(work, grant, ApprovalTrustStore(), request=request)
    assert decision.effect == "DENY"
    assert decision.code == APPROVAL_NOT_AUTHENTICATED
    assert ran == 0 and rows == 0

    boundary = _permissive_boundary(
        work, runtime_context=RuntimeContext.for_test(work, at=NOW, revision=TEST_REVISION)
    )
    boundary.approver_trust_store = ApprovalTrustStore()
    low, result = boundary.evaluate_and_execute(
        mission_id="CASE-LOW", risk="low", action=lambda: "done"
    )
    assert low.effect == "ALLOW" and result == "done"


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("not JSON", "{not json"),
        ("no signers list", json.dumps({"keys": []})),
        ("signer missing fields", json.dumps({"signers": [{"key_id": "k"}]})),
        ("unsupported algorithm", json.dumps({"signers": [{
            "key_id": "k", "algorithm": "HS256", "subject": "s",
            "subject_type": "human", "roles": ["operations_owner"], "public_key": "x"}]})),
        ("no roles", json.dumps({"signers": [{
            "key_id": "k", "algorithm": "Ed25519", "subject": "s",
            "subject_type": "human", "roles": [], "public_key": "x"}]})),
    ],
)
def test_a_malformed_trust_store_is_a_governed_refusal(
    label: str, payload: str, tmp_path: Path
):
    """Absence and malformation are different facts and must not look alike."""
    store = tmp_path / "trusted_approvers.json"
    store.write_text(payload, encoding="utf-8")
    with pytest.raises(TrustStoreUnavailable):
        ApprovalTrustStore.load(store)


def test_a_revoked_key_cannot_release(tmp_path: Path, keypair):
    work = _repo(tmp_path)
    _, public = keypair
    store = load_trust_store_from_entries(
        [{"key_id": KEY_ID, "algorithm": "Ed25519", "subject": SUBJECT,
          "subject_type": "human", "roles": ["operations_owner"],
          "public_key": public, "status": "revoked"}],
        tmp_path,
    )
    request = _request()
    decision, ran, rows = _release(work, _grant(request, keypair), store, request=request)
    assert decision.effect == "DENY"
    assert ran == 0 and rows == 0


def test_a_non_human_trusted_subject_cannot_release(tmp_path: Path, keypair):
    """A trusted key is not automatically a trusted *human*."""
    work = _repo(tmp_path)
    _, public = keypair
    store = load_trust_store_from_entries(
        [{"key_id": KEY_ID, "algorithm": "Ed25519", "subject": SUBJECT,
          "subject_type": "service", "roles": ["operations_owner"],
          "public_key": public, "status": "active"}],
        tmp_path,
    )
    request = _request()
    decision, ran, rows = _release(work, _grant(request, keypair), store, request=request)
    assert decision.effect == "DENY"
    assert ran == 0 and rows == 0


def test_the_trust_store_is_not_inside_the_governed_repository():
    """Root authority a builder can edit is not root authority.

    Committing the store would mean: change the repo, add your key, sign your
    own approval, and the boundary agrees.
    """
    from nornyx_forge.approval_trust import DEFAULT_TRUST_STORE

    repo = Path(__file__).resolve().parents[1]
    assert repo not in DEFAULT_TRUST_STORE.parents
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    assert "trusted_approvers.json" not in tracked


def test_the_runtime_cannot_sign(tmp_path: Path):
    """The verifier must not be able to produce what it verifies.

    This is the whole reason for Ed25519 over a shared secret, so it is asserted
    rather than assumed.
    """
    runtime = (
        Path(__file__).resolve().parents[1] / "src/nornyx_forge/nornyx_runtime.py"
    ).read_text(encoding="utf-8")
    assert "sign_grant" not in runtime
    assert "Ed25519PrivateKey" not in runtime


def test_no_module_under_src_implements_signing(tmp_path: Path):
    """Level 1 of 3: source topology.

    No exception, and no module carrying a signer with a comment saying not to
    call it — that would leave the property resting on nobody calling it. The
    issuer lives in scripts/, across the trust boundary.
    """
    src = Path(__file__).resolve().parents[1] / "src"
    offenders = [
        str(path.relative_to(src))
        for path in sorted(src.rglob("*.py"))
        if "Ed25519PrivateKey" in path.read_text(encoding="utf-8")
        or "def sign_grant" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"signing must not appear under src/: {offenders}"


def test_the_runtime_image_does_not_ship_the_signer():
    """Level 2 of 3: package and image contents.

    The Dockerfile copies src and .nornyx. It must not copy scripts/, which is
    where the private-key tooling lives.
    """
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    copied = [
        line.split()[1]
        for line in dockerfile.splitlines()
        if line.startswith("COPY ") and len(line.split()) > 2
    ]
    assert "scripts" not in copied, "the image must not contain the issuer"
    assert "." not in copied, "copying the whole context would ship the issuer"
    assert (root / "scripts/issue_action_approval.py").exists()


def test_runtime_configuration_exposes_no_private_key_path():
    """Level 3 of 3: runtime configuration.

    The compose environment and the trust-store contract deal in public
    verification material only. A private-key path reachable from runtime
    configuration would reopen the boundary the other two levels close.
    """
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8").lower()
    for forbidden in ("private_key", "private-key", "signing_key", "secret_key"):
        assert forbidden not in compose, f"compose exposes {forbidden}"

    trust = (root / "src/nornyx_forge/approval_trust.py").read_text(encoding="utf-8")
    assert "private_key" not in trust.replace("private_key_bytes", "")


def test_an_operator_issued_approval_verifies_through_the_production_verifier(
    tmp_path: Path,
):
    """The boundary must accept what the issuer produces, and only that.

    End to end across the trust boundary: the CLI generates a keypair, Forge
    emits a pending request, the issuer signs that exact request with the
    private key, and the production verifier releases it — once.
    """
    import subprocess as sp

    root = Path(__file__).resolve().parents[1]
    issuer = root / "scripts/issue_action_approval.py"

    generated = json.loads(
        sp.run([sys.executable, str(issuer), "--generate-keypair"],
               capture_output=True, text=True, check=True).stdout
    )
    key_file = tmp_path / "operator.key"
    key_file.write_text(generated["private_key"], encoding="utf-8")

    request = _request()
    pending = tmp_path / "pending.json"
    pending.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.pending_action_request.v1",
                "request": request.canonical(),
                "request_digest": request.digest,
                "attempt_id": request.attempt_id,
            }
        ),
        encoding="utf-8",
    )

    signed = json.loads(
        sp.run(
            [sys.executable, str(issuer), "--request", str(pending),
             "--approver", SUBJECT, "--role", "operations_owner",
             "--key-id", KEY_ID, "--private-key", str(key_file),
             "--expires", "2099-01-01T00:00:00Z"],
            capture_output=True, text=True, check=True,
        ).stdout
    )
    # The bindings validate_action_approval checks, carried alongside.
    signed.update(
        {
            "approver_type": "human",
            "request_id": request.request_id,
            "attempt_id": request.attempt_id,
            "subject_revision": request.subject_revision,
            "capability": request.capability,
            "destination": request.destination,
            "payload_digest": request.payload_digest,
            "generated_at": signed["generated_at"],
            "expires_at": signed["expires_at"],
        }
    )

    store = load_trust_store_from_entries(
        [{"key_id": KEY_ID, "algorithm": "Ed25519", "subject": SUBJECT,
          "subject_type": "human", "roles": ["operations_owner"],
          "public_key": generated["public_key"], "status": "active"}],
        tmp_path,
    )
    authentic, reason, evidence = verify_signed_approval(signed, trust_store=store)
    assert authentic, reason
    assert evidence["signature_verified"] is True


def test_the_verifier_process_cannot_mint_what_it_accepts():
    """The property, stated directly rather than inferred from file layout."""
    import nornyx_forge.approval_trust as trust_module

    assert not hasattr(trust_module, "sign_grant")
    package = Path(trust_module.__file__).resolve().parent
    assert not any(
        "Ed25519PrivateKey" in path.read_text(encoding="utf-8")
        for path in package.rglob("*.py")
    )


def test_approval_trust_does_not_import_the_application_or_effect_layers():
    """A verifier that can reach effect code is no longer separable from it."""
    module = (
        Path(__file__).resolve().parents[1] / "src/nornyx_forge/approval_trust.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("demo_app", "nornyx_runtime", "evidence", "claude_worker"):
        assert f"import {forbidden}" not in module, forbidden
        assert f"from .{forbidden}" not in module, forbidden
        assert f"from nornyx_forge.{forbidden}" not in module, forbidden


def test_the_trust_store_is_resolved_once_not_per_decision():
    """The environment must not be an ambient selector of the root of trust.

    Resolving the location per authorization would mean setting a variable
    between two calls makes the second answer to a different authority.
    """
    runtime = (
        Path(__file__).resolve().parents[1] / "src/nornyx_forge/nornyx_runtime.py"
    ).read_text(encoding="utf-8")
    # The load happens in the constructor, and the decision path uses the object.
    constructor, decision_path = runtime.split("def _official(", 1)
    assert "ApprovalTrustStore.load()" in constructor
    assert "ApprovalTrustStore.load()" not in decision_path
    assert "trust_store_path()" not in decision_path


def test_authentication_evidence_names_the_store_without_leaking_key_material(
    tmp_path: Path, keypair, trust_store
):
    """A reader needs to know the decision was anchored, not to re-derive it."""
    work = _repo(tmp_path)
    request = _request()
    decision, _, _ = _release(work, _grant(request, keypair), trust_store, request=request)

    authentication = decision.evidence["approval_authentication"]
    assert authentication["signature_verified"] is True
    assert authentication["identity_verified"] is True
    assert authentication["role_verified"] is True
    assert authentication["signer_key_id"] == KEY_ID
    assert authentication["trust_store_digest"].startswith("sha256:")

    _, public = keypair
    assert public not in json.dumps(decision.evidence), "public key material leaked"
