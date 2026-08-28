"""A file claiming to be a human approval is a claim, not an approval.

`load_canonical_approval` validated shape exhaustively — `producer.type` is
`human`, every required field present, every scalar safe, the window positive and
within the P7D cap — and authenticated nothing. Dropping a JSON file into the
evidence directory was sufficient to be indexed as a human approval.

This is the same defect R2 removed for inspections. `load_inspection_attestation`
is entombed forty lines below the loader in the same file, with a comment
explaining that a thorough-looking validator which authenticates nothing is worse
than none — because it invites the wrong call. The pattern survived, in that same
file, for the artifact that grants *human approval*: the strongest authority the
system recognises.

An independent exact-head review of `13844c7` found the evidence set forgeable
end to end. This closes the half of it that mints authority.

The tests here sign with a real ephemeral key through the production verifier.
None of them creates a human approval for this repository: every artifact lives
in a temp directory, is verified against a temp trust store, and is discarded.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

REFRESH = "scripts/refresh_governance_evidence.py"
sys.path.insert(0, str(ROOT / "tests"))
from signing import live_window  # noqa: E402

_WINDOW = live_window()
ARTIFACT = "architecture_human_approval.json"


def _unsigned_approval(revision: str) -> dict:
    """Exactly what the old shape-only validator would have accepted."""
    return {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.attacker:architecture_reviewer", "type": "human"},
        "status": "pass",
        "subject_revision": revision,
        # A window around the real clock. The production loader now judges the
        # signed window against a trusted instant, so a date pinned to the
        # calendar expires the day after it is written and every adoption test
        # would fail for a reason unrelated to what it asserts.
        "generated_at": _WINDOW[0],
        "expires_at": _WINDOW[1],
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }


def _run(work: Path, *args: str, store: Path | None = None):
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    # Point at nowhere by default, so an operator's real store cannot leak in and
    # make a negative case pass for the wrong reason.
    env["FORGE_APPROVER_TRUST_STORE"] = str(store or (work / "no-such-store.json"))
    return subprocess.run(
        [sys.executable, *args],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def test_the_loader_refuses_an_unsigned_artifact(tmp_path: Path):
    """The exploit, run against the production loader.

    Asserted in the exploitable direction: the artifact claims the most
    favourable thing it can — a human producer, `status: pass`, a live window —
    and must still establish nothing.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_governance_evidence as r  # noqa: PLC0415

    evidence = tmp_path / "evidence"
    evidence.mkdir(parents=True)
    (evidence / ARTIFACT).write_bytes(
        json.dumps(_unsigned_approval("sha256:" + "a" * 64), indent=2).encode("utf-8")
    )

    original = r.EVIDENCE_DIR
    try:
        r.EVIDENCE_DIR = evidence
        with pytest.raises(SystemExit) as refusal:
            r.load_canonical_approval(ARTIFACT)
    finally:
        r.EVIDENCE_DIR = original

    message = str(refusal.value)
    assert "not an authenticated human approval" in message
    assert "APPROVER_TRUST" in message or "not authenticated" in message.lower()


def test_absence_of_a_trust_store_is_not_permission(tmp_path: Path):
    """Nothing to authenticate against means nothing may be adopted.

    The failure direction matters more than the refusal. A missing store used to
    be irrelevant, because no signature was consulted at all; the tempting fix is
    to treat "no store configured" as "skip the check", which would restore the
    defect under a new name.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_governance_evidence as r  # noqa: PLC0415

    evidence = tmp_path / "evidence"
    evidence.mkdir(parents=True)
    payload = _unsigned_approval("sha256:" + "b" * 64)
    payload["signature"] = "not-a-real-signature"
    (evidence / ARTIFACT).write_bytes(json.dumps(payload, indent=2).encode("utf-8"))

    original = r.EVIDENCE_DIR
    monkey_store = tmp_path / "absent-store.json"
    previous_env = os.environ.get("FORGE_APPROVER_TRUST_STORE")
    try:
        os.environ["FORGE_APPROVER_TRUST_STORE"] = str(monkey_store)
        r.EVIDENCE_DIR = evidence
        with pytest.raises(SystemExit) as refusal:
            r.load_canonical_approval(ARTIFACT)
    finally:
        r.EVIDENCE_DIR = original
        if previous_env is None:
            os.environ.pop("FORGE_APPROVER_TRUST_STORE", None)
        else:
            os.environ["FORGE_APPROVER_TRUST_STORE"] = previous_env

    assert "not an authenticated human approval" in str(refusal.value)


def test_an_absent_artifact_is_still_simply_absent(tmp_path: Path):
    """No approval is the honest state here, and must stay distinguishable.

    A refusal and an absence are different facts. Collapsing them would make
    "nobody has approved this" indistinguishable from "someone tried to forge an
    approval", which is precisely the distinction an audit needs.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_governance_evidence as r  # noqa: PLC0415

    evidence = tmp_path / "evidence"
    evidence.mkdir(parents=True)

    original = r.EVIDENCE_DIR
    try:
        r.EVIDENCE_DIR = evidence
        assert r.load_canonical_approval(ARTIFACT) is None
    finally:
        r.EVIDENCE_DIR = original


def test_the_loader_no_longer_relies_on_shape_alone():
    """Structural: the authentication call must exist in the loader.

    A behavioural test can be satisfied by an unrelated early exit. This pins
    that the authenticating call is actually on the path a valid-shaped artifact
    takes, so a future refactor cannot delete it and stay green because some
    other validation happens to reject the fixture first.
    """
    source = (ROOT / REFRESH).read_text(encoding="utf-8")
    loader = source.split("def load_canonical_approval(", 1)[1].split("\ndef ", 1)[0]
    assert "_authenticate_approval(" in loader, (
        "the human-approval loader no longer authenticates; shape validation "
        "establishes what an artifact says, never who wrote it"
    )
    assert "producer.get(\"type\") != \"human\"" in loader, (
        "the shape checks were removed rather than supplemented"
    )


# --------------------------------------------------------------------------
# With a trust store present, so authentication is what decides
# --------------------------------------------------------------------------
#
# Every test above refuses before reaching `verify_governance_approval`.
# `_authenticate_approval` returns APPROVER_TRUST_UNAVAILABLE when the store has
# no signers, and no test in this module ever configured one -- the `_run`
# helper that sets `FORGE_APPROVER_TRUST_STORE` was written and never called.
#
# Measured consequence: replacing the entire authentication call with
# `return True, "authenticated", {}` left 195 tests passing, across every module
# that can reach the loader. The module is in REQUIRED_MODULES, so its presence
# satisfied the anti-shrink gate while proving nothing about the control it is
# named for.
#
# This is the defect the module's own docstring describes -- a thorough-looking
# validator that authenticates nothing -- reproduced one layer up, in the tests
# written to prove it had been fixed.
#
# So these install a real store first. With one present the store check cannot
# fire, and whatever refuses has to be the authentication.


@pytest.fixture
def anchored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """An evidence directory and a real trust store the loader will consult."""
    from signing import write_trust_store  # noqa: PLC0415

    sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_governance_evidence as r  # noqa: PLC0415

    evidence = tmp_path / "evidence"
    evidence.mkdir(parents=True)
    store = write_trust_store(tmp_path / "approvers.json")
    monkeypatch.setenv("FORGE_APPROVER_TRUST_STORE", str(store))
    monkeypatch.setattr(r, "EVIDENCE_DIR", evidence)
    return r, evidence


def _write(evidence: Path, payload: dict) -> None:
    (evidence / ARTIFACT).write_bytes(json.dumps(payload, indent=2).encode("utf-8"))


def _approval(revision: str) -> dict:
    """A shape-valid approval naming the fixture's trusted human approver."""
    from signing import SUBJECT  # noqa: PLC0415

    payload = _unsigned_approval(revision)
    payload["producer"] = {
        "id": f"{SUBJECT}:architecture_reviewer",
        "type": "human",
    }
    return payload


def test_an_unsigned_artifact_is_refused_when_a_store_is_present(anchored):
    """The exploit, with the store check unable to answer for the refusal.

    This is the case that kills the mutation. With no store the loader refused
    for a reason that had nothing to do with the artifact; with one, an unsigned
    artifact must be refused BY the authentication.
    """
    r, evidence = anchored
    _write(evidence, _approval("sha256:" + "c" * 64))

    with pytest.raises(SystemExit) as refusal:
        r.load_canonical_approval(ARTIFACT)

    message = str(refusal.value)
    assert "not an authenticated human approval" in message
    assert "APPROVAL_UNSIGNED" in message, (
        f"refused, but not for being unsigned: {message}"
    )
    assert "APPROVER_TRUST_UNAVAILABLE" not in message, (
        "the store check answered again, so this test measures nothing"
    )


def test_a_signature_from_an_untrusted_key_is_refused(anchored):
    """A real signature is not authority; a signature from a trusted key is."""
    from signing import sign_governance_record  # noqa: PLC0415

    r, evidence = anchored
    payload = sign_governance_record(_approval("sha256:" + "d" * 64))
    payload["signer_key_id"] = "not-in-the-store"
    _write(evidence, payload)

    with pytest.raises(SystemExit) as refusal:
        r.load_canonical_approval(ARTIFACT)
    assert "not an authenticated human approval" in str(refusal.value)


def test_an_artifact_altered_after_signing_is_refused(anchored):
    """The signature covers the claim, so changing the claim breaks it."""
    from signing import sign_governance_record  # noqa: PLC0415

    r, evidence = anchored
    payload = sign_governance_record(_approval("sha256:" + "e" * 64))
    payload["subject_revision"] = "sha256:" + "f" * 64
    _write(evidence, payload)

    with pytest.raises(SystemExit) as refusal:
        r.load_canonical_approval(ARTIFACT)
    assert "not an authenticated human approval" in str(refusal.value)


def test_a_correctly_signed_approval_is_adopted(anchored):
    """The benign control, and what makes the three refusals above mean anything.

    Without it every refusal here could be "the loader refuses everything", and
    an implementation that always refused would satisfy this module completely.

    This is a SYNTHETIC fixture: an ephemeral key, a temp trust store and a temp
    evidence directory, all discarded when the test ends. It creates no approval
    for this repository and none of it is written into the governed tree.
    """
    from signing import sign_governance_record  # noqa: PLC0415

    r, evidence = anchored
    revision = "sha256:" + "1" * 64
    _write(evidence, sign_governance_record(_approval(revision)))

    adopted = r.load_canonical_approval(ARTIFACT)

    assert adopted is not None, "a correctly signed approval was not adopted"
    assert adopted["subject_revision"] == revision
    assert adopted["producer"]["type"] == "human"


def test_the_loader_authenticates_before_it_reports_success(anchored):
    """Deleting the authentication call must break something here.

    The structural test below pins that `_authenticate_approval(` appears in the
    loader. That survives a mutation of what `_authenticate_approval` RETURNS,
    which is exactly the mutation that went unnoticed -- so this asserts the
    behaviour instead: an artifact that cannot authenticate is not adopted, with
    a store present and the shape entirely valid.
    """
    r, evidence = anchored
    payload = _approval("sha256:" + "2" * 64)
    payload["signature"] = "bm90LWEtc2lnbmF0dXJl"  # valid base64, wrong bytes
    _write(evidence, payload)

    with pytest.raises(SystemExit):
        r.load_canonical_approval(ARTIFACT)
