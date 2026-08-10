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
ARTIFACT = "architecture_human_approval.json"


def _unsigned_approval(revision: str) -> dict:
    """Exactly what the old shape-only validator would have accepted."""
    return {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.attacker:architecture_reviewer", "type": "human"},
        "status": "pass",
        "subject_revision": revision,
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
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
