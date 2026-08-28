"""Deleting an expected member of an authority collection must become visible.

Governed source already answered this: a removed file moves the input digest, a
removed contract refuses as SUBJECT_SCOPE_INCOMPLETE. That says nothing about
the other collections, and the failure mode is the same shape wherever it hides:

    expected member deleted
    -> smaller collection accepted as normal
    -> previous authority remains valid

Measured across seven collections, six answered correctly and one did not.
`review_binding.json` was guarded by `if binding_path.exists():` with no else,
so removing it removed every comparison it drives -- eleven integrity-bearing
claims -- and verification reported `intact` with no problems while a real
authenticated inspection stayed standing. Deleting the check was a way to pass
it.

Asserted here against a workspace that genuinely reaches
`independently_inspected`, because the claim is about LOSING that state. The
real repository has no reviewer trust material and never holds it, so measuring
there would prove nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

EVIDENCE = ".nornyx/contracts/evidence"
REFRESH = "scripts/refresh_governance_evidence.py"
AS_OF = "2026-08-11T00:00:00Z"

#: Every collection whose completeness carries authority. Attestations first:
#: once an authenticated inspection claims the required reviewer set, a
#: two-of-three inspection must not keep the authority a three-of-three earned.
DELETIONS = [
    ("one required attestation", f"{EVIDENCE}/attestations/security-inspector.json"),
    ("every attestation", f"{EVIDENCE}/attestations"),
    ("the independent review record", f"{EVIDENCE}/architecture_independent_review.json"),
    ("the evidence index", f"{EVIDENCE}/INDEX.json"),
    ("the review binding", f"{EVIDENCE}/review_binding.json"),
    ("an evidence manifest", f"{EVIDENCE}/architecture_evidence_manifest.json"),
    ("the conformance report", f"{EVIDENCE}/architecture_conformance_report.json"),
]


def _run(work: Path, reviewers, *args: str):
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    env["FORGE_REVIEWER_TRUST_STORE"] = str(
        reviewers.store if reviewers is not None else work / "no-such-store.json"
    )
    env["FORGE_BUILDER_IDENTITY"] = "builder.nornyx_forge"
    return subprocess.run([sys.executable, *args], cwd=work, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", env=env)


def _git(work: Path, *args: str):
    return subprocess.run(["git", "-C", str(work), *args], capture_output=True, check=True)


def _state(work: Path, reviewers) -> dict:
    completed = _run(work, reviewers, REFRESH, "--verify")
    start = completed.stdout.find("{")
    assert start >= 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout[start:])["verification"]


@pytest.fixture(scope="module")
def inspected(tmp_path_factory):
    """A workspace holding a real authenticated inspection."""
    from inspection import authenticate_inspection

    work = tmp_path_factory.mktemp("collections") / "repo"
    work.mkdir(parents=True)
    archive = work.parent / "tree.tar"
    subprocess.run(["git", "-C", str(ROOT), "archive", "-o", str(archive), "HEAD"], check=True)
    shutil.unpack_archive(str(archive), str(work), format="tar")
    archive.unlink()
    for command in (["init", "-q"], ["config", "user.email", "f@x.invalid"],
                    ["config", "user.name", "f"]):
        _git(work, *command)
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "base")

    for step in (["--as-of", AS_OF], ["--sync-contracts"], ["--review-binding"]):
        assert _run(work, None, REFRESH, *step).returncode == 0
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "settled")
    assert _run(work, None, REFRESH, "--as-of", AS_OF).returncode == 0

    reviewers = authenticate_inspection(work, work.parent / "store")
    assert _run(work, reviewers, REFRESH, "--as-of", AS_OF).returncode == 0
    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0
    return work, reviewers


def test_the_fixture_actually_holds_the_state_being_withdrawn(inspected):
    """The benign control. Every case below is about LOSING this."""
    work, reviewers = inspected
    state = _state(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", state
    assert state["integrity_state"] == "intact", state["problems"]


@pytest.mark.parametrize(
    ("label", "relative"), DELETIONS, ids=[case[0] for case in DELETIONS]
)
def test_deleting_an_expected_member_withdraws_authority(
    inspected, label: str, relative: str
):
    """Absence must be detected, never observed as a smaller normal collection."""
    work, reviewers = inspected
    target = work / relative
    assert target.exists(), f"{label}: the fixture does not hold this member"

    holding = work.parent / "held"
    shutil.rmtree(holding, ignore_errors=True)
    holding.mkdir(parents=True)
    if target.is_dir():
        shutil.copytree(target, holding / target.name)
    else:
        shutil.copy2(target, holding / target.name)

    try:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        state = _state(work, reviewers)
    finally:
        if target.is_dir() or not target.exists():
            source = holding / target.name
            if source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        shutil.rmtree(holding, ignore_errors=True)

    assert state["assurance_state"] != "independently_inspected", (
        f"{label}: the collection shrank and the inspection authority survived"
    )


def test_a_missing_binding_is_not_a_passing_verification(inspected):
    """The one that answered wrongly, pinned by its own diagnostic.

    Every case above asserts assurance is withdrawn, and the binding deletion
    could satisfy that for an unrelated reason. This asserts the specific
    failure: verification cannot pass while the artifact carrying the claims it
    recomputes is absent.
    """
    work, reviewers = inspected
    target = work / EVIDENCE / "review_binding.json"
    original = target.read_bytes()
    try:
        target.unlink()
        state = _state(work, reviewers)
    finally:
        target.write_bytes(original)

    assert state["integrity_state"] != "intact", (
        "deleting the binding removed every claim it drives and verification "
        "still reported intact -- deleting the check passed it"
    )
    assert any("review binding is absent" in problem for problem in state["problems"]), (
        state["problems"]
    )


def test_the_fixture_is_restored_after_the_matrix(inspected):
    """Each case must leave the workspace able to reach the state again."""
    work, reviewers = inspected
    state = _state(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", (
        "a deletion case did not restore what it removed"
    )
    assert state["integrity_state"] == "intact", state["problems"]
