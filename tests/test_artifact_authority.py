"""Every artifact that can influence a decision declares what kind it is.

TASK 2. An artifact-specific `if` in whichever module happened to read a file is
how `architecture_independent_review.json` came to be stamped `status: pass` in
a contract while its own bytes reported no authenticated inspection: nobody had
written down what kind of thing it was, so nothing could say which check
applied.

So the classification is closed, declared once, and enforced structurally --
an artifact nobody classified fails rather than defaulting to harmless.

TASK 2A. Then each class has to make its claim good behaviourally:

    AUTHENTICATED_EXTERNAL     tamper -> authentication fails
    DERIVED_AUTHENTICATED      tamper -> integrity mismatch, authority withdrawn
    DERIVED_NON_AUTHORITATIVE  tamper -> no decision changes

The third is the one worth attacking hardest. "It is only a report" is exactly
the assumption that was wrong about the review record.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nornyx_forge.governed_subject import (  # noqa: E402
    ARTIFACT_AUTHORITY,
    AUTHENTICATED_EXTERNAL,
    AUTHORITY_CLASSIFICATIONS,
    DERIVED_AUTHENTICATED,
    DERIVED_NON_AUTHORITATIVE,
    INTEGRITY_COMPROMISED,
    INTEGRITY_INTACT,
    UnclassifiedArtifact,
    artifact_authority,
)
from nornyx_forge.subject_observer import observe_governance_integrity  # noqa: E402

EVIDENCE = ROOT / ".nornyx/contracts/evidence"
CONTRACTS = ROOT / ".nornyx/contracts"


# --------------------------------------------------------------------------
# The classification is closed and complete
# --------------------------------------------------------------------------


def test_every_artifact_present_is_classified():
    """The anti-drift control: a new evidence file must declare its kind.

    Derived from what is on disk rather than from a second list, so adding an
    artifact cannot be forgotten here -- the test reads the directory.
    """
    unclassified = []
    for location in sorted(EVIDENCE.rglob("*.json")):
        parent = location.parent.name if location.parent != EVIDENCE else ""
        try:
            artifact_authority(location.name, parent=parent)
        except UnclassifiedArtifact:
            unclassified.append(location.name)
    assert unclassified == [], (
        "these artifacts influence governance, assurance or authorization and "
        f"declare no authority classification: {unclassified}"
    )


def test_an_unknown_artifact_fails_closed():
    """Absence of a classification is a refusal, never a default."""
    with pytest.raises(UnclassifiedArtifact):
        artifact_authority("something_new_nobody_classified.json")


def test_every_declared_classification_is_in_the_closed_vocabulary():
    """A typo'd classification would silently match no verification rule."""
    unknown = {
        name: kind
        for name, kind in ARTIFACT_AUTHORITY.items()
        if kind not in AUTHORITY_CLASSIFICATIONS
    }
    assert unknown == {}, unknown


def test_the_two_derived_classes_are_actually_distinguished():
    """The distinction has to be load-bearing, not decorative.

    If everything derived were classified the same way, the model would say
    nothing. The authenticated-derived artifacts are exactly those recomputed
    from signed material, and they are the ones integrity observation covers.
    """
    authenticated = {n for n, k in ARTIFACT_AUTHORITY.items() if k == DERIVED_AUTHENTICATED}
    plain = {n for n, k in ARTIFACT_AUTHORITY.items() if k == DERIVED_NON_AUTHORITATIVE}
    assert authenticated, "no artifact is derived from authenticated material"
    assert plain, "no artifact is merely derived"
    assert authenticated.isdisjoint(plain)
    assert "architecture_independent_review.json" in authenticated
    assert "architecture_approval_record.json" in authenticated


# --------------------------------------------------------------------------
# TASK 2A: each class makes its claim good
# --------------------------------------------------------------------------


DERIVED_AUTHENTICATED_ATTACKS = [
    ("review verdict replacement", "architecture_independent_review.json",
     b'"authenticated_inspections": {}', b'"authenticated_inspections": {"x": 1}'),
    ("approval state replacement", "architecture_approval_record.json",
     b'"approval": "not_granted"', b'"approval": "granted"'),
]


@pytest.mark.parametrize(
    ("label", "name", "find", "replace"),
    DERIVED_AUTHENTICATED_ATTACKS,
    ids=[case[0] for case in DERIVED_AUTHENTICATED_ATTACKS],
)
def test_forging_a_derived_authenticated_artifact_is_caught(
    label: str, name: str, find: bytes, replace: bytes, tmp_path: Path
):
    """Its digest is recorded, so editing it breaks the recorded digest.

    This is what makes `DERIVED_AUTHENTICATED` safe to keep outside the
    inspection subject: the contract records what the artifact hashed to, and
    integrity observation recomputes it before any authority is granted.

    Against a copy. A sibling test in this file forged inspection records into
    the real tree under `try/finally`, an interrupted run left them there, and
    they reached a commit. The same hazard applies here.
    """
    from mutation_workspace import faithful_copy  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    target = tree / ".nornyx/contracts/evidence" / name
    original = target.read_bytes()
    assert find in original, f"{label}: the fixture no longer matches the artifact"

    target.write_bytes(original.replace(find, replace, 1))
    state = observe_governance_integrity(tree / ".nornyx/contracts")

    assert state.status == INTEGRITY_COMPROMISED, f"{label}: forgery went unobserved"
    assert state.authorizes_consequential_action is False


def test_forging_a_derived_authenticated_artifact_cannot_mint_assurance(tmp_path: Path):
    """The forged verdict must not become `independently_inspected`.

    Editing the review record to claim inspections it does not have is the
    most direct route to fabricated independence, so it is attacked directly
    rather than inferred from the digest check above.

    RUN IN A COPY, and that is not a stylistic preference. This forged three
    `authenticated_inspections` records into the REAL tracked evidence file and
    restored them in `finally` -- which holds right up until a run is
    interrupted between the two. One was: the forged content stayed on disk and
    reached a commit, so a governed artifact in this repository carried three
    `"reviewer": "forged", "verdict": "pass"` entries and `verdict_basis:
    "forged"` until it was regenerated.

    A `finally` is not isolation. The attack is identical against a copy, and a
    copy cannot leave a manufactured attestation in the repository.
    """
    import subprocess  # noqa: PLC0415

    from mutation_validity import require_discriminating_baseline  # noqa: PLC0415
    from mutation_workspace import faithful_copy, isolated_env  # noqa: PLC0415

    def integrity_of(where: Path) -> str:
        done = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
            cwd=where, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=isolated_env(where), timeout=900,
        )
        return json.loads(done.stdout[done.stdout.find("{"):])["verification"][
            "integrity_state"
        ]

    tree = faithful_copy(tmp_path)
    # SETTLE THE COPY FIRST. `faithful_copy` reproduces tracked files verbatim
    # and does not regenerate evidence, so it inherits whatever staleness the
    # repository has -- and a copy that already reports `compromised` cannot
    # show that the forgery below is what compromised it. Lens C found this
    # assertion in exactly that state.
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        settle = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=isolated_env(tree), timeout=900,
        )
        assert settle.returncode == 0, settle.stderr[-400:]
    require_discriminating_baseline(
        "forging a derived authenticated artifact",
        baseline=integrity_of(tree), expected="compromised",
        what="--verify integrity_state in the workspace before the forgery",
    )

    target = tree / ".nornyx/contracts/evidence/architecture_independent_review.json"
    payload = json.loads(target.read_bytes().decode("utf-8"))
    payload["authenticated_inspections"] = {
        role: {"reviewer": "forged", "verdict": "pass"}
        for role in ("test-inspector", "architecture-inspector", "security-inspector")
    }
    payload["verdict_basis"] = "forged"
    target.write_bytes(
        json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )

    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["assurance_state"] == "not_independently_inspected", (
        "a hand-edited review record produced independent inspection"
    )
    assert report["integrity_state"] == "compromised"


NON_AUTHORITATIVE = [
    name for name, kind in ARTIFACT_AUTHORITY.items()
    if kind == DERIVED_NON_AUTHORITATIVE
]


@pytest.mark.parametrize("name", sorted(NON_AUTHORITATIVE))
def test_a_non_authoritative_artifact_cannot_mint_assurance(name: str, tmp_path: Path):
    """The claim each of these makes: forging it changes no verdict.

    Asserted rather than assumed. "It is only a report" was exactly the belief
    that was wrong about the independent review record, and the only way to
    know is to edit the file and look at what the derivation says afterwards.

    Against a copy, for the reason recorded on the sibling tests: a `finally`
    restores nothing if the run does not reach it, and one that did not left
    forged attestation records in a commit.
    """
    import subprocess  # noqa: PLC0415

    from mutation_workspace import faithful_copy  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    target = tree / ".nornyx/contracts/evidence" / name
    if not target.exists():
        pytest.skip(f"{name} is not present in this tree")
    payload = json.loads(target.read_bytes().decode("utf-8"))
    if not isinstance(payload, dict):
        pytest.skip(f"{name} is not an object")
    payload["status"] = "pass"
    payload["approval"] = "granted"
    payload["independent"] = True
    target.write_bytes(
        json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )

    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["assurance_state"] == "not_independently_inspected", (
        f"{name} is classified non-authoritative, but forging it produced "
        "independent inspection"
    )
    # The forgery stays in the copy; the real tree was never touched, so there
    # is nothing here to assert about restoring it.


def test_the_attestation_directory_is_authenticated_external():
    """Classified by location, because attestations are named per role.

    A filename rule would let an attacker choose the classification by choosing
    the filename, which is the opposite of what a classification is for.
    """
    assert artifact_authority("anything.json", parent="attestations") == (
        AUTHENTICATED_EXTERNAL
    )


def test_the_real_repository_is_intact_under_this_model():
    """The benign control for the whole matrix above."""
    state = observe_governance_integrity(CONTRACTS)
    assert state.status == INTEGRITY_INTACT, state.problems
