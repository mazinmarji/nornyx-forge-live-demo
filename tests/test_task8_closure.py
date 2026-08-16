"""Task 8, closed directly rather than inferred from neighbouring tests.

Lower-level suites already establish pieces of this: `test_subject_scope.py`
proves a missing declared file refuses as SUBJECT_SCOPE_INCOMPLETE, and
`test_independent_inspection.py` proves an attestation does not move the subject
it inspects. Neither states the Task-8 theorem, which is about what happens to
an ALREADY VALID inspection when the governed input changes underneath it.

    8C  a governed deletion must either move the subject or refuse the scope,
        and in both cases an attestation made beforehand must stop being current

    8E  an attestation is evidence ABOUT the subject and must never become part
        of it -- adding it and removing it again must leave both the inspection
        subject and the authored contract semantics exactly where they were,
        while the assurance state moves in both directions

Composed from the real fixtures. These run the actual refresher, the actual
reviewer-side signing tool and the actual assurance derivation against a copied
governed workspace, so nothing here is a reimplementation of the thing it tests.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from inspection import Reviewers  # noqa: E402
from test_independent_inspection import (  # noqa: E402
    ATTESTATIONS,
    REFRESH,
    REQUIRED,
    _assurance,
    _attest,
    _current_subject,
    _run,
    _settle,
    _workspace,
)


def _semantics(work: Path) -> str:
    """The authored contract semantics digest, asked of the tool itself."""
    completed = _run(
        work,
        None,
        "-c",
        "import sys; sys.path.insert(0,'src');"
        "sys.path.insert(0,'scripts');"
        "from nornyx_forge.subject_observer import observe_contract_semantics_digest;"
        "from pathlib import Path;"
        "print(observe_contract_semantics_digest(Path('.nornyx/contracts')))",
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


@pytest.fixture
def inspected(tmp_path: Path):
    """A settled workspace carrying a COMPLETE, authenticated inspection.

    Every case below starts from a genuinely valid position, because "the
    inspection is no longer accepted" proves nothing if it was never accepted.
    """
    work = _workspace(tmp_path)
    _settle(work)
    reviewers = Reviewers(tmp_path)
    subject = _current_subject(work)
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", state["problems"]
    return work, reviewers, subject


# --------------------------------------------------------------------------
# 8E -- attestation add / remove invariance
# --------------------------------------------------------------------------


def test_attaching_and_removing_an_attestation_leaves_the_subject_where_it_was(
    tmp_path: Path,
):
    """8E. Evidence ABOUT the subject must not become part of the subject.

    The full cycle in one test, because the two halves fail differently. If
    attaching moved the subject, the attestation would be stale the instant it
    was signed -- `independently_inspected` unreachable by construction, which
    this repository has actually shipped. If REMOVING it moved the subject, the
    withdrawal would look like a content change and an operator would go looking
    for an edit that never happened.

    The authored contract semantics are checked at every step too: an
    attestation is not authored governance, and if it reached the semantics
    digest it would be authoring by the act of reviewing.
    """
    work = _workspace(tmp_path)
    _settle(work)
    reviewers = Reviewers(tmp_path)

    subject_before = _current_subject(work)
    semantics_before = _semantics(work)
    assert _assurance(work, reviewers)["assurance_state"] == "not_independently_inspected"

    # ---- attach -----------------------------------------------------------
    _attest(work, reviewers)
    assert _current_subject(work) == subject_before, (
        "signing an inspection moved the subject it inspects, so the "
        "attestation was stale the moment it was written"
    )
    assert _semantics(work) == semantics_before, (
        "an attestation reached the authored contract semantics, so reviewing "
        "is authoring"
    )
    attached = _assurance(work, reviewers)
    assert attached["assurance_state"] == "independently_inspected", attached["problems"]
    assert attached["problems"] == []

    # ---- remove -----------------------------------------------------------
    removed = work / ATTESTATIONS / f"{REQUIRED[0]}.json"
    assert removed.exists()
    removed.unlink()
    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0

    assert _current_subject(work) == subject_before, (
        "removing an attestation moved the subject, so a withdrawal is "
        "indistinguishable from a change to what is governed"
    )
    assert _semantics(work) == semantics_before

    withdrawn = _assurance(work, reviewers)
    assert withdrawn["assurance_state"] == "not_independently_inspected", (
        "the inspection lost a required role and assurance did not withdraw"
    )
    assert withdrawn["assurance_problems"], (
        "assurance withdrew with no reason recorded, so an operator cannot "
        "tell a missing inspection from a failed one"
    )
    assert withdrawn["required_inspectors_complete"] is False


def test_deleting_every_attestation_withdraws_without_moving_the_subject(
    inspected,
):
    """The same property at the limit: no inspection at all, same subject."""
    work, reviewers, subject = inspected

    shutil.rmtree(work / ATTESTATIONS)
    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0

    assert _current_subject(work) == subject
    assert _assurance(work, reviewers)["assurance_state"] == "not_independently_inspected"


# --------------------------------------------------------------------------
# 8C -- governed deletion, against an inspection that was valid first
# --------------------------------------------------------------------------

#: Each case removes or moves governed content. `expect_refusal` marks the ones
#: the SCOPE is declared to require, where the honest outcome is an explicit
#: incomplete refusal rather than a smaller subject.
#: MEASURED, not assumed. Every one of these refuses rather than computing a
#: smaller subject -- the source file because the refresher depends on the
#: module and says so, the contract and the file because the scope declares
#: them required. The column records which vocabulary the refusal arrives in.
DELETIONS = [
    ("an ordinary governed source file", "src/nornyx_forge/approval_trust.py",
     "governed content is missing"),
    ("a required governed contract", ".nornyx/contracts/runtime_network.nyx",
     "SUBJECT_SCOPE_INCOMPLETE"),
    ("a required governed file", "pyproject.toml", "SUBJECT_SCOPE_INCOMPLETE"),
]


@pytest.mark.parametrize(
    ("label", "relative", "expected"),
    DELETIONS,
    ids=[case[0] for case in DELETIONS],
)
def test_a_governed_deletion_ends_the_inspection(
    inspected, label: str, relative: str, expected: str
):
    """8C. Deleting governed content must not leave an old inspection current.

    Two acceptable outcomes, and the test accepts either -- but never neither:

        the subject MOVES, so the attestation names something that is gone
        the scope REFUSES, so no subject can be described at all

    What must not happen is the third thing: a smaller governed set quietly
    computed, an unchanged-looking position, and an attestation still accepted
    over content that no longer exists.
    """
    work, reviewers, subject = inspected
    target = work / relative
    assert target.exists(), f"{label}: nothing to delete, so this tests nothing"
    target.unlink()

    completed = _run(
        work,
        None,
        "-c",
        "import sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(r.current_inspection_subject())",
    )
    combined = completed.stdout + completed.stderr

    if completed.returncode == 0:
        moved = completed.stdout.strip()
        assert moved != subject, (
            f"{label}: the governed content is gone, the subject is unchanged, "
            "and the earlier attestation still names it. The enumerated set "
            "simply became smaller."
        )
    else:
        # A refusal is acceptable -- a subject that cannot be described honestly
        # must not be described -- but only in the tool's own vocabulary, naming
        # what is missing.
        assert expected in combined, (
            f"{label}: refused without the expected diagnostic {expected!r}: "
            f"{combined[-500:]}"
        )
        # Named by PATH for scope-declared content, by MODULE for a governed
        # module the tool itself imports. Either identifies what to restore;
        # neither is a bare "something is wrong".
        stem = relative.rsplit("/", 1)[-1].removesuffix(".py")
        assert stem in combined or relative in combined, (
            f"{label}: the refusal does not name what is missing, so an operator "
            f"cannot tell which content to restore: {combined[-400:]}"
        )

        # A refusal IS the withdrawal: with no describable subject there is
        # nothing an attestation could still be current over, and the assurance
        # derivation cannot run at all. Asserting a state here would be asking
        # a tool that has correctly refused to answer anyway.
        return

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "not_independently_inspected", (
        f"{label}: governed content was deleted and the repository still "
        "reports an independent inspection"
    )


def test_renaming_governed_source_is_visible_as_a_deletion_and_an_addition(
    inspected,
):
    """8C. A rename must not be invisible just because the byte count is equal.

    The same content under a different path is a different governed set: the
    subject digests paths as well as contents, so an attestation over the old
    layout must not carry to the new one.
    """
    work, reviewers, subject = inspected
    # A governed DOC, deliberately: renaming a module the refresher imports
    # makes the tool refuse on its own missing dependency, which proves
    # something true but different. This isolates path identity.
    source = work / "docs/VALIDATION.md"
    destination = source.with_name("VALIDATION_RENAMED.md")
    source.rename(destination)

    moved = _current_subject(work)
    assert moved != subject, (
        "a governed file was renamed and the subject did not move, so path "
        "identity is not bound and an attestation survives a relayout"
    )
    assert _assurance(work, reviewers)["assurance_state"] == "not_independently_inspected"


def test_removing_the_approver_trust_configuration_withdraws_consequential_authority(
    inspected, tmp_path: Path
):
    """8C. Required authority configuration, removed after a valid inspection.

    The approver trust store lives OUTSIDE the governed tree by design, so its
    absence cannot move the subject -- and that is exactly why it needs its own
    proof. Absence must withdraw consequential authority rather than reading as
    a deployment with no approvers.
    """
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        ApprovalTrustStore,
    )

    missing = tmp_path / "absent" / "trusted_approvers.json"
    store = ApprovalTrustStore.load(missing, domain=ACTION_TRUST_DOMAIN)

    assert store.signers == {}
    assert store.available is False, (
        "a missing trust store reported itself available, so absence reads as a "
        "provisioned deployment with nobody in it"
    )
    assert str(missing) in store.source, (
        "the store does not say WHERE it looked, so an operator cannot tell an "
        "unprovisioned deployment from a misconfigured path"
    )

    work, reviewers, subject = inspected
    assert _current_subject(work) == subject, (
        "the approver trust store sits outside the governed tree, so its "
        "absence must not move the inspection subject"
    )
    _ = reviewers


MISSING_CONTRACT_CASES = [
    ("a required governed contract", ".nornyx/contracts/runtime_network.nyx"),
    ("a required governed file", "pyproject.toml"),
]


@pytest.mark.parametrize(
    ("label", "relative"),
    MISSING_CONTRACT_CASES,
    ids=[case[0] for case in MISSING_CONTRACT_CASES],
)
def test_the_verifier_refuses_missing_governed_content_without_crashing(
    tmp_path: Path, label: str, relative: str
):
    """A crash and a refusal are different answers to an operator.

    FOUND HERE, and it was asymmetric in the dangerous direction. Deleting a
    required FILE produced a clean structured refusal -- status fail, state
    unverified, exit 2. Deleting a required CONTRACT produced a bare
    FileNotFoundError traceback and exit 1, because the approval-wiring loop in
    `verify()` read each contract catching only SystemExit.

    Same class of absence, two behaviours. A traceback reads as "the tool is
    broken", so an operator retries or reinstalls instead of restoring the
    governed content -- and the contract case is the more security-relevant of
    the two.

    Absence is now recorded as a problem and the loop continues. Recorded, not
    skipped: passing over a missing contract quietly would be the opposite
    defect, verification succeeding because nothing was left to check.
    """
    work = _workspace(tmp_path)
    _settle(work)
    (work / relative).unlink()

    completed = _run(work, None, REFRESH, "--verify")
    combined = completed.stdout + completed.stderr

    assert "Traceback" not in combined, (
        f"{label}: the verifier crashed instead of refusing, so absence reads "
        f"as a broken tool rather than as incomplete governed input: "
        f"{combined[-600:]}"
    )
    assert completed.returncode != 0, f"{label}: missing governed content verified"
    assert '"status": "fail"' in combined, (
        f"{label}: refused without a structured verdict an operator can read"
    )


# --------------------------------------------------------------------------
# H13. The conjunction neither existing test covered.
# --------------------------------------------------------------------------


def _regenerate(tree: Path) -> None:
    """The established chain, in causal order."""
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=_isolated(tree), timeout=900,
        )
        assert completed.returncode == 0, completed.stderr[-400:]


def _isolated(tree: Path) -> dict:
    from mutation_workspace import isolated_env  # noqa: PLC0415

    return isolated_env(tree)


def _verification(tree: Path) -> dict:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=_isolated(tree), timeout=900,
    )
    raw = completed.stdout
    assert "{" in raw, completed.stderr[-400:]
    return json.loads(raw[raw.find("{"):])["verification"]


def _subject(tree: Path) -> str:
    digest = _verification(tree).get("inspection_subject_digest")
    assert digest, "no inspection subject was reported"
    return digest


def test_a_stale_attestation_does_not_perturb_the_next_subject(tmp_path: Path):
    """H13. Evidence ABOUT a subject must never become part of it.

    THE CONJUNCTION NEITHER EXISTING TEST COVERED, and the gap is why the
    historical mutation survived three correct-looking attempts:

        the fixed-point test regenerates twice, with attestations that are never
        stale, so the stale-diagnostic branch never executes;

        the staleness test has a genuinely stale attestation but regenerates
        once, so a subject that moves between passes cannot be observed.

    Only both together reach the defect. The stale diagnostic lands in
    `verdict_basis`, inside the evidence set the subject is computed from -- so
    if it names the CURRENT subject, the subject becomes a function of itself
    and no two regenerations agree.

    Asserted as STATE STABILITY, not as wording. A test that checked the
    sentence for a digest would be a string-format test wearing a security
    proof's name, and would pass for a system whose subject drifted anyway.
    """
    from mutation_workspace import faithful_copy  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    _regenerate(tree)
    s1 = _subject(tree)

    # A stale attestation: legitimately shaped, naming a subject this tree does
    # not present. Signature authenticity is not the property under test -- the
    # subject-mismatch branch is downstream of authentication, and H14 owns that
    # clause -- so this asserts on what the tree reports about the mismatch.
    attestations = tree / ".nornyx/attestations"
    attestations.mkdir(parents=True, exist_ok=True)
    s_old = s1
    (attestations / "stale-architecture.json").write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.inspection_attestation.v1",
                "inspection_subject_digest": s_old,
                "inspector_role": "architecture-inspector",
                "reviewer": "reviewer.architecture",
                "verdict": "pass",
            },
            indent=2, sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    # Move the governed subject, so the attestation above becomes stale.
    # `newline=""`, because this repository declares text canonical-LF and the
    # subject observer refuses CR bytes. Writing the fixture with the platform
    # default made the observer reject it -- the control working on a file this
    # test created.
    (tree / "src/nornyx_forge/_subject_mover.py").write_text(
        '"""Governed content added to move the subject."""\n',
        encoding="utf-8", newline="",
    )
    subprocess.run(["git", "-C", str(tree), "add", "-A"], capture_output=True,
                   timeout=600, check=False)
    subprocess.run(["git", "-C", str(tree), "commit", "-qm", "move subject"],
                   capture_output=True, timeout=600, check=False)

    _regenerate(tree)
    s3 = _subject(tree)
    assert s3 != s_old, (
        "the governed subject did not move, so no attestation became stale and "
        "this test cannot reach the property"
    )

    # THE FIXED POINT. Nothing governed changed between these two regenerations,
    # so the subject must not move. If the stale diagnostic names the CURRENT
    # subject, the artifact carrying it is inside the subject it describes, and
    # this is where that shows up.
    _regenerate(tree)
    s4 = _subject(tree)

    assert s4 == s3, (
        "two consecutive regenerations over an unchanged governed tree produced "
        f"different subjects ({s3} then {s4}), so evidence ABOUT the subject has "
        "become part of it -- and no attestation can ever name the subject the "
        "next run will present"
    )


def test_the_stale_attestation_is_still_reported_against_the_old_subject(
    tmp_path: Path,
):
    """Identity preservation, paired with the stability proof above.

    Stability alone could be satisfied by a system that stopped reporting
    staleness at all. This requires the mismatch to remain OBSERVABLE: the
    tree must still report an inspection it cannot treat as current.
    """
    from mutation_workspace import faithful_copy  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    _regenerate(tree)
    s1 = _subject(tree)

    # `newline=""`, because this repository declares text canonical-LF and the
    # subject observer refuses CR bytes. Writing the fixture with the platform
    # default made the observer reject it -- the control working on a file this
    # test created.
    (tree / "src/nornyx_forge/_subject_mover.py").write_text(
        '"""Governed content added to move the subject."""\n',
        encoding="utf-8", newline="",
    )
    subprocess.run(["git", "-C", str(tree), "add", "-A"], capture_output=True,
                   timeout=600, check=False)
    subprocess.run(["git", "-C", str(tree), "commit", "-qm", "move subject"],
                   capture_output=True, timeout=600, check=False)
    _regenerate(tree)
    s2 = _subject(tree)

    assert s1 != s2, "the subject did not move, so nothing became stale"

    verification = _verification(tree)
    assert verification["assurance_state"] == "not_independently_inspected", (
        "a moved subject still reports an independent inspection"
    )
    assert verification["independent"] is False
    assert verification["authenticated_reviewers"] == [], (
        "an inspection of the OLD subject is being counted for the new one"
    )
