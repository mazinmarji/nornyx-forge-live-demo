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

import shutil
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
