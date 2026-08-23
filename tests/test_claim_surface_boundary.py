"""The boundary between the mechanically certified claim surface and prose.

C9-P1-7 ended in an adjudicated Outcome B. The English detector reached 10 of
11 approval sentences with no misflags, and the eleventh --

    cleared for production deployment by the CAB

-- carries no assurance vocabulary at all: `cleared`, `production`,
`deployment`, `CAB`. Closing it means deciding which nouns denote governance
authorities, and the next sentence would be "the release authority gave the
green light", or "operations signed us through to live service". The grammar
would chase English forever.

So the residual is not evidence that an eleventh lexical patch is needed. It
is evidence that ARBITRARY ENGLISH SEMANTICS CANNOT BE THE MECHANICALLY
CLAIMED SECURITY PROPERTY. This module states the property that can be
claimed, and measures it:

    Machine assurance verifies a CLOSED, EXPLICITLY DEFINED claim surface.
    Arbitrary natural-language prose is NOT mechanically certified and cannot
    create, upgrade, or satisfy assurance, inspection, approval, or
    production-readiness state.

That is the programme's central invariant applied to this control: a gate may
claim only the exact property its authoritative execution path mechanically
measures. `find_overclaims` remains useful as lint and defence in depth. It is
NOT the proof that all repository prose is free of false governance claims,
and nothing here may say that it is.

Every test below runs against a DETACHED WORKTREE at HEAD, because the
authoritative digest covers COMMITTED content -- an edit that is not committed
is invisible to it, and measuring the gate against an uncommitted edit would
measure the wrong thing. The real tree is never modified.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)

#: THE RESIDUAL, kept verbatim. It is a specimen of the machine boundary, not
#: a defect awaiting a lexical patch, and it must never be quietly "fixed" by
#: teaching the grammar what a CAB is.
RESIDUAL_SENTENCE = "cleared for production deployment by the CAB"

#: What this repository mechanically certifies: structured records whose
#: content is bound by hash, and the contracts that consume them.
AUTHORITATIVE_SURFACE = (
    ".nornyx/contracts/runtime_network.nyx",
    ".nornyx/contracts/architecture_governance.nyx",
    ".nornyx/contracts/evidence",
)


@pytest.fixture
def worktree(tmp_path: Path):
    """A detached checkout of HEAD that tests may commit into."""
    tree = tmp_path / "tree"
    done = subprocess.run(  # noqa: S603
        ["git", "worktree", "add", "--detach", str(tree), "HEAD"],
        cwd=ROOT, capture_output=True, text=True, timeout=600, check=False,
    )
    if done.returncode != 0:
        pytest.skip(f"could not create a worktree: {done.stderr[-200:]}")
    try:
        yield tree
    finally:
        subprocess.run(  # noqa: S603
            ["git", "worktree", "remove", "--force", str(tree)],
            cwd=ROOT, capture_output=True, text=True, timeout=600, check=False,
        )


def _commit(tree: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=tree,  # noqa: S603
                   capture_output=True, text=True, timeout=600, check=True)
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=boundary@test", "-c", "user.name=boundary",
         "commit", "-q", "-m", message],
        cwd=tree, capture_output=True, text=True, timeout=600, check=True,
    )


def _authoritative_state(tree: Path) -> dict:
    """The gate's verdict, reduced to what it actually decides.

    Read from `check_pre_approval_baseline.py`, which is the script this
    repository's own success criteria name as authoritative for which
    diagnostics an autonomous run may leave outstanding.
    """
    done = subprocess.run(  # noqa: S603
        [sys.executable, "scripts/check_pre_approval_baseline.py"],
        cwd=tree, capture_output=True, text=True, timeout=1800, check=False,
    )
    report = json.loads(done.stdout[done.stdout.index("{"):])
    if "contracts" not in report:
        pytest.skip(f"the gate could not run in the worktree: {report}")
    return {
        "status": report["status"],
        "human_approval_present": report["human_approval_present"],
        "contracts": {
            entry["contract"]: (
                entry["validates"],
                entry["approval_blocked"],
                sorted(
                    problem.get("code", "")
                    for problem in entry["unexpected_diagnostics"]
                ),
            )
            for entry in report["contracts"]
        },
    }


@needs_nornyx
def test_a_correct_structured_claim_backed_by_evidence_is_accepted(worktree):
    """THE POSITIVE CONTROL, and it carries the rest of this module.

    Every refusal below is satisfied by a gate that refuses everything. The
    structured records here state ABSENCES -- approval not_granted, human
    review not_performed -- and each is bound to content by hash. A correct
    structured claim backed by the evidence it names must be ACCEPTED, or
    "the false one is refused" proves nothing.
    """
    state = _authoritative_state(worktree)
    assert state["status"] == "pass", state
    assert state["human_approval_present"] is False, (
        "the baseline reports a human approval on a branch that has none"
    )
    for contract, (validates, blocked, unexpected) in state["contracts"].items():
        assert validates is False, f"{contract} validates without an approval"
        assert blocked is True, f"{contract} is not blocked on the approval"
        assert unexpected == [], f"{contract}: {unexpected}"


@needs_nornyx
@pytest.mark.parametrize(
    "document",
    ["docs/ASSURANCE_BOUNDARY.md", "README.md", "docs/governance/LENS_C_CLOSURE.md"],
)
def test_prose_cannot_change_any_authoritative_assurance_state(worktree, document):
    """THE BOUNDARY, measured with the exact sentence the grammar cannot see.

    This is the property that replaces "no repository prose contains a false
    governance claim", which this repository cannot mechanically support. What
    it CAN support is that prose is not an input to the authoritative decision
    at all -- so a sentence the detector misses changes nothing that matters.

    The residual is inserted into a real governed document and COMMITTED, so
    the digest that covers committed content genuinely sees it. The
    authoritative verdict must be byte-identical.
    """
    target = worktree / document
    if not target.is_file():
        pytest.skip(f"{document} is not in this tree")

    before = _authoritative_state(worktree)

    target.write_bytes(
        target.read_bytes()
        + (
            "\n\nThe release was "
            + RESIDUAL_SENTENCE
            + ". Independent inspection is complete and production approval "
            + "has been granted.\n"
        ).encode("utf-8")
    )
    _commit(worktree, "insert an unearned approval claim into prose")

    after = _authoritative_state(worktree)
    assert after == before, (
        "PROSE MOVED AN AUTHORITATIVE STATE. Free text is not part of the "
        "certified claim surface, and if it can change this verdict then the "
        f"surface is not closed:\n  before {before}\n  after  {after}"
    )


@needs_nornyx
def test_a_false_claim_on_the_structured_surface_is_refused(worktree):
    """The other half: the closed surface must actually be load-bearing.

    A boundary is only worth stating if the inside of it is enforced. The
    structured approval record is edited to claim what this branch does not
    hold -- approval granted, human review performed -- and committed, so the
    digest sees it.

    WHAT REFUSES IT MATTERS. Measured: falsifying the record makes
    `approval_blocked` go FALSE for the architecture contract, because the
    absence diagnostic disappears along with the absence. The approval check
    ALONE would have been satisfied by the forgery. What refuses it is
    `EVIDENCE_ARTIFACT_HASH_MISMATCH` -- the content hash binding the record
    to what it describes. That binding is the authoritative mechanism here,
    and this test names it rather than accepting any refusal.
    """
    record = worktree / ".nornyx/contracts/evidence/architecture_approval_record.json"
    assert record.is_file(), "the approval record is not where this test expects"

    claim = json.loads(record.read_text(encoding="utf-8"))
    assert claim["approval"] == "not_granted", claim
    claim["approval"] = "granted"
    claim["production_approval"] = "granted"
    claim["human_review"] = "performed"
    record.write_bytes(
        (json.dumps(claim, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    _commit(worktree, "claim an approval this branch does not hold")

    state = _authoritative_state(worktree)
    assert state["status"] == "fail", (
        "a forged approval on the structured surface was ACCEPTED: " + str(state)
    )
    codes = {
        code
        for _validates, _blocked, unexpected in state["contracts"].values()
        for code in unexpected
    }
    assert "EVIDENCE_ARTIFACT_HASH_MISMATCH" in codes, (
        "the forgery was refused for some other reason, so the content-hash "
        f"binding is not what is holding this surface closed: {codes}"
    )


def test_the_residual_sentence_stays_outside_the_closed_grammar():
    """The specimen, pinned as a MEASURED LIMIT rather than a hidden gap.

    If someone later teaches the grammar what a CAB is, this test fails and
    they have to come here and read why that was the wrong repair. The point
    is not that the sentence must never be caught -- it is that catching it by
    enumerating governance-authority nouns trades a bounded control for an
    unbounded one, and the boundary above is what makes that trade
    unnecessary.
    """
    from test_documented_claims import find_overclaims  # noqa: PLC0415

    hits = [match.group() for match in find_overclaims(RESIDUAL_SENTENCE)]
    assert hits == [], (
        "the residual is now caught by the prose grammar. If that was done by "
        "deriving a rule from something already in the vocabulary, update this "
        "test and the boundary note. If it was done by adding CAB, board, "
        "committee, authority or council to a list, revert it: the next "
        f"sentence is 'the release authority gave the green light'. {hits}"
    )


def test_the_authoritative_surface_is_declared_and_contains_no_prose():
    """The surface is CLOSED by declaration, and prose is not in it.

    Stated structurally so that widening it is a visible diff rather than a
    side effect. A markdown file appearing here would mean the repository had
    started certifying free text, which is the claim this module exists to
    refuse.
    """
    for entry in AUTHORITATIVE_SURFACE:
        path = ROOT / entry
        assert path.exists(), f"{entry} is declared authoritative but is absent"

    prose = [
        entry for entry in AUTHORITATIVE_SURFACE
        if entry.endswith((".md", ".rst", ".txt"))
    ]
    assert prose == [], (
        "a prose document is declared part of the mechanically certified "
        f"surface: {prose}"
    )

    documents = sorted(
        path.relative_to(ROOT).as_posix()
        for entry in AUTHORITATIVE_SURFACE
        for path in ([ROOT / entry] if (ROOT / entry).is_file()
                     else (ROOT / entry).rglob("*"))
        if path.is_file() and path.suffix.lower() in {".md", ".rst", ".txt"}
    )
    assert documents == [], (
        f"prose files sit inside the authoritative surface: {documents}"
    )
