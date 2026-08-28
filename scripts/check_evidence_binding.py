"""The evidence a commit ships must describe the tree that commit contains.

NAMED FOR WHAT IT PROVES. This was `check_evidence_causality.py`, which
overclaimed: it establishes BINDING FRESHNESS -- evidence and tree agree -- not
causality. Causality requires the evidence to identify the immutable prior state
it validated, which needs a `subject_commit` field the schema does not yet carry.
Calling freshness "causality" would be this repository's own defect: the label
standing in for the thing.

THE INCIDENT THIS EXISTS FOR. Commit 729a900 added
`docs/governance/TASK11_CLOSURE.md` -- a governed input, because `docs` is in
`GOVERNED_INPUT_PATHS` -- and did not regenerate the evidence set. The document
asserted `--verify` reports `status: pass, integrity_state: intact,
problems: []`. It was the sole reason `--verify` returned `fail`,
`compromised`, 12 problems. A document claiming validation of bytes that did not
exist until the document was written is circular, and nothing refused it.

THE INVARIANT. For finalized evidence E claiming validation of governed state S:

    S < E

S is an already-existing state, not the same one. A commit may CHANGE governed
inputs, or FINALIZE evidence about them, but not both for the same claimed
state. Mechanically, at every commit:

    digest(governed inputs at that commit) == governed_input_digest recorded
                                              by the evidence at that commit

EVERY COMMIT IN THE RANGE, not just the tip. A bad commit followed by a
corrective one leaves false evidence permanently in history while HEAD goes
green -- and anyone reading that commit, or bisecting through it, sees evidence
that does not describe the tree it ships with.

The digest is computed by the PRODUCTION function over a real checkout of each
commit, not reimplemented here. A second implementation would drift, and the
drift would be invisible in exactly the direction that matters.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nornyx_forge.governed_subject import REPOSITORY_SCOPE  # noqa: E402
from nornyx_forge.subject_observer import observe_input_manifest  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
from governed_content import digest_of  # noqa: E402

BINDING = ".nornyx/contracts/evidence/review_binding.json"
BASELINE = ROOT / "docs/governance/EVIDENCE_BINDING_BASELINE.json"


def known_violations() -> set[str]:
    """Commits recorded as predating enforcement, by EXACT SHA.

    Not a cutoff. "Ignore everything before X" grandfathers anything that sorts
    before X and survives a rebase that rewrites the content it excused. An
    exact set loses grandfathering automatically when history is rewritten,
    because the new commits have different SHAs.

    A grandfathered artifact that is MODIFIED is new work: the commit doing the
    modifying is not in this set, so it is enforced strictly.
    """
    if not BASELINE.is_file():
        return set()
    return {
        entry["commit"]
        for entry in json.loads(BASELINE.read_text(encoding="utf-8"))["known_violations"]
    }


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=300, check=False,
    )


def commits_in(spec: str) -> list[str]:
    """Every commit in the range, oldest first."""
    completed = _git("rev-list", "--reverse", spec)
    if completed.returncode != 0:
        raise SystemExit(f"cannot list commits for {spec!r}: {completed.stderr.strip()}")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


#: `recorded_digest` returns this when the binding file is not at that commit.
#:
#: DISTINCT FROM `None`, and that distinction is the whole repair. The function
#: used to return `None` for four different states -- file absent, field absent,
#: field null, JSON unparseable -- and `evaluate` skipped all four under a
#: comment written for the first one: "No binding at this commit: nothing is
#: being claimed, so there is nothing that can be false."
#:
#: That reasoning is sound for an absent FILE and false for the other three. A
#: commit that ships `review_binding.json` with `governed_input_digest` deleted,
#: null, or in a file truncated by a failed write IS carrying evidence -- it is
#: carrying evidence that says nothing, which is not the same as carrying none.
#: Measured: such a commit produced `commits_carrying_evidence: 0`,
#: `status: pass`, rc 0. `--verify` would catch it at HEAD, but this checker
#: exists precisely because HEAD going green does not clear the history behind
#: it: a bad commit followed by a corrective one leaves false evidence in the
#: range permanently.
NO_BINDING = object()

#: The binding file is there, and has no `governed_input_digest` KEY.
#:
#: NOT A VIOLATION, and the first draft of this repair called it one. Measured
#: over `origin/main...HEAD`: 24 commits, every one of them carrying the OLDER
#: artifact schema, which recorded `control_pack_commit` and had no
#: `governed_input_digest` field at all. Flagging them would have been
#: anachronistic -- a rule that fails every commit made before the field it
#: requires existed, dressed up as a finding.
#:
#: A deliberately DELETED key is indistinguishable from a key that never
#: existed without dating the schema, so this checker does not claim to catch
#: that. It counts these commits and reports the count, which is the honest
#: shape: the gap is visible, and nothing asserts a violation it cannot
#: substantiate. What IS caught is the file being present and the claim being
#: unusable -- null, empty, the wrong type, or a file that will not parse.
PREDATES_THE_CLAIM = object()


def recorded_digest(commit: str):
    """What the evidence AT THAT COMMIT claims the governed inputs digest to.

    Returns the claimed digest, `NO_BINDING` when the file is not there at all,
    or `None` when the file IS there and the claim is missing or unreadable.
    """
    completed = _git("show", f"{commit}:{BINDING}")
    if completed.returncode != 0:
        return NO_BINDING
    try:
        body = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(body, dict):
        return None
    if "governed_input_digest" not in body:
        return PREDATES_THE_CLAIM
    return body["governed_input_digest"]


def actual_digest(commit: str) -> str:
    """The governed inputs AT THAT COMMIT, digested by the production function."""
    with tempfile.TemporaryDirectory(prefix="causality-") as scratch:
        tree = Path(scratch) / "tree"
        tree.mkdir()
        archive = Path(scratch) / "commit.tar"
        completed = _git("archive", "-o", str(archive), commit)
        if completed.returncode != 0:
            raise SystemExit(f"cannot archive {commit}: {completed.stderr.strip()}")
        import shutil

        shutil.unpack_archive(str(archive), str(tree), format="tar")
        return digest_of(observe_input_manifest(tree, REPOSITORY_SCOPE))


def evaluate(spec: str, *, apply_baseline: bool = True) -> int:
    problems: list[str] = []
    checked = 0

    # `apply_baseline=False` is how the regression proves this checker still
    # detects the original incident. With the baseline applied, 729a900 is
    # grandfathered and the control that demonstrates the checker works reports
    # PASS -- so the evidence for the checker would be excused by the checker's
    # own exemption list.
    grandfathered = known_violations() if apply_baseline else set()
    excused: list[str] = []
    predating: list[str] = []

    for commit in commits_in(spec):
        if commit in grandfathered:
            excused.append(commit[:12])
            continue
        claimed = recorded_digest(commit)
        if claimed is NO_BINDING:
            # No binding file at this commit: nothing is being claimed, so
            # there is nothing that can be false. Absence of a claim is not a
            # violation. This is the ONLY state that reasoning covers.
            continue
        if claimed is PREDATES_THE_CLAIM:
            predating.append(commit[:12])
            continue
        checked += 1
        if not isinstance(claimed, str) or not claimed:
            # The file is here and says nothing. That is a claim that cannot be
            # checked, shipped in the artifact whose entire job is to be
            # checkable -- and it is indistinguishable, to every later reader,
            # from a commit that was verified.
            subject = _git("log", "-1", "--format=%h %s", commit).stdout.strip()
            problems.append(
                f"{subject}"
                f"{chr(10)}      ships {BINDING} with no usable governed_input_digest"
                f" (found {claimed!r})"
                f"{chr(10)}      -> this commit carries evidence that cannot be"
                " checked against anything"
            )
            continue
        actual = actual_digest(commit)
        if claimed != actual:
            subject = _git("log", "-1", "--format=%h %s", commit).stdout.strip()
            problems.append(
                f"{subject}\n"
                f"      evidence claims governed inputs digest to {claimed}\n"
                f"      the tree at that commit digests to        {actual}\n"
                f"      -> this commit ships evidence that does not describe it"
            )

    report = {
        "schema": "nornyx.forge.evidence_binding.v1",
        "range": spec,
        "commits_carrying_evidence": checked,
        "grandfathered_commits": len(excused),
        # Reported rather than silently skipped: these commits carry a
        # binding artifact from before `governed_input_digest` existed, so
        # there is nothing to check and nothing false. A number nobody can
        # see is the difference between a known gap and an invisible one.
        "commits_predating_the_digest_claim": len(predating),
        "problems": problems,
        "status": "fail" if problems else "pass",
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if problems:
        print(
            "\nEvidence must describe a state that already existed when it was "
            "measured. A commit may CHANGE governed inputs, or FINALIZE evidence "
            "about them, but not both for the same claimed state: regenerate in "
            "the same commit as the governed change, or scope the evidence to "
            "the revision it actually measured.",
            file=sys.stderr,
        )
        return 2
    return 0


def main() -> int:
    # PR-SCOPED by default. `origin/main..HEAD` fails this branch forever on 130
    # recorded historical violations, and a permanently red security control is
    # one that gets switched off. The three-dot range asks the only question
    # enforcement can act on: is anything NEW introducing the defect.
    #
    # THREE DOTS IS THE SYMMETRIC DIFFERENCE, not the merge-base range, and
    # this comment called it the latter. They agree whenever HEAD descends from
    # `origin/main`, which is the normal case and why the wording survived; on
    # a DIVERGED branch three dots also walks the commits that are on
    # `origin/main` and not here, which are somebody else's to answer for.
    args = [a for a in sys.argv[1:] if a != "--no-baseline"]
    spec = args[0] if args else "origin/main...HEAD"
    return evaluate(spec, apply_baseline="--no-baseline" not in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
