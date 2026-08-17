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


def recorded_digest(commit: str) -> str | None:
    """What the evidence AT THAT COMMIT claims the governed inputs digest to."""
    completed = _git("show", f"{commit}:{BINDING}")
    if completed.returncode != 0:
        return None
    try:
        return json.loads(completed.stdout).get("governed_input_digest")
    except json.JSONDecodeError:
        return None


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

    for commit in commits_in(spec):
        if commit in grandfathered:
            excused.append(commit[:12])
            continue
        claimed = recorded_digest(commit)
        if claimed is None:
            # No binding at this commit: nothing is being claimed, so there is
            # nothing that can be false. Absence of a claim is not a violation.
            continue
        checked += 1
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
    # one that gets switched off. The merge-base range asks the only question
    # enforcement can act on: is anything NEW introducing the defect.
    args = [a for a in sys.argv[1:] if a != "--no-baseline"]
    spec = args[0] if args else "origin/main...HEAD"
    return evaluate(spec, apply_baseline="--no-baseline" not in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
