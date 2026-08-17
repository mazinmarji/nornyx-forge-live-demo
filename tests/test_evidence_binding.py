"""The evidence a commit ships must describe the tree that commit contains.

Measured on this branch: 130 of 168 evidence-bearing commits ship a
`review_binding.json` whose `governed_input_digest` describes a different tree
than the commit contains. The closure document that started this was not an
isolated slip; it was the first noticed instance of a pattern through 77% of the
history.

THE BASELINE IS EVIDENCE, NOT CONFIGURATION. That distinction is what these
tests defend. A contributor must not be able to turn this check green by
appending a SHA, and the generator must never overwrite the committed baseline
during ordinary verification -- because the generator already did exactly that
once, absorbing the very commit that motivated the baseline.

The broader principle, earned four times in one session:

    EVERY EXCEPTION MECHANISM GETS AN ADVERSARIAL TEST PROVING IT CANNOT
    AUTOMATICALLY ENLARGE ITS OWN EXCEPTION SET.

    the trigger tests did not reach the trigger control
    the repair's tests did not reach the consume path
    the freshness exemption hid its own regression
    the baseline generator grandfathered the defect that motivated it
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

BASELINE = ROOT / "docs/governance/EVIDENCE_BINDING_BASELINE.json"
CHECKER = ROOT / "scripts/check_evidence_binding.py"

#: Pinned. The counts are a claim about history, so a change to either is a
#: change to what this repository says happened -- not a config tweak.
PRE_ENFORCEMENT_VIOLATIONS = 129
POST_KNOWLEDGE_VIOLATIONS = 1

#: The commit committed AFTER the defect was described, kept separate on purpose.
#: "130 legacy violations" and "129 legacy violations plus one made after
#: describing the defect" are different statements and only the second is true.
POST_KNOWLEDGE_CATEGORY = "committed_after_the_defect_was_known"


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _run_checker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(CHECKER), *args],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=1800,
    )


def test_the_checker_still_detects_the_original_incident():
    """The regression, with grandfathering DEFEATED.

    729a900 added a governed document and did not regenerate the binding. With
    the baseline applied this range reports PASS, because that commit is
    grandfathered -- so the evidence that this checker works would be excused by
    the checker's own exemption list. `--no-baseline` is what keeps the proof
    honest.
    """
    completed = _run_checker("73695c1..729a900", "--no-baseline")

    assert completed.returncode == 2, completed.stdout[-600:]
    report = json.loads(completed.stdout[completed.stdout.find("{"):])
    assert report["status"] == "fail"
    assert any("729a900" in problem for problem in report["problems"]), report["problems"]


def test_the_legitimate_corrective_sequence_is_allowed():
    """The control. A checker that refuses everything proves nothing.

    45ea93e changed a governed document AND regenerated the binding in the same
    commit, which is the pattern the rule permits.
    """
    completed = _run_checker("729a900..45ea93e", "--no-baseline")

    assert completed.returncode == 0, completed.stdout[-600:]
    assert json.loads(completed.stdout[completed.stdout.find("{"):])["status"] == "pass"


def test_the_baseline_counts_are_pinned():
    """The counts are a claim about history, so they cannot drift quietly."""
    baseline = _baseline()
    post = [
        entry for entry in baseline["known_violations"]
        if entry.get("category") == POST_KNOWLEDGE_CATEGORY
    ]
    pre = [
        entry for entry in baseline["known_violations"]
        if entry.get("category") != POST_KNOWLEDGE_CATEGORY
    ]

    assert len(pre) == PRE_ENFORCEMENT_VIOLATIONS, (
        f"{len(pre)} pre-enforcement violations recorded, pinned at "
        f"{PRE_ENFORCEMENT_VIOLATIONS}. Changing this changes what this "
        "repository says happened."
    )
    assert len(post) == POST_KNOWLEDGE_VIOLATIONS, (
        f"{len(post)} post-knowledge violations recorded, pinned at "
        f"{POST_KNOWLEDGE_VIOLATIONS}. This category must never be merged into "
        "the pre-enforcement count -- it is adverse evidence about the workflow, "
        "not legacy history."
    )
    assert baseline["violating_commits"] == len(baseline["known_violations"])


def test_every_baseline_entry_is_a_real_commit_carrying_a_real_mismatch():
    """A grandfathered SHA must name a commit that genuinely violated.

    Otherwise the exemption list becomes a place to park anything: a SHA that
    does not resolve, or one whose binding was fine, would be excused for free.
    """
    unresolvable: list[str] = []
    for entry in _baseline()["known_violations"]:
        resolved = subprocess.run(  # noqa: S603
            ["git", "-C", str(ROOT), "cat-file", "-e", f"{entry['commit']}^{{commit}}"],
            capture_output=True, timeout=120,
        )
        if resolved.returncode != 0:
            unresolvable.append(entry["commit"])
        assert entry.get("recorded_governed_input_digest") or entry.get("note"), (
            f"{entry['commit']} is grandfathered with neither a recorded digest "
            "nor a reason"
        )
    assert unresolvable == [], (
        f"these grandfathered SHAs do not resolve to commits: {unresolvable}"
    )


def test_appending_a_new_sha_to_the_baseline_does_not_make_a_violation_pass(
    tmp_path: Path,
):
    """THE ADVERSARIAL TEST FOR THE EXCEPTION MECHANISM ITSELF.

    The generator already absorbed 062ed8b -- the ledger fix, committed thirty
    minutes after the defect was described -- because it was regenerated at that
    head. So the failure mode is demonstrated, not hypothetical.

    This proves the pinned counts refuse a silently enlarged baseline: appending
    a SHA fails `test_the_baseline_counts_are_pinned`, so the cheap route to a
    green check is closed. Enlarging the exception set has to be a deliberate,
    reviewable change to a pinned number.
    """
    baseline = _baseline()
    synthetic = dict(baseline["known_violations"][0])
    synthetic["commit"] = "0" * 40
    synthetic["note"] = "synthetic entry, must not be silently accepted"
    enlarged = {**baseline, "known_violations": [*baseline["known_violations"], synthetic]}

    pre = [
        entry for entry in enlarged["known_violations"]
        if entry.get("category") != POST_KNOWLEDGE_CATEGORY
    ]
    assert len(pre) != PRE_ENFORCEMENT_VIOLATIONS, (
        "an enlarged baseline still matches the pinned pre-enforcement count, so "
        "appending a SHA would pass unnoticed"
    )

    # And the synthetic SHA does not resolve, so the reality check catches it too.
    resolved = subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), "cat-file", "-e", f"{'0' * 40}^{{commit}}"],
        capture_output=True, timeout=120,
    )
    assert resolved.returncode != 0, "the synthetic SHA unexpectedly resolves"


def test_the_generator_never_overwrites_the_committed_baseline():
    """Ordinary verification must not rewrite the evidence it verifies against.

    The baseline is EVIDENCE. A checker that regenerates its own exemption list
    while verifying is not checking anything -- it is recording whatever it
    found, which is how 062ed8b was absorbed in the first place.
    """
    source = CHECKER.read_text(encoding="utf-8")
    assert "write_text" not in source and "open(" not in source, (
        "the binding checker can write files, so it can rewrite the baseline it "
        "is meant to be constrained by"
    )
    assert "known_violations" in source, "the checker no longer reads the baseline"


@pytest.mark.parametrize("flag", ["--no-baseline"])
def test_the_baseline_can_be_defeated_for_adversarial_runs(flag: str):
    """Grandfathering must be switchable off, or no regression can be trusted."""
    source = CHECKER.read_text(encoding="utf-8")
    assert flag in source, (
        f"{flag} is gone, so every adversarial range is silently excused by the "
        "historical baseline"
    )
