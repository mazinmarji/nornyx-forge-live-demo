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
POST_KNOWLEDGE_VIOLATIONS = 6

#: The commit committed AFTER the defect was described, kept separate on purpose.
#: Six, not one. The second batch is five commits made while remediating
#: Lens C -- recorded because the alternative is rewriting history to hide an
#: evidence defect. Pinned so the culpable count cannot grow quietly: a rising
#: number here means the commit discipline is not being followed, and that is
#: exactly what it should be loud about.
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


#: (what `git show` returns for the binding file, what recorded_digest answers)
#:
#: FOUR STATES COLLAPSED INTO ONE `None`, and `evaluate` skipped all four under
#: a comment written for the first: "No binding at this commit: nothing is
#: being claimed, so there is nothing that can be false." That reasoning is
#: sound for an absent FILE and false for a file that is present and says
#: nothing -- which is not the absence of evidence, it is unusable evidence,
#: shipped in the artifact whose whole job is to be checkable.
BINDING_STATES = [
    ("absent", None, "NO_BINDING"),
    ("a usable claim", '{"governed_input_digest": "sha256:abc"}', "sha256:abc"),
    ("the key deleted", '{"other": 1}', "PREDATES_THE_CLAIM"),
    ("the claim null", '{"governed_input_digest": null}', None),
    ("the claim empty", '{"governed_input_digest": ""}', ""),
    ("the claim a number", '{"governed_input_digest": 7}', 7),
    ("truncated by a failed write", '{"governed_input_dig', None),
    ("not an object at all", '["governed_input_digest"]', None),
]


@pytest.mark.parametrize(("label", "content", "expected"), BINDING_STATES)
def test_the_binding_reader_separates_absence_from_an_unusable_claim(
    label: str, content, expected, monkeypatch: pytest.MonkeyPatch,
):
    """Absence of a claim is not a violation. An unusable claim is.

    Driven through the production `recorded_digest` with `_git` stubbed, so
    this measures the function the checker actually calls.
    """
    import check_evidence_binding as binding  # noqa: PLC0415

    def fake_git(*args: str):
        failed = content is None
        return subprocess.CompletedProcess(
            args=list(args), returncode=1 if failed else 0,
            stdout="" if failed else content, stderr="",
        )

    monkeypatch.setattr(binding, "_git", fake_git)
    answer = binding.recorded_digest("0" * 40)
    if expected == "NO_BINDING":
        assert answer is binding.NO_BINDING, label
    elif expected == "PREDATES_THE_CLAIM":
        assert answer is binding.PREDATES_THE_CLAIM, label
    else:
        assert answer == expected and answer is not binding.NO_BINDING, label


def test_a_commit_shipping_an_unusable_claim_is_a_violation(
    monkeypatch: pytest.MonkeyPatch, capsys,
):
    """The end-to-end consequence, at the checker's verdict.

    Measured before the repair: a commit shipping `review_binding.json` with
    the digest set to null produced `commits_carrying_evidence: 0`,
    `status: pass`, rc 0. `--verify` would catch it at HEAD -- and this checker
    exists precisely because HEAD going green does not clear the history behind
    it. A bad commit followed by a corrective one leaves false evidence in the
    range permanently, which is the incident it was written for.
    """
    import check_evidence_binding as binding  # noqa: PLC0415

    commit = "1" * 40
    monkeypatch.setattr(binding, "commits_in", lambda spec: [commit])
    monkeypatch.setattr(binding, "known_violations", set)
    monkeypatch.setattr(
        binding, "recorded_digest",
        lambda sha: None,  # present, and says nothing
    )
    monkeypatch.setattr(
        binding, "_git",
        lambda *args: subprocess.CompletedProcess(list(args), 0, "1111111 a commit", ""),
    )
    code = binding.evaluate("does-not-matter")
    report = json.loads(capsys.readouterr().out)
    assert code != 0, "a commit shipping an unusable claim was accepted"
    assert report["problems"], report
    assert "no usable governed_input_digest" in report["problems"][0]


def test_a_commit_with_no_binding_file_at_all_is_skipped(
    monkeypatch: pytest.MonkeyPatch, capsys,
):
    """Absence of a claim is not a violation, measured at the VERDICT.

    The reader's own table covers this, and a reader test is not a verdict:
    when I mutated `evaluate` to treat an absent file as a violation, every
    other control in this group stayed green. Over-strictness here would fail
    every commit made before the binding artifact existed at all -- the same
    date bug as the anachronistic rule above, pointing the other way.
    """
    import check_evidence_binding as binding  # noqa: PLC0415

    commit = "3" * 40
    monkeypatch.setattr(binding, "commits_in", lambda spec: [commit])
    monkeypatch.setattr(binding, "known_violations", set)
    monkeypatch.setattr(binding, "recorded_digest", lambda sha: binding.NO_BINDING)
    code = binding.evaluate("does-not-matter")
    report = json.loads(capsys.readouterr().out)
    assert code == 0, report
    assert report["problems"] == [], report
    assert report["commits_carrying_evidence"] == 0, report
    assert report["commits_predating_the_digest_claim"] == 0, (
        "a commit with no binding file was counted as one that predates the "
        "digest claim; those are different states and the report says so"
    )


def test_a_binding_from_before_the_field_existed_is_counted_not_blamed(
    monkeypatch: pytest.MonkeyPatch, capsys,
):
    """The first draft of this repair flagged 24 real commits anachronistically.

    Every one of them carried the OLDER artifact schema, which recorded
    `control_pack_commit` and had no `governed_input_digest` field at all. A
    rule that fails every commit made before the field it requires existed is
    not a finding, it is a rule with a date bug -- so the checker reports these
    as a COUNT and asserts nothing about them.

    A deliberately deleted key is indistinguishable from a key that never
    existed without dating the schema, and this checker does not claim to catch
    that. Saying so in the report is the difference between a known gap and an
    invisible one.
    """
    import check_evidence_binding as binding  # noqa: PLC0415

    commit = "2" * 40
    monkeypatch.setattr(binding, "commits_in", lambda spec: [commit])
    monkeypatch.setattr(binding, "known_violations", set)
    monkeypatch.setattr(binding, "recorded_digest",
                        lambda sha: binding.PREDATES_THE_CLAIM)
    code = binding.evaluate("does-not-matter")
    report = json.loads(capsys.readouterr().out)
    assert code == 0, report
    assert report["problems"] == []
    assert report["commits_predating_the_digest_claim"] == 1, report
    assert report["commits_carrying_evidence"] == 0, (
        "a commit with nothing to check was counted as carrying checked evidence"
    )


def _a_grandfathered_commit() -> str:
    """The first baselined commit that is an ancestor of HEAD, deterministically."""
    import check_evidence_binding as binding  # noqa: PLC0415

    for sha in sorted(binding.known_violations()):
        reachable = subprocess.run(  # noqa: S603
            ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", sha, "HEAD"],
            capture_output=True, timeout=120, check=False,
        )
        if reachable.returncode == 0:
            return sha
    raise AssertionError(
        "no commit in the evidence-binding baseline is reachable from HEAD, so "
        "the grandfathering path cannot be exercised by any range"
    )


@pytest.mark.parametrize("apply_baseline", [True, False])
def test_the_generator_never_overwrites_the_committed_baseline(apply_baseline: bool):
    """Ordinary verification must not rewrite the evidence it verifies against.

    The baseline is EVIDENCE. A checker that regenerates its own exemption list
    while verifying is not checking anything -- it is recording whatever it
    found, which is how 062ed8b was absorbed in the first place.

    THIS USED TO BE `assert "write_text" not in source and "open(" not in
    source`. That is a claim about two tokens in one file, and the claim being
    made is about behaviour. Measured against the real source plus each
    realistic way of writing that file:

        BASELINE.write_bytes(...)          the guard PASSED
        shutil.copyfile(staging, BASELINE) the guard PASSED
        os.replace(staging, BASELINE)      the guard PASSED
        json.dump(x, BASELINE.open("w"))   caught
        Path.write_text alias              caught

    Three of five evade it, and `shutil` is already imported in that file for
    `unpack_archive`, so `copyfile` is the natural spelling. This module's own
    docstring says every exception mechanism gets an adversarial test proving it
    cannot enlarge its own exception set; a text scan is not that test.

    So the checker is RUN, over the real range, in both baseline modes, and the
    file's bytes are compared either side. Behaviour, measured as behaviour.
    """
    import hashlib  # noqa: PLC0415

    import check_evidence_binding as binding  # noqa: PLC0415

    def digest() -> str:
        return hashlib.sha256(BASELINE.read_bytes()).hexdigest()

    # A ONE-COMMIT RANGE THAT CONTAINS A GRANDFATHERED VIOLATION.
    #
    # The property is "verifying does not rewrite the evidence", which does not
    # depend on range size -- but the range has to reach the code that consults
    # the baseline at all, or the run proves nothing about grandfathering. This
    # one does, and both modes diverge on it:
    #
    #     apply_baseline=True   grandfathered 1, status pass, rc 0   (0.1s)
    #     apply_baseline=False  problems 1,     status fail, rc 2    (2.0s)
    #
    # The full `origin/main...HEAD` range costs ~2.5s per commit over 135+
    # commits, twice. A control nobody can afford to run is a control that
    # stops being run.
    spec = f"{_a_grandfathered_commit()}~1...{_a_grandfathered_commit()}"
    before, before_mtime = digest(), BASELINE.stat().st_mtime_ns
    binding.evaluate(spec, apply_baseline=apply_baseline)
    assert digest() == before, (
        "the binding checker REWROTE the baseline it is meant to be constrained "
        "by. Every violation it just found is now grandfathered, and the next "
        "run will report a clean range over exactly the evidence that was bad."
    )
    assert BASELINE.stat().st_mtime_ns == before_mtime, (
        "the baseline was rewritten with identical content. The bytes match, so "
        "nothing is lost today -- but a checker that opens its own exemption "
        "list for writing at all is one edit away from recording what it found."
    )


def test_the_immutability_control_is_not_a_text_scan():
    """The repair, pinned so it cannot quietly revert to reading the source.

    The predecessor asserted two tokens were absent from a file. Reverting to
    that shape would leave a test with the same name, the same docstring, and
    none of the property -- which is the exact substitution this module exists
    to refuse.
    """
    import inspect  # noqa: PLC0415

    body = inspect.getsource(test_the_generator_never_overwrites_the_committed_baseline)
    executable = body[body.index('"""', body.index('"""') + 3) + 3:]
    assert "evaluate(" in executable, (
        "the immutability control no longer RUNS the checker, so whatever it "
        "asserts is about text rather than about what the checker does"
    )
    assert "read_text" not in executable, (
        "the immutability control reads the checker's source again"
    )


@pytest.mark.parametrize("flag", ["--no-baseline"])
def test_the_baseline_can_be_defeated_for_adversarial_runs(flag: str):
    """FG22. Grandfathering must be switchable off, or no regression can be trusted."""
    source = CHECKER.read_text(encoding="utf-8")
    assert flag in source, (
        f"{flag} is gone, so every adversarial range is silently excused by the "
        "historical baseline"
    )


# THE MARKER MOVED HERE, to the node that fails for this class.
#
# It sat on `test_the_baseline_can_be_defeated_for_adversarial_runs`, whose
# whole body is `assert flag in CHECKER.read_text(...)` -- a SUBSTRING SCAN,
# which is FG21's own class. Measured by deleting FG22's defect from
# `scripts/check_evidence_binding.py` (`known_violations() if apply_baseline
# else set()` -> `known_violations()`), so the baseline can no longer be
# defeated and every adversarial range is silently excused:
#
#     the marked owner                          PASSED
#     this node, unmarked at the time           FAILED
#     all three audit certifications            PASSED
#
# The token `--no-baseline` stays in the file, so the scan still finds it.
# This module's own docstring already recorded that repair -- "both were
# looking at the file rather than running it" -- and the marker was left
# behind on the one that looks.
@pytest.mark.false_green("FG22")
def test_the_escape_hatch_is_exercised_not_merely_present(tmp_path: Path):
    """FG22's specimen read source text; removing the hatch left it green.

    A review deleted the `--no-baseline` behaviour -- making `apply_baseline`
    unconditionally True and leaving the token only in a comment -- and both
    this class's specimen and the audit's self-attack still passed, because
    both were looking at the file rather than running it.

    This calls `evaluate` on a range containing a KNOWN grandfathered violation
    twice, and requires the two answers to differ. A baseline that cannot be
    defeated cannot be audited, and a check that greps for the flag cannot tell
    the difference.
    """
    import check_evidence_binding as binding  # noqa: PLC0415

    violation = sorted(binding.known_violations())[0]
    spec = f"{violation}~1..{violation}"

    with_baseline = binding.evaluate(spec, apply_baseline=True)
    without_baseline = binding.evaluate(spec, apply_baseline=False)

    assert with_baseline == 0, (
        f"a grandfathered commit was reported as a violation with the baseline "
        f"applied, so the range {spec} is not the specimen this test needs"
    )
    assert without_baseline != 0, (
        "the same range passed with the baseline DEFEATED, so the escape hatch "
        "does nothing and every grandfathered commit is unauditable"
    )
