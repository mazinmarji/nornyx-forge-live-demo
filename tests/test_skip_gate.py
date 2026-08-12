"""A green run that skipped the controls is not a green run.

CI installed `[dev]` while `nornyx` lived in the `demo` extra, so every
`@needs_nornyx` test skipped and the job reported success over 139 of 202 tests.
The approval-wiring, injection, materialization, expiry and baseline controls
were guarded by nothing, and nothing said so — pytest reports skips as a count
in a line nobody reads.

Installing the extra fixes that instance. These test the guard that fixes the
class, including its failure path: a gate whose refusal has never executed is a
guess about what it would do.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_test_coverage import (  # noqa: E402
    EXPECTED_SKIPS,
    MINIMUM_COLLECTED,
    REQUIRED_MODULES,
    classify,
    evaluate,
)

_REPORT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="3">
  <testcase classname="tests.test_ran" name="test_ran"/>
  <testcase classname="tests.test_container_launch" name="test_compose_up_build_starts_the_application">
    <skipped message="set FORGE_DOCKER_TESTS=1 with Docker running to build"/>
  </testcase>
  <testcase classname="tests.test_governance" name="{name}">
    <skipped message="{reason}"/>
  </testcase>
</testsuite></testsuites>
"""


def _report(tmp_path: Path, reason: str, name: str = "test_wiring") -> Path:
    path = tmp_path / "report.xml"
    path.write_text(_REPORT.format(reason=reason, name=name), encoding="utf-8")
    return path


def test_the_historical_failure_is_now_caught(tmp_path: Path):
    """The exact skip reason that hid 63 tests behind a green run."""
    total, allowed, unexpected, _modules, _skipped = classify(_report(tmp_path, "nornyx CLI is not installed"))
    assert total == 3
    assert allowed == 1, "the declared Docker skip should still be allowed"
    assert len(unexpected) == 1
    assert "test_wiring" in unexpected[0]
    assert "nornyx CLI is not installed" in unexpected[0]


def test_a_declared_skip_is_allowed(tmp_path: Path):
    """The gate must not force tests to run where the design says they cannot."""
    total, allowed, unexpected, _modules, _skipped = classify(
        _report(
            tmp_path,
            "cannot be built on a Windows workstation",
            name="test_a_fifo_under_a_governed_root_is_refused",
        )
    )
    assert total == 3
    # Only the container-launch case is declared; the second names a test that
    # is not in tests.test_governance, so its reason buys nothing.
    assert allowed == 1
    assert len(unexpected) == 1


def test_borrowing_a_declared_reason_does_not_exempt_a_new_test(tmp_path: Path):
    """The defect this keying replaces, asserted directly.

    Exemptions were matched as a substring of the skip *message*, so a new test
    whose reason happened to contain a declared phrase was exempted without
    anyone deciding it should be. Two tests in this repository were written that
    way — borrowing `set FORGE_DOCKER_TESTS=1`, one for a POSIX-only fixture and
    one for a Docker-daemon fixture — and the census counted both and said
    nothing.

    Word for word the declared reason, on a test nobody exempted.
    """
    total, allowed, unexpected, _modules, _skipped = classify(
        _report(
            tmp_path,
            "set FORGE_DOCKER_TESTS=1 with Docker running to build",
            name="test_something_new_that_borrowed_the_reason",
        )
    )
    assert total == 3
    assert allowed == 1, "a borrowed reason exempted a test that was never declared"
    assert len(unexpected) == 1
    assert "test_something_new_that_borrowed_the_reason" in unexpected[0]


def test_every_declared_exemption_names_a_test_that_exists():
    """An exemption for a deleted test is a hole nobody is watching.

    Renaming a skipping test would otherwise leave its old name exempted forever
    while the renamed test skips undeclared — or, worse, leave the entry as
    cover for some future test that happens to take the name.
    """
    for node in EXPECTED_SKIPS:
        relative, _, name = node.partition("::")
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert f"def {name}(" in source, f"{node} names a test that does not exist"


def test_every_expected_skip_records_why_it_is_acceptable():
    """An allowlist without reasons becomes a place to hide things.

    Each entry has to carry an explanation, so adding one is a decision someone
    made in writing rather than a line quietly appended to silence a failure.
    """
    assert EXPECTED_SKIPS, "an empty allowlist would make the gate meaningless"
    for marker, reason in EXPECTED_SKIPS.items():
        assert len(reason) > 60, f"{marker!r} is allowed without a real explanation"
        assert marker.strip() == marker


def test_the_ci_test_job_installs_what_the_governance_tests_need():
    """The instance, not just the class.

    `nornyx` is in the `demo` extra; a job installing only `[dev]` cannot run a
    single governance test and will not say so.
    """
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    test_job = workflow.split("  test:", 1)[1].split("\n  container-launch:", 1)[0]
    assert "'.[demo,dev]'" in test_job, "the test matrix must install nornyx"
    assert "check_test_coverage.py" in test_job, "the test matrix must gate on skips"

    # Split on the next key rather than the next `]`: `uvicorn[standard]` carries
    # a bracket, and splitting on that silently truncated the block to two lines.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    demo_extra = pyproject.split("demo = [", 1)[1].split("dev = [", 1)[0]
    assert "nornyx==" in demo_extra, "the demo extra is where nornyx lives"


# --------------------------------------------------------------------------
# A suite that silently shrinks looks exactly like a suite that passes
# --------------------------------------------------------------------------


def test_classify_reports_which_modules_contributed(tmp_path: Path):
    """The floor cannot see a swap: one file deleted, tests added elsewhere.

    Counting alone keeps the total up while an invariant goes unproven, so the
    census reports module identity and not just arithmetic.
    """
    _total, _allowed, _unexpected, modules, _skipped = classify(
        _report(tmp_path, "nornyx CLI is not installed")
    )
    assert "tests/test_container_launch.py" in modules
    assert "tests/test_ran.py" in modules


def test_every_required_module_exists_and_is_a_test_file():
    """A required module that was renamed away would fail the gate forever."""
    # The guard that was missing. `test_every_expected_skip_records_why_it_is
    # _acceptable` carries exactly this assertion two functions earlier; it was
    # not repeated here, so emptying the tuple made this loop vacuous and the
    # whole anti-shrink gate could be neutered with a one-line edit while this
    # file stayed green. An independent review found it by doing precisely that.
    # Non-emptiness was the fix for a reviewer who emptied the tuple. One
    # surviving entry satisfies it, so the same edit still worked: the list was
    # cut from twenty modules to one and this file stayed green.
    #
    # A named set is what a count cannot be talked out of. These are the
    # reproduced-exploit proofs, and dropping one has to be a deliberate edit
    # here that a reviewer can see, not a quiet deletion over there.
    must_include = {
        "tests/test_approval_authentication.py",
        "tests/test_approval_artifact_authentication.py",
        "tests/test_approval_ledger.py",
        "tests/test_approval_injection.py",
        "tests/test_approval_wiring.py",
        "tests/test_action_binding.py",
        "tests/test_materialization_injection.py",
        "tests/test_expiry_semantics.py",
        "tests/test_pre_approval_baseline.py",
        "tests/test_reviewer_authentication.py",
        "tests/test_governance_approval_verifier.py",
        "tests/test_independent_inspection.py",
        "tests/test_trust_directionality.py",
        "tests/test_content_binding.py",
        "tests/test_untrusted_text.py",
        "tests/test_production_security_context.py",
        "tests/test_evidence_integrity_verifier.py",
        "tests/test_process_capability.py",
        "tests/test_skip_gate.py",
        "tests/test_subject_completeness.py",
        "tests/test_governance_integrity_authority.py",
        "tests/test_artifact_authority.py",
        "tests/test_collection_completeness.py",
        "tests/test_absence_is_not_success.py",
        "tests/test_trust_snapshot.py",
    }
    missing = sorted(must_include - set(REQUIRED_MODULES))
    assert missing == [], (
        "the anti-shrink gate no longer requires these reproduced-exploit "
        f"proofs, so deleting them would go unnoticed: {missing}"
    )
    for name in REQUIRED_MODULES:
        path = ROOT / name
        assert path.is_file(), f"{name} is required by the gate but does not exist"
        assert "def test_" in path.read_text(encoding="utf-8"), (
            f"{name} is required by the gate but contributes no tests"
        )


def test_the_floor_sits_below_the_current_suite_and_above_nothing():
    """A floor at zero is decoration; a floor above the suite blocks every run."""
    # Counted by COLLECTING, not by counting `def test_` strings. That count
    # missed every parametrised case -- 426 function definitions against 645
    # collected -- so a guard reading "at least half" licensed a floor of 213,
    # a third of the real suite. The guard measuring the floor has to measure
    # the same thing the floor is compared against.
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    collected = sum(
        int(line.rsplit(":", 1)[1])
        for line in completed.stdout.splitlines()
        if line.startswith("tests/") and line.rsplit(":", 1)[-1].strip().isdigit()
    )
    assert collected > 0, f"collection produced no counts:\n{completed.stdout[-500:]}"

    # `> 0` was the whole lower bound, so a floor of 1 satisfied a test whose
    # docstring says "a floor at zero is decoration". Half was the same
    # decoration one step up. The floor has to sit close enough to the suite
    # that deleting a module of any size trips it.
    assert MINIMUM_COLLECTED >= collected * 9 // 10, (
        f"a floor of {MINIMUM_COLLECTED} against {collected} collected tests "
        f"leaves {collected - MINIMUM_COLLECTED} of slack: whole modules could "
        "be deleted with this gate still passing"
    )
    assert MINIMUM_COLLECTED <= collected * 2, (
        "the floor is above what the suite can collect, so every run fails"
    )


# --------------------------------------------------------------------------
# The gate's own refusals, executed
# --------------------------------------------------------------------------


def _report_with(tmp_path, cases: str):
    path = tmp_path / "report.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        + chr(10)
        + "<testsuites><testsuite name=\"pytest\">"
        + cases
        + "</testsuite></testsuites>"
        + chr(10),
        encoding="utf-8",
    )
    return path


def _module_cases(modules) -> str:
    """One testcase per named module, so the report mentions each of them."""
    return "".join(
        f'<testcase classname="{name.removesuffix(".py").replace("/", ".")}"'
        ' name="test_probe"/>'
        for name in modules
    )


def _filler_cases(count: int) -> str:
    """Testcases from an unrelated module, purely to reach the floor."""
    return "".join(
        f'<testcase classname="tests.test_filler" name="test_{index}"/>'
        for index in range(max(count, 0))
    )


def _complete_report_cases(count: int) -> str:
    """Every required module present, and enough total tests to clear the floor."""
    return _module_cases(REQUIRED_MODULES) + _filler_cases(count - len(REQUIRED_MODULES))


def test_the_missing_module_refusal_actually_runs(tmp_path, capsys):
    """A guard whose failure path has never executed is a guess.

    The module docstring says exactly that, and only `classify` had been
    separated far enough to act on it: the three paths that make this a gate --
    missing module, below floor, GATE: FAIL -- lived inline in `main()` and had
    never once run under test.
    """
    dropped = REQUIRED_MODULES[0]
    # Every module except the dropped one, plus enough filler to clear the floor
    # -- so the ONLY reason to refuse is the absent module.
    cases = _module_cases(REQUIRED_MODULES[1:]) + _filler_cases(MINIMUM_COLLECTED)
    code = evaluate(_report_with(tmp_path, cases), 0)
    captured = capsys.readouterr().out
    assert code == 2
    assert dropped in captured
    assert "required test module is missing" in captured


def test_the_floor_refusal_actually_runs(tmp_path, capsys):
    """A shrunken suite must fail even when every required module reported."""
    code = evaluate(_report_with(tmp_path, _module_cases(REQUIRED_MODULES)), 0)
    captured = capsys.readouterr().out
    assert code == 2
    assert "below the floor" in captured
    assert "collection below floor" in captured


def test_a_failing_pytest_is_reported_as_failure_on_the_last_line(tmp_path, capsys):
    """The census reads like success whatever pytest concluded.

    A truncated view of this output was once taken for a passing suite while
    tests were failing, which is why the verdict must be the final line.
    """
    code = evaluate(_report_with(tmp_path, _complete_report_cases(MINIMUM_COLLECTED)), 1)
    captured = capsys.readouterr().out.strip().splitlines()
    assert code == 1
    assert captured[-1].startswith("GATE: FAIL")
    assert "pytest exited 1" in captured[-1]


def test_a_clean_report_passes(tmp_path, capsys):
    """The gate must permit the case it exists to recognise."""
    code = evaluate(_report_with(tmp_path, _complete_report_cases(MINIMUM_COLLECTED)), 0)
    captured = capsys.readouterr().out.strip().splitlines()
    assert code == 0
    assert captured[-1] == "GATE: PASS"
