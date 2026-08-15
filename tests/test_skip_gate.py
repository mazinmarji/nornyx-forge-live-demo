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

import check_test_coverage as census  # noqa: E402
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
    total, allowed, unexpected, _modules, _skipped, _xfails, _errors = classify(_report(tmp_path, "nornyx CLI is not installed"))
    assert total == 3
    assert allowed == 1, "the declared Docker skip should still be allowed"
    assert len(unexpected) == 1
    assert "test_wiring" in unexpected[0]
    assert "nornyx CLI is not installed" in unexpected[0]


def test_a_declared_skip_is_allowed(tmp_path: Path):
    """The gate must not force tests to run where the design says they cannot."""
    total, allowed, unexpected, _modules, _skipped, _xfails, _errors = classify(
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
    total, allowed, unexpected, _modules, _skipped, _xfails, _errors = classify(
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
    _total, _allowed, _unexpected, modules, _skipped, _xfails, _errors = classify(
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
        "tests/test_authority_domains.py",
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
    """Each named module, contributing at least its declared floor.

    One testcase per module was enough while the gate only asked whether a
    module was PRESENT. It is not enough now: presence was exactly the weakness
    -- 43 tests could be deleted across six modules with every one still
    "present" -- so a report meeting the requirements has to meet the per-module
    floors too. A helper called "complete" that produced an incomplete report
    would make every test built on it refuse for the wrong clause.
    """
    cases = []
    for name in modules:
        classname = name.removesuffix(".py").replace("/", ".")
        for index in range(max(census.REQUIRED_MODULE_MINIMUMS.get(name, 1), 1)):
            cases.append(
                f'<testcase classname="{classname}" name="test_probe_{index}"/>'
            )
    return "".join(cases)


def _required_total() -> int:
    """How many testcases `_module_cases(REQUIRED_MODULES)` emits."""
    return sum(
        max(census.REQUIRED_MODULE_MINIMUMS.get(name, 1), 1)
        for name in REQUIRED_MODULES
    )


def _filler_cases(count: int) -> str:
    """Testcases from an unrelated module, purely to reach the floor."""
    return "".join(
        f'<testcase classname="tests.test_filler" name="test_{index}"/>'
        for index in range(max(count, 0))
    )


def _complete_report_cases(count: int) -> str:
    """Every required module at its floor, and enough total to clear the floor."""
    return _module_cases(REQUIRED_MODULES) + _filler_cases(count - _required_total())


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


_XFAIL_REPORT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="2">
  <testcase classname="tests.test_ran" name="test_ran"/>
  <testcase classname="tests.test_authority_domains" name="test_characterized">
    <skipped type="{kind}" message="{reason}"/>
  </testcase>
</testsuite></testsuites>
"""


def _typed_report(tmp_path: Path, kind: str) -> Path:
    path = tmp_path / "typed.xml"
    path.write_text(
        _XFAIL_REPORT.format(kind=kind, reason="characterization"), encoding="utf-8"
    )
    return path


def test_an_expected_failure_is_not_counted_as_a_skip(tmp_path: Path):
    """An xfail ran and asserted. A skip did not. They are different facts.

    pytest reports both as `<skipped>` in JUnit XML, distinguished only by
    `type`, and the gate conflated them -- so a strict xfail failed the run as
    an undeclared skip. "Fixing" that by adding it to EXPECTED_SKIPS would put a
    test that executes into a list whose stated meaning is "asserts nothing",
    and would then also exempt it if it ever became a genuine skip.
    """
    _total, allowed, unexpected, _modules, _skipped, _xfails, _errors = classify(
        _typed_report(tmp_path, "pytest.xfail")
    )
    assert unexpected == [], "an expected failure was reported as an undeclared skip"
    assert allowed == 0, "an xfail must not consume a skip exemption either"


def test_a_real_skip_with_the_same_shape_is_still_caught(tmp_path: Path):
    """The discrimination must cut only where intended.

    Same test id, same message, same element -- only `type` differs. If the gate
    keyed on anything looser, an undeclared skip could dress itself as an xfail.
    """
    _total, _allowed, unexpected, _modules, _skipped, _xfails, _errors = classify(
        _typed_report(tmp_path, "pytest.skip")
    )
    assert len(unexpected) == 1
    assert "test_characterized" in unexpected[0]


# --------------------------------------------------------------------------
# B-P2-2. Presence is not coverage.
# --------------------------------------------------------------------------


def _counted_report(tmp_path, counts: dict[str, int]):
    """A JUnit report contributing `counts[module]` passing tests per module."""
    cases = []
    for module, number in counts.items():
        classname = module.removesuffix(".py").replace("/", ".")
        for index in range(number):
            cases.append(
                f'<testcase classname="{classname}" name="test_{index}" '
                f'file="{module}"></testcase>'
            )
    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<testsuites><testsuite '
        f'name="pytest" tests="{sum(counts.values())}">'
        + "".join(cases)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return report


def test_a_required_module_that_shrinks_is_refused(tmp_path):
    """The defect: 43 tests deleted across six modules, aggregate floor intact.

    Every module stays PRESENT, so `REQUIRED_MODULES` is satisfied, and the
    total still clears `MINIMUM_COLLECTED` because the surviving modules were
    padded. Only a per-module floor can see it.
    """
    counts = dict.fromkeys(census.REQUIRED_MODULES, 0)
    for name, floor in census.REQUIRED_MODULE_MINIMUMS.items():
        counts[name] = floor
    victim = "tests/test_action_binding.py"
    assert victim in counts, "the victim must be a required, floored module"

    # Gut the victim, keeping ONE test so it is still present, and pad another
    # module by the same amount so the aggregate total does not move.
    removed = counts[victim] - 1
    counts[victim] = 1
    # Padded elsewhere so the AGGREGATE total does not move. That is the whole
    # shape of the defect: the suite loses a security module's proofs and the
    # headline count is undisturbed because something else grew.
    counts["tests/test_filler.py"] = (
        census.MINIMUM_COLLECTED - sum(counts.values()) + removed + 1
    )

    assert sum(counts.values()) >= census.MINIMUM_COLLECTED, (
        "this case only demonstrates the gap while the aggregate floor passes"
    )
    assert census.evaluate(_counted_report(tmp_path, counts), 0) != 0, (
        "the gate accepted a run in which a security module lost all but one "
        "of its tests"
    )


def test_the_declared_floors_are_met_by_the_real_suite(tmp_path):
    """The control, and the thing that keeps the floors honest.

    Floors set above what the suite actually contributes would fail every run;
    floors set at zero would accept anything. Measured against a report built
    from the current counts.
    """
    counts = dict(census.REQUIRED_MODULE_MINIMUMS)
    padding = census.MINIMUM_COLLECTED - sum(counts.values())
    if padding > 0:
        counts["tests/test_filler.py"] = padding

    assert census.evaluate(_counted_report(tmp_path, counts), 0) == 0, (
        "a run meeting every declared floor was refused, so the floors are "
        "above what the suite actually proves"
    )


def test_every_required_module_has_a_declared_floor():
    """A module required but unfloored is one that can be gutted freely."""
    unfloored = sorted(
        set(census.REQUIRED_MODULES) - set(census.REQUIRED_MODULE_MINIMUMS)
    )
    assert unfloored == [], (
        f"these modules are required to exist but may shrink to one test: "
        f"{unfloored}"
    )


def test_no_floor_is_zero():
    """A zero floor is indistinguishable from having no floor at all."""
    zeroed = sorted(
        name for name, floor in census.REQUIRED_MODULE_MINIMUMS.items() if floor < 1
    )
    assert zeroed == [], zeroed


def test_a_collection_error_is_not_counted_as_coverage(tmp_path):
    """A module that fails to import cannot have proved anything.

    pytest emits a `<testcase>` carrying `<error>` when collection fails.
    Counting it meant a broken module still incremented the total, still
    satisfied REQUIRED_MODULES, and would now still contribute to its
    per-module floor -- the census certifying coverage that never executed.
    """
    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1">'
        '<testcase classname="tests.test_action_binding" name="test_action_binding" '
        'file="tests/test_action_binding.py">'
        '<error message="collection failure">ImportError: no module named x</error>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    total, *_rest, errors = census.classify(report)

    assert total == 0, "an errored case was counted as a test that ran"
    assert errors == ["tests/test_action_binding.py::test_action_binding"], errors
    assert census.evaluate(report, 0) != 0, (
        "the gate accepted a run whose module failed to import"
    )


def test_the_errored_module_is_not_marked_as_present(tmp_path):
    """The second half: presence must not be satisfied by a failure to load.

    This is what let a broken security module keep satisfying REQUIRED_MODULES.
    """
    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1">'
        '<testcase classname="tests.test_action_binding" name="test_x" '
        'file="tests/test_action_binding.py">'
        '<error message="boom">ImportError</error>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    _total, _allowed, _unexpected, modules, *_rest = census.classify(report)

    assert "tests/test_action_binding.py" not in modules, (
        "a module that failed to import was marked as seen"
    )
