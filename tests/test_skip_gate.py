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

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_test_coverage as census  # noqa: E402
from check_test_coverage import (  # noqa: E402
    EXPECTED_SKIPS,
    MINIMUM_COLLECTED,
    REQUIRED_MODULE_MINIMUMS,  # noqa: E402
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
    total, allowed, unexpected, _modules, _executed, _skipped, _xfails, _errors = classify(_report(tmp_path, "nornyx CLI is not installed"))
    assert total == 3
    assert allowed == 1, "the declared Docker skip should still be allowed"
    assert len(unexpected) == 1
    assert "test_wiring" in unexpected[0]
    assert "nornyx CLI is not installed" in unexpected[0]


def test_a_declared_skip_is_allowed(tmp_path: Path):
    """The gate must not force tests to run where the design says they cannot."""
    total, allowed, unexpected, _modules, _executed, _skipped, _xfails, _errors = classify(
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
    total, allowed, unexpected, _modules, _executed, _skipped, _xfails, _errors = classify(
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
    _total, _allowed, _unexpected, modules, _executed, _skipped, _xfails, _errors = classify(
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


def collected_per_module() -> dict:
    """{module: collected} from a real collection, not from counting `def test_`.

    That count missed every parametrised case -- 426 definitions against 645
    collected -- so anything derived from it measured a different suite than the
    floors are compared against.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    counts: dict = {}
    for line in completed.stdout.splitlines():
        if not line.startswith("tests/"):
            continue
        name, _, tail = line.rpartition(":")
        if tail.strip().isdigit():
            counts[name] = int(tail)
    assert counts, (
        "collection produced no per-module counts:" + chr(10)
        + completed.stdout[-500:]
    )
    return counts


def documented_band_slack() -> int:
    """The one derived census number that lived in prose rather than a row."""
    text = (ROOT / "scripts" / "check_test_coverage.py").read_text(encoding="utf-8")
    found = re.findall(r"per-module bands already grant (\d+) in total", text)
    assert len(found) == 1, (
        "the sentence naming the slack the per-module bands grant is gone or "
        f"doubled, so this guard measures nothing: {found}"
    )
    return int(found[0])


def test_the_slack_the_bands_grant_is_the_measured_sum():
    """The last hand-derived number in that comment, now read by something.

    It has gone stale FIVE times. It said 152 when the bands granted 163; the
    commit that corrected it to 163 also raised two module floors and made the
    answer 166; two independent reviews then found 163 again. Every other
    derived quantity in that block was promoted to a row and stopped rotting,
    and this one is the last, so it gets the same treatment: parsed out of the
    prose and compared against the sum the floors actually permit.

    Two routes, and they are NOT independent -- said plainly, because
    "derived twice over" was the claim and `total - sum(floors)` is
    algebraically the same as summing `collected - floor`, which is not
    what the code computes either. What the two routes actually catch is a
    declared floor that is not the band of what its module collects: they
    agree only when every floor equals `band(collected)`.

    That comparison is over SUMS, so compensating deviations would pass it.
    Per-module drift below the band is caught separately by
    `test_no_module_floor_drifts_far_below_its_module`, leaving only the
    harmless above-band direction unpinned here -- stated rather than left
    for a reader to discover, because the failure message below names a
    per-module fact and the assertion is over a total.
    """
    from check_test_coverage import REQUIRED_MODULE_MINIMUMS, band  # noqa: PLC0415

    counts = collected_per_module()
    missing = sorted(set(REQUIRED_MODULE_MINIMUMS) - set(counts))
    assert missing == [], (
        "a module with a declared floor collects nothing, so the slack cannot "
        f"be computed: {missing}"
    )
    per_module = sum(
        counts[name] - floor for name, floor in REQUIRED_MODULE_MINIMUMS.items()
    )
    by_band = sum(
        counts[name] - band(counts[name]) for name in REQUIRED_MODULE_MINIMUMS
    )
    assert per_module == by_band, (
        "a declared floor is not the band of what its module collects, so "
        f"'the slack the bands grant' is two different numbers: {per_module} "
        f"and {by_band}. Recompute the floors."
    )
    assert documented_band_slack() == per_module, (
        "the comment says the per-module bands grant "
        + str(documented_band_slack()) + " in total; they grant "
        + str(per_module) + ". This number has gone stale five times, which is "
        "why it is read here instead of trusted."
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
    assert MINIMUM_COLLECTED >= census.band(collected), (
        f"a floor of {MINIMUM_COLLECTED} against {collected} collected tests "
        f"leaves {collected - MINIMUM_COLLECTED} of slack: whole modules could "
        "be deleted with this gate still passing"
    )
    # `<= collected * 2` under the message "the floor is above what the suite
    # can collect, so every run fails". Every value in (collected, 2*collected]
    # makes every run fail AND satisfies that bound, so the assertion admitted
    # exactly the state its message describes. The correct bound is the count.
    assert MINIMUM_COLLECTED <= collected, (
        f"the floor is {MINIMUM_COLLECTED} against {collected} collected, so "
        "every run fails the aggregate no matter what the suite does"
    )

    # THE ROW THAT COSTS A COLLECTION. This test already paid for one, so the
    # documented count is checked here rather than in a second full run.
    documented = documented_census_numbers()["collected across tests/"]
    assert documented == collected, (
        f"the dated table beside MINIMUM_COLLECTED says {documented} tests "
        f"collect across tests/; {collected} do. That comment has gone stale "
        "twice already and both times a human found it. Re-measure it and "
        "update the rows together -- the band row depends on this one."
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
        required_names = (
            sorted(
                identity.split("::", 1)[1]
                for identity in census.PR16_REQUIRED_EXECUTED
                if identity.split("::", 1)[0] == name
            )
            if name == "tests/test_trusted_greenfield_acceptance.py"
            else []
        )
        for test_name in required_names:
            cases.append(f'<testcase classname="{classname}" name="{test_name}"/>')
        floor = max(census.REQUIRED_MODULE_MINIMUMS.get(name, 1), 1)
        for index in range(max(floor - len(required_names), 0)):
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
    # EVERY MODULE WITH A FLOOR, not just the required ones. This built
    # cases for `REQUIRED_MODULES` alone, so a module that had a floor
    # and was not required contributed zero -- and a helper called
    # `_complete_report_cases` produced a report the gate refuses, making
    # every test built on it fail for a clause it was not about.
    floored = tuple(sorted(
        set(REQUIRED_MODULES) | set(census.REQUIRED_MODULE_MINIMUMS)
    ))
    return _module_cases(floored) + _filler_cases(count - _floored_total(floored))


def _floored_total(modules) -> int:
    """How many testcases `_module_cases(modules)` emits."""
    return sum(
        max(census.REQUIRED_MODULE_MINIMUMS.get(name, 1), 1)
        for name in modules
    )


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


#: The six rows of the dated table above `MINIMUM_COLLECTED`.
_DOCUMENTED_ROW = re.compile(
    r"^#\s{4,}(collected across tests/|sum of the module floors|"
    r"band\(\d+\) = ceil\(0\.9\*n\)|MINIMUM_COLLECTED|"
    r"above the module sum|below what collects)\s+(\d+)",
    re.MULTILINE,
)


def documented_census_numbers() -> dict:
    """The table beside `MINIMUM_COLLECTED`, parsed."""
    source = (ROOT / "scripts/check_test_coverage.py").read_text(encoding="utf-8")
    found = _DOCUMENTED_ROW.findall(source)
    # A DICT SILENTLY KEEPS THE LAST OF ANY DUPLICATE LABEL, so a stale row
    # sitting above a correct one would be masked and `len(rows)` could not
    # see it. Each label has to appear exactly once.
    labels = [label for label, _ in found]
    duplicated = sorted({label for label in labels if labels.count(label) > 1})
    assert duplicated == [], (
        "the table has more than one row for these labels, so a stale row can "
        f"hide behind a correct one: {duplicated}"
    )
    rows = {label: int(value) for label, value in found}
    assert len(rows) == 6, (
        "the dated table beside MINIMUM_COLLECTED no longer has its six rows, "
        f"so nothing here is being checked: found {sorted(rows)}"
    )
    return rows


def test_the_aggregate_floor_comment_states_the_measured_numbers():
    """The comment beside the constant has gone stale TWICE. Not again.

    Both times a human review caught it, and both times every test beside it
    stayed green -- because prose beside a constant is not a measurement of
    it. The first stale line was wrong by 27 the day it was written; the
    second stated three numbers of which none was true and whose arithmetic
    did not hold between them either.

    This reads all six rows and checks the five that are pure source facts.
    The sixth -- what actually collects -- costs a collection, so it is
    checked by `test_the_floor_sits_below_the_current_suite_and_above_nothing`,
    which was already paying for one.
    """
    rows = documented_census_numbers()
    module_sum = sum(REQUIRED_MODULE_MINIMUMS.values())

    assert rows["sum of the module floors"] == module_sum, (
        f"the comment says the module floors sum to "
        f"{rows['sum of the module floors']}; they sum to {module_sum}"
    )
    # THE TWO MARGINS. These were prose until a review moved the constant and
    # its row together and left both sentences wrong by 38, with every guard
    # green -- in the comment whose repair had just been committed for exactly
    # that. A number nothing reads is a number that has already started to rot.
    assert rows["above the module sum"] == MINIMUM_COLLECTED - module_sum, (
        f"the comment says the aggregate sits {rows['above the module sum']} "
        f"above the module sum; it sits {MINIMUM_COLLECTED - module_sum}"
    )
    assert rows["below what collects"] == (
        rows["collected across tests/"] - MINIMUM_COLLECTED
    ), (
        f"the comment says the aggregate sits {rows['below what collects']} "
        "below what collects; it sits "
        f"{rows['collected across tests/'] - MINIMUM_COLLECTED}"
    )
    assert rows["MINIMUM_COLLECTED"] == MINIMUM_COLLECTED, (
        f"the comment says the aggregate floor is {rows['MINIMUM_COLLECTED']}; "
        f"the constant below it is {MINIMUM_COLLECTED}"
    )
    band_label = next(key for key in rows if key.startswith("band("))
    stated_band = census.band(rows["collected across tests/"])
    assert rows[band_label] == stated_band, (
        f"the comment records {band_label} = {rows[band_label]}; the census "
        f"computes {stated_band} for {rows['collected across tests/']} "
        "collected. The row and the function disagree."
    )
    assert band_label == "band(%d) = ceil(0.9*n)" % rows["collected across tests/"], (
        f"the band row is labelled {band_label} but the table says "
        f"{rows['collected across tests/']} collect: the label names a "
        "different suite than the row above it."
    )

    # EVERY GUARD THE CENSUS CITES MUST EXIST.
    #
    # One draft of the comment above the constant named two tests that were
    # never written; the next broke a real name across a line so it cited
    # nothing either. Prose pointing at a guard is worth exactly what the
    # guard is worth, and a name nobody can resolve is worth nothing.
    #
    # Scanned over the WHOLE census script rather than the one comment block,
    # because narrowing it to the block would have made this assertion's own
    # message the broader claim -- and it found a second imprecision straight
    # away: a module was cited by its bare stem where a path was meant.
    source = (ROOT / "scripts/check_test_coverage.py").read_text(encoding="utf-8")
    cited = set(re.findall(r"`(test_[a-z0-9_]+)`", source))
    assert cited, "the census cites no guard at all, so this checks nothing"
    defined = set()
    for module in sorted((ROOT / "tests").glob("test_*.py")):
        defined.update(re.findall(
            r"^def (test_[a-z0-9_]+)\(", module.read_text(encoding="utf-8"),
            re.MULTILINE,
        ))
    unresolved = sorted(cited - defined)
    assert unresolved == [], (
        "the census script cites guards that do not exist in tests/: "
        f"{unresolved}. A citation nobody can resolve reads as assurance and "
        "carries none. If a MODULE was meant, name it as a path."
    )


@pytest.mark.false_green("FG35")
def test_the_aggregate_floor_sits_above_the_sum_of_the_module_floors():
    """A floor below the sum of its parts can never fire.
    FG35: a floor whose check could not reach its own verdict.

    MEASURED: `MINIMUM_COLLECTED` was 1450 while the per-module floors summed to
    1458, so any report satisfying every module floor also satisfied the
    aggregate. It was a declared check that could not reach a verdict of its
    own -- the shape this repository calls a false green.

    Found because `test_the_floor_refusal_actually_runs` started returning 0
    where it requires 2: its synthetic report, built from one case per required
    module, had grown past the aggregate floor.
    """
    module_sum = sum(REQUIRED_MODULE_MINIMUMS.values())
    assert MINIMUM_COLLECTED > module_sum, (
        f"the aggregate floor is {MINIMUM_COLLECTED} and the per-module floors "
        f"sum to {module_sum}. The aggregate cannot refuse anything the module "
        "floors already accept, so it is decoration. Raise it above the sum."
    )


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
    _total, allowed, unexpected, _modules, _executed, _skipped, _xfails, _errors = classify(
        _typed_report(tmp_path, "pytest.xfail")
    )
    assert unexpected == [], "an expected failure was reported as an undeclared skip"
    assert allowed == 0, "an xfail must not consume a skip exemption either"


def test_a_real_skip_with_the_same_shape_is_still_caught(tmp_path: Path):
    """The discrimination must cut only where intended.

    Same test id, same message, same element -- only `type` differs. If the gate
    keyed on anything looser, an undeclared skip could dress itself as an xfail.
    """
    _total, _allowed, unexpected, _modules, _executed, _skipped, _xfails, _errors = classify(
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


def _real_module_counts() -> dict:
    """How many tests each module ACTUALLY contributes, by collecting them.

    The floors are a hand-written table and the census enforces them. Nothing
    compared them against the suite: the test below built its report from the
    floors and then checked the floors against it, so every floor was met by
    construction and a floor set ABOVE a module's real contribution -- which
    fails every census run -- could not be detected here.
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:randomly"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=1800,
    )
    assert completed.returncode == 0, (
        "the suite could not be collected, so nothing about the floors was "
        f"measured: {completed.stdout[-400:]}{completed.stderr[-300:]}"
    )
    # `-q --collect-only` prints one `path/to/module.py: COUNT` line per module,
    # not one line per test. Parsing it as `module::test` returned an empty
    # dict -- caught by the floor below, which is why that floor is here.
    counts: dict = {}
    for line in completed.stdout.splitlines():
        module, separator, tail = line.partition(": ")
        if not separator or not module.endswith(".py"):
            continue
        if tail.strip().isdigit():
            counts[module.strip().replace(chr(92), "/")] = int(tail.strip())
    assert len(counts) > 50, (
        f"only {len(counts)} modules were collected; the parse above has "
        "stopped matching pytest's output and this measures nothing"
    )
    return counts


def test_the_declared_floors_are_met_by_the_real_suite():
    """The control, and the thing that keeps the floors honest.

    Floors set above what the suite actually contributes would fail every run;
    floors set at zero would accept anything. Measured by COLLECTING, because
    the previous version built its report out of the floors it was checking.
    """
    real = _real_module_counts()
    impossible = []
    for module, floor in sorted(census.REQUIRED_MODULE_MINIMUMS.items()):
        actual = real.get(module)
        if actual is None:
            impossible.append(f"{module}: floored at {floor}, collects nothing")
        elif actual < floor:
            impossible.append(f"{module}: floored at {floor}, collects {actual}")
    assert impossible == [], (
        "these floors are above what the module actually contributes, so every "
        f"census run fails until they are corrected: {impossible}"
    )


# A per-module drift guard is NOT added here: this module already has one,
# `test_no_module_floor_drifts_far_below_its_module`, and it fired on the
# floors this round changed. Writing a second implementation of a check
# that already exists is FG26 -- the defect where a guard and its owner
# test two different copies of the same rule -- committed while repairing
# a sibling of it.


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


def test_every_test_module_is_named_in_the_census():
    """No module may be invisible to the anti-shrink gate.

    A review deleted four whole modules -- 81 tests, including the dirty-tree
    gate and the runtime-authority proofs -- and the census still returned
    GATE: PASS, because 24 of 78 modules were named nowhere. The global floor
    absorbed the loss.

    `test_dirty_tree_gate.py` is the sharpest case: three comments in that file
    say a floor raise was made to protect it, while the census could not see it
    at all. A comment is not a check.

    Exhaustive by construction, so adding a module without protecting it fails
    here rather than being discovered by the next review.
    """
    modules = {f"tests/{path.name}" for path in (ROOT / "tests").glob("test_*.py")}
    covered = set(census.REQUIRED_MODULES) | set(census.REQUIRED_MODULE_MINIMUMS)
    unprotected = sorted(modules - covered)
    assert unprotected == [], (
        "these test modules are named nowhere in the census, so deleting them "
        f"entirely would not trip it: {unprotected}"
    )


def test_the_census_names_no_module_that_does_not_exist():
    """The other direction. A stale name is a check that can never fail.

    Padding the list with modules that do not exist would make the sweep above
    pass while protecting nothing, which is the count-versus-identity defect
    one level along.
    """
    modules = {f"tests/{path.name}" for path in (ROOT / "tests").glob("test_*.py")}
    named = set(census.REQUIRED_MODULES) | set(census.REQUIRED_MODULE_MINIMUMS)
    phantom = sorted(named - modules)
    assert phantom == [], (
        f"the census names modules that do not exist: {phantom}"
    )


def _report_omitting(tmp_path: Path, omit: set[str]) -> Path:
    """A JUnit report holding every module at its declared floor, minus `omit`.

    Synthesised rather than produced by a real run: driving the census through
    a full nested pytest takes over fifty minutes, and the property under test
    is the VERDICT FUNCTION, not pytest. `evaluate` is the census's single
    decision point, so exercising it directly measures the gate itself.
    """
    cases = []
    for module, floor in census.REQUIRED_MODULE_MINIMUMS.items():
        if module in omit:
            continue
        classname = module[len("tests/"):-len(".py")]
        required_names = (
            sorted(
                identity.split("::", 1)[1]
                for identity in census.PR16_REQUIRED_EXECUTED
                if identity.split("::", 1)[0] == module
            )
            if module == "tests/test_trusted_greenfield_acceptance.py"
            else []
        )
        for test_name in required_names:
            cases.append(
                f'<testcase classname="tests.{classname}" name="{test_name}" '
                f'file="{module}"></testcase>'
            )
        for index in range(max(floor - len(required_names), 0)):
            cases.append(
                f'<testcase classname="tests.{classname}" name="test_{index}" '
                f'file="{module}"></testcase>'
            )
    # Pad to the global floor. Per-module floors sum to less than
    # MINIMUM_COLLECTED, so an unpadded complete report would be refused for
    # being too small -- a true refusal, but not the one under test, and it
    # would make the positive control fail for the wrong reason.
    if omit == set():
        classname = "test_padding"
        while len(cases) < census.MINIMUM_COLLECTED:
            cases.append(
                f'<testcase classname="tests.{classname}" '
                f'name="test_pad_{len(cases)}" file="tests/test_padding.py">'
                "</testcase>"
            )
    report = tmp_path / "synthetic.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites>'
        f'<testsuite name="pytest" tests="{len(cases)}">' + "".join(cases)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return report


def test_deleting_whole_security_modules_is_refused_by_the_census(tmp_path: Path):
    """The exact deletion a review performed, now refused.

    Four modules -- 81 tests including the dirty-tree gate and the
    runtime-authority proofs -- were deleted and the census still returned
    GATE: PASS, because those modules were named nowhere and the global floor
    absorbed the loss.
    """
    victims = {
        "tests/test_dirty_tree_gate.py",
        "tests/test_architecture_coverage.py",
        "tests/test_runtime_authority.py",
        "tests/test_authority_config.py",
    }
    verdict = census.evaluate(_report_omitting(tmp_path, victims), 0)
    assert verdict != 0, (
        "the census accepted a run missing four whole security modules, so "
        "deleting them would still report GATE: PASS"
    )


def test_the_census_accepts_a_complete_report(tmp_path: Path):
    """The positive control.

    Without it the refusal above is satisfied by a census that refuses
    everything, which would be a broken gate rather than a strict one.
    """
    verdict = census.evaluate(_report_omitting(tmp_path, set()), 0)
    assert verdict == 0, (
        "the census refused a report holding every declared module at its "
        "declared floor, so it now refuses valid runs"
    )


@pytest.mark.parametrize("victim", sorted(census.PR16_REQUIRED_EXECUTED))
def test_each_pr16_hostile_and_real_flow_identity_is_load_bearing(
    tmp_path: Path, victim: str
) -> None:
    module, test_name = victim.split("::", 1)
    classname = module.removesuffix(".py").replace("/", ".")
    exact = f'<testcase classname="{classname}" name="{test_name}"/>'
    cases = _complete_report_cases(MINIMUM_COLLECTED)
    assert exact in cases, f"the synthetic complete report does not carry {victim}"
    cases = cases.replace(exact, "", 1) + (
        '<testcase classname="tests.test_filler" name="test_pr16_replacement"/>'
    )

    verdict = evaluate(_report_with(tmp_path, cases), 0)

    assert verdict != 0, f"the census accepted a run missing {victim}"


def _band(collected: int) -> int:
    """The lowest floor that still counts as 90% of `collected`.

    Delegates to `census.band`, which is now the only definition. This module
    had its own, `tests/attack_property.py` had a third, and two of the three
    truncated. See the note there.

    CEILING, not floor division. `collected * 9 // 10` TRUNCATES, so a
    two-test module passed with a floor of 1 (50%) and a three-test module with
    2 (67%) -- a review measured five modules sitting in that vacuous band. The
    smaller the module, the further the truncation let it drift, which is
    backwards: a small module is the one a single deletion guts.
    """
    return census.band(collected)


def test_the_band_is_not_vacuous_for_small_modules():
    """The arithmetic itself, since it decides every other floor.

    Truncation is invisible in the assertion that uses it; it shows up only as
    a module quietly passing at half its size.
    """
    assert _band(2) == 2, "a two-test module can still pass at 50%"
    assert _band(3) == 3
    assert _band(10) == 9
    assert _band(70) == 63
    assert _band(1) == 1


def test_no_module_floor_drifts_far_below_its_module():
    """B-P2-4: the aggregate floor has a band guard; the per-module ones had none.

    `test_no_floor_is_zero` required `floor >= 1`, and that was the whole
    protection. Measured before this test existed: 48 of 79 modules sat below
    90% of what they collect, several between 25% and 38%, for a total of 317
    tests deletable while the census still reported GATE: PASS -- including
    both R2 regressions and the Task 11R route-inventory proofs, none of which
    is named by any other inventory.

    The aggregate floor cannot see this. Other modules grow, the total stays
    above `MINIMUM_COLLECTED`, and a module can be hollowed out underneath it.
    That is the same argument the aggregate band guard already makes for the
    suite as a whole, applied one level down where the deletions actually land.

    The band is 90%, matching the aggregate. A module that grows past its floor
    trips this rather than drifting: raising the number is a diff someone can
    argue with, which is the point.
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider", "-p", "no:warnings"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=1800,
    )
    collected = {}
    for line in completed.stdout.splitlines():
        match = re.match(r"^(tests/[^:]+):\s*(\d+)$", line.strip())
        if match:
            collected[match.group(1)] = int(match.group(2))
    assert collected, f"collection produced no counts:\n{completed.stdout[-500:]}"

    drifted = sorted(
        f"{name}: floor {floor} against {collected[name]} collected "
        f"({floor * 100 // collected[name]}%, needs {_band(collected[name])})"
        for name, floor in census.REQUIRED_MODULE_MINIMUMS.items()
        if collected.get(name) and floor < _band(collected[name])
    )
    assert drifted == [], (
        "these module floors have drifted far below the modules they protect, "
        "so tests can be deleted from them without the census noticing -- the "
        "aggregate floor cannot see a module being hollowed out while other "
        f"modules grow: {drifted}"
    )


def test_the_module_band_guard_would_notice_a_drifted_floor():
    """The guard's own discrimination, since a band test that never fires is
    indistinguishable from one that cannot.

    Arithmetic rather than a mutated file: the comparison is the whole check,
    so exercising it directly is exercising the thing.
    """
    collected, floor = 40, 12
    assert floor < _band(collected), (
        "a floor at 30% of its module no longer counts as drifted, so the band "
        "has been widened past the point of noticing anything"
    )
    assert not (36 < _band(collected)), (
        "a floor at 90% is being reported as drifted, so the guard would refuse "
        "every honest floor and would be turned off"
    )


#: Skip exemptions permitted to claim a HUMAN dependency, with the authority
#: that is missing. EMPTY, and that is the finding rather than an oversight.
#:
#: Four entries claimed HUMAN-BLOCKED on the premise that the shipped
#: demonstration needs a runtime lock. It does not -- measured on a clean
#: tracked-files copy, `demo --offline` exits 0 with the absence landing in the
#: deterministic fallback. Removing the precondition took the module from 9
#: skips to 10 passing tests.
DECLARED_HUMAN_BLOCKED_SKIPS: dict[str, str] = {}


def test_no_exemption_may_declare_itself_human_blocked_without_saying_so():
    """`HUMAN_BLOCKED` is the one category no autonomous run may close.

    Which makes over-declaring it the mirror image of the substitution this
    repository exists to police: claiming a blocker that is not there rather
    than a control that is not there. A reviewer auditing the census was told
    the strongest check of BRD-F-005 was permanently unobtainable, and accepted
    nine permanent skips instead of spending a minute disproving it.

    `EXPECTED_SKIPS` requires only that a reason exceed sixty characters, so
    its content is unbound and the phrase could be written back in tomorrow.
    A reason claiming a human dependency must now name it in
    `DECLARED_HUMAN_BLOCKED_SKIPS` -- a diff someone has to argue for, rather
    than a sentence anyone can type.

    This does not verify that a declared blocker is REAL; nothing mechanical
    can, since the authority is external by definition. It makes the claim
    visible and countable, which is what let four copies of a false one sit
    unexamined.
    """
    claiming = sorted(
        marker for marker, reason in EXPECTED_SKIPS.items()
        if "human-blocked" in reason.lower() or "human approval" in reason.lower()
    )
    undeclared = [
        marker for marker in claiming
        if marker not in DECLARED_HUMAN_BLOCKED_SKIPS
    ]
    assert undeclared == [], (
        "these skip exemptions claim a human dependency in prose without "
        "declaring it, so the claim is unbound and uncounted. If the blocker "
        "is real, name it in DECLARED_HUMAN_BLOCKED_SKIPS with the authority "
        f"that is missing: {undeclared}"
    )
    stale = sorted(set(DECLARED_HUMAN_BLOCKED_SKIPS) - set(EXPECTED_SKIPS))
    assert stale == [], (
        "these declared human-blocked skips are no longer exempted at all, so "
        f"the declaration is stale: {stale}"
    )


def test_the_brd_f_005_exemption_still_describes_the_ci_workflow():
    """CI must never mint a runtime lock unguarded.

    THE NINE SKIPS THIS WAS WRITTEN FOR ARE GONE, and the reason matters more
    than the guard. Those entries said "This measurement runs the shipped
    demonstration, which needs `.nornyx/runtime/nornyx.agentic_network.lock`
    ... HUMAN-BLOCKED". This guard bound the CI half of that sentence -- true
    then and true now -- and nothing bound the load-bearing half, which was
    false: the demonstration runs without the lock, measured on a copy of the
    216 tracked files, EXIT 0 with the absence landing in the deterministic
    fallback. Nine cases now run and pass.

    That is the shape worth recording: the repository noticed the sentence was
    unbound, bound the clause that was already true, and left the clause that
    was false. `EXPECTED_SKIPS` still requires only that a reason exceed sixty
    characters, so reason CONTENT remains unbound in general --
    `test_no_exemption_may_declare_itself_human_blocked_without_saying_so`
    closes the specific case that matters.

    The property here survives its original motivation and is kept on its own
    merit: a `prepare_runtime.py` step added to CI without an approval guard
    would attempt to mint a lock in an environment that has no authority to
    hold one. Either the workflow never runs it, or every step that does is
    conditional on an approval being present.
    """
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    lines = workflow.splitlines()
    unguarded = []
    for number, line in enumerate(lines, start=1):
        if "prepare_runtime.py" not in line:
            continue
        # The `if:` guarding a step precedes its `run:`. Look back a few lines
        # rather than parsing YAML: a dependency on a YAML library here would
        # be a new install for one assertion.
        window = lines[max(0, number - 6):number]
        if not any("steps.approval.outputs.present" in earlier for earlier in window):
            unguarded.append(f".github/workflows/ci.yml:{number}")

    assert unguarded == [], (
        "CI runs `prepare_runtime.py` without gating it on an approval being "
        "present, so the BRD-F-005 skip reasons -- which tell a reader that no "
        "CI job can produce a runtime lock -- now describe a workflow this "
        f"repository does not have: {unguarded}"
    )
    assert "prepare_runtime.py" in workflow, (
        "the workflow no longer mentions `prepare_runtime.py` at all, so this "
        "check passes vacuously and the skip reasons are unbound again"
    )
