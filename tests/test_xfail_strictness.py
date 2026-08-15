"""An expected failure must not be a security proof with an off switch.

The census used to skip xfails outright, on the written ground that they were
strict here. `xfail_strict` was set nowhere. One `@pytest.mark.xfail` could
therefore silence a failing integrity proof with the gate reporting PASS, zero
unexpected skips, and an unchanged collection count.

Two things close it, and both are self-attacked below rather than described:

    xfail_strict = true       an XPASS fails the run, so a marked test that
                              starts passing is reported, not accepted
    EXPECTED_XFAILS = {}      an undeclared expected failure fails the gate in
                              its own vocabulary, instead of being waved past

The intended inventory is EMPTY. A security proof expected to fail is a proof
that is off; the honest response is to fix it or delete it, not to record that
it does not work.

Configuration is EVALUATED, never grepped: the point of the original defect was
that prose asserted a setting that did not exist.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_test_coverage as census  # noqa: E402


def _ini_options() -> dict:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["tool"]["pytest"]["ini_options"]


def _run_pytest(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", *args, "-p", "no:cacheprovider",
         "-p", "no:warnings", "-q"],
        cwd=work, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=600,
    )


def _project(work: Path, *, strict: bool | None) -> None:
    """A minimal project whose pytest configuration we control."""
    lines = ["[tool.pytest.ini_options]", 'testpaths = ["tests"]']
    if strict is not None:
        lines.append(f"xfail_strict = {str(strict).lower()}")
    (work / "pyproject.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (work / "tests").mkdir(exist_ok=True)


# --------------------------------------------------------------------------
# The configuration itself
# --------------------------------------------------------------------------


def test_xfail_strict_is_configured_and_true():
    """Parsed from the real file, not asserted about prose."""
    options = _ini_options()
    assert "xfail_strict" in options, (
        "xfail_strict is not configured, so an xfail is not strict and an XPASS "
        "passes silently -- the exact state that let a decorator switch off four "
        "integrity proofs"
    )
    assert options["xfail_strict"] is True, options["xfail_strict"]


def test_removing_the_setting_is_visible():
    """Self-attack: the guard must fail when the key is absent."""
    options = dict(_ini_options())
    options.pop("xfail_strict", None)
    assert "xfail_strict" not in options  # the state the guard must reject


def test_flipping_the_setting_to_false_is_visible():
    """Self-attack: `false` must not satisfy the guard."""
    options = dict(_ini_options())
    options["xfail_strict"] = False
    assert options["xfail_strict"] is not True


# --------------------------------------------------------------------------
# Strictness, exercised by running pytest
# --------------------------------------------------------------------------


def test_an_xpass_fails_the_run_under_strict(tmp_path: Path):
    """The behaviour the setting buys, measured rather than assumed.

    A test marked xfail that PASSES is a proof someone turned off and then
    fixed without noticing. Strict makes that a failure.
    """
    _project(tmp_path, strict=True)
    (tmp_path / "tests" / "test_probe.py").write_text(
        "import pytest\n\n"
        "@pytest.mark.xfail(reason='claimed broken')\n"
        "def test_actually_passes():\n    assert True\n",
        encoding="utf-8",
    )
    completed = _run_pytest(tmp_path)
    assert completed.returncode != 0, (
        "an XPASS did not fail the run under xfail_strict=true:\n"
        + completed.stdout[-400:]
    )
    assert "XPASS" in (completed.stdout + completed.stderr).upper()


def test_the_same_xpass_passes_without_strict(tmp_path: Path):
    """The control. Without it the test above proves nothing about the setting.

    This is the world the repository was actually in.
    """
    _project(tmp_path, strict=None)
    (tmp_path / "tests" / "test_probe.py").write_text(
        "import pytest\n\n"
        "@pytest.mark.xfail(reason='claimed broken')\n"
        "def test_actually_passes():\n    assert True\n",
        encoding="utf-8",
    )
    completed = _run_pytest(tmp_path)
    assert completed.returncode == 0, (
        "the unstrict control failed, so the strict test above is not measuring "
        "the setting"
    )


# --------------------------------------------------------------------------
# The census, which is what a marked security test would have to get past
# --------------------------------------------------------------------------


def test_the_expected_xfail_inventory_is_closed_and_empty():
    """A recorded expected failure needs a reason a reviewer can check."""
    assert isinstance(census.EXPECTED_XFAILS, dict)
    assert census.EXPECTED_XFAILS == {}, (
        "the intended inventory is empty; every entry here is a security proof "
        f"recorded as not working: {sorted(census.EXPECTED_XFAILS)}"
    )


def test_an_undeclared_xfail_fails_the_gate(tmp_path: Path):
    """Self-attack: mark any test xfail and the census must refuse.

    Built as a JUnit report so the census's own parser is what decides, which is
    the code path a real run takes.
    """
    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1">'
        '<testcase classname="tests.test_security" name="test_a_control" '
        'file="tests/test_security.py">'
        '<skipped type="pytest.xfail" message="known, tracked in TICKET-1"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    (
        total, _allowed, unexpected, _modules, _skipped, unexpected_xfails, _errors,
    ) = census.classify(report)

    assert total == 1
    assert unexpected == [], "an xfail must not be counted as a skip"
    assert unexpected_xfails == ["tests/test_security.py::test_a_control"], (
        "an undeclared expected failure was not reported, so a decorator can "
        "still silence a security proof"
    )


def test_a_declared_xfail_would_be_permitted(tmp_path: Path):
    """The allowlist must actually work, or the empty inventory is meaningless.

    Checked against a temporarily extended copy of the inventory rather than by
    adding a real entry, so the shipped inventory stays empty.
    """
    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1">'
        '<testcase classname="tests.test_security" name="test_a_control" '
        'file="tests/test_security.py">'
        '<skipped type="pytest.xfail" message="declared"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    original = census.EXPECTED_XFAILS
    census.EXPECTED_XFAILS = {
        "tests/test_security.py::test_a_control": "declared for this test only"
    }
    try:
        *_rest, unexpected_xfails, _errors = census.classify(report)
    finally:
        census.EXPECTED_XFAILS = original
    assert unexpected_xfails == []
    assert census.EXPECTED_XFAILS == {}, "the shipped inventory was mutated"


def test_the_gate_refuses_a_run_carrying_an_undeclared_xfail(tmp_path: Path):
    """End to end through `evaluate`, so the verdict itself is proven."""
    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuites><testsuite name="pytest" tests="1">'
        '<testcase classname="tests.test_security" name="test_a_control" '
        'file="tests/test_security.py">'
        '<skipped type="pytest.xfail" message="switched off"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    assert census.evaluate(report, 0) != 0, (
        "the gate accepted a run in which a security proof was marked as an "
        "expected failure"
    )


def test_the_suite_currently_carries_no_expected_failures():
    """The intended state, asserted so a first xfail has to be deliberate."""
    marked = [
        path.name
        for path in (ROOT / "tests").glob("*.py")
        if "pytest.mark.xfail" in path.read_text(encoding="utf-8")
        and path.name != Path(__file__).name
    ]
    assert marked == [], (
        f"these modules now carry xfail markers: {marked}. Each must be fixed "
        "or added to EXPECTED_XFAILS with a checkable reason."
    )
