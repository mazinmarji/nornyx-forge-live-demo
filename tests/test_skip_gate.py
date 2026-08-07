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

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_test_coverage import EXPECTED_SKIPS, classify  # noqa: E402

_REPORT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="3">
  <testcase classname="tests.test_ran" name="test_ran"/>
  <testcase classname="tests.test_docker" name="test_launch">
    <skipped message="set FORGE_DOCKER_TESTS=1 with Docker running to build"/>
  </testcase>
  <testcase classname="tests.test_governance" name="test_wiring">
    <skipped message="{reason}"/>
  </testcase>
</testsuite></testsuites>
"""


def _report(tmp_path: Path, reason: str) -> Path:
    path = tmp_path / "report.xml"
    path.write_text(_REPORT.format(reason=reason), encoding="utf-8")
    return path


def test_the_historical_failure_is_now_caught(tmp_path: Path):
    """The exact skip reason that hid 63 tests behind a green run."""
    total, allowed, unexpected = classify(_report(tmp_path, "nornyx CLI is not installed"))
    assert total == 3
    assert allowed == 1, "the declared Docker skip should still be allowed"
    assert len(unexpected) == 1
    assert "test_wiring" in unexpected[0]
    assert "nornyx CLI is not installed" in unexpected[0]


def test_a_declared_skip_is_allowed(tmp_path: Path):
    """The gate must not force tests to run where the design says they cannot."""
    total, allowed, unexpected = classify(
        _report(tmp_path, "set FORGE_DOCKER_TESTS=1 with Docker running to build")
    )
    assert total == 3
    assert allowed == 2
    assert unexpected == []


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
