"""A kill must be attributed to the exact node, phase, and property.

`require_caused_failure` sums `<failure>` and `<error>` elements across the
WHOLE JUnit report. The node argument is used only in messages. So:

    the named node PASSES
    an unrelated node FAILS
    -----------------------
    the campaign records KILLED

H05 is why this matters concretely: the contradiction between "the mutation
kills" and "the recorded control is not decisive" was only resolved by reading
WHICH assertion failed. An aggregate cannot answer that question, and every
defect this cycle found has the same shape -- a count or a label standing in for
the thing it summarises.

The hierarchy a valid kill must satisfy:

    exact node identity
      -> exact execution phase (call, not setup or teardown)
        -> an actual assertion failure, not an error
          -> attributable to the intended root property

Not: `rc != 0` -> some `<failure>` somewhere -> the string looks plausible.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from mutation_workspace import (  # noqa: E402
    AttackNotAdmissible,
    require_caused_failure,
)

NODE = "tests/test_target.py::test_the_named_proof"
OTHER = "tests/test_target.py::test_something_else"


def _report(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "report.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<testsuites><testsuite name="pytest">{body}</testsuite></testsuites>',
        encoding="utf-8",
    )
    return path


def _case(classname: str, name: str, inner: str = "") -> str:
    return (
        f'<testcase classname="{classname}" name="{name}" '
        f'file="tests/test_target.py">{inner}</testcase>'
    )


PASSED = _case("tests.test_target", "test_the_named_proof")
OTHER_FAILED = _case(
    "tests.test_target", "test_something_else",
    '<failure message="an unrelated proof broke">assert 1 == 2</failure>',
)


def test_case1_an_unrelated_node_failing_is_not_a_kill(tmp_path: Path):
    """The named node PASSED. Something else broke. That is not evidence.

    This is the defect in its purest form: the campaign would record the
    control as removed while the proof of that control still passes.
    """
    report = _report(tmp_path, PASSED + OTHER_FAILED)

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(report, NODE, "")
    assert "test_the_named_proof" in str(refusal.value)


def test_case2_a_setup_error_on_the_named_node_is_not_a_kill(tmp_path: Path):
    """A fixture that could not be built says nothing about the control.

    The node never reached its assertions, so no security property was
    exercised -- the mutant may simply have broken the workspace.
    """
    report = _report(tmp_path, _case(
        "tests.test_target", "test_the_named_proof",
        '<error message="fixture failure" type="pytest.fixture">setup failed</error>',
    ))

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(report, NODE, "")
    assert refusal.value.outcome.value in {
        "INVALID_MUTATION", "INVALID_MUTATION_ENVIRONMENT",
    }, refusal.value.outcome


def test_case3_a_teardown_error_does_not_substitute_for_the_result(tmp_path: Path):
    """Teardown runs AFTER the assertions, so it cannot be the verdict.

    A node that passed and then failed to clean up has demonstrated the control
    HOLDING, which is the opposite of a kill.
    """
    report = _report(tmp_path, _case(
        "tests.test_target", "test_the_named_proof",
        '<error message="teardown of the workspace failed">rmtree failed</error>',
    ))

    with pytest.raises(AttackNotAdmissible):
        require_caused_failure(report, NODE, "")


def test_case4_a_collection_error_is_not_a_kill(tmp_path: Path):
    """The mutant did not import. Nothing was measured."""
    report = _report(tmp_path, _case(
        "tests.test_target", "test_the_named_proof",
        '<error message="collection failure">ImportError: no module named x</error>',
    ))

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(report, NODE, "")
    assert refusal.value.outcome.value != "KILLED_VALIDLY"


def test_case5_a_missing_named_node_is_not_a_kill(tmp_path: Path):
    """The report contains other nodes but not the registered one.

    A renamed or deleted proof must not be satisfied by whatever else ran.
    """
    report = _report(tmp_path, OTHER_FAILED)

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(report, NODE, "")
    assert "test_the_named_proof" in str(refusal.value)


def test_case6_the_named_node_failing_for_the_wrong_reason_is_not_a_kill(
    tmp_path: Path,
):
    """CORRECT NODE, WRONG REASON is still a false kill.

    Exact-node attribution alone permits it: the node fails, in the call phase,
    with a genuine assertion -- about something the attack never touched. This
    is the case that stops `<failure>` becoming the next label standing in for
    semantics.
    """
    report = _report(tmp_path, _case(
        "tests.test_target", "test_the_named_proof",
        '<failure message="AssertionError: the fixture directory is missing">'
        "assert Path(work).exists()</failure>",
    ))

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(
            report, NODE, "", expected_property="the verifier crashed instead of refusing"
        )
    assert "not attributable" in str(refusal.value).lower(), str(refusal.value)


def test_case7_the_named_node_failing_for_the_intended_property_is_a_kill(
    tmp_path: Path,
):
    """The accepting case. Without it, every refusal above could be
    "refuses everything", which proves nothing."""
    report = _report(tmp_path, _case(
        "tests.test_target", "test_the_named_proof",
        '<failure message="AssertionError: the verifier crashed instead of '
        'refusing">assert "Traceback" not in stderr</failure>',
    ))

    require_caused_failure(
        report, NODE, "", expected_property="the verifier crashed instead of refusing"
    )


def test_case8_mixed_failure_and_error_evidence_cannot_be_credited(tmp_path: Path):
    """Ambiguous evidence for the SAME node is not resolved in favour of a kill.

    "There exists a `<failure>` for this node" is the aggregate shortcut one
    level down. If the node also errored, the run cannot show that the intended
    call-phase assertion is what decided the outcome, so nothing is credited.
    """
    report = _report(tmp_path, _case(
        "tests.test_target", "test_the_named_proof",
        '<failure message="AssertionError: the verifier crashed instead of '
        'refusing">assert x</failure>'
        '<error message="teardown blew up">rmtree failed</error>',
    ))

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(
            report, NODE, "", expected_property="the verifier crashed instead of refusing"
        )
    assert refusal.value.outcome.value != "KILLED_VALIDLY"


def test_case9_a_partly_failing_parametrised_family_is_reported_as_partial(
    tmp_path: Path,
):
    """A family is not a node, and "the node failed" hides which parameters did.

    A review measured H07 under its mutant as 25 cases with 8 failed and 17
    PASSED -- the control only partly removed -- while the report said the node
    failed. The verdict no longer rests on this (the attack's executable
    property criterion decides), but collapsing a family into one word is how
    "resolves every spelling" got credited from a third of its cases.
    """
    body = (
        _case("tests.test_target", "test_the_named_proof[a]",
              '<failure message="AssertionError: broke">assert 0</failure>')
        + _case("tests.test_target", "test_the_named_proof[b]")
        + _case("tests.test_target", "test_the_named_proof[c]")
    )
    report = _report(tmp_path, body)

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(
            report, NODE, "", expected_property="a property nothing mentions"
        )
    message = str(refusal.value)
    assert "parametrised family" in message, message
    assert "1 of 3" in message, (
        f"the split was not reported, so a partial family still reads as a "
        f"whole-node failure: {message}"
    )


def test_case10_a_wholly_failing_family_is_not_reported_as_partial(tmp_path: Path):
    """The control. Marking every family partial would make the signal useless."""
    body = "".join(
        _case("tests.test_target", f"test_the_named_proof[{p}]",
              '<failure message="AssertionError: broke">assert 0</failure>')
        for p in "abc"
    )
    report = _report(tmp_path, body)

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(
            report, NODE, "", expected_property="a property nothing mentions"
        )
    assert "parametrised family" not in str(refusal.value), str(refusal.value)
