"""What each execution mode DOES, not what it requests.

`docs/VALIDATION.md` said the normal bootstrap, the CI demo job and the Docker
path "request strict Nornyx/CrewAI execution and fail closed", and that only an
explicit local smoke path was labelled `deterministic_fallback`. Measured, the
shipped container requests neither:

    demo_app.main:app  ->  AUTHORITY = demonstration_authority()
                       ->  policy_backend    = "deterministic_demo"
                       ->  execution_backend = "sequential"

So the sentence described the strict posture while the thing that ships runs the
permissive one -- the same direction of error as the compose file that claimed a
fail-closed default nothing implemented.

The implementation was not the problem and was not changed. `deterministic_demo`
is a deliberate choice: no human approval exists in this repository, so strict
Nornyx refuses everything, and a demonstration that cannot run is not a
demonstration. What was wrong is that the document claimed otherwise.

These tests pin the OBSERVED matrix, so the document can be checked against
behaviour rather than against intent.
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from nornyx_forge.governed_subject import (  # noqa: E402
    GovernedSubjectError,
    RuntimeAuthorityConfig,
)

CASE = {
    "id": "MODE-TRUTH",
    "customer": "Omar",
    "summary": "Issue a high-value external refund",
    "risk": "high",
    "requested_action": "issue refund",
}


def _run(config: RuntimeAuthorityConfig) -> dict:
    """Run one case, with the orchestrator's console noise contained."""
    from demo_app.agentic import run_case  # noqa: PLC0415

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        return run_case(dict(CASE), root=ROOT, config=config)


def test_the_shipped_application_requests_the_permissive_backend():
    """The container's authority, stated as a fact rather than an aspiration.

    This is the assertion the documentation was contradicting. If a future
    change makes the shipped path strict, this fails and the document has to be
    updated with it -- which is the only arrangement under which the two can
    stay in agreement.
    """
    from demo_app.agentic import demonstration_authority  # noqa: PLC0415
    from demo_app.main import AUTHORITY  # noqa: PLC0415

    assert AUTHORITY == demonstration_authority()
    assert AUTHORITY.policy_backend == "deterministic_demo"
    assert AUTHORITY.execution_backend == "sequential"


def test_the_bare_default_is_strict_and_the_shipped_choice_is_not():
    """Both facts together, because either alone reads as the other.

    `RuntimeAuthorityConfig()` defaults to ("nornyx", "crewai"). A reader who
    knows only that would reasonably conclude the application is strict. It is
    not: it names its mode explicitly, and names the permissive one.
    """
    default = RuntimeAuthorityConfig()
    assert (default.policy_backend, default.execution_backend) == ("nornyx", "crewai")

    from demo_app.main import AUTHORITY  # noqa: PLC0415

    assert (AUTHORITY.policy_backend, AUTHORITY.execution_backend) != (
        default.policy_backend,
        default.execution_backend,
    )


def test_the_strict_backend_actually_fails_closed_in_this_repository():
    """"Fails closed" is claimed, so it is measured.

    Nornyx cannot authorize here -- there is no human approval record, which is
    the honest state of this repository -- and the strict path RAISES rather
    than falling back to a deterministic decision under an unchanged label.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable  # noqa: PLC0415

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        _run(RuntimeAuthorityConfig("nornyx", "sequential"))

    reason = str(refusal.value)
    assert "CONTRACT_INVALID" in reason, reason
    # The refusal names WHY, and the why is the absent approval -- not a
    # generic unavailability that could equally mean a broken install.
    assert "APPROVAL" in reason, reason


def test_a_malformed_backend_refuses_before_anything_runs():
    """Unreadable configuration is refused at construction, not interpreted.

    A mode that fell back to a default when it could not be parsed would let a
    typo select the permissive backend silently.
    """
    with pytest.raises(GovernedSubjectError, match="unknown policy backend"):
        RuntimeAuthorityConfig("NOT_A_BACKEND", "sequential")
    with pytest.raises(GovernedSubjectError, match="unknown execution backend"):
        RuntimeAuthorityConfig("nornyx", "NOT_A_BACKEND")


def test_crewai_cannot_be_claimed_when_crewai_cannot_run(monkeypatch):
    """"CrewAI execution" must mean CrewAI executed.

    A silent downgrade to the sequential driver under an unchanged label is how
    a whole suite once stayed green with CrewAI absent, so the unavailable case
    refuses instead.
    """
    import demo_app.agentic as agentic  # noqa: PLC0415

    monkeypatch.setattr(agentic, "CREWAI_AVAILABLE", False)
    with pytest.raises(agentic.ExecutionBackendUnavailable, match="Refusing to run"):
        _run(RuntimeAuthorityConfig("deterministic_demo", "crewai"))


def test_the_observed_backend_comes_from_the_driver_not_the_configuration():
    """The field that makes the claim checkable at all.

    Restating the configuration would make every backend test tautological --
    it would assert the config equals itself. `_sequential_driver` is set only
    by `run_sequential`, so this reads the execution path.
    """
    from demo_app.agentic import CustomerCaseFlow  # noqa: PLC0415

    flow = CustomerCaseFlow.__new__(CustomerCaseFlow)
    flow.case = {}

    flow._sequential_driver = True
    flow._record_observed_backend()
    assert flow.case["observed_execution_backend"] == "sequential"

    flow._sequential_driver = False
    flow._record_observed_backend()
    assert flow.case["observed_execution_backend"] == "crewai_flow"


def test_the_sequential_path_reports_the_sequential_driver():
    """End to end, so the field above is shown to be reached by a real run."""
    case = _run(RuntimeAuthorityConfig("deterministic_demo", "sequential"))

    assert case["configured_execution_backend"] == "sequential"
    assert case["observed_execution_backend"] == "sequential"
    assert case["configured_policy_backend"] == "deterministic_demo"
    # The high-risk effect is still prevented on the permissive backend. That
    # is the point of recording the mode rather than hiding it: the fallback
    # is a cooperative control, and it refuses this action.
    assert case["status"] == "prevented"
    assert case["action_status"] == "prevented"


def test_the_validation_record_does_not_claim_a_posture_the_container_lacks():
    """The document is checked against the measured matrix, not against intent.

    Kept as a test rather than a review habit because the false sentence
    survived every review that read it.
    """
    text = (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8")

    assert "deterministic_demo" in text, (
        "the validation record does not name the backend the shipped container "
        "actually runs"
    )
    forbidden = "Docker path request strict Nornyx/CrewAI execution"
    assert forbidden not in text, (
        "the validation record claims the Docker path requests strict "
        "Nornyx/CrewAI execution; demo_app.main runs deterministic_demo and "
        "sequential"
    )
