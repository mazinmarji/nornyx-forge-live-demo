"""An ambiguous orchestration failure must never replay a consequential stage.

`run_case` caught a `kickoff()` failure and called `run_sequential()` on the
*same* flow object, re-running every stage including `execution()`. A reviewer
drove a kickoff that died after the consequential stage and watched the action
happen twice from one call, with the case still reporting `completed`.

The approval ledger reduces the damage for an approved high-risk attempt — the
same request digest cannot be consumed twice — but it is not the fix, and for a
low-risk action it is not even engaged: nothing consumes an approval, so nothing
downstream stops the callable running again.

Two controls, because they fail differently:

* the backend is chosen once, and after `kickoff()` begins there is no automatic
  full-flow fallback — how far it got is unknowable;
* `execution()` is one-way per flow, so even a future refactor cannot enter the
  consequential stage twice.

The second is not a licence for the first. Resuming from an inspected timeline
would assume the timeline is a transactional checkpoint, and it is not: an
effect may be released immediately before the process fails to record that it
was.
"""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import demo_app.agentic as agentic
from demo_app.agentic import CustomerCaseFlow, run_case
from nornyx_forge.governed_subject import RuntimeAuthorityConfig

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _case(risk: str = "low") -> dict[str, Any]:
    return {
        "id": "C1",
        "customer": "Omar",
        "summary": "Refund request",
        "risk": risk,
        "requested_action": "send guidance",
    }


def _stages(case: dict[str, Any]) -> list[str]:
    return [entry["stage"] for entry in case.get("timeline", [])]


@pytest.fixture
def no_kickoff(monkeypatch: pytest.MonkeyPatch):
    """Force the sequential backend, chosen before anything runs."""
    monkeypatch.setenv("FORGE_USE_CREWAI_KICKOFF", "false")
    monkeypatch.setenv("FORGE_STRICT_CREWAI", "false")


# --------------------------------------------------------------------------
# After kickoff begins, there is no automatic replay
# --------------------------------------------------------------------------


@pytest.mark.parametrize("risk", ["low", "high"])
def test_a_kickoff_failure_does_not_replay_the_flow(
    risk: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The reviewer's proof, driven at the recovery boundary.

    Whether the failure landed before or after the consequential stage is
    exactly what cannot be known, so the run terminates either way.
    """
    monkeypatch.setenv("FORGE_USE_CREWAI_KICKOFF", "true")
    monkeypatch.setenv("FORGE_STRICT_CREWAI", "false")
    monkeypatch.setattr(agentic, "CREWAI_AVAILABLE", True)

    replays: list[int] = []
    monkeypatch.setattr(
        CustomerCaseFlow,
        "kickoff",
        lambda self: (_ for _ in ()).throw(RuntimeError("orchestration died")),
        raising=False,
    )
    monkeypatch.setattr(
        CustomerCaseFlow,
        "run_sequential",
        lambda self: replays.append(1) or self.case,
    )

    result = run_case(_case(risk), root=tmp_path, worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", "crewai"))

    assert replays == [], "the flow was replayed after kickoff began"
    assert result["orchestration_status"] == "failed"
    assert result["status"] == "failed"
    assert result["status"] != "completed"


def test_a_failed_run_does_not_claim_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Two truths kept apart: the effect may have happened; the run did not finish."""
    monkeypatch.setenv("FORGE_USE_CREWAI_KICKOFF", "true")
    monkeypatch.setattr(agentic, "CREWAI_AVAILABLE", True)
    monkeypatch.setattr(
        CustomerCaseFlow,
        "kickoff",
        lambda self: (_ for _ in ()).throw(RuntimeError("died")),
        raising=False,
    )

    result = run_case(_case(), root=tmp_path, worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", "crewai"))
    assert result["status"] == "failed"
    assert result["orchestration_status"] == "failed"
    # The action never got as far as being attempted, and says so rather than
    # being reported as prevented — which would imply a governance decision.
    assert result["action_status"] == "not_reached"
    assert "orchestration_error" in result
    assert any("terminated rather than replayed" in note for note in result["limitations"])


def test_governed_policy_still_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Under the governed policy a failure must surface, not be absorbed.

    This was test_strict_mode_still_raises, keyed on `FORGE_STRICT_CREWAI`.
    That variable is retired: a boolean in the environment could change which
    governance path ran while every governed byte — and therefore the whole
    authority identity — stayed identical. The behaviour is now selected by
    naming `policy_backend`, and is bound into the subject.
    """
    monkeypatch.setenv("FORGE_STRICT_CREWAI", "true")  # hostile; must not decide
    monkeypatch.setattr(agentic, "CREWAI_AVAILABLE", True)
    monkeypatch.setattr(
        CustomerCaseFlow,
        "kickoff",
        lambda self: (_ for _ in ()).throw(RuntimeError("died")),
        raising=False,
    )
    with pytest.raises(RuntimeError):
        run_case(
            _case(),
            root=tmp_path,
            worker_mode="deterministic",
            config=RuntimeAuthorityConfig("nornyx", "crewai"),
        )


def test_backend_fallback_before_execution_is_still_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Choosing sequential *before* anything runs is not a replay."""
    monkeypatch.setenv("FORGE_USE_CREWAI_KICKOFF", "false")
    result = run_case(_case(), root=tmp_path, worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", "crewai"))
    assert _stages(result).count("execution") == 1
    assert result["orchestration_status"] == "completed"


# --------------------------------------------------------------------------
# The consequential stage is one-way per flow
# --------------------------------------------------------------------------


def test_entering_the_execution_stage_twice_is_refused(tmp_path: Path, no_kickoff):
    """The second layer, and the only one that helps a low-risk action.

    Nothing consumes an approval on the low-risk path, so the ledger cannot be
    what stops a second callable invocation.
    """
    flow = CustomerCaseFlow(_case(), root=tmp_path, worker_mode="deterministic",
                             allow_policy_fallback=True)
    flow.intake()
    flow.knowledge()
    flow.resolution()
    flow.risk()

    flow.execution()
    first = _stages(flow.case).count("execution")
    assert first == 1
    assert flow.case["action_status"] == "executed"

    flow.execution()
    assert _stages(flow.case).count("execution") == first, "the stage ran twice"
    assert any("EXECUTION_STAGE_REPLAY" in note for note in flow.case["limitations"])


def test_a_refused_re_entry_does_not_reach_the_boundary(tmp_path: Path, no_kickoff):
    """No evaluation, no callable, no consumption on a second entry."""
    flow = CustomerCaseFlow(_case(), root=tmp_path, worker_mode="deterministic",
                             allow_policy_fallback=True)
    flow.intake()
    flow.knowledge()
    flow.resolution()
    flow.risk()
    flow.execution()

    evaluations: list[int] = []
    original = flow.boundary.evaluate_and_execute
    flow.boundary.evaluate_and_execute = (  # type: ignore[method-assign]
        lambda **kwargs: evaluations.append(1) or original(**kwargs)
    )

    flow.execution()
    assert evaluations == [], "a refused re-entry still consulted the boundary"


def test_the_guard_is_one_way(tmp_path: Path, no_kickoff):
    """Never reset, so no recovery path can re-arm it."""
    flow = CustomerCaseFlow(_case(), root=tmp_path, worker_mode="deterministic",
                             allow_policy_fallback=True)
    flow.intake()
    flow.knowledge()
    flow.resolution()
    flow.risk()
    flow.execution()
    assert flow._execution_entered is True

    flow.run_sequential()  # a full replay attempt on the same instance
    assert _stages(flow.case).count("execution") == 1


def test_a_second_flow_for_the_same_mission_is_a_new_attempt(tmp_path: Path, no_kickoff):
    """Retry is an explicit new attempt, never manufactured by recovery.

    The guard is per flow instance, so a deliberately constructed second run
    proceeds — and its attempt number is whatever the operator supplied, not
    something recovery code incremented.
    """
    case = _case()
    first = CustomerCaseFlow(case, root=tmp_path, worker_mode="deterministic",
                             allow_policy_fallback=True)
    first.run_sequential()
    assert first.attempt == 1

    # Deep copy: a shallow one shares the timeline list, so the second run would
    # append to the first's and look like a replay of it.
    retry = deepcopy(_case())
    retry["attempt"] = 2
    second = CustomerCaseFlow(retry, root=tmp_path, worker_mode="deterministic",
                              allow_policy_fallback=True)
    assert second.attempt == 2
    assert second._execution_entered is False
    second.run_sequential()
    assert _stages(second.case).count("execution") == 1


def test_recovery_never_increments_the_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A retry is an operator decision, not something the failure path invents."""
    monkeypatch.setenv("FORGE_USE_CREWAI_KICKOFF", "true")
    monkeypatch.setattr(agentic, "CREWAI_AVAILABLE", True)
    monkeypatch.setattr(
        CustomerCaseFlow,
        "kickoff",
        lambda self: (_ for _ in ()).throw(RuntimeError("died")),
        raising=False,
    )
    result = run_case(_case(), root=tmp_path, worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", "crewai"))
    assert result["attempt"] == 1


def test_the_recovery_path_does_not_inspect_the_timeline(tmp_path: Path):
    """Resuming from a timeline assumes it is a transactional checkpoint.

    It is not: an effect may be released immediately before the process fails to
    append its stage record, so a missing entry is not evidence the stage did
    not run. Asserted against the source, because the tempting fix is to write
    exactly that.
    """
    source = (
        Path(__file__).resolve().parents[1] / "src/demo_app/agentic.py"
    ).read_text(encoding="utf-8")
    recovery = source.split("except Exception as exc:", 1)[1]
    assert "timeline" not in recovery.split("return flow.case", 1)[0]
    assert "run_sequential" not in recovery.split("return flow.case", 1)[0]
