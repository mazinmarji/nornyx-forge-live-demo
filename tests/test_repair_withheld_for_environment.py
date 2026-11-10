"""Repairs are not requested for a verifier refusal no project change can fix."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import nornyx_forge.development_flow as flow_module
from nornyx_forge.development_flow import DevelopmentFlow, unrepairable_environment_refusal
from nornyx_forge.gates import GREENFIELD_IDENTITY_GATE, GREENFIELD_RESOURCE_LIMITS_MISMATCH
from nornyx_forge.models import GateResult, WorkerResult


def _identity_failure(detail: str) -> GateResult:
    return GateResult(GREENFIELD_IDENTITY_GATE, False, detail, (), 2)


def test_the_resource_limit_refusal_is_named_unrepairable():
    assert unrepairable_environment_refusal(
        [_identity_failure(GREENFIELD_RESOURCE_LIMITS_MISMATCH)]
    )


def test_other_identity_failures_still_get_repairs():
    assert unrepairable_environment_refusal(
        [_identity_failure("trusted verifier wrote unexpected stderr")]
    ) is None
    assert unrepairable_environment_refusal(
        [GateResult("greenfield:test-execution", False, GREENFIELD_RESOURCE_LIMITS_MISMATCH)]
    ) is None


def test_a_passing_gate_is_never_a_refusal():
    assert unrepairable_environment_refusal(
        [GateResult(GREENFIELD_IDENTITY_GATE, True, GREENFIELD_RESOURCE_LIMITS_MISMATCH)]
    ) is None


class _CountingWorker:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **request: Any) -> WorkerResult:
        self.calls.append(dict(request))
        return WorkerResult(role=str(request["role"]), goal=str(request["goal"]),
                            success=True, output="ok", command=("counting-worker",))


def test_the_flow_withholds_repairs_and_still_rejects(tmp_path: Path, monkeypatch):
    (tmp_path / "BRD.md").write_text(
        "# BRD\n\n## BRD-001 Purpose\n\nAdd numbers.\n\n"
        "## BRD-002 Functional requirements\n\n### BRD-F-001 Add\n\nAdd two numbers.\n",
        encoding="utf-8",
    )
    failure = _identity_failure(GREENFIELD_RESOURCE_LIMITS_MISMATCH)
    monkeypatch.setattr(
        flow_module, "trusted_greenfield_gates", lambda _root, **_kw: ([failure], {})
    )
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", repo_mode="greenfield")
    worker = _CountingWorker()
    flow.worker = worker
    result = flow.run_sequential()
    roles = [call["role"] for call in worker.calls]
    assert roles == ["solution-architect", "application-builder"], roles
    assert result["repair_attempts"] == 0
    assert result["accepted"] is False
    assert "no repair requested" in result["repair_withheld"]
    failed = [g for g in result["gates"] if not g["passed"]]
    assert any(g["name"] == GREENFIELD_IDENTITY_GATE for g in failed)
