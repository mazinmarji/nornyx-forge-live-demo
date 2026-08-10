from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .claude_worker import ClaudeCodeWorker
from .contract_generator import generate_brd_contract
from .evidence import EvidenceLedger
from .gates import default_gates
from .governed_subject import RuntimeAuthorityConfig
from .models import GateResult
from .repo_qualifier import qualify_local, qualify_remote
from .repo_scout import scout
from .requirements import parse_brd, profile_from_brd, write_requirements_artifacts
from .util import write_json

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("CREWAI_TESTING", "true")

try:
    from crewai.flow.flow import Flow, listen, start

    CREWAI_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    CREWAI_AVAILABLE = False
    Flow = object  # type: ignore[assignment]

    def start(*_args: Any, **_kwargs: Any):
        return lambda fn: fn

    def listen(*_args: Any, **_kwargs: Any):
        return lambda fn: fn


class DevelopmentFlow(Flow):  # type: ignore[misc]
    """CrewAI Flow coordinating bounded Claude Code workers and hard gates."""

    def __init__(
        self,
        root: Path,
        *,
        worker_mode: str = "deterministic",
        config: RuntimeAuthorityConfig | None = None,
        repo_mode: str = "certified",
        target_repo: str | None = None,
    ) -> None:
        try:
            super().__init__()
        except Exception:
            pass
        self.config = config if config is not None else RuntimeAuthorityConfig()
        if worker_mode not in {"deterministic", "claude-code", "in-session"}:
            raise ValueError(f"unsupported worker mode: {worker_mode}")
        if repo_mode not in {"certified", "target", "scout", "greenfield"}:
            raise ValueError(f"unsupported repository mode: {repo_mode}")
        self.root = root
        self.worker_mode = worker_mode
        self.repo_mode = repo_mode
        self.target_repo = target_repo
        self.mission = "FORGE-BUILD-001"
        self.ledger = EvidenceLedger(root / ".nornyx/runs/build-events.jsonl")
        self.worker = ClaudeCodeWorker()
        self.data: dict[str, Any] = {}
        self.started_at = time.monotonic()
        self.repair_attempts = 0
        self.pre_gate_failures: list[GateResult] = []
        self.execution_backend = "sequential"

    @start()
    def requirements(self) -> dict[str, Any]:
        model = parse_brd(self.root / "BRD.md")
        write_requirements_artifacts(self.root, model)
        generated_contract = generate_brd_contract(self.root, model)
        self.data["requirements"] = [item.id for item in model.requirements]
        self.data["generated_brd_contract"] = str(generated_contract.relative_to(self.root))
        self.data["requirements_model"] = model.to_dict()
        self.data["requirement_profile"] = profile_from_brd(model).__dict__
        write_json(
            self.root / ".nornyx/goals.json",
            {
                "schema": "nornyx.forge.goals.v1",
                "goals": [
                    {
                        "id": "GOAL-001",
                        "title": "Qualify foundation",
                        "requirements": self.data["requirements"],
                    },
                    {
                        "id": "GOAL-002",
                        "title": "Conform architecture",
                        "requirements": self.data["requirements"],
                    },
                    {
                        "id": "GOAL-003",
                        "title": "Implement and verify application",
                        "requirements": self.data["requirements"],
                    },
                    {
                        "id": "GOAL-004",
                        "title": "Run governed agentic network",
                        "requirements": ["BRD-F-002", "BRD-F-004", "BRD-F-005"],
                    },
                ],
            },
        )
        self.ledger.append(
            "requirements_normalized",
            mission_id=self.mission,
            actor="requirements-analyst",
            count=len(model.requirements),
            source_digest=model.source_digest,
            generated_contract=str(generated_contract.relative_to(self.root)),
        )
        if not model.requirements:
            self.pre_gate_failures.append(
                GateResult("requirements", False, "No traceable BRD requirements were found.")
            )
        return self.data

    @listen(requirements)
    def foundation(self, _previous: Any = None) -> dict[str, Any]:
        profile = profile_from_brd(parse_brd(self.root / "BRD.md"))
        if self.repo_mode == "target":
            if not self.target_repo:
                report: dict[str, Any] = {
                    "verdict": "INSUFFICIENT_EVIDENCE",
                    "hard_stops": ["Target mode requires --target-repo."],
                }
            else:
                report = qualify_remote(self.target_repo, profile).to_dict()
        elif self.repo_mode == "scout":
            candidates = scout(profile=profile, limit=5)
            report = {
                "verdict": "GO" if candidates else "INSUFFICIENT_EVIDENCE",
                "candidates": candidates,
                "selected": candidates[0] if candidates else None,
                "overall_score": candidates[0]["overall_score"] if candidates else 0,
            }
        elif self.repo_mode == "greenfield":
            report = {
                "repository": "greenfield",
                "revision": None,
                "verdict": "CONDITIONAL_GO",
                "overall_score": 65,
                "remediations": ["Implement every BRD capability from first principles."],
                "metadata": {"mode": "greenfield"},
            }
        else:
            report = qualify_local(self.root, profile).to_dict()
            report.setdefault("metadata", {})["mode"] = "certified"
        self.data["foundation"] = report
        write_json(self.root / ".nornyx/foundation-decision.json", report)
        verdict = str(report.get("verdict", "INSUFFICIENT_EVIDENCE"))
        self.ledger.append(
            "foundation_qualified",
            mission_id=self.mission,
            actor="repo-scout",
            verdict=verdict,
            score=report.get("overall_score"),
        )
        if verdict not in {"GO", "CONDITIONAL_GO"}:
            self.pre_gate_failures.append(
                GateResult("foundation", False, f"Foundation verdict is {verdict}.")
            )
        return self.data

    @listen(foundation)
    def architecture(self, _previous: Any = None) -> dict[str, Any]:
        if self.worker_mode == "claude-code":
            result = self.worker.run(
                role="solution-architect",
                goal=(
                    "Review BRD.md, docs/ARCHITECTURE.md, and the Nornyx contracts. "
                    "Improve architecture declarations and tests only where required."
                ),
                workspace=self.root,
                allowed_tools=("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
                max_turns=30,
                timeout_seconds=900,
            )
            self.data["architecture_worker"] = result.__dict__
            if not result.success:
                self.pre_gate_failures.append(
                    GateResult("solution-architect", False, result.output, result.command, result.returncode)
                )
        self.ledger.append(
            "architecture_prepared",
            mission_id=self.mission,
            actor="solution-architect",
            worker_mode=self.worker_mode,
        )
        return self.data

    @listen(architecture)
    def implementation(self, _previous: Any = None) -> dict[str, Any]:
        if self.worker_mode == "claude-code":
            result = self.worker.run(
                role="application-builder",
                goal=(
                    "Implement every missing BRD acceptance criterion. Keep external side effects "
                    "behind the Nornyx action boundary, preserve architecture direction, and add tests."
                ),
                workspace=self.root,
                allowed_tools=("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
                max_turns=45,
                timeout_seconds=1200,
            )
            self.data["builder_worker"] = result.__dict__
            if not result.success:
                self.pre_gate_failures.append(
                    GateResult("application-builder", False, result.output, result.command, result.returncode)
                )
        self.ledger.append(
            "implementation_completed",
            mission_id=self.mission,
            actor="application-builder",
            worker_mode=self.worker_mode,
        )
        return self.data

    @listen(implementation)
    def acceptance(self, _previous: Any = None) -> dict[str, Any]:
        max_repairs = int(os.getenv("FORGE_MAX_REPAIR_ATTEMPTS", "3"))
        in_session_reviews: list[dict[str, Any]] = []
        if self.worker_mode == "in-session":
            review_path = self.root / ".nornyx/in-session/reviews.json"
            try:
                payload = json.loads(review_path.read_text(encoding="utf-8"))
                in_session_reviews = payload.get("reviews", [])
                required_roles = {
                    "test-inspector",
                    "architecture-inspector",
                    "security-inspector",
                }
                observed_roles = {
                    str(item.get("role"))
                    for item in in_session_reviews
                    if isinstance(item, dict)
                }
                # `builder_self_approval is False` used to be a term in this
                # expression. It was the builder certifying their own
                # independence, in a gitignored file the builder writes — the
                # same defect removed from the evidence tool, still gating
                # acceptance here. A file cannot witness the conditions under
                # which it was produced, so nothing it says about its own
                # provenance is consulted.
                #
                # What remains is a completeness and outcome check over records
                # this session produced. That is a useful local gate and it is
                # not an independent review: independence requires an
                # authenticated attestation from a reviewer who is not the
                # builder, which lives in `nornyx_forge.reviewer_trust` and
                # cannot be satisfied by anything written here.
                review_passed = (
                    payload.get("schema") == "nornyx.forge.in_session_reviews.v1"
                    and payload.get("human_review") == "not_performed"
                    and required_roles.issubset(observed_roles)
                    and all(
                        isinstance(item, dict) and item.get("status") == "pass"
                        for item in in_session_reviews
                        if item.get("role") in required_roles
                    )
                )
                detail = (
                    f"Validated {len(in_session_reviews)} self-reported in-session "
                    "review records. Establishes completeness, not independence."
                    if review_passed
                    else "The in-session review artifact is incomplete or contains a failed review."
                )
            except (OSError, json.JSONDecodeError, TypeError, AttributeError) as exc:
                review_passed = False
                detail = f"Cannot load in-session review evidence: {type(exc).__name__}: {exc}"
            self.pre_gate_failures.append(
                GateResult("in-session AI review records complete", review_passed, detail)
            )
        gates = [*self.pre_gate_failures, *default_gates(self.root)]
        while not all(gate.passed for gate in gates) and self.worker_mode == "claude-code":
            if self.repair_attempts >= max_repairs:
                break
            self.repair_attempts += 1
            failures = "\n\n".join(
                f"{gate.name}: {gate.detail[-2500:]}" for gate in gates if not gate.passed
            )
            self.ledger.append(
                "repair_requested",
                mission_id=self.mission,
                actor="forge-coordinator",
                attempt=self.repair_attempts,
                failures=failures,
            )
            repair = self.worker.run(
                role="application-builder",
                goal=(
                    f"Repair only these failing gates for attempt {self.repair_attempts}. "
                    "Do not weaken governance, tests, architecture, or security checks.\n\n"
                    + failures
                ),
                workspace=self.root,
                allowed_tools=("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
                max_turns=35,
                timeout_seconds=900,
            )
            self.data.setdefault("repair_workers", []).append(repair.__dict__)
            if not repair.success:
                break
            self.pre_gate_failures = []
            gates = default_gates(self.root)

        self.data["gates"] = [gate.__dict__ for gate in gates]
        passed = all(gate.passed for gate in gates)
        reviews: list[dict[str, Any]] = list(in_session_reviews)
        if passed and self.worker_mode == "claude-code":
            review_specs = (
                (
                    "test-inspector",
                    "Independently verify BRD acceptance coverage, regression behavior, and failure handling. Do not edit files.",
                ),
                (
                    "architecture-inspector",
                    "Compare implementation dependencies and side-effect boundaries with docs/ARCHITECTURE.md and the Nornyx contracts. Do not edit files.",
                ),
                (
                    "security-inspector",
                    "Review secret handling, subprocess use, untrusted input, permissions, and autonomous-demo limitations. Do not edit files.",
                ),
            )
            for role, goal in review_specs:
                review = self.worker.run(
                    role=role,
                    goal=goal,
                    workspace=self.root,
                    allowed_tools=("Read", "Glob", "Grep", "Bash"),
                    max_turns=22,
                    timeout_seconds=600,
                )
                reviews.append(review.__dict__)
                passed = passed and review.success
        self.data["review_workers"] = reviews
        self.data["repair_attempts"] = self.repair_attempts
        self.data["accepted"] = passed
        self.data["assurance"] = {
            "mode": "autonomous_demonstration",
            "human_review": "not_performed",
            "production_approval": "not_granted",
            # A count of worker processes that ran, named as such. It was
            # `independent_ai_review: bool(reviews)` — a non-empty list of
            # subprocesses standing in for a verdict, so launching a reviewer
            # was indistinguishable from passing a review, and neither was
            # independent of the builder that launched it.
            "review_workers_executed": len(reviews),
            "independent_ai_review": "not_established",
        }
        self.ledger.append(
            "build_acceptance",
            mission_id=self.mission,
            actor="forge-coordinator",
            decision="ALLOW" if passed else "DENY",
            reason=(
                "All automated gates passed."
                if passed
                else "One or more automated gates or worker stages failed."
            ),
            repair_attempts=self.repair_attempts,
        )
        report = self.ledger.validate(
            report_path=self.root / ".nornyx/runs/build-evidence-report.json"
        )
        self.data["evidence"] = report
        foundation = self.data.get("foundation", {})
        self.data["value"] = {
            "schema": "nornyx.forge.value_report.v1",
            "elapsed_seconds": round(time.monotonic() - self.started_at, 3),
            "requirements_count": len(self.data.get("requirements", [])),
            "repair_attempts": self.repair_attempts,
            "gates_total": len(gates),
            "gates_passed": sum(1 for gate in gates if gate.passed),
            "worker_mode": self.worker_mode,
            "foundation_mode": self.repo_mode,
            "foundation_score": foundation.get("overall_score"),
            "foundation_verdict": foundation.get("verdict"),
            "measured": {
                "elapsed_seconds": True,
                "repair_attempts": True,
                "gate_results": True,
            },
            "not_claimed": [
                "universal productivity improvement",
                "guaranteed cost savings",
                "human production approval",
            ],
        }
        write_json(self.root / ".nornyx/runs/value-report.json", self.data["value"])
        self.data["execution_backend"] = self.execution_backend
        write_json(self.root / ".nornyx/runs/build-summary.json", self.data)
        return self.data

    def run(self) -> dict[str, Any]:
        """Run through CrewAI Flow when installed; otherwise use the same deterministic chain."""
        # Mode comes from the authority configuration, never the environment.
        # This flow generates contracts and evidence that later enter
        # governed_subject_digest, so an ambient mode selection here would alter
        # authority indirectly — the build path is not exempt from the rule
        # simply because it is not the consequential runtime.
        use_kickoff = self.config.execution_backend == "crewai"
        if use_kickoff:
            self.execution_backend = "crewai_flow"
            try:
                result = self.kickoff()  # type: ignore[attr-defined]
                if isinstance(result, dict):
                    result["execution_backend"] = self.execution_backend
                    return result
                self.data["execution_backend"] = self.execution_backend
                return self.data
            except Exception as exc:
                if self.config.policy_backend == "nornyx":
                    raise
                # A fresh flow prevents a partially-run kickoff from being accepted twice.
                fresh = DevelopmentFlow(
                    self.root,
                    worker_mode=self.worker_mode,
                    repo_mode=self.repo_mode,
                    target_repo=self.target_repo,
                )
                fresh.execution_backend = "sequential_fallback"
                fresh.data["limitations"] = [
                    f"CrewAI kickoff failed ({type(exc).__name__}); deterministic fallback used."
                ]
                return fresh.run_sequential()
        self.execution_backend = "sequential"
        return self.run_sequential()

    def run_sequential(self) -> dict[str, Any]:
        self.requirements()
        self.foundation()
        self.architecture()
        self.implementation()
        return self.acceptance()
