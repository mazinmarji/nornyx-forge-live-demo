from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .claude_worker import ClaudeCodeWorker
from .contract_generator import generate_brd_contract
from .evidence import EvidenceLedger
from .gates import default_gates, trusted_greenfield_gates
from .governed_subject import RuntimeAuthorityConfig
from .models import GateResult
from .providers import ProviderRoutedWorker, get_provider
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


#: How much of each failing gate's detail the repair goal quotes: the TAIL,
#: where a test runner or a gate puts its verdict. The same number bounds the
#: ESCAPED form of that tail inside the composed goal (`compose_repair_goal`):
#: escaping may not buy a gate more of the goal than its raw tail would have.
REPAIR_DETAIL_TAIL_CHARACTERS = 2500

#: The ceiling on the goal `compose_repair_goal` hands the repair worker. The
#: Provider Contract refuses a task goal above 8000 characters
#: (`ProviderTask.validate`), and refuses it by RAISING `ProviderError` out of
#: the routed worker's `run` -- which `acceptance()` does not catch, so an
#: over-long composed goal ended the flow with an exception rather than a
#: repair attempt. Four ordinary failing gates quoting 2500 characters each
#: could already do that before any escaping existed; the `\xNN` escaping
#: (four characters per control character) made ONE control-heavy gate
#: enough. Set under the contract's number with room to spare, so a longer
#: opening sentence cannot quietly close the gap. The contract exposes no
#: constant to derive this from, so the relation is pinned by test
#: (tests/test_provider_execution.py) against the contract's own validation.
COMPOSED_GOAL_MAX_CHARACTERS = 7000

#: The characters provider-authored text may not carry into an argument Forge
#: composes: NUL and the other C0 controls, EXCEPT tab, newline and carriage
#: return, which are ordinary text layout. Each is replaced by its Python
#: escape (`\x00`), so what was there is still legible rather than silently
#: gone. Built as a `str.translate` table: one pass, no pattern.
_CONTROL_CHARACTER_ESCAPES = {
    code: f"\\x{code:02x}" for code in range(0x20) if chr(code) not in "\t\n\r"
}


def sanitised_for_composition(text: str) -> str:
    """Provider-authored text with the characters the operating system
    refuses in a process argument escaped, so it can be COMPOSED into a new
    invocation. Safe in that one respect only: the escaping lengthens the
    text (four characters per control character), and length is the other
    way a composed goal fails, bounded in `compose_repair_goal`, not here.

    A `WorkerResult.output` is the provider's bytes, decoded strictly and
    otherwise untouched -- and a literal NUL is valid UTF-8, so a provider can
    put one there. The adapters are right to carry it: the result is what the
    provider wrote. What must not happen is that text travelling, unaltered,
    into the NEXT invocation's arguments: the operating system refuses a NUL
    in any process argument (the adapters' launcher raises `ValueError`
    before a process exists), so a provider that emitted one would have made
    the repair step unrunnable. Measured directly on both adapters before this
    existed: `a\\x00b` on a failing provider's stdout reached the repair
    `goal` and raised out of the adapter's `run()`. This module starts no
    process itself; the adapters do, and `docs/ARCHITECTURE.md` lists them.

    This is the ONE place that transformation belongs. The flow is the party
    composing provider output into something new, so it is the flow's own
    text it is sanitising -- not the provider's record, which stays exactly
    as emitted in the ledger and the gate result. Tab, newline and carriage
    return are left alone: they are layout, not control, in a goal.
    """
    return text.translate(_CONTROL_CHARACTER_ESCAPES)


def _within(text: str, limit: int, *, keep: str) -> str:
    """`text` unchanged when it fits `limit`; otherwise exactly `limit`
    characters -- the kept end of the text and a marker saying how many
    characters were left out. `keep="tail"` keeps the END (a gate's verdict
    sits there) and puts the marker first; `keep="head"` keeps the START and
    puts the marker last, on its own line. The marker's own length counts
    against `limit`, and the number in it is settled against that length, so
    the count it names is the count actually omitted.

    PRECONDITION for "exactly `limit`": `limit` is at least the marker plus
    the glue -- 29 fixed characters plus the omitted count's digits, plus
    one newline for `keep="head"` and nothing for `keep="tail"`. Below that
    the kept length bottoms out at zero and the result is the marker (and
    glue) alone, LONGER than `limit` (measured: `limit=5` over 100
    characters returns 33). Both callers pass 2500 and 7000.
    """
    if len(text) <= limit:
        return text
    glue = "" if keep == "tail" else "\n"
    omitted = len(text) - limit
    marker = ""
    for _ in range(4):  # the count's own digits lengthen the marker; settle it
        marker = f"[... {omitted} characters omitted ...]"
        settled = len(text) - (limit - len(marker) - len(glue))
        if settled == omitted:
            break
        omitted = settled
    kept = max(limit - len(marker) - len(glue), 0)
    if keep == "tail":
        return marker + text[len(text) - kept:]
    return text[:kept] + glue + marker


def _failing_gate_quotes(gates: list[GateResult]) -> list[tuple[str, str]]:
    """Each failing gate's name and the tail of its detail, exactly as the
    gate said it -- the ONE source both the ledger's record and the composed
    goal quote from, so the two can never quote different text."""
    return [
        (gate.name, gate.detail[-REPAIR_DETAIL_TAIL_CHARACTERS:])
        for gate in gates
        if not gate.passed
    ]


def failing_gate_details(gates: list[GateResult]) -> str:
    """What the failing gates said, as the ledger records it: each failing
    gate's name and the last `REPAIR_DETAIL_TAIL_CHARACTERS` (2500)
    characters of its detail. That per-gate tail is the only cut: nothing
    is escaped, and the total is not bounded -- a record, not an argument,
    so it is neither sanitised nor held to the composed goal's ceiling."""
    return "\n\n".join(f"{name}: {tail}" for name, tail in _failing_gate_quotes(gates))


def compose_repair_goal(attempt: int, gates: list[GateResult]) -> str:
    """The goal handed to the repair worker, composed from the failing gates.

    Every character a provider could have authored passes through
    `sanitised_for_composition` here, at the composition, and nowhere else --
    so the sanitising cannot be skipped by a caller that builds the goal by
    hand, and cannot leak into the record of what the gates said, which
    `failing_gate_details` renders from the same quotes, untouched.

    AND THE RESULT IS BOUNDED, twice. Each gate's ESCAPED tail is held to
    `REPAIR_DETAIL_TAIL_CHARACTERS`, keeping its end (where the verdict is)
    behind a marker naming what was left out -- so one gate whose tail is all
    control characters (2500 of them escape to 10000) can neither crowd the
    other gates out nor, alone, push the goal past the contract. Then the
    whole goal is held to `COMPOSED_GOAL_MAX_CHARACTERS`, keeping its start
    (the gates in the order they failed) behind the same kind of marker. The
    markers appear in the composed goal only: the ledger's record is neither
    escaped nor cut by either of these two bounds.
    """
    quotes = [
        (name, _within(sanitised_for_composition(tail),
                       REPAIR_DETAIL_TAIL_CHARACTERS, keep="tail"))
        for name, tail in _failing_gate_quotes(gates)
    ]
    goal = (
        f"Repair only these failing gates for attempt {attempt}. "
        "Do not weaken governance, tests, architecture, or security checks.\n\n"
        + "\n\n".join(f"{name}: {tail}" for name, tail in quotes)
    )
    return _within(goal, COMPOSED_GOAL_MAX_CHARACTERS, keep="head")


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
        provider: str | None = None,
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
        # Provider routing is opt-in and EXPLICIT. `None` is the path every
        # existing caller takes, byte-identical to before this parameter
        # existed. A named provider routes the same worker calls through the
        # Provider Contract's identity-validated adapter instead — and an
        # undeclared name is refused HERE, before anything runs. A selected
        # provider whose CLI is absent reports `unavailable` at each step;
        # nothing anywhere falls back to the direct Claude worker, because a
        # run that silently swaps providers under an unchanged label is the
        # downgrade this repository's history exists to forbid.
        if provider is not None and worker_mode != "claude-code":
            raise ValueError(
                "a provider selection routes external CLI workers, so it "
                "requires worker_mode='claude-code'; "
                f"got worker_mode={worker_mode!r}"
            )
        self.root = root
        self.worker_mode = worker_mode
        self.repo_mode = repo_mode
        self.target_repo = target_repo
        self.provider = provider
        self.mission = "FORGE-BUILD-001"
        self.ledger = EvidenceLedger(root / ".nornyx/runs/build-events.jsonl")
        if provider is None:
            self.worker: Any = ClaudeCodeWorker()
        else:
            self.worker = ProviderRoutedWorker(get_provider(provider))
        self.data: dict[str, Any] = {}
        if provider is not None:
            self.data["engineering_provider"] = {"selected": provider}
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
        gates = [*self.pre_gate_failures, *self._acceptance_gates()]
        while not all(gate.passed for gate in gates) and self.worker_mode == "claude-code":
            if self.repair_attempts >= max_repairs:
                break
            self.repair_attempts += 1
            # The ledger records what the gates said, verbatim; the GOAL is
            # composed from the same failing gates through
            # `compose_repair_goal`, which is where provider-authored control
            # characters are escaped and where the result is bounded. Two
            # values on purpose: the record is evidence and stays exact, the
            # goal is an argument to a new process and must be one the OS
            # will accept and the Provider Contract will not refuse.
            failures = failing_gate_details(gates)
            self.ledger.append(
                "repair_requested",
                mission_id=self.mission,
                actor="forge-coordinator",
                attempt=self.repair_attempts,
                failures=failures,
            )
            repair = self.worker.run(
                role="application-builder",
                goal=compose_repair_goal(self.repair_attempts, gates),
                workspace=self.root,
                allowed_tools=("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
                max_turns=35,
                timeout_seconds=900,
            )
            self.data.setdefault("repair_workers", []).append(repair.__dict__)
            if not repair.success:
                break
            self.pre_gate_failures = []
            gates = self._acceptance_gates()

        passed = all(gate.passed for gate in gates)
        reviews: list[dict[str, Any]] = list(in_session_reviews)
        review_gates: list[GateResult] = []
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
                    allowed_tools=("Read", "Glob", "Grep"),
                    max_turns=22,
                    timeout_seconds=600,
                )
                reviews.append(review.__dict__)
                review_gates.append(
                    GateResult(
                        f"review-worker:{role}",
                        review.success,
                        review.output,
                        review.command,
                        review.returncode,
                    )
                )
            # Reviewers run after the initial gates, so their success can never
            # authorize stale bytes. The external adapter is read-only by tool
            # policy, and this final verification still catches a faulty or
            # adversarial adapter that ignores that policy and mutates files.
            if self.repo_mode == "greenfield":
                final_subject_gates = self._acceptance_gates()
                gates = [
                    gate for gate in gates if not gate.name.startswith("greenfield:")
                ] + final_subject_gates
            gates.extend(review_gates)
            passed = all(gate.passed for gate in gates)

        pre_evidence = self.ledger.validate(
            report_path=self.root / ".nornyx/runs/build-evidence-report.json"
        )
        gates.append(
            GateResult(
                "build-evidence-ledger-valid-before-verdict",
                pre_evidence.get("status") == "pass",
                (
                    "build evidence is readable, contiguous, linked, and complete"
                    if pre_evidence.get("status") == "pass"
                    else "; ".join(str(item) for item in pre_evidence.get("diagnostics", []))
                ),
            )
        )
        passed = all(gate.passed for gate in gates)
        self.data["gates"] = [gate.__dict__ for gate in gates]
        self.data["review_workers"] = reviews
        self.data["repair_attempts"] = self.repair_attempts
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
            verdict_source="all_recorded_gate_results",
            acceptance_provenance=self.data.get("acceptance_provenance"),
        )
        report = self.ledger.validate(
            report_path=self.root / ".nornyx/runs/build-evidence-report.json"
        )
        if report.get("status") != "pass":
            candidate_was_allowed = passed
            passed = False
            gates.append(
                GateResult(
                    "build-evidence-ledger-valid-after-verdict",
                    False,
                    "; ".join(str(item) for item in report.get("diagnostics", [])),
                )
            )
            if candidate_was_allowed:
                self.ledger.append(
                    "build_acceptance_correction",
                    mission_id=self.mission,
                    actor="forge-coordinator",
                    decision="DENY",
                    reason="Post-verdict evidence validation failed; the prior candidate is not accepted.",
                    verdict_source="build_evidence_ledger_validation",
                )
                report = self.ledger.validate(
                    report_path=self.root / ".nornyx/runs/build-evidence-report.json"
                )
        self.data["gates"] = [gate.__dict__ for gate in gates]
        self.data["accepted"] = passed
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
            "acceptance_profile": (
                self.data.get("acceptance_provenance", {})
                .get("gate_profile", {})
                .get("id")
            ),
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

    def _acceptance_gates(self) -> list[GateResult]:
        """Select the profile in trusted flow code, never from project data."""
        if self.repo_mode == "greenfield":
            gates, provenance = trusted_greenfield_gates(self.root)
            verifier = provenance.get("verifier", {})
            invocation = provenance.get("invocation", {})
            stable_identity = {
                "schema": provenance.get("schema"),
                "trust": provenance.get("trust"),
                "gate_profile": provenance.get("gate_profile"),
                "verifier": {
                    key: verifier.get(key)
                    for key in (
                        "id",
                        "origin",
                        "digest",
                        "forge_version",
                        "forge_revision",
                    )
                },
                "invocation": {
                    key: invocation.get(key)
                    for key in (
                        "python",
                        "isolated_python",
                        "cwd",
                        "environment",
                        "verifier_execution",
                    )
                },
                "resource_limits": provenance.get("resource_limits"),
            }
            previous = self.data.get("acceptance_verifier_identity")
            if previous is not None and previous != stable_identity:
                return [
                    GateResult(
                        "greenfield:provenance-stability",
                        False,
                        "trusted verifier provenance changed during one acceptance run",
                        provenance=provenance,
                    )
                ]
            self.data["acceptance_verifier_identity"] = stable_identity
            self.data["acceptance_provenance"] = provenance
            return gates
        return default_gates(self.root)

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
