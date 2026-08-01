from __future__ import annotations

import re
from pathlib import Path

import yaml

from .requirements import RequirementsModel

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


def _safe_id(value: str) -> str:
    cleaned = _SAFE_ID_RE.sub("-", value).strip("-")
    return cleaned or "BRD-UNSPECIFIED"


def generate_brd_contract(root: Path, model: RequirementsModel) -> Path:
    """Generate a deterministic Nornyx repo-harness contract from a BRD model."""

    purpose = next(
        (item.statement for item in model.requirements if item.id == "BRD-001"),
        "Deliver the BRD through governed AI-assisted software engineering.",
    )
    goals = []
    for item in model.requirements:
        goals.append(
            {
                "id": _safe_id(item.id),
                "title": item.title,
                "phase": "brd-delivery",
                "goal": item.statement,
                "scope": ["BRD.md", "src/", "tests/", "docs/"],
                "non_goals": [
                    "production_deployment",
                    "automatic_human_approval",
                ],
                "validation": [
                    "python scripts/validate_repository.py",
                    "python -m pytest -q",
                ],
                "evidence": ".nornyx/runs/",
                "approval": (
                    "autonomous demonstration acceptance only; "
                    "human production approval is not granted"
                ),
                "stop_rules": [
                    "stop_on_secret_exposure",
                    "stop_on_unresolved_security_or_license_risk",
                    "stop_after_three_failed_repairs",
                ],
            }
        )

    contract = {
        "nornyx": "0.2",
        "project": {
            "name": "GeneratedBRDDeliveryContract",
            "profile": "agentic_repo_harness",
            "purpose": purpose,
        },
        "intents": [
            {
                "name": "DeliverBRD",
                "goal": (
                    "Convert the exact BRD revision into a tested, architecture-conformant, "
                    "evidence-backed application."
                ),
            }
        ],
        "contexts": [
            {
                "name": "GeneratedRepoContext",
                "include": [
                    "BRD.md",
                    "README.md",
                    "docs/**/*.md",
                    "src/**/*",
                    "tests/**/*",
                    ".nornyx/contracts/*.nyx",
                ],
                "exclude": [
                    ".env",
                    "secrets/**",
                    ".venv/**",
                    ".nornyx/runs/**",
                ],
                "authority": [
                    "BRD.md",
                    ".nornyx/contracts/*.nyx",
                    "tests/**/*",
                ],
                "budget": {
                    "max_tokens": 100000,
                    "reserve_output_tokens": 8000,
                },
            }
        ],
        "agents": [
            {
                "name": "RequirementsAnalyst",
                "role": "Normalize BRD requirements and acceptance criteria.",
                "policy": "GeneratedSafeDelivery",
            },
            {
                "name": "SolutionArchitect",
                "role": "Design bounded components and architecture constraints.",
                "policy": "GeneratedSafeDelivery",
            },
            {
                "name": "ApplicationBuilder",
                "role": "Implement bounded goals with tests.",
                "policy": "GeneratedSafeDelivery",
            },
            {
                "name": "IndependentReviewer",
                "role": "Inspect tests, architecture, security, and evidence without editing.",
                "policy": "GeneratedIndependentReview",
            },
        ],
        "skills": [
            {
                "name": "RequirementsDesign",
                "purpose": "Convert BRD statements into traceable goals.",
                "input": ["BRD"],
                "output": ["RequirementsModel"],
            },
            {
                "name": "PatchBuild",
                "purpose": "Implement one bounded goal with tests.",
                "input": ["Goal", "Architecture"],
                "output": ["Patch"],
            },
            {
                "name": "IndependentInspection",
                "purpose": "Inspect implementation and evidence independently.",
                "input": ["Patch", "TestReport", "ArchitectureReport"],
                "output": ["ReviewReport"],
            },
        ],
        "policies": [
            {
                "name": "GeneratedSafeDelivery",
                "deny": [
                    "secrets_to_llm",
                    "production_write_without_approval",
                    "policy_weakening_for_green_build",
                    "destructive_command",
                ],
                "require": [
                    "tests_if_code_changed",
                    "architecture_evidence_if_boundary_changed",
                    "evidence_if_goal_completed",
                ],
            },
            {
                "name": "GeneratedIndependentReview",
                "deny": [
                    "reviewer_modifies_patch",
                    "autonomous_production_approval",
                ],
                "require": [
                    "risk_check",
                    "evidence_check",
                    "architecture_check",
                    "test_check",
                ],
            },
        ],
        "harnesses": [
            {
                "name": "GeneratedDevelopmentHarness",
                "context": "GeneratedRepoContext",
                "flow": [
                    {"agent": "RequirementsAnalyst", "action": "normalize"},
                    {"agent": "SolutionArchitect", "action": "design"},
                    {"agent": "ApplicationBuilder", "action": "implement"},
                    {"tool": "tests", "action": "run"},
                    {"tool": "architecture", "action": "check"},
                    {"agent": "IndependentReviewer", "action": "review"},
                    {"tool": "evidence", "action": "pack"},
                ],
                "gates": [
                    "tests.pass",
                    "architecture.pass",
                    "security.pass",
                    "evidence.exists",
                ],
            }
        ],
        "evidence": {
            "required": [
                "requirements/requirements.json",
                "requirements/traceability.md",
                "runs/build-summary.json",
                "runs/build-evidence-report.json",
            ]
        },
        "goals": goals,
        "budgets": [
            {
                "name": "GeneratedDeliveryBudget",
                "max_tokens": 100000,
                "max_tool_calls": 80,
                "max_runtime_minutes": 90,
            }
        ],
    }
    target = root / ".nornyx/generated/brd_contract.nyx"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(contract, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return target
