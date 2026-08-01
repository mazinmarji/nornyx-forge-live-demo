from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Verdict = Literal["GO", "CONDITIONAL_GO", "REBASE_RECOMMENDED", "NO_GO", "INSUFFICIENT_EVIDENCE"]


@dataclass(frozen=True)
class RequirementProfile:
    application_type: str = "customer operations portal"
    languages: tuple[str, ...] = ("Python",)
    topics: tuple[str, ...] = ("fastapi", "dashboard", "docker")
    required_files: tuple[str, ...] = ("README.md",)
    preferred_files: tuple[str, ...] = (
        "pyproject.toml",
        "Dockerfile",
        "docker-compose.yml",
        ".github/workflows",
        "tests",
    )
    require_license: bool = True
    require_active: bool = True


@dataclass(frozen=True)
class ScoreDimension:
    name: str
    score: float
    weight: float
    evidence: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class QualificationReport:
    repository: str
    revision: str | None
    verdict: Verdict
    overall_score: float
    dimensions: tuple[ScoreDimension, ...]
    hard_stops: tuple[str, ...] = ()
    remediations: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WorkerResult:
    role: str
    goal: str
    success: bool
    output: str
    session_id: str | None = None
    command: tuple[str, ...] = ()
    returncode: int = 0


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    detail: str
    command: tuple[str, ...] = ()
    returncode: int = 0
