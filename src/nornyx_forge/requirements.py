from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import RequirementProfile
from .util import digest, write_canonical_text, write_json

_HEADING_RE = re.compile(r"^(#{2,3})\s+(BRD-[A-Z0-9-]+)\s+(.+?)\s*$")
_ANY_HEADING_RE = re.compile(r"^(#{1,6})\s+.+?\s*$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(.+?)\s*$")


@dataclass(frozen=True)
class Requirement:
    id: str
    title: str
    statement: str
    source: str


@dataclass(frozen=True)
class RequirementsModel:
    schema: str
    source: str
    source_digest: str
    requirements: tuple[Requirement, ...]
    assumptions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def parse_brd(path: Path) -> RequirementsModel:
    """Convert a Markdown BRD into a deterministic, traceable requirement model.

    Each `## BRD-*` or `### BRD-*` leaf heading becomes a requirement. Text and
    bullets are retained until the next peer/parent heading. Empty container
    headings are skipped. The parser deliberately
    does not invent missing requirements; assumptions are explicit.
    """

    text = path.read_text(encoding="utf-8")
    requirements: list[Requirement] = []
    current_id: str | None = None
    current_title = ""
    current_level: int | None = None
    body: list[str] = []

    def flush() -> None:
        nonlocal current_id, current_title, current_level, body
        if current_id is None:
            return
        statement = " ".join(part.strip() for part in body if part.strip())
        if statement:
            requirements.append(
                Requirement(
                    id=current_id,
                    title=current_title,
                    statement=statement,
                    source=f"{path.name}#{current_id.lower()}",
                )
            )
        current_id = None
        current_title = ""
        current_level = None
        body = []

    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match:
            flush()
            hashes, current_id, current_title = match.groups()
            current_level = len(hashes)
            continue
        heading = _ANY_HEADING_RE.match(line)
        if heading and current_id is not None and len(heading.group(1)) <= (current_level or 6):
            flush()
            continue
        if current_id is not None:
            bullet = _BULLET_RE.match(line)
            body.append(bullet.group(1) if bullet else line)
    flush()

    assumptions: list[str] = []
    if not requirements:
        assumptions.append(
            "No `## BRD-*` or `### BRD-*` requirements were found; manual normalization is required."
        )
    return RequirementsModel(
        schema="nornyx.forge.requirements.v1",
        source=path.name,
        source_digest=digest(text.encode("utf-8")),
        requirements=tuple(requirements),
        assumptions=tuple(assumptions),
    )


def profile_from_brd(model: RequirementsModel) -> RequirementProfile:
    corpus = " ".join(f"{item.title} {item.statement}" for item in model.requirements).lower()
    topics: list[str] = []
    for topic, needles in {
        "fastapi": ("fastapi", "api", "rest"),
        "dashboard": ("dashboard", "portal", "user interface", "ui"),
        "docker": ("docker", "container"),
        "crewai": ("crewai", "agentic", "multi-agent"),
        "postgresql": ("postgres", "database", "persistence"),
    }.items():
        if any(needle in corpus for needle in needles):
            topics.append(topic)
    if not topics:
        topics.extend(("fastapi", "dashboard", "docker"))
    return RequirementProfile(topics=tuple(dict.fromkeys(topics)))


def write_requirements_artifacts(root: Path, model: RequirementsModel) -> None:
    target = root / ".nornyx/requirements"
    write_json(target / "requirements.json", model.to_dict())
    lines = [
        "# BRD traceability",
        "",
        f"Source: `{model.source}`",
        f"Digest: `{model.source_digest}`",
        "",
        "| Requirement | Title | Implementation evidence |",
        "|---|---|---|",
    ]
    for item in model.requirements:
        lines.append(
            f"| `{item.id}` | {item.title} | Tests, architecture report, and build evidence |"
        )
    if model.assumptions:
        lines.extend(("", "## Assumptions", ""))
        lines.extend(f"- {item}" for item in model.assumptions)
    write_canonical_text(target / "traceability.md", "\n".join(lines) + "\n")
