from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import RequirementProfile
from .util import digest, write_canonical_text


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


def brd_requirement_identity(text: str) -> dict[str, list[Any]]:
    """THE requirement-identity rule: which BRD headings are requirements.

    One definition for every reader of a BRD (A-045). `parse_brd` reads
    requirements through it, `brd_authoring` checks its own rendering
    against it, and the trusted greenfield verifier, which imports no
    first-party code, carries this function verbatim, held identical by
    `tests/test_requirement_identity.py`.

    Lines are `str.splitlines()` lines. An IDENTIFIER HEADING is a level 2
    to 6 heading whose text begins with `BRD-` followed by upper-case
    letters, digits or hyphens. Its BODY is the lines after it up to the
    next identifier heading at any level or the next heading at its own or
    a higher level; a deeper heading without an identifier is body text. Its
    STATEMENT is the body's non-blank lines, stripped of a bullet marker and
    joined by single spaces. Each identifier heading is exactly one of:

    - a REQUIREMENT: its identifier is `BRD-` and hyphen-separated groups of
      upper-case letters and digits, followed by whitespace and a title; no
      other identifier heading carries the same identifier; and its
      statement is non-empty;
    - a SECTION: the same, with an empty statement and at least one
      requirement among the identifier headings nested beneath it; it
      states nothing, so nothing traces to it;
    - MALFORMED: anything else, with the reason. A malformed heading is
      never dropped silently: the parser reports it and the verifier
      refuses the BRD.

    Returns plain data, in document order: `requirements` (id, level, title,
    statement), `sections` (ids) and `malformed` (id, reason).
    """
    import re

    identifier_heading = re.compile(r"^(#{2,6})\s+(BRD-[A-Z0-9-]+)\b(.*)$")
    other_heading = re.compile(r"^(#{1,6})\s+.+?\s*$")
    well_formed = re.compile(r"^BRD-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
    bullet = re.compile(r"^\s*[-*]\s+(.+?)\s*$")

    lines = text.splitlines()
    headings: list[tuple[int, int, str | None, str]] = []
    for index, line in enumerate(lines):
        match = identifier_heading.match(line)
        if match:
            headings.append((index, len(match.group(1)), match.group(2), match.group(3)))
            continue
        match = other_heading.match(line)
        if match:
            headings.append((index, len(match.group(1)), None, ""))

    counts: dict[str, int] = {}
    for _index, _level, ident, _rest in headings:
        if ident is not None:
            counts[ident] = counts.get(ident, 0) + 1

    entries: list[dict[str, Any]] = []
    for position, (index, level, ident, rest) in enumerate(headings):
        if ident is None:
            continue
        body_end = len(lines)
        nested: list[str] = []
        for later_index, later_level, later_ident, _rest in headings[position + 1:]:
            if later_level <= level:
                body_end = min(body_end, later_index)
                break
            if later_ident is not None:
                body_end = min(body_end, later_index)
                nested.append(later_ident)
        parts = []
        for line in lines[index + 1:body_end]:
            match = bullet.match(line)
            part = (match.group(1) if match else line).strip()
            if part:
                parts.append(part)
        title = rest.strip()
        reason = None
        if not well_formed.match(ident) or not rest[:1].isspace() or not title:
            reason = "it is not an identifier followed by a space and a title"
        elif counts[ident] > 1:
            reason = "its identifier names more than one heading"
        entries.append({"id": ident, "level": level, "title": title,
                        "statement": " ".join(parts), "nested": nested, "reason": reason})

    requirement_ids = {entry["id"] for entry in entries
                       if entry["reason"] is None and entry["statement"]}
    result: dict[str, list[Any]] = {"requirements": [], "sections": [], "malformed": []}
    for entry in entries:
        if entry["reason"] is None and entry["statement"]:
            result["requirements"].append({key: entry[key] for key in
                                           ("id", "level", "title", "statement")})
        elif entry["reason"] is None and requirement_ids.intersection(entry["nested"]):
            result["sections"].append(entry["id"])
        else:
            result["malformed"].append({
                "id": entry["id"],
                "reason": entry["reason"] or "it has no statement and no requirement beneath it",
            })
    return result


def parse_brd(path: Path) -> RequirementsModel:
    """Convert a Markdown BRD into a deterministic, traceable requirement model.

    The requirements are exactly those `brd_requirement_identity` reads, in
    document order: a section heading with requirements beneath it is not one
    of them, and a malformed identifier heading is reported as an assumption
    rather than dropped. The parser deliberately does not invent missing
    requirements; assumptions are explicit.
    """

    text = path.read_text(encoding="utf-8")
    identity = brd_requirement_identity(text)
    requirements = tuple(
        Requirement(
            id=entry["id"],
            title=entry["title"],
            statement=entry["statement"],
            source=f"{path.name}#{entry['id'].lower()}",
        )
        for entry in identity["requirements"]
    )
    assumptions: list[str] = [
        f"`{entry['id']}` is neither a requirement nor a section: {entry['reason']}; "
        "the acceptance verifier refuses it."
        for entry in identity["malformed"]
    ]
    if not requirements:
        assumptions.append(
            "No BRD requirement heading was found; manual normalization is required."
        )
    return RequirementsModel(
        schema="nornyx.forge.requirements.v1",
        source=path.name,
        source_digest=digest(text.encode("utf-8")),
        requirements=requirements,
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


def render_requirements_json(model: RequirementsModel) -> str:
    """`requirements.json` as `write_requirements_artifacts` writes it, as text
    written nowhere (the input stage renders it, A-055)."""
    return json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n"


def render_traceability(model: RequirementsModel) -> str:
    """`traceability.md` as `write_requirements_artifacts` writes it, as text
    written nowhere (the input stage renders it, A-055)."""
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
    return "\n".join(lines) + "\n"


def write_requirements_artifacts(root: Path, model: RequirementsModel) -> None:
    target = root / ".nornyx/requirements"
    write_canonical_text(target / "requirements.json", render_requirements_json(model))
    write_canonical_text(target / "traceability.md", render_traceability(model))
