"""Derive a BRD from the capsule's CONFIRMED region. Authority in, BRD out.

WHAT THIS IS FOR. The build flow reads requirements from a BRD; the basic
user writes plain language into the capsule. This module is the bridge,
and it carries the authority line across: the BRD is derived from the
AUTHORITATIVE region only -- the intent and requirements a human
confirmed -- rendered by a fixed template with no free-text parameter of
its own. The user's words appear in the BRD because the user confirmed
them, which is precisely the provenance a requirements document should
have; an open proposal, whoever made it, authors nothing here.

The output is shaped for `parse_brd` and the derivation is verified
against it: every confirmed requirement becomes a leaf heading the parser
reads back, so what the flow will build from is provably what the human
confirmed -- not a paraphrase, not a superset.

`layer.domain`: mappings and strings in, one string out. Writing the file
is the caller's act.
"""

from __future__ import annotations

from typing import Any, Mapping


class BrdAuthoringError(Exception):
    """A capsule state this derivation refuses."""


def _confirmed(document: Mapping[str, Any], field: str) -> Any:
    if not isinstance(document, Mapping):
        raise BrdAuthoringError("a BRD is derived from a capsule document")
    return document.get("authoritative", {}).get(field)


def _refuse_heading_collisions(value: str, where: str) -> str:
    if "\n" in value or "\r" in value or value.lstrip().startswith("#"):
        raise BrdAuthoringError(
            f"{where} collides with the BRD's heading grammar and cannot be "
            "rendered without changing what a parser would read back"
        )
    return value


def brd_from_capsule(document: Mapping[str, Any]) -> str:
    """The confirmed intent and requirements, as a parseable BRD.

    Refuses a capsule with no CONFIRMED intent: a project whose need was
    only proposed has not decided what to build, and deriving a BRD from a
    proposal would put unconfirmed words in front of the build flow.
    """
    project_name = _confirmed(document, "project_name")
    intent = _confirmed(document, "intent")
    if not isinstance(intent, str) or not intent.strip():
        raise BrdAuthoringError(
            "the capsule has no confirmed intent; confirm one through "
            "onboarding before deriving a BRD"
        )
    requirements = _confirmed(document, "requirements") or []

    lines: list[str] = [
        f"# BRD — {_refuse_heading_collisions(str(project_name), 'the project name')}",
        "",
        "This document is DERIVED from the project capsule's confirmed",
        "region. The capsule is the authority; regenerate this file after",
        "new confirmations rather than editing it in place.",
        "",
        "## BRD-001 Purpose",
        "",
        _refuse_heading_collisions(intent, "the confirmed intent"),
        "",
    ]
    if requirements:
        lines.extend(["## BRD-002 Functional requirements", ""])
        for index, row in enumerate(requirements, start=1):
            lines.extend([
                f"### BRD-F-{index:03d} {row['id']}",
                "",
                _refuse_heading_collisions(
                    row["text"], f"requirement {row['id']}"
                ),
                "",
            ])
    return "\n".join(lines)


def confirmed_requirement_texts(document: Mapping[str, Any]) -> tuple[str, ...]:
    """What a parser must read back: the confirmed statements, in order."""
    intent = _confirmed(document, "intent")
    rows = _confirmed(document, "requirements") or []
    statements = [intent] if isinstance(intent, str) else []
    statements.extend(row["text"] for row in rows)
    return tuple(statements)
