"""Source-specification provenance: what the confirmed requirements came from.

WHAT THIS IS FOR. A capsule's confirmed requirements are what Forge builds
from, but the person usually started from something else: a document, a
paragraph, a list written elsewhere. Without that original, Forge can show
what was confirmed and never what was lost on the way in. This module holds
the check that relates the two facts the capsule records (A-060):

    the source specification   the original text, confirmed by a human as
                               the specification, and identified by the
                               SHA-256 of its UTF-8 bytes
    the requirement sources    one record per confirmed requirement: the
                               part of the source it came from, and whether
                               it is that part VERBATIM, a CHANGED rendering
                               of it, or ADDED with no source part at all

A changed or added requirement carries the person's own account of what
changed and what was lost. Forge checks what is checkable -- that each
recorded part occurs exactly in the source, that a verbatim requirement is
exactly its part, that every confirmed requirement has one record and no
record names anything else -- and computes what no record covers. It does
NOT check that a change note is accurate or complete: that is the person's
statement, recorded as theirs.

WHAT "UNCOVERED" MEANS. The parts of the source that no requirement record
and no verbatim intent covers, after whitespace-only gaps are dropped. A
heading or a sentence of context is uncovered as surely as a requirement
nobody carried across, and this module cannot tell them apart; it shows them
so a person can. Coverage is located at the FIRST occurrence of each recorded
part; a part that occurs more than once says so in `occurrences`, because its
first occurrence may not be the one the person meant.

`layer.domain`: mappings and strings in, values out. No filesystem, clock or
process.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

#: The record kinds, closed.
KINDS = ("verbatim", "changed", "added")

#: The largest source text the capsule holds, in characters.
SOURCE_TEXT_LIMIT = 200_000

#: The longest change note, in characters (the capsule's row limit).
CHANGE_LIMIT = 2000

#: How much of an uncovered part a report quotes.
EXCERPT_PREVIEW = 200


def source_sha256(text: str) -> str:
    """The specification's identity: SHA-256 of its UTF-8 bytes, as hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _authoritative(document: Mapping[str, Any]) -> Mapping[str, Any]:
    region = document.get("authoritative")
    return region if isinstance(region, Mapping) else {}


def confirmed_source(document: Mapping[str, Any]) -> str | None:
    """The confirmed source specification's text, or None."""
    value = _authoritative(document).get("source_specification")
    if isinstance(value, Mapping) and isinstance(value.get("text"), str):
        return value["text"]
    return None


def binding_problems(document: Mapping[str, Any]) -> list[str]:
    """Why the confirmed requirements are not bound to the confirmed source.

    Empty when they are. Reads the AUTHORITATIVE region only: a proposed
    source or record binds nothing until a human confirms it.
    """
    region = _authoritative(document)
    source = confirmed_source(document)
    if source is None:
        return ["no source specification has been confirmed"]
    rows = region.get("requirements") or []
    records = region.get("requirement_sources")
    if records is None:
        if rows:
            return ["no requirement sources have been confirmed, so no confirmed "
                    "requirement says what part of the source it came from"]
        return []
    problems: list[str] = []
    texts = {row["id"]: row["text"] for row in rows}
    named = [record["requirement"] for record in records]
    for row in rows:
        count = named.count(row["id"])
        if count == 0:
            problems.append(f"requirement {row['id']} has no confirmed source record")
        elif count > 1:
            problems.append(f"requirement {row['id']} has {count} source records, not one")
    for record in records:
        rid = record["requirement"]
        if rid not in texts:
            problems.append(f"a source record names {rid}, which is not a confirmed requirement")
            continue
        excerpt = record["excerpt"]
        if record["kind"] in ("verbatim", "changed") and excerpt not in source:
            problems.append(f"the source part recorded for {rid} does not occur in the "
                            "confirmed source specification")
        if record["kind"] == "verbatim" and texts[rid] != excerpt:
            problems.append(f"{rid} is recorded as verbatim but its text is not exactly "
                            "its source part")
    return problems


def _located(source: str, part: str) -> tuple[int | None, int]:
    if not part or part not in source:
        return None, 0
    return source.find(part), source.count(part)


def _uncovered(source: str, covered: list[tuple[int, int]]) -> list[dict[str, Any]]:
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in sorted(covered):
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < len(source):
        gaps.append((cursor, len(source)))
    uncovered = []
    for start, end in gaps:
        part = source[start:end]
        if not part.strip():
            continue
        uncovered.append({
            "start": start,
            "end": end,
            "characters": end - start,
            "excerpt": part.strip()[:EXCERPT_PREVIEW],
        })
    return uncovered


def provenance_report(document: Mapping[str, Any]) -> dict[str, Any]:
    """What the confirmed region says about where its requirements came from.

    A report, not a verdict: `bound` is `binding_problems` being empty, and
    `uncovered` is the source that no record and no verbatim intent covers.
    """
    region = _authoritative(document)
    source = confirmed_source(document)
    problems = binding_problems(document)
    if source is None:
        return {"bound": False, "problems": problems, "source_sha256": None,
                "source_characters": None, "intent": None, "requirements": [],
                "uncovered": [], "uncovered_characters": None}
    covered: list[tuple[int, int]] = []
    intent = region.get("intent")
    intent_view: dict[str, Any] | None = None
    if isinstance(intent, str):
        start, occurrences = _located(source, intent)
        intent_view = {"found_verbatim": start is not None, "occurrences": occurrences,
                       "start": start, "end": None if start is None else start + len(intent)}
        if start is not None:
            covered.append((start, start + len(intent)))
    entries = []
    for record in region.get("requirement_sources") or []:
        start, occurrences = _located(source, record["excerpt"])
        end = None if start is None else start + len(record["excerpt"])
        if start is not None:
            covered.append((start, end))
        entries.append({"requirement": record["requirement"], "kind": record["kind"],
                        "change": record["change"], "occurrences": occurrences,
                        "start": start, "end": end})
    uncovered = _uncovered(source, covered)
    return {
        "bound": not problems,
        "problems": problems,
        "source_sha256": source_sha256(source),
        "source_characters": len(source),
        "intent": intent_view,
        "requirements": entries,
        "uncovered": uncovered,
        "uncovered_characters": sum(part["characters"] for part in uncovered),
    }
