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

UNMAPPED SOURCE TEXT. The parts of the source that no requirement record
and no verbatim intent maps, reported one entry per Markdown block -- a
heading, a list item, a paragraph or a fenced block -- or per part of one
that a record maps only in part, each with its line, its character positions
and a preview (A-061). A specification's interface section is often one list
with no blank line in it; cut only at blank lines, that list was one entry
of thousands of characters, and the one item nobody carried across was lost
inside it. A heading or a sentence of context is unmapped as surely as a
requirement nobody carried across, and this module cannot tell them apart; it
shows them so a person can, and it claims nothing about what is missing. The
report keeps its field names, `uncovered` and `uncovered_characters`, so a
receipt exported before this change still verifies. Coverage is located at
the FIRST occurrence of each recorded part; a part that occurs more than once
says so in `occurrences`, because its first occurrence may not be the one the
person meant.

`layer.domain`: mappings and strings in, values out. No filesystem, clock or
process.
"""

from __future__ import annotations

import bisect
import hashlib
import re
from typing import Any, Mapping

#: The record kinds, closed.
KINDS = ("verbatim", "changed", "added")

#: The largest source text the capsule holds, in characters.
SOURCE_TEXT_LIMIT = 200_000

#: The longest change note, in characters (the capsule's row limit).
CHANGE_LIMIT = 2000

#: How much of an unmapped entry a report quotes.
EXCERPT_PREVIEW = 200

#: The Markdown blocks unmapped source text is reported by (A-061), closed.
BLOCK_KINDS = ("heading", "list item", "paragraph", "fenced block")

_HEADING = re.compile(r"[ \t]{0,3}#{1,6}(?:[ \t]|\Z)")
_LIST_ITEM = re.compile(r"[ \t]*(?:[-*+]|[0-9]{1,9}[.)])(?:[ \t]|\Z)")
_FENCE = re.compile(r"[ \t]{0,3}(`{3,}|~{3,})")


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


def _opens_block(line: str) -> bool:
    return bool(_HEADING.match(line) or _LIST_ITEM.match(line) or _FENCE.match(line))


def _blocks(source: str) -> list[tuple[int, int, str]]:
    """The source's Markdown blocks, in order, as `(start, end, kind)`.

    A small reading of Markdown's block structure, not a Markdown parser. A
    line opening with one to six `#` and a space is a heading. A line opening
    with a list marker -- `-`, `*`, `+`, or a number and `.` or `)` -- and a
    space starts a list item. A fence of three or more backticks or tildes
    starts a fenced block, which runs to its closing fence or to the end of
    the text. Any other line starts a paragraph. A list item or a paragraph
    runs on through the following lines until a blank line or a line that
    opens a block, so a nested item is a block of its own. Blank lines belong
    to no block. A table, a quotation, indented code or an underlined heading
    reads as a paragraph. A line ends at LF or CRLF, and `end` stops before
    the last line's terminator, so a CRLF line is read, and ends its block,
    without its carriage return while every offset still indexes the text as
    given (Codex P2 4492746866).
    """
    lines: list[tuple[int, int, str]] = []
    position = 0
    for text in source.split("\n"):
        body = text[:-1] if text.endswith("\r") else text
        lines.append((position, position + len(body), body))
        position += len(text) + 1
    blocks: list[tuple[int, int, str]] = []
    index = 0
    while index < len(lines):
        start, _, text = lines[index]
        if not text.strip():
            index += 1
            continue
        fence = _FENCE.match(text)
        if fence:
            marker = fence.group(1)
            closing = re.compile(r"[ \t]{0,3}" + re.escape(marker[0])
                                 + "{" + str(len(marker)) + r",}[ \t]*\Z")
            last = index + 1
            while last < len(lines) and not closing.match(lines[last][2]):
                last += 1
            if last == len(lines):  # unclosed: it runs to the last line with text
                last -= 1
                while not lines[last][2].strip():
                    last -= 1
            blocks.append((start, lines[last][1], "fenced block"))
            index = last + 1
            continue
        if _HEADING.match(text):
            blocks.append((start, lines[index][1], "heading"))
            index += 1
            continue
        kind = "list item" if _LIST_ITEM.match(text) else "paragraph"
        last = index
        while (last + 1 < len(lines) and lines[last + 1][2].strip()
               and not _opens_block(lines[last + 1][2])):
            last += 1
        blocks.append((start, lines[last][1], kind))
        index = last + 1
    return blocks


def _unmapped(source: str, covered: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """The source text that nothing in `covered` maps, one entry per block.

    Each entry is a block, or the part of one that a mapped part leaves, with
    the whitespace at its ends trimmed: its character positions, its line,
    the kind of block it is, and a preview. Text between blocks is blank, so
    it is never an entry."""
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in sorted(covered):
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < len(source):
        gaps.append((cursor, len(source)))
    line_starts = [0] + [index + 1 for index, char in enumerate(source) if char == "\n"]
    entries: list[dict[str, Any]] = []
    first = 0
    for block_start, block_end, kind in _blocks(source):
        while first < len(gaps) and gaps[first][1] <= block_start:
            first += 1
        index = first
        while index < len(gaps) and gaps[index][0] < block_end:
            start, end = max(block_start, gaps[index][0]), min(block_end, gaps[index][1])
            part = source[start:end]
            text = part.strip()
            if text:
                start += len(part) - len(part.lstrip())
                end = start + len(text)
                entries.append({
                    "start": start,
                    "end": end,
                    "characters": end - start,
                    "line": bisect.bisect_right(line_starts, start),
                    "block": kind,
                    "excerpt": text[:EXCERPT_PREVIEW],
                })
            index += 1
    return entries


def provenance_report(document: Mapping[str, Any]) -> dict[str, Any]:
    """What the confirmed region says about where its requirements came from.

    A report, not a verdict: `bound` is `binding_problems` being empty, and
    `uncovered` is the unmapped source text: what no record and no verbatim
    intent maps, one entry per Markdown block or part of one (A-061).
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
    uncovered = _unmapped(source, covered)
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
