"""A mutation is valid only if it changed an executable or authoritative node.

THREE FALSE GREENS forced this rule, all of them the same shape: a textual
first-occurrence replacement landed somewhere that could not affect behaviour,
and the result was read as evidence.

    a retired policy token survived in a comment explaining its removal, so the
    probe searching for it mutated prose

    `architecture_reviewer` first occurs in a comment about narrowing
    eligibility, so a "separation of duties" probe had been mutating prose for
    as long as that comment existed

    a mutation harness that could not tell "the anchor no longer matches" from
    "the mutation applied and nothing happened" would report a survivor

None of those changed a governance decision. All of them passed.

THE RULE, enforced here rather than remembered:

    TARGET FOUND                 the anchor matches, the expected number of times
    TARGET IS EXECUTABLE         the match is not inside a comment or docstring
    TARGET CHANGED               the parsed structure differs afterwards
    NO INERT-ONLY MATCH          prose changes are refused outright
    STILL PARSES                 a syntax error is an invalid mutation, not a kill

`INTENDED TEST EXECUTED` and `INTENDED PROPERTY FAILED` are the caller's half,
because only the caller knows which property it aimed at. This module makes the
first five mechanical.
"""

from __future__ import annotations

import ast
import io
import json
import tokenize
from pathlib import Path

import yaml


class InvalidMutation(AssertionError):
    """The mutation did not modify an executable or authoritative construct.

    Deliberately NOT an ordinary assertion failure in the caller's vocabulary:
    an invalid mutation is neither a kill nor a survivor, and collapsing it into
    either is how a catalogue reports a number that means nothing.
    """


class IndiscriminateBaseline(AssertionError):
    """The baseline already exhibits the outcome the attack is looking for.

    Sibling of `InvalidMutation`, and refused for the same reason. There the
    mutation could not have caused an effect; here the effect was present
    before the mutation ran. Both produce a green tick that means nothing, and
    neither is a kill or a survivor.
    """


def require_discriminating_baseline(
    label: str, *, baseline: object, expected: object, what: str
) -> None:
    """Refuse an experiment that cannot tell the attack from the starting state.

    Lens C found two live assertions where `baseline == expected` on the
    unmutated tree, so the attack was credited with an outcome it did not
    produce. Enforced here rather than remembered, because both of them read
    as perfectly ordinary proofs right up until the value was measured.
    """
    if baseline != expected:
        return
    raise IndiscriminateBaseline(
        f"{label}: {what} is already {baseline!r} BEFORE the attack is applied, "
        f"so asserting it becomes {expected!r} afterwards proves nothing -- the "
        "value was there either way.\n"
        "This is normally a stale evidence set rather than a broken test. "
        "Regenerate evidence in the same commit as the governed change:\n"
        "  python scripts/refresh_governance_evidence.py "
        "--sync-contracts --review-binding\n"
        "then re-run. Do not weaken the assertion to make this pass."
    )


def _line_starts(source: str) -> list[int]:
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _offset(starts: list[int], lineno: int, col: int) -> int:
    return starts[lineno - 1] + col


def inert_spans(source: str) -> list[tuple[int, int]]:
    """Offset ranges that cannot change behaviour: comments and docstrings.

    Docstrings are included even though they DO appear in the AST, because a
    changed docstring changes the parse tree while changing nothing a security
    control consults. Treating that as a mutation is exactly the false green
    this module exists to refuse.
    """
    spans: list[tuple[int, int]] = []
    starts = _line_starts(source)

    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                spans.append(
                    (
                        _offset(starts, token.start[0], token.start[1]),
                        _offset(starts, token.end[0], token.end[1]),
                    )
                )
    except (tokenize.TokenError, IndentationError):
        # A file that cannot be tokenized cannot be reasoned about; the caller's
        # parse check below will refuse it.
        pass

    tree = ast.parse(source)
    # EVERY BARE STRING STATEMENT, not only a leading one.
    #
    # Only `body[0]` was treated as prose, so a string expression one
    # statement further down -- a PEP-224 attribute docstring, a
    # free-standing note -- was in neither `inert_spans` nor
    # `executable_projection`. An anchor inside one cleared TARGET IS
    # INERT, cleared TARGET UNCHANGED (a string constant is an AST node)
    # and cleared PROSE-ONLY MUTATION (the projection does not blank it),
    # so a prose-only edit would have been credited as a real change to
    # executable Python -- the class this module exists to refuse, one
    # statement position away.
    #
    # A bare string is never load-bearing: its value is computed and
    # discarded wherever it appears, so treating them all as prose
    # cannot hide a real change.
    for first in ast.walk(tree):
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            and first.end_lineno is not None
        ):
            spans.append(
                (
                    _offset(starts, first.lineno, first.col_offset),
                    _offset(starts, first.end_lineno, first.end_col_offset or 0),
                )
            )
    return spans


def executable_projection(source: str) -> str:
    """`source` with every comment and docstring blanked out.

    The offset test below asks where the ANCHOR STARTS. That is not the same
    question as what the edit CHANGED: an anchor beginning on a line of code and
    running on into a docstring passes the start-offset test while the only
    bytes that actually differ are prose. A mutation like that changes the parse
    tree -- docstrings are AST nodes -- so the AST-inequality check downstream
    passes too, and the result is credited as a kill for an edit that removed
    nothing. Lens B demonstrated exactly this against H07.

    Comparing projections asks the real question: after ignoring everything that
    cannot execute, is this still a different program?
    """
    spans = inert_spans(source)
    if not spans:
        return source
    kept: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if start < cursor:  # overlapping spans; keep the outermost
            cursor = max(cursor, end)
            continue
        kept.append(source[cursor:start])
        cursor = end
    kept.append(source[cursor:])
    return "".join(kept)


def _occurrences(source: str, anchor: str) -> list[int]:
    found, start = [], 0
    while (index := source.find(anchor, start)) != -1:
        found.append(index)
        start = index + 1
    return found


def check_python_mutation(
    relative: str, before: str, after: str, anchor: str, expected: int
) -> None:
    """Refuse anything that is not a real change to executable Python."""
    offsets = _occurrences(before, anchor)
    if len(offsets) != expected:
        raise InvalidMutation(
            f"TARGET NOT FOUND in {relative}: expected {expected} occurrence(s) "
            f"of {anchor.strip()[:70]!r}, found {len(offsets)}. The mutation did "
            "not apply, so any result would be the unmutated behaviour wearing a "
            "mutant's name."
        )

    inert = inert_spans(before)
    for offset in offsets:
        if any(start <= offset < end for start, end in inert):
            line = before.count("\n", 0, offset) + 1
            raise InvalidMutation(
                f"TARGET IS INERT in {relative}:{line}: {anchor.strip()[:60]!r} "
                "matches inside a comment or docstring, so this mutation changes "
                "prose and cannot change a governance decision. Three false "
                "greens in this repository had exactly this shape."
            )

    try:
        mutated_tree = ast.parse(after)
    except SyntaxError as exc:
        raise InvalidMutation(
            f"MUTANT DOES NOT PARSE ({relative}): {exc}. A syntax error is an "
            "invalid mutation, never a killed one."
        ) from exc

    if ast.dump(mutated_tree) == ast.dump(ast.parse(before)):
        raise InvalidMutation(
            f"TARGET UNCHANGED in {relative}: the parse tree is identical after "
            "the edit, so nothing executable was modified."
        )

    # AST inequality is necessary and NOT sufficient. Docstrings are AST nodes,
    # so a prose-only edit clears the check above; and the inert test earlier
    # asks where the anchor STARTS, which an anchor beginning on code and
    # running into a docstring satisfies while changing only prose. Lens B built
    # exactly that against H07 and it reported `1 passed`, a kill credited for
    # an edit that removed nothing.
    if executable_projection(before) == executable_projection(after):
        raise InvalidMutation(
            f"PROSE-ONLY MUTATION in {relative}: with comments and docstrings "
            "removed, the mutant is byte-identical to the original. The parse "
            "tree differs because docstrings are AST nodes, not because any "
            "executable construct changed. Whatever the named test then does, "
            "it is not responding to this edit."
        )


def check_structured_mutation(relative: str, before: str, after: str) -> None:
    """Refuse a contract/config edit that did not change the parsed document.

    A `.nyx` or `.json` edit that only touches comments or whitespace leaves the
    loaded structure identical -- and the loaded structure is what any governance
    check reads.
    """
    loader = json.loads if relative.endswith(".json") else yaml.safe_load
    try:
        parsed_after = loader(after)
    except Exception as exc:  # noqa: BLE001 - any parse failure is invalid
        raise InvalidMutation(
            f"MUTANT DOES NOT PARSE ({relative}): {type(exc).__name__}: {exc}"
        ) from exc
    if parsed_after == loader(before):
        raise InvalidMutation(
            f"TARGET UNCHANGED in {relative}: the parsed document is identical "
            "after the edit, so only prose or formatting moved."
        )


def check_mutation(relative: str, before: str, after: str, anchor: str, expected: int) -> None:
    """Dispatch on file kind. Unknown kinds are refused rather than waved through."""
    if relative.endswith(".py"):
        check_python_mutation(relative, before, after, anchor, expected)
    elif relative.endswith((".nyx", ".yml", ".yaml", ".json")):
        offsets = _occurrences(before, anchor)
        if len(offsets) != expected:
            raise InvalidMutation(
                f"TARGET NOT FOUND in {relative}: expected {expected} "
                f"occurrence(s) of {anchor.strip()[:70]!r}, found {len(offsets)}"
            )
        for offset in offsets:
            line_start = before.rfind("\n", 0, offset) + 1
            if before[line_start:offset].lstrip().startswith("#"):
                line = before.count("\n", 0, offset) + 1
                raise InvalidMutation(
                    f"TARGET IS INERT in {relative}:{line}: the match is inside a "
                    "comment, so it cannot change what any check reads."
                )
        check_structured_mutation(relative, before, after)
    else:
        raise InvalidMutation(
            f"UNSUPPORTED TARGET {relative}: this harness can only prove a "
            "mutation reached an executable or authoritative construct for "
            "Python and parsed contract/config formats."
        )


def mutate(tree: Path, edits) -> None:
    """Apply every edit, proving each one reached something that can decide."""
    for relative, old, new, occurrences in edits:
        target = tree / relative
        before = target.read_text(encoding="utf-8")
        after = before.replace(old, new)
        check_mutation(relative, before, after, old, occurrences)
        target.write_text(after, encoding="utf-8", newline="")
