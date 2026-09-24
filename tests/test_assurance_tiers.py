"""Escalation reaches the highest applicable tier, never merely the next one.

`docs/governance/ASSURANCE_TIERS.md` once said that any escalation trigger "moves
a milestone up a tier". Three of those triggers -- consuming an authorization,
writing state that cannot be restored, being the first record in a chain -- are
Tier G's own properties. A milestone declared N that turned out to be
irreversible therefore escalated to H: below the floor its own properties set,
and without exactly what Tier G exists to require -- exact-byte human
authorization, fail-closed refusal tests, a rehearsal, and consumption of the
authorization. A Codex review found it; nothing here would have.

WHY THE WHOLE DOCUMENT IS PINNED, AND HOW. Nothing executes prose, and prose
cannot be parsed for contradictions. Read-only review showed it twice: tests
matching the prose's spelling were evaded first inside the rule section, then
outside it, where one clause added to the batching rule reopened the
after-acceptance path. So the document is pinned twice over:

- BYTE FOR BYTE, by SHA-256 and length, in this project's exact-byte idiom. This
  catches every change, including ones a reader cannot see: a BOM, a no-break
  or zero-width space, a look-alike letter, CRLF. `.gitattributes` checks the
  document out with LF on every platform, so an unchanged document hashes the
  same everywhere.
- AS TEXT, unit by unit: every heading, paragraph, list item and table row,
  whitespace collapsed. A digest can be replaced without being read. This pin
  cannot be updated without writing the new sentences into this file, where a
  reviewer can read them in the diff, and a failure names the section and the
  units that moved.

Beside the pins, a structure check rejects these kinds of markup, each of which
can hide or demote text in the rendered document: HTML tags, comments,
declarations and processing instructions; code fences; lines indented four or
more spaces or with a tab; nested list items; setext heading underlines;
strikethrough; and a split property table. It is deliberately stricter than
CommonMark, and some of what it rejects would render harmlessly. It is not
exhaustive: characters outside printable ASCII that split lines or imitate
letters, read differently by Python and by a Markdown renderer, are a named and
deferred gap.
The specimens resolve THROUGH the document's own table and rule sentences, each
required before it is used, never through a copy.

What no test here can stop is a deliberate change to the document AND both pins
that nobody reads. That is a review question, and the text pin puts the change in
front of the reviewer as sentences rather than as a hash.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "governance" / "ASSURANCE_TIERS.md"

#: The reviewed document, byte for byte. Change it only together with the text pin
#: below and the document itself, in one reviewed diff.
_PINNED_SHA256 = "3c2ca8b9dd787bb3dddefe9d5ca10da88685ed61844b793dacbfee2ca213c11b"
_PINNED_BYTES = 8161

#: The properties that make work Tier G, whatever it was declared.
TIER_G_PROPERTIES = frozenset(
    {
        "irreversible",
        "authorization-consuming",
        "genesis",
        "privileged",
        "one-shot",
        "authority-changing",
    }
)

_ORDER = ("N", "H", "G")

# The escalation section, unit by unit, whitespace collapsed. Each rule sentence
# is named so the specimens below can require the exact rule they resolve through.
_RULE = (
    "When a trigger below fires, the milestone is re-tiered to the **highest applicable "
    "tier**, the highest tier any firing trigger requires, and the move is recorded."
)
_PROPERTY_INTRO = (
    "**Property triggers.** These are Tier G's own properties. Work found to have any of "
    "them is Tier G, whether it was declared N or H:"
)
_TABLE = (
    "| Property the work is found to have | Tier |",
    "|---|---|",
    "| irreversible: it writes to state that cannot be restored from the repository | G |",
    "| authorization-consuming: it can consume an authorization | G |",
    "| genesis: it is the first record in a chain that later records depend on | G |",
    "| privileged: it is a privileged act, such as privileged provisioning | G |",
    "| one-shot: it cannot be retried | G |",
    "| authority-changing: it can alter an authorization, or permanently alter authority "
    "or trust state | G |",
)
_INVARIANT = (
    "**Tier H is never a terminal tier for work that has a Tier G property.** Moving such "
    "work one step up from N would leave it at H, below the floor its own properties set, "
    "and without the exact-byte authorization, refusal tests and rehearsal that Tier G "
    "requires."
)
_AFTER_ACCEPTANCE = (
    "**A Tier G property is blocking whenever it is found, including after acceptance.** "
    "It is never batched as a non-blocking finding: an acceptance at a lower tier lapses, "
    "and the milestone re-enters the review-entry gate at Tier G."
)
_PROCESS_RULE = (
    "**Process triggers.** These say the declared tier is proving too little, not that the "
    "work has a Tier G property. Either one moves the milestone up one tier:"
)
_PROCESS_TRIGGERS = (
    "1. a deterministic gate cannot express the property, so a human reading is the only "
    "check;",
    "2. two review rounds find defects in the same structural class.",
)
_BOTH_KINDS = (
    "Where both kinds fire, the higher result stands: a process trigger never lowers the "
    "tier a property trigger requires."
)
_PINNED_ESCALATION = (
    _RULE,
    _PROPERTY_INTRO,
    *_TABLE,
    _INVARIANT,
    _AFTER_ACCEPTANCE,
    _PROCESS_RULE,
    *_PROCESS_TRIGGERS,
    _BOTH_KINDS,
)

# The rest of the document, generated from the reviewed text and pinned the same way.
_BEFORE_ESCALATION: tuple[str, ...] = (
    "# Assurance tiers",
    (
        "This document states, before work begins, how much proof a change is required to carry. "
        "It establishes nothing about any change, and it is not evidence that any tier was "
        "applied."
    ),
    "## Activation boundary",
    (
        "This document canonizes the assurance-tier model and the review-entry semantics. It is "
        "not yet a step of standing-development admission: the admission mechanism does not "
        "currently require a development cycle to load this document or to declare a tier. Making "
        "pre-work tier declaration mandatory requires a separate, admitted repository-changing "
        "tranche that wires this document into the controlling development procedure. This "
        "document neither authorizes nor performs that wiring."
    ),
    "## Why this document exists",
    (
        "The hardening programme that produced `RELEASE_CONTRACT_V1.md` ran fifteen review rounds, "
        "and every round found something real. That contract fixed the *termination* problem: a "
        "frozen, explicit contract replaced \"keep attacking until a capable reviewer cannot find "
        "another P1\"."
    ),
    (
        "It did not fix the *proportionality* problem. Under a single standard, a documentation "
        "correction and an irreversible one-shot operation carry the same ceremony. The observable "
        "cost is not that the rigor is wasted — the rounds found genuine defects — but that the "
        "same rigor applied everywhere makes the expensive work indistinguishable from the cheap "
        "work, and so the cheap work gets expensive rather than the expensive work getting safer."
    ),
    "This document states, before work begins, how much proof a change has to carry.",
    (
        "**It cannot be used to lower a bar that something else sets.** A tier selects a recipe; "
        "it never overrides `RELEASE_CONTRACT_V1.md`, `CLOSURE_PROTOCOL.md`, "
        "`HUMAN_BLOCKED_MEASUREMENTS.md`, a deterministic gate, an evidence requirement, or any "
        "human or organizational authority. Where a tier and one of those disagree, the other wins "
        "and this document is wrong."
    ),
    "## The rule",
    (
        "> Escalate assurance because of what the step can permanently break, not because > the "
        "previous step happened to be difficult."
    ),
    (
        "A milestone declares its tier **before** work begins. Declaring it afterwards is choosing "
        "the recipe once the result is known, which is not a control."
    ),
    "## The tiers",
    (
        "### Tier G — genesis, irreversible, privileged, authority-changing, one-shot, "
        "authorization-consuming"
    ),
    (
        "For anything that can permanently alter authority or trust state, or that cannot be "
        "retried: the first record in a chain, a privileged provisioning act, a checkpoint or host "
        "mutation, retirement of a capability, anything consuming a one-shot authorization."
    ),
    "Required:",
    (
        "- the production entry point rehearsed end to end against a local fixture, not a unit "
        "test of its parts;"
    ),
    "- adversarial review by a reader who did not build it;",
    "- fail-closed tests for every refusal path the operation can take;",
    "- mutation testing where executable guards decide the outcome;",
    "- exact-byte review: path, SHA-256, byte count, scope;",
    "- explicit human authorization naming those exact bytes;",
    (
        "- the authorization consumed by the invocation, whether it succeeds, refuses, or fails "
        "after mutation begins."
    ),
    "### Tier H — high-impact but recoverable",
    (
        "For work whose failure is visible and correctable: measurement logic a decision rests on, "
        "architecture acceptance, instrumentation, analysis that feeds a claim."
    ),
    (
        "Required: behavioural tests including the negative paths, targeted adversarial review, an "
        "independent reviewer, exact-head acceptance. Mutation testing only where a guard decides "
        "the outcome — **not** as a ritual over every line."
    ),
    "### Tier N — normal governed engineering",
    (
        "For ordinary reversible work: documentation, reporting, inventory disposition, "
        "implementation that changes no authority."
    ),
    (
        "Required: the repository's ordinary CI, review and evidence discipline. Escalate only "
        "when a trigger fires."
    ),
)
_AFTER_ESCALATION: tuple[str, ...] = (
    "## The review-entry gate",
    (
        "Independent acceptance review does not start while the architecture or decision surface "
        "is still moving."
    ),
    (
        "Measured reason: a review that participates in design cannot be the review that falsifies "
        "it, and no round can be known to be the last, because each round's repairs create the "
        "next round's subject. Before review is entered:"
    ),
    "- the architecture and decision surface are frozen;",
    (
        "- every proof obligation is in a terminal state — proved, deliberately deferred and "
        "named, or explicitly NOT ESTABLISHED;"
    ),
    "- the real entry point has been rehearsed where the tier requires it;",
    "- every active mutant carries a terminal disposition;",
    "- the deterministic finalize sequence has run;",
    "- candidate hashes are frozen.",
    (
        "A finite obligation ledger is what makes a review round the last one. Without it, each "
        "round is a draw from an unknown distribution."
    ),
    "## Stopping rules",
    (
        "**One repair cycle, not another fifteen.** `RELEASE_CONTRACT_V1.md` governs, with "
        "`CLOSURE_PROTOCOL.md` for the specimen and revert control: a finding proven to violate a "
        "property that `RELEASE_CONTRACT_V1.md` names gets a root fix, a permanent specimen, a "
        "revert control, and a re-run of the affected review. The assurance philosophy is not "
        "redesigned because a third reviewer found something in its own scope."
    ),
    (
        "**Non-blocking findings are batched.** After acceptance with non-blocking findings, bytes "
        "change before execution only if a finding touches an irreversible assertion, an authority "
        "or security boundary, or a known unmeasured execution path. Everything else becomes a "
        "named deferred item. Re-opening accepted bytes for an improvement invalidates the "
        "acceptance and buys nothing."
    ),
    (
        "**Absence is never self-justifying.** Anything leaving a measured set — a mutant, an "
        "obligation, a specimen — carries an explicit terminal disposition. A shrinking count is "
        "not evidence of improvement unless the reason each item left is recorded."
    ),
    (
        "**The complexity alarm.** Stop feature work and simplify when assurance or support code "
        "materially exceeds the mechanism it governs, or when three review cycles find defects in "
        "the same structural class. The response is lower complexity, not lower assurance."
    ),
    "## What this document does not do",
    (
        "It does not authorize anything. It does not establish that any milestone was correctly "
        "tiered, that a declared tier was honoured, or that a rehearsal was faithful. Those are "
        "claims a reviewer checks against evidence, and this document is not evidence for them."
    ),
    (
        "It sets no schedule and predicts no duration. A tier is a floor on proof, never a budget "
        "for it."
    ),
)

_PINNED_DOCUMENT = (
    *_BEFORE_ESCALATION,
    "## Escalation triggers",
    *_PINNED_ESCALATION,
    *_AFTER_ESCALATION,
)

_LIST_ITEM = re.compile(r"^\s*(?:\d+[.)]|[-*+])\s+")
_ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*(?:#+[ \t]*)?$")
_SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
_HTML = re.compile(r"<(?:[!?/]|[A-Za-z][\w-]*[\s/>])")


def _collapse(text: str) -> str:
    return " ".join(text.split())


def _units(text: str) -> list[str]:
    """Each heading, table row, list item and paragraph, whitespace collapsed."""
    units: list[str] = []
    for block in re.split(r"\n[ \t]*\n", text.strip()):
        lines = block.splitlines()
        if all(line.lstrip().startswith("|") for line in lines):
            units.extend(_collapse(line) for line in lines)
        elif _LIST_ITEM.match(lines[0]):
            item: list[str] = []
            for line in lines:
                if _LIST_ITEM.match(line) and item:
                    units.append(_collapse(" ".join(item)))
                    item = []
                item.append(line)
            units.append(_collapse(" ".join(item)))
        else:
            units.append(_collapse(" ".join(lines)))
    return units


def _headings(lines: list[str]) -> list[tuple[int, int, str]]:
    """(line index, level, title) for every ATX and setext heading.

    Titles are compared with Unicode whitespace collapsed and case folded, so a
    heading cannot become a different one by spacing or capitals alone.
    """
    found = []
    for index, line in enumerate(lines):
        atx = _ATX.match(line)
        if atx:
            found.append((index, len(atx.group(1)), _collapse(atx.group(2) or "").casefold()))
        elif (
            index + 1 < len(lines)
            and line.strip()
            and not line.lstrip().startswith("|")
            and not _LIST_ITEM.match(line)
            and _SETEXT.match(lines[index + 1])
        ):
            level = 1 if lines[index + 1].strip()[0] == "=" else 2
            found.append((index, level, _collapse(line).casefold()))
    return found


def _section(title: str) -> str:
    """The body of the document's one `## title` section, up to the next H1 or H2.

    ATX and setext headings both count, compared as `_headings` compares them, so a
    second section with this title is found when its heading differs only in
    spacing, case, or ATX versus setext form.
    """
    lines = DOC.read_text(encoding="utf-8").splitlines(keepends=True)
    heads = _headings([line.rstrip("\n") for line in lines])
    wanted = _collapse(title).casefold()
    matches = [head for head in heads if head[1] == 2 and head[2] == wanted]
    assert len(matches) == 1, (
        f"ASSURANCE_TIERS.md has {len(matches)} '## {title}' sections; exactly one may "
        "state the rule, or a second one can override the first unseen"
    )
    index = matches[0][0]
    start = index + 1
    if not _ATX.match(lines[index].rstrip("\n")):
        start += 1  # a setext heading's underline
    end = next((head[0] for head in heads if head[0] >= start and head[1] <= 2), len(lines))
    return "".join(lines[start:end])


def _sectioned(units: list[str] | tuple[str, ...]) -> list[tuple[str, str]]:
    """Pair each unit with the heading it sits under, for a readable report."""
    current, paired = "(before the first heading)", []
    for unit in units:
        if unit.startswith("#"):
            current = unit
        paired.append((current, unit))
    return paired


def _difference(expected, actual) -> str:
    expected_pairs, actual_pairs = _sectioned(expected), _sectioned(actual)
    removed = [pair for pair in expected_pairs if pair[1] not in actual]
    added = [pair for pair in actual_pairs if pair[1] not in expected]
    lines = [f"  - under {section}: no longer present: {unit}" for section, unit in removed]
    lines += [f"  + under {section}: not in the pin: {unit}" for section, unit in added]
    if not lines:
        lines = ["  (the same units in a different order)"]
    return "\n".join(lines)


def _property_table() -> dict[str, str]:
    """{property: tier}, exactly as the document's escalation table states it."""
    rows = re.findall(
        r"^\|\s*([a-z][a-z-]*):[^|\n]*\|\s*([NHG])\s*\|\s*$",
        _section("Escalation triggers"),
        re.M,
    )
    assert rows, (
        "the escalation section carries no property table, so nothing states which "
        "properties escalate to which tier"
    )
    table: dict[str, str] = {}
    for name, tier in rows:
        assert name not in table, f"the escalation table lists {name!r} twice"
        table[name] = tier
    return table


def _terminal_tier(declared: str, properties: frozenset[str], process_trigger: bool) -> str:
    """Resolve a milestone's terminal tier through the DOCUMENT's rule.

    With no trigger nothing is resolved, so nothing is required. Otherwise each rule
    sentence is required before it is used: the highest-applicable-tier rule, the
    property table for a property, the one-step rule for a process trigger, and the
    both-kinds rule when the two combine. The arithmetic below is only the reading
    of those sentences; if the document stops saying them, the specimen fails
    rather than resolving through an assumption.
    """
    if not properties and not process_trigger:
        return declared
    units = _units(_section("Escalation triggers"))

    def require(rule: str, what: str) -> None:
        assert rule in units, f"the escalation section no longer states {what}: {rule!r}"

    require(_RULE, "that a re-tiered milestone goes to the highest tier any trigger requires")
    candidates = [_ORDER.index(declared)]
    if properties:
        table = _property_table()
        for name in properties:
            assert name in table, f"{name!r} is not a property the document's table names"
            candidates.append(_ORDER.index(table[name]))
    if process_trigger:
        require(_PROCESS_RULE, "that a process trigger moves a milestone up one tier")
        candidates.append(min(_ORDER.index(declared) + 1, len(_ORDER) - 1))
    if properties and process_trigger:
        require(_BOTH_KINDS, "that a process trigger never lowers a property trigger's tier")
    return _ORDER[max(candidates)]


def test_the_document_is_byte_for_byte_the_reviewed_text():
    """Any change to the document, anywhere, visible or not, fails until the pins change too."""
    data = DOC.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert (digest, len(data)) == (_PINNED_SHA256, _PINNED_BYTES), (
        f"ASSURANCE_TIERS.md is not the reviewed text: its sha256 begins {digest[:12]} and it "
        f"is {len(data)} bytes; the pin begins {_PINNED_SHA256[:12]} at {_PINNED_BYTES} bytes. "
        "Read the change with git diff, then update the text pin and this byte pin together "
        "in the same reviewed diff."
    )


def test_the_document_is_the_pinned_text_unit_by_unit():
    """The reviewed text itself, so a change to its words appears in the diff as sentences."""
    actual = _units(DOC.read_text(encoding="utf-8"))
    assert actual == list(_PINNED_DOCUMENT), (
        "ASSURANCE_TIERS.md is not the pinned text:\n"
        + _difference(_PINNED_DOCUMENT, actual)
        + "\nIf the change is deliberate, make it in the pinned units here too, in the same "
        "reviewed diff."
    )


def test_no_markup_that_can_hide_or_demote_text():
    """The document carries none of the markup the module docstring lists."""
    text = DOC.read_text(encoding="utf-8")
    lines = text.splitlines()
    problems = []
    if _HTML.search(text):
        problems.append("an HTML tag, comment, declaration or processing instruction")
    if "~~" in text:
        problems.append("strikethrough")
    for number, line in enumerate(lines, 1):
        previous = lines[number - 2] if number > 1 else ""
        if re.match(r"\s*(?:`{3,}|~{3,})", line):
            problems.append(f"line {number}: a code fence")
        if line.startswith("\t") or re.match(r" {4,}\S", line):
            problems.append(f"line {number}: indented four or more")
        if re.match(r"\s+(?:\d+[.)]|[-*+])\s", line):
            problems.append(f"line {number}: a nested list item")
        if (
            _SETEXT.match(line)
            and previous.strip()
            and not previous.lstrip().startswith("|")
            and not _LIST_ITEM.match(previous)
        ):
            problems.append(f"line {number}: a setext heading underline")
    # Whether the table exists is the table tests' question; this one asks only whether
    # what exists renders as one table.
    section = _section("Escalation triggers").splitlines()
    rows = [index for index, line in enumerate(section) if line.lstrip().startswith("|")]
    if rows and rows != list(range(rows[0], rows[0] + len(rows))):
        problems.append("the property table is split, so it does not render as one table")
    assert problems == [], "markup that can hide or demote text: " + "; ".join(problems)


def test_every_tier_g_property_escalates_directly_to_tier_g():
    """Each Tier G property is in the table, and each one resolves to G."""
    table = _property_table()
    assert set(table) == set(TIER_G_PROPERTIES), (
        "the escalation table does not name exactly the Tier G properties: "
        f"missing {sorted(TIER_G_PROPERTIES - set(table))}, "
        f"unexpected {sorted(set(table) - TIER_G_PROPERTIES)}"
    )
    not_g = {name: tier for name, tier in table.items() if tier != "G"}
    assert not_g == {}, (
        f"these Tier G properties escalate below Tier G: {not_g}. Work with its own "
        "Tier G property would end below the floor that property sets"
    )


def test_the_tier_g_heading_and_the_escalation_table_name_the_same_properties():
    """Two statements of one set, held to agree rather than trusted to."""
    heading = re.search(r"^### Tier G — (.+)$", DOC.read_text(encoding="utf-8"), re.M)
    assert heading, "ASSURANCE_TIERS.md has no Tier G heading in the expected form"
    named = {part.strip() for part in heading.group(1).split(",")}
    table = set(_property_table())
    assert named == table, (
        "the Tier G heading and the escalation table disagree about which properties "
        f"are Tier G: heading only {sorted(named - table)}, table only {sorted(table - named)}"
    )


@pytest.mark.parametrize(
    ("declared", "found"),
    [("N", "irreversible"), ("H", "authorization-consuming")],
)
def test_work_with_a_tier_g_property_is_tier_g_however_it_was_declared(declared, found):
    """The P1 itself: a stepwise rule resolves (N, irreversible) to H."""
    terminal = _terminal_tier(declared, frozenset({found}), process_trigger=False)
    assert terminal == "G", (
        f"work declared {declared} and found to be {found} resolves to Tier {terminal}; "
        "its own property requires Tier G"
    )


@pytest.mark.parametrize(
    ("declared", "found", "process_trigger", "expected"),
    [
        ("N", frozenset(), True, "H"),
        ("H", frozenset(), True, "G"),
        ("N", frozenset({"genesis"}), True, "G"),
        ("N", frozenset(), False, "N"),
    ],
    ids=[
        "a process trigger alone moves N one tier",
        "a process trigger alone moves H one tier",
        "a process trigger never lowers a property trigger",
        "no trigger, no move",
    ],
)
def test_a_process_trigger_moves_one_tier_and_never_lowers_a_property(
    declared, found, process_trigger, expected
):
    """The one-step move survives, for the triggers that are not Tier G properties."""
    assert _terminal_tier(declared, found, process_trigger) == expected


def test_the_document_states_that_tier_h_is_never_terminal_for_tier_g_work():
    """The invariant and its after-acceptance case are written, not only implied."""
    units = _units(_section("Escalation triggers"))
    for rule in (_INVARIANT, _AFTER_ACCEPTANCE):
        assert rule in units, f"the escalation section no longer states: {rule!r}"
