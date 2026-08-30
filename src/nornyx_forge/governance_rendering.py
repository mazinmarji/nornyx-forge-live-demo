"""Business-language governance as a deterministic rendering. Never authority.

WHAT THIS IS FOR. A basic user must be able to READ what governs their
project without reading a .nyx contract. The founder's correction C1 fixes
how that may work: the Nornyx contract is the authority; business language
is a DERIVED, DETERMINISTIC rendering of it with round-trip guards, and
model prose never becomes authority. This module is that rule as code.

Three properties carry the rule:

  * DERIVED, NOT WRITTEN. Every line of the rendered view is produced from
    contract facts by a fixed template. There is no free-text parameter, no
    prose slot, no way for a caller to add a sentence.
  * ROUND-TRIP CLOSED. The view parses back to exactly the facts it was
    rendered from. A dropped clause, a paraphrase, a reordering — each
    changes what parses, so each is detectable by comparison, and
    `verify_round_trip` performs that comparison for the shipped renderer.
  * STRICT ON THE WAY BACK. The parser accepts ONLY lines this module's own
    grammar produces. Injected prose — a model's, a tool's, anyone's — is a
    refused line, not absorbed content. The authority and scope sentences
    are verified verbatim, so a view whose disclaimer was tampered with does
    not parse at all.

The rendered scope is CLOSED and DISCLOSED: five construct kinds are shown
(project purpose, intents, agents with their bound policies, policy
forbid/require rules, and demanded human approvals), and every other
top-level construct in the contract is NAMED in the view's final section —
not silently omitted. Within rendered constructs, only the fields the scope
statement lists are shown; undeclared fields never leak into the view.

Absence is recorded, not implied: a contract with no approvals renders an
explicit absence sentence, never an empty gap a reader could misread.

`layer.domain`: pure functions over parsed mappings and strings. No file
I/O, no YAML parsing, no processes — the caller supplies the parsed
contract document.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

#: The construct kinds this view renders. Closed on purpose: growing the
#: rendered scope is a diff to this tuple, the template, the parser, and the
#: scope statement together — never a quiet extension.
RENDERED_CONSTRUCTS = ("project", "intents", "agents", "policies", "approvals")

_TITLE_PREFIX = "# Governance in plain language: "

_AUTHORITY_STATEMENT = (
    "DERIVED VIEW. This document is rendered from the governance contract and",
    "holds no authority of its own: the contract is the authority, and when",
    "the two disagree the contract wins. Every line below is produced from",
    "the contract by a fixed rule; this view has no slot for free text.",
)

_SCOPE_STATEMENT = (
    "Shown in this view: the project's purpose (name, purpose), its intents",
    "(name, goal), its agents (name, role, bound policy), each policy's",
    "forbid and require rules (name, deny, require), and the human approvals",
    "the contract demands (name, accountable authority, required for,",
    "approving roles). Every other governed construct is named in the final",
    "section, never silently omitted.",
)

_SECTION_HEADERS = (
    "## Purpose",
    "## Intents",
    "## Agents and their authority",
    "## Policies",
    "## Human approvals this contract demands",
    "## Governed constructs not shown in this view",
)

_ABSENCE_LINE = "None declared. Absence is recorded, not invented."


class RenderingError(Exception):
    """A document, fact set, or rendered view this module refuses."""


@dataclass(frozen=True)
class IntentFact:
    name: str
    goal: str


@dataclass(frozen=True)
class AgentFact:
    name: str
    role: str
    policy: str


@dataclass(frozen=True)
class PolicyFact:
    name: str
    deny: tuple[str, ...]
    require: tuple[str, ...]


@dataclass(frozen=True)
class ApprovalFact:
    name: str
    accountable_authority: str
    required_for: tuple[str, ...]
    required_roles: tuple[str, ...]


@dataclass(frozen=True)
class GovernanceFacts:
    project_name: str
    purpose: str
    intents: tuple[IntentFact, ...] = field(default_factory=tuple)
    agents: tuple[AgentFact, ...] = field(default_factory=tuple)
    policies: tuple[PolicyFact, ...] = field(default_factory=tuple)
    approvals: tuple[ApprovalFact, ...] = field(default_factory=tuple)
    #: Top-level contract keys outside RENDERED_CONSTRUCTS, sorted. These are
    #: governed content the view does not show and therefore must name.
    unrendered: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Extraction: contract document -> facts
# ---------------------------------------------------------------------------

def _required_str(container: Mapping[str, Any], key: str, where: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RenderingError(f"{where} needs a non-empty string {key!r}")
    return value


def _str_items(container: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = container.get(key, [])
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise RenderingError(f"{where} needs {key!r} to be a list of non-empty strings")
    return tuple(value)


def _entries(document: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], ...]:
    value = document.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise RenderingError(f"contract construct {key!r} must be a list of mappings")
    return tuple(value)


def facts_from_contract(document: Mapping[str, Any]) -> GovernanceFacts:
    """Project the governed facts this view renders out of a parsed contract.

    A projection, not an interpretation: fields the scope statement does not
    list are dropped here and never reach the rendering; construct kinds
    outside the rendered set survive as names in `unrendered`.
    """
    if not isinstance(document, Mapping):
        raise RenderingError("a contract document must be a mapping")
    project = document.get("project")
    if not isinstance(project, Mapping):
        raise RenderingError("the contract has no project mapping to render")

    intents = tuple(
        IntentFact(
            name=_required_str(entry, "name", "an intent"),
            goal=_required_str(entry, "goal", "an intent"),
        )
        for entry in _entries(document, "intents")
    )
    agents = tuple(
        AgentFact(
            name=_required_str(entry, "name", "an agent"),
            role=_required_str(entry, "role", "an agent"),
            policy=_required_str(entry, "policy", "an agent"),
        )
        for entry in _entries(document, "agents")
    )
    policies = tuple(
        PolicyFact(
            name=_required_str(entry, "name", "a policy"),
            deny=_str_items(entry, "deny", "a policy"),
            require=_str_items(entry, "require", "a policy"),
        )
        for entry in _entries(document, "policies")
    )
    approvals = tuple(
        ApprovalFact(
            name=_required_str(entry, "name", "an approval"),
            accountable_authority=_required_str(
                entry, "accountable_authority", "an approval"
            ),
            required_for=_str_items(entry, "required_for", "an approval"),
            required_roles=_str_items(entry, "required_roles", "an approval"),
        )
        for entry in _entries(document, "approvals")
    )
    unrendered = tuple(
        sorted(key for key in document if key not in RENDERED_CONSTRUCTS)
    )
    return GovernanceFacts(
        project_name=_required_str(project, "name", "the project"),
        purpose=_required_str(project, "purpose", "the project"),
        intents=intents,
        agents=agents,
        policies=policies,
        approvals=approvals,
        unrendered=unrendered,
    )


# ---------------------------------------------------------------------------
# Rendering: facts -> deterministic view
# ---------------------------------------------------------------------------

def _refuse_grammar_collisions(value: str, where: str, *, in_list: bool = False) -> str:
    """A value that could be mistaken for the view's own grammar is refused.

    Refusal beats escaping here: an escaped view stops being readable plain
    language, and an ambiguous one stops being parseable. The colliding
    strings are rare in real governance text and the refusal names them.
    """
    if "\n" in value or "\r" in value:
        raise RenderingError(f"{where} contains a line break and cannot be rendered")
    if "|" in value:
        raise RenderingError(f"{where} contains '|', the view's field separator")
    if value != value.strip():
        raise RenderingError(f"{where} has leading or trailing whitespace")
    if in_list and "," in value:
        raise RenderingError(f"{where} contains ',', the view's list separator")
    return value


def _tokens(values: tuple[str, ...], where: str) -> str:
    if not values:
        return "(none)"
    if "(none)" in values:
        raise RenderingError(f"{where} is the literal '(none)', the empty marker")
    return ", ".join(_refuse_grammar_collisions(v, where, in_list=True) for v in values)


def render_business(facts: GovernanceFacts) -> str:
    """The one deterministic template. Same facts, same bytes, every time."""
    check = _refuse_grammar_collisions
    lines: list[str] = []
    lines.append(_TITLE_PREFIX + check(facts.project_name, "the project name"))
    lines.append("")
    lines.extend(_AUTHORITY_STATEMENT)
    lines.append("")
    lines.extend(_SCOPE_STATEMENT)
    lines.append("")

    lines.append(_SECTION_HEADERS[0])
    lines.append("")
    purpose = check(facts.purpose, "the purpose")
    if purpose.startswith(("#", "-")) or purpose == _ABSENCE_LINE:
        raise RenderingError("the purpose collides with the view's grammar")
    lines.append(purpose)
    lines.append("")

    lines.append(_SECTION_HEADERS[1])
    lines.append("")
    if not facts.intents:
        lines.append(_ABSENCE_LINE)
    for intent in facts.intents:
        name = check(intent.name, "an intent name")
        if ": " in name:
            raise RenderingError("an intent name contains ': ', the view's separator")
        lines.append(f"- {name}: {check(intent.goal, 'an intent goal')}")
    lines.append("")

    lines.append(_SECTION_HEADERS[2])
    lines.append("")
    if not facts.agents:
        lines.append(_ABSENCE_LINE)
    for agent in facts.agents:
        name = check(agent.name, "an agent name")
        role = check(agent.role, "an agent role")
        for value, where in ((name, "an agent name"), (role, "an agent role")):
            if " -- " in value or "(bound to policy " in value:
                raise RenderingError(f"{where} collides with the view's grammar")
        lines.append(
            f"- {name} -- {role} "
            f"(bound to policy {check(agent.policy, 'an agent policy')})"
        )
    lines.append("")

    lines.append(_SECTION_HEADERS[3])
    lines.append("")
    if not facts.policies:
        lines.append(_ABSENCE_LINE)
    for policy in facts.policies:
        lines.append(
            f"- {check(policy.name, 'a policy name')}"
            f" | forbids: {_tokens(policy.deny, 'a deny rule')}"
            f" | requires: {_tokens(policy.require, 'a require rule')}"
        )
    lines.append("")

    lines.append(_SECTION_HEADERS[4])
    lines.append("")
    if not facts.approvals:
        lines.append(_ABSENCE_LINE)
    for approval in facts.approvals:
        lines.append(
            f"- {check(approval.name, 'an approval name')}"
            f" | accountable authority: "
            f"{check(approval.accountable_authority, 'an accountable authority')}"
            f" | required for: {_tokens(approval.required_for, 'a required-for entry')}"
            f" | approving roles: {_tokens(approval.required_roles, 'an approving role')}"
        )
    lines.append("")

    lines.append(_SECTION_HEADERS[5])
    lines.append("")
    if not facts.unrendered:
        lines.append(_ABSENCE_LINE)
    for key in facts.unrendered:
        lines.append(f"- {check(key, 'a construct name')}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parsing: view -> facts, refusing every line the template cannot produce
# ---------------------------------------------------------------------------

def _split_fields(line: str, expected: int, where: str) -> list[str]:
    parts = line[2:].split(" | ")
    if len(parts) != expected:
        raise RenderingError(f"{where} line does not match the view's grammar: {line!r}")
    return parts


def _strip_label(part: str, label: str, where: str) -> str:
    if not part.startswith(label):
        raise RenderingError(f"{where} line does not match the view's grammar: {part!r}")
    return part[len(label):]


def _untokens(rendered: str) -> tuple[str, ...]:
    if rendered == "(none)":
        return ()
    return tuple(rendered.split(", "))


def parse_business(text: str) -> GovernanceFacts:
    """Read a rendered view back to facts. Anything off-template is refused.

    Strictness is the point: a view someone appended prose to, softened the
    authority statement of, or hand-edited into a different shape does not
    parse at all — so downstream code can never mistake edited prose for
    governed facts.
    """
    lines = text.split("\n")
    index = 0

    def take() -> str:
        nonlocal index
        while index < len(lines) and lines[index] == "":
            index += 1
        if index >= len(lines):
            raise RenderingError("the view ended before its template did")
        line = lines[index]
        index += 1
        return line

    title = take()
    if not title.startswith(_TITLE_PREFIX):
        raise RenderingError("the view does not begin with the rendered title")
    project_name = title[len(_TITLE_PREFIX):]

    for expected in _AUTHORITY_STATEMENT + _SCOPE_STATEMENT:
        if take() != expected:
            raise RenderingError(
                "the authority or scope statement was altered; this view is "
                "not the renderer's output"
            )

    def section(header: str) -> list[str]:
        if take() != header:
            raise RenderingError(f"expected section header {header!r}")
        collected: list[str] = []
        nonlocal index
        while index < len(lines):
            line = lines[index]
            if line.startswith("## "):
                break
            index += 1
            if line:
                collected.append(line)
        return collected

    purpose_lines = section(_SECTION_HEADERS[0])
    if len(purpose_lines) != 1:
        raise RenderingError("the purpose section must hold exactly one line")
    purpose = purpose_lines[0]

    def entries(header: str, where: str) -> list[str]:
        body = section(header)
        if body == [_ABSENCE_LINE]:
            return []
        bad = [line for line in body if not line.startswith("- ")]
        if bad:
            raise RenderingError(
                f"{where} contains a line the renderer cannot produce: {bad[0]!r}"
            )
        return body

    intents = []
    for line in entries(_SECTION_HEADERS[1], "the intents section"):
        name, separator, goal = line[2:].partition(": ")
        if not separator:
            raise RenderingError(f"an intent line does not match the grammar: {line!r}")
        intents.append(IntentFact(name=name, goal=goal))

    agents = []
    for line in entries(_SECTION_HEADERS[2], "the agents section"):
        head, separator, tail = line[2:].partition(" -- ")
        if not separator or not tail.endswith(")"):
            raise RenderingError(f"an agent line does not match the grammar: {line!r}")
        role, separator, policy = tail[:-1].partition(" (bound to policy ")
        if not separator:
            raise RenderingError(f"an agent line does not match the grammar: {line!r}")
        agents.append(AgentFact(name=head, role=role, policy=policy))

    policies = []
    for line in entries(_SECTION_HEADERS[3], "the policies section"):
        name, deny, require = _split_fields(line, 3, "a policy")
        policies.append(PolicyFact(
            name=name,
            deny=_untokens(_strip_label(deny, "forbids: ", "a policy")),
            require=_untokens(_strip_label(require, "requires: ", "a policy")),
        ))

    approvals = []
    for line in entries(_SECTION_HEADERS[4], "the approvals section"):
        name, authority, required_for, roles = _split_fields(line, 4, "an approval")
        approvals.append(ApprovalFact(
            name=name,
            accountable_authority=_strip_label(
                authority, "accountable authority: ", "an approval"
            ),
            required_for=_untokens(
                _strip_label(required_for, "required for: ", "an approval")
            ),
            required_roles=_untokens(
                _strip_label(roles, "approving roles: ", "an approval")
            ),
        ))

    unrendered = []
    for line in entries(_SECTION_HEADERS[5], "the unrendered section"):
        unrendered.append(line[2:])

    while index < len(lines):
        if lines[index] != "":
            raise RenderingError(
                f"content after the view's template: {lines[index]!r}"
            )
        index += 1

    return GovernanceFacts(
        project_name=project_name,
        purpose=purpose,
        intents=tuple(intents),
        agents=tuple(agents),
        policies=tuple(policies),
        approvals=tuple(approvals),
        unrendered=tuple(unrendered),
    )


def verify_round_trip(document: Mapping[str, Any]) -> str:
    """Render a contract's facts and prove the view parses back to them.

    Returns the rendered view on success so callers gate on the guard and
    use its output in one step; raises RenderingError on any divergence.
    """
    facts = facts_from_contract(document)
    rendered = render_business(facts)
    recovered = parse_business(rendered)
    if recovered != facts:
        raise RenderingError(
            "the rendered view does not parse back to the facts it was "
            "rendered from; the renderer and parser disagree"
        )
    return rendered
