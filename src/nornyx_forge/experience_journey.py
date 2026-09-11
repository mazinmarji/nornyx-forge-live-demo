"""The basic-user journey: semantic actions mapped onto the Experience Contract.

WHAT THIS IS FOR. The onboarding surface offers a person a handful of
business-language actions -- start tracking, confirm the scope, start the
build, retry, mark ready. The Experience Contract offers stages, edges,
actors and evidence. This module is the one place the two meet, and its
whole discipline is that THE BROWSER CHOOSES AN ACTION, NEVER A STAGE:
each action names exactly one canonical transition (or none), the actor on
the request is judged by the contract's own KIND rule, and every evidence
reference presented to the contract is the translator's reading of a real
flow result, never a claim the caller typed.

The invariant the routes rely on, stated once: every recorded lifecycle
advancement comes from `experience.advance`, `experience.fail`,
`experience.retry` or `experience.start_experience`, under the actor and
evidence authority those functions already enforce. Nothing here writes a
stage, a status or a history event by hand, and nothing here catches a
refusal in order to try a quieter route in -- a refusal is returned to the
caller in the contract's own words.

WHAT THIS MODULE REFUSES TO KNOW. It never reads a provider's prose. A
worker result saying `tests_passed: true` or `ready: true` is not an input
to anything below; only the completed flow dictionary is, and only through
`experience_build.flow_evidence`, the single translator this repository
keeps for that mapping. It has no filesystem, no clock and no process:
timestamps and what the surface measured about BRD.md -- present, derived,
and its digest -- arrive as arguments, persistence belongs to the store,
and the surface composes the three. It computes no digest of its own, so
every hex string below is one the surface handed in.

`layer.application`, like `experience_build`: it interprets application
state and results and starts nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping

from .capsule import Actor, CapsuleTransitionError, CapsuleValidationError
from .experience import (
    TRANSITIONS,
    EvidenceRef,
    ExperienceError,
    advance,
    fail,
    retry,
    start_experience,
)
from .experience_build import flow_evidence

#: The actor under which the SURFACE ITSELF records evidence-driven
#: transitions (BUILD -> TEST -> GOVERN) and build failures. A system actor
#: by the contract's table; never a human, because no person made those
#: decisions, and never a model, because the table admits none.
SYSTEM_ACTOR = Actor(kind="system", ident="forge-onboarding")

#: The closed vocabulary of actions the surface offers, and the ONE stage
#: each may enter. `None` means the action moves no stage at all: `retry`
#: re-enters the failed stage, and `start_tracking` begins a lifecycle that
#: did not exist. A client cannot spell a destination that is not a value
#: here, and the routes look up the action, not the stage.
ACTION_TARGETS: Mapping[str, str | None] = {
    "start_tracking": "DISCOVER",
    "confirm_scope": "CONFIRM",
    "start_build": "BUILD",
    "retry": None,
    "mark_ready": "READY",
}

#: What READY consumes: the two proof kinds the contract requires for it,
#: taken from what GOVERN recorded rather than re-derived from anything.
READY_EVIDENCE_KINDS = ("gate_results", "governance_validation")

#: The prerequisites for the human scope confirmation, each named by the
#: thing that is missing. Derived from what the build already refuses by
#: name (a confirmed provider, a derived BRD) plus what the BRD derivation
#: itself refuses (a confirmed intent): confirming the scope means confirming
#: the exact inputs the build will consume, so all three must exist first.
_SCOPE_PREREQUISITES: tuple[tuple[str, str], ...] = (
    ("intent", "no confirmed intent: describe what you need and confirm the proposal"),
    ("provider", "no confirmed provider: propose an engineering agent and confirm it"),
)
_BRD_MISSING = "no derived BRD: derive it from the confirmed capsule before confirming the scope"

#: THE PREREQUISITE USED TO BE `BRD.md` EXISTING, and it was reported to the
#: reader as "a derived BRD". Measured on the parent through the real gated
#: surface: a BRD.md overwritten by hand after the scope confirmation was
#: accepted at CONFIRM and handed to the build, and a legacy project whose
#: BRD.md was never derived from anything confirmed the scope over it. The
#: file's EXISTENCE stood in for its DERIVATION -- a label standing in for
#: the thing measured, which is the substitution this repository keeps
#: finding. What is measured now is equality with the pure renderer over the
#: capsule beside the file, and these two name the failure of that equality
#: at the two places it matters.
_BRD_STALE = (
    "BRD.md does not match the confirmed capsule; derive it again before "
    "confirming the scope"
)
_BRD_STALE_BUILD = (
    "BRD.md does not match the confirmed capsule; derive it again before building"
)
#: The build route's own words for an absent BRD, kept here beside the stale
#: one so the route and the projection cannot drift apart on what the
#: prerequisite is called. Shorter than `_BRD_MISSING` because the build has
#: no scope confirmation to talk about; both sentences now live in one place.
_BRD_ABSENT_BUILD = "no BRD.md in the project; derive it first"

#: Every sentence the PROJECTION has for the state of `BRD.md`. They are one
#: measurement addressed to different next actions, so a position that offers
#: both a scope confirmation and a build lists one of them rather than the
#: same fact twice. `_BRD_ABSENT_BUILD` is deliberately absent: it is the
#: route's refusal and never appears in a blocker list.
_BRD_SENTENCES = (_BRD_MISSING, _BRD_STALE, _BRD_STALE_BUILD)


@dataclass(frozen=True)
class BrdState:
    """What the surface measured about `BRD.md`, as data this module reads.

    THREE FACTS, KEPT APART. `present` is whether the file is there;
    `derived` is whether its decoded text IS `brd_from_capsule` of the
    capsule beside it; `digest` names those bytes under the flow parser's
    own convention (`sha256` of the decoded text, without the `sha256:`
    prefix `parse_brd` puts on it). Keeping them apart is the whole point:
    the prerequisite that shipped conflated the first with the second.

    The digest arrives from the surface rather than being computed here,
    because this module has no filesystem and hashes nothing.
    """

    present: bool
    derived: bool
    digest: str | None

    @classmethod
    def absent(cls) -> BrdState:
        """No file. Nothing to name and nothing to compare."""
        return cls(present=False, derived=False, digest=None)

    @classmethod
    def matching(cls, digest: str) -> BrdState:
        """Present, and equal to the rendering of the confirmed capsule.

        NAMED `matching` AND NOT `derived`, which is what the work order
        asked for: `derived` is a FIELD of this dataclass, and a classmethod
        of that name in the class body is read by the dataclass machinery as
        that field's DEFAULT VALUE rather than as a constructor. The field
        keeps the name the surface publishes (`brd_derived`); the
        constructor takes the one that does not collide.
        """
        return cls(present=True, derived=True, digest=digest)

    @classmethod
    def stale(cls, digest: str | None) -> BrdState:
        """Present, and not that rendering. `digest` is `None` only when the
        bytes could not be decoded at all, which is present-and-unreadable
        rather than absent, and is refused for the same reason."""
        return cls(present=True, derived=False, digest=digest)


#: What the record says when it does not name the content in front of the
#: build. A refusal, not a warning: a scope confirmation given for one
#: capsule and one BRD does not license a build of another, and the surface
#: measured exactly that happening before this slice.
#:
#: ONE SENTENCE FOR TWO STATES, AND THE WORDING IS WHY. It covers a binding
#: that names OTHER content and a lifecycle that carries NO binding, and the
#: obvious phrasing -- "the scope was confirmed against different content" --
#: is false of the second: a record that names nothing has not been shown to
#: name something else, and asserting it would be the surface stating as fact
#: what it cannot see. What both states share is that the confirmation does
#: not name these bytes, so that is what it says.
_SCOPE_DRIFT = (
    "the scope confirmation does not name the capsule and the BRD this build "
    "would consume; confirm the scope again before building"
)
#: The re-confirmation self-edge exists for CHANGED content. Pressing it over
#: content the record already names moves nothing, and says so rather than
#: writing a second identical row.
_SCOPE_NO_OP = (
    "the scope confirmation already matches the capsule and the BRD; there is "
    "nothing to re-confirm"
)
#: A capsule with no digest chain cannot be named. Reachable from the domain
#: API with a malformed document; the store validates one before it lands.
_SCOPE_UNNAMEABLE = (
    "the capsule has no digest chain, so the scope confirmation has nothing to name"
)
#: A BUILD re-entry the record cannot bind. The contract declares no
#: BUILD -> BUILD edge, so re-entering carries no transition and there is
#: nothing for a new binding to ride on: a run whose content moved underneath
#: it is a DEAD END, named rather than re-bound. Disclosed in A-032.
_SCOPE_DRIFT_BUILD = (
    "the build was not recorded against the capsule and the BRD in the project "
    "now, so this lifecycle cannot re-run it"
)
#: READY over content the build never saw. Two states, two sentences, because
#: they are two different facts: the record says the content moved, or the
#: record says nothing at all about what the build consumed.
_SCOPE_DRIFT_READY = (
    "the capsule or the BRD changed after the build; READY would be recorded "
    "for content that is no longer there"
)
_SCOPE_UNBOUND_READY = (
    "the build recorded no scope binding, so READY would be recorded for "
    "content the record does not name"
)

#: The shape of a scope reference: the capsule's chain tip and the BRD's
#: digest, both sha256 hex. 141 characters, inside `EvidenceRef`'s 200-char
#: bound. Parsed rather than string-matched, so a reference in any other shape
#: -- including one a previous version wrote, of which there are none -- reads
#: as NO BINDING and fails closed instead of half-matching.
SCOPE_REF = re.compile(r"^capsule/([0-9a-f]{64})/brd/([0-9a-f]{64})$")

#: The shape `experience_build` gives a `flow_run` reference when the flow
#: recorded which BRD it parsed. Read the same way and for the same reason:
#: a reference in any other shape says nothing, and nothing is inferred.
FLOW_BRD_REF = re.compile(r"^flow/[A-Za-z0-9._-]+/brd/([0-9a-f]{64})$")

#: The flow's own statement of what it read, disagreeing with what the build
#: was licensed to consume. Not a claim that either is wrong -- only that the
#: two do not describe the same bytes, which is enough to refuse a completion
#: claim over them.
_FLOW_BRD_MISMATCH = (
    "the flow parsed a BRD other than the one the build was licensed to consume"
)


class JourneyRefusal(CapsuleTransitionError):
    """The action cannot be performed from this state. Nothing moved."""


# ---------------------------------------------------------------------------
# What a lifecycle position is ABOUT: the content it names, and the content
# that is there now. Two tuples and a comparison; no digest is computed here.
# ---------------------------------------------------------------------------

def scope_current(document: Mapping[str, Any], brd: BrdState) -> tuple[str, str] | None:
    """The content a scope confirmation would name right now, or `None` when
    it cannot be named -- no capsule chain, or no readable BRD."""
    chain = document.get("digest_chain")
    tip = chain[-1] if isinstance(chain, list) and chain else None
    if not isinstance(tip, str) or brd.digest is None:
        return None
    return (tip, brd.digest)


def scope_ref(document: Mapping[str, Any], brd: BrdState) -> str | None:
    """That same pair as one resolvable reference, or `None`.

    The capsule half is the chain tip, which is ALREADY a content digest --
    `sha256(previous | canonical(authoritative))` -- so the reference names
    the confirmed region rather than a revision number that could point
    anywhere. The BRD half is the digest the surface measured under the flow
    parser's own convention.
    """
    current = scope_current(document, brd)
    return None if current is None else f"capsule/{current[0]}/brd/{current[1]}"


def scope_binding(state: Mapping[str, Any], stage: str) -> tuple[str, str] | None:
    """The content the record says `stage` was entered over, or `None`.

    The LAST parsing `brd_requirements` row wins, because a re-confirmation
    appends rather than replaces and the most recent one is the binding. A row
    whose reference does not parse is not a binding: it is read as absent, and
    everything that consults this then fails closed.
    """
    for row in reversed(list(state.get("evidence", {}).get(stage, []))):
        if row.get("kind") != "brd_requirements":
            continue
        found = SCOPE_REF.match(str(row.get("ref", "")))
        if found:
            return (found.group(1), found.group(2))
    return None


def flow_brd_digest(state: Mapping[str, Any]) -> str | None:
    """The BRD the FLOW said it parsed, read back from what TEST recorded.

    This is the run's own statement, translated by `experience_build` from
    `requirements_model.source_digest` and never re-derived here. A run that
    recorded none yields `None`, and the comparison that consumes it is then
    simply not made -- an absence, not a pass and not a failure.
    """
    for row in reversed(list(state.get("evidence", {}).get("TEST", []))):
        if row.get("kind") != "flow_run":
            continue
        found = FLOW_BRD_REF.match(str(row.get("ref", "")))
        if found:
            return found.group(1)
    return None


def _contract_would_accept(state: Mapping[str, Any], target: str) -> bool:
    """Whether the contract's own table admits this edge from here, and the
    workflow is in a position to take it.

    Read from `TRANSITIONS` rather than re-implemented, and consulted so that
    a journey-level content check never PRE-EMPTS a contract refusal: a build
    requested from DISCOVER, or from a failed stage, gets the contract's
    answer, which is the one that is true of the request.
    """
    return target in TRANSITIONS[state["stage"]] and state["status"] == "active"


def _scope_evidence(document: Mapping[str, Any], brd: BrdState) -> EvidenceRef:
    """One `brd_requirements` reference for the content that is there now.

    Every caller reaches this only once the BRD half is known to exist -- the
    blockers guarantee it for a scope confirmation, and the binding
    comparison guarantees it for a build -- so the one way the reference can
    fail to form is a capsule with no chain, which is what the refusal names.
    """
    ref = scope_ref(document, brd)
    if ref is None:
        raise JourneyRefusal(_SCOPE_UNNAMEABLE)
    # `passed` is the MEASUREMENT, not a constant: a BRD that is not the
    # capsule's rendering presents failing evidence, which the contract
    # refuses outright rather than recording as a weaker pass.
    return EvidenceRef(kind="brd_requirements", ref=ref, passed=brd.derived)


# ---------------------------------------------------------------------------
# The actions. Each is a thin, named mapping onto one contract call.
# ---------------------------------------------------------------------------

def _brd_blocker(brd: BrdState, stale: str) -> str | None:
    """Absent, stale, or nothing to say -- in the words of one caller."""
    if not brd.present:
        return _BRD_MISSING
    return None if brd.derived else stale


def scope_blockers(document: Mapping[str, Any], brd: BrdState) -> tuple[str, ...]:
    """What still stands between this project and a scope confirmation."""
    authoritative = document.get("authoritative", {})
    missing = [why for field, why in _SCOPE_PREREQUISITES if field not in authoritative]
    blocker = _brd_blocker(brd, _BRD_STALE)
    if blocker is not None:
        missing.append(blocker)
    return tuple(missing)


def build_brd_refusal(brd: BrdState) -> str | None:
    """The build route's BRD prerequisite, or `None` when it is met.

    The route enforces independently of the projection, and both must say
    the same thing about the same file: this is the one place either gets
    the sentence from.
    """
    if not brd.present:
        return _BRD_ABSENT_BUILD
    return None if brd.derived else _BRD_STALE_BUILD


def build_blockers(document: Mapping[str, Any], brd: BrdState) -> tuple[str, ...]:
    """What the build route refuses by name: a confirmed provider and a
    derived BRD. The route enforces these itself; the projection reads them
    so the page offers only what the route would accept."""
    authoritative = document.get("authoritative", {})
    missing = [why for field, why in _SCOPE_PREREQUISITES if field == "provider"
               and field not in authoritative]
    blocker = _brd_blocker(brd, _BRD_STALE_BUILD)
    if blocker is not None:
        missing.append(blocker)
    return tuple(missing)


def start_tracking(actor: Actor, at: str) -> dict[str, Any]:
    """Begin a lifecycle at DISCOVER for a project that has none.

    Used for a fresh project and for a capsule that predates lifecycle
    tracking alike. In neither case is any later stage inferred from what
    the capsule or the project directory contains: the lifecycle begins
    where the contract says lifecycles begin, and the contract itself
    refuses a non-human starter.
    """
    return start_experience(actor, at)


def confirm_scope(
    state: Mapping[str, Any],
    document: Mapping[str, Any],
    brd: BrdState,
    actor: Actor,
    at: str,
) -> dict[str, Any]:
    """The scope confirmation: lifecycle CONFIRM, over content it names.

    Distinct from confirming a capsule proposal, which moves one field into
    authority. This records that the confirmed intent, the confirmed
    provider and the DERIVED BRD together are the scope to build -- so it
    refuses, by name, while any of the three is missing or the BRD is not
    that derivation, and then asks the contract, which refuses every actor
    kind but a human.

    WHAT IT NOW RECORDS. One `brd_requirements` reference naming the
    capsule's chain tip and the BRD's digest -- the content the build is
    thereby licensed to consume. From CONFIRM this is a RE-confirmation over
    content that changed; over content the record already names it is a
    no-op and is refused, so "recorded once" survives the new self-edge.
    """
    blockers = scope_blockers(document, brd)
    if blockers:
        raise JourneyRefusal("the scope cannot be confirmed yet: " + "; ".join(blockers))
    evidence = _scope_evidence(document, brd)
    if (state["stage"] == "CONFIRM"
            and scope_binding(state, "CONFIRM") == scope_current(document, brd)):
        raise JourneyRefusal(_SCOPE_NO_OP)
    return advance(state, ACTION_TARGETS["confirm_scope"], actor, at, (evidence,))


def begin_build(
    state: Mapping[str, Any],
    document: Mapping[str, Any],
    brd: BrdState,
    actor: Actor,
    at: str,
) -> tuple[dict[str, Any], bool]:
    """Position the lifecycle at BUILD for a run that is about to start.

    Returns the state and whether it advanced. From CONFIRM (or ARCHITECT)
    the contract is asked to enter BUILD under the actor who pressed the
    button. A lifecycle already AT BUILD and active is re-entered without a
    transition -- that is the state a retried failure leaves, and the state
    an interrupted server leaves -- because the contract declares no
    BUILD -> BUILD edge and the stage is already the right one. Every other
    position, including a failed one, is put to the contract, whose refusal
    is the caller's answer.

    AND THE SCOPE CONFIRMATION HAS TO BE ABOUT THIS CONTENT. The record's
    `brd_requirements` binding is compared with the capsule and BRD in front
    of the build; an absent binding and a differing one are both refused,
    which is fail-closed for a lifecycle written before bindings existed.
    One scope confirmation clears it.

    THE CONTRACT STILL SPEAKS FIRST FOR EVERYTHING THAT IS ITS BUSINESS. The
    binding is only consulted where the contract would ACCEPT the edge --
    read from its own table, not re-implemented here -- so a build from
    DISCOVER is still refused as "no transition DISCOVER -> BUILD" and a
    failed lifecycle is still told to retry. A journey-level refusal that
    pre-empted those would be answering a question the caller did not reach.

    AND THE TRANSITION CARRIES THE BINDING FORWARD. BUILD requires no
    evidence -- the contract asks for none -- but `advance` stores what is
    presented, so the run's own record says what it was licensed to consume.
    A RE-ENTRY cannot do that: there is no BUILD -> BUILD edge to carry a new
    row, so a re-entry whose content moved is a dead end and says so.
    """
    current = scope_current(document, brd)
    if state["stage"] == "BUILD" and state["status"] == "active":
        recorded = scope_binding(state, "BUILD")
        if current is None or recorded is None or recorded != current:
            raise JourneyRefusal(_SCOPE_DRIFT_BUILD)
        return dict(state), False
    if not _contract_would_accept(state, ACTION_TARGETS["start_build"]):
        # NOTHING TO ADD, so nothing is added -- and the reference is not
        # BUILT either. Constructing it here was a real defect: argument
        # evaluation precedes the call, so a build requested from DISCOVER
        # with no BRD raised "the capsule has no digest chain" -- a refusal
        # naming a cause nobody measured -- in place of the contract's "there
        # is no transition DISCOVER -> BUILD". The edge is not declared from
        # here, or the workflow is failed and has to be retried first; either
        # way the answer belongs to the contract.
        return advance(state, ACTION_TARGETS["start_build"], actor, at), True
    recorded = scope_binding(state, "CONFIRM")
    if current is None or recorded is None or recorded != current:
        raise JourneyRefusal(_SCOPE_DRIFT)
    # `current` is not None here, so the reference can be formed.
    return advance(state, ACTION_TARGETS["start_build"], actor, at,
                   (_scope_evidence(document, brd),)), True


def build_outcome(
    state: Mapping[str, Any],
    result: Any,
    clock: Callable[[], str],
) -> Iterator[tuple[dict[str, Any], str]]:
    """The lifecycle consequences of one completed flow run, one persisted
    state at a time.

    Evidence-driven and system-performed: `flow_run` licenses TEST,
    `gate_results` licenses GOVERN, and the governance-validation reference
    -- when the translator produced one -- is recorded alongside GOVERN so a
    later human READY can consume it after a restart. Each step is the
    contract's decision, asked in memory first: only a run every step of
    which the contract licenses is persisted, stage by stage, and a run the
    contract refuses anywhere is recorded as ONE failure of the stage the
    run started from, in the contract's own words -- because the contract
    declares no edge back from TEST, so a failure persisted there could
    never be re-run. GOVERN is where this stops. READY is not a system act.
    """
    try:
        refs = flow_evidence(result)
    except CapsuleValidationError as error:
        yield (
            fail(state, SYSTEM_ACTOR, _reason("the build produced no usable evidence", error), clock()),
            "build result unusable",
        )
        return
    by_kind = {ref.kind: ref for ref in refs}
    steps: tuple[tuple[str, tuple[EvidenceRef, ...]], ...] = (
        ("TEST", (by_kind["flow_run"],)),
        ("GOVERN", tuple(by_kind[kind] for kind in READY_EVIDENCE_KINDS if kind in by_kind)),
    )
    licensed: list[tuple[dict[str, Any], str]] = []
    current: Mapping[str, Any] = state
    for stage, evidence in steps:
        try:
            current = advance(current, stage, SYSTEM_ACTOR, clock(), evidence)
        except ExperienceError as error:
            yield fail(state, SYSTEM_ACTOR, _reason("refused", error), clock()), (
                f"failed at {state['stage']}"
            )
            return
        licensed.append((current, f"reached {stage}"))
    yield from licensed


def build_error(state: Mapping[str, Any], error: str, at: str) -> dict[str, Any]:
    """A run that raised or never completed: the stage failed, and says why."""
    return fail(state, SYSTEM_ACTOR, _reason("the build did not complete", error), at)


def retry_after_failure(state: Mapping[str, Any], actor: Actor, at: str) -> dict[str, Any]:
    """Re-enter the failed stage. The contract's retry, nothing beside it."""
    return retry(state, actor, at)


def ready_evidence(state: Mapping[str, Any]) -> tuple[EvidenceRef, ...]:
    """The proofs READY consumes, read back from what GOVERN recorded.

    Never re-derived and never read from a build result held in memory: the
    persisted lifecycle is the only source, so a server restart between
    GOVERN and READY loses nothing, and a governance validation that was
    never recorded is simply not presented -- the contract then refuses,
    which is the honest outcome for a build that never asked the question.
    """
    latest: dict[str, EvidenceRef] = {}
    for row in state.get("evidence", {}).get("GOVERN", []):
        if row["kind"] in READY_EVIDENCE_KINDS:
            latest[row["kind"]] = EvidenceRef(kind=row["kind"], ref=row["ref"], passed=row["passed"])
    return tuple(latest[kind] for kind in READY_EVIDENCE_KINDS if kind in latest)


def ready_scope_refusal(
    state: Mapping[str, Any], document: Mapping[str, Any], brd: BrdState
) -> str | None:
    """Why READY may not be recorded over this content, or `None`.

    Compared against what the BUILD transition recorded, because that is what
    the run was licensed to consume -- CONFIRM's binding could have been
    re-confirmed after the build and would then say nothing about it. An
    ABSENT binding and a DIFFERING one are two different facts and get two
    different sentences; neither is a claim about the other.

    AND THE RUN GETS A SAY. Where the flow recorded which BRD it parsed, that
    is compared with the same binding: a run that read something else was not
    doing what the build was licensed to do, whatever the record says about
    the disk. A run that recorded nothing is not judged for it.
    """
    recorded = scope_binding(state, "BUILD")
    if recorded is None:
        return _SCOPE_UNBOUND_READY
    if recorded != scope_current(document, brd):
        return _SCOPE_DRIFT_READY
    parsed = flow_brd_digest(state)
    return None if parsed is None or parsed == recorded[1] else _FLOW_BRD_MISMATCH


def mark_ready(
    state: Mapping[str, Any],
    document: Mapping[str, Any],
    brd: BrdState,
    actor: Actor,
    at: str,
) -> dict[str, Any]:
    """The human completion claim: lifecycle READY, with GOVERN's evidence.

    Refused over content the build never saw. What READY claims is that THIS
    lifecycle completed -- and a completion claim recorded beside a capsule
    and a BRD the run was not licensed to consume is a claim about something
    that did not happen. As everywhere here, the contract speaks first for
    positions from which READY is not an edge at all.
    """
    if _contract_would_accept(state, ACTION_TARGETS["mark_ready"]):
        refusal = ready_scope_refusal(state, document, brd)
        if refusal is not None:
            raise JourneyRefusal(refusal)
    return advance(state, ACTION_TARGETS["mark_ready"], actor, at, ready_evidence(state))


# ---------------------------------------------------------------------------
# The projection the page renders. Reads the contract's tables; decides nothing.
# ---------------------------------------------------------------------------

#: Fixed application text for each position, in business language. This is
#: the surface describing where the lifecycle is and what a person can do
#: next -- ordinary status, not governance. What governs the project is
#: rendered elsewhere, from the contracts, by the deterministic renderer.
_NEXT: Mapping[str, str] = {
    "DISCOVER": (
        "Describe what you need and confirm it, choose your engineering agent "
        "and confirm it, derive the BRD, then confirm the scope."
    ),
    "CONFIRM": "The scope is confirmed. Start the build.",
    "BUILD": "The build is running; its result will move the lifecycle when it completes.",
    "TEST": "The build's flow evidence has been recorded; its gate results are next.",
    "GOVERN": (
        "The build's gate results have been recorded. Marking ready is your act: "
        "it needs the gate results and a Nornyx governance validation from this build."
    ),
    # "a person confirmed it" stood here, and it was the stop route's retired
    # sentence in another costume: this is not a refusal but the page's own
    # account of what READY MEANS, so the unbacked claim was being told to the
    # reader as settled fact.
    #
    # THE FIRST REPLACEMENT WAS MORE SPECIFIC AND THEREFORE MORE FALSE. It read
    # "this run's session holder confirmed it". But `journey_view` renders this
    # from the PERSISTED stage -- its own docstring says so -- and the bearer is
    # PER RUN. Its whole input is the record plus the document: no request, no
    # session and no bearer reaches it, so nothing written here can be about the
    # reader's run at all. A READY persisted in an earlier run is therefore
    # served to a later reader as something "this run's session holder" did, and
    # for any project reopened after a restart -- the ordinary case -- nobody
    # present did it. Making an unbacked claim more precise about something the
    # code cannot see makes it worse, not better.
    #
    # SO IT DEFERS TO THE RECORD, which is the one thing this projection reads.
    # `experience.advance` writes `by` and `kind` into `entered` and appends
    # them to `history` on every transition, READY included, so "the ident
    # recorded in this project's history" names an artifact the reader can go
    # and look at. It says nothing about WHO that ident belongs to -- it is an
    # unauthenticated self-declaration, A-030 -- and that is exactly why it is
    # the honest referent: it points at the record instead of interpreting it.
    #
    # "a Forge session holder confirmed it" was the other candidate and was
    # rejected. The persisted record does not record that a bearer was ever
    # presented, and `mark_ready` is reachable from the importable domain with
    # no surface in front of it, so the page would be asserting an admission
    # path it cannot see -- unbacked in the same way, one step less visibly.
    #
    # The disclaimer that follows is unchanged and still the load-bearing half.
    # Pinned in the affirmative by
    # `test_the_ready_line_defers_to_the_record_and_claims_nobody`, because a
    # forbidden-phrase list alone let a synonym back into this exact site.
    "READY": (
        "READY has been recorded: the build's gate results and governance validation "
        "licensed it and the ident recorded in this project's history confirmed it. "
        "READY is this lifecycle's completion claim and nothing more -- not "
        "deployment, not production approval, not an independent inspection."
    ),
}
_NEXT_OUTSIDE_PATH = (
    "This stage is not part of the basic-user path; the actions below are the "
    "ones the contract still allows from it."
)
_BUILD_NOT_RUNNING = (
    "The lifecycle is at BUILD, but no build is running in this server session. "
    "Start the build again to run it."
)
_READY_UNREACHABLE = (
    "no Nornyx governance validation was recorded by this build, so READY cannot "
    "be reached for this lifecycle; a build whose acceptance profile runs no "
    "Nornyx gate produces none"
)
_TRACKING_ABSENT = (
    "This project has no recorded lifecycle. Start tracking to begin at DISCOVER; "
    "no earlier progress is inferred from the project's files."
)
_NEXT_SCOPE_DRIFT = (
    "The capsule or the BRD has changed since the scope was confirmed. Confirm "
    "the scope again to record what the build may consume."
)

#: What the page says about the record's referent. Three sentences for three
#: states, and each says what was COMPARED rather than what it means: a digest
#: that matches establishes that the bytes are the ones the record names, and
#: nothing at all about whether they were read (A-032). The page does not
#: display the BRD.
_SCOPE_UNBOUND_SUMMARY = (
    "This lifecycle's record does not name the content it was recorded against."
)
_SCOPE_MATCHES_SUMMARY = (
    "The record names the capsule and the BRD that are in the project now."
)
_SCOPE_DIFFERS_SUMMARY = (
    "The capsule or the BRD has changed since the record was written, so the "
    "record names content that is no longer there."
)


def _fingerprint(pair: tuple[str, str] | None) -> dict[str, str] | None:
    """A pair of digests, shortened for a reader. Eight hex characters each:
    enough to see two of them differ, and never presented as an identifier
    anything resolves -- the full reference lives in the record."""
    return None if pair is None else {"capsule": pair[0][:8], "brd": pair[1][:8]}


def _scope_projection(
    experience: Mapping[str, Any] | None,
    document: Mapping[str, Any],
    brd: BrdState,
) -> dict[str, Any]:
    """What the record was recorded against, what is there now, and whether
    they are the same -- as DATA, with the difference reported rather than
    interpreted.

    The BUILD binding is preferred over CONFIRM's because it is the later
    statement of the same thing: what the build was licensed to consume.
    Before BUILD there is none, and the scope confirmation's own binding is
    what the reader is looking at.
    """
    recorded = None
    if experience is not None:
        recorded = scope_binding(experience, "BUILD") or scope_binding(experience, "CONFIRM")
    current = scope_current(document, brd)
    unchanged = None if recorded is None else recorded == current
    return {
        "confirmed_against": _fingerprint(recorded),
        "current": _fingerprint(current),
        "unchanged": unchanged,
        "summary": (
            _SCOPE_UNBOUND_SUMMARY if unchanged is None
            else _SCOPE_MATCHES_SUMMARY if unchanged
            else _SCOPE_DIFFERS_SUMMARY
        ),
    }


def journey_view(
    experience: Mapping[str, Any] | None,
    document: Mapping[str, Any],
    brd: BrdState,
    build_running: bool,
    provider_blocker: str | None = None,
) -> dict[str, Any]:
    """What the page shows: the persisted position, the actions the contract
    allows from it, and what still blocks the ones it does not.

    Every `actions` entry is derived from the contract's own transition
    table, so the page enables exactly what the contract would accept -- as
    a convenience. The routes enforce independently; a request the page
    would not have offered gets the same refusal. `provider_blocker` is the
    surface's governed-eligibility verdict for the confirmed provider when
    that verdict is a refusal: the build is then not offered and the reason
    is listed, in the same words the build route refuses with.

    `scope` is what the record NAMES beside what is there now, reported as
    data. It is present in every shape this returns, including the ones with
    nothing to report, so the page renders one field rather than testing for
    its absence.
    """
    scope = _scope_projection(experience, document, brd)
    if experience is None:
        return {
            "tracking": "absent", "stage": None, "status": None,
            "actions": ["start_tracking"], "blockers": [], "failure": None,
            "scope": scope, "next": _TRACKING_ABSENT,
        }
    stage = experience["stage"]
    status = experience["status"]
    failure = None
    if status == "failed":
        failure = next(
            (event["detail"] for event in reversed(experience["history"]) if event["event"] == "failed"),
            "",
        )
        return {
            "tracking": "recorded", "stage": stage, "status": status,
            "actions": ["retry"], "blockers": [], "failure": failure,
            "scope": scope,
            "next": f"The workflow failed at {stage}. Retry to re-enter {stage}.",
        }

    allowed = TRANSITIONS[stage]
    build_reachable = "BUILD" in allowed or (stage == "BUILD" and not build_running)
    # THE ONE COMPARISON EVERY OFFER BELOW TURNS ON. `unchanged` is True only
    # when the record names content and that content is what is there; an
    # absent binding is `None` and is not a pass.
    bound = scope["unchanged"] is True
    actions: list[str] = []
    blockers: list[str] = []
    if "CONFIRM" in allowed:
        missing = list(scope_blockers(document, brd))
        # THE SAME FILE, NAMED ONCE. Both branches read the same `BrdState`
        # and each has its own sentence for the action it is about. Where
        # both branches run -- at CONFIRM, which allows a re-confirmation and
        # a build -- the reader is heading for the build, so the build's
        # sentence is the one that survives. The OFFER below still turns on
        # the full set: what is filtered is the reading, not the decision.
        blockers.extend(why for why in missing
                        if not (build_reachable and why in _BRD_SENTENCES))
        # From CONFIRM the edge is a RE-confirmation, and it is offered only
        # when there is something to re-confirm. Offering it over content the
        # record already names would put a button on the page for a request
        # `confirm_scope` refuses as a no-op.
        if not missing and not (stage == "CONFIRM" and bound):
            actions.append("confirm_scope")
    if build_reachable:
        missing = list(build_blockers(document, brd))
        if provider_blocker:
            missing.append(provider_blocker)
        if not missing and not bound:
            # Listed only once the BRD itself is settled: an absent or stale
            # BRD is already named, and saying both would report the same
            # fact twice in different words. At BUILD the refusal is the
            # re-entry one, because from BUILD there is no scope confirmation
            # to offer -- advice the route would not honour is worse than
            # none.
            missing.append(_SCOPE_DRIFT_BUILD if stage == "BUILD" else _SCOPE_DRIFT)
        blockers.extend(why for why in missing if why not in blockers)
        if not missing:
            actions.append("start_build")
    if "READY" in allowed:
        if not any(ref.kind == "governance_validation" for ref in ready_evidence(experience)):
            blockers.append(_READY_UNREACHABLE)
        else:
            refusal = ready_scope_refusal(experience, document, brd)
            if refusal is None:
                actions.append("mark_ready")
            else:
                blockers.append(refusal)

    if stage == "BUILD" and not build_running:
        next_text = _BUILD_NOT_RUNNING
    elif stage == "CONFIRM" and not bound:
        next_text = _NEXT_SCOPE_DRIFT
    else:
        next_text = _NEXT.get(stage, _NEXT_OUTSIDE_PATH)
    return {
        "tracking": "recorded", "stage": stage, "status": status,
        "actions": actions, "blockers": blockers, "failure": failure,
        "scope": scope, "next": next_text,
    }


def _reason(prefix: str, error: object) -> str:
    """A failure reason under the contract's 500-character bound."""
    return f"{prefix}: {error}"[:500]
