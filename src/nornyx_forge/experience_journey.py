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
timestamps and the "is a BRD present" fact arrive as arguments, persistence
belongs to the store, and the surface composes the three.

`layer.application`, like `experience_build`: it interprets application
state and results and starts nothing.
"""

from __future__ import annotations

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


class JourneyRefusal(CapsuleTransitionError):
    """The action cannot be performed from this state. Nothing moved."""


# ---------------------------------------------------------------------------
# The actions. Each is a thin, named mapping onto one contract call.
# ---------------------------------------------------------------------------

def scope_blockers(document: Mapping[str, Any], brd_present: bool) -> tuple[str, ...]:
    """What still stands between this project and a scope confirmation."""
    authoritative = document.get("authoritative", {})
    missing = [why for field, why in _SCOPE_PREREQUISITES if field not in authoritative]
    if not brd_present:
        missing.append(_BRD_MISSING)
    return tuple(missing)


def build_blockers(document: Mapping[str, Any], brd_present: bool) -> tuple[str, ...]:
    """What the build route refuses by name: a confirmed provider and a
    derived BRD. The route enforces these itself; the projection reads them
    so the page offers only what the route would accept."""
    authoritative = document.get("authoritative", {})
    missing = [why for field, why in _SCOPE_PREREQUISITES if field == "provider"
               and field not in authoritative]
    if not brd_present:
        missing.append(_BRD_MISSING)
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
    brd_present: bool,
    actor: Actor,
    at: str,
) -> dict[str, Any]:
    """The human scope confirmation: lifecycle CONFIRM.

    Distinct from confirming a capsule proposal, which moves one field into
    authority. This is the person saying the confirmed intent, the confirmed
    provider and the derived BRD together are the scope to build -- so it
    refuses, by name, while any of the three is missing, and then asks the
    contract, which refuses every actor kind but a human.
    """
    blockers = scope_blockers(document, brd_present)
    if blockers:
        raise JourneyRefusal("the scope cannot be confirmed yet: " + "; ".join(blockers))
    return advance(state, ACTION_TARGETS["confirm_scope"], actor, at)


def begin_build(
    state: Mapping[str, Any], actor: Actor, at: str
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
    """
    if state["stage"] == "BUILD" and state["status"] == "active":
        return dict(state), False
    return advance(state, ACTION_TARGETS["start_build"], actor, at), True


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


def mark_ready(state: Mapping[str, Any], actor: Actor, at: str) -> dict[str, Any]:
    """The human completion claim: lifecycle READY, with GOVERN's evidence."""
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
    "READY": (
        "READY has been recorded: the build's gate results and governance validation "
        "licensed it and a person confirmed it. READY is this lifecycle's completion "
        "claim and nothing more -- not deployment, not production approval, not an "
        "independent inspection."
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


def journey_view(
    experience: Mapping[str, Any] | None,
    document: Mapping[str, Any],
    brd_present: bool,
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
    """
    if experience is None:
        return {
            "tracking": "absent", "stage": None, "status": None,
            "actions": ["start_tracking"], "blockers": [], "failure": None,
            "next": _TRACKING_ABSENT,
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
            "next": f"The workflow failed at {stage}. Retry to re-enter {stage}.",
        }

    allowed = TRANSITIONS[stage]
    actions: list[str] = []
    blockers: list[str] = []
    if "CONFIRM" in allowed:
        missing = scope_blockers(document, brd_present)
        blockers.extend(missing)
        if not missing:
            actions.append("confirm_scope")
    if "BUILD" in allowed or (stage == "BUILD" and not build_running):
        missing = list(build_blockers(document, brd_present))
        if provider_blocker:
            missing.append(provider_blocker)
        blockers.extend(why for why in missing if why not in blockers)
        if not missing:
            actions.append("start_build")
    if "READY" in allowed:
        if any(ref.kind == "governance_validation" for ref in ready_evidence(experience)):
            actions.append("mark_ready")
        else:
            blockers.append(_READY_UNREACHABLE)

    if stage == "BUILD" and not build_running:
        next_text = _BUILD_NOT_RUNNING
    else:
        next_text = _NEXT.get(stage, _NEXT_OUTSIDE_PATH)
    return {
        "tracking": "recorded", "stage": stage, "status": status,
        "actions": actions, "blockers": blockers, "failure": failure,
        "next": next_text,
    }


def _reason(prefix: str, error: object) -> str:
    """A failure reason under the contract's 500-character bound."""
    return f"{prefix}: {error}"[:500]
