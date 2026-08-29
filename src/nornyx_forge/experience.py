"""The Forge Experience Contract: the project lifecycle as canonical data.

WHAT THIS IS FOR. Forge is becoming usable through more than one AI provider,
and the one thing providers must not be able to do is invent their own
workflow. The Experience Contract is the mechanism: the lifecycle's stages,
its legal transitions, who may perform each one, and what evidence each
advancement requires are all DATA in this module — not prose in a prompt, not
convention in an adapter. A provider that wants Forge to move forward has to
move it through these transitions, and the guards here decide, deterministically,
whether it may.

THE STAGES, and what each means:

    DISCOVER    the user is describing what they want
    UNDERSTAND  Forge's reading of the business is being assembled
    MODEL       processes and roles are being modelled
    PROPOSE     an application shape and authority boundaries are proposed
    CONFIRM     THE HUMAN GATE: the user confirms scope and authority
    ARCHITECT   the technical shape is fixed
    BUILD       the application is constructed
    TEST        deterministic gates run against what was built
    GOVERN      Nornyx governance validation of the built artifact
    SIMULATE    behaviour is exercised on sample cases before real use
    REVIEW      an independent read of the result
    READY       the completion claim — and therefore the most guarded word here

THE AUTHORITY RULE, one sentence: **a model actor never moves the workflow.**
Models propose CONTENT (through the capsule's `proposed` region); the workflow
position is moved by the system when deterministic evidence licenses it, and by
a human where the stage is a human decision (CONFIRM, READY). This is the
capsule's authority split applied to time: content authority and progress
authority are both things a model must not be able to manufacture.

EVIDENCE, not assertion. An advancement that requires evidence takes typed
evidence references — kind, ref, passed — and the guard checks the kinds and
their passed flags. What it does NOT do is re-run the gates: the contract
consumes evidence produced by the real runners (`gates.py`, the development
flow, Nornyx validation) via the application-layer translator in
`experience_build`. The guard's claim is exactly "the required evidence was
presented and reports passing", never "the gates passed" — the distinction the
evidence discipline in this repository exists to keep.

INTEGRITY. The state carries a digest chain in the same pattern as the capsule:
each transition extends sha256(prev + canonical(state-sans-chain)), and
`verify_experience` recomputes the last link. `READY` reached by editing a JSON
file fails closed as TAMPERED. The bound is the same as the capsule's and is
stated rather than implied away: a forger who rebuilds the entire chain defeats
in-document integrity, and detecting that belongs to the store's git history.

PURITY. `layer.domain`, like the capsule: no filesystem, no clock, no process,
no randomness. Timestamps arrive as parameters; persistence lives in the
store adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .capsule import Actor, CapsuleTamperError, CapsuleTransitionError, CapsuleValidationError

EXPERIENCE_SCHEMA_VERSION = 1

#: The canonical stage order. A tuple, because the order IS the contract.
STAGES = (
    "DISCOVER", "UNDERSTAND", "MODEL", "PROPOSE", "CONFIRM",
    "ARCHITECT", "BUILD", "TEST", "GOVERN", "SIMULATE", "REVIEW", "READY",
)

#: Stages that may not be skipped on any path to READY. The optional ones
#: (UNDERSTAND, MODEL, PROPOSE, SIMULATE, REVIEW) may be bypassed by the edges
#: below; these may not, because each is a distinct authority or evidence
#: moment: CONFIRM is the human scope decision, BUILD/TEST/GOVERN are the
#: construction and its two kinds of proof, READY is the claim.
MANDATORY_STAGES = ("DISCOVER", "CONFIRM", "BUILD", "TEST", "GOVERN", "READY")

#: Legal transitions. Forward edges only, plus the self-edge implied by retry
#: after failure. There is deliberately NO edge into READY except from GOVERN,
#: SIMULATE or REVIEW — a path that has not passed TEST and GOVERN cannot
#: spell READY at all, whatever evidence it claims.
TRANSITIONS: Mapping[str, tuple[str, ...]] = {
    "DISCOVER": ("UNDERSTAND", "MODEL", "PROPOSE", "CONFIRM"),
    "UNDERSTAND": ("MODEL", "PROPOSE", "CONFIRM"),
    "MODEL": ("PROPOSE", "CONFIRM"),
    "PROPOSE": ("CONFIRM",),
    "CONFIRM": ("ARCHITECT", "BUILD"),
    "ARCHITECT": ("BUILD",),
    "BUILD": ("TEST",),
    "TEST": ("GOVERN",),
    "GOVERN": ("SIMULATE", "REVIEW", "READY"),
    "SIMULATE": ("REVIEW", "READY"),
    "REVIEW": ("READY",),
    "READY": (),
}

#: Who may perform an advancement INTO each stage. `model` appears nowhere,
#: and that absence is the rule — checked structurally by a test, so adding it
#: anywhere becomes a visible, arguable diff.
STAGE_ACTORS: Mapping[str, tuple[str, ...]] = {
    "DISCOVER": ("human", "system"),
    "UNDERSTAND": ("human", "system"),
    "MODEL": ("human", "system"),
    "PROPOSE": ("human", "system"),
    "CONFIRM": ("human",),
    "ARCHITECT": ("human", "system"),
    "BUILD": ("human", "system"),
    "TEST": ("system", "human"),
    "GOVERN": ("system", "human"),
    "SIMULATE": ("system", "human"),
    "REVIEW": ("human", "system"),
    "READY": ("human",),
}

#: The closed vocabulary of evidence kinds. Growing it is a diff.
EVIDENCE_KINDS = (
    "brd_requirements",
    "flow_run",
    "gate_results",
    "governance_validation",
    "simulation_report",
    "review_record",
)

#: Evidence each stage REQUIRES on entry: every listed kind must be present
#: among the presented references and must report passed=True. Stages absent
#: here require none — their substance lives in the capsule as content, not
#: here as workflow proof.
STAGE_EVIDENCE: Mapping[str, tuple[str, ...]] = {
    "TEST": ("flow_run",),
    "GOVERN": ("gate_results",),
    "SIMULATE": ("governance_validation",),
    "REVIEW": ("governance_validation",),
    "READY": ("gate_results", "governance_validation"),
}

_REF_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_ISO_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")

GENESIS = "0" * 64


class ExperienceError(CapsuleTransitionError):
    """Base for workflow refusals, so callers may catch either family."""


@dataclass(frozen=True)
class EvidenceRef:
    """One piece of presented evidence: what kind, where it lives, what it says.

    `passed` is the evidence's own verdict, restated here so the guard can
    refuse without re-reading the artifact. The `ref` is expected to resolve
    (a gate name, a report path, a capsule revision) — resolution is the
    store's and the reviewers' business; the guard checks shape and verdict.
    """

    kind: str
    ref: str
    passed: bool

    def validate(self) -> None:
        if self.kind not in EVIDENCE_KINDS:
            raise CapsuleValidationError(
                f"evidence kind {self.kind!r} is not one of {EVIDENCE_KINDS}"
            )
        if not isinstance(self.ref, str) or not _REF_ID.match(self.ref):
            raise CapsuleValidationError(f"evidence ref {self.ref!r} is not acceptable")
        if not isinstance(self.passed, bool):
            raise CapsuleValidationError("evidence passed must be a bool")

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "ref": self.ref, "passed": self.passed}


# ---------------------------------------------------------------------------
# Canonical form and integrity
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _without_chain(state: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in state.items() if key != "chain"}


def _link(previous: str, state: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (previous + "|" + _canonical(_without_chain(state))).encode("utf-8")
    ).hexdigest()


def verify_experience(state: Mapping[str, Any]) -> None:
    """Fail closed if the state does not match its own chain.

    The same disclosed bound as the capsule: this detects any edit that does
    not rebuild the final link, and a full-chain rebuild is git history's to
    catch, not this function's.
    """
    chain = state.get("chain")
    if not isinstance(chain, list) or not chain:
        raise CapsuleTamperError("the experience chain is missing")
    previous = chain[-2] if len(chain) > 1 else GENESIS
    if chain[-1] != _link(previous, state):
        raise CapsuleTamperError(
            "the experience state does not match its digest chain; the workflow "
            "position was modified outside the contract and is not trusted"
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_TOP_KEYS = {"schema_version", "stage", "status", "entered", "evidence", "history", "chain"}
_STATUSES = ("active", "failed")


def validate_experience(state: Mapping[str, Any]) -> None:
    """Structure only; `verify_experience` handles integrity separately."""
    if not isinstance(state, Mapping):
        raise CapsuleValidationError("the experience state must be an object")
    unknown = set(state) - _TOP_KEYS
    if unknown:
        raise CapsuleValidationError(f"unknown experience keys: {sorted(unknown)}")
    missing = _TOP_KEYS - set(state)
    if missing:
        raise CapsuleValidationError(f"missing experience keys: {sorted(missing)}")
    if state["schema_version"] != EXPERIENCE_SCHEMA_VERSION:
        raise CapsuleValidationError(
            f"experience schema_version {state['schema_version']!r} is not "
            f"{EXPERIENCE_SCHEMA_VERSION}"
        )
    if state["stage"] not in STAGES:
        raise CapsuleValidationError(f"stage {state['stage']!r} is not a declared stage")
    if state["status"] not in _STATUSES:
        raise CapsuleValidationError(f"status {state['status']!r} is not permitted")

    entered = state["entered"]
    if not isinstance(entered, dict) or set(entered) != {"by", "kind", "at"}:
        raise CapsuleValidationError("entered must be an object with exactly {by, kind, at}")
    Actor(kind=entered["kind"], ident=entered["by"]).validate()
    _validate_at(entered["at"], "entered.at")

    evidence = state["evidence"]
    if not isinstance(evidence, dict):
        raise CapsuleValidationError("evidence must be an object keyed by stage")
    for stage, refs in evidence.items():
        if stage not in STAGES:
            raise CapsuleValidationError(f"evidence recorded for undeclared stage {stage!r}")
        if not isinstance(refs, list):
            raise CapsuleValidationError(f"evidence[{stage}] must be a list")
        for row in refs:
            if not isinstance(row, dict) or set(row) != {"kind", "ref", "passed"}:
                raise CapsuleValidationError(
                    "each evidence entry must be an object with exactly {kind, ref, passed}"
                )
            EvidenceRef(kind=row["kind"], ref=row["ref"], passed=row["passed"]).validate()

    history = state["history"]
    if not isinstance(history, list) or not history:
        raise CapsuleValidationError("history must be a non-empty list")
    for event in history:
        expected = {"event", "from", "to", "by", "kind", "at", "detail"}
        if not isinstance(event, dict) or set(event) != expected:
            raise CapsuleValidationError(
                "each history event must be an object with exactly "
                "{event, from, to, by, kind, at, detail}"
            )
        if event["event"] not in ("started", "advanced", "failed", "retried"):
            raise CapsuleValidationError(f"history event {event['event']!r} is not permitted")
        for field in ("from", "to"):
            if event[field] is not None and event[field] not in STAGES:
                raise CapsuleValidationError(f"history {field} {event[field]!r} is not a stage")
        Actor(kind=event["kind"], ident=event["by"]).validate()
        _validate_at(event["at"], "history.at")
        if not isinstance(event["detail"], str) or len(event["detail"]) > 500:
            raise CapsuleValidationError("history detail must be a string under 500 chars")

    chain = state["chain"]
    if not isinstance(chain, list) or not chain or not all(
        isinstance(link, str) and re.fullmatch(r"[0-9a-f]{64}", link) for link in chain
    ):
        raise CapsuleValidationError("chain must be a non-empty list of sha256 hex")


def _validate_at(value: Any, field: str = "at") -> None:
    if not isinstance(value, str) or not _ISO_AT.match(value):
        raise CapsuleValidationError(f"{field} must be an ISO-8601 UTC/offset timestamp")


# ---------------------------------------------------------------------------
# Transitions. Pure: state in, new state out; inputs never mutated.
# ---------------------------------------------------------------------------

def _copy(state: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(_canonical(state))


def _sealed(state: dict[str, Any]) -> dict[str, Any]:
    previous = state["chain"][-1] if state["chain"] else GENESIS
    state["chain"] = state["chain"] + [_link(previous, state)]
    validate_experience(state)
    verify_experience(state)
    return state


def start_experience(started_by: Actor, at: str) -> dict[str, Any]:
    """A new workflow, at DISCOVER. Starting is a human act, like creating a
    capsule: a project's lifecycle begins because a person began it."""
    started_by.validate()
    _validate_at(at)
    if started_by.kind != "human":
        raise ExperienceError("an experience is started by a human actor")
    state: dict[str, Any] = {
        "schema_version": EXPERIENCE_SCHEMA_VERSION,
        "stage": "DISCOVER",
        "status": "active",
        "entered": {"by": started_by.ident, "kind": started_by.kind, "at": at},
        "evidence": {},
        "history": [{
            "event": "started", "from": None, "to": "DISCOVER",
            "by": started_by.ident, "kind": started_by.kind, "at": at, "detail": "",
        }],
        "chain": [],
    }
    return _sealed(state)


def advance(
    state: Mapping[str, Any],
    to_stage: str,
    actor: Actor,
    at: str,
    evidence: Sequence[EvidenceRef] = (),
) -> dict[str, Any]:
    """The only way the workflow moves forward. Four refusals, in order:

      * integrity first — a tampered state advances nowhere;
      * the edge must be declared in TRANSITIONS;
      * the actor's KIND must be permitted for the target stage — and `model`
        is permitted for none, which is the progress-authority rule;
      * every evidence kind the target stage requires must be presented and
        must report passed=True. Presenting failing evidence is a refusal,
        not a downgrade: the caller's next honest move is `fail`, not a
        quieter route in.
    """
    actor.validate()
    _validate_at(at)
    validate_experience(state)
    verify_experience(state)

    if state["status"] != "active":
        raise ExperienceError(
            f"the workflow is {state['status']} at {state['stage']}; retry it "
            "before advancing"
        )
    current = state["stage"]
    if to_stage not in STAGES:
        raise CapsuleValidationError(f"stage {to_stage!r} is not a declared stage")
    if to_stage not in TRANSITIONS[current]:
        raise ExperienceError(
            f"there is no transition {current} -> {to_stage}; the contract "
            f"allows {current} -> {TRANSITIONS[current]}"
        )
    if actor.kind not in STAGE_ACTORS[to_stage]:
        raise ExperienceError(
            f"an actor of kind {actor.kind!r} may not advance the workflow into "
            f"{to_stage}; permitted kinds are {STAGE_ACTORS[to_stage]}"
        )

    presented: dict[str, EvidenceRef] = {}
    for item in evidence:
        item.validate()
        presented[item.kind] = item
    for required in STAGE_EVIDENCE.get(to_stage, ()):
        if required not in presented:
            raise ExperienceError(
                f"advancing into {to_stage} requires evidence of kind "
                f"{required!r}, which was not presented"
            )
        if not presented[required].passed:
            raise ExperienceError(
                f"the presented {required!r} evidence ({presented[required].ref}) "
                "reports failure; a failing proof does not license advancement"
            )

    updated = _copy(state)
    updated["stage"] = to_stage
    updated["entered"] = {"by": actor.ident, "kind": actor.kind, "at": at}
    if evidence:
        updated["evidence"].setdefault(to_stage, [])
        updated["evidence"][to_stage].extend(item.as_dict() for item in evidence)
    updated["history"].append({
        "event": "advanced", "from": current, "to": to_stage,
        "by": actor.ident, "kind": actor.kind, "at": at, "detail": "",
    })
    return _sealed(updated)


def fail(state: Mapping[str, Any], actor: Actor, reason: str, at: str) -> dict[str, Any]:
    """Record that the current stage failed. Any actor kind may report failure —
    refusing a model the ability to say 'this broke' would suppress the one
    thing models must always be allowed to do: surface bad news."""
    actor.validate()
    _validate_at(at)
    validate_experience(state)
    verify_experience(state)
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise CapsuleValidationError("a failure needs a reason under 500 chars")
    if state["status"] == "failed":
        raise ExperienceError("the workflow is already failed; retry it first")

    updated = _copy(state)
    updated["status"] = "failed"
    updated["history"].append({
        "event": "failed", "from": state["stage"], "to": state["stage"],
        "by": actor.ident, "kind": actor.kind, "at": at, "detail": reason.strip(),
    })
    return _sealed(updated)


def retry(state: Mapping[str, Any], actor: Actor, at: str) -> dict[str, Any]:
    """Re-enter the failed stage. Human or system; a model does not decide that
    work resumes, for the same reason it does not decide that work advances."""
    actor.validate()
    _validate_at(at)
    validate_experience(state)
    verify_experience(state)
    if state["status"] != "failed":
        raise ExperienceError("only a failed workflow can be retried")
    if actor.kind not in ("human", "system"):
        raise ExperienceError(
            f"an actor of kind {actor.kind!r} may not resume the workflow"
        )

    updated = _copy(state)
    updated["status"] = "active"
    updated["history"].append({
        "event": "retried", "from": state["stage"], "to": state["stage"],
        "by": actor.ident, "kind": actor.kind, "at": at, "detail": "",
    })
    return _sealed(updated)
