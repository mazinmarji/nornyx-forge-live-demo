"""The Experience Contract, proven in both directions.

THE PROPERTY UNDER TEST. The workflow's position must be movable (else Forge
never finishes anything) and must not be movable by the wrong authority or
without the required proof (else READY becomes a word a model or a JSON edit
can spell). Every test holds one edge:

  * the full legal path DISCOVER -> READY works, with evidence, for the right
    actors -- the permissive half;
  * a model actor advances NOTHING, structurally: the rule is checked against
    the declaration table itself, not one transition;
  * CONFIRM and READY are human-only;
  * no declared path reaches READY without passing TEST and GOVERN;
  * required evidence must be presented AND passing -- failing proof refuses;
  * a hand-edited stage fails closed as TAMPERED;
  * the flow translator never improves the news: accepted=False, a failing
    gate, or an absent Nornyx CLI all surface as exactly what they are.

Load-bearing guards are additionally revert-proven on isolated clones.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nornyx_forge.capsule import (
    Actor,
    CapsuleTamperError,
    CapsuleValidationError,
    create_document,
)
from nornyx_forge.capsule_store import CapsuleStore, CapsuleStoreError
from nornyx_forge.experience import (
    EVIDENCE_KINDS,
    MANDATORY_STAGES,
    STAGE_ACTORS,
    STAGE_EVIDENCE,
    STAGES,
    TRANSITIONS,
    EvidenceRef,
    ExperienceError,
    advance,
    fail,
    retry,
    start_experience,
    verify_experience,
)
from nornyx_forge.experience_build import flow_evidence

HUMAN = Actor(kind="human", ident="owner@example")
SYSTEM = Actor(kind="system", ident="forge-core")
MODEL = Actor(kind="model", ident="provider-codex")
AT = "2026-08-29T18:00:00Z"

GATES_OK = EvidenceRef(kind="gate_results", ref="gates/6-run", passed=True)
FLOW_OK = EvidenceRef(kind="flow_run", ref="flow/sequential", passed=True)
GOV_OK = EvidenceRef(kind="governance_validation", ref="gates/nornyx/5-run", passed=True)


def _at_stage(stage: str) -> dict:
    """A state legitimately advanced to `stage` along a legal path."""
    state = start_experience(HUMAN, AT)
    path = {
        "DISCOVER": [],
        "CONFIRM": [("CONFIRM", HUMAN, ())],
        "BUILD": [("CONFIRM", HUMAN, ()), ("BUILD", SYSTEM, ())],
        "TEST": [("CONFIRM", HUMAN, ()), ("BUILD", SYSTEM, ()), ("TEST", SYSTEM, (FLOW_OK,))],
        "GOVERN": [
            ("CONFIRM", HUMAN, ()), ("BUILD", SYSTEM, ()),
            ("TEST", SYSTEM, (FLOW_OK,)), ("GOVERN", SYSTEM, (GATES_OK,)),
        ],
    }[stage]
    for to, actor, evidence in path:
        state = advance(state, to, actor, AT, evidence)
    return state


# ---------------------------------------------------------------------------
# The declaration tables ARE the contract: structural properties first
# ---------------------------------------------------------------------------

def test_a_model_actor_may_advance_into_no_stage_at_all():
    """THE PROGRESS-AUTHORITY RULE, checked against the table itself.

    Testing one refused transition would prove one cell; the rule is the whole
    column. If anyone ever adds "model" to any stage's actor list, this fails
    and the addition becomes an argued diff rather than a quiet capability.
    """
    offenders = [stage for stage, kinds in STAGE_ACTORS.items() if "model" in kinds]
    assert offenders == [], (
        f"the declaration table permits a model actor to advance into "
        f"{offenders}; models propose content, they do not move the workflow"
    )
    # And the guard actually consults the table: a model is refused live, on a
    # transition that would otherwise be legal for a system actor.
    state = _at_stage("BUILD")
    with pytest.raises(ExperienceError, match="model"):
        advance(state, "TEST", MODEL, AT, (FLOW_OK,))


def test_every_stage_is_reachable_and_every_edge_lands_on_a_declared_stage():
    """The graph is closed and connected: no orphan stages, no edges to
    nowhere, and READY is reachable -- a lifecycle with an unreachable end
    state would make every completion claim vacuously false."""
    for stage, targets in TRANSITIONS.items():
        assert stage in STAGES
        for target in targets:
            assert target in STAGES, f"{stage} -> {target} lands outside STAGES"
    reachable = {"DISCOVER"}
    frontier = ["DISCOVER"]
    while frontier:
        for target in TRANSITIONS[frontier.pop()]:
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    assert reachable == set(STAGES), f"unreachable stages: {set(STAGES) - reachable}"


def test_no_declared_path_reaches_ready_without_test_and_govern():
    """Mandatory means structurally unavoidable, not strongly suggested.

    Walks EVERY simple path from DISCOVER to READY through the declared edges
    and asserts each one passes through every mandatory stage. The guard's
    per-edge checks then only have to be right locally; the global property is
    held here, against the table, where a new bypass edge would surface."""
    complete: list[list[str]] = []

    def walk(stage: str, path: list[str]) -> None:
        if stage == "READY":
            complete.append(path)
            return
        for target in TRANSITIONS[stage]:
            if target not in path:
                walk(target, path + [target])

    walk("DISCOVER", ["DISCOVER"])
    assert complete, "no path reaches READY at all"
    for path in complete:
        for mandatory in MANDATORY_STAGES:
            assert mandatory in path, (
                f"path {' -> '.join(path)} reaches READY without {mandatory}"
            )


def test_ready_and_confirm_are_human_only_in_the_table_and_live():
    assert STAGE_ACTORS["CONFIRM"] == ("human",)
    assert STAGE_ACTORS["READY"] == ("human",)

    state = start_experience(HUMAN, AT)
    with pytest.raises(ExperienceError, match="may not advance"):
        advance(state, "CONFIRM", SYSTEM, AT)

    governed = _at_stage("GOVERN")
    with pytest.raises(ExperienceError, match="may not advance"):
        advance(governed, "READY", SYSTEM, AT, (GATES_OK, GOV_OK))


def test_ready_requires_both_proof_kinds_present_and_passing():
    governed = _at_stage("GOVERN")

    with pytest.raises(ExperienceError, match="governance_validation"):
        advance(governed, "READY", HUMAN, AT, (GATES_OK,))

    failing_gov = EvidenceRef(kind="governance_validation", ref="gates/nornyx/5-run", passed=False)
    with pytest.raises(ExperienceError, match="reports failure"):
        advance(governed, "READY", HUMAN, AT, (GATES_OK, failing_gov))

    ready = advance(governed, "READY", HUMAN, AT, (GATES_OK, GOV_OK))
    assert ready["stage"] == "READY"
    assert ready["evidence"]["READY"][1]["kind"] == "governance_validation"


# ---------------------------------------------------------------------------
# The permissive half: the lifecycle actually runs
# ---------------------------------------------------------------------------

def test_the_full_legal_path_advances_with_evidence_and_records_history():
    ready = advance(_at_stage("GOVERN"), "READY", HUMAN, AT, (GATES_OK, GOV_OK))
    events = [(event["event"], event["to"]) for event in ready["history"]]
    assert events == [
        ("started", "DISCOVER"), ("advanced", "CONFIRM"), ("advanced", "BUILD"),
        ("advanced", "TEST"), ("advanced", "GOVERN"), ("advanced", "READY"),
    ]
    verify_experience(ready)


def test_skipping_a_declared_edge_is_refused_even_for_a_human():
    """Authority does not waive the graph: a human cannot jump DISCOVER->READY."""
    state = start_experience(HUMAN, AT)
    with pytest.raises(ExperienceError, match="no transition"):
        advance(state, "READY", HUMAN, AT, (GATES_OK, GOV_OK))
    with pytest.raises(ExperienceError, match="no transition"):
        advance(state, "TEST", SYSTEM, AT, (FLOW_OK,))


def test_failure_and_retry_are_recorded_and_gate_advancement():
    building = _at_stage("BUILD")
    broken = fail(building, MODEL, "compile error in generated app", AT)
    assert broken["status"] == "failed"

    with pytest.raises(ExperienceError, match="retry it before advancing"):
        advance(broken, "TEST", SYSTEM, AT, (FLOW_OK,))
    with pytest.raises(ExperienceError, match="may not resume"):
        retry(broken, MODEL, AT)

    resumed = retry(broken, SYSTEM, AT)
    assert resumed["status"] == "active"
    advanced = advance(resumed, "TEST", SYSTEM, AT, (FLOW_OK,))
    assert advanced["stage"] == "TEST"


def test_starting_is_a_human_act():
    for actor in (MODEL, SYSTEM):
        with pytest.raises(ExperienceError, match="human"):
            start_experience(actor, AT)


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

def test_a_hand_edited_stage_fails_closed_as_tampered():
    """THE FORGED-READY SPECIMEN: editing the stage field must not load."""
    state = _at_stage("BUILD")
    forged = json.loads(json.dumps(state))
    forged["stage"] = "READY"
    with pytest.raises(CapsuleTamperError):
        verify_experience(forged)
    with pytest.raises(CapsuleTamperError):
        advance(forged, "READY", HUMAN, AT, (GATES_OK, GOV_OK))


def test_a_truncated_chain_is_tampered():
    state = _at_stage("TEST")
    truncated = json.loads(json.dumps(state))
    truncated["chain"] = truncated["chain"][:-1]
    with pytest.raises(CapsuleTamperError):
        verify_experience(truncated)


def test_the_store_round_trips_and_a_forged_ready_on_disk_is_refused(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(create_document("proj-1", "Maintenance Assistant", HUMAN, AT))

    state = _at_stage("BUILD")
    first = store.save_experience(state, "reached BUILD")
    assert store.load_experience()["stage"] == "BUILD"

    raw = json.loads((store.root / "experience.json").read_text(encoding="utf-8"))
    raw["stage"] = "READY"
    (store.root / "experience.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(CapsuleTamperError):
        store.load_experience()

    # Legitimate progress still persists, as a distinct revision.
    second = store.save_experience(
        advance(state, "TEST", SYSTEM, AT, (FLOW_OK,)), "reached TEST"
    )
    assert first != second
    assert store.load_experience()["stage"] == "TEST"


def test_a_no_op_experience_save_is_refused(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(create_document("proj-1", "Maintenance Assistant", HUMAN, AT))
    state = _at_stage("CONFIRM")
    store.save_experience(state, "reached CONFIRM")
    with pytest.raises(CapsuleStoreError, match="identical"):
        store.save_experience(state, "same again")


# ---------------------------------------------------------------------------
# The BUILD wiring: real flow shapes, news never improved
# ---------------------------------------------------------------------------

def _flow_data(accepted: bool = True, gates: list | None = None) -> dict:
    """A flow-result dictionary in the exact shape `DevelopmentFlow` records:
    `gates` as GateResult.__dict__ rows, `accepted`, `execution_backend`."""
    if gates is None:
        gates = [
            {"name": "python -m compileall -q src scripts", "passed": True,
             "detail": "", "command": ("python", "-m", "compileall", "-q", "src", "scripts"),
             "returncode": 0},
            {"name": "nornyx check .nornyx/contracts/forge_control.nyx", "passed": True,
             "detail": "ok", "command": ("nornyx", "check", ".nornyx/contracts/forge_control.nyx"),
             "returncode": 0},
        ]
    return {"accepted": accepted, "gates": gates, "execution_backend": "sequential"}


def test_the_translator_reports_exactly_what_the_flow_recorded():
    refs = {ref.kind: ref for ref in flow_evidence(_flow_data())}
    assert refs["flow_run"].passed is True
    assert refs["flow_run"].ref == "flow/sequential"
    assert refs["gate_results"].passed is True
    assert refs["governance_validation"].passed is True


def test_a_failing_gate_fails_gate_results_and_refuses_advancement():
    gates = _flow_data()["gates"]
    gates[0] = dict(gates[0], passed=False, returncode=1)
    refs = {ref.kind: ref for ref in flow_evidence(_flow_data(gates=gates))}
    assert refs["gate_results"].passed is False, (
        "one failing gate did not fail gate_results; the translator improved the news"
    )
    tested = _at_stage("TEST")
    with pytest.raises(ExperienceError, match="reports failure"):
        advance(tested, "GOVERN", SYSTEM, AT, (refs["gate_results"],))


def test_an_absent_nornyx_cli_yields_no_governance_evidence_not_a_pass():
    """The honest-absence rule. An environment that never asked the governance
    question produces NO governance answer -- and the contract then refuses
    the stages that need one, which is the correct end-to-end outcome."""
    gates = [row for row in _flow_data()["gates"] if row["command"][0] != "nornyx"]
    refs = {ref.kind: ref for ref in flow_evidence(_flow_data(gates=gates))}
    assert "governance_validation" not in refs, (
        "governance evidence was synthesized for a run in which no nornyx "
        "gate executed"
    )
    governed = _at_stage("GOVERN")
    with pytest.raises(ExperienceError, match="governance_validation"):
        advance(governed, "READY", HUMAN, AT, tuple(refs.values()))


def test_nornyx_gates_are_recognised_by_command_not_by_spelling():
    """A gate NAMED like nornyx but running something else must not count."""
    impostor = {"name": "nornyx check something", "passed": True, "detail": "",
                "command": ("python", "evil.py"), "returncode": 0}
    gates = [row for row in _flow_data()["gates"] if row["command"][0] != "nornyx"]
    refs = {ref.kind: ref for ref in flow_evidence(_flow_data(gates=gates + [impostor]))}
    assert "governance_validation" not in refs, (
        "a gate whose NAME says nornyx but whose command ran something else "
        "was counted as governance validation -- deciding by spelling"
    )


def test_rejected_flow_run_translates_to_failing_evidence():
    refs = {ref.kind: ref for ref in flow_evidence(_flow_data(accepted=False))}
    assert refs["flow_run"].passed is False
    tested = _at_stage("BUILD")
    with pytest.raises(ExperienceError, match="reports failure"):
        advance(tested, "TEST", SYSTEM, AT, (refs["flow_run"],))


def test_an_incomplete_flow_result_translates_to_nothing():
    for missing in ("accepted", "gates", "execution_backend"):
        data = _flow_data()
        del data[missing]
        with pytest.raises(CapsuleValidationError, match=missing):
            flow_evidence(data)


# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

def test_the_declaration_tables_and_vocabularies_are_mutually_closed():
    assert set(STAGE_ACTORS) == set(STAGES)
    assert set(TRANSITIONS) == set(STAGES)
    assert set(STAGE_EVIDENCE) <= set(STAGES)
    for stage, kinds in STAGE_EVIDENCE.items():
        for kind in kinds:
            assert kind in EVIDENCE_KINDS, f"{stage} requires undeclared kind {kind!r}"
    with pytest.raises(CapsuleValidationError, match="not one of"):
        EvidenceRef(kind="vibes", ref="x", passed=True).validate()
