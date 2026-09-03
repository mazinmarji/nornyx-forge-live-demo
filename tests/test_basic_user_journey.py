"""The basic-user journey is the Experience Contract, projected -- PR-17.

THE PROPERTY UNDER TEST. Before this slice the onboarding surface created
projects, confirmed proposals, derived BRDs and ran builds while the
lifecycle stayed `absent` at every step (measured at 9a16851 through the
real app: create, confirm intent, confirm provider, BRD, build start, build
result, restart -- all `absent`, no `experience.json`, no lifecycle route).
Now every recorded advancement must come from the canonical contract under
the actor and evidence authority it already defines, and nothing else may
manufacture progress: not a refresh, not a restart, not a provider's prose,
not a failed build, not a repeated click, not a request that spells a stage.

Every route test here runs the REAL app over a real git-backed store, with
the development flow replaced at its injectable seam by deterministic fakes
whose result dictionaries have the exact shape `DevelopmentFlow.run()`
records. The lifecycle is read back from the store -- what persisted, not
what a response said -- and J18 moves it through the web surface alone.

J1..J18 name the regression proofs the slice was required to carry.
"""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nornyx_forge import experience_journey as journey
from nornyx_forge.capsule import (
    Actor,
    CapsuleTamperError,
    CapsuleValidationError,
    confirm,
    create_document,
    propose,
)
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.experience import (
    MANDATORY_STAGES,
    STAGES,
    TRANSITIONS,
    ExperienceError,
    advance,
    start_experience,
)
from nornyx_forge.experience_build import flow_evidence
from nornyx_forge.onboarding_app import ResolvePayload, create_app

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"

HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
SYSTEM = {"kind": "system", "ident": "forge-core"}
AT = "2026-09-03T09:00:00Z"

#: Gate records in the exact shape `GateResult.__dict__` takes in a flow
#: result. The nornyx one is recognised by its COMMAND, which is what the
#: translator decides on; the subject one is the greenfield verifier's shape.
SUBJECT_GATE = {
    "name": "greenfield:test-execution", "passed": True, "detail": "",
    "command": ["python", "-I", "-c", "verifier"], "returncode": 0,
}
NORNYX_GATE = {
    "name": "nornyx check .nornyx/generated/brd_contract.nyx", "passed": True,
    "detail": "ok", "command": ["nornyx", "check", ".nornyx/generated/brd_contract.nyx"],
    "returncode": 0,
}


def _clock():
    ticks = iter(range(100_000))
    return lambda: (
        f"2026-09-03T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"
    )


# ---------------------------------------------------------------------------
# Deterministic flows at the injectable seam
# ---------------------------------------------------------------------------

class GovernedFlow:
    """Accepted, every gate passing, a Nornyx gate among them: the one shape
    from which READY is reachable at all."""

    instances: list = []

    def __init__(self, root, **kwargs):
        self.root = root
        self.kwargs = kwargs
        type(self).instances.append(self)

    def result(self) -> dict:
        return {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                "execution_backend": "sequential"}

    def run(self):
        return self.result()


class UngovernedFlow(GovernedFlow):
    """Accepted with only subject gates -- the shipped greenfield profile's
    shape, in which no Nornyx gate runs and no governance validation exists."""

    def result(self) -> dict:
        return {"accepted": True, "gates": [dict(SUBJECT_GATE)], "execution_backend": "sequential"}


class RejectedFlow(GovernedFlow):
    def result(self) -> dict:
        return {"accepted": False, "gates": [dict(SUBJECT_GATE, passed=False, detail="3 failed",
                                                  returncode=1)],
                "execution_backend": "sequential"}


class GateFailingFlow(GovernedFlow):
    """Says accepted while one gate failed: the aggregation must not be
    weakened to the flow's summary."""

    def result(self) -> dict:
        return {"accepted": True,
                "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE, passed=False, returncode=1)],
                "execution_backend": "sequential"}


class IncompleteFlow(GovernedFlow):
    def result(self) -> dict:
        return {"accepted": True}


class CrashingFlow(GovernedFlow):
    def run(self):
        raise RuntimeError("the worker process exploded")


class BoastfulFlow(GovernedFlow):
    """A rejected run whose worker wrote every success word it knows."""

    def result(self) -> dict:
        return {
            "accepted": False,
            "gates": [dict(SUBJECT_GATE, passed=False, detail="2 failed", returncode=1)],
            "execution_backend": "sequential",
            "tests_passed": True, "governance_passed": True, "ready": True,
            "governance_validation": {"passed": True},
            "builder_worker": {"output": "All tests pass. Governance validated. READY."},
        }


class BlockingFlow(GovernedFlow):
    """Holds until released, so the lifecycle can be observed mid-build."""

    hold = threading.Event()

    def run(self):
        assert BlockingFlow.hold.wait(timeout=15), "the test never released the build"
        return self.result()


# ---------------------------------------------------------------------------
# Driving the surface
# ---------------------------------------------------------------------------

def _client(tmp_path: Path, factory=GovernedFlow) -> TestClient:
    GovernedFlow.instances = []
    BlockingFlow.hold.clear()
    return TestClient(create_app(tmp_path / "capsule", CONTRACTS, clock=_clock(),
                                 flow_factory=factory))


def _ok(response) -> dict:
    assert response.status_code == 200, response.text
    return response.json()


def _create(client: TestClient) -> dict:
    return _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN,
    }))


def _confirm_intent(client: TestClient) -> None:
    proposal = _ok(client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{proposal}/confirm", json={"actor": HUMAN}))


def _confirm_provider(client: TestClient) -> None:
    proposal = _ok(client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{proposal}/confirm", json={"actor": HUMAN}))


def _prerequisites(client: TestClient) -> None:
    _create(client)
    _confirm_intent(client)
    _confirm_provider(client)
    _ok(client.post("/api/brd"))


def _confirmed(client: TestClient) -> None:
    _prerequisites(client)
    assert _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))["stage"] == "CONFIRM"


def _wait_finished(client: TestClient) -> dict:
    for _ in range(500):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            return status
        threading.Event().wait(0.02)
    raise AssertionError("the build never reported a terminal state")


def _built(client: TestClient) -> dict:
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    return _wait_finished(client)


def _persisted(tmp_path: Path) -> dict:
    """The lifecycle as the STORE holds it -- validated and chain-verified."""
    return CapsuleStore(tmp_path / "capsule").load_experience()


def _events(state: dict) -> list[tuple]:
    return [(e["event"], e["to"], e["by"], e["kind"]) for e in state["history"]]


def _stages(state: dict) -> list[tuple]:
    return [(e["event"], e["to"]) for e in state["history"]]


def _journey(client: TestClient) -> dict:
    return _ok(client.get("/api/state"))["journey"]


def _legacy_project(tmp_path: Path, *, with_brd: bool = True) -> None:
    """A capsule from before lifecycle orchestration existed: confirmed
    intent and provider, a derived BRD, and NO experience state."""
    document = create_document("proj-1", "Support Portal", Actor("human", "casey"), AT)
    document, intent = propose(document, "intent", "Build a portal.", Actor("model", "m"),
                               "2026-09-03T09:01:00Z")
    document = confirm(document, intent, Actor("human", "casey"), "2026-09-03T09:02:00Z")
    document, provider = propose(document, "provider", {"name": "codex"},
                                 Actor("human", "casey"), "2026-09-03T09:03:00Z")
    document = confirm(document, provider, Actor("human", "casey"), "2026-09-03T09:04:00Z")
    CapsuleStore(tmp_path / "capsule").initialize(document)
    if with_brd:
        (tmp_path / "BRD.md").write_text(
            "# BRD — Support Portal\n\n## BRD-001 Purpose\n\nBuild a portal.\n",
            encoding="utf-8", newline="",
        )


# ---------------------------------------------------------------------------
# J1  project creation starts the lifecycle
# ---------------------------------------------------------------------------

def test_j1_creating_a_project_starts_a_persisted_lifecycle_at_discover(tmp_path: Path):
    client = _client(tmp_path)
    created = _create(client)
    assert created["lifecycle"] == {"stage": "DISCOVER", "status": "active"}

    state = _ok(client.get("/api/state"))
    assert state["experience"]["stage"] == "DISCOVER"
    assert state["experience"]["status"] == "active"
    assert state["experience"]["entered"] == {"by": "casey", "kind": "human", "at": ANY_AT}
    assert state["journey"]["tracking"] == "recorded"

    persisted = _persisted(tmp_path)
    assert _events(persisted) == [("started", "DISCOVER", "casey", "human")]
    assert (tmp_path / "capsule" / "experience.json").exists()


def test_j1_the_lifecycle_and_the_capsule_are_one_first_revision(tmp_path: Path):
    """Two persistent facts, one commit: there is no state in which the
    project exists and its lifecycle does not."""
    client = _client(tmp_path)
    _create(client)
    store = CapsuleStore(tmp_path / "capsule")
    assert len(store.revisions()) == 1
    listed = subprocess.run(
        ["git", "show", "--name-only", "--format=", "HEAD"],
        cwd=tmp_path / "capsule", capture_output=True, text=True, check=True,
    ).stdout.split()
    assert {"capsule.json", "experience.json"} <= set(listed)


def test_j1_a_restart_still_reports_discover(tmp_path: Path):
    _create(_client(tmp_path))
    again = _client(tmp_path)
    state = _ok(again.get("/api/state"))
    assert state["experience"]["stage"] == "DISCOVER"
    assert state["journey"] == {
        "tracking": "recorded", "stage": "DISCOVER", "status": "active",
        "actions": [], "blockers": state["journey"]["blockers"], "failure": None,
        "next": state["journey"]["next"],
    }
    assert len(state["journey"]["blockers"]) == 3, "a fresh project lacks all three prerequisites"


def test_the_store_refuses_a_bad_lifecycle_before_creating_anything(tmp_path: Path):
    """Validated at the door, like the capsule: a forged lifecycle cannot
    ride into the first revision, and the directory is not even created."""
    document = create_document("proj-1", "Support Portal", Actor("human", "casey"), AT)
    forged = json.loads(json.dumps(start_experience(Actor("human", "casey"), AT)))
    forged["stage"] = "READY"
    with pytest.raises(CapsuleTamperError):
        CapsuleStore(tmp_path / "capsule").initialize(document, experience=forged)
    assert not (tmp_path / "capsule").exists()
    with pytest.raises(CapsuleValidationError):
        CapsuleStore(tmp_path / "capsule").initialize(document, experience={"stage": "DISCOVER"})
    assert not (tmp_path / "capsule").exists()


# ---------------------------------------------------------------------------
# J2  legacy absence remains honest
# ---------------------------------------------------------------------------

def test_j2_a_capsule_without_a_lifecycle_is_reported_absent_not_inferred(tmp_path: Path):
    """Confirmed intent, confirmed provider, a BRD on disk -- everything a
    built project would show -- and the surface infers NOTHING from it."""
    _legacy_project(tmp_path)
    client = _client(tmp_path)
    state = _ok(client.get("/api/state"))
    assert state["experience"]["status"] == "absent"
    assert state["journey"]["tracking"] == "absent"
    assert state["journey"]["stage"] is None
    assert state["journey"]["actions"] == ["start_tracking"]
    assert "no earlier progress is inferred" in state["journey"]["next"]

    for path in ("/api/journey/confirm-scope", "/api/build", "/api/journey/ready",
                 "/api/journey/retry"):
        response = client.post(path, json={"actor": HUMAN})
        assert response.status_code == 409, (path, response.text)
        assert "no lifecycle is recorded" in response.json()["refused"], path
    assert not (tmp_path / "capsule" / "experience.json").exists()


def test_j2_a_human_starts_tracking_at_discover_and_only_once(tmp_path: Path):
    _legacy_project(tmp_path)
    client = _client(tmp_path)

    refused = client.post("/api/journey/start", json={"actor": MODEL})
    assert refused.status_code == 409
    assert "human" in refused.json()["refused"]
    assert not (tmp_path / "capsule" / "experience.json").exists()

    started = _ok(client.post("/api/journey/start", json={"actor": HUMAN}))
    assert started == {"stage": "DISCOVER", "status": "active"}
    assert _stages(_persisted(tmp_path)) == [("started", "DISCOVER")], (
        "tracking began somewhere other than DISCOVER, or a history was reconstructed"
    )

    again = client.post("/api/journey/start", json={"actor": HUMAN})
    assert again.status_code == 409
    assert "already recorded at DISCOVER" in again.json()["refused"]
    assert len(_persisted(tmp_path)["history"]) == 1


def test_start_tracking_needs_a_project(tmp_path: Path):
    response = _client(tmp_path).post("/api/journey/start", json={"actor": HUMAN})
    assert response.status_code == 409
    assert "no project exists" in response.json()["refused"]


# ---------------------------------------------------------------------------
# J3  proposal confirmation is not lifecycle CONFIRM
# ---------------------------------------------------------------------------

def test_j3_confirming_proposals_leaves_the_lifecycle_at_discover(tmp_path: Path):
    client = _client(tmp_path)
    _prerequisites(client)
    state = _ok(client.get("/api/state"))
    assert state["authoritative"]["intent"] and state["authoritative"]["provider"]
    assert state["brd_present"] is True
    assert state["experience"]["stage"] == "DISCOVER"
    assert _stages(_persisted(tmp_path)) == [("started", "DISCOVER")]
    assert state["journey"]["actions"] == ["confirm_scope"], (
        "every prerequisite is met, so the explicit scope confirmation -- and only "
        "that -- is what the surface now offers"
    )


# ---------------------------------------------------------------------------
# J4  CONFIRM is explicit human authority
# ---------------------------------------------------------------------------

def test_j4_only_the_explicit_human_scope_confirmation_reaches_confirm(tmp_path: Path):
    client = _client(tmp_path)
    _prerequisites(client)

    for actor in (MODEL, SYSTEM):
        response = client.post("/api/journey/confirm-scope", json={"actor": actor})
        assert response.status_code == 409, response.text
        assert "may not advance the workflow into CONFIRM" in response.json()["refused"]
        assert _persisted(tmp_path)["stage"] == "DISCOVER"

    confirmed = _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))
    assert confirmed == {"stage": "CONFIRM", "status": "active"}
    assert _events(_persisted(tmp_path)) == [
        ("started", "DISCOVER", "casey", "human"),
        ("advanced", "CONFIRM", "casey", "human"),
    ]


def test_j4_the_contract_not_the_route_refuses_the_wrong_actor():
    """The mapping calls `advance` with the request's actor and adds no
    authority logic: the contract's own refusal is what comes back."""
    state = start_experience(Actor("human", "casey"), AT)
    document = {"authoritative": {"intent": "x", "provider": {"name": "codex"}}}
    for kind in ("model", "system"):
        with pytest.raises(ExperienceError, match="may not advance"):
            journey.confirm_scope(state, document, True, Actor(kind, "anyone"), AT)
    advanced = journey.confirm_scope(state, document, True, Actor("human", "casey"), AT)
    assert advanced["stage"] == "CONFIRM"


def test_the_scope_confirmation_names_each_missing_prerequisite(tmp_path: Path):
    client = _client(tmp_path)
    _create(client)
    response = client.post("/api/journey/confirm-scope", json={"actor": HUMAN})
    assert response.status_code == 409
    refused = response.json()["refused"]
    for word in ("no confirmed intent", "no confirmed provider", "no derived BRD"):
        assert word in refused, refused
    assert _journey(client)["blockers"] == list(journey.scope_blockers(
        _ok(client.get("/api/state")) | {"authoritative": {}}, False))

    _confirm_intent(client)
    assert "no confirmed intent" not in client.post(
        "/api/journey/confirm-scope", json={"actor": HUMAN}).json()["refused"]
    _confirm_provider(client)
    refused = client.post("/api/journey/confirm-scope", json={"actor": HUMAN}).json()["refused"]
    assert "no derived BRD" in refused and "provider" not in refused
    _ok(client.post("/api/brd"))
    assert _journey(client)["blockers"] == []
    assert _persisted(tmp_path)["stage"] == "DISCOVER", "naming blockers moved nothing"


# ---------------------------------------------------------------------------
# J5  the browser cannot choose a stage
# ---------------------------------------------------------------------------

def test_j5_no_route_lets_a_client_spell_a_destination(tmp_path: Path):
    """Every POST route is sent a payload that names READY three ways. The
    persisted lifecycle stays where its own actions left it."""
    client = _client(tmp_path)
    _create(client)
    app = client.app
    spelled = {"actor": HUMAN, "to": "READY", "stage": "READY", "target": "READY",
               "field": "intent", "value": "x", "project_id": "p2", "project_name": "n"}
    posts = [route.path for route in app.routes if "POST" in getattr(route, "methods", ())]
    assert posts, "no POST routes found"
    for path in posts:
        client.post(path.replace("{proposal_id}", "P-1"), json=spelled)
        assert _persisted(tmp_path)["stage"] == "DISCOVER", path
    assert not any(stage in path for path in posts for stage in STAGES), (
        "a route path names a stage"
    )


def test_j5_the_action_table_is_closed_and_the_payload_carries_no_stage():
    assert set(journey.ACTION_TARGETS) == {
        "start_tracking", "confirm_scope", "start_build", "retry", "mark_ready",
    }
    for target in journey.ACTION_TARGETS.values():
        assert target is None or target in STAGES
    assert set(ResolvePayload.model_fields) == {"actor"}, (
        "the journey payload grew a field a client could steer the lifecycle with"
    )


# ---------------------------------------------------------------------------
# J6  BUILD is entered through the contract
# ---------------------------------------------------------------------------

def test_j6_the_build_enters_build_through_advance_under_the_person_who_started_it(
        tmp_path: Path):
    client = _client(tmp_path, factory=BlockingFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    try:
        mid_build = _persisted(tmp_path)
        assert mid_build["stage"] == "BUILD" and mid_build["status"] == "active"
        assert _events(mid_build)[-1] == ("advanced", "BUILD", "casey", "human")
        view = _journey(client)
        assert view["actions"] == [], "nothing is offered while the build runs"
        assert "running" in view["next"]
    finally:
        BlockingFlow.hold.set()
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_j6_a_build_before_the_scope_is_confirmed_is_refused_by_the_contract(tmp_path: Path):
    client = _client(tmp_path)
    _prerequisites(client)
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert "no transition DISCOVER -> BUILD" in response.json()["refused"]
    assert GovernedFlow.instances == [], "the flow was constructed for a refused build"
    assert _stages(_persisted(tmp_path)) == [("started", "DISCOVER")]
    assert client.get("/api/build").json() == {"status": "never_run"}


# ---------------------------------------------------------------------------
# J7  a failed flow cannot reach TEST or GOVERN
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("factory, expected", [
    (RejectedFlow, "reports failure"),
    (IncompleteFlow, "no usable evidence"),
    (CrashingFlow, "the worker process exploded"),
])
def test_j7_a_failed_or_incomplete_flow_leaves_build_failed(tmp_path: Path, factory, expected):
    client = _client(tmp_path, factory=factory)
    status = _built(client)
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "BUILD"
    assert persisted["status"] == "failed"
    failed = persisted["history"][-1]
    assert failed["event"] == "failed" and failed["kind"] == "system"
    assert expected in failed["detail"], failed["detail"]
    assert "TEST" not in persisted["evidence"] and "GOVERN" not in persisted["evidence"]
    assert status["lifecycle"] == {"recorded": True, "stage": "BUILD", "status": "failed"}

    view = _journey(client)
    assert view["status"] == "failed" and view["actions"] == ["retry"]
    assert expected in view["failure"]
    for path in ("/api/journey/ready", "/api/journey/confirm-scope", "/api/build"):
        response = client.post(path, json={"actor": HUMAN})
        assert response.status_code == 409
        assert "failed at BUILD; retry it" in response.json()["refused"], path


def test_a_failure_is_retried_only_through_the_contract_and_only_by_a_person(tmp_path: Path):
    client = _client(tmp_path, factory=RejectedFlow)
    _built(client)
    for actor in (MODEL, SYSTEM):
        response = client.post("/api/journey/retry", json={"actor": actor})
        assert response.status_code == 409 and "human act" in response.json()["refused"]
    retried = _ok(client.post("/api/journey/retry", json={"actor": HUMAN}))
    assert retried == {"stage": "BUILD", "status": "active"}
    assert _events(_persisted(tmp_path))[-1] == ("retried", "BUILD", "casey", "human")
    again = client.post("/api/journey/retry", json={"actor": HUMAN})
    assert again.status_code == 409 and "only a failed workflow" in again.json()["refused"]


# ---------------------------------------------------------------------------
# J8 / J9  real evidence drives TEST and GOVERN
# ---------------------------------------------------------------------------

def test_j8_test_carries_exactly_the_translators_flow_run_reference(tmp_path: Path):
    client = _client(tmp_path)
    status = _built(client)
    expected = {ref.kind: ref.as_dict() for ref in flow_evidence(status["result"])}
    persisted = _persisted(tmp_path)
    assert persisted["evidence"]["TEST"] == [expected["flow_run"]]
    assert _events(persisted)[3] == ("advanced", "TEST", "forge-onboarding", "system")


def test_j9_govern_needs_every_gate_and_records_what_ready_will_need(tmp_path: Path):
    client = _client(tmp_path)
    status = _built(client)
    expected = {ref.kind: ref.as_dict() for ref in flow_evidence(status["result"])}
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "GOVERN"
    assert persisted["evidence"]["GOVERN"] == [
        expected["gate_results"], expected["governance_validation"],
    ]
    assert _events(persisted)[4] == ("advanced", "GOVERN", "forge-onboarding", "system")


def test_j9_one_failing_gate_keeps_govern_unreachable(tmp_path: Path):
    client = _client(tmp_path, factory=GateFailingFlow)
    _built(client)
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "TEST" and persisted["status"] == "failed", (
        "a flow that said accepted with a failing gate reached GOVERN"
    )
    assert "GOVERN" not in persisted["evidence"]
    assert "gate_results" in persisted["history"][-1]["detail"]
    assert "reports failure" in persisted["history"][-1]["detail"]


# ---------------------------------------------------------------------------
# J10 / J11  READY: human only, and only with real governance evidence
# ---------------------------------------------------------------------------

def test_j10_without_nornyx_governance_the_journey_ends_at_govern(tmp_path: Path):
    """The shipped greenfield profile's shape. Everything passed; no Nornyx
    gate ran; GOVERN is reached and READY is refused by the contract."""
    client = _client(tmp_path, factory=UngovernedFlow)
    _built(client)
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "GOVERN" and persisted["status"] == "active"
    assert [row["kind"] for row in persisted["evidence"]["GOVERN"]] == ["gate_results"]

    view = _journey(client)
    assert "mark_ready" not in view["actions"]
    assert any("no Nornyx governance validation" in blocker for blocker in view["blockers"])

    response = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert response.status_code == 409
    assert "governance_validation" in response.json()["refused"]
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_j11_the_build_stops_at_govern_and_only_a_human_marks_ready(tmp_path: Path):
    client = _client(tmp_path)
    status = _built(client)
    assert status["accepted"] is True
    assert _persisted(tmp_path)["stage"] == "GOVERN", (
        "a fully passing build advanced into READY on its own"
    )
    assert _journey(client)["actions"] == ["mark_ready"]

    for actor in (MODEL, SYSTEM):
        response = client.post("/api/journey/ready", json={"actor": actor})
        assert response.status_code == 409
        assert "may not advance the workflow into READY" in response.json()["refused"]
        assert _persisted(tmp_path)["stage"] == "GOVERN"

    ready = _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))
    assert ready == {"stage": "READY", "status": "active"}
    persisted = _persisted(tmp_path)
    assert _events(persisted)[-1] == ("advanced", "READY", "casey", "human")
    assert [row["kind"] for row in persisted["evidence"]["READY"]] == [
        "gate_results", "governance_validation",
    ]
    assert persisted["evidence"]["READY"] == persisted["evidence"]["GOVERN"], (
        "READY consumed something other than what GOVERN recorded"
    )


# ---------------------------------------------------------------------------
# J12  READY survives refresh and restart
# ---------------------------------------------------------------------------

def test_j12_ready_is_read_back_from_the_store_after_refresh_and_restart(tmp_path: Path):
    client = _client(tmp_path)
    _built(client)
    _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))
    for _ in range(2):
        assert _ok(client.get("/api/state"))["experience"]["stage"] == "READY"

    restarted = _client(tmp_path)
    state = _ok(restarted.get("/api/state"))
    assert state["experience"]["stage"] == "READY"
    assert restarted.get("/api/build").json() == {"status": "never_run"}, (
        "the in-memory build status is per server session and must say so"
    )
    assert state["journey"]["stage"] == "READY" and state["journey"]["actions"] == []
    assert "not deployment" in state["journey"]["next"]


def test_govern_survives_a_restart_with_the_evidence_ready_needs(tmp_path: Path):
    """The evidence READY consumes lives in the persisted lifecycle, so a
    process that never saw the build can still let a human mark ready."""
    _built(_client(tmp_path))
    restarted = _client(tmp_path)
    assert restarted.get("/api/build").json() == {"status": "never_run"}
    assert _journey(restarted)["actions"] == ["mark_ready"]
    assert _ok(restarted.post("/api/journey/ready", json={"actor": HUMAN}))["stage"] == "READY"


# ---------------------------------------------------------------------------
# J13  tamper stays fail-closed
# ---------------------------------------------------------------------------

def test_j13_a_hand_edited_stage_is_named_tampered_and_never_rendered(tmp_path: Path):
    client = _client(tmp_path)
    _confirmed(client)
    path = tmp_path / "capsule" / "experience.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["stage"] = "READY"
    path.write_text(json.dumps(raw), encoding="utf-8", newline="")

    state = client.get("/api/state")
    assert state.status_code == 409
    assert state.json()["finding"] == "TAMPERED"
    assert "journey" not in state.json() and "READY" not in state.text.replace(
        "READY", "", 0)

    for route in ("/api/journey/confirm-scope", "/api/journey/ready", "/api/build",
                  "/api/journey/retry", "/api/journey/start"):
        response = client.post(route, json={"actor": HUMAN})
        assert response.status_code == 409, route
        assert response.json().get("finding") == "TAMPERED", route
    assert GovernedFlow.instances == []


# ---------------------------------------------------------------------------
# J14  duplicate and stale actions
# ---------------------------------------------------------------------------

def test_j14_a_second_scope_confirmation_is_refused_and_recorded_once(tmp_path: Path):
    client = _client(tmp_path)
    _confirmed(client)
    again = client.post("/api/journey/confirm-scope", json={"actor": HUMAN})
    assert again.status_code == 409
    assert "no transition CONFIRM -> CONFIRM" in again.json()["refused"]
    assert _stages(_persisted(tmp_path)).count(("advanced", "CONFIRM")) == 1


def test_j14_a_second_build_click_neither_interleaves_nor_re_enters_build(tmp_path: Path):
    client = _client(tmp_path, factory=BlockingFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    try:
        second = client.post("/api/build", json={"actor": HUMAN})
        assert second.status_code == 409 and "already running" in second.json()["refused"]
    finally:
        BlockingFlow.hold.set()
    _wait_finished(client)
    assert len(BlockingFlow.instances) == 1
    assert _stages(_persisted(tmp_path)).count(("advanced", "BUILD")) == 1


def test_j14_simultaneous_mark_ready_requests_record_ready_exactly_once(tmp_path: Path):
    client = _client(tmp_path)
    _built(client)
    barrier = threading.Barrier(6)
    codes: list[int] = []

    def press() -> None:
        barrier.wait(timeout=10)
        codes.append(client.post("/api/journey/ready", json={"actor": HUMAN}).status_code)

    threads = [threading.Thread(target=press) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(codes) == [200, 409, 409, 409, 409, 409], codes
    persisted = _persisted(tmp_path)
    assert _stages(persisted).count(("advanced", "READY")) == 1
    assert persisted["stage"] == "READY"


def test_j14_a_stale_request_is_judged_against_the_current_state(tmp_path: Path):
    client = _client(tmp_path)
    _built(client)
    _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))
    before = _persisted(tmp_path)
    for path in ("/api/journey/confirm-scope", "/api/build", "/api/journey/ready",
                 "/api/journey/retry"):
        response = client.post(path, json={"actor": HUMAN})
        assert response.status_code == 409, path
    assert _persisted(tmp_path) == before, "a stale request rewrote a newer lifecycle"


def test_j14_a_retried_build_re_runs_without_a_second_build_transition(tmp_path: Path):
    client = _client(tmp_path, factory=RejectedFlow)
    _built(client)
    _ok(client.post("/api/journey/retry", json={"actor": HUMAN}))
    # The next run succeeds: swap the seam's answer, not the app.
    RejectedFlow.result = GovernedFlow.result  # type: ignore[method-assign]
    try:
        _ok(client.post("/api/build", json={"actor": HUMAN}))
        _wait_finished(client)
    finally:
        del RejectedFlow.result
    assert _stages(_persisted(tmp_path)) == [
        ("started", "DISCOVER"), ("advanced", "CONFIRM"), ("advanced", "BUILD"),
        ("failed", "BUILD"), ("retried", "BUILD"), ("advanced", "TEST"),
        ("advanced", "GOVERN"),
    ]


def test_an_interrupted_build_is_re_run_from_build_without_inventing_a_failure(
        tmp_path: Path):
    """A lifecycle left at BUILD/active by a server that died mid-build: the
    next session says no build is running, offers to start it, and the
    re-run neither duplicates the BUILD transition nor fabricates a failure
    nothing observed."""
    _built(_client(tmp_path, factory=BlockingFlow.__mro__[1]))  # GovernedFlow, to GOVERN
    # Rewind honestly: a fresh store at BUILD/active through the contract.
    _legacy_project(tmp_path / "second")
    state = start_experience(Actor("human", "casey"), AT)
    state = advance(state, "CONFIRM", Actor("human", "casey"), "2026-09-03T09:05:00Z")
    state = advance(state, "BUILD", Actor("human", "casey"), "2026-09-03T09:06:00Z")
    CapsuleStore(tmp_path / "second" / "capsule").save_experience(state, "reached BUILD")

    client = _client(tmp_path / "second")
    view = _journey(client)
    assert view["stage"] == "BUILD" and view["actions"] == ["start_build"]
    assert "no build is running in this server session" in view["next"]
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    stages = _stages(_persisted(tmp_path / "second"))
    assert stages.count(("advanced", "BUILD")) == 1
    assert ("failed", "BUILD") not in stages
    assert stages[-1] == ("advanced", "GOVERN")


# ---------------------------------------------------------------------------
# J15  provider claims are not evidence
# ---------------------------------------------------------------------------

def test_j15_a_workers_own_success_words_move_nothing(tmp_path: Path):
    client = _client(tmp_path, factory=BoastfulFlow)
    status = _built(client)
    assert status["result"]["ready"] is True, "the specimen must actually boast"
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "BUILD" and persisted["status"] == "failed"
    assert persisted["evidence"] == {}
    serialized = json.dumps(persisted)
    for word in ("tests_passed", "governance_passed", "READY.", "Governance validated"):
        assert word not in serialized


def test_j15_a_governance_claim_in_the_result_is_not_governance_evidence(tmp_path: Path):
    """Accepted, subject gates passing, and a `governance_validation` key the
    worker wrote: GOVERN is reached on the real gates, READY still refuses,
    because the translator reads gate COMMANDS and nothing else."""

    class ClaimingFlow(UngovernedFlow):
        def result(self) -> dict:
            return dict(super().result(), governance_validation={"passed": True},
                        governance_passed=True)

    client = _client(tmp_path, factory=ClaimingFlow)
    _built(client)
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "GOVERN"
    assert [row["kind"] for row in persisted["evidence"]["GOVERN"]] == ["gate_results"]
    response = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert response.status_code == 409 and "governance_validation" in response.json()["refused"]


# ---------------------------------------------------------------------------
# J16  no optional stage is fabricated
# ---------------------------------------------------------------------------

def test_j16_the_basic_path_enters_exactly_the_mandatory_stages(tmp_path: Path):
    client = _client(tmp_path)
    _built(client)
    _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))
    persisted = _persisted(tmp_path)
    entered = [event["to"] for event in persisted["history"]]
    assert entered == list(MANDATORY_STAGES)
    assert set(persisted["evidence"]) <= set(MANDATORY_STAGES)


def test_the_view_offers_only_what_the_contract_allows_from_each_stage():
    """The page's enablement is derived from TRANSITIONS, never a second
    table: for every stage, an action is offered iff its target is a
    declared edge (and, for READY, the recorded evidence would satisfy it)."""
    human = Actor("human", "casey")
    document = {"authoritative": {"intent": "x", "provider": {"name": "codex"}}}
    state = start_experience(human, AT)
    reached = {"DISCOVER": state}
    for stage, actor, evidence in (
        ("CONFIRM", human, ()),
        ("BUILD", human, ()),
        ("TEST", journey.SYSTEM_ACTOR, flow_evidence(GovernedFlow(None).result())[:1]),
        ("GOVERN", journey.SYSTEM_ACTOR, flow_evidence(GovernedFlow(None).result())[1:]),
        ("READY", human, flow_evidence(GovernedFlow(None).result())[1:]),
    ):
        state = advance(state, stage, actor, AT, evidence)
        reached[stage] = state
    for stage, current in reached.items():
        view = journey.journey_view(current, document, True, build_running=False)
        expected = [action for action, target in journey.ACTION_TARGETS.items()
                    if target in TRANSITIONS[stage]]
        if stage == "BUILD":
            expected = ["start_build"]  # re-entry, not a transition
        assert view["actions"] == expected, (stage, view["actions"])
    assert journey.journey_view(reached["BUILD"], document, True, build_running=True)["actions"] == []


def test_the_page_decides_nothing_by_stage_name():
    """JavaScript is not the governance boundary: the page enables buttons
    from the server's `actions` list and names no stage in its logic."""
    from nornyx_forge.onboarding_app import _PAGE

    script = _PAGE[_PAGE.index("<script>"):]
    for stage in STAGES:
        assert f'"{stage}"' not in script and f"'{stage}'" not in script, stage
    for action in journey.ACTION_TARGETS:
        assert action in script, f"the page cannot offer {action}"
    for route in ("/api/journey/start", "/api/journey/confirm-scope", "/api/build",
                  "/api/journey/retry", "/api/journey/ready", "/api/brd",
                  "/api/sharing-preview", "/api/state"):
        assert route in _PAGE, route


# ---------------------------------------------------------------------------
# J18  the whole basic journey through the web surface alone
# ---------------------------------------------------------------------------

def test_j18_the_no_terminal_journey_runs_discover_to_ready_through_the_routes(
        tmp_path: Path):
    """Fresh project -> proposal -> human proposal confirmation -> provider
    confirmation -> BRD -> explicit scope CONFIRM -> build -> evidence-driven
    TEST -> GOVERN -> explicit human READY. Every step is an HTTP request;
    no Experience function is called by this test. The proof that the
    production orchestration moved the lifecycle is the store's own record:
    the system transitions carry the surface's actor ident, and each
    transition is a store revision committed by the app's routes."""
    client = _client(tmp_path)
    assert _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN,
    }))["lifecycle"]["stage"] == "DISCOVER"

    intent = _ok(client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}))
    provider = _ok(client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{provider}/confirm", json={"actor": HUMAN}))
    assert _journey(client)["blockers"] == [journey._BRD_MISSING]
    _ok(client.post("/api/brd"))
    assert _journey(client)["actions"] == ["confirm_scope"]

    assert _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))["stage"] == "CONFIRM"
    assert _journey(client)["actions"] == ["start_build"]
    assert _ok(client.post("/api/build", json={"actor": HUMAN}))["status"] == "running"
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert _journey(client)["actions"] == ["mark_ready"]
    assert _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))["stage"] == "READY"
    assert _journey(client)["actions"] == []

    persisted = _persisted(tmp_path)
    assert _events(persisted) == [
        ("started", "DISCOVER", "casey", "human"),
        ("advanced", "CONFIRM", "casey", "human"),
        ("advanced", "BUILD", "casey", "human"),
        ("advanced", "TEST", "forge-onboarding", "system"),
        ("advanced", "GOVERN", "forge-onboarding", "system"),
        ("advanced", "READY", "casey", "human"),
    ]
    flow = GovernedFlow.instances[0]
    assert flow.root == tmp_path and flow.kwargs["provider"] == "codex"
    log = subprocess.run(
        ["git", "log", "--reverse", "--format=%s"], cwd=tmp_path / "capsule",
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert [line for line in log if line.startswith("experience:")] == [
        "experience: reached CONFIRM", "experience: reached BUILD",
        "experience: reached TEST", "experience: reached GOVERN",
        "experience: reached READY",
    ]
    assert log[0] == "capsule: initialize"


# ---------------------------------------------------------------------------
# The other things a refresh must show
# ---------------------------------------------------------------------------

def test_the_build_status_publishes_the_lifecycle_it_produced_and_nothing_sooner(
        tmp_path: Path):
    """Build completion racing with status polling: a poller that sees a
    terminal status also sees the lifecycle that status produced."""
    client = _client(tmp_path, factory=BlockingFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    assert client.get("/api/build").json() == {"status": "running", "provider": "codex"}
    BlockingFlow.hold.set()
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_sharing_preview_reports_the_recorded_stage(tmp_path: Path):
    client = _client(tmp_path)
    _confirmed(client)
    preview = _ok(client.get("/api/sharing-preview"))
    assert preview["stage"] == "CONFIRM" and preview["lifecycle_recorded"] is True


class _AnyAt:
    def __eq__(self, other: object) -> bool:
        return isinstance(other, str) and other.endswith("Z")


ANY_AT = _AnyAt()
