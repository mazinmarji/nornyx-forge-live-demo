"""CONFIRM and READY are bound to the content they were recorded about.

THE PROPERTY UNDER TEST. Before this slice the lifecycle's two human
positions named no content at all. `CONFIRM` recorded a stage, an actor and
a timestamp; `READY` recorded a stage and two count-shaped evidence rows.
Neither carried a reference to the record's confirmed capsule region or to
the BRD the build would read, so nothing could notice either changing
underneath the record -- and nothing did. Measured at `ea16d97` through
the real gated surface: a BRD.md overwritten by hand after CONFIRM was
built without a murmur; a further intent confirmed under CONFIRM left the
page offering `start_build`; a new intent confirmed under READY left every
reader reporting READY beside content that was never built.

What this module holds is the repair and, just as deliberately, its limit.
A digest binding establishes that the BYTES have not changed since the
record was written. It establishes nothing about whether anyone read them,
and the last test here pins that boundary against the disclosure register
so a later slice cannot quietly widen the claim.

Every route test runs the REAL app over a real git-backed store, with the
development flow replaced at its injectable seam by deterministic doubles
whose result dictionaries have the exact shape `DevelopmentFlow.run()`
records. The lifecycle is read back from the store -- what persisted, not
what a response said.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from session_client import authed_client
from test_actor_declaration_boundary import FORBIDDEN_CLAIMS

from nornyx_forge import experience as experience_contract
from nornyx_forge import experience_build, onboarding_app
from nornyx_forge import experience_journey as journey
from nornyx_forge.brd_authoring import brd_from_capsule
from nornyx_forge.capsule import (
    Actor,
    CapsuleValidationError,
    confirm,
    create_document,
    propose,
)
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.experience import (
    EvidenceRef,
    ExperienceError,
    advance,
    start_experience,
)
from nornyx_forge.experience_build import flow_evidence
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.provider_contract import GovernedEligibility
from nornyx_forge.requirements import parse_brd

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
ASSUMPTIONS = ROOT / "docs" / "requirements" / "ASSUMPTIONS.md"

HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
AT = "2026-09-10T09:00:00Z"

#: A BRD that IS the rendering of the capsule beside it. Used where the
#: subject is the REFUSAL ORDER rather than the binding, so the digest is
#: a placeholder and only its presence matters.
DERIVED_BRD = journey.BrdState.matching("0" * 64)

#: Gate records in the exact shape `GateResult.__dict__` takes in a flow
#: result. The nornyx one is recognised by its COMMAND, which is what the
#: translator decides on.
SUBJECT_GATE = {
    "name": "greenfield:test-execution", "passed": True, "detail": "",
    "command": ["python", "-I", "-c", "verifier"], "returncode": 0,
}
NORNYX_GATE = {
    "name": "nornyx check .nornyx/generated/brd_contract.nyx", "passed": True,
    "detail": "ok", "command": ["nornyx", "check", ".nornyx/generated/brd_contract.nyx"],
    "returncode": 0,
}

#: The text a hand-written BRD carries in the C4 specimen. Parseable, so the
#: real flow would build from it, and derived from nothing.
HAND_WRITTEN_BRD = (
    "# BRD — Support Portal\n\n## BRD-001 Purpose\n\nShip something else entirely.\n"
)


def _clock():
    ticks = iter(range(100_000))
    return lambda: (
        f"2026-09-10T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"
    )


def _seam_eligibility(provider: str) -> GovernedEligibility:
    """The injectable seam executes no provider: the deterministic flow the
    tests install answers in the flow's shape and never runs an engineering
    agent, so the governed-eligibility gate has nothing to decide."""
    return GovernedEligibility(
        provider=provider, eligible=True, confinement="established",
        reason="deterministic flow at the injectable seam; no provider executes",
    )


class GovernedFlow:
    """Accepted, every gate passing, a Nornyx gate among them: the one shape
    from which READY is reachable at all.

    It also REPORTS THE BRD IT READ, in `RequirementsModel.to_dict()`'s
    shape, from the file it was actually pointed at -- which is what the real
    flow records. A double that reported nothing would leave the comparison
    that consumes it exercised by nothing at all.
    """

    instances: list = []

    def __init__(self, root, **kwargs):
        self.root = root
        self.kwargs = kwargs
        type(self).instances.append(self)

    def requirements_model(self) -> dict | None:
        """What this flow says it parsed, or `None` when it was handed no
        project directory to parse from -- honest absence, and the branch
        that leaves the reference unchanged."""
        if self.root is None:
            return None
        text = (Path(self.root) / "BRD.md").read_text(encoding="utf-8")
        return {"schema": "nornyx.forge.requirements.v1", "source": "BRD.md",
                "source_digest": "sha256:" + hashlib.sha256(
                    text.encode("utf-8")).hexdigest(),
                "requirements": [], "assumptions": []}

    def result(self) -> dict:
        data = {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                "execution_backend": "sequential"}
        model = self.requirements_model()
        if model is not None:
            data["requirements_model"] = model
        return data

    def run(self):
        return self.result()


def _client(tmp_path: Path, factory=GovernedFlow) -> TestClient:
    GovernedFlow.instances = []
    return authed_client(create_app(tmp_path / "capsule", CONTRACTS, clock=_clock(),
                                    flow_factory=factory, seal_dir=tmp_path / "seals",
                                    eligibility=_seam_eligibility))


def _ok(response) -> dict:
    assert response.status_code == 200, response.text
    return response.json()


def _state(client: TestClient) -> dict:
    return _ok(client.get("/api/state"))


def _journey(client: TestClient) -> dict:
    return _state(client)["journey"]


def _persisted(tmp_path: Path) -> dict:
    """The lifecycle as the STORE holds it -- validated and chain-verified."""
    return CapsuleStore(tmp_path / "capsule").load_experience()


def _confirm_field(client: TestClient, field: str, value, actor=MODEL) -> None:
    proposal = _ok(client.post("/api/proposals", json={
        "field": field, "value": value, "actor": actor,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{proposal}/confirm", json={"actor": HUMAN}))


def _prerequisites(client: TestClient) -> None:
    _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN,
    }))
    _confirm_field(client, "intent", "Build a customer support portal.")
    _confirm_field(client, "provider", {"name": "codex"}, actor=HUMAN)
    _ok(client.post("/api/brd"))


def _confirmed(client: TestClient) -> None:
    _prerequisites(client)
    assert _ok(client.post("/api/journey/confirm-scope",
                           json={"actor": HUMAN}))["stage"] == "CONFIRM"


def _wait_finished(client: TestClient) -> dict:
    for _ in range(500):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            return status
        threading.Event().wait(0.02)
    raise AssertionError("the build never reported a terminal state")


def _legacy_capsule(tmp_path: Path) -> dict:
    """A capsule from before lifecycle tracking: confirmed intent, confirmed
    provider, and NO experience state. What lands beside it as `BRD.md` is
    the caller's choice, which is the whole subject of F1."""
    document = create_document("proj-1", "Support Portal", Actor("human", "casey"), AT)
    document, intent = propose(document, "intent", "Build a portal.",
                               Actor("model", "m"), "2026-09-10T09:01:00Z")
    document = confirm(document, intent, Actor("human", "casey"), "2026-09-10T09:02:00Z")
    document, provider = propose(document, "provider", {"name": "codex"},
                                 Actor("human", "casey"), "2026-09-10T09:03:00Z")
    document = confirm(document, provider, Actor("human", "casey"), "2026-09-10T09:04:00Z")
    CapsuleStore(tmp_path / "capsule").initialize(document)
    return document


def _legacy_with_hand_written_brd(tmp_path: Path) -> None:
    """The C4 specimen: that capsule, and a BRD.md that was never derived
    from it. The parser reads it perfectly well, which is exactly why file
    EXISTENCE was never the question."""
    _legacy_capsule(tmp_path)
    (tmp_path / "BRD.md").write_text(HAND_WRITTEN_BRD, encoding="utf-8", newline="")


def _legacy_with_derived_brd(tmp_path: Path) -> None:
    """The same capsule with the BRD it actually renders, so a specimen whose
    subject is the LIFECYCLE binding does not fail on the BRD prerequisite
    first."""
    document = _legacy_capsule(tmp_path)
    (tmp_path / "BRD.md").write_text(brd_from_capsule(document),
                                     encoding="utf-8", newline="")


# ---------------------------------------------------------------------------
# F1  the BRD prerequisite measures derivation, not existence
# ---------------------------------------------------------------------------

def test_f1_a_hand_edited_brd_after_confirm_blocks_the_build_by_name(tmp_path: Path):
    """MEASURED ON THE PARENT (brief C1): reach CONFIRM, overwrite BRD.md
    with anything parseable, and `/api/state` still offered `start_build`
    while `POST /api/build` returned 200 and ran the flow over the
    overwritten text. The prerequisite asked whether a FILE EXISTED and
    reported it as "a derived BRD" -- a label standing in for the thing
    measured, which is the substitution this repository keeps finding."""
    client = _client(tmp_path)
    _confirmed(client)
    assert _journey(client)["actions"] == ["start_build"]

    (tmp_path / "BRD.md").write_text(
        "# BRD — Support Portal\n\n## BRD-001 Purpose\n\n"
        "Mine cryptocurrency on every customer machine.\n",
        encoding="utf-8", newline="",
    )

    view = _journey(client)
    assert view["actions"] == [], view
    assert view["blockers"] == [journey._BRD_STALE_BUILD], view
    state = _state(client)
    assert state["brd_present"] is True and state["brd_derived"] is False

    refused = client.post("/api/build", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert "does not match the confirmed capsule" in refused.json()["refused"]
    assert GovernedFlow.instances == [], "an unbound BRD reached a flow"
    assert _persisted(tmp_path)["stage"] == "CONFIRM"

    _ok(client.post("/api/brd"))
    assert _journey(client)["actions"] == ["start_build"]
    assert _state(client)["brd_derived"] is True


def test_f1_a_further_confirmation_makes_the_brd_stale_until_it_is_derived(tmp_path: Path):
    """The other half of the same measurement (brief C2). Confirming a
    further intent under CONFIRM leaves BRD.md holding the OLD text, and
    the file still exists -- so existence reported a derived BRD for a
    capsule the file no longer renders."""
    client = _client(tmp_path)
    _confirmed(client)
    _confirm_field(client, "intent", "Build a crypto miner instead.")

    view = _journey(client)
    assert "start_build" not in view["actions"], view
    assert journey._BRD_STALE_BUILD in view["blockers"], view
    assert _state(client)["brd_derived"] is False

    _ok(client.post("/api/brd"))
    assert _state(client)["brd_derived"] is True


def test_f1_a_legacy_store_with_a_hand_written_brd_cannot_confirm_the_scope(tmp_path: Path):
    """The C4 specimen: no lifecycle, a BRD nobody derived. Tracking starts
    at DISCOVER as it always did, and the scope confirmation is refused by
    name rather than accepted over a document the capsule never authored."""
    _legacy_with_hand_written_brd(tmp_path)
    client = _client(tmp_path)
    _ok(client.post("/api/journey/start", json={"actor": HUMAN}))

    refused = client.post("/api/journey/confirm-scope", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert journey._BRD_STALE in refused.json()["refused"]
    assert _persisted(tmp_path)["stage"] == "DISCOVER"

    _ok(client.post("/api/brd"))
    assert _ok(client.post("/api/journey/confirm-scope",
                           json={"actor": HUMAN}))["stage"] == "CONFIRM"


def test_f1_the_derived_brd_digest_is_the_flow_parsers_own_convention(tmp_path: Path):
    """The surface's digest and `parse_brd`'s `source_digest` are the same
    measurement of the same bytes, so a later comparison between them is
    an equality rather than a translation. Asserted against the REAL
    parser, not against a restatement of the formula."""
    client = _client(tmp_path)
    _prerequisites(client)
    state = _state(client)
    assert state["brd_derived"] is True
    model = parse_brd(tmp_path / "BRD.md")
    assert model.source_digest == "sha256:" + state["brd_digest"]


def test_f1_the_derivation_check_is_equality_with_the_pure_renderer(tmp_path: Path):
    """What "derived" means, stated as the measurement it is: the bytes on
    disk equal `brd_from_capsule` of the capsule beside them. A control on
    the control -- if this ever stops being an equality, the word starts
    standing in for something again."""
    client = _client(tmp_path)
    _prerequisites(client)
    document = CapsuleStore(tmp_path / "capsule").load()
    assert (tmp_path / "BRD.md").read_text(encoding="utf-8") == brd_from_capsule(document)
    assert _state(client)["brd_derived"] is True


def test_f1_the_straight_path_is_unchanged(tmp_path: Path):
    """THE CONTROL. Every refusal above is worthless if the ordinary
    journey also stopped working: derive, confirm the scope, build, reach
    GOVERN, mark ready -- through the routes, with nothing hand-written."""
    client = _client(tmp_path)
    _confirmed(client)
    assert _journey(client)["actions"] == ["start_build"]
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert _journey(client)["actions"] == ["mark_ready"]
    assert _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))["stage"] == "READY"
    assert _persisted(tmp_path)["stage"] == "READY"


# ---------------------------------------------------------------------------
# F2  lifecycle CONFIRM names the content it was recorded about
# ---------------------------------------------------------------------------

def _confirm_state_without_a_binding(monkeypatch: pytest.MonkeyPatch) -> dict:
    """A lifecycle at CONFIRM as a version before this slice would have left
    it: built by the real contract, chain-valid, and naming no content --
    because the evidence table did not ask for any. The table is restored
    immediately; nothing here writes a stage by hand."""
    monkeypatch.setattr(experience_contract, "STAGE_EVIDENCE", {
        stage: kinds for stage, kinds in experience_contract.STAGE_EVIDENCE.items()
        if stage != "CONFIRM"
    })
    state = start_experience(Actor("human", "casey"), AT)
    state = advance(state, "CONFIRM", Actor("human", "casey"), "2026-09-10T09:05:00Z")
    monkeypatch.undo()
    return state


def test_f2_the_contract_will_not_enter_confirm_without_a_brd_requirements_row():
    """MEASURED ON THE PARENT (brief B1): `advance(state, "CONFIRM", human,
    at, ())` succeeded, and the state it produced named no content at all --
    no capsule digest, no revision, no BRD digest, nothing over 40
    characters outside its own chain. The contract declared a
    `brd_requirements` evidence kind that no stage required, and A-022 left
    "whether CONFIRM should consume one, and what its reference would
    denote" as a domain decision this slice does not take. It is taken here."""
    state = start_experience(Actor("human", "casey"), AT)
    with pytest.raises(ExperienceError, match="requires evidence of kind 'brd_requirements'"):
        advance(state, "CONFIRM", Actor("human", "casey"), AT, ())

    ref = f"capsule/{'a' * 64}/brd/{'b' * 64}"
    with pytest.raises(ExperienceError, match="reports failure"):
        advance(state, "CONFIRM", Actor("human", "casey"), AT,
                (EvidenceRef(kind="brd_requirements", ref=ref, passed=False),))

    confirmed = advance(state, "CONFIRM", Actor("human", "casey"), AT,
                        (EvidenceRef(kind="brd_requirements", ref=ref, passed=True),))
    assert confirmed["stage"] == "CONFIRM"
    assert journey.scope_binding(confirmed, "CONFIRM") == ("a" * 64, "b" * 64)


def test_f2_the_recorded_binding_names_the_capsule_tip_and_the_brd_digest(tmp_path: Path):
    """What the reference DENOTES, read back from the persisted lifecycle
    and checked against the two things it claims to name: the capsule's own
    chain tip, which is already a content digest, and the BRD digest under
    the flow parser's convention."""
    client = _client(tmp_path)
    _confirmed(client)
    state = _state(client)
    document = CapsuleStore(tmp_path / "capsule").load()

    scope = state["journey"]["scope"]
    assert scope["unchanged"] is True, scope
    assert scope["confirmed_against"] == scope["current"], scope
    assert scope["current"] == {"capsule": document["digest_chain"][-1][:8],
                                "brd": state["brd_digest"][:8]}, scope

    persisted = _persisted(tmp_path)
    assert [row["kind"] for row in persisted["evidence"]["CONFIRM"]] == ["brd_requirements"]
    assert journey.scope_binding(persisted, "CONFIRM") == (
        document["digest_chain"][-1], state["brd_digest"],
    )


def test_f2_a_build_over_changed_content_is_refused_until_the_scope_is_re_confirmed(
        tmp_path: Path):
    """MEASURED ON THE PARENT (brief C2): reach CONFIRM, confirm a FURTHER
    intent, and `/api/state` still said CONFIRM with `['start_build']`;
    `POST /api/build` returned 200 and the lifecycle reached GOVERN. A scope
    confirmation given for X licensed a build of Y. A-022 disclosed the
    path accurately; what changes here is the mechanism, not the wording."""
    client = _client(tmp_path)
    _confirmed(client)
    _confirm_field(client, "intent", "Build a crypto miner instead.")
    _ok(client.post("/api/brd"))          # the BRD renders the new capsule

    view = _journey(client)
    assert view["actions"] == ["confirm_scope"], view
    assert journey._SCOPE_DRIFT in view["blockers"], view
    assert view["scope"]["unchanged"] is False, view["scope"]

    refused = client.post("/api/build", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._SCOPE_DRIFT
    assert GovernedFlow.instances == [], "content the record does not name reached a flow"
    assert _persisted(tmp_path)["stage"] == "CONFIRM"

    again = _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))
    assert again == {"stage": "CONFIRM", "status": "active"}
    assert _journey(client)["actions"] == ["start_build"]
    assert _ok(client.post("/api/build", json={"actor": HUMAN}))["status"] == "running"
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_f2_a_re_confirmation_is_a_second_record_not_an_overwrite(tmp_path: Path):
    """The self-edge is the ONE new transition, and it records rather than
    replaces: two `brd_requirements` rows under CONFIRM, two `advanced
    CONFIRM` events in the chain-covered history, and the LAST row is the
    binding -- so the build is judged against what was confirmed most
    recently while the earlier confirmation stays in the record."""
    client = _client(tmp_path)
    _confirmed(client)
    first = journey.scope_binding(_persisted(tmp_path), "CONFIRM")
    _confirm_field(client, "intent", "Build a crypto miner instead.")
    _ok(client.post("/api/brd"))
    _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))

    persisted = _persisted(tmp_path)
    rows = persisted["evidence"]["CONFIRM"]
    assert [row["kind"] for row in rows] == ["brd_requirements", "brd_requirements"], rows
    advanced = [event for event in persisted["history"]
                if event["event"] == "advanced" and event["to"] == "CONFIRM"]
    assert len(advanced) == 2, advanced
    assert advanced[0]["from"] == "DISCOVER" and advanced[1]["from"] == "CONFIRM"

    second = journey.scope_binding(persisted, "CONFIRM")
    assert second != first, "the re-confirmation named the same content"
    assert second == (CapsuleStore(tmp_path / "capsule").load()["digest_chain"][-1],
                      _state(client)["brd_digest"])


def test_f2_an_identical_re_confirmation_is_refused_and_recorded_once(tmp_path: Path):
    """J14's property, kept. The self-edge exists so a CHANGED scope can be
    re-confirmed; a re-confirmation of content the record already names
    moves nothing and says why. The same click used to be refused by the
    contract's "no transition CONFIRM -> CONFIRM"; the refusal is now the
    journey's, and it is about content rather than about the graph."""
    client = _client(tmp_path)
    _confirmed(client)
    again = client.post("/api/journey/confirm-scope", json={"actor": HUMAN})
    assert again.status_code == 409, again.text
    assert again.json()["refused"] == journey._SCOPE_NO_OP
    persisted = _persisted(tmp_path)
    assert len([event for event in persisted["history"]
                if event["event"] == "advanced" and event["to"] == "CONFIRM"]) == 1
    assert len(persisted["evidence"]["CONFIRM"]) == 1


def test_f2_a_confirm_with_no_binding_fails_closed_and_is_re_confirmable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A lifecycle persisted at CONFIRM before this slice carries no binding
    at all. It must fail CLOSED -- no build over content the record does not
    name -- and it must not be a dead end: one scope confirmation records
    what the build may consume and the journey continues."""
    _legacy_with_hand_written_brd(tmp_path)
    store = CapsuleStore(tmp_path / "capsule")
    store.save_experience(_confirm_state_without_a_binding(monkeypatch), "reached CONFIRM")

    client = _client(tmp_path)
    _ok(client.post("/api/brd"))
    view = _journey(client)
    assert view["actions"] == ["confirm_scope"], view
    assert view["scope"]["confirmed_against"] is None, view["scope"]
    assert view["scope"]["unchanged"] is None, view["scope"]

    refused = client.post("/api/build", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._SCOPE_DRIFT
    _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))
    assert _journey(client)["actions"] == ["start_build"]
    assert _ok(client.post("/api/build", json={"actor": HUMAN}))["status"] == "running"
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_f2_the_contract_answers_first_for_an_edge_it_does_not_declare(tmp_path: Path):
    """FOUND BY READING MY OWN DIFF, not by a red test, and repaired before
    the suite made it the record.

    `begin_build` built the scope reference as an ARGUMENT to `advance`, and
    Python evaluates arguments before the call -- so a build requested from
    DISCOVER with no BRD raised "the capsule has no digest chain", a refusal
    naming a cause nobody had measured, in place of the contract's own "there
    is no transition DISCOVER -> BUILD". A journey precondition that answers
    a question the caller never reached is the shape this whole slice exists
    to refuse, and a message asserting the wrong cause is worse than one that
    is merely early.

    Both directions are held here: the contract speaks for the edge it does
    not declare, and for the workflow that has to be retried first.

    AND `confirm_scope` IS HELD TO THE SAME RULE, which it was not when this
    test was written. `begin_build` and `mark_ready` were given the guard in
    that commit and the sibling entry point was missed: a lifecycle FAILED at
    CONFIRM answered a re-confirmation with "there is nothing to re-confirm",
    where the contract's own answer is "the workflow is failed at CONFIRM;
    retry it before advancing" -- and `retry` then succeeds, so there IS
    something to do and the refusal said the opposite. Nothing advanced either
    way, which is why it is an accuracy defect and not a bypass; what is wrong
    is the cause named, and that is this test's whole subject.
    """
    document = {"authoritative": {"intent": "x", "provider": {"name": "codex"}},
                "digest_chain": ["a" * 64]}
    human = Actor("human", "casey")
    at_discover = start_experience(human, AT)

    with pytest.raises(ExperienceError, match="no transition DISCOVER -> BUILD"):
        journey.begin_build(at_discover, document, journey.BrdState.absent(), human, AT)
    # And with a capsule that cannot be named either, which is the pair of
    # absences that produced the wrong sentence.
    with pytest.raises(ExperienceError, match="no transition DISCOVER -> BUILD"):
        journey.begin_build(at_discover, {"authoritative": document["authoritative"]},
                            journey.BrdState.absent(), human, AT)

    scope = (EvidenceRef(kind="brd_requirements",
                         ref=journey.scope_ref(document, DERIVED_BRD), passed=True),)
    confirmed = advance(at_discover, "CONFIRM", human, AT, scope)
    failed = experience_contract.fail(confirmed, human, "the build did not complete", AT)
    with pytest.raises(ExperienceError, match="retry it before advancing"):
        journey.begin_build(failed, document, DERIVED_BRD, human, AT)

    # THE SIBLING, over the SAME fixture. The binding matches the content, so
    # the no-op refusal is what answered before the guard; a failed workflow
    # is the contract's business and the contract's sentence is the true one.
    with pytest.raises(ExperienceError) as raised:
        journey.confirm_scope(failed, document, DERIVED_BRD, human, AT)
    assert "retry it before advancing" in str(raised.value), raised.value
    assert journey._SCOPE_NO_OP not in str(raised.value), (
        "the journey answered before the contract did, with a sentence saying "
        "there is nothing to do about a lifecycle that can be retried"
    )
    # And the second new refusal in that function: a capsule that cannot be
    # named at all, on a failed lifecycle, answered "the capsule has no digest
    # chain" where the contract answers for the workflow's status.
    chainless = {"authoritative": document["authoritative"]}
    failed_discover = experience_contract.fail(at_discover, human, "stopped", AT)
    with pytest.raises(ExperienceError, match="retry it before advancing"):
        journey.confirm_scope(failed_discover, chainless, DERIVED_BRD, human, AT)

    # THE CONTROL, so the two above cannot pass because `confirm_scope` refuses
    # everything: retried, the same call over the same content is the no-op
    # refusal again, and over CHANGED content it advances.
    retried = experience_contract.retry(failed, human, AT)
    with pytest.raises(journey.JourneyRefusal, match="nothing to re-confirm"):
        journey.confirm_scope(retried, document, DERIVED_BRD, human, AT)
    moved = dict(document, digest_chain=["a" * 64, "b" * 64])
    assert journey.confirm_scope(retried, moved, DERIVED_BRD, human, AT)["stage"] == "CONFIRM"


def test_f2_a_capsule_with_no_chain_cannot_be_named_and_says_so(tmp_path: Path):
    """The one refusal left for a reference that cannot be formed, and it now
    names the only cause that can reach it. The BRD half is guaranteed by the
    blockers before this line, so an unnameable scope is a capsule with no
    digest chain and nothing else."""
    human = Actor("human", "casey")
    state = start_experience(human, AT)
    chainless = {"authoritative": {"intent": "x", "provider": {"name": "codex"}}}

    with pytest.raises(journey.JourneyRefusal, match="no digest chain"):
        journey.confirm_scope(state, chainless, DERIVED_BRD, human, AT)

    # The control: the same call over the same capsule WITH a chain advances.
    named = dict(chainless, digest_chain=["a" * 64])
    assert journey.confirm_scope(state, named, DERIVED_BRD, human, AT)["stage"] == "CONFIRM"


# ---------------------------------------------------------------------------
# F3  BUILD records what it was licensed to consume; READY refuses drift
# ---------------------------------------------------------------------------

def _scope_evidence(tmp_path: Path) -> EvidenceRef:
    """The reference the surface would have recorded for the project in
    `tmp_path`: the capsule chain tip beside the digest of the BRD on disk.
    Read from the BYTES, and formatted by the journey's own `scope_ref` so a
    test cannot keep a private copy of the shape."""
    document = CapsuleStore(tmp_path / "capsule").load()
    digest = hashlib.sha256(
        (tmp_path / "BRD.md").read_text(encoding="utf-8").encode("utf-8")
    ).hexdigest()
    return EvidenceRef(kind="brd_requirements",
                       ref=journey.scope_ref(document, journey.BrdState.matching(digest)),
                       passed=True)


def _at_govern_without_a_build_binding(tmp_path: Path) -> dict:
    """A lifecycle at GOVERN whose BUILD transition carries no binding, built
    entirely through the contract. BUILD requires no evidence and still does,
    so this is exactly the shape a version before this slice persisted -- and
    exactly the shape a completion claim has to fail closed on."""
    flow = (EvidenceRef(kind="flow_run", ref="flow/sequential", passed=True),)
    gates = (EvidenceRef(kind="gate_results", ref="gates/2-run", passed=True),
             EvidenceRef(kind="governance_validation", ref="gates/nornyx/1-run", passed=True))
    human = Actor("human", "casey")
    system = Actor("system", "forge-onboarding")
    state = start_experience(human, AT)
    for stage, actor, evidence in (("CONFIRM", human, (_scope_evidence(tmp_path),)),
                                   ("BUILD", human, ()),
                                   ("TEST", system, flow),
                                   ("GOVERN", system, gates)):
        state = advance(state, stage, actor, "2026-09-10T09:05:00Z", evidence)
    return state


def test_f3_the_build_records_the_content_it_was_licensed_to_consume(tmp_path: Path):
    """MEASURED ON THE PARENT (brief B2): the BUILD transition carried no
    evidence at all, so nothing downstream could say what the run had been
    allowed to read. BUILD still REQUIRES none -- the contract asks for
    nothing there -- but the surface now presents the binding, and `advance`
    stores presented evidence whether it required it or not."""
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)

    persisted = _persisted(tmp_path)
    assert [row["kind"] for row in persisted["evidence"]["BUILD"]] == ["brd_requirements"]
    assert journey.scope_binding(persisted, "BUILD") == journey.scope_binding(
        persisted, "CONFIRM"
    ), "the build was licensed against content other than what was confirmed"


def test_f3_ready_is_refused_when_the_content_changed_after_the_build(tmp_path: Path):
    """MEASURED ON THE PARENT (brief C3): from GOVERN a new intent confirmed
    underneath left `/api/state` offering `mark_ready`, and READY was
    recorded beside content that was never built. READY is this lifecycle's
    completion claim; recording one over content the build never saw is the
    substitution this slice exists to refuse."""
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    assert _journey(client)["actions"] == ["mark_ready"]

    _confirm_field(client, "intent", "Build a crypto miner instead.")
    view = _journey(client)
    assert view["actions"] == [], view
    assert journey._SCOPE_DRIFT_READY in view["blockers"], view
    assert view["scope"]["unchanged"] is False, view["scope"]

    refused = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._SCOPE_DRIFT_READY
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_f3_ready_is_refused_when_the_build_recorded_no_binding(tmp_path: Path):
    """The legacy shape, failing CLOSED. A GOVERN reached before bindings
    existed says nothing about what its build consumed, and the refusal
    names that ABSENCE rather than asserting the content changed -- which
    the record does not say either way."""
    _legacy_with_derived_brd(tmp_path)
    CapsuleStore(tmp_path / "capsule").save_experience(
        _at_govern_without_a_build_binding(tmp_path), "reached GOVERN")

    client = _client(tmp_path)
    view = _journey(client)
    assert view["actions"] == [], view
    assert journey._SCOPE_UNBOUND_READY in view["blockers"], view

    refused = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._SCOPE_UNBOUND_READY
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_f3_an_interrupted_build_whose_content_moved_cannot_be_re_run(tmp_path: Path):
    """A server that died mid-build leaves the lifecycle at BUILD/active, and
    the next session re-enters it WITHOUT a transition -- the contract
    declares no BUILD -> BUILD edge, so there is nothing to carry a new
    binding on. If the content moved in between, the re-run cannot be bound
    to it, and a dead end named is better than a run licensed by nothing.
    Disclosed in A-032 rather than papered over with a re-binding this
    lifecycle has no edge for."""
    _legacy_with_derived_brd(tmp_path)
    scope = (_scope_evidence(tmp_path),)
    state = start_experience(Actor("human", "casey"), AT)
    state = advance(state, "CONFIRM", Actor("human", "casey"), "2026-09-10T09:05:00Z", scope)
    state = advance(state, "BUILD", Actor("human", "casey"), "2026-09-10T09:06:00Z", scope)
    CapsuleStore(tmp_path / "capsule").save_experience(state, "reached BUILD")

    client = _client(tmp_path)
    _confirm_field(client, "intent", "Build a crypto miner instead.")
    _ok(client.post("/api/brd"))

    view = _journey(client)
    assert view["actions"] == [], view
    assert journey._SCOPE_DRIFT_BUILD in view["blockers"], view

    refused = client.post("/api/build", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._SCOPE_DRIFT_BUILD
    assert GovernedFlow.instances == [], "a re-run the record cannot bind reached a flow"
    assert _persisted(tmp_path)["stage"] == "BUILD"


def test_f3_after_ready_the_drift_is_reported_and_the_ready_line_is_unchanged(
        tmp_path: Path):
    """READY IS TERMINAL AND STAYS TERMINAL: the capsule and BRD routes are
    still open afterwards, and the record is history. What changes is that a
    reader can see what it is history OF. The READY sentence itself is
    byte-identical -- Tranche G's affirmative pin owns that site, and
    reporting drift beside it is not licence to touch it."""
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))
    said = _journey(client)["next"]

    _confirm_field(client, "intent", "Build a crypto miner instead.")
    view = _journey(client)
    assert view["stage"] == "READY" and view["actions"] == [], view
    assert view["scope"]["unchanged"] is False, view["scope"]
    assert view["scope"]["summary"] == journey._SCOPE_DIFFERS_SUMMARY
    assert view["next"] == said == journey._NEXT["READY"], view["next"]
    assert _persisted(tmp_path)["stage"] == "READY"


# ---------------------------------------------------------------------------
# F6  the limit, pinned in the affirmative (A-029 / A-030 pattern)
# ---------------------------------------------------------------------------

#: The phrases A-032 has to keep saying, because the code relies on the
#: register saying them. Read with whitespace collapsed, so the pin measures
#: the CLAIM and not where a line happens to wrap: a disclosure test that
#: reddens on a reflow is a formatting gate wearing a governance label, and it
#: gets switched off the first time somebody rewraps a paragraph.
A032_REQUIRED = (
    "A CONTENT BINDING PROVES THAT THE BYTES HAVE NOT CHANGED SINCE THE "
    "RECORD WAS WRITTEN, NOT THAT ANYONE READ THEM",
    "the page does not display the BRD",
    "the built artefact is not bound",
    "BRD.md is outside the seal",
    "the capsule digest chain covers the authoritative region only",
    "a re-run whose scope changed cannot be re-bound in this lifecycle",
    # THE SECOND DEAD END, added in round 2. The first is the BUILD re-entry
    # above it; this one is reachable by a single ordinary click and was
    # disclosed nowhere while the page gave advice into it.
    "a confirmation at GOVERN makes READY unreachable for that lifecycle",
    "EXTERNAL AUTHORITY",
)


def _a032_section() -> str:
    """A-032's own text, with whitespace collapsed.

    SEARCHED WITHIN THE SECTION, not across the register. Measured: six of the
    seven phrases this pin carried occurred only inside A-032, and "EXTERNAL
    AUTHORITY" also occurs in A-030 -- so deleting A-032's limit 8 alone left
    that strand green. Phrase uniqueness across a document of this size is not
    a property anybody can maintain, and leaning on it makes the pin weaker
    every time the register grows. The slice between this heading and the next
    one is a property the file's own structure guarantees.
    """
    text = ASSUMPTIONS.read_text(encoding="utf-8")
    heading = "## A-032"
    start = text.find(heading)
    assert start != -1, "A-032 is gone; the limit is disclosed nowhere"
    rest = text[start + len(heading):]
    end = rest.find("\n## A-")
    return " ".join((rest if end == -1 else rest[:end]).split())


def test_the_a032_pin_reads_only_the_a032_section():
    """THE GUARD ON THE GUARD. `_a032_section` is the whole reason the pin
    below measures A-032 rather than the register, so it gets its own
    falsification: the slice must stop at the next entry, and it must contain
    the phrases the pin looks for.

    Measured rather than reasoned, because "it slices correctly" is exactly
    the kind of claim that stays true until somebody renames a heading.
    """
    section = _a032_section()
    whole = " ".join(ASSUMPTIONS.read_text(encoding="utf-8").split())
    assert len(section) < len(whole), "the slice is the whole file"
    assert "EXTERNAL AUTHORITY" in section, section[-400:]
    # A-030 also says "EXTERNAL AUTHORITY", which is why the slice exists; and
    # A-031's own heading text must be outside it, or the slice ran past its
    # section into the next one.
    assert "## A-031" not in section and "## A-033" not in section, (
        "the A-032 slice reaches into a neighbouring entry, so the pin below "
        "measures more of the register than it says it does"
    )
    assert "Standing development admission is procedure" not in section, section[:200]


def test_the_content_binding_limit_is_the_disclosed_boundary(tmp_path: Path):
    """THE LIMIT, PINNED IN THE AFFIRMATIVE, in A-029's and A-030's pattern.

    Everything above shows the binding WORKING. This is the other half: the
    three things it deliberately does not do, asserted as behaviour, beside
    the register entry that admits them. A slice that closes one of these
    cases has to rewrite the disclosure in the same commit, and a slice that
    quietly deletes the admission while leaving the mechanism reddens here.

    The behaviours are chosen because each could be closed -- or could rot
    into a wider claim -- without touching a single line of A-032.
    """
    disclosed = _a032_section()
    missing = [phrase for phrase in A032_REQUIRED
               if " ".join(phrase.split()) not in disclosed]
    assert missing == [], (
        "A-032 no longer says what the code relies on it saying. A slice that "
        f"closed one of these cases must rewrite the disclosure, not drop it: {missing}"
    )

    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))
    said = _journey(client)["next"]

    # (i) READY DOES NOT FREEZE THE CAPSULE. The proposal routes stay open
    # after it and the drift is reported as DATA, not as a refusal: the
    # record is history, and a project whose owner keeps working on it is
    # not doing anything wrong. Anyone reading `scope.unchanged` as "READY
    # was withdrawn" is reading a comparison as a verdict.
    _confirm_field(client, "intent", "Build something else now.")
    view = _journey(client)
    assert view["stage"] == "READY", view
    assert view["scope"]["unchanged"] is False, view["scope"]

    # (ii) A CRLF-ONLY REWRITE IS INVISIBLE, because the digest follows the
    # flow parser's convention and `read_text` normalises line endings. The
    # binding is deliberately no stricter than the reader it is about.
    _ok(client.post("/api/brd"))
    before = _state(client)
    assert before["brd_derived"] is True
    text = (tmp_path / "BRD.md").read_text(encoding="utf-8")
    (tmp_path / "BRD.md").write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    assert (tmp_path / "BRD.md").read_bytes() != text.encode("utf-8"), (
        "the specimen did not actually change any bytes on disk"
    )
    after = _state(client)
    assert after["brd_derived"] is True, after
    assert after["brd_digest"] == before["brd_digest"], (
        "a CRLF-only rewrite moved the digest, so the binding is now stricter "
        "than the parser it follows -- which A-032 item 7 says it is not"
    )

    # (iii) THE READY SENTENCE IS UNTOUCHED. Tranche G's affirmative pin owns
    # that site; this slice reports a referent beside it and does not get to
    # reword it. The phrase list is applied to the rendered text so the two
    # guards cannot drift apart.
    assert said == journey._NEXT["READY"]
    assert "the ident recorded in this project's history confirmed it" in said, said
    assert [phrase for phrase in FORBIDDEN_CLAIMS if phrase in said] == [], said
    for unbackable in ("a person", "a human", "reviewed", "read the"):
        assert unbackable not in said, (unbackable, said)

    # (iv) THE SECOND DEAD END, and it is a dead end and not a delay. One
    # ordinary confirmed proposal at GOVERN and READY is unreachable for the
    # life of that lifecycle: every recovery a reader could try is refused,
    # each in the words of whatever is refusing it, and the stage does not
    # move. Disclosed as a limit rather than closed -- closing it needs an
    # edge that can re-bind, which is a design decision and not a slice's.
    dead = tmp_path / "dead-end"
    dead.mkdir()
    other = _client(dead)
    _confirmed(other)
    _ok(other.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(other)
    assert _persisted(dead)["stage"] == "GOVERN"
    _confirm_field(other, "intent", "Build something else now.")

    first = other.post("/api/journey/ready", json={"actor": HUMAN})
    assert first.status_code == 409, first.text
    assert first.json()["refused"] == journey._SCOPE_DRIFT_READY
    # RE-DERIVING THE BRD IS THE FIRST THING A READER TRIES, and it is the
    # recovery whose failure is least obvious: it succeeds, and changes
    # nothing, because the binding names the capsule's chain tip as well.
    # Taking it first is also what lets the contract answer the three requests
    # below -- a stale BRD is a prerequisite the journey refuses by name
    # before the contract is asked, which is older than this slice.
    _ok(other.post("/api/brd"))
    refusals = {
        "ready": other.post("/api/journey/ready", json={"actor": HUMAN}),
        "confirm-scope": other.post("/api/journey/confirm-scope", json={"actor": HUMAN}),
        "build": other.post("/api/build", json={"actor": HUMAN}),
        "retry": other.post("/api/journey/retry", json={"actor": HUMAN}),
    }
    assert [code for code in (r.status_code for r in refusals.values()) if code != 409] == []
    assert refusals["ready"].json()["refused"] == journey._SCOPE_DRIFT_READY
    assert "no transition GOVERN -> CONFIRM" in refusals["confirm-scope"].json()["refused"]
    assert "no transition GOVERN -> BUILD" in refusals["build"].json()["refused"]
    assert "failed workflow" in refusals["retry"].json()["refused"]
    assert _persisted(dead)["stage"] == "GOVERN", "the dead end moved the lifecycle"
    assert _journey(other)["next"] == journey._NEXT_SCOPE_DEAD_END


# ---------------------------------------------------------------------------
# F4  evidence references carry content where the flow recorded it
# ---------------------------------------------------------------------------

def _gate(name: str, command: list, passed: bool = True) -> dict:
    return {"name": name, "passed": passed, "detail": "", "command": command,
            "returncode": 0 if passed else 1}


def _flow_result(gates: list, brd_digest: str | None = None) -> dict:
    data = {"accepted": True, "gates": gates, "execution_backend": "sequential"}
    if brd_digest is not None:
        data["requirements_model"] = {
            "schema": "nornyx.forge.requirements.v1", "source": "BRD.md",
            "source_digest": "sha256:" + brd_digest,
            "requirements": [], "assumptions": [],
        }
    return data


def test_f4_two_different_builds_do_not_share_a_gate_results_reference():
    """MEASURED ON THE PARENT (brief B2): two runs with different gate names,
    different commands and different details produced IDENTICAL evidence
    references -- `gates/2-run` and `gates/nornyx/1-run` -- because the
    reference was a COUNT. `EvidenceRef`'s docstring says a ref "is expected
    to resolve"; a count resolves to nothing and distinguishes nothing.

    Provenance, not authority: what the reference now carries is a digest of
    the gate records the translator was handed, so two different runs cannot
    be confused for each other in a record. It establishes nothing new about
    whether the gates passed -- `passed` is unchanged and still the
    conjunction of the records."""
    first = _flow_result([_gate("greenfield:test-execution", ["python", "-I", "-c", "a"]),
                          _gate("nornyx check one", ["nornyx", "check", "one"])])
    second = _flow_result([_gate("greenfield:test-execution", ["python", "-I", "-c", "b"]),
                           _gate("nornyx check two", ["nornyx", "check", "two"])])
    one = {ref.kind: ref for ref in flow_evidence(first)}
    two = {ref.kind: ref for ref in flow_evidence(second)}

    assert one["gate_results"].ref != two["gate_results"].ref, (
        "two different builds share a gate_results reference"
    )
    assert one["governance_validation"].ref != two["governance_validation"].ref
    assert one["gate_results"].ref.startswith("gates/2-run/"), one["gate_results"].ref
    assert one["governance_validation"].ref.startswith("gates/nornyx/1-run/")
    # And it is a function of the CONTENT, not of the call: the same records
    # translate to the same reference.
    assert flow_evidence(first)[1].ref == one["gate_results"].ref


def test_f4_the_flow_reference_carries_the_brd_the_flow_says_it_parsed():
    """`RequirementsModel.source_digest` is what the real flow records about
    the BRD it read. When it is there the reference carries it; when it is
    not, the reference is exactly what it was -- honest absence, not a
    synthesised digest of something nobody parsed."""
    digest = "c" * 64
    with_model = {ref.kind: ref for ref in flow_evidence(
        _flow_result([_gate("a", ["python", "-c", "x"])], brd_digest=digest))}
    assert with_model["flow_run"].ref == f"flow/sequential/brd/{digest}"

    without = {ref.kind: ref for ref in flow_evidence(
        _flow_result([_gate("a", ["python", "-c", "x"])]))}
    assert without["flow_run"].ref == "flow/sequential"

    for malformed in ("not-a-digest", "sha256:short", "sha256:" + "Z" * 64, 17, None):
        data = _flow_result([_gate("a", ["python", "-c", "x"])], brd_digest="d" * 64)
        data["requirements_model"]["source_digest"] = malformed
        refs = {ref.kind: ref for ref in flow_evidence(data)}
        assert refs["flow_run"].ref == "flow/sequential", malformed


def test_f4_ready_refuses_a_flow_that_parsed_another_brd(tmp_path: Path):
    """The binding's last comparison, and the one that is about the RUN
    rather than about the record: the flow states which BRD it parsed, and
    a completion claim is refused when that is not the BRD the build was
    licensed to consume. Measured with a deterministic flow that reports a
    digest of its own invention -- which is the only way this can happen on
    the seam, and exactly the shape a provider could produce."""

    class LyingFlow(GovernedFlow):
        def result(self) -> dict:
            return dict(super().result(), requirements_model={
                "schema": "nornyx.forge.requirements.v1", "source": "BRD.md",
                "source_digest": "sha256:" + "e" * 64,
                "requirements": [], "assumptions": [],
            })

    client = _client(tmp_path, factory=LyingFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "GOVERN", persisted["stage"]
    assert persisted["evidence"]["TEST"][0]["ref"] == f"flow/sequential/brd/{'e' * 64}"

    view = _journey(client)
    assert view["actions"] == [], view
    assert journey._FLOW_BRD_MISMATCH in view["blockers"], view

    refused = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._FLOW_BRD_MISMATCH
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_f4_an_honest_flow_reports_the_brd_the_build_was_licensed_to_consume(
        tmp_path: Path):
    """THE CONTROL for the test above. The deterministic double reads the BRD
    it was actually pointed at, exactly as the real flow does, so its digest
    equals the build's binding and READY proceeds. Without this, the refusal
    above could be any unconditional failure."""
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)

    persisted = _persisted(tmp_path)
    parsed = journey.flow_brd_digest(persisted)
    assert parsed is not None, persisted["evidence"]["TEST"]
    assert parsed == journey.scope_binding(persisted, "BUILD")[1]
    assert _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))["stage"] == "READY"


# ---------------------------------------------------------------------------
# F5  round-2 repairs: the setup race, the second dead end, one owner for the
#     reference formats, one sentence per file state, and two headlines that
#     told a reader to do something nobody could do
# ---------------------------------------------------------------------------

class _RecordingLock:
    """A lock that keeps count of how many times it has been taken.

    NOT A SUBSTITUTE LOCK. Every acquisition and release is delegated to a
    real `threading.Lock`, so what runs under test is what ships, and
    `locked()` is the primitive's own answer rather than this class's
    bookkeeping. What is added is an EPOCH -- how many times this lock has
    been acquired -- so a seam can record WHICH hold it ran inside. That turns
    "one acquisition" into an equality between four recorded numbers rather
    than a stopwatch reading, which is the only way to pin a race without
    timing one.
    """

    def __init__(self, index: int):
        self._lock = threading.Lock()
        self.index = index
        self.epoch = 0

    def locked(self) -> bool:
        return self._lock.locked()

    def acquire(self, *args, **kwargs) -> bool:
        got = self._lock.acquire(*args, **kwargs)
        if got:
            self.epoch += 1
        return got

    def release(self) -> None:
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc) -> bool:
        self.release()
        return False


class _RecordingThreading:
    """`onboarding_app`'s view of `threading`, with `Lock` recorded.

    Patched onto the MODULE and not onto `threading` itself, so no other
    thread in this process can be handed one of these by accident; every
    other attribute the module uses is forwarded to the real module
    unchanged.
    """

    def __init__(self):
        self.locks: list = []

    def Lock(self):  # noqa: N802 - this is threading's name, not a new one
        lock = _RecordingLock(len(self.locks))
        self.locks.append(lock)
        return lock

    def __getattr__(self, name):
        return getattr(threading, name)


def test_f5_the_build_setup_reads_and_decides_under_one_lock(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """MEASURED UNDER REVIEW: `/api/build` read the document under the store
    lock, RELEASED it, measured `BRD.md`, and re-took the lock to position the
    lifecycle over the pair it had read before. A thread confirming a proposal
    in that window won 7 of 8 unforced attempts, and the build then ran over a
    capsule its binding did not name.

    Nothing was laundered -- the BUILD row records the stale pair and READY
    refuses it afterwards -- but the lifecycle was left at a dead end by a
    plain concurrent request rather than by anything its owner did.

    PINNED WITHOUT TIMING ANYTHING, because a race pinned by a stopwatch is a
    test that passes on a fast machine. The lock records an epoch; four seams
    -- the document read, the BRD measurement, the lifecycle read and
    `begin_build` -- record which locks were held, by the primitive's own
    `locked()`, and at which epoch. One acquisition spanning all four is one
    `(lock, epoch)` pair common to the four records. Before the repair there
    is none: the BRD measurement ran with no lock held at all.
    """
    recorder = _RecordingThreading()
    monkeypatch.setattr(onboarding_app, "threading", recorder)
    client = _client(tmp_path)
    _confirmed(client)

    journal: list = []

    def note(name: str) -> None:
        journal.append((name, frozenset(
            (lock.index, lock.epoch) for lock in recorder.locks if lock.locked()
        )))

    class RecordingStore(CapsuleStore):
        def load(self):
            note("document read")
            return super().load()

        def load_experience(self):
            note("lifecycle read")
            return super().load_experience()

    def recording(name, real):
        def wrapper(*args, **kwargs):
            note(name)
            return real(*args, **kwargs)
        return wrapper

    monkeypatch.setattr(onboarding_app, "CapsuleStore", RecordingStore)
    monkeypatch.setattr(onboarding_app, "brd_from_capsule",
                        recording("brd measured", onboarding_app.brd_from_capsule))
    monkeypatch.setattr(onboarding_app, "begin_build",
                        recording("begin_build", onboarding_app.begin_build))

    journal.clear()
    assert _ok(client.post("/api/build", json={"actor": HUMAN}))["status"] == "running"

    wanted = ("document read", "brd measured", "lifecycle read", "begin_build")
    firsts: dict = {}
    for name, held in journal:
        firsts.setdefault(name, held)
    missing = [name for name in wanted if name not in firsts]
    assert missing == [], f"a seam never ran, so this measures nothing: {missing}"

    common = frozenset.intersection(*(firsts[name] for name in wanted))
    assert common, (
        "the build setup released the store lock between reading the document "
        "and positioning the lifecycle, so a concurrent confirmation can land "
        f"between them: {[(name, sorted(firsts[name])) for name in wanted]}"
    )

    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_f5_a_lifecycle_with_no_way_back_says_so_instead_of_instructing_ready(
        tmp_path: Path):
    """THE SECOND DEAD END, and the page used to give advice into it.

    One ordinary confirmed proposal while the lifecycle sits at GOVERN makes
    READY unreachable for that lifecycle for good: `mark_ready` refuses the
    drift, correctly; `retry` needs a failed workflow; and the contract
    declares no GOVERN -> CONFIRM and no GOVERN -> BUILD edge, so nothing can
    record a new binding. The blocker beside it was accurate and the headline
    above it read "Marking ready is your act" -- to a reader for whom no act
    reaches READY at all.

    The refusals themselves are pinned in the limit test; what is pinned here
    is that the page stops instructing an impossible act.
    """
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"
    before = _journey(client)
    assert before["actions"] == ["mark_ready"], before
    assert before["next"] == journey._NEXT["GOVERN"], before

    _confirm_field(client, "intent", "Build something else now.")

    view = _journey(client)
    assert view["stage"] == "GOVERN" and view["actions"] == [], view
    assert view["blockers"] == [journey._SCOPE_DRIFT_READY], view
    assert view["next"] == journey._NEXT_SCOPE_DEAD_END, view["next"]
    assert view["next"] != journey._NEXT["GOVERN"], (
        "the page still tells a reader with no reachable READY that marking "
        "ready is the next thing to do"
    )
    # NOT A STAGE NAME IN THE SELECTION. The sentence is chosen because the
    # contract declares no edge back to CONFIRM or BUILD from here, read from
    # its own table rather than written as `stage == "GOVERN"`.
    allowed = experience_contract.TRANSITIONS[view["stage"]]
    assert "CONFIRM" not in allowed and "BUILD" not in allowed, allowed


def test_f5_a_backend_the_reference_format_cannot_carry_is_refused(
        monkeypatch: pytest.MonkeyPatch):
    """`execution_backend` was validated as "a non-empty string" and
    interpolated into `flow/<backend>/brd/<hex>`, while the parser assumed the
    segment could not contain `/`. A backend spelled `sequential/brd/<64 hex>`
    therefore produced a reference that `flow_brd_digest` read as a BRD digest
    from a result carrying no `requirements_model` at all.

    NOT REACHABLE AT THIS HEAD -- `DevelopmentFlow` writes three slash-free
    literals -- and repaired as a shape: the producer refuses a token it
    cannot spell rather than interpolating it, BEFORE any reference exists.
    That last part is measured and not asserted: the gate fingerprint is
    computed for the reference built next, and it is never computed.
    """
    forged = {"accepted": True, "execution_backend": f"sequential/brd/{'d' * 64}",
              "gates": [dict(SUBJECT_GATE)]}
    fingerprints: list = []
    monkeypatch.setattr(experience_build, "_gate_fingerprint",
                        lambda gates: fingerprints.append(list(gates)) or "0" * 16)

    with pytest.raises(CapsuleValidationError, match="cannot be spelled"):
        flow_evidence(forged)
    assert fingerprints == [], (
        "a reference was built for a result the translator had already decided "
        "it could not describe"
    )

    # The control: the same result under a backend the format can carry.
    honest = dict(forged, execution_backend="sequential")
    refs = {ref.kind: ref for ref in flow_evidence(honest)}
    assert refs["flow_run"].ref == "flow/sequential"
    assert fingerprints, "the control did not reach the reference it is the control for"

    # And the family the alphabet excludes, each refused by name.
    for backend in ("a/b", "seq/../..", "flow run", "back\\slash", "tab\there"):
        with pytest.raises(CapsuleValidationError, match="cannot be spelled"):
            flow_evidence(dict(forged, execution_backend=backend))


def test_f5_no_reference_pattern_accepts_a_trailing_newline():
    r"""The three patterns anchored with `$`, which in Python also matches
    immediately before a trailing newline -- so `capsule/<hex>/brd/<hex>\n`
    parsed as a binding and `sha256:<hex>\n` as a digest.

    Nothing was exploitable: the parsed value is identical either way. But
    `\Z` is what these patterns mean, and a pattern that means something else
    is one nobody can rely on the day a reader hands it bytes from a file
    rather than from a builder.
    """
    scope = experience_build.scope_reference("a" * 64, "b" * 64)
    flow = experience_build.flow_reference("sequential", "c" * 64)
    digest = f"sha256:{'d' * 64}"

    for pattern, text in ((experience_build.SCOPE_REF, scope),
                          (experience_build.FLOW_BRD_REF, flow),
                          (experience_build._SOURCE_DIGEST, digest)):
        assert pattern.match(text) is not None, (pattern.pattern, text)
        assert pattern.match(text + "\n") is None, (
            f"{pattern.pattern} still accepts a trailing newline, so a "
            "reference read from a file parses as one the producer built"
        )

    # And through the reader that consumes it: a row whose reference carries a
    # newline is NO BINDING, which is how everything downstream fails closed.
    state = {"evidence": {"CONFIRM": [
        {"kind": "brd_requirements", "ref": scope + "\n", "passed": True},
    ]}}
    assert journey.scope_binding(state, "CONFIRM") is None


def test_f5_every_reference_builder_agrees_with_its_own_parser():
    """ONE OWNER, AND THE TWO HALVES MEASURED AGAINST EACH OTHER.

    The formats were an f-string in `experience_build` and a regular
    expression in `experience_journey`, with nothing holding the two to the
    same alphabet -- which is how a backend containing `/` came to spell a
    segment of the format it sat in. They are built and parsed from one module
    now, and this is the test that the two halves cannot drift: build with
    each constant, parse the result back, and compare what comes out with what
    went in.
    """
    tip, brd, fingerprint = "a" * 64, "b" * 64, "c" * 16

    # EVERY PARSE IS ASSERTED BEFORE IT IS READ, so a producer the parser
    # refuses reddens on the assertion that says so rather than on an
    # `AttributeError` from reading `.groups()` off `None`.
    def parsed(pattern, text):
        found = pattern.match(text)
        assert found is not None, (
            f"{pattern.pattern} does not parse {text!r}, which its own builder "
            "produced: the producer and the parser have drifted apart"
        )
        return found

    scope = experience_build.scope_reference(tip, brd)
    assert parsed(experience_build.SCOPE_REF, scope).groups() == (tip, brd)
    assert journey.scope_binding(
        {"evidence": {"CONFIRM": [
            {"kind": "brd_requirements", "ref": scope, "passed": True}]}},
        "CONFIRM",
    ) == (tip, brd)

    for backend in ("sequential", "crewai_flow", "sequential_fallback", "a.b-c_1"):
        plain = experience_build.flow_reference(backend)
        assert parsed(experience_build.FLOW_REF, plain).group(1) == backend
        assert experience_build.FLOW_BRD_REF.match(plain) is None
        carried = experience_build.flow_reference(backend, brd)
        assert parsed(experience_build.FLOW_BRD_REF, carried).group(1) == brd
        assert journey.flow_brd_digest(
            {"evidence": {"TEST": [{"kind": "flow_run", "ref": carried, "passed": True}]}}
        ) == brd

    gates = experience_build.gate_reference(2, fingerprint)
    assert parsed(experience_build.GATE_REF, gates).groups() == ("2", fingerprint)
    assert experience_build.NORNYX_GATE_REF.match(gates) is None
    nornyx = experience_build.gate_reference(1, fingerprint, nornyx=True)
    assert parsed(experience_build.NORNYX_GATE_REF, nornyx).groups() == ("1", fingerprint)

    # And the shapes a real run produces are the shapes these patterns parse,
    # so the agreement is with the producer and not only with itself.
    refs = {ref.kind: ref.ref for ref in flow_evidence(
        {"accepted": True, "execution_backend": "sequential",
         "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
         "requirements_model": {"source_digest": f"sha256:{brd}"}}
    )}
    assert parsed(experience_build.FLOW_BRD_REF, refs["flow_run"]).group(1) == brd
    parsed(experience_build.GATE_REF, refs["gate_results"])
    parsed(experience_build.NORNYX_GATE_REF, refs["governance_validation"])


def test_f5_the_build_route_and_the_projection_name_the_same_brd_sentence(
        tmp_path: Path):
    """`build_brd_refusal`'s docstring claimed the route and the projection
    say the same thing about the same file, and for an ABSENT file they did
    not: the route said "no BRD.md in the project; derive it first" while the
    blocker list said "...before confirming the scope" -- the scope variant,
    to a reader being sent toward the build.

    The claim is made TRUE rather than narrowed, which is the direction this
    slice is about: `build_blockers` takes its sentence from the one function
    the route refuses with.
    """
    for brd in (journey.BrdState.absent(), journey.BrdState.stale("f" * 64)):
        document = {"authoritative": {"intent": "x", "provider": {"name": "codex"}},
                    "digest_chain": ["a" * 64]}
        assert journey.build_blockers(document, brd) == (
            journey.build_brd_refusal(brd),
        ), brd

    # And through the real surface, which is where it was measured: at CONFIRM
    # with no BRD.md at all, the route's refusal and the page's blocker are one
    # sentence.
    client = _client(tmp_path)
    _confirmed(client)
    (tmp_path / "BRD.md").unlink()

    view = _journey(client)
    refused = client.post("/api/build", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["refused"] == journey._BRD_ABSENT_BUILD
    assert view["blockers"] == [journey._BRD_ABSENT_BUILD], view

    # The scope variant is still what a reader BEFORE CONFIRM is told, because
    # that reader is heading for a scope confirmation and not for a build.
    assert journey.scope_blockers(
        {"authoritative": {"intent": "x", "provider": {"name": "codex"}}},
        journey.BrdState.absent(),
    ) == (journey._BRD_MISSING,)


def test_f5_a_failing_scope_row_is_not_a_binding():
    """The writer records `passed` as the MEASUREMENT -- a BRD that is not the
    capsule's rendering presents failing evidence -- and the reader ignored it,
    so a row the writer marked as not a licence was honoured as one.

    NOT REACHABLE THROUGH ANY ROUTE: the contract refuses a failing
    `brd_requirements` into CONFIRM outright, and `/api/build` measures the
    BRD before `begin_build` is called. BUILD is where such a row can exist at
    all, because BUILD requires no evidence and `advance` stores what it is
    given -- which is exactly the row this reads.
    """
    human = Actor("human", "casey")
    document = {"authoritative": {"intent": "x", "provider": {"name": "codex"}},
                "digest_chain": ["a" * 64]}
    ref = journey.scope_ref(document, DERIVED_BRD)
    state = start_experience(human, AT)
    state = advance(state, "CONFIRM", human, AT,
                    (EvidenceRef(kind="brd_requirements", ref=ref, passed=True),))
    failing = advance(state, "BUILD", human, AT,
                      (EvidenceRef(kind="brd_requirements", ref=ref, passed=False),))

    assert failing["evidence"]["BUILD"][0]["passed"] is False, failing["evidence"]
    assert journey.scope_binding(failing, "BUILD") is None, (
        "a failing proof was read as the licence the build was given"
    )
    assert journey.ready_scope_refusal(failing, document, DERIVED_BRD) == (
        journey._SCOPE_UNBOUND_READY
    )

    # The control: the same row, passing, IS the binding -- so the refusal
    # above is about `passed` and not about anything else in the row.
    passing = advance(state, "BUILD", human, AT,
                      (EvidenceRef(kind="brd_requirements", ref=ref, passed=True),))
    assert journey.scope_binding(passing, "BUILD") == journey.scope_current(
        document, DERIVED_BRD)
    assert journey.ready_scope_refusal(passing, document, DERIVED_BRD) is None


def test_f5_a_stale_brd_at_confirm_does_not_headline_a_re_confirmation(
        tmp_path: Path):
    """`_NEXT_SCOPE_DRIFT` was selected at CONFIRM whenever the record was
    unbound, which is true whichever half moved. When the BRD is the half that
    moved, the headline said "Confirm the scope again" and the route refused
    exactly that by name, while the blocker under it named the real next step.

    Both halves are held: the capsule-moved case still gets the
    re-confirmation headline, and the BRD-moved case gets the build's own
    sentence for that file -- the one the route refuses with.
    """
    client = _client(tmp_path)
    _confirmed(client)

    # (a) THE BRD MOVED. No re-confirmation is offered, and none is suggested.
    (tmp_path / "BRD.md").write_text(
        "# BRD — Support Portal\n\n## BRD-001 Purpose\n\nSomething else.\n",
        encoding="utf-8", newline="",
    )
    view = _journey(client)
    assert view["stage"] == "CONFIRM" and view["actions"] == [], view
    assert view["next"] == journey._BRD_STALE_BUILD, view["next"]
    assert view["next"] != journey._NEXT_SCOPE_DRIFT, (
        "the page tells the reader to confirm the scope again while the route "
        "refuses a re-confirmation until the BRD is derived again"
    )
    assert view["next"] in view["blockers"], view
    refused = client.post("/api/journey/confirm-scope", json={"actor": HUMAN})
    assert refused.status_code == 409, refused.text
    assert journey._BRD_STALE in refused.json()["refused"], refused.text

    # (b) THE CAPSULE MOVED. A re-confirmation IS offered, and the headline
    # that was always about this case is the one that survives.
    _ok(client.post("/api/brd"))
    _confirm_field(client, "intent", "Build a portal for a different team.")
    _ok(client.post("/api/brd"))
    view = _journey(client)
    assert view["actions"] == ["confirm_scope"], view
    assert view["next"] == journey._NEXT_SCOPE_DRIFT, view["next"]
