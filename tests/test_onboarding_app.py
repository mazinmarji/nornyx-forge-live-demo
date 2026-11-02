"""The onboarding surface serves the capsule's authority rules unchanged.

WHAT WOULD FALSIFY THIS MODULE: a route that upgrades an actor, confirms
without a human, invents lifecycle state, serves prose instead of the
guarded rendering, or dresses a tamper finding up as an empty page. Each
has a specimen here, and each specimen exercises the REAL app over a real
git-backed store — the surface under test is the shipping composition, not
a mock of it.

The actor on a request is judged by the capsule's KIND rule, so the
hostile requests here claim kind "model" outright. That is the honest
version of the threat on a local single-user surface: the module's
docstring discloses that humans are not authenticated yet, and these tests
pin that the surface at least never REFUSES less than the capsule does.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from session_client import authed_client

from nornyx_forge import onboarding_app as onboarding
from nornyx_forge.brd_authoring import brd_from_capsule
from nornyx_forge.capsule import PROVIDERS
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.contract_generator import render_brd_contract
from nornyx_forge.governance_rendering import parse_business, verify_round_trip
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.requirements import parse_brd

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / ".nornyx" / "contracts"

HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}


def _clock():
    ticks = iter(range(10_000))
    return lambda: (
        f"2026-08-30T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"
    )


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = create_app(tmp_path / "capsule", CONTRACTS_DIR, clock=_clock(),
                     seal_dir=tmp_path / "seals")
    return authed_client(app)


def _created(client: TestClient) -> None:
    response = client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Test Project", "actor": HUMAN,
    })
    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# The page and the uninitialized state
# ---------------------------------------------------------------------------

def test_the_page_serves_and_says_who_holds_authority(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "the contracts, not\nthis page, are the authority" in response.text


def test_an_uninitialized_store_is_reported_not_invented(client: TestClient):
    state = client.get("/api/state").json()
    assert state == {"initialized": False, "providers": list(PROVIDERS)}


# ---------------------------------------------------------------------------
# Creation and the authority line
# ---------------------------------------------------------------------------

def test_a_human_creates_a_project_and_it_persists(client: TestClient):
    _created(client)
    state = client.get("/api/state").json()
    assert state["initialized"] is True
    assert state["authoritative"] == {"project_name": "Test Project"}
    # PR-17: creation starts the lifecycle through the contract. This line
    # read `== "absent"` before, and pinned the gap it now closes.
    assert state["experience"]["stage"] == "DISCOVER"
    assert state["experience"]["status"] == "active"
    assert state["revision"]


def test_a_model_actor_cannot_create_a_project(client: TestClient):
    response = client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Test Project", "actor": MODEL,
    })
    assert response.status_code == 409
    assert "created by a human actor" in response.json()["refused"]
    assert client.get("/api/state").json()["initialized"] is False


def test_a_need_enters_only_as_a_proposal(client: TestClient):
    """C2 on the wire: a model's plain-language need is stored, validated,
    and NOT authoritative."""
    _created(client)
    response = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.",
        "actor": MODEL,
    })
    assert response.status_code == 200
    proposal_id = response.json()["proposal_id"]
    state = client.get("/api/state").json()
    assert "intent" not in state["authoritative"]
    row = next(p for p in state["proposals"] if p["proposal_id"] == proposal_id)
    assert row["status"] == "open" and row["kind"] == "model"


def test_a_human_confirmation_moves_the_need_into_authority(client: TestClient):
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": MODEL,
    }).json()["proposal_id"]
    before = client.get("/api/state").json()["digest_chain_length"]
    response = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})
    assert response.status_code == 200
    state = client.get("/api/state").json()
    assert state["authoritative"]["intent"] == "Build a portal."
    assert state["digest_chain_length"] == before + 1


def test_a_model_actor_cannot_confirm(client: TestClient):
    """The authority line itself, exercised through the route."""
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": MODEL,
    }).json()["proposal_id"]
    response = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": MODEL})
    assert response.status_code == 409
    assert "only a human actor may confirm" in response.json()["refused"]
    state = client.get("/api/state").json()
    assert "intent" not in state["authoritative"]


def test_a_forged_or_double_confirmation_is_refused(client: TestClient):
    _created(client)
    missing = client.post("/api/proposals/P-99/confirm", json={"actor": HUMAN})
    assert missing.status_code == 409 and "no proposal" in missing.json()["refused"]

    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": HUMAN,
    }).json()["proposal_id"]
    assert client.post(
        f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN}
    ).status_code == 200
    again = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})
    assert again.status_code == 409 and "not open" in again.json()["refused"]


def test_rejection_closes_without_touching_authority(client: TestClient):
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": MODEL,
    }).json()["proposal_id"]
    assert client.post(
        f"/api/proposals/{proposal_id}/reject", json={"actor": MODEL}
    ).status_code == 200
    state = client.get("/api/state").json()
    assert "intent" not in state["authoritative"]


# ---------------------------------------------------------------------------
# Provider selection through the same gate
# ---------------------------------------------------------------------------

def test_provider_selection_is_capsule_gated(client: TestClient):
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN,
    }).json()["proposal_id"]
    client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})
    state = client.get("/api/state").json()
    assert state["authoritative"]["provider"] == {"name": "codex"}

    undeclared = client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "gemini"}, "actor": HUMAN,
    })
    assert undeclared.status_code == 422
    assert "not one of" in undeclared.json()["refused"]


def test_an_undeclared_field_is_refused_at_the_door(client: TestClient):
    _created(client)
    response = client.post("/api/proposals", json={
        "field": "telemetry_endpoint", "value": "https://x", "actor": HUMAN,
    })
    assert response.status_code == 422
    assert "undeclared field" in response.json()["refused"]


# ---------------------------------------------------------------------------
# The governance view and honest failure states
# ---------------------------------------------------------------------------

def test_the_governance_view_is_the_guarded_renderers_output(client: TestClient):
    first = client.get("/api/governance").json()
    assert [c["file"] for c in first["contracts"]] == [
        "architecture_governance.nyx", "forge_control.nyx", "runtime_network.nyx",
    ]
    for contract in first["contracts"]:
        assert "the contract is the authority" in contract["view"]
        parse_business(contract["view"])  # strict grammar: prose cannot hide here
    second = client.get("/api/governance").json()
    assert second == first, "the governance view must be deterministic"


def test_an_unrenderable_contract_is_a_reported_failure(tmp_path: Path):
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "broken.nyx").write_text("project: [not, a, mapping]\n",
                                          encoding="utf-8", newline="")
    app = create_app(tmp_path / "capsule", contracts, clock=_clock(),
                     seal_dir=tmp_path / "seals")
    response = authed_client(app).get("/api/governance")
    assert response.status_code == 502
    assert "broken.nyx" in response.json()["refused"]


def test_a_tampered_capsule_is_named_tampered(client: TestClient, tmp_path: Path):
    _created(client)
    capsule_file = tmp_path / "capsule" / "capsule.json"
    document = json.loads(capsule_file.read_text(encoding="utf-8"))
    document["authoritative"]["project_name"] = "Renamed Behind The Chain"
    capsule_file.write_text(json.dumps(document), encoding="utf-8", newline="")
    response = client.get("/api/state")
    assert response.status_code == 409
    assert response.json()["finding"] == "TAMPERED"


# ---------------------------------------------------------------------------
# The project's own contract, told apart from Forge's packaged contracts
# ---------------------------------------------------------------------------

INTENT = "Track facilities service requests for the operations team."
ROWS = [
    {"id": "RQ-1", "text": "Create a request with a description, a priority and a due date."},
    {"id": "RQ-2", "text": "Assign an owner to a request."},
    {"id": "RQ-3", "text": "Export the requests as a dated CSV file."},
]


def _confirm(client: TestClient, field: str, value, actor=HUMAN) -> None:
    proposal = client.post("/api/proposals", json={"field": field, "value": value, "actor": actor})
    assert proposal.status_code == 200, proposal.text
    confirmed = client.post(f"/api/proposals/{proposal.json()['proposal_id']}/confirm",
                            json={"actor": HUMAN})
    assert confirmed.status_code == 200, confirmed.text


def _requirements_confirmed(client: TestClient, intent: str = INTENT) -> None:
    _created(client)
    _confirm(client, "intent", intent, MODEL)
    _confirm(client, "requirements", ROWS)


def _contract_a_build_generates(tmp_path: Path) -> str:
    """The contract text the development flow writes for this capsule: the
    derived BRD parsed by the flow's own parser, rendered by the flow's own
    generator. Computed here the way a build computes it, from the store."""
    document = CapsuleStore(tmp_path / "capsule").load()
    brd = tmp_path / "flow-view" / "BRD.md"
    brd.parent.mkdir()
    brd.write_text(brd_from_capsule(document), encoding="utf-8", newline="")
    return render_brd_contract(parse_brd(brd))


def test_the_project_contract_is_the_one_its_confirmed_requirements_generate(
        client: TestClient, tmp_path: Path):
    _requirements_confirmed(client)
    text = _contract_a_build_generates(tmp_path)
    served = client.get("/api/governance")
    assert served.status_code == 200, served.text
    project = served.json()["project"]

    assert project["status"] == "derived"
    assert project["view"] == verify_round_trip(yaml.safe_load(text))
    parse_business(project["view"])  # the strict grammar holds for this view too
    assert INTENT in project["view"]
    assert project["contract_digest"] == "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert project["goals"] == ["BRD-001", "BRD-F-001", "BRD-F-002", "BRD-F-003"]
    document = CapsuleStore(tmp_path / "capsule").load()
    assert project["capsule_digest"] == document["digest_chain"][-1]
    assert project["standing"] == onboarding.PROJECT_CONTRACT_STANDING
    assert [c["file"] for c in served.json()["contracts"]] == [
        "architecture_governance.nyx", "forge_control.nyx", "runtime_network.nyx",
    ], "Forge's packaged contracts are still served, unchanged, beside the project's"


def test_the_project_contract_is_not_read_from_brd_md(client: TestClient, tmp_path: Path):
    """BRD.md is a derived file anyone can edit. The project contract comes
    from the sealed capsule, so an edit to the file changes nothing shown."""
    _requirements_confirmed(client)
    assert client.post("/api/brd").status_code == 200
    first = client.get("/api/governance").json()["project"]
    (tmp_path / "BRD.md").write_text(
        "# BRD — Test Project\n\n## BRD-001 Purpose\n\nSomething nobody confirmed.\n",
        encoding="utf-8", newline="",
    )
    second = client.get("/api/governance").json()["project"]
    assert second == first
    assert "nobody confirmed" not in json.dumps(second)
    (tmp_path / "BRD.md").unlink()
    assert client.get("/api/governance").json()["project"] == first


def test_a_missing_project_has_no_project_contract_and_says_so(client: TestClient):
    served = client.get("/api/governance")
    assert served.status_code == 200, served.text
    assert served.json()["project"] == onboarding.PROJECT_CONTRACT_ABSENT
    assert served.json()["contracts"], "Forge's own contracts are served without a project"


def test_a_project_without_a_confirmed_intent_has_no_contract_yet(client: TestClient):
    _created(client)
    project = client.get("/api/governance").json()["project"]
    assert project["status"] == "unavailable"
    assert "no confirmed intent" in project["refused"]
    assert "view" not in project and "contract_digest" not in project


def test_a_tampered_capsule_serves_no_project_contract(client: TestClient, tmp_path: Path):
    _requirements_confirmed(client)
    capsule_file = tmp_path / "capsule" / "capsule.json"
    document = json.loads(capsule_file.read_text(encoding="utf-8"))
    document["authoritative"]["intent"] = "Delete every request without asking."
    capsule_file.write_text(json.dumps(document), encoding="utf-8", newline="")

    response = client.get("/api/governance")

    assert response.status_code == 409, response.text
    assert response.json()["finding"] == "TAMPERED"
    assert "project" not in response.json() and "Delete every" not in response.text


def test_an_unreadable_capsule_is_refused_not_reported_absent(client: TestClient, tmp_path: Path):
    _requirements_confirmed(client)
    (tmp_path / "capsule" / "capsule.json").write_bytes(b'{"project_id": ')
    response = client.get("/api/governance")
    assert response.status_code == 409, response.text
    assert "project" not in response.json()


def test_a_project_contract_the_view_cannot_carry_is_refused_not_shown(
        client: TestClient, tmp_path: Path):
    """The business view refuses text that collides with its own grammar
    rather than escape it; an intent holding the field separator yields a
    contract the view cannot carry, and the section says so with no view."""
    _requirements_confirmed(client, intent="Track requests | and owners.")
    served = client.get("/api/governance")
    assert served.status_code == 200, served.text
    project = served.json()["project"]
    assert project["status"] == "refused"
    assert "'|'" in project["refused"]
    assert "view" not in project and "contract_digest" not in project
    assert served.json()["contracts"]


def test_the_page_tells_the_project_contract_from_forges_own(client: TestClient):
    page = client.get("/").text
    assert "the contracts that actually govern this project" not in page
    assert 'id="gov_project"' in page and 'id="gov_forge"' in page
    assert page.index('id="gov_project"') < page.index('id="gov_forge"')
    for phrase in ("not a human approval", "not production authority",
                   "not enforced at runtime"):
        assert phrase in onboarding.PROJECT_CONTRACT_STANDING, phrase
    script = page[page.index("<script>"):]
    body = script[script.index("async function governance(){"):script.index("async function runtime(){")]
    assert 'getElementById("gov_project")' in body and 'getElementById("gov_forge")' in body
    assert "g.project" in body and "g.contracts" in body
    # The standing statement is rendered from the response, and every status
    # without a view shows its reason: the element, the assignment and the
    # fallback are each pinned, not a substring they happen to share.
    assert '<p id="gov_project_standing"></p>' in page
    assert 'getElementById("gov_project_standing").textContent = p.standing || ""' in body
    assert 'p.view || p.detail || ("not shown: " + (p.refused || "no project contract"))' in body
    refresh = script[script.index("async function refresh(){"):script.index("async function governance(){")]
    assert refresh.startswith('async function refresh(){\n  governance();\n'), (
        "the project section must follow every refresh, started before /api/state "
        "is read so a state failure cannot leave it unrendered")
    assert "A contract generated for your\nproject is not an approval of it." in page


def test_a_sealed_store_whose_directory_was_removed_is_refused_not_absent(
        client: TestClient, tmp_path: Path):
    """No project and a removed project are different facts. The seal, kept
    outside the project, still names the store, so its removal is the
    seal's finding, refused as `/api/state` refuses it."""
    import shutil

    _requirements_confirmed(client)
    shutil.rmtree(tmp_path / "capsule")
    response = client.get("/api/governance")
    assert response.status_code == 409, response.text
    assert response.json()["finding"] == "TAMPERED"
    assert "project" not in response.json()


def test_a_schema_breaking_capsule_serves_no_project_contract(client: TestClient, tmp_path: Path):
    """A store with no seal, whose capsule parses and breaks the schema: the
    store's INVALID refusal, passed through, and no project section."""
    from nornyx_forge.capsule import Actor, create_document

    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(create_document("proj-1", "Test Project", Actor("human", "casey"),
                                     "2026-08-30T00:00:00Z"))
    (tmp_path / "capsule" / "capsule.json").write_text(json.dumps({"project_id": 5}),
                                                       encoding="utf-8", newline="")
    response = client.get("/api/governance")
    assert response.status_code == 422, response.text
    assert "project" not in response.json()


def test_confirmed_text_that_cannot_be_encoded_is_refused_not_a_server_error(client: TestClient):
    _created(client)
    proposal = client.post(
        "/api/proposals",
        content='{"field": "intent", "value": "Track \\ud800 requests.", '
                '"actor": {"kind": "human", "ident": "casey"}}',
        headers={"content-type": "application/json"},
    )
    assert proposal.status_code == 200, proposal.text
    assert client.post(f"/api/proposals/{proposal.json()['proposal_id']}/confirm",
                       json={"actor": HUMAN}).status_code == 200
    served = client.get("/api/governance")
    assert served.status_code == 200, served.text
    project = served.json()["project"]
    assert project["status"] == "refused"
    assert "UTF-8" in project["refused"]
    assert "view" not in project


@pytest.mark.parametrize("intent", [
    'Track "quoted" and \'single\' requests.',
    "Track {braces} and [brackets] and a: colon.",
    "null",
    "yes",
    "&anchor *alias !tag requests.",
    "Suivre les demandes du café ✓.",
    "Track requests. " * 150,
])
def test_an_ordinary_but_odd_intent_still_yields_a_derived_contract(
        client: TestClient, tmp_path: Path, intent: str):
    """Text YAML or the view treat specially, short of the view's own
    separators, still produces the contract a build generates, shown."""
    _requirements_confirmed(client, intent=intent.strip())
    served = client.get("/api/governance")
    assert served.status_code == 200, served.text
    project = served.json()["project"]
    assert project["status"] == "derived", project
    assert project["view"] == verify_round_trip(yaml.safe_load(_contract_a_build_generates(tmp_path)))
