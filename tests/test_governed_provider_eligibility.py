"""Declared is not eligible: the governed build executes no unconfined provider.

THE FINDING (independent review of 89910b8, R1 to R3). The seal kept the
provider from rewriting the authority store unnoticed, but the default
Claude provider and the seal occupy the same operating-system trust domain:
Claude runs on the governed path with general shell capability and no
filesystem confinement as the user whose files hold the anchor, so a
validation mechanism cannot establish independence from an actor that can
replace the validation state. And a protected store whose anchor had gone
missing was reported like a store from before sealing existed.

THE INVARIANT these tests hold. The governed basic-user path executes an
engineering provider only when Forge itself can establish that the provider
is confined to the project subject. The decision is Forge-owned
deterministic data in the Provider Contract, read from nothing but its own
table: not the request, not the capsule, not the project directory, not the
provider's account of itself. Today neither declared provider is eligible,
so the governed build fails closed -- explicitly, before the lifecycle moves,
before any flow exists, with no fallback and no change of execution mode --
and the page says why. A store Forge ever sealed is refused when its seal is
gone; a store never sealed stays distinguishable as legacy.

E1..E11 name the required proofs held here; E12 is the journey module,
which must stay green beside them. No external provider is called and no
bypass is demonstrated; the defect was independently established.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from session_client import authed_client

from nornyx_forge import onboarding_serve, provider_contract
from nornyx_forge.capsule import PROVIDERS, Actor, confirm, create_document, propose
from nornyx_forge.capsule_store import CapsuleSealMissing, CapsuleStore
from nornyx_forge.experience import EvidenceRef, advance, start_experience
from nornyx_forge.onboarding_app import create_app, served_platform
from nornyx_forge.provider_contract import (
    CONFINEMENT,
    PROVIDER_CONFINEMENT,
    GovernedEligibility,
    ProviderError,
    governed_build_eligibility,
)
from nornyx_forge.providers import get_provider

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
AT = "2026-09-03T09:00:00Z"
#: TWO PLATFORMS, AND CONFLATING THEM MADE THREE TESTS PASS ONLY ON WINDOWS.
#:
#: `PLATFORM` is the platform the shipped TABLE carries rows for. Tests that
#: call the contract's decision directly ask about it, because the row's
#: content is what they are asserting.
#:
#: `SERVED` is the platform the shipped SURFACE decides for on THIS host --
#: whatever `served_platform()` derives. Tests that drive `create_app` or
#: `assemble` without passing a platform get this one, and comparing their
#: output against `PLATFORM` is correct only on a Windows host.
#:
#: Measured: the first version of this module used `PLATFORM` for both, and CI
#: went red on Linux for E5, E6 and E7 -- where the served refusal is "no
#: confinement row for platform 'linux'", which is the fail-closed behaviour
#: working exactly as designed, against an assertion that had quietly assumed
#: the host. The two names are kept apart so that cannot recur.
PLATFORM = "windows"
SERVED = served_platform()
SUBJECT_GATE = {"name": "greenfield:test-execution", "passed": True, "detail": "",
                "command": ["python", "-I", "-c", "verifier"], "returncode": 0}
NORNYX_GATE = {"name": "nornyx check .nornyx/generated/brd_contract.nyx", "passed": True,
               "detail": "ok", "command": ["nornyx", "check", "brd_contract.nyx"], "returncode": 0}


class RecordingFactory:
    """Records every construction the route attempts. On the governed path
    with the contract's own decision it must never be called."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, root, **kwargs):
        self.calls.append({"root": root, **kwargs})
        return self

    def run(self):
        return {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                "execution_backend": "sequential"}


def _seam_eligibility(provider: str, platform: str) -> GovernedEligibility:
    return GovernedEligibility(provider=provider, platform=platform, eligible=True,
                               confinement="established",
                               reason="deterministic flow at the injectable seam; no provider executes")


def _client(tmp_path: Path, factory, *, seam: bool = False) -> TestClient:
    """The shipped decision unless `seam` is asked for explicitly."""
    kwargs = {"eligibility": _seam_eligibility} if seam else {}
    return authed_client(create_app(tmp_path / "capsule", CONTRACTS, flow_factory=factory,
                                    seal_dir=tmp_path / "seals", **kwargs))


def _ok(response) -> dict:
    assert response.status_code == 200, response.text
    return response.json()


def _confirmed(client: TestClient, provider: str = "codex") -> None:
    _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN}))
    intent = _ok(client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}))
    chosen = _ok(client.post("/api/proposals", json={
        "field": "provider", "value": {"name": provider}, "actor": HUMAN,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{chosen}/confirm", json={"actor": HUMAN}))
    _ok(client.post("/api/brd"))
    assert _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))["stage"] == "CONFIRM"


def _persisted(tmp_path: Path) -> dict:
    return CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").load_experience()


# ---------------------------------------------------------------------------
# E1  declaration is not eligibility
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", PROVIDERS)
def test_e1_a_declared_registered_provider_is_not_thereby_eligible(provider: str):
    adapter = get_provider(provider)
    assert adapter.name == provider, "the provider is declared and registered"
    verdict = governed_build_eligibility(provider, PLATFORM)
    assert verdict.eligible is False
    assert verdict.provider == provider and verdict.confinement in CONFINEMENT
    assert verdict.platform == PLATFORM
    assert provider in verdict.reason and "not eligible" in verdict.reason
    assert "no other provider is tried" in verdict.reason


def test_the_confinement_table_covers_every_declared_provider_and_establishes_none():
    """The current state, pinned as a diff: growing PROVIDERS needs a row,
    and promoting a row to `established` is the deliberate act that would
    make a governed build executable again."""
    assert set(PROVIDER_CONFINEMENT) == set(PROVIDERS)
    states = {state for rows in PROVIDER_CONFINEMENT.values() for state in rows.values()}
    assert states <= set(CONFINEMENT)
    assert "established" not in states
    # THE CENSUS LITERAL, moved to the nested shape rather than deleted: the
    # row a promotion would edit now names the platform it would be promoted
    # on, and a flat value cannot be written here at all.
    assert PROVIDER_CONFINEMENT == {
        "claude": {"windows": "none"}, "codex": {"windows": "declared"},
    }
    with pytest.raises(ProviderError):
        governed_build_eligibility("gemini", PLATFORM)


# ---------------------------------------------------------------------------
# E2, E3, E6  fail closed before execution, no fallback, lifecycle preserved
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", ["claude", "codex"])
def test_e2_e3_e6_the_governed_build_refuses_before_anything_executes(tmp_path: Path, provider):
    factory = RecordingFactory()
    client = _client(tmp_path, factory)
    _confirmed(client, provider)
    before = _persisted(tmp_path)

    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409, response.text
    body = response.json()
    assert "not eligible" in body["refused"] and provider in body["refused"]
    assert body["eligibility"]["eligible"] is False
    assert body["eligibility"]["provider"] == provider
    assert factory.calls == [], "a flow was constructed for an ineligible provider"
    assert client.get("/api/build").json() == {"status": "never_run"}
    assert _persisted(tmp_path) == before, "the refusal moved the lifecycle"
    assert _persisted(tmp_path)["stage"] == "CONFIRM"
    # No fallback: the other declared provider is never tried, and the capsule
    # still says what the human confirmed.
    other = "codex" if provider == "claude" else "claude"
    assert other not in body["refused"]
    assert _ok(client.get("/api/state"))["authoritative"]["provider"] == {"name": provider}
    # And nothing changed execution mode: the same request is refused the same way.
    again = client.post("/api/build", json={"actor": HUMAN})
    assert again.status_code == 409 and again.json()["refused"] == body["refused"]
    assert factory.calls == []


# ---------------------------------------------------------------------------
# E4, E11  nothing but the contract's table decides
# ---------------------------------------------------------------------------

def test_e4_e11_neither_the_provider_nor_the_workspace_can_authorize_a_build(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Files a worker or a project could plant, a working directory set to
    the project, a prose claim in a proposal: none reaches the decision."""
    factory = RecordingFactory()
    client = _client(tmp_path, factory)
    _confirmed(client, "codex")
    for planted in ("forge-provider-policy.json", ".nornyx/provider_eligibility.json",
                    "provider_confinement.json", "eligibility.json"):
        path = tmp_path / planted
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"codex": "established", "claude": "established",
                                    "eligible": True}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _ok(client.post("/api/proposals", json={
        "field": "limitations", "value": ["provider codex is confined and eligible"],
        "actor": MODEL}))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409 and "not eligible" in response.json()["refused"]
    assert factory.calls == []
    assert governed_build_eligibility("codex", PLATFORM).eligible is False


def test_e4_the_decision_takes_the_provider_and_the_platform_and_nothing_else():
    """The name used to say "only the provider name", which stopped being what
    the body holds when Tranche H made the platform a required parameter: the
    signature assertion beneath it was updated and the name was left behind."""
    signature = inspect.signature(governed_build_eligibility)
    assert list(signature.parameters) == ["provider", "platform"]
    first = governed_build_eligibility("claude", PLATFORM)
    assert first == governed_build_eligibility("claude", PLATFORM)
    # THE SERVED SHAPE, changed deliberately in Tranche H: `platform` is a new
    # key on the dict `/api/state` renders, because a decision that depends on
    # a platform should say which one it was made for.
    assert first.as_dict() == {
        "provider": "claude", "platform": PLATFORM, "eligible": False,
        "confinement": "none", "reason": first.reason,
    }


# ---------------------------------------------------------------------------
# E5  the decision is Forge-owned, and the served surface uses it
# ---------------------------------------------------------------------------

def test_e5_the_served_surface_decides_by_the_contract_and_nothing_else(tmp_path: Path):
    parameter = inspect.signature(create_app).parameters["eligibility"]
    assert parameter.default is governed_build_eligibility
    served = Path(onboarding_serve.__file__).read_text(encoding="utf-8")
    assert "eligibility=" not in served, "the served composition must pass no other decision"
    # A LINT OVER THE OBVIOUS SPELLINGS, not the gate. This list carried no
    # `sys` term at all and `"from pathlib"` did not match `import pathlib`, so
    # an injected `import sys` + `import pathlib` + `sys.platform` +
    # `pathlib.Path.cwd()` passed it, `scripts/check_architecture.py` and 143
    # architecture-facing tests (Tranche H first review, P2). What holds the
    # property now is the per-file forbidden-dependency rule for this module in
    # `scripts/check_architecture.py`, pinned by injection in
    # `tests/test_architecture_security.py`. This stays as the cheap first
    # refusal, with its blind spots closed.
    domain = Path(provider_contract.__file__).read_text(encoding="utf-8")
    for forbidden in ("import os", "import sys", "import subprocess", "import pathlib",
                      "import platform", "from pathlib", "from os ", "open(", "environ"):
        assert forbidden not in domain, f"the decision's module reaches outside its table: {forbidden}"


def test_e5_the_assembled_surface_refuses_the_governed_build(tmp_path: Path, monkeypatch):
    """`assemble`, the shipped composition, over a confirmed project: the
    build is refused by the contract's own decision. The seal directory is
    redirected so this test writes nothing under the user's home, and the
    default flow class is replaced by a recorder so that a REGRESSED gate
    fails this test without ever starting a real flow or reaching a
    provider's CLI -- a review measured that it otherwise would."""
    from nornyx_forge import development_flow

    factory = RecordingFactory()
    monkeypatch.setattr(development_flow, "DevelopmentFlow", factory)
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    # A loopback base URL: the served composition refuses the test client's
    # default `testserver` Host, and the production rule is not widened for it.
    client = authed_client(onboarding_serve.assemble(tmp_path), base_url="http://127.0.0.1")
    _confirmed(client, "claude")
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert response.json()["eligibility"] == governed_build_eligibility("claude", SERVED).as_dict()
    assert factory.calls == [], "the shipped composition constructed a flow for an ineligible provider"
    assert _persisted(tmp_path)["stage"] == "CONFIRM"


# ---------------------------------------------------------------------------
# E7  the page communicates the refusal
# ---------------------------------------------------------------------------

def test_e7_the_surface_tells_the_user_the_build_is_unavailable_and_why(tmp_path: Path):
    client = _client(tmp_path, RecordingFactory())
    _confirmed(client, "codex")
    state = _ok(client.get("/api/state"))
    verdict = governed_build_eligibility("codex", SERVED)
    assert state["provider_eligibility"] == verdict.as_dict()
    assert "start_build" not in state["journey"]["actions"]
    assert verdict.reason in state["journey"]["blockers"]
    assert client.post("/api/build", json={"actor": HUMAN}).json()["refused"] == verdict.reason
    from nornyx_forge.onboarding_app import _PAGE
    assert 'id="blockers"' in _PAGE and "b_build" in _PAGE


# ---------------------------------------------------------------------------
# E8  the deterministic seam still proves orchestration
# ---------------------------------------------------------------------------

def test_e8_the_injectable_seam_still_carries_the_journey_to_govern(tmp_path: Path):
    factory = RecordingFactory()
    client = _client(tmp_path, factory, seam=True)
    _confirmed(client, "codex")
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    for _ in range(500):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            break
        import threading
        threading.Event().wait(0.02)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert len(factory.calls) == 1 and factory.calls[0]["provider"] == "codex"


# ---------------------------------------------------------------------------
# E9, E10  the anchor's three states
# ---------------------------------------------------------------------------

def _sealed_store(tmp_path: Path) -> CapsuleStore:
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    store.initialize(document, experience=start_experience(Actor("human", "casey"), AT))
    return store


def test_e9_a_protected_store_whose_seal_is_missing_fails_closed(tmp_path: Path):
    store = _sealed_store(tmp_path)
    assert store.protected() and store.sealed() is not None
    store.seal_path().unlink()
    with pytest.raises(CapsuleSealMissing):
        store.load()
    with pytest.raises(CapsuleSealMissing):
        store.load_experience()
    client = _client(tmp_path, RecordingFactory())
    state = client.get("/api/state")
    assert state.status_code == 409
    assert state.json()["finding"] == "TAMPERED" and state.json()["anchor"] == "missing"
    assert state.json()["restorable"] is False
    assert "unsealed" not in state.text and "journey" not in state.json()
    for path in ("/api/journey/confirm-scope", "/api/build", "/api/journey/ready",
                 "/api/journey/restore", "/api/proposals/P-1/confirm", "/api/brd"):
        response = client.post(path, json={"actor": HUMAN})
        assert response.status_code == 409 and response.json().get("finding") == "TAMPERED", path


def test_e10_a_legacy_store_stays_distinguishable_from_a_protected_one(tmp_path: Path):
    """Never sealed: unsealed and trusted as before, then sealed by Forge's
    next save -- which commits the marker. From then on the store is
    protected, and losing its seal is a refusal, not a return to legacy."""
    legacy = CapsuleStore(tmp_path / "capsule")
    legacy.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                      experience=start_experience(Actor("human", "casey"), AT))
    assert not (tmp_path / "capsule" / ".forge-seal").exists()
    client = _client(tmp_path, RecordingFactory())
    state = _ok(client.get("/api/state"))
    assert state["authority"]["anchor"] == "unsealed" and state["authority"]["currency"] is None
    # A store that was never sealed holds no interval either: the process
    # witness reports continuity only over a seal it wrote or verified.
    assert state["authority"]["continuity"] is None
    assert state["authority"]["held_since"] is None

    _ok(client.post("/api/proposals", json={"field": "intent", "value": "x", "actor": HUMAN}))
    protected = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    assert protected.protected() and protected.sealed() is not None
    assert protected.seal_problems(protected.sealed()) == []
    state = _ok(client.get("/api/state"))
    assert state["authority"]["anchor"] == "sealed"
    # THE WORD IS UNCHANGED. Tranche E's witness detects a wholesale rollback
    # only while this process lives, which is a separate and smaller fact and
    # is reported in a separate field; nothing anchors this seal as the latest.
    assert state["authority"]["currency"] == "not_independently_anchored"
    assert state["authority"]["continuity"] == "process"
    assert state["authority"]["held_since"] is not None

    protected.seal_path().unlink()
    refused = client.get("/api/state")
    assert refused.status_code == 409 and refused.json()["anchor"] == "missing"


def test_the_seal_marker_is_committed_and_names_this_seal(tmp_path: Path):
    store = _sealed_store(tmp_path)
    marker = json.loads((tmp_path / "capsule" / ".forge-seal").read_text(encoding="utf-8"))
    assert marker == {"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": store.seal_ident()}
    import subprocess
    tracked = subprocess.run(["git", "ls-files"], cwd=tmp_path / "capsule",
                             capture_output=True, text=True, check=True).stdout.split()
    assert ".forge-seal" in tracked
    (tmp_path / "capsule" / ".forge-seal").write_text(
        json.dumps({"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": "0" * 24}),
        encoding="utf-8")
    assert any("does not name this store's seal" in p for p in store.seal_problems(store.sealed()))


def test_restoration_recreates_the_marker_when_the_repository_is_rebuilt(tmp_path: Path):
    from nornyx_forge.capsule_store import _remove_tree

    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    _remove_tree(tmp_path / "capsule" / ".git")
    (tmp_path / "capsule" / ".forge-seal").write_text(
        json.dumps({"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": "0" * 24}),
        encoding="utf-8")
    revision, notes = store.restore(sealed)
    assert notes and store.protected()
    assert store.seal_problems(store.sealed()) == [], (
        "a review measured a tampered marker surviving the rebuild, so restore never converged"
    )
    assert json.loads((tmp_path / "capsule" / ".forge-seal").read_text(encoding="utf-8"))["seal"]         == store.seal_ident()


# ---------------------------------------------------------------------------
# The lifecycle a refused build leaves, exercised through the contract
# ---------------------------------------------------------------------------

def test_e6_a_lifecycle_already_at_build_is_not_moved_by_a_refused_re_run(tmp_path: Path):
    """An interrupted build's re-run is a governed build too: refused for an
    ineligible provider, and the lifecycle stays at BUILD/active, honestly
    reported with the reason as its blocker."""
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    document, intent = propose(document, "intent", "Build a portal.", Actor("model", "m"),
                               "2026-09-03T09:01:00Z")
    document = confirm(document, intent, Actor("human", "casey"), "2026-09-03T09:02:00Z")
    document, chosen = propose(document, "provider", {"name": "claude"}, Actor("human", "casey"),
                               "2026-09-03T09:03:00Z")
    document = confirm(document, chosen, Actor("human", "casey"), "2026-09-03T09:04:00Z")
    lifecycle = start_experience(Actor("human", "casey"), AT)
    # CONFIRM requires evidence naming the content it is about. What this
    # module tests is PROVIDER ELIGIBILITY, which the build route decides
    # before it looks at the BRD at all, so a specimen reference is what this
    # lifecycle needs; the binding itself is measured in
    # tests/test_content_bound_transitions.py.
    lifecycle = advance(lifecycle, "CONFIRM", Actor("human", "casey"),
                        "2026-09-03T09:05:00Z",
                        (EvidenceRef(kind="brd_requirements",
                                     ref=f"capsule/{'a' * 64}/brd/{'b' * 64}",
                                     passed=True),))
    lifecycle = advance(lifecycle, "BUILD", Actor("human", "casey"), "2026-09-03T09:06:00Z")
    store.initialize(document, experience=lifecycle)
    (tmp_path / "BRD.md").write_text("# BRD\n\n## BRD-001 Purpose\n\nBuild a portal.\n",
                                     encoding="utf-8", newline="")
    client = _client(tmp_path, RecordingFactory())
    view = _ok(client.get("/api/state"))["journey"]
    assert view["stage"] == "BUILD" and view["actions"] == []
    assert governed_build_eligibility("claude", SERVED).reason in view["blockers"]
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    # THE SENTENCE, not only the code. With this specimen binding and a
    # hand-written BRD, three independent refusals now produce a 409 here --
    # eligibility, the scope binding, and the derivation check -- where before
    # this tranche only eligibility did. Asserting the status alone would let
    # this test pass for a reason it does not name; the route decides
    # eligibility first, and that is what it must still be refusing.
    assert response.json()["refused"] == governed_build_eligibility("claude", SERVED).reason, (
        response.text
    )
    assert _persisted(tmp_path)["stage"] == "BUILD" and _persisted(tmp_path)["status"] == "active"


# ---------------------------------------------------------------------------
# E13  the decision carries a PLATFORM (Tranche H, item 1)
#
# The verifier was already platform-bound -- `assess_confinement` refuses a
# `linux` record asked about `windows` -- and the CLAIM TABLE was not. So a
# green assessment taken on any platform could be written into a row that the
# served governed-build decision read on every platform. These hold the two
# to each other.
# ---------------------------------------------------------------------------

def test_e13_a_measurement_that_is_green_elsewhere_does_not_make_this_platform_eligible(
        monkeypatch: pytest.MonkeyPatch):
    """THE FAIL-OPEN THIS CLOSES, driven end to end.

    A Claude measurement that genuinely closes every property on `linux` makes
    `assess_confinement("claude", "linux", ...)` green. That green must not
    reach `governed_build_eligibility("claude", "windows")`, and the refusal
    must name BOTH platforms so a reader can see why the green did not count.

    This test could not be written against the parent revision at all: the
    function took no platform, so there was no `windows` to ask about and no
    `linux` row to put beside it. That is its FAIL-if-absent.
    """
    from nornyx_forge.provider_contract import (  # noqa: PLC0415
        CONFINEMENT_PROPERTIES,
        PROPERTY_EVIDENCE_MECHANISMS,
        ConfinementMeasurement,
        ConfinementProbe,
        assess_confinement,
    )

    green_on_linux = ConfinementMeasurement(
        provider="claude", platform="linux",
        measured_at_commit="0" * 40,
        probes=tuple(
            ConfinementProbe(
                provider="claude", property=prop, platform="linux",
                attempt_observed=True, outcome=required,
                mechanism=PROPERTY_EVIDENCE_MECHANISMS[prop][0],
            )
            for prop, required in CONFINEMENT_PROPERTIES.items()
        ),
    )
    assert assess_confinement("claude", "linux", green_on_linux).establishes is True

    # And a table that HAS been given that linux row, which is the state a
    # later slice would create by admitting a WSL2 measurement.
    monkeypatch.setattr(provider_contract, "PROVIDER_CONFINEMENT", {
        "claude": {"linux": "established"},
        "codex": {"windows": "declared"},
    })
    verdict = provider_contract.governed_build_eligibility("claude", "windows")
    assert verdict.eligible is False, (
        "a measurement taken on linux made the shipped Windows platform "
        "eligible; evidence does not travel between platforms"
    )
    assert verdict.platform == "windows"
    assert "windows" in verdict.reason and "linux" in verdict.reason


def test_e13_the_decision_will_not_be_made_without_a_platform():
    """The second parameter is REQUIRED, not defaulted. A default would
    rebuild the hole one level down: every caller that forgot the platform
    would silently get the same row on every host."""
    with pytest.raises(TypeError):
        governed_build_eligibility("claude")  # type: ignore[call-arg]
    for absent in ("", "   "):
        with pytest.raises(ProviderError):
            governed_build_eligibility("claude", absent)


def test_e13_a_platform_with_no_row_is_refused_by_name_and_claims_nothing(monkeypatch):
    """An unrecognised host must fail CLOSED and say which word it failed on
    -- never fall through to whichever row happens to be first.

    THE FALL-THROUGH HALF WAS NOT MEASURED HERE, and a review found it. An
    injected `rows.get(platform, next(iter(rows.values())))` left this test
    GREEN, because the generic not-eligible branch also interpolates the
    platform, so the refusal still named `plan9`. Naming the platform is
    therefore not the discriminator. Two things are: the refusal has to be the
    NO-ROW refusal, which says so and names the platforms that do have rows;
    and it has to stay a refusal when the row it would fall through to reads
    `established`, which is the fail-open the platform axis exists to close.
    """
    verdict = governed_build_eligibility("claude", "plan9")
    assert verdict.eligible is False
    assert verdict.confinement == "none"
    assert "plan9" in verdict.reason, "the refusal does not name the platform it refused"
    assert "no confinement row for platform" in verdict.reason, (
        "the refusal is not the no-row refusal, so the decision found a row for "
        "a platform that has none: it fell through to another platform's "
        "measurement"
    )
    for rowed in sorted(PROVIDER_CONFINEMENT["claude"]):
        assert repr(rowed) in verdict.reason, (
            f"the refusal does not say which platforms DO have rows ({rowed!r} "
            "is missing), so a reader cannot tell what was and was not measured"
        )
    assert "established" not in verdict.reason, (
        "a refusal for a platform nothing was measured on used the word that "
        "means the opposite"
    )
    assert "confined" not in verdict.reason

    # THE SAME QUESTION AGAINST A PROMOTED ROW. Nothing here promotes a shipped
    # row: the table is replaced IN MEMORY for the length of this test, so what
    # is measured is the decision's behaviour on a table that has one -- which
    # is the table a later slice would ship, and the arrangement under which a
    # fall-through stops being cosmetic and starts being an admission.
    monkeypatch.setattr(provider_contract, "PROVIDER_CONFINEMENT", {
        "claude": {"windows": "established"},
        "codex": {"windows": "declared"},
    })
    # POSITIVE CONTROL FIRST, as the sibling test below does it. Without it a
    # rebinding that stopped taking effect -- a refactor reading the table
    # through a closure, a local import, a copy -- would leave the assertion
    # after it passing for the wrong reason, and this arm would measure nothing.
    assert provider_contract.governed_build_eligibility(
        "claude", "windows").eligible is True, (
        "the in-memory promotion did not take effect, so the fall-through "
        "assertion below would pass against the shipped table"
    )
    fell_through = provider_contract.governed_build_eligibility("claude", "plan9")
    assert fell_through.eligible is False, (
        "a platform with no row read a row measured on another platform, and "
        "that row was established: evidence travelled between platforms"
    )
    assert fell_through.confinement == "none"
    assert "plan9" in fell_through.reason


def test_e13_the_served_platform_word_and_the_table_answer_each_other():
    """Both directions, so neither half can drift alone.

    Forward: every platform key in the table is a word `served_platform()` can
    actually produce, so no row is dead. Backward: every word it can produce is
    DECIDED -- either it has a row, or the decision refuses it by name -- so
    there is no derivable host for which the decision falls through.
    """
    from nornyx_forge.onboarding_app import PLATFORM_WORDS  # noqa: PLC0415

    derivable = set(PLATFORM_WORDS.values())
    rows = {platform for table in PROVIDER_CONFINEMENT.values() for platform in table}
    assert rows <= derivable, (
        f"the table carries rows no served host can ask about: {sorted(rows - derivable)}"
    )
    # THE SECOND TAUTOLOGY, FOUND BY A REVIEW AND REMOVED. This line used to
    # read `current in derivable or current == f"unsupported:{sys.platform}"`,
    # which is a RESTATEMENT OF `served_platform()`'S BODY: if `sys.platform`
    # is a key the first disjunct holds by construction, and if it is not the
    # second does, so the assertion was true for EVERY possible content of
    # `PLATFORM_WORDS`. Measured: swapping `win32 -> linux` and
    # `linux -> windows` left all 153 tests in the three modules green, and a
    # Linux host then read the Windows-measured row through the served surface.
    # The oracle has to live outside the code under test, so it is a LITERAL in
    # `test_e13_the_platform_mapping_is_this_exact_table` and the per-key
    # behaviour is driven under a monkeypatched `sys.platform` beside it.
    for word in sorted(derivable | {"a-host-nobody-has-heard-of"}):
        verdict = governed_build_eligibility("claude", word)
        assert verdict.platform == word
        if word not in PROVIDER_CONFINEMENT["claude"]:
            assert verdict.eligible is False and word in verdict.reason


def test_a_promoted_row_would_not_serve_its_own_unmet_property(monkeypatch):
    """The measured FINDING is appended on the refused branch only.

    Every finding in `_CONFINEMENT_FINDING` is written for a row that is NOT
    established: each one names the property left unmet. Appended on both
    branches -- as it was -- a promotion would serve one string reading "is
    eligible ... Forge has established that it is confined ... The property
    left unmet is 'control_plane_authority'", on the surface a basic user
    reads.

    NOTHING IS PROMOTED HERE. The table is replaced in memory for the length of
    this test; the shipped rows are untouched, and the assertion at the end
    says so by reading them back.
    """
    # WHICH ROW IS SIMULATED, AND WHY THIS ONE: Claude/Windows is the row
    # Tranche H measured as `none` because no mechanism is REACHABLE there, so
    # it is the row no later tranche promotes; simulating on codex/windows
    # would go VACUOUS the day a tranche legitimately ships
    # `codex: established`, because the patch would then set the table to what
    # it already is and this test would stop simulating a promotion at all.
    monkeypatch.setattr(provider_contract, "PROVIDER_CONFINEMENT", {
        "claude": {"windows": "established"},
        "codex": {"windows": "declared"},
    })
    promoted = provider_contract.governed_build_eligibility("claude", "windows")
    assert promoted.eligible is True, "the in-memory promotion did not take effect"
    # THE MARKER IS THE FINDING'S OWN DOCUMENT, not one phrase out of it.
    # Measured: the Claude finding says "All six properties are unmet" and
    # carries no "property left unmet" at all, so that phrase alone would be
    # VACUOUS on this row -- which would have traded a test that goes vacuous
    # at C4 for one that is vacuous now. Every finding in the table names the
    # document it was measured in, so that is what discriminates for whichever
    # row is simulated.
    assert "CLAUDE_CONFINEMENT_MEASUREMENT" not in promoted.reason, (
        "an eligible verdict serves a finding written for a refusal, so one "
        "string says the provider is confined and then cites the measurement "
        "that refused it"
    )
    assert "property left unmet" not in promoted.reason, (
        "an eligible verdict serves a finding written for a refusal, so one "
        "string says the provider is confined and that a property is unmet"
    )
    assert "not eligible" not in promoted.reason

    # The refused twin still carries its finding, so this did not simply delete
    # the evidence from the reason a person reads.
    refused = provider_contract.governed_build_eligibility("codex", "windows")
    assert refused.eligible is False
    assert "CODEX_CONFINEMENT_MEASUREMENT" in refused.reason

    monkeypatch.undo()
    assert PROVIDER_CONFINEMENT == {
        "claude": {"windows": "none"}, "codex": {"windows": "declared"},
    }, "the shipped table did not survive this test unchanged"


def test_e13_the_platform_mapping_is_this_exact_table():
    """THE CENSUS LITERAL for the one derivation the platform axis rests on.

    Written out here, in the same style as the confinement table's own literal
    above, because an assertion derived from `PLATFORM_WORDS` cannot tell a
    right mapping from a wrong one: its oracle would be the code under test.
    Measured, before this existed: swapping two entries so `win32 -> linux` and
    `linux -> windows` -- leaving the VALUE SET identical -- left every test in
    this module and the two beside it green, while the shipped Windows host
    reported its governed-build decision as made for `linux` and a Linux host
    read the row measured on Windows. Editing the mapping is a legitimate act;
    editing it without editing this line is not.
    """
    from nornyx_forge.onboarding_app import PLATFORM_WORDS  # noqa: PLC0415

    assert PLATFORM_WORDS == {
        "win32": "windows", "linux": "linux", "darwin": "macos",
    }


@pytest.mark.parametrize(("host", "word"), [
    ("win32", "windows"), ("linux", "linux"), ("darwin", "macos"),
])
def test_e13_each_mapped_host_serves_its_own_word(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str, word: str):
    """Each key SERVES its word -- through the derivation and through the
    surface -- with the host driven rather than observed.

    On a real host only one row of the mapping is ever exercised, so the other
    two are held by nothing that runs. `sys.platform` is patched on the module
    object `onboarding_app` reads, and the decision is then followed all the
    way to `/api/state`'s eligibility block, because that is where a wrong word
    would be read as an answer about this host.
    """
    import sys as _sys  # noqa: PLC0415

    from nornyx_forge import onboarding_app  # noqa: PLC0415

    monkeypatch.setattr(_sys, "platform", host)
    assert onboarding_app.served_platform() == word

    client = _client(tmp_path, RecordingFactory())
    _confirmed(client, "claude")
    served = _ok(client.get("/api/state"))["provider_eligibility"]
    assert served["platform"] == word, (
        f"a host reporting {host!r} had its governed-build decision made for "
        f"{served['platform']!r} rather than {word!r}, so the served verdict "
        "answers for a platform this host is not"
    )
    assert served == governed_build_eligibility("claude", word).as_dict()


def test_e13_an_unmapped_host_fails_closed_and_reads_no_row(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """THE FALLBACK BRANCH, REACHED. It was asserted by nothing that ran.

    Every host CI runs on (`win32`, `linux`) hits the mapping, so the default
    was unexercised: a review replaced it with `PLATFORM_WORDS.get(sys.platform,
    "windows")` and 47 tests stayed green while an unrecognised host silently
    read the shipped Windows row. Here the host is driven to one nothing maps,
    and the word it gets has to name the host, have no row in ANY provider's
    table, and be refused by the decision without claiming anything.
    """
    import sys as _sys  # noqa: PLC0415

    from nornyx_forge import onboarding_app  # noqa: PLC0415

    monkeypatch.setattr(_sys, "platform", "freebsd14")
    word = onboarding_app.served_platform()
    assert word == "unsupported:freebsd14", (
        f"an unrecognised host derived {word!r}; a fail-closed default must name "
        "the host it could not map, and must not be a word any table carries"
    )
    for provider, rows in PROVIDER_CONFINEMENT.items():
        assert word not in rows, f"{word!r} has a row under {provider!r}"

    for provider in sorted(PROVIDER_CONFINEMENT):
        verdict = governed_build_eligibility(provider, word)
        assert verdict.eligible is False
        assert verdict.confinement == "none"
        assert verdict.platform == word
        assert "freebsd14" in verdict.reason
        assert "established" not in verdict.reason
        assert "confined" not in verdict.reason

    # And through the surface, because that is where it would be read.
    client = _client(tmp_path, RecordingFactory())
    _confirmed(client, "claude")
    served = _ok(client.get("/api/state"))["provider_eligibility"]
    assert served["platform"] == word and served["eligible"] is False


def test_e13_the_surface_serves_the_platform_it_decided_for(tmp_path: Path):
    """`/api/state` says which platform the eligibility decision was made for,
    and an injected platform proves the surface is not hard-coding the word."""
    factory = RecordingFactory()
    client = authed_client(create_app(
        tmp_path / "capsule", CONTRACTS, flow_factory=factory,
        seal_dir=tmp_path / "seals", platform="linux"))
    _confirmed(client, "claude")
    served = _ok(client.get("/api/state"))["provider_eligibility"]
    assert served["platform"] == "linux", (
        "the served decision ignored the platform it was built with, so the "
        "surface is deciding on a word of its own"
    )
    assert served == governed_build_eligibility("claude", "linux").as_dict()

    default = _client(tmp_path / "b", RecordingFactory())
    _confirmed(default, "claude")
    from nornyx_forge.onboarding_app import served_platform  # noqa: PLC0415
    assert _ok(default.get("/api/state"))["provider_eligibility"]["platform"] == served_platform()
