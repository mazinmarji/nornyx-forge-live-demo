"""The journey receipt: one verifiable, allowlisted record of a project's journey.

WHAT THESE TESTS HOLD (A-058).
- A real build the Provider Contract refuses stays REFUSED in the receipt,
  with the build route's own refusal sentence, word for word.
- A journey whose build came from a deterministic flow at the test seam --
  the only way any build reaches the lifecycle while no provider is eligible
  -- is classified SIMULATED, and no receipt ever says a runnable application
  exists.
- The receipt's own digest proves integrity only. Tampering with the project
  is caught by re-deriving the receipt from the sealed store, whose seal lives
  outside the project; a forged receipt with a recomputed digest is caught by
  that re-derivation or by a digest the holder obtained out of band. Without
  either, the verifier says authenticity is not established.
- Missing or inconsistent required evidence is refused. A lifecycle the store
  cannot read is refused, never exported as absent, and a stage's evidence
  is judged as experience.advance() judges it: by the last row of each kind.
- Nothing outside an explicit allowlist leaves the project: no actor
  identity, project name, requirement text, BRD text, local path or bearer.
- Exporting and verifying construct no flow and call no provider.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from session_client import authed_client, session_token
from typer.testing import CliRunner

from nornyx_forge import capsule_store as store_module
from nornyx_forge import journey_receipt as receipt_module
from nornyx_forge.capsule import Actor, CapsuleError, create_document
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.cli import app as cli_app
from nornyx_forge.experience import EvidenceRef, ExperienceError, advance, start_experience
from nornyx_forge.experience_journey import BrdState
from nornyx_forge.journey_receipt import (
    RECEIPT_SCHEMA,
    ReceiptError,
    body_digest,
    build_body,
    export_receipt,
    measure_brd,
    parse_receipt,
    receipt_bytes,
    verify_receipt,
)
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.provider_contract import GovernedEligibility, governed_build_eligibility

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
PROJECT_NAME = "Support Portal Receipt Specimen"
INTENT = "Build a customer support portal for the receipt specimen."
PLATFORM = "windows"
CLOCK = "2026-10-31T12:00:00Z"
SUBJECT_GATE = {"name": "greenfield:test-execution", "passed": True, "detail": "",
                "command": ["python", "-I", "-c", "verifier"], "returncode": 0}
NORNYX_GATE = {"name": "nornyx check .nornyx/generated/brd_contract.nyx", "passed": True,
               "detail": "ok", "command": ["nornyx", "check", "brd_contract.nyx"], "returncode": 0}

#: The exact key set of every object in a receipt. A key outside these is
#: refused by the verifier, so growing the receipt is a schema change.
RECEIPT_KEYS = {"schema", "body", "integrity"}
BODY_KEYS = {"forge", "generated_at", "project", "brd", "journey", "evidence",
             "provider", "build", "classification"}
FORGE_KEYS = {"version", "exporter"}
PROJECT_KEYS = {"project_id", "store_revision", "requirements_digest",
                "requirements_revisions", "seal"}
BRD_KEYS = {"present", "derived", "digest"}
JOURNEY_KEYS = {"tracking", "stage", "status", "lifecycle_digest", "events", "failure"}
EVENT_KEYS = {"event", "from", "to", "actor_kind", "at", "detail_sha256"}
EVIDENCE_KEYS = {"stage", "kind", "ref", "ref_sha256", "passed"}
PROVIDER_KEYS = {"name", "platform", "eligible", "confinement", "reason"}
BUILD_KEYS = {"outcome", "refusal", "recorded"}
CLASSIFICATION_KEYS = {"execution", "runnable_application", "basis"}
INTEGRITY_KEYS = {"algorithm", "canonicalization", "body_sha256", "authenticity"}


class RecordingFactory:
    """A deterministic flow at the injectable seam: it executes no provider."""

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
                               reason="deterministic flow at the injectable seam")


def _ok(response) -> dict:
    assert response.status_code == 200, response.text
    return response.json()


def _client(tmp_path: Path, factory, *, seam: bool) -> TestClient:
    kwargs = {"eligibility": _seam_eligibility} if seam else {}
    return authed_client(create_app(tmp_path / "capsule", CONTRACTS, flow_factory=factory,
                                    seal_dir=tmp_path / "seals", platform=PLATFORM, **kwargs))


def _confirmed(client: TestClient, provider: str = "codex") -> None:
    _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": PROJECT_NAME, "actor": HUMAN}))
    intent = _ok(client.post("/api/proposals", json={
        "field": "intent", "value": INTENT, "actor": MODEL}))["proposal_id"]
    _ok(client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}))
    chosen = _ok(client.post("/api/proposals", json={
        "field": "provider", "value": {"name": provider}, "actor": HUMAN}))["proposal_id"]
    _ok(client.post(f"/api/proposals/{chosen}/confirm", json={"actor": HUMAN}))
    _ok(client.post("/api/brd"))
    assert _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))["stage"] == "CONFIRM"


def _wait_build(client: TestClient) -> dict:
    status: dict = {}
    for _ in range(500):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            return status
        threading.Event().wait(0.02)
    raise AssertionError(f"the seam build did not finish: {status}")


def _export(tmp_path: Path) -> dict:
    return export_receipt(tmp_path, seal_dir=tmp_path / "seals", platform=PLATFORM,
                          clock=lambda: CLOCK)


def _refused_project(tmp_path: Path) -> tuple[TestClient, dict]:
    client = _client(tmp_path, RecordingFactory(), seam=False)
    _confirmed(client)
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409, response.text
    return client, response.json()


def _simulated_ready_project(tmp_path: Path) -> TestClient:
    factory = RecordingFactory()
    client = _client(tmp_path, factory, seam=True)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    assert _wait_build(client)["lifecycle"]["stage"] == "GOVERN"
    assert _ok(client.post("/api/journey/ready", json={"actor": HUMAN}))["stage"] == "READY"
    assert len(factory.calls) == 1
    return client


def _verify_live(tmp_path: Path, receipt: dict, **kwargs):
    """Re-derive against the sealed store, for the VERIFIER's own platform word."""
    kwargs.setdefault("platform", PLATFORM)
    return verify_receipt(receipt, project_dir=tmp_path, seal_dir=tmp_path / "seals", **kwargs)


def reseal(receipt: dict) -> dict:
    """What anyone who edits a receipt can do: recompute its digest."""
    resealed = copy.deepcopy(receipt)
    resealed["integrity"]["body_sha256"] = body_digest(resealed["body"])
    return resealed


# ---------------------------------------------------------------------------
# Shape: every object has exactly its declared keys
# ---------------------------------------------------------------------------

def test_the_receipt_has_exactly_the_declared_shape(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    receipt = _export(tmp_path)
    assert set(receipt) == RECEIPT_KEYS
    assert receipt["schema"] == RECEIPT_SCHEMA == "nornyx.forge.journey_receipt.v1"
    body = receipt["body"]
    assert set(body) == BODY_KEYS
    assert set(body["forge"]) == FORGE_KEYS
    assert set(body["project"]) == PROJECT_KEYS
    assert set(body["brd"]) == BRD_KEYS
    assert set(body["journey"]) == JOURNEY_KEYS
    assert body["journey"]["events"] and all(set(e) == EVENT_KEYS for e in body["journey"]["events"])
    assert body["evidence"] and all(set(e) == EVIDENCE_KEYS for e in body["evidence"])
    assert set(body["provider"]) == PROVIDER_KEYS
    assert set(body["build"]) == BUILD_KEYS
    assert set(body["classification"]) == CLASSIFICATION_KEYS
    assert set(receipt["integrity"]) == INTEGRITY_KEYS
    assert receipt["integrity"]["authenticity"] == "not_established_by_this_digest"
    assert body["generated_at"] == CLOCK


def test_unknown_or_missing_keys_are_refused(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    extra = copy.deepcopy(receipt)
    extra["body"]["provider"]["token"] = "x"
    verdict = verify_receipt(reseal(extra))
    assert not verdict.verified and any("provider" in p and "token" in p for p in verdict.problems)
    missing = copy.deepcopy(receipt)
    del missing["body"]["build"]["refusal"]
    verdict = verify_receipt(reseal(missing))
    assert not verdict.verified and any("refusal" in p for p in verdict.problems)
    wrong = copy.deepcopy(receipt)
    wrong["schema"] = "nornyx.forge.journey_receipt.v2"
    assert not verify_receipt(wrong).verified


# ---------------------------------------------------------------------------
# Assurance 1: a refused real build stays REFUSED, in the route's own words
# ---------------------------------------------------------------------------

def test_a_refused_real_build_is_refused_with_the_routes_exact_reason(tmp_path: Path):
    _client_, refusal = _refused_project(tmp_path)
    receipt = _export(tmp_path)
    body = receipt["body"]
    shipped = governed_build_eligibility("codex", PLATFORM)
    assert shipped.eligible is False
    assert body["provider"] == {"name": shipped.provider, "platform": shipped.platform,
                                "eligible": False, "confinement": shipped.confinement,
                                "reason": shipped.reason}
    assert body["build"] == {"outcome": "refused", "refusal": refusal["refused"], "recorded": False}
    assert body["build"]["refusal"] == shipped.reason
    assert body["classification"]["execution"] == "refused"
    assert body["classification"]["runnable_application"] is False
    assert body["journey"]["stage"] == "CONFIRM"
    verdict = _verify_live(tmp_path, receipt)
    assert verdict.verified, verdict.problems


# ---------------------------------------------------------------------------
# Assurance 2: a simulated journey is SIMULATED and never runnable
# ---------------------------------------------------------------------------

def test_a_seam_journey_to_ready_is_simulated_and_never_runnable(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    receipt = _export(tmp_path)
    body = receipt["body"]
    assert body["journey"]["stage"] == "READY"
    assert body["build"]["recorded"] is True
    assert body["build"]["outcome"] == "refused"
    assert body["classification"]["execution"] == "simulated"
    assert body["classification"]["runnable_application"] is False
    assert "could not have admitted" in body["classification"]["basis"]
    kinds = {(e["stage"], e["kind"]) for e in body["evidence"]}
    assert {("TEST", "flow_run"), ("GOVERN", "gate_results"),
            ("READY", "governance_validation")} <= kinds
    verdict = _verify_live(tmp_path, receipt)
    assert verdict.verified, verdict.problems


def test_no_receipt_can_claim_a_runnable_application(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    receipt = _export(tmp_path)
    forged = copy.deepcopy(receipt)
    forged["body"]["classification"]["runnable_application"] = True
    verdict = verify_receipt(reseal(forged))
    assert not verdict.verified and any("runnable" in p for p in verdict.problems)
    relabelled = copy.deepcopy(receipt)
    relabelled["body"]["classification"]["execution"] = "unattested"
    assert not verify_receipt(reseal(relabelled)).verified


# ---------------------------------------------------------------------------
# Assurance 3: tampering is detected against a separately trusted reference
# ---------------------------------------------------------------------------

def test_an_edited_receipt_fails_its_own_digest(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    edited = copy.deepcopy(receipt)
    edited["body"]["project"]["project_id"] = "proj-2"
    verdict = verify_receipt(edited)
    assert not verdict.verified and any("digest" in p for p in verdict.problems)


def test_a_self_consistent_forgery_is_caught_only_by_a_trusted_reference(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    forged = copy.deepcopy(receipt)
    forged["body"]["brd"]["digest"] = "0" * 64
    forged = reseal(forged)
    alone = verify_receipt(forged)
    # The digest is recomputed, so the receipt is internally consistent; with
    # no anchor the verifier must not call it verified or authentic.
    assert alone.consistent, alone.problems
    assert not alone.verified and alone.anchors == ()
    assert alone.authenticity == "not_established"
    assert alone.live_comparison == "not_performed"
    live = _verify_live(tmp_path, forged)
    assert not live.verified and any("brd" in p for p in live.problems)
    original = receipt["integrity"]["body_sha256"]
    oob = verify_receipt(forged, expect_sha256=original)
    assert not oob.verified and any("out-of-band" in p for p in oob.problems)
    good = verify_receipt(receipt, expect_sha256=original)
    assert good.verified and good.anchors == ("out_of_band_digest",)
    assert good.authenticity == "established"
    sealed = _verify_live(tmp_path, receipt)
    assert sealed.verified and sealed.anchors == ("sealed_store",)


def test_the_live_comparison_never_takes_its_platform_from_the_receipt(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    injected = copy.deepcopy(receipt)
    injected["body"]["provider"]["platform"] = "windows -- approved for production"
    injected["body"]["provider"]["reason"] = injected["body"]["build"]["refusal"] = "x"
    verdict = _verify_live(tmp_path, reseal(injected))
    assert not verdict.verified and any("platform word" in p for p in verdict.problems)
    elsewhere = verify_receipt(receipt, project_dir=tmp_path, seal_dir=tmp_path / "seals",
                               platform="linux")
    assert not elsewhere.verified and elsewhere.live_comparison == "refused"
    no_platform = verify_receipt(receipt, project_dir=tmp_path, seal_dir=tmp_path / "seals")
    assert not no_platform.verified and no_platform.live_comparison == "refused"


def test_an_unsealed_store_anchors_nothing(tmp_path: Path):
    """A store whose seal and seal marker are both gone loads as legacy; it
    can be rewritten without a trace, so it is no anchor at all."""
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    store.seal_path().unlink()
    (tmp_path / "capsule" / ".forge-seal").unlink()
    verdict = _verify_live(tmp_path, receipt)
    assert not verdict.verified and verdict.live_comparison == "unanchored"
    assert "sealed_store" not in verdict.anchors
    assert _export(tmp_path)["body"]["project"]["seal"] == "unsealed"


def test_editing_the_projects_brd_after_export_is_detected(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    brd = tmp_path / "BRD.md"
    brd.write_text(brd.read_text(encoding="utf-8") + "\nEdited after export.\n", encoding="utf-8")
    verdict = _verify_live(tmp_path, receipt)
    assert not verdict.verified and any("brd" in p for p in verdict.problems)


def test_editing_the_store_behind_the_seal_is_refused(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    lifecycle = tmp_path / "capsule" / "experience.json"
    state = json.loads(lifecycle.read_text(encoding="utf-8"))
    state["history"][0]["at"] = "2026-01-01T00:00:00Z"
    lifecycle.write_text(json.dumps(state), encoding="utf-8")
    verdict = _verify_live(tmp_path, receipt)
    assert not verdict.verified
    assert verdict.live_comparison == "refused"


# ---------------------------------------------------------------------------
# Assurance 4: missing or inconsistent required evidence is refused
# ---------------------------------------------------------------------------

def test_a_stage_without_its_required_evidence_is_refused(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    receipt = _export(tmp_path)
    stripped = copy.deepcopy(receipt)
    stripped["body"]["evidence"] = [e for e in stripped["body"]["evidence"]
                                    if e["kind"] != "governance_validation"]
    verdict = verify_receipt(reseal(stripped))
    assert not verdict.verified
    assert any("READY" in p and "governance_validation" in p for p in verdict.problems)


def test_a_walk_that_breaks_the_experience_contract_is_refused(tmp_path: Path):
    """READY without BUILD, entered by a model: never described, and never
    classified as anything less than what it would claim."""
    _simulated_ready_project(tmp_path)
    receipt = _export(tmp_path)
    events = receipt["body"]["journey"]["events"]
    skipped = copy.deepcopy(receipt)
    skipped["body"]["journey"]["events"] = [
        e for e in events if e["to"] not in ("BUILD", "TEST", "GOVERN") or e["event"] != "advanced"]
    skipped["body"]["build"]["recorded"] = True
    verdict = verify_receipt(reseal(skipped))
    assert not verdict.verified and any("not a contract transition" in p
                                        for p in verdict.problems)
    by_model = copy.deepcopy(receipt)
    by_model["body"]["journey"]["events"][-1]["actor_kind"] = "model"
    assert any("may not advance into READY" in p
               for p in verify_receipt(reseal(by_model)).problems)
    document = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").load()
    lifecycle = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").load_experience()
    forged = copy.deepcopy(lifecycle)
    forged["history"] = [h for h in forged["history"] if h["to"] not in ("BUILD", "TEST", "GOVERN")]
    with pytest.raises(ReceiptError, match="Experience Contract"):
        build_body(document=document, lifecycle=forged, brd=BrdState.absent(),
                   revision="r", seal="sealed", platform=PLATFORM, generated_at=CLOCK)


def test_a_consistent_receipt_without_an_anchor_is_not_verified(tmp_path: Path):
    _refused_project(tmp_path)
    verdict = verify_receipt(_export(tmp_path))
    assert verdict.consistent and not verdict.verified


def test_only_the_canonical_bytes_of_a_receipt_are_read(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    receipt = _export(tmp_path)
    data = receipt_bytes(receipt)
    assert parse_receipt(data) == receipt
    twice = data.replace(b'"execution":"simulated"',
                         b'"execution":"simulated","execution":"unattested"')
    with pytest.raises(ReceiptError, match="repeats a key"):
        parse_receipt(twice)
    with pytest.raises(ReceiptError, match="canonical"):
        parse_receipt(json.dumps(receipt, indent=2).encode("utf-8"))
    surrogate = copy.deepcopy(receipt)
    surrogate["body"]["generated_at"] = "\ud800"
    verdict = verify_receipt(surrogate)
    assert not verdict.verified and verdict.problems


def test_an_unknown_flow_backend_label_is_withheld(tmp_path: Path):
    class LabelledFactory(RecordingFactory):
        def run(self):
            return {**super().run(), "execution_backend": "sk-ant-api03-SECRET"}

    client = _client(tmp_path, LabelledFactory(), seam=True)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_build(client)
    receipt = _export(tmp_path)
    assert "sk-ant" not in receipt_bytes(receipt).decode("utf-8")
    flow = [e for e in receipt["body"]["evidence"] if e["kind"] == "flow_run"]
    assert flow and all(e["ref"] is None and len(e["ref_sha256"]) == 64 for e in flow)


def test_an_eligibility_the_contract_does_not_give_is_refused(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    forged = copy.deepcopy(receipt)
    forged["body"]["provider"]["eligible"] = True
    forged["body"]["provider"]["confinement"] = "established"
    verdict = verify_receipt(reseal(forged))
    assert not verdict.verified and any("eligib" in p for p in verdict.problems)


def test_a_refusal_that_is_not_the_contracts_sentence_is_refused(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    forged = copy.deepcopy(receipt)
    forged["body"]["build"]["refusal"] = "temporarily unavailable"
    assert not verify_receipt(reseal(forged)).verified


def test_a_receipt_from_another_forge_version_is_not_judged(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    other = copy.deepcopy(receipt)
    other["body"]["forge"]["version"] = "0.0.1"
    verdict = verify_receipt(reseal(other))
    assert not verdict.verified and any("version" in p for p in verdict.problems)


def test_an_unrecognised_evidence_reference_is_withheld_not_exported(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    actor = Actor("human", "casey")
    lifecycle = start_experience(actor, CLOCK)
    for stage in ("UNDERSTAND", "MODEL", "PROPOSE"):
        lifecycle = advance(lifecycle, stage, actor, CLOCK)
    lifecycle = advance(lifecycle, "CONFIRM", actor, CLOCK, evidence=(
        EvidenceRef(kind="brd_requirements", ref="home/casey/private/notes", passed=True),))
    store.initialize(create_document("proj-1", PROJECT_NAME, actor, CLOCK), experience=lifecycle)
    receipt = _export(tmp_path)
    (item,) = receipt["body"]["evidence"]
    assert item["ref"] is None
    assert item["ref_sha256"] == hashlib.sha256(b"home/casey/private/notes").hexdigest()
    assert "casey" not in receipt_bytes(receipt).decode("utf-8")
    assert _verify_live(tmp_path, receipt).verified


# ---------------------------------------------------------------------------
# Assurance 5: an explicit export allowlist
# ---------------------------------------------------------------------------

def test_nothing_outside_the_allowlist_leaves_the_project(tmp_path: Path):
    client = _simulated_ready_project(tmp_path)
    text = receipt_bytes(_export(tmp_path)).decode("utf-8")
    brd_text = (tmp_path / "BRD.md").read_text(encoding="utf-8")
    forbidden = [HUMAN["ident"], MODEL["ident"], PROJECT_NAME, INTENT,
                 session_token(client.app), str(tmp_path), tmp_path.name,
                 str(tmp_path / "seals"), "casey"]
    forbidden += [line for line in brd_text.splitlines() if len(line.strip()) > 12]
    for value in forbidden:
        assert value not in text, f"{value!r} leaked into the receipt"


def test_failure_details_are_bound_by_digest_not_exported_verbatim(tmp_path: Path):
    class FailingFactory(RecordingFactory):
        def run(self):
            gate = dict(SUBJECT_GATE, passed=False, detail="see /home/casey/secret/run.log")
            return {"accepted": False, "gates": [gate], "execution_backend": "sequential"}

    client = _client(tmp_path, FailingFactory(), seam=True)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_build(client)
    receipt = _export(tmp_path)
    text = receipt_bytes(receipt).decode("utf-8")
    assert "/home/casey" not in text and "run.log" not in text
    failed = [e for e in receipt["body"]["journey"]["events"] if e["event"] == "failed"]
    assert failed and all(len(e["detail_sha256"]) == 64 for e in failed)
    assert receipt["body"]["journey"]["status"] == "failed"
    assert set(receipt["body"]["journey"]["failure"]) == {"summary", "check"}
    assert _verify_live(tmp_path, receipt).verified


# ---------------------------------------------------------------------------
# Assurance 6 and 7: nothing executes; existing controls are unchanged
# ---------------------------------------------------------------------------

def test_export_and_verify_construct_no_flow_and_call_no_provider(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _simulated_ready_project(tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("the receipt path reached a provider or a flow")

    monkeypatch.setattr("nornyx_forge.providers.get_provider", refuse)
    monkeypatch.setattr("nornyx_forge.development_flow.DevelopmentFlow.__init__", refuse)
    receipt = _export(tmp_path)
    assert _verify_live(tmp_path, receipt).verified


def test_the_build_route_still_refuses_after_an_export(tmp_path: Path):
    client, first = _refused_project(tmp_path)
    _export(tmp_path)
    again = client.post("/api/build", json={"actor": HUMAN})
    assert again.status_code == 409 and again.json()["refused"] == first["refused"]


def test_measure_brd_is_the_surfaces_own_reading(tmp_path: Path):
    client, _ = _refused_project(tmp_path)
    state = _ok(client.get("/api/state"))
    document = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").load()
    measured = measure_brd(tmp_path / "BRD.md", document)
    assert (measured.present, measured.derived, measured.digest) == (
        state["brd_present"], state["brd_derived"], state["brd_digest"])


# ---------------------------------------------------------------------------
# Determinism and the command line
# ---------------------------------------------------------------------------

def test_export_is_deterministic_for_the_same_state_and_clock(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    assert receipt_bytes(_export(tmp_path)) == receipt_bytes(_export(tmp_path))


def test_the_command_line_exports_and_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _refused_project(tmp_path)
    monkeypatch.setattr(receipt_module, "_now_iso", lambda: CLOCK)
    out = tmp_path.parent / f"{tmp_path.name}-receipt.json"
    runner = CliRunner()
    exported = runner.invoke(cli_app, ["journey-receipt", "--project-dir", str(tmp_path),
                                       "--seal-dir", str(tmp_path / "seals"),
                                       "--out", str(out)])
    assert exported.exit_code == 0, exported.output
    digest = json.loads(out.read_text(encoding="utf-8"))["integrity"]["body_sha256"]
    assert digest in exported.output
    verified = runner.invoke(cli_app, ["verify-journey-receipt", str(out),
                                       "--project-dir", str(tmp_path),
                                       "--seal-dir", str(tmp_path / "seals"),
                                       "--expect-sha256", digest])
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["verified"] is True
    tampered = json.loads(out.read_text(encoding="utf-8"))
    tampered["body"]["classification"]["execution"] = "unattested"
    out.write_text(json.dumps(tampered), encoding="utf-8")
    refused = runner.invoke(cli_app, ["verify-journey-receipt", str(out)])
    assert refused.exit_code == 1
    assert json.loads(refused.output)["verified"] is False


def test_without_the_demo_extra_export_refuses_in_json(tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch):
    """The platform word's one owner is the onboarding surface (FastAPI, the
    `demo` extra). Without it the command refuses in its own JSON, not with a
    traceback; verifying a receipt alone needs no extra."""
    _refused_project(tmp_path)
    out = tmp_path.parent / f"{tmp_path.name}-receipt.json"
    out.write_bytes(receipt_bytes(_export(tmp_path)))
    monkeypatch.setitem(sys.modules, "nornyx_forge.onboarding_app", None)
    runner = CliRunner()
    exported = runner.invoke(cli_app, ["journey-receipt", "--project-dir", str(tmp_path),
                                       "--seal-dir", str(tmp_path / "seals"),
                                       "--out", str(tmp_path.parent / "never.json")])
    assert exported.exit_code == 1, exported.output
    assert json.loads(exported.output)["exported"] is False
    alone = runner.invoke(cli_app, ["verify-journey-receipt", str(out)])
    assert alone.exit_code == 1 and json.loads(alone.output)["consistent"] is True


def test_the_exporters_clock_must_be_a_utc_instant_and_is_never_anchored(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    claimed = copy.deepcopy(receipt)
    claimed["body"]["generated_at"] = "2020-01-01 -- approved for production"
    verdict = _verify_live(tmp_path, reseal(claimed))
    assert not verdict.verified and any("generated_at" in p for p in verdict.problems)
    good = _verify_live(tmp_path, receipt)
    assert good.verified and good.as_dict()["not_anchored"] == ["body.generated_at"]


def test_the_contracts_status_and_actor_guards_hold_over_the_walk(tmp_path: Path):
    client = _client(tmp_path, RecordingFactory(), seam=True)
    _confirmed(client)
    receipt = _export(tmp_path)
    events = receipt["body"]["journey"]["events"]
    stage = receipt["body"]["journey"]["stage"]
    retried = copy.deepcopy(receipt)
    retried["body"]["journey"]["events"].append({
        "event": "retried", "from": stage, "to": stage, "actor_kind": "model",
        "at": CLOCK, "detail_sha256": None})
    assert any("retries without a failure" in p
               for p in verify_receipt(reseal(retried)).problems)
    started = copy.deepcopy(receipt)
    started["body"]["journey"]["events"][0]["actor_kind"] = "system"
    assert any("started by a human" in p for p in verify_receipt(reseal(started)).problems)
    phantom = copy.deepcopy(receipt)
    phantom["body"]["journey"]["failure"] = {"summary": "It failed.", "check": None}
    assert any("exactly when the workflow failed" in p
               for p in verify_receipt(reseal(phantom)).problems)
    assert events and verify_receipt(receipt).consistent


def test_a_deeply_nested_receipt_file_is_refused_in_words():
    with pytest.raises(ReceiptError):
        parse_receipt(b"[" * 200_000 + b"]" * 200_000)


# ---------------------------------------------------------------------------
# Mutant-killing coverage: every section the live comparison anchors, every
# class, every verifier rule, and the guards (independent test review)
# ---------------------------------------------------------------------------

def _scope_ref() -> str:
    return f"capsule/{'a' * 64}/brd/{'b' * 64}"


@pytest.mark.parametrize("section", ["project", "journey", "evidence", "brd"])
def test_the_live_comparison_anchors_every_section_it_can_disagree_on(
        tmp_path: Path, section: str):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    forged = copy.deepcopy(receipt)
    body = forged["body"]
    if section == "project":
        body["project"]["project_id"] = "proj-2"
    elif section == "journey":
        body["journey"]["events"][-1]["at"] = "2026-01-01T00:00:00Z"
    elif section == "evidence":
        ref = _scope_ref()
        body["evidence"][0].update(ref=ref, ref_sha256=hashlib.sha256(ref.encode()).hexdigest())
    else:
        body["brd"]["digest"] = "0" * 64
    forged = reseal(forged)
    assert verify_receipt(forged).consistent, "the forgery must be self-consistent"
    verdict = _verify_live(tmp_path, forged)
    assert not verdict.verified and verdict.live_comparison == "refused"
    assert any(section in p for p in verdict.problems)


def test_a_store_rewritten_behind_its_seal_refuses_export_and_live_comparison(tmp_path: Path):
    from nornyx_forge.experience import fail

    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    unsealed = CapsuleStore(tmp_path / "capsule")
    lifecycle = unsealed.load_experience()
    unsealed.save_experience(fail(lifecycle, Actor("system", "s"), "rewritten", CLOCK),
                             "rewritten behind the seal")
    verdict = _verify_live(tmp_path, receipt)
    assert not verdict.verified and verdict.live_comparison == "refused"
    assert any("store refused" in p for p in verdict.problems)
    with pytest.raises(CapsuleError):
        _export(tmp_path)


def test_a_forged_class_and_basis_together_are_still_refused(tmp_path: Path):
    _simulated_ready_project(tmp_path)
    forged = copy.deepcopy(_export(tmp_path))
    forged["body"]["classification"]["execution"] = "unattested"
    forged["body"]["classification"]["basis"] = (
        receipt_module._BASIS["unattested"] + receipt_module._RUNNABLE_NOTE)
    assert not verify_receipt(reseal(forged)).consistent


def test_an_eligible_provider_with_a_recorded_build_is_unattested_never_real(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The day a provider is eligible: the receipt still claims no real
    execution, because Forge records no build-admission attestation."""
    _simulated_ready_project(tmp_path)
    monkeypatch.setattr(receipt_module, "governed_build_eligibility", _seam_eligibility)
    receipt = _export(tmp_path)
    body = receipt["body"]
    assert body["build"] == {"outcome": "admissible", "refusal": None, "recorded": True}
    assert body["classification"]["execution"] == "unattested"
    assert body["classification"]["runnable_application"] is False
    assert "does not establish that a real provider executed" in body["classification"]["basis"]
    assert _verify_live(tmp_path, receipt).verified


def test_no_confirmed_provider_and_no_build_is_none(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    store.initialize(create_document("proj-1", PROJECT_NAME, Actor("human", "casey"), CLOCK),
                     experience=start_experience(Actor("human", "casey"), CLOCK))
    body = _export(tmp_path)["body"]
    assert body["provider"]["name"] is None and body["provider"]["eligible"] is None
    assert body["build"] == {"outcome": "no_provider", "refusal": None, "recorded": False}
    assert body["classification"]["execution"] == "none"
    assert body["project"]["seal"] == "sealed"


def test_an_absent_lifecycle_is_exported_as_absent(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    store.initialize(create_document("proj-1", PROJECT_NAME, Actor("human", "casey"), CLOCK))
    receipt = _export(tmp_path)
    assert receipt["body"]["journey"]["tracking"] == "absent"
    assert receipt["body"]["evidence"] == []
    assert _verify_live(tmp_path, receipt).verified


def test_a_raised_flow_error_never_reaches_the_receipt_verbatim(tmp_path: Path):
    class RaisingFactory(RecordingFactory):
        def run(self):
            raise RuntimeError("token sk-live-SECRET at /home/casey/secret/run.log")

    client = _client(tmp_path, RaisingFactory(), seam=True)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_build(client)
    receipt = _export(tmp_path)
    text = receipt_bytes(receipt).decode("utf-8")
    for secret in ("sk-live-SECRET", "/home/casey", "run.log"):
        assert secret not in text
    lifecycle = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").load_experience()
    assert any("sk-live-SECRET" in h["detail"] for h in lifecycle["history"]), (
        "the secret must have reached the lifecycle, or this proves nothing")
    assert _verify_live(tmp_path, receipt).verified


def _forge_entered_never(body):
    ref = _scope_ref()
    body["evidence"].append({"stage": "READY", "kind": "gate_results", "ref": None,
                             "ref_sha256": hashlib.sha256(ref.encode()).hexdigest(),
                             "passed": True})


def _forge_not_passed(body):
    body["evidence"][0]["passed"] = False


def _forge_ref_digest(body):
    body["evidence"][0]["ref_sha256"] = "1" * 64


def _forge_stage(body):
    body["journey"]["stage"] = "UNDERSTAND"


def _forge_absent_with_events(body):
    body["journey"]["tracking"] = "absent"


def _forge_derived_without_digest(body):
    body["brd"]["digest"] = None


def _forge_absent_brd_with_digest(body):
    body["brd"].update(present=False, derived=False)


def _forge_recorded(body):
    # Recorded, with the class that recording would imply, so only the rule
    # that reads how far the journey reached can catch it.
    body["build"]["recorded"] = True
    body["classification"]["execution"] = "simulated"
    body["classification"]["basis"] = (
        receipt_module._BASIS["simulated"] + receipt_module._RUNNABLE_NOTE)


def _forge_no_provider_with_eligibility(body):
    # No provider named, with the outcome and class that would follow, so only
    # the rule against stating an eligibility for nobody can catch it.
    body["provider"]["name"] = None
    body["build"].update(outcome="no_provider", refusal=None)
    body["classification"]["execution"] = "none"
    body["classification"]["basis"] = receipt_module._BASIS["none"] + receipt_module._RUNNABLE_NOTE


def _forge_advance_failed(body):
    stage = body["journey"]["stage"]
    body["journey"]["events"] += [
        {"event": "failed", "from": stage, "to": stage, "actor_kind": "system", "at": CLOCK,
         "detail_sha256": "2" * 64},
        {"event": "advanced", "from": stage, "to": "CONFIRM", "actor_kind": "human",
         "at": CLOCK, "detail_sha256": None}]
    # The second admission carries its own passed row, so only the rule
    # against advancing a failed workflow can catch it.
    body["evidence"].append({"stage": "CONFIRM", "kind": "brd_requirements", "ref": None,
                             "ref_sha256": hashlib.sha256(_scope_ref().encode()).hexdigest(),
                             "passed": True})


def _forge_fail_twice(body):
    stage = body["journey"]["stage"]
    failed = {"event": "failed", "from": stage, "to": stage, "actor_kind": "system",
              "at": CLOCK, "detail_sha256": "2" * 64}
    body["journey"]["events"] += [failed, dict(failed)]
    body["journey"]["status"] = "failed"
    body["journey"]["failure"] = {"summary": "It failed.", "check": None}


@pytest.mark.parametrize(("forge", "rule"), [
    (_forge_entered_never, "was never entered"),
    (_forge_not_passed, "without a passed brd_requirements"),
    (_forge_ref_digest, "does not match its digest"),
    (_forge_stage, "the walk ends at"),
    (_forge_absent_with_events, "an absent lifecycle"),
    (_forge_derived_without_digest, "a derived BRD must be present"),
    (_forge_absent_brd_with_digest, "an absent BRD carries neither"),
    (_forge_recorded, "disagrees with how far the journey reached"),
    (_forge_no_provider_with_eligibility, "no provider is named"),
    (_forge_advance_failed, "advances a failed workflow"),
    (_forge_fail_twice, "fails a workflow already failed"),
], ids=lambda value: getattr(value, "__name__", "rule"))
def test_each_verifier_rule_refuses_its_forgery(tmp_path: Path, forge, rule: str):
    _refused_project(tmp_path)
    forged = copy.deepcopy(_export(tmp_path))
    forge(forged["body"])
    verdict = verify_receipt(reseal(forged))
    assert not verdict.consistent and not verdict.verified, verdict
    assert [p for p in verdict.problems if rule in p], (rule, verdict.problems)
    others = [p for p in verdict.problems if rule not in p]
    assert others == [], f"the forgery tripped other rules too, so it isolates nothing: {others}"


def test_a_failed_workflow_with_an_empty_plain_summary_is_refused(tmp_path: Path):
    class FailingFactory(RecordingFactory):
        def run(self):
            return {"accepted": False, "gates": [dict(SUBJECT_GATE, passed=False)],
                    "execution_backend": "sequential"}

    client = _client(tmp_path, FailingFactory(), seam=True)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_build(client)
    receipt = _export(tmp_path)
    assert receipt["body"]["journey"]["failure"]["summary"]
    empty = copy.deepcopy(receipt)
    empty["body"]["journey"]["failure"]["summary"] = ""
    assert any("non-empty plain summary" in p for p in verify_receipt(reseal(empty)).problems)


def test_a_receipt_file_over_the_size_limit_is_refused_before_it_is_read_whole(tmp_path: Path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (receipt_module._MAX_RECEIPT_BYTES + 10))
    with pytest.raises(ReceiptError, match="larger than"):
        receipt_module.read_receipt(big)
    with pytest.raises(ReceiptError, match="larger than"):
        parse_receipt(b" " * (receipt_module._MAX_RECEIPT_BYTES + 1))


def test_the_digest_is_reproducible_from_the_documented_canonicalization(tmp_path: Path):
    _refused_project(tmp_path)
    receipt = _export(tmp_path)
    independent = hashlib.sha256(json.dumps(
        receipt["body"], sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    assert receipt["integrity"]["body_sha256"] == independent
    assert receipt["integrity"]["canonicalization"] == "json-sorted-keys-compact-utf8"


def test_the_command_line_refuses_a_wrong_digest_and_a_drifted_project(tmp_path: Path):
    from nornyx_forge.onboarding_app import served_platform

    _refused_project(tmp_path)
    out = tmp_path.parent / f"{tmp_path.name}-receipt.json"
    runner = CliRunner()
    assert runner.invoke(cli_app, ["journey-receipt", "--project-dir", str(tmp_path),
                                   "--seal-dir", str(tmp_path / "seals"),
                                   "--out", str(out)]).exit_code == 0
    receipt = parse_receipt(out.read_bytes())
    assert receipt["body"]["provider"]["platform"] == served_platform()
    wrong = runner.invoke(cli_app, ["verify-journey-receipt", str(out),
                                    "--expect-sha256", "0" * 64])
    assert wrong.exit_code == 1
    brd = tmp_path / "BRD.md"
    brd.write_text(brd.read_text(encoding="utf-8") + "\ndrift\n", encoding="utf-8")
    drifted = runner.invoke(cli_app, ["verify-journey-receipt", str(out),
                                      "--project-dir", str(tmp_path),
                                      "--seal-dir", str(tmp_path / "seals")])
    assert drifted.exit_code == 1


def test_export_and_verify_start_no_process_but_the_stores_git(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import subprocess

    _simulated_ready_project(tmp_path)
    real_popen = subprocess.Popen

    class GitOnly(real_popen):
        def __init__(self, args, *rest, **kwargs):
            first = args[0] if isinstance(args, (list, tuple)) else args
            program = Path(str(first)).name
            assert program in ("git", "git.exe"), f"the receipt path started {program!r}"
            super().__init__(args, *rest, **kwargs)

    def refuse(*args, **kwargs):
        raise AssertionError("the receipt path reached a provider or a flow")

    monkeypatch.setattr(subprocess, "Popen", GitOnly)
    import os

    # `posix_spawn` is left alone: `subprocess` itself may start git through
    # it, and the Popen guard above already judges every such start.
    for name in ("system", "popen", "spawnv", "spawnve", "spawnl", "spawnlp", "spawnvp",
                 "execv", "execve", "startfile"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse)
    monkeypatch.setattr("nornyx_forge.development_flow.get_provider", refuse, raising=False)
    monkeypatch.setattr("nornyx_forge.providers.get_provider", refuse)
    receipt = _export(tmp_path)
    assert _verify_live(tmp_path, receipt).verified


# ---------------------------------------------------------------------------
# Absence is told from corruption by type, and evidence is judged the way
# experience.advance() judges it (exact-head review repair)
# ---------------------------------------------------------------------------

def _corrupt(path: Path, how: str) -> None:
    text = path.read_text(encoding="utf-8")
    if how == "truncated":
        path.write_text(text[: len(text) // 2], encoding="utf-8")
    else:
        # A second "stage" ahead of the real one: two readers, two lifecycles.
        path.write_text('{"stage": "READY", ' + text.lstrip()[1:], encoding="utf-8")


def _absent_twin(receipt: dict) -> dict:
    """What an exporter that read corruption as absence would have written."""
    twin = copy.deepcopy(receipt)
    twin["body"]["journey"] = {"tracking": "absent", "stage": None, "status": None,
                               "lifecycle_digest": None, "events": [], "failure": None}
    twin["body"]["evidence"] = []
    return reseal(twin)


@pytest.mark.parametrize("sealed", [True, False], ids=["sealed", "unsealed"])
@pytest.mark.parametrize("how", ["truncated", "duplicate_key"])
def test_an_unreadable_lifecycle_refuses_export_and_live_verification(
        tmp_path: Path, how: str, sealed: bool):
    """Corruption is never exported as absence: only a store holding no
    lifecycle at all reads as `tracking: absent`."""
    _refused_project(tmp_path)
    honest = _export(tmp_path)
    if not sealed:
        CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").seal_path().unlink()
        (tmp_path / "capsule" / ".forge-seal").unlink()
    _corrupt(tmp_path / "capsule" / "experience.json", how)
    with pytest.raises(CapsuleError) as raised:
        _export(tmp_path)
    assert not isinstance(raised.value, store_module.ExperienceStateAbsent)
    twin = _absent_twin(honest)
    assert verify_receipt(twin).consistent, "the twin must be self-consistent to prove anything"
    for receipt in (honest, twin):
        verdict = _verify_live(tmp_path, receipt,
                               expect_sha256=receipt["integrity"]["body_sha256"])
        assert not verdict.verified and verdict.live_comparison == "refused", verdict
        assert any("store refused" in p for p in verdict.problems), verdict.problems


def test_only_a_store_without_a_lifecycle_raises_the_absence_type(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    store.initialize(create_document("proj-1", PROJECT_NAME, Actor("human", "casey"), CLOCK))
    with pytest.raises(store_module.ExperienceStateAbsent, match="contains no experience state"):
        store.load_experience()
    assert issubclass(store_module.ExperienceStateAbsent, store_module.CapsuleStoreError)


def _row(passed: bool) -> EvidenceRef:
    return EvidenceRef("brd_requirements", _scope_ref(), passed)


def _admitted_by_hand(state: dict, rows: list[EvidenceRef]) -> dict:
    """What advance() records for an admission into CONFIRM, without its guard:
    the chain-valid record a store owner can write by hand (A-029)."""
    from nornyx_forge.experience import _sealed

    updated = copy.deepcopy(state)
    updated["stage"] = "CONFIRM"
    updated["entered"] = {"by": "casey", "kind": "human", "at": CLOCK}
    updated["evidence"].setdefault("CONFIRM", []).extend(row.as_dict() for row in rows)
    updated["history"].append({"event": "advanced", "from": state["stage"], "to": "CONFIRM",
                               "by": "casey", "kind": "human", "at": CLOCK, "detail": ""})
    return _sealed(updated)


def _store_with(tmp_path: Path, lifecycle: dict) -> None:
    CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").initialize(
        create_document("proj-1", PROJECT_NAME, Actor("human", "casey"), CLOCK),
        experience=lifecycle)


def test_a_later_failing_row_is_not_masked_by_an_earlier_pass(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    human = Actor("human", "casey")
    start = start_experience(human, CLOCK)
    with pytest.raises(ExperienceError, match="reports failure"):
        advance(start, "CONFIRM", human, CLOCK, [_row(True), _row(False)])
    _store_with(tmp_path, _admitted_by_hand(start, [_row(True), _row(False)]))
    with pytest.raises(ReceiptError, match="last brd_requirements row"):
        _export(tmp_path)
    # The receipt an any-pass checker would have exported and anchored.
    monkeypatch.setattr(receipt_module, "walk_problems", lambda *args: [])
    masked = _export(tmp_path)
    monkeypatch.undo()
    for verdict in (verify_receipt(masked),
                    _verify_live(tmp_path, masked,
                                 expect_sha256=masked["integrity"]["body_sha256"])):
        assert not verdict.consistent and not verdict.verified, verdict
        assert any("last brd_requirements row" in p for p in verdict.problems), verdict.problems
    assert _verify_live(tmp_path, masked).live_comparison == "refused"


def test_a_failing_row_replaced_by_a_passing_one_is_admitted_as_advance_admits_it(
        tmp_path: Path):
    human = Actor("human", "casey")
    admitted = advance(start_experience(human, CLOCK), "CONFIRM", human, CLOCK,
                       [_row(False), _row(True)])
    _store_with(tmp_path, admitted)
    receipt = _export(tmp_path)
    assert [item["passed"] for item in receipt["body"]["evidence"]] == [False, True]
    assert _verify_live(tmp_path, receipt).verified
    assert verify_receipt(receipt, expect_sha256=receipt["integrity"]["body_sha256"]).verified


def test_every_admission_into_a_re_entered_stage_needs_its_own_passing_row(tmp_path: Path):
    """CONFIRM -> CONFIRM keeps every admission's rows in one list. Each
    admission's last row is a distinct passed row, so two admissions with one
    passed row between them cannot both have been licensed."""
    human = Actor("human", "casey")
    once = advance(start_experience(human, CLOCK), "CONFIRM", human, CLOCK,
                   [_row(False), _row(True)])
    twice = advance(once, "CONFIRM", human, CLOCK, [_row(True)])
    _store_with(tmp_path, twice)
    receipt = _export(tmp_path)
    assert [item["passed"] for item in receipt["body"]["evidence"]] == [False, True, True]
    assert _verify_live(tmp_path, receipt).verified
    forged = copy.deepcopy(receipt)
    forged["body"]["evidence"][1]["passed"] = False
    verdict = verify_receipt(reseal(forged))
    assert not verdict.consistent
    assert [p for p in verdict.problems if "admissions" in p] == list(verdict.problems) != []
