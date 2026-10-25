"""The Produced Application Manifest in the store, in the build, and at the
"Open application" handoff gate (A-051).

WHAT WOULD FALSIFY IT:
  * a protected store from before the manifest became TAMPERED, or a seal of
    another shape read as trusted;
  * a manifest that reaches the store by any path but Forge's one commit with
    the accepted transition, or one whose sealed bytes are not the bytes Forge
    rendered;
  * an accepted build issued a manifest whose subject is not the verifier's,
    whose BRD is not the bound one, or whose application has no entry point,
    a third-party import or an import of Forge;
  * the handoff gate offering "Open application" for a store that is not
    sealed, a manifest that is not the sealed one, a produced file changed,
    added or removed since, a build whose provider the Provider Contract does
    not make eligible -- or for any simulated build at all;
  * produced code executed, or a produced file read by reopening its path;
  * READY changed, or a shipped path depending on the test-only reference app.

THE REFERENCE APPLICATION is Forge's own support-case specimen, written by a
test-only simulated provider from templates under
`tests/specimens/produced_app/*.py.txt`, which pytest does not collect and no
shipped path reads. It exercises the mechanism; it is not a provider build and
not a runnable Forge-generated application, and nothing here executes it.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from session_client import authed_client
from test_build_trigger import _client as _trigger_client
from test_build_trigger import _project as _confirmed_project
from test_build_trigger import _wait_finished
from test_simulated_journey import PROVIDER, SIMULATED_COMMAND, SIMULATED_OUTPUT, _walk

from nornyx_forge import capsule_store as store_module
from nornyx_forge import experience, gates, greenfield_verifier, onboarding_app
from nornyx_forge.capsule import Actor, CapsuleValidationError, canonical_json, create_document
from nornyx_forge.capsule_store import (
    CapsuleSealError,
    CapsuleSealUnreadable,
    CapsuleStore,
    CapsuleStoreError,
)
from nornyx_forge.experience import fail, start_experience
from nornyx_forge.experience_journey import SYSTEM_ACTOR
from nornyx_forge.models import WorkerResult
from nornyx_forge.provider_contract import GovernedEligibility, governed_build_eligibility
from nornyx_forge.requirements import parse_brd

try:
    from nornyx_forge import produced_app_handoff as handoff
    from nornyx_forge import produced_app_manifest as pam
except ImportError as missing:  # red first: on a parent without the modules
    _ABSENT = str(missing)

    class _Missing:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"the manifest modules do not exist here: {_ABSENT}")

    handoff = pam = _Missing()  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
SPECIMEN = ROOT / "tests" / "specimens" / "produced_app"
AT = "2026-10-23T09:00:00Z"
CASEY = Actor("human", "casey")
PLATFORM = onboarding_app.served_platform()


# ---------------------------------------------------------------------------
# The reference application and the test-only provider that writes it
# ---------------------------------------------------------------------------

def reference_application(requirements: dict[str, str], defect: str | None = None) -> dict[str, str]:
    """The reference application's files, rendered from the specimen templates.

    `requirements` maps each BRD requirement id to its statement; each gets a
    test that names it, so the trusted verifier's traceability gate holds.
    `defect="forge-import"` plants `import nornyx_forge` in the application;
    `defect="no-entry-point"` writes no `app/__main__.py`.
    """
    files: dict[str, str] = {}
    for template in sorted(SPECIMEN.rglob("*.py.txt")):
        relative = template.relative_to(SPECIMEN).as_posix()[: -len(".txt")]
        files[relative] = template.read_text(encoding="utf-8")
    files["app/cases.py"] = files["app/cases.py"].replace("__REQUIREMENTS__", repr(requirements))
    files["tests/test_cases.py"] = files["tests/test_cases.py"].replace(
        "__REQUIREMENT_TESTS__", "".join(
            f"\n\ndef test_{ident.lower().replace('-', '_')}():\n"
            f"    # {ident}\n"
            f"    assert requirement({ident!r}) == {text!r}\n"
            for ident, text in requirements.items()))
    if defect == "forge-import":
        files["app/cases.py"] = files["app/cases.py"].replace(
            "from __future__ import annotations\n",
            "from __future__ import annotations\n\nimport nornyx_forge  # noqa: F401\n", 1)
    elif defect == "no-entry-point":
        del files["app/__main__.py"]
        tests = files["tests/test_cases.py"].replace("from app.__main__ import main\n", "")
        files["tests/test_cases.py"] = tests.replace(
            '\n\ndef test_the_self_test_passes():\n    assert main(["--self-test"]) == 0\n', "\n")
        assert "main" not in files["tests/test_cases.py"].replace("domain", "")
    return files


class ReferenceProvider:
    """A simulated provider with the flow's worker surface, writing the
    reference application on the builder's implementation goal and nothing
    on any other call. It never touches the capsule store, and every result
    says no live provider executed."""

    def __init__(self, defect: str | None = None) -> None:
        self.defect = defect
        self.written: dict[str, str] = {}

    def run(self, *, role: str, goal: str, workspace: Path, allowed_tools: tuple[str, ...],
            max_turns: int, timeout_seconds: int) -> WorkerResult:
        if role == "application-builder" and goal.startswith("Implement"):
            model = parse_brd(Path(workspace) / "BRD.md")
            self.written = reference_application(
                {item.id: item.statement for item in model.requirements}, self.defect)
            for relative, text in self.written.items():
                target = Path(workspace) / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8", newline="")
        return WorkerResult(role=role, goal=goal, success=True, output=SIMULATED_OUTPUT,
                            command=(SIMULATED_COMMAND, role))


def _injected(eligible: bool):
    """A UNIT-LEVEL verdict for the gate's logic. No production path takes it:
    `open_application_readiness` passes the Provider Contract's own."""
    def verdict(provider: str, platform: str) -> GovernedEligibility:
        return GovernedEligibility(provider=provider, platform=platform, eligible=eligible,
                                   confinement="injected", reason="a unit test's verdict")
    return verdict


# ---------------------------------------------------------------------------
# A sealed store carrying a manifest over a real project, built directly
# ---------------------------------------------------------------------------

def _handed_off(base: Path, *, eligible_row: bool = True,
                cases_suffix: str = "",
                provenance: dict | None = None) -> tuple[CapsuleStore, Path, str]:
    """A project holding the reference application and a sealed store whose
    manifest lists it. The manifest is rendered by the domain's own renderer;
    `eligible_row` is the row it records, which only a unit test may set, and
    `cases_suffix` is appended to `app/cases.py` before the manifest lists it."""
    project = base / "project"
    application = reference_application({"BRD-001": "Track support cases."})
    application["app/cases.py"] += cases_suffix
    for relative, text in application.items():
        (project / relative).parent.mkdir(parents=True, exist_ok=True)
        (project / relative).write_text(text, encoding="utf-8", newline="")
    (project / "BRD.md").write_text("# BRD\n\n## BRD-001 Cases\n\nTrack support cases.\n",
                                    encoding="utf-8", newline="")
    store = CapsuleStore(project / "capsule", seal_dir=base / "seals")
    document = create_document("proj-1", "Portal", CASEY, AT)
    store.initialize(document, experience=start_experience(CASEY, AT))
    files, problems = handoff.read_subject(project)
    assert problems == []
    digests = {path: "sha256:" + hashlib.sha256(data).hexdigest() for path, data in files.items()}
    tip = document["digest_chain"][-1]
    text = pam.render_pam(
        files=digests, accepted_subject_digest=pam.subject_digest(digests),
        store_directory="capsule", generated_contract_digest="sha256:" + "c" * 64,
        brd_scope_binding=f"capsule/{tip}/brd/{'b' * 64}", capsule_chain_tip=tip,
        sealed_revision=store.revision(), provider="codex",
        eligibility={"provider": "codex", "platform": PLATFORM, "eligible": eligible_row,
                     "confinement": "injected", "reason": "a unit test's row"},
        verifier_digest="sha256:" + "e" * 64,
        gate_profile={"id": gates.GREENFIELD_PROFILE_ID, "digest": gates.GREENFIELD_PROFILE_DIGEST},
        forge_version="0.1.0", forge_revision="git:" + "f" * 40,
        runtime_contract_digest="sha256:" + "9" * 64, gate_provenance=provenance,
    )
    state = fail(store.load_experience(), SYSTEM_ACTOR, "a transition to commit beside", AT)
    store.save_produced_application(state, text, "reached GOVERN")
    return store, project, text


def _assess(store: CapsuleStore, project: Path, eligible: bool = True):
    return handoff.assess_readiness(store, project, platform=PLATFORM,
                                    eligibility=_injected(eligible))


# ---------------------------------------------------------------------------
# The seal: version 2, and version 1 still read
# ---------------------------------------------------------------------------

def _store(base: Path) -> CapsuleStore:
    store = CapsuleStore(base / "capsule", seal_dir=base / "seals")
    store.initialize(create_document("proj-1", "Portal", CASEY, AT),
                     experience=start_experience(CASEY, AT))
    return store


def _as_v1(store: CapsuleStore) -> dict[str, Any]:
    """Rewrite the store's seal exactly as Forge wrote seals before the
    manifest existed: schema v1, the two files, no `pam` reference."""
    record = json.loads(store.seal_path().read_text(encoding="utf-8"))
    old = {"schema": "nornyx.forge.capsule_seal.v1", "store": record["store"],
           "revision": record["revision"],
           "files": {name: record["files"][name] for name in ("capsule.json", "experience.json")}}
    store.seal_path().write_text(canonical_json(old) + "\n", encoding="utf-8", newline="")
    return old


def test_every_seal_is_version_2_and_names_the_manifest_or_its_absence(tmp_path: Path):
    store = _store(tmp_path)
    record = json.loads(store.seal_path().read_text(encoding="utf-8"))
    assert record["schema"] == "nornyx.forge.capsule_seal.v2"
    assert set(record["files"]) == {"capsule.json", "experience.json", "pam.json"}
    assert record["files"]["pam.json"] is None and record["pam"] is None
    assert store.sealed().files["pam.json"] is None


def test_a_version_1_seal_still_anchors_its_store_and_is_rewritten_by_the_next_commit(
        tmp_path: Path):
    """No existing protected store becomes TAMPERED: a v1 seal with exactly its
    two files reads as sealing no manifest, every route answers, and the next
    commit Forge makes rewrites it as v2."""
    store = _store(tmp_path)
    _as_v1(store)
    assert store.sealed().files == {**{name: (store.root / name).read_text(encoding="utf-8")
                                       for name in ("capsule.json", "experience.json")},
                                    "pam.json": None}
    store.assert_sealed()
    assert store.load()["project_id"] == "proj-1"
    assert store.load_experience()["stage"] == "DISCOVER"
    app = onboarding_app.create_app(store.root, ROOT / ".nornyx" / "contracts",
                                    seal_dir=tmp_path / "seals")
    state = authed_client(app).get("/api/state")
    assert state.status_code == 200, state.text
    assert state.json()["authority"]["anchor"] == "sealed"
    store.save_experience(fail(store.load_experience(), SYSTEM_ACTOR, "next commit", AT), "next")
    assert json.loads(store.seal_path().read_text(encoding="utf-8"))["schema"] == (
        "nornyx.forge.capsule_seal.v2")
    # And a manifest planted beside a v1 seal is a breach, not a manifest.
    _as_v1(store)
    (store.root / "pam.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(CapsuleSealError, match="pam.json differs from the sealed bytes"):
        store.assert_sealed()


@pytest.mark.parametrize("label", [
    "v1 naming the manifest", "v1 naming one file", "v1 with a pam field",
    "v2 with two files", "v2 whose reference disagrees", "v2 with no reference field",
    "v2 whose manifest is not text",
])
def test_a_seal_of_any_other_shape_is_not_one_this_adapter_wrote(tmp_path: Path, label: str):
    store = _store(tmp_path)
    v2 = json.loads(store.seal_path().read_text(encoding="utf-8"))
    v1 = _as_v1(store)
    damaged = {
        "v1 naming the manifest": {**v1, "files": {**v1["files"], "pam.json": None}},
        "v1 naming one file": {**v1, "files": {"capsule.json": v1["files"]["capsule.json"]}},
        "v1 with a pam field": {**v1, "pam": None},
        "v2 with two files": {**v2, "files": v1["files"]},
        "v2 whose reference disagrees": {**v2, "pam": "pam/" + "0" * 64},
        "v2 with no reference field": {k: v for k, v in v2.items() if k != "pam"},
        "v2 whose manifest is not text": {**v2, "files": {**v2["files"], "pam.json": 7}},
    }[label]
    store.seal_path().write_text(canonical_json(damaged) + "\n", encoding="utf-8", newline="")
    with pytest.raises(CapsuleSealUnreadable):
        store.load()


# ---------------------------------------------------------------------------
# Forge-only writing, in one commit, held to the rendered bytes
# ---------------------------------------------------------------------------

def test_the_manifest_is_committed_with_the_transition_and_sealed_outside_the_project(
        tmp_path: Path):
    store, project, text = _handed_off(tmp_path)
    changed = subprocess.run(["git", "show", "--name-only", "--format=", "HEAD"],
                             cwd=store.root, capture_output=True, text=True, check=True)
    assert sorted(changed.stdout.split()) == ["experience.json", "pam.json"]
    assert (store.root / "pam.json").read_text(encoding="utf-8") == text
    record = json.loads(store.seal_path().read_text(encoding="utf-8"))
    assert record["files"]["pam.json"] == text
    assert record["pam"] == pam.pam_reference(text)
    assert not store.seal_path().resolve().is_relative_to(project.resolve())
    store.assert_sealed()


def test_a_manifest_that_does_not_validate_is_never_written(tmp_path: Path):
    store = _store(tmp_path)
    state = fail(store.load_experience(), SYSTEM_ACTOR, "x", AT)
    for bad in ("{}\n", "not json"):
        with pytest.raises(CapsuleValidationError):
            store.save_produced_application(state, bad, "reached GOVERN")
    assert not (store.root / "pam.json").exists()
    _, _, valid = _handed_off(tmp_path / "specimen")
    unsealed = CapsuleStore(tmp_path / "unsealed")
    with pytest.raises(CapsuleStoreError, match="sealed store"):
        unsealed.save_produced_application(state, valid, "x")


def _lingering_writer(monkeypatch: pytest.MonkeyPatch, name: str, payload: str) -> list[str]:
    """Between Forge's commit and its seal, replace one file -- what a process
    left running in the workspace can do. Fires once."""
    fired: list[str] = []
    real = CapsuleStore.seal

    def seal(self: CapsuleStore):
        if not fired and (self.root / "pam.json").exists():
            fired.append(name)
            (self.root / name).write_text(payload, encoding="utf-8", newline="")
        return real(self)

    monkeypatch.setattr(CapsuleStore, "seal", seal)
    return fired


@pytest.mark.parametrize("name", ["pam.json", "experience.json"])
def test_bytes_sealed_in_place_of_the_rendered_ones_are_refused_and_restorable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str):
    store = _store(tmp_path)
    before = store.sealed()
    _, _, text = _handed_off(tmp_path / "specimen")
    fired = _lingering_writer(monkeypatch, name, text.replace("0.1.0", "6.6.6"))
    state = fail(store.load_experience(), SYSTEM_ACTOR, "x", AT)
    with pytest.raises(CapsuleSealError) as raised:
        store.save_produced_application(state, text, "reached GOVERN")
    assert fired == [name]
    assert raised.value.problems == [f"the sealed {name} is not the one Forge rendered"]
    assert raised.value.snapshot == before
    store.restore(raised.value.snapshot)
    assert not (store.root / "pam.json").exists()
    assert store.seal_problems(store.sealed()) == []
    assert store.sealed().files["pam.json"] is None


def test_the_build_thread_records_a_failure_when_what_was_sealed_is_not_what_was_rendered(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Through the shipped build route: an accepted build whose manifest is
    swapped between Forge's commit and its seal is not recorded at GOVERN; the
    commit is removed with the seal it followed and the run says why."""
    _, _, text = _handed_off(tmp_path / "specimen")

    class Accepted:
        def __init__(self, root, **kwargs):
            pass

        def run(self):
            return {"accepted": True, "execution_backend": "sequential",
                    "gates": [{"name": "greenfield:all", "passed": True}]}

    monkeypatch.setattr(onboarding_app, "issue_manifest",
                        lambda **_: handoff.ManifestIssue(text, ()))
    project = _confirmed_project(tmp_path / "build")
    fired = _lingering_writer(monkeypatch, "pam.json", text.replace("0.1.0", "6.6.6"))
    client = _trigger_client(project, factory=Accepted)
    assert client.post("/api/build", json={"actor": {"kind": "human", "ident": "casey"}}
                       ).status_code == 200
    status = _wait_finished(client)
    assert fired == ["pam.json"]
    assert status["lifecycle"] == {"recorded": True, "stage": "TEST", "status": "failed",
                                   "authority": "restored from seal"}
    assert status["produced_application"] == {
        "manifest": None, "findings": ["the sealed pam.json is not the one Forge rendered"]}
    store = CapsuleStore(project / "capsule", seal_dir=project / "seals")
    assert not (store.root / "pam.json").exists()
    assert store.seal_problems(store.sealed()) == []


def test_an_issuance_that_raises_never_keeps_the_build_from_being_recorded(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    class Accepted:
        def __init__(self, root, **kwargs):
            pass

        def run(self):
            return {"accepted": True, "execution_backend": "sequential",
                    "gates": [{"name": "greenfield:all", "passed": True}]}

    def broken(**_: Any):
        raise RuntimeError("an unforeseen read failure")

    monkeypatch.setattr(onboarding_app, "issue_manifest", broken)
    project = _confirmed_project(tmp_path)
    client = _trigger_client(project, factory=Accepted)
    assert client.post("/api/build", json={"actor": {"kind": "human", "ident": "casey"}}
                       ).status_code == 200
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert status["produced_application"] == {"manifest": None, "findings": [
        "Forge could not issue the manifest: RuntimeError: an unforeseen read failure"]}
    assert not (project / "capsule" / "pam.json").exists()


# ---------------------------------------------------------------------------
# Issuance over a real accepted build: the reference journey
# ---------------------------------------------------------------------------

def test_an_accepted_build_of_the_reference_application_is_issued_a_sealed_manifest(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Identity, on the mechanism: the shipped composition, the real flow and the
    real trusted verifier over the reference application written by the
    test-only provider. The manifest is in the store, in the GOVERN commit and
    in the seal; its subject digest is the one the verifier accepted; every
    listed file's digest is the file's; its eligibility row is the Provider
    Contract's own -- not the verdict the test handed the build route -- so
    the gate never offers this simulated build. READY is unchanged."""
    provider = ReferenceProvider()
    run = _walk(monkeypatch, tmp_path, provider)
    status, project = run.status, run.project
    assert status["status"] == "finished" and status["accepted"] is True, status
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    store = run.store()
    text = (store.root / "pam.json").read_text(encoding="utf-8")
    assert status["produced_application"] == {"manifest": pam.pam_reference(text), "findings": []}
    assert store.sealed().files["pam.json"] == text
    manifest = pam.validate_pam(text)

    # The verifier's accepted subject, and every listed file as it is on disk.
    accepted = status["result"]["acceptance_provenance"]["subject"]
    assert manifest["subject"]["digest"] == accepted["digest"]
    assert manifest["subject"]["file_count"] == accepted["file_count"]
    for path in manifest["application"]["files"]:
        assert manifest["subject"]["files"][path] == "sha256:" + hashlib.sha256(
            (project / path).read_bytes()).hexdigest(), path
    assert set(provider.written) <= set(manifest["application"]["files"])
    assert "BRD.md" in manifest["application"]["files"]
    assert not any(path.startswith("capsule/") for path in manifest["application"]["files"])

    # Provenance from Forge's own records.
    verifier = status["result"]["acceptance_provenance"]["verifier"]
    assert manifest["verifier"] == {
        "id": gates.GREENFIELD_VERIFIER_ID, "digest": verifier["digest"],
        "gate_profile": {"id": gates.GREENFIELD_PROFILE_ID,
                         "digest": gates.GREENFIELD_PROFILE_DIGEST}}
    assert manifest["forge"] == {"version": verifier["forge_version"],
                                 "revision": verifier["forge_revision"]}
    document = store.load()
    assert manifest["capsule"]["chain_tip"] == document["digest_chain"][-1]
    brd_text = (project / "BRD.md").read_text(encoding="utf-8")
    assert manifest["brd"]["scope_binding"] == (
        f"capsule/{document['digest_chain'][-1]}/brd/"
        f"{hashlib.sha256(brd_text.encode('utf-8')).hexdigest()}")
    contract = project / ".nornyx" / "generated" / "brd_contract.nyx"
    assert manifest["generated_contract"]["digest"] == "sha256:" + hashlib.sha256(
        contract.read_bytes()).hexdigest()
    assert manifest["provider"] == {
        "name": PROVIDER, "eligibility": governed_build_eligibility(PROVIDER, PLATFORM).as_dict()}
    assert manifest["provider"]["eligibility"]["eligible"] is False

    # One commit with the GOVERN transition; the flow wrote no manifest.
    changed = subprocess.run(["git", "show", "--name-only", "--format=%s", "HEAD"],
                             cwd=store.root, capture_output=True, text=True, check=True)
    assert changed.stdout.split() == ["experience:", "reached", "GOVERN",
                                      "experience.json", "pam.json"]
    assert [path for path in project.rglob("pam.json")] == [store.root / "pam.json"]

    # READY is unchanged by the manifest: the contract's requirement, and the
    # manifest is not READY evidence. Since A-049 the greenfield profile runs
    # the real `nornyx check` on the contract this build generated, so the
    # build records a governance validation from that gate and the human may
    # mark READY. Marking it moves nothing the handoff gate reads: the sealed
    # manifest is the one issued at GOVERN, and the gate below, asked after
    # READY, still never offers this simulated build.
    assert experience.STAGE_EVIDENCE["READY"] == ("gate_results", "governance_validation")
    assert "produced_app" not in experience.EVIDENCE_KINDS
    governance = [gate for gate in status["result"]["gates"]
                  if gate["name"] == "greenfield:nornyx-contract-check"]
    assert [gate["passed"] for gate in governance] == [True], governance
    ready = run.client.post("/api/journey/ready", json={"actor": {"kind": "human", "ident": "casey"}})
    assert ready.status_code == 200, ready.text
    assert ready.json() == {"stage": "READY", "status": "active"}
    assert (store.root / "pam.json").read_text(encoding="utf-8") == text
    assert store.sealed().files["pam.json"] == text

    # The handoff gate: never offered for this simulated build, READY or not.
    production = handoff.open_application_readiness(store, project, PLATFORM)
    assert production.offered is False and production.manifest == pam.pam_reference(text)
    assert any("was not eligible when the manifest was issued" in r for r in production.reasons)
    assert any("is not eligible for the governed build" in r for r in production.reasons)
    injected = _assess(store, project, eligible=True)
    assert injected.offered is False
    assert [r for r in injected.reasons if "eligible" in r] == [
        r for r in production.reasons if "was not eligible when the manifest was issued" in r]
    assert not any("changed" in r or "missing" in r or "not listed" in r for r in injected.reasons)


@pytest.mark.parametrize("defect, finding", [
    ("forge-import", "imports nornyx_forge; a produced application must not depend on Forge"),
    ("no-entry-point", "the entry point app/__main__.py is missing"),
])
def test_an_accepted_build_the_static_check_refuses_is_issued_no_manifest(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str, finding: str):
    """An import of Forge, and no entry point, through the real build: the trusted
    verifier accepts the application -- an import of Forge resolves in its
    test environment, and its profile asks for no entry point -- and the
    static check refuses it, so no manifest is issued and the build is
    recorded exactly as before."""
    run = _walk(monkeypatch, tmp_path, ReferenceProvider(defect))
    status = run.status
    assert status["status"] == "finished" and status["accepted"] is True, status
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert status["produced_application"]["manifest"] is None
    assert any(finding in item for item in status["produced_application"]["findings"]), status
    store = run.store()
    assert not (store.root / "pam.json").exists() and store.sealed().files["pam.json"] is None
    readiness = handoff.open_application_readiness(store, run.project, PLATFORM)
    assert readiness.offered is False and readiness.reasons == (
        "no produced-application manifest is sealed for this project",)


# ---------------------------------------------------------------------------
# Issuance's own refusals, at the unit level
# ---------------------------------------------------------------------------

def _issue_inputs(base: Path, **change: Any) -> dict[str, Any]:
    """A project and the records issuance takes. The verifier record is
    FABRICATED for this unit test, shaped as `trusted_greenfield_gates`
    returns it, with the subject digest of the files on disk."""
    store, project, _ = _handed_off(base)
    document = store.load()
    (store.root / "pam.json").unlink()  # the store's own state is not under test here
    files, _ = handoff.read_subject(project)
    digests = {p: "sha256:" + hashlib.sha256(d).hexdigest() for p, d in files.items()}
    tip = document["digest_chain"][-1]
    brd = hashlib.sha256((project / "BRD.md").read_text(encoding="utf-8").encode()).hexdigest()
    record = {
        "schema": "nornyx.forge.verifier_provenance.v1", "trust": "structural-origin-and-digest",
        "gate_profile": {"id": gates.GREENFIELD_PROFILE_ID, "digest": gates.GREENFIELD_PROFILE_DIGEST},
        "verifier": {"id": gates.GREENFIELD_VERIFIER_ID, "digest": "sha256:" + "e" * 64,
                     "forge_version": "0.1.0", "forge_revision": "git:" + "f" * 40},
        "subject": {"root": str(project.resolve()), "digest": pam.subject_digest(digests),
                    "file_count": len(digests)},
    }
    inputs = {
        "project_root": project, "store_root": store.root,
        "result": {"accepted": True, "acceptance_provenance": record},
        "document": {**document, "authoritative": {**document["authoritative"],
                                                   "provider": {"name": "codex"}}},
        "lifecycle": {"evidence": {"BUILD": [{"kind": "brd_requirements", "passed": True,
                                              "ref": f"capsule/{tip}/brd/{brd}"}]}},
        "sealed_revision": store.revision(), "platform": PLATFORM,
    }
    inputs.update(change)
    return inputs


def test_issuance_renders_from_forges_records_and_the_contracts_row(tmp_path: Path):
    issued = handoff.issue_manifest(**_issue_inputs(tmp_path))
    assert issued.findings == () and issued.text is not None
    manifest = pam.validate_pam(issued.text)
    assert manifest["provider"]["eligibility"] == governed_build_eligibility(
        "codex", PLATFORM).as_dict()
    assert issued.as_dict() == {"manifest": pam.pam_reference(issued.text), "findings": []}


def test_issuance_refuses_what_its_records_do_not_support(tmp_path: Path):
    inputs = _issue_inputs(tmp_path)
    record = inputs["result"]["acceptance_provenance"]
    project = inputs["project_root"]
    cases = {
        "not accepted": {"result": {**inputs["result"], "accepted": False}},
        "no verifier record": {"result": {"accepted": True}},
        "another trust": {"result": {"accepted": True, "acceptance_provenance": {
            **record, "trust": "not_established"}}},
        "another profile": {"result": {"accepted": True, "acceptance_provenance": {
            **record, "gate_profile": {"id": "x", "digest": "y"}}}},
        "another project": {"result": {"accepted": True, "acceptance_provenance": {
            **record, "subject": {**record["subject"], "root": "/elsewhere"}}}},
        "a bool file count": {"result": {"accepted": True, "acceptance_provenance": {
            **record, "subject": {**record["subject"], "file_count": True}}}},
        "another BRD bound": {"lifecycle": {"evidence": {"BUILD": [{
            "kind": "brd_requirements", "passed": True,
            "ref": f"capsule/{inputs['document']['digest_chain'][-1]}/brd/{'0' * 64}"}]}}},
        "no binding": {"lifecycle": {"evidence": {}}},
        "no provider": {"document": {**inputs["document"], "authoritative": {}}},
    }
    expected = {
        "not accepted": "the build was not accepted",
        "no verifier record": "carries no trusted verifier record",
        "another trust": "not a trusted structural record",
        "another profile": "another gate profile",
        "another project": "does not describe this project's subject",
        "a bool file count": "does not describe this project's subject",
        "another BRD bound": "is not the BRD the scope confirmation bound",
        "no binding": "records no scope binding",
        "no provider": "names no confirmed provider",
    }
    for label, change in cases.items():
        issued = handoff.issue_manifest(**{**inputs, **change})
        assert issued.text is None and any(expected[label] in f for f in issued.findings), (
            label, issued.findings)
    # A file changed after verification: Forge's read is not the accepted subject.
    (project / "app" / "cases.py").write_text("X = 2\n", encoding="utf-8")
    changed = handoff.issue_manifest(**inputs)
    assert changed.text is None and "something changed them after verification" in changed.findings[0]


def test_a_third_party_import_is_refused_at_issue(tmp_path: Path):
    """A third-party import: the verifier record here names the changed subject,
    so the refusal measured is the import's and not a digest mismatch."""
    inputs = _issue_inputs(tmp_path)
    path = inputs["project_root"] / "app" / "cases.py"
    path.write_text("import requests\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
    files, _ = handoff.read_subject(inputs["project_root"])
    digests = {p: "sha256:" + hashlib.sha256(d).hexdigest() for p, d in files.items()}
    record = inputs["result"]["acceptance_provenance"]
    record["subject"] = {**record["subject"], "digest": pam.subject_digest(digests)}
    issued = handoff.issue_manifest(**inputs)
    assert issued.text is None
    assert issued.findings == ("app/cases.py:1 imports requests, which is neither the Python "
                               "standard library nor the application's own module",)


#: A reference to a dynamic primitive the alias tracking did not follow (Codex
#: P2 4361814368): an annotated binding, used, then rebound to something
#: harmless.
ANNOTATED_PRIMITIVE = "\nimp: object = __import__\nimp('json')\nimp = len\n"


def test_issuance_refuses_a_dynamic_primitive_however_it_is_bound(tmp_path: Path):
    inputs = _issue_inputs(tmp_path)
    path = inputs["project_root"] / "app" / "cases.py"
    path.write_text(path.read_text(encoding="utf-8") + ANNOTATED_PRIMITIVE, encoding="utf-8")
    files, _ = handoff.read_subject(inputs["project_root"])
    digests = {p: "sha256:" + hashlib.sha256(d).hexdigest() for p, d in files.items()}
    record = inputs["result"]["acceptance_provenance"]
    record["subject"] = {**record["subject"], "digest": pam.subject_digest(digests)}
    issued = handoff.issue_manifest(**inputs)
    assert issued.text is None and issued.findings, issued
    assert all("dynamic import or execution primitive" in f for f in issued.findings), issued


# ---------------------------------------------------------------------------
# The handoff gate
# ---------------------------------------------------------------------------

def test_the_gate_refuses_a_dynamic_primitive_however_it_is_bound(tmp_path: Path):
    """The gate re-runs the static check on what it reads, so a manifest whose
    listed files carry a primitive the issuer's check would now refuse is not
    offered -- and the files are exactly the listed ones, so the refusal is the
    primitive's and not a changed file's."""
    store, project, _ = _handed_off(tmp_path, cases_suffix=ANNOTATED_PRIMITIVE)
    readiness = _assess(store, project)
    assert readiness.offered is False and readiness.reasons, readiness
    assert all("dynamic import or execution primitive" in r for r in readiness.reasons), readiness

def test_the_gate_offers_only_a_sealed_manifest_whose_files_and_provider_still_hold(
        tmp_path: Path):
    """The positive path exists only at the unit level, with a row and a
    verdict the test supplies. Production never reaches it today."""
    store, project, text = _handed_off(tmp_path)
    assert _assess(store, project) == handoff.Readiness(True, (), pam.pam_reference(text))
    production = handoff.open_application_readiness(store, project, PLATFORM)
    assert production.offered is False
    assert production.reasons == (
        f"the build's provider codex is not eligible for the governed build: "
        f"{governed_build_eligibility('codex', PLATFORM).reason[:200]}",)
    assert _assess(store, project, eligible=False).offered is False


def test_a_row_for_one_platform_and_a_verdict_about_another_offer_nothing(tmp_path: Path):
    store, project, _ = _handed_off(tmp_path)
    elsewhere = handoff.assess_readiness(store, project, platform="another-platform",
                                         eligibility=_injected(True))
    assert elsewhere.offered is False and elsewhere.reasons == (
        f"the manifest was issued for platform {PLATFORM}, not another-platform; an "
        "eligibility row for one platform says nothing about another",)

    def other_provider(provider: str, platform: str) -> GovernedEligibility:
        return GovernedEligibility(provider="claude", platform=platform, eligible=True,
                                   confinement="injected", reason="about another provider")

    mismatched = handoff.assess_readiness(store, project, platform=PLATFORM,
                                          eligibility=other_provider)
    assert mismatched.offered is False


def test_a_simulated_build_is_never_offered_whatever_verdict_the_gate_is_given(tmp_path: Path):
    store, project, _ = _handed_off(tmp_path, eligible_row=False)
    readiness = _assess(store, project, eligible=True)
    assert readiness.offered is False
    assert len(readiness.reasons) == 1 and "was not eligible when the manifest was issued" in (
        readiness.reasons[0])


@pytest.mark.parametrize("change, reason", [
    ("edit", "app/cases.py has changed since the manifest was issued"),
    ("remove", "app/cases.py is listed in the manifest and is missing"),
    ("add", "app/extra.py is not listed in the manifest"),
    ("brd", "BRD.md has changed since the manifest was issued"),
])
def test_a_produced_file_changed_since_the_manifest_is_named(tmp_path: Path, change: str,
                                                           reason: str):
    store, project, _ = _handed_off(tmp_path)
    if change == "edit":
        (project / "app" / "cases.py").write_text("X = 1\n", encoding="utf-8")
    elif change == "remove":
        (project / "app" / "cases.py").unlink()
    elif change == "add":
        (project / "app" / "extra.py").write_text("X = 1\n", encoding="utf-8")
    else:
        (project / "BRD.md").write_text("# another\n", encoding="utf-8")
    readiness = _assess(store, project)
    assert readiness.offered is False and reason in readiness.reasons, readiness.reasons


def test_the_gate_reads_the_manifest_only_from_a_store_that_matches_its_seal(tmp_path: Path):
    store, project, text = _handed_off(tmp_path)
    (store.root / "pam.json").write_text(text.replace("0.1.0", "6.6.6"), encoding="utf-8",
                                         newline="")
    readiness = _assess(store, project)
    assert readiness.offered is False and readiness.manifest is None
    assert readiness.reasons[0].startswith("the authority store is not trusted")
    assert "pam.json differs from the sealed bytes" in readiness.reasons[0]


def test_the_legacy_fall_open_licenses_no_handoff(tmp_path: Path):
    """The `_rebuild` table's new rows: with the seal gone, a readable manifest
    licenses nothing, whether or not the marker is still there."""
    store, project, _ = _handed_off(tmp_path)
    store.seal_path().unlink()
    missing = _assess(store, project)
    assert missing.offered is False and "seal is missing" in missing.reasons[0]
    (store.root / ".forge-seal").unlink()
    assert store.protected() is False and (store.root / "pam.json").exists()
    legacy = _assess(store, project)
    assert legacy.offered is False and legacy.reasons == (
        "the store carries no seal; a manifest is read only from a store Forge has sealed",)


def test_the_neutralisation_takes_the_manifest_with_the_other_authority(tmp_path: Path):
    """The rebuild route, with the repository gone: the manifest is put back
    from the seal exactly, and a forged one at its name does not survive."""
    store, project, text = _handed_off(tmp_path)
    sealed = store.sealed()
    store_module._remove_tree(store.root / ".git")
    (store.root / "pam.json").write_text('{"forged": true}\n', encoding="utf-8")
    store.restore(sealed)
    assert (store.root / "pam.json").read_text(encoding="utf-8") == text
    assert _assess(store, project).offered is True


# ---------------------------------------------------------------------------
# Unreadable authority and seal bytes fail closed (Codex P1 4362912628 and
# its class): every shape is a seal problem or a refusal, never an exception
# ---------------------------------------------------------------------------

SHAPES = ("invalid UTF-8", "UTF-8 BOM", "UTF-16", "NUL bytes", "truncated JSON",
          "duplicate keys", "huge", "empty", "directory", "link", "vanishes")


def _plant(path: Path, shape: str, monkeypatch: pytest.MonkeyPatch, limit_name: str,
           outside: Path) -> None:
    """Put `shape` where the file at `path` was. `limit_name` is the module
    constant bounding a read of this kind of file, lowered here to just above
    the original's size so a padded copy exceeds it. A link points at a copy
    in `outside`, beyond the project."""
    original = path.read_bytes()
    if shape == "invalid UTF-8":
        path.write_bytes(b"\xff\xfe\xfa" + original)
    elif shape == "UTF-8 BOM":
        path.write_bytes(b"\xef\xbb\xbf" + original)
    elif shape == "UTF-16":
        path.write_bytes(original.decode("utf-8").encode("utf-16"))
    elif shape == "NUL bytes":
        path.write_bytes(original[:-1] + b"\x00\n")
    elif shape == "truncated JSON":
        path.write_bytes(original[: len(original) // 2])
    elif shape == "duplicate keys":
        # The document's first key repeated ahead of the real one: a parser
        # that keeps the last value reads the original document back unchanged.
        first = sorted(json.loads(original))[0]
        path.write_bytes(b'{' + json.dumps(first).encode() + b':null,' + original[1:])
    elif shape == "huge":
        monkeypatch.setattr(store_module, limit_name, len(original) + 8, raising=False)
        path.write_bytes(original + b" " * 64)
    elif shape == "empty":
        path.write_bytes(b"")
    elif shape == "directory":
        path.unlink()
        path.mkdir()
    elif shape == "link":
        outside.mkdir(parents=True, exist_ok=True)
        copy = outside / path.name
        copy.write_bytes(original)
        path.unlink()
        try:
            os.symlink(copy, path)
        except OSError:  # no privilege for a symlink on this host: a directory instead
            path.mkdir()
    elif shape == "vanishes":
        # Removed between the check and the read, wherever the reader checks.
        real_exists, real_open = Path.exists, os.open

        def exists(self: Path, *args: Any, **kwargs: Any) -> bool:
            if self == path and real_exists(self):
                self.unlink()
                return True
            return real_exists(self, *args, **kwargs)

        def opened(target: Any, flags: int, *args: Any) -> int:
            if Path(target) == path and path.exists():
                path.unlink()
            return real_open(target, flags, *args)

        monkeypatch.setattr(Path, "exists", exists)
        monkeypatch.setattr(store_module.os, "open", opened)


@pytest.mark.parametrize("name", ["pam.json", "capsule.json", "experience.json"])
@pytest.mark.parametrize("shape", SHAPES)
def test_an_unreadable_authority_file_is_a_seal_problem_and_restorable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, shape: str):
    """Every shape at every authority file is the ordinary refusal with a
    snapshot to restore from -- never an exception out of the seal check -- and
    the restore puts the sealed bytes back. The handoff gate refuses it too."""
    store, project, _ = _handed_off(tmp_path)
    sealed = store.sealed()
    with monkeypatch.context() as patch:
        _plant(store.root / name, shape, patch, "_AUTHORITY_READ_LIMIT", tmp_path / "outside")
        with pytest.raises(CapsuleSealError) as refused:
            store.load()
        readiness = _assess(store, project)
    assert any(name in problem for problem in refused.value.problems), refused.value.problems
    assert readiness.offered is False and readiness.reasons[0].startswith(
        "the authority store is not trusted"), readiness
    store.restore(sealed)
    assert store.seal_problems(store.sealed()) == []
    assert _assess(store, project).offered is True


@pytest.mark.parametrize("shape", SHAPES)
def test_an_unreadable_seal_record_is_a_tamper_finding(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str):
    """The seal itself, in every shape: not a seal this adapter wrote, refused
    as a finding on every route and at the handoff gate, never an exception."""
    store, project, _ = _handed_off(tmp_path)
    with monkeypatch.context() as patch:
        _plant(store.seal_path(), shape, patch, "_SEAL_READ_LIMIT", tmp_path / "outside")
        with pytest.raises(CapsuleSealUnreadable):
            store.load()
        readiness = _assess(store, project)
    assert readiness.offered is False and readiness.reasons[0].startswith(
        "the authority store is not trusted"), readiness


@pytest.mark.parametrize("shape", SHAPES)
def test_an_unreadable_authority_file_in_an_unsealed_store_is_refused(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str):
    """A store with no seal (a domain store, or one from before sealing): the
    load refuses by the store's own error, never an exception of another kind."""
    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(create_document("proj-1", "Portal", CASEY, AT),
                     experience=start_experience(CASEY, AT))
    for name, load in (("capsule.json", store.load), ("experience.json", store.load_experience)):
        with monkeypatch.context() as patch:
            path = store.root / name
            original = path.read_bytes()
            _plant(path, shape, patch, "_AUTHORITY_READ_LIMIT", tmp_path / "outside")
            with pytest.raises(CapsuleStoreError):
                load()
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
        path.write_bytes(original)


#: A seal record that parses and holds a value of the wrong kind (Codex P2
#: 4363826001 named the first). Each change is applied to the parsed record,
#: which is written back with `\u` escapes, so a surrogate parses back intact.
SEAL_VALUES = {
    "a lone surrogate in the manifest": lambda r: r["files"].update(
        {"pam.json": r["files"]["pam.json"][:-2] + "\ud800}\n"}),
    "a reversed surrogate pair in the manifest": lambda r: r["files"].update(
        {"pam.json": r["files"]["pam.json"][:-2] + "\udc00\ud800}\n"}),
    "a lone surrogate in the sealed capsule": lambda r: r["files"].update(
        {"capsule.json": r["files"]["capsule.json"][:-2] + "\ud800}\n"}),
    "a lone surrogate in the revision": lambda r: r.update(revision="\ud800" * 40),
    "a lone surrogate in the store": lambda r: r.update(store=r["store"] + "\ud800"),
    "a non-hex revision": lambda r: r.update(revision="z" * 40),
    "a short revision": lambda r: r.update(revision="abc"),
    "an empty revision": lambda r: r.update(revision=""),
    "a number as the revision": lambda r: r.update(revision=7),
    "NaN as the revision": lambda r: r.update(revision=float("nan")),
    "a huge integer as the revision": lambda r: r.update(revision=10 ** 400),
    "null as the revision": lambda r: r.update(revision=None),
    "a list as the revision": lambda r: r.update(revision=[]),
    "a number as the store": lambda r: r.update(store=7),
    "an empty store": lambda r: r.update(store=""),
    "a number as a sealed file": lambda r: r["files"].update({"capsule.json": 7}),
    "a list as a sealed file": lambda r: r["files"].update({"capsule.json": []}),
    "an object as a sealed file": lambda r: r["files"].update({"capsule.json": {}}),
    "an empty sealed file": lambda r: r["files"].update({"capsule.json": ""}),
    "a sealed file that is not JSON": lambda r: r["files"].update({"experience.json": "{"}),
    "a sealed file with a repeated key": lambda r: r["files"].update(
        {"experience.json": '{"stage":"x",' + r["files"]["experience.json"][1:]}),
    "a list as the files": lambda r: r.update(files=[]),
    "null as the files": lambda r: r.update(files=None),
    "a number as the manifest reference": lambda r: r.update(pam=7),
    "Infinity as the manifest reference": lambda r: r.update(pam=float("inf")),
    "an empty manifest reference": lambda r: r.update(pam=""),
    "a non-hex manifest reference": lambda r: r.update(pam="pam/" + "z" * 64),
    "an object as the manifest reference": lambda r: r.update(pam={}),
    "a bool as the schema": lambda r: r.update(schema=True),
    "NaN as the schema": lambda r: r.update(schema=float("nan")),
    "an extra key": lambda r: r.update(extra=1),
    "a missing key": lambda r: r.pop("revision"),
    "an extra sealed file": lambda r: r["files"].update({"other.json": None}),
    "a missing sealed file": lambda r: r["files"].pop("experience.json"),
}


@pytest.mark.parametrize("label", sorted(SEAL_VALUES))
def test_a_seal_record_holding_a_value_of_the_wrong_kind_is_refused(tmp_path: Path, label: str):
    """The seal parses and is still not one Forge wrote: `CapsuleSealUnreadable`
    on the load path, and "not offered" at the handoff gate -- never an
    exception of another kind from either."""
    store, project, _ = _handed_off(tmp_path)
    record = json.loads(store.seal_path().read_text(encoding="utf-8"))
    SEAL_VALUES[label](record)
    store.seal_path().write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                                 encoding="utf-8", newline="")
    with pytest.raises(CapsuleSealUnreadable):
        store.load()
    readiness = _assess(store, project)
    assert readiness.offered is False and readiness.reasons[0].startswith(
        "the authority store is not trusted"), readiness


def test_a_store_forge_wrote_with_an_escaped_surrogate_in_its_content_stays_readable(
        tmp_path: Path):
    """The strict value rule is the seal record's and the manifest's, not the
    capsule's: a proposal whose text holds a lone surrogate is accepted by the
    capsule, written escaped, sealed, and read back, so the rule refuses a
    damaged seal without making a store Forge wrote unreadable."""
    from nornyx_forge.capsule import propose

    document = create_document("proj-1", "Portal", CASEY, AT)
    document, _ = propose(document, "intent", "need \ud800", Actor("model", "m"), AT)
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    store.initialize(document, experience=start_experience(CASEY, AT))
    assert store.sealed() is not None
    assert store.load()["proposed"] and store.seal_problems(store.sealed()) == []


def test_a_manifest_holding_unencodable_text_is_not_offered(tmp_path: Path):
    """A manifest sealed consistently -- committed, sealed by Forge's own
    `seal()` -- whose reason field holds a lone surrogate: the gate refuses it
    through the manifest's own validation, never offers it, never raises."""
    store, project, text = _handed_off(tmp_path)
    document = json.loads(text)
    document["provider"]["eligibility"]["reason"] = "ok \ud800"
    damaged = canonical_json(document) + "\n"
    (store.root / "pam.json").write_text(damaged, encoding="utf-8", newline="")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid", "commit",
                    "--quiet", "-am", "damaged"], cwd=store.root, check=True)
    store.seal()
    readiness = _assess(store, project)
    assert readiness.offered is False and readiness.reasons, readiness
    assert readiness.reasons[0].startswith("produced-application manifest:"), readiness


@pytest.mark.parametrize("shape", SHAPES)
def test_bytes_that_cannot_be_sealed_are_refused_and_the_commit_restorable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str):
    """A lingering writer leaves `shape` at pam.json between Forge's commit and
    its seal. Bytes the seal cannot represent are refused as the store's error,
    bytes it can are not the rendered ones; either way the manifest's save
    raises the restorable finding carrying the seal its commit followed."""
    store = _store(tmp_path)
    before = store.sealed()
    _, _, text = _handed_off(tmp_path / "specimen")
    real = CapsuleStore.seal
    fired: list[str] = []
    state = fail(store.load_experience(), SYSTEM_ACTOR, "x", AT)
    with monkeypatch.context() as patch:

        def seal(self: CapsuleStore):
            if not fired and (self.root / "pam.json").exists():
                fired.append(shape)
                _plant(self.root / "pam.json", shape, patch, "_AUTHORITY_READ_LIMIT",
                       tmp_path / "outside")
            return real(self)

        patch.setattr(CapsuleStore, "seal", seal)
        with pytest.raises(CapsuleSealError) as raised:
            store.save_produced_application(state, text, "reached GOVERN")
    assert fired and raised.value.snapshot == before
    assert any("pam.json" in problem for problem in raised.value.problems), raised.value.problems
    store.restore(raised.value.snapshot)
    assert store.seal_problems(store.sealed()) == []
    assert store.sealed().files["pam.json"] is None


# ---------------------------------------------------------------------------
# Reading by held descriptor, and nothing executed
# ---------------------------------------------------------------------------

def test_the_handoff_collects_the_subject_by_the_verifiers_own_rule():
    assert handoff.IGNORED_DIRECTORIES == greenfield_verifier._IGNORED_DIRECTORIES
    assert (handoff.MAX_FILES, handoff.MAX_FILE_BYTES, handoff.MAX_TOTAL_BYTES) == (
        greenfield_verifier._MAX_FILES, greenfield_verifier._MAX_FILE_BYTES,
        greenfield_verifier._MAX_TOTAL_BYTES)


def test_a_file_replaced_between_inspection_and_open_is_refused(tmp_path: Path,
                                                                monkeypatch: pytest.MonkeyPatch):
    """The read judges the DESCRIPTOR: a file renamed into place after `lstat`
    and before `open` is not the one inspected, and its bytes are not used."""
    target, other = tmp_path / "cases.py", tmp_path / "other.py"
    target.write_text("X = 1\n", encoding="utf-8")
    other.write_text("X = 2\n", encoding="utf-8")
    real_open = os.open

    def swapping_open(path, flags, *args):
        if Path(path) == target and other.exists():
            os.replace(other, target)
        return real_open(path, flags, *args)

    monkeypatch.setattr(handoff.os, "open", swapping_open)
    data, reason = handoff.read_held(target)
    assert data is None and reason == (
        "changed while it was inspected: the file opened is not the one inspected")


def test_what_is_not_a_regular_file_is_refused_without_blocking(tmp_path: Path):
    shapes = [tmp_path / "a-directory"]
    shapes[0].mkdir()
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "a-pipe")
        shapes.append(tmp_path / "a-pipe")
    try:
        os.symlink(tmp_path / "a-directory", tmp_path / "a-link")
        shapes.append(tmp_path / "a-link")
    except OSError:  # no privilege to create a symlink on this host
        pass
    for shape in shapes:
        data, reason = handoff.read_held(shape)
        assert data is None and reason == "is not a regular file", (shape, reason)
    big = tmp_path / "big"
    big.write_bytes(b"x" * 11)
    assert handoff.read_held(big, limit=10) == (None, "is larger than 10 bytes")


def test_neither_issuance_nor_the_gate_starts_a_process_on_produced_code(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The only children are the capsule store's own `git`; no interpreter is
    started and no produced module is imported."""
    started: list[list[str]] = []
    real = subprocess.Popen

    class Recording(real):  # type: ignore[misc, valid-type]
        def __init__(self, args, *rest, **kwargs):
            started.append([str(part) for part in (args if isinstance(args, (list, tuple))
                                                   else [args])])
            super().__init__(args, *rest, **kwargs)

    inputs = _issue_inputs(tmp_path / "issue")
    store, project, _ = _handed_off(tmp_path / "gate")
    before = set(sys.modules)
    monkeypatch.setattr(subprocess, "Popen", Recording)
    for name in ("system", "posix_spawn", "posix_spawnp", "execv", "execve", "spawnv"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, lambda *a, **k: pytest.fail("a process was started"))
    issued = handoff.issue_manifest(**inputs)
    readiness = _assess(store, project)
    assert issued.text is not None and readiness.offered is True
    assert started and all(Path(argv[0]).name in ("git", "git.exe") for argv in started), started
    assert not any(name == "app" or name.startswith("app.") for name in set(sys.modules) - before)


# ---------------------------------------------------------------------------
# Scope: no shipped path depends on the reference app; Forge alone writes
# ---------------------------------------------------------------------------

def test_no_shipped_path_depends_on_the_reference_application():
    templates = sorted(SPECIMEN.rglob("*"))
    assert templates and all(t.is_dir() or t.name.endswith(".py.txt") for t in templates), (
        "a template that pytest would collect or an installer would ship")
    shipped = [ROOT / "pyproject.toml", ROOT / "Dockerfile",
               *sorted((ROOT / "src").rglob("*.py")), *sorted((ROOT / "scripts").rglob("*.py"))]
    for path in shipped:
        text = path.read_text(encoding="utf-8")
        assert "specimens/produced_app" not in text and "reference_application" not in text, path
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import build_windows_bundle
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    assert not any(entry.startswith("tests") for entry in build_windows_bundle.BUNDLE_TREE)


def test_forge_alone_writes_the_manifest():
    """In shipped code the manifest's file name is spelled by the store, which
    alone writes it, and by the gate, which reads it from the seal; the
    development flow neither names it nor writes into the store."""
    naming = sorted(path.name for path in (ROOT / "src" / "nornyx_forge").glob("*.py")
                    if "pam.json" in path.read_text(encoding="utf-8"))
    assert naming == ["capsule_store.py", "produced_app_handoff.py"]
    flow = (ROOT / "src" / "nornyx_forge" / "development_flow.py").read_text(encoding="utf-8")
    assert "produced_app" not in flow and "pam.json" not in flow
    store = (ROOT / "src" / "nornyx_forge" / "capsule_store.py").read_text(encoding="utf-8")
    assert store.count("_write_fresh(self.root / _PAM_FILE") == 1
    assert "eligibility=governed_build_eligibility" in (
        ROOT / "src" / "nornyx_forge" / "produced_app_handoff.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A-055: the runtime contract bound into the sealed manifest, and a gated
# build never offered
# ---------------------------------------------------------------------------

def test_issuance_binds_the_runtime_contract_rendered_from_the_accepted_brd(tmp_path: Path):
    from nornyx_forge.contract_generator import render_runtime_contract

    inputs = _issue_inputs(tmp_path)
    issued = handoff.issue_manifest(**inputs)
    assert issued.findings == () and issued.text is not None
    manifest = pam.validate_pam(issued.text)
    model = parse_brd(inputs["project_root"] / "BRD.md")
    assert manifest["runtime_contract"]["digest"] == "sha256:" + hashlib.sha256(
        render_runtime_contract(model).encode("utf-8")).hexdigest()
    assert manifest["gate_provenance"] is None


def test_an_accepted_build_seals_the_runtime_contract_the_flow_rendered(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The real flow and the real verifier: the sealed manifest's runtime
    contract digest is the digest the flow recorded and the bytes it wrote."""
    run = _walk(monkeypatch, tmp_path, ReferenceProvider())
    status, project = run.status, run.project
    assert status["accepted"] is True, status
    text = run.store().sealed().files["pam.json"]
    manifest = pam.validate_pam(text)
    written = project / ".nornyx" / "generated" / "runtime-contract.json"
    assert manifest["runtime_contract"]["digest"] == "sha256:" + hashlib.sha256(
        written.read_bytes()).hexdigest()
    assert manifest["runtime_contract"]["digest"] == \
        status["result"]["generated_runtime_contract_digest"]
    assert manifest["gate_provenance"] is None


def test_the_handoff_gate_never_offers_a_gated_build(tmp_path: Path):
    from nornyx_forge import gate_release_model, provider_gate

    provenance = gate_release_model.gate_provenance(
        cycle_id="c01", run_act_sha256=provider_gate.PINNED_RUN_ACT_SHA256,
        stage_manifest="sha256:" + "1" * 64, release_manifest="sha256:" + "2" * 64,
        import_record="sha256:" + "3" * 64, completeness_list="sha256:" + "4" * 64,
        check_d3g_result="sha256:" + "5" * 64,
        credential_pattern=gate_release_model.GATE_SEED_PATTERN.record())
    direct_store, direct_project, _ = _handed_off(tmp_path / "direct")
    assert _assess(direct_store, direct_project).offered is True
    store, project, _ = _handed_off(tmp_path / "gated", provenance=provenance)
    readiness = _assess(store, project)
    assert readiness.offered is False
    assert readiness.reasons == (
        "the build crossed the run-act gate and was verified statically only; its tests "
        "were not run, so nothing is offered for it",)
