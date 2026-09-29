"""The basic-user journey, simulated from start to GOVERN through the shipped surfaces.

WHAT THIS PROVES. One path, driven the way the onboarding page drives it --
start Forge, describe the outcome, confirm the intent, choose a provider, read
the rendered governance, derive the BRD, confirm the scope, run the governed
build -- joins the real pieces deterministically and ends at GOVERN: the
shipped composition `onboarding_serve.assemble` with its session gate, the
capsule and its git-backed store and seal, the journey mapping and the
Experience Contract, the real `DevelopmentFlow` on its configured backend,
the real trusted greenfield verifier with its isolated test execution, and
the translation of the flow's result into lifecycle evidence. Every step is
an HTTP request, every expected answer is asserted at the step that gives it,
and what the lifecycle recorded is read back from the store.

WHAT IS SIMULATED, AND WHERE. The provider act, together with the provider
adapter path beneath the flow's worker. The build constructs the real flow
for the confirmed provider, and the test replaces the provider-routed worker
that flow built with `SimulatedProvider` before any worker call, so the
Provider Contract's task validation and result normalization, the provider's
adapter and its CLI worker's process launch do not run. The simulated
provider writes a small application derived from the BRD -- whose sources
the real verifier then parses and whose tests it runs -- and every record it
leaves says that no live provider executed. Three other things are test
seams: the eligibility verdict (because no provider is eligible and a
simulated one executes nothing) and the clock, both passed by wrapping the
composition's one call to `create_app`; and the seal directory, redirected
through the composition's own `SEAL_DIR` so that it stays outside the
project, as the shipped one does, without being the user's. Nothing shipped
changes, and no simulation mode exists outside this module.

WHERE IT ENDS. At GOVERN. The greenfield acceptance profile runs no Nornyx
gate, so the build records no governance validation, READY is refused, and
the page says the lifecycle is a dead end (A-032). That refusal is asserted,
not worked around. The optional SIMULATE and REVIEW stages come after GOVERN
and are not reached either.

WHAT THIS DOES NOT PROVE is stated once, in the assumption entry "The
simulated journey proves the path, not a provider build" in
docs/requirements/ASSUMPTIONS.md.
"""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml
from fastapi.testclient import TestClient

from nornyx_forge import experience_journey as journey
from nornyx_forge import gates as gate_module
from nornyx_forge import onboarding_app, onboarding_serve
from nornyx_forge.brd_authoring import brd_from_capsule
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.codex_worker import CodexWorker
from nornyx_forge.control_plane_session import NO_SESSION, REDEEM_PATH
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.experience import MANDATORY_STAGES
from nornyx_forge.experience_build import flow_evidence, flow_reference, scope_reference
from nornyx_forge.gates import GREENFIELD_GATE_IDS, GREENFIELD_PROFILE_DIGEST, GREENFIELD_PROFILE_ID
from nornyx_forge.governance_rendering import verify_round_trip
from nornyx_forge.governed_subject import RuntimeAuthorityConfig
from nornyx_forge.greenfield_verifier import _IGNORED_DIRECTORIES
from nornyx_forge.models import WorkerResult
from nornyx_forge.provider_contract import GovernedEligibility
from nornyx_forge.providers import ProviderRoutedWorker
from nornyx_forge.requirements import parse_brd
from nornyx_forge.subject_bootstrap import resolve_packaged_root

#: The page's actor: `actor()` in `_PAGE` always declares a human.
HUMAN = {"kind": "human", "ident": "casey"}
NEED = "Build a customer support portal."
PROVIDER = "codex"
#: The shipped composition answers only a loopback Host, and the redeem
#: route requires an Origin that names it.
LOOPBACK = "http://127.0.0.1"

SIMULATED_COMMAND = "simulated-provider"
SIMULATED_OUTPUT = "simulated provider at the test seam; no live provider executed this step"
SIMULATED_ELIGIBILITY = (
    "simulated at the test seam: no provider executes, and nothing about any "
    "provider's confinement was measured"
)
#: The worker calls a passing build makes, in order: the architect, the
#: builder, then the three review workers the flow runs after its gates pass.
ROLES = ("solution-architect", "application-builder",
         "test-inspector", "architecture-inspector", "security-inspector")
REVIEW_ROLES = ROLES[2:]
#: Generous: the trusted verifier runs twice on a passing build and bounds
#: each run at 120 seconds; a build this slow has failed.
BUILD_DEADLINE_SECONDS = 600


# ---------------------------------------------------------------------------
# The simulated provider, at the flow's worker seam
# ---------------------------------------------------------------------------

def simulated_application(requirements: dict[str, str], defect: str | None = None) -> dict[str, str]:
    """The files the simulated provider writes, as a pure function of the BRD.

    For each BRD requirement: an entry in `src/simulated_app.py` mapping its
    id to its statement, and a test in `tests/test_simulated_app.py` that
    names the id and asserts the statement. `defect` makes the negative
    specimens: `absent` writes nothing, `untraced` writes tests that name no
    requirement, `failing` serves the wrong statements so the tests fail
    when they are run.
    """
    if defect == "absent":
        return {}
    served = {ident: text[::-1] if defect == "failing" else text
              for ident, text in requirements.items()}
    source = (
        '"""Written by the simulated provider of a Forge journey test.\n\n'
        "No live provider wrote this file; it is derived from BRD.md.\n"
        '"""\n\n'
        "REQUIREMENTS = {\n"
        + "".join(f"    {ident!r}: {text!r},\n" for ident, text in served.items())
        + "}\n\n\n"
        "def requirement(identifier: str) -> str:\n"
        '    """The statement BRD.md gives for one requirement."""\n'
        "    return REQUIREMENTS[identifier]\n"
    )
    if defect == "untraced":
        tests = (
            "from simulated_app import REQUIREMENTS\n\n\n"
            "def test_every_statement_is_recorded():\n"
            f"    assert len(REQUIREMENTS) == {len(served)}\n"
        )
    else:
        tests = "from simulated_app import requirement\n" + "".join(
            f"\n\ndef test_{ident.lower().replace('-', '_')}():\n"
            f"    # {ident}\n"
            f"    assert requirement({ident!r}) == {text!r}\n"
            for ident, text in requirements.items()
        )
    return {"src/simulated_app.py": source, "tests/test_simulated_app.py": tests}


class SimulatedProvider:
    """A benign provider with exactly the worker surface the flow calls.

    It records every call. For the builder's implementation goal it reads
    `BRD.md` in the workspace with the flow's own parser and writes
    `simulated_application`'s files; every other call writes nothing. Every
    result it returns names itself: the command is `simulated-provider` and
    the output says no live provider executed. It never touches the
    capsule store, so the seal has nothing to restore.
    """

    def __init__(self, defect: str | None = None) -> None:
        self.defect = defect
        self.calls: list[dict[str, Any]] = []
        self.written: dict[str, str] = {}

    def run(self, *, role: str, goal: str, workspace: Path, allowed_tools: tuple[str, ...],
            max_turns: int, timeout_seconds: int) -> WorkerResult:
        self.calls.append({"role": role, "goal": goal, "workspace": Path(workspace),
                           "allowed_tools": tuple(allowed_tools)})
        if role == "application-builder" and goal.startswith("Implement"):
            model = parse_brd(Path(workspace) / "BRD.md")
            files = simulated_application(
                {item.id: item.statement for item in model.requirements}, self.defect)
            for relative, text in files.items():
                target = Path(workspace) / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8", newline="")
            self.written = files
        return WorkerResult(role=role, goal=goal, success=True, output=SIMULATED_OUTPUT,
                            command=(SIMULATED_COMMAND, role))


# ---------------------------------------------------------------------------
# Guards: no real provider, no network
# ---------------------------------------------------------------------------

def _forbid_real_providers(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Tripwires on every worker that would start a real provider CLI.

    A call is recorded and refused, so a journey that reached one fails and
    says which. Live by `test_without_the_seam_the_real_provider_is_reached_and_the_build_stops`.
    """
    reached: list[str] = []

    def tripwire(self: Any, **_request: Any) -> WorkerResult:
        reached.append(type(self).__name__)
        raise AssertionError(f"a real provider worker was reached: {type(self).__name__}")

    for worker in (ProviderRoutedWorker, ClaudeCodeWorker, CodexWorker):
        monkeypatch.setattr(worker, "run", tripwire)
    return reached


def _is_local(address: Any) -> bool:
    """A Unix socket path or a loopback address. Anything else is network."""
    if isinstance(address, (str, bytes)):
        return True
    host = address[0].decode("ascii") if isinstance(address[0], bytes) else str(address[0])
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return host == "localhost"


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Refuse and record non-loopback use, in this process, of these socket
    entry points: `socket.socket.connect`, `connect_ex`, `sendto` and (where
    the platform has it) `sendmsg`, and `socket.getaddrinfo`, `gethostbyname`,
    `gethostbyname_ex`, `gethostbyaddr` and `getnameinfo`. Each is shown
    refusing by `test_the_network_guard_refuses_what_it_is_shown`. `sendmsg`
    is checked only when its address is the fourth positional argument; its
    other calling forms are not recognized. Raw
    `_socket` objects, native code, callables bound before the guard, and
    child processes are outside it: the trusted verifier's isolated
    interpreters, which run in an environment the verifier builds, and the
    `git` processes of the capsule store and of this test, which inherit this
    process's environment."""
    attempts: list[str] = []

    def unreachable() -> Any:
        raise OSError(errno.ENETUNREACH, "the simulated journey makes no network connection")

    def unresolved() -> Any:
        raise socket.gaierror(socket.EAI_NONAME, "the simulated journey resolves no name")

    def guard(owner: Any, name: str, target_of: Callable[..., Any], refuse: Callable[[], Any]) -> None:
        real = getattr(owner, name)

        def guarded(*args: Any, **kwargs: Any) -> Any:
            target = target_of(*args, **kwargs)
            if target is None or _is_local(target):
                return real(*args, **kwargs)
            attempts.append(f"{name} {target!r}")
            return refuse()

        monkeypatch.setattr(owner, name, guarded)

    guard(socket.socket, "connect", lambda _sock, target: target, unreachable)
    guard(socket.socket, "connect_ex", lambda _sock, target: target, lambda: errno.ENETUNREACH)
    guard(socket.socket, "sendto", lambda _sock, *rest: rest[-1], unreachable)
    if hasattr(socket.socket, "sendmsg"):  # not on Windows
        guard(socket.socket, "sendmsg", lambda _sock, *rest: rest[3] if len(rest) > 3 else None,
              unreachable)
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        guard(socket, name, lambda host=None, *_a, **_k: None if host is None else (host, 0),
              unresolved)
    guard(socket, "getnameinfo", lambda target, *_a: target, unresolved)
    return attempts


# ---------------------------------------------------------------------------
# Driving the shipped surfaces
# ---------------------------------------------------------------------------

def _clock():
    """The journey tests' deterministic clock: the same requests, the same times."""
    ticks = iter(range(100_000))
    return lambda: f"2026-09-03T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"


def _call(client: TestClient, method: str, path: str, expected: int, step: str,
          **kwargs: Any) -> Any:
    """One request, failing closed: any other status stops the journey here."""
    response = client.request(method, path, **kwargs)
    assert response.status_code == expected, (
        f"{step}: {method} {path} answered {response.status_code}, not {expected}: {response.text}")
    return response.json()


def _inspected(project: Path) -> list[str]:
    """The project files the trusted verifier inspects, by its own directory
    rule, relative and sorted."""
    return sorted(path.relative_to(project).as_posix() for path in project.rglob("*")
                  if path.is_file()
                  and not _IGNORED_DIRECTORIES & set(path.relative_to(project).parts[:-1]))


class Journey:
    """One run: the composition, the seams, and what they recorded."""

    def __init__(self, base: Path, provider: SimulatedProvider | None) -> None:
        self.project = base / "project"
        self.seals = base / "forge-seals"
        self.provider = provider
        self.compositions: list[tuple[Path, Path, dict[str, Any]]] = []
        self.flows: list[tuple[Any, dict[str, Any], Any]] = []
        self.views: list[dict[str, Any]] = []
        self.reached: list[str] = []
        self.attempts: list[str] = []
        self.client: TestClient | None = None
        self.status: dict[str, Any] = {}

    def flow_factory(self, root: Path, **kwargs: Any) -> Any:
        """The build's own request, served by the REAL flow; only its
        provider-routed worker is replaced, before any worker call."""
        flow = DevelopmentFlow(root, **kwargs)
        self.flows.append((flow, dict(kwargs), flow.worker))
        if self.provider is not None:
            flow.worker = self.provider
        return flow

    def store(self) -> CapsuleStore:
        return CapsuleStore(self.project / "capsule", seal_dir=self.seals)

    def state(self, step: str) -> dict[str, Any]:
        state = _call(self.client, "GET", "/api/state", 200, step)
        if "journey" in state:
            self.views.append(state["journey"])
        return state


def _simulated_eligibility(provider: str, platform: str) -> GovernedEligibility:
    return GovernedEligibility(provider=provider, platform=platform, eligible=True,
                               confinement="simulated", reason=SIMULATED_ELIGIBILITY)


def _walk(monkeypatch: pytest.MonkeyPatch, base: Path, provider: SimulatedProvider | None) -> Journey:
    """Start Forge and walk the journey to the end of the build.

    Everything asserted here holds on every run whatever the provider does,
    so a deviation anywhere before the build fails the test at that step.
    """
    run = Journey(base, provider)
    run.project.mkdir(parents=True)
    run.reached = _forbid_real_providers(monkeypatch)
    run.attempts = _forbid_network(monkeypatch)
    # CrewAI's own switch for its package-index check, which GitHub Actions'
    # `CI=true` also turns off: the journey must not need the network. And
    # CrewAI's storage directory, so the kickoff's memory store is written
    # here rather than under the user's data directory.
    monkeypatch.setenv("CREWAI_DISABLE_VERSION_CHECK", "true")
    monkeypatch.setenv("CREWAI_STORAGE_DIR", str(base / "crewai-storage"))
    clock = _clock()

    def composed(capsule_root: Path, contracts_dir: Path, **kwargs: Any):
        run.compositions.append((Path(capsule_root), Path(contracts_dir), dict(kwargs)))
        return onboarding_app.create_app(capsule_root, contracts_dir, clock=clock,
                                         flow_factory=run.flow_factory,
                                         eligibility=_simulated_eligibility, **kwargs)

    monkeypatch.setattr(onboarding_serve, "create_app", composed)
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", run.seals)

    # Start Forge: the shipped composition, the page, the gate, the bearer.
    app = onboarding_serve.assemble(run.project)
    contracts = resolve_packaged_root() / ".nornyx" / "contracts"
    assert run.compositions == [(run.project / "capsule", contracts, {"seal_dir": run.seals})], (
        "the shipped composition passed something of its own beyond the seams")
    assert not run.seals.resolve().is_relative_to(run.project.resolve()), (
        "the seal directory is inside the provider's workspace")
    client = run.client = TestClient(app, base_url=LOOPBACK)
    assert "Nornyx Forge" in client.get("/").text
    refused = client.get("/api/state")
    assert refused.status_code == 401 and refused.json() == dict(NO_SESSION)
    nonce = app.state.session.mint()
    token = _call(client, "POST", REDEEM_PATH, 200, "redeem the start link",
                  json={"nonce": nonce}, headers={"Origin": LOOPBACK})["token"]
    client.headers["Authorization"] = f"Bearer {token}"
    assert run.state("start") == {"initialized": False, "providers": ["codex", "claude"]}

    # Describe the outcome, then confirm the intent: a proposal first,
    # authority only on the human confirmation.
    created = _call(client, "POST", "/api/project", 200, "create the project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN})
    assert created["lifecycle"] == {"stage": "DISCOVER", "status": "active"}
    assert _call(client, "POST", "/api/proposals", 200, "describe the outcome", json={
        "field": "intent", "value": NEED, "actor": HUMAN}) == {"proposal_id": "P-1", "status": "open"}
    described = run.state("described")
    assert "intent" not in described["authoritative"]
    assert described["experience"]["stage"] == "DISCOVER"
    assert _call(client, "POST", "/api/proposals/P-1/confirm", 200, "confirm the intent",
                 json={"actor": HUMAN}) == {"proposal_id": "P-1", "status": "confirmed"}

    # Select a provider. The verdict the surface serves is the seam's.
    assert _call(client, "POST", "/api/proposals", 200, "choose the provider", json={
        "field": "provider", "value": {"name": PROVIDER}, "actor": HUMAN})["proposal_id"] == "P-2"
    _call(client, "POST", "/api/proposals/P-2/confirm", 200, "confirm the provider",
          json={"actor": HUMAN})
    chosen = run.state("provider chosen")
    assert chosen["authoritative"] == {"project_name": "Support Portal", "intent": NEED,
                                       "provider": {"name": PROVIDER}}
    assert chosen["provider_eligibility"] == _simulated_eligibility(
        PROVIDER, onboarding_app.served_platform()).as_dict()
    assert chosen["experience"]["stage"] == "DISCOVER"
    assert chosen["journey"]["blockers"] == [journey._BRD_MISSING]

    # Render governance: the guarded rendering of every packaged contract.
    expected_views = [
        {"file": path.name, "view": verify_round_trip(yaml.safe_load(path.read_text(encoding="utf-8")))}
        for path in sorted(contracts.glob("*.nyx"))
    ]
    assert expected_views, "no contract to render"
    assert _call(client, "GET", "/api/governance", 200, "render governance")["contracts"] == expected_views

    # Derive the BRD: the confirmed capsule's rendering, byte for byte.
    brd = run.project / "BRD.md"
    assert _call(client, "POST", "/api/brd", 200, "derive the BRD")["written"] == str(brd)
    assert brd.read_bytes() == brd_from_capsule(run.store().load()).encode("utf-8")
    derived = run.state("BRD derived")
    assert derived["brd_derived"] is True
    assert derived["brd_digest"] == hashlib.sha256(brd.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    assert derived["journey"]["actions"] == ["confirm_scope"] and derived["journey"]["blockers"] == []

    # The scope confirmation: lifecycle CONFIRM, declared by a human actor and
    # bound to the content it names.
    assert _call(client, "POST", "/api/journey/confirm-scope", 200, "confirm the scope",
                 json={"actor": HUMAN}) == {"stage": "CONFIRM", "status": "active"}
    assert run.state("scope confirmed")["journey"]["actions"] == ["start_build"]

    # The governed build. Nothing the provider will write exists yet.
    assert not (run.project / "src").exists() and not (run.project / "tests").exists()
    assert _call(client, "POST", "/api/build", 200, "start the build",
                 json={"actor": HUMAN}) == {"status": "running", "provider": PROVIDER}
    deadline = time.monotonic() + BUILD_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        run.status = _call(client, "GET", "/api/build", 200, "poll the build")
        if run.status["status"] in ("finished", "failed"):
            break
        threading.Event().wait(0.05)
    else:
        raise AssertionError("the build never reported a terminal state")
    assert len(run.flows) == 1, "the build did not construct exactly one flow"
    return run


def _events(state: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    return [(event["event"], event["to"], event["by"], event["kind"]) for event in state["history"]]


def _scope_row(run: Journey) -> dict[str, Any]:
    """The binding CONFIRM and BUILD record: the capsule's chain tip beside the
    digest of the BRD's bytes, formatted by the translator's own builder."""
    tip = run.store().load()["digest_chain"][-1]
    digest = hashlib.sha256((run.project / "BRD.md").read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    return {"kind": "brd_requirements", "ref": scope_reference(tip, digest), "passed": True}


# ---------------------------------------------------------------------------
# The journey, from start to GOVERN
# ---------------------------------------------------------------------------

def test_the_simulated_journey_reaches_govern_through_the_shipped_surfaces(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Start Forge -> intent -> provider -> governance -> BRD -> CONFIRM ->
    build on the real flow with the simulated provider -> the real verifier
    -> TEST -> GOVERN, and READY refused. Each stage's recorded outcome and
    the evidence it produced are asserted against the store and the flow's
    own files, not against what a response claimed."""
    provider = SimulatedProvider()
    run = _walk(monkeypatch, tmp_path, provider)
    status, project = run.status, run.project
    assert status["status"] == "finished" and status["accepted"] is True, status
    assert status["provider"] == PROVIDER
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    result = status["result"]

    # The build ran the REAL flow for the confirmed provider, greenfield, on
    # the configured backend; the routed worker it built for that provider
    # was replaced before any call and never reached.
    flow, asked, replaced = run.flows[0]
    assert type(flow) is DevelopmentFlow and flow.root == project
    assert asked == {"worker_mode": "claude-code", "repo_mode": "greenfield", "provider": PROVIDER}
    assert isinstance(replaced, ProviderRoutedWorker) and replaced.provider_name == PROVIDER
    assert flow.worker is provider
    assert RuntimeAuthorityConfig().execution_backend == "crewai"
    assert result["execution_backend"] == "crewai_flow"
    assert run.reached == [] and run.attempts == []
    assert (tmp_path / "crewai-storage" / "memory").is_dir(), (
        "the kickoff's memory store was not kept in the test's directory")

    # The simulated act: five calls in order over the project, two files
    # written, byte-identical to the generator's rendering of the BRD, and
    # every worker record in the result naming the simulation.
    assert [call["role"] for call in provider.calls] == list(ROLES)
    assert {call["workspace"] for call in provider.calls} == {project}
    assert all(call["allowed_tools"] == ("Read", "Glob", "Grep")
               for call in provider.calls if call["role"] in REVIEW_ROLES)
    model = parse_brd(project / "BRD.md")
    expected_files = simulated_application({item.id: item.statement for item in model.requirements})
    assert [item.id for item in model.requirements] == ["BRD-001"]
    assert provider.written == expected_files
    for relative, text in expected_files.items():
        assert (project / relative).read_bytes() == text.encode("utf-8"), relative
    workers = [result["architecture_worker"], result["builder_worker"], *result["review_workers"]]
    assert [(w["role"], w["command"], w["output"], w["success"]) for w in workers] == [
        (role, [SIMULATED_COMMAND, role], SIMULATED_OUTPUT, True) for role in ROLES]
    assert result["engineering_provider"] == {"selected": PROVIDER}
    assert result["assurance"] == {
        "mode": "autonomous_demonstration", "human_review": "not_performed",
        "production_approval": "not_granted", "review_workers_executed": len(REVIEW_ROLES),
        "independent_ai_review": "not_established"}

    # Deterministic validation: the trusted verifier's profile decided, over
    # the files the simulated provider generated.
    assert [(gate["name"], gate["passed"]) for gate in result["gates"]] == [
        *((f"greenfield:{check}", True) for check in GREENFIELD_GATE_IDS),
        *((f"review-worker:{role}", True) for role in REVIEW_ROLES),
        ("build-evidence-ledger-valid-before-verdict", True)]
    provenance = result["acceptance_provenance"]
    assert provenance["gate_profile"]["id"] == GREENFIELD_PROFILE_ID
    assert provenance["gate_profile"]["digest"] == GREENFIELD_PROFILE_DIGEST
    installed = Path(gate_module.__file__).with_name("greenfield_verifier.py").resolve(strict=True)
    assert provenance["verifier"]["origin"] == str(installed)
    assert provenance["verifier"]["digest"] == "sha256:" + hashlib.sha256(installed.read_bytes()).hexdigest()
    inspected = _inspected(project)
    assert set(expected_files) <= set(inspected)
    assert provenance["subject"]["root"] == str(project.resolve())
    assert provenance["subject"]["file_count"] == len(inspected)

    # Evidence, as the store holds it: the translator's own references over
    # the served result, and no governance validation anywhere.
    persisted = run.store().load_experience()
    translated = {ref.kind: ref.as_dict() for ref in flow_evidence(result)}
    brd_digest = hashlib.sha256((project / "BRD.md").read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    assert set(translated) == {"flow_run", "gate_results"}
    assert translated["flow_run"]["ref"] == flow_reference("crewai_flow", brd_digest)
    assert persisted["evidence"] == {
        "CONFIRM": [_scope_row(run)], "BUILD": [_scope_row(run)],
        "TEST": [translated["flow_run"]], "GOVERN": [translated["gate_results"]]}
    assert _events(persisted) == [
        ("started", "DISCOVER", "casey", "human"),
        ("advanced", "CONFIRM", "casey", "human"),
        ("advanced", "BUILD", "casey", "human"),
        ("advanced", "TEST", "forge-onboarding", "system"),
        ("advanced", "GOVERN", "forge-onboarding", "system"),
    ]
    assert [event["to"] for event in persisted["history"]] == [
        stage for stage in MANDATORY_STAGES if stage != "READY"]
    log = subprocess.run(["git", "log", "--reverse", "--format=%s"], cwd=project / "capsule",
                         capture_output=True, text=True, check=True, timeout=60).stdout.splitlines()
    assert log == ["capsule: initialize",
                   "capsule: capsule: propose P-1", "capsule: capsule: confirm P-1",
                   "capsule: capsule: propose P-2", "capsule: capsule: confirm P-2",
                   "experience: reached CONFIRM", "experience: reached BUILD",
                   "experience: reached TEST", "experience: reached GOVERN"]
    store = run.store()
    assert store.sealed().revision == store.revision(), "the seal did not follow Forge's save"

    # Inspecting the evidence: what the surface serves is the flow's own record.
    runs = project / ".nornyx" / "runs"
    assert json.loads((runs / "build-summary.json").read_text(encoding="utf-8")) == result
    assert json.loads((runs / "build-evidence-report.json").read_text(encoding="utf-8"))["status"] == "pass"
    ledger = [json.loads(line) for line in
              (runs / "build-events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(row["event_type"], row["decision"]) for row in ledger] == [
        ("requirements_normalized", None), ("foundation_qualified", None),
        ("architecture_prepared", None), ("implementation_completed", None),
        ("build_acceptance", "ALLOW")]
    assert result["requirements_model"]["source_digest"] == "sha256:" + brd_digest
    governed = run.state("after the build")
    assert governed["experience"] == persisted
    assert governed["authority"]["anchor"] == "sealed"
    assert governed["authority"]["last_restoration"] is None

    # The allowed outcome is GOVERN, and READY cannot be manufactured.
    view = governed["journey"]
    assert (view["stage"], view["status"], view["actions"]) == ("GOVERN", "active", [])
    assert view["blockers"] == [journey._READY_UNREACHABLE]
    assert view["next"] == journey._NEXT_SCOPE_DEAD_END
    assert view["scope"]["unchanged"] is True
    refused = _call(run.client, "POST", "/api/journey/ready", 409, "mark ready", json={"actor": HUMAN})
    assert "governance_validation" in refused["refused"]
    assert run.store().load_experience() == persisted, "a refused READY moved the lifecycle"
    assert run.reached == [] and run.attempts == []


def _record(run: Journey) -> dict[str, Any]:
    """What a second run must reproduce. The gate fingerprint is left out
    because the gate records carry run-specific paths; the gates' names and
    verdicts are kept."""
    persisted = run.store().load_experience()
    evidence = json.loads(json.dumps(persisted["evidence"]))
    for row in evidence["GOVERN"]:
        row["ref"] = row["ref"].rsplit("/", 1)[0]
    result = run.status["result"]
    return {
        "history": persisted["history"],
        "evidence": evidence,
        "capsule": (run.project / "capsule" / "capsule.json").read_bytes(),
        "brd": (run.project / "BRD.md").read_bytes(),
        "generated": {relative: (run.project / relative).read_bytes()
                      for relative in sorted(run.provider.written)},
        "gates": [(gate["name"], gate["passed"]) for gate in result["gates"]],
        "requirements_model": result["requirements_model"],
        "views": run.views,
        "roles": [call["role"] for call in run.provider.calls],
    }


def test_two_runs_of_the_simulated_journey_record_the_same_outcome(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Deterministic: the same requests through two fresh compositions over
    two fresh projects record the same lifecycle (timestamps included), the
    same evidence apart from the gate fingerprint, the same capsule, BRD and
    generated bytes, the same gate verdicts and the same journey views."""
    first = _walk(monkeypatch, tmp_path / "first", SimulatedProvider())
    second = _walk(monkeypatch, tmp_path / "second", SimulatedProvider())
    for run in (first, second):
        assert run.status["status"] == "finished" and run.status["accepted"] is True, run.status
        assert run.status["lifecycle"]["stage"] == "GOVERN"
        assert run.state("after the build")["journey"]["stage"] == "GOVERN"
        assert run.reached == [] and run.attempts == []
    one, two = _record(first), _record(second)
    assert one["generated"] and one["views"]
    for key in one:
        assert one[key] == two[key], f"the two runs recorded different {key}"


@pytest.mark.parametrize("defect, refused_by", [
    ("absent", ["project-structure", "requirements-traceability", "test-semantics", "test-execution"]),
    ("untraced", ["requirements-traceability", "test-execution"]),
    ("failing", ["test-execution"]),
])
def test_the_real_verifier_refuses_what_the_simulated_provider_got_wrong(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str, refused_by: list[str]):
    """The provider reports success every time; the verifier decides. Nothing
    generated, tests that name no requirement, and tests that fail when run
    are each refused by exactly the verifier's own gates for that defect, and
    the lifecycle records a failed BUILD in the contract's words with nothing
    at TEST or GOVERN. No repair round runs (the flow's own knob), so the
    simulated provider is asked exactly twice."""
    monkeypatch.setenv("FORGE_MAX_REPAIR_ATTEMPTS", "0")
    provider = SimulatedProvider(defect)
    run = _walk(monkeypatch, tmp_path, provider)
    status = run.status
    assert status["status"] == "finished" and status["accepted"] is False, status
    assert status["lifecycle"] == {"recorded": True, "stage": "BUILD", "status": "failed"}
    result = status["result"]
    assert result["builder_worker"]["success"] is True, "the specimen must report success"
    assert [call["role"] for call in provider.calls] == ["solution-architect", "application-builder"]
    failed = [gate["name"] for gate in result["gates"] if not gate["passed"]]
    assert failed == [f"greenfield:{check}" for check in refused_by]
    execution = next(gate for gate in result["gates"] if gate["name"] == "greenfield:test-execution")
    if defect == "failing":
        assert "isolated project tests failed" in execution["detail"], execution["detail"]
        assert "1 failed, 0 skipped, 1 of 1 collected tests executed" in execution["detail"], (
            execution["detail"])
    else:
        assert "were not run because a preceding static gate failed" in execution["detail"]

    persisted = run.store().load_experience()
    assert set(persisted["evidence"]) == {"CONFIRM", "BUILD"}, persisted["evidence"]
    last = persisted["history"][-1]
    assert (last["event"], last["to"], last["kind"]) == ("failed", "BUILD", "system")
    assert "reports failure" in last["detail"], last["detail"]
    view = run.state("after the refused build")["journey"]
    assert view["status"] == "failed" and view["actions"] == ["retry"]
    refused = _call(run.client, "POST", "/api/journey/ready", 409, "mark ready", json={"actor": HUMAN})
    assert "failed at BUILD; retry it" in refused["refused"]
    assert run.reached == [] and run.attempts == []


def test_without_the_seam_the_real_provider_is_reached_and_the_build_stops(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The control removed. The same journey with no simulated provider at
    the seam: the flow's own routed worker for the confirmed provider is the
    one called, the tripwire fires on it, the build does not complete, and
    the lifecycle records a failed BUILD. GOVERN above depends on the seam,
    and the tripwire guarding it is live."""
    run = _walk(monkeypatch, tmp_path, None)
    flow, _asked, built = run.flows[0]
    assert isinstance(built, ProviderRoutedWorker) and flow.worker is built
    assert run.reached == ["ProviderRoutedWorker"]
    assert run.status["status"] == "failed"
    assert "a real provider worker was reached" in run.status["error"]
    assert run.status["lifecycle"] == {"recorded": True, "stage": "BUILD", "status": "failed"}
    persisted = run.store().load_experience()
    assert set(persisted["evidence"]) == {"CONFIRM", "BUILD"}
    assert "the build did not complete" in persisted["history"][-1]["detail"]
    assert not (run.project / "src").exists() and not (run.project / "tests").exists()
    assert run.attempts == []


def test_the_network_guard_refuses_what_it_is_shown(monkeypatch: pytest.MonkeyPatch):
    """The guard is live on each entry point it names: a connection, a send
    and a name lookup aimed at a documentation address or a reserved name are
    refused and recorded, and a loopback connection is handed to the
    operating system and completes."""
    attempts = _forbid_network(monkeypatch)
    outward, name = ("192.0.2.1", 9), "forge-journey.invalid"
    expected: list[str] = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        stream.settimeout(10)
        datagram.settimeout(10)
        sends = [("connect", lambda: stream.connect(outward)),
                 ("sendto", lambda: datagram.sendto(b"x", outward))]
        if hasattr(socket.socket, "sendmsg"):
            sends.append(("sendmsg", lambda: datagram.sendmsg([b"x"], [], 0, outward)))
        for label, send in sends:
            with pytest.raises(OSError, match="makes no network connection"):
                send()
            expected.append(f"{label} {outward!r}")
        assert stream.connect_ex(outward) == errno.ENETUNREACH
        expected.append(f"connect_ex {outward!r}")
    lookups = [("getaddrinfo", lambda: socket.getaddrinfo(name, 80), (name, 0)),
               ("gethostbyname", lambda: socket.gethostbyname(name), (name, 0)),
               ("gethostbyname_ex", lambda: socket.gethostbyname_ex(name), (name, 0)),
               ("gethostbyaddr", lambda: socket.gethostbyaddr(outward[0]), (outward[0], 0)),
               ("getnameinfo", lambda: socket.getnameinfo(outward, 0), outward)]
    for label, lookup, target in lookups:
        with pytest.raises(socket.gaierror, match="resolves no name"):
            lookup()
        expected.append(f"{label} {target!r}")
    assert attempts == expected
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=10):
            accepted, _peer = listener.accept()
            accepted.close()
    assert attempts == expected, "a loopback connection was refused"
