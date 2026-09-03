"""Forge's own onboarding surface: the capsule's authority rules, served.

WHAT THIS IS FOR. A basic user describes what they need in ordinary
language, watches it enter the project capsule as a PROPOSAL, confirms it
as a human, selects a provider, derives the BRD, confirms the scope, starts
the governed build, reads the business-language rendering of what governs
the project, and -- when the recorded evidence licenses it -- marks the
project ready, all through a local web page, never a terminal. This module
is that surface, and it adds NO authority logic of its own: every refusal a
route returns is the capsule's, the Experience Contract's, the journey
mapping's or the renderer's, passed through with its exact reason.

The corrections this surface exists to honor, stated as route behaviour:

  * C2 — model output enters only as proposed, schema-validated deltas:
    the proposal route accepts any actor kind and the capsule validates the
    value at the door; nothing a proposal contains reaches the
    authoritative region here.
  * C1 — the governance route serves ONLY the deterministic renderer's
    output, produced through its round-trip guard, so what the user reads
    is provably the contract's projection and never free prose.
  * C4 — persistence is the git-backed capsule store; no route knows git
    exists.
  * Honest state — absent lifecycle state is reported as recorded absence,
    and a capsule whose digest chain disagrees with its content is reported
    as the tamper finding it is, not blurred into an empty page.

THE LIFECYCLE IS THE EXPERIENCE CONTRACT'S, PROJECTED. The journey routes
offer a person semantic actions -- start tracking, confirm the scope, start
the build, retry, mark ready -- and `experience_journey` maps each onto the
one canonical transition it names. No route takes a stage from the client.
The build thread records BUILD -> TEST -> GOVERN as the system actor, from
the translated flow result and nothing else, and stops there: READY is a
human act, offered only when the persisted GOVERN evidence would satisfy
the contract, and refused by the contract otherwise. What the page shows
is read back from the persisted lifecycle on every refresh; a JavaScript
variable never decides a stage.

THE TRUST BOUNDARY, disclosed rather than implied: this surface runs
locally for one person, like the CLI it sits beside. The actor on each
request is taken verbatim from the request and judged by the capsule's
KIND rule; the surface does not authenticate humans, and it also never
upgrades an actor — a client that says it is a model is refused exactly
where a model must be refused. Authenticating the human is a later,
separately-scoped slice, and until it lands no claim of authentication is
made anywhere on this surface.

`layer.application`, following the forge_cli precedent: this module
composes the capsule domain, the store adapter, the journey mapping and
the renderer — it is declared for that composition, not for the FastAPI
decorators sitting on top of it. It starts no process; serving it is the launcher's job.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .brd_authoring import BrdAuthoringError, brd_from_capsule
from .capsule import (
    PROVIDERS,
    Actor,
    CapsuleError,
    CapsuleTamperError,
    CapsuleValidationError,
    confirm,
    create_document,
    propose,
    reject,
)
from .capsule_store import CapsuleStore, CapsuleStoreError
from .experience_journey import (
    JourneyRefusal,
    begin_build,
    build_error,
    build_outcome,
    confirm_scope,
    journey_view,
    mark_ready,
    retry_after_failure,
    start_tracking,
)
from .experience_sharing import sharing_preview
from .governance_rendering import RenderingError, verify_round_trip

#: The honest words for lifecycle state that does not exist. A surface that
#: invented a starting stage here would be reporting a workflow position
#: nobody ever recorded.
EXPERIENCE_ABSENT = {
    "status": "absent",
    "detail": "no lifecycle state has been recorded for this project yet",
}

_NO_PROJECT = "no project exists; create one first"
_NO_LIFECYCLE = (
    "no lifecycle is recorded for this project; start tracking it first -- "
    "nothing about its history is inferred"
)

#: A flow that raised returned nothing; distinguished from a flow that
#: returned `None`, which is a completed call with an unusable result and
#: is judged by the translator rather than reported as a crash.
_NOT_RETURNED = object()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


class ActorPayload(BaseModel):
    kind: str
    ident: str

    def to_actor(self) -> Actor:
        return Actor(kind=self.kind, ident=self.ident)


class ProjectPayload(BaseModel):
    project_id: str
    project_name: str
    actor: ActorPayload


class ProposalPayload(BaseModel):
    field: str
    value: Any
    actor: ActorPayload


class ResolvePayload(BaseModel):
    actor: ActorPayload


def _refusal(error: CapsuleError) -> JSONResponse:
    """The capsule's refusals, passed through with their kind and reason.

    Validation refusals are the client's shape being wrong (422); transition
    refusals are the authority and state rules speaking (409); a tamper
    finding is named as such and carried on the same conflict status rather
    than dressed up as a server fault — the server is fine, the record is
    not.
    """
    if isinstance(error, CapsuleValidationError):
        return JSONResponse(status_code=422, content={"refused": str(error)})
    if isinstance(error, CapsuleTamperError):
        return JSONResponse(
            status_code=409, content={"refused": str(error), "finding": "TAMPERED"}
        )
    return JSONResponse(status_code=409, content={"refused": str(error)})


def _refused(reason: str) -> JSONResponse:
    return JSONResponse(status_code=409, content={"refused": reason})


def _human_act(payload: ResolvePayload, what: str) -> Actor | JSONResponse:
    """The actions this surface offers are a person's. A request claiming any
    other kind is refused here by name, before any contract is consulted --
    and where the contract is stricter still (CONFIRM, READY admit only a
    human), the contract's refusal is returned as well, in its own words."""
    actor = payload.actor.to_actor()
    try:
        actor.validate()
    except CapsuleError as error:
        return _refusal(error)
    if actor.kind != "human":
        return _refused(f"{what} is a human act on this surface; got kind={actor.kind!r}")
    return actor


def create_app(
    capsule_root: Path,
    contracts_dir: Path,
    clock: Callable[[], str] | None = None,
    flow_factory: Callable[..., Any] | None = None,
) -> FastAPI:
    """The onboarding application over one capsule store and one contract set.

    `flow_factory` is the injectable seam for the build trigger, defaulting
    to the real `DevelopmentFlow`; tests capture it, the shipped surface
    runs the real flow.
    """
    root = Path(capsule_root)
    contracts = Path(contracts_dir)
    at = clock if clock is not None else _now_iso
    if flow_factory is None:
        from .development_flow import DevelopmentFlow
        flow_factory = DevelopmentFlow
    app = FastAPI(title="Nornyx Forge — Onboarding", version="0.1.0")
    app.state.build = {"status": "never_run"}
    build_lock = threading.Lock()
    # ONE STORE, ONE WRITER AT A TIME. The capsule and the lifecycle are two
    # files in one git repository, and every save stages the whole tree, so
    # a capsule save that interleaved with a lifecycle save would sweep the
    # other's half-written file into its own commit (measured under review:
    # a concurrent proposal committed experience.json as "capsule: propose
    # P-3", and the lifecycle save then found nothing left to commit). Every
    # route that reads or writes the store does so under this lock, and so
    # does the build thread -- so a stale request is judged against the
    # CURRENT persisted state rather than the one its sender last saw, two
    # requests cannot each load the same state and both persist a
    # successor, and a reader never sees a file mid-write. The lock is held
    # around store access only, never around the build itself. A local
    # single-user surface needs no more.
    store_lock = threading.Lock()

    def store() -> CapsuleStore:
        return CapsuleStore(root)

    def brd_present() -> bool:
        return (root.parent / "BRD.md").exists()

    def project(current: CapsuleStore) -> dict[str, Any]:
        """The capsule, or the journey's refusal when no store exists at all.

        Only a MISSING store is translated; every other refusal the store
        raises -- unreadable, invalid, tampered, or a save it declined --
        passes through in the store's own words. A review measured the
        broader mapping reporting "no project exists" for a lifecycle that
        had in fact just been persisted.
        """
        try:
            return current.load()
        except CapsuleStoreError:
            if not root.exists():
                raise JourneyRefusal(_NO_PROJECT) from None
            raise

    def recorded(current: CapsuleStore) -> dict[str, Any]:
        """The persisted lifecycle, or the journey's refusal when there is
        none. Corruption and tamper raise their own findings through."""
        try:
            return current.load_experience()
        except CapsuleStoreError:
            raise JourneyRefusal(_NO_LIFECYCLE) from None

    @app.get("/", response_class=HTMLResponse)
    def page() -> str:
        return _PAGE

    @app.get("/api/state")
    def state():
        current = store()
        with store_lock:
            try:
                document = current.load()
            except CapsuleStoreError:
                return {"initialized": False, "providers": list(PROVIDERS)}
            except CapsuleError as error:
                return _refusal(error)
            lifecycle: dict[str, Any] | None
            try:
                lifecycle = current.load_experience()
                revision = current.revision()
            except CapsuleStoreError as error:
                if "experience state" not in str(error):
                    return _refusal(error)  # a store with no commit: reported, not a 500
                lifecycle = None
                revision = current.revision()
            except CapsuleError as error:
                return _refusal(error)
        return {
            "initialized": True,
            "project_id": document["project_id"],
            "authoritative": document["authoritative"],
            "proposals": document["proposed"],
            "digest_chain_length": len(document["digest_chain"]),
            "experience": lifecycle if lifecycle is not None else EXPERIENCE_ABSENT,
            "journey": journey_view(lifecycle, document, brd_present(), build_lock.locked()),
            "brd_present": brd_present(),
            "providers": list(PROVIDERS),
            "revision": revision,
        }

    @app.post("/api/project")
    def create_project(payload: ProjectPayload):
        """A project and its lifecycle, as one first revision.

        The capsule is created by a human (the capsule refuses otherwise)
        and the lifecycle is started at DISCOVER by the same human through
        the contract's own `start_experience`; the store commits both
        together, so there is no state in which the project exists and its
        lifecycle does not.
        """
        try:
            actor = payload.actor.to_actor()
            document = create_document(
                payload.project_id, payload.project_name, actor, at(),
            )
            lifecycle = start_tracking(actor, at())
            with store_lock:
                revision = store().initialize(document, experience=lifecycle)
        except CapsuleError as error:
            return _refusal(error)
        return {
            "project_id": payload.project_id,
            "revision": revision,
            "lifecycle": {"stage": lifecycle["stage"], "status": lifecycle["status"]},
        }

    @app.post("/api/proposals")
    def create_proposal(payload: ProposalPayload):
        current = store()
        with store_lock:
            try:
                document = current.load()
                updated, proposal_id = propose(
                    document, payload.field, payload.value,
                    payload.actor.to_actor(), at(),
                )
                current.save(updated, f"capsule: propose {proposal_id}")
            except CapsuleError as error:
                return _refusal(error)
        return {"proposal_id": proposal_id, "status": "open"}

    @app.post("/api/proposals/{proposal_id}/confirm")
    def confirm_proposal(proposal_id: str, payload: ResolvePayload):
        """Confirms ONE proposal into the capsule's authority. This is not the
        lifecycle's CONFIRM: that is the separate scope confirmation below,
        and nothing here touches the lifecycle."""
        current = store()
        with store_lock:
            try:
                document = current.load()
                updated = confirm(document, proposal_id, payload.actor.to_actor(), at())
                current.save(updated, f"capsule: confirm {proposal_id}")
            except CapsuleError as error:
                return _refusal(error)
        return {"proposal_id": proposal_id, "status": "confirmed"}

    @app.post("/api/proposals/{proposal_id}/reject")
    def reject_proposal(proposal_id: str, payload: ResolvePayload):
        current = store()
        with store_lock:
            try:
                document = current.load()
                updated = reject(document, proposal_id, payload.actor.to_actor(), at())
                current.save(updated, f"capsule: reject {proposal_id}")
            except CapsuleError as error:
                return _refusal(error)
        return {"proposal_id": proposal_id, "status": "rejected"}

    # -- the journey: semantic actions, each one canonical transition ------

    @app.post("/api/journey/start")
    def start_journey(payload: ResolvePayload):
        """Begin lifecycle tracking at DISCOVER for a project that has none.

        The bounded, human-controlled way in for a capsule that predates
        lifecycle orchestration. It starts where every lifecycle starts and
        infers nothing from the project's files; a project that already has
        a lifecycle is refused, because tracking begins once.
        """
        current = store()
        with store_lock:
            try:
                project(current)
                try:
                    existing = current.load_experience()
                except CapsuleStoreError:
                    existing = None
                if existing is not None:
                    return _refused(
                        f"a lifecycle is already recorded at {existing['stage']}; "
                        "tracking starts once"
                    )
                started = start_tracking(payload.actor.to_actor(), at())
                current.save_experience(started, "started at DISCOVER")
            except CapsuleError as error:
                return _refusal(error)
        return {"stage": started["stage"], "status": started["status"]}

    @app.post("/api/journey/confirm-scope")
    def confirm_project_scope(payload: ResolvePayload):
        """The human scope confirmation: lifecycle CONFIRM.

        Loads the persisted lifecycle and the authoritative capsule, lets
        the journey mapping name what is still missing, and otherwise asks
        the contract to advance into CONFIRM under the requesting actor --
        which the contract grants to a human and to nobody else.
        """
        current = store()
        with store_lock:
            try:
                document = project(current)
                lifecycle = recorded(current)
                updated = confirm_scope(
                    lifecycle, document, brd_present(), payload.actor.to_actor(), at(),
                )
                current.save_experience(updated, "reached CONFIRM")
            except CapsuleError as error:
                return _refusal(error)
        return {"stage": updated["stage"], "status": updated["status"]}

    @app.post("/api/journey/retry")
    def retry_journey(payload: ResolvePayload):
        """Re-enter a failed stage. The contract's own retry; no second
        state machine, and nothing about the failure is forgotten."""
        actor = _human_act(payload, "retrying")
        if isinstance(actor, JSONResponse):
            return actor
        current = store()
        with store_lock:
            try:
                project(current)
                lifecycle = recorded(current)
                updated = retry_after_failure(lifecycle, actor, at())
                current.save_experience(updated, f"retried at {updated['stage']}")
            except CapsuleError as error:
                return _refusal(error)
        return {"stage": updated["stage"], "status": updated["status"]}

    @app.post("/api/journey/ready")
    def mark_project_ready(payload: ResolvePayload):
        """The human completion claim: lifecycle READY.

        Presents to the contract exactly the gate-results and
        governance-validation references GOVERN recorded, read back from
        the persisted lifecycle. A build that recorded no governance
        validation is refused by the contract, in its words; nothing here
        supplies what the build did not produce.
        """
        current = store()
        with store_lock:
            try:
                project(current)
                lifecycle = recorded(current)
                updated = mark_ready(lifecycle, payload.actor.to_actor(), at())
                current.save_experience(updated, "reached READY")
            except CapsuleError as error:
                return _refusal(error)
        return {"stage": updated["stage"], "status": updated["status"]}

    @app.post("/api/build")
    def trigger_build(payload: ResolvePayload):
        """Run the governed build for this project, from confirmed state only.

        The no-terminal path to `nornyx-forge build`: the flow runs over the
        PROJECT directory with the capsule's CONFIRMED provider, in
        greenfield mode (a fresh user project is not a certified
        foundation, and saying so is what the mode vocabulary is for). The
        prerequisites are refused by name -- no derived BRD, no confirmed
        provider, a build already running -- and triggering is a human act
        on this surface, judged by the same KIND rule as every confirmation.

        The lifecycle enters BUILD through the contract before the flow
        starts, under the person who started it. When the flow completes,
        the thread records what the translated result licenses -- TEST,
        then GOVERN -- as the system actor, and a flow that raised, returned
        nothing usable, or was not accepted is recorded as a failure of the
        stage the workflow is at. The flow's own result is recorded
        verbatim, gates and worker endings included; this route improves no
        news, and no field a worker wrote is read as lifecycle evidence.
        """
        actor = _human_act(payload, "starting a build")
        if isinstance(actor, JSONResponse):
            return actor
        current = store()
        with store_lock:
            try:
                document = project(current)
            except CapsuleError as error:
                return _refusal(error)
        provider = document["authoritative"].get("provider")
        if provider is None:
            return _refused("no confirmed provider; confirm one before building")
        project_dir = root.parent
        if not brd_present():
            return _refused("no BRD.md in the project; derive it first")
        if not build_lock.acquire(blocking=False):
            return _refused("a build is already running for this project")
        try:
            with store_lock:
                lifecycle = recorded(current)
                positioned, advanced = begin_build(lifecycle, actor, at())
                if advanced:
                    current.save_experience(positioned, "reached BUILD")
        except CapsuleError as error:
            build_lock.release()
            return _refusal(error)
        except BaseException:
            # Anything else -- an absent git, an interrupted request -- must
            # not leave the build lock held for the rest of the session.
            build_lock.release()
            raise
        app.state.build = {"status": "running", "provider": provider["name"]}

        def run() -> None:
            outcome: dict[str, Any]
            result: Any = _NOT_RETURNED
            try:
                flow = flow_factory(
                    project_dir,
                    worker_mode="claude-code",
                    repo_mode="greenfield",
                    provider=provider["name"],
                )
                result = flow.run()
                outcome = {
                    "status": "finished",
                    "provider": provider["name"],
                    "accepted": isinstance(result, Mapping) and bool(result.get("accepted")),
                    "result": result,
                }
            except Exception as error:  # noqa: BLE001 - recorded, not judged
                outcome = {"status": "failed", "error": str(error)}
            try:
                with store_lock:
                    lifecycle = current.load_experience()
                    if result is _NOT_RETURNED:
                        steps = [(build_error(lifecycle, outcome["error"], at()),
                                  "build did not complete")]
                    else:
                        steps = list(build_outcome(lifecycle, result, at))
                    for step, message in steps:
                        current.save_experience(step, message)
                        lifecycle = step
                    outcome["lifecycle"] = {
                        "recorded": True,
                        "stage": lifecycle["stage"],
                        "status": lifecycle["status"],
                    }
            except Exception as error:  # noqa: BLE001 - the record, not the run
                outcome["lifecycle"] = {"recorded": False, "error": str(error)}
            finally:
                # Published last, so a poller that sees a terminal build
                # status also sees the lifecycle that status produced.
                app.state.build = outcome
                build_lock.release()

        threading.Thread(target=run, name="forge-build", daemon=True).start()
        return {"status": "running", "provider": provider["name"]}

    @app.get("/api/build")
    def build_status():
        """The build's state as last recorded IN THIS SERVER SESSION. Never
        improved, never guessed; the lifecycle's persisted position is the
        record that survives a restart, and /api/state carries it."""
        return app.state.build

    @app.post("/api/brd")
    def derive_brd():
        """Derive the project's BRD from the CONFIRMED capsule region.

        The bridge from plain language to the build flow, with the
        authority line intact: only confirmed intent and requirements reach
        the document, the derivation refuses a proposal-only capsule with
        its own reason, and the file lands in the project directory beside
        the capsule -- where the build reads it.
        """
        current = store()
        try:
            document = current.load()
            rendered = brd_from_capsule(document)
        except BrdAuthoringError as error:
            return JSONResponse(status_code=409, content={"refused": str(error)})
        except CapsuleError as error:
            return _refusal(error)
        target = root.parent / "BRD.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8", newline="")
        return {"written": str(target), "bytes": len(rendered.encode("utf-8"))}

    @app.get("/api/sharing-preview")
    def sharing():
        """What sharing WOULD contain, for the user's review. Never sent.

        Serves the minimized payload derived by the sharing module — counts,
        closed-vocabulary names, one fingerprint, and the transmission state
        as data. The module has no network path, and neither does this
        route: display is the whole feature until a founder decision
        authorizes a receiving backend.
        """
        current = store()
        with store_lock:
            try:
                document = current.load()
            except CapsuleStoreError:
                return JSONResponse(
                    status_code=409,
                    content={"refused": "no project exists to preview sharing for"},
                )
            except CapsuleError as error:
                return _refusal(error)
            try:
                experience: Mapping[str, Any] | None = current.load_experience()
            except CapsuleStoreError:
                experience = None
            except CapsuleError as error:
                return _refusal(error)
        return sharing_preview(document, experience)

    @app.get("/api/governance")
    def governance():
        """Every shipped contract, as the strict renderer's guarded output.

        `verify_round_trip` is the only producer used here: if a contract
        cannot be rendered AND parsed back to the same facts, this route
        reports the failure instead of serving an unguarded view.
        """
        views = []
        for path in sorted(contracts.glob("*.nyx")):
            try:
                rendered = verify_round_trip(
                    yaml.safe_load(path.read_text(encoding="utf-8"))
                )
            except (RenderingError, yaml.YAMLError, OSError) as error:
                return JSONResponse(
                    status_code=502,
                    content={"refused": f"{path.name}: {error}"},
                )
            views.append({"file": path.name, "view": rendered})
        return {"contracts": views}

    return app


_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>Nornyx Forge — Onboarding</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
 fieldset{margin:1rem 0;border:1px solid #999;border-radius:4px}
 pre{white-space:pre-wrap;background:#f4f4f4;padding:0.75rem;overflow-x:auto}
 button{margin:0.25rem 0}
 #notice{color:#a00;min-height:1.5em}
 #stage{font-weight:bold}
 .failed{color:#a00}
 ul{margin:0.25rem 0}
</style>
<h1>Nornyx Forge</h1>
<p>Describe what you need. It becomes a <em>proposal</em>; nothing is
authoritative until you confirm it. The governance shown below is rendered
from the contracts that actually govern this project — the contracts, not
this page, are the authority.</p>
<fieldset><legend>Your name</legend>
 <input id="who" placeholder="your name"></fieldset>
<fieldset><legend>1 · Create the project</legend>
 <input id="pid" placeholder="project-id"> <input id="pname" placeholder="Project name">
 <button onclick="createProject()">Create</button></fieldset>
<fieldset><legend>2 · Describe what you need</legend>
 <textarea id="need" rows="3" cols="50" placeholder="I need an application that..."></textarea>
 <button onclick="proposeNeed()">Propose</button></fieldset>
<fieldset><legend>3 · Choose your engineering agent</legend>
 <select id="provider"></select>
 <button onclick="proposeProvider()">Propose</button></fieldset>
<fieldset><legend>Open proposals — confirming is your act, not the model's</legend>
 <div id="proposals"></div></fieldset>
<fieldset><legend>4 · Your project's lifecycle</legend>
 <div>Stage: <span id="stage">—</span> <span id="status"></span></div>
 <div id="next"></div>
 <div id="failure" class="failed"></div>
 <div id="blockers"></div>
 <div>
  <button id="b_start" onclick="act('/api/journey/start')">Start lifecycle tracking</button>
  <button id="b_brd" onclick="deriveBrd()">Derive BRD</button>
  <button id="b_confirm" onclick="act('/api/journey/confirm-scope')">Confirm scope</button>
  <button id="b_build" onclick="act('/api/build')">Start build</button>
  <button id="b_retry" onclick="act('/api/journey/retry')">Retry</button>
  <button id="b_ready" onclick="act('/api/journey/ready')">Mark ready</button>
 </div>
 <div id="notice"></div>
 <div>Build (this server session): <span id="build">—</span></div></fieldset>
<fieldset><legend>Project state</legend><pre id="state">loading…</pre></fieldset>
<fieldset><legend>Sharing preview — reviewed here, never sent</legend>
 <button onclick="sharingPreview()">Show sharing preview</button><pre id="share"></pre></fieldset>
<fieldset><legend>What governs this project</legend><pre id="gov">loading…</pre></fieldset>
<script>
const actor = () => ({kind: "human", ident: document.getElementById("who").value || "user"});
const json = (r) => r.json();
const text = (id, value) => { document.getElementById(id).textContent = value; };
async function call(url, body){
  const r = await fetch(url, {method: "POST", headers: {"content-type": "application/json"},
                              body: JSON.stringify(body)});
  const data = await r.json();
  text("notice", r.ok ? "" : ("Refused: " + (data.refused || JSON.stringify(data))));
  await refresh();
}
function act(url){ call(url, {actor: actor()}); }
function createProject(){ call("/api/project", {project_id: pid.value, project_name: pname.value, actor: actor()}); }
function proposeNeed(){ call("/api/proposals", {field: "intent", value: need.value, actor: actor()}); }
function proposeProvider(){ call("/api/proposals", {field: "provider", value: {name: provider.value}, actor: actor()}); }
async function deriveBrd(){
  const r = await fetch("/api/brd", {method: "POST"});
  const data = await r.json();
  text("notice", r.ok ? "BRD derived from the confirmed capsule." : ("Refused: " + (data.refused || JSON.stringify(data))));
  await refresh();
}
async function sharingPreview(){
  const r = await fetch("/api/sharing-preview");
  text("share", JSON.stringify(await r.json(), null, 1));
}
const BUTTONS = {b_start: "start_tracking", b_confirm: "confirm_scope", b_build: "start_build",
                 b_retry: "retry", b_ready: "mark_ready"};
function renderJourney(s){
  const j = s.journey;
  if(s.finding){ text("stage", s.finding); text("status", ""); text("next", s.refused); }
  else if(!s.initialized){ text("stage", "no project"); text("status", ""); text("next", "Create a project to begin."); }
  else if(j.tracking === "absent"){ text("stage", "no lifecycle recorded"); text("status", ""); text("next", j.next); }
  else { text("stage", j.stage); text("status", j.status === "failed" ? "· FAILED" : "· active"); text("next", j.next); }
  text("failure", (j && j.failure) ? ("Failure recorded: " + j.failure) : "");
  const blockers = document.getElementById("blockers");
  blockers.replaceChildren();
  if(j && j.blockers && j.blockers.length){
    blockers.append("Still required:");
    const list = document.createElement("ul");
    for(const b of j.blockers){ const item = document.createElement("li"); item.textContent = b; list.append(item); }
    blockers.append(list);
  }
  const actions = new Set((j && j.actions) || []);
  for(const [id, action] of Object.entries(BUTTONS)){ document.getElementById(id).disabled = !actions.has(action); }
  document.getElementById("b_brd").disabled = !s.initialized;
}
async function refreshBuild(){
  const b = await fetch("/api/build").then(json);
  let line = b.status;
  if(b.status === "finished"){ line += b.accepted ? " · accepted by the flow" : " · not accepted by the flow"; }
  if(b.status === "failed"){ line += " · " + b.error; }
  if(b.lifecycle){ line += b.lifecycle.recorded ? ` · lifecycle recorded at ${b.lifecycle.stage} (${b.lifecycle.status})`
                                                : ` · lifecycle NOT recorded: ${b.lifecycle.error}`; }
  text("build", line);
  if(b.status === "running"){ setTimeout(refresh, 2000); }
}
async function refresh(){
  const r = await fetch("/api/state");
  const s = await r.json();
  document.getElementById("state").textContent = JSON.stringify(s, null, 1);
  renderJourney(s);
  const sel = document.getElementById("provider");
  sel.innerHTML = (s.providers || []).map(p => `<option>${p}</option>`).join("");
  const open = (s.proposals || []).filter(p => p.status === "open");
  document.getElementById("proposals").innerHTML = open.map(p =>
    `<div>${p.proposal_id} · ${p.field} · by ${p.author} (${p.kind})
     <button onclick='call("/api/proposals/${p.proposal_id}/confirm", {actor: actor()})'>Confirm</button>
     <button onclick='call("/api/proposals/${p.proposal_id}/reject", {actor: actor()})'>Reject</button></div>`
  ).join("") || "none";
  await refreshBuild();
}
async function governance(){
  const g = await fetch("/api/governance").then(json);
  document.getElementById("gov").textContent =
    (g.contracts || []).map(c => c.view).join("\\n\\n" + "=".repeat(60) + "\\n\\n");
}
refresh(); governance();
</script>
"""
