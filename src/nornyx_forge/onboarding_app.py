"""Forge's own onboarding surface: the capsule's authority rules, served.

WHAT THIS IS FOR. A basic user describes what they need in ordinary
language, watches it enter the project capsule as a PROPOSAL, confirms it
as a human, selects a provider, and reads the business-language rendering
of what governs the project — all through a local web page, never a
terminal. This module is that surface, and it adds NO authority logic of
its own: every refusal a route returns is the capsule's or the renderer's,
passed through with its exact reason.

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

THE TRUST BOUNDARY, disclosed rather than implied: this surface runs
locally for one person, like the CLI it sits beside. The actor on each
request is taken verbatim from the request and judged by the capsule's
KIND rule; the surface does not authenticate humans, and it also never
upgrades an actor — a client that says it is a model is refused exactly
where a model must be refused. Authenticating the human is a later,
separately-scoped slice, and until it lands no claim of authentication is
made anywhere on this surface.

`layer.application`, following the forge_cli precedent: this module
composes the capsule domain, the store adapter, and the renderer — it is
declared for that composition, not for the FastAPI decorators sitting on
top of it. It starts no process; serving it is the launcher's job.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

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
from .experience_sharing import sharing_preview
from .governance_rendering import RenderingError, verify_round_trip

#: The honest words for lifecycle state that does not exist. A surface that
#: invented a starting stage here would be reporting a workflow position
#: nobody ever recorded.
EXPERIENCE_ABSENT = {
    "status": "absent",
    "detail": "no lifecycle state has been recorded for this project yet",
}


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


def create_app(
    capsule_root: Path,
    contracts_dir: Path,
    clock: Callable[[], str] | None = None,
) -> FastAPI:
    """The onboarding application over one capsule store and one contract set."""
    root = Path(capsule_root)
    contracts = Path(contracts_dir)
    at = clock if clock is not None else _now_iso
    app = FastAPI(title="Nornyx Forge — Onboarding", version="0.1.0")

    def store() -> CapsuleStore:
        return CapsuleStore(root)

    @app.get("/", response_class=HTMLResponse)
    def page() -> str:
        return _PAGE

    @app.get("/api/state")
    def state():
        current = store()
        try:
            document = current.load()
        except CapsuleStoreError:
            return {"initialized": False, "providers": list(PROVIDERS)}
        except CapsuleError as error:
            return _refusal(error)
        try:
            experience: Mapping[str, Any] = current.load_experience()
        except CapsuleStoreError:
            experience = EXPERIENCE_ABSENT
        except CapsuleError as error:
            return _refusal(error)
        return {
            "initialized": True,
            "project_id": document["project_id"],
            "authoritative": document["authoritative"],
            "proposals": document["proposed"],
            "digest_chain_length": len(document["digest_chain"]),
            "experience": experience,
            "providers": list(PROVIDERS),
            "revision": current.revision(),
        }

    @app.post("/api/project")
    def create_project(payload: ProjectPayload):
        try:
            document = create_document(
                payload.project_id, payload.project_name,
                payload.actor.to_actor(), at(),
            )
            revision = store().initialize(document)
        except CapsuleError as error:
            return _refusal(error)
        return {"project_id": payload.project_id, "revision": revision}

    @app.post("/api/proposals")
    def create_proposal(payload: ProposalPayload):
        current = store()
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
        current = store()
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
        try:
            document = current.load()
            updated = reject(document, proposal_id, payload.actor.to_actor(), at())
            current.save(updated, f"capsule: reject {proposal_id}")
        except CapsuleError as error:
            return _refusal(error)
        return {"proposal_id": proposal_id, "status": "rejected"}

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
<fieldset><legend>Project state</legend><pre id="state">loading…</pre></fieldset>
<fieldset><legend>What governs this project</legend><pre id="gov">loading…</pre></fieldset>
<script>
const actor = () => ({kind: "human", ident: document.getElementById("who").value || "user"});
const json = (r) => r.json();
async function call(url, body){
  const r = await fetch(url, {method: "POST", headers: {"content-type": "application/json"},
                              body: JSON.stringify(body)});
  const data = await r.json();
  if(!r.ok){ alert(data.refused || JSON.stringify(data)); }
  await refresh();
}
function createProject(){ call("/api/project", {project_id: pid.value, project_name: pname.value, actor: actor()}); }
function proposeNeed(){ call("/api/proposals", {field: "intent", value: need.value, actor: actor()}); }
function proposeProvider(){ call("/api/proposals", {field: "provider", value: {name: provider.value}, actor: actor()}); }
async function refresh(){
  const s = await fetch("/api/state").then(json);
  document.getElementById("state").textContent = JSON.stringify(s, null, 1);
  const sel = document.getElementById("provider");
  sel.innerHTML = (s.providers || []).map(p => `<option>${p}</option>`).join("");
  const open = (s.proposals || []).filter(p => p.status === "open");
  document.getElementById("proposals").innerHTML = open.map(p =>
    `<div>${p.proposal_id} · ${p.field} · by ${p.author} (${p.kind})
     <button onclick='call("/api/proposals/${p.proposal_id}/confirm", {actor: actor()})'>Confirm</button>
     <button onclick='call("/api/proposals/${p.proposal_id}/reject", {actor: actor()})'>Reject</button></div>`
  ).join("") || "none";
}
async function governance(){
  const g = await fetch("/api/governance").then(json);
  document.getElementById("gov").textContent =
    (g.contracts || []).map(c => c.view).join("\\n\\n" + "=".repeat(60) + "\\n\\n");
}
refresh(); governance();
</script>
"""
