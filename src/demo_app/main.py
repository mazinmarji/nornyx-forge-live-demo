from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agentic import NornyxRuntimeUnavailable, run_case, run_demo_scenarios
from .store import JsonStore

GOVERNANCE_UNAVAILABLE = (
    "The Nornyx authorization path is unavailable and the deterministic fallback "
    "is disabled, so no capability can be authorized and no case may be processed. "
    "This is a governed refusal, not an application error."
)

def _packaged_root() -> Path:
    """Where this application is installed. Fixed relationship, not a search.

    Derived here rather than imported from `nornyx_forge`: the HTTP surface may
    not depend on the governance package, and the architecture gate enforces
    that by path. `<root>/src/demo_app/main.py` yields `<root>`, in a checkout
    and under `/app` alike.

    Never the environment and never the launch directory. `FORGE_ROOT` used to
    choose which tree the application governed, which is authority over subject
    identity itself; `Path.cwd()` would be the same defect wearing different
    clothes.
    """
    candidate = Path(__file__).resolve().parents[2]
    missing = [
        marker
        for marker in ("src/demo_app", ".nornyx/contracts")
        if not (candidate / marker).is_dir()
    ]
    if missing:
        raise RuntimeError(
            f"PACKAGED_ROOT_UNRESOLVED: {candidate} lacks {', '.join(missing)}. "
            "Refusing to guess which tree this application governs."
        )
    return candidate


ROOT = _packaged_root()
STATIC = Path(__file__).resolve().parent / "static"
STORE = JsonStore(ROOT / ".nornyx/demo-data.json")

app = FastAPI(title="Nornyx Forge — Governed Customer Operations", version="0.3.0")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class CaseInput(BaseModel):
    customer: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=3, max_length=1200)
    risk: str = Field(pattern="^(low|medium|high|critical)$")
    requested_action: str = Field(min_length=2, max_length=300)


def _read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/dashboard")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    """Report what this deployment can and cannot do, without leaking how.

    A packaged image usually has no approver trust store, so consequential
    approval authority is unavailable there. Saying so is the point: a reader
    should be able to tell the difference between "no approval has been sought"
    and "no approval could be authenticated even if one were".

    Deliberately no store path and no key material — that a deployment is
    anchored is the operator's business; where its keys live is not.
    """
    from demo_app.agentic import assurance_state

    return {
        "status": "ok",
        "assurance_mode": "autonomous_demonstration",
        "human_review": "not_performed",
        "production_approval": "not_granted",
        **assurance_state(),
    }


@app.get("/api/build")
def build_summary():
    return {
        "summary": _read_json(ROOT / ".nornyx/runs/build-summary.json", {}),
        "value": _read_json(ROOT / ".nornyx/runs/value-report.json", {}),
        "evidence": _read_json(ROOT / ".nornyx/runs/build-evidence-report.json", {}),
        "requirements": _read_json(ROOT / ".nornyx/requirements/requirements.json", {}),
    }


@app.get("/api/cases")
def list_cases():
    return {"cases": STORE.list_cases()}


@app.post("/api/cases")
def create_case(payload: CaseInput):
    case = {
        "id": f"CASE-{uuid.uuid4().hex[:8].upper()}",
        **payload.model_dump(),
        "status": "queued",
        "timeline": [],
    }
    try:
        case = run_case(case, root=ROOT)
    except NornyxRuntimeUnavailable as exc:
        raise HTTPException(
            503,
            {
                "error": "governance_unavailable",
                "message": GOVERNANCE_UNAVAILABLE,
                "detail": exc.public_detail,
                "human_review": "not_performed",
                "production_approval": "not_granted",
            },
        ) from exc
    STORE.put_case(case)
    return case


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    case = STORE.get_case(case_id)
    if not case:
        raise HTTPException(404, "case not found")
    return case


@app.post("/api/demo/run")
def run_demo():
    try:
        result = run_demo_scenarios(ROOT)
    except NornyxRuntimeUnavailable as exc:
        raise HTTPException(
            503,
            {
                "error": "governance_unavailable",
                "message": GOVERNANCE_UNAVAILABLE,
                "detail": exc.public_detail,
                "human_review": "not_performed",
                "production_approval": "not_granted",
            },
        ) from exc
    STORE.put_case(result["low_risk"])
    STORE.put_case(result["high_risk"])
    return result
