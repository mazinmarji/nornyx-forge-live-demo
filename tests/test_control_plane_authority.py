"""The real-surface control-plane probe harness -- Tranche C, slice C2.

WHAT WOULD FALSIFY THIS SLICE: a route on the served composition the route-table
census cannot see (a Mount, a WebSocketRoute); a probe that classifies itself
confined while running as the surface's own principal; a classifier that reads
a row's stored allowlist flag instead of deriving it; a partial log that earns a
confined state; a `principal_separated` that can be truth-tested wrongly; a
memory handle recorded as `observed` on the probe's own pid; a redaction that
leaves the login, the machine or an 8.3 profile folder in the record; a subject
block that can be emptied; an instance match that is declared rather than
computed; a positive control that claims admission without a request; an
artefact producer replaced by a constant; a `--host` that is not loopback; a
black-holed surface that outruns the deadline; a provider CLI or a synchronous
`launch()` anywhere in the harness.

WHAT IS PROVED ON THE WIRE AND WHAT IN PROCESS, kept apart. The route TABLE --
which paths exist -- is read in process from the served composition (`assemble`
plus `attach_runtime_routes`) and held equal to the probe's `DOCUMENTED_PATHS`.
The LIVE census over a real socket cannot see a route table: a gated route and an
unrouted path both answer the fixed 401 by design, so what the wire proves is
that the four allowlisted pairs answer and every other documented cell is refused
-- the gate's coverage, and any hole in it -- not which paths are routed.

THE RECORD IS A SELF-REPORT. `transport: loopback_socket` is a declaration the
producer makes; the validator can refuse a non-socket declaration and a socket
fact mislabelled as an inference, and it cannot tell a log built in process and
labelled as a socket log from one that opened a socket. What holds the label
honest is the producer, `probe()`, which has no in-process path -- a property of
the module, pinned here by an AST test.

This module changes NO admission criterion and runs NO provider. Every launch is
held to a watched deadline through the `Launch` harness reused from
`tests/test_windows_runtime.py`; the probe itself is bounded by its own
deadline; the census and the self-probe run on every CI platform, and the
Windows-only artefact facilities degrade to `not_applicable` off Windows rather
than skipping. THE OFF-WINDOWS ARM IS UNVERIFIED ON THE DEVELOPMENT HOST: patching
`sys.platform` breaks `windows_runtime` at import (`import fcntl`), so the Linux
CI matrix is the witness for every `not_applicable`-off-Windows assertion below.
"""

from __future__ import annotations

import ast
import ctypes
import hashlib
import json
import ntpath
import os
import posixpath
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Mount, Route, WebSocketRoute

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import probe_control_plane as probe  # noqa: E402
from probe_control_plane import (  # noqa: E402
    ALLOWLISTED_PAIRS,
    ARTEFACT_NOT_APPLICABLE,
    ARTEFACT_OBSERVED,
    ARTEFACT_OUTCOMES,
    ARTEFACT_REFUSED,
    DOCUMENTED_PATHS,
    MECH_ACL,
    MECH_SURFACE,
    NOT_DERIVABLE_HERE,
    PROBED_METHODS,
    SCHEMA,
    SEPARATION_NOT_SEPARATED,
    SEPARATION_SEPARATED,
    SEPARATION_UNKNOWN,
    STATES,
    NonLoopbackHostError,
    ProbeRecordError,
    capability_acquired,
    classify,
    derive,
    is_separated,
    not_confinement_reason,
    validate_record,
)

# The harnesses this slice reuses rather than forks.
from test_control_plane_session import PROBED_METHODS as SESSION_PROBED_METHODS  # noqa: E402
from test_control_plane_session import SERVED, _composed  # noqa: E402
from test_windows_runtime import Launch, _scratch_profile, _served_bundle  # noqa: E402

from nornyx_forge import onboarding_serve  # noqa: E402
from nornyx_forge.control_plane_session import ALLOWLIST  # noqa: E402

SCRIPT = ROOT / "scripts" / "probe_control_plane.py"
HUMAN = {"kind": "human", "ident": "casey"}
#: The wall-clock bound on the in-process self-probe, and on the CLI witness.
PROBE_DEADLINE_S = 240.0
WITNESS_DEADLINE_S = 180.0


# ---------------------------------------------------------------------------
# One live surface, probed twice -- in process and from a child process --
# then stopped through its record.
# ---------------------------------------------------------------------------

def _cli_witness(ready: dict, session_path: Path) -> dict:
    """The probe as a SEPARATE PROCESS against the live surface: the same
    module through its CLI, in a child of this interpreter, so the memory
    handle is opened on a pid that is not its own. Bounded: the child gets a
    `--deadline` of its own and the parent waits no longer than
    `WITNESS_DEADLINE_S` before killing it."""
    started = time.monotonic()
    child = subprocess.Popen(  # noqa: S603
        [sys.executable, str(SCRIPT), "--port", str(ready["port"]),
         "--expect-instance", ready["instance"], "--session-file", str(session_path),
         "--principal-separated", SEPARATION_NOT_SEPARATED,
         "--deadline", str(WITNESS_DEADLINE_S - 30), "--timeout", "5"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
        errors="replace", cwd=str(ROOT))
    try:
        out, err = child.communicate(timeout=WITNESS_DEADLINE_S)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise AssertionError(f"the CLI witness did not return within {WITNESS_DEADLINE_S:g} s") from None
    wall = time.monotonic() - started
    assert out.strip(), f"the CLI witness printed no record; stderr: {err[-2000:]}"
    return {"record": json.loads(out), "exit_code": child.returncode, "pid": child.pid,
            "stderr": err, "wall": wall}


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Launch the SERVED composition (`assemble`, the runtime's default seam,
    over a bundle whose marker `assemble` sees) on a real loopback socket; run
    the probe in process as the unconfined local caller; run it again from a
    child process; then stop the runtime through its record WITH the bearer,
    whatever happened in between (the `_returns` doctrine: a runtime a failed
    assertion leaves listening outlives the test).

    One launch, two probes, so the Windows artefact facilities (a real
    `Get-CimInstance`) run twice at most. The profile is relocated so the
    `--session-file` fence admits the file the positive control reads.
    """
    tmp = tmp_path_factory.mktemp("c2-live")
    with pytest.MonkeyPatch.context() as monkeypatch:
        _scratch_profile(monkeypatch, tmp)
        bundle = _served_bundle(tmp, monkeypatch)
        run = Launch(tmp, bundle, assemble_app=onboarding_serve.assemble, session_file=True).start()
        outcome: dict = {}
        try:
            ready = run.wait_for("ready")
            in_process = probe.probe(
                ready["port"],
                expect_instance=ready["instance"],
                session_file=run.session_path,
                principal_separated=SEPARATION_NOT_SEPARATED,
                runtime_record=run.paths.record,
                runtime_log=run.paths.log,
                seal_dir=tmp / "seals",
                root=ROOT,
                deadline=PROBE_DEADLINE_S,
            )
            cli = _cli_witness(ready, run.session_path)
        finally:
            record = run.record()
            if record is not None and record.get("status") == "ready":
                outcome["stop"] = run.stop()[0]
                outcome["code"] = run.join()
        assert outcome == {"stop": 200, "code": 0}, outcome
    return {"in_process": in_process, "cli": cli, "ready": ready}


@pytest.fixture(scope="module")
def live_record(live: dict) -> dict:
    return live["in_process"]


@pytest.fixture(scope="module")
def cli_record(live: dict) -> dict:
    return live["cli"]


# ---------------------------------------------------------------------------
# Record builders for the unit pins. A COMPLETE matrix by default, because a
# state that counts as confinement needs one.
# ---------------------------------------------------------------------------

_DEFAULT_STATUS = {
    ("GET", "/"): 200,
    ("GET", "/api/runtime"): 200,
    ("POST", "/api/session/redeem"): 404,
    ("POST", "/api/runtime/reopen"): 200,
}


def _row(method: str, path: str, status: int | None, *, mechanism: str = MECH_SURFACE,
         attempted: bool = True) -> dict:
    allowlisted, authority = probe._membership(method, path)
    return {"method": method, "path": path, "attempted": attempted, "status": status,
            "body_length": 0, "echoed": False, "synthesised_headers": [],
            "allowlisted": allowlisted, "authority_route": authority, "mechanism": mechanism}


def _matrix(overrides: dict | None = None, *, absent: bool = False) -> list[dict]:
    """Every DOCUMENTED_PATHS x PROBED_METHODS cell, answered the way the real
    surface answers an unauthenticated caller, with `overrides` applied."""
    overrides = overrides or {}
    rows = []
    for path in DOCUMENTED_PATHS:
        for method in PROBED_METHODS:
            cell = (method, path)
            status = None if absent else overrides.get(cell, _DEFAULT_STATUS.get(cell, 401))
            rows.append(_row(method, path, status))
    return rows


def _subject(**surface: object) -> dict:
    surface_block = {"reachable": True, "instance": "0123456789abcdef", "pid": 4243, "port": 8710,
                     "expected_instance": None, "expected_instance_matches": None, "detail": None}
    surface_block.update(surface)
    return {
        "probe_pid": 4242,
        "probe_executable": "~/venv/bin/python",
        "probe_executable_sha256": None,
        "sys_executable": "~/venv/bin/python",
        "nornyx_forge_file": "~/tree/src/nornyx_forge/__init__.py",
        "nornyx_forge_origin": "~/tree/src/nornyx_forge/__init__.py",
        "tree_git_sha": None,
        "principal": {"platform": "synthetic", "sid": None, "uid": None},
        "surface": surface_block,
    }


def _valid_record(requests: list[dict], *, classification: str | None = None,
                  principal_separated: str = SEPARATION_NOT_SEPARATED, bearer: bool = False,
                  subject: dict | None = None) -> dict:
    derivation = derive(requests, bearer_acquired=bearer)
    state = classification or derivation.state
    if subject is None:
        answered = any(r["status"] is not None for r in requests)
        subject = _subject() if answered else _subject(reachable=False, instance=None, pid=None)
    return {
        "schema": SCHEMA,
        "generated_at": "2026-01-01T00:00:00Z",
        "transport": "loopback_socket",
        "subject": subject,
        "requests": requests,
        "coverage": derivation.coverage,
        "deadline_seconds": 300.0,
        "deadline_exceeded": False,
        "deadline_note": None,
        "artefacts_truncated": 0,
        "reopen_pull_status": None,
        "positive_control": {"attempted": False, "status": None, "admitted": None},
        "artefacts": [],
        "bearer_acquired_through_surface": bearer,
        "classification": state,
        "classification_reason": derivation.reason,
        "principal_separated": principal_separated,
        "not_confinement_reason": (
            not_confinement_reason(principal_separated) if state == "admitted_nuisance" else None),
    }


def _without_the_cim_query(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a bounded pin off the real `Get-CimInstance` query.

    The browser-handler read starts PowerShell and costs seconds; a pin about
    the host rule, the exit codes, the deadline or a hostile body has no
    business paying for it once per probe. The read itself is pinned through
    its own `query` seam in
    `test_the_command_line_channel_digests_a_nonce_and_never_records_it_raw`,
    and the REAL query runs twice in the live fixture -- in process and in the
    CLI witness -- so nothing about it goes unmeasured."""
    monkeypatch.setattr(
        probe, "_browser_handler_cmdline",
        lambda **kw: probe._not_applicable("browser_handler_cmdline",
                                           "not queried: this pin stubs the Win32_Process read"))


def _composed_concrete_paths(app) -> set[str]:
    """The concrete route census of a composed surface, refusing any route the
    matrix cannot probe. A Mount or a WebSocketRoute -- anything that is not a
    plain HTTP Route with methods -- is a hole, so it FAILS here rather than
    being skipped (INV-B5's lesson)."""
    paths: set[str] = set()
    for route in app.routes:
        assert isinstance(route, Route) and route.methods, (
            f"a live route the matrix cannot probe: {route!r}")
        paths.add(route.path.replace("{proposal_id}", "P-1"))
    return paths


# ---------------------------------------------------------------------------
# C9 -- the route table, held equal to the documented constant IN PROCESS.
# ---------------------------------------------------------------------------

def test_the_documented_paths_equal_the_served_compositions_route_table(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The probe reads no router; its `DOCUMENTED_PATHS` must equal the paths
    the SERVED composition (`assemble` plus `attach_runtime_routes` -- the
    same composition the live fixture launches) actually routes, or a route
    added to the surface is invisible to a stranger's census. Read in process:
    the wire cannot see a route table (module docstring). The four allowlisted
    pairs the probe restates must be the surface's own allowlist, and the
    probe's methods must be the session census's own -- a method added to that
    census and not here would leave the probe narrower, green."""
    app, _stops, _opened = _composed(tmp_path, monkeypatch)
    assert _composed_concrete_paths(app) == set(DOCUMENTED_PATHS), (
        "the probe's documented path list has drifted from the served composition")
    assert ALLOWLISTED_PAIRS == ALLOWLIST, (
        "the probe's allowlisted pairs are not the surface's own ALLOWLIST")
    assert PROBED_METHODS == SESSION_PROBED_METHODS, (
        "the probe's methods are not the session census's PROBED_METHODS")
    assert len(PROBED_METHODS) == 7 and len(probe.MATRIX_CELLS) == 7 * len(DOCUMENTED_PATHS)


def test_a_mount_or_websocket_route_fails_the_route_table_census(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A route the matrix cannot probe is a hole, not a skip. A `Mount` or a
    `WebSocketRoute` injected into a copy of the composed surface reddens the
    census (round-2 P2-1 measured a Mount plus a prefix exemption passing a
    census that only looked at routes with `.methods`)."""
    app, _stops, _opened = _composed(tmp_path, monkeypatch)
    assert _composed_concrete_paths(app) == set(DOCUMENTED_PATHS)  # green before

    async def _asgi(scope, receive, send):  # pragma: no cover - never called
        raise AssertionError("the mounted app must not run")

    app.router.routes.append(Mount("/api/mounted", app=_asgi))
    with pytest.raises(AssertionError, match="cannot probe"):
        _composed_concrete_paths(app)

    app2, _s, _o = _composed(tmp_path / "ws", monkeypatch)
    app2.router.routes.append(WebSocketRoute("/api/ws", endpoint=_asgi))
    with pytest.raises(AssertionError, match="cannot probe"):
        _composed_concrete_paths(app2)


# ---------------------------------------------------------------------------
# C9 over the wire, and R10 -- the self-probe classifies itself.
# ---------------------------------------------------------------------------

def test_the_live_census_admits_only_the_four_allowlisted_pairs(live_record: dict):
    """Over a REAL port: every allowlisted pair answers (never 401) and every
    other documented cell is refused 401 without a bearer. What this proves is
    the gate's coverage over the documented cells and any hole in it -- NOT
    the route table: a gated route and an unrouted path both answer the fixed
    401 by design, so the wire cannot tell them apart; the route table is the
    in-process row's. The surface was live: the positive control reached 200."""
    surface = live_record["subject"]["surface"]
    assert surface["reachable"] is True and surface["expected_instance_matches"] is True
    reached_allowlisted = set()
    for entry in live_record["requests"]:
        pair = (entry["method"], entry["path"])
        assert entry["attempted"] is True and entry["status"] is not None, entry
        if pair in ALLOWLISTED_PAIRS:
            assert entry["status"] != 401, (pair, entry["status"])
            reached_allowlisted.add(pair)
        else:
            assert entry["status"] == 401, (pair, entry["status"])
    assert reached_allowlisted == set(ALLOWLISTED_PAIRS)
    assert live_record["positive_control"]["admitted"] is True, (
        "the authenticated positive control did not reach 200; the surface was "
        "not live and this census would be vacuous")


def test_the_self_probe_is_admitted_nuisance_and_not_separated(live_record: dict):
    """The unconfined local caller reaches the allowlisted pairs and moves no
    authority: `admitted_nuisance`, `principal_separated: not_separated`
    (`is_separated` -> False, not merely falsy). It did NOT acquire the bearer
    through the surface, so it is not `authority_reachable`; and the record says
    in one field why admitted_nuisance is not confinement for a principal that
    is not separated from the owner (A-027)."""
    assert live_record["classification"] == "admitted_nuisance"
    assert live_record["principal_separated"] == SEPARATION_NOT_SEPARATED
    assert is_separated(live_record) is False
    assert live_record["bearer_acquired_through_surface"] is False
    reason = live_record["not_confinement_reason"]
    assert reason == not_confinement_reason(SEPARATION_NOT_SEPARATED)
    assert "A-027" in reason and "principal_separated=not_separated" in reason
    assert "not" in reason.lower() and "confinement" in reason.lower()
    validate_record(live_record)  # the record answers for itself


def test_the_self_probe_answered_every_documented_cell_inside_its_deadline(live_record: dict):
    """The confined-looking state was EARNED over the whole matrix: every cell
    answered, nothing unattempted, the deadline not exceeded."""
    coverage = live_record["coverage"]
    assert coverage["expected_cells"] == len(probe.MATRIX_CELLS) == 133
    assert coverage["answered_cells"] == 133 and coverage["unanswered_cells"] == []
    assert live_record["deadline_exceeded"] is False and live_record["deadline_note"] is None
    assert live_record["deadline_seconds"] == PROBE_DEADLINE_S
    assert "every matrix cell answered" in live_record["classification_reason"]


def test_the_self_probe_leaks_no_bearer_and_no_host_identity_into_the_record(live_record: dict):
    """The positive control read this run's bearer to prove the surface live;
    the record stores THAT a bearered request was made and its status, never
    the token, and carries no credential-shaped run. The subject paths spell
    no login, machine name or home (A-025) -- checked against THIS host's
    identity, which is what a leak would be."""
    validate_record(live_record)
    blob = json.dumps(live_record)
    assert '"token"' not in blob and "Bearer " not in blob
    login = probe.getpass.getuser()
    node = probe.platform.node()
    for token in (login, node):
        if token and len(token) >= 3:
            assert token.lower() not in blob.lower(), f"the record names the host: {token!r}"
    assert "~1." not in live_record["subject"]["sys_executable"], (
        "an 8.3 profile folder fragment survived redaction")
    assert live_record["positive_control"]["request"] == {
        "method": "GET", "path": "/api/state", "bearer_presented": True, "mechanism": MECH_SURFACE}


def test_the_reopen_channel_is_one_mint_per_run(live_record: dict):
    """The matrix's allowlisted POST answers 200 (one mint, the owner's browser
    opened through the launcher's adapter seam here); the explicit pull that
    follows answers 429 inside the rate-limit interval. The redeem rows record
    that their Origin was synthesised by the probe."""
    by_cell = {(r["method"], r["path"]): r for r in live_record["requests"]}
    assert by_cell[("POST", "/api/runtime/reopen")]["status"] == 200
    assert live_record["reopen_pull_status"] == 429
    assert by_cell[("POST", "/api/session/redeem")]["status"] == 404
    for method in PROBED_METHODS:
        assert by_cell[(method, "/api/session/redeem")]["synthesised_headers"] == ["Origin"]
        assert by_cell[(method, "/api/state")]["synthesised_headers"] == []


def test_the_record_shows_which_answers_echoed_the_request(live_record: dict):
    """ROUND-2 TEST F-7: every row carries `echoed`, and nothing anywhere read
    it -- a field recorded by the producer and asserted by nobody is a field
    that can go constant unnoticed.

    What it means: the answer's body contained the path that was asked for, or
    the nonsense nonce the probe sent. It discriminates on the LIVE surface --
    the served page echoes its own path, while the gate's fixed 401 body
    echoes nothing -- so both values appear in one run, and each is checked
    against the body length beside it."""
    by_cell = {(r["method"], r["path"]): r for r in live_record["requests"]}
    echoed = [r for r in live_record["requests"] if r["echoed"]]
    silent = [r for r in live_record["requests"] if not r["echoed"]]
    assert echoed, "no answer echoed its request; `echoed` is constant and pins nothing"
    assert silent, "every answer echoed; `echoed` is constant the other way"
    assert by_cell[("GET", "/")]["echoed"] is True, "the served page did not echo its own path"
    for row in echoed:
        assert row["body_length"] > 0, row
    # The gated cells all answer the SAME fixed body -- `{"refused": "no
    # session for this Forge instance"}` -- which names no path, and that is
    # what makes a 401 uninformative about whether the path is routed.
    gated = [r for r in live_record["requests"]
             if (r["method"], r["path"]) not in ALLOWLISTED_PAIRS]
    assert gated and all(r["echoed"] is False for r in gated), (
        "a gated 401 echoed the request; the fixed body is what makes the gate uninformative")


def test_the_self_probe_memory_handle_is_not_applicable_on_its_own_pid(live_record: dict):
    """The in-process self-probe IS the surface's process: the surface pid it
    reads from `/api/runtime` is its own. A `PROCESS_VM_READ` handle on oneself
    measures nothing, so the artefact is `not_applicable` with the reason
    `self process` -- on every platform, and never `observed` (round-1
    security P2-3 found it recorded observed on the probe's own pid). Every
    artefact stays an inference and never a pass."""
    subject = live_record["subject"]
    assert subject["probe_pid"] == os.getpid() == subject["surface"]["pid"]
    by_name = {a["name"]: a for a in live_record["artefacts"]}
    vm = by_name["process_vm_read"]
    assert vm["outcome"] == ARTEFACT_NOT_APPLICABLE and "self process" in vm["detail"], vm
    assert capability_acquired(vm) is False
    assert capability_acquired(by_name["runtime_record"]) is True, by_name["runtime_record"]
    assert capability_acquired(by_name["runtime_log"]) is True, by_name["runtime_log"]
    for artefact in live_record["artefacts"]:
        assert artefact["mechanism"] == MECH_ACL, artefact
        assert artefact["outcome"] in ARTEFACT_OUTCOMES, artefact
        assert "deadline" not in artefact["detail"], artefact
    assert live_record["artefacts_truncated"] == 0, live_record["artefacts"]


def test_the_cross_process_witness_opens_the_memory_handle_on_windows_only(cli_record: dict):
    """The SEPARATE cross-process witness: the same module through its CLI in
    a child process, against the same live surface. Its probe pid is the
    child's, not this process's; the surface pid is this process's. On Windows
    the same-user child acquires `PROCESS_VM_READ` on the surface -- the
    capability A-027 concedes to a same-user caller -- recorded `observed` and
    still an inference. Off Windows the facility is absent and the artefact is
    `not_applicable`; that arm is exercised by the Linux CI matrix, not on the
    development host (module docstring). The recorded probe pid is NOT compared
    to `Popen.pid`: on Windows a venv's `Scripts\\python.exe` is a launcher
    whose interpreter is a grandchild (measured: 21976 launched, 21736
    recorded), so the fact that matters is that neither is this process."""
    record = cli_record["record"]
    assert record["subject"]["probe_pid"] != os.getpid() and cli_record["pid"] != os.getpid()
    assert isinstance(record["subject"]["probe_pid"], int)
    assert record["subject"]["surface"]["pid"] == os.getpid()
    vm = {a["name"]: a for a in record["artefacts"]}["process_vm_read"]
    assert vm["mechanism"] == MECH_ACL
    if sys.platform == "win32":
        assert vm["outcome"] == ARTEFACT_OBSERVED and "handle acquired" in vm["detail"], vm
        assert capability_acquired(vm) is True
    else:
        assert vm["outcome"] == ARTEFACT_NOT_APPLICABLE and "Windows facility" in vm["detail"], vm
        assert capability_acquired(vm) is False


def test_the_cross_process_witness_exits_zero_and_binds_the_same_source(
        live_record: dict, cli_record: dict):
    """The child classified itself `admitted_nuisance` too, exited 0 (the
    no-authority code, which is NOT a confinement verdict), answered the whole
    matrix, made its own real positive control, and imported the SAME source
    this process did (A-026: the subject is what ran, not the checkout)."""
    record = cli_record["record"]
    assert cli_record["exit_code"] == probe.EXIT_NO_AUTHORITY == 0, cli_record["stderr"][-2000:]
    assert cli_record["wall"] < WITNESS_DEADLINE_S
    assert record["classification"] == "admitted_nuisance"
    assert record["coverage"]["answered_cells"] == 133
    assert record["positive_control"]["admitted"] is True
    assert record["subject"]["nornyx_forge_file"] == live_record["subject"]["nornyx_forge_file"]
    assert record["subject"]["surface"]["instance"] == live_record["subject"]["surface"]["instance"]
    validate_record(record)


def test_the_positive_control_made_a_real_authenticated_request_in_the_live_run(live_record: dict):
    """In the SAME run, the bare `GET /api/state` in the matrix answered 401
    and the bearered one answered 200: the bearer made the difference, so the
    control was a real request against a live gate, not a declaration."""
    bare = next(r for r in live_record["requests"]
                if (r["method"], r["path"]) == ("GET", "/api/state"))
    assert bare["status"] == 401
    control = live_record["positive_control"]
    assert control["attempted"] is True and control["status"] == 200 and control["admitted"] is True


# ---------------------------------------------------------------------------
# The classification rule, as a unit: derived from the constants and the whole
# matrix, a counterexample dominating.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("requests, bearer, expected", [
    (_matrix(), False, "admitted_nuisance"),
    (_matrix(), True, "authority_reachable"),
    (_matrix({("POST", "/api/build"): 200}), False, "authority_reachable"),
    (_matrix({("GET", "/"): 401, ("GET", "/api/runtime"): 401, ("POST", "/api/runtime/reopen"): 429}),
     False, "reachable_unadmitted"),
    (_matrix({("GET", "/"): 403, ("GET", "/api/runtime"): 403, ("POST", "/api/runtime/reopen"): 409}),
     False, "reachable_unadmitted"),
    (_matrix({("DELETE", "/api/state"): 404}), False, "inconclusive"),
    (_matrix({("PUT", "/api/build"): 500}), False, "inconclusive"),
    (_matrix(absent=True), False, "inconclusive"),
    ([], False, "inconclusive"),
])
def test_classify_derives_the_state_from_a_complete_matrix(requests, bearer, expected):
    assert classify(requests, bearer_acquired=bearer) == expected


def test_a_partial_log_cannot_earn_a_confined_state():
    """A state that counts as confinement requires EVERY documented cell
    answered. A two-row log, a matrix missing one authority cell, and a matrix
    with one cell unanswered are all `inconclusive` with the coverage in the
    reason -- and a record that claims `admitted_nuisance` over any of them is
    refused (round-1 security P2-1 measured a 2-row log validating as
    admitted_nuisance)."""
    two = [_row("GET", "/", 200), _row("POST", "/api/build", 401)]
    derivation = derive(two)
    assert derivation.state == "inconclusive"
    assert "coverage incomplete: 2 of 133 matrix cells answered" in derivation.reason
    assert derivation.coverage["answered_cells"] == 2
    assert ["POST", "/api/journey/ready"] in derivation.coverage["unanswered_cells"]
    with pytest.raises(ProbeRecordError, match="derives 'inconclusive'"):
        validate_record(_valid_record(two, classification="admitted_nuisance"))

    without_build = [r for r in _matrix() if (r["method"], r["path"]) != ("POST", "/api/build")]
    assert derive(without_build).state == "inconclusive"
    with pytest.raises(ProbeRecordError, match="derives 'inconclusive'"):
        validate_record(_valid_record(without_build, classification="reachable_unadmitted"))

    one_silent = _matrix({("POST", "/api/journey/ready"): None})
    assert derive(one_silent).state == "inconclusive"
    assert derive(one_silent).coverage["unanswered_cells"] == [["POST", "/api/journey/ready"]]

    assert derive(_matrix()).state == "admitted_nuisance"  # the whole matrix earns it
    validate_record(_valid_record(_matrix()))


def test_a_gated_2xx_dominates_at_any_coverage():
    """A credible counterexample is never withheld as `inconclusive`: a gated
    2xx on a two-row log is `authority_reachable`, and so is a bearer acquired
    through the surface with no log at all."""
    partial = [_row("GET", "/api/state", 401), _row("POST", "/api/build", 200)]
    derivation = derive(partial)
    assert derivation.state == "authority_reachable"
    assert "POST /api/build 200" in derivation.reason and "dominates" in derivation.reason
    assert derive([], bearer_acquired=True).state == "authority_reachable"
    validate_record(_valid_record(partial))  # accepted as the counterexample it is


def test_allowlist_membership_is_derived_from_the_constant_not_the_row():
    """A gated 2xx whose row is relabelled `allowlisted: true` is REFUSED, not
    read as admitted (round-1 security P1-1 measured it accepted as
    admitted_nuisance). With the stored flags removed, the derivation from
    `ALLOWLISTED_PAIRS` stands: authority_reachable."""
    breached = _matrix({("POST", "/api/build"): 200})
    relabelled = [dict(r, allowlisted=True) if (r["method"], r["path"]) == ("POST", "/api/build") else r
                  for r in breached]
    with pytest.raises(ProbeRecordError, match="disagrees with ALLOWLISTED_PAIRS"):
        classify(relabelled)
    record = _valid_record(breached)
    record["requests"] = relabelled
    record["classification"] = "admitted_nuisance"
    record["not_confinement_reason"] = not_confinement_reason(SEPARATION_NOT_SEPARATED)
    with pytest.raises(ProbeRecordError, match="disagrees with ALLOWLISTED_PAIRS"):
        validate_record(record)
    stripped = [{k: v for k, v in r.items() if k not in ("allowlisted", "authority_route")}
                for r in relabelled]
    assert classify(stripped) == "authority_reachable"
    mislabelled_authority = [dict(r, authority_route=False)
                             if r["path"] == "/api/journey/ready" else r for r in _matrix()]
    with pytest.raises(ProbeRecordError, match="AUTHORITY_ROUTES"):
        classify(mislabelled_authority)


def test_unreachable_is_not_in_this_harnesss_vocabulary():
    """C2 derives three states plus `inconclusive`. `unreachable` needs a
    positive control from a separated principal (C3); a record claiming it is
    refused BY NAME, with the reason, not as an unknown word."""
    assert "unreachable" not in STATES and NOT_DERIVABLE_HERE == ("unreachable",)
    assert STATES == ("reachable_unadmitted", "admitted_nuisance", "authority_reachable", "inconclusive")
    with pytest.raises(ProbeRecordError, match="not derivable by this harness.*separated principal"):
        validate_record(_valid_record(_matrix(absent=True), classification="unreachable"))


# ---------------------------------------------------------------------------
# M6 -- what the validator can refuse about transport, and what it cannot.
# ---------------------------------------------------------------------------

def test_a_non_socket_transport_declaration_is_refused():
    record = _valid_record(_matrix())
    validate_record(record)  # the socket record is accepted
    record["transport"] = "in_process_testclient"
    with pytest.raises(ProbeRecordError, match="not a socket result"):
        validate_record(record)


def test_a_socket_fact_labelled_as_an_inference_is_refused():
    """A request that answered but carries a mechanism other than
    `observed_surface_record` is refused."""
    tampered = _matrix()
    tampered[0]["mechanism"] = MECH_ACL
    record = _valid_record(tampered)
    with pytest.raises(ProbeRecordError, match="must be labelled"):
        validate_record(record)


def test_the_validator_cannot_refuse_a_self_declared_transport_and_the_docs_say_so(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """THE BOUND, measured rather than implied away (round-1 test T-F1): a log
    built IN PROCESS with a `TestClient` over the composed surface, carrying
    the self-declared `transport: loopback_socket` and
    `mechanism: observed_surface_record` labels, is ACCEPTED by the validator
    -- no socket was opened, and nothing in a request row could show it. The
    record is a self-report; what holds the label honest is the producer,
    which has no in-process path (`test_the_harness_runs_no_provider_and_starts_no_synchronous_launch`).
    The module docstring and docs/VALIDATION.md must say exactly this."""
    app, _stops, _opened = _composed(tmp_path, monkeypatch)
    client = TestClient(app, base_url=SERVED)
    rows = []
    for path in DOCUMENTED_PATHS:
        for method in PROBED_METHODS:
            headers = {"Origin": SERVED} if path == "/api/session/redeem" else {}
            body = {"nonce": "not-a-real-nonce"} if path == "/api/session/redeem" else {"actor": HUMAN}
            response = client.request(method, path, headers=headers,
                                      json=body if method in ("POST", "PUT", "PATCH") else None)
            rows.append(_row(method, path, response.status_code))
    laundered = _valid_record(rows)
    assert laundered["classification"] == "admitted_nuisance"
    validate_record(laundered)  # ACCEPTED: the bound this test records

    docstring = " ".join(ast.get_docstring(ast.parse(SCRIPT.read_text(encoding="utf-8"))).split())
    assert "SELF-REPORT" in docstring and "CANNOT tell a log built in process" in docstring
    validation = " ".join((ROOT / "docs" / "VALIDATION.md").read_text(encoding="utf-8").split())
    assert "self-report" in validation and "cannot tell a log built in process" in validation


# ---------------------------------------------------------------------------
# M8 -- a label may not disagree with the record's own log.
# ---------------------------------------------------------------------------

def test_a_state_that_disagrees_with_the_log_is_refused():
    """A gated 2xx in the log with the state claiming `reachable_unadmitted` is
    the mislabel M8 exists to catch; so is a reason or a coverage block that
    was not derived from the log."""
    breached = _matrix({("POST", "/api/build"): 200})
    record = _valid_record(breached, classification="reachable_unadmitted")
    with pytest.raises(ProbeRecordError, match="derives 'authority_reachable'"):
        validate_record(record)
    record = _valid_record(_matrix())
    record["classification_reason"] = "every matrix cell answered; trust me"
    with pytest.raises(ProbeRecordError, match="classification_reason"):
        validate_record(record)
    record = _valid_record(_matrix())
    record["coverage"] = dict(record["coverage"], answered_cells=1)
    with pytest.raises(ProbeRecordError, match="coverage block disagrees"):
        validate_record(record)
    record = _valid_record(_matrix())
    record["deadline_exceeded"] = True
    with pytest.raises(ProbeRecordError, match="deadline_exceeded"):
        validate_record(record)


def test_a_surface_absent_record_must_be_inconclusive_not_a_state():
    """The surface-absent record is `inconclusive`, never `reachable_unadmitted`
    or any other state.

    THE `match=` AND THE CASE ONLY THIS RULE CATCHES (round-2 test F-5). The
    two wrong states above are ALSO caught by the state-disagrees-with-the-log
    rule, so deleting this `_require` left the test green: it was pinned by a
    different rule than the one it was written for. The shape only this rule
    refuses is a record whose log answered NOTHING and which claims
    `authority_reachable` through `bearer_acquired_through_surface` -- the
    dominating clause makes the derivation agree, the coverage block agrees,
    the deadline agrees, and every other check passes. An empty log is not
    evidence of reaching authority; the bearer would have had to come from
    somewhere else."""
    absent = _matrix(absent=True)
    validate_record(_valid_record(absent, classification="inconclusive"))
    for wrong in ("reachable_unadmitted", "admitted_nuisance"):
        with pytest.raises(ProbeRecordError, match="derives 'inconclusive'"):
            validate_record(_valid_record(absent, classification=wrong))
    bearered = _valid_record(absent, bearer=True)
    assert bearered["classification"] == "authority_reachable"  # the derivation AGREES
    assert derive(absent, bearer_acquired=True).state == "authority_reachable"
    with pytest.raises(ProbeRecordError, match="absent surface is inconclusive, never a state"):
        validate_record(bearered)
    empty_log = _valid_record([], bearer=True)
    with pytest.raises(ProbeRecordError, match="absent surface is inconclusive, never a state"):
        validate_record(empty_log)


def test_the_separation_vocabulary_cannot_be_truth_tested_wrongly():
    """Three words, one helper. `is_separated` answers True / False / None and
    RAISES on anything else -- the retired `"true"`/`"false"` strings (a
    non-empty `"false"` is truthy, round-1 security P2-2) and Python booleans
    included. The validator refuses `separated` from C2 by name and the retired
    spellings as outside the vocabulary."""
    assert is_separated({"principal_separated": SEPARATION_SEPARATED}) is True
    assert is_separated({"principal_separated": SEPARATION_NOT_SEPARATED}) is False
    assert is_separated({"principal_separated": SEPARATION_UNKNOWN}) is None
    for retired in ("true", "false", True, False, None, "yes", ""):
        with pytest.raises(ProbeRecordError, match="vocabulary"):
            is_separated({"principal_separated": retired})
    with pytest.raises(ProbeRecordError, match="C2 may not record"):
        validate_record(_valid_record(_matrix(), principal_separated=SEPARATION_SEPARATED))
    with pytest.raises(ProbeRecordError, match="retired"):
        validate_record(_valid_record(_matrix(), principal_separated="false"))
    unknown = _valid_record(_matrix(), principal_separated=SEPARATION_UNKNOWN)
    validate_record(unknown)
    assert "principal_separated=unknown" in unknown["not_confinement_reason"]
    with pytest.raises(ValueError, match="principal_separated"):
        probe.probe(1, principal_separated=SEPARATION_SEPARATED)


def test_a_bearer_written_into_the_record_is_refused():
    """A credential-shaped run in the record is refused: a bearer or a raw nonce
    must never enter it (nonces are sha256 prefixes only)."""
    record = _valid_record(_matrix())
    record["leaked"] = secrets.token_urlsafe(32)
    with pytest.raises(ProbeRecordError, match="credential-shaped"):
        validate_record(record)


def test_an_artefact_may_not_report_a_pass_or_a_socket_mechanism():
    """The outcome vocabulary is three words and `pass` is not one of them;
    `capability_acquired` raises on anything outside it rather than reading it
    as False, so an unknown word is never silently benign."""
    record = _valid_record(_matrix())
    record["artefacts"] = [{"name": "process_vm_read", "outcome": "pass", "mechanism": MECH_ACL,
                            "detail": "x"}]
    with pytest.raises(ProbeRecordError, match="never a pass"):
        validate_record(record)
    with pytest.raises(ProbeRecordError, match="the vocabulary is"):
        capability_acquired(record["artefacts"][0])
    record["artefacts"] = [{"name": "runtime_log", "outcome": ARTEFACT_OBSERVED,
                            "mechanism": MECH_SURFACE, "detail": "x"}]
    with pytest.raises(ProbeRecordError, match="kept apart"):
        validate_record(record)


# ---------------------------------------------------------------------------
# Subject binding: a complete block, a computed instance match, a self-pid rule.
# ---------------------------------------------------------------------------

def test_an_empty_or_incomplete_subject_block_is_refused():
    """Round-1 security P2-4: the validator never inspected the subject, so the
    binding could be emptied. Now: no subject, an empty one, a missing key, a
    missing surface key, and a non-integer probe pid are each refused."""
    for broken in (None, {}, "subject"):
        record = _valid_record(_matrix())
        record["subject"] = broken
        with pytest.raises(ProbeRecordError, match="no subject block"):
            validate_record(record)
    record = _valid_record(_matrix())
    del record["subject"]["nornyx_forge_origin"]
    with pytest.raises(ProbeRecordError, match="incomplete; missing \\['nornyx_forge_origin'\\]"):
        validate_record(record)
    record = _valid_record(_matrix())
    del record["subject"]["surface"]["pid"]
    with pytest.raises(ProbeRecordError, match="surface block is incomplete"):
        validate_record(record)
    record = _valid_record(_matrix())
    record["subject"]["probe_pid"] = "4242"
    with pytest.raises(ProbeRecordError, match="probe_pid"):
        validate_record(record)


def test_the_expected_instance_match_is_computed_not_declared():
    """Unit rows over the surface-dict builder: a mismatching expectation is
    False, an absent one is None, a matching one is True (round-1 test T-F4:
    hardcoded True survived). The validator recomputes: a False match is
    refused as not-the-subject, and a True declared over a mismatch is refused
    as declared rather than computed."""
    identity = {"instance": "0123456789abcdef", "pid": 7}
    assert probe._surface_identity(identity, 8710, "0123456789abcdef")["expected_instance_matches"] is True
    assert probe._surface_identity(identity, 8710, "fedcba9876543210")["expected_instance_matches"] is False
    assert probe._surface_identity(identity, 8710, None)["expected_instance_matches"] is None
    absent = probe._surface_identity(None, 8710, "0123456789abcdef")
    assert absent["expected_instance_matches"] is None and absent["reachable"] is False
    with pytest.raises(ProbeRecordError, match="not the expected"):
        validate_record(_valid_record(_matrix(), subject=_subject(
            expected_instance="fedcba9876543210", expected_instance_matches=False)))
    with pytest.raises(ProbeRecordError, match="computed, never declared"):
        validate_record(_valid_record(_matrix(), subject=_subject(
            expected_instance="fedcba9876543210", expected_instance_matches=True)))
    validate_record(_valid_record(_matrix(), subject=_subject(
        expected_instance="0123456789abcdef", expected_instance_matches=True)))


def test_a_self_pid_record_claiming_an_observed_memory_handle_is_refused():
    record = _valid_record(_matrix(), subject=_subject(pid=4242))  # the probe's own pid
    record["artefacts"] = [probe._observed("process_vm_read", "handle acquired")]
    with pytest.raises(ProbeRecordError, match="own pid"):
        validate_record(record)
    record["artefacts"] = [probe._not_applicable("process_vm_read", "self process")]
    validate_record(record)


def test_a_record_naming_the_host_in_the_clear_is_refused(monkeypatch: pytest.MonkeyPatch):
    """With the identity tokens set to synthetic values, a subject path that
    spells the home, the login or the machine name is refused."""
    monkeypatch.setattr(probe, "_identity_tokens",
                        lambda: (("/home/casey", "C:\\Users\\CASEY~1"), "casey", "WORKSTATION-7"))
    for leak in ("/home/casey/venv/bin/python", "C:\\Users\\CASEY~1\\python.exe",
                 "/opt/python by casey", "built on WORKSTATION-7"):
        record = _valid_record(_matrix())
        record["subject"]["sys_executable"] = leak
        with pytest.raises(ProbeRecordError, match="names the host in the clear"):
            validate_record(record)
    validate_record(_valid_record(_matrix()))


def test_a_fabricated_positive_control_is_refused_and_a_real_one_is_recorded(tmp_path: Path):
    """The control performed a REAL request: through the `exchange` seam, one
    bearered `GET /api/state` is observed, the token is not recorded, and
    admission is the status. A control claiming admission with no request, one
    whose admission disagrees with its status, and one not attempted yet
    carrying a status are each refused (round-1 test T-F5)."""
    token = secrets.token_urlsafe(32)
    session = tmp_path / "session.json"
    session.write_text(json.dumps({"token": token}), encoding="utf-8")
    calls: list[tuple] = []

    def exchange(host, port, method, path, *, body=None, headers=None, timeout=5.0):
        calls.append((host, port, method, path, headers))
        return 200, b"{}"

    control = probe._positive_control("127.0.0.1", 4321, session, 1.0, exchange=exchange)
    assert calls == [("127.0.0.1", 4321, "GET", "/api/state", {"Authorization": "Bearer " + token})]
    assert control["attempted"] is True and control["status"] == 200 and control["admitted"] is True
    assert token not in json.dumps(control)
    record = _valid_record(_matrix())
    record["positive_control"] = control
    validate_record(record)

    for fabricated in (
        {"attempted": True, "status": None, "admitted": True},
        {"attempted": True, "status": 401, "admitted": True, "request": control["request"]},
        {"attempted": False, "status": 200, "admitted": True},
    ):
        record["positive_control"] = fabricated
        with pytest.raises(ProbeRecordError, match="positive"):
            validate_record(record)
    missing = probe._positive_control("127.0.0.1", 4321, tmp_path / "absent.json", 1.0, exchange=exchange)
    assert missing == {"attempted": False, "status": None, "admitted": None,
                       "detail": "the session file does not exist"}
    assert len(calls) == 1  # no request without a bearer to present


# ---------------------------------------------------------------------------
# Redaction, pinned (A-025; round-1 architecture F6 / security P2-4).
# ---------------------------------------------------------------------------

def test_redaction_folds_every_spelling_of_home_and_removes_the_login_and_machine(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Synthetic tokens, so the pin is deterministic on every host: the long
    and the 8.3 short spelling of home both fold to `~`; the login and the
    machine name are removed wherever they occur; an unrelated path is left
    alone; the boundary holds (`/home/caseyx` is not `/home/casey`); and the
    result is idempotent. Then the REAL host's tokens as a known-positive
    control, and `_long_form` on a real 8.3 name where the volume makes one."""
    monkeypatch.setattr(probe, "_identity_tokens",
                        lambda: (("C:\\Users\\CASEY~1", "/home/casey", "C:\\Users\\casey"),
                                 "casey", "WORKSTATION-7"))
    assert probe.redact("/home/casey/venv/bin/python") == "~/venv/bin/python"
    assert probe.redact("C:\\Users\\casey\\venv\\python.exe") == "~\\venv\\python.exe"
    assert probe.redact("C:\\Users\\CASEY~1\\AppData\\Local\\Temp\\c-venv\\Scripts\\python.exe") == (
        "~\\AppData\\Local\\Temp\\c-venv\\Scripts\\python.exe")
    assert probe.redact("/home/casey") == "~"
    out = probe.redact("built on WORKSTATION-7 by Casey for casey")
    assert "WORKSTATION-7" not in out and "casey" not in out.lower()
    assert probe.redact("/opt/python/bin/python") == "/opt/python/bin/python"
    assert probe.redact("gate_runner") == "gate_runner"
    boundary = probe.redact("/home/caseyx/y")
    assert boundary.startswith("/home/") and "casey" not in boundary
    for text in ("/home/casey/x", "WORKSTATION-7", "C:\\Users\\CASEY~1\\x"):
        assert probe.redact(probe.redact(text)) == probe.redact(text)
    assert probe.redact(None) is None and probe.redact("") == ""
    monkeypatch.undo()

    # The real host: whatever this machine is called, the record cannot say.
    home = str(Path.home())
    assert probe.redact(home) == "~"
    assert probe.redact(os.path.join(home, "x")) == "~" + os.sep + "x"
    login, node = probe.getpass.getuser(), probe.platform.node()
    for token in (login, node):
        if token and len(token) >= 3:
            assert token.lower() not in probe.redact(f"built on {node} by {login}").lower()
    for form in probe._windows_path_forms(home):
        assert probe.redact(form + "\\x") == "~\\x", form
    long_dir = tmp_path / "LongDirectoryNameForShortForms"
    long_dir.mkdir()
    short_forms = [f for f in probe._windows_path_forms(str(long_dir)) if "~" in f]
    for short in short_forms:  # only where the volume generates 8.3 names (it does on the dev host)
        assert probe._long_form(short) == os.path.realpath(str(long_dir))
    assert probe._long_form(str(long_dir)) == os.path.realpath(str(long_dir))
    assert probe._long_form(None) is None


def test_the_redaction_backstop_matches_a_json_escaped_home_path(monkeypatch: pytest.MonkeyPatch):
    """ROUND-2 SECURITY P3-1: the validator's whole-record backstop runs over
    `json.dumps(record)`, in which every Windows separator is DOUBLED -- and
    the home pattern was built with single separators, so a home path inside
    a nested JSON string walked straight past it. The rule is now the one
    `tests/test_independent_inspection.py::_identity_leaks` uses for the same
    reason: one separator, or two.

    KNOWN POSITIVES first, so the instrument is falsified before it is
    trusted: the raw spelling folds (it always did), the doubled spelling
    folds (it did not), and a record carrying a doubled home path in any field
    is REFUSED. KNOWN NEGATIVE: an unrelated doubled path is left alone."""
    monkeypatch.setattr(probe, "_identity_tokens",
                        lambda: (("C:\\Users\\CASEY~1", "C:\\Users\\casey", "/home/casey"),
                                 "casey", "WORKSTATION-7"))
    raw = "C:\\Users\\casey\\venv\\python.exe"
    escaped = raw.replace("\\", "\\\\")
    assert probe.redact(raw) == "~\\venv\\python.exe"
    assert probe.redact(escaped) == "~\\\\venv\\\\python.exe", probe.redact(escaped)
    assert "casey" not in probe.redact(escaped).lower()
    assert probe.redact("C:\\\\Users\\\\CASEY~1\\\\AppData") == "~\\\\AppData"
    assert probe.redact("/home/casey/x") == "~/x"
    assert probe.redact(probe.redact(escaped)) == probe.redact(escaped)  # still idempotent
    assert probe.redact("C:\\\\Tools\\\\bin") == "C:\\\\Tools\\\\bin"  # known negative
    # THE BACKSTOP, on a whole record: the leak is inside a nested JSON string,
    # which is the shape `json.dumps` produces and the shape that got through.
    record = _valid_record(_matrix())
    record["subject"]["nornyx_forge_origin"] = raw
    assert "\\\\Users\\\\casey" in json.dumps(record), "the fixture is not the doubled shape"
    with pytest.raises(ProbeRecordError, match="names the host in the clear"):
        validate_record(record)
    # And the same leak one level down, inside a value that is itself JSON.
    record = _valid_record(_matrix())
    record["subject"]["principal"] = dict(record["subject"]["principal"],
                                          detail=json.dumps({"exe": raw}))
    with pytest.raises(ProbeRecordError, match="names the host in the clear"):
        validate_record(record)


def test_no_host_derived_spelling_survives_in_the_probe_module():
    """A-025 / round-2 security P3-2: this host's own 8.3 profile spelling --
    the login plus three characters of the machine name -- was committed in
    two docstrings of `probe_control_plane.py` as the EXAMPLE of the form the
    redaction exists to remove. A placeholder does that job; the real one is a
    host identity in committed text, which is the thing forbidden.

    Anchored on `module.__file__`, so it sweeps the source that is imported
    rather than a path this test recomputes, and it sweeps THIS module too --
    the placeholder shapes here must be placeholders as well. The patterns
    include the 8.3 forms: `<LOGIN>~1` for a login of three characters or
    more, and `~1.<MACHINE-prefix>` for the first three characters of the
    machine name -- the shape that was committed.

    SEGMENTS, NEVER BARE SUBSTRINGS, for the long spellings -- the same
    correction `_identity_leaks` carries: on a GitHub runner the login is
    `runner`, and this very module contains `gate_runner`, so a bare-substring
    sweep would be red on every CI interpreter over a file that leaks
    nothing. The 8.3 forms have no such problem and are matched as they are.
    """
    sources = {Path(probe.__file__): "the probe module", Path(__file__): "this test module"}
    login, node = probe.getpass.getuser(), probe.platform.node()
    assert Path(probe.__file__).name == "probe_control_plane.py"
    patterns = []
    for label, name in (("login", login), ("machine name", node)):
        if len(name) >= 3:
            patterns.append((f"the reader's {label} as a path segment", re.compile(
                r"[\\/]{1,2}" + re.escape(name) + r"(?=[\\/]{1,2}|[.\"'\s]|$)", re.I)))
    if len(node) >= 3:
        patterns.append(("the reader's machine name as the machine half of a profile folder",
                         re.compile(r"[\\/]{1,2}[A-Za-z0-9_-]+\." + re.escape(node)
                                    + r"(?=[\\/]{1,2}|[\"'\s]|$)", re.I)))
    if len(login) >= 3:
        patterns.append(("the reader's login in 8.3 short form",
                         re.compile(re.escape(login[:6]) + r"~\d", re.I)))
    if len(node) >= 3:
        patterns.append(("the reader's machine name as an 8.3 profile suffix",
                         re.compile(r"~\d\." + re.escape(node[:3]), re.I)))
    assert len(patterns) >= 2, "this host has no login or machine name long enough to sweep for"
    for path, what in sources.items():
        text = path.read_text(encoding="utf-8")
        for label, pattern in patterns:
            found = pattern.search(text)
            assert not found, f"{what} names {label}: {found.group(0)!r} at offset {found.start()}"
    # KNOWN POSITIVES: the sweep fires on the shapes it exists to catch, in
    # both the raw and the doubled-separator spelling.
    for specimen in (f"an interpreter under C:\\Users\\{login[:6]}~1.{node[:3]}\\python.exe",
                     f"an interpreter under C:\\\\Users\\\\{login[:6]}~1.{node[:3]}\\\\python.exe",
                     f"a home at /home/{login}/venv", f"a profile at C:\\Users\\x.{node}\\v"):
        assert any(pattern.search(specimen) for _label, pattern in patterns), specimen
    # KNOWN NEGATIVE: the placeholder the module uses is not a hit here.
    assert not any(pattern.search("C:\\Users\\DEVUSER~1.BOX\\python.exe")
                   for _label, pattern in patterns), "the placeholder collides with this host"


# ---------------------------------------------------------------------------
# The artefact producers, pinned (round-1 test T-F2).
# ---------------------------------------------------------------------------

def test_the_path_read_artefacts_observe_a_present_file_and_degrade_on_a_missing_one(tmp_path: Path):
    present = tmp_path / "runtime.json"
    present.write_bytes(b"0123456789")
    observed = probe._artefact_path_read("runtime_record", present)
    assert observed == {"name": "runtime_record", "outcome": ARTEFACT_OBSERVED, "mechanism": MECH_ACL,
                        "detail": "readable by this principal (10 bytes)"}
    assert capability_acquired(observed) is True
    missing = probe._artefact_path_read("runtime_log", tmp_path / "absent.log")
    assert missing["outcome"] == ARTEFACT_NOT_APPLICABLE and "does not exist" in missing["detail"]
    unsupplied = probe._artefact_path_read("runtime_log", None)
    assert unsupplied["outcome"] == ARTEFACT_NOT_APPLICABLE and "no path supplied" in unsupplied["detail"]


def test_a_present_artefact_this_principal_cannot_open_is_refused_not_observed(tmp_path: Path):
    """ROUND-2 TEST F-3, branch one. A file that EXISTS and whose `open` raises
    is a denial, not a capability, and it used to record `observed` -- the same
    machine-readable word as a real read, with the reason buried in prose.

    THE OS PRODUCES THE ERROR, not a stub: `open(<a directory>, "rb")` raises
    `PermissionError` on Windows and `IsADirectoryError` on POSIX, both
    `OSError`, so the refusal branch is reached the way a locked artefact
    reaches it and no monkeypatch decides the outcome. `capability_acquired`
    is False for it, and the validator refuses the collapse back to
    `observed`."""
    unopenable = tmp_path / "present-but-not-a-file"
    unopenable.mkdir()
    refused = probe._artefact_path_read("runtime_record", unopenable)
    assert refused["outcome"] == ARTEFACT_REFUSED, refused
    assert refused["mechanism"] == MECH_ACL
    assert "present but not readable by this principal" in refused["detail"], refused
    assert refused["detail"].split(": ")[-1].endswith("Error"), refused
    assert capability_acquired(refused) is False
    # The collapse this replaces: the same fact under the acquired word.
    collapsed = dict(refused, outcome=ARTEFACT_OBSERVED)
    record = _valid_record(_matrix())
    record["artefacts"] = [collapsed]
    with pytest.raises(ProbeRecordError, match="records a denial"):
        validate_record(record)
    record["artefacts"] = [refused]
    validate_record(record)  # the refusal itself is a legitimate record
    # And a refusal that does not say so is refused too: the word and the
    # sentence have to agree in both directions.
    record["artefacts"] = [dict(refused, detail="present by this principal (10 bytes)")]
    with pytest.raises(ProbeRecordError, match="does not say it was refused"):
        validate_record(record)


def test_the_seal_dir_listing_observes_a_present_dir_and_degrades_on_a_missing_one(tmp_path: Path):
    seals = tmp_path / "seals"
    seals.mkdir()
    (seals / "a.seal").write_text("x", encoding="utf-8")
    (seals / "b.seal").write_text("y", encoding="utf-8")
    listed = probe._seal_dir_listing(seals)
    assert listed["outcome"] == ARTEFACT_OBSERVED
    assert listed["detail"] == "listable by this principal (2 entries)"
    absent = probe._seal_dir_listing(tmp_path / "no-seals")
    assert absent["outcome"] == ARTEFACT_NOT_APPLICABLE and "does not exist" in absent["detail"]
    assert probe._seal_dir_listing(None)["outcome"] == ARTEFACT_NOT_APPLICABLE
    # A directory that exists and cannot be listed is the same fact as a file
    # that exists and cannot be opened: `refused`, not "not applicable".
    not_a_dir = tmp_path / "not-a-directory"
    not_a_dir.write_bytes(b"x")
    denied = probe._seal_dir_listing(not_a_dir)
    assert denied["outcome"] == ARTEFACT_REFUSED, denied
    assert "present but not listable by this principal" in denied["detail"], denied
    assert capability_acquired(denied) is False


def test_the_command_line_channel_digests_a_nonce_and_never_records_it_raw():
    """Through the query seam: a synthetic browser command line carrying a real
    `token_urlsafe(32)` fragment yields a `sha256:` prefix of that nonce in the
    detail and the raw nonce nowhere; no lines, an unavailable query and an
    off-Windows platform each degrade to `not_applicable` with the reason."""
    nonce = secrets.token_urlsafe(32)
    line = ('"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --single-argument '
            f"http://127.0.0.1:8710/#{nonce}")
    artefact = probe._browser_handler_cmdline(query=lambda timeout: [line], platform_name="win32")
    digest = "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()[:12]
    assert artefact["outcome"] == "observed" and digest in artefact["detail"], artefact
    assert "1 browser command line" in artefact["detail"]
    assert nonce not in json.dumps(artefact) and nonce[:16] not in json.dumps(artefact)
    assert probe._digest_fragments([line]) == [digest]
    empty = probe._browser_handler_cmdline(query=lambda timeout: [], platform_name="win32")
    assert empty["outcome"] == "not_applicable" and "no browser handler" in empty["detail"]

    def unavailable(timeout):
        raise probe._QueryUnavailable("powershell.exe was not found under SystemRoot")

    down = probe._browser_handler_cmdline(query=unavailable, platform_name="win32")
    assert down["outcome"] == "not_applicable" and "not found under SystemRoot" in down["detail"]
    off = probe._browser_handler_cmdline(query=lambda timeout: [line], platform_name="linux")
    assert off["outcome"] == "not_applicable" and "Windows facility" in off["detail"]
    # The raw line, had it been recorded, is what the validator's secret check refuses.
    with pytest.raises(ProbeRecordError, match="credential-shaped"):
        probe._refuse_embedded_secret(json.dumps({"detail": line}))


def test_the_history_channel_reads_a_present_store_and_degrades_on_an_absent_one(tmp_path: Path):
    """A fake `LOCALAPPDATA` tree drives the Windows branch on every host."""
    store = tmp_path / "Google" / "Chrome" / "User Data" / "Default" / "History"
    store.parent.mkdir(parents=True)
    store.write_bytes(b"SQLite format 3\0")
    present = probe._browser_history(local_appdata=str(tmp_path), platform_name="win32")
    assert present["outcome"] == ARTEFACT_OBSERVED
    assert present["detail"] == "1 of 1 present history store(s) readable by this principal"
    absent = probe._browser_history(local_appdata=str(tmp_path / "empty"), platform_name="win32")
    assert absent["outcome"] == ARTEFACT_NOT_APPLICABLE and "no measured history store" in absent["detail"]
    unset = probe._browser_history(local_appdata="", platform_name="win32")
    assert unset["outcome"] == ARTEFACT_NOT_APPLICABLE and "LOCALAPPDATA is unset" in unset["detail"]
    off = probe._browser_history(local_appdata=str(tmp_path), platform_name="linux")
    assert off["outcome"] == ARTEFACT_NOT_APPLICABLE and "Windows paths" in off["detail"]
    # A store that is PRESENT and opens for nobody is a denial, not a read:
    # `0 of 1 ... readable` used to carry the acquired word (round-2 test F-3).
    denied_root = tmp_path / "denied"
    denied_store = denied_root / "Google" / "Chrome" / "User Data" / "Default" / "History"
    denied_store.mkdir(parents=True)  # exists, and `open` on it raises
    denied = probe._browser_history(local_appdata=str(denied_root), platform_name="win32")
    assert denied["outcome"] == ARTEFACT_REFUSED, denied
    assert "denied every one" in denied["detail"] and capability_acquired(denied) is False


def test_the_memory_handle_degrades_on_the_self_pid_and_on_a_missing_process():
    """The self rule first, on every platform; then a pid that names no process
    is `not_applicable` with `no such process` on Windows and `Windows
    facility` elsewhere -- never `observed`.

    THE MISSING PID IS 0, the System Idle Process, which `OpenProcess` refuses
    with ERROR_INVALID_PARAMETER by documented contract -- the same code and
    branch a pid that names no process reaches. Two drafts were falsified on
    this host before this one. The first spawned a child, let it exit and used
    its pid: under a concurrent pytest session that pid was RECYCLED by a new
    same-user process before the call and the handle was acquired on the
    newcomer (measured once in 24 runs). The second used an odd id on the
    premise that process ids are multiples of four: measured, `OpenProcess`
    ignores the low two bits and an odd id OPENS the neighbouring live
    process. Neither precondition held; pid 0 depends on nothing scheduled."""
    own = probe._process_vm_read(os.getpid(), probe_pid=os.getpid())
    assert own["outcome"] == ARTEFACT_NOT_APPLICABLE and "self process" in own["detail"], own
    assert probe._process_vm_read(None, probe_pid=os.getpid())["outcome"] == ARTEFACT_NOT_APPLICABLE
    nobody = 0  # the System Idle Process: never openable, by contract
    missing = probe._process_vm_read(nobody, probe_pid=os.getpid())
    assert missing["outcome"] == ARTEFACT_NOT_APPLICABLE, missing
    if sys.platform == "win32":
        assert "no such process" in missing["detail"] and "error 87" in missing["detail"], missing
        assert str(probe._ERROR_INVALID_PARAMETER) == "87"
    else:
        assert "Windows facility" in missing["detail"], missing
    forced_off = probe._process_vm_read(nobody, probe_pid=os.getpid(), platform_name="linux")
    assert forced_off["outcome"] == ARTEFACT_NOT_APPLICABLE and "Windows facility" in forced_off["detail"]


def test_the_memory_handle_maps_every_open_process_outcome_and_a_denial_is_refused():
    """ROUND-2 TEST F-3, branch two, plus round-2 architecture F-E.

    `OpenProcess` failing with ERROR_ACCESS_DENIED on a LIVE process is the
    interesting negative -- the process is there and this principal may not
    read its memory -- and it recorded `observed`, the word for the capability
    it is the absence of. `_ERROR_ACCESS_DENIED` was a constant nothing read.
    Now: a handle is `observed`, error 5 is `refused`, error 87 (a pid that
    names no process) stays `not_applicable`, and any other failure is
    `refused`.

    DRIVEN THROUGH THE `open_process` SEAM, because the ACCESS_DENIED branch
    depends on the host's privileges and a branch only some hosts reach is a
    branch no CI run holds. The REAL call is exercised below on pid 4, which
    degrades rather than skipping -- a skip in this module would fail the
    windows-runtime job's no-skip census."""
    mapping = {
        (0x1234, 0): (ARTEFACT_OBSERVED, "handle acquired"),
        (0, probe._ERROR_ACCESS_DENIED): (ARTEFACT_REFUSED, "ERROR_ACCESS_DENIED"),
        (0, probe._ERROR_INVALID_PARAMETER): (ARTEFACT_NOT_APPLICABLE, "no such process"),
        (0, 6): (ARTEFACT_REFUSED, "error 6"),
    }
    for (handle, error), (outcome, fragment) in mapping.items():
        artefact = probe._process_vm_read(
            4321, probe_pid=os.getpid(), platform_name="win32",
            open_process=lambda pid, _r=(handle, error): _r)
        assert artefact["outcome"] == outcome, (handle, error, artefact)
        assert fragment in artefact["detail"], artefact
        assert artefact["mechanism"] == MECH_ACL
        assert capability_acquired(artefact) is (outcome == ARTEFACT_OBSERVED)
    denied = probe._process_vm_read(4321, probe_pid=os.getpid(), platform_name="win32",
                                    open_process=lambda pid: (0, probe._ERROR_ACCESS_DENIED))
    assert "may not open it" in denied["detail"], denied
    # The collapse this replaces, refused by the validator.
    record = _valid_record(_matrix())
    record["artefacts"] = [dict(denied, outcome=ARTEFACT_OBSERVED)]
    with pytest.raises(ProbeRecordError, match="records a denial"):
        validate_record(record)
    record["artefacts"] = [denied]
    validate_record(record)
    # A raised call is still not a pass.
    def raising(pid):
        raise OSError("no ctypes here")

    broken = probe._process_vm_read(4321, probe_pid=os.getpid(), platform_name="win32",
                                    open_process=raising)
    assert broken["outcome"] == ARTEFACT_NOT_APPLICABLE and "could not be attempted" in broken["detail"]


def test_the_real_open_process_on_a_system_pid_is_refused_not_observed():
    """The REAL Win32 call against a real process this principal should not be
    able to open: pid 4, the System process, whose token the kernel protects.

    DEGRADES, NEVER SKIPS. A `pytest.skip` here would be a declared skip in a
    module the windows-runtime job runs under a no-skip census, so both arms
    ASSERT instead. Off Windows the facility is absent and the artefact is
    `not_applicable`; on Windows the host decides which of the three outcomes
    the call reaches -- `observed` if it grants the handle (an elevated runner
    with SeDebugPrivilege), `refused` if it denies it, `not_applicable` if pid
    4 somehow names no process -- and each is held to the detail that goes with
    it. The one shape that may never appear is `observed` beside a detail
    saying it was denied, which is what the validator refuses below."""
    artefact = probe._process_vm_read(4, probe_pid=os.getpid())
    assert artefact["outcome"] in ARTEFACT_OUTCOMES, artefact
    assert artefact["mechanism"] == MECH_ACL
    if sys.platform != "win32":
        assert artefact["outcome"] == ARTEFACT_NOT_APPLICABLE
        assert "Windows facility" in artefact["detail"], artefact
    elif capability_acquired(artefact):
        assert "handle acquired" in artefact["detail"], artefact
    elif artefact["outcome"] == ARTEFACT_REFUSED:
        assert "pid 4" in artefact["detail"], artefact
    else:
        assert "no such process" in artefact["detail"], artefact
    record = _valid_record(_matrix())
    record["artefacts"] = [artefact]
    validate_record(record)


def _sid_from_this_process_token() -> str:
    """This process's user SID, asked of the OS through the token API.

    An INDEPENDENT oracle for what `_principal` reports. It shares no code and
    no mechanism with the thing it checks: `_principal` starts `whoami.exe` and
    matches a regex over its stdout, while this reads the access token of the
    running process and asks Windows itself to format the SID. Re-running
    `whoami` with different flags would have been the obvious oracle and is a
    weaker one -- same command, same parser family, and this module's own
    `test_the_harness_runs_no_provider_and_starts_no_synchronous_launch`
    forbids starting any executable here but `sys.executable`, a rule worth
    more than the convenience of breaking it.

    Windows only; called only under `sys.platform == "win32"`. Written against
    `ctypes` primitives rather than `ctypes.wintypes`, which does not import on
    the Linux leg of the matrix where this module also runs.
    """
    handle = ctypes.c_void_p
    dword = ctypes.c_ulong
    token_query, token_user_class = 0x0008, 1
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
    advapi32.GetTokenInformation.argtypes = [handle, ctypes.c_int, ctypes.c_void_p,
                                             dword, ctypes.POINTER(dword)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_wchar_p)]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    token = handle()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query,
                                     ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        size = dword()
        advapi32.GetTokenInformation(token, token_user_class, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, token_user_class, buffer, size,
                                            ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        # TOKEN_USER is a SID_AND_ATTRIBUTES: the SID pointer comes first.
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
        try:
            return text.value
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def test_system_executables_are_resolved_absolutely_and_never_from_the_cwd(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`powershell.exe` and `whoami.exe` are found under `%SystemRoot%` at the
    location they ship in, else on a DRIVE-ABSOLUTE `PATH` entry, and never in
    the working directory -- a planted copy there is not chosen even when the
    search finds nothing else (round-1 security P3-3).

    DRIVE-absolute, not `os.path.isabs` (round-2 security P4-4): on Windows
    `\\tools` is "absolute" and means `tools` from the root of the CURRENT
    drive, which the working directory chooses -- so a root-relative entry
    handed the choice back to the place this walk exists to avoid.

    THE PREDICATE IS PINNED AS A TABLE, both arms, every interpreter (round-3
    CI). The round-3 spelling asserted a handful of rows and left the rest to
    the stdlib, and went red on TWO jobs at TWO DIFFERENT rows: on
    `windows-runtime` (3.13) at `_is_drive_absolute("/usr/bin",
    platform_name="linux")`, and on `test (3.10)` at
    `_is_drive_absolute("\\\\server\\share", platform_name="win32")`. One
    helper, two interpreters, two answers -- because `os.path` IS `ntpath` on
    Windows, `ntpath.isabs` stopped calling a root-relative path absolute at
    3.13, and `ntpath.splitdrive` leaves a UNC share with an empty tail on
    3.10. The table below is asserted on BOTH `platform_name` arms on EVERY
    interpreter, and then asserted a SECOND time with every stdlib path
    predicate replaced by one that raises: the rule answers by construction,
    not by a measurement taken on whichever host happened to run it."""
    planted = tmp_path / "cwd"
    planted.mkdir()
    for name in ("powershell.exe", "whoami.exe"):
        (planted / name).write_bytes(b"")
    monkeypatch.chdir(planted)
    nowhere = {"SystemRoot": str(tmp_path / "missing"), "PATH": os.pathsep.join(["", ".", "relative"])}
    assert probe._system_executable("powershell.exe", environ=nowhere) is None
    assert probe._system_executable("whoami.exe", environ=nowhere) is None
    # The root-relative entry, on both platform arms, with a REAL planted copy
    # at the place it would resolve to. `tail` is the same location spelled
    # without its volume, and it is rooted by ONE separator on every host:
    # `\pytest-of-...\cwd` where a drive was stripped, `/tmp/.../cwd` where
    # there was no drive to strip.
    drive, tail = os.path.splitdrive(str(planted))
    root_relative = tail if drive else str(planted)
    windows_rows = [
        (root_relative, False),     # the planted location, spelled without its volume
        ("C:\\tools", True),        # drive-rooted
        ("C:/tools", True),         # drive-rooted; Windows takes either separator
        ("C:tools", False),         # drive-RELATIVE: the current directory ON C: completes it
        ("\\\\server\\share", True),  # UNC: the share names the volume
        ("\\\\?\\C:\\x", True),     # extended-length/device prefix: two separators, then `?`
        ("\\\\\\srv", False),       # THREE separators is not a UNC prefix
        ("\\tools", False),         # root-relative: the CURRENT DRIVE completes it
        ("/tools", False),          # the same, in the spelling Windows also accepts
        ("tools", False),           # relative
        ("", False),                # the empty `PATH` entry, which means the cwd
    ]
    posix_rows = [
        ("/usr/bin", True),
        ("usr/bin", False),
        ("C:\\tools", False),       # a drive letter names no volume off Windows
        ("\\usr\\bin", False),      # nor does a backslash root
        ("", False),
    ]

    def verdicts():
        return ([probe._is_drive_absolute(entry, platform_name="win32") for entry, _ in windows_rows],
                [probe._is_drive_absolute(entry, platform_name="linux") for entry, _ in posix_rows])

    windows_said, posix_said = verdicts()
    assert windows_said == [expected for _, expected in windows_rows], list(zip(windows_rows, windows_said))
    assert posix_said == [expected for _, expected in posix_rows], list(zip(posix_rows, posix_said))
    assert all(said is True or said is False for said in windows_said + posix_said), "bool, not truthy"
    # AND THE ANSWERS DO NOT COME FROM THE STDLIB. Every path predicate that
    # could have supplied one is replaced by a function that raises -- both
    # modules, because `os.path` IS one of them (`ntpath` on Windows,
    # `posixpath` elsewhere) -- and the whole table is asked again and comes
    # back IDENTICAL. The two interpreters that went red in round 3 are not
    # available on any single host, so this is the only way to establish
    # interpreter-independence rather than to sample it.
    with monkeypatch.context() as sealed:
        def refuse(*_args, **_kwargs):
            raise AssertionError("_is_drive_absolute consulted a stdlib path predicate")

        for module in (ntpath, posixpath):
            for attribute in ("isabs", "splitdrive", "splitroot", "abspath", "normpath"):
                if hasattr(module, attribute):
                    sealed.setattr(module, attribute, refuse)
        sealed_windows, sealed_posix = verdicts()
    assert sealed_windows == windows_said, list(zip(windows_rows, sealed_windows))
    assert sealed_posix == posix_said, list(zip(posix_rows, sealed_posix))
    root_relative_env = {"SystemRoot": str(tmp_path / "missing"), "PATH": root_relative}
    assert probe._system_executable("whoami.exe", environ=root_relative_env,
                                    platform_name="win32") is None, (
        "a PATH entry the current drive completes was admitted")
    # KNOWN POSITIVE, unconditional. First: the entry just refused DOES resolve
    # to the planted copy -- on Windows the CURRENT DRIVE completes `\...` and
    # the cwd is inside `tmp_path`, so it is that drive; off Windows the
    # spelling is the path itself. Asked of the FILESYSTEM, because
    # `os.path.isabs` -- which is what round 3 asked -- gives a different
    # answer for this very string on 3.12 and on 3.13.
    assert (Path(root_relative) / "whoami.exe").is_file(), root_relative
    # Second: the SAME directory, spelled the way this host's own arm admits,
    # IS found by the same walk. So what excluded it above was the predicate
    # and not a missing file.
    found = probe._system_executable(
        "whoami.exe", environ={"SystemRoot": str(tmp_path / "missing"), "PATH": str(planted)},
        platform_name=sys.platform)
    assert found == str(planted / "whoami.exe"), found
    root = tmp_path / "root"
    powershell = root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    powershell.write_bytes(b"")
    whoami = root / "System32" / "whoami.exe"
    whoami.write_bytes(b"")
    assert probe._system_executable("powershell.exe", environ={"SystemRoot": str(root), "PATH": ""}) == str(powershell)
    assert probe._system_executable("whoami.exe", environ={"SystemRoot": str(root)}) == str(whoami)
    alt = tmp_path / "alt"
    alt.mkdir()
    (alt / "whoami.exe").write_bytes(b"")
    assert probe._system_executable("whoami.exe", environ={"PATH": str(alt)}) == str(alt / "whoami.exe")
    monkeypatch.setattr(probe, "_system_executable",
                        lambda name, environ=None, platform_name=sys.platform: None)
    with pytest.raises(probe._QueryUnavailable, match="not found under SystemRoot"):
        probe._run_system("powershell.exe", ["-Command", "1"], 5.0)
    # Round-2 test F-6: this read `... is None or sys.platform != "win32"`, and
    # the left side is true on EVERY platform (off Windows `_principal` records
    # a uid and leaves `sid` None), so the disjunct asserted nothing and the
    # test would have stayed green with the Windows branch gone. One assertion,
    # no escape hatch: with no executable to find, no SID is read anywhere.
    unfindable = probe._principal()
    assert unfindable["sid"] is None, unfindable
    assert unfindable["platform"] == sys.platform
    monkeypatch.undo()
    if sys.platform == "win32":
        found = probe._system_executable("whoami.exe")
        assert found and os.path.isabs(found)
        assert found.lower().startswith(os.environ["SystemRoot"].lower())
        # ROUND-3 P3: `startswith("S-1-")` is a SHAPE, and a shape is satisfied
        # by a constant. A `_principal` that returned a hardcoded `S-1-...`,
        # and one that INVENTED a SID when the regex matched nothing, both
        # passed that assertion -- so what was pinned was the spelling of the
        # answer and not the reading of it. The OS is asked here by a route
        # that shares no code with the one under test: the running process's
        # own access token, formatted by Windows, against `whoami` stdout
        # matched by a regex. The two answers must be EQUAL, so a constant is
        # red unless it happens to be this host's own SID -- which is the
        # answer being asked for. Nothing about this host is written down: the
        # expected value is read from the OS at run time, never committed.
        os_sid = _sid_from_this_process_token()
        assert os_sid.startswith("S-1-") and os_sid.count("-") >= 4, (
            "the token answered no SID, so this comparison would compare nothing")
        assert probe._principal()["sid"] == os_sid, (
            "`_principal` did not report the SID the OS reports for this process")
        # ... and the no-match branch must RECORD NOTHING. Inventing a SID
        # there survived every assertion above, because on a real host the
        # regex always matches and the branch never runs. Given a command that
        # answers WITHOUT a SID, `sid` is None or this is not a read.
        monkeypatch.setattr(
            probe, "_run_system",
            lambda name, args, timeout: subprocess.CompletedProcess(
                [name, *args], 0, stdout="USER INFORMATION\n---\nno sid here\n", stderr=""))
        assert probe._principal() == {"platform": "win32", "sid": None, "uid": None}
        monkeypatch.undo()


# ---------------------------------------------------------------------------
# The host rule, the deadline, and the CLI.
# ---------------------------------------------------------------------------

def test_a_non_loopback_host_is_refused_by_name(capsys: pytest.CaptureFixture,
                                                monkeypatch: pytest.MonkeyPatch):
    """`--host` must be loopback: a documentation address, a LAN address, the
    wildcard and a hostname are refused with `NonLoopbackHostError` before any
    socket opens (no port is even needed); `main()` turns it into exit 4 on
    stderr. Loopback spellings are admitted without name resolution, and
    `localhost` is NORMALISED to the address it names (round-2 security P4-1):
    admitting a NAME and then connecting by it leaves the destination to the
    resolver and to a `hosts` file an administrator can write, so the rule
    would decide the spelling and not the destination. What the function
    returns is what `probe()` connects to."""
    for host in ("127.0.0.1", "127.0.0.2", "::1"):
        assert probe.require_loopback(host) == host
    assert probe.require_loopback("localhost") == "127.0.0.1" == probe._ONBOARDING_HOST
    for host in ("203.0.113.7", "10.0.0.1", "0.0.0.0", "192.168.1.20", "example.com", "", "::"):
        with pytest.raises(NonLoopbackHostError, match="not a loopback address"):
            probe.require_loopback(host)
        with pytest.raises(NonLoopbackHostError):
            probe.probe(1, host=host)
    assert probe.main(["--port", "1", "--host", "203.0.113.7"]) == probe.EXIT_REFUSED == 4
    captured = capsys.readouterr()
    assert "refused" in captured.err and "203.0.113.7" in captured.err and captured.out == ""
    assert captured.err.count("\n") == 1, "a refusal is ONE line"
    # `localhost` reaches a socket, not a resolver: pointed at a port nothing
    # serves, it produces the same absent-surface record 127.0.0.1 does.
    _without_the_cim_query(monkeypatch)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()
    # ROUND-3 P3: every assertion below is blind to the normalisation. Discard
    # `require_loopback`'s RETURN VALUE inside `probe()` -- keep the call, so
    # the refusals above still fire -- and `localhost` travels all the way to
    # the socket unchanged, producing exactly this record, because a dead port
    # is a dead port under either spelling. The rule's whole point is that the
    # DESTINATION is decided here rather than left to a resolver and to a
    # `hosts` file an administrator can write, so the discriminator has to be
    # the transport: a spy on the connection factory records the host each
    # exchange actually opens, and it must be the address, never the name.
    opened_hosts: list[str] = []
    real_connection = probe.http.client.HTTPConnection

    def _spy_on_the_transport(connect_host, *args, **kwargs):
        opened_hosts.append(connect_host)
        return real_connection(connect_host, *args, **kwargs)

    monkeypatch.setattr(probe.http.client, "HTTPConnection", _spy_on_the_transport)
    # Bounded at 3 s: a refused connection is not instant on Windows (measured
    # ~0.15 s each, so the whole matrix against a dead port is ~20 s), and what
    # this asserts is the destination, not the coverage.
    record = probe.probe(dead_port, host="localhost", timeout=0.2, deadline=3.0, root=ROOT)
    assert opened_hosts, "the probe opened no connection, so the spy measured nothing"
    assert set(opened_hosts) == {"127.0.0.1"}, (
        "the transport was handed the NAME the operator typed, not the loopback "
        f"address `require_loopback` returned: {sorted(set(opened_hosts))}")
    assert record["classification"] == "inconclusive"
    assert record["subject"]["surface"]["reachable"] is False
    assert record["coverage"]["answered_cells"] == 0
    validate_record(record)


def test_a_black_holed_surface_ends_the_probe_at_the_deadline_as_inconclusive():
    """A listener that accepts and never answers: with a 0.5 s socket timeout
    and a 2 s deadline the probe returns in a few seconds, not the 133 x 0.5 s
    the per-request timeouts alone would allow, and records `inconclusive`
    with the deadline in the reason, the unreached cells unattempted, the
    artefact reads and the positive control skipped (round-1 architecture F2,
    test T-F7)."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    held: list[socket.socket] = []
    stop = threading.Event()

    def swallow() -> None:
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
                held.append(connection)
            except socket.timeout:
                continue
            except OSError:
                return

    thread = threading.Thread(target=swallow, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        record = probe.probe(port, timeout=0.5, deadline=2.0, root=ROOT)
        wall = time.monotonic() - started
    finally:
        stop.set()
        thread.join(5)
        listener.close()
        for connection in held:
            connection.close()
    # THE OVERSHOOT BOUND (round-2 security P3-3 / test F-4). `wall < 8.0` was
    # slack enough to hide the whole defect: with `Deadline.budget` unpinned
    # the effective bound was the deadline PLUS the longest single timeout
    # still to run -- 60 s on the `Get-CimInstance` query and 30 s on each
    # subject-binding subprocess. The bound is the deadline, plus the ONE
    # request in flight when it expired, plus the tail every operation after
    # the expiry is clamped to (`Deadline.FLOOR_S` each, for the two
    # subject-binding subprocesses, beside the interpreter digest). Measured
    # on the development host: 2.1 s against a 2.0 s deadline.
    tail = 2 * probe.Deadline.FLOOR_S + 0.5
    assert wall < 2.0 + 0.5 + tail, (wall, tail)
    assert record["classification"] == "inconclusive"
    assert record["deadline_exceeded"] is True and "deadline of 2 s exceeded" in record["deadline_note"]
    assert "deadline of 2 s exceeded" in record["classification_reason"]
    assert "any expiry of the deadline" in record["classification_reason"].lower()
    unattempted = [r for r in record["requests"] if r["attempted"] is False]
    assert unattempted and all(r["status"] is None and "deadline" in r["detail"] for r in unattempted)
    assert record["coverage"]["answered_cells"] == 0
    assert record["reopen_pull_status"] is None
    assert all(a["outcome"] == ARTEFACT_NOT_APPLICABLE and "deadline" in a["detail"]
               for a in record["artefacts"])
    assert record["artefacts_truncated"] == len(record["artefacts"]) == 6
    validate_record(record)
    with pytest.raises(ValueError, match="positive number"):
        probe.Deadline(0)


def test_a_deadline_expiring_after_the_matrix_is_recorded_counted_and_inconclusive(
        monkeypatch: pytest.MonkeyPatch):
    """ROUND-2 ARCHITECTURE F-B, reproduced and closed. `deadline_exceeded`
    was set only inside the matrix loop, so a deadline expiring AFTER the
    matrix -- during the reads that follow -- left it FALSE beside artefact
    rows saying "not attempted: the deadline was exceeded", and the validator
    accepted a confinement-shaped state over evidence that was never gathered
    (measured at 133/133 answered).

    Here the clock is spent by an artefact read, not by the matrix: the record
    is complete on the wire and short of every read after the first. What must
    be true: `deadline_exceeded` is true, `artefacts_truncated` counts the
    reads that were cut off and the validator RECOMPUTES it from the artefacts
    themselves, and the classification is `inconclusive` at full coverage --
    the documented choice between the two candidate repairs, taken as both.

    The choice is deliberate. The alternative -- keeping the state and
    renaming the flag -- leaves a reader to decide which missing evidence
    mattered, and this record exists so that nobody has to."""
    app_deadline = 3.0
    rows = _matrix()

    def spend_the_clock(name, path):
        time.sleep(app_deadline)
        return probe._not_applicable(name, "the artefact does not exist on this host")

    monkeypatch.setattr(probe, "_artefact_path_read", spend_the_clock)
    monkeypatch.setattr(probe, "_request_fact",
                        lambda host, port, method, path, timeout: next(
                            r for r in rows if (r["method"], r["path"]) == (method, path)))
    monkeypatch.setattr(probe, "_runtime_identity", lambda host, port, timeout: None)
    monkeypatch.setattr(probe, "_exchange", lambda *a, **kw: (None, b""))
    _without_the_cim_query(monkeypatch)

    record = probe.probe(1, timeout=0.1, deadline=app_deadline, root=ROOT)

    assert record["coverage"]["answered_cells"] == 133, "the matrix completed; only the reads did not"
    assert record["deadline_exceeded"] is True, record["deadline_note"]
    assert "after the request matrix" in record["deadline_note"], record["deadline_note"]
    assert record["classification"] == "inconclusive"
    assert "the run was cut short" in record["classification_reason"]
    assert "133 of 133 matrix cells answered" in record["classification_reason"]
    cut_off = [a for a in record["artefacts"] if a["detail"].startswith(probe._DEADLINE_TRUNCATED)]
    assert record["artefacts_truncated"] == len(cut_off) >= 4, record["artefacts"]
    validate_record(record)
    # The count is RECOMPUTED, never read: a record that understates what the
    # deadline cut off is refused, and so is one that says it never expired.
    understated = dict(record, artefacts_truncated=0)
    with pytest.raises(ProbeRecordError, match="deadline cut them off"):
        validate_record(understated)
    denied = dict(record, deadline_exceeded=False)
    with pytest.raises(ProbeRecordError, match="deadline_exceeded must say exactly"):
        validate_record(denied)
    # AND the shape the old code produced, exactly: full coverage, the reads
    # cut off and counted, a confinement-shaped state, and a record that says
    # the deadline never expired.
    old_shape = _valid_record(rows)
    assert old_shape["classification"] == "admitted_nuisance"
    old_shape["artefacts"] = cut_off
    old_shape["artefacts_truncated"] = len(cut_off)
    with pytest.raises(ProbeRecordError, match="cannot also report that it finished"):
        validate_record(old_shape)


def test_the_deadline_budget_clamps_every_operation_it_bounds():
    """ROUND-2 SECURITY P3-3 / TEST F-4: the one mutant that survived. The
    docstring said an operation "cannot outlive the deadline" and nothing
    read it, so `budget` could have returned its argument unchanged and the
    suite stayed green -- while the real bound became the deadline plus 60 s,
    the `Get-CimInstance` timeout.

    Three properties, as arithmetic: a timeout SMALLER than what remains is
    passed through, a timeout larger than what remains is cut to what remains,
    and after the deadline has passed every operation gets `FLOOR_S` -- not
    zero, because a zero timeout means "fail now" on some calls and "wait
    forever" on others."""
    clock = probe.Deadline(1.0)
    time.sleep(0.2)  # so "what remains" is strictly less than the deadline
    assert clock.budget(0.1) == 0.1, "a timeout inside the budget is passed through"
    clamped = clock.budget(60.0)
    assert clamped < 0.9, f"a 60 s timeout survived a 1 s deadline: {clamped}"
    assert clamped == pytest.approx(clock.remaining(), abs=0.05), clamped
    assert clock.budget(clock.remaining() / 2) < clamped, "the smaller of the two wins"
    expired = probe.Deadline(0.05)
    time.sleep(0.1)
    assert expired.exceeded() and expired.remaining() < 0
    assert expired.budget(60.0) == probe.Deadline.FLOOR_S == 0.05
    assert expired.budget(0.001) == probe.Deadline.FLOOR_S, "the floor is a floor in both directions"


def test_the_deadline_bounds_the_subject_binding_subprocesses(monkeypatch: pytest.MonkeyPatch):
    """ROUND-2 ARCHITECTURE F-A: `_tree_git_sha` (git, 30 s) and `_principal`
    (whoami, 30 s) ran OUTSIDE the deadline, so `probe(deadline=0.5)` took
    6.67 s with two 3 s subprocesses and the VALIDATION row saying "the whole
    probe is bounded by a deadline" was held by nothing.

    The stub is a subprocess that takes 3 s AND HONOURS ITS TIMEOUT, which is
    what a real one does: it sleeps for as long as it is allowed and raises
    `TimeoutExpired` if that was not long enough. Only `probe`'s reference to
    the module is replaced, so nothing else in the session sees it. Both the
    outcome (the wall clock) and the mechanism (the timeouts the calls
    actually received) are asserted -- a wall-clock bound alone would pass if
    the calls simply failed fast for another reason."""
    asked: list[float] = []

    def slow_run(argv, **kwargs):
        timeout = kwargs.get("timeout")
        asked.append(timeout)
        assert timeout is not None, "an unbounded subprocess in the probe"
        time.sleep(min(3.0, timeout))
        if timeout < 3.0:
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, 0, "deadbeef", "")

    monkeypatch.setattr(probe, "subprocess", types.SimpleNamespace(
        run=slow_run, SubprocessError=subprocess.SubprocessError,
        TimeoutExpired=subprocess.TimeoutExpired,
        CompletedProcess=subprocess.CompletedProcess))
    _without_the_cim_query(monkeypatch)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()

    started = time.monotonic()
    record = probe.probe(port, timeout=0.1, deadline=0.5, root=ROOT)
    wall = time.monotonic() - started

    assert asked, "the subject binding started no subprocess, so this measures nothing"
    assert all(t <= 0.5 for t in asked), f"an unclamped subprocess timeout: {asked}"
    assert all(t >= probe.Deadline.FLOOR_S for t in asked), asked
    assert wall < 1.5, (wall, asked)
    assert record["subject"]["tree_git_sha"] is None  # the clamped git call did not finish
    assert record["classification"] == "inconclusive"


def test_main_exit_codes_follow_the_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    capsys: pytest.CaptureFixture):
    """0 for admitted_nuisance and reachable_unadmitted (no authority reached
    by this caller -- not a confinement verdict), 2 for authority_reachable,
    3 for inconclusive, 4 when the record fails its own validation; `--out`
    writes the record as LF JSON and it is printed either way."""
    expected = {"admitted_nuisance": 0, "reachable_unadmitted": 0, "authority_reachable": 2,
                "inconclusive": 3}
    assert probe.EXIT_CODES == expected
    for state, code in expected.items():
        monkeypatch.setattr(probe, "probe", lambda port, **kw: {"classification": state, "kw": kw})
        out = tmp_path / f"{state}.json"
        assert probe.main(["--port", "1", "--out", str(out)]) == code
        written = out.read_bytes()
        assert b"\r" not in written and json.loads(written)["classification"] == state
        assert json.loads(capsys.readouterr().out)["classification"] == state

    def refusing(port, **kw):
        raise ProbeRecordError("the record failed its own validation")

    monkeypatch.setattr(probe, "probe", refusing)
    assert probe.main(["--port", "1"]) == 4
    assert "failed its own validation" in capsys.readouterr().err
    monkeypatch.setattr(probe, "probe", lambda port, **kw: {"classification": "inconclusive", "kw": kw})
    probe.main(["--port", "7", "--deadline", "12", "--timeout", "0.25", "--principal-separated", "unknown"])
    passed = json.loads(capsys.readouterr().out)["kw"]
    assert passed["deadline"] == 12.0 and passed["timeout"] == 0.25 and passed["principal_separated"] == "unknown"


def test_main_maps_every_refusal_to_exit_four_on_one_line_naming_no_path(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    """ROUND-2 SECURITY P2-1, the `except` itself. `main()` caught
    `NonLoopbackHostError`, `ProbeRecordError` and `ValueError`; a `TypeError`
    -- which a hostile surface can provoke by putting a value of any type in a
    body this tool reads -- went straight out as a traceback, exit 1, with the
    host's own paths printed in the frames. That falsified the exit-code
    enumeration in the README, in A-028 and in `--help` at once.

    Every refusal is now exit 4 and ONE line on stderr that names no path:
    `redact` folds home and removes the login and machine name, and any
    remaining path fragment becomes `<path>` -- a path this host did not put
    in the token list is still a path."""
    home = str(Path.home())
    cases = [
        ProbeRecordError("the record failed its own validation"),
        ValueError("principal_separated must be one of (...)"),
        TypeError("int() argument must be a string, not 'list'"),
        NonLoopbackHostError("host 'example.com' is not a loopback address"),
        ProbeRecordError(f"could not read {home}\\.nornyx\\runtime.json\nsecond line"),
        ProbeRecordError(f"could not read {os.path.join('C:' + os.sep, 'Secret', 'plans.txt')}"),
        ProbeRecordError("could not read /home/someone/.ssh/id_ed25519"),
    ]
    for error in cases:
        def raising(port, _error=error, **kw):
            raise _error

        monkeypatch.setattr(probe, "probe", raising)
        assert probe.main(["--port", "1"]) == probe.EXIT_REFUSED == 4, error
        captured = capsys.readouterr()
        assert captured.out == "", "a refused run writes no record"
        assert captured.err.count("\n") == 1, captured.err
        assert captured.err.startswith("probe_control_plane: refused: "), captured.err
        assert "Traceback" not in captured.err
        for fragment in (home, os.path.join("C:" + os.sep, "Secret"), "/home/someone"):
            assert fragment.lower() not in captured.err.lower(), (fragment, captured.err)
    # A refusal with nothing to say still says something.
    monkeypatch.setattr(probe, "probe", lambda port, **kw: (_ for _ in ()).throw(TypeError()))
    assert probe.main(["--port", "1"]) == 4
    assert "TypeError" in capsys.readouterr().err


def test_an_out_path_inside_the_repository_is_refused_by_the_tool(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    """ROUND-2 ARCHITECTURE F-D: `--out` was DOCUMENTED against writing inside
    the tree and refused by nobody. A record written there is an untracked
    artefact in a repository whose evidence cycle reads the tree, and the next
    `git add -A` commits a measurement as if it were source.

    Refused now, on RESOLVED paths, before the probe runs at all -- so a
    refused `--out` starts no socket and the run is exit 4 with the usual one
    line. A path outside the tree still writes, as LF JSON.

    ROUND-3 P3: the candidates are REAL paths in the real working tree, and
    they have to be -- the rule under test compares against the root
    `main()` derives from the tool's own `__file__`, so a fake repository
    would exercise a different root than the one that matters. What was wrong
    was the CLEANUP: this test's tidiness rested on the very refusal it is
    testing. Mutate the refusal away and the run leaves an untracked
    `record.json` at the repository root -- which the next evidence cycle
    would commit as if it were source, and which poisoned the mutation runs
    that followed it -- measured: the session's own tree-state fixture then
    ERRORS, so an unrelated test in the same run goes red for a reason that
    has nothing to do with it. The removal is unconditional now, in a
    `finally`, and it touches ONLY a path this test caused to appear: a file
    that was already there is left exactly as found. A `finally` rather than
    a copied workspace, deliberately: on the CORRECT code path this test
    writes nothing inside the tree at all -- every candidate is refused
    before `main()` reaches its writer -- so the net is load-bearing only
    when the refusal is mutated away, which is a bounded test run and not a
    process this suite expects to die under it."""
    monkeypatch.setattr(probe, "probe", lambda port, **kw: {"classification": "inconclusive"})
    inside = [ROOT / "record.json", ROOT / "docs" / "record.json",
              ROOT / "scripts" / ".." / "record.json"]
    already_there = {candidate for candidate in inside if candidate.exists()}
    try:
        for candidate in inside:
            assert probe.main(["--port", "1", "--out", str(candidate)]) == 4, candidate
            captured = capsys.readouterr()
            assert "inside this repository" in captured.err, captured.err
            assert captured.err.count("\n") == 1 and captured.out == ""
            assert not candidate.exists(), f"a refused --out still wrote {candidate.name}"
    finally:
        for candidate in inside:
            if candidate not in already_there and candidate.exists():
                candidate.unlink()
    outside = tmp_path / "record.json"
    assert probe.main(["--port", "1", "--out", str(outside)]) == 3
    assert b"\r" not in outside.read_bytes()
    assert json.loads(outside.read_bytes())["classification"] == "inconclusive"
    capsys.readouterr()


class _HostileRuntime(BaseHTTPRequestHandler):
    """A loopback listener imitating the surface, badly and on purpose.

    It answers the four ALLOWLISTED pairs 200 -- `/api/runtime` with an
    operator-chosen body -- and every other cell with the fixed 401, so the log
    it produces is the one the real surface produces and the classification is
    `admitted_nuisance`. What differs is the one thing the probe reads as data:
    the identity body. Answering an allowlisted pair only, rather than every
    request, matters: `HEAD /api/runtime` is a GATED cell, and a 200 there
    would be a genuine `authority_reachable` about the wrong thing."""

    body = b"{}"

    def _answer(self) -> None:
        # DRAIN THE REQUEST BODY FIRST. Answering a POST without reading its
        # body closes the socket with bytes still in the receive queue, which
        # Windows answers with an RST: the client sees a reset instead of the
        # 401 that was written, the cell records `status: None`, and the run
        # is `inconclusive` for a reason that has nothing to do with the case
        # under test. Measured here as a two-of-nine flake before this line.
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        allowlisted = (self.command, self.path) in ALLOWLISTED_PAIRS
        if allowlisted:
            payload = self.body if self.path == "/api/runtime" else b"{}"
        else:
            payload = b'{"detail":"no session"}'
        self.send_response(200 if allowlisted else 401)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _answer

    def log_message(self, *args) -> None:  # keep the pytest output clean
        return


HOSTILE_BODIES = {
    "pid_list": b'{"schema":"nornyx.forge.runtime.v1","pid":[1,2],"instance":"abc"}',
    "pid_dict": b'{"schema":"nornyx.forge.runtime.v1","pid":{"a":1},"instance":"abc"}',
    "pid_string": b'{"schema":"nornyx.forge.runtime.v1","pid":"4321","instance":"abc"}',
    "pid_bool": b'{"schema":"nornyx.forge.runtime.v1","pid":true,"instance":"abc"}',
    "instance_list": b'{"schema":"nornyx.forge.runtime.v1","pid":7,"instance":["a"]}',
    "not_json": b"this is not json at all",
    "json_list": b"[1, 2, 3]",
    "no_schema": b'{"pid":7,"instance":"abc"}',
    "long_instance": b'{"schema":"nornyx.forge.runtime.v1","pid":7,"instance":"' + b"aB" * 100 + b'"}',
}


@pytest.mark.parametrize("case", sorted(HOSTILE_BODIES))
def test_a_hostile_runtime_body_never_becomes_a_traceback(case: str, monkeypatch: pytest.MonkeyPatch,
                                                          capsys: pytest.CaptureFixture):
    """ROUND-2 SECURITY P2-1, reproduced and closed. A hostile listener on
    loopback answering `/api/runtime` with `pid` as a LIST reached `int(pid)`
    in the memory-handle read and crashed the probe: exit 1, a traceback, and
    the host's paths in the frames.

    `/api/runtime` is read off a socket anything on this host may be serving,
    so `pid` and `instance` are TYPE-CHECKED where they are recorded: a
    malformed identity is refused, the surface is recorded unreachable with
    the reason, and the run continues -- the classification comes from the
    request log and never from `/api/runtime`. Every body below ends in a
    clean exit code with a valid record, or in exit 4 with one line; none ends
    in a traceback.

    The listener answers 200 on `/api/runtime` and the surface's own fixed 401
    everywhere else, so the log earns `admitted_nuisance` -- one allowlisted
    2xx, every gated cell denied -- and the exit code is 0. The 200-character
    instance is the exception, and deliberately: a credential-shaped run in
    the record is refused by the secret backstop, which is exit 4."""
    _without_the_cim_query(monkeypatch)
    handler = type("_Case", (_HostileRuntime,), {"body": HOSTILE_BODIES[case]})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        code = probe.main(["--port", str(server.server_address[1]), "--timeout", "2",
                           "--deadline", "120"])
    finally:
        server.shutdown()
        thread.join(10)
        server.server_close()
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err and "Traceback" not in captured.out
    if case == "long_instance":
        assert code == probe.EXIT_REFUSED, captured.err
        assert "credential-shaped" in captured.err and captured.err.count("\n") == 1
        return
    assert code == probe.EXIT_NO_AUTHORITY, (code, captured.err[-500:])
    record = json.loads(captured.out)
    validate_record(record)
    assert record["classification"] == "admitted_nuisance"
    surface = record["subject"]["surface"]
    if case in ("pid_list", "pid_dict", "pid_string", "pid_bool", "instance_list"):
        assert surface["reachable"] is False, surface
        assert surface["pid"] is None and surface["instance"] is None
        assert "refused as malformed" in surface["detail"], surface
        assert ("pid of type" in surface["detail"]) is (case != "instance_list"), surface
    else:
        assert surface["reachable"] is False and surface["detail"] is None, surface
    vm = {a["name"]: a for a in record["artefacts"]}["process_vm_read"]
    assert vm["outcome"] == ARTEFACT_NOT_APPLICABLE and "no pid" in vm["detail"], vm


def test_the_harness_runs_no_provider_and_starts_no_synchronous_launch():
    """Held by reading the code, not by prose (round-1 security P3-5). In the
    probe module: every process start is `subprocess.run` inside
    `_tree_git_sha` (argv[0] the literal `git`) or `_run_system` (argv[0] the
    absolute path it resolved), every `_run_system` call names
    `powershell.exe` or `whoami.exe`, no string constant names a provider CLI,
    and no in-process transport (`TestClient`, `fastapi`, `starlette`, `httpx`)
    is imported or named. In this test module: the only process started is
    `sys.executable`, and `launch` is never called directly -- every launch
    goes through the watched `Launch` harness."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    providers = {"codex", "claude", "codex.exe", "claude.exe", "codex.cmd", "claude.cmd"}

    def enclosing(target: ast.AST) -> str | None:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and any(child is target for child in ast.walk(node)):
                return node.name
        return None

    starts = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute)
              and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"]
    assert starts, "the probe module starts no process at all, so this checks nothing"
    for call in starts:
        assert call.func.attr == "run" and isinstance(call.args[0], ast.List), ast.dump(call)
        head = call.args[0].elts[0]
        owner = enclosing(call)
        if isinstance(head, ast.Constant):
            assert head.value == "git" and owner == "_tree_git_sha", (head.value, owner)
        else:
            assert isinstance(head, ast.Name) and head.id == "executable" and owner == "_run_system", owner
    named = {call.args[0].value for call in ast.walk(tree) if isinstance(call, ast.Call)
             and isinstance(call.func, ast.Name) and call.func.id == "_run_system"
             and isinstance(call.args[0], ast.Constant)}
    assert named == {"powershell.exe", "whoami.exe"}, named
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value.lower().strip() not in providers, node.value
        if isinstance(node, (ast.Name, ast.Attribute)):
            assert getattr(node, "id", getattr(node, "attr", "")) != "TestClient"
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert not [m for m in imported if m.split(".")[0] in {"fastapi", "starlette", "httpx", "nornyx_forge"}], imported

    here = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    for call in ast.walk(here):
        if not isinstance(call, ast.Call):
            continue
        if isinstance(call.func, ast.Name):
            assert call.func.id != "launch", "a synchronous launch() in a test is a stall, not a witness"
        if (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "subprocess"):
            # Only the process STARTS carry an argv. `subprocess.TimeoutExpired`
            # and `subprocess.CompletedProcess` are the exception and the result
            # type the deadline stub constructs to imitate a slow subprocess;
            # they start nothing, and an unrecognised member is a red test
            # rather than a silently skipped one.
            if call.func.attr not in ("run", "Popen", "call", "check_call", "check_output"):
                assert call.func.attr in ("TimeoutExpired", "CompletedProcess", "SubprocessError"), (
                    f"an unrecognised subprocess.{call.func.attr} in this module")
                continue
            head = call.args[0].elts[0]
            assert isinstance(head, ast.Attribute) and head.attr == "executable", ast.dump(head)
    imported_here = {alias.name for node in ast.walk(here) if isinstance(node, ast.ImportFrom)
                     for alias in node.names}
    assert "launch" not in imported_here and "Launch" in imported_here


# ---------------------------------------------------------------------------
# C3's finding against C2's harness: a presence check may be DENIED, and an
# artefact read may not raise.
#
# Measured, on a Codex-sandboxed principal running this module's own CLI: the
# browser-history read raised `PermissionError: [WinError 5]` out of `probe()`,
# the run ended in a traceback and exit 1, and NO record was produced -- for
# exactly the kind of caller this harness exists to measure, and against the
# exit-code enumeration `--help`, the README and A-028 all state. The cause is
# that `Path.exists()` is not total: it swallows "not found" and RE-RAISES a
# permission error.
# ---------------------------------------------------------------------------


class _DeniedPath(type(Path())):
    """A path whose every `stat` is denied to this principal, as the OS does
    it -- the exception the sandboxed run actually raised, not a sentinel."""

    def exists(self, *args, **kwargs):
        raise PermissionError(13, "Access is denied")

    def stat(self, *args, **kwargs):
        raise PermissionError(13, "Access is denied")

    def open(self, *args, **kwargs):
        raise PermissionError(13, "Access is denied")

    def iterdir(self):
        raise PermissionError(13, "Access is denied")


def test_a_presence_check_denied_to_this_principal_answers_none():
    """`_presence` has three answers because there are three facts, and None
    is NEVER folded into False: a path this caller may not stat is not a path
    that is absent, and recording it as absent would let a confinement
    measurement read a denial as "there was nothing to try"."""
    assert probe._presence(Path(__file__)) is True
    assert probe._presence(Path(__file__).with_name("no-such-file-here")) is False
    assert probe._presence(_DeniedPath(__file__)) is None


@pytest.mark.parametrize("name,read", [
    ("runtime_record", lambda p: probe._artefact_path_read("runtime_record", p)),
    ("seal_dir_listing", lambda p: probe._seal_dir_listing(p)),
])
def test_a_denied_presence_check_is_refused_not_not_applicable(name, read):
    """The word and the fact have to agree. `not_applicable` means there was
    nothing to try; a caller denied the check itself HAD something to try and
    was refused, and only one of those two words can never satisfy a
    capability claim while also recording that a facility said no."""
    artefact = read(_DeniedPath(__file__))
    assert artefact["outcome"] == probe.ARTEFACT_REFUSED
    assert probe.capability_acquired(artefact) is False
    assert "denied" in artefact["detail"]
    assert "not determinable" in artefact["detail"], (
        "a denied presence check must not read as an existence claim"
    )


def test_the_history_read_reports_a_denied_presence_check_rather_than_absence(
        monkeypatch: pytest.MonkeyPatch):
    """The exact read that crashed. Both branches are held: every candidate
    denied is `refused`, and a present-and-readable store beside a denied one
    is still `observed` -- with the denied path counted as NOT CHECKABLE, never
    as a refusal, because `observed` is the word for an acquired capability and
    the validator refuses a record whose detail contradicts it."""
    monkeypatch.setattr(probe, "_presence", lambda path: None)
    denied = probe._browser_history(local_appdata=str(Path(__file__).parent),
                                    platform_name="win32")
    assert denied["outcome"] == probe.ARTEFACT_REFUSED
    assert "could not be checked at all" in denied["detail"]
    assert probe.capability_acquired(denied) is False

    class _Readable:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, size):
            return b"x"[:size]

    seen = iter([True, None])
    monkeypatch.setattr(probe, "_presence", lambda path: next(seen))
    monkeypatch.setattr(probe.Path, "open", lambda self, *a, **k: _Readable())
    mixed = probe._browser_history(local_appdata=str(Path(__file__).parent),
                                   platform_name="win32")
    assert mixed["outcome"] == probe.ARTEFACT_OBSERVED
    assert "not checkable" in mixed["detail"]
    assert not probe._DENIAL_DETAIL.search(mixed["detail"]), (
        "an acquired capability may not carry a denial in its own detail; the "
        "validator refuses exactly that record"
    )


def test_no_artefact_read_can_raise_out_of_the_probe(monkeypatch: pytest.MonkeyPatch):
    """THE BACKSTOP, and it is not belt-and-braces.

    Each reader handles the denials it can foresee; this catches the one it did
    not, because an artefact read that RAISES produces no record at all -- and
    this module's whole contract with an operator is a record and an exit code,
    never a traceback that prints the host's directories. The two OSError
    classes are kept apart: a PermissionError is a facility that said no
    (`refused`); anything else is "the read could not be attempted"
    (`not_applicable`).
    """
    _without_the_cim_query(monkeypatch)
    # The SOCKET is stubbed away, not pointed at a closed port. Driving the
    # 133-cell matrix at a dead port cost more than the deadline on this host,
    # so the run came back `inconclusive` with the artefacts truncated -- and a
    # pin about the artefact backstop would have been measuring the clock. Here
    # the surface is simply absent, which is the record's own vocabulary for it.
    monkeypatch.setattr(probe, "_runtime_identity", lambda *a, **k: None)
    monkeypatch.setattr(probe, "_exchange", lambda *a, **k: (None, b""))
    monkeypatch.setattr(probe, "_request_fact", lambda host, port, method, path, timeout:
                        probe._unattempted_fact(method, path, "not attempted: the socket is stubbed"))
    for raising, expected in ((PermissionError(13, "Access is denied"), probe.ARTEFACT_REFUSED),
                              (OSError(22, "Invalid argument"), probe.ARTEFACT_NOT_APPLICABLE)):
        def boom(*, _raise=raising, **kwargs):
            raise _raise

        monkeypatch.setattr(probe, "_browser_history", boom)
        record = probe.probe(8710, expect_instance=None, deadline=120.0, timeout=0.2)
        probe.validate_record(record)
        history = [a for a in record["artefacts"] if a["name"] == "browser_history"]
        assert [a["outcome"] for a in history] == [expected], history
        assert record["deadline_exceeded"] is False, (
            "the pin ran out of clock, so what it measured is the deadline rule "
            "and not the artefact backstop"
        )
        assert record["classification"] == probe.STATE_INCONCLUSIVE, (
            "the surface is absent in this pin; the artefact backstop must not "
            "change what the request log derives"
        )
