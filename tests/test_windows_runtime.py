"""The Windows basic-user runtime: mechanics held, authority untouched -- PR-18.

CROSS-PLATFORM DETERMINISTIC EVIDENCE. Everything here runs on the Linux
census as well as on a Windows workstation: real loopback sockets, real
file locks, real records on disk, a real uvicorn server loop driven
in-process, and the real onboarding surface where the property is about
it. What needs an actual Windows host -- a real child process started from
the bundle's own code at a path with spaces and non-ASCII characters, the
literal launcher -- lives in tests/test_windows_host_runtime.py and is
labelled as such. Nothing here claims the operator's real embedded
interpreter run.

WHAT WOULD FALSIFY THIS SLICE: a launch where the working directory, PATH
or an environment variable selects which Forge runs; a self-contained
bundle quietly running on a system Python; a browser opened before the
server answered for itself; two runtimes racing over one authority store;
a recorded pid or port read as identity; an unrelated listener accepted
as Forge; a runtime record or bundle marker reaching a governance answer.
"""

from __future__ import annotations

import contextlib
import http.client
import http.server
import inspect
import json
import os
import socket
import sys
import threading
import time
import warnings
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from nornyx_forge import app_launcher, onboarding_app, windows_launch, windows_runtime
from nornyx_forge.app_launcher import open_in_default_browser
from nornyx_forge.capsule import PROVIDERS
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.onboarding_serve import ONBOARDING_HOST, assemble
from nornyx_forge.subject_bootstrap import resolve_packaged_root
from nornyx_forge.windows_runtime import (
    BUNDLE_MARKER,
    BUNDLE_SCHEMA,
    GIT_MISSING,
    RUNTIME_SCHEMA,
    RuntimeLock,
    RuntimePaths,
    RuntimeRefusal,
    attach_runtime_routes,
    bind_loopback,
    launch,
    probe_instance,
    read_record,
    runtime_key,
    verify_launched_bundle,
    write_record,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}


# ---------------------------------------------------------------------------
# Fixtures: a bundle folder, a light surface, a launch held in a thread
# ---------------------------------------------------------------------------

def _parsed(token: str | None) -> bool:
    """True when a bearer was actually read: a non-empty string. `.token`
    answers None for a session file that is absent, unreadable, not JSON, or
    JSON without a `token` -- and the empty string for one carrying an empty
    one, which is not a bearer either and would be sent as `Bearer `."""
    return isinstance(token, str) and bool(token)


def _staging(path: Path) -> Path:
    """The staging name `_place_session_file` writes beside its target. Named
    once here so that every pin on "nothing named `.tmp` survives" reads the
    same rule the writer uses."""
    return path.with_name(path.name + ".tmp")


def _marker(root: Path, mode: str = "developer", **extra) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / BUNDLE_MARKER).write_text(json.dumps({
        "schema": BUNDLE_SCHEMA, "mode": mode, "interpreter": None, **extra,
    }), encoding="utf-8")
    return root


def _light_app(project: Path) -> FastAPI:
    """A stand-in for the onboarding surface where the property is about
    the runtime around it, not the surface itself."""
    app = FastAPI()

    @app.get("/api/state")
    def state():
        return {"initialized": False, "providers": ["claude", "codex"], "project": str(project)}

    @app.get("/", response_class=HTMLResponse)
    def page():
        return "<title>light</title>"

    return app


class Launch:
    """One `launch()` held in a thread, with its seams recorded."""

    def __init__(self, tmp_path: Path, bundle: Path, *, project: Path | None = None,
                 port: int = 0, assemble_app=_light_app, browser: bool = True,
                 which=None, readiness: float = 60.0, session_file: bool = False):
        self.bundle = bundle
        self.project = project or (tmp_path / "project")
        self.runtime_dir = tmp_path / "runtime"
        self.opened: list[str] = []
        self.notices: list[tuple[str, str]] = []
        self.probe_at_open: list[dict | None] = []
        argv = ["--bundle-root", str(bundle), "--project-dir", str(self.project),
                "--runtime-dir", str(self.runtime_dir), "--port", str(port),
                "--readiness-timeout", str(readiness)]
        if not browser:
            argv.append("--no-browser")
        # The bearer for a REAL surface reaches the test through the explicit
        # session file (the same route the smoke uses); a stand-in surface has
        # no session, so the file is never written and `token` stays None.
        self.session_path: Path | None = None
        if session_file:
            self.session_path = tmp_path / "session.json"
            argv += ["--session-file", str(self.session_path)]
        self.argv = argv

        def opener(url: str) -> None:
            # Evidence at the moment of the call: does the server answer with
            # its own token? A browser opened early would record None here.
            # A SHORT probe: on Windows a connect to a bound-but-not-listening
            # loopback port retries its SYN until the timeout, so a long probe
            # could succeed on a retransmit that lands after startup and
            # launder an early opening as a late one (measured under mutation).
            # The bootstrap nonce rides the URL fragment, so strip it before
            # reading the port.
            base = url.split("#", 1)[0]
            port = int(base.rsplit(":", 1)[1].rstrip("/"))
            self.probe_at_open.append(probe_instance(port, timeout=0.5))
            self.opened.append(url)

        self.seams = dict(
            packaged_root=lambda: bundle, assemble_app=assemble_app, open_browser=opener,
            notify=lambda title, text: self.notices.append((title, text)),
        )
        if which is not None:
            self.seams["which"] = which
        self.code: int | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        self.code = launch(self.argv, **self.seams)

    def start(self) -> "Launch":
        self.thread.start()
        return self

    @property
    def paths(self) -> RuntimePaths:
        return RuntimePaths.for_project(self.runtime_dir, self.project)

    def record(self) -> dict | None:
        try:
            return read_record(self.paths.record)
        except RuntimeRefusal:
            return None

    def wait_for(self, status: str, timeout: float = 60.0) -> dict:
        """The record at `status`. For `ready` with a session file configured,
        ALSO A BEARER THAT PARSES out of that file: the bearer is written
        AFTER readiness is recorded
        (`test_the_session_file_is_written_only_after_readiness`), so `.token`
        read on the record alone can be None for an instant and a test's first
        bearered request would go bare (measured in the host suite as a `401`).

        Waiting for the file to EXIST closed that window and left a narrower
        one inside it, for a writer that creates the path and fills it
        afterwards: the file is there, `.token` answers None, and the request
        goes bare out of exactly the `wait_for` that just returned. That is
        the shape the windows-runtime job failed on at PR #46's head. The
        writer no longer opens the window at all -- `_place_session_file`
        moves the file into place complete -- and this wait is the harness's
        own guarantee, held by
        `test_the_scripted_wait_holds_until_the_bearer_parses`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.record()
            if record is not None and record["status"] == status:
                if status != "ready" or self.session_path is None or _parsed(self.token):
                    return record
            elif self.code is not None and not self.thread.is_alive():
                break
            time.sleep(0.05)
        raise AssertionError(
            f"runtime never reached {status} (with a parseable session file, if any): "
            f"record={self.record()} session file present="
            f"{self.session_path is not None and self.session_path.exists()} "
            f"bearer parsed={_parsed(self.token)} code={self.code} notices={self.notices}"
        )

    @property
    def token(self) -> str | None:
        """This run's bearer, read from the explicit session file, or None for a
        stand-in surface that has no session -- and None, not an exception, for
        a file that is unreadable or does not parse, so that a harness polling
        it can tell "no bearer yet" from "a bearer"."""
        if self.session_path is None:
            return None
        try:
            return json.loads(self.session_path.read_text(encoding="utf-8"))["token"]
        except (OSError, ValueError, KeyError):
            return None

    def stop(self, actor: dict = HUMAN) -> tuple[int, dict]:
        record = self.record()
        assert record is not None
        status, body = _post(record["port"], "/api/runtime/stop", {"actor": actor},
                             token=self.token)
        return status, body

    def join(self, timeout: float = 30.0) -> int:
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "the runtime did not stop"
        assert self.code is not None
        return self.code


def _returns(run: Launch, seconds: float = 30.0) -> int:
    """`launch()` for a launch that must RETURN -- a refusal before anything
    starts, or a second launch that joins. Held in a thread and WATCHED, not
    merely bounded: a regression that turns it into a server (a fence that
    does not refuse, a lock that does not exclude) writes a record of its own
    -- one whose instance is not the record found before it started -- and
    that record makes it a red test within about a second, not a hang. The
    runaway server, if any, is stopped through its record WITH this run's
    bearer (the stop route is gated; round-2 P3-2 found the stop sent bare,
    which leaked a listener), so it does not outlive the test. A hard
    deadline stands behind the watch for a launch that neither returns nor
    records. Measured under the second review: two mutation rows and the
    Linux CI matrix hung on synchronous `launch()` calls that had quietly
    become servers."""
    before = run.record()
    known = before.get("instance") if before else None

    def own_record() -> dict | None:
        record = run.record()
        return record if record is not None and record.get("instance") != known else None

    outcome: dict[str, int] = {}
    thread = threading.Thread(target=lambda: outcome.update(code=launch(run.argv, **run.seams)),
                              daemon=True)
    thread.start()
    deadline = time.monotonic() + seconds
    own: dict | None = None
    while thread.is_alive() and time.monotonic() < deadline:
        thread.join(0.05)
        own = own_record()
        if own is not None:
            break
    if own is None and not thread.is_alive():
        return outcome["code"]
    # It became a server, or it stalled: stop what can be stopped, then fail
    # with what was observed.
    settle = time.monotonic() + 10
    while thread.is_alive() and time.monotonic() < settle and (own or {}).get("status") != "ready":
        time.sleep(0.05)
        own = own_record() or own
    if own is not None and own.get("status") == "ready":
        try:
            token = run.token
        except (OSError, ValueError, KeyError):
            token = None
        try:
            _post(own["port"], "/api/runtime/stop", {"actor": HUMAN}, token=token)
        except (OSError, ValueError):
            pass
        thread.join(10)
    if own is not None:
        raise AssertionError(f"a launch that must return became a server: record={own}")
    raise AssertionError(
        f"a launch that must return did not within {seconds:g}s: record={run.record()}")


def _auth(token: str | None, extra: dict | None = None) -> dict:
    headers = dict(extra or {})
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def _get(port: int, path: str, token: str | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.request("GET", path, headers=_auth(token))
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _post(port: int, path: str, payload: dict, token: str | None = None) -> tuple[int, dict]:
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.request("POST", path, body=json.dumps(payload).encode("utf-8"),
                           headers=_auth(token, {"content-type": "application/json"}))
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind((ONBOARDING_HOST, 0))
        return sock.getsockname()[1]


class _PlainServer:
    """An unrelated HTTP listener: answers 200 with whatever it was given."""

    def __init__(self, body: bytes, content_type: str = "text/plain"):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("content-type", content_type)
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):  # silence
                pass

        self.body = body
        self.server = http.server.HTTPServer((ONBOARDING_HOST, 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# W1 / W2  the launched folder is the code that runs
# ---------------------------------------------------------------------------

def test_w1_the_launched_folder_must_be_the_code_that_is_running(tmp_path: Path):
    bundle = _marker(tmp_path / "bundle")
    with pytest.raises(RuntimeRefusal, match="not in the launched folder"):
        verify_launched_bundle(bundle, packaged_root=lambda: ROOT)
    identity = verify_launched_bundle(bundle, packaged_root=lambda: bundle)
    assert identity.root == bundle.resolve() and identity.mode == "developer"
    with pytest.raises(RuntimeRefusal, match="must be absolute"):
        verify_launched_bundle(Path("bundle"), packaged_root=lambda: bundle)
    with pytest.raises(RuntimeRefusal, match="not a directory"):
        verify_launched_bundle(tmp_path / "missing", packaged_root=lambda: bundle)


def test_w1_the_real_resolver_names_this_checkout_and_refuses_any_other_folder(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """With the DEFAULT resolver -- the one `main` composes -- a foreign
    folder is refused however the process was started, and chdir changes
    nothing: the launch directory selects no Forge."""
    elsewhere = _marker(tmp_path / "elsewhere")
    monkeypatch.chdir(elsewhere)
    with pytest.raises(RuntimeRefusal, match="not in the launched folder"):
        verify_launched_bundle(elsewhere)
    assert resolve_packaged_root() == ROOT
    # This checkout is the running code but not a bundle: refused for the
    # missing marker, never accepted by accident.
    with pytest.raises(RuntimeRefusal, match="not a complete Forge bundle"):
        verify_launched_bundle(ROOT)


def test_w14_a_self_contained_bundle_runs_only_on_the_interpreter_it_carries(tmp_path: Path):
    bundle = _marker(tmp_path / "bundle", mode="self_contained")
    with pytest.raises(RuntimeRefusal, match="runs only on the interpreter it carries"):
        verify_launched_bundle(bundle, packaged_root=lambda: bundle, executable=sys.executable)
    carried = bundle / "python" / "pythonw.exe"
    carried.parent.mkdir()
    carried.write_bytes(b"")
    identity = verify_launched_bundle(bundle, packaged_root=lambda: bundle, executable=str(carried))
    assert identity.mode == "self_contained" and identity.interpreter == carried.resolve()
    # A developer bundle says what it is and accepts the interpreter it was given.
    developer = _marker(tmp_path / "developer")
    assert verify_launched_bundle(developer, packaged_root=lambda: developer).mode == "developer"


def test_a_forged_marker_can_only_refuse_or_name_a_mode(tmp_path: Path):
    bundle = _marker(tmp_path / "bundle", approved=True, experience="READY",
                     provider_eligibility={"claude": "established"})
    identity = verify_launched_bundle(bundle, packaged_root=lambda: bundle)
    assert set(identity.__dataclass_fields__) == {"root", "mode", "interpreter"}
    for bad in ({"schema": BUNDLE_SCHEMA, "mode": "portable"},
                {"schema": "nornyx.forge.other.v1", "mode": "developer"},
                "not json at all"):
        content = bad if isinstance(bad, str) else json.dumps(bad)
        (bundle / BUNDLE_MARKER).write_text(content, encoding="utf-8")
        with pytest.raises(RuntimeRefusal):
            verify_launched_bundle(bundle, packaged_root=lambda: bundle)
    (bundle / BUNDLE_MARKER).unlink()
    with pytest.raises(RuntimeRefusal, match="not a complete Forge bundle"):
        verify_launched_bundle(bundle, packaged_root=lambda: bundle)


# ---------------------------------------------------------------------------
# W10  project authority is explicit and absolute
# ---------------------------------------------------------------------------

def test_w10_the_working_directory_cannot_select_the_project(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bundle = _marker(tmp_path / "bundle")
    monkeypatch.chdir(tmp_path)
    # A RELATIVE project directory, exactly as a launch directory would supply
    # it; held to a watched deadline like every launch that must return, so a
    # regression that accepted it would be a red test and not a server.
    run = Launch(tmp_path, bundle, project=Path("forge-project"))
    assert _returns(run) == 2 and run.opened == []
    assert "must be absolute" in run.notices[-1][1]
    assert not (tmp_path / "forge-project").exists()
    assert list((tmp_path / "runtime").glob("*.json")) == [] if (tmp_path / "runtime").exists() else True
    # A file where the project directory should be is refused too.
    (tmp_path / "file").write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeRefusal, match="not a directory"):
        windows_runtime.project_location(tmp_path / "file")


def test_the_runtime_key_is_one_per_project_on_this_platforms_terms():
    a, b = Path("C:/Users/Casey/ForgeProject"), Path("c:/users/casey/forgeproject")
    assert runtime_key(a) == runtime_key(a)
    assert runtime_key(a) != runtime_key(Path("C:/Users/Casey/Other"))
    if sys.platform == "win32":
        assert runtime_key(a) == runtime_key(b), "NTFS is case-insensitive; one directory, one key"


# ---------------------------------------------------------------------------
# The lock, the port, the probe
# ---------------------------------------------------------------------------

def test_w6_the_lock_admits_one_owner_and_is_released_with_it(tmp_path: Path):
    first, second = RuntimeLock(tmp_path / "x.lock"), RuntimeLock(tmp_path / "x.lock")
    assert first.acquire() and first.held
    assert second.acquire() is False and not second.held
    first.release()
    assert second.acquire()
    second.release()


def test_w8_bind_loopback_takes_the_preferred_port_or_another_and_only_loopback():
    preferred = _free_port()
    sock = bind_loopback(preferred)
    try:
        assert sock.getsockname() == (ONBOARDING_HOST, preferred)
        # The occupant LISTENS, as a real server does. Linux lets a second
        # socket bind a port whose only holder is bound-but-not-listening
        # under SO_REUSEADDR (measured on the CI census), which is not the
        # occupied port this proof is about.
        sock.listen(1)
        other = bind_loopback(preferred)
        try:
            assert other.getsockname()[0] == ONBOARDING_HOST
            assert other.getsockname()[1] != preferred, "an occupied port must cost a port"
        finally:
            other.close()
    finally:
        sock.close()
    assert bind_loopback(0).getsockname()[0] == ONBOARDING_HOST


def test_w8_the_probe_accepts_only_a_forge_runtime_answer():
    plain = _PlainServer(b"<html>not forge</html>", "text/html")
    other_schema = _PlainServer(json.dumps({"schema": "nornyx.forge.other.v1",
                                            "instance": "x"}).encode(), "application/json")
    try:
        assert probe_instance(plain.port) is None
        assert probe_instance(other_schema.port) is None
        assert probe_instance(_free_port()) is None
    finally:
        plain.close()
        other_schema.close()
    app = FastAPI()
    calls: list[str] = []
    attach_runtime_routes(app, identity={"schema": RUNTIME_SCHEMA, "instance": "abc",
                                         "bundle_root": "r"}, request_stop=lambda: calls.append("stop"))
    sock = bind_loopback(0)
    port = sock.getsockname()[1]
    import uvicorn
    server = uvicorn.Server(uvicorn.Config(app, host=ONBOARDING_HOST, port=port, log_config=None,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 30
        answered = None
        while time.monotonic() < deadline and answered is None:
            answered = probe_instance(port, timeout=1)
            time.sleep(0.05)
        assert answered == {"schema": RUNTIME_SCHEMA, "instance": "abc", "bundle_root": "r"}
    finally:
        server.should_exit = True
        thread.join(10)


def test_the_stop_route_is_a_persons_act_and_the_identity_route_is_a_copy():
    app = FastAPI()
    calls: list[str] = []
    identity = {"schema": RUNTIME_SCHEMA, "instance": "abc", "port": 1}
    attach_runtime_routes(app, identity=identity, request_stop=lambda: calls.append("stop"))
    identity["instance"] = "mutated after attachment"
    client = TestClient(app)
    assert client.get("/api/runtime").json()["instance"] == "abc"
    refused = client.post("/api/runtime/stop", json={"actor": MODEL})
    assert refused.status_code == 409 and "person's act" in refused.json()["refused"]
    assert calls == []
    assert client.post("/api/runtime/stop").status_code == 422
    # The surface's actor rule, not a looser one: an unacceptable ident is 422.
    assert client.post("/api/runtime/stop", json={"actor": {"kind": "human", "ident": ""}}).status_code == 422
    # A JSON body with no Content-Type is what a cross-origin page can send
    # without a preflight; it must not be parsed as a stop request.
    bare = client.post("/api/runtime/stop", content=json.dumps({"actor": HUMAN}).encode("utf-8"))
    assert bare.status_code == 422, bare.text
    for content_type in ("text/plain", "application/x-www-form-urlencoded"):
        sent = client.post("/api/runtime/stop", content=json.dumps({"actor": HUMAN}).encode("utf-8"),
                           headers={"content-type": content_type})
        assert sent.status_code == 422, content_type
    assert calls == []
    assert client.post("/api/runtime/stop", json={"actor": HUMAN}).json() == {
        "stopping": True, "instance": "abc"}
    assert calls == ["stop"]


# ---------------------------------------------------------------------------
# W3 / W5  serve on loopback; browser only after the server answered itself
# ---------------------------------------------------------------------------

def _slow_start(seconds: float):
    """An app whose startup takes a while, so that "the browser opened before
    the server answered" is a state a regressed watcher would actually reach
    -- a runtime that opens without probing was measured to slip past a fast
    app, because uvicorn was listening by the time the opener looked."""
    import asyncio
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def stalled_startup(app: FastAPI):
        await asyncio.sleep(seconds)
        yield

    def build(project: Path) -> FastAPI:
        app = FastAPI(lifespan=stalled_startup)

        @app.get("/api/state")
        def state():
            return {"initialized": False, "providers": ["claude", "codex"], "project": str(project)}

        @app.get("/", response_class=HTMLResponse)
        def page():
            return "<title>slow</title>"

        return app

    return build


def test_w5_the_browser_opens_only_after_the_server_answered_with_its_own_token(tmp_path: Path):
    run = Launch(tmp_path, _marker(tmp_path / "bundle"), assemble_app=_slow_start(3)).start()
    # While the server does not answer, the record must not say ready either:
    # `ready` is the probe's verdict, not the watcher's schedule.
    unanswered_polls = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        record = run.record()
        if record is not None and probe_instance(record["port"], timeout=0.5) is None:
            assert record["status"] != "ready", "ready was recorded before the server answered"
            unanswered_polls += 1
        elif record is not None:
            break
        time.sleep(0.1)
    assert unanswered_polls > 0, "the slow app never left the runtime unanswered"
    ready = run.wait_for("ready")
    assert ready["url"].startswith(f"http://{ONBOARDING_HOST}:")
    # WAIT FOR BOTH CHANNELS THIS TEST READS -- here, the browser seam and the
    # record. The runtime opens the browser first and publishes the record
    # saying so afterwards: measured at 1.3-1.8 ms, always in that order,
    # because publishing costs a whole-file replace. `wait_for("ready")` below
    # cannot cover that gap -- the status was already `ready` before the
    # browser was opened, so it returns the record as it stands, with
    # `browser.opened` possibly still None. The asserts are unchanged, so a
    # record that never settles still fails rather than hangs.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (
            not run.opened or run.record()["browser"]["opened"] is None):
        time.sleep(0.05)
    assert run.opened == [ready["url"]]
    assert run.probe_at_open[0] is not None, "the browser was opened before the server answered"
    assert run.probe_at_open[0]["instance"] == ready["instance"]
    record = run.wait_for("ready")
    assert record["browser"] == {"requested": True, "opened": True, "error": None,
                                 "at": record["browser"]["at"]}
    assert record["ready_at"] is not None and record["browser"]["at"] >= record["ready_at"]
    status, body = _get(ready["port"], "/api/state")
    assert status == 200 and json.loads(body)["project"] == str(run.project)
    assert _get(ready["port"], "/")[0] == 200
    served = json.loads(_get(ready["port"], "/api/runtime")[1])
    assert served["bundle_root"] == str(run.bundle.resolve()) and served["project_dir"] == str(run.project)
    assert run.stop()[0] == 200
    assert run.join() == 0
    stopped = run.record()
    assert stopped["status"] == "stopped" and stopped["stopped_at"] is not None
    assert RuntimeLock(run.paths.lock).acquire(), "the lock outlived its owner"


def test_w5_readiness_is_bounded_and_a_timeout_is_a_visible_failure(tmp_path: Path):
    run = Launch(tmp_path, _marker(tmp_path / "bundle"), assemble_app=_slow_start(3),
                 readiness=0.5).start()
    assert run.join(60) == 2
    record = run.record()
    assert record["status"] == "failed" and "did not answer" in record["reason"]
    assert run.opened == [], "a timeout must not open a browser"
    assert any("did not answer" in text for _, text in run.notices)


def test_a_browser_failure_does_not_unmake_a_ready_runtime(tmp_path: Path):
    run = Launch(tmp_path, _marker(tmp_path / "bundle"))

    def broken(url: str) -> None:
        raise OSError("no browser is registered")

    run.seams["open_browser"] = broken
    run.start()
    ready = run.wait_for("ready")
    # The same two-channel wait, in the other direction. The runtime records the
    # failed opening and TELLS the person one statement later, on its own daemon
    # thread; record-then-tell is deliberate there and is not the defect. A poll
    # that waits only for the record samples `notices` inside that gap --
    # measured at 0.09-0.29 ms, always in that order, and observed once as a CI
    # failure where `opened is False` and the error text both matched and only
    # the notice was missing. The assertion below is unchanged and outlives the
    # bounded poll, so a notice that never arrives is still a red test.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (
            run.record()["browser"]["opened"] is None
            or not any(ready["url"] in text for _, text in run.notices)):
        time.sleep(0.05)
    record = run.record()
    assert record["status"] == "ready"
    assert record["browser"]["opened"] is False and "no browser" in record["browser"]["error"]
    assert any(ready["url"] in text for _, text in run.notices), "the person must be told the URL"
    assert _get(ready["port"], "/api/state")[0] == 200, "the server is still serving"
    run.stop()
    assert run.join() == 0


# ---------------------------------------------------------------------------
# W6 / W7 / W8  second launch, stale metadata, unrelated listener
# ---------------------------------------------------------------------------

def test_w6_a_second_launch_joins_the_healthy_instance_and_starts_nothing(tmp_path: Path):
    first = Launch(tmp_path, _marker(tmp_path / "bundle")).start()
    ready = first.wait_for("ready")
    second = Launch(tmp_path, first.bundle)
    assert _returns(second) == 0
    assert second.opened == [ready["url"]], "the second launch must open the running page"
    assert second.probe_at_open[0]["instance"] == ready["instance"]
    assert [p.name for p in first.runtime_dir.glob("*.json")] == [first.paths.record.name]
    assert first.record()["instance"] == ready["instance"], "the record was not replaced"
    quiet = Launch(tmp_path, first.bundle, browser=False)
    assert _returns(quiet) == 0 and quiet.opened == []
    first.stop()
    assert first.join() == 0


def test_a_join_whose_browser_adapter_cannot_speak_is_told_not_traced(tmp_path: Path):
    """The THIRD `_said` site, at the join (round-4 test P3: the other two had
    specimens and this one had none -- no test reached exit 3 at all).

    A join onto a running instance that exposes no reopen route -- the
    stand-in surface here -- opens the page directly. When the browser adapter
    raises an exception whose own `__str__` raises, a bare `str(exc)` inside
    that handler throws OUT of the except and the person gets a traceback
    instead of the notice. With `_said` the join exits 3 with the fixed
    notice, the URL to open by hand, and the class name -- and the first
    instance is still serving, untouched."""
    class Unspeakable(Exception):
        def __str__(self) -> str:
            raise RuntimeError("this exception cannot render itself")

    def raising(url: str) -> None:
        raise Unspeakable()

    first = Launch(tmp_path, _marker(tmp_path / "bundle")).start()
    ready = first.wait_for("ready")
    second = Launch(tmp_path, first.bundle)
    second.seams["open_browser"] = raising
    assert _returns(second) == 3
    title, text = second.notices[-1]
    assert title == "Forge is running"
    assert text.startswith(f"Open {ready['url']} in your browser."), text
    assert "Unspeakable" in text and "could not be rendered" in text, text
    assert probe_instance(ready["port"])["instance"] == ready["instance"]
    first.stop()
    assert first.join() == 0


def test_w6_a_second_launch_from_another_folder_is_refused_not_substituted(tmp_path: Path):
    first = Launch(tmp_path, _marker(tmp_path / "bundle a")).start()
    ready = first.wait_for("ready")
    other = _marker(tmp_path / "bundle b")
    second = Launch(tmp_path, other)
    assert _returns(second) == 2
    assert second.opened == []
    assert "another folder" in second.notices[-1][0]
    assert repr(str(first.bundle.resolve())) in second.notices[-1][1], "the notice names the other folder, quoted"
    assert probe_instance(ready["port"])["instance"] == ready["instance"], "the first still serves"
    first.stop()
    assert first.join() == 0


def test_w7_stale_metadata_identifies_nothing_and_nothing_is_terminated(tmp_path: Path):
    """A record whose owner is gone -- pointing at a port where an UNRELATED
    service answers -- is overwritten, and that service is left alone."""
    bundle = _marker(tmp_path / "bundle")
    impostor = _PlainServer(json.dumps({"schema": RUNTIME_SCHEMA, "instance": "old-token",
                                        "bundle_root": str(bundle)}).encode(), "application/json")
    try:
        run = Launch(tmp_path, bundle, browser=False)
        run.runtime_dir.mkdir()
        write_record(run.paths.record, {
            "schema": RUNTIME_SCHEMA, "instance": "old-token", "status": "ready",
            "port": impostor.port, "pid": 4, "bundle_root": str(bundle),
        })
        run.start()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and (run.record() or {}).get("instance") == "old-token":
            time.sleep(0.05)
        ready = run.wait_for("ready")
        assert ready["instance"] != "old-token" and ready["port"] != impostor.port
        assert probe_instance(impostor.port)["instance"] == "old-token", "the impostor was not touched"
        run.stop()
        assert run.join() == 0
    finally:
        impostor.close()


def test_w8_an_unrelated_listener_on_the_preferred_port_costs_a_port_not_a_process(tmp_path: Path):
    occupant = _PlainServer(b"something else entirely")
    try:
        run = Launch(tmp_path, _marker(tmp_path / "bundle"), port=occupant.port, browser=False).start()
        ready = run.wait_for("ready")
        assert ready["port"] != occupant.port
        assert _get(occupant.port, "/")[1] == b"something else entirely", "the occupant still answers"
        run.stop()
        assert run.join() == 0
    finally:
        occupant.close()


def test_corrupt_metadata_beside_a_held_lock_is_a_visible_refusal(tmp_path: Path):
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, readiness=1.0)
    run.runtime_dir.mkdir()
    holder = RuntimeLock(run.paths.lock)
    assert holder.acquire()
    try:
        run.paths.record.write_text("{not json", encoding="utf-8")
        assert _returns(run) == 2
        assert run.opened == [] and "unreadable" in run.notices[-1][1]
        run.paths.record.write_text(json.dumps({"schema": "other", "status": "ready"}), encoding="utf-8")
        assert _returns(run) == 2
        assert f"not a {RUNTIME_SCHEMA} record" in run.notices[-1][1]
        run.paths.record.unlink()
        assert _returns(run) == 2
        assert "recorded nothing within" in run.notices[-1][1]
    finally:
        holder.release()


def test_a_launch_takes_over_when_the_holder_goes_away(tmp_path: Path):
    """The lock is retried while a launch waits: a holder that crashed or
    stopped releases it, and the waiting launch becomes the owner instead of
    refusing over a record nobody will update."""
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, browser=False)
    run.runtime_dir.mkdir()
    holder = RuntimeLock(run.paths.lock)
    assert holder.acquire()
    write_record(run.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "gone", "status": "ready",
                                    "port": _free_port(), "pid": 4})
    run.start()
    time.sleep(1.0)
    assert run.record()["instance"] == "gone" and run.code is None, "still waiting on the holder"
    holder.release()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and (run.record() or {}).get("instance") == "gone":
        time.sleep(0.05)
    ready = run.wait_for("ready")
    assert ready["instance"] != "gone"
    run.stop()
    assert run.join() == 0


def test_a_finished_runs_record_is_provisional_for_a_moment(tmp_path: Path):
    """Two launches in the same instant: the loser must not read the previous
    run's `stopped` record as this launch's verdict (measured under review)."""
    bundle = _marker(tmp_path / "bundle")
    (tmp_path / "runtime").mkdir()
    write_record(RuntimePaths.for_project(tmp_path / "runtime", tmp_path / "project").record,
                 {"schema": RUNTIME_SCHEMA, "instance": "previous", "status": "stopped",
                  "port": _free_port(), "pid": 4, "reason": None})
    # Either launch may win the lock; the property is about the loser.
    first = Launch(tmp_path, bundle, browser=False).start()
    second = Launch(tmp_path, bundle, browser=False).start()
    # The loser returns once the winner answers; the winner keeps serving.
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and first.code is None and second.code is None:
        time.sleep(0.05)
    loser, winner = (first, second) if first.code is not None else (second, first)
    assert loser.code == 0, loser.notices
    assert loser.notices == [], "the loser reported the previous run's record"
    ready = winner.wait_for("ready")
    assert ready["instance"] != "previous" and winner.code is None
    winner.stop()
    assert winner.join() == 0


def test_the_runtime_directory_stays_out_of_the_project_and_the_seals(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Refused BEFORE anything is created: a review measured the refusal
    creating the fenced directory and writing its trail inside it -- into
    the developer's real seal directory, from this very test."""
    seals = tmp_path / "seals"
    seals.mkdir()
    monkeypatch.setattr(windows_runtime, "DEFAULT_SEAL_DIR", seals)
    bundle = _marker(tmp_path / "bundle")
    inside = Launch(tmp_path, bundle)
    inside.runtime_dir = inside.project / "runtime"
    inside.argv[inside.argv.index("--runtime-dir") + 1] = str(inside.runtime_dir)
    assert _returns(inside) == 2
    assert "inside the project directory" in inside.notices[-1][1]
    assert not inside.project.exists(), "the refusal created something inside the project"
    for fenced in (seals, seals / "x"):
        sealed = Launch(tmp_path, bundle)
        sealed.runtime_dir = fenced
        sealed.argv[sealed.argv.index("--runtime-dir") + 1] = str(fenced)
        assert _returns(sealed) == 2
        assert "inside the seal directory" in sealed.notices[-1][1]
    assert list(seals.iterdir()) == [], "the refusal wrote into the seal directory"
    # The same two roots spelled with the extended-length prefix (security
    # P2-1, round 3, pre-existing here: `--runtime-dir \\?\<seals>\x` was
    # admitted because `resolve()` keeps the prefix and the plain roots never
    # appear among the parents). Refused BY NAME before resolution; nothing
    # created. The device prefix is the same rule.
    for fenced in (inside.project / "runtime", seals / "x"):
        for prefix in (_EXT, _DEV):
            prefixed = Launch(tmp_path, bundle)
            prefixed.runtime_dir = fenced
            prefixed.argv[prefixed.argv.index("--runtime-dir") + 1] = prefix + str(fenced)
            assert _returns(prefixed) == 2
            assert "the runtime directory" in prefixed.notices[-1][1], prefixed.notices[-1]
            assert "namespace prefix" in prefixed.notices[-1][1], prefixed.notices[-1]
            assert not fenced.exists()
    assert not inside.project.exists() and list(seals.iterdir()) == []
    # A prefixed PROJECT is the same hole from the other side: it would make the
    # project fence root a spelling no plain runtime directory can be under.
    misspelled = Launch(tmp_path, bundle)
    misspelled.argv[misspelled.argv.index("--project-dir") + 1] = _EXT + str(misspelled.project)
    assert _returns(misspelled) == 2
    assert "the project directory" in misspelled.notices[-1][1], misspelled.notices[-1]
    assert "namespace prefix" in misspelled.notices[-1][1], misspelled.notices[-1]
    assert not misspelled.runtime_dir.exists() and not misspelled.project.exists()


def test_an_out_of_range_port_is_a_refusal_not_a_traceback(tmp_path: Path):
    run = Launch(tmp_path, _marker(tmp_path / "bundle"), port=70000)
    assert _returns(run) == 2
    assert "0-65535" in run.notices[-1][1]
    assert (run.runtime_dir / "launch-failures.log").exists()


def test_notices_quote_and_cut_what_they_echo(tmp_path: Path):
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, readiness=3.0)
    run.runtime_dir.mkdir()
    holder = RuntimeLock(run.paths.lock)
    assert holder.acquire()
    try:
        write_record(run.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "t", "status": "failed",
                                        "port": _free_port(), "reason": "CALL 555-0100 NOW " * 2000})
        assert _returns(run) == 2
        assert len(run.notices[-1][1]) < 500 and "..." in run.notices[-1][1]
    finally:
        holder.release()


def test_w7_an_answer_without_this_runtimes_token_is_not_this_runtime(tmp_path: Path):
    """The token half of the identity rule, held while the lock is held by
    someone else: a listener on the RECORDED port that speaks the runtime
    schema with a different token -- even naming this very bundle -- is not
    this runtime; the launch neither opens it nor starts anything."""
    bundle = _marker(tmp_path / "bundle")
    impostor = _PlainServer(json.dumps({"schema": RUNTIME_SCHEMA, "instance": "other",
                                        "bundle_root": str(bundle.resolve())}).encode(),
                            "application/json")
    run = Launch(tmp_path, bundle, readiness=2.0)
    run.runtime_dir.mkdir()
    holder = RuntimeLock(run.paths.lock)
    assert holder.acquire()
    try:
        write_record(run.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "recorded",
                                        "status": "ready", "port": impostor.port, "pid": 4})
        assert _returns(run) == 2
        assert run.opened == [] and "did not answer" in run.notices[-1][1]
        assert probe_instance(impostor.port)["instance"] == "other", "the impostor was left alone"
    finally:
        holder.release()
        impostor.close()


def test_a_holder_that_recorded_a_failure_is_reported_in_its_own_words(tmp_path: Path):
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle)
    run.runtime_dir.mkdir()
    holder = RuntimeLock(run.paths.lock)
    assert holder.acquire()
    try:
        write_record(run.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "t", "status": "failed",
                                        "port": _free_port(), "reason": "the disk is full"})
        assert _returns(run) == 2
        assert "the disk is full" in run.notices[-1][1]
    finally:
        holder.release()


# ---------------------------------------------------------------------------
# Failure visibility: git, assembly
# ---------------------------------------------------------------------------

def test_a_launch_without_git_is_refused_by_name_before_anything_starts(tmp_path: Path):
    run = Launch(tmp_path, _marker(tmp_path / "bundle"), which=lambda name: None)
    assert _returns(run) == 2
    assert run.notices[-1][1] == GIT_MISSING and run.opened == []
    assert not run.paths.record.exists()
    trail = run.runtime_dir / "launch-failures.log"
    assert trail.exists() and "git was not found" in trail.read_text(encoding="utf-8")


def test_an_assembly_failure_is_recorded_and_told(tmp_path: Path):
    def broken(project: Path) -> FastAPI:
        raise RuntimeError("contracts directory unreadable")

    run = Launch(tmp_path, _marker(tmp_path / "bundle"), assemble_app=broken).start()
    assert run.join() == 2
    record = run.record()
    assert record["status"] == "failed" and "contracts directory unreadable" in record["reason"]
    assert "contracts directory unreadable" in run.notices[-1][1]
    assert RuntimeLock(run.paths.lock).acquire(), "the lock outlived a failed launch"


def test_the_entry_guard_makes_an_unloadable_folder_a_visible_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    """Under pythonw a traceback goes nowhere; the guard tells the person and
    leaves the traceback in the trail. Forced here by making the runtime
    module unimportable, which is what a partial copy looks like."""
    monkeypatch.setattr(windows_launch, "FAILURE_TRAIL", tmp_path / "trail.log")
    monkeypatch.setitem(sys.modules, "nornyx_forge.windows_runtime", None)
    with pytest.raises(SystemExit) as exit_:
        windows_launch.main(["--bundle-root", str(tmp_path)])
    assert exit_.value.code == 2
    assert "could not be loaded" in capsys.readouterr().err
    trail = (tmp_path / "trail.log").read_text(encoding="utf-8")
    assert "Traceback" in trail and "nornyx_forge.windows_runtime" in trail


def test_the_entry_guard_reports_a_crash_it_could_not_explain(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    """A non-refusal exception after the import guard -- measured under
    review with a lock path that was a directory -- is still a notice and a
    trail entry, never a traceback into nowhere."""
    monkeypatch.setattr(windows_launch, "FAILURE_TRAIL", tmp_path / "trail.log")

    def crash(argv):
        raise PermissionError(13, "Access is denied", str(tmp_path / "x.lock"))

    monkeypatch.setattr(windows_runtime, "launch", crash)
    with pytest.raises(SystemExit) as exit_:
        windows_launch.main(["--bundle-root", str(tmp_path)])
    assert exit_.value.code == 2
    err = capsys.readouterr().err
    assert "could not explain" in err and "PermissionError" in err
    assert "Access is denied" in (tmp_path / "trail.log").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# W18 / W20  operational state is not governance state; authority persists
# ---------------------------------------------------------------------------

def _real_surface(tmp_path: Path):
    def assemble_real(project: Path) -> FastAPI:
        return create_app(project / "capsule", CONTRACTS, seal_dir=tmp_path / "seals",
                          flow_factory=lambda *a, **k: None)

    return assemble_real


def _served_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A bundle folder the SERVED composition (`assemble`, the runtime's
    default seam) will run over: the packaged root pointed at it so the
    marker is the one `assemble` would see, the shipped contracts beside it,
    the seals kept out of the home, and no real flow constructible."""
    from nornyx_forge import development_flow, onboarding_serve

    bundle = _marker(tmp_path / "bundle")
    monkeypatch.setattr(onboarding_serve, "resolve_packaged_root", lambda: bundle)
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    monkeypatch.setattr(development_flow, "DevelopmentFlow", lambda *a, **k: None)
    (bundle / ".nornyx" / "contracts").mkdir(parents=True)
    for contract in CONTRACTS.glob("*.nyx"):
        (bundle / ".nornyx" / "contracts" / contract.name).write_bytes(contract.read_bytes())
    return bundle


def _request(port: int, method: str, path: str, host: str, body: dict | None = None,
             token: str | None = None) -> int:
    """One request on the real socket carrying an explicit Host header."""
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        headers = {"Host": host}
        if token:
            headers["Authorization"] = "Bearer " + token
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["content-type"] = "application/json"
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_h5_the_windows_runtime_composition_answers_only_to_a_loopback_host(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Through the SERVED composition on the real socket: a rebinding page's
    foreign Host is refused on every route, reads and the stop alike; both
    loopback identities answer, with or without a port; and the runtime adds
    no second copy of the rule -- the policy is `assemble`'s (N3 of the
    independent PR-18 review), so this launcher and the console `onboard`
    path inherit one and the same rule rather than each remembering it."""
    from nornyx_forge import onboarding_serve

    bundle = _served_bundle(tmp_path, monkeypatch)
    _scratch_profile(monkeypatch, tmp_path)
    run = Launch(tmp_path, bundle, assemble_app=onboarding_serve.assemble, browser=False,
                 session_file=True).start()
    ready = run.wait_for("ready")
    port = ready["port"]
    for host in ("evil.example", f"evil.example:{port}", "testserver", "192.168.1.20",
                 "127.0.0.1.evil.example", ""):
        for path in ("/api/runtime", "/api/state", "/"):
            assert _request(port, "GET", path, host, token=run.token) == 400, (host, path)
        assert _request(port, "POST", "/api/runtime/stop", host, {"actor": HUMAN},
                        token=run.token) == 400, host
    assert run.record()["status"] == "ready", "a foreign Host stopped the runtime"
    for host in ("127.0.0.1", "localhost", f"127.0.0.1:{port}", f"localhost:{port}"):
        for path in ("/api/runtime", "/api/state", "/"):
            assert _request(port, "GET", path, host, token=run.token) == 200, (host, path)
    runtime_source = Path(windows_runtime.__file__).read_text(encoding="utf-8")
    assert "TrustedHostMiddleware" not in runtime_source and "allowed_hosts" not in runtime_source, (
        "the runtime must inherit the Host rule from assemble, not restate it")
    assert run.stop()[0] == 200
    assert run.join() == 0


def test_w18_runtime_metadata_cannot_reach_the_governance_answer(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The real surface through the SERVED composition (`assemble`, the
    runtime's default), with the packaged root pointed at the bundle so the
    marker is the one `assemble` would see: a forged record and a forged
    marker beside it change nothing `/api/state` says, and neither module of
    the surface mentions the runtime's state. A review measured that the
    same pin over `create_app` alone missed a leak placed in `assemble`."""
    from nornyx_forge import onboarding_serve

    bundle = _served_bundle(tmp_path, monkeypatch)
    _scratch_profile(monkeypatch, tmp_path)
    run = Launch(tmp_path, bundle, assemble_app=onboarding_serve.assemble, browser=False,
                 session_file=True).start()
    ready = run.wait_for("ready")
    before = json.loads(_get(ready["port"], "/api/state", token=run.token)[1])
    assert before == {"initialized": False, "providers": list(PROVIDERS)}
    forged = {**ready, "experience": {"stage": "READY", "status": "active"},
              "approval": "granted", "provider_eligibility": {"claude": True}}
    write_record(run.paths.record, forged)
    (bundle / BUNDLE_MARKER).write_text(json.dumps({
        "schema": BUNDLE_SCHEMA, "mode": "developer", "approved": True, "stage": "READY"}),
        encoding="utf-8")
    assert json.loads(_get(ready["port"], "/api/state", token=run.token)[1]) == before
    served = json.loads(_get(ready["port"], "/api/runtime")[1])
    assert set(served) == {"schema", "instance", "bundle_root", "bundle_mode", "project_dir",
                           "port", "pid", "python", "started_at"}
    run.stop()
    assert run.join() == 0
    for module in (onboarding_app, onboarding_serve):
        surface = Path(module.__file__).read_text(encoding="utf-8")
        for absent in ("windows_runtime", RUNTIME_SCHEMA, "forge-bundle", ".nornyx/forge/runtime",
                       "BUNDLE_MARKER", "runtime_key"):
            assert absent not in surface, f"{module.__name__} must never read {absent}"
    record_keys = set(ready)
    for vocabulary in ("experience", "approval", "eligib", "ready_for", "verified", "inspect"):
        assert not any(vocabulary in key for key in record_keys), vocabulary


def test_w20_capsule_authority_persists_across_a_runtime_restart(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Create a project through the running surface, stop the runtime,
    start it again over the same project: the store is read back, the
    lifecycle is the one recorded, and the runtime is a new instance."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    first = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False,
                   session_file=True).start()
    ready = first.wait_for("ready")
    status, created = _post(ready["port"], "/api/project", {
        "project_id": "proj-w20", "project_name": "Persisting", "actor": HUMAN}, token=first.token)
    assert status == 200, created
    assert first.stop()[0] == 200 and first.join() == 0

    second = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False,
                    session_file=True).start()
    again = second.wait_for("ready")
    assert again["instance"] != ready["instance"]
    state = json.loads(_get(again["port"], "/api/state", token=second.token)[1])
    assert state["initialized"] is True and state["project_id"] == "proj-w20"
    assert state["experience"]["stage"] == "DISCOVER" and state["revision"] == created["revision"]
    assert state["authority"]["anchor"] == "sealed"
    second.stop()
    assert second.join() == 0


# ---------------------------------------------------------------------------
# Tranche B: the control-plane session over the real runtime
# ---------------------------------------------------------------------------

#: The only response headers the served runtime may emit (uvicorn adds date
#: and server). Declared, so a header carrying a secret is refused by NAME.
_ALLOWED_RESPONSE_HEADERS = frozenset({
    "content-type", "content-length", "date", "server", "connection", "transfer-encoding",
})


def _scratch_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *,
                     at: Path | None = None) -> Path:
    """Relocate the user profile for one test, as the bundle smoke and the
    Windows host test do for their child process. The `--session-file` fence
    refuses a path under the profile (A-027). Where tmp_path lies relative to
    the real profile is a property of the HOST, not of the suite -- under it
    on the development workstation (%LOCALAPPDATA%\\Temp resolves beneath
    Path.home()), outside it on the Linux CI matrix (/tmp against
    /home/runner) -- so no test here may depend on either: a test that passes
    a session file gives the runtime a profile of its own to be fenced from,
    and a test that needs the profile to CONTAIN a path relocates it to `at`
    and then asserts the containment. Nothing else here reads the relocated
    profile: the capsule store's git carries `-c` identity overrides, and the
    seal and runtime directories are passed explicitly."""
    profile = at if at is not None else tmp_path / "profile"
    profile.mkdir(exist_ok=True)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("HOME", str(profile))
    assert Path.home() == profile
    return profile


def _exchange(port: int, method: str, path: str, *, body: bytes | None = None,
              headers: dict | None = None) -> tuple[int, dict, bytes]:
    """One request on the real socket; the status, the response headers
    (lowercased) and the body. Header values may be bytes, so a non-latin-1
    credential can be sent exactly as an attacker would send it."""
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.putrequest(method, path)
        for name, value in (headers or {}).items():
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("content-length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        connection.close()


def _redeem(port: int, nonce: str) -> tuple[int, dict]:
    """Redeem a bootstrap nonce over the socket, as the page does: a same-origin
    POST carries an Origin matching the Host, which the gate requires."""
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.request("POST", "/api/session/redeem",
                           body=json.dumps({"nonce": nonce}).encode("utf-8"),
                           headers={"content-type": "application/json",
                                    "Origin": f"http://{ONBOARDING_HOST}:{port}"})
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def _reopen(port: int) -> tuple[int, dict]:
    """Ask a runtime to reopen, as a non-browser caller does: no Origin, no
    Sec-Fetch-Site, which the gate permits for reopen only."""
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.request("POST", "/api/runtime/reopen", body=b"{}",
                           headers={"content-type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def _await_opened(run: "Launch", count: int = 1, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(run.opened) < count:
        time.sleep(0.05)
    assert len(run.opened) >= count, f"the browser was opened {len(run.opened)} times, not {count}"


def _nonce_of(opened_url: str) -> str:
    return opened_url.split("#", 1)[1]


def _secret_free(blob: str, secrets: dict[str, str], where: str) -> None:
    for label, secret in secrets.items():
        assert secret not in blob, f"{label} leaked into {where}"


def test_the_runtime_opens_the_browser_with_a_nonce_and_leaks_neither_secret(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """INV-B2 over the REAL surface: the browser is opened at `/#<nonce>`, the
    nonce redeems ONCE for the bearer, and neither the token nor the nonce
    appears in the record, the log, the launch-failures trail, the
    unauthenticated `/` page, `/api/runtime`, or ANY response header the
    served runtime emits -- which are only the declared ones, never Set-Cookie."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True).start()
    ready = run.wait_for("ready")
    _await_opened(run)
    opened = run.opened[0]
    assert opened.startswith(ready["url"] + "#"), opened
    nonce = _nonce_of(opened)
    token = run.token
    assert token and nonce and nonce != token
    port = ready["port"]
    secrets = {"token": token, "nonce": nonce}

    # Every kind of response the served runtime emits, with its headers.
    observed = {
        "401": _exchange(port, "GET", "/api/state"),
        "page": _exchange(port, "GET", "/"),
        "runtime": _exchange(port, "GET", "/api/runtime"),
        "404 nonce": _exchange(port, "POST", "/api/session/redeem", body=b'{"nonce": "wrong"}',
                               headers={"content-type": "application/json",
                                        "Origin": f"http://{ONBOARDING_HOST}:{port}"}),
        "403": _exchange(port, "POST", "/api/session/redeem", body=b'{"nonce": "wrong"}',
                         headers={"content-type": "application/json", "Origin": "null"}),
        "authed": _exchange(port, "GET", "/api/state", headers=_auth(token)),
    }
    # The nonce is single-use: it redeems for the bearer once, then never again.
    status, body = _redeem(port, nonce)
    assert status == 200 and body["token"] == token
    assert _redeem(port, nonce)[0] == 404
    for label, (status, headers, payload) in observed.items():
        assert set(headers) <= _ALLOWED_RESPONSE_HEADERS, (label, set(headers) - _ALLOWED_RESPONSE_HEADERS)
        assert "set-cookie" not in headers, label
        _secret_free(json.dumps(headers), secrets, f"{label} headers")
        _secret_free(payload.decode("utf-8", errors="replace"), secrets, f"{label} body")
    assert observed["401"][0] == 401 and observed["403"][0] == 403 and observed["404 nonce"][0] == 404
    assert observed["authed"][0] == 200

    record_text = run.paths.record.read_text(encoding="utf-8")
    log_text = run.paths.log.read_text(encoding="utf-8")
    trail_text = (run.paths.failures.read_text(encoding="utf-8")
                  if run.paths.failures.exists() else "")
    for blob, where in ((record_text, "record"), (log_text, "log"), (trail_text, "trail")):
        _secret_free(blob, secrets, where)
    assert run.stop()[0] == 200 and run.join() == 0
    # Stopping removes the explicit session file.
    assert run.session_path is not None and not run.session_path.exists()


def test_reopen_mints_a_fresh_nonce_never_returns_the_token_and_is_rate_limited(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """reopen opens a second page with a nonce of its OWN slot: the body is
    exactly {"reopening": true}, the launch nonce still redeems afterwards
    (a local process calling reopen cannot invalidate the person's pending
    bootstrap), both nonces are single-use, and a second reopen within the
    interval is refused with the fixed body."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True).start()
    ready = run.wait_for("ready")
    _await_opened(run)
    launch_nonce = _nonce_of(run.opened[0])
    status, body = _reopen(ready["port"])
    assert status == 200 and body == {"reopening": True}, body
    _await_opened(run, count=2)
    reopen_nonce = _nonce_of(run.opened[1])
    assert run.opened[1].startswith(ready["url"] + "#") and reopen_nonce != launch_nonce
    assert run.token not in json.dumps(body) and reopen_nonce not in json.dumps(body)
    # A second reopen within the interval is refused, and the refusal names nothing.
    status, refused = _reopen(ready["port"])
    assert status == 429 and refused == windows_runtime.REOPEN_BUSY
    # The launch nonce survived the reopen; each nonce redeems exactly once.
    assert _redeem(ready["port"], launch_nonce)[1]["token"] == run.token
    assert _redeem(ready["port"], reopen_nonce)[1]["token"] == run.token
    assert _redeem(ready["port"], launch_nonce)[0] == 404
    assert _redeem(ready["port"], reopen_nonce)[0] == 404
    assert run.stop()[0] == 200 and run.join() == 0


def test_reopen_is_refused_when_the_runtime_was_started_without_a_browser(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`--no-browser` never granted browser authority to this run, so no
    caller can make it open one: reopen is 409 with a fixed body, before the
    rate limit, and nothing is opened. The page's Reconnect says so."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False,
                 session_file=True).start()
    ready = run.wait_for("ready")
    for _ in range(3):
        status, body = _reopen(ready["port"])
        assert status == 409 and body == windows_runtime.REOPEN_NOT_GRANTED, (status, body)
    time.sleep(0.2)
    assert run.opened == [], "a --no-browser runtime opened a browser on request"
    assert run.token not in json.dumps(body)
    from nornyx_forge.onboarding_app import _PAGE  # noqa: PLC0415
    assert "r.status === 409" in _PAGE
    assert run.stop()[0] == 200 and run.join() == 0


def test_a_second_launch_reopens_the_owner_rather_than_opening_itself(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The joining launcher has no session, so it asks the OWNING process to
    open a fresh page (with a nonce) instead of opening the URL itself."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    first = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True).start()
    ready = first.wait_for("ready")
    _await_opened(first)
    second = Launch(tmp_path, bundle)
    assert _returns(second) == 0
    assert second.opened == [], "the joining launch opened its own browser"
    assert second.notices == [], "a successful reopen needs no notice"
    _await_opened(first, count=2)
    assert first.opened[-1].startswith(ready["url"] + "#"), "the owner reopened with a nonce"
    assert _nonce_of(first.opened[-1]) != _nonce_of(first.opened[0])
    assert first.stop()[0] == 200 and first.join() == 0


def test_a_second_launch_is_told_when_the_owner_will_not_reopen(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Architecture P3-2: when the owner refuses to reopen -- rate-limited, or
    started without a browser -- the joining launch does not return 0 in
    silence; it tells the person, with the fragmentless URL to open by hand,
    and no secret."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    # Rate-limited: the owner just opened a page.
    owner = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True).start()
    ready = owner.wait_for("ready")
    _await_opened(owner)
    assert _reopen(ready["port"])[0] == 200
    _await_opened(owner, count=2)
    joiner = Launch(tmp_path, bundle)
    assert _returns(joiner) == 0
    assert joiner.opened == []
    assert len(joiner.notices) == 1, joiner.notices
    title, text = joiner.notices[0]
    assert title == "Forge is running" and ready["url"] in text and "a moment ago" in text
    assert "#" not in text and owner.token not in text
    for opened in owner.opened:
        assert _nonce_of(opened) not in text
    assert len(owner.opened) == 2, "the refused join made the owner open another page"
    assert owner.stop()[0] == 200 and owner.join() == 0

    # Started without a browser: reopen is 409 and the joiner says why.
    quiet = Launch(tmp_path / "quiet", bundle, assemble_app=_real_surface(tmp_path / "quiet"),
                   browser=False, session_file=True)
    (tmp_path / "quiet").mkdir(exist_ok=True)
    quiet.start()
    ready = quiet.wait_for("ready")
    joiner = Launch(tmp_path / "quiet", bundle)
    assert _returns(joiner) == 0
    assert joiner.opened == [] and quiet.opened == []
    assert len(joiner.notices) == 1
    title, text = joiner.notices[0]
    assert title == "Forge is running" and ready["url"] in text and "without a browser" in text
    assert "#" not in text and quiet.token not in text
    assert quiet.stop()[0] == 200 and quiet.join() == 0


def test_a_second_launch_is_told_when_the_owner_cannot_open_a_browser(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Security N-2: the owner's browser adapter raises on the reopen. The
    joiner reads the 503 and tells the person, with the fragmentless URL and
    no secret, instead of returning 0 in silence over a 200 it never
    inspected (measured under the second review)."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    owner = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True)
    targets: list[str] = []
    original = owner.seams["open_browser"]

    def opener(url: str) -> None:
        targets.append(url)
        if len(targets) > 1:
            raise OSError(1155, "No application is associated with the specified file", url)
        original(url)

    owner.seams["open_browser"] = opener
    owner.start()
    ready = owner.wait_for("ready")
    _await_opened(owner)
    joiner = Launch(tmp_path, bundle)
    assert _returns(joiner) == 0
    assert joiner.opened == [], "the joiner opened a page itself"
    assert len(targets) == 2, "the owner was not asked to reopen"
    assert len(joiner.notices) == 1, joiner.notices
    title, text = joiner.notices[0]
    assert title == "Forge is running" and ready["url"] in text and "could not open a browser" in text
    assert "#" not in text and owner.token not in text and _nonce_of(targets[1]) not in text
    assert owner.stop()[0] == 200 and owner.join() == 0


def _raising_openers():
    """Every way the browser adapter fails, each embedding the URL it was
    given -- fragment included -- the way the real sources do: the adapter's
    own ValueError names the URL with repr, its Windows-only OSError names it
    in prose, os.startfile raises an OSError whose `filename` is the URL, and
    a handler may raise a class of its own that is neither (which a branch
    naming only OSError and ValueError let out of the thread)."""
    def prose(url: str) -> None:
        raise OSError(f"opening the default browser is implemented for Windows only; open {url} yourself")

    def quoted(url: str) -> None:
        raise ValueError(f"only the loopback onboarding surface may be opened in the browser, not {url!r}")

    def filename(url: str) -> None:
        raise OSError(1155, "No application is associated with the specified file for this operation", url)

    class HandlerRefused(Exception):
        """Neither OSError nor ValueError: a handler's own class."""

    def custom(url: str) -> None:
        raise HandlerRefused(f"the default handler declined {url}")

    class Unspeakable(Exception):
        """A class whose own `__str__` raises (security P4-4, round 3): the
        scrubber ran `str(exc)` INSIDE the except that caught the adapter, so
        this would have thrown from there -- out of the branch, out of the
        thread, into a traceback carrying the instance and its URL."""

        def __str__(self) -> str:
            raise RuntimeError("this exception cannot be rendered")

    def unspeakable(url: str) -> None:
        raise Unspeakable(url)

    unspeakable.renders = False  # type: ignore[attr-defined]

    return [pytest.param(prose, id="OSError-prose"), pytest.param(quoted, id="ValueError-repr"),
            pytest.param(filename, id="OSError-filename"), pytest.param(custom, id="custom-class"),
            pytest.param(unspeakable, id="str-raises")]


@pytest.mark.parametrize("failure", _raising_openers())
def test_a_failed_browser_open_records_and_logs_neither_the_nonce_nor_the_token(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure):
    """Architecture P1-1: on the browser-open FAILURE branch the record, the
    log, the notice and the trail carry neither the launch nonce nor the token,
    whatever the exception text embedded -- and they live under the runtime
    directory, which CodexSandboxUsers can read. The record still says the
    browser did not open, and names the fragmentless URL."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True)
    targets: list[str] = []

    def opener(url: str) -> None:
        targets.append(url)
        failure(url)

    run.seams["open_browser"] = opener
    run.start()
    ready = run.wait_for("ready")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (run.record() or {}).get("browser", {}).get("opened") is not False:
        time.sleep(0.05)
    record = run.record()
    assert record["browser"]["opened"] is False and record["browser"]["error"], record["browser"]
    assert targets and "#" in targets[0]
    nonce = _nonce_of(targets[0])
    secrets = {"token": run.token, "nonce": nonce, "target": targets[0]}
    trail = run.paths.failures.read_text(encoding="utf-8") if run.paths.failures.exists() else ""
    for blob, where in ((run.paths.record.read_text(encoding="utf-8"), "record"),
                        (run.paths.log.read_text(encoding="utf-8"), "log"),
                        (json.dumps(run.notices), "notices"), (trail, "trail")):
        _secret_free(blob, secrets, where)
    error = record["browser"]["error"]
    if getattr(failure, "renders", True):
        assert ready["url"] in error or "<redacted>" in error, error
    else:
        # A `__str__` that raises is described by class name and nothing the
        # instance rendered; the branch survived it instead of throwing.
        assert "Unspeakable" in error and "could not be rendered" in error, error
    assert run.notices and run.notices[-1][0] == "Forge is running" and ready["url"] in run.notices[-1][1]
    # A failed opening did not spend the nonce: the page can still be redeemed by hand.
    assert _redeem(ready["port"], nonce)[0] == 200
    assert run.stop()[0] == 200 and run.join() == 0


@pytest.mark.parametrize("failure", _raising_openers())
def test_a_failed_reopen_logs_no_secret_and_names_only_the_fragmentless_url(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure):
    """Security N-2 / architecture P4-3: when the owner's browser adapter
    raises -- whatever the exception's class -- reopen answers 503 with the
    fixed body, never 200 (a 200 was read as success by the joining launcher,
    which returned in silence), the log names the fragmentless URL and no
    traceback, and neither the log nor the record carries the reopen nonce or
    the target. The page has a branch for 503 and for 429."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True)
    targets: list[str] = []
    original = run.seams["open_browser"]

    def opener(url: str) -> None:
        targets.append(url)
        if len(targets) > 1:
            failure(url)
        original(url)

    run.seams["open_browser"] = opener
    run.start()
    ready = run.wait_for("ready")
    _await_opened(run)
    status, body = _reopen(ready["port"])
    assert status == 503 and body == windows_runtime.REOPEN_FAILED, (status, body)
    assert len(targets) == 2
    secrets = {"token": run.token, "reopen nonce": _nonce_of(targets[1]), "target": targets[1]}
    _secret_free(json.dumps(body), secrets, "reopen body")
    log_text = run.paths.log.read_text(encoding="utf-8")
    _secret_free(log_text, secrets, "log")
    assert "Traceback" not in log_text and ready["url"] in log_text
    _secret_free(run.paths.record.read_text(encoding="utf-8"), secrets, "record")
    from nornyx_forge.onboarding_app import _PAGE  # noqa: PLC0415
    assert "r.status === 503" in _PAGE and "r.status === 429" in _PAGE
    assert run.stop()[0] == 200 and run.join() == 0


#: The Windows namespace prefixes, spelled once: extended-length and device.
_EXT = "\\\\?\\"
_DEV = "\\\\.\\"
#: The words the fence uses for a path it will not compare at all.
_DOUBLE_SEPARATOR = "begins with a double separator"


def _unc_spelling(path: Path) -> str:
    r"""`path` reached through the local administrative share -- the same
    NTFS location in a UNC spelling (`\\localhost\C$\Users\...`). On POSIX the
    same string shape, which is what the fence judges."""
    tail = str(path).replace("\\", "/").split(":", 1)[-1].lstrip("/")
    return "//localhost/C$/" + tail


#: kind -> (how the refused path is built from the launch, the words the refusal must carry).
#: The root cases name the fence that FIRED ("is inside <root>"): every root
#: refusal ends with a tail listing all four roots, so a root's bare name
#: would be satisfied by any fence at all. The `*_extended` cases are the
#: same four roots spelled with the `\\?\` prefix -- security P2-1 (round 3),
#: measured end to end: `--session-file \\?\<profile>\stolen.json` launched
#: READY and wrote the bearer inside the profile -- plus the device prefix, a
#: forward-slash prefix, and a UNC spelling, each refused BY NAME before the
#: fence compares anything.
_FENCED_SESSION_PATHS = {
    "relative": (lambda tmp_path, run: "session.json", "must be absolute"),
    "project": (lambda tmp_path, run: str(run.project / "session.json"), "is inside the project directory"),
    "runtime": (lambda tmp_path, run: str(run.runtime_dir / "session.json"), "is inside the runtime directory"),
    "profile": (lambda tmp_path, run: str(tmp_path / "session.json"), "is inside the user profile"),
    "seal": (lambda tmp_path, run: str(windows_runtime.DEFAULT_SEAL_DIR / "session.json"),
             "is inside the seal directory"),
    "missing": (lambda tmp_path, run: str(tmp_path / "missing" / "session.json"), "existing directory"),
    "directory": (lambda tmp_path, run: str(tmp_path), "is a directory"),
    "project_extended": (lambda tmp_path, run: _EXT + str(run.project / "session.json"), _DOUBLE_SEPARATOR),
    "runtime_extended": (lambda tmp_path, run: _EXT + str(run.runtime_dir / "session.json"), _DOUBLE_SEPARATOR),
    "profile_extended": (lambda tmp_path, run: _EXT + str(tmp_path / "session.json"), _DOUBLE_SEPARATOR),
    "seal_extended": (lambda tmp_path, run: _EXT + str(windows_runtime.DEFAULT_SEAL_DIR / "session.json"),
                      _DOUBLE_SEPARATOR),
    "profile_device": (lambda tmp_path, run: _DEV + str(tmp_path / "session.json"), _DOUBLE_SEPARATOR),
    "profile_forward_extended": (lambda tmp_path, run: "//?/" + str(tmp_path / "session.json").replace("\\", "/"),
                                 _DOUBLE_SEPARATOR),
    "profile_unc": (lambda tmp_path, run: _unc_spelling(tmp_path / "session.json"), _DOUBLE_SEPARATOR),
}
_PROFILE_CASES = ("profile", "profile_extended", "profile_device", "profile_forward_extended", "profile_unc")
_SEAL_CASES = ("seal", "seal_extended")


@pytest.mark.parametrize("kind", sorted(_FENCED_SESSION_PATHS))
def test_the_session_file_is_fenced_and_a_refused_path_creates_nothing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str):
    """Security F-2 / architecture P3-1: `--session-file` is reachable through
    `Forge.cmd %*`, and review measured it writing the bearer inside
    <project>/capsule/. Fenced like `--runtime-dir`: it must lie outside the
    project, the runtime directory, the seal directory and the user profile,
    be absolute, and land in an existing directory. A refused launch returns
    2, tells the person, and creates NOTHING -- not the runtime directory, not
    the trail, not the file.

    Each case makes its own precondition TRUE and asserts it, rather than
    reading it off the host. The `profile*` cases relocate the profile so that
    it CONTAINS the candidate; the `seal*` cases relocate the profile AWAY and
    point the seal directory at a scratch directory of their own, so the seal
    fence is the ONLY fence that can fire (round-3 test P4: with the seal
    directory under the real profile this case was a three-way disjunction
    and the seal fence entry could be deleted without a red test); the two
    shape cases relocate the profile away so the profile fence cannot mask
    them; the root cases need no profile at all, because their roots are
    judged first. Round-2 test P1-1 measured the alternative: this case
    assumed tmp_path lay under the profile, which is true on the development
    workstation and false on the Linux CI matrix, where the unfenced launch
    became a server and the job hung. Every launch here is held to a watched
    deadline for the same reason: under a fence-removed mutant the launch
    serves instead of refusing, and that must be a red test within seconds,
    never a stall."""
    if kind in ("directory", "missing"):
        _scratch_profile(monkeypatch, tmp_path)
    elif kind in _PROFILE_CASES:
        _scratch_profile(monkeypatch, tmp_path, at=tmp_path)
    elif kind in _SEAL_CASES:
        _scratch_profile(monkeypatch, tmp_path)
        seals = tmp_path / "seals"
        seals.mkdir()
        monkeypatch.setattr(windows_runtime, "DEFAULT_SEAL_DIR", seals)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, browser=False)
    (tmp_path / "project").mkdir(exist_ok=True)
    build, words = _FENCED_SESSION_PATHS[kind]
    candidate = build(tmp_path, run)
    if kind in _PROFILE_CASES:
        # The precondition is about the LOCATION, so it is asserted on the
        # plain spelling of the candidate, whatever prefix the case adds.
        plain = str(tmp_path / "session.json")
        assert Path.home().resolve() in Path(plain).resolve().parents, (
            "this case's precondition -- the profile contains the candidate -- is false")
    if kind in _SEAL_CASES:
        seal_dir = windows_runtime.DEFAULT_SEAL_DIR.resolve()
        assert Path.home().resolve() not in seal_dir.parents and seal_dir != Path.home().resolve(), (
            "this case's precondition -- the seal directory lies outside the profile -- is false")
        assert run.runtime_dir.resolve() not in seal_dir.parents and run.project.resolve() not in seal_dir.parents
    run.argv = [*run.argv, "--session-file", candidate]
    assert _returns(run) == 2
    assert not run.runtime_dir.exists(), "a refused session file still created the runtime directory"
    if kind not in ("directory", "relative", "profile_unc"):
        assert not Path(candidate).exists()
    assert not (tmp_path / "session.json").exists()
    assert run.notices and run.notices[-1][0] == "Forge could not start"
    text = run.notices[-1][1]
    assert text.startswith("the session file"), text
    assert words in text, text
    if kind in _SEAL_CASES:
        assert list((tmp_path / "seals").iterdir()) == [], "the refusal wrote into the seal directory"


def test_the_session_file_is_written_only_after_readiness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Test P3-1: the bearer reaches the explicit file only once the server has
    answered for itself. The readiness probe is slowed so the window between
    serving and readiness is observable; at every observation in that window
    the file is absent, and once it exists the record already says ready.
    On POSIX the file is created with mode 0600."""
    _scratch_profile(monkeypatch, tmp_path)
    real_probe = windows_runtime.probe_instance
    delayed = {"done": False}

    def slow_probe(port, *, timeout=windows_runtime.PROBE_TIMEOUT_S):
        if not delayed["done"]:
            delayed["done"] = True
            time.sleep(1.5)
        return real_probe(port, timeout=timeout)

    monkeypatch.setattr(windows_runtime, "probe_instance", slow_probe)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False,
                 session_file=True).start()
    observed_window = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        exists = run.session_path.exists()   # checked FIRST: the file follows the record
        record = run.record()
        if exists:
            assert record is not None and record["status"] == "ready", (
                f"the session file existed while the record said {record and record['status']}")
            break
        if record is not None and record["status"] == "starting":
            observed_window = True
        time.sleep(0.02)
    else:
        raise AssertionError("the session file was never written")
    assert observed_window, "the readiness window was never observed; the test proved nothing"
    if sys.platform != "win32":
        import stat  # noqa: PLC0415
        assert stat.S_IMODE(run.session_path.stat().st_mode) == 0o600
    assert run.stop()[0] == 200 and run.join() == 0


def test_a_pre_existing_session_file_is_left_as_found_and_the_person_is_told(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Architecture P4-2: the session file is created EXCLUSIVELY, and a file
    already at the path -- stale, or planted ahead of the launch -- is
    neither overwritten nor removed at stop. The runtime still reaches ready
    and serves; the person is told, by path, that this run's bearer was
    written nowhere; the log names the path and no secret; and the planted
    bytes are identical afterwards. A stale token authenticates nothing."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True)
    planted = json.dumps({"schema": windows_runtime.RUNTIME_SESSION_SCHEMA,
                          "instance": "stale", "token": "STALE-TOKEN-NOT-THIS-RUNS"}).encode("utf-8")
    run.session_path.write_bytes(planted)
    run.start()
    ready = run.wait_for("ready")
    _await_opened(run)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not any("already exists" in text for _, text in run.notices):
        time.sleep(0.05)
    assert run.session_path.read_bytes() == planted, "the pre-existing file was overwritten"
    assert any(title == "Forge is running" and "already exists" in text and str(run.session_path) in text
               for title, text in run.notices), run.notices
    real_token = _redeem(ready["port"], _nonce_of(run.opened[0]))[1]["token"]
    assert real_token != "STALE-TOKEN-NOT-THIS-RUNS"
    log_text = run.paths.log.read_text(encoding="utf-8")
    assert "already exists" in log_text and real_token not in log_text
    assert real_token not in json.dumps(run.notices)
    assert _post(ready["port"], "/api/runtime/stop", {"actor": HUMAN},
                 token="STALE-TOKEN-NOT-THIS-RUNS")[0] == 401
    assert _post(ready["port"], "/api/runtime/stop", {"actor": HUMAN}, token=real_token)[0] == 200
    assert run.join() == 0
    assert run.session_path.read_bytes() == planted, "stop removed a file this run did not write"
    assert not _staging(run.session_path).exists(), "a staging file outlived the refusal"


def test_the_session_file_is_never_observable_with_partial_content(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The window this PR closes, at the writer.

    The old shape created the FINAL name with `O_EXCL` and wrote the payload
    afterwards. A reader between the two -- and the harnesses were readers,
    waiting for exactly that name to appear -- found an empty file, parsed no
    bearer and sent its first request bare. The windows-runtime job failed
    that way once at PR #46's head: the first bearered `POST /api/project`
    answered `401`, one child ever started, its record `ready`. The bundle
    smoke was immune because it polls until the token PARSES; nothing else
    was.

    The specimen is a slow writer: a 200 ms pause between the create and the
    content, on whichever file the placement opens. A reader polls the FINAL
    path throughout, and EVERY observation must be either the path absent or
    a complete record carrying the bearer -- never the empty or half-written
    file the old shape exposed. The count of absent observations is asserted
    too, so a test that raced past the window proves nothing quietly.

    Revert `_place_session_file` to create-then-write on the final name and
    this is red on the first observation inside the pause."""
    path = tmp_path / "session.json"
    payload = json.dumps({"schema": windows_runtime.RUNTIME_SESSION_SCHEMA,
                          "instance": "this-run", "token": "THE-BEARER"}) + "\n"
    inside = threading.Event()
    watched: set[int] = set()
    real_open, real_fdopen = os.open, os.fdopen

    def watching_open(file, flags, mode=0o777, **kwargs):
        descriptor = real_open(file, flags, mode, **kwargs)
        # The final name (the old shape) or the staging name beside it (the
        # new one): whichever this placement opens for the payload.
        if str(file).startswith(str(path)):
            watched.add(descriptor)
        return descriptor

    class _Paused:
        """The sink, with the pause between the create and the content."""

        def __init__(self, sink):
            self._sink = sink

        def __enter__(self):
            self._sink.__enter__()
            return self

        def __exit__(self, *info):
            return self._sink.__exit__(*info)

        def write(self, text):
            inside.set()
            time.sleep(0.2)
            return self._sink.write(text)

        def flush(self):
            return self._sink.flush()

        def fileno(self):
            return self._sink.fileno()

    def slow_fdopen(descriptor, *args, **kwargs):
        sink = real_fdopen(descriptor, *args, **kwargs)
        if descriptor in watched:
            # Once: a closed descriptor's NUMBER is reusable, and an unrelated
            # open that inherited it must not be slowed.
            watched.discard(descriptor)
            return _Paused(sink)
        return sink

    monkeypatch.setattr(windows_runtime.os, "open", watching_open)
    monkeypatch.setattr(windows_runtime.os, "fdopen", slow_fdopen)
    failed: list[BaseException] = []

    def place() -> None:
        try:
            windows_runtime._place_session_file(path, payload)
        except BaseException as exc:  # noqa: BLE001 - reported by the assertion below
            failed.append(exc)

    writer = threading.Thread(target=place, name="placing", daemon=True)
    writer.start()
    assert inside.wait(30), "the write step was never reached; the test proved nothing"
    partial: list[bytes] = []
    absent = observations = 0
    while writer.is_alive():
        observations += 1
        try:
            seen = path.read_bytes()
        except FileNotFoundError:
            absent += 1
            time.sleep(0.002)
            continue
        except OSError:
            # A sharing refusal at the instant of the move is not an
            # observation of content, and is not counted as one either way.
            time.sleep(0.002)
            continue
        try:
            complete = json.loads(seen.decode("utf-8")).get("token") == "THE-BEARER"
        except (UnicodeDecodeError, ValueError):
            complete = False
        if complete:
            break
        partial.append(seen)
        time.sleep(0.002)
    writer.join(timeout=30)
    assert not failed, failed
    assert not partial, (
        f"the final path held incomplete content {partial[0]!r} while it was being "
        f"written ({len(partial)} of {observations} observations)")
    assert absent >= 3, (
        f"the write window was never observed ({observations} observations, {absent} "
        "with the path absent); the test proved nothing")
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == "THE-BEARER"
    assert [entry.name for entry in tmp_path.iterdir()] == ["session.json"], (
        "the placement left something beside its target")


def test_placing_a_session_file_refuses_one_already_there_and_leaves_it_as_found(
        tmp_path: Path):
    """The exclusive create moved to the MOVE and still means what it meant.

    Staging and then moving could have become an overwrite by accident:
    `os.replace` and POSIX `os.rename` both silently clobber the target, and
    either would have turned a stale or planted bearer into this run's
    without a word. The move is `os.rename` on Windows and `os.link` on
    POSIX, each of which REFUSES an existing target, so the caller's
    `FileExistsError` branch -- the notice, by path, that this run's bearer
    was written nowhere -- is reached by the same exception as before.

    A staging name already taken is a DIFFERENT fact: the target may be free,
    and reporting it as "already exists" would name a path that does not
    exist. It is raised as a plain `OSError`, which is also why the raise
    carries ONE argument: `OSError(errno, text)` is remapped by the
    constructor to the errno's own subclass, and 17 is `FileExistsError`."""
    path = tmp_path / "session.json"
    planted = json.dumps({"schema": windows_runtime.RUNTIME_SESSION_SCHEMA,
                          "instance": "stale", "token": "PLANTED"}).encode("utf-8")
    path.write_bytes(planted)
    with pytest.raises(FileExistsError):
        windows_runtime._place_session_file(path, '{"token": "THIS-RUNS"}\n')
    assert path.read_bytes() == planted, "the pre-existing file was overwritten"
    assert not _staging(path).exists(), "a staging file outlived the refusal"

    free = tmp_path / "other.json"
    _staging(free).write_bytes(b"a staging file from somewhere else")
    with pytest.raises(OSError) as caught:  # noqa: PT011 - the class IS the assertion below
        windows_runtime._place_session_file(free, '{"token": "THIS-RUNS"}\n')
    assert not isinstance(caught.value, FileExistsError), (
        "a taken staging name was reported as the target already existing")
    assert "staging" in str(caught.value) and str(_staging(free)) in str(caught.value)
    assert not free.exists(), "the target was created after the staging name was refused"
    assert _staging(free).read_bytes() == b"a staging file from somewhere else", (
        "a staging file this call did not make was removed")


def test_no_staging_file_outlives_a_placement_that_succeeded_or_failed(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The staging name is an implementation detail and must never become
    litter the person finds, or a `FileExistsError` the NEXT launch trips
    over: the file is gone before the call returns, on success and on
    failure alike.

    The failure specimen is one that strikes AFTER the staging file exists
    and holds the bearer -- the only interesting shape, and the one a `finally`
    exists for. `os.fsync` is refused rather than the move, because the move
    is platform-split and the flush is not."""
    placed = tmp_path / "ok.json"
    windows_runtime._place_session_file(placed, '{"token": "THE-BEARER"}\n')
    assert json.loads(placed.read_text(encoding="utf-8"))["token"] == "THE-BEARER"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["ok.json"]

    def refusing_fsync(descriptor):
        raise OSError("the write could not be flushed")

    monkeypatch.setattr(windows_runtime.os, "fsync", refusing_fsync)
    refused = tmp_path / "bad.json"
    with pytest.raises(OSError, match="could not be flushed"):
        windows_runtime._place_session_file(refused, '{"token": "THE-BEARER"}\n')
    assert not refused.exists(), "a failed placement left the target behind"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["ok.json"], (
        "a failed placement left its staging file behind")


def test_the_scripted_wait_holds_until_the_bearer_parses(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The harness half, and it does not depend on the writer's shape.

    `Launch.wait_for("ready")` used to return the moment the session file
    EXISTED. `.token` answers None for a file it cannot parse, so a reader
    that arrived between a create and its content got None out of exactly the
    `wait_for` that had just returned, and sent its first request bare. The
    real writer no longer opens that window; this pins that the WAIT would
    survive one that did.

    So the placement is replaced by the adversary: a create that exposes an
    empty file and completes it 0.3 s later. The wait must not return inside
    that window, and what it returns with must be a bearer. Restore
    `self.session_path.exists()` and this is red on the first assertion, with
    `None` for a token."""
    _scratch_profile(monkeypatch, tmp_path)
    seen: dict = {}

    def exposing_placement(path: Path, payload: str) -> None:
        path.write_bytes(b"")
        seen["empty_at"] = time.monotonic()
        time.sleep(0.3)
        seen["content_at"] = time.monotonic()
        path.write_text(payload, encoding="utf-8", newline="")

    monkeypatch.setattr(windows_runtime, "_place_session_file", exposing_placement)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False,
                 session_file=True).start()
    run.wait_for("ready")
    returned_at = time.monotonic()
    assert _parsed(run.token), f"the wait returned with no bearer: {run.token!r}"
    # The moment content BEGAN, not the moment it finished: an assertion on
    # the finish could be beaten by microseconds and would be flaky in the
    # direction of passing.
    assert returned_at >= seen["content_at"], (
        f"the wait returned {seen['content_at'] - returned_at:.3f}s before the bearer was "
        "written, on a file that existed and parsed to nothing")
    assert returned_at - seen["empty_at"] >= 0.25, (
        f"the wait returned {returned_at - seen['empty_at']:.3f}s after the empty file "
        "appeared, which is inside the 0.3s window")
    assert run.stop()[0] == 200 and run.join() == 0


def _mover() -> str:
    """The name of the `os` function `_move_onto` actually calls here, so a
    test patches the arm this platform runs rather than the one it does
    not: `rename` on Windows, `link` on POSIX."""
    return "rename" if sys.platform == "win32" else "link"


def test_a_target_already_there_is_refused_before_any_bearer_reaches_disk(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Round-2 P3-1. The refusal notice says this run's bearer was written
    NOWHERE, and staging made that inexact: the whole payload was written to
    `<name>.tmp` and fsynced before the move discovered the target, then
    unlinked. A hard kill in between would have left a live bearer on disk
    for a case the person was told wrote none.

    So the ordinary case is decided FIRST, and the instrument is the file
    system call itself: with a file at the target, `os.open` is never reached
    and the directory gains nothing.

    The check is not the refusal. The MOVE still is, and the second half
    proves it: a target planted AFTER the check -- at the instant the staging
    file is created, which is inside the window a check cannot cover -- is
    still refused, still by `FileExistsError`, and is still left as found.
    Delete the `lexists` check and the first half is red; delete the move's
    refusal and the second half is."""
    planted = b'{"schema": "x", "instance": "stale", "token": "PLANTED"}\n'
    payload = json.dumps({"schema": windows_runtime.RUNTIME_SESSION_SCHEMA,
                          "instance": "this-run", "token": "THE-BEARER"}) + "\n"
    path = tmp_path / "session.json"
    path.write_bytes(planted)
    opened: list[str] = []
    real_open = os.open

    def watching_open(file, flags, mode=0o777, **kwargs):
        opened.append(str(file))
        return real_open(file, flags, mode, **kwargs)

    monkeypatch.setattr(windows_runtime.os, "open", watching_open)
    with pytest.raises(FileExistsError) as caught:
        windows_runtime._place_session_file(path, payload)
    assert str(path) in str(caught.value), caught.value
    assert opened == [], f"a file was created for a target already there: {opened}"
    assert [entry.name for entry in tmp_path.iterdir()] == ["session.json"]
    assert path.read_bytes() == planted, "the pre-existing file was touched"
    assert "THE-BEARER" not in path.read_text(encoding="utf-8")

    # The window the check cannot cover: the target appears while the staging
    # file is being created. The move is what refuses it.
    late = tmp_path / "late.json"

    def open_then_plant(file, flags, mode=0o777, **kwargs):
        descriptor = real_open(file, flags, mode, **kwargs)
        if str(file) == str(_staging(late)):
            late.write_bytes(planted)
        return descriptor

    monkeypatch.setattr(windows_runtime.os, "open", open_then_plant)
    with pytest.raises(FileExistsError):
        windows_runtime._place_session_file(late, payload)
    assert late.read_bytes() == planted, "the target that appeared late was overwritten"
    assert not _staging(late).exists(), "a staging file outlived the late refusal"

    # The residual this leaves is STATED, not implied: what a `finally` cannot
    # cover is a process that dies before it runs.
    assumptions = (ROOT / "docs" / "requirements" / "ASSUMPTIONS.md").read_text(encoding="utf-8")
    assert "between the fsync and the move" in assumptions, (
        "A-027 does not state the residual: a hard kill between the fsync and the move "
        "leaves the staging file holding a live bearer")


def test_the_move_retries_a_sharing_violation_and_never_leaves_a_staging_survivor(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Round-2 P3-2. Windows refuses to rename a file another process holds
    open at that instant, and the session file is polled by exactly such
    readers; one `ERROR_SHARING_VIOLATION` was observed at the move instant
    under review. The sibling `write_record` has retried its own replace for
    that reason all along; the move had no retry, so a reader mid-read turned
    a placement into a notice and a run into a bearer nobody could read.

    Windows: two refusals then a success is a SUCCESS, and it WAITED between
    them -- the pauses are counted at `time.sleep`, and the elapsed time is
    asserted as well, so neither a loop that spun without pausing nor a test
    that never entered it is mistaken for the repair. The count is the
    instrument and the clock is the corroboration, not the other way round:
    two nominal 50 ms sleeps measured 0.094 s on this host, so a threshold
    set at the nominal 0.1 s fails a loop that did exactly what it should.

    POSIX: the asymmetry is deliberate and is pinned as such. `os.link`
    refusing with `PermissionError` is a filesystem that forbids hard links,
    which no amount of waiting changes, so the first one is raised at once.

    Both: a mover that ALWAYS refuses ends in the caller's notice branch -- a
    plain `OSError` -- with no target and no staging survivor."""
    payload = json.dumps({"token": "THE-BEARER"}) + "\n"
    real_move = getattr(os, _mover())
    real_sleep = time.sleep
    refusals = {"left": 2}
    paused: list[float] = []

    def sticky(source, destination):
        if refusals["left"]:
            refusals["left"] -= 1
            raise PermissionError(32, "the file is in use by another process")
        return real_move(source, destination)

    def counting_sleep(seconds):
        paused.append(seconds)
        return real_sleep(seconds)

    monkeypatch.setattr(windows_runtime.os, _mover(), sticky)
    monkeypatch.setattr(windows_runtime.time, "sleep", counting_sleep)
    path = tmp_path / "retried.json"
    started = time.monotonic()
    if sys.platform == "win32":
        windows_runtime._place_session_file(path, payload)
        assert json.loads(path.read_text(encoding="utf-8"))["token"] == "THE-BEARER"
        assert paused == [0.05, 0.05], (
            f"two refusals were survived with pauses of {paused}, not the sibling "
            "`write_record`'s two of 50 ms")
        assert time.monotonic() - started >= 0.05, "the recorded pauses did not happen"
        assert refusals["left"] == 0, "the retry loop was never entered"
    else:
        with pytest.raises(OSError) as caught:  # noqa: PT011 - the class IS the assertion
            windows_runtime._place_session_file(path, payload)
        assert "in use by another process" in str(caught.value)
        assert refusals["left"] == 1, "a POSIX link refusal was retried; it is permanent"
        assert paused == [], f"a POSIX link refusal was waited on: {paused}"
        assert not path.exists()
    assert not _staging(path).exists(), "a staging file outlived the retried move"

    def always(source, destination):
        raise PermissionError(32, "the file is in use by another process")

    monkeypatch.setattr(windows_runtime.os, _mover(), always)
    hopeless = tmp_path / "hopeless.json"
    with pytest.raises(OSError) as refused:  # noqa: PT011 - the class IS the assertion below
        windows_runtime._place_session_file(hopeless, payload)
    assert not isinstance(refused.value, FileExistsError), (
        "a mover that refuses forever was reported as the target already existing")
    assert not hopeless.exists(), "a placement that never moved left a target behind"
    assert not _staging(hopeless).exists(), "a staging file outlived a move that never happened"


def test_a_staging_name_taken_after_a_successful_move_is_left_alone(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Round-2 P4-3. The unlink in the `finally` ran on every path, including
    the successful one -- where, on Windows, the rename has already taken the
    staging NAME and whatever holds it now belongs to somebody else: a second
    launch staging its own bearer, or the person. Deleting it was silent.

    The specimen is that race made deterministic: the mover does the real
    move and a foreign file takes the staging name in the same instant. The
    placement must succeed and the foreign file must survive, on both arms --
    on POSIX the link leaves the staging name in place, so the unlink DOES
    run and the identity check is the whole protection there.

    Remove the identity check (or the `consumed` flag) and this is red with
    the foreign file gone."""
    payload = json.dumps({"token": "THE-BEARER"}) + "\n"
    path = tmp_path / "session.json"
    real_move = getattr(os, _mover())
    foreign = b"a staging file another launch made"

    def move_then_take_the_name(source, destination):
        real_move(source, destination)
        with contextlib.suppress(OSError):
            os.unlink(source)          # the POSIX arm leaves the link behind
        Path(source).write_bytes(foreign)

    monkeypatch.setattr(windows_runtime.os, _mover(), move_then_take_the_name)
    windows_runtime._place_session_file(path, payload)
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == "THE-BEARER"
    assert _staging(path).exists(), "a file this call did not make was deleted"
    assert _staging(path).read_bytes() == foreign


def test_every_placement_failure_names_the_file_it_could_not_use(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Round-2 P4-1 and P4-2, and the failures read uniformly.

    A staging failure was announced against the FINAL path -- "the session
    file <target> could not be created" for a target that was never touched
    -- so the person was sent to look at the wrong file. Each failure now
    names the file the placement could not use.

    `path.with_name` is the second half: it raises `ValueError`, not
    `OSError`, for a path with no name, and this runs on the readiness
    thread, where the caller catches `OSError` and a `ValueError` would take
    the notice with it. A drive root is refused by `launch`'s fence long
    before this; the guard is here because the distance between the fence and
    this call is where that kind of assumption rots."""
    payload = json.dumps({"token": "THE-BEARER"}) + "\n"

    # 1. no staging name can be formed: a path whose name is empty.
    root = Path(tmp_path.anchor)
    with pytest.raises(OSError) as no_name:  # noqa: PT011 - the class IS the assertion
        windows_runtime._place_session_file(root, payload)
    assert not isinstance(no_name.value, ValueError), (
        "a ValueError escaped the placement onto the readiness thread")
    assert str(root) in str(no_name.value) and "staging name" in str(no_name.value)

    # 2. the target is already there: the ONE failure that names the target,
    #    because it is the caller's refusal branch.
    taken = tmp_path / "taken.json"
    taken.write_bytes(b"{}")
    with pytest.raises(FileExistsError) as exists:
        windows_runtime._place_session_file(taken, payload)
    assert str(taken) in str(exists.value)

    # 3. the staging name is already taken.
    free = tmp_path / "free.json"
    _staging(free).write_bytes(b"somebody else's staging file")
    with pytest.raises(OSError) as staged:  # noqa: PT011 - the class IS the assertion
        windows_runtime._place_session_file(free, payload)
    assert not isinstance(staged.value, FileExistsError)
    assert str(_staging(free)) in str(staged.value)

    # 4. the payload cannot be flushed.
    def refusing_fsync(descriptor):
        raise OSError("the write could not be flushed")

    monkeypatch.setattr(windows_runtime.os, "fsync", refusing_fsync)
    unwritable = tmp_path / "unwritable.json"
    with pytest.raises(OSError) as write_failed:  # noqa: PT011 - the class IS the assertion
        windows_runtime._place_session_file(unwritable, payload)
    assert str(_staging(unwritable)) in str(write_failed.value), (
        f"a staging failure was announced against the wrong file: {write_failed.value}")
    assert "could not be flushed" in str(write_failed.value), "the cause was dropped"
    monkeypatch.undo()

    # 5. the move fails for a reason that is not the target.
    def refusing_move(source, destination):
        raise OSError("the volume is full")

    monkeypatch.setattr(windows_runtime.os, _mover(), refusing_move)
    unmovable = tmp_path / "unmovable.json"
    with pytest.raises(OSError) as move_failed:  # noqa: PT011 - the class IS the assertion
        windows_runtime._place_session_file(unmovable, payload)
    assert str(_staging(unmovable)) in str(move_failed.value)
    assert str(unmovable) in str(move_failed.value)
    assert "the volume is full" in str(move_failed.value)
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["free.json.tmp", "taken.json"], (
        "a failed placement left a file behind")


class _Mute(Exception):
    """An exception that cannot render itself: `str(exc)` raises out of the
    `except` that caught it, which is what `_said` exists to survive. The
    class NAME is all `_said` may report, and nothing an instance holds."""

    def __str__(self) -> str:
        raise RuntimeError("this exception refuses to render itself")


class _MuteOSError(OSError):
    """The same, as an `OSError`, for the branches that catch that."""

    def __str__(self) -> str:
        raise RuntimeError("this exception refuses to render itself")


def test_an_assembly_failure_that_cannot_render_itself_is_still_a_notice(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Round-5 test P4-a. `_said` was put at the assembly-failure site in
    round 5 with NO test: no test in this suite so much as referenced "could
    not be assembled", so reverting `_said(exc)` to `str(exc)` there changed
    nothing that was measured.

    The specimen is the case `_said` exists for: an exception whose `__str__`
    raises. Interpolating it directly would throw from inside the `except`
    that is building the notice -- past the record update, past the socket
    close, past `notify` -- and the person would get a traceback where the
    contract says a fixed notice. Revert to `str(exc)` and this is red."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")

    def cannot_assemble(project: Path):
        raise _Mute()

    run = Launch(tmp_path, bundle, assemble_app=cannot_assemble)
    run.start()
    assert run.join() == 2
    title, text = run.notices[-1]
    assert title == "Forge could not start", run.notices
    assert "the onboarding surface could not be assembled" in text, text
    assert "_Mute" in text and "could not be rendered" in text, text
    # The record carries the same reason, and the runtime did not stay up.
    record = run.record()
    assert record is not None and record["status"] == "failed", record
    assert "could not be rendered" in record["reason"], record


def test_a_session_file_error_that_cannot_render_itself_is_still_a_notice(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Round-5 test P4-a, the second site. The session file is written on the
    READINESS thread, where an exception escaping the `except OSError` takes
    the notice with it and leaves a runtime that is serving while the person
    has been told nothing. Nothing referenced "could not be created" either,
    so that `_said` was equally unmeasured.

    `os.open` is refused for THIS path only, with an `OSError` that cannot
    render itself. The runtime must still reach ready and serve; the person
    must be told, by path, that the file could not be created; and no secret
    may appear in the notice or the log. Revert to `str(exc)` and this is
    red."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True)
    real_open = os.open

    def refusing_open(path, flags, mode=0o777, **kwargs):
        # The target AND the staging name beside it: the bearer is written to
        # `<name>.tmp` and moved onto the final name complete, so the open
        # this run makes is the staging one.
        if str(path).startswith(str(run.session_path)):
            raise _MuteOSError()
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(windows_runtime.os, "open", refusing_open)
    run.start()
    # NOT `wait_for("ready")`: that waits for the session file too, and the
    # whole point here is that the file never arrives.
    deadline = time.monotonic() + 60
    record = None
    while time.monotonic() < deadline:
        record = run.record()
        if record is not None and record["status"] == "ready":
            break
        assert run.code is None or run.thread.is_alive(), (run.code, run.notices)
        time.sleep(0.05)
    assert record is not None and record["status"] == "ready", (record, run.notices)
    _await_opened(run)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not any(
            "could not be created" in text for _, text in run.notices):
        time.sleep(0.05)
    told = [(title, text) for title, text in run.notices if "could not be created" in text]
    assert told, run.notices
    title, text = told[-1]
    assert title == "Forge is running", told
    assert str(run.session_path) in text, text
    assert "_MuteOSError" in text and "could not be rendered" in text, text
    assert not run.session_path.exists(), "a file was created after the open was refused"
    assert not _staging(run.session_path).exists(), "a staging file outlived the refused open"
    token = _redeem(record["port"], _nonce_of(run.opened[0]))[1]["token"]
    assert token not in json.dumps(run.notices), "the bearer reached a notice"
    log_text = run.paths.log.read_text(encoding="utf-8")
    assert "could not be rendered" in log_text and token not in log_text
    assert _post(record["port"], "/api/runtime/stop", {"actor": HUMAN}, token=token)[0] == 200
    assert run.join() == 0


def test_the_session_file_fence_resolves_the_runtime_directory_itself(tmp_path: Path):
    """Architecture P4-1: the fence must not depend on its caller having
    resolved `runtime_dir`. Given the runtime directory spelled through `..`,
    a candidate inside it is still refused by THAT root, by name."""
    runtime_dir = tmp_path / "rt"
    runtime_dir.mkdir()
    unresolved = tmp_path / "elsewhere" / ".." / "rt"
    assert unresolved != unresolved.resolve() and unresolved.resolve() == runtime_dir.resolve()
    refusal = windows_runtime._session_file_refusal(
        runtime_dir / "session.json", unresolved, tmp_path / "project")
    # The fence that FIRED must be named: every root refusal ends with a
    # generic tail that lists all four roots, so "the runtime directory" alone
    # is satisfied by the profile fence too (measured under mutation on this
    # host, where tmp_path lies under the profile: the row was GREEN).
    assert refusal is not None and "is inside the runtime directory" in refusal, refusal


def _fence(candidate, tmp_path: Path) -> str | None:
    """`_session_file_refusal` with the runtime and project roots at scratch
    locations that contain none of the candidates below."""
    return windows_runtime._session_file_refusal(Path(candidate), tmp_path / "rt", tmp_path / "project")


def _link_to(directory: Path, link: Path) -> None:
    """A second name for `directory`: a junction on Windows (no privilege
    needed, unlike a symlink), a symlink elsewhere. Both are followed by
    `Path.resolve()`."""
    if sys.platform == "win32":
        import _winapi  # noqa: PLC0415 - the unprivileged Windows link
        _winapi.CreateJunction(str(directory), str(link))
    else:  # pragma: no cover - the Linux census runs this branch
        os.symlink(directory, link, target_is_directory=True)


def test_namespace_and_unc_spellings_are_refused_by_name_before_the_fence_compares(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    r"""Security P2-1 (round 3), the fence function itself. Measured before the
    repair on this host: `\\?\<inside profile>` -> None (admitted), and so were
    the forward-slash spelling, `\\?\UNC\localhost\C$\...` and the plain
    administrative-share UNC `\\localhost\C$\...`; `Path.resolve()` keeps each
    prefix, so the plain roots are never among the candidate's parents. Now
    every double-separator spelling is refused by NAME, first, wherever it
    points -- INSIDE a root and OUTSIDE every root alike, because the fence
    judges the spelling before it resolves anything and never compares a
    prefixed path; the plain outside spelling is the admitted control."""
    _scratch_profile(monkeypatch, tmp_path)
    inside = Path.home() / "session.json"
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    plain_outside = outside / "session.json"
    assert _fence(plain_outside, tmp_path) is None, "the plain outside control was refused"
    assert "is inside the user profile" in (_fence(inside, tmp_path) or "")
    spellings = {
        "extended": lambda path: _EXT + str(path),
        "device": lambda path: _DEV + str(path),
        "forward extended": lambda path: "//?/" + str(path).replace("\\", "/"),
        "extended UNC": lambda path: _EXT + "UNC\\localhost\\C$\\" + str(path).replace("\\", "/").split(":", 1)[-1].lstrip("/").replace("/", "\\"),
        "UNC": lambda path: _unc_spelling(path),
    }
    for label, spell in spellings.items():
        for where, path in (("inside", inside), ("outside", plain_outside)):
            refusal = _fence(spell(path), tmp_path)
            assert refusal is not None and _DOUBLE_SEPARATOR in refusal, (label, where, refusal)
            assert refusal.startswith("the session file"), (label, where, refusal)


def test_a_plain_session_file_spelling_that_resolves_prefixed_is_refused_after_resolving(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    r"""Round-4 test P2, the session-file half. The fence's SECOND spelling
    check -- `_double_separator(resolved)`, the one that reads the RESOLUTION
    rather than the spelling -- had no witness: on this host no plain path
    resolves to a doubled-separator path, so deleting that branch left all 76
    tests of this module green while the docstring said spellings are refused
    "before resolving, and again after".

    What it exists for is real: a substituted or mapped drive, or a junction
    chain, whose target is a UNC share -- `X:\s.json`, spelled plainly,
    resolving to `\\server\share\s.json`. `subst` and `net use` change the
    HOST, not the scratch, so the CANDIDATE's resolution is a seam and this
    test presents that answer directly, on both platforms; the fenced roots
    are resolved for real either way.

    Delete the branch and this is red: the prefixed resolution is ADMITTED,
    which is exactly the admission it exists to prevent.

    The profile is relocated for the same reason its neighbours relocate it:
    where `tmp_path` sits relative to the real profile is a property of the
    HOST -- under it on this workstation, outside it on the Linux matrix --
    and the ADMITTED control below must be admitted on both."""
    _scratch_profile(monkeypatch, tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    plain = outside / "session.json"
    assert _fence(plain, tmp_path) is None, "the plain control was refused"
    for resolved in (_EXT + "C:\\share\\session.json",
                     _DEV + "C:\\share\\session.json",
                     "\\\\server\\share\\session.json",
                     _EXT + "UNC\\localhost\\C$\\session.json"):
        refusal = windows_runtime._session_file_refusal(
            plain, tmp_path / "rt", tmp_path / "project",
            resolve=lambda path, answer=resolved: Path(answer))
        assert refusal is not None, f"a plain spelling resolving to {resolved} was admitted"
        assert "resolved to" in refusal, (resolved, refusal)
        assert "UNC or extended-length" in refusal, (resolved, refusal)
    # The seam is the CANDIDATE's resolution and nothing else: handed the real
    # `Path.resolve`, the fence answers exactly as it does with no seam at all.
    assert windows_runtime._session_file_refusal(
        plain, tmp_path / "rt", tmp_path / "project", resolve=Path.resolve) is None


def test_the_fenced_roots_are_resolved_for_real_and_never_through_the_candidate_seam(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    r"""Round-5 test P3-a. The docstring says the seam is the CANDIDATE's
    resolution and that "the roots are Forge's own and are always resolved for
    real" -- and resolving the roots THROUGH the seam as well left all 80
    tests of this module green. A sentence with no witness.

    The witness is a resolver that ALIASES anything but the candidate. Two
    things then have to hold, and each kills that mutant on its own:

      * it is called exactly ONCE, and with the candidate;
      * a candidate inside the profile is still refused BY THE PROFILE, which
        it could not be if the profile root had been resolved to the alias --
        an aliased root contains nothing, so every fence would miss and a
        secret inside the profile would be admitted.

    That second one is the reason the sentence matters: a fence whose ROOTS a
    caller can redirect is not a fence. The roots are Forge's own -- the seal
    directory, the profile, and the two directories this launch was given --
    and a caller supplies none of them."""
    profile = _scratch_profile(monkeypatch, tmp_path)
    inside = profile / "stolen.json"
    alias = tmp_path / "nowhere-real"
    alias.mkdir()
    calls: list[Path] = []

    def aliasing(path: Path) -> Path:
        calls.append(Path(path))
        if Path(path) == inside:
            return Path(path).resolve()
        # Any ROOT handed here comes back as somewhere that contains nothing.
        return alias / "aliased"

    refusal = windows_runtime._session_file_refusal(
        inside, tmp_path / "rt", tmp_path / "project", resolve=aliasing)
    assert calls == [inside], (
        f"the fence resolved {len(calls)} paths through the candidate seam, not one: {calls}")
    assert refusal is not None, "a session file inside the profile was admitted"
    assert "is inside the user profile" in refusal, refusal
    # The control: the same fence, same candidate, the real resolver -- the
    # refusal above is the profile's answer and not an artefact of the spy.
    plain = windows_runtime._session_file_refusal(inside, tmp_path / "rt", tmp_path / "project")
    assert plain is not None and "is inside the user profile" in plain, plain


def test_launch_resolves_its_fenced_roots_for_real_and_never_through_the_seam(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    r"""Round-6 test T-P3-3: the other half of the round-5 finding above.

    `_session_file_refusal` got its witness in round 6. `launch` has the same
    sentence in its own docstring -- "the fenced roots below (the seal
    directory and the candidate project) are Forge's own and are always
    resolved for real" -- and had no witness at all: routing BOTH roots
    through the candidate seam left all 87 tests of this module green.

    The same witness, in the same two halves, each of which kills that mutant
    on its own:

      * the seam is called exactly ONCE, and with the runtime directory --
        `launch`'s only candidate on this path, the session file being the
        other and unused here;
      * a runtime directory inside the PROJECT is still refused BY THE
        PROJECT, which it could not be if a caller's resolver had aliased that
        root to a directory containing nothing. That is what makes the
        sentence matter rather than tidy: a fence whose ROOTS a caller can
        redirect is not a fence, and this launch takes its resolver from a
        keyword.

    `--session-file` is passed and left alone: `_returns` stops a launch that
    wrongly became a server with that run's bearer, and under the mutant this
    launch does become one (nothing fences it, so it creates its runtime
    directory inside the project and serves). The session path is outside the
    project, the relocated profile and the runtime directory, so it is
    admitted and the bearer is written where the test can read it."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    project = tmp_path / "project"
    project.mkdir()
    alias = tmp_path / "nowhere-real"
    alias.mkdir()
    run = Launch(tmp_path, bundle, project=project, session_file=True)
    run.runtime_dir = project / "state"
    run.argv[run.argv.index("--runtime-dir") + 1] = str(run.runtime_dir)
    calls: list[Path] = []

    def aliasing(path: Path) -> Path:
        calls.append(Path(path))
        if Path(path) == run.runtime_dir:
            return Path(path).resolve()
        # Any ROOT handed here comes back as somewhere that contains nothing.
        return alias / "aliased"

    run.seams["resolve"] = aliasing
    assert _returns(run) == 2
    assert calls == [run.runtime_dir], (
        f"launch resolved {len(calls)} paths through the candidate seam, not one: {calls}")
    title, text = run.notices[-1]
    assert title == "Forge could not start", run.notices[-1]
    assert "is inside the project directory" in text, text
    assert not run.runtime_dir.exists(), "the refusal created the runtime directory"
    # The control: the same placement with the real resolver. The refusal
    # above is the project fence's answer and not an artefact of the spy.
    plain = Launch(tmp_path, bundle, project=project, session_file=True)
    plain.runtime_dir = project / "state"
    plain.argv[plain.argv.index("--runtime-dir") + 1] = str(plain.runtime_dir)
    assert _returns(plain) == 2
    assert "is inside the project directory" in plain.notices[-1][1], plain.notices[-1]


def test_a_plain_runtime_directory_that_resolves_prefixed_is_refused_after_resolving(
        tmp_path: Path):
    r"""Round-4 test P2, the launch half, and the same defect: deleting the
    post-resolution `_namespace_prefixed(runtime_dir)` block left the module
    green because no plain scratch path resolves to a prefixed one here.

    Presented through the same candidate-resolution seam: a plain, absolute
    `--runtime-dir` whose RESOLUTION is extended-length is refused after
    resolving, with exit 2 and nothing created -- the fence compares plain
    paths, and a prefixed root would put every plain candidate outside it."""
    bundle = _marker(tmp_path / "bundle")
    for prefix in (_EXT, _DEV):
        run = Launch(tmp_path, bundle)
        run.seams["resolve"] = lambda path, spelling=prefix: Path(spelling + str(path))
        assert _returns(run) == 2
        title, text = run.notices[-1]
        assert title == "Forge could not start"
        assert "resolved to" in text and "extended-length" in text, (prefix, text)
        assert not run.runtime_dir.exists(), "the refusal created the runtime directory"
        assert not run.project.exists()


def _resolve_answering_the_nul(path: Path) -> Path:
    r"""A resolution that ANSWERS with the NUL-bearing path instead of
    raising: what CPython 3.13 on Windows does, presented on any host.

    3.13's `Path.resolve` is `self.with_segments(os.path.realpath(self,
    strict=strict))` and nothing else. <= 3.12's runs that same `realpath`
    and THEN, in non-strict mode, `p.stat()` as a symlink-loop check
    (pathlib.py:1250); `os.stat` raises `ValueError: stat: embedded null
    character in path`, the `except OSError` around that call does not catch
    a `ValueError`, and it escapes `resolve`. Measured on this host, 3.12.10:
    `ntpath.realpath(p, strict=False)` RETURNS `p` (it swallows the
    `ValueError` from `_getfinalpathname` and falls back to `normpath`, so an
    8.3 segment is left short) while `Path.resolve(p)` raises.

    So the Windows answer is reached by calling what 3.13 calls. `posixpath`
    is not obliged to swallow it -- its `realpath` may raise the `ValueError`
    through -- and this row must exist on the Linux matrix too, where the
    fence is censused. The fallback therefore states the answer directly. The
    row is the same either way: a fence handed a resolution that COMES BACK,
    NUL and all, which is what round 5's windows-latest job had."""
    try:
        return Path(os.path.realpath(str(path), strict=False))
    except ValueError:
        return path


#: The two resolutions a fence must answer the same way. A NUL rule that
#: lives in the `except ValueError` alone passes the first and fails the
#: second -- which is precisely how round 5 was green here and red on
#: windows-latest.
#:
#: The ids name the RESOLVER, not a version. `resolve-raises (<=3.12)` was a
#: misnomer on the interpreter this most matters on: 3.13's `Path.resolve`
#: ANSWERS, so on the windows CI job that row and the next are the same
#: behaviour under two names (round-6 test P4-3). What each row is, on every
#: interpreter, is the real `Path.resolve` of the host and a resolver that
#: answers with the NUL-bearing path the way 3.13's does; whether the host
#: distinguishes them is what
#: `test_the_resolution_the_nul_rule_is_measured_against_really_answers`
#: measures and records.
_NUL_RESOLVERS = (("Path.resolve", Path.resolve),
                  ("realpath-answering", _resolve_answering_the_nul))


@pytest.mark.parametrize("under_profile", [True, False],
                         ids=["candidate-under-profile", "candidate-outside-profile"])
@pytest.mark.parametrize("resolver_name,resolver", _NUL_RESOLVERS,
                         ids=[name for name, _ in _NUL_RESOLVERS])
def test_an_embedded_nul_in_any_operand_is_a_notice_not_a_traceback(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        resolver_name: str, resolver, under_profile: bool):
    r"""Round-4 security 4.2, and the round-5 CI failure that showed the rule
    was in the wrong place.

    THE RULE: an embedded NUL is refused EXPLICITLY and FIRST -- before
    `_double_separator`, before `resolve`, before any root comparison -- in
    every fence that takes a caller-supplied path. All FOUR of `launch`'s
    caller-supplied paths are fenced here, and four is the whole of them:
    `--session-file`, `--runtime-dir`, `--project-dir` and `--bundle-root`
    (its other three flags -- `--port`, `--no-browser`, `--readiness-timeout`
    -- are not paths). Round 6 covered three under this name and the universal
    was false of the fourth (round-6 security S-1): `Forge.cmd` emits
    `--bundle-root "%~dp0." <project> %*` and argparse takes the last value,
    so it is as caller-supplied as the rest; `verify_launched_bundle` resolves
    it outside every `try`, from a `try` that catches only `RuntimeRefusal`;
    and it is reached only AFTER `runtime_dir.mkdir()`, so that refusal had
    already created the runtime directory. The bundle row therefore asserts
    what all four assert -- that nothing was created -- and means it hardest.

    It used to live in an `except ValueError`, which made the ANSWER a
    property of the interpreter. On <= 3.12 `Path.resolve()` raises for a NUL
    (from a trailing `stat`, not from `realpath`), so that branch fired and
    the notice read "cannot be resolved". On 3.13 `resolve()` returns the
    NUL-bearing path, so the root comparison ran on an UNRESOLVED spelling
    and, on a runner whose `tmp_path` lies under `C:\Users\runneradmin`, the
    profile fence answered first -- the exact windows-latest failure at
    7414556. Both resolutions are exercised here, on every host, through
    `_resolve_answering_the_nul`, and both PLACEMENTS are too: the profile is
    relocated (as this test's neighbours relocate it), either ONTO `tmp_path`
    so the candidate is inside it -- the runner's shape -- or beside it so
    the candidate is outside. Four parametrised combinations, four operands
    inside each: sixteen refusals, one answer.

    Remove the NUL check and this is red in every combination, and for
    distinct reasons per operand -- MEASURED, not deduced. Round 6's docstring
    said that outside the profile "the `is_dir()` further down raises the
    `ValueError` back out through a call that is in no `try`". It does not:
    `Path.is_dir()` catches `ValueError` and returns False (round-6 test
    P4-1). What actually happens to `--session-file` with an answering
    resolution is that the fence ADMITS the NUL path -- the profile does not
    contain it, its parent directory exists -- and the runtime goes on to
    become a server; and under the profile it is the PROFILE refusal, the CI
    failure reproduced. `--bundle-root` is the one that still raises out of a
    call in no `try`: `verify_launched_bundle`'s `launched.resolve()`, on
    <= 3.12, where `Path.resolve` raises rather than `is_dir` swallowing it.

    Unreachable from a real Windows command line: `CreateProcess` carries no
    NUL in an argument."""
    _scratch_profile(monkeypatch, tmp_path, at=tmp_path if under_profile else None)
    bundle = _marker(tmp_path / "bundle")

    def refuse(run: Launch, flag: str, value: Path, named: str) -> str:
        run.seams["resolve"] = resolver
        run.argv[run.argv.index(flag) + 1] = str(value)
        assert _returns(run) == 2, (flag, resolver_name)
        title, text = run.notices[-1]
        assert title == "Forge could not start", (flag, resolver_name, run.notices[-1])
        assert named in text, (flag, resolver_name, text)
        assert "cannot be resolved" in text, (flag, resolver_name, text)
        assert "embedded null character" in text, (flag, resolver_name, text)
        # A FIXED notice: the candidate is the caller's own text and this
        # branch does not echo it back, in any spelling.
        assert "\x00" not in text and str(value) not in text, (flag, text)
        assert not run.runtime_dir.exists(), "the refusal created the runtime directory"
        return text

    # EVERY row carries a real `--session-file`, and only the session row
    # overwrites it with the NUL path (round-6 test P4-5). `_returns` stops a
    # launch that wrongly became a server through its record WITH this run's
    # bearer, and the bearer reaches the test only through that file: a row
    # whose argv session path is the NUL path can have no bearer, because the
    # runtime could not write one anywhere. So the three rows where a
    # regression CAN produce a listener keep a writable session path and can
    # stop it; the session row itself cannot, by construction, and falls back
    # to `_returns`' hard deadline. Under the profile the session path is
    # inside the relocated profile and would be refused by that fence -- which
    # is a refusal, not a listener, so it needs no stop either.
    session_text = refuse(Launch(tmp_path, bundle, session_file=True),
                          "--session-file", tmp_path / "a\x00b.json", "the session file path")
    # The CI failure was this substitution exactly; name it so a regression
    # that reinstates it cannot read as some other refusal.
    assert "is inside" not in session_text, session_text
    refuse(Launch(tmp_path, bundle, session_file=True), "--runtime-dir", tmp_path / "r\x00t",
           "the runtime directory")
    refuse(Launch(tmp_path, bundle, session_file=True), "--project-dir", tmp_path / "p\x00j",
           "the project directory")
    # THE FOURTH, and the one the rule's universal was false of. Its own
    # assertion is the "nothing created" one `refuse` already makes: this
    # operand is read by `verify_launched_bundle`, which runs only after
    # `runtime_dir.mkdir()`, so before this row the refusal LEFT THE RUNTIME
    # DIRECTORY BEHIND. `run.bundle` is untouched -- only the argv value is
    # the NUL path -- so the seam still names a real bundle and this row
    # fails on the fence, not on a missing marker.
    bundle_run = Launch(tmp_path, bundle, session_file=True)
    bundle_text = refuse(bundle_run, "--bundle-root", tmp_path / "b\x00d", "the bundle folder")
    assert "is not a complete Forge bundle" not in bundle_text, bundle_text
    assert not bundle_run.runtime_dir.exists(), (
        "the bundle-folder refusal created the runtime directory: the NUL is "
        "being caught at `verify_launched_bundle` rather than before `mkdir`")
    # Nothing at all was created by any of the four rows: what is under
    # `tmp_path` is the bundle this test made and, when the profile was
    # relocated beside the candidate rather than onto it, that profile.
    left = {entry.name for entry in tmp_path.iterdir()}
    assert left <= {"bundle", "profile"}, (
        f"a NUL refusal created something under {tmp_path}: {sorted(left)}")


def test_the_resolution_the_nul_rule_is_measured_against_really_answers():
    r"""The control for the parametrisation above. Its second row is only a
    witness if that resolver ANSWERS -- were it to raise, both rows would be
    the `except ValueError` path, the four combinations would be two, and the
    windows-latest failure would stay unreproducible on this workstation.

    Measured on 3.12.10: `os.path.realpath` answers with the NUL-bearing
    path; `Path.resolve` raises `ValueError` from its trailing `stat`. Where
    `Path.resolve` ALSO answers -- 3.13, which the windows CI job runs -- the
    two rows converge and this control says so rather than failing: what it
    forbids is a silent collapse on a host that still distinguishes them, and
    what it records is that on such a host the belt-and-braces `except
    ValueError` in the fences has no witness and the NUL rule is the only
    guard there is.

    "Says so" was an assertion that PASSES SILENTLY on 3.13, which is the
    interpreter it is about (round-6 test P4-3): a green tick is not a
    record. It emits the finding instead.

    ON WHICH CHANNELS, corrected in round 8 (finding F-3). The claim was "two
    channels a reader actually sees -- a `record_property`, which lands in the
    `--junitxml` the windows-runtime job writes and READS, and a warning". The
    `record_property` half was false in the second word: pytest warned
    `record_property is incompatible with junit_family 'xunit2'` -- this
    repository sets no family, so xunit2 is what it gets -- and every junit
    reader here (the two workflow jobs, `check_test_coverage`,
    `mutation_workspace`, the audit suites) reads `testcase` and `skipped`
    elements and no `properties` element at all. The windows job's own reader
    counts cases and skips; the file is not uploaded either. So the property
    was written and read by nobody, under a warning saying it did not belong
    in that file. It is dropped rather than switched to `xunit1`: no reader
    wants it, and six would have had to be re-checked against the change.

    What remains, said exactly: the CONVERGENCE finding -- the one that says a
    guard is unwitnessed on the interpreter CI runs -- is emitted on a
    `warnings.warn`, which pytest prints in its warnings summary even under
    `-q`, AND on a `print`. The distinct case, which is the ordinary one,
    prints only: it is the record that the host still separates the two
    resolutions, not a finding, and warning on it would put a line in the
    warnings summary of every Linux job for a state that is expected. So the
    absence of the convergence warning is a reading and not a silence, and
    both branches leave a printed record."""
    interpreter = "%d.%d.%d" % sys.version_info[:3]
    candidate = Path.home() / "x" / "a\x00b.json"
    assert "\x00" in str(_resolve_answering_the_nul(candidate)), (
        "the 3.13-shaped resolver no longer answers with the NUL-bearing path")
    try:
        Path.resolve(candidate)
    except ValueError:
        # The two resolutions differ here, as the parametrisation assumes, and
        # the belt-and-braces `except ValueError` in the fences is witnessed.
        print(f"nul resolutions are DISTINCT on {interpreter}: Path.resolve raises "
              "ValueError, so the two parametrised rows are two behaviours and the "
              "belt-and-braces `except ValueError` in the fences is witnessed here")
        return
    assert sys.version_info >= (3, 13), (
        "Path.resolve stopped raising on an embedded NUL before 3.13, so the "
        "belt-and-braces `except ValueError` in both fences is unwitnessed on "
        "this interpreter and the explicit NUL rule is the only guard")
    note = (f"nul resolutions CONVERGE on {interpreter}: Path.resolve answers with the "
            "NUL-bearing path, so the two parametrised rows are one behaviour under two "
            "names, the belt-and-braces `except ValueError` in the fences is unwitnessed "
            "here, and the explicit NUL rule is the only guard on this interpreter")
    print(note)
    warnings.warn(note, stacklevel=1)


def test_an_alias_spelling_of_a_path_inside_the_profile_is_refused_by_the_profile_fence(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A spelling `Path.resolve()` DOES fold is compared after folding: a
    junction (or symlink) whose target lies inside the profile resolves into
    the profile and is refused by that fence, by name; and on Windows, when the
    volume produces an 8.3 short name for the profile, the short spelling
    resolves to the long one and is refused the same way (measured on this
    host: `C:\\Users\\MAZIN~1.LAP\\stolen.json` -> refused, inside the profile).
    A volume with 8.3 names off yields the long name back, in which case that
    half of this test is the plain case and says so."""
    profile = _scratch_profile(monkeypatch, tmp_path)
    deep = profile / "deep"
    deep.mkdir()
    link = tmp_path / "alias"
    _link_to(deep, link)
    assert (link / ".").exists()
    assert profile.resolve() in (link / "session.json").resolve().parents, "the alias does not resolve into the profile"
    refusal = _fence(link / "session.json", tmp_path)
    assert refusal is not None and "is inside the user profile" in refusal, refusal
    if sys.platform == "win32":
        import ctypes  # noqa: PLC0415 - Windows-only 8.3 lookup
        buffer = ctypes.create_unicode_buffer(1024)
        ctypes.windll.kernel32.GetShortPathNameW(str(deep), buffer, 1024)
        short = buffer.value
        assert short, "GetShortPathNameW returned nothing"
        refusal = _fence(Path(short) / "session.json", tmp_path)
        assert refusal is not None and "is inside the user profile" in refusal, (short, refusal)


def test_trailing_dot_and_space_spellings_land_inside_their_root(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A trailing dot or space is kept in the string by `Path` and by
    `resolve()`, so it changes which FILE would be opened (Win32 strips it at
    open) and not which directory the candidate lies in: inside the profile
    it is refused by the profile fence, outside every root it is admitted
    like its plain neighbour."""
    profile = _scratch_profile(monkeypatch, tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    for tail in ("session.json.", "session.json "):
        refusal = _fence(str(profile / tail), tmp_path)
        assert refusal is not None and "is inside the user profile" in refusal, (tail, refusal)
        assert _fence(str(outside / tail), tmp_path) is None, tail


def test_the_runtime_writes_no_access_log_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Test P2-1: uvicorn's access logger walks to the root logger, which the
    runtime gives a FileHandler, so with the default access log every request
    line -- path included -- would land in <key>.log for good. Pinned two
    ways: the Config the runtime builds says access_log=False, and after real
    requests the log holds no request line."""
    seen: dict = {}
    real_config = windows_runtime.uvicorn.Config

    def spying_config(app, **kwargs):
        seen.update(kwargs)
        return real_config(app, **kwargs)

    monkeypatch.setattr(windows_runtime.uvicorn, "Config", spying_config)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, browser=False).start()
    ready = run.wait_for("ready")
    assert seen.get("access_log") is False, seen
    for _ in range(6):
        assert _get(ready["port"], "/api/runtime")[0] == 200
        assert _get(ready["port"], "/api/state")[0] == 200
    assert run.stop()[0] == 200 and run.join() == 0
    log_text = run.paths.log.read_text(encoding="utf-8")
    assert "runtime" in log_text and "stopped" in log_text, "the runtime's own log lines are missing"
    for request_line in ('"GET ', "HTTP/1.1\"", "/api/state", "/api/runtime HTTP"):
        assert request_line not in log_text, f"an access-log line reached the runtime log: {request_line!r}"


def test_a_flood_of_non_ascii_credentials_leaves_no_traceback_in_the_log(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Security F-1 on the REAL runtime: 50 requests with `Authorization:
    Bearer \\xff` and 50 redeems of a non-ASCII nonce (with the launch nonce
    outstanding) are each refused with their fixed status, the log carries no
    traceback, and the launch nonce still redeems afterwards."""
    _scratch_profile(monkeypatch, tmp_path)
    bundle = _marker(tmp_path / "bundle")
    run = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), session_file=True).start()
    ready = run.wait_for("ready")
    _await_opened(run)
    launch_nonce = _nonce_of(run.opened[0])
    port = ready["port"]
    origin = {"content-type": "application/json", "Origin": f"http://{ONBOARDING_HOST}:{port}"}
    statuses = set()
    for _ in range(50):
        statuses.add(_exchange(port, "GET", "/api/state", headers={"Authorization": b"Bearer \xff"})[0])
        statuses.add(_exchange(port, "POST", "/api/session/redeem",
                               body=json.dumps({"nonce": "\u00ff\u00fe"}).encode("utf-8"), headers=origin)[0])
    assert statuses == {401, 404}, statuses
    log_text = run.paths.log.read_text(encoding="utf-8")
    assert "Traceback" not in log_text and "Exception" not in log_text and "Error" not in log_text
    assert _redeem(port, launch_nonce)[0] == 200, "the flood consumed the launch nonce"
    assert run.stop()[0] == 200 and run.join() == 0
    assert "Traceback" not in run.paths.log.read_text(encoding="utf-8")


def test_launch_without_a_session_file_writes_only_record_lock_and_log(tmp_path: Path):
    """The shipped launchers pass no --session-file, so the runtime directory
    holds the record, the lock and the log and nothing else -- no secret on
    disk (A-027)."""
    # The argparse default is None: a default pointing at a path would write the
    # bearer to disk on every shipped launch (mutation: default to a runtime-dir
    # path).
    parsed = windows_runtime._parser().parse_args(
        ["--bundle-root", str(run_bundle := _marker(tmp_path / "bundle")),
         "--project-dir", str(tmp_path / "p")])
    assert parsed.session_file is None
    run = Launch(tmp_path, run_bundle, browser=False).start()
    run.wait_for("ready")
    names = sorted(p.name for p in run.runtime_dir.iterdir())
    assert names == sorted([run.paths.record.name, run.paths.lock.name, run.paths.log.name])
    assert run.token is None, "no session file is written without --session-file"
    assert run.stop()[0] == 200 and run.join() == 0


# ---------------------------------------------------------------------------
# Composition pins and static bounds
# ---------------------------------------------------------------------------

def test_the_served_composition_passes_no_seam():
    signature = inspect.signature(launch)
    assert signature.parameters["packaged_root"].default is resolve_packaged_root
    assert signature.parameters["assemble_app"].default is assemble
    assert signature.parameters["open_browser"].default is open_in_default_browser
    assert signature.parameters["notify"].default is windows_runtime.notify_person
    assert signature.parameters["resolve"].default is Path.resolve
    for entry in (windows_runtime.main, windows_launch.main):
        source = inspect.getsource(entry)
        assert "launch(" in source
        for seam in ("packaged_root=", "assemble_app=", "open_browser=", "notify=",
                     "which=", "resolve="):
            assert seam not in source, f"{entry.__module__}.main passes {seam}"


def test_the_browser_adapter_opens_only_the_loopback_surface(monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(ValueError, match="only the loopback onboarding surface"):
        open_in_default_browser("http://example.com/")
    for disguised in ("file:///C:/Windows/system.ini",
                      # loopback text as userinfo, host elsewhere (measured under review)
                      "http://127.0.0.1:8710@evil.example/",
                      "http://127.0.0.1:8710.evil.example/",
                      "http://127.0.0.1:-1/", "http://127.0.0.1/", "https://127.0.0.1:8710/"):
        with pytest.raises(ValueError):
            open_in_default_browser(disguised)
    if sys.platform == "win32":
        opened: list[str] = []
        monkeypatch.setattr(app_launcher.os, "startfile", opened.append)
        open_in_default_browser("http://127.0.0.1:8710/")
        assert opened == ["http://127.0.0.1:8710/"]
    else:
        with pytest.raises(OSError, match="Windows only"):
            open_in_default_browser("http://127.0.0.1:8710/")


def test_w3_w15_the_runtime_speaks_only_to_loopback_and_fetches_nothing():
    source = Path(windows_runtime.__file__).read_text(encoding="utf-8")
    assert source.count("HTTPConnection(") == 1 and "HTTPConnection(ONBOARDING_HOST" in source
    assert source.count("sock.bind(") == 1 and "sock.bind((ONBOARDING_HOST" in source
    for absent in ("0.0.0.0", "urllib", "requests", "httpx", "pip ", "download", "https://"):
        assert absent not in source, absent
    assert ONBOARDING_HOST == "127.0.0.1"


def test_w19_no_privilege_or_machine_wide_mechanism_is_used():
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_windows_bundle as builder

    sources = [Path(m.__file__).read_text(encoding="utf-8")
               for m in (windows_runtime, windows_launch, app_launcher)]
    sources.extend(builder.LAUNCHERS.values())
    for text in sources:
        for absent in ("winreg", "HKEY_", "schtasks", "sc.exe", "netsh", "runas", "ProgramData",
                       "Program Files", "services.msc", "New-Service", "elevat"):
            assert absent not in text, absent
    assert Path.home() in windows_runtime.DEFAULT_RUNTIME_DIR.parents
    assert windows_runtime.PREFERRED_PORT > 1024


def test_the_page_offers_the_stop_control_and_nothing_decides_by_it():
    from nornyx_forge.onboarding_app import _PAGE

    assert '/api/runtime/stop' in _PAGE and 'id="b_stop"' in _PAGE
    script = _PAGE[_PAGE.index("<script>"):]
    assert "actor: actor()" in script.split("stopForge")[1][:400]
