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

import http.client
import http.server
import inspect
import json
import socket
import sys
import threading
import time
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
                 which=None, readiness: float = 60.0):
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
        self.argv = argv

        def opener(url: str) -> None:
            # Evidence at the moment of the call: does the server answer with
            # its own token? A browser opened early would record None here.
            # A SHORT probe: on Windows a connect to a bound-but-not-listening
            # loopback port retries its SYN until the timeout, so a long probe
            # could succeed on a retransmit that lands after startup and
            # launder an early opening as a late one (measured under mutation).
            port = int(url.rsplit(":", 1)[1].rstrip("/"))
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
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.record()
            if record is not None and record["status"] == status:
                return record
            if self.code is not None and not self.thread.is_alive():
                break
            time.sleep(0.05)
        raise AssertionError(
            f"runtime never reached {status}: record={self.record()} code={self.code} "
            f"notices={self.notices}"
        )

    def stop(self, actor: dict = HUMAN) -> tuple[int, dict]:
        record = self.record()
        assert record is not None
        status, body = _post(record["port"], "/api/runtime/stop", {"actor": actor})
        return status, body

    def join(self, timeout: float = 30.0) -> int:
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "the runtime did not stop"
        assert self.code is not None
        return self.code


def _returns(run: Launch, seconds: float = 30.0) -> int:
    """`launch()` for a launch that must RETURN -- a second launch that joins
    or refuses. Held in a thread with a deadline, so a regression that turns
    it into a server (a lock that does not exclude) is a red test rather
    than a hang; the runaway server, if any, is stopped through its record."""
    outcome: dict[str, int] = {}
    thread = threading.Thread(target=lambda: outcome.update(code=launch(run.argv, **run.seams)),
                              daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        record = run.record()
        if record is not None and record["status"] == "ready":
            _post(record["port"], "/api/runtime/stop", {"actor": HUMAN})
            thread.join(10)
        raise AssertionError(
            f"a launch that must return became a server: record={record}"
        )
    return outcome["code"]


def _get(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _post(port: int, path: str, payload: dict) -> tuple[int, dict]:
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=5)
    try:
        connection.request("POST", path, body=json.dumps(payload).encode("utf-8"),
                           headers={"content-type": "application/json"})
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
    notices: list[tuple[str, str]] = []
    opened: list[str] = []
    code = launch(
        ["--bundle-root", str(bundle), "--project-dir", "forge-project",
         "--runtime-dir", str(tmp_path / "runtime")],
        packaged_root=lambda: bundle, assemble_app=_light_app,
        open_browser=opened.append, notify=lambda t, x: notices.append((t, x)),
    )
    assert code == 2 and opened == []
    assert "must be absolute" in notices[-1][1]
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
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not run.opened:
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
    # A rebinding page reaches the port with a foreign Host header: refused.
    foreign = http.client.HTTPConnection(ONBOARDING_HOST, ready["port"], timeout=5)
    try:
        foreign.request("GET", "/api/runtime", headers={"Host": "evil.example"})
        assert foreign.getresponse().status == 400
    finally:
        foreign.close()
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
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and run.record()["browser"]["opened"] is None:
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
    inside.argv[inside.argv.index("--runtime-dir") + 1] = str(inside.project / "runtime")
    assert launch(inside.argv, **inside.seams) == 2
    assert "inside the project directory" in inside.notices[-1][1]
    assert not inside.project.exists(), "the refusal created something inside the project"
    for fenced in (seals, seals / "x"):
        sealed = Launch(tmp_path, bundle)
        sealed.argv[sealed.argv.index("--runtime-dir") + 1] = str(fenced)
        assert launch(sealed.argv, **sealed.seams) == 2
        assert "inside the seal directory" in sealed.notices[-1][1]
    assert list(seals.iterdir()) == [], "the refusal wrote into the seal directory"


def test_an_out_of_range_port_is_a_refusal_not_a_traceback(tmp_path: Path):
    run = Launch(tmp_path, _marker(tmp_path / "bundle"), port=70000)
    assert launch(run.argv, **run.seams) == 2
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
    assert launch(run.argv, **run.seams) == 2
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


def test_w18_runtime_metadata_cannot_reach_the_governance_answer(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The real surface through the SERVED composition (`assemble`, the
    runtime's default), with the packaged root pointed at the bundle so the
    marker is the one `assemble` would see: a forged record and a forged
    marker beside it change nothing `/api/state` says, and neither module of
    the surface mentions the runtime's state. A review measured that the
    same pin over `create_app` alone missed a leak placed in `assemble`."""
    from nornyx_forge import development_flow, onboarding_serve

    bundle = _marker(tmp_path / "bundle")
    monkeypatch.setattr(onboarding_serve, "resolve_packaged_root", lambda: bundle)
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    monkeypatch.setattr(development_flow, "DevelopmentFlow", lambda *a, **k: None)
    (bundle / ".nornyx" / "contracts").mkdir(parents=True)
    for contract in CONTRACTS.glob("*.nyx"):
        (bundle / ".nornyx" / "contracts" / contract.name).write_bytes(contract.read_bytes())
    run = Launch(tmp_path, bundle, assemble_app=onboarding_serve.assemble, browser=False).start()
    ready = run.wait_for("ready")
    before = json.loads(_get(ready["port"], "/api/state")[1])
    assert before == {"initialized": False, "providers": list(PROVIDERS)}
    forged = {**ready, "experience": {"stage": "READY", "status": "active"},
              "approval": "granted", "provider_eligibility": {"claude": True}}
    write_record(run.paths.record, forged)
    (bundle / BUNDLE_MARKER).write_text(json.dumps({
        "schema": BUNDLE_SCHEMA, "mode": "developer", "approved": True, "stage": "READY"}),
        encoding="utf-8")
    assert json.loads(_get(ready["port"], "/api/state")[1]) == before
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


def test_w20_capsule_authority_persists_across_a_runtime_restart(tmp_path: Path):
    """Create a project through the running surface, stop the runtime,
    start it again over the same project: the store is read back, the
    lifecycle is the one recorded, and the runtime is a new instance."""
    bundle = _marker(tmp_path / "bundle")
    first = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False).start()
    ready = first.wait_for("ready")
    status, created = _post(ready["port"], "/api/project", {
        "project_id": "proj-w20", "project_name": "Persisting", "actor": HUMAN})
    assert status == 200, created
    assert first.stop()[0] == 200 and first.join() == 0

    second = Launch(tmp_path, bundle, assemble_app=_real_surface(tmp_path), browser=False).start()
    again = second.wait_for("ready")
    assert again["instance"] != ready["instance"]
    state = json.loads(_get(again["port"], "/api/state")[1])
    assert state["initialized"] is True and state["project_id"] == "proj-w20"
    assert state["experience"]["stage"] == "DISCOVER" and state["revision"] == created["revision"]
    assert state["authority"]["anchor"] == "sealed"
    second.stop()
    assert second.join() == 0


# ---------------------------------------------------------------------------
# Composition pins and static bounds
# ---------------------------------------------------------------------------

def test_the_served_composition_passes_no_seam():
    signature = inspect.signature(launch)
    assert signature.parameters["packaged_root"].default is resolve_packaged_root
    assert signature.parameters["assemble_app"].default is assemble
    assert signature.parameters["open_browser"].default is open_in_default_browser
    assert signature.parameters["notify"].default is windows_runtime.notify_person
    for entry in (windows_runtime.main, windows_launch.main):
        source = inspect.getsource(entry)
        assert "launch(" in source
        for seam in ("packaged_root=", "assemble_app=", "open_browser=", "notify=", "which="):
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
