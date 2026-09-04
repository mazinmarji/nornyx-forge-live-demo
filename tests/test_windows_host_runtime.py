"""Windows-hosted evidence for the basic-user runtime -- PR-18.

WINDOWS-HOSTED AUTOMATED EVIDENCE, and labelled as exactly that. Every
test here starts the runtime as a REAL child process from a REAL bundle
folder -- built by the bundle builder's own copy step, at a path with
spaces and non-ASCII characters -- from an unrelated working directory, on
a Windows host. The interpreter is the test session's own CPython: the
DEVELOPER-bundle arrangement (an installed Python, isolated mode, the
bundle's `src` and `pylib` placed first), invoked through the developer
launcher's own bootstrap string verbatim. It is NOT the operator-supplied
embeddable interpreter; that run needs the archive A-017 says the operator
supplies, and stays operator evidence, measured by the builder's `--smoke`.

On a non-Windows host every runtime test skips, declared by identity in
the census. The `windows-runtime` CI job runs this module with a skip
census of its own, so a skip there fails the job rather than passing
quietly -- and ONE test here runs on every platform: the pin that the job
exists and does exactly that, which is what makes the declared skips
truthful and keeps this module from being a required module that executes
nothing on the Linux census.
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-hosted runtime evidence: a real child process from a real bundle "
           "folder; runs in the windows-runtime CI job and on a Windows workstation",
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_windows_bundle import (  # noqa: E402
    DEVELOPER,
    DEVELOPER_BOOTSTRAP,
    SELF_CONTAINED,
    copy_tree,
    write_bundle_marker,
    write_launcher,
)

from nornyx_forge.capsule import PROVIDERS  # noqa: E402
from nornyx_forge.windows_runtime import (  # noqa: E402
    RUNTIME_SCHEMA,
    RuntimePaths,
    RuntimeRefusal,
    probe_instance,
    read_record,
    write_record,
)

#: Spaces and non-ASCII in BOTH the bundle and the project path, deliberately.
BUNDLE_NAME = "Forge Bündle 測試"
PROJECT_NAME = "Forge Prøject 專案"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A developer bundle built by the builder's own copy step."""
    dist = tmp_path_factory.mktemp("host") / BUNDLE_NAME
    copy_tree(ROOT, dist)
    (dist / "pylib").mkdir()
    write_bundle_marker(dist, mode=DEVELOPER, interpreter_sha256=None)
    write_launcher(dist, DEVELOPER)
    return dist


def _get(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _post(port: int, path: str, payload: dict | None = None) -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {} if payload is None else {"content-type": "application/json"}
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


class HostRuntime:
    """The runtime as a real child process, exactly as the developer
    launcher's bootstrap starts it, from an unrelated working directory."""

    def __init__(self, bundle: Path, work: Path, *, project: Path | None = None,
                 port: int = 0, label: str = "runtime"):
        self.bundle = bundle
        self.project = project or (work / PROJECT_NAME)
        self.runtime_dir = work / "runtime state"
        self.cwd = work / "unrelated cwd"
        self.cwd.mkdir(exist_ok=True)
        bootstrap = DEVELOPER_BOOTSTRAP.format(src=bundle / "src", pylib=bundle / "pylib")
        # `%~dp0.` in the launcher is the folder with a trailing `\.`; passed here verbatim.
        self.argv = [
            sys.executable, "-I", "-c", bootstrap,
            "--bundle-root", str(bundle) + "\\.",
            "--project-dir", str(self.project),
            "--runtime-dir", str(self.runtime_dir),
            "--port", str(port), "--readiness-timeout", "240", "--no-browser",
        ]
        self.output = work / f"{label}-stdout.log"
        self.process: subprocess.Popen | None = None

    @property
    def paths(self) -> RuntimePaths:
        return RuntimePaths.for_project(self.runtime_dir, self.project)

    def start(self) -> "HostRuntime":
        stream = open(self.output, "w", encoding="utf-8")  # noqa: SIM115 - closed in stop
        self._stream = stream
        # A scratch profile: the child's seals, default runtime directory and
        # failure trail then land here, never in the developer's real
        # `~/.nornyx/forge` (a review found scratch-project seals there).
        profile = self.cwd.parent / "profile"
        profile.mkdir(exist_ok=True)
        env = {**os.environ, "USERPROFILE": str(profile), "HOME": str(profile)}
        self.process = subprocess.Popen(self.argv, cwd=str(self.cwd), stdout=stream,
                                        stderr=subprocess.STDOUT, env=env)
        return self

    def record(self) -> dict | None:
        try:
            return read_record(self.paths.record)
        except RuntimeRefusal:
            return None

    def wait_for(self, status: str, timeout: float = 240.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.record()
            if record is not None and record["status"] == status:
                return record
            if self.process is not None and self.process.poll() is not None and status != "stopped":
                break
            time.sleep(0.1)
        raise AssertionError(
            f"the runtime never reached {status}; record={self.record()} "
            f"exit={self.process.poll() if self.process else None} "
            f"output={self.output.read_text(encoding='utf-8', errors='replace')[-2000:]}"
        )

    def stop(self) -> int:
        record = self.record()
        if record is not None and record["status"] == "ready":
            _post(record["port"], "/api/runtime/stop", {"actor": HUMAN})
        try:
            code = self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            # A venv shim's kill() would orphan the interpreter; the tree goes.
            subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                           capture_output=True)
            code = self.process.wait(timeout=30)
        self._stream.close()
        return code

    def kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                           capture_output=True)
        self._stream.close()


@pytest.fixture()
def host(bundle: Path, tmp_path: Path):
    started: list[HostRuntime] = []

    def make(**kwargs) -> HostRuntime:
        if kwargs.get("project") is not None and not kwargs["project"].is_absolute():
            kwargs["project"] = tmp_path / kwargs["project"]
        runtime = HostRuntime(bundle, tmp_path, **kwargs)
        started.append(runtime)
        return runtime

    yield make
    for runtime in started:
        runtime.kill()


def host_project(suffix: str) -> Path:
    """A project name (relative; the fixture places it under tmp_path)."""
    return Path(f"{PROJECT_NAME} {suffix}")


def _listeners_on(port: int) -> list[str]:
    out = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True).stdout
    return [line.split()[1] for line in out.splitlines()
            if len(line.split()) >= 4 and line.split()[1].endswith(f":{port}")
            and line.split()[3] == "LISTENING"]


# ---------------------------------------------------------------------------
# W1 / W2 / W11 / W12  the bundle's own code, from anywhere, at any path
# ---------------------------------------------------------------------------

def test_the_windows_runtime_job_runs_this_module_under_its_own_skip_census():
    """Runs everywhere. The census declares every Windows-hosted test here as
    an expected skip off Windows on the strength of the `windows-runtime`
    job; this pins that the job exists, runs this module, lists skips, and
    fails on any -- so the declaration cannot outlive the job."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "\n  windows-runtime:\n" in workflow
    job = workflow.split("\n  windows-runtime:\n", 1)[1]
    assert "runs-on: windows-latest" in job
    assert "'.[demo,dev]'" in job, "the job must install what the runtime needs"
    assert "tests/test_windows_host_runtime.py" in job and "-rs" in job
    assert "if skipped:" in job and "sys.exit(1)" in job, "a skip in the Windows job must fail it"
    # Runtime validation only: no step of the job publishes, signs or packages.
    steps = [line for line in job.splitlines() if line.strip().startswith(("run:", "- run:", "python", "pip"))]
    for line in steps:
        for other in ("gh release", "signtool", "ForgeSetup", "msi", "pyinstaller", "wix"):
            assert other.lower() not in line.lower(), (other, line)


@windows_only
def test_w1_w2_w11_w12_the_bundles_own_code_serves_from_an_unrelated_directory(host):
    runtime = host().start()
    ready = runtime.wait_for("ready")
    assert " " in str(runtime.bundle) and "ü" in str(runtime.bundle) and "測" in str(runtime.bundle)
    assert "ø" in ready["project_dir"] and "專" in ready["project_dir"]
    served = json.loads(_get(ready["port"], "/api/runtime")[1])
    assert os.path.normcase(served["bundle_root"]) == os.path.normcase(str(runtime.bundle.resolve()))
    assert os.path.normcase(served["python"]) == os.path.normcase(str(Path(sys.executable).resolve()))
    assert served["bundle_mode"] == "developer" and served["pid"] != os.getpid()
    status, body = _get(ready["port"], "/api/state")
    assert status == 200 and json.loads(body) == {"initialized": False, "providers": list(PROVIDERS)}
    status, page = _get(ready["port"], "/")
    assert status == 200 and b"Nornyx Forge" in page and b"Stop Forge" in page
    assert ready["bundle_mode"] == "developer" and ready["url"] == f"http://127.0.0.1:{ready['port']}/"
    assert runtime.stop() == 0
    assert runtime.record()["status"] == "stopped"
    log = runtime.paths.log.read_text(encoding="utf-8", errors="replace")
    assert "answered with its own instance token" in log


@windows_only
def test_w3_the_windows_runtime_binds_loopback_only(host):
    runtime = host().start()
    ready = runtime.wait_for("ready")
    listeners = _listeners_on(ready["port"])
    assert listeners and all(entry.startswith("127.0.0.1:") for entry in listeners), listeners
    lan = socket.gethostbyname(socket.gethostname())
    if not lan.startswith("127."):
        with pytest.raises(OSError):
            socket.create_connection((lan, ready["port"]), timeout=2).close()
    assert runtime.stop() == 0


# ---------------------------------------------------------------------------
# W6 / W7 / W8  second process, stale metadata, an impostor on the port
# ---------------------------------------------------------------------------

@windows_only
def test_w6_a_second_process_joins_the_running_instance_and_starts_nothing(host):
    first = host(label="first").start()
    ready = first.wait_for("ready")
    second = host(label="second").start()
    assert second.process.wait(timeout=120) == 0, second.output.read_text(encoding="utf-8")
    assert first.record()["instance"] == ready["instance"], "the record was replaced"
    assert [p.name for p in first.runtime_dir.glob("*.json")] == [first.paths.record.name]
    assert len(_listeners_on(ready["port"])) == 1
    assert probe_instance(ready["port"])["instance"] == ready["instance"]
    assert first.stop() == 0


@windows_only
def test_w7_w8_stale_metadata_and_an_impostor_are_not_this_runtime(host, tmp_path: Path):
    """A stale record names a port where an IMPOSTOR answers `/api/runtime`
    with the runtime schema and a different token: not accepted, not
    terminated. Preferring that port costs a port, not the impostor."""
    class Impostor(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"schema": RUNTIME_SCHEMA, "instance": "impostor",
                                         "bundle_root": "C:\\elsewhere"}).encode())

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Impostor)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        runtime = host(port=port)
        runtime.runtime_dir.mkdir()
        write_record(runtime.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "impostor",
                                            "status": "ready", "port": port, "pid": 4})
        runtime.start()
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline and (runtime.record() or {}).get("instance") == "impostor":
            time.sleep(0.1)
        ready = runtime.wait_for("ready")
        assert ready["port"] != port and ready["instance"] != "impostor"
        assert probe_instance(port)["instance"] == "impostor", "the impostor was left alone"
        assert runtime.stop() == 0
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# W9 / W20 / W16 / W17  restart, persistence, and the governed journey
# ---------------------------------------------------------------------------

@windows_only
def test_w9_w20_a_stopped_runtime_restarts_over_the_same_persisted_project(host):
    first = host(label="first").start()
    ready = first.wait_for("ready")
    status, created = _post(ready["port"], "/api/project", {
        "project_id": "proj-host", "project_name": "Persists", "actor": HUMAN})
    assert status == 200, created
    assert (first.project / "capsule" / ".git").is_dir(), "the store is git-backed at a non-ASCII path"
    assert first.stop() == 0

    second = host(label="second").start()
    again = second.wait_for("ready")
    assert again["instance"] != ready["instance"]
    state = json.loads(_get(again["port"], "/api/state")[1])
    assert state["initialized"] is True and state["project_id"] == "proj-host"
    assert state["revision"] == created["revision"]
    assert state["experience"]["stage"] == "DISCOVER" and state["authority"]["anchor"] == "sealed"
    assert second.stop() == 0


@windows_only
@pytest.mark.parametrize("provider", list(PROVIDERS))
def test_w16_w17_the_journey_reaches_the_governed_boundary_and_the_build_is_refused(host, provider):
    """The PR-17 semantics through a real Windows runtime, for EACH declared
    provider: creation, proposals, human confirmations, BRD, scope
    confirmation -- then the governed build refuses the provider before
    anything executes."""
    runtime = host(project=host_project(provider)).start()
    port = runtime.wait_for("ready")["port"]
    assert _post(port, "/api/project", {"project_id": "proj-j", "project_name": "Portal",
                                        "actor": HUMAN})[0] == 200
    status, intent = _post(port, "/api/proposals", {
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL})
    assert status == 200
    assert _post(port, f"/api/proposals/{intent['proposal_id']}/confirm", {"actor": HUMAN})[0] == 200
    status, chosen = _post(port, "/api/proposals", {
        "field": "provider", "value": {"name": provider}, "actor": HUMAN})
    assert status == 200
    assert _post(port, f"/api/proposals/{chosen['proposal_id']}/confirm", {"actor": HUMAN})[0] == 200
    assert _post(port, "/api/brd")[0] == 200
    status, confirmed = _post(port, "/api/journey/confirm-scope", {"actor": HUMAN})
    assert status == 200 and confirmed["stage"] == "CONFIRM"

    status, refused = _post(port, "/api/build", {"actor": HUMAN})
    assert status == 409 and "not eligible" in refused["refused"] and provider in refused["refused"]
    assert refused["eligibility"]["eligible"] is False
    state = json.loads(_get(port, "/api/state")[1])
    assert state["journey"]["stage"] == "CONFIRM" and state["journey"]["status"] == "active"
    assert "start_build" not in state["journey"]["actions"]
    assert state["provider_eligibility"]["eligible"] is False
    assert state["providers"] == list(PROVIDERS)
    assert json.loads(_get(port, "/api/build")[1]) == {"status": "never_run"}
    assert runtime.stop() == 0


# ---------------------------------------------------------------------------
# The launchers themselves, and the entry guard
# ---------------------------------------------------------------------------

@windows_only
def test_w13_w14_the_self_contained_launcher_refuses_visibly_without_its_interpreter(tmp_path: Path):
    """The literal `Forge.cmd` of a self-contained bundle whose `python\\`
    is missing: a message, exit 2, and no Python of this computer started --
    shown by handing the launcher a runtime directory and a project through
    `%*` that a started runtime would have created, and finding neither."""
    dist = tmp_path / "self contained ünvollständig"
    dist.mkdir()
    write_bundle_marker(dist, mode=SELF_CONTAINED, interpreter_sha256="ab" * 32)
    write_launcher(dist, SELF_CONTAINED)
    runtime_dir, project = tmp_path / "rt", tmp_path / "p"
    completed = subprocess.run(
        ["cmd.exe", "/c", str(dist / "Forge.cmd"), "--no-browser",
         "--runtime-dir", str(runtime_dir), "--project-dir", str(project)],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120, cwd=str(tmp_path),
        encoding="utf-8", errors="replace",
    )
    assert completed.returncode == 2
    assert "not a complete self-contained bundle" in completed.stdout
    time.sleep(1.0)
    assert not runtime_dir.exists() and not project.exists(), "a fallback interpreter started"


@windows_only
def test_the_entry_guard_speaks_when_the_folder_cannot_load(bundle: Path, tmp_path: Path):
    """A partial copy: the runtime module raises on import. Under a console
    the guard prints; under pythonw it would show a message box; either way
    the traceback lands in the trail under the profile it was given."""
    broken = tmp_path / "partial copy"
    shutil.copytree(bundle, broken, ignore=shutil.ignore_patterns(".nornyx", "pylib"))
    (broken / "src" / "nornyx_forge" / "windows_runtime.py").write_text(
        "raise ImportError('No module named uvicorn (pylib is missing)')\n", encoding="utf-8")
    home = tmp_path / "profile"
    home.mkdir()
    env = {**os.environ, "USERPROFILE": str(home)}
    completed = subprocess.run(
        [sys.executable, "-I", "-c",
         DEVELOPER_BOOTSTRAP.format(src=broken / "src", pylib=broken / "pylib"),
         "--bundle-root", str(broken), "--project-dir", str(tmp_path / "p")],
        capture_output=True, text=True, timeout=120, env=env, cwd=str(tmp_path),
        encoding="utf-8", errors="replace",
    )
    assert completed.returncode == 2
    assert "could not be loaded" in completed.stderr and "pylib is missing" in completed.stderr
    trail = home / ".nornyx" / "forge" / "runtime" / "launch-failures.log"
    assert trail.exists() and "ImportError" in trail.read_text(encoding="utf-8")
