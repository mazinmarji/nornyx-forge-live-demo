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
quietly -- and THREE tests here run on every platform, because each is a
property of the HARNESS and starts no runtime: the pin that the job exists
and does exactly that, which is what makes the declared skips truthful and
keeps this module from being a required module that executes nothing on the
Linux census, and the two pins on `wait_for` -- that it stops the moment its
child is dead, and that it waits for a bearer it can PARSE rather than for a
file that merely exists.
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import re
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
from nornyx_forge.control_plane_session import NO_SESSION  # noqa: E402
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


def _get(port: int, path: str, token: str | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _post(port: int, path: str, payload: dict | None = None,
          token: str | None = None) -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {} if payload is None else {"content-type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def _parsed(token: str | None) -> bool:
    """True when a bearer was actually read: a non-empty string. `.token`
    answers None for a file that is absent, unreadable, not JSON, or JSON
    without a `token` -- and the empty string for one that carries an empty
    one, which is not a bearer either and would be sent as `Bearer `."""
    return isinstance(token, str) and bool(token)


class HostRuntime:
    """The runtime as a real child process, exactly as the developer
    launcher's bootstrap starts it, from an unrelated working directory."""

    def __init__(self, bundle: Path, work: Path, *, project: Path | None = None,
                 port: int = 0, label: str = "runtime"):
        self.bundle = bundle
        self.project = project or (work / PROJECT_NAME)
        self.runtime_dir = work / "runtime state"
        # The gate needs the bearer on /api/state and the authority routes; the
        # test drives them over a socket with no browser to redeem a nonce, so
        # the runtime writes the token to this explicit scratch path.
        self.session_path = work / "session.json"
        self.cwd = work / "unrelated cwd"
        self.cwd.mkdir(exist_ok=True)
        bootstrap = DEVELOPER_BOOTSTRAP.format(src=bundle / "src", pylib=bundle / "pylib")
        # `%~dp0.` in the launcher is the folder with a trailing `\.`; passed here verbatim.
        self.argv = [
            sys.executable, "-I", "-c", bootstrap,
            "--bundle-root", str(bundle) + "\\.",
            "--project-dir", str(self.project),
            "--runtime-dir", str(self.runtime_dir),
            "--session-file", str(self.session_path),
            "--port", str(port), "--readiness-timeout", "240", "--no-browser",
        ]
        self.output = work / f"{label}-stdout.log"
        self.process: subprocess.Popen | None = None

    @property
    def paths(self) -> RuntimePaths:
        return RuntimePaths.for_project(self.runtime_dir, self.project)

    @property
    def token(self) -> str | None:
        """This run's bearer, from the explicit session file, once ready."""
        try:
            return json.loads(self.session_path.read_text(encoding="utf-8"))["token"]
        except (OSError, ValueError, KeyError):
            return None

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
        """The record at `status`. For `ready`, ALSO A PARSEABLE BEARER: the
        runtime writes the bearer AFTER it records readiness (pinned by
        `test_the_session_file_is_written_only_after_readiness`), so a test
        that read `.token` on the record alone could read nothing and send its
        first request bare -- measured once on this host as a `401` on the
        first `/api/project` of the restart specimen, with one child ever
        started and its record `ready`.

        THE WAIT IS ON `.token`, NOT ON THE FILE'S EXISTENCE. Waiting for the
        path to appear closed the window the record opened and left a narrower
        one inside it: `.token` swallows every read and parse error and answers
        None, so a reader that arrived after the create and before the content
        got a bare request out of exactly the same `wait_for` that had just
        returned. The windows-runtime job failed that way once at PR #46's
        head -- the first bearered `POST /api/project` answered `401` -- with
        six modules loading the host. The WRITER now moves the file into place
        complete (`_place_session_file`), so the window is closed there too;
        this wait is what makes the harness independent of that, and what makes
        the failure legible when it is not: the message says whether the file
        was there and whether it parsed, which "session file present=True" on
        its own never did.

        THE DEAD-CHILD CHECK IS A SIBLING `if`, not an `elif` (round-4
        architecture F-P4-4 and test P3). As an `elif` it was unreachable in
        exactly the case the session-file wait created: a child that records
        `ready` and then dies before writing the file takes the first branch,
        does not return, and never reaches the poll -- so eight `wait_for`
        sites spun the full 240 s before failing. As a sibling it fires on
        every pass, and a dead child raises in the time it takes to notice."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.record()
            if record is not None and record["status"] == status:
                if status != "ready" or _parsed(self.token):
                    return record
            if self.process is not None and self.process.poll() is not None and status != "stopped":
                break
            time.sleep(0.1)
        raise AssertionError(
            f"the runtime never reached {status} with a parseable session file; "
            f"record={self.record()} session file present={self.session_path.exists()} "
            f"bearer parsed={_parsed(self.token)} "
            f"exit={self.process.poll() if self.process else None} "
            f"output={self.output.read_text(encoding='utf-8', errors='replace')[-2000:]}"
        )

    def stop(self) -> int:
        record = self.record()
        if record is not None and record["status"] == "ready":
            _post(record["port"], "/api/runtime/stop", {"actor": HUMAN}, token=self.token)
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


def test_the_harness_stops_waiting_the_moment_its_child_is_dead(tmp_path: Path):
    """Round-4 architecture F-P4-4 and test P3, and one of the two tests here
    that runs on EVERY platform: this is a property of the HARNESS, not of a
    Windows runtime, and no child of the runtime is started.

    The case is the one round 4's session-file wait created. A child that
    records `ready` and then dies before writing the bearer matched the first
    branch, did not return, and -- while the dead-child check was an `elif` --
    never reached the poll at all, so each of the eight `wait_for("ready")`
    sites spun its whole 240 s timeout before failing. With the sibling `if`
    the death is seen on the next pass, in a tenth of a second.

    Restore the `elif` and this does not fail: it HANGS to the timeout given,
    which is why the timeout given here is twenty seconds and the assertion
    is on the elapsed time."""
    work = tmp_path / "work"
    work.mkdir()
    run = HostRuntime(tmp_path / "no such bundle", work)
    run.runtime_dir.mkdir(parents=True)
    write_record(run.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "dead-child",
                                    "status": "ready", "port": 8710,
                                    "url": "http://127.0.0.1:8710/"})
    assert run.record()["status"] == "ready", "the record the harness reads says ready"
    assert not run.session_path.exists(), "the specimen is a child that never wrote the bearer"
    # A REAL dead process: `poll()` answers a real exit code, which is the
    # thing the loop reads.
    run.process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])
    assert run.process.wait(timeout=60) == 3
    run._stream = open(run.output, "w", encoding="utf-8")  # noqa: SIM115 - closed below
    try:
        started = time.monotonic()
        with pytest.raises(AssertionError, match="never reached ready"):
            run.wait_for("ready", timeout=20.0)
        elapsed = time.monotonic() - started
    finally:
        run._stream.close()
    assert elapsed < 5.0, f"the dead child was not noticed; the wait ran {elapsed:.1f}s"


def test_the_harness_waits_for_a_bearer_it_can_parse_not_for_a_file(tmp_path: Path):
    """The THIRD test here that runs on every platform: a property of the
    HARNESS, and no runtime is started.

    `wait_for("ready")` used to return the moment the session file EXISTED.
    `.token` swallows every read and parse error and answers None, so a
    reader arriving between the create and the content got None and sent its
    first request bare -- which is how the windows-runtime job failed at
    PR #46's head: a `401` on the first bearered `POST /api/project`, one
    child ever started, its record `ready`. The writer no longer opens that
    window (`_place_session_file` moves the file into place complete), and
    this is the harness half, which does not depend on the writer's shape.

    The specimen is a writer that exposes an EMPTY file and completes it
    0.3 s later -- exactly what the old writer did under load. The wait must
    not return inside that window. Restore `self.session_path.exists()` and
    this is red: the wait returns while `.token` is still None.

    The child is alive throughout, so the dead-child branch decides nothing
    here; it has its own test above."""
    work = tmp_path / "work"
    work.mkdir()
    run = HostRuntime(tmp_path / "no such bundle", work)
    run.runtime_dir.mkdir(parents=True)
    write_record(run.paths.record, {"schema": RUNTIME_SCHEMA, "instance": "slow-writer",
                                    "status": "ready", "port": 8711,
                                    "url": "http://127.0.0.1:8711/"})
    # A REAL live process: `poll()` answers None, which is what the sibling
    # dead-child branch reads, so this test turns on the session file alone.
    run.process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    seen: dict = {}

    def slow_writer() -> None:
        run.session_path.write_bytes(b"")
        seen["empty_at"] = time.monotonic()
        seen["empty_token"] = run.token
        time.sleep(0.3)
        seen["content_at"] = time.monotonic()
        run.session_path.write_text(
            json.dumps({"schema": "x", "instance": "slow-writer", "token": "THE-BEARER"}) + "\n",
            encoding="utf-8")

    writer = threading.Thread(target=slow_writer, name="slow-writer", daemon=True)
    run._stream = open(run.output, "w", encoding="utf-8")  # noqa: SIM115 - closed below
    try:
        writer.start()
        record = run.wait_for("ready", timeout=20.0)
        returned_at = time.monotonic()
    finally:
        writer.join(timeout=10)
        run.process.kill()
        run.process.wait(timeout=30)
        run._stream.close()
    assert record["instance"] == "slow-writer"
    assert seen["empty_token"] is None, (
        "the empty file still parsed to a bearer; the window was never open and "
        "this test proved nothing")
    # The moment CONTENT began, not the moment it finished: an assertion on
    # the finish could be beaten by microseconds and would be flaky in the
    # direction of passing.
    assert returned_at >= seen["content_at"], (
        f"the wait returned {seen['content_at'] - returned_at:.3f}s before the bearer "
        "was written, on a file that existed and parsed to nothing")
    assert returned_at - seen["empty_at"] >= 0.25, (
        f"the wait returned {returned_at - seen['empty_at']:.3f}s after the empty file "
        "appeared, which is inside the 0.3s window")
    assert run.token == "THE-BEARER"


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

def _windows_runtime_job(workflow: str) -> str:
    """The `windows-runtime` job's text, bounded at the NEXT job key. It is
    the last job today, so the bound changes nothing yet; unbounded, a module
    list in a job added after it would satisfy this module's reader."""
    assert "\n  windows-runtime:\n" in workflow, "the windows-runtime job is gone"
    after = workflow.split("\n  windows-runtime:\n", 1)[1]
    return re.split(r"\n  [A-Za-z][\w-]*:", after, maxsplit=1)[0]


def _windows_job_pytest_commands(workflow: str) -> list[str]:
    """The job's `python -m pytest ...` invocation lines, comments dropped.

    Round-7 finding F-6: this test asked whether the module path appeared
    anywhere in the job block, which a YAML COMMENT naming the module
    satisfies -- and one was added to that block in round 7, which is how the
    same construction in `tests/test_provider_execution.py` went green with
    the module deleted from the command (F-1). A comment is not a run."""
    return [line for line in _windows_runtime_job(workflow).splitlines()
            if "python -m pytest" in line and not line.lstrip().startswith("#")]


def _windows_job_code(workflow: str) -> str:
    """The job's non-comment lines: `# if skipped:` is not a guard either."""
    return "\n".join(line for line in _windows_runtime_job(workflow).splitlines()
                     if not line.lstrip().startswith("#"))


#: A job that MENTIONS this module in a comment and runs a different one --
#: built here as text, so the control is the specimen. The pre-round-8
#: assertion accepts it; the reader above must not.
_COMMENT_ONLY_JOB = (
    "jobs:\n"
    "  windows-runtime:\n"
    "    runs-on: windows-latest\n"
    "    steps:\n"
    "      # tests/test_windows_host_runtime.py is what this job is for\n"
    "      - name: Windows runtime tests\n"
    "        run: |\n"
    "          python -m pytest tests/test_windows_runtime.py -q -rs\n"
    "  a-later-job:\n"
    "    runs-on: ubuntu-latest\n"
)


def test_the_windows_runtime_job_runs_this_module_under_its_own_skip_census():
    """Runs everywhere. The census declares every Windows-hosted test here as
    an expected skip off Windows on the strength of the `windows-runtime`
    job; this pins that the job exists, runs this module, lists skips, and
    fails on any -- so the declaration cannot outlive the job.

    "Runs this module" is read from the job's PYTEST COMMAND, not from the job
    text: round-7 finding F-6 is that a YAML comment naming the module
    satisfied the old assertion, so the module could be dropped from the
    command with this test still green and every Windows-hosted skip here
    still declared expected. The comment-only specimen below is refused and
    the same job with the module in its command is accepted."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    code = _windows_job_code(workflow)
    assert "runs-on: windows-latest" in code
    assert "'.[demo,dev]'" in code, "the job must install what the runtime needs"
    commands = _windows_job_pytest_commands(workflow)
    assert commands, "the windows-runtime job invokes pytest on no line"
    assert any("tests/test_windows_host_runtime.py" in line and "-rs" in line
               for line in commands), (
        "the windows-runtime job's pytest command does not run this module with -rs, "
        f"so this module's declared skips rest on nothing: {commands}")
    assert "if skipped:" in code and "sys.exit(1)" in code, "a skip in the Windows job must fail it"
    # Runtime validation only: no step of the job publishes, signs or packages.
    steps = [line for line in code.splitlines() if line.strip().startswith(("run:", "- run:", "python", "pip"))]
    for line in steps:
        for other in ("gh release", "signtool", "ForgeSetup", "msi", "pyinstaller", "wix"):
            assert other.lower() not in line.lower(), (other, line)
    # The reader's controls. NEGATIVE first: the comment-only job satisfied
    # the pre-round-8 assertion and must not satisfy this one.
    assert "tests/test_windows_host_runtime.py" in _windows_runtime_job(_COMMENT_ONLY_JOB), (
        "the specimen no longer reproduces the finding it exists to reproduce")
    assert not any("tests/test_windows_host_runtime.py" in line
                   for line in _windows_job_pytest_commands(_COMMENT_ONLY_JOB)), (
        "a job that only MENTIONS this module in a comment satisfies the reader (F-6)")
    runs_it = _COMMENT_ONLY_JOB.replace(
        "python -m pytest tests/test_windows_runtime.py -q -rs",
        "python -m pytest tests/test_windows_host_runtime.py -q -rs")
    assert any("tests/test_windows_host_runtime.py" in line and "-rs" in line
               for line in _windows_job_pytest_commands(runs_it)), (
        "the reader does not see a module that IS in the pytest command")


#: The job's collected-count guard, read from the CODE and not from the
#: sentence beside it: the two disagreeing is the finding this pins.
_FLOOR = re.compile(r"if len\(cases\) < (\d+):")


def _windows_job_floor(workflow: str) -> int:
    """The one collected-count floor the job enforces."""
    floors = _FLOOR.findall(_windows_job_code(workflow))
    assert len(floors) == 1, (
        f"the windows-runtime job has {len(floors)} collected-count guards, not one: {floors}")
    return int(floors[0])


def _windows_job_modules(workflow: str) -> list[str]:
    """The test modules the job's pytest command names. ONE command: a floor
    that covers one invocation while a second runs other modules would be a
    floor over part of the job."""
    commands = _windows_job_pytest_commands(workflow)
    assert len(commands) == 1, (
        f"the windows-runtime job runs pytest on {len(commands)} lines; the floor below "
        f"is arithmetic over one command: {commands}")
    return [word for word in commands[0].split() if word.endswith(".py")]


def _collected_per_module(modules: list[str]) -> dict[str, int]:
    """How many tests each module COLLECTS, measured by collecting them.

    One bounded child, `--collect-only`, so nothing here runs a test. pytest 8
    summarises `-q` collection as `<path>: <count>`; a node id per line is the
    older shape and is counted too, and a module the output does not account
    for is a loud failure rather than a zero."""
    finished = subprocess.run(  # noqa: S603 - this repository's own interpreter and tests
        [sys.executable, "-m", "pytest", *modules, "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=600, check=False)
    assert finished.returncode == 0, (
        f"collecting the windows job's modules failed ({finished.returncode}): "
        f"{finished.stdout[-3000:]}{finished.stderr[-2000:]}")
    counts: dict[str, int] = {}
    for line in finished.stdout.splitlines():
        summary = re.fullmatch(r"(\S+\.py): (\d+)", line.strip())
        if summary:
            counts[summary.group(1).replace("\\", "/")] = int(summary.group(2))
    if not counts:
        for line in finished.stdout.splitlines():
            head = line.strip().split("::", 1)[0].replace("\\", "/")
            if "::" in line and head.endswith(".py"):
                counts[head] = counts.get(head, 0) + 1
    missing = [module for module in modules if module not in counts]
    assert not missing, (
        f"the collection accounted for {sorted(counts)} and not for {missing}, so the "
        f"floor below would be arithmetic over an unread output: {finished.stdout[-2000:]}")
    return counts


def _floor_matches(modules: list[str], floor: int, counts: dict[str, int]) -> bool:
    """THE RULE, in one place: the floor is one above what the job would
    collect with its SMALLEST module gone, so any whole module dropping out
    trips it and no smaller loss does."""
    picked = [counts[module] for module in modules]
    return floor == sum(picked) - min(picked) + 1


def test_the_windows_job_floor_is_the_arithmetic_it_states():
    """Runs everywhere. Round-2 P2-1: the floor was moved to `196 - 15 + 1`
    and called "the smallest of the five" when the smallest of the five was
    13, this module. At 182 the whole 13-test module could vanish from the
    job -- reproduced by the reviewer with the job's own reader over its own
    junit, at 183 collected and the guard silent -- and nothing anywhere read
    the number, which is why the prose and the arithmetic could drift apart
    at all.

    So the number is DERIVED here, from a live collection of the modules the
    job's own command names, and the sentence beside the guard is held to the
    same measurement. Both controls are specimens rather than edits: the
    round-1 mistake itself -- the second-smallest module in the subtraction
    -- must be refused, and so must the real floor once any one module has
    left the command."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    modules = _windows_job_modules(workflow)
    assert len(modules) > 2, f"the windows-runtime job names {modules}"
    counts = _collected_per_module(modules)
    ascending = sorted(counts[module] for module in modules)
    total, smallest = sum(ascending), ascending[0]
    floor = _windows_job_floor(workflow)
    assert _floor_matches(modules, floor, counts), (
        f"the windows job's floor is {floor}; its {len(modules)} modules collect {total} "
        f"({'/'.join(str(n) for n in ascending)}) and the smallest is {smallest}, so the "
        f"floor that catches a whole module leaving is {total - smallest + 1}. Below that, "
        "the smallest module can vanish with the job still green.")
    # The sentence must say what the guard does. It did not, and the sentence
    # is what a reader of this job believes.
    code = _windows_job_code(workflow)
    assert f"fewer than {floor} tests" in code, (
        f"the job's message does not repeat its own floor of {floor}")
    assert f"carry {total} here" in code, (
        f"the job's message does not state the {total} tests its modules collect")
    assert f"({'/'.join(str(n) for n in ascending)})" in code, (
        f"the job's message does not state the measured breakdown "
        f"{'/'.join(str(n) for n in ascending)}")
    assert f"{total} - {smallest} + 1" in code, (
        f"the job's message does not state the arithmetic {total} - {smallest} + 1")
    # CONTROL 1: the round-1 error. The second-smallest module in the
    # subtraction leaves the smallest one free to disappear.
    second = ascending[1]
    assert second != smallest or len(set(ascending)) == 1, "the specimen needs two sizes"
    assert not _floor_matches(modules, total - second + 1, counts), (
        f"a floor of {total - second + 1} -- the SECOND smallest module subtracted, which "
        "is exactly how this job came to accept a whole module vanishing -- satisfies the "
        "rule above, so the rule is not the one that was broken")
    # CONTROL 2: this floor must stop being right the moment the command
    # stops running any one of the modules it was computed over.
    for dropped in modules:
        rest = [module for module in modules if module != dropped]
        assert not _floor_matches(rest, floor, counts), (
            f"the floor {floor} still satisfies the rule with {dropped} gone from the "
            "command, so it does not pin what it claims to")


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
    status, body = _get(ready["port"], "/api/state", token=runtime.token)
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


@windows_only
def test_an_unbearered_stop_against_the_real_child_is_refused_and_leaves_it_serving(host):
    """Round-2 test P2-2: the host suite discriminates the gate. Against the
    REAL child process, `POST /api/runtime/stop` without the bearer -- and
    with a wrong one -- is 401 with the fixed body; the record still says
    ready, the process is alive and answers with the same instance; and
    `<key>.log` carries no request line and no traceback afterwards. Then
    the bearered stop ends it."""
    runtime = host().start()
    ready = runtime.wait_for("ready")
    for token in (None, "not-this-runs-bearer"):
        status, body = _post(ready["port"], "/api/runtime/stop", {"actor": HUMAN}, token=token)
        assert status == 401 and body == NO_SESSION, (token, status, body)
    time.sleep(0.5)
    assert runtime.process.poll() is None, "the child exited on an un-bearered stop"
    assert runtime.record()["status"] == "ready"
    assert probe_instance(ready["port"])["instance"] == ready["instance"]
    log = runtime.paths.log.read_text(encoding="utf-8", errors="replace")
    assert "Traceback" not in log
    for request_line in ('"POST ', '"GET ', 'HTTP/1.1"', "/api/runtime/stop"):
        assert request_line not in log, f"an access-log line reached the runtime log: {request_line!r}"
    assert runtime.stop() == 0
    assert runtime.record()["status"] == "stopped"


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
        "project_id": "proj-host", "project_name": "Persists", "actor": HUMAN}, token=first.token)
    assert status == 200, created
    assert (first.project / "capsule" / ".git").is_dir(), "the store is git-backed at a non-ASCII path"
    assert first.stop() == 0

    second = host(label="second").start()
    again = second.wait_for("ready")
    assert again["instance"] != ready["instance"]
    state = json.loads(_get(again["port"], "/api/state", token=second.token)[1])
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
    tok = runtime.token
    assert _post(port, "/api/project", {"project_id": "proj-j", "project_name": "Portal",
                                        "actor": HUMAN}, token=tok)[0] == 200
    status, intent = _post(port, "/api/proposals", {
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL}, token=tok)
    assert status == 200
    assert _post(port, f"/api/proposals/{intent['proposal_id']}/confirm",
                 {"actor": HUMAN}, token=tok)[0] == 200
    status, chosen = _post(port, "/api/proposals", {
        "field": "provider", "value": {"name": provider}, "actor": HUMAN}, token=tok)
    assert status == 200
    assert _post(port, f"/api/proposals/{chosen['proposal_id']}/confirm",
                 {"actor": HUMAN}, token=tok)[0] == 200
    assert _post(port, "/api/brd", token=tok)[0] == 200
    status, confirmed = _post(port, "/api/journey/confirm-scope", {"actor": HUMAN}, token=tok)
    assert status == 200 and confirmed["stage"] == "CONFIRM"

    status, refused = _post(port, "/api/build", {"actor": HUMAN}, token=tok)
    assert status == 409 and "not eligible" in refused["refused"] and provider in refused["refused"]
    assert refused["eligibility"]["eligible"] is False
    state = json.loads(_get(port, "/api/state", token=tok)[1])
    assert state["journey"]["stage"] == "CONFIRM" and state["journey"]["status"] == "active"
    assert "start_build" not in state["journey"]["actions"]
    assert state["provider_eligibility"]["eligible"] is False
    assert state["providers"] == list(PROVIDERS)
    assert json.loads(_get(port, "/api/build", token=tok)[1]) == {"status": "never_run"}
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
