"""The Windows basic-user runtime: launch mechanics, and no authority.

WHAT THIS IS FOR. A person receives the Forge folder, double-clicks
`Forge.cmd`, and their browser opens on the governed onboarding journey --
no terminal, no Python command, no port, no path typed. This module is the
process behind that double-click. It decides only OPERATIONAL questions:

  * which Forge is running -- the code inside the launched folder, checked
    structurally against where the running package actually sits, so the
    launch directory, PATH, an environment variable or another installed
    `nornyx_forge` can never substitute one installation for another;
  * on which interpreter -- a self-contained bundle runs on the interpreter
    it carries and on nothing else (no fallback to a system Python under
    the same label), a developer bundle runs on the Python it was pointed at
    and says so;
  * on which project -- an explicit absolute directory the launcher passed,
    refused when relative, so the working directory selects nothing;
  * whether this project's runtime is ALREADY running -- one runtime per
    project, held by an operating-system file lock for the life of the
    process, so two launches can never race over one authority store;
  * on which loopback port -- the preferred port when it is free, otherwise
    a port the operating system hands out, recorded so the next launch and
    the browser reach the server Forge actually started;
  * when the browser may open -- only after this process has round-tripped
    a request through its own socket and read its own instance token back,
    bounded by a timeout that fails visibly instead of hanging.

WHAT IT MAY NEVER DECIDE. Nothing here is governance authority. The runtime
record (instance token, port, pid, status, log path) lives OUTSIDE every
project, under the person's own Forge place, and answers exactly one
question: is the local Windows runtime running? It cannot advance an
Experience stage, create or imply an approval, make a provider eligible,
validate a contract, or stand in for an inspection. The onboarding surface
never reads it; this module never reads or writes the capsule store. A
forged record can at most make a launch refuse or take another port. The
bundle marker `forge-bundle.json` is the same kind of thing: it says which
KIND of folder this is, and a forged marker can only make the launcher
refuse or run a developer bundle on the interpreter it was given.

IDENTITY IS NEVER A PID. A recorded pid is informational. Liveness is the
file lock -- released by the operating system when the owner dies, whatever
the pid was reused for -- and identity is the instance token this process
generated and serves on `/api/runtime`. A listener that answers on the
recorded port without that token, whatever it is, is not this runtime, and
this runtime never terminates anything: an unrelated occupant of the
preferred port costs a different port, not a process.

THE TRUST BOUNDARY is the one the onboarding surface already discloses:
loopback, one person, this machine's logged-in user. The stop route is a
person's act at that surface, with the same actor rule and no more.

`layer.application`, by the forge_onboarding precedent: this module
composes the served surface and runs the server loop in the current
process. The one process it causes to start -- the person's browser -- is
started by the declared launcher adapter, not here.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import logging
import os
import secrets
import shutil
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .app_launcher import open_in_default_browser
from .capsule import CapsuleValidationError
from .capsule_store import DEFAULT_SEAL_DIR
from .governed_subject import GovernedSubjectError
from .onboarding_app import ActorPayload
from .onboarding_serve import ONBOARDING_HOST, assemble
from .subject_bootstrap import resolve_packaged_root

if sys.platform == "win32":
    import msvcrt
else:  # pragma: no cover - exercised on the Linux census, not on this host
    import fcntl

#: The runtime record's schema. Operational state; see the module docstring.
RUNTIME_SCHEMA = "nornyx.forge.windows_runtime.v1"
#: The bundle marker the builder writes at the folder root, naming its kind.
BUNDLE_MARKER = "forge-bundle.json"
BUNDLE_SCHEMA = "nornyx.forge.windows_bundle.v1"
#: The two kinds of folder. A self-contained bundle carries its interpreter
#: under `python\`; a developer bundle carries none and runs on an installed
#: Python. Neither is ever mistaken for the other.
BUNDLE_MODES = ("self_contained", "developer")
#: The port tried first. Not a promise: an occupied port costs a different
#: port, and the record says which one was taken.
PREFERRED_PORT = 8710
#: Where runtime records, locks and logs live: outside every project, under
#: the person's own Forge place, beside -- and distinct from -- the seals.
DEFAULT_RUNTIME_DIR = Path.home() / ".nornyx" / "forge" / "runtime"
#: How long the server may take to answer its own probe before the launch is
#: recorded as failed. CrewAI's import tree dominates a cold start; measured
#: on the development workstation at about seven seconds.
READINESS_TIMEOUT_S = 90.0
PROBE_TIMEOUT_S = 2.0
RUNTIME_ROUTE = "/api/runtime"
RUNTIME_STOP_ROUTE = "/api/runtime/stop"
STATUSES = ("starting", "ready", "failed", "stopped")

GIT_MISSING = (
    "git was not found on this computer's PATH. Forge keeps each project's "
    "capsule in a git repository, so the journey cannot create a project "
    "without it. Install Git for Windows and launch Forge again."
)

_log = logging.getLogger("nornyx_forge.windows_runtime")


class RuntimeRefusal(Exception):
    """A launch this runtime refuses, in words a person can act on."""


class RuntimeRecordUnreadable(RuntimeRefusal):
    """A record exists and is not a runtime record this module wrote."""


def _shown(value: Any, limit: int = 200) -> str:
    """A fragment of something read from disk or from a socket, made fit for
    a notice: quoted, and cut. What a record or a listener says is data; a
    message box that echoed it whole was measured at 200 KB under review."""
    text = str(value)
    return repr(text if len(text) <= limit else text[:limit] + "...")


# ---------------------------------------------------------------------------
# Which Forge, on which interpreter
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BundleIdentity:
    """The folder that was launched, verified to be the code that is running."""

    root: Path
    mode: str
    interpreter: Path


def read_bundle_marker(root: Path) -> dict[str, Any]:
    """The builder's marker, or a refusal naming what is wrong with it."""
    path = Path(root) / BUNDLE_MARKER
    if not path.is_file():
        raise RuntimeRefusal(
            f"{root} is not a complete Forge bundle: {BUNDLE_MARKER} is missing. "
            "Launch Forge from the folder the bundle builder produced."
        )
    try:
        marker = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeRefusal(f"{path} is unreadable: {exc}") from exc
    if not isinstance(marker, dict) or marker.get("schema") != BUNDLE_SCHEMA:
        raise RuntimeRefusal(f"{path} is not a {BUNDLE_SCHEMA} marker")
    if marker.get("mode") not in BUNDLE_MODES:
        raise RuntimeRefusal(
            f"{path} names an unknown bundle mode {_shown(marker.get('mode'))}; "
            f"a bundle is one of {', '.join(BUNDLE_MODES)}"
        )
    return marker


def verify_launched_bundle(
    bundle_root: str | Path,
    *,
    packaged_root: Callable[[], Path] = resolve_packaged_root,
    executable: str | None = None,
) -> BundleIdentity:
    """The launched folder must be the code that is running, on its own interpreter.

    The launcher passes its own directory explicitly. That alone would be a
    claim; the check is that `resolve_packaged_root()` -- derived from where
    the running package's file actually is -- names the same directory. If a
    PATH-installed or shadowing `nornyx_forge` had been imported instead, the
    two differ and the launch refuses rather than serve one installation
    under another's name.
    """
    launched = Path(bundle_root)
    if not launched.is_absolute():
        raise RuntimeRefusal(
            "the bundle root must be absolute: the launcher derives it from its "
            "own location, and a relative path would let the launch directory "
            "choose which Forge runs"
        )
    launched = launched.resolve()
    if not launched.is_dir():
        raise RuntimeRefusal(f"the bundle root {launched} is not a directory")
    try:
        running = Path(packaged_root()).resolve()
    except GovernedSubjectError as exc:
        raise RuntimeRefusal(f"the running Forge cannot resolve its own root: {exc}") from exc
    if os.path.normcase(str(running)) != os.path.normcase(str(launched)):
        raise RuntimeRefusal(
            f"the Forge code that is running lives in {running}, not in the "
            f"launched folder {launched}. Refusing to serve one installation "
            "under another's name; nothing on PATH, in the environment or in "
            "the working directory may select which Forge runs."
        )
    marker = read_bundle_marker(launched)
    interpreter = Path(executable or sys.executable).resolve()
    if marker["mode"] == "self_contained":
        carried = launched / "python"
        if carried not in interpreter.parents:
            raise RuntimeRefusal(
                "this self-contained bundle runs only on the interpreter it "
                f"carries under {carried}, and was started with {interpreter}. "
                "No other Python is substituted for a bundle that ships its own."
            )
    return BundleIdentity(root=launched, mode=marker["mode"], interpreter=interpreter)


def project_location(argument: str | Path) -> Path:
    """The project directory the launcher chose: absolute, or refused."""
    chosen = Path(argument)
    if not chosen.is_absolute():
        raise RuntimeRefusal(
            "the project directory must be absolute: a relative path would let "
            "the launch directory select project authority, which is the "
            "FORGE_ROOT defect wearing different clothes"
        )
    chosen = chosen.resolve()
    if chosen.exists() and not chosen.is_dir():
        raise RuntimeRefusal(f"the project location {chosen} exists and is not a directory")
    return chosen


# ---------------------------------------------------------------------------
# Runtime state: a record, a lock and a log, keyed by project
# ---------------------------------------------------------------------------

def runtime_key(project_dir: Path) -> str:
    """One key per project directory. Case-folded on this platform's terms,
    because the same NTFS directory spelled two ways is one authority store."""
    canonical = os.path.normcase(str(Path(project_dir).resolve()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class RuntimePaths:
    directory: Path
    key: str

    @classmethod
    def for_project(cls, directory: Path, project_dir: Path) -> "RuntimePaths":
        return cls(Path(directory), runtime_key(project_dir))

    @property
    def record(self) -> Path:
        return self.directory / f"{self.key}.json"

    @property
    def lock(self) -> Path:
        return self.directory / f"{self.key}.lock"

    @property
    def log(self) -> Path:
        return self.directory / f"{self.key}.log"

    @property
    def failures(self) -> Path:
        return self.directory / "launch-failures.log"


def write_record(path: Path, record: dict[str, Any]) -> None:
    """Whole-file replace, so a reader never sees a half-written record.

    Windows refuses to replace a file another process has open at that
    instant, and the record is polled by exactly such readers; a handful of
    short retries covers the read, which is milliseconds long.
    """
    staging = path.with_name(path.name + ".tmp")
    staging.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8", newline="")
    for attempt in range(20):
        try:
            os.replace(staging, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def read_record(path: Path) -> dict[str, Any] | None:
    """The record, `None` when there is none, a refusal when there is
    something else. Missing and damaged are different findings."""
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeRecordUnreadable(f"the runtime record {path} is unreadable: {exc}") from exc
    if (
        not isinstance(record, dict)
        or record.get("schema") != RUNTIME_SCHEMA
        or record.get("status") not in STATUSES
        or not isinstance(record.get("instance"), str)
        or not isinstance(record.get("port"), int)
    ):
        raise RuntimeRecordUnreadable(
            f"the runtime record {path} is not a {RUNTIME_SCHEMA} record; "
            "it decides nothing and this launch will not act on it"
        )
    return record


class RuntimeLock:
    """One owner per project, for the owner's lifetime.

    An exclusive byte-range lock on a file the operating system releases
    when the process ends -- however it ends. That is what makes it the
    liveness oracle: a stale record beside an unheld lock identifies nothing,
    and a held lock means an owner is alive whatever its pid was reused for.
    Measured on Windows: a second handle in the SAME process is refused too,
    and the locked file cannot be unlinked from under its owner.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> bool:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if sys.platform == "win32":
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - the Linux census runs this branch
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            if sys.platform == "win32":
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            else:  # pragma: no cover
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(self._fd)
        self._fd = None


# ---------------------------------------------------------------------------
# The loopback port, and who answers on it
# ---------------------------------------------------------------------------

def bind_loopback(preferred: int) -> socket.socket:
    """A bound loopback socket: the preferred port when free, else any port.

    Bound HERE and handed to the server, so there is no window between
    "checked free" and "bound" in which another process could take it. On
    Windows the exclusive-use option makes an occupied port refuse the bind
    outright instead of sharing it.
    """

    def attempt(port: int) -> socket.socket | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform == "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:  # pragma: no cover
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((ONBOARDING_HOST, port))
        except (OSError, OverflowError, ValueError):
            sock.close()
            return None
        return sock

    if preferred:
        sock = attempt(preferred)
        if sock is not None:
            return sock
    sock = attempt(0)
    if sock is None:
        raise RuntimeRefusal("no loopback port could be bound on this computer")
    return sock


def runtime_url(port: int) -> str:
    return f"http://{ONBOARDING_HOST}:{port}/"


def probe_instance(port: int, *, timeout: float = PROBE_TIMEOUT_S) -> dict[str, Any] | None:
    """What answers on the loopback port, IF it is a Forge runtime.

    Anything else -- nothing, a refusal, a different service, a page that is
    not JSON, JSON of another schema -- is `None`. "Something answered on the
    port" is never read as "this runtime is healthy".
    """
    connection = http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=timeout)
    try:
        connection.request("GET", RUNTIME_ROUTE)
        response = connection.getresponse()
        body = response.read(65536)
        status = response.status
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()
    if status != 200:
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("schema") != RUNTIME_SCHEMA:
        return None
    return payload


# ---------------------------------------------------------------------------
# The two operational routes
# ---------------------------------------------------------------------------

class StopPayload(BaseModel):
    actor: ActorPayload


def attach_runtime_routes(
    application: FastAPI,
    *,
    identity: dict[str, Any],
    request_stop: Callable[[], None],
) -> None:
    """`/api/runtime` says which runtime this is; `/api/runtime/stop` ends it.

    Both are operational. Neither reads or writes the capsule store, and
    neither appears in any lifecycle, eligibility or governance answer.
    """
    served = dict(identity)

    @application.get(RUNTIME_ROUTE)
    def runtime() -> dict[str, Any]:
        return dict(served)

    @application.post(RUNTIME_STOP_ROUTE)
    def stop(payload: StopPayload):
        try:
            payload.actor.to_actor().validate()
        except CapsuleValidationError as error:
            return JSONResponse(status_code=422, content={"refused": str(error)})
        if payload.actor.kind != "human":
            return JSONResponse(status_code=409, content={
                "refused": "stopping Forge is a person's act at this computer; "
                           f"a {payload.actor.kind} actor may not do it",
            })
        request_stop()
        return {"stopping": True, "instance": served["instance"]}


# ---------------------------------------------------------------------------
# Presentation: telling the person, and opening their browser
# ---------------------------------------------------------------------------

def notify_person(title: str, text: str) -> None:
    """The failure a basic user can see.

    Launched from `Forge.cmd` this process has no console (pythonw), so text
    on a stream nobody reads is not a presentation; a Windows message box
    is. Launched from a console, the console is the presentation. The rule
    reads the ORIGINAL stream, so redirecting output to the log changes
    nothing about it.
    """
    if sys.platform == "win32" and sys.__stdout__ is None:
        import ctypes  # noqa: PLC0415 - Windows-only presentation

        mb_iconerror, mb_setforeground = 0x10, 0x10000
        ctypes.windll.user32.MessageBoxW(None, text, title, mb_iconerror | mb_setforeground)
        return
    print(f"{title}: {text}", file=sys.stderr, flush=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _note_failure(runtime_dir: Path | None, text: str) -> None:
    """A diagnostic trail for launches that ended before a record existed."""
    if runtime_dir is None:
        return
    try:
        runtime_dir.mkdir(parents=True, exist_ok=True)
        with (runtime_dir / "launch-failures.log").open("a", encoding="utf-8") as trail:
            trail.write(f"{_now_iso()} {text}\n")
    except OSError:
        pass


def _log_to(log_path: Path) -> logging.Handler:
    """The runtime's log file: everything this module and the server log.

    Only when there is NO console (pythonw, which is how the launcher runs
    this) are the process's standard streams pointed at the same file too;
    a console launch keeps its console, and a host process that runs the
    launch in-process -- the test suite -- keeps its streams untouched.
    """
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > logging.INFO:
        root.setLevel(logging.INFO)
    if sys.stdout is None:
        sys.stdout = handler.stream
    if sys.stderr is None:
        sys.stderr = handler.stream
    return handler


def _stop_logging(handler: logging.Handler) -> None:
    logging.getLogger().removeHandler(handler)
    handler.close()


# ---------------------------------------------------------------------------
# The launch
# ---------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nornyx_forge.windows_runtime",
        description="Start the Forge onboarding runtime for one project and open the browser",
    )
    parser.add_argument("--bundle-root", required=True,
                        help="The launched folder; the launcher passes its own directory")
    parser.add_argument("--project-dir", required=True,
                        help="Absolute project directory; the launcher passes it explicitly")
    parser.add_argument("--port", type=int, default=PREFERRED_PORT,
                        help="Preferred loopback port; 0 asks the OS for any free port")
    parser.add_argument("--runtime-dir", default=str(DEFAULT_RUNTIME_DIR),
                        help="Where the runtime record, lock and log live (operational state)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open the browser once ready (tests and operator runs)")
    parser.add_argument("--readiness-timeout", type=float, default=READINESS_TIMEOUT_S,
                        help="Seconds the server may take to answer its own probe")
    return parser


def _same_root(a: str, b: str) -> bool:
    return os.path.normcase(str(Path(a))) == os.path.normcase(str(Path(b)))


#: Returned by `_join_existing` when the holder went away while this launch
#: waited and the lock is now this process's: the launch proceeds as owner.
_BECAME_OWNER = -1
#: How long a record left by a FINISHED run may still be read while a new
#: owner, lock in hand, has not yet written its own. Measured under review:
#: two launches in the same instant, the loser read the previous run's
#: `stopped` record and refused with a reason that was not this launch's.
_PROVISIONAL_S = 2.0


def _join_existing(
    paths: RuntimePaths,
    identity: BundleIdentity,
    *,
    lock: RuntimeLock,
    timeout: float,
    open_browser: Callable[[str], None],
    notify: Callable[[str, str], None],
    want_browser: bool,
) -> int:
    """Another process holds this project's runtime. Reach it, or say why not.

    Deterministic second launch: the same Forge already healthy on this
    project opens its page; another installation serving this project is a
    visible refusal, never a silent substitution; a holder that does not
    answer within the timeout is a visible failure. The lock is retried on
    every turn of the wait: a holder that died -- crashed, or was stopped a
    moment ago -- releases it, and this launch then becomes the owner instead
    of waiting on a record nobody will update. A record from a FINISHED run
    is provisional for a moment, because the new owner may not have written
    its own yet.
    """
    deadline = time.monotonic() + timeout
    terminal_since: float | None = None
    while True:
        if lock.acquire():
            return _BECAME_OWNER
        record = read_record(paths.record)
        if record is None:
            if time.monotonic() >= deadline:
                notify("Forge is already starting",
                       "another Forge process holds this project's runtime lock but "
                       f"recorded nothing within {timeout:g}s; see {paths.log}")
                return 2
            time.sleep(0.25)
            continue
        if record.get("status") in ("failed", "stopped"):
            # A finished run's port is never probed: on Windows a probe of a
            # closed loopback port costs the whole timeout (measured, 2 s),
            # and the record it would be judged by must be a FRESH read.
            now = time.monotonic()
            terminal_since = now if terminal_since is None else terminal_since
            if now - terminal_since >= _PROVISIONAL_S:
                notify("Forge could not start",
                       f"the Forge process holding this project's runtime lock "
                       f"recorded '{record['status']}': {_shown(record.get('reason'))}")
                return 2
            time.sleep(0.25)
            continue
        terminal_since = None
        answered = probe_instance(record["port"])
        if answered is not None and answered.get("instance") == record["instance"]:
            if not _same_root(str(answered.get("bundle_root", "")), str(identity.root)):
                notify("Forge is already running from another folder",
                       f"this project is being served by the Forge in "
                       f"{_shown(answered.get('bundle_root'))} (port {record['port']}). Stop "
                       f"that one before launching the Forge in {identity.root}.")
                return 2
            url = runtime_url(record["port"])
            _log.info("already running: %s", url)
            if want_browser:
                try:
                    open_browser(url)
                except (OSError, ValueError) as exc:
                    notify("Forge is running", f"Open {url} in your browser. ({exc})")
                    return 3
            return 0
        if time.monotonic() >= deadline:
            notify("Forge did not answer",
                   f"a Forge runtime holds the lock for this project but did not "
                   f"answer on port {record['port']} within {timeout:g}s. See {paths.log}.")
            return 2
        time.sleep(0.25)


def launch(
    argv: list[str],
    *,
    packaged_root: Callable[[], Path] = resolve_packaged_root,
    assemble_app: Callable[[Path], FastAPI] = assemble,
    open_browser: Callable[[str], None] = open_in_default_browser,
    notify: Callable[[str, str], None] = notify_person,
    which: Callable[[str], str | None] = shutil.which,
    clock: Callable[[], str] = _now_iso,
) -> int:
    """One launch, start to finish. Returns the process exit code.

    Every keyword is a composition-time seam with the real thing as its
    default; `main` passes none of them, and a test pins that.
    """
    arguments = _parser().parse_args(argv)
    runtime_dir = Path(arguments.runtime_dir)
    if not runtime_dir.is_absolute():
        notify("Forge could not start", "the runtime directory must be absolute")
        return 2
    runtime_dir = runtime_dir.resolve()
    # THE FENCE FIRST, before anything is created. Operational state stays
    # out of the project -- the build hands that directory to a provider as
    # its workspace and the verifier censuses it -- and out of the seal
    # directory beside it; and a place this launch refuses is a place it
    # writes nothing into, not even the trail (measured under review: the
    # refusal used to create the fenced directory and log inside it).
    fences = [(DEFAULT_SEAL_DIR.resolve(), "the seal directory")]
    candidate_project = Path(arguments.project_dir)
    if candidate_project.is_absolute():
        fences.append((candidate_project.resolve(), "the project directory"))
    for fenced, name in fences:
        if runtime_dir == fenced or fenced in runtime_dir.parents:
            notify("Forge could not start",
                   f"the runtime directory {runtime_dir} is inside {name} {fenced}; "
                   "operational state lives outside every project and outside the seals")
            return 2
    # Then the trail directory, so that every refusal below leaves a trace a
    # person can find, whichever check refused.
    try:
        try:
            runtime_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeRefusal(f"the runtime directory {runtime_dir} cannot be created: {exc}") from exc
        identity = verify_launched_bundle(arguments.bundle_root, packaged_root=packaged_root)
        if which("git") is None:
            raise RuntimeRefusal(GIT_MISSING)
        project = project_location(arguments.project_dir)
        if not 0 <= arguments.port <= 65535:
            raise RuntimeRefusal(f"the port must be 0-65535, not {arguments.port}")
        paths = RuntimePaths.for_project(runtime_dir, project)
    except RuntimeRefusal as refusal:
        _note_failure(runtime_dir, f"refused before the lock: {refusal}")
        notify("Forge could not start", str(refusal))
        return 2

    lock = RuntimeLock(paths.lock)
    if not lock.acquire():
        try:
            joined = _join_existing(
                paths, identity, lock=lock, timeout=arguments.readiness_timeout,
                open_browser=open_browser, notify=notify, want_browser=not arguments.no_browser,
            )
        except RuntimeRefusal as refusal:
            _note_failure(runtime_dir, f"could not join the running instance: {refusal}")
            notify("Forge could not start", str(refusal))
            return 2
        if joined != _BECAME_OWNER:
            return joined
    try:
        return _own_runtime(
            paths, identity, project, arguments,
            assemble_app=assemble_app, open_browser=open_browser, notify=notify, clock=clock,
        )
    finally:
        lock.release()


def _own_runtime(
    paths: RuntimePaths,
    identity: BundleIdentity,
    project: Path,
    arguments: argparse.Namespace,
    *,
    assemble_app: Callable[[Path], FastAPI],
    open_browser: Callable[[str], None],
    notify: Callable[[str, str], None],
    clock: Callable[[], str],
) -> int:
    """This process owns the project's runtime: bind, record, serve, then
    open the browser only once the server has answered for itself."""
    try:
        sock = bind_loopback(arguments.port)
    except RuntimeRefusal as refusal:
        _note_failure(paths.directory, str(refusal))
        notify("Forge could not start", str(refusal))
        return 2
    port = sock.getsockname()[1]
    url = runtime_url(port)
    token = secrets.token_hex(16)
    record_lock = threading.Lock()
    record: dict[str, Any] = {
        "schema": RUNTIME_SCHEMA,
        "instance": token,
        "status": "starting",
        "reason": None,
        "bundle_root": str(identity.root),
        "bundle_mode": identity.mode,
        "project_dir": str(project),
        "port": port,
        "url": url,
        # Informational. Liveness is the lock; identity is the token.
        "pid": os.getpid(),
        "python": str(identity.interpreter),
        "started_at": clock(),
        "ready_at": None,
        "stopped_at": None,
        "browser": {"requested": not arguments.no_browser, "opened": None,
                    "error": None, "at": None},
        "log": str(paths.log),
    }

    def update(**changes: Any) -> None:
        with record_lock:
            record.update(changes)
            write_record(paths.record, record)

    handler = _log_to(paths.log)
    update()
    _log.info("runtime %s starting for %s from %s on %s", token, project, identity.root, url)

    try:
        application = assemble_app(project)
    except Exception as exc:  # noqa: BLE001 - the reason must reach the person
        reason = f"the onboarding surface could not be assembled: {exc}"
        update(status="failed", reason=reason, stopped_at=clock())
        _log.exception("assembly failed")
        notify("Forge could not start", reason)
        sock.close()
        _stop_logging(handler)
        return 2

    server = uvicorn.Server(uvicorn.Config(
        application, host=ONBOARDING_HOST, port=port, log_config=None, log_level="info",
    ))
    served_identity = {
        "schema": RUNTIME_SCHEMA, "instance": token, "bundle_root": str(identity.root),
        "bundle_mode": identity.mode, "project_dir": str(project), "port": port,
        "pid": os.getpid(), "python": str(identity.interpreter), "started_at": record["started_at"],
    }

    def request_stop() -> None:
        _log.info("stop requested at the surface")
        server.should_exit = True

    attach_runtime_routes(application, identity=served_identity, request_stop=request_stop)
    # A page that rebinds a name to 127.0.0.1 would otherwise reach the
    # surface with a foreign Host header (measured under review). The surface
    # is loopback; so is the only host it answers to.
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
    outcome: dict[str, Any] = {"code": 0, "notice": None}

    def await_readiness() -> None:
        deadline = time.monotonic() + arguments.readiness_timeout
        while time.monotonic() < deadline:
            answered = probe_instance(port, timeout=1.0)
            if answered is not None and answered.get("instance") == token:
                update(status="ready", ready_at=clock())
                _log.info("ready: %s answered with its own instance token", url)
                if arguments.no_browser:
                    return
                try:
                    open_browser(url)
                except (OSError, ValueError) as exc:
                    update(browser={**record["browser"], "opened": False,
                                    "error": str(exc), "at": clock()})
                    _log.warning("browser not opened: %s", exc)
                    notify("Forge is running", f"Open {url} in your browser. ({exc})")
                    return
                update(browser={**record["browser"], "opened": True, "at": clock()})
                _log.info("browser opened on %s", url)
                return
            if server.should_exit:
                return
            time.sleep(0.2)
        reason = (f"the local server did not answer on {url} within "
                  f"{arguments.readiness_timeout:g}s; see {paths.log}")
        # Recorded here; TOLD from the main thread once the server has exited,
        # so the notice outlives this daemon thread (measured under review:
        # a message box raised here died with the process).
        outcome["code"] = 2
        outcome["notice"] = reason
        update(status="failed", reason=reason)
        _log.error(reason)
        server.should_exit = True

    watcher = threading.Thread(target=await_readiness, name="forge-readiness", daemon=True)
    watcher.start()
    try:
        server.run(sockets=[sock])
    finally:
        watcher.join(timeout=5)
        with record_lock:
            if record["status"] != "failed":
                record["status"] = "stopped"
            record["stopped_at"] = clock()
            write_record(paths.record, record)
        _log.info("runtime %s stopped", token)
        _stop_logging(handler)
    if outcome["notice"] is not None:
        notify("Forge could not start", outcome["notice"])
    return outcome["code"]


def main(argv: list[str] | None = None) -> None:
    """The console entry: the real launcher, the real browser, the real notice."""
    sys.exit(launch(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":  # pragma: no cover - the process entry
    main()
