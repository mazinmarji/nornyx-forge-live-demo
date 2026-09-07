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
from types import MappingProxyType
from typing import Any, Callable, Mapping

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .app_launcher import open_in_default_browser
from .capsule import CapsuleValidationError
from .capsule_store import DEFAULT_SEAL_DIR
from .control_plane_session import LAUNCH_SLOT, REOPEN_PATH, REOPEN_SLOT, RUNTIME_PATH
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
#: The allowlisted operational paths come from the gate, so the route this
#: module attaches and the path the gate lets through cannot drift apart.
RUNTIME_ROUTE = RUNTIME_PATH
RUNTIME_STOP_ROUTE = "/api/runtime/stop"
#: The reopen route: a launcher or the page's Reconnect asks the OWNING process
#: to mint a fresh nonce and open the browser on its own URL. Allowlisted by the
#: session gate; rate-limited here. The caller never receives the token.
RUNTIME_REOPEN_ROUTE = REOPEN_PATH
#: One reopen per this many seconds, in-process: a provider that spams it can
#: open at most one browser window every interval -- a visible nuisance, bounded.
#: This interval also sizes the session's reopen-nonce queue: at one mint per
#: interval, `control_plane_session.REOPEN_PENDING_BOUND` is the most nonces
#: that can be outstanding within one TTL, so under this limit no pending
#: reopen nonce -- the person's own Reconnect included -- is ever evicted by
#: another caller's reopen. The two constants are pinned together by test.
REOPEN_INTERVAL_S = 10.0
#: The smoke/test-only session file's schema. Written only when an explicit
#: `--session-file` path is given; the shipped launchers never pass one.
RUNTIME_SESSION_SCHEMA = "nornyx.forge.runtime_session.v1"
#: The reopen route's fixed refusals, as read-only views (a shared module dict
#: a handler grew in place would be served to every later caller).
#: `REOPEN_BUSY` is the rate limit; `REOPEN_NOT_GRANTED` is a run started with
#: `--no-browser`: browser authority was never granted to it, so no caller may
#: make it open one.
REOPEN_BUSY: Mapping[str, str] = MappingProxyType(
    {"refused": "a browser window was just opened; wait a moment"})
REOPEN_NOT_GRANTED: Mapping[str, str] = MappingProxyType(
    {"refused": "this Forge was started without a browser; open its page yourself"})
#: `REOPEN_FAILED` is the owner's browser adapter raising: 503, so that a
#: caller reading the STATUS learns the page did not open. A 200 carrying
#: `reopening: false` was read as success by the joining launcher, which
#: then returned in silence (measured under the second review).
REOPEN_FAILED: Mapping[str, str] = MappingProxyType(
    {"refused": "Forge could not open a browser on this computer; open its page yourself"})
#: Path spellings the two path fences refuse before comparing anything. A
#: Windows namespace prefix (`\\?\` extended-length, `\\.\` device, and their
#: forward-slash spellings) survives `Path.resolve()`, so a path so spelled
#: never has the plain fenced roots among its parents and the fence admits a
#: file INSIDE the profile (measured under the third review, end to end:
#: `--session-file \\?\<profile>\stolen.json` launched ready and wrote the
#: bearer there). The session-file fence goes further and refuses any path
#: that begins with a double separator -- a UNC share included -- because a
#: local-drive root reached through `\\localhost\C$\...` is the same bypass
#: in another spelling (measured here: admitted before this rule). A secret's
#: path is a plain local drive path or it is refused.
_NAMESPACE_PREFIXES = ("\\\\?\\", "\\\\.\\")
#: What the joining launcher tells the person when the owner refused to
#: reopen, or could not. Each names the fragmentless URL and no secret: the
#: joiner has none to name. Silence here left the person with no page and no
#: reason (measured under review).
_REOPEN_NOTICES = {
    429: "Forge is already running for this project and opened a page a moment ago. "
         "Open {url} in your browser if you do not see it.",
    409: "Forge is already running for this project without a browser. "
         "Open {url} in your browser.",
    503: "Forge is already running for this project but could not open a browser on "
         "this computer. Open {url} in your browser.",
}
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


def _scrubbed(text: str, *secrets: str | None) -> str:
    """`text` with every given secret replaced. Belt and braces for the
    browser-failure path: the message is composed without the fragment
    URL, and whatever an exception said is scrubbed of it as well."""
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def _said(exc: BaseException) -> str:
    """What an exception says, or a fixed description when it cannot say it.

    `str(exc)` runs the exception's own `__str__`, and an adapter or handler
    class whose `__str__` raises would throw from INSIDE the `except` that
    was catching it -- out of the scrubber, out of the branch, and into a
    traceback carrying whatever the exception object holds (third review,
    P4-4). Nothing the description below names can be a secret: it is the
    class name and nothing the instance rendered.
    """
    try:
        return str(exc)
    except Exception:  # noqa: BLE001 - a __str__ that raises is the case handled
        return f"<{type(exc).__name__} whose message could not be rendered>"


def _namespace_prefixed(path: Path | str) -> bool:
    r"""True when `path` is spelled with a Windows namespace prefix, `\\?\` or
    `\\.\`, in either separator. `str(Path)` on Windows already folds `//?/`
    to `\\?\`; the fold here makes the rule read the same on POSIX, where the
    fence is exercised by the Linux census."""
    return str(path).replace("/", "\\").startswith(_NAMESPACE_PREFIXES)


def _double_separator(path: Path | str) -> bool:
    """True when `path` begins with two separators: a namespace prefix or a
    UNC share, in either separator."""
    return str(path).replace("/", "\\").startswith("\\\\")


def _embedded_nul(path: Path | str) -> bool:
    r"""True when `path` carries an embedded NUL, which no fence may resolve.

    THE RULE THIS STATES, and every fence below obeys: an embedded NUL is
    refused EXPLICITLY and FIRST -- before any spelling check, before
    `resolve`, and before any root comparison -- in every fence that takes a
    caller-supplied path. A NUL-bearing path is one no fence can compare, and
    which fence answers must not depend on the interpreter's version.

    THAT UNIVERSAL IS CHECKABLE, so it is enumerated here rather than merely
    asserted. `launch` takes FOUR caller-supplied paths and there is no fifth:
    `--bundle-root`, `--project-dir` and `--runtime-dir`, all three refused by
    the loop at the top of `launch` before anything is created, and
    `--session-file`, refused the same way and equally first inside
    `_session_file_refusal`. The remaining flags -- `--port`, `--no-browser`
    and `--readiness-timeout` -- are not paths. Round 6 fenced three of the
    four and wrote this universal anyway; `--bundle-root` was the fourth, and
    the one the universal was false of (round-6 security S-1).

    It DID depend on it, measured on this repository's own CI. What
    `ntpath.realpath(p, strict=False)` does with a NUL is RETURN `p`
    unchanged: it catches the `ValueError` `_getfinalpathname` raises and
    falls back to `normpath`, so nothing is expanded and an 8.3 segment stays
    short. On CPython <= 3.12 `Path.resolve()` then runs its non-strict
    symlink-loop check, `p.stat()` (pathlib.py:1250); `os.stat` raises
    `ValueError: stat: embedded null character in path`, the `except OSError`
    around that call does not catch it, and it escapes `resolve` -- so the
    fences' `except ValueError` fired and the notice read "cannot be
    resolved". On 3.13 `resolve()` is `os.path.realpath` and nothing more: it
    RETURNS the NUL-bearing path, and the root comparison then ran on an
    UNRESOLVED, possibly short-spelled path. That is why round 5's NUL case
    was red on the windows-latest job (CPython 3.13.15, whose `tmp_path` lies
    under `C:\Users\runneradmin`, so the profile fence answered first); it is
    now `test_an_embedded_nul_in_any_operand_is_a_notice_not_a_traceback`,
    which crosses both resolutions with both placements. The hole is an
    ORDERING one and not only a version-dependent test: a comparison written
    to read a resolution read a spelling instead.

    The NUL also reached TWO paths that catch nothing, not one. `launch`
    resolved the candidate PROJECT while building its fence list, outside any
    `try`; and `verify_launched_bundle` resolves the caller's `--bundle-root`
    (`launched = launched.resolve()`) outside every `try` as well, reached
    from `launch` inside a `try` that catches only `RuntimeRefusal`. On
    <= 3.12 a NUL in either was a traceback rather than the fixed notice. The
    bundle folder was the worse of the two, and the reason it is refused at
    the top rather than where it is used: `verify_launched_bundle` runs AFTER
    `runtime_dir.mkdir()`, so that refusal had already created the runtime
    directory -- against the rule the fence list states, that a place this
    launch refuses is a place it writes nothing into.

    The `except ValueError` sites stay as belt-and-braces for a resolution
    this rule did not anticipate; they are no longer the NUL's only guard.
    """
    return "\x00" in str(path)


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


def _loopback_connection(port: int, timeout: float) -> http.client.HTTPConnection:
    """The ONE place this module opens a loopback connection. Both the probe
    and the reopen request go through it, so
    `test_w3_w15_the_runtime_speaks_only_to_loopback_and_fetches_nothing` can
    pin that every connection this module makes is to `ONBOARDING_HOST`."""
    return http.client.HTTPConnection(ONBOARDING_HOST, port, timeout=timeout)


def probe_instance(port: int, *, timeout: float = PROBE_TIMEOUT_S) -> dict[str, Any] | None:
    """What answers on the loopback port, IF it is a Forge runtime.

    Anything else -- nothing, a refusal, a different service, a page that is
    not JSON, JSON of another schema -- is `None`. "Something answered on the
    port" is never read as "this runtime is healthy". `/api/runtime` is
    allowlisted by the session gate, so the probe needs no bearer.
    """
    connection = _loopback_connection(port, timeout)
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


def request_reopen(port: int, *, timeout: float = PROBE_TIMEOUT_S) -> int | None:
    """Ask the runtime on `port` to open a fresh page. Returns the HTTP status,
    or None if it could not be reached. A non-browser caller (the second
    launcher) sends no Origin and no Sec-Fetch-Site, which the gate permits for
    reopen; the caller never receives the token."""
    connection = _loopback_connection(port, timeout)
    try:
        connection.request("POST", RUNTIME_REOPEN_ROUTE, body=b"{}",
                           headers={"content-type": "application/json"})
        response = connection.getresponse()
        response.read(4096)
        return response.status
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


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
    session: Any = None,
    open_browser: Callable[[str], None] | None = None,
    url: str | None = None,
    clock: Callable[[], float] = time.monotonic,
    browser_granted: bool = True,
) -> None:
    """`/api/runtime` says which runtime this is; `/api/runtime/stop` ends it;
    `/api/runtime/reopen` opens a fresh page for a launcher or Reconnect --
    unless `browser_granted` is False (a `--no-browser` run), in which case
    it refuses 409 before the rate limit: browser authority was never
    granted to this run, and no caller may grant it by request. When the
    owner's browser adapter raises, reopen is 503 with a fixed body.

    All three are operational. None reads or writes the capsule store, and none
    appears in any lifecycle, eligibility or governance answer. `/api/runtime`
    and `/api/runtime/reopen` are allowlisted by the session gate; `/stop`
    requires the bearer like every authority-moving route. The reopen route is
    wired only when a `session`, an `open_browser` and a `url` are given (the
    real composition); a stand-in surface without a session gets no reopen
    route, and the join path falls back to opening the page directly.
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

    if session is not None and open_browser is not None and url is not None:
        reopen_lock = threading.Lock()
        last_reopen: dict[str, float | None] = {"at": None}

        @application.post(RUNTIME_REOPEN_ROUTE)
        def reopen():
            if not browser_granted:
                return JSONResponse(status_code=409, content=dict(REOPEN_NOT_GRANTED))
            now = clock()
            with reopen_lock:
                previous = last_reopen["at"]
                # The module constant directly. This was a `reopen_interval`
                # keyword no caller ever passed -- a seam whose only effect
                # was to make the rate limit look configurable while the
                # queue depth it sizes stayed a constant (round-4
                # architecture F-P4-1). The two are pinned together by
                # `test_the_reopen_queue_bound_is_what_the_rate_limit_admits_in_one_ttl`.
                if previous is not None and now - previous < REOPEN_INTERVAL_S:
                    return JSONResponse(status_code=429, content=dict(REOPEN_BUSY))
                last_reopen["at"] = now
            # The nonce goes into the URL fragment, which is never sent to a
            # server and never logged. It is a REOPEN slot nonce: minting it
            # JOINS the reopen queue -- it replaces neither the launch nonce
            # the person's first page may still be about to redeem nor a
            # reopen nonce the person's own Reconnect minted a moment ago
            # (a single reopen slot let any local caller kill that one; the
            # queue's depth is what this route's rate limit admits within one
            # TTL, so under the limit nothing unexpired is evicted). The token
            # is never exposed here: only a browser opens, on this process's
            # own URL, and the body says exactly that and nothing else.
            nonce = session.mint(REOPEN_SLOT)
            target = url + "#" + nonce
            try:
                open_browser(target)
            except Exception as exc:  # noqa: BLE001 - every failure shape is scrubbed here
                # ANY exception class. The adapter's own ValueError, the
                # OSError os.startfile raises and a handler's own class can
                # each embed the target, fragment included; one that escaped
                # this branch would carry it into a traceback. Non-200 with a
                # fixed body, so a joining launcher can tell the person.
                # `_said`, not `str`: a `__str__` that raises must not throw
                # from inside this except.
                _log.warning("browser not reopened on %s: %s", url, _scrubbed(_said(exc), nonce, target))
                return JSONResponse(status_code=503, content=dict(REOPEN_FAILED))
            _log.info("reopened on %s", url)
            return {"reopening": True}


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
        with (runtime_dir / "launch-failures.log").open("a", encoding="utf-8", newline="") as trail:
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
    parser.add_argument("--session-file", default=None,
                        help="Smoke/test only: an EXPLICIT absolute path, in an existing "
                             "directory outside the project, the seal directory, the runtime "
                             "directory and the user profile, to write this run's bearer "
                             "token to after readiness and remove at stop; the shipped "
                             "launchers never pass it, and its default is None")
    parser.add_argument("--readiness-timeout", type=float, default=READINESS_TIMEOUT_S,
                        help="Seconds the server may take to answer its own probe")
    return parser


def _session_file_refusal(path: Path, runtime_dir: Path, project: Path, *,
                          resolve: Callable[[Path], Path] = Path.resolve) -> str | None:
    r"""Why an explicit `--session-file` path is refused, or None if it may be used.

    The flag is reachable through `Forge.cmd %*` (A-027), and review measured
    it writing the bearer inside `<project>/capsule/`, the provider's own
    workspace. The same fence as `--runtime-dir`, plus the user profile: the
    measured `CodexSandboxUsers` ACEs read the profile, the seal directory and
    the runtime directory, so a secret on any of them is a secret the provider
    can read. It must be absolute and land in an EXISTING directory: the
    runtime creates no directory for a secret. Decided before anything is
    created, so a refused path is a path nothing was written to.

    Every root is resolved HERE, whatever the caller did with it. The fence
    compares resolved paths, and a root left unresolved (`..` inside it, a
    short 8.3 spelling) is not among the candidate's resolved parents, so a
    file inside it would pass; the fence must not depend on `launch` having
    resolved `runtime_dir` first (second review, P4-1).

    The candidate's SPELLING is judged before it is resolved. A Windows
    namespace prefix or a UNC share survives resolution and keeps the plain
    roots out of the candidate's parents, so a path inside the profile spelled
    `\\?\C:\Users\...` or `\\localhost\C$\Users\...` was admitted (third
    review, P2-1, measured end to end). Both are refused by name, first, on
    both platforms; and a resolution that nonetheless yields a prefixed path
    is refused after, so nothing prefixed ever reaches the comparison. What
    remains is compared as Windows itself compares it: an 8.3 short name
    resolves to its long form and a trailing dot or space stays in the string,
    so each lands inside the root it lives under (measured on this host).

    `resolve` is the CANDIDATE's resolution, a seam whose default is the real
    `Path.resolve`; the roots are Forge's own and are always resolved for
    real. It exists because the post-resolution refusal below had NO witness:
    on this host no plain spelling resolves to a doubled-separator path, so
    deleting that branch left all 76 tests of this module green (round-4 test
    P2) while the paragraph above claimed the spelling is judged "again
    after". A junction chain or a mapped/substituted drive that resolves to a
    UNC target is the real thing this models; the seam lets a test present
    that resolution on any host, on both platforms, without administrator
    rights. A caller other than `launch` and the tests passes nothing.

    An embedded NUL is refused FIRST, by name, before any of the above
    (`_embedded_nul` says why: what `resolve` does with one is version-
    dependent, and on 3.13 it answers with the unresolved path, which put the
    root comparison below on a spelling). Unreachable from a real Windows
    command line -- `CreateProcess` carries no NUL in an argument -- and
    refused anyway, with a FIXED notice that echoes no path: the candidate is
    the caller's text and this branch does not repeat it (round-4 security
    4.2, round-5 CI). The `except ValueError` below stays behind it.
    """
    if _embedded_nul(path):
        return ("the session file path cannot be resolved: it contains an embedded "
                "null character; give a plain local drive path")
    if _double_separator(path):
        return (f"the session file path {path} begins with a double separator -- a UNC share "
                "or a Windows namespace prefix such as \\\\?\\ or \\\\.\\ -- which the fence does "
                "not compare against its roots; give a plain local drive path")
    if not path.is_absolute():
        return "the session file path must be absolute"
    try:
        resolved = resolve(path)
    except ValueError as exc:
        # BELT AND BRACES behind `_embedded_nul` above, for a resolution that
        # refuses in some way this fence did not anticipate. `_said`, not
        # `str`: an exception whose `__str__` raises must not throw out of the
        # branch that is turning a refusal into a notice (round-5 security
        # P4). The path is not echoed, for the same reason as the NUL branch.
        return (f"the session file path cannot be resolved: {_said(exc)}; "
                "give a plain local drive path")
    if _double_separator(resolved):
        return (f"the session file {path} resolved to {resolved}, a UNC or extended-length "
                "path the fence does not compare against its roots; give a plain local drive path")
    # The fenced roots first, most specific first, so the refusal names the
    # root rather than a directory that happens not to exist yet (the runtime
    # directory is created only after every fence has passed).
    fences = [(runtime_dir.resolve(), "the runtime directory"),
              (DEFAULT_SEAL_DIR.resolve(), "the seal directory"),
              (Path.home().resolve(), "the user profile")]
    if project.is_absolute():
        fences.insert(0, (project.resolve(), "the project directory"))
    for fenced, name in fences:
        if resolved == fenced or fenced in resolved.parents:
            return (f"the session file {resolved} is inside {name} {fenced}; a secret lives "
                    "outside every project, outside the seals, outside the runtime directory "
                    "and outside the user profile")
    if resolved.is_dir():
        return f"the session file {resolved} is a directory"
    if not resolved.parent.is_dir():
        return (f"the session file {resolved} must land in an existing directory; "
                "Forge creates none for a secret")
    return None


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
                # Ask the OWNING process to open a fresh page with a new nonce,
                # rather than opening the URL here: this process has no session,
                # so a page it opened directly would show the no-session state.
                status = request_reopen(record["port"])
                if status == 200:
                    return 0
                if status in _REOPEN_NOTICES:
                    # The owner refused (rate-limited, or started without a
                    # browser) or could not open one (503), and the person is
                    # told so, with the page to open by hand: this launch
                    # found Forge running, which is not a failure, but
                    # silence here was (measured under review: a provider
                    # calling reopen every ~9 s kept the join path returning
                    # 0 with no page and no notice; and an owner whose
                    # adapter raised answered 200, read here as success).
                    notify("Forge is running", _REOPEN_NOTICES[status].format(url=url))
                    return 0
                # The running instance exposes no reopen route (a stand-in or an
                # older surface): open its page directly. Reached with no nonce
                # it shows the no-session state and its Reconnect button. The
                # URL opened here carries no fragment, so the exception text
                # can name no secret; caught whatever its class, so no class
                # becomes a traceback.
                try:
                    open_browser(url)
                except Exception as exc:  # noqa: BLE001 - told, never a traceback
                    notify("Forge is running", f"Open {url} in your browser. ({_said(exc)})")
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
    resolve: Callable[[Path], Path] = Path.resolve,
) -> int:
    """One launch, start to finish. Returns the process exit code.

    Every keyword is a composition-time seam with the real thing as its
    default; `main` passes none of them, and a test pins that.

    `resolve` resolves the two CALLER-supplied candidates -- the runtime
    directory here and the session file in `_session_file_refusal` -- and
    nothing else; the fenced roots below (the seal directory and the
    candidate project) are Forge's own and are always resolved for real.

    That last clause was a sentence with no witness: routing both roots
    through the seam as well left all 87 tests of this module green (round-6
    test T-P3-3, the `launch` half of the finding `_session_file_refusal`
    closed in round 5).
    `test_launch_resolves_its_fenced_roots_for_real_and_never_through_the_seam`
    is the witness -- the seam is called exactly once and with the runtime
    directory, and a runtime directory inside the project is still refused BY
    THE PROJECT, which it could not be if a caller's resolver had aliased
    that root to somewhere containing nothing.

    The seam's reason is the same as the one that function gives: the refusal
    that reads the resolution, rather than the spelling, had no witness on a
    host where no plain path resolves to a prefixed one.
    """
    arguments = _parser().parse_args(argv)
    runtime_dir = Path(arguments.runtime_dir)
    candidate_project = Path(arguments.project_dir)
    # AN EMBEDDED NUL FIRST, before every other check on every operand, for
    # the reason `_embedded_nul` gives: what `resolve` does with one is the
    # interpreter's business (<= 3.12 raises out of a trailing stat, 3.13
    # answers with the path unchanged), and a fence must not let the version
    # decide which refusal a caller sees -- nor compare an unresolved
    # spelling against a resolved root. THREE of this launch's four
    # caller-supplied paths are here; the fourth, `--session-file`, is fenced
    # the same way and equally first inside `_session_file_refusal`. Two of
    # these three reached code that catches nothing: the PROJECT's `resolve()`
    # below, in the fence list, sits outside every `try`, and
    # `verify_launched_bundle` resolves the BUNDLE folder outside every `try`
    # too -- and it is called only after `runtime_dir.mkdir()`, so that
    # refusal had already created the runtime directory (round-6 security
    # S-1). Refusing here puts both before anything is created. Fixed text,
    # no path echoed.
    for candidate, described in ((Path(arguments.bundle_root), "the bundle folder"),
                                 (runtime_dir, "the runtime directory"),
                                 (candidate_project, "the project directory")):
        if _embedded_nul(candidate):
            notify("Forge could not start",
                   f"{described} path cannot be resolved: it contains an embedded "
                   "null character; give a plain absolute path")
            return 2
    # SPELLING BEFORE RESOLUTION, for both fenced operands. A `\\?\` or `\\.\`
    # prefix survives `resolve()` and keeps the plain roots out of the
    # candidate's parents, so `--runtime-dir \\?\<seals>\x` was admitted
    # (third review, P2-1: the same class as the session-file bypass, and
    # pre-existing). A prefixed PROJECT is the same hole from the other side:
    # it would make the project fence root a spelling no plain runtime
    # directory can be under. Both are refused by name; neither creates
    # anything. A UNC runtime directory is NOT refused here -- a profile on a
    # share is a legitimate configuration this launch has not measured -- so
    # a UNC alias of a fenced root is a disclosed residual of this fence
    # (A-027), where the session-file fence refuses UNC outright.
    if _namespace_prefixed(runtime_dir):
        notify("Forge could not start",
               f"the runtime directory {runtime_dir} uses a Windows namespace prefix "
               "(\\\\?\\ or \\\\.\\), which the fence does not compare; give a plain absolute path")
        return 2
    if _namespace_prefixed(candidate_project):
        notify("Forge could not start",
               f"the project directory {candidate_project} uses a Windows namespace prefix "
               "(\\\\?\\ or \\\\.\\), which the fence does not compare; give a plain absolute path")
        return 2
    if not runtime_dir.is_absolute():
        notify("Forge could not start", "the runtime directory must be absolute")
        return 2
    try:
        runtime_dir = resolve(runtime_dir)
    except ValueError as exc:
        # BELT AND BRACES behind the `_embedded_nul` loop above, which is now
        # the NUL's guard: this is here for a resolution that refuses in some
        # way this fence did not anticipate, and it answers with the fixed
        # notice rather than a traceback (round-4 security 4.2, the same shape
        # `_session_file_refusal` keeps for its own candidate). `_said`, not
        # `str`, and no path echoed, for the reasons given there.
        notify("Forge could not start",
               f"the runtime directory path cannot be resolved: {_said(exc)}")
        return 2
    if _namespace_prefixed(runtime_dir):
        notify("Forge could not start",
               f"the runtime directory resolved to {runtime_dir}, an extended-length path "
               "the fence does not compare; give a shorter plain absolute path")
        return 2
    # THE FENCE FIRST, before anything is created. Operational state stays
    # out of the project -- the build hands that directory to a provider as
    # its workspace and the verifier censuses it -- and out of the seal
    # directory beside it; and a place this launch refuses is a place it
    # writes nothing into, not even the trail (measured under review: the
    # refusal used to create the fenced directory and log inside it).
    fences = [(DEFAULT_SEAL_DIR.resolve(), "the seal directory")]
    if candidate_project.is_absolute():
        fences.append((candidate_project.resolve(), "the project directory"))
    for fenced, name in fences:
        if runtime_dir == fenced or fenced in runtime_dir.parents:
            notify("Forge could not start",
                   f"the runtime directory {runtime_dir} is inside {name} {fenced}; "
                   "operational state lives outside every project and outside the seals")
            return 2
    # THE SESSION-FILE FENCE, the same shape, and also before anything is
    # created (`_session_file_refusal` says why each root is fenced).
    if arguments.session_file is not None:
        refusal = _session_file_refusal(Path(arguments.session_file), runtime_dir,
                                        candidate_project, resolve=resolve)
        if refusal is not None:
            notify("Forge could not start", refusal)
            return 2
        arguments.session_file = str(resolve(Path(arguments.session_file)))
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
        # `_said`, not `str`: an assembly failure whose `__str__` raises must
        # still reach the person as a notice, not as a second traceback out
        # of this handler (round-4 architecture F-P4-3).
        reason = f"the onboarding surface could not be assembled: {_said(exc)}"
        update(status="failed", reason=reason, stopped_at=clock())
        _log.exception("assembly failed")
        notify("Forge could not start", reason)
        sock.close()
        _stop_logging(handler)
        return 2

    # The onboarding surface minted a control-plane session in `create_app`;
    # the runtime reads it to mint the bootstrap nonce it opens the browser
    # with, and to wire the reopen route. A stand-in surface without one gets
    # a plain URL and no reopen route.
    session = getattr(application.state, "session", None)

    session_file_written = False

    def write_session_file() -> None:
        """Only when an explicit `--session-file` was given, and only for a real
        session: the smoke and the runtime tests read the bearer here because
        they drive the surface over a socket and have no browser to redeem a
        nonce. The shipped launchers pass no path, so nothing is written.

        EXCLUSIVE CREATE, and a file already there is a refusal, never an
        overwrite. The previous shape unlinked first and then created
        exclusively, which detected nothing and let a `FileExistsError` from
        a race escape the readiness thread (second review, P4-2). A file that
        exists before this run writes -- a stale one, or one planted ahead of
        the launch -- is left as found and is not this run's to remove; the
        person is told by path; the bearer stays in memory and the runtime
        keeps serving, so a smoke reading the stale file authenticates with a
        dead token and fails visibly. Nothing this branch logs or tells names
        a secret.
        """
        nonlocal session_file_written
        if not arguments.session_file or session is None:
            return
        # The path passed the fence in `launch` and its directory exists;
        # nothing is created here but the file. 0o600 where the OS honours
        # a mode (POSIX); on Windows a mode sets no ACL (A-027), which is
        # why the fence, not the mode, is the protection there.
        path = Path(arguments.session_file)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            _log.warning("session file not written: %s already exists", path)
            notify("Forge is running",
                   f"the session file {path} already exists and was not overwritten; "
                   "this run's bearer was written nowhere")
            return
        except OSError as exc:
            # `_said` for the same reason as the assembly branch above: this
            # runs on the readiness thread, where a raising `__str__` would
            # take the notice with it (round-4 architecture F-P4-3).
            _log.warning("session file not written at %s: %s", path, _said(exc))
            notify("Forge is running",
                   f"the session file {path} could not be created: {_said(exc)}")
            return
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as sink:
            sink.write(json.dumps({"schema": RUNTIME_SESSION_SCHEMA, "instance": token,
                                   "token": session.token}) + "\n")
        session_file_written = True

    def remove_session_file() -> None:
        # Only a file THIS run created is removed: a pre-existing one was
        # refused above and is not this run's to delete.
        if not session_file_written:
            return
        try:
            Path(arguments.session_file).unlink()
        except OSError:
            pass

    # access_log=False: uvicorn's access logger walks to the root logger, which
    # _log_to gives a FileHandler in append mode, so a request PATH would land
    # in <key>.log for good. The bootstrap nonce travels in a URL fragment,
    # never a path, and no route puts a secret in a path -- but the access log
    # is turned off as defence in depth (A-027).
    server = uvicorn.Server(uvicorn.Config(
        application, host=ONBOARDING_HOST, port=port, log_config=None, log_level="info",
        access_log=False,
    ))
    served_identity = {
        "schema": RUNTIME_SCHEMA, "instance": token, "bundle_root": str(identity.root),
        "bundle_mode": identity.mode, "project_dir": str(project), "port": port,
        "pid": os.getpid(), "python": str(identity.interpreter), "started_at": record["started_at"],
    }

    def request_stop() -> None:
        _log.info("stop requested at the surface")
        server.should_exit = True

    attach_runtime_routes(application, identity=served_identity, request_stop=request_stop,
                          session=session, open_browser=open_browser, url=url,
                          browser_granted=not arguments.no_browser)
    # The loopback Host rule is `assemble`'s -- the composition this seam
    # defaults to, pinned -- so it is applied once, there, and inherited here
    # exactly as the console `onboard` path inherits it. Nothing is added
    # twice and no launcher has to remember it.
    outcome: dict[str, Any] = {"code": 0, "notice": None}

    def await_readiness() -> None:
        deadline = time.monotonic() + arguments.readiness_timeout
        while time.monotonic() < deadline:
            answered = probe_instance(port, timeout=1.0)
            if answered is not None and answered.get("instance") == token:
                update(status="ready", ready_at=clock())
                _log.info("ready: %s answered with its own instance token", url)
                write_session_file()
                if arguments.no_browser:
                    return
                # The nonce rides the URL fragment, which is never sent to the
                # server; the log lines below name the URL WITHOUT it, so no
                # secret reaches <key>.log. On failure, the record, the log
                # and the notice are composed from the fragmentless URL and
                # the exception text is SCRUBBED of the target and the nonce:
                # every exception source (the adapter's own refusal, the
                # OSError.filename os.startfile raises, a handler's own class)
                # embeds the URL it was given, fragment included, and the
                # record and the log live where CodexSandboxUsers can read
                # (measured under review). Caught whatever its class: a type
                # this branch did not name would carry the target out of the
                # thread into a traceback (second review, P4-3).
                nonce = session.mint(LAUNCH_SLOT) if session is not None else None
                target = url if nonce is None else url + "#" + nonce
                try:
                    open_browser(target)
                except Exception as exc:  # noqa: BLE001 - every failure shape is scrubbed here
                    problem = _scrubbed(_said(exc), nonce, target)
                    update(browser={**record["browser"], "opened": False,
                                    "error": problem, "at": clock()})
                    _log.warning("browser not opened on %s: %s", url, problem)
                    notify("Forge is running", f"Open {url} in your browser. ({problem})")
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
        remove_session_file()
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
