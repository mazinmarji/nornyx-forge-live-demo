"""Build the Windows bundle: the container's install pattern, in a folder.

THE PACKAGING DIRECTION IS THE REPOSITORY'S OWN. `resolve_packaged_root`
pins the deployment assumption -- the package sits at `<root>/src/...`
with the governance tree beside it, exactly what the Dockerfile builds --
and refuses any layout that breaks it. A frozen-executable bundle would
move `__file__` into a private archive and be refused by design. So the
Windows bundle IS the incumbent layout: the same tree the Dockerfile
copies, a private dependency library, and an embedded CPython whose path
file puts `src` FIRST -- source shadows any installed copy, the same
order the development environment proves daily.

The bundle layout:

    <dist>/
      pyproject.toml README.md BRD.md     (the Dockerfile's copy set)
      src/                                (imported directly, shadows pylib)
      .nornyx/                            (contracts and evidence)
      pylib/                              (dependency closure, project pruned)
      python/                             (embedded CPython, when supplied)
      forge-bundle.json                   (which KIND of bundle this is)
      Forge.cmd                           (the person's entry point)

TWO KINDS OF BUNDLE, never confused. A SELF-CONTAINED bundle carries an
interpreter the operator supplied as a zip WITH its expected sha256 -- this
script verifies the digest before extracting and refuses a mismatch, and it
never downloads anything itself. Its launcher runs `python\\pythonw.exe` and
nothing else: no fallback to a system Python, because a folder represented
as self-contained that quietly ran on something else would be a different
runtime under the same name. A DEVELOPER bundle carries no interpreter;
its launcher says so, runs on an installed Python through the `py` launcher
in isolated mode, and puts the bundle's own `src` and `pylib` first on the
import path so nothing installed elsewhere shadows the shipped code. The
marker records the kind, and the runtime refuses a self-contained bundle
started on a foreign interpreter.

The launcher passes its own directory as the bundle root and the person's
profile project directory explicitly; the launch directory selects nothing.

THE SMOKE VERDICT. `--smoke` runs the built folder's own launcher and records
every observation the smoke contract names; `result` is then DERIVED from
those recorded observations by `evaluate_smoke_observations` and has no
other source. The independent PR-18 review found (N1) that `pass` had meant
only "a stopped record exists": the endpoint statuses, the instance-token
comparison and the stop outcome were recorded and never judged. The smoke
measures whether the built runtime starts, answers as itself, serves its
page and state, and stops on request. It is operator evidence about a
bundle; it is never governance evidence about approval, READY, provider
eligibility or model safety, and it decides nothing about any project.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]

#: The copy set, and nothing else. A test compares this against the
#: Dockerfile's COPY sources so the two deployment surfaces cannot drift
#: apart silently.
BUNDLE_TREE = ("pyproject.toml", "README.md", "src", ".nornyx", "BRD.md")

#: Never carried into a bundle: developer state, caches, local machinery.
EXCLUDED_NAMES = {"__pycache__", ".venv", ".git", "node_modules"}

#: The interpreter path file, in resolution order. `..\\src` before
#: `..\\pylib` is load-bearing: the shipped source must shadow any copy of
#: the project that dependency installation dragged into the library. No
#: `import site` line: the embedded interpreter sees exactly these entries
#: and nothing installed anywhere else on the machine.
PTH_LINES = ("python313.zip", ".", "..\\src", "..\\pylib")

#: The marker at the bundle root. The runtime reads its `mode` and nothing
#: else decides how the folder may be run.
BUNDLE_MARKER = "forge-bundle.json"
BUNDLE_SCHEMA = "nornyx.forge.windows_bundle.v1"
SELF_CONTAINED = "self_contained"
DEVELOPER = "developer"

#: The interpreter files the embeddable distribution ships and the launcher
#: needs. `pythonw.exe` is the one the person's double-click runs: no
#: console window, which is what makes failure need a message box.
EMBED_EXECUTABLES = ("python.exe", "pythonw.exe")

#: The person's project: under their Windows profile, passed explicitly.
PROJECT_ARGUMENT = '--project-dir "%USERPROFILE%\\ForgeProject"'

#: cmd.exe looks for a command in the CURRENT DIRECTORY before PATH unless
#: this variable is set. A hostile folder the person happened to launch from
#: could otherwise supply `pyw.cmd` or `timeout.cmd` (measured under review:
#: a `pyw.cmd` in the working directory ran in place of the Python launcher).
#: Set first, so every command the launchers run resolves the same way.
NO_CWD_SEARCH = "set NoDefaultCurrentDirectoryInExePath=1"

SELF_CONTAINED_LAUNCHER = """@echo off
""" + NO_CWD_SEARCH + """
rem Forge (self-contained bundle): start the local runtime, then the browser.
rem The bundle root is this file's own folder (%~dp0), passed explicitly; the
rem project directory is passed explicitly; the launch directory selects
rem nothing. This bundle carries its interpreter and runs on nothing else:
rem there is NO fallback to a Python installed on this computer.
if not exist "%~dp0python\\pythonw.exe" (
  echo Forge: this folder is not a complete self-contained bundle.
  echo python\\pythonw.exe is missing. Nothing else is substituted for it.
  timeout /t 60
  exit /b 2
)
start "" "%~dp0python\\pythonw.exe" -m nornyx_forge.windows_launch --bundle-root "%~dp0." """ + PROJECT_ARGUMENT + """ %*
"""

#: The developer bundle's bootstrap: the bundle's own code first, under an
#: isolated interpreter, so PATH, PYTHONPATH and user site select nothing.
#: One template, shared with the tests that run it on a real process.
DEVELOPER_BOOTSTRAP = (
    "import sys; sys.path[:0] = [r'{src}', r'{pylib}']; "
    "from nornyx_forge.windows_launch import main; main()"
)

DEVELOPER_LAUNCHER = """@echo off
""" + NO_CWD_SEARCH + """
rem Forge (DEVELOPER bundle): this folder carries NO interpreter. It runs on a
rem Python 3.10-3.13 already installed on this computer, found through the
rem Windows py launcher, in isolated mode (-I) with the bundle's own src and
rem pylib placed first on the import path -- nothing installed elsewhere can
rem shadow the shipped code. A self-contained bundle is a different folder.
where pyw >nul 2>nul
if errorlevel 1 (
  echo Forge developer bundle: the Python launcher ^(pyw.exe^) was not found.
  echo A developer bundle runs on an installed Python; a self-contained bundle carries its own.
  timeout /t 60
  exit /b 2
)
start "" pyw -3 -I -c \"""" + DEVELOPER_BOOTSTRAP.format(src="%~dp0src", pylib="%~dp0pylib") + """\" --bundle-root "%~dp0." """ + PROJECT_ARGUMENT + """ %*
"""

LAUNCHERS = {SELF_CONTAINED: SELF_CONTAINED_LAUNCHER, DEVELOPER: DEVELOPER_LAUNCHER}


class BundleError(Exception):
    """A build input or state this script refuses."""


def bundle_manifest() -> tuple[str, ...]:
    """What the bundle carries: the Dockerfile's copy set, verbatim."""
    return BUNDLE_TREE


def _copy_filter(directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in EXCLUDED_NAMES}


def copy_tree(repo_root: Path, dist: Path) -> None:
    if dist.exists() and any(dist.iterdir()):
        raise BundleError(
            f"{dist} already contains files; a bundle is built fresh, never "
            "layered over an old one"
        )
    dist.mkdir(parents=True, exist_ok=True)
    for entry in bundle_manifest():
        source = repo_root / entry
        target = dist / entry
        if source.is_dir():
            shutil.copytree(source, target, ignore=_copy_filter)
        else:
            shutil.copy2(source, target)


def _installer_command(python_exe: str) -> list[str]:
    """The installer that actually exists here, probed rather than assumed.

    A uv-managed environment ships no pip module -- measured on this
    repository's own venv, where `python -m pip` answers `No module named
    pip`. The probe asks; the fallback is uv's pip interface pointed at the
    same interpreter; and an environment with neither is refused by name
    instead of failing three layers down.
    """
    probe = subprocess.run(
        [python_exe, "-m", "pip", "--version"],
        capture_output=True, text=True, timeout=60,
    )
    if probe.returncode == 0:
        return [python_exe, "-m", "pip", "install", "--quiet"]
    uv = shutil.which("uv")
    if uv is not None:
        # --native-tls: trust the system certificate store, which is where a
        # Windows machine behind TLS inspection keeps the issuer uv needs.
        return [uv, "pip", "install", "--quiet", "--native-tls",
                "--python", python_exe]
    raise BundleError(
        "no installer is available: the interpreter has no pip module and "
        "uv is not on PATH"
    )


def install_dependencies(dist: Path, python_exe: str) -> None:
    """The dependency closure into pylib, with the project itself pruned.

    Installing `.[demo]` also installs a non-editable copy of this project;
    left in place it would sit on the import path behind `src` -- dormant
    under the pinned path order, but a second copy of the code is a second
    place to read it wrong, so it is removed.
    """
    subprocess.run(
        [*_installer_command(python_exe),
         "--target", str(dist / "pylib"), f"{dist}[demo]"],
        check=True, timeout=1800,
    )
    for own in ("nornyx_forge", "demo_app"):
        installed = dist / "pylib" / own
        if installed.is_dir():
            shutil.rmtree(installed)
    # Building the project sdist from the dist tree leaves a setuptools
    # `build/` directory beside it -- measured on the first real build. It
    # is a build byproduct, not bundle content.
    leftover = dist / "build"
    if leftover.is_dir():
        shutil.rmtree(leftover)


def install_python(dist: Path, embed_zip: Path, expected_sha256: str) -> None:
    """The operator-supplied interpreter, verified before it is extracted.

    The digest is checked over the whole archive first; only a match is
    opened. Then the archive must be the embeddable distribution -- exactly
    one `._pth` file, and both executables the launcher needs -- and its
    path file is rewritten to the pinned resolution order.
    """
    digest = hashlib.sha256(embed_zip.read_bytes()).hexdigest()
    if digest != expected_sha256.lower():
        raise BundleError(
            "the embedded interpreter zip does not match its declared "
            f"sha256: expected {expected_sha256.lower()}, measured {digest}"
        )
    target = dist / "python"
    with zipfile.ZipFile(embed_zip) as archive:
        archive.extractall(target)
    pth_files = list(target.glob("python*._pth"))
    if len(pth_files) != 1:
        raise BundleError(
            f"expected exactly one python*._pth in the embed zip; found "
            f"{len(pth_files)}"
        )
    missing = [name for name in EMBED_EXECUTABLES if not (target / name).is_file()]
    if missing:
        raise BundleError(
            "the embed zip is not the CPython embeddable distribution: it lacks "
            f"{', '.join(missing)}, which the launcher needs"
        )
    zip_name = pth_files[0].name.replace("._pth", ".zip")
    lines = (zip_name, *PTH_LINES[1:])
    pth_files[0].write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")


def _source_commit(repo_root: Path) -> str | None:
    """Informational provenance for a reader of the folder; never authority."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(repo_root),
            capture_output=True, text=True, timeout=60,
        )
    except OSError:
        return None
    return completed.stdout.strip() or None if completed.returncode == 0 else None


def write_bundle_marker(dist: Path, *, mode: str, interpreter_sha256: str | None,
                        source_commit: str | None = None) -> None:
    if mode not in LAUNCHERS:
        raise BundleError(f"unknown bundle mode {mode!r}")
    if (mode == SELF_CONTAINED) != (interpreter_sha256 is not None):
        raise BundleError(
            "a self-contained bundle records its interpreter digest and a "
            "developer bundle records none; the marker cannot say otherwise"
        )
    marker = {
        "schema": BUNDLE_SCHEMA,
        "mode": mode,
        "interpreter": None if interpreter_sha256 is None else {
            "source": "operator-supplied", "sha256": interpreter_sha256.lower(),
        },
        "built_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                    .replace("+00:00", "Z"),
        "source_commit": source_commit,
        "note": (
            "Says which kind of folder this is. Operational: it selects how the "
            "launcher may run, and nothing about any project's governance."
        ),
    }
    (dist / BUNDLE_MARKER).write_text(
        json.dumps(marker, indent=2) + "\n", encoding="utf-8", newline="",
    )


def write_launcher(dist: Path, mode: str = SELF_CONTAINED) -> None:
    try:
        text = LAUNCHERS[mode]
    except KeyError:
        raise BundleError(f"unknown bundle mode {mode!r}") from None
    (dist / "Forge.cmd").write_text(text, encoding="utf-8", newline="")


def verify_bundle(dist: Path) -> None:
    """The bundle proves itself: its own interpreter resolves its own root."""
    python = dist / "python" / "python.exe"
    if not python.exists():
        return  # developer bundle: verified by the system interpreter's tests
    completed = subprocess.run(
        [str(python), "-c",
         "import nornyx_forge.cli, nornyx_forge.windows_launch, "
         "nornyx_forge.windows_runtime, demo_app.main; "
         "from nornyx_forge.subject_bootstrap import resolve_packaged_root; "
         "print(resolve_packaged_root())"],
        capture_output=True, text=True, timeout=300,
    )
    if completed.returncode != 0:
        raise BundleError(
            f"the built bundle cannot resolve itself:\n{completed.stderr}"
        )
    resolved = Path(completed.stdout.strip()).resolve()
    if resolved != dist.resolve():
        raise BundleError(
            f"the built bundle's interpreter resolves {resolved}, not {dist.resolve()}: "
            "the code it would run is not the code in the folder"
        )


# ---------------------------------------------------------------------------
# The smoke: the built folder's own launcher, observed; a verdict derived from
# the observations and from nothing else
# ---------------------------------------------------------------------------

#: The smoke report's schema. v2: `result` is derived from the recorded
#: observations by `evaluate_smoke_observations`. Under v1 it said `pass`
#: whenever a stopped record existed (finding N1 of the independent PR-18
#: review) while the statuses and the token comparison were recorded and
#: never judged; a reader of a v1 report must not read its `pass` as this one.
SMOKE_SCHEMA = "nornyx.forge.windows_bundle_smoke.v2"
#: The runtime record's schema, restated from `nornyx_forge.windows_runtime`
#: and pinned equal to it by test, so that this script imports nothing from
#: the package whose bundle it measures.
RUNTIME_SCHEMA = "nornyx.forge.windows_runtime.v1"
#: The actor the smoke stops the runtime as: a person, by the route's contract.
SMOKE_ACTOR = {"kind": "human", "ident": "bundle-smoke"}
#: How much of a response body is read. Enough for the page; a listener that
#: sends more is not this runtime and is not read further.
RESPONSE_LIMIT = 1 << 20
#: A recorded response string is cut here, and a launcher's output there: the
#: report explains a failure; it does not archive bodies.
FACT_LIMIT = 200
OUTPUT_LIMIT = 500

#: THE SMOKE CONTRACT: every observation a `pass` requires, in the order the
#: smoke makes them. Each name is judged by exactly one predicate in
#: `_SMOKE_CHECKS` over the facts the report records for that step. An
#: observation that is absent, duplicated or failed is a named failure, and
#: only the conjunction of all seven is a pass.
SMOKE_REQUIRED = ("launcher", "runtime_record", "get /api/runtime", "get /api/state",
                  "get /", "stop", "stopped")


class _Budget:
    """One time budget for a whole exchange -- status line, headers and body
    alike -- enforced by a watchdog that shuts the socket down when the
    budget ends.

    A socket timeout bounds each RECEIVE, not the response, and `read` loops
    receives internally until its amount or EOF: measured under inspection,
    a listener trickling one byte per receive under a long Content-Length
    held the smoke open for the body's length with a per-receive timeout
    and again with a deadline checked between reads. The watchdog is the
    bound that does not depend on how the reader loops.

    THE BOUND, MEASURED (round 3 of the security inspection, Windows): the
    shutdown does not itself wake a receive already pending; the exchange
    then ends at the next inbound byte or at that receive's own socket
    timeout. So an exchange ends within `timeout` for the budget plus at
    most one receive timeout -- twice `timeout`, at most 40 s across the
    smoke's four exchanges with the 5 s default -- never at the trickle's
    pace. `connect()` runs before the budget exists and is bounded by the
    socket timeout alone.
    """

    def __init__(self, sock: socket.socket, seconds: float) -> None:
        self.expired = False
        self._sock = sock
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        self.expired = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def cancel(self) -> None:
        self._timer.cancel()


def _exchange(port: int, method: str, path: str, *, body: bytes | None = None,
              headers: dict[str, str] | None = None,
              timeout: float = 5.0) -> tuple[int, bytes, str]:
    """One request on the loopback port under one time budget (`_Budget`).
    The body is read up to RESPONSE_LIMIT; a body shorter than the length it
    declared, as far as it is read, is a broken answer, not the answer. An
    exchange the budget ended is reported as a TimeoutError, an OSError the
    caller records."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    connection.connect()
    budget = _Budget(connection.sock, timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        # http.client's own parse of Content-Length, taken before the read
        # (the read counts it down): None when absent, chunked, or not a
        # number it accepts. The header is not parsed here a second time --
        # measured under inspection, a parse of our own raised on a one-byte
        # latin-1 value and on a 5000-digit one.
        declared = response.length
        data = response.read(RESPONSE_LIMIT)
        content_type = response.getheader("content-type", "") or ""
        if declared is not None and len(data) < min(declared, RESPONSE_LIMIT):
            # A listener that closes early delivers a short body with no
            # IncompleteRead (measured under inspection). Short of what it
            # declared, as far as it is read, the body is not the answer.
            raise http.client.IncompleteRead(data, declared - len(data))
    except (OSError, http.client.HTTPException) as error:
        if budget.expired:
            raise TimeoutError(
                "the exchange did not complete within the smoke's time budget") from error
        raise
    finally:
        budget.cancel()
        connection.close()
    if budget.expired:
        raise TimeoutError("the exchange did not complete within the smoke's time budget")
    return response.status, data, content_type


def _get(port: int, path: str, timeout: float = 5.0) -> tuple[int, bytes, str]:
    return _exchange(port, "GET", path, timeout=timeout)


def _post_json(port: int, path: str, payload: dict, timeout: float = 5.0) -> tuple[int, bytes]:
    status, data, _ = _exchange(port, "POST", path, body=json.dumps(payload).encode("utf-8"),
                                headers={"content-type": "application/json"}, timeout=timeout)
    return status, data


def _fact(value: Any) -> Any:
    """A response value as the report records it: scalars kept, strings cut,
    anything else named by type. The report explains; it does not archive."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= FACT_LIMIT else value[:FACT_LIMIT] + "..."
    return type(value).__name__


#: The runtime record as the report keeps it: the four fields the verdict
#: reads, plus `reason` so a failed record explains itself, each bounded by
#: `_fact`. The record is the child's own file, not a listener's body, but
#: the report explains it rather than archiving it.
RECORD_FACTS = ("schema", "instance", "status", "port", "reason")


def _record_facts(record: Any) -> Any:
    if not isinstance(record, dict):
        return _fact(record)
    return {key: _fact(record.get(key)) for key in RECORD_FACTS if key in record}


def _parse_object(body: bytes) -> tuple[dict | None, str]:
    """(payload, outcome): the JSON object a body carries, or why it is none.
    A body nested deeper than the interpreter decodes raises RecursionError,
    which is not a ValueError (measured under review): it is invalid too."""
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None, "invalid"
    if not isinstance(payload, dict):
        return None, "not an object"
    return payload, "object"


def _read_record(path: Path | None) -> Any:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def _record_shape(record: Any) -> str | None:
    """Why a runtime record cannot be used by the smoke, or None if it can:
    the runtime's schema, a non-empty instance token, and a port."""
    if not isinstance(record, dict):
        return "no runtime record was observed"
    if record.get("schema") != RUNTIME_SCHEMA:
        return f"record schema {_fact(record.get('schema'))!r}, not {RUNTIME_SCHEMA!r}"
    instance = record.get("instance")
    if not isinstance(instance, str) or not instance:
        return "record carries no instance token"
    if len(instance) > FACT_LIMIT:
        # A Forge token is 32 hex characters. Recorded facts are cut at
        # FACT_LIMIT, so a longer token could never be compared whole; it is
        # refused here rather than compared truncated (measured under review).
        return "record instance token is longer than the recorded-fact bound"
    port = record.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return f"record port {_fact(port)!r} is not a port"
    return None


# Each predicate: (the recorded step, the recorded runtime's instance token or
# None) -> why the observation failed, or None if it succeeded.

def _launcher_completed(step: dict, expected: str | None) -> str | None:
    if step.get("timed_out"):
        return "the launcher did not return within its timeout"
    if step.get("returncode") != 0:
        return f"exit code {_fact(step.get('returncode'))!r}, not 0"
    return None


def _record_ready(step: dict, expected: str | None) -> str | None:
    record = step.get("record")
    shape = _record_shape(record)
    if shape is not None:
        return shape
    if record.get("status") != "ready":
        return f"record status {_fact(record.get('status'))!r}, not 'ready'"
    return None


def _http_ok(step: dict) -> str | None:
    if step.get("status") != 200:
        detail = f" ({step['error']})" if step.get("error") else ""
        return f"HTTP {_fact(step.get('status'))!r}, not 200{detail}"
    return None


def _runtime_route(step: dict, expected: str | None) -> str | None:
    if (reason := _http_ok(step)) is not None:
        return reason
    if step.get("json") != "object":
        return f"body is {_fact(step.get('json'))!r}, not a JSON object"
    if step.get("schema") != RUNTIME_SCHEMA:
        return (f"schema {_fact(step.get('schema'))!r}, not {RUNTIME_SCHEMA!r}: "
                "not a Forge runtime answer")
    if expected is None:
        return "no recorded instance token to compare against"
    if step.get("instance") != expected:
        return f"instance {_fact(step.get('instance'))!r} is not the recorded runtime's"
    return None


def _state_route(step: dict, expected: str | None) -> str | None:
    if (reason := _http_ok(step)) is not None:
        return reason
    if step.get("json") != "object":
        return f"body is {_fact(step.get('json'))!r}, not a JSON object"
    if not isinstance(step.get("initialized"), bool):
        return "no boolean 'initialized': not usable as the onboarding state response"
    return None


def _page_route(step: dict, expected: str | None) -> str | None:
    if (reason := _http_ok(step)) is not None:
        return reason
    content_type = step.get("content_type")
    if not isinstance(content_type, str) or not content_type.lower().startswith("text/html"):
        return f"content type {_fact(content_type)!r}, not text/html"
    if not step.get("bytes"):
        return "an empty page"
    return None


def _stop_route(step: dict, expected: str | None) -> str | None:
    if (reason := _http_ok(step)) is not None:
        return reason
    if step.get("json") != "object":
        return f"body is {_fact(step.get('json'))!r}, not a JSON object"
    if step.get("stopping") is not True:
        return f"stopping is {_fact(step.get('stopping'))!r}, not true"
    if expected is None:
        return "no recorded instance token to compare against"
    if step.get("instance") != expected:
        return f"instance {_fact(step.get('instance'))!r} is not the recorded runtime's"
    return None


def _record_stopped(step: dict, expected: str | None) -> str | None:
    record = step.get("record")
    if record is None:
        return "no stopped record within the wait"
    shape = _record_shape(record)
    if shape is not None:
        return shape
    if record.get("status") != "stopped":
        return f"record status {_fact(record.get('status'))!r}, not 'stopped'"
    if expected is None:
        return "no recorded instance token to compare against"
    if record.get("instance") != expected:
        return f"instance {_fact(record.get('instance'))!r} is not the recorded runtime's"
    return None


_SMOKE_CHECKS: dict[str, Callable[[dict, str | None], str | None]] = {
    "launcher": _launcher_completed,
    "runtime_record": _record_ready,
    "get /api/runtime": _runtime_route,
    "get /api/state": _state_route,
    "get /": _page_route,
    "stop": _stop_route,
    "stopped": _record_stopped,
}


def _identity(step: dict) -> str:
    """Which observation a recorded step is: its name, plus the path for a GET."""
    if step.get("step") == "get":
        return f"get {step.get('path')}"
    return str(step.get("step"))


def evaluate_smoke_observations(steps: list[dict]) -> dict:
    """The verdict, derived from the recorded observations and nothing else.

    Every name in `SMOKE_REQUIRED` must be observed exactly once and its
    predicate must hold; the instance token every comparison uses is the one
    the recorded runtime record carries. Returns the rule, the required
    names, the failures (`"<observation>: <reason>"`, in contract order) and
    `result`, which is `pass` only when the failure list is empty.
    """
    observed: dict[str, list[dict]] = {}
    for step in steps:
        observed.setdefault(_identity(step), []).append(step)
    records = observed.get("runtime_record", [])
    expected: str | None = None
    if len(records) == 1 and _record_shape(records[0].get("record")) is None:
        expected = records[0]["record"]["instance"]
    failed: list[str] = []
    for name in SMOKE_REQUIRED:
        candidates = observed.get(name, [])
        if not candidates:
            failed.append(f"{name}: not observed")
        elif len(candidates) > 1:
            failed.append(f"{name}: observed {len(candidates)} times, "
                          "so there is no one observation to judge")
        elif (reason := _SMOKE_CHECKS[name](candidates[0], expected)) is not None:
            failed.append(f"{name}: {reason}")
    return {
        "rule": "pass only when every required observation was made once and succeeded",
        "required": list(SMOKE_REQUIRED),
        "failed": failed,
        "result": "pass" if not failed else "fail",
    }


def _observe_launch(dist: Path, scratch: Path, step: Callable[..., None], *,
                    timeout: float, stop_timeout: float) -> None:
    """Make the smoke's observations in contract order, recording each as it
    is made. Ends early when the runtime never becomes ready: nothing can be
    reached, and the verdict names what was not observed."""
    project = scratch / "project"
    runtime_dir = scratch / "runtime"
    # A scratch profile for the child: the scratch project's seal and any
    # failure trail land under it, not in the operator's own `~/.nornyx`.
    profile = scratch / "profile"
    profile.mkdir()
    environment = {**os.environ, "USERPROFILE": str(profile), "HOME": str(profile)}
    command = ["cmd.exe", "/c", str(dist / "Forge.cmd"), "--project-dir", str(project),
               "--runtime-dir", str(runtime_dir), "--port", "0", "--no-browser"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120,
                                   cwd=str(scratch), env=environment)
    except subprocess.TimeoutExpired as expired:
        step("launcher", returncode=None, timed_out=True,
             stdout=str(expired.stdout or "")[-OUTPUT_LIMIT:],
             stderr=str(expired.stderr or "")[-OUTPUT_LIMIT:])
    else:
        step("launcher", returncode=completed.returncode, timed_out=False,
             stdout=completed.stdout[-OUTPUT_LIMIT:], stderr=completed.stderr[-OUTPUT_LIMIT:])
    record: Any = None
    record_path: Path | None = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = sorted(runtime_dir.glob("*.json")) if runtime_dir.exists() else []
        if candidates:
            record_path = candidates[0]
            record = _read_record(record_path)
            if isinstance(record, dict) and record.get("status") in ("ready", "failed", "stopped"):
                break
        time.sleep(0.5)
    step("runtime_record", record=_record_facts(record))
    if _record_shape(record) is not None or record.get("status") != "ready":
        return  # nothing to reach; the verdict says what was not observed
    port = record["port"]
    for path in ("/api/runtime", "/api/state", "/"):
        try:
            status, body, content_type = _get(port, path)
        except (OSError, http.client.HTTPException) as error:
            step("get", path=path, status=None, error=_fact(f"{type(error).__name__}: {error}"))
            continue
        facts: dict[str, Any] = {"status": status, "bytes": len(body),
                                 "content_type": _fact(content_type)}
        if path != "/":
            payload, facts["json"] = _parse_object(body)
            if path == "/api/runtime" and payload is not None:
                facts["schema"] = _fact(payload.get("schema"))
                facts["instance"] = _fact(payload.get("instance"))
            if path == "/api/state" and payload is not None:
                facts["initialized"] = _fact(payload.get("initialized"))
        step("get", path=path, **facts)
    try:
        status, body = _post_json(port, "/api/runtime/stop", {"actor": SMOKE_ACTOR})
    except (OSError, http.client.HTTPException) as error:
        step("stop", status=None, error=_fact(f"{type(error).__name__}: {error}"))
    else:
        payload, parsed = _parse_object(body)
        step("stop", status=status, json=parsed,
             stopping=_fact(payload.get("stopping")) if payload is not None else None,
             instance=_fact(payload.get("instance")) if payload is not None else None,
             body=_fact(body[:FACT_LIMIT].decode("utf-8", "replace")))
    stopped = None
    deadline = time.monotonic() + stop_timeout
    while time.monotonic() < deadline:
        current = _read_record(record_path)
        if isinstance(current, dict) and current.get("status") == "stopped":
            stopped = current
            break
        time.sleep(0.5)
    step("stopped", record=_record_facts(stopped))


def smoke_bundle(dist: Path, *, timeout: float = 180.0, stop_timeout: float = 60.0) -> dict:
    """Run the built folder's OWN launcher, record what happened, and judge it.

    This is the operator's real-runtime evidence, measured rather than
    observed by eye: `Forge.cmd` is invoked exactly as a double-click would
    invoke it (plus `--no-browser`, a scratch project and a scratch runtime
    directory so the operator's own project and records are untouched), the
    runtime record is polled until it says ready, the operational and
    onboarding routes are read, the runtime is stopped through its own route,
    and every step is reported with the facts that explain it. `result` is
    then DERIVED from those recorded facts by `evaluate_smoke_observations`
    and has no other source: `pass` means every observation the smoke
    contract names succeeded, and a failure names which did not. Nothing
    here is a verdict about governance.
    """
    import tempfile  # noqa: PLC0415

    scratch = Path(tempfile.mkdtemp(prefix="forge-bundle-smoke-"))
    report: dict = {"schema": SMOKE_SCHEMA, "dist": str(dist), "launcher": "Forge.cmd",
                    "steps": []}

    def step(name: str, **facts) -> None:
        report["steps"].append({"step": name, **facts})

    try:
        _observe_launch(dist, scratch, step, timeout=timeout, stop_timeout=stop_timeout)
    finally:
        # Whatever happened -- every observation made, an early end, or a
        # raise -- the scratch does not outlive the smoke (measured under
        # review: a raise mid-observation had left it behind).
        shutil.rmtree(scratch, ignore_errors=True)
    report["verdict"] = evaluate_smoke_observations(report["steps"])
    report["result"] = report["verdict"]["result"]
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist" / "forge-windows")
    parser.add_argument("--python-embed", type=Path, default=None,
                        help="CPython embeddable zip, supplied by the operator")
    parser.add_argument("--python-embed-sha256", default=None,
                        help="Expected sha256 of the embed zip; required with it")
    parser.add_argument("--smoke", action="store_true",
                        help="After building, run the folder's own launcher and report")
    arguments = parser.parse_args(argv)
    if (arguments.python_embed is None) != (arguments.python_embed_sha256 is None):
        raise BundleError(
            "--python-embed and --python-embed-sha256 travel together: an "
            "unverified interpreter is not bundled"
        )
    mode = SELF_CONTAINED if arguments.python_embed is not None else DEVELOPER
    copy_tree(ROOT, arguments.dist)
    install_dependencies(arguments.dist, sys.executable)
    if arguments.python_embed is not None:
        install_python(arguments.dist, arguments.python_embed,
                       arguments.python_embed_sha256)
    write_bundle_marker(
        arguments.dist, mode=mode, interpreter_sha256=arguments.python_embed_sha256,
        source_commit=_source_commit(ROOT),
    )
    write_launcher(arguments.dist, mode)
    verify_bundle(arguments.dist)
    print(f"bundle built: {arguments.dist} ({mode})")
    if arguments.smoke:
        report = smoke_bundle(arguments.dist)
        report_path = arguments.dist.parent / f"{arguments.dist.name}-smoke.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="")
        print(json.dumps(report, indent=2))
        print(f"smoke report: {report_path}")
        if report["result"] != "pass":
            raise BundleError("the bundle smoke did not pass: "
                              + "; ".join(report["verdict"]["failed"]))


if __name__ == "__main__":
    main()
