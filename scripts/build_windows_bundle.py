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
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

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


def _get(port: int, path: str, timeout: float = 5.0) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _post_json(port: int, path: str, payload: dict, timeout: float = 5.0) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        body = json.dumps(payload).encode("utf-8")
        connection.request("POST", path, body=body,
                           headers={"content-type": "application/json"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def smoke_bundle(dist: Path, *, timeout: float = 180.0) -> dict:
    """Run the built folder's OWN launcher and record what happened.

    This is the operator's real-runtime evidence, measured rather than
    observed by eye: `Forge.cmd` is invoked exactly as a double-click would
    invoke it (plus `--no-browser`, a scratch project and a scratch runtime
    directory so the operator's own project and records are untouched), the
    runtime record is polled until it says ready, the operational and
    onboarding routes are read, the runtime is stopped through its own route,
    and every step is reported. Nothing here is a verdict about governance.
    """
    import tempfile  # noqa: PLC0415

    scratch = Path(tempfile.mkdtemp(prefix="forge-bundle-smoke-"))
    project = scratch / "project"
    runtime_dir = scratch / "runtime"
    report: dict = {"schema": "nornyx.forge.windows_bundle_smoke.v1", "dist": str(dist),
                    "launcher": "Forge.cmd", "steps": []}

    def step(name: str, **facts) -> None:
        report["steps"].append({"step": name, **facts})

    # A scratch profile for the child: the scratch project's seal and any
    # failure trail land under it, not in the operator's own `~/.nornyx`.
    profile = scratch / "profile"
    profile.mkdir()
    environment = {**os.environ, "USERPROFILE": str(profile), "HOME": str(profile)}
    completed = subprocess.run(
        ["cmd.exe", "/c", str(dist / "Forge.cmd"), "--project-dir", str(project),
         "--runtime-dir", str(runtime_dir), "--port", "0", "--no-browser"],
        capture_output=True, text=True, timeout=120, cwd=str(scratch), env=environment,
    )
    step("launcher", returncode=completed.returncode, stdout=completed.stdout[-500:],
         stderr=completed.stderr[-500:])
    record = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = list(runtime_dir.glob("*.json")) if runtime_dir.exists() else []
        if candidates:
            try:
                record = json.loads(candidates[0].read_text(encoding="utf-8"))
            except ValueError:
                record = None
            if record and record.get("status") in ("ready", "failed", "stopped"):
                break
        time.sleep(0.5)
    step("runtime_record", record=record)
    if not record or record.get("status") != "ready":
        report["result"] = "not ready"
        shutil.rmtree(scratch, ignore_errors=True)
        return report
    port = record["port"]
    for path in ("/api/runtime", "/api/state", "/"):
        status, body = _get(port, path)
        step("get", path=path, status=status, bytes=len(body),
             runtime_instance_matches=(
                 json.loads(body).get("instance") == record["instance"]
                 if path == "/api/runtime" else None))
    status, body = _post_json(port, "/api/runtime/stop",
                              {"actor": {"kind": "human", "ident": "bundle-smoke"}})
    step("stop", status=status, body=body[:200].decode("utf-8", "replace"))
    stopped = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = json.loads(next(iter(runtime_dir.glob("*.json"))).read_text(encoding="utf-8"))
        if current.get("status") == "stopped":
            stopped = current
            break
        time.sleep(0.5)
    step("stopped", record=stopped)
    report["result"] = "pass" if stopped is not None else "did not stop"
    shutil.rmtree(scratch, ignore_errors=True)
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
        if report.get("result") != "pass":
            raise BundleError(f"the bundle smoke did not pass: {report.get('result')}")


if __name__ == "__main__":
    main()
