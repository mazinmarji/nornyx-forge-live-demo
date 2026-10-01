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

THE SELF-CONTAINED BUNDLE IS A DETERMINISTIC PAYLOAD. Built twice from one
commit with the same pinned inputs it is the same bytes, and nothing here
reads the wall clock. Its inputs are the commit; the pins in
`scripts/windows_installer/` (a dependency lock with a hash on every
distribution, resolved for CPython 3.13 on win_amd64; the installer, uv, by
the version it reports; the interpreter archive by URL and SHA-256); and the
host tools that act on them (uv, git, the Python running this script), which
CI's rebuild varies to show they do not reach the bytes. Everything read from
the repository is read from the commit: the copy set, the pins and the lock
come from its blobs, and the build refuses an uncommitted tree and a builder
or verifier file that differs from the commit even where an index flag hides
the change from `git status` (drift detection, not a defence against a
writer of the clone). uv installs the lock for the target platform
with no cache, no configuration file and none of this environment's `UV_*`
variables; the host-specific files it writes are pruned together with their
RECORD rows; every native module is traced to a wheel built for the target;
every path must be one Windows can hold (`check_name`); every time is set to
the commit's; and `forge-payload.json` (`nornyx_forge.windows_payload`)
gives the payload its identity. A DEVELOPER bundle is still installed for
the interpreter running this script, so it is not a deterministic payload
and carries no manifest; like the payload it needs a clean commit, copies the
commit's blobs, and its marker carries no `built_at`.

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
import csv
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from email.parser import HeaderParser
from pathlib import Path
from typing import Any, Callable

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the dev extra installs tomli
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
# The payload manifest is written and checked by ONE implementation, the one
# the installed copy runs: this commit's own, not whichever copy is installed
# (`require_clean_commit` refuses a build that loaded another).
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import nornyx_forge.windows_payload as _payload_module  # noqa: E402
from nornyx_forge.windows_payload import (  # noqa: E402
    ARCHIVE_URL,
    PAYLOAD_MANIFEST,
    PayloadError,
    build_manifest,
    check_names,
    render_manifest,
    verify,
)

#: The pinned inputs of the self-contained payload, as repository paths: the
#: build reads them from the commit, never from the working tree.
INSTALLER_PATH = "scripts/windows_installer"
PINS_PATH = f"{INSTALLER_PATH}/pins.json"
PINS_SCHEMA = "nornyx.forge.windows_build_pins.v1"
#: The code that makes and checks the payload. Each file's raw bytes must
#: equal the commit's blob, which no index flag or clean filter can hide.
BUILDER_FILES = ("scripts/build_windows_bundle.py", "src/nornyx_forge/__init__.py",
                 "src/nornyx_forge/windows_payload.py")

#: What uv writes into a `--target` directory besides the distributions: the
#: entry-point launchers it generates for the BUILD host (`bin`, each naming
#: the interpreter that ran the build), and its own lock file. Neither is
#: Forge's to ship -- the runtime starts with `-m` -- and their RECORD rows
#: are dropped with them.
PYLIB_PRUNED = ("bin", ".lock")

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


def _git_environment() -> dict[str, str]:
    """This environment without git's own variables, and with replace refs
    off. A `GIT_DIR`, `GIT_OBJECT_DIRECTORY` or `GIT_INDEX_FILE` left in the
    environment (git hooks set them) would point every call at another
    repository, and a local `refs/replace/*` would change what a blob reads
    as. `GIT_CEILING_DIRECTORIES` is kept: it can only stop git finding a
    repository, which the build then refuses."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("GIT_") or key == "GIT_CEILING_DIRECTORIES"}
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _git(repo_root: Path, *arguments: str, stdin: bytes | None = None) -> bytes:
    """One git command's standard output, as bytes, in `_git_environment`; a
    failure is refused."""
    completed = subprocess.run(["git", *arguments], cwd=str(repo_root), input=stdin,
                               capture_output=True, timeout=300, env=_git_environment())
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:300]
        raise BundleError(f"git {arguments[0]} failed: {detail}")
    return completed.stdout


def _read_blobs(repo_root: Path, objects: list[bytes]) -> list[bytes]:
    """The raw bytes of each blob, in order, through one `git cat-file
    --batch`: no checkout, no line-ending conversion, no working-tree file."""
    output = _git(repo_root, "cat-file", "--batch", stdin=b"".join(o + b"\n" for o in objects))
    blobs, position = [], 0
    for expected in objects:
        end = output.find(b"\n", position)
        header = output[position:end].split(b" ") if end >= 0 else []
        if len(header) != 3 or header[0] != expected or header[1] != b"blob":
            raise BundleError(f"git cat-file answered {output[position:end][:120]!r} "
                              f"for {expected.decode('ascii')}")
        start, size = end + 1, int(header[2])
        if output[start + size:start + size + 1] != b"\n":
            raise BundleError("git cat-file's answer is truncated")
        blobs.append(output[start:start + size])
        position = start + size + 1
    if position != len(output):
        raise BundleError("git cat-file answered more than was asked")
    return blobs


def _git_blob(repo_root: Path, commit: str, path: str) -> bytes:
    """A committed file's bytes, from the commit itself."""
    return _git(repo_root, "cat-file", "blob", f"{commit}:{path}")


def copy_tree(repo_root: Path, dist: Path, commit: str = "HEAD") -> None:
    """The copy set as COMMITTED (the default is HEAD's, so a caller that
    names no commit copies HEAD's blobs, not its working-tree edits): tracked
    regular files only, from the commit's blobs. A file git ignores -- local
    runtime state, a review record, a disposition -- is not in the commit and
    cannot ride along; a tracked name in `EXCLUDED_NAMES` is left out; a link
    or submodule is refused rather than followed; and every path must be one
    the payload's name rule admits, so nothing is written outside `dist` or
    under a name Windows cannot hold."""
    if dist.exists() and any(dist.iterdir()):
        raise BundleError(
            f"{dist} already contains files; a bundle is built fresh, never "
            "layered over an old one"
        )
    listing = _git(repo_root, "ls-tree", "-r", "-z", "--full-tree", commit, "--",
                   *bundle_manifest())
    paths, objects = [], []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        mode, kind, obj = meta.split(b" ")
        path = raw_path.decode("utf-8", "surrogateescape")
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise BundleError(f"{path!r} is a {mode.decode()} {kind.decode()} entry; the "
                              "bundle copies regular files only")
        if EXCLUDED_NAMES.intersection(path.split("/")):
            continue
        paths.append(path)
        objects.append(obj)
    # The payload's name rule, over every path and every pair, before
    # anything is written: no path leaves `dist` or is one Windows cannot hold.
    if refused := check_names(paths):
        raise BundleError("the copy set holds paths a payload cannot: " + "; ".join(refused[:20]))
    absent = [entry for entry in bundle_manifest()
              if not any(path == entry or path.startswith(entry + "/") for path in paths)]
    if absent:
        raise BundleError(f"the commit carries none of {absent}; it is not this repository")
    dist.mkdir(parents=True, exist_ok=True)
    for path, data in zip(paths, _read_blobs(repo_root, objects)):
        target = dist.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def require_clean_commit(repo_root: Path) -> str:
    """The commit the build is made from. A payload is a function of a commit,
    so a tree that differs from it -- a modified or an untracked file -- is
    refused, and so is a build where git names no commit at all. `git status`
    does not see a change an index flag (skip-worktree, assume-unchanged) or
    a clean filter hides, so the raw bytes of the code that makes and checks
    the payload are also compared with the commit's blobs (line endings
    normalized, so a Windows checkout that converts them still builds), and
    the verifier this process loaded must be the one in this repository.
    This detects drift in the build clone; it is no defence against a writer
    of the clone, who can change this check too. The rebuild from a fresh
    clone (CI's) is what anchors a commit's payload."""
    commit = _source_commit(repo_root)
    if commit is None or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BundleError("git names no commit for this tree; a bundle records the commit "
                          "it was built from, and there is none to record")
    status = _git(repo_root, "status", "--porcelain", "--untracked-files=normal")
    if status.strip():
        raise BundleError(f"the working tree differs from {commit}: commit or remove these "
                          f"first: {status.decode('utf-8', 'replace')[:400]}")
    for name in BUILDER_FILES:
        working = repo_root.joinpath(*name.split("/")).read_bytes().replace(b"\r\n", b"\n")
        if working != _git_blob(repo_root, commit, name):
            raise BundleError(f"{name} is not the file {commit} holds, although git status "
                              "may not show it: the build runs only the committed builder")
    own = Path(__file__).resolve().parents[1] / "src" / "nornyx_forge" / "windows_payload.py"
    if Path(_payload_module.__file__).resolve() != own.resolve():
        raise BundleError(f"the payload verifier was loaded from {_payload_module.__file__}, "
                          f"not from {own}")
    return commit


def source_date_epoch(repo_root: Path, commit: str) -> int:
    """The commit's committer time: the only time a payload carries."""
    return int(_git(repo_root, "show", "-s", "--format=%ct", commit).decode("ascii").strip())


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


def load_pins(repo_root: Path, commit: str) -> dict:
    """The pinned inputs AS COMMITTED: a working-tree edit, even one an index
    flag hides, cannot reach the build."""
    try:
        pins = json.loads(_git_blob(repo_root, commit, PINS_PATH).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise BundleError(f"{PINS_PATH} at {commit} is not JSON: {error}") from None
    return check_pins(pins)


def check_pins(pins: object) -> dict:
    """The pins, refused unless they carry every field the build reads and
    the interpreter they pin is the target's CPython."""
    try:
        if pins["schema"] != PINS_SCHEMA:
            raise BundleError(f"{PINS_PATH} has schema {pins['schema']!r}, not {PINS_SCHEMA!r}")
        target, interpreter = pins["target"], pins["interpreter"]
        fields = [pins["lock"], pins["installer"]["name"], pins["installer"]["version"],
                  *(target[key] for key in
                    ("python_version", "python_platform", "wheel_platform", "abi")),
                  *(interpreter[key] for key in ("version", "archive_url", "archive_sha256"))]
    except (KeyError, TypeError) as error:
        raise BundleError(f"{PINS_PATH} is not a complete pin set: {error}") from None
    if not all(isinstance(field, str) and field for field in fields):
        raise BundleError(f"{PINS_PATH} pins an empty or non-string value")
    if pins["installer"]["name"] != "uv":
        raise BundleError(f"{PINS_PATH} names installer {pins['installer']['name']!r}; "
                          "this builder drives uv")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", pins["lock"]):
        raise BundleError(f"{PINS_PATH} names the lock {pins['lock']!r}, not a file beside it")
    version = target["python_version"]
    if (interpreter["version"].split(".")[:2] != version.split(".")
            or target["abi"] != "cp" + version.replace(".", "")):
        raise BundleError(f"{PINS_PATH} pins interpreter {interpreter['version']} for a "
                          f"CPython {version} ({target['abi']}) target: they must agree")
    if not ARCHIVE_URL.fullmatch(interpreter["archive_url"]) or not re.fullmatch(
            r"[0-9a-f]{64}", interpreter["archive_sha256"]):
        raise BundleError(f"{PINS_PATH} pins no https archive URL and SHA-256")
    return pins


def load_lock(repo_root: Path, commit: str, pins: dict) -> bytes:
    """The lock's bytes, from the commit."""
    return _git_blob(repo_root, commit, f"{INSTALLER_PATH}/{pins['lock']}")


def _hermetic_environment() -> dict[str, str]:
    """This environment without uv's own variables. `--no-config` blocks uv's
    configuration files only; a `UV_*` variable (`UV_COMPILE_BYTECODE`, an
    index, a cache) would otherwise reach the install."""
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith("UV_")}


def _uv_version(uv: str) -> str:
    """The version uv REPORTS. This checks the string a binary prints, not
    the binary: the hash pin in `build-tools.txt` holds only where uv is
    installed from it, as CI does."""
    completed = subprocess.run([uv, "--version"], capture_output=True, timeout=60,
                               env=_hermetic_environment())
    words = completed.stdout.decode("utf-8", "replace").split()
    return words[1] if completed.returncode == 0 and len(words) > 1 else "unknown"


def _drop_pruned_records(pylib: Path) -> None:
    """Remove every RECORD row that names a pruned path. Each such row
    described a host file (a launcher naming the interpreter that ran the
    build), not a file of the payload. Other rows keep their bytes. A RECORD
    that is not UTF-8, or holds a blank row, is refused by name."""
    for record in sorted(pylib.glob("*.dist-info/RECORD")):
        try:
            lines = record.read_bytes().decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError:
            raise BundleError(f"{record.relative_to(pylib)} is not UTF-8") from None
        rows = [next(csv.reader([line]), []) for line in lines]
        if any(not row for row in rows):
            raise BundleError(f"{record.relative_to(pylib)} holds a blank row")
        kept = [line for line, row in zip(lines, rows)
                if row[0].split("/", 1)[0] not in PYLIB_PRUNED]
        if len(kept) != len(lines):
            record.write_bytes("".join(kept).encode("utf-8"))


def install_locked_dependencies(dist: Path, pins: dict, lock: bytes) -> None:
    """The lock into `pylib`, for the TARGET platform and interpreter.

    uv is told the target (`--python-platform`, `--python-version`), so the
    wheels chosen and the environment markers evaluated are Windows' and
    CPython 3.13's, whatever runs this script; `--only-binary` makes a
    distribution with no wheel for the target a refusal rather than a build
    on this host; `--require-hashes` makes every distribution match the lock,
    and every dependency the resolver needs be in it; `--no-cache` and the
    scrubbed environment keep a populated cache and the operator's `UV_*`
    variables out. Then the host files are pruned with their RECORD rows, and
    every native module is traced to a wheel built for the target."""
    uv = shutil.which("uv")
    wanted = pins["installer"]["version"]
    if uv is None:
        raise BundleError(f"uv is not on PATH; the payload is installed by uv {wanted}")
    reported = _uv_version(uv)
    if reported != wanted:
        raise BundleError(f"uv reports version {reported}, not the pinned {wanted}")
    target = pins["target"]
    with tempfile.TemporaryDirectory(prefix="forge-lock-") as scratch:
        requirements = Path(scratch) / "requirements.txt"
        requirements.write_bytes(lock)
        subprocess.run(
            [uv, "pip", "install", "--no-config", "--no-cache", "--no-python-downloads",
             "--python", sys.executable, "--target", str(dist / "pylib"),
             "--python-platform", target["python_platform"],
             "--python-version", target["python_version"],
             "--only-binary", ":all:", "--require-hashes", "--link-mode", "copy",
             "-r", str(requirements)],
            check=True, timeout=1800, env=_hermetic_environment(),
        )
    for name in PYLIB_PRUNED:
        pruned = dist / "pylib" / name
        if pruned.is_dir():
            shutil.rmtree(pruned)
        elif pruned.exists():
            pruned.unlink()
    _drop_pruned_records(dist / "pylib")
    problems = wheel_tag_census(dist / "pylib", abi=target["abi"],
                                platform=target["wheel_platform"])
    if problems:
        raise BundleError("the dependency library is not built for "
                          f"{target['abi']} {target['wheel_platform']}: " + "; ".join(problems))


def _tag_fits(tag: str, abi: str, platform: str) -> str | None:
    """'native' for a tag whose extension modules load into the target
    interpreter, 'pure' for a tag with no ABI, or None for a tag that does
    not fit the target at all."""
    parts = tag.split("-")
    if len(parts) != 3:
        return None
    interpreter, tag_abi, tag_platform = parts
    if tag_platform == "any":
        return "pure" if tag_abi == "none" else None
    if tag_platform != platform:
        return None
    if tag_abi == abi and interpreter == abi:
        return "native"
    stable = re.fullmatch(r"cp3(\d+)", interpreter)
    if tag_abi == "abi3" and stable and int(stable.group(1)) <= int(abi[3:]):
        return "native"
    return "pure" if tag_abi == "none" else None


def _inside_library(row_path: str) -> bool:
    """A RECORD path that stays inside the library: relative, POSIX, with no
    drive, no backslash and no `..` component."""
    return bool(row_path) and not row_path.startswith("/") and ":" not in row_path and (
        "\\" not in row_path) and ".." not in row_path.split("/")


def wheel_tag_census(pylib: Path, *, abi: str, platform: str) -> list[str]:
    """Every distribution's wheel tags fit the target, and every extension
    module (`.pyd`) is listed in the RECORD of a distribution whose wheel was
    built for the target's ABI (`cp313`, or the stable `abi3`). A native
    library for another platform (`.so`, `.dylib`) anywhere is refused.
    Every RECORD row must name a file the library holds, inside it. Returns
    the problems, each naming its file or distribution."""
    problems: list[str] = []
    owners: dict[str, set[str | None]] = {}
    for dist_info in sorted(pylib.glob("*.dist-info")):
        wheel = HeaderParser().parsestr((dist_info / "WHEEL").read_text(encoding="utf-8"))
        tags = wheel.get_all("Tag") or []
        fits = {_tag_fits(tag.strip(), abi, platform) for tag in tags}
        if not tags or None in fits:
            problems.append(f"{dist_info.name}: wheel tags {tags} do not fit {abi} {platform}")
        record = (dist_info / "RECORD").read_text(encoding="utf-8")
        for row in csv.reader(io.StringIO(record)):
            if not row:
                continue
            owners.setdefault(row[0], set()).update(fits)
            if not _inside_library(row[0]) or not (pylib / row[0]).is_file():
                problems.append(f"{dist_info.name}/RECORD lists {row[0]}, which the "
                                "library does not hold")
    for path in sorted(pylib.rglob("*")):
        relative = path.relative_to(pylib).as_posix()
        if re.search(r"\.(so(\.\d+)*|dylib)$", path.name):
            problems.append(f"{relative}: a native library for another platform")
        elif path.suffix == ".pyd":
            if relative not in owners:
                problems.append(f"{relative}: listed in no installed distribution's RECORD")
            elif "native" not in owners[relative]:
                problems.append(f"{relative}: installed from a wheel not built for {abi}")
    return problems


def install_python(dist: Path, embed_zip: Path, expected_sha256: str,
                   abi: str | None = None) -> None:
    """The operator-supplied interpreter, verified before it is extracted.

    The digest is checked over the whole archive first, and only those
    bytes, if they match, are opened. Then the archive must be the
    embeddable distribution -- exactly one `._pth` file, and both executables
    the launcher needs -- and, given the target's `abi`, its path file must be
    that CPython's (`cp313` means `python313._pth`), so the archive's bytes,
    not only the pins' labels, agree with the target. Its path file is
    rewritten to the pinned resolution order.
    """
    data = embed_zip.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256.lower():
        raise BundleError(
            "the embedded interpreter zip does not match its declared "
            f"sha256: expected {expected_sha256.lower()}, measured {digest}"
        )
    target = dist / "python"
    # The bytes that were hashed are the bytes extracted: the path is not
    # opened a second time.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(target)
    pth_files = list(target.glob("python*._pth"))
    if len(pth_files) != 1:
        raise BundleError(
            f"expected exactly one python*._pth in the embed zip; found "
            f"{len(pth_files)}"
        )
    if abi is not None and pth_files[0].name != f"python{abi[2:]}._pth":
        raise BundleError(f"the embed zip holds {pth_files[0].name}, not the "
                          f"python{abi[2:]}._pth of the {abi} target")
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
    """The commit the tree is at, or None. Provenance for a reader of the
    folder, required by the build (`require_clean_commit`); never authority."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(repo_root),
            capture_output=True, text=True, timeout=60, env=_git_environment(),
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


def _project_version(dist: Path) -> str:
    return tomllib.loads((dist / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"]


def normalize_mtimes(dist: Path, epoch: int) -> None:
    """Every file and directory, the root included, takes the commit's time.
    Directories last, because writing into one moves its own time."""
    for directory, _subdirectories, files in os.walk(dist, topdown=False):
        for name in files:
            os.utime(os.path.join(directory, name), (epoch, epoch))
        os.utime(directory, (epoch, epoch))


def seal_payload(dist: Path, *, pins: dict, lock: bytes, commit: str, epoch: int) -> dict:
    """Write `forge-payload.json` and fix every time to the commit's. A folder
    the payload rules refuse -- bytecode, a link, a name Windows cannot hold --
    is refused here, at the build, by name (`build_manifest` applies the same
    checks `verify` does). Returns the manifest; `main` verifies the folder
    against it once the build has finished with the folder."""
    target = pins["target"]
    interpreter = pins["interpreter"]
    try:
        manifest = build_manifest(
            dist, version=_project_version(dist), source_commit=commit,
            source_date_epoch=epoch, target=f"{target['abi']}-{target['wheel_platform']}",
            lock_sha256=hashlib.sha256(lock).hexdigest(),
            installer={"name": pins["installer"]["name"],
                       "version": pins["installer"]["version"]},
            interpreter={key: interpreter[key]
                         for key in ("version", "archive_url", "archive_sha256")},
        )
        (dist / PAYLOAD_MANIFEST).write_bytes(render_manifest(manifest))
        normalize_mtimes(dist, epoch)
    except PayloadError as error:
        raise BundleError(f"the folder cannot be sealed: {error}") from None
    return manifest


def verify_bundle(dist: Path) -> None:
    """The bundle proves itself: its own interpreter resolves its own root.

    Only on Windows, the one platform that interpreter runs on: elsewhere this
    says so and runs nothing. `-B`: the check writes no bytecode, so a sealed
    payload is the same folder after it."""
    python = dist / "python" / "python.exe"
    if not python.exists():
        return  # developer bundle: verified by the system interpreter's tests
    if os.name != "nt":
        print("the bundle's interpreter runs only on Windows; its imports were not "
              "exercised on this host")
        return
    completed = subprocess.run(
        [str(python), "-B", "-c",
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
#: and pinned equal to it by test, so that the smoke imports nothing from the
#: runtime whose bundle it measures. (This script does import
#: `nornyx_forge.windows_payload`, on purpose: one implementation writes and
#: checks the payload manifest.)
RUNTIME_SCHEMA = "nornyx.forge.windows_runtime.v1"
#: The actor the smoke DECLARES when it stops the runtime. NOT a person: the
#: smoke is a program, and the route's kind rule declines only an actor that
#: declares itself non-human, so this declaration is simply what gets past it.
#: The stop observation therefore means "the holder of this run's session
#: requested a stop" -- true of the smoke, which read this run's bearer out of
#: the session file -- and never "a person stopped Forge". A-023 recorded the
#: mismatch as an open finding while the route still claimed personhood; the
#: declaration is unchanged and the route's CLAIM is what moved (A-030).
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
#: only the conjunction of all EIGHT is a pass. Seven until `session_file`
#: joined them in round 4, and this line still said seven a round later
#: (round-5 security P4) -- prose beside a tuple, again. The count is checked
#: against the tuple by `test_the_smoke_contract_counts_the_observations_it_lists`.
SMOKE_REQUIRED = ("launcher", "runtime_record", "session_file", "get /api/runtime",
                  "get /api/state", "get /", "stop", "stopped")


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


def _bearer(token: str | None, base: dict[str, str] | None = None) -> dict[str, str]:
    """Request headers carrying this run's control-plane bearer, if the smoke
    read one from the session file. `/api/state` and the stop route require it;
    the allowlisted `/api/runtime` and `/` ignore it."""
    headers = dict(base or {})
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def _get(port: int, path: str, timeout: float = 5.0, token: str | None = None) -> tuple[int, bytes, str]:
    return _exchange(port, "GET", path, headers=_bearer(token), timeout=timeout)


def _post_json(port: int, path: str, payload: dict, timeout: float = 5.0,
               token: str | None = None) -> tuple[int, bytes]:
    status, data, _ = _exchange(port, "POST", path, body=json.dumps(payload).encode("utf-8"),
                                headers=_bearer(token, {"content-type": "application/json"}),
                                timeout=timeout)
    return status, data


def _read_session_token(path: Path) -> str | None:
    """The bearer the runtime wrote to the explicit session file, or None.
    Only the smoke passes `--session-file`; the shipped launchers never do."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    token = data.get("token") if isinstance(data, dict) else None
    return token if isinstance(token, str) and token else None


def _fact(value: Any) -> Any:
    """A response value as the report records it: scalars kept, strings cut,
    anything else named by type. The report explains; it does not archive."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= FACT_LIMIT else value[:FACT_LIMIT] + "..."
    return type(value).__name__


def _launcher_log(path: Path) -> str:
    """The tail of one launcher log, as text the report can carry.

    The launcher writes BYTES in the console's own code page, so the bytes are
    decoded here with replacement rather than by a `text=True` that would raise
    on the first character the page does not share with UTF-8. The cut is the
    LAST `OUTPUT_LIMIT` characters, exactly what the captured string was cut to
    before: an error the launcher prints last is the one worth keeping. A log
    that cannot be read at all is recorded as empty rather than raised -- the
    smoke's business is recording what happened to the launcher, not failing
    over its own scratch.
    """
    try:
        return path.read_bytes().decode("utf-8", "replace")[-OUTPUT_LIMIT:]
    except OSError:
        return ""


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
    """WHAT A PASSING STOP OBSERVATION MEANS: the holder of this run's session
    asked the built runtime to stop, over loopback, and it answered that it was
    stopping as the instance the record named. It does NOT mean a person
    stopped Forge -- `SMOKE_ACTOR` says why, and A-030 says why no observation
    on this path could mean that."""
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


def _session_file_written(step: dict, expected: str | None) -> str | None:
    """The smoke's bearer arrived, or the reason nothing downstream could be
    authenticated. Without it `/api/state` and the stop route answer 401 and
    the report says only that -- so this is judged FIRST of the reachable
    observations, and names the cause once instead of three times."""
    if step.get("token_read") is not True:
        return ("no bearer was read from the session file "
                f"(present={step.get('present')!r}); the runtime writes it after it "
                "records readiness, so nothing downstream could be authenticated")
    return None


_SMOKE_CHECKS: dict[str, Callable[[dict, str | None], str | None]] = {
    "launcher": _launcher_completed,
    "runtime_record": _record_ready,
    "session_file": _session_file_written,
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
    # The gate needs the bearer on /api/state and the stop route. The smoke has
    # no browser to redeem a nonce, so it asks the runtime to write the token to
    # an EXPLICIT scratch path (the shipped launchers never pass one), reads it
    # after readiness, and authenticates those two calls. WHERE IT LANDS, stated
    # exactly: `scratch` is `tempfile.mkdtemp()`, which on the operator's machine
    # is %LOCALAPPDATA%\Temp -- under the operator's profile, and a directory
    # A-027 records as Modify for CodexSandboxUsers. The runtime's own fence
    # admits it only because the child's profile is relocated to scratch/profile
    # (below), which the file is not under. Acceptable for the smoke, and only
    # the smoke: no provider runs during it, the runtime it authenticates to
    # serves a throwaway scratch project, and the file is removed at stop and
    # the scratch with it.
    session_file = scratch / "session.json"
    command = ["cmd.exe", "/c", str(dist / "Forge.cmd"), "--project-dir", str(project),
               "--runtime-dir", str(runtime_dir), "--port", "0", "--no-browser",
               "--session-file", str(session_file)]
    # FILES, NOT PIPES, AND THE MEASUREMENT THAT SETTLES IT. `Forge.cmd` ends
    # by detaching the runtime with `start ""`, which creates that grandchild
    # with handle inheritance ON: it is handed DUPLICATES of whatever standard
    # handles this call passes, at the instant it is created, and regardless of
    # where its own standard handles are afterwards pointed. Held as PIPES --
    # which is exactly what `capture_output=True` holds -- those duplicates
    # keep the read waiting for an EOF that cannot arrive while the runtime
    # lives. `subprocess.run` then times out, kills the long-since-exited
    # `cmd.exe`, and blocks in a post-kill `communicate()` that carries NO
    # timeout of its own, so the 120 s bound below did not bound this call at
    # all. Measured on the first real embedded-interpreter run: the smoke sat
    # there four and a half minutes past its own timeout and resumed only when
    # the detached runtime was killed.
    #
    # A file handle held open by the grandchild blocks nobody, so the wait ends
    # when `cmd.exe` exits -- and the launcher's output is still CAPTURED, read
    # back from those files below, which a null sink would have thrown away.
    # Adding redirection to `Forge.cmd` is the one repair measured NOT to work
    # (arms B and D of `docs/governance/EMBEDDED_INTERPRETER_RUN.md`): the
    # duplication has already happened by the time the grandchild could
    # redirect anything. Arm E changed only what the PARENT holds, on a
    # byte-for-byte identical launcher line, and the hang vanished outright. So
    # the repair is on the driving side, and it covers BOTH launcher templates
    # because both detach the same way and neither is touched.
    launcher_out = scratch / "launcher-stdout.log"
    launcher_err = scratch / "launcher-stderr.log"
    with launcher_out.open("wb") as out_handle, launcher_err.open("wb") as err_handle:
        try:
            completed = subprocess.run(command, stdout=out_handle, stderr=err_handle,
                                       timeout=120, cwd=str(scratch), env=environment)
        except subprocess.TimeoutExpired:
            returncode, timed_out = None, True
        else:
            returncode, timed_out = completed.returncode, False
    # Read on BOTH branches. `TimeoutExpired.stdout` is None when no pipe was
    # held, so the timed-out branch would otherwise record the launcher's
    # output as empty -- the facts it carries come from the files or from
    # nowhere.
    step("launcher", returncode=returncode, timed_out=timed_out,
         stdout=_launcher_log(launcher_out), stderr=_launcher_log(launcher_err))
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
    # THE RACE THE TEST HARNESSES ALREADY CLOSED, left here. The runtime writes
    # the session file AFTER it records readiness, so reading the token the
    # instant the record says `ready` reads nothing, every later call goes bare,
    # and the report carries three 401s that name no cause (round-4
    # architecture F-P3-1). Await it inside the record wait's OWN deadline: the
    # bound is the `timeout` already given and there is no second one to keep
    # in step with it.
    token = _read_session_token(session_file)
    while token is None and time.monotonic() < deadline:
        time.sleep(0.1)
        token = _read_session_token(session_file)
    # AN OBSERVATION, not a silent None. A bearer that never arrived is the
    # cause of everything that follows, so the verdict names it rather than
    # leaving a reader to infer it from the refusals downstream. The token
    # itself is never recorded -- only that one was read.
    step("session_file", present=session_file.exists(), token_read=token is not None)
    for path in ("/api/runtime", "/api/state", "/"):
        try:
            status, body, content_type = _get(port, path, token=token)
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
        status, body = _post_json(port, "/api/runtime/stop", {"actor": SMOKE_ACTOR}, token=token)
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
        #
        # ONE EXCEPTION, stated because it is a consequence of the repair
        # above rather than something to discover later. The detached runtime
        # inherits duplicates of the two launcher log handles, and Windows
        # will not unlink a file another process holds open. So when the
        # runtime OUTLIVES the smoke -- which is precisely the case that used
        # not to terminate at all -- those two logs, and the directory holding
        # them, survive `rmtree`; everything else under the scratch is still
        # removed, and `ignore_errors` already tolerates it. When the stop
        # route does its work the runtime is gone by now and the removal is
        # complete.
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
    commit = require_clean_commit(ROOT)
    pins = load_pins(ROOT, commit) if mode == SELF_CONTAINED else None
    if pins is not None and (arguments.python_embed_sha256.lower()
                             != pins["interpreter"]["archive_sha256"]):
        raise BundleError(
            "--python-embed-sha256 is not the pinned interpreter archive "
            f"{pins['interpreter']['archive_sha256']} ({PINS_PATH}); the payload "
            "carries the pinned interpreter or none")
    copy_tree(ROOT, arguments.dist, commit)
    manifest = None
    if pins is not None:
        lock = load_lock(ROOT, commit, pins)
        install_locked_dependencies(arguments.dist, pins, lock)
        install_python(arguments.dist, arguments.python_embed,
                       arguments.python_embed_sha256, pins["target"]["abi"])
    else:
        install_dependencies(arguments.dist, sys.executable)
    write_bundle_marker(
        arguments.dist, mode=mode, interpreter_sha256=arguments.python_embed_sha256,
        source_commit=commit,
    )
    write_launcher(arguments.dist, mode)
    if pins is not None:
        manifest = seal_payload(arguments.dist, pins=pins, lock=lock, commit=commit,
                                epoch=source_date_epoch(ROOT, commit))
        print(f"payload {manifest['payload_sha256']}: {len(manifest['files'])} files, "
              f"source {commit}")
    verify_bundle(arguments.dist)
    if manifest is not None:
        try:
            verify(arguments.dist, expected_payload_sha256=manifest["payload_sha256"])
        except PayloadError as error:
            raise BundleError(f"the import check changed the sealed folder: {error}") from None
    print(f"bundle built: {arguments.dist} ({mode})")
    if arguments.smoke:
        report = smoke_bundle(arguments.dist)
        report_path = arguments.dist.parent / f"{arguments.dist.name}-smoke.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="")
        print(json.dumps(report, indent=2))
        print(f"smoke report: {report_path}")
        if manifest is not None:
            print(f"the folder has been run: it is now operator evidence about payload "
                  f"{manifest['payload_sha256']}, not that payload")
        if report["result"] != "pass":
            raise BundleError("the bundle smoke did not pass: "
                              + "; ".join(report["verdict"]["failed"]))


if __name__ == "__main__":
    main()
