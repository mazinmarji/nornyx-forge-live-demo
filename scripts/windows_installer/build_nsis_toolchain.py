"""Build the installer compiler (NSIS) from pinned source, and check what comes out.

The installer compiler is not taken from a distribution
package: upstream fixed two local privilege-escalation faults in 3.11 and 3.12
that no supported Ubuntu release carries. This script builds NSIS 3.13 from the
upstream source archive, in a container pinned by digest, with every build-tool
package pinned by size and SHA-256 (`nsis-build-debs.json`), and then compares
two independent builds byte for byte.

WHAT THE SOURCE PIN IS, stated exactly. It is a TRUST-ON-FIRST-USE (TOFU)
provenance ceiling, not authenticated upstream provenance. No upstream
cryptographic release signature is available to Forge: neither the release
archive nor the upstream Git tag is signed.

* The SHA-256 in `nsis-toolchain.json` establishes exact byte identity for
  subsequent builds, not publisher identity.
* The size and MD5 that SourceForge publishes, and the agreement of the
  extracted source with the upstream Git tree (`against-tag`), are
  corroboration and consistency checks. They are not cryptographic provenance.
* The Git mirror is not an independent authenticated provenance channel.
* Any mismatch, and any later change to the pinned source, its published
  metadata or the Git tree, fails closed and requires a new governed admission
  of the pins, not an edit that makes the build pass. Every build checks the
  archive's size, SHA-256 and MD5; the published metadata and the Git tree are
  compared with the pins only when `against-tag` is run (by hand, or by the
  manually dispatched corroboration job), and nothing notices a change
  otherwise.

WHAT THE BUILD REFUSES, before anything is compiled: an archive whose size,
SHA-256 or MD5 differs from the pin; a member that is a link, a device, an
absolute or `..` path, a duplicate, or outside the one pinned root directory; a
package whose size or SHA-256 differs from the lock. Inside the container,
which has no network, the installed packages must equal the lock exactly, and
the compiler must report the pinned version.

WHAT IT PROVES AND DOES NOT. Two builds on separate machines from the same
image digest and the same packages giving the same bytes shows that the output
is a function of the pinned inputs. It does not show that another distribution
or another image agrees, and it says nothing about the publisher of the source.
`outputs` in the pin file holds the compiler's and the data tree's digests; the
`verify` command fails until they are pinned and fails on any difference after.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLCHAIN_PATH = HERE / "nsis-toolchain.json"
TOOLCHAIN_SCHEMA = "nornyx.forge.nsis_toolchain.v1"
LOCK_SCHEMA = "nornyx.forge.nsis_build_debs.v1"
FILES_SCHEMA = "nornyx.forge.nsis_toolchain_files.v1"
BUILD_SCRIPT = HERE / "build-inside.sh"
SMOKE_SCRIPT = HERE / "nsis-smoke.nsi"
SNAPSHOT_PREFIX = "https://snapshot.ubuntu.com/ubuntu"
#: What the smoke installer writes and exits with; the Windows job reads both.
SMOKE_EXIT_ELEVATED = 10
SMOKE_EXEC_EXIT = "7"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_DIGEST_IMAGE = re.compile(r"[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}")
_SNAPSHOT = re.compile(r"\d{8}T\d{6}Z")
_PACKAGE_FIELDS = {"name", "architecture", "version", "url", "size", "sha256"}
#: Where the compiler sits in the built tree. makensis takes its data folder (stubs,
#: plug-ins, includes) to be the PARENT of the folder it runs from, as in the Windows
#: distribution (`Bin\\makensis.exe`), so the build installs it one folder down.
COMPILER = "Bin/makensis"
#: Capabilities the build container keeps: what dpkg and its maintainer scripts need
#: as root, nothing else. The compile itself runs as an unprivileged user with none.
BUILD_CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID", "SETPCAP")
#: One location gets this long, in all, to give the pinned bytes.
FETCH_BUDGET_SECONDS = 600
_MAX_MEMBERS = 20_000
_MAX_UNPACKED = 1 << 30


class ToolchainError(Exception):
    """An input, a pin or an output this script refuses."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _run_child(argv: list[str], *, timeout: int, check: bool = False,
               capture_output: bool = False, env: dict | None = None):
    """The one place a child process is started. Its output is bytes, never
    decoded here, so no locale codec decides what a compiler said."""
    return subprocess.run(argv, timeout=timeout, check=check, capture_output=capture_output,
                          env=env)


# ---------------------------------------------------------------------------
# The pins
# ---------------------------------------------------------------------------

def load_pins(path: Path = TOOLCHAIN_PATH) -> tuple[dict, dict]:
    """The pin file and the package lock it names, refused unless well formed."""
    try:
        pins = json.loads(path.read_text(encoding="utf-8"))
        lock = json.loads((path.parent / pins["container"]["lock"]).read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ToolchainError(f"the toolchain pins cannot be read: {error}") from None
    check_pins(pins, lock)
    return pins, lock


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ToolchainError(message)


def _https(url: object) -> bool:
    return isinstance(url, str) and url.startswith("https://") and " " not in url


def check_pins(pins: dict, lock: dict) -> None:
    """Every pin complete and consistent with the lock; refuses anything else."""
    try:
        _require(pins["schema"] == TOOLCHAIN_SCHEMA, "the pin file has another schema")
        source, container, build = pins["source"], pins["container"], pins["build"]
        git = source["git"]
        _require(isinstance(source["size"], int) and source["size"] > 0, "source.size")
        _require(bool(_HEX64.fullmatch(source["sha256"])), "source.sha256 is not a SHA-256")
        _require(bool(_HEX32.fullmatch(source["md5"])), "source.md5 is not an MD5")
        _require(all(_https(url) for url in [source["url"], *source["fallback_urls"]]),
                 "a source location is not an https URL")
        _require(source["root"] == f"nsis-{source['version']}-src", "source.root")
        _require(all(_HEX40.fullmatch(git[key]) for key in ("tag_object", "commit", "tree")),
                 "a Git object id is not 40 hex digits")
        moment = datetime.strptime(git["commit_time"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
        _require(build["source_date_epoch"] == int(moment.timestamp()),
                 "build.source_date_epoch is not the pinned commit time")
        _require(build["version_output"] == f"v{source['version']}", "build.version_output")
        _require(f"PREFIX_BIN=/out/nsis/{COMPILER.rsplit('/', 1)[0]}" in build["scons_args"],
                 "build.scons_args does not install the compiler where the build looks for it")
        args = build["scons_args"]
        _require(f"VERSION={source['version']}" in args and "TARGET_ARCH=x86" in args
                 and "NSIS_CONFIG_CONST_DATA_PATH=no" in args,
                 "build.scons_args lacks the version, the target or the relocatable layout")
        _require(bool(_DIGEST_IMAGE.fullmatch(container["image"])), "container.image is not "
                 "pinned by digest")
        _require(bool(_SNAPSHOT.fullmatch(container["snapshot"])), "container.snapshot")
        outputs = pins["outputs"]
        _require(outputs is None or (
            set(outputs) == {"makensis_sha256", "data_tree_sha256"}
            and all(_HEX64.fullmatch(str(value)) for value in outputs.values())),
            "outputs is neither null nor the two SHA-256 pins")
        _check_lock(lock, container)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ToolchainError(f"the pin file is not complete: {error!r}") from None


def _check_lock(lock: dict, container: dict) -> None:
    _require(lock["schema"] == LOCK_SCHEMA, "the package lock has another schema")
    _require(lock["image"] == container["image"] and lock["snapshot"] == container["snapshot"]
             and lock["install"] == container["install"],
             "the package lock was made for another image, snapshot or package list")
    signed = lock["signed_indexes"]
    _require(isinstance(signed, dict) and sorted(signed) == sorted(container["suites"]),
             "the lock does not record the signed index of each suite")
    for suite, record in signed.items():
        _require(set(record) == {"inrelease_sha256", "date", "indexes"}
                 and bool(_HEX64.fullmatch(record["inrelease_sha256"]))
                 and isinstance(record["date"], str) and record["indexes"],
                 f"the signed-index record of {suite} is incomplete")
        _require(all(set(index) == {"size", "sha256"} and isinstance(index["size"], int)
                     and bool(_HEX64.fullmatch(index["sha256"]))
                     for index in record["indexes"].values())
                 and sorted(record["indexes"]) == sorted(
                     f"{component}/binary-amd64/Packages.xz" for component in container["components"]),
                 f"the index records of {suite} do not match the components")
    packages = lock["packages"]
    _require(isinstance(packages, list) and packages, "the package lock lists no packages")
    names = [package.get("name") for package in packages]
    _require(len(set(names)) == len(names), "the package lock names a package twice")
    for package in packages:
        _require(set(package) == _PACKAGE_FIELDS, f"{package.get('name')!r} is not an exact entry")
        basename = package["url"].rsplit("/", 1)[-1]
        _require(
            bool(_HEX64.fullmatch(package["sha256"])) and isinstance(package["size"], int)
            and package["size"] > 0
            and package["url"].startswith(f"{SNAPSHOT_PREFIX}/{lock['snapshot']}/pool/")
            and basename.startswith(f"{package['name']}_") and basename.endswith(".deb"),
            f"{package['name']} lacks a snapshot pool URL that names it, its size and its SHA-256")
    base = lock["base"]
    _require(all(isinstance(row, str) and len(row.split(" ")) == 3 for row in base),
             "the package lock's base list is malformed")
    known = set(names) | {row.split(" ")[0] for row in base}
    _require(all(top in known for top in lock["install"]),
             "a requested package is neither locked nor in the image")
    _require(not any(name.startswith("libwinpthread") or name.endswith("-posix")
                     for name in known),
             "a POSIX-thread MinGW package is locked; the build needs the win32 thread model only")


def expected_packages(lock: dict) -> list[str]:
    """The lines `dpkg-query` must print after the install: the image's packages
    with the locked ones in place of any they replace, in byte order."""
    final = {}
    for row in lock["base"]:
        name, arch, version = row.split(" ")
        final[name] = (arch, version)
    final.update({p["name"]: (p["architecture"], p["version"]) for p in lock["packages"]})
    return sorted(f"{name} {arch} {version}" for name, (arch, version) in final.items())


# ---------------------------------------------------------------------------
# Fetching and unpacking the source
# ---------------------------------------------------------------------------

def _read_bounded(response, limit: int, deadline: float) -> bytes:
    """At most `limit` bytes, in blocks, within a deadline for the whole transfer
    (a socket timeout alone restarts with every block that trickles in)."""
    blocks, total = [], 0
    while total < limit:
        if time.monotonic() > deadline:
            raise OSError("the transfer used up its time budget")
        block = response.read(min(1 << 20, limit - total))
        if not block:
            break
        blocks.append(block)
        total += len(block)
    return b"".join(blocks)


def _byte_problem(data: bytes, size: int, sha256: str, md5: str | None) -> str | None:
    if len(data) != size:
        return f"gave {len(data)} bytes, not the pinned {size}"
    if hashlib.sha256(data).hexdigest() != sha256:
        return f"has SHA-256 {hashlib.sha256(data).hexdigest()}, not the pinned {sha256}"
    if md5 is not None and hashlib.md5(data, usedforsecurity=False).hexdigest() != md5:
        return f"has an MD5 other than the pinned {md5}"
    return None


def fetch_verified(urls: list[str], *, size: int, sha256: str, md5: str | None, dest: Path,
                   opener: Callable = urllib.request.urlopen, timeout: int = 120,
                   budget: float = FETCH_BUDGET_SECONDS) -> str:
    """Fetch from the first location that gives the pinned bytes, and keep them
    only then: size, SHA-256 and (when given) MD5. At most one byte beyond the
    pinned size is read, within a time budget. A location that cannot be read, or
    that answers with other bytes (an error page from a redirector, say), is passed
    over for the next; if none gives the pinned bytes the fetch is refused with
    what each one gave. Returns the URL used."""
    failures = []
    for url in urls:
        try:
            with opener(url, timeout=timeout) as response:
                data = _read_bounded(response, size + 1, time.monotonic() + budget)
        except (OSError, http.client.HTTPException) as error:
            failures.append(f"{url}: {error}")
            continue
        problem = _byte_problem(data, size, sha256, md5)
        if problem:
            failures.append(f"{url} {problem}")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".partial")
        partial.write_bytes(data)
        os.replace(partial, dest)
        return url
    raise ToolchainError("no location gave the pinned bytes: " + "; ".join(failures))


def _member_problem(member: tarfile.TarInfo, root: str) -> str | None:
    name = member.name
    if not name or "\0" in name or "\\" in name or name.startswith("/"):
        return "has an empty, absolute or backslash name"
    if posixpath.normpath(name) != name or ".." in name.split("/"):
        return "is not a plain relative path"
    if name.split("/")[0] != root:
        return f"is outside the single root {root}/"
    if member.issparse() or not (member.isreg() or member.isdir()):
        return f"is not a regular file or folder (tar type {member.type!r})"
    if name == root and not member.isdir():
        return "is named like the root folder but is not a folder"
    return None


def safe_extract(archive: Path, dest: Path, *, root: str, epoch: int) -> int:
    """Unpack the source archive into an empty `dest`, or refuse it entirely.

    Every member is checked before any is written. Only regular files and
    folders are created, by this function and not by `tarfile`'s extraction,
    so no link, device, mode, owner or time of the archive's reaches the disk.
    Returns the number of files."""
    if dest.exists() and any(dest.iterdir()):
        raise ToolchainError(f"{dest} is not empty")
    with tarfile.open(archive, "r:bz2") as tar:
        members = tar.getmembers()
        if not 0 < len(members) <= _MAX_MEMBERS:
            raise ToolchainError(f"the archive holds {len(members)} members")
        seen: set[str] = set()
        spelling: dict[str, str] = {}
        total = 0
        for member in members:
            problem = _member_problem(member, root)
            if problem:
                raise ToolchainError(f"member {member.name!r} {problem}")
            if member.name in seen:
                raise ToolchainError(f"member {member.name!r} appears twice")
            seen.add(member.name)
            parts = member.name.split("/")
            for end in range(1, len(parts) + 1):
                prefix = "/".join(parts[:end])
                if spelling.setdefault(prefix.casefold(), prefix) != prefix:
                    raise ToolchainError(f"member {member.name!r} differs only in letter case "
                                         f"from {spelling[prefix.casefold()]!r}")
            total += member.size if member.isreg() else 0
        if total > _MAX_UNPACKED:
            raise ToolchainError(f"the archive unpacks to {total} bytes")
        file_names = {member.name for member in members if member.isreg()}
        for member in members:
            parts = member.name.split("/")
            if any("/".join(parts[:end]) in file_names for end in range(1, len(parts))):
                raise ToolchainError(f"member {member.name!r} lies below a file")
        dest.mkdir(parents=True, exist_ok=True)
        files = 0
        folders = []
        for member in members:
            target = dest.joinpath(*member.name.split("/"))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                folders.append(target)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            with target.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            os.chmod(target, 0o644)
            os.utime(target, (epoch, epoch))
            files += 1
        for folder in sorted(folders, reverse=True):
            os.chmod(folder, 0o755)
            os.utime(folder, (epoch, epoch))
    return files


def fetch_debs(lock: dict, dest: Path, *, opener: Callable = urllib.request.urlopen) -> list[str]:
    """Every locked package, kept only if its size and SHA-256 are the locked
    ones. `dest` must be empty, so nothing the lock does not name is ever
    installed. Returns the file names."""
    if dest.exists() and any(dest.iterdir()):
        raise ToolchainError(f"{dest} is not empty")
    names = []
    for package in lock["packages"]:
        name = package["url"].rsplit("/", 1)[-1]
        fetch_verified([package["url"]], size=package["size"], sha256=package["sha256"],
                       md5=None, dest=dest / name, opener=opener)
        names.append(name)
    return names


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def docker_argv(pins: dict, *, debs: Path, src: Path, out: Path, expected: Path,
                script: Path = BUILD_SCRIPT, docker: str = "docker",
                name: str | None = None) -> list[str]:
    """The one `docker run` that builds: no network, the image by digest, the
    inputs read-only, the output folder the only writable mount, and only the
    capabilities dpkg needs (the compile drops them all)."""
    build = pins["build"]
    for path in (debs, src, out, expected, script):
        if not path.is_absolute():
            raise ToolchainError(f"{path} is not absolute, so docker would take it for a volume")
    environment = {
        **build["environment"], "SOURCE_DATE_EPOCH": str(build["source_date_epoch"]),
        "DEBIAN_FRONTEND": "noninteractive", "NSIS_SRC_ROOT": pins["source"]["root"],
        "NSIS_VERSION_OUTPUT": build["version_output"]}
    argv = [docker, "run", "--rm", "--network", "none", "--user", "0",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL"]
    for capability in BUILD_CAPABILITIES:
        argv += ["--cap-add", capability]
    if name:
        argv += ["--name", name]
    for variable in sorted(environment):
        argv += ["-e", f"{variable}={environment[variable]}"]
    for mount in (f"{debs}:/debs:ro", f"{src}:/src:ro", f"{out}:/out",
                  f"{script}:/work/build-inside.sh:ro",
                  f"{expected}:/work/expected-packages.txt:ro"):
        argv += ["-v", mount]
    return [*argv, pins["container"]["image"], "sh", "-eu", "/work/build-inside.sh",
            *build["scons_args"]]


def fetch_inputs(pins: dict, lock: dict, work: Path) -> None:
    """Everything the build reads, fetched and verified into `work`."""
    source = pins["source"]
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source.tar.bz2"
    url = fetch_verified([source["url"], *source["fallback_urls"]], size=source["size"],
                         sha256=source["sha256"], md5=source["md5"], dest=archive)
    print(f"source: {source['size']} bytes from {url.split('?')[0]}; SHA-256 and MD5 as pinned")
    count = safe_extract(archive, work / "src", root=source["root"],
                         epoch=pins["build"]["source_date_epoch"])
    print(f"source: {count} files unpacked")
    names = fetch_debs(lock, work / "debs")
    print(f"packages: {len(names)} fetched; sizes and SHA-256 as locked")
    (work / "expected-packages.txt").write_text(
        "\n".join(expected_packages(lock)) + "\n", encoding="utf-8", newline="")


def build(pins: dict, work: Path, out: Path, *, run: Callable = _run_child) -> None:
    """Run the container build over inputs `fetch_inputs` placed in `work`. A
    container that outlives its time limit is killed, not left running."""
    work, out = work.resolve(), out.resolve()
    if out.exists() and any(out.iterdir()):
        raise ToolchainError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)
    name = f"nsis-build-{os.getpid()}-{int(time.time())}"
    argv = docker_argv(pins, debs=work / "debs", src=work / "src", out=out,
                       expected=work / "expected-packages.txt", name=name)
    try:
        completed = run(argv, timeout=3600, check=False)
    except subprocess.TimeoutExpired:
        run(["docker", "kill", name], timeout=60, check=False)
        raise ToolchainError("the container build ran out of time and was killed") from None
    if completed.returncode != 0:
        raise ToolchainError(f"the container build exited {completed.returncode}")
    compiler = out / "nsis" / COMPILER
    if not (compiler.exists() and stat.S_ISREG(os.lstat(compiler).st_mode)):
        raise ToolchainError("the build left no makensis")


# ---------------------------------------------------------------------------
# What came out
# ---------------------------------------------------------------------------

def _lstat_walk(root: Path) -> list[Path]:
    """Every regular file under `root`, found by lstat alone: the root itself, every
    folder and every file must be what it looks like. A link anywhere (the root
    included), a pipe, a device, a socket, and a set-user-id or set-group-id
    file or folder are refused, because what a container wrote into a folder is
    not trusted to be only files. Setting the sticky bit on a file is refused too."""
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode):
        raise ToolchainError(f"{root} is not a folder (a link or another kind of file)")
    pending, found = [root], []
    while pending:
        folder = pending.pop()
        with os.scandir(folder) as entries:
            listed = sorted(entries, key=lambda entry: entry.name)
        for entry in listed:
            path = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise ToolchainError(f"{path} is set-user-id or set-group-id")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_mode & stat.S_ISVTX:
                    raise ToolchainError(f"{path} has the sticky bit")
                found.append(path)
            else:
                raise ToolchainError(f"{path} is not a regular file or folder")
    return sorted(found)


def tree_digest(root: Path) -> str:
    """One digest for a directory tree: every regular file's relative path and
    SHA-256 in byte order. A link, or anything that is not a regular file or a
    folder, is refused: the tool's data directory holds none."""
    lines = [f"{path.relative_to(root).as_posix()}\0{_sha256(path)}\n"
             for path in _lstat_walk(root)]
    lines.sort(key=lambda line: line.encode("utf-8"))
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def describe_tree(root: Path) -> dict:
    """The tree as a document: each file's path, size, SHA-256 and whether it is
    executable, with the compiler's and the tree's digests."""
    files = [{"path": path.relative_to(root).as_posix(), "size": os.lstat(path).st_size,
              "sha256": _sha256(path), "executable": bool(os.lstat(path).st_mode & 0o111)}
             for path in _lstat_walk(root)]
    files.sort(key=lambda row: row["path"].encode("utf-8"))
    compiler = next((row for row in files if row["path"] == COMPILER), None)
    if compiler is None:
        raise ToolchainError(f"{root} holds no makensis at {COMPILER}")
    return {"schema": FILES_SCHEMA, "makensis_sha256": compiler["sha256"],
            "data_tree_sha256": tree_digest(root), "files": files}


def export_tree(out: Path, dest: Path) -> dict:
    """Copy the build's output to a new folder this process owns, and describe it.

    `out` is where the container wrote, so it is read as untrusted: it must hold
    exactly one entry, `nsis`, a real folder; that tree is walked by lstat (links,
    pipes, devices and set-id bits refused), and each file is opened without
    following a link and copied with its hash checked against the walk. The copy
    gets plain modes, and `files.json` is created exclusively beside it, so
    nothing the container could place under `out` is uploaded or written through."""
    info = os.lstat(out)
    if not stat.S_ISDIR(info.st_mode):
        raise ToolchainError(f"{out} is not a folder")
    names = sorted(os.listdir(out))
    if names != ["nsis"]:
        raise ToolchainError(f"{out} holds {names}, not exactly ['nsis']")
    description = describe_tree(out / "nsis")
    if os.path.lexists(dest):
        raise ToolchainError(f"{dest} already exists")
    dest.mkdir(parents=True)
    for row in description["files"]:
        target = dest / "nsis" / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        descriptor = os.open(out / "nsis" / row["path"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source, target.open("xb") as handle:
            for block in iter(lambda: source.read(1 << 20), b""):
                digest.update(block)
                handle.write(block)
        if digest.hexdigest() != row["sha256"]:
            raise ToolchainError(f"{row['path']} changed while it was copied")
        os.chmod(target, 0o755 if row["executable"] else 0o644)
    with (dest / "files.json").open("x", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(description, indent=1) + "\n")
    return description


def compare_descriptions(first: dict, second: dict, *, modes: bool = True) -> list[str]:
    """Every difference between two descriptions, by path."""
    rows = [{row["path"]: row for row in description["files"]} for description in (first, second)]
    problems = [f"{path}: only in the {'first' if path in rows[0] else 'second'}"
                for path in sorted(set(rows[0]) ^ set(rows[1]))]
    for path in sorted(set(rows[0]) & set(rows[1])):
        left, right = rows[0][path], rows[1][path]
        if left["sha256"] != right["sha256"] or left["size"] != right["size"]:
            problems.append(f"{path}: bytes differ ({left['sha256'][:12]} vs {right['sha256'][:12]})")
        elif modes and left["executable"] != right["executable"]:
            problems.append(f"{path}: executable bit differs")
    return problems


def load_leg(folder: Path) -> tuple[dict, dict]:
    """A downloaded build leg: the description its job wrote and the one
    recomputed from the files. The two must describe the same bytes, the
    compiler's and the tree's digests included."""
    recorded = json.loads((folder / "files.json").read_text(encoding="utf-8"))
    actual = describe_tree(folder / "nsis")
    problems = compare_descriptions(recorded, actual, modes=False)
    for key in ("makensis_sha256", "data_tree_sha256"):
        if recorded.get(key) != actual[key]:
            problems.append(f"{key}: recorded {recorded.get(key)!r}, actual {actual[key]}")
    if problems:
        raise ToolchainError(f"{folder.name}: files.json does not describe the downloaded tree: "
                             f"{problems[:5]}")
    return recorded, actual


def verify_legs(first: Path, second: Path, pins: dict) -> dict:
    """Two legs must agree on every byte and on the executable bits their jobs
    recorded, and must equal the pinned outputs. Until the outputs are pinned
    this fails and prints the digests to pin. The digests compared are those of
    the downloaded bytes, never those the legs wrote about themselves."""
    (recorded_a, actual_a), (recorded_b, _) = load_leg(first), load_leg(second)
    problems = compare_descriptions(recorded_a, recorded_b)
    if problems:
        raise ToolchainError("the two builds differ:\n  " + "\n  ".join(problems[:50]))
    measured = {"makensis_sha256": actual_a["makensis_sha256"],
                "data_tree_sha256": actual_a["data_tree_sha256"]}
    pinned = pins["outputs"]
    if pinned is None:
        raise ToolchainError("the two builds agree, but the outputs are NOT PINNED. Measured: "
                             + json.dumps(measured, sort_keys=True))
    if pinned != measured:
        raise ToolchainError("the builds are not the pinned outputs. Measured: "
                             + json.dumps(measured, sort_keys=True) + " Pinned: "
                             + json.dumps(pinned, sort_keys=True))
    return measured


def check_tree(tree: Path, pins: dict, *, allow_unpinned: bool = False) -> str:
    """Refuse a compiler tree that contradicts the pinned outputs. While no outputs
    are pinned there is nothing to check it against, which is refused too unless the
    caller says in so many words that it runs an unpinned tree (`allow_unpinned`):
    resetting `outputs` to null must not quietly switch this check off."""
    description = describe_tree(tree)
    pinned = pins["outputs"]
    if pinned is None:
        if not allow_unpinned:
            raise ToolchainError("the outputs are not pinned, so this tree cannot be checked "
                                 "against them; pass --allow-unpinned to run it anyway")
        return ("UNPINNED, run anyway by request; measured makensis "
                f"{description['makensis_sha256']}, tree {description['data_tree_sha256']}")
    if pinned != {"makensis_sha256": description["makensis_sha256"],
                  "data_tree_sha256": description["data_tree_sha256"]}:
        raise ToolchainError("the compiler tree is not the pinned one")
    return "the compiler tree is the pinned one"


# ---------------------------------------------------------------------------
# The source against the upstream Git tree
# ---------------------------------------------------------------------------

def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def compare_with_git(members: dict[str, bytes], blobs: dict[str, str]) -> dict:
    """The archive's files against a Git tree's blob ids, file by file: identical,
    identical once the archive's CRLF line ends are LF, different, or present on
    one side only."""
    result = {"identical": 0, "crlf_only": 0, "different": [], "tarball_only": [], "git_only": []}
    for name, data in members.items():
        wanted = blobs.get(name)
        if wanted is None:
            result["tarball_only"].append(name)
        elif git_blob_id(data) == wanted:
            result["identical"] += 1
        elif git_blob_id(data.replace(b"\r\n", b"\n")) == wanted:
            result["crlf_only"] += 1
        else:
            result["different"].append(name)
    result["git_only"] = sorted(set(blobs) - set(members))
    for key in ("different", "tarball_only"):
        result[key].sort()
    return result


def _get_json(url: str) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": "forge-nsis-toolchain",
                                                   "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read(1 << 26))


def check_published_md5(rss: str, pins: dict) -> None:
    """SourceForge's own listing must show the pinned size and MD5 for the archive.
    The listing is read with one regular expression over the structure it has
    today; a listing in any other shape is refused as not showing the archive,
    never guessed at."""
    source = pins["source"]
    pattern = (r'url="[^"]*/' + re.escape(f"nsis-{source['version']}-src.tar.bz2")
               + r'/download" filesize="(\d+)"><media:hash algo="md5">([0-9a-f]{32})<')
    match = re.search(pattern, rss)
    if match is None:
        raise ToolchainError("the SourceForge listing does not show the source archive")
    if (int(match.group(1)), match.group(2)) != (source["size"], source["md5"]):
        raise ToolchainError(f"SourceForge lists size {match.group(1)} and MD5 {match.group(2)}, "
                             f"not the pinned {source['size']} and {source['md5']}")


def against_tag(pins: dict, *, get_json: Callable = _get_json, get_text: Callable | None = None,
                archive: Path | None = None) -> dict:
    """Corroborate the pinned source: the upstream tag still names the pinned
    commit and tree, SourceForge still lists the pinned size and MD5, and every
    file of the archive compares as the pins record. This is a consistency check
    between two unauthenticated copies of upstream's material; it is not a
    signature check and it proves nothing about who published either."""
    source, git = pins["source"], pins["source"]["git"]
    base = f"https://api.github.com/repos/{git['repository']}/git"
    ref = get_json(f"{base}/ref/tags/{git['tag']}")["object"]
    tag = get_json(f"{base}/tags/{ref['sha']}")
    commit = get_json(f"{base}/commits/{tag['object']['sha']}")
    if (ref["sha"], tag["object"]["sha"], commit["tree"]["sha"], commit["committer"]["date"]) != (
            git["tag_object"], git["commit"], git["tree"], git["commit_time"]):
        raise ToolchainError("the upstream tag no longer names the pinned object, commit, tree and time")
    tree = get_json(f"{base}/trees/{git['tree']}?recursive=1")
    if tree.get("truncated") or tree["sha"] != git["tree"]:
        raise ToolchainError("the Git tree listing is truncated or is not the pinned tree")
    blobs = {row["path"]: row["sha"] for row in tree["tree"] if row["type"] == "blob"}
    if get_text is None:
        def get_text(url: str) -> str:
            with urllib.request.urlopen(url, timeout=120) as response:
                return response.read(1 << 24).decode("utf-8", "replace")
    check_published_md5(get_text(f"https://sourceforge.net/projects/nsis/rss?path=/NSIS%203/{source['version']}"), pins)
    with tempfile.TemporaryDirectory(prefix="nsis-tag-") as scratch:
        if archive is None:
            archive = Path(scratch) / "source.tar.bz2"
            fetch_verified([source["url"], *source["fallback_urls"]], size=source["size"],
                           sha256=source["sha256"], md5=source["md5"], dest=archive)
        members = {}
        with tarfile.open(archive, "r:bz2") as tar:
            for member in tar:
                if member.isreg():
                    members[member.name.split("/", 1)[1]] = tar.extractfile(member).read()
    result = compare_with_git(members, blobs)
    if result != git["comparison"]:
        raise ToolchainError("the source no longer compares to the Git tree as pinned: "
                             + json.dumps(result, sort_keys=True))
    return result


# ---------------------------------------------------------------------------
# The smoke installer
# ---------------------------------------------------------------------------

_REFUSED_IN_EXE = (b"requireAdministrator", b"highestAvailable", b'uiAccess="true"')


def check_executable(path: Path) -> None:
    """A PE that asks for no privilege: MZ, a PE header, an asInvoker manifest
    and none of the elevating levels."""
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ToolchainError(f"{path.name} does not start with MZ")
    header = int.from_bytes(data[0x3C:0x40], "little")
    if data[header:header + 4] != b"PE\0\0":
        raise ToolchainError(f"{path.name} has no PE signature where its header says")
    if b'<requestedExecutionLevel level="asInvoker" uiAccess="false"/>' not in data:
        raise ToolchainError(f"{path.name} does not carry an asInvoker manifest")
    for refused in _REFUSED_IN_EXE:
        if refused in data:
            raise ToolchainError(f"{path.name} contains {refused.decode()}")


_WARNING_LINE = re.compile(r"^\s*warning\b|^\d+ warnings?:", re.IGNORECASE | re.MULTILINE)


def compiler_argv(pins: dict, *, tree: Path, mounts: list[tuple[Path, str, bool]],
                  command: list[str], epoch: int, docker: str = "docker") -> list[str]:
    """The `docker run` that runs the built compiler, for every consumer of the tree:
    the pinned image, no network, no capability, no way to gain one, a read-only root,
    the compiler tree read-only at `/nsis`, and the caller's `mounts` (host folder or
    file, container path, read-only or not). NSISDIR and the configuration are fixed
    (makensis otherwise takes both from outside the tree it was pinned as), and so is
    the rest of the environment; `epoch` is the SOURCE_DATE_EPOCH the caller decides.
    The image is never pulled here (`--pull never`): the caller pulls it by digest
    beforehand, so a missing image is a refusal, not a download. On a POSIX host a
    path holding the `:` that `-v` splits on is refused, for every mount."""
    for path in (tree, *(host for host, _, _ in mounts)):
        if not path.is_absolute():
            raise ToolchainError(f"{path} is not absolute, so docker would take it for a volume")
        if os.name != "nt" and ":" in str(path):
            raise ToolchainError(f"{path} holds a ':', which docker -v would split on")
    user = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "65534:65534"
    environment = {"HOME": "/tmp", "NSISDIR": "/nsis", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                   "SOURCE_DATE_EPOCH": str(epoch)}
    argv = [docker, "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", user, "--read-only",
            "--tmpfs", "/tmp"]
    for variable in sorted(environment):
        argv += ["-e", f"{variable}={environment[variable]}"]
    argv += ["-v", f"{tree}:/nsis:ro"]
    for host, target, read_only in mounts:
        argv += ["-v", f"{host}:{target}" + (":ro" if read_only else "")]
    return [*argv, pins["container"]["image"], *command]


def smoke_argv(pins: dict, *, tree: Path, nsi: Path, out_dir: Path, command: list[str],
               docker: str = "docker") -> list[str]:
    """The `docker run` that runs the built compiler for the smoke installer: the
    script read-only, and one writable folder for the installer it makes."""
    return compiler_argv(pins, tree=tree, mounts=[(nsi, "/work/nsis-smoke.nsi", True),
                                                  (out_dir, "/smoke", False)],
                         command=command, epoch=pins["build"]["source_date_epoch"],
                         docker=docker)


def compile_smoke(tree: Path, pins: dict, out: Path, *, nsi: Path = SMOKE_SCRIPT,
                  run: Callable = _run_child) -> int:
    """Compile the smoke installer with the built compiler, INSIDE the pinned image
    (no network, nothing writable but the output folder): the compiler was built
    here a moment ago and is not trusted with the host. It must report the pinned
    version, and warnings are errors. Returns the warning count, which is zero."""
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if not hasattr(os, "getuid"):
        os.chmod(out.parent, 0o777)
    where = {"tree": tree.resolve(), "nsi": nsi.resolve(), "out_dir": out.parent}
    version = run(smoke_argv(pins, command=["/nsis/" + COMPILER, "-VERSION"], **where),
                  capture_output=True, timeout=120)
    reported = version.stdout.decode("utf-8", "replace").strip()
    if version.returncode != 0 or reported != pins["build"]["version_output"]:
        raise ToolchainError(f"makensis reports {reported!r}, not "
                             f"{pins['build']['version_output']!r}")
    compile_command = ["/nsis/" + COMPILER, "-NOCONFIG", "-NOCD", "-INPUTCHARSET", "UTF8", "-V2",
                       "-WX", f"-DOUT_FILE=/smoke/{out.name}", "/work/nsis-smoke.nsi"]
    completed = run(smoke_argv(pins, command=compile_command, **where), capture_output=True,
                    timeout=600)
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if completed.returncode != 0 or not out.is_file():
        raise ToolchainError(f"makensis exited {completed.returncode}:\n{text[-4000:]}")
    warnings = _WARNING_LINE.findall(text)
    if warnings:
        raise ToolchainError("makensis printed warnings:\n" + text[-2000:])
    check_executable(out)
    return len(warnings)


def check_smoke_result(text: str, exit_code: int, *, elevated: bool, pins: dict) -> None:
    """What the smoke installer reported from the Windows host: the System
    plug-in read the token, nsExec returned the child's exit code and output,
    the compiler version it was built by, and, when the host is elevated, the
    refusal branch's exit code."""
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    values = {key.strip(): value.strip() for key, value in values.items()}
    expected = {"system_call": "ok", "elevated": "1" if elevated else "0",
                "nsexec_exit": SMOKE_EXEC_EXIT, "nsexec_output": "smoke",
                "nsis": pins["build"]["version_output"]}
    for key, wanted in expected.items():
        if values.get(key) != wanted:
            raise ToolchainError(f"the smoke installer reported {key}={values.get(key)!r}, "
                                 f"expected {wanted!r}")
    wanted_exit = SMOKE_EXIT_ELEVATED if elevated else 0
    if exit_code != wanted_exit:
        raise ToolchainError(f"the smoke installer exited {exit_code}, expected {wanted_exit}")


def run_smoke(exe: Path, work: Path, pins: dict, *, elevated: bool,
              run: Callable = _run_child) -> None:
    """Run the compiled smoke installer on the Windows host and check it."""
    check_executable(exe)
    work.mkdir(parents=True, exist_ok=True)
    result = work / "smoke-result.txt"
    completed = run([str(exe), "/S", f"/RESULT={result}"], timeout=120, check=False)
    if not result.is_file():
        raise ToolchainError(f"the smoke installer exited {completed.returncode} and wrote no result")
    check_smoke_result(result.read_text(encoding="utf-8", errors="replace"), completed.returncode,
                       elevated=elevated, pins=pins)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="validate the pin file and the package lock")
    fetch = commands.add_parser("fetch", help="fetch and verify the source and the packages")
    fetch.add_argument("--work", type=Path, required=True)
    built = commands.add_parser("build", help="run the container build over fetched inputs")
    built.add_argument("--work", type=Path, required=True)
    built.add_argument("--out", type=Path, required=True)
    describe = commands.add_parser("describe", help="copy a built tree to a new folder with files.json")
    describe.add_argument("--from", dest="source", type=Path, required=True,
                          help="the folder the container wrote (read as untrusted)")
    describe.add_argument("--to", dest="dest", type=Path, required=True,
                          help="a new folder this process owns; it is what gets uploaded")
    verify = commands.add_parser("verify", help="compare two legs and the pinned outputs")
    verify.add_argument("--a", type=Path, required=True)
    verify.add_argument("--b", type=Path, required=True)
    tree = commands.add_parser("check-tree", help="refuse a compiler tree that contradicts the pins")
    tree.add_argument("--tree", type=Path, required=True)
    tree.add_argument("--allow-unpinned", action="store_true",
                      help="run a tree while no outputs are pinned (refused otherwise)")
    commands.add_parser("against-tag", help="compare the source with the upstream Git tag")
    smoke = commands.add_parser("compile-smoke", help="compile the smoke installer")
    smoke.add_argument("--tree", type=Path, required=True)
    smoke.add_argument("--out", type=Path, required=True)
    smoke_run = commands.add_parser("run-smoke", help="run the smoke installer on Windows")
    smoke_run.add_argument("--exe", type=Path, required=True)
    smoke_run.add_argument("--work", type=Path, required=True)
    smoke_run.add_argument("--expect", choices=("elevated", "standard"), required=True)
    arguments = parser.parse_args(argv)
    try:
        pins, lock = load_pins()
        if arguments.command == "check":
            print(f"pins complete; {len(lock['packages'])} packages locked")
        elif arguments.command == "fetch":
            fetch_inputs(pins, lock, arguments.work)
        elif arguments.command == "build":
            build(pins, arguments.work, arguments.out)
        elif arguments.command == "describe":
            description = export_tree(arguments.source, arguments.dest)
            print(f"makensis {description['makensis_sha256']}; data tree "
                  f"{description['data_tree_sha256']}; {len(description['files'])} files")
        elif arguments.command == "verify":
            measured = verify_legs(arguments.a, arguments.b, pins)
            print("the two builds are byte-identical and equal the pinned outputs: "
                  + json.dumps(measured, sort_keys=True))
        elif arguments.command == "check-tree":
            print(check_tree(arguments.tree, pins, allow_unpinned=arguments.allow_unpinned))
        elif arguments.command == "against-tag":
            print("source corroborated: " + json.dumps(against_tag(pins), sort_keys=True))
        elif arguments.command == "compile-smoke":
            compile_smoke(arguments.tree, pins, arguments.out)
            print(f"compiled {arguments.out.name}: no warnings")
        else:
            run_smoke(arguments.exe, arguments.work, pins, elevated=arguments.expect == "elevated")
            print("the smoke installer ran as expected")
    except ToolchainError as error:
        print(f"toolchain refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError,
            http.client.HTTPException, subprocess.TimeoutExpired) as error:
        print(f"toolchain could not read what it needs: {error!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
