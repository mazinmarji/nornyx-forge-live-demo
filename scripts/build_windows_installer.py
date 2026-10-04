"""Build ForgeSetup.exe from a verified Windows payload, with the pinned NSIS.

`scripts/build_windows_bundle.py` makes the payload folder; this script wraps
that folder, unchanged, in the installer `scripts/windows_installer/forge-setup.nsi`
describes. The compiler is the NSIS 3.13 tree that
`scripts/windows_installer/build_nsis_toolchain.py` builds from pinned source
(`nsis-toolchain.json`); CI builds it, compares two builds with the pinned
outputs, and hands the tree to this script. Nothing is downloaded here: the
image is pulled by digest beforehand and the container is started with
`--pull never`. The compiler runs in a container of the pinned image, not as a
process of the build machine's own userland: no network, no capability, a
read-only root, as the toolchain's own smoke compile does
(`build_nsis_toolchain.compiler_argv`, one definition for both). A container
shares the runner's kernel; it is isolation, not a separate machine.

THE INTEGRITY CHECK OF THIS SCRIPT'S OWN FILES (`INSTALLER_FILES` against the
commit's blobs) runs after this script and its modules were imported, so it
detects a working tree that drifted from the commit; it cannot stop code that
was already running.

WHAT THE BUILD REFUSES, before any executable exists:

* a tree that is not a clean commit, and a builder, script, contract, toolchain
  module or pin file whose bytes differ from the commit's (as the payload
  builder does);
* a payload folder that does not verify against its own manifest, or whose
  manifest is not this commit's: the source commit, the lock's digest, the
  installer and the interpreter must each equal what the commit pins, and every
  copy-set file (the repository's own files in the payload) and the version
  must equal the commit's, and so must the two files the payload builder
  writes (`GENERATED_FILES`: the launcher and the bundle marker, rendered again
  by the commit's own writers). Only `UNCOMPARED_ROOTS` (`pylib/`, `python/`)
  are NOT compared with anything the commit holds; the payload's identity, the
  lock digest and the interpreter archive digest are what hold them. Any other
  top-level name is refused. The tiny test payloads of CI's refusal checks are
  built through `--test-only-synthetic`, which skips the copy-set comparison
  and lists, in the build record, every top-level name it did not compare;
* a payload whose files and folders do not all carry the commit's time (the
  installer stores each file's time, so a disturbed copy would change the
  bytes);
* a payload without the files the installer launches and verifies with;
* toolchain pins whose outputs are not pinned, a compiler tree that is not the
  pinned outputs (the compiler's SHA-256 and the tree digest, `tree_digest`,
  the toolchain's one definition), and a compiler that does not report the
  pinned version.

WHAT IT CHECKS AFTER, on what the container wrote: one regular file and
nothing else, a PE with an `asInvoker` manifest and no `requireAdministrator`,
`highestAvailable` or `uiAccess="true"`, and with the version, commit and
payload identity in its version-information resource, so the identity the
installer verifies against is the one the build record names.

WHAT THE OUTPUT IS: `ForgeSetup.exe`, `ForgeSetup.exe.sha256` and
`ForgeSetup.build.json`, in an empty folder, and nothing else. The build record
is operator evidence about the artifact: it carries no clock and no path.

DETERMINISM, stated exactly. The executable is a function of the payload's
bytes and times (its identity), of the script, of the generated includes, of
the pinned compiler tree and of the pinned image; this script reads no clock,
mounts every input at a fixed path inside the container and gives the compiler
a fixed environment. CI builds it twice from two checkouts and compares the
bytes. Not established: any other compiler tree, any other image, and any
property of the Windows loader or a scanner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "scripts" / "windows_installer", ROOT / "scripts", ROOT / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import build_nsis_toolchain as toolchain  # noqa: E402
import build_windows_bundle as bundle  # noqa: E402
import installer_contract as contract  # noqa: E402

from nornyx_forge.windows_payload import (  # noqa: E402
    PAYLOAD_MANIFEST,
    PayloadError,
    read_manifest,
    verify,
)

INSTALLER_DIR = "scripts/windows_installer"
TOOLCHAIN_PATH = f"{INSTALLER_DIR}/nsis-toolchain.json"
LOCK_PATH = f"{INSTALLER_DIR}/nsis-build-debs.json"
NSI_PATH = f"{INSTALLER_DIR}/{contract.NSI_NAME}"
RECORD_SCHEMA = "nornyx.forge.windows_installer_build.v2"
#: Each file's raw bytes must equal the commit's blob (line endings
#: normalized), which no index flag or clean filter can hide. The two modules
#: are imported by this script, and the two pin files decide the compiler.
INSTALLER_FILES = ("scripts/build_windows_installer.py", NSI_PATH, TOOLCHAIN_PATH, LOCK_PATH,
                   f"{INSTALLER_DIR}/installer_contract.py",
                   f"{INSTALLER_DIR}/build_nsis_toolchain.py")
OUTPUT_NAMES = ("ForgeSetup.exe", "ForgeSetup.exe.sha256", "ForgeSetup.build.json")
#: What the payload builder writes outside the copy set. Each is compared byte
#: for byte with what the commit's own writers render.
GENERATED_FILES = ("Forge.cmd", "forge-bundle.json")
#: What no check compares with the commit: the dependency closure and the
#: interpreter (whose path file the payload builder rewrites). They are held by
#: the payload's identity, the lock digest and the interpreter archive digest.
UNCOMPARED_ROOTS = ("pylib", "python")
#: Where the container sees each input. The script, the includes and the
#: payload are read-only; the output folder is the one writable mount.
STAGE_MOUNT, PAYLOAD_MOUNT, OUT_MOUNT = "/stage", "/payload", "/out"
COMPILER = f"/nsis/{toolchain.COMPILER}"
#: What the installer launches and verifies with. A payload without these
#: installs and cannot start.
REQUIRED_ENTRIES = (
    "python/python.exe", "python/pythonw.exe", "forge-bundle.json", "Forge.cmd",
    "src/nornyx_forge/__init__.py", "src/nornyx_forge/windows_launch.py",
    "src/nornyx_forge/windows_payload.py",
)
#: NSIS refuses an installer of 2 GiB or more.
MAX_INSTALLER_BYTES = (1 << 31) - 1


class InstallerError(Exception):
    """A build input or state this script refuses."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _runner(run: Callable | None) -> Callable:
    """The one way a child is started: the toolchain's, unless a test gives another."""
    return run or toolchain._run_child


# ---------------------------------------------------------------------------
# The pinned compiler
# ---------------------------------------------------------------------------

def load_toolchain_pins(pins_blob: bytes, lock_blob: bytes) -> dict:
    """The toolchain pins as the commit holds them, refused unless complete,
    consistent with their lock, and with the outputs pinned: an installer is
    never compiled with a compiler tree nothing names."""
    try:
        pins, lock = json.loads(pins_blob.decode("utf-8")), json.loads(lock_blob.decode("utf-8"))
        toolchain.check_pins(pins, lock)
    except ValueError as error:
        raise InstallerError(f"{TOOLCHAIN_PATH} or {LOCK_PATH} is not JSON: {error}") from None
    except toolchain.ToolchainError as error:
        raise InstallerError(f"{TOOLCHAIN_PATH} is refused: {error}") from None
    if pins["container"]["lock"] != LOCK_PATH.rsplit("/", 1)[1]:
        raise InstallerError(f"{TOOLCHAIN_PATH} names the lock {pins['container']['lock']!r}, "
                             f"not {LOCK_PATH}")
    if pins["outputs"] is None:
        raise InstallerError(f"{TOOLCHAIN_PATH} pins no outputs, so no compiler tree can be "
                             "checked against them; an installer is not built with an unpinned one")
    return pins


def mount_source(path: Path) -> Path:
    """A host path as docker is given it: resolved. What docker cannot mount
    (a relative path, a `:` on a POSIX host) is refused by `compiler_argv`, the
    one container definition."""
    return path.resolve()


def _compiler_argv(pins: dict, **arguments) -> list[str]:
    try:
        return toolchain.compiler_argv(pins, **arguments)
    except toolchain.ToolchainError as error:
        raise InstallerError(str(error)) from None


def check_toolchain(pins: dict, tree: Path, *, run: Callable | None = None) -> dict:
    """The compiler that will run is the pinned one: the tree's compiler and
    tree digest must equal the pinned outputs (`check_tree`, which refuses a
    link, a pipe, a device or a set-id file anywhere in it), and the compiler,
    run in the pinned image, must report the pinned version exactly. Returns
    the facts the build record carries."""
    tree = mount_source(tree)
    try:
        toolchain.check_tree(tree, pins)
    except toolchain.ToolchainError as error:
        raise InstallerError(f"the compiler tree {tree} is refused: {error}") from None
    completed = _runner(run)(
        _compiler_argv(pins, tree=tree, mounts=[], command=[COMPILER, "-VERSION"],
                       epoch=pins["build"]["source_date_epoch"]),
        capture_output=True, timeout=120)
    reported = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or reported != pins["build"]["version_output"]:
        raise InstallerError(f"makensis reports {reported!r}, not "
                             f"{pins['build']['version_output']!r}")
    return {"name": "makensis", "version_output": reported,
            "makensis_sha256": pins["outputs"]["makensis_sha256"],
            "data_tree_sha256": pins["outputs"]["data_tree_sha256"],
            "image": pins["container"]["image"],
            "source": {key: pins["source"][key] for key in ("version", "sha256")}}


# ---------------------------------------------------------------------------
# The payload
# ---------------------------------------------------------------------------

def check_times(payload: Path, epoch: int) -> None:
    """Every file and folder, the root included, carries the commit's time."""
    wanted = epoch * 1_000_000_000
    for directory, subdirectories, files in os.walk(payload):
        for name in [*files, *subdirectories, ""]:
            path = Path(directory) / name if name else Path(directory)
            if os.lstat(path).st_mtime_ns != wanted:
                raise InstallerError(f"{path} does not carry the commit's time {epoch}: the "
                                     "installer stores each file's time, so a payload that was "
                                     "copied or touched would change its bytes")


def check_payload(repo_root: Path, commit: str, payload: Path) -> dict:
    """The payload folder verified and tied to this commit; returns its
    manifest. Verified against its own identity, then each field the commit
    decides is recomputed from the commit and compared."""
    try:
        manifest = read_manifest(payload)
        verify(payload, expected_payload_sha256=manifest["payload_sha256"])
    except PayloadError as error:
        raise InstallerError(f"the payload does not verify: {error}") from None
    pins = bundle.load_pins(repo_root, commit)
    lock = bundle.load_lock(repo_root, commit, pins)
    expected = {
        "source_commit": commit,
        "lock_sha256": hashlib.sha256(lock).hexdigest(),
        "installer": {"name": pins["installer"]["name"], "version": pins["installer"]["version"]},
        "interpreter": {key: pins["interpreter"][key]
                        for key in ("version", "archive_url", "archive_sha256")},
        "target": f"{pins['target']['abi']}-{pins['target']['wheel_platform']}",
        "source_date_epoch": bundle.source_date_epoch(repo_root, commit),
    }
    for key, value in expected.items():
        if manifest[key] != value:
            raise InstallerError(f"the payload's {key} is {manifest[key]!r}, but this commit "
                                 f"says {value!r}: it is not this commit's payload")
    listed = {entry[0] for entry in manifest["files"]}
    if missing := [name for name in REQUIRED_ENTRIES if name not in listed]:
        raise InstallerError(f"the payload lacks {missing}, which the installer starts and "
                             "verifies with")
    check_generated(manifest, commit, pins)
    check_times(payload, manifest["source_date_epoch"])
    return manifest


def expected_generated(commit: str, pins: dict) -> dict[str, bytes]:
    """The bytes the commit's payload builder writes for `GENERATED_FILES`,
    rendered by its own writers into a scratch folder."""
    with tempfile.TemporaryDirectory(prefix="forge-generated-") as name:
        folder = Path(name)
        bundle.write_bundle_marker(folder, mode=bundle.SELF_CONTAINED,
                                   interpreter_sha256=pins["interpreter"]["archive_sha256"],
                                   source_commit=commit)
        bundle.write_launcher(folder, bundle.SELF_CONTAINED)
        return {file: (folder / file).read_bytes() for file in GENERATED_FILES}


def check_generated(manifest: dict, commit: str, pins: dict) -> None:
    """Each generated file the payload carries (its manifest entry, which the
    payload verified against) is the one the commit's builder writes."""
    entries = {entry[0]: entry for entry in manifest["files"]}
    for file, data in expected_generated(commit, pins).items():
        entry = entries.get(file)
        if entry is None or entry[1] != len(data) or entry[2] != hashlib.sha256(data).hexdigest():
            raise InstallerError(f"the payload's {file} is not the one this commit's payload "
                                 "builder writes")


def uncompared_names(manifest: dict, *, synthetic: bool) -> list[str]:
    """The top-level names of the payload that no check compares with the
    commit, derived from the payload itself. For a commit payload these may only
    be `UNCOMPARED_ROOTS`, and any top-level name that is neither compared nor
    one of those is refused; for a synthetic payload the copy set is not
    compared either, so every top-level name but the generated files is listed."""
    tops = sorted({entry[0].split("/", 1)[0] for entry in manifest["files"]})
    if synthetic:
        return [name for name in tops if name not in GENERATED_FILES]
    compared = set(bundle.bundle_manifest()) | set(GENERATED_FILES)
    if unknown := [name for name in tops if name not in compared
                   and name not in UNCOMPARED_ROOTS]:
        raise InstallerError(f"the payload holds {unknown} at its top, which the payload "
                             "builder does not write and nothing here would compare")
    return [name for name in tops if name in UNCOMPARED_ROOTS]


def check_copy_set(repo_root: Path, commit: str, manifest: dict) -> None:
    """The payload's copy of the repository IS the commit's: every tracked
    file of the copy set (`BUNDLE_TREE`, minus the excluded names) is in the
    payload with the commit's bytes, the payload holds no other file under
    those roots, and the payload's version is `pyproject.toml`'s at the
    commit. What this does NOT compare: `pylib/` and `python/`, which the
    commit cannot reproduce without the network; they are held by the payload's
    own identity, the lock digest and the interpreter archive digest the
    manifest records and `check_payload` compares."""
    roots = bundle.bundle_manifest()
    listing = bundle._git(repo_root, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *roots)
    paths, objects = [], []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        path = raw_path.decode("utf-8", "surrogateescape")
        if bundle.EXCLUDED_NAMES.intersection(path.split("/")):
            continue
        paths.append(path)
        objects.append(meta.split(b" ")[2])
    committed = {path: (len(data), hashlib.sha256(data).hexdigest())
                 for path, data in zip(paths, bundle._read_blobs(repo_root, objects))}
    payload = {entry[0]: (entry[1], entry[2]) for entry in manifest["files"]
               if any(entry[0] == root or entry[0].startswith(root + "/") for root in roots)}
    problems = [f"missing: {path}" for path in committed if path not in payload]
    problems += [f"changed: {path}" for path in committed
                 if path in payload and payload[path] != committed[path]]
    problems += [f"not in the commit: {path}" for path in payload if path not in committed]
    if problems:
        problems.sort()
        raise InstallerError(f"the payload's copy of the repository is not the commit's: "
                             f"{'; '.join(problems[:20])}"
                             + (f"; and {len(problems) - 20} more" if len(problems) > 20 else ""))
    pyproject = bundle.tomllib.loads(
        bundle._git_blob(repo_root, commit, "pyproject.toml").decode("utf-8"))
    if pyproject["project"]["version"] != manifest["version"]:
        raise InstallerError(f"the payload's version is {manifest['version']!r}, but the "
                             f"commit's pyproject.toml says {pyproject['project']['version']!r}")


def vi_version(version: str) -> str:
    """VIProductVersion takes four numbers: the first three of the version,
    then 0. A version without three leading numbers is 0.0.0.0 (the full
    version is in the ProductVersion string)."""
    match = re.match(r"(\d{1,5})\.(\d{1,5})\.(\d{1,5})", version)
    if match is None or any(int(part) > 65535 for part in match.groups()):
        return "0.0.0.0"
    return ".".join(match.groups()) + ".0"


def longest_relative(manifest: dict) -> int:
    """The longest relative path the installer extracts, in UTF-16 code units
    (Windows' unit): the manifest's entries and the manifest itself."""
    paths = [entry[0] for entry in manifest["files"]] + [PAYLOAD_MANIFEST]
    return max(len(path.encode("utf-16-le")) // 2 for path in paths)


def longest_directory(manifest: dict) -> int:
    """The longest relative folder path the installer creates (0 for the
    payload root), in UTF-16 code units: every folder that holds an entry."""
    folders = [entry[0].rpartition("/")[0] for entry in manifest["files"]]
    return max(len(folder.encode("utf-16-le")) // 2 for folder in folders)


# ---------------------------------------------------------------------------
# Staging, compiling, checking
# ---------------------------------------------------------------------------

def stage(scratch: Path, nsi: bytes, manifest: dict) -> Path:
    """The script and the two generated includes, in a fresh folder. The
    includes name the payload where the container mounts it."""
    stage_dir = scratch / "stage"
    stage_dir.mkdir()
    (stage_dir / contract.NSI_NAME).write_bytes(nsi)
    try:
        (stage_dir / "files.nsh").write_text(
            contract.files_nsh(manifest["files"], PAYLOAD_MOUNT, manifest_name=PAYLOAD_MANIFEST),
            encoding="utf-8", newline="")
        (stage_dir / "receipt.nsh").write_text(contract.receipt_nsh(manifest),
                                               encoding="utf-8", newline="")
    except contract.ContractError as error:
        raise InstallerError(str(error)) from None
    return stage_dir


def compile_installer(pins: dict, tree: Path, stage_dir: Path, payload: Path, out_dir: Path,
                      manifest: dict, *, run: Callable | None = None) -> int:
    """Run `makensis` in the pinned image over the staged script and the
    payload, both read-only, into `out_dir`, the one writable mount; returns
    how many warnings it printed (every form NSIS 3.13 prints, as the
    toolchain counts them). A non-zero exit is a refusal that carries the
    compiler's own words."""
    defines = {
        "VERSION": manifest["version"], "COMMIT12": manifest["source_commit"][:12],
        "PAYLOAD_SHA256": manifest["payload_sha256"],
        "LONGEST_RELATIVE": str(longest_relative(manifest)),
        "LONGEST_DIRECTORY": str(longest_directory(manifest)),
        "VI_VERSION": vi_version(manifest["version"]), "STAGE_DIR": STAGE_MOUNT,
        "OUT_FILE": f"{OUT_MOUNT}/ForgeSetup.exe",
    }
    command = [COMPILER, "-NOCONFIG", "-NOCD", "-INPUTCHARSET", "UTF8", "-V2",
               *(f"-D{name}={value}" for name, value in defines.items()),
               f"{STAGE_MOUNT}/{contract.NSI_NAME}"]
    argv = _compiler_argv(
        pins, tree=mount_source(tree),
        mounts=[(mount_source(stage_dir), STAGE_MOUNT, True),
                (mount_source(payload), PAYLOAD_MOUNT, True),
                (mount_source(out_dir), OUT_MOUNT, False)],
        command=command, epoch=manifest["source_date_epoch"])
    completed = _runner(run)(argv, capture_output=True, timeout=3600)
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if completed.returncode != 0:
        raise InstallerError(f"makensis exited {completed.returncode}:\n{text[-4000:]}")
    warnings = count_warnings(text)
    if warnings:
        print(text[-4000:], file=sys.stderr)
    return warnings


_INLINE_WARNING = re.compile(r"^\s*warning\b", re.IGNORECASE | re.MULTILINE)
_WARNING_SUMMARY = re.compile(r"^(\d+) warnings?:\s*$", re.IGNORECASE | re.MULTILINE)


def count_warnings(text: str) -> int:
    """How many warnings the compiler printed, each counted once. NSIS can
    print a warning where it occurs (`warning: ...`, `warning <code>: ...`) and
    again under a closing summary (`N warning(s):` and an indented list). When
    the summary is there its N is the count, and the lines printed where they
    occurred may not number more than N; with no summary the count is those
    lines. Two summaries, or more warning lines than the summary says, is output
    this does not read, and is refused instead of guessed at."""
    inline = len(_INLINE_WARNING.findall(text))
    summaries = [int(number) for number in _WARNING_SUMMARY.findall(text)]
    if len(summaries) > 1:
        raise InstallerError(f"makensis printed {len(summaries)} warning summaries")
    if summaries and inline > summaries[0]:
        raise InstallerError(f"makensis printed {inline} warnings where they occurred but its "
                             f"summary says {summaries[0]}")
    return summaries[0] if summaries else inline


def take_output(out_dir: Path) -> Path:
    """What the container wrote is read as untrusted: the folder must hold
    exactly `ForgeSetup.exe`, a regular file found by lstat (not a link, which
    could point anywhere on the host)."""
    names = sorted(os.listdir(out_dir))
    if names != ["ForgeSetup.exe"]:
        raise InstallerError(f"the compiler's output folder holds {names}, not exactly "
                             "['ForgeSetup.exe']")
    built = out_dir / "ForgeSetup.exe"
    if not stat.S_ISREG(os.lstat(built).st_mode):
        raise InstallerError("the compiler's ForgeSetup.exe is not a regular file")
    return built


def check_executable(path: Path, manifest: dict) -> None:
    """The built file is a PE that asks for no privilege and carries the
    payload's identity in its version-information resource."""
    size = path.stat().st_size
    if not 0 < size <= MAX_INSTALLER_BYTES:
        raise InstallerError(f"{path.name} is {size} bytes; NSIS installers stay under 2 GiB")
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if data[:2] != b"MZ":
            raise InstallerError(f"{path.name} does not start with MZ")
        header = int.from_bytes(data[0x3C:0x40], "little")
        if data[header:header + 4] != b"PE\0\0":
            raise InstallerError(f"{path.name} has no PE signature where its header says")
        if data.find(b'<requestedExecutionLevel level="asInvoker" uiAccess="false"/>') < 0:
            raise InstallerError(f"{path.name} does not carry an asInvoker manifest")
        for refused in (b"requireAdministrator", b"highestAvailable", b'uiAccess="true"'):
            if data.find(refused) >= 0:
                raise InstallerError(f"{path.name} contains {refused.decode()}")
        for label, needle in (
                ("version", f"{manifest['version']}+{manifest['source_commit'][:12]}"),
                ("payload identity", f"payload sha256 {manifest['payload_sha256']}")):
            if data.find(needle.encode("utf-16-le")) < 0:
                raise InstallerError(f"{path.name} does not carry its {label} ({needle}) in "
                                     "its version information")


def build(repo_root: Path, payload: Path, out_dir: Path, *, nsis_tree: Path,
          synthetic: bool = False, run: Callable | None = None) -> dict:
    """The whole build; returns the build record it wrote. `nsis_tree` is the
    compiler tree the toolchain built (the folder holding `Bin/makensis`).
    `synthetic` is the explicit TEST-ONLY path for the tiny sealed payloads
    that exercise the installer's refusals: it skips the comparison of the
    payload's copy of the repository with the commit (those payloads are not a
    copy of it), and the record says so in `payload_kind`."""
    payload = payload.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise InstallerError(f"{out_dir} already holds files; an installer is built into an "
                             "empty folder")
    try:
        commit = bundle.require_clean_commit(repo_root)
    except bundle.BundleError as error:
        raise InstallerError(str(error)) from None
    blobs = {}
    for name in INSTALLER_FILES:
        working = repo_root.joinpath(*name.split("/")).read_bytes().replace(b"\r\n", b"\n")
        blobs[name] = bundle._git_blob(repo_root, commit, name)
        if working != blobs[name]:
            raise InstallerError(f"{name} is not the file {commit} holds, although git status "
                                 "may not show it: the build runs only the committed script")
    pins = load_toolchain_pins(blobs[TOOLCHAIN_PATH], blobs[LOCK_PATH])
    manifest = check_payload(repo_root, commit, payload)
    uncompared = uncompared_names(manifest, synthetic=synthetic)
    if not synthetic:
        check_copy_set(repo_root, commit, manifest)
    toolchain_facts = check_toolchain(pins, nsis_tree, run=run)
    with tempfile.TemporaryDirectory(prefix="forge-setup-") as scratch_name:
        scratch = Path(scratch_name)
        stage_dir = stage(scratch, blobs[NSI_PATH], manifest)
        compiled = scratch / "out"
        compiled.mkdir()
        if not hasattr(os, "getuid"):
            os.chmod(compiled, 0o777)
        warnings = compile_installer(pins, nsis_tree, stage_dir, payload, compiled, manifest,
                                     run=run)
        built = take_output(compiled)
        check_executable(built, manifest)
        digest = _sha256(built)
        record = {
            "schema": RECORD_SCHEMA,
            "installer": {"file": "ForgeSetup.exe", "sha256": digest,
                          "size": built.stat().st_size},
            "payload": {"sha256": manifest["payload_sha256"], "version": manifest["version"],
                        "source_commit": manifest["source_commit"],
                        "files": len(manifest["files"]) + 1,
                        "payload_kind": "synthetic-test-payload" if synthetic else "commit-payload",
                        "compared_with_the_commit": (
                            [*GENERATED_FILES, "lock digest", "installer and interpreter pins",
                             "target", "time"]
                            if synthetic else
                            ["every copy-set file's bytes", "the set of copy-set files",
                             *GENERATED_FILES, "version", "lock digest",
                             "installer and interpreter pins", "target", "time"]),
                        "not_compared_with_the_commit": uncompared},
            "inputs": {name: hashlib.sha1(  # noqa: S324 - git's blob id, not a security claim
                b"blob %d\0" % len(blob) + blob).hexdigest() for name, blob in blobs.items()},
            "tool": toolchain_facts,
            "host": {"image_os": os.environ.get("ImageOS"),
                     "image_version": os.environ.get("ImageVersion")},
            "makensis_warnings": warnings,
            "note": ("Operator evidence about one artifact. It binds the executable's digest to "
                     "the payload identity, the commit, the script and the compiler tree and "
                     "image that made it; it is not governance evidence and not a signature."),
        }
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(built, out_dir / "ForgeSetup.exe")
    (out_dir / "ForgeSetup.exe.sha256").write_text(f"{digest}  ForgeSetup.exe\n",
                                                   encoding="utf-8", newline="")
    (out_dir / "ForgeSetup.build.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--payload", type=Path, required=True,
                        help="the folder build_windows_bundle.py made from this commit")
    parser.add_argument("--out", type=Path, required=True, help="an empty or absent folder")
    parser.add_argument("--nsis-tree", type=Path, required=True,
                        help="the compiler tree build_nsis_toolchain.py built (holds Bin/makensis)")
    parser.add_argument("--test-only-synthetic", action="store_true",
                        help="the payload is a tiny sealed test payload, not a copy of this "
                             "commit's repository; the build record says so")
    arguments = parser.parse_args(argv)
    try:
        record = build(ROOT, arguments.payload, arguments.out, nsis_tree=arguments.nsis_tree,
                       synthetic=arguments.test_only_synthetic)
    except InstallerError as error:
        print(f"installer refused: {error}", file=sys.stderr)
        return 1
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"installer could not run what it needs: {error!r}", file=sys.stderr)
        return 1
    print(f"installer {record['installer']['sha256']}: {record['installer']['size']} bytes, "
          f"payload {record['payload']['sha256']}, {record['makensis_warnings']} warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
