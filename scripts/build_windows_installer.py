"""Build ForgeSetup.exe from a verified Windows payload, with a pinned NSIS.

`scripts/build_windows_bundle.py` makes the payload folder; this script wraps
that folder, unchanged, in the installer `scripts/windows_installer/forge-setup.nsi`
describes. Nothing here installs or runs anything on the build machine except
`makensis`, and nothing is downloaded: CI fetches the two Ubuntu packages named
in `installer-tools.json` by their pinned hashes before this script runs.

WHAT THE BUILD REFUSES, before any executable exists:

* a tree that is not a clean commit, and a builder, script, contract or pin
  file whose bytes differ from the commit's (as the payload builder does);
* a payload folder that does not verify against its own manifest, or whose
  manifest is not this commit's: the source commit, the lock's digest, the
  installer and the interpreter must each equal what the commit pins, and every
  copy-set file (the repository's own files in the payload) and the version
  must equal the commit's. `pylib/` and `python/` are NOT compared with
  anything the commit holds; the payload's identity, the lock digest and the
  interpreter archive digest are what hold them. The tiny test payloads of
  CI's refusal checks are built through `--test-only-synthetic`, which skips
  the copy-set comparison and says so in the build record;
* a payload whose files and folders do not all carry the commit's time (the
  installer stores each file's time, so a disturbed copy would change the
  bytes);
* a payload without the files the installer launches and verifies with;
* a `makensis` whose binary or whose data directory (stubs, plug-ins,
  includes) is not the pinned one, or that does not report the pinned version.

WHAT IT CHECKS AFTER, on the executable: a PE with an `asInvoker` manifest and
no `requireAdministrator`, `highestAvailable` or `uiAccess="true"`, and with the
version, commit and payload identity in its version-information resource, so
the identity the installer verifies against is the one the build record names.

WHAT THE OUTPUT IS: `ForgeSetup.exe`, `ForgeSetup.exe.sha256` and
`ForgeSetup.build.json`, in an empty folder, and nothing else. The build record
is operator evidence about the artifact: it carries no clock and no path.

DETERMINISM, stated exactly. The executable is a function of the payload's
bytes and times (its identity), of the script, of the generated includes, and
of the pinned `makensis`; this script reads no clock and passes `makensis` a
fixed environment. CI builds it twice from two checkouts and compares the
bytes. Not established: any other `makensis`, any other image, and any
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
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "scripts" / "windows_installer", ROOT / "scripts", ROOT / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import build_windows_bundle as bundle  # noqa: E402
import installer_contract as contract  # noqa: E402

from nornyx_forge.windows_payload import (  # noqa: E402
    PAYLOAD_MANIFEST,
    PayloadError,
    read_manifest,
    verify,
)

INSTALLER_DIR = "scripts/windows_installer"
TOOLS_PATH = f"{INSTALLER_DIR}/installer-tools.json"
NSI_PATH = f"{INSTALLER_DIR}/{contract.NSI_NAME}"
TOOLS_SCHEMA = "nornyx.forge.windows_installer_tools.v1"
RECORD_SCHEMA = "nornyx.forge.windows_installer_build.v1"
#: Each file's raw bytes must equal the commit's blob (line endings
#: normalized), which no index flag or clean filter can hide.
INSTALLER_FILES = ("scripts/build_windows_installer.py", NSI_PATH, TOOLS_PATH,
                   f"{INSTALLER_DIR}/installer_contract.py")
OUTPUT_NAMES = ("ForgeSetup.exe", "ForgeSetup.exe.sha256", "ForgeSetup.build.json")
#: What the installer launches and verifies with. A payload without these
#: installs and cannot start.
REQUIRED_ENTRIES = (
    "python/python.exe", "python/pythonw.exe", "forge-bundle.json", "Forge.cmd",
    "src/nornyx_forge/__init__.py", "src/nornyx_forge/windows_launch.py",
    "src/nornyx_forge/windows_payload.py",
)
#: NSIS refuses an installer of 2 GiB or more.
MAX_INSTALLER_BYTES = (1 << 31) - 1
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PACKAGE_FIELDS = {"name", "architecture", "version", "url", "size", "sha256"}


class InstallerError(Exception):
    """A build input or state this script refuses."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# The pinned tool
# ---------------------------------------------------------------------------

def check_tools(tools: object) -> dict:
    """The tool pins, refused unless complete and well-formed."""
    try:
        if tools["schema"] != TOOLS_SCHEMA:
            raise InstallerError(f"{TOOLS_PATH} has schema {tools['schema']!r}")
        makensis = tools["makensis"]
        packages = makensis["packages"]
        fields = [tools["builder_image"], makensis["version_output"], makensis["binary_sha256"],
                  makensis["data_tree_sha256"], makensis["archive_suite"]]
    except (KeyError, TypeError) as error:
        raise InstallerError(f"{TOOLS_PATH} is not a complete pin set: {error}") from None
    if not all(isinstance(field, str) and field for field in fields):
        raise InstallerError(f"{TOOLS_PATH} pins an empty or non-string value")
    if not (_HEX64.fullmatch(makensis["binary_sha256"])
            and _HEX64.fullmatch(makensis["data_tree_sha256"])):
        raise InstallerError(f"{TOOLS_PATH} pins a binary or tree digest that is not a SHA-256")
    if not (isinstance(packages, list) and packages and all(
            isinstance(p, dict) and set(p) == _PACKAGE_FIELDS for p in packages)):
        raise InstallerError(f"{TOOLS_PATH} does not pin its packages as exact entries")
    for package in packages:
        if not (_HEX64.fullmatch(str(package["sha256"])) and isinstance(package["size"], int)
                and package["size"] > 0
                and str(package["url"]).startswith("https://archive.ubuntu.com/ubuntu/pool/")
                and str(package["url"]).endswith(".deb")
                and package["url"].rsplit("/", 1)[1].startswith(
                    f"{package['name']}_{package['version']}_")):
            raise InstallerError(f"{TOOLS_PATH} pins the package {package.get('name')!r} "
                                 "without a pool URL that names it, its size and its SHA-256")
    return tools


def tree_digest(root: Path) -> str:
    """One digest for a directory tree: every regular file's relative path and
    SHA-256 in byte order. A link, or anything that is not a regular file or a
    folder, is refused: the tool's data directory holds none."""
    lines = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories.sort()
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise InstallerError(f"{path} is not a regular file")
            relative = path.relative_to(root).as_posix()
            lines.append(f"{relative}\0{_sha256(path)}\n")
        for name in subdirectories:
            if (Path(directory) / name).is_symlink():
                raise InstallerError(f"{Path(directory) / name} is a link")
    lines.sort(key=lambda line: line.encode("utf-8"))
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def check_toolchain(tools: dict, makensis: str, nsis_dir: Path) -> dict:
    """The `makensis` that will run is the pinned one: the binary's SHA-256,
    the data directory's tree digest, and the version it reports. Returns the
    facts the build record carries."""
    pins = tools["makensis"]
    resolved = shutil.which(makensis)
    if resolved is None:
        raise InstallerError(f"{makensis} is not on PATH; CI installs the pinned packages "
                             f"named in {TOOLS_PATH}")
    binary = _sha256(Path(resolved).resolve())
    if binary != pins["binary_sha256"]:
        raise InstallerError(f"{resolved} has SHA-256 {binary}, not the pinned "
                             f"{pins['binary_sha256']}")
    if not nsis_dir.is_dir():
        raise InstallerError(f"{nsis_dir} is not a directory")
    tree = tree_digest(nsis_dir)
    if tree != pins["data_tree_sha256"]:
        raise InstallerError(f"{nsis_dir} has tree digest {tree}, not the pinned "
                             f"{pins['data_tree_sha256']}")
    completed = subprocess.run([resolved, "-VERSION"], capture_output=True, timeout=60,
                               env=_makensis_environment(nsis_dir, 0))
    reported = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or pins["version_output"] not in reported:
        raise InstallerError(f"makensis reports {reported!r}, not a version containing "
                             f"{pins['version_output']!r}")
    return {"name": "makensis", "version_output": reported, "binary_sha256": binary,
            "data_tree_sha256": tree,
            "packages": [{key: package[key] for key in ("name", "version", "sha256")}
                         for package in pins["packages"]]}


def _makensis_environment(home: Path, epoch: int) -> dict[str, str]:
    """A fixed environment: nothing of the caller's reaches the compiler but
    the search path."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "HOME": str(home), "SOURCE_DATE_EPOCH": str(epoch)}


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
    check_times(payload, manifest["source_date_epoch"])
    return manifest


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

def stage(scratch: Path, nsi: bytes, manifest: dict, payload: Path) -> Path:
    """The script and the two generated includes, in a fresh folder."""
    stage_dir = scratch / "stage"
    stage_dir.mkdir()
    (stage_dir / contract.NSI_NAME).write_bytes(nsi)
    try:
        (stage_dir / "files.nsh").write_text(
            contract.files_nsh(manifest["files"], payload, manifest_name=PAYLOAD_MANIFEST),
            encoding="utf-8", newline="")
        (stage_dir / "receipt.nsh").write_text(contract.receipt_nsh(manifest),
                                               encoding="utf-8", newline="")
    except contract.ContractError as error:
        raise InstallerError(str(error)) from None
    return stage_dir


def compile_installer(makensis: str, stage_dir: Path, out_file: Path, manifest: dict,
                      nsis_dir: Path) -> int:
    """Run `makensis`; returns how many warnings it printed. A non-zero exit
    is a refusal that carries the compiler's own words."""
    defines = {
        "VERSION": manifest["version"], "COMMIT12": manifest["source_commit"][:12],
        "PAYLOAD_SHA256": manifest["payload_sha256"],
        "LONGEST_RELATIVE": str(longest_relative(manifest)),
        "LONGEST_DIRECTORY": str(longest_directory(manifest)),
        "VI_VERSION": vi_version(manifest["version"]), "STAGE_DIR": stage_dir.as_posix(),
        "OUT_FILE": out_file.as_posix(),
    }
    command = [makensis, "-NOCONFIG", "-NOCD", "-INPUTCHARSET", "UTF8", "-V2",
               *(f"-D{name}={value}" for name, value in defines.items()),
               str(stage_dir / contract.NSI_NAME)]
    completed = subprocess.run(command, capture_output=True, timeout=3600,
                               env=_makensis_environment(stage_dir, manifest["source_date_epoch"]))
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if completed.returncode != 0 or not out_file.is_file():
        raise InstallerError(f"makensis exited {completed.returncode}:\n{text[-4000:]}")
    warnings = [line for line in text.splitlines() if re.match(r"\s*warning:", line, re.I)]
    for line in warnings:
        print(line, file=sys.stderr)
    return len(warnings)


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


def build(repo_root: Path, payload: Path, out_dir: Path, *, makensis: str = "makensis",
          nsis_dir: Path = Path("/usr/share/nsis"), synthetic: bool = False) -> dict:
    """The whole build; returns the build record it wrote. `synthetic` is the
    explicit TEST-ONLY path for the tiny sealed payloads that exercise the
    installer's refusals: it skips the comparison of the payload's copy of the
    repository with the commit (those payloads are not a copy of it), and the
    record says so in `payload_kind`."""
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
    try:
        tools = check_tools(json.loads(blobs[TOOLS_PATH].decode("utf-8")))
    except ValueError as error:
        raise InstallerError(f"{TOOLS_PATH} is not JSON: {error}") from None
    manifest = check_payload(repo_root, commit, payload)
    if not synthetic:
        check_copy_set(repo_root, commit, manifest)
    toolchain = check_toolchain(tools, makensis, nsis_dir)
    with tempfile.TemporaryDirectory(prefix="forge-setup-") as scratch_name:
        scratch = Path(scratch_name)
        stage_dir = stage(scratch, blobs[NSI_PATH], manifest, payload)
        built = scratch / "ForgeSetup.exe"
        warnings = compile_installer(makensis, stage_dir, built, manifest, nsis_dir)
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
                            ["lock digest", "installer and interpreter pins", "target", "time"]
                            if synthetic else
                            ["every copy-set file's bytes", "the set of copy-set files",
                             "version", "lock digest", "installer and interpreter pins",
                             "target", "time"]),
                        "not_compared_with_the_commit": (
                            ["the copy set", "pylib", "python"] if synthetic
                            else ["pylib", "python"])},
            "inputs": {name: hashlib.sha1(  # noqa: S324 - git's blob id, not a security claim
                b"blob %d\0" % len(blob) + blob).hexdigest() for name, blob in blobs.items()},
            "tool": toolchain,
            "host": {"image_os": os.environ.get("ImageOS"),
                     "image_version": os.environ.get("ImageVersion")},
            "makensis_warnings": warnings,
            "note": ("Operator evidence about one artifact. It binds the executable's digest to "
                     "the payload identity, the commit, the script and the tool that made it; "
                     "it is not governance evidence and not a signature."),
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
    parser.add_argument("--makensis", default="makensis")
    parser.add_argument("--nsis-dir", type=Path, default=Path("/usr/share/nsis"))
    parser.add_argument("--test-only-synthetic", action="store_true",
                        help="the payload is a tiny sealed test payload, not a copy of this "
                             "commit's repository; the build record says so")
    arguments = parser.parse_args(argv)
    try:
        record = build(ROOT, arguments.payload, arguments.out, makensis=arguments.makensis,
                       nsis_dir=arguments.nsis_dir, synthetic=arguments.test_only_synthetic)
    except InstallerError as error:
        print(f"installer refused: {error}", file=sys.stderr)
        return 1
    print(f"installer {record['installer']['sha256']}: {record['installer']['size']} bytes, "
          f"payload {record['payload']['sha256']}, {record['makensis_warnings']} warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
