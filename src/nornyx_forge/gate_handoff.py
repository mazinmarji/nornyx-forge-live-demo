"""Forge's side of the run-act gate's boundary: writing a run's read-only input
stage, importing a released output set, verifying it statically, and issuing
the produced-application manifest for a gated build (A-055).

WHAT THIS IS, AND WHAT IT IS NOT. Data handling only. Nothing here creates an
account, changes an access-control list or a right, logs anyone on, starts or
impersonates a process for a provider, or touches a virtual machine; and
nothing here starts the gate (that is `provider_gate`, A-052) or changes its
bytes or its pin. The directories it is given -- the role's input zone, the
gate's release directory, the verification root -- are provisioned by acts
outside Forge, and their access rules are those acts'; Forge reads and writes
what it is given and judges what it finds.

THE INPUT STAGE (`stage_inputs`). For one role, one stage: a new directory
`s<16 hex>` in the role's input zone holding only what Forge rendered -- the
BRD, the generated contract and the runtime operation contract rendered from
it, the requirements artefacts, Forge's instructions to the provider, and, for
a repair run or one that reads an earlier run's output, the workspace of a
passed import -- written as new files, read back, and described by a stage manifest of exactly what was
written. The stage is refused unless the role's zone is empty: at most one
stage per role, and a stage left by an earlier cycle, whatever its state, is
the act's to remove, never Forge's. The intent is recorded in Forge's records
directory before anything is written; a failure after it leaves the stage
REJECTED and retained, with its reason recorded, and nothing is removed.

THE IMPORT (`import_release`). The gate's release is untrusted input. It is
imported only if every check passes, in this order, before anything is
written: the release directory is a plain directory named for the cycle; it
holds exactly the manifest, the optional release record and one plain file per
manifest row -- no directory, link, junction, hard link or named data stream;
the manifest's SHA-256 is the digest the act cites; every row's bytes have its
size and digest; every name is one spelling of one file (`gate_release_model`);
the workspace's completeness list names exactly the other workspace files;
and Forge's own credential pattern (`IMPORT_PATTERN`, Forge-owned and never
a caller's choice) finds nothing in any byte released -- a known false
positive of that pattern included, which refuses the import until an approved
correction is effective. Then
the intent is recorded in a FRESH destination, every file is written new and
read back, the release is re-listed to show it did not change, the
destination is enumerated to show it holds exactly what was written, and only
then is the import record written. A destination with an intent and no record
is INCOMPLETE and is never read as an import (`load_import`); a new import
needs a new, absent destination.

STATIC VERIFICATION (`verify_import_static`). The trusted verifier runs in its
static-only mode over the imported workspace: every static gate, and the
subject's tests NOT run, so no produced code executes. Its test gate fails by
construction, so this is never an acceptance.

THE MANIFEST (`issue_gate_manifest`). For a passed import that verified
statically, Forge renders the produced-application manifest with its
`gate_provenance`: the cycle, the pinned run-act digest, the stage, release
and import digests, the completeness list, the pattern used and the cited
check result. The handoff gate never offers such a manifest.

NAMED DATA STREAMS. On NTFS a file may carry streams a content digest does not
cover; every item judged here is enumerated by stream on Windows and any
stream but the default refuses. Off Windows there are none to enumerate.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .capsule import CapsuleValidationError
from .contract_generator import render_brd_contract, render_runtime_contract
from .experience_journey import scope_binding
from .gate_release_model import (
    COMPLETENESS_LIST,
    CYCLE_ID,
    IMPORT_INTENT_SCHEMA,
    IMPORT_PATTERN,
    ROLE,
    STAGE_INTENT_SCHEMA,
    STAGE_REJECTION_SCHEMA,
    GateReleaseRefused,
    ReleaseLayout,
    collision_problems,
    completeness_problems,
    credential_hits,
    gate_provenance,
    name_problem,
    parse_completeness_list,
    parse_release_manifest,
    render_import_record,
    render_intent,
    render_stage_manifest,
    sha256_text,
    strict_json,
    validate_import_record,
    validate_stage_manifest,
    workspace_path_of,
)
from .gates import (
    GREENFIELD_PROFILE_DIGEST,
    GREENFIELD_PROFILE_ID,
    GREENFIELD_STATIC_ONLY_DETAIL,
    GREENFIELD_STATIC_ONLY_MODE,
    trusted_greenfield_gates,
)
from .produced_app_handoff import (
    IGNORED_DIRECTORIES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    STDLIB,
    ManifestIssue,
    brd_text_digest,
    read_held,
    rendered_contract_digest,
    rendered_runtime_contract_digest,
)
from .produced_app_manifest import render_pam, static_findings, subject_digest
from .provider_contract import governed_build_eligibility
from .provider_gate import PINNED_RUN_ACT_SHA256
from .requirements import parse_brd, render_requirements_json, render_traceability

#: Where each rendered input sits in a stage.
STAGE_BRD = "BRD.md"
STAGE_CONTRACT = "contract/brd_contract.nyx"
STAGE_RUNTIME_CONTRACT = "contract/runtime-contract.json"
STAGE_REQUIREMENTS = "requirements/requirements.json"
STAGE_TRACEABILITY = "requirements/traceability.md"
STAGE_INSTRUCTIONS = "INSTRUCTIONS.md"
STAGE_VERIFIED = "verified"

#: The destination of an import: its intent, its record, the workspace and
#: the gate's other items, and nothing else.
IMPORT_INTENT = "import-intent.json"
IMPORT_RECORD = "import-record.json"
IMPORT_WORKSPACE = "workspace"
IMPORT_ITEMS = "items"

#: Forge's instructions to a provider in a gated run: what it reads, what it
#: writes, and the completeness list the import holds it to.
PROVIDER_INSTRUCTIONS = f"""# Instructions for this run

Read your inputs from this directory; it is read-only. Write only in your own
run directory, as your workspace.

1. Build the application the BRD (`BRD.md`) describes: a package `app/` run as
   `python -m app`, using the Python standard library only, with its tests in
   `tests/` (files `tests/test_*.py`). Respect `contract/runtime-contract.json`:
   every state-changing operation goes through it, and an operation it does not
   permit is refused.
2. Copy `BRD.md` to the root of your workspace unchanged.
3. Leave only UTF-8 text files in your workspace. Remove every cache
   (`__pycache__`, `.pytest_cache` and the like), every virtual environment,
   every link and every empty directory before you finish. Do not create `.git`
   or `.nornyx`. Use only ASCII letters, digits, `.`, `_` and `-` in names.
4. Last, write `{COMPLETENESS_LIST}` at the root of your workspace: every OTHER
   file you leave there, one relative path per line with `/` separators, each
   line ending in a line feed. Do not list `{COMPLETENESS_LIST}` itself.

Your output is imported only if that list names exactly the files released,
and only if no released byte matches a credential pattern. Never write a
credential, a key or a token into any file.
"""

#: Reserved at any depth in an imported workspace: everything the trusted
#: verifier never inspects, so nothing unverified enters the verification root.
RESERVED_DIRECTORIES = frozenset(IGNORED_DIRECTORIES)

_RELEASE_READ_LIMIT = 4_000_000


# ---------------------------------------------------------------------------
# Judging what is on disk, without following anything
# ---------------------------------------------------------------------------

def _reparse(status: os.stat_result) -> bool:
    return bool(getattr(status, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _plain_directory(path: Path) -> str | None:
    """Why `path` is not a plain directory (no link, junction or other
    reparse point, no named stream), or None."""
    try:
        status = os.lstat(path)
    except OSError as error:
        return f"cannot be inspected ({error.strerror or error})"
    if stat.S_ISLNK(status.st_mode) or _reparse(status) or not stat.S_ISDIR(status.st_mode):
        return "is not a plain directory (a link, junction or other reparse point, or a file)"
    streams = named_streams(path)
    if streams is None:
        return "cannot be enumerated for named data streams"
    if streams:
        return "carries a named data stream"
    return None


def _plain_file(path: Path) -> tuple[os.stat_result | None, str | None]:
    """The status of `path` if it is one plain file with one name and no named
    stream, or why not."""
    try:
        status = os.lstat(path)
    except OSError as error:
        return None, f"cannot be inspected ({error.strerror or error})"
    if stat.S_ISLNK(status.st_mode) or _reparse(status):
        return None, "is a link or another reparse point"
    if not stat.S_ISREG(status.st_mode):
        return None, "is not a regular file"
    if status.st_nlink != 1:
        return None, "has more than one name (a hard link)"
    streams = named_streams(path)
    if streams is None:
        return None, "cannot be enumerated for named data streams"
    if streams:
        return None, "carries a named data stream"
    return status, None


def named_streams(path: Path) -> list[str] | None:
    """The named data streams of `path` -- every stream but the default
    `::$DATA` -- or None when they cannot be enumerated. Windows only; off
    Windows a file has no named streams and the answer is an empty list."""
    if os.name != "nt":
        return []
    import ctypes  # noqa: PLC0415 - Windows only
    from ctypes import wintypes  # noqa: PLC0415

    class _StreamData(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong),
                    ("cStreamName", ctypes.c_wchar * (260 + 36))]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.FindFirstStreamW.restype = wintypes.HANDLE
    kernel32.FindFirstStreamW.argtypes = (wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD)
    kernel32.FindNextStreamW.restype = wintypes.BOOL
    kernel32.FindNextStreamW.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
    kernel32.FindClose.argtypes = (wintypes.HANDLE,)
    data = _StreamData()
    handle = kernel32.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    invalid = wintypes.HANDLE(-1).value
    if handle is None or handle == invalid:
        # ERROR_HANDLE_EOF: the item has no stream at all (a directory).
        return [] if ctypes.get_last_error() == 38 else None
    names: list[str] = []
    try:
        while True:
            if data.cStreamName != "::$DATA":
                names.append(data.cStreamName)
            if not kernel32.FindNextStreamW(handle, ctypes.byref(data)):
                return names if ctypes.get_last_error() == 38 else None
    finally:
        kernel32.FindClose(handle)


def _tree(root: Path) -> tuple[dict[str, Path], list[str]]:
    """Every file under `root` by relative POSIX path, walked without following
    anything; the problems are every entry that is not a plain directory or a
    plain file with one name and no named stream, and every empty directory
    below `root`, which nothing Forge writes holds."""
    files: dict[str, Path] = {}
    problems: list[str] = []
    pending = [(root, "")]
    while pending:
        here, prefix = pending.pop()
        try:
            with os.scandir(here) as entries:
                names = sorted(entry.name for entry in entries)
        except OSError as error:
            problems.append(f"{prefix or '.'} cannot be listed ({error.strerror or error})")
            continue
        if prefix and not names:
            problems.append(f"{prefix.rstrip('/')} is an empty directory, which nothing "
                            "written holds")
        for name in names:
            relative = f"{prefix}{name}"
            path = here / name
            try:
                status = os.lstat(path)
            except OSError as error:
                problems.append(f"{relative} cannot be inspected ({error.strerror or error})")
                continue
            if stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode):
                problem = _plain_directory(path)
                if problem:
                    problems.append(f"{relative} {problem}")
                else:
                    pending.append((path, relative + "/"))
                continue
            _, problem = _plain_file(path)
            if problem:
                problems.append(f"{relative} {problem}")
            else:
                files[relative] = path
    return files, problems


def _write_new(path: Path, data: bytes) -> None:
    """Create `path` -- never an existing name, never through a link -- and
    write `data` to it, flushed to the disk."""
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new_tree(root: Path, files: Mapping[str, bytes]) -> None:
    """Write every file under `root` (which this call creates), creating each
    directory once and every file new."""
    os.mkdir(root)
    made = {""}
    for relative in sorted(files):
        parts = relative.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            if directory not in made:
                os.mkdir(root.joinpath(*parts[:depth]))
                made.add(directory)
        _write_new(root.joinpath(*parts), files[relative])


def _readback_problems(root: Path, files: Mapping[str, bytes]) -> list[str]:
    """`root` holds exactly `files`, each a plain file with these bytes."""
    found, problems = _tree(root)
    for relative in sorted(set(found) - set(files)):
        problems.append(f"{relative} is present and was not written")
    for relative in sorted(set(files) - set(found)):
        problems.append(f"{relative} was written and is not present")
    for relative in sorted(set(files) & set(found)):
        data, problem = read_held(found[relative], limit=max(len(files[relative]), 1))
        if data is None:
            problems.append(f"{relative} {problem}")
        elif data != files[relative]:
            problems.append(f"{relative} does not hold the bytes written")
    return problems


def _ancestor_identities(path: Path) -> set[tuple[int, int]]:
    """The identities of `path` and every ancestor, by its spelling and by its
    resolved location, so a link or junction on the way is not a way around."""
    identities: set[tuple[int, int]] = set()
    for start in (os.path.abspath(path), os.path.realpath(path)):
        current = Path(start)
        while True:
            try:
                status = os.lstat(current)
                identities.add((status.st_dev, status.st_ino))
            except OSError:
                pass
            if current.parent == current:
                break
            current = current.parent
    return identities


# ---------------------------------------------------------------------------
# The input stage
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StageOutcome:
    """What `stage_inputs` did. `WRITTEN` with a manifest; `REFUSED` with
    nothing written; `REJECTED` when a failure came after the intent was
    recorded -- the stage, if any of it was written, is retained."""

    state: str
    stage: str | None
    manifest: str | None
    reasons: tuple[str, ...]

    @property
    def manifest_digest(self) -> str | None:
        return None if self.manifest is None else sha256_text(self.manifest.encode("utf-8"))


def _render_inputs(brd: bytes, instructions: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    """The rendered stage files, from the BRD's bytes, and their sources."""
    with tempfile.TemporaryDirectory(prefix="nornyx-forge-stage-") as scratch:
        root = Path(scratch)
        (root / "BRD.md").write_bytes(brd)
        model = parse_brd(root / "BRD.md")
    files = {
        STAGE_BRD: brd,
        STAGE_CONTRACT: render_brd_contract(model).encode("utf-8"),
        STAGE_RUNTIME_CONTRACT: render_runtime_contract(model).encode("utf-8"),
        STAGE_REQUIREMENTS: render_requirements_json(model).encode("utf-8"),
        STAGE_TRACEABILITY: render_traceability(model).encode("utf-8"),
        STAGE_INSTRUCTIONS: instructions.encode("utf-8"),
    }
    sources = {
        "brd": sha256_text(files[STAGE_BRD]),
        "generated_contract": sha256_text(files[STAGE_CONTRACT]),
        "runtime_contract": sha256_text(files[STAGE_RUNTIME_CONTRACT]),
        "requirements": sha256_text(files[STAGE_REQUIREMENTS]),
        "instructions": sha256_text(files[STAGE_INSTRUCTIONS]),
        "verified_import": None,
    }
    return files, sources


def stage_inputs(
    workspace: Path,
    zone: Path,
    records: Path,
    *,
    role: str,
    verified: Path | None = None,
    instructions: str = PROVIDER_INSTRUCTIONS,
) -> StageOutcome:
    """Write one stage for `role` into `zone` (the role's input zone, named
    for the role) from the Forge workspace `workspace`, and its intent and
    manifest into Forge's `records` directory. `verified` is the destination
    of a passed import whose workspace a later run reads."""

    def refuse(reason: str) -> StageOutcome:
        return StageOutcome("REFUSED", None, None, (reason,))

    if not isinstance(role, str) or not ROLE.match(role):
        return refuse("the role is not a letter followed by up to 63 letters, digits or "
                      "underscores")
    zone, records, workspace = Path(zone), Path(records), Path(workspace)
    if zone.name != role:
        return refuse(f"the input zone is named {zone.name!r}, not for the role {role!r}")
    for label, directory in (("input zone", zone), ("records directory", records),
                             ("workspace", workspace)):
        problem = _plain_directory(directory)
        if problem:
            return refuse(f"the {label} {problem}")
    try:
        with os.scandir(zone) as entries:
            present = sorted(entry.name for entry in entries)
    except OSError as error:
        return refuse(f"the input zone cannot be listed ({error.strerror or error})")
    if present:
        return refuse("the role's input zone is not empty: at most one stage per role, and "
                      "a stage left by an earlier cycle is the act's to remove, not Forge's")
    zone_status = os.lstat(zone)
    if (zone_status.st_dev, zone_status.st_ino) in _ancestor_identities(records):
        return refuse("the records directory is inside the input zone")

    brd, problem = read_held(workspace / "BRD.md")
    if brd is None:
        return refuse(f"the workspace's BRD.md {problem}")
    try:
        files, sources = _render_inputs(brd, instructions)
    except (OSError, UnicodeError, ValueError) as error:
        return refuse(f"Forge could not render the inputs from the BRD: {error}")
    if verified is not None:
        loaded = load_import(verified)
        if loaded.state != "COMPLETE":
            return refuse("the verified import is not a complete import: "
                          + "; ".join(loaded.reasons))
        for path, data in loaded.workspace_files.items():
            files[f"{STAGE_VERIFIED}/{path}"] = data
        sources["verified_import"] = loaded.record_digest
    if len(files) > MAX_FILES or sum(len(data) for data in files.values()) > MAX_TOTAL_BYTES:
        return refuse("the stage exceeds the subject's file or byte bound")

    name = "s" + secrets.token_hex(8)
    listing = {path: (len(data), sha256_text(data)) for path, data in files.items()}
    intent = render_intent(STAGE_INTENT_SCHEMA, {
        "role": role, "stage": name,
        "files": {path: digest for path, (_, digest) in sorted(listing.items())},
    })
    intent_path = records / f"{name}.intent.json"
    try:
        _write_new(intent_path, intent.encode("utf-8"))
    except OSError as error:
        return refuse(f"the intent could not be recorded ({error.strerror or error}); "
                      "nothing was written")
    readback, problem = read_held(intent_path)
    if readback != intent.encode("utf-8"):
        return _rejected(records, role, name,
                         [f"the recorded intent did not read back ({problem or 'differs'})"])

    stage_dir = zone / name
    try:
        _write_new_tree(stage_dir, files)
    except OSError as error:
        return _rejected(records, role, name,
                         [f"the stage could not be written ({error.strerror or error})"])
    problems = _readback_problems(stage_dir, files)
    try:
        with os.scandir(zone) as entries:
            if sorted(entry.name for entry in entries) != [name]:
                problems.append("the input zone holds something besides the stage")
    except OSError as error:
        problems.append(f"the input zone cannot be listed ({error.strerror or error})")
    if problems:
        return _rejected(records, role, name, problems)
    try:
        manifest = render_stage_manifest(role=role, stage=name, files=listing, sources=sources)
        _write_new(records / f"{name}.manifest.json", manifest.encode("utf-8"))
    except (OSError, GateReleaseRefused) as error:
        return _rejected(records, role, name, [f"the stage manifest could not be recorded: "
                                               f"{error}"])
    readback, problem = read_held(records / f"{name}.manifest.json")
    if readback != manifest.encode("utf-8"):
        return _rejected(records, role, name,
                         [f"the stage manifest did not read back ({problem or 'differs'})"])
    return StageOutcome("WRITTEN", name, manifest, ())


def _rejected(records: Path, role: str, name: str, problems: list[str]) -> StageOutcome:
    """A failure after the intent: the stage is retained, never removed, and
    its rejection is recorded if it can be."""
    reasons = tuple(problems)
    try:
        _write_new(records / f"{name}.rejected.json", render_intent(
            STAGE_REJECTION_SCHEMA, {"role": role, "stage": name, "reasons": list(reasons)},
        ).encode("utf-8"))
    except OSError as error:
        reasons += (f"the rejection could not be recorded ({error.strerror or error})",)
    return StageOutcome("REJECTED", name, None, reasons)


def verify_stage(zone: Path, manifest: str) -> list[str]:
    """Whether `zone` holds exactly the stage `manifest` describes: one entry,
    the stage, holding exactly its files with their digests, each a plain file
    with one name and no named stream. Reads only; empty means it does."""
    try:
        document = validate_stage_manifest(manifest)
    except GateReleaseRefused as error:
        return [f"the stage manifest is refused: {error}"]
    zone = Path(zone)
    if zone.name != document["role"]:
        return [f"the input zone is not the zone of role {document['role']!r}"]
    problem = _plain_directory(zone)
    if problem:
        return [f"the input zone {problem}"]
    try:
        with os.scandir(zone) as entries:
            present = sorted(entry.name for entry in entries)
    except OSError as error:
        return [f"the input zone cannot be listed ({error.strerror or error})"]
    if present != [document["stage"]]:
        return ["the input zone does not hold exactly the one stage the manifest names"]
    stage_dir = zone / document["stage"]
    problem = _plain_directory(stage_dir)
    if problem:
        return [f"the stage {problem}"]
    found, problems = _tree(stage_dir)
    listed = document["files"]
    problems += [f"{path} is in the stage and not in its manifest"
                 for path in sorted(set(found) - set(listed))]
    problems += [f"{path} is in the manifest and not in the stage"
                 for path in sorted(set(listed) - set(found))]
    for path in sorted(set(found) & set(listed)):
        data, reason = read_held(found[path])
        if data is None:
            problems.append(f"{path} {reason}")
        elif len(data) != listed[path]["size"] or sha256_text(data) != listed[path]["digest"]:
            problems.append(f"{path} does not have the digest its manifest lists")
    return problems


# ---------------------------------------------------------------------------
# The import
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ImportOutcome:
    """What an import did, or what `load_import` found. `COMPLETE` with a
    record; `REFUSED` with nothing written; `INCOMPLETE` when a failure came
    after the intent -- the destination is then unusable, never an import."""

    state: str
    destination: Path | None
    record: str | None
    reasons: tuple[str, ...]
    workspace_files: Mapping[str, bytes] = field(default_factory=dict)

    @property
    def record_digest(self) -> str | None:
        return None if self.record is None else sha256_text(self.record.encode("utf-8"))


def _snapshot(release: Path) -> tuple[dict[str, tuple[int, int, int, int]], list[str]]:
    """Each entry of the flat release directory by name, with the identity it
    had -- device, file, size and modification time -- and every entry that is
    not a plain file with one name and no named stream."""
    entries: dict[str, tuple[int, int, int, int]] = {}
    problems: list[str] = []
    try:
        with os.scandir(release) as listing:
            names = sorted(entry.name for entry in listing)
    except OSError as error:
        return {}, [f"the release cannot be listed ({error.strerror or error})"]
    for name in names:
        status, problem = _plain_file(release / name)
        if status is None:
            problems.append(f"the released entry {name!r} {problem}")
            continue
        entries[name] = (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)
    return entries, problems


def import_release(
    release: Path,
    destination: Path,
    *,
    cycle_id: str,
    layout: ReleaseLayout,
    expected_manifest_sha256: str,
) -> ImportOutcome:
    """Import the release at `release` into the fresh `destination`, or refuse.

    `expected_manifest_sha256` is the release manifest's digest as the act
    cites it from the gate's journal: 64 lower-case hex. The credential
    pattern is `IMPORT_PATTERN`; there is no way to pass another.
    """
    pattern = IMPORT_PATTERN
    release, destination = Path(release), Path(destination)

    def refuse(*reasons: str) -> ImportOutcome:
        return ImportOutcome("REFUSED", None, None, tuple(reasons))

    if not isinstance(cycle_id, str) or not CYCLE_ID.match(cycle_id):
        return refuse("the cycle id is not one plain name")
    if not isinstance(layout, ReleaseLayout):
        return refuse("the layout is not one this model built")
    if (not isinstance(expected_manifest_sha256, str) or len(expected_manifest_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_manifest_sha256)):
        return refuse("the cited release-manifest digest is not 64 lower-case hex")
    if os.path.basename(os.path.normpath(str(release))) != cycle_id:
        return refuse("the release directory is not named for the cycle")
    problem = _plain_directory(release)
    if problem:
        return refuse(f"the release directory {problem}")
    parent_problem = _plain_directory(destination.parent)
    if parent_problem:
        return refuse(f"the destination's parent {parent_problem}")
    if os.path.lexists(destination):
        return refuse("the destination exists; an import is made only into a fresh, absent "
                      "destination")
    release_status = os.lstat(release)
    if (release_status.st_dev, release_status.st_ino) in _ancestor_identities(destination.parent):
        return refuse("the destination is inside the release")

    before, problems = _snapshot(release)
    if problems:
        return refuse(*problems)
    folded: dict[str, str] = {}
    for name in before:
        if name.casefold() in folded:
            return refuse(f"the released entries {name!r} and {folded[name.casefold()]!r} "
                          "differ only in case")
        folded[name.casefold()] = name
    if layout.manifest_name not in before:
        return refuse("the release holds no manifest")
    if layout.record_name is not None and layout.record_name not in before:
        return refuse("the release holds no release record")

    def read(name: str, limit: int) -> tuple[bytes | None, str]:
        data, reason = read_held(release / name, limit=limit)
        if data is None:
            return None, f"the released entry {name!r} {reason}"
        return data, ""

    manifest_bytes, reason = read(layout.manifest_name, _RELEASE_READ_LIMIT)
    if manifest_bytes is None:
        return refuse(reason)
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
        return refuse("the release manifest is not the manifest the act cites")
    try:
        rows = parse_release_manifest(manifest_bytes, layout)
    except GateReleaseRefused as error:
        return refuse(str(error))
    expected_entries = {row.id for row in rows} | set(layout.reserved_entries())
    extra = sorted(set(before) - expected_entries)
    missing = sorted(expected_entries - set(before))
    if extra or missing:
        return refuse(*[f"the released entry {name!r} is not in the manifest" for name in extra],
                      *[f"the manifest's item {name!r} was not released" for name in missing])

    record_bytes = None
    if layout.record_name is not None:
        record_bytes, reason = read(layout.record_name, _RELEASE_READ_LIMIT)
        if record_bytes is None:
            return refuse(reason)

    problems = []
    hits = []
    workspace: dict[str, bytes] = {}
    gate_items: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []
    total = 0
    for row in rows:
        problem = name_problem(row.name, layout, RESERVED_DIRECTORIES)
        if problem:
            problems.append(f"item {row.id}: its name {problem}")
            continue
        data, reason = read(row.id, MAX_FILE_BYTES)
        if data is None:
            problems.append(reason)
            continue
        total += len(data)
        if len(data) != row.size or hashlib.sha256(data).hexdigest() != row.digest:
            problems.append(f"item {row.id} does not have the size and digest its row lists")
            continue
        if credential_hits(data, pattern):
            hits.append(row.id)
        path = workspace_path_of(row.name, layout)
        if path is None:
            gate_items[row.id] = data
            entries.append({"id": row.id, "name": row.name, "kind": "gate_item",
                            "path": row.id, "size": len(data), "digest": sha256_text(data)})
        else:
            workspace[path] = data
            entries.append({"id": row.id, "name": row.name, "kind": "workspace",
                            "path": path, "size": len(data), "digest": sha256_text(data)})
    if total > MAX_TOTAL_BYTES or len(workspace) > MAX_FILES:
        problems.append("the release exceeds the subject's file or byte bound")
    for label, data in (("the release manifest", manifest_bytes),
                        ("the release record", record_bytes)):
        if data is not None and credential_hits(data, pattern):
            hits.append(label)
    if hits:
        problems.append(f"Forge's credential pattern {pattern.id!r} matches in "
                        f"{len(hits)} released item(s): {', '.join(hits[:20])}; a hit "
                        "refuses the import, whatever its cause")
    problems += collision_problems(workspace)
    listing = workspace.get(COMPLETENESS_LIST)
    if listing is None:
        problems.append(f"the workspace holds no {COMPLETENESS_LIST}")
    else:
        try:
            problems += completeness_problems(parse_completeness_list(listing), workspace)
        except GateReleaseRefused as error:
            problems.append(str(error))
    if problems:
        return refuse(*problems)

    after, problems = _snapshot(release)
    if problems or after != before:
        return refuse("the release changed while it was read", *problems)

    # ----- nothing has been written before this line; the intent is first ---
    intent = render_intent(IMPORT_INTENT_SCHEMA, {
        "cycle_id": cycle_id, "release_manifest": sha256_text(manifest_bytes),
        "credential_pattern": pattern.record(),
    })
    try:
        os.mkdir(destination)
    except OSError as error:
        return refuse(f"the destination could not be created ({error.strerror or error})")
    try:
        _write_new(destination / IMPORT_INTENT, intent.encode("utf-8"))
    except OSError as error:
        return _incomplete(destination, f"the intent could not be recorded ({error})")
    written = {IMPORT_INTENT: intent.encode("utf-8")}
    written.update({f"{IMPORT_WORKSPACE}/{path}": data for path, data in workspace.items()})
    written.update({f"{IMPORT_ITEMS}/{ident}": data for ident, data in gate_items.items()})
    try:
        _write_new_tree(destination / IMPORT_WORKSPACE, workspace)
        if gate_items:
            _write_new_tree(destination / IMPORT_ITEMS, gate_items)
    except OSError as error:
        return _incomplete(destination, f"the import could not be written ({error})")
    problems = _readback_problems(destination, written)
    after, changed = _snapshot(release)
    if changed or after != before:
        problems.append("the release changed while it was imported")
    if problems:
        return _incomplete(destination, *problems)
    try:
        record = render_import_record(
            cycle_id=cycle_id,
            release_manifest_digest=sha256_text(manifest_bytes),
            release_record_digest=None if record_bytes is None else sha256_text(record_bytes),
            completeness_list_digest=sha256_text(listing),
            items=entries,
            workspace_subject_digest=subject_digest(
                {path: sha256_text(data) for path, data in workspace.items()}),
        )
        _write_new(destination / IMPORT_RECORD, record.encode("utf-8"))
    except (OSError, GateReleaseRefused) as error:
        return _incomplete(destination, f"the import record could not be written: {error}")
    return load_import(destination)


def _incomplete(destination: Path, *reasons: str) -> ImportOutcome:
    return ImportOutcome("INCOMPLETE", destination, None, tuple(reasons) + (
        "the destination is unusable: an intent without a record is never an import, and a "
        "new import needs a fresh, absent destination",))


def load_import(destination: Path) -> ImportOutcome:
    """Read a destination back as an import, re-verifying everything: the
    record, its intent, and every file on disk against the record. A
    destination with an intent and no record is INCOMPLETE."""
    destination = Path(destination)

    def refused(state: str, *reasons: str) -> ImportOutcome:
        return ImportOutcome(state, destination, None, tuple(reasons))

    problem = _plain_directory(destination)
    if problem:
        return refused("REFUSED", f"the destination {problem}")
    intent_present = os.path.lexists(destination / IMPORT_INTENT)
    if not os.path.lexists(destination / IMPORT_RECORD):
        if intent_present:
            return refused("INCOMPLETE", "the import's intent is recorded and its record is "
                           "not: the import did not complete, and the destination is unusable")
        return refused("REFUSED", "the destination is not an import")
    raw, reason = read_held(destination / IMPORT_RECORD, limit=_RELEASE_READ_LIMIT)
    intent_raw, intent_reason = read_held(destination / IMPORT_INTENT, limit=_RELEASE_READ_LIMIT)
    if raw is None or intent_raw is None:
        return refused("REFUSED", f"the import record {reason or intent_reason}")
    try:
        text = raw.decode("utf-8")
        document = validate_import_record(text)
        intent = strict_json(intent_raw.decode("utf-8"))
    except (UnicodeError, ValueError, GateReleaseRefused) as error:
        return refused("REFUSED", f"the import record is refused: {error}")
    if (not isinstance(intent, dict) or intent.get("schema") != IMPORT_INTENT_SCHEMA
            or intent.get("cycle_id") != document["cycle_id"]
            or intent.get("release_manifest") != document["release_manifest"]
            or intent.get("credential_pattern") != document["credential_pattern"]):
        return refused("REFUSED", "the import record does not agree with its intent")
    expected: dict[str, str] = {IMPORT_INTENT: sha256_text(intent_raw),
                                IMPORT_RECORD: sha256_text(raw)}
    for item in document["items"]:
        where = IMPORT_WORKSPACE if item["kind"] == "workspace" else IMPORT_ITEMS
        expected[f"{where}/{item['path']}"] = item["digest"]
    found, problems = _tree(destination)
    problems += [f"{path} is in the destination and not in its record"
                 for path in sorted(set(found) - set(expected))]
    problems += [f"{path} is in the record and not in the destination"
                 for path in sorted(set(expected) - set(found))]
    workspace: dict[str, bytes] = {}
    for path in sorted(set(found) & set(expected)):
        data, reason = read_held(found[path])
        if data is None:
            problems.append(f"{path} {reason}")
            continue
        if sha256_text(data) != expected[path]:
            problems.append(f"{path} has changed since it was imported")
        if path.startswith(IMPORT_WORKSPACE + "/"):
            workspace[path[len(IMPORT_WORKSPACE) + 1:]] = data
    if not problems and subject_digest(
            {path: sha256_text(data) for path, data in workspace.items()}
    ) != document["workspace_subject_digest"]:
        problems.append("the workspace is not the subject the record names")
    if problems:
        return refused("REFUSED", *problems)
    return ImportOutcome("COMPLETE", destination, text, (), workspace)


# ---------------------------------------------------------------------------
# Static verification, and the manifest
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StaticVerification:
    """The trusted verifier's static-only result over an imported workspace.
    `passed` means every static gate passed; its tests were not run."""

    passed: bool
    findings: tuple[str, ...]
    provenance: Mapping[str, Any]


def verify_import_static(destination: Path, *,
                         runner=trusted_greenfield_gates) -> StaticVerification:
    """Run the trusted verifier in its static-only mode over the workspace of
    the complete import at `destination`. `runner` exists for unit tests."""
    loaded = load_import(destination)
    if loaded.state != "COMPLETE":
        return StaticVerification(False, ("the import is not complete: "
                                          + "; ".join(loaded.reasons),), {})
    workspace = Path(destination) / IMPORT_WORKSPACE
    results, provenance = runner(workspace, static_only=True)
    findings: list[str] = []
    names = [result.name for result in results]
    if "greenfield:test-execution" not in names:
        findings.append("the verifier did not return its gates: "
                        + "; ".join(result.detail for result in results)[:600])
    for result in results:
        if result.name == "greenfield:test-execution":
            if result.passed or result.detail != GREENFIELD_STATIC_ONLY_DETAIL:
                findings.append("the test gate is not the static-only record")
        elif not result.passed:
            findings.append(f"{result.name}: {result.detail}")
    test_execution = provenance.get("test_execution") if isinstance(provenance, Mapping) else None
    if not isinstance(test_execution, Mapping) or test_execution.get(
            "mode") != GREENFIELD_STATIC_ONLY_MODE:
        findings.append("the verifier's record is not a static-only record")
    subject = provenance.get("subject") if isinstance(provenance, Mapping) else None
    record = validate_import_record(loaded.record)
    if (not isinstance(subject, Mapping)
            or subject.get("digest") != record["workspace_subject_digest"]
            or subject.get("root") != str(workspace.resolve())):
        findings.append("the verifier did not inspect the subject the import recorded")
    return StaticVerification(not findings, tuple(findings), provenance)


def issue_gate_manifest(
    *,
    destination: Path,
    store_root: Path,
    document: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    sealed_revision: str,
    platform: str,
    stage_manifest: str,
    verification: StaticVerification,
    run_act_sha256: str,
    check_d3g_result: str,
) -> ManifestIssue:
    """Render the manifest of a gated build, or say why none is issued.

    `document` and `lifecycle` are the capsule and lifecycle Forge sealed; the
    caller persists the text with `CapsuleStore.save_produced_application`.
    Nothing here writes. `run_act_sha256` must be the pinned gate digest and
    `check_d3g_result` is the act's cited check digest, recorded as cited.
    """
    findings: list[str] = []
    loaded = load_import(destination)
    if loaded.state != "COMPLETE":
        return ManifestIssue(None, ("the import is not complete: " + "; ".join(loaded.reasons),))
    record = validate_import_record(loaded.record)
    if not verification.passed:
        findings.append("the imported workspace did not verify statically: "
                        + "; ".join(verification.findings)[:600])
    subject = verification.provenance.get("subject") if verification.passed else None
    if verification.passed and (not isinstance(subject, Mapping) or subject.get(
            "digest") != record["workspace_subject_digest"]):
        findings.append("the static verification is of another subject")
    if run_act_sha256 != PINNED_RUN_ACT_SHA256:
        findings.append("the run-act digest is not the gate's pinned digest")
    if not isinstance(check_d3g_result, str) or not check_d3g_result.startswith("sha256:"):
        findings.append("the cited check result is not a sha256 digest")
    try:
        stage = validate_stage_manifest(stage_manifest)
    except GateReleaseRefused as error:
        return ManifestIssue(None, (f"the stage manifest is refused: {error}",))
    files = dict(loaded.workspace_files)
    store_directory = Path(store_root).resolve().name
    if any(path.split("/")[0] == store_directory for path in files):
        findings.append("the imported workspace holds a directory named for the store")
    brd = files.get("BRD.md")
    if brd is None:
        return ManifestIssue(None, tuple(findings) + ("BRD.md is not in the imported workspace",))
    if sha256_text(brd) != stage["sources"]["brd"]:
        findings.append("the BRD the provider returned is not the BRD it was given")
    try:
        contract = rendered_contract_digest(brd)
        runtime_contract = rendered_runtime_contract_digest(brd)
    except (OSError, UnicodeError, ValueError) as error:
        return ManifestIssue(None, (f"Forge could not render the contracts: {error}",))
    if contract != stage["sources"]["generated_contract"] or (
            runtime_contract != stage["sources"]["runtime_contract"]):
        findings.append("the contracts rendered from the returned BRD are not the staged ones")
    findings.extend(static_findings(files, store_directory=store_directory, stdlib=STDLIB))
    bound = scope_binding(lifecycle, "BUILD")
    chain = document.get("digest_chain") if isinstance(document, Mapping) else None
    tip = chain[-1] if isinstance(chain, list) and chain else None
    if bound is None:
        findings.append("the lifecycle records no scope binding for this build")
    elif bound[0] != tip:
        findings.append("the scope binding names another capsule than the one sealed")
    elif brd_text_digest(brd) != bound[1]:
        findings.append("the BRD the provider returned is not the BRD the scope "
                        "confirmation bound")
    provider = (document.get("authoritative", {}).get("provider") or {}).get("name") \
        if isinstance(document, Mapping) else None
    if not isinstance(provider, str):
        findings.append("the sealed capsule names no confirmed provider")
    if findings:
        return ManifestIssue(None, tuple(findings))
    verifier = verification.provenance.get("verifier") or {}
    try:
        provenance = gate_provenance(
            cycle_id=record["cycle_id"],
            run_act_sha256=run_act_sha256,
            stage_manifest=sha256_text(stage_manifest.encode("utf-8")),
            release_manifest=record["release_manifest"],
            import_record=loaded.record_digest,
            completeness_list=record["completeness_list"],
            check_d3g_result=check_d3g_result,
            credential_pattern=record["credential_pattern"],
        )
        text = render_pam(
            files={path: sha256_text(data) for path, data in files.items()},
            accepted_subject_digest=record["workspace_subject_digest"],
            store_directory=store_directory,
            generated_contract_digest=contract,
            brd_scope_binding=f"capsule/{bound[0]}/brd/{bound[1]}",
            capsule_chain_tip=tip,
            sealed_revision=sealed_revision,
            provider=provider,
            eligibility=governed_build_eligibility(provider, platform).as_dict(),
            verifier_digest=verifier.get("digest"),
            gate_profile={"id": GREENFIELD_PROFILE_ID, "digest": GREENFIELD_PROFILE_DIGEST},
            forge_version=verifier.get("forge_version"),
            forge_revision=verifier.get("forge_revision"),
            runtime_contract_digest=runtime_contract,
            gate_provenance=provenance,
        )
    except (CapsuleValidationError, GateReleaseRefused) as error:
        return ManifestIssue(None, (str(error),))
    return ManifestIssue(text, ())


__all__ = [
    "IMPORT_INTENT",
    "IMPORT_ITEMS",
    "IMPORT_RECORD",
    "IMPORT_WORKSPACE",
    "ImportOutcome",
    "PROVIDER_INSTRUCTIONS",
    "RESERVED_DIRECTORIES",
    "StageOutcome",
    "StaticVerification",
    "import_release",
    "issue_gate_manifest",
    "load_import",
    "named_streams",
    "stage_inputs",
    "verify_import_static",
    "verify_stage",
]
