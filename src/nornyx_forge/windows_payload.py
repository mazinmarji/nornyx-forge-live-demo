"""The Windows payload manifest: what a built folder holds, and whether a copy
of it still holds exactly that.

`forge-payload.json` at the folder's root lists every payload file as
`[relative path, size, sha256]`, sorted by the path's UTF-8 bytes, together
with the source commit, the commit's time (`source_date_epoch`), the target,
the dependency lock's digest, the installer and the interpreter archive.
`payload_sha256` is the SHA-256 of the canonical JSON of everything else in
the manifest, and it is the payload's identity.

WHAT `verify` ESTABLISHES, AND WHAT IT DOES NOT. It walks the folder and
refuses, by name: a listed file that is missing, has another size or other
bytes; a file the manifest does not list, wherever it sits (bytecode under
`__pycache__` included: nothing is exempt); an empty directory; a link, a
reparse point or a hard link, the root and the manifest included; anything
that is neither a regular file nor a directory; a name the payload's name
rule refuses (`check_name`, `check_names`); and a manifest that is malformed
or whose `payload_sha256` is not the digest of its own content. Given an
expected identity, it also refuses a folder with any other identity. So a
folder that verifies holds exactly the listed files, byte for byte, in no
directory that holds nothing. Not covered: file modes, modification times
and NTFS alternate data streams. Every file is opened with `O_NOFOLLOW` where
the platform has it (POSIX) and `O_NONBLOCK`, and checked by device and inode,
everywhere, to be the file the walk saw. The walk is not race-free against a
process writing the folder while it runs. And it is not a signature or
tamper-proofing: without an expected identity from outside the folder,
anyone who can write the folder can rewrite a file and recompute the
manifest, and any process running as the same user can change the files and
this checker alike.

A RUN UNSEALS THE FOLDER unless bytecode writing is off: the interpreter
writes `__pycache__` beside what it imports, and `verify` refuses it. Whoever
launches from a payload that is to stay verifiable starts the interpreter
with bytecode writing off (`-B`).

Standard library only: the installed copy checks itself with the interpreter
it carries, before any dependency is imported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path

PAYLOAD_MANIFEST = "forge-payload.json"
PAYLOAD_SCHEMA = "nornyx.forge.windows_payload.v1"

#: The longest relative path a payload may list, in UTF-16 code units, which
#: is how Windows counts. It refuses a path of 260 or more unless long paths
#: are enabled machine-wide, and an install root under a user profile plus a
#: versioned directory takes about 90 of them. The real closure's longest
#: path is 106.
MAX_RELATIVE_PATH = 160
#: How deep the walk descends before it refuses: the real payload's deepest
#: path has 9 components.
MAX_DEPTH = 32
#: The largest manifest read. The real one is about 1.8 MB.
MAX_MANIFEST_BYTES = 16 << 20

#: The manifest's fields, closed. `payload_sha256` is computed over the rest.
MANIFEST_FIELDS = frozenset({
    "schema", "version", "source_commit", "source_date_epoch", "target",
    "lock_sha256", "installer", "interpreter", "files", "payload_sha256",
})
INSTALLER_FIELDS = frozenset({"name", "version"})
INTERPRETER_FIELDS = frozenset({"version", "archive_url", "archive_sha256"})

#: How many problems a refusal names before it counts the rest.
REPORTED_PROBLEMS = 20

#: Names Windows resolves to a device whatever their extension.
RESERVED_NAMES = frozenset(
    ["con", "prn", "aux", "nul", "conin$", "conout$"]
    + [f"{device}{digit}" for device in ("com", "lpt") for digit in "0123456789¹²³"])
#: Characters no NTFS file name may hold, besides the control characters.
FORBIDDEN_CHARACTERS = frozenset('<>:"|?*\\')
#: Bytecode is never payload: the interpreter writes and runs it.
BYTECODE_NAME = "__pycache__"
BYTECODE_SUFFIXES = (".pyc", ".pyo")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
#: The interpreter archive's URL: https, printable ASCII, no space. One rule,
#: used by the manifest check and by the builder's pin check.
ARCHIVE_URL = re.compile(r"https://[\x21-\x7e]+")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_CHUNK = 1 << 20
#: `O_NOFOLLOW` and `O_NONBLOCK` exist on POSIX only. Where they do not, the
#: device-and-inode check after the open is what refuses a swapped file, and
#: nothing stops an open from waiting on something that is not a file.
_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
               | getattr(os, "O_NONBLOCK", 0))


class PayloadError(Exception):
    """The folder is not the payload its manifest describes, or the manifest
    is not one this module accepts."""


def is_link(status: os.stat_result) -> bool:
    """One predicate for every path the walk meets: a symbolic link, or any
    reparse point (a Windows junction is not a symbolic link to
    `Path.is_symlink()`, and carries only the reparse attribute)."""
    return stat.S_ISLNK(status.st_mode) or bool(
        getattr(status, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def check_name(path: object) -> str | None:
    """Why `path` cannot be a payload path, or None. ONE RULE, used by the
    manifest check, the walk and the builder's copy: a relative POSIX path
    of at most `MAX_RELATIVE_PATH` UTF-16 code units, valid UTF-8 in NFC
    form, no control character and none of `<>:"|?*\\`, and components that
    are not empty, `.` or `..`, do not end in a dot or a space, are not a
    Windows device name with or without an extension, and are not bytecode
    in any letter case. Collisions are a property of a set of paths:
    `check_names`. Not covered: 8.3 short-name spellings (`PROGRA~1`)."""
    if not isinstance(path, str) or not path:
        return "not a non-empty string"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "not valid UTF-8"
    if len(path.encode("utf-16-le")) // 2 > MAX_RELATIVE_PATH:
        return f"longer than {MAX_RELATIVE_PATH} UTF-16 code units"
    if unicodedata.normalize("NFC", path) != path:
        return "not in Unicode NFC form"
    if path.startswith("/"):
        return "absolute"
    if any(ord(character) < 0x20 or ord(character) == 0x7f for character in path):
        return "a control character"
    if FORBIDDEN_CHARACTERS.intersection(path):
        return 'one of <>:"|?*\\'
    for part in path.split("/"):
        if part in ("", ".", ".."):
            return "an empty, '.' or '..' component"
        if part.endswith((".", " ")):
            return "a component ending in a dot or a space"
        if part.split(".", 1)[0].rstrip(" ").casefold() in RESERVED_NAMES:
            return "a Windows device name"
        folded = part.casefold()
        if folded == BYTECODE_NAME or folded.endswith(BYTECODE_SUFFIXES):
            return "bytecode"
    return None


def check_names(paths: list[str]) -> list[str]:
    """Every refusal for a set of file paths: each name by `check_name`; and,
    over every path AND every directory that holds one, keyed by the NFC form
    folded for case, any key spelled two ways (`src/d/x` beside `src/D/y`, or
    `src/a.py` beside `src/A.py`) and any key that is both a file and a
    directory (`src/a` beside `src/A/b`). A case-insensitive file system
    holds each such key once."""
    problems = [f"{path!r}: {reason}" for path in paths
                if (reason := check_name(path)) is not None]
    spelling: dict[str, str] = {}
    role: dict[str, str] = {}
    for path in paths:
        if check_name(path) is not None:
            continue
        parts = path.split("/")
        for depth in range(1, len(parts) + 1):
            spelled = "/".join(parts[:depth])
            key = unicodedata.normalize("NFC", spelled).casefold()
            kind = "file" if depth == len(parts) else "directory"
            if spelling.setdefault(key, spelled) != spelled:
                problems.append(f"{path!r}: {spelled!r} and {spelling[key]!r} are one name "
                                "on Windows")
                break
            if role.setdefault(key, kind) != kind:
                problems.append(f"{path!r}: {spelled!r} is both a file and a directory")
                break
    return problems


def _hash_file(path: str, expected: os.stat_result) -> tuple[int, str]:
    """(size, sha256) of the file the walk saw: opened with `_OPEN_FLAGS`, and
    refused unless the opened file is that same regular file, by device and
    inode, with one link."""
    descriptor = os.open(path, _OPEN_FLAGS)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or is_link(opened)
                or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)):
            raise PayloadError(f"{path} changed between the walk and its read")
        if opened.st_nlink != 1:
            raise PayloadError(f"{path} is a hard link ({opened.st_nlink} links); a "
                               "payload file is its own file")
        digest, size = hashlib.sha256(), 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for block in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(block)
                size += len(block)
        return size, digest.hexdigest()
    finally:
        os.close(descriptor)


def payload_files(root: Path) -> list[list]:
    """Every file under `root` but the manifest, as `[path, size, sha256]`,
    sorted by the path's UTF-8 bytes. Iterative, bounded in depth, and every
    refusal is a `PayloadError` naming its path."""
    entries: list[list] = []
    try:
        if is_link(os.lstat(root)):
            raise PayloadError(f"{root} is a link or reparse point")
        stack = [(os.fspath(root), "", 0)]
        while stack:
            directory, prefix, depth = stack.pop()
            if depth > MAX_DEPTH:
                raise PayloadError(f"{prefix} is deeper than {MAX_DEPTH} levels")
            with os.scandir(directory) as iterator:
                names = sorted(entry.name for entry in iterator)
            if not names and prefix:
                raise PayloadError(f"{prefix.rstrip('/')} is an empty directory; a payload "
                                   "directory holds a listed file")
            for name in names:
                relative = prefix + name
                if (reason := check_name(relative)) is not None:
                    raise PayloadError(f"{relative!r} cannot be a payload path: {reason}")
                full = os.path.join(directory, name)
                status = os.lstat(full)
                if is_link(status):
                    raise PayloadError(f"{relative} is a link or reparse point; a payload "
                                       "holds none")
                if stat.S_ISDIR(status.st_mode):
                    stack.append((full, relative + "/", depth + 1))
                elif not stat.S_ISREG(status.st_mode):
                    raise PayloadError(f"{relative} is neither a regular file nor a directory")
                elif relative != PAYLOAD_MANIFEST:
                    entries.append([relative, *_hash_file(full, status)])
    except OSError as error:
        raise PayloadError(f"cannot read the folder: {error}") from None
    entries.sort(key=lambda entry: entry[0].encode("utf-8"))
    return entries


def canonical_bytes(document: dict) -> bytes:
    """One byte sequence per document: sorted keys, no whitespace, ASCII."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def payload_identity(manifest: dict) -> str:
    """The SHA-256 of the canonical manifest without its `payload_sha256`."""
    body = {key: value for key, value in manifest.items() if key != "payload_sha256"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def build_manifest(root: Path, *, version: str, source_commit: str, source_date_epoch: int,
                   target: str, lock_sha256: str, installer: dict, interpreter: dict) -> dict:
    """The manifest of the folder as it is now, with its identity; refused by
    `check_manifest` exactly as `verify` would refuse it."""
    manifest = {
        "schema": PAYLOAD_SCHEMA, "version": version, "source_commit": source_commit,
        "source_date_epoch": source_date_epoch, "target": target, "lock_sha256": lock_sha256,
        "installer": installer, "interpreter": interpreter, "files": payload_files(root),
    }
    manifest["payload_sha256"] = payload_identity(manifest)
    check_manifest(manifest)
    return manifest


def render_manifest(manifest: dict) -> bytes:
    return (json.dumps(manifest, sort_keys=True, indent=1, ensure_ascii=True, allow_nan=False)
            + "\n").encode("ascii")


def _check_object(manifest: dict, name: str, fields: frozenset) -> None:
    value = manifest[name]
    if not isinstance(value, dict) or set(value) != fields or not all(
            isinstance(item, str) for item in value.values()):
        raise PayloadError(f"the manifest's {name} is not exactly {sorted(fields)}, as strings")


def check_manifest(manifest: object) -> None:
    """Refuse anything but a well-formed manifest whose identity matches it."""
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        raise PayloadError(f"{PAYLOAD_MANIFEST} does not carry exactly the fields "
                           f"{sorted(MANIFEST_FIELDS)}")
    if manifest["schema"] != PAYLOAD_SCHEMA:
        raise PayloadError(f"{PAYLOAD_MANIFEST} has schema {manifest['schema']!r}, "
                           f"not {PAYLOAD_SCHEMA!r}")
    if not isinstance(manifest["source_commit"], str) or not _HEX40.fullmatch(
            manifest["source_commit"]):
        raise PayloadError("the manifest names no 40-hex source commit")
    epoch = manifest["source_date_epoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise PayloadError("the manifest's source_date_epoch is not a non-negative integer")
    for name in ("lock_sha256", "payload_sha256"):
        if not isinstance(manifest[name], str) or not _HEX64.fullmatch(manifest[name]):
            raise PayloadError(f"the manifest's {name} is not a lowercase SHA-256")
    for name in ("version", "target"):
        if not isinstance(manifest[name], str) or not _TOKEN.fullmatch(manifest[name]):
            raise PayloadError(f"the manifest's {name} is not a short token of "
                               "letters, digits and .+_-")
    _check_object(manifest, "installer", INSTALLER_FIELDS)
    _check_object(manifest, "interpreter", INTERPRETER_FIELDS)
    interpreter = manifest["interpreter"]
    if not _TOKEN.fullmatch(interpreter["version"]) or not _HEX64.fullmatch(
            interpreter["archive_sha256"]):
        raise PayloadError("the manifest's interpreter version or archive digest is malformed")
    if not ARCHIVE_URL.fullmatch(interpreter["archive_url"]):
        raise PayloadError("the manifest's interpreter archive_url is not an https URL")
    if not all(_TOKEN.fullmatch(value) for value in manifest["installer"].values()):
        raise PayloadError("the manifest's installer is not a name and a version")
    files = manifest["files"]
    if not isinstance(files, list):
        raise PayloadError("the manifest's files is not a list")
    previous = b""
    for entry in files:
        if not (isinstance(entry, list) and len(entry) == 3 and isinstance(entry[0], str)
                and isinstance(entry[1], int) and not isinstance(entry[1], bool)
                and entry[1] >= 0 and isinstance(entry[2], str) and _HEX64.fullmatch(entry[2])):
            raise PayloadError(f"the manifest lists a malformed entry: {entry!r:.200}")
        if (reason := check_name(entry[0])) is not None:
            raise PayloadError(f"the manifest lists {entry[0]!r:.200}, which cannot be a "
                               f"payload path: {reason}")
        key = entry[0].encode("utf-8")
        if key <= previous or entry[0] == PAYLOAD_MANIFEST:
            raise PayloadError(f"the manifest's files are not unique and in byte order, or "
                               f"list the manifest, at {entry[0]!r}")
        previous = key
    collisions = check_names([entry[0] for entry in files])
    if collisions:
        raise PayloadError("the manifest lists paths that are one path on Windows: "
                           + "; ".join(collisions[:REPORTED_PROBLEMS]))
    if payload_identity(manifest) != manifest["payload_sha256"]:
        raise PayloadError("the manifest's payload_sha256 is not the digest of its own "
                           "content: the manifest was changed after it was made")


def _refuse_constant(name: str) -> object:
    raise PayloadError(f"{PAYLOAD_MANIFEST} carries the non-JSON constant {name}")


def _closed_object(pairs: list[tuple[str, object]]) -> dict:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise PayloadError(f"{PAYLOAD_MANIFEST} repeats a key")
    return document


def read_manifest(root: Path) -> dict:
    """The manifest, read through the same open-then-check rule as every
    payload file (one link, the file the `lstat` saw), size-bounded, and
    checked."""
    path = os.path.join(os.fspath(root), PAYLOAD_MANIFEST)
    try:
        status = os.lstat(path)
        if is_link(status) or not stat.S_ISREG(status.st_mode):
            raise PayloadError(f"{PAYLOAD_MANIFEST} is not a regular file")
        if status.st_size > MAX_MANIFEST_BYTES:
            raise PayloadError(f"{PAYLOAD_MANIFEST} is larger than {MAX_MANIFEST_BYTES} bytes")
        descriptor = os.open(path, _OPEN_FLAGS)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
                raise PayloadError(f"{PAYLOAD_MANIFEST} changed while it was opened")
            if opened.st_nlink != 1:
                raise PayloadError(f"{PAYLOAD_MANIFEST} is a hard link ({opened.st_nlink} "
                                   "links); the manifest is its own file")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(MAX_MANIFEST_BYTES + 1)
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        raise PayloadError(f"{root} has no {PAYLOAD_MANIFEST}; it is not a sealed payload") \
            from None
    except OSError as error:
        raise PayloadError(f"cannot read {PAYLOAD_MANIFEST}: {error}") from None
    if len(data) > MAX_MANIFEST_BYTES:
        raise PayloadError(f"{PAYLOAD_MANIFEST} is larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        manifest = json.loads(data.decode("utf-8"), object_pairs_hook=_closed_object,
                              parse_constant=_refuse_constant)
    except (ValueError, RecursionError) as error:  # UnicodeDecodeError is a ValueError
        raise PayloadError(f"{PAYLOAD_MANIFEST} is not readable JSON: {error}") from None
    check_manifest(manifest)
    return manifest


def verify(root: Path, *, expected_payload_sha256: str | None = None) -> dict:
    """Recompute the folder and compare it with its manifest; raise
    `PayloadError` naming every difference (up to `REPORTED_PROBLEMS`).
    With `expected_payload_sha256` -- an identity carried from outside the
    folder -- a folder with any other identity is refused too."""
    manifest = read_manifest(root)
    if expected_payload_sha256 is not None and (
            manifest["payload_sha256"] != expected_payload_sha256):
        raise PayloadError(f"the folder is payload {manifest['payload_sha256']}, not the "
                           f"expected {expected_payload_sha256}")
    listed = {path: (size, digest) for path, size, digest in manifest["files"]}
    present = {path: (size, digest) for path, size, digest in payload_files(root)}
    problems = [f"missing: {path}" for path in listed if path not in present]
    problems += [f"changed: {path}" for path in listed
                 if path in present and present[path] != listed[path]]
    problems += [f"unlisted: {path}" for path in present if path not in listed]
    if problems:
        problems.sort()
        shown = "; ".join(problems[:REPORTED_PROBLEMS])
        more = len(problems) - REPORTED_PROBLEMS
        raise PayloadError(
            f"the folder is not the payload {manifest['payload_sha256']} its manifest "
            f"describes: {shown}" + (f"; and {more} more" if more > 0 else ""))
    return {"payload_sha256": manifest["payload_sha256"], "files_compared": len(listed)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Windows payload against its manifest.")
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("root", type=Path)
    parser.add_argument("--expect", default=None, metavar="SHA256",
                        help="refuse a folder whose payload_sha256 is not this one")
    arguments = parser.parse_args(argv)
    try:
        result = verify(arguments.root, expected_payload_sha256=arguments.expect)
    except PayloadError as error:
        print(f"payload refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
