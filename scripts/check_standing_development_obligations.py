r"""Validate and disposition cross-session Forge development obligations.

WHAT THIS IS. A procedural admission check. A new model, tool, workstation or
developer loads the public standing-obligation registry, optionally an
external overlay the caller supplies BY PATH, writes a local cycle disposition
naming every loaded item, and runs this script until it stops refusing. The
disposition is bound by content digest to the exact registry and overlay
bytes it was written against, so a registry that moves after the disposition
was written makes the disposition stale rather than silently honoured.

WHAT PASSING MEANS, AND ONLY THIS. Passing standing-development admission
means only that a local cycle disposition covers exactly the loaded
public-registry and overlay items, gives every one of them a disposition from
the resolved vocabulary, carries a non-empty reason beside each, and is bound
by SHA-256 to the exact registry and overlay bytes it was checked against. It
establishes nothing about whether anyone read, understood or weighed an
obligation: a disposition written mechanically passes, and so does one reused
from an earlier cycle under a new cycle_id, because the cycle_id is a label
the developer chose and nothing binds it to a cycle. It does not authorize
the development cycle itself, and it confers no human, organizational, merge,
publication, release, deployment or other consequential authority. Every
deterministic Forge and Nornyx gate, every evidence requirement and every
real human or organizational authority the repository already requires
remains controlling after admission exactly as before it.

THE OVERLAY IS NEVER DISCOVERED. There is no default overlay path, no
environment variable, no directory scan and no search of the working
directory or the home directory: the only way an overlay reaches this script
is the `--overlay` argument.

WHERE AN OVERLAY MAY LIVE, AND HOW THAT IS JUDGED. Outside this repository at
every component of the path as given. Where the handle backend exists (POSIX)
the judgment is made through HELD DIRECTORY DESCRIPTORS and nothing else:
the walk starts at the filesystem root, inspects each component relative to
the directory it already holds without following a link, refuses any
component that is a link of any kind -- no link is followed, wherever it
points, so a link inside the tree, a link outside it, a chain that hops
through it and a loop are all refused for the first link met -- and opens
the component relative to the held directory without following, refusing it
unless it is the entry just inspected. Every directory held is compared
lexically against the repository root and BY IDENTITY (device and inode)
against every directory of the repository, so a bind mount of the root or of
any directory below it is still the repository. The identities come from the
one traversal this script performs, of the repository's own tree, through
descriptors as well: each child directory is opened relative to its parent
without following a link and must still be the entry inspected; the set is
taken fresh for every judgment and cached for none. The final component is
opened relative to the last held directory, without following, and THE
DESCRIPTOR SO OPENED IS THE ONLY OBJECT READ. No pathname is resolved again
after it was inspected, by this script or by the kernel on its behalf, so a
component swapped between an inspection and the next lookup is not followed:
the lookup is relative to a handle the swap cannot move. `Path.resolve` takes
part in no security decision. A regular file with more than one name -- a
hard link -- is refused rather than judged by one of its names. What this
does not see: an alias of a single file made by a bind mount, which keeps
one name and one identity.

WHERE NO HANDLE-BASED JUDGMENT EXISTS, THE OVERLAY IS REFUSED. Windows has no
`openat`, no `O_NOFOLLOW` and no `scandir` on a handle in `os`, and a
pathname inspected and then used again is a race an external review
measured against this script. So on a platform without the handle backend a
private `--overlay` is refused outright, with a sentence that names the
platform and nothing else, until a separately reviewed HANDLE-based backend
exists. Public-registry admission stays available there: the disposition is
created by pathname with an exclusive create, and the gap between inspecting
that pathname and using it is stated as the platform's limitation.

NOTHING FROM A PRIVATE OVERLAY IS EMITTED. Nothing from it reaches stdout,
stderr, the disposition or any evidence except the opaque item identifiers
the caller chose and a SHA-256 of the file's bytes, both of which go to the
gitignored disposition and nowhere else; not even the overlay's item count is
printed. A refusal about the overlay's CONTENT says that the overlay is not
valid and nothing else: no item index, no count, no size class, no field, no
value, no position. A refusal about its PATH says where the rule was broken
-- inside the repository, unreadable, unresolvable, a link not followed,
changed during admission -- and never what the path is. Refusals about the
public registry stay specific, because the public registry is public. The
loaders raise their refusals outside the handler that caught the underlying
error, so the refusal carries no `__context__` at all, not merely a
suppressed one; and a failure no handler foresaw still exits 2 with the
exception's class name and nothing else.

WHAT THIS DOES NOT ESTABLISH. It cannot make anyone run it: a model or a
person who edits the repository without invoking it is outside what it
measures. It cannot tell whether a free-text `reason` quotes overlay content,
and it cannot judge whether an identifier the overlay author chose is itself
sensitive -- it bounds the identifier's SHAPE to a short token and no more.
It is repository content, so a commit can change it or the registry; both are
governed inputs, so such a change moves the governed input digest the
evidence set binds, but that is visibility, not prevention. It is admission
procedure, not a sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, NamedTuple, Sequence

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REGISTRY = ROOT / "docs" / "governance" / "STANDING_DEVELOPMENT_OBLIGATIONS.json"
RUNTIME_ROOT = ROOT / ".nornyx" / "runtime"

PUBLIC_SCHEMA = "nornyx.forge.standing_development_obligations.v1"
OVERLAY_SCHEMA = "nornyx.forge.private_standing_overlay.v1"
DISPOSITION_SCHEMA = "nornyx.forge.development_cycle_disposition.v1"

ITEM_KINDS = frozenset({"invariant", "deferred_capability", "learning"})
ITEM_STATUSES = frozenset({"active", "deferred", "retired"})
#: A disposition that resolves an item for the cycle. `defer` is admitted only
#: for an item whose registry status is already `deferred`: deferring an
#: ACTIVE obligation would be a way of ignoring it under a resolved-looking
#: label, and the label is not the decision. Each word is the developer's
#: assertion about the cycle; this script checks that the word is in the
#: vocabulary and does not, and cannot, check the assertion.
RESOLVED_DISPOSITIONS = frozenset({"considered", "unchanged", "defer", "not_applicable"})
#: Dispositions that refuse admission. `pending` is what `--init` writes;
#: `requires_decision` records that an authority outside this script must
#: act. Replacing either word with any other string is refused, because the
#: vocabulary is closed: a string outside it is not a disposition, and no
#: string inside it manufactures the decision the item is waiting for.
BLOCKING_DISPOSITIONS = frozenset({"pending", "requires_decision"})
ALL_DISPOSITIONS = RESOLVED_DISPOSITIONS | BLOCKING_DISPOSITIONS

#: Closed field sets. An unknown field is refused rather than ignored, in every
#: document, so that nothing rides along inside a registry, an overlay or a
#: disposition -- a fabricated `approved_by`, a smuggled disposition, a key
#: whose name is itself private text -- and is later read by a person as if
#: this script had accepted it.
PUBLIC_DOCUMENT_FIELDS = frozenset({"schema", "visibility", "items"})
OVERLAY_DOCUMENT_FIELDS = frozenset({"schema", "classification", "items"})
ITEM_FIELDS = frozenset(
    {"id", "kind", "dedupe_key", "status", "title", "rule", "reopen_condition"}
)
DISPOSITION_FIELDS = frozenset(
    {"schema", "cycle_id", "public_registry_sha256", "private_overlay_sha256", "items"}
)
ROW_FIELDS = frozenset({"id", "source", "disposition", "reason"})
ROW_SOURCES = frozenset({"public", "private"})

#: Identifier grammars. An item id is the one thing from an overlay that is
#: carried into the local disposition, so its shape is bounded to a short
#: upper-case token: it cannot be a sentence. Its MEANING is the overlay
#: author's responsibility, and this script does not claim to judge it.
#: Matched with `fullmatch`, never `match` against a `$`-anchored pattern:
#: `$` also matches before a trailing newline, so `PRV-001` followed by a line
#: break satisfied the anchored form and was written into the disposition as
#: an identifier a viewer cannot tell from the real one.
ITEM_ID = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}")
DEDUPE_KEY = re.compile(r"[a-z0-9][a-z0-9-]{2,79}")
CYCLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TEXT_BOUND = 2000
DOCUMENT_BYTES_BOUND = 1_048_576
#: Directories the identity traversal will record before refusing to judge.
DIRECTORY_SCAN_BOUND = 250_000

#: FILE_ATTRIBUTE_REPARSE_POINT, spelled here so that no platform's `stat`
#: module can leave the test with a zero mask and every reparse point looking
#: plain. Only Windows sets `st_file_attributes` at all; there a junction, a
#: mount point and a cloud placeholder carry it, and none of them is followed.
_REPARSE_POINT_ATTRIBUTE = 0x400

#: True where every security-sensitive operation can be made relative to a
#: held directory descriptor without following a link: `openat` with
#: `O_NOFOLLOW` and `O_DIRECTORY`, `fstatat` without following, `mkdirat`,
#: and `scandir` on a descriptor. POSIX has them all. Windows has no
#: equivalent in `os`, and a HANDLE-based backend for it is a separate change
#: with its own review: where this is False a private overlay is refused
#: outright, and the disposition is created by pathname with an exclusive
#: create, which is the platform's stated limitation.
HANDLE_BACKEND = (
    os.name == "posix"
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.scandir in os.supports_fd
    and all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"))
)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
#: A directory that only needs to be traversed, not listed: `O_PATH` where the
#: platform has it, so an execute-only ancestor of an overlay can be held.
_O_PATH = getattr(os, "O_PATH", 0)
#: A directory the identity traversal lists.
_LISTED_DIRECTORY = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
#: A directory a walk passes through and holds.
_HELD_DIRECTORY = _LISTED_DIRECTORY | _O_PATH
#: A file read through its descriptor and nothing else.
_READ_FILE = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC
#: A disposition created exclusively: an entry of any kind at the name refuses.
_CREATE_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
#: This script's own place in its repository, and the public registry's: the
#: names each is reached by from the root handle, one no-follow open at a time.
_OWN_SCRIPT = ("scripts", "check_standing_development_obligations.py")
_PUBLIC_REGISTRY_NAMES = ("docs", "governance", "STANDING_DEVELOPMENT_OBLIGATIONS.json")

#: Printed after every PASS. The sentence is the boundary, stated where a
#: reader of the output will see it rather than only in a document, and it
#: claims exactly what `validate_disposition` measures and nothing about the
#: person or model that wrote the file.
ADMISSION_BOUNDARY = (
    "Admission is procedural: it records that a local disposition covers exactly the "
    "loaded standing obligations, gives each a resolved disposition with a non-empty "
    "reason, and is digest-bound to the exact input bytes checked. It establishes "
    "nothing about whether anyone read or weighed them, authorizes nothing, and "
    "confers no merge, publication, release, deployment, approval or other authority."
)
OVERLAY_NOTICE = (
    "External overlay: supplied explicitly, validated and digest-bound; its path, "
    "contents, size and item count are not emitted, and a refusal about its content "
    "carries no detail."
)


class AdmissionError(ValueError):
    """A standing-obligation input or disposition is invalid.

    Every message is composed from a label, a constant detail and, for a
    public document, at most an item index or a public item id. A message
    about private input carries the label and nothing else. No message
    carries a value, key name, path or byte from any input.
    """


class Registries(NamedTuple):
    """The loaded standing items and the digests of the bytes they came from.

    A NamedTuple rather than a dataclass on purpose: with postponed
    annotations a dataclass resolves its field types through `sys.modules`,
    and this script is loaded by path -- as a test does -- without being
    registered there.
    """

    public_items: tuple[dict[str, Any], ...]
    public_digest: str
    private_items: tuple[dict[str, Any], ...]
    private_digest: str | None
    statuses: dict[tuple[str, str], str]


class _Identity(NamedTuple):
    """A file's identity: device and inode; volume serial and file index on Windows."""

    device: int
    inode: int




def _identity_of(info: os.stat_result) -> _Identity:
    return _Identity(int(info.st_dev), int(info.st_ino))


# ---------------------------------------------------------------------------
# Refusing, without echoing
# ---------------------------------------------------------------------------


def _refuse(
    label: str, detail: str, *, index: int | None = None, confidential: bool = False
) -> AdmissionError:
    """A refusal composed from a label, a constant detail and at most an index.

    For private input the detail is dropped: the message says the input is
    not valid and nothing else, so no index, count, size class, field, value
    or position of the private document is summarised on stderr. Measured by
    an external review of the merged head: `private overlay item 42 ...` said
    the overlay held at least forty-three items, and the size-bound refusal
    said the file was larger than a megabyte. The public registry keeps its
    specific diagnostics, because the public registry is public.
    """
    if confidential:
        return AdmissionError(f"{label} is not valid; no detail is reported for private input")
    subject = label if index is None else f"{label} item {index}"
    return AdmissionError(f"{subject} {detail}")


def _row_refusal(
    detail: str, *, index: int, public_id: str | None, confidential: bool
) -> AdmissionError:
    """A refusal about one disposition row.

    Named by its public item id where it has one -- public ids are public --
    by its index only while no overlay is loaded, and generically otherwise:
    with an overlay loaded, a row index is a lower bound on the overlay's
    item count.
    """
    if public_id is not None:
        return AdmissionError(f"cycle disposition item {public_id} {detail}")
    return _refuse("cycle disposition", detail, index=index, confidential=confidential)


# ---------------------------------------------------------------------------
# Reading, without echoing
# ---------------------------------------------------------------------------


class _DuplicateKey(ValueError):
    """A JSON object repeats a key; `json.loads` would keep the last silently."""


def _refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """`object_pairs_hook`: an object whose key appears twice is refused.

    `json.loads` keeps the LAST value of a repeated key and drops the first
    without a word, so a row could read `requires_decision` to a person and
    `considered` to this script, and a shadowed `items` could carry any field
    at all past the closed field set. Measured, both.
    """
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise _DuplicateKey(key)
        document[key] = value
    return document


def _read_bytes_bounded(descriptor: int, *, label: str, confidential: bool = False) -> bytes:
    """The bytes behind a descriptor the caller opened without following a link.

    ONE descriptor, opened relative to a held directory by the walk that
    judged its location, then `fstat` on that descriptor and a bounded read
    from it -- never a second open by pathname, so the bytes read are the
    object that was judged and not whatever the same name means a moment
    later. A FIFO, a directory or a device is refused rather than read, and
    for private input the refusal says only that it cannot be read: what the
    object IS stays with the caller. `O_NONBLOCK` on the open keeps a FIFO
    swapped in from hanging the caller's own run.

    The descriptor is closed here, whatever happens. The refusal is raised
    AFTER the handler has been left: `raise ... from None` only suppresses
    the display of `__context__`, and the original `OSError`, with a
    filename in it, would still hang off the exception for any caller that
    looked. Constructing the refusal inside the handler and raising outside
    it leaves no context at all.
    """
    refusal: AdmissionError | None = None
    raw = b""
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) and confidential:
            refusal = _refuse(label, "cannot be read")
        elif not stat.S_ISREG(info.st_mode):
            refusal = _refuse(label, "is not a regular file")
        elif info.st_size > DOCUMENT_BYTES_BOUND:
            refusal = _refuse(label, "exceeds the size bound", confidential=confidential)
        else:
            chunks: list[bytes] = []
            remaining = DOCUMENT_BYTES_BOUND + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > DOCUMENT_BYTES_BOUND:
                refusal = _refuse(label, "exceeds the size bound", confidential=confidential)
    except OSError:
        refusal = _refuse(label, "cannot be read")
    finally:
        os.close(descriptor)
    if refusal is not None:
        raise refusal
    return raw


def _read_document(
    descriptor: int, *, label: str, confidential: bool = False
) -> tuple[dict[str, Any], str]:
    """The parsed JSON object and the SHA-256 of the bytes it was parsed from.

    ONE read, through the descriptor the caller opened, which is closed here.
    The digest is taken from the same bytes that were parsed, so nothing is
    reopened between the parse and the digest: a file replaced after the read
    cannot bind a disposition to bytes nobody validated.

    `UnicodeDecodeError` quotes the offending byte, `JSONDecodeError` quotes a
    position, `RecursionError` comes out of a deeply nested document, and a
    repeated key is refused by the pairs hook. None of them travels further
    than this function, and none is left as the refusal's `__context__`.
    """
    raw = _read_bytes_bounded(descriptor, label=label, confidential=confidential)
    refusal: AdmissionError | None = None
    value: Any = None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_refuse_duplicate_keys)
    except _DuplicateKey:
        refusal = _refuse(label, "repeats a key inside one object", confidential=confidential)
    except (ValueError, RecursionError):
        refusal = _refuse(label, "is not a UTF-8 JSON document", confidential=confidential)
    if refusal is not None:
        raise refusal
    if not isinstance(value, dict):
        raise _refuse(label, "must be a JSON object", confidential=confidential)
    return value, hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Where a path leads, judged through held descriptors and never looked up twice
# ---------------------------------------------------------------------------


def _lexical_absolute(path: Path) -> Path:
    """The path as given, made absolute lexically, with NO symlink followed.

    POSIX keeps a double leading slash as a root of its own, so `//home/...`
    is a different anchor from `/home/...` to a lexical comparison and the
    same directory to the kernel. Measured: an in-repository path spelled
    with two leading slashes was outside for every walked component. It is
    collapsed here, and the identity comparison catches the spellings this
    does not. `..` is collapsed lexically too, and that is what the walk then
    opens: the kernel is never asked to resolve `..` through a link, because
    every component is opened relative to the directory already held.
    """
    text = os.path.abspath(path)
    if os.name != "nt" and text.startswith("//"):
        text = "/" + text.lstrip("/")
    return Path(text)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_link(info: os.stat_result) -> bool:
    """A symlink, or on Windows any reparse point: nothing this script follows."""
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE)


class _Swapped(Exception):
    """The entry opened is not the entry inspected a moment before; refused, never re-looked-up."""


class _ScanBound(Exception):
    """The identity traversal passed its bound; refused rather than judged partially."""


def _inspect(handle: int, name: str, *, label: str) -> os.stat_result:
    """`name` inside the held directory, inspected without following a link; a link refuses.

    Relative to the descriptor, so the kernel resolves nothing above `name`
    on this script's behalf: a directory swapped for a link after it was
    held is not consulted, because the held descriptor still names the
    directory that was inspected.
    """
    info = os.stat(name, dir_fd=handle, follow_symlinks=False)
    if _is_link(info):
        raise AdmissionError(f"{label} path crosses a link that is not followed")
    return info


def _open_inspected(
    handle: int | None, name: str, info: os.stat_result, *, flags: int
) -> tuple[int, os.stat_result]:
    """Open `name` relative to the held directory, without following, as the entry inspected.

    `O_NOFOLLOW` refuses a link swapped in between the inspection and the
    open; `fstat` on what was opened must name the very object inspected --
    same device, inode and kind -- or the open is refused as a swap. The
    descriptor returned is the object that will be used, and nothing about
    it is ever looked up by name again.
    """
    opened = os.open(name, flags, dir_fd=handle)
    try:
        held = os.fstat(opened)
        if _identity_of(held) != _identity_of(info) or stat.S_IFMT(held.st_mode) != stat.S_IFMT(
            info.st_mode
        ):
            raise _Swapped()
    except BaseException:
        os.close(opened)
        raise
    return opened, held


def _hold_below(handle: int, names: Sequence[str], *, label: str, create: bool = False) -> int:
    """Hold the directory `names` deep below the held `handle`, one no-follow open at a time.

    Every intermediate descriptor is closed; the one returned is the
    caller's to close; `handle` itself is left open. With `create`, a
    missing directory is made relative to the one held (`mkdirat`) and then
    inspected and opened like any other, so a link put in its place between
    the two is refused rather than followed.
    """
    current = handle
    owned = False
    try:
        for name in names:
            if create:
                try:
                    os.mkdir(name, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
            info = _inspect(current, name, label=label)
            if not stat.S_ISDIR(info.st_mode):
                raise AdmissionError(f"{label} path cannot be resolved")
            opened, _held = _open_inspected(current, name, info, flags=_HELD_DIRECTORY)
            if owned:
                os.close(current)
            current, owned = opened, True
        return current if owned else os.dup(handle)
    except BaseException:
        if owned:
            os.close(current)
        raise


def _open_file_below(handle: int, names: Sequence[str], *, label: str) -> int:
    """A regular-file descriptor for `names` below the held `handle`, reached without following."""
    parent = _hold_below(handle, names[:-1], label=label)
    try:
        info = _inspect(parent, names[-1], label=label)
        descriptor, _held = _open_inspected(parent, names[-1], info, flags=_READ_FILE)
    finally:
        os.close(parent)
    return descriptor


def _open_repository_root() -> int:
    """The repository root as a held descriptor, bound to the checker that is running.

    The root is this script's own location, found by this script's own
    path. That is not an input: a caller who can move the checker controls
    the code anyway. What is checked is that the directory held contains
    the very file that is running -- same device and inode, reached without
    following a link -- so the handle every later judgment descends from is
    the root of the checkout this code came from, not a directory swapped
    in under the same name after the path was resolved.
    """
    refusal: AdmissionError | None = None
    handle = os.open(ROOT, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    try:
        scripts = _hold_below(handle, _OWN_SCRIPT[:-1], label="repository")
        try:
            own = os.stat(_OWN_SCRIPT[-1], dir_fd=scripts, follow_symlinks=False)
        finally:
            os.close(scripts)
        if _identity_of(own) != _identity_of(os.stat(__file__)):
            refusal = AdmissionError("repository root cannot be established")
    except AdmissionError:
        os.close(handle)
        raise
    except (OSError, ValueError):
        refusal = AdmissionError("repository root cannot be established")
    if refusal is not None:
        os.close(handle)
        raise refusal
    return handle


def _repository_directory_identities(handle: int) -> frozenset[_Identity]:
    r"""The identity of every directory in the repository, the root included.

    THE ONE TRAVERSAL THIS SCRIPT PERFORMS, and it is of the repository's own
    tree, through descriptors: each directory is listed from its handle, each
    child directory is inspected without following a link and then opened
    relative to its parent without following one, and must still be the
    entry inspected -- a directory swapped for a link between the two is a
    swap, and the whole judgment is refused. No file is opened, no name is
    read into any output, nothing is selected. Comparing against the root's
    identity alone was not enough: an alias of a directory BELOW the root --
    a bind mount, a mapped or substituted drive rooted at a subdirectory --
    has that directory's identity at its mount point and external identities
    above it, so the root was never among the candidates; a real bind mount
    of `.nornyx/runtime` was measured to admit an in-repository overlay
    before every directory was compared.

    Bounded, and refused rather than judged when the bound is passed; each
    directory scanned once, whatever else it is called, so the bound limits
    the directories traversed and not only the identities collected; refused
    whole, never judged from a partial set, when any entry cannot be judged,
    because a directory missing from the set is one an alias could reach
    unjudged. Taken fresh for every judgment and cached for none: a snapshot
    that outlived the judgment it was taken for would be stale for the next.
    """
    identities: set[_Identity] = set()
    refusal: AdmissionError | None = None
    stack: list[tuple[int, Any]] = [(handle, None)]
    try:
        identities.add(_identity_of(os.fstat(handle)))
        while stack:
            current, entries = stack[-1]
            if entries is None:
                entries = os.scandir(current)
                stack[-1] = (current, entries)
            entry = next(entries, None)
            if entry is None:
                entries.close()
                stack.pop()
                if current != handle:
                    os.close(current)
                continue
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or _is_link(info):
                continue
            identity = _identity_of(info)
            if identity in identities:
                continue
            opened, _held = _open_inspected(current, entry.name, info, flags=_LISTED_DIRECTORY)
            identities.add(identity)
            if len(identities) > DIRECTORY_SCAN_BOUND:
                os.close(opened)
                raise _ScanBound()
            stack.append((opened, None))
    except _ScanBound:
        refusal = AdmissionError("repository is too large to judge by identity")
    except (_Swapped, OSError):
        refusal = AdmissionError("repository directories cannot be judged by identity")
    finally:
        for current, entries in stack:
            if entries is not None:
                entries.close()
            if current != handle:
                os.close(current)
    if refusal is not None:
        raise refusal
    return frozenset(identities)


def _judge_held(walked: Path, held: os.stat_result, *, label: str, identities: frozenset[_Identity]) -> None:
    """A held directory of the overlay's path: outside the repository by name and by identity."""
    if _is_within(walked, ROOT) or _identity_of(held) in identities:
        raise AdmissionError(f"{label} must remain outside the Forge repository")


def _open_confined(path: Path, *, label: str, identities: frozenset[_Identity]) -> int:
    """The overlay's descriptor, reached only through held directories that stay outside.

    From the filesystem root down, every component is judged lexically
    against the repository root BEFORE it is inspected -- a link that sits
    inside the tree is refused for sitting there, the rule broken first --
    then inspected relative to the directory already held, refused if it is
    a link of any kind, opened relative to that directory without following,
    refused unless it is the entry inspected, and judged by identity against
    every directory of the repository. The final component is opened the same
    way and its descriptor is returned as the only object that will be read.
    A regular file with more than one name is refused: a hard link gives one
    object a name outside the tree and one inside, and this script judges the
    object, not the name it was handed.
    """
    start = _lexical_absolute(path)
    parts = start.parts
    if len(parts) < 2:
        raise AdmissionError(f"{label} path cannot be resolved")
    walked = Path(parts[0])
    current = os.open(parts[0], _HELD_DIRECTORY)
    try:
        _judge_held(walked, os.fstat(current), label=label, identities=identities)
        for name in parts[1:-1]:
            walked = walked / name
            if _is_within(walked, ROOT):
                raise AdmissionError(f"{label} must remain outside the Forge repository")
            info = _inspect(current, name, label=label)
            if not stat.S_ISDIR(info.st_mode):
                raise AdmissionError(f"{label} path cannot be resolved")
            opened, held = _open_inspected(current, name, info, flags=_HELD_DIRECTORY)
            os.close(current)
            current = opened
            _judge_held(walked, held, label=label, identities=identities)
        name = parts[-1]
        walked = walked / name
        if _is_within(walked, ROOT):
            raise AdmissionError(f"{label} must remain outside the Forge repository")
        info = _inspect(current, name, label=label)
        descriptor, held = _open_inspected(current, name, info, flags=_READ_FILE)
        try:
            if stat.S_ISDIR(held.st_mode):
                _judge_held(walked, held, label=label, identities=identities)
            elif stat.S_ISREG(held.st_mode) and held.st_nlink > 1:
                raise AdmissionError(f"{label} has more than one name")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(current)


def _judge_overlay(path: Path, *, label: str, root: int) -> int:
    """The overlay's descriptor on a platform with the handle backend; a refusal without one.

    Where no handle-based judgment exists -- Windows, whose `os` has no
    `openat`, no `O_NOFOLLOW` and no `scandir` on a handle -- a pathname
    inspected and then used again is a race an external review measured
    against this script, so the overlay is refused outright rather than
    admitted over that race. Public-registry admission stays available
    there. A HANDLE-based backend for that platform is a separate change,
    with its own review.

    `_Swapped` is raised inside the walk and turned into a refusal here,
    outside the handler; an `OSError` or `ValueError` from any lookup -- a
    missing component, one this process may not traverse, a name too long
    to reach, an embedded NUL -- is the one refusal that says the path
    cannot be resolved, and never what the path is.
    """
    if not HANDLE_BACKEND:
        raise AdmissionError(f"{label} is not admitted on this platform without a handle-based backend")
    refusal: AdmissionError | None = None
    descriptor = -1
    try:
        identities = _repository_directory_identities(root)
        descriptor = _open_confined(path, label=label, identities=identities)
    except AdmissionError:
        raise
    except _Swapped:
        refusal = _refuse(label, "changed during admission")
    except (OSError, ValueError):
        refusal = _refuse(label, "path cannot be resolved")
    if refusal is not None:
        raise refusal
    return descriptor


def _open_public_registry(root: int) -> int:
    """The public registry's descriptor: below the root handle where one exists, by pathname otherwise."""
    refusal: AdmissionError | None = None
    descriptor = -1
    try:
        if HANDLE_BACKEND:
            descriptor = _open_file_below(root, _PUBLIC_REGISTRY_NAMES, label="public registry")
        else:
            descriptor = os.open(PUBLIC_REGISTRY, os.O_RDONLY | _O_BINARY | _O_CLOEXEC)
    except AdmissionError:
        raise
    except _Swapped:
        refusal = _refuse("public registry", "changed during admission")
    except (OSError, ValueError):
        refusal = _refuse("public registry", "cannot be read")
    if refusal is not None:
        raise refusal
    return descriptor


def _runtime_names(path: Path, *, label: str) -> list[str]:
    """The disposition's components below the repository root, or a refusal.

    The disposition lives under the gitignored runtime root and only there,
    judged lexically on the path as given; where the handle backend exists
    it is then reached from the root handle one no-follow open at a time, so
    the lexical rule and the object reached cannot disagree.
    """
    given = _lexical_absolute(path)
    if given == RUNTIME_ROOT or not _is_within(given, RUNTIME_ROOT):
        raise AdmissionError(f"{label} must be under .nornyx/runtime/")
    return list(given.relative_to(ROOT).parts)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _create_disposition(output: Path, payload: bytes, *, label: str) -> None:
    """Create the disposition EXCLUSIVELY, so no existing entry is truncated or followed.

    With the handle backend the file is created relative to its parent
    directory, which was reached from the root handle without following a
    link, with `O_CREAT | O_EXCL | O_NOFOLLOW`: a second initializer, a link
    put at the name, or a parent swapped for a link after the judgment
    refuses rather than writes elsewhere. Measured by an external review of
    this script: a check followed by a truncating write let one initializer
    overwrite another's cycle, and a parent swapped to a symlink in the same
    gap put the disposition outside the runtime root.

    Without the handle backend the create is exclusive by pathname, which
    closes the overwrite and leaves the parent race as the platform's stated
    limitation.
    """
    names = _runtime_names(output, label=label)
    refusal: AdmissionError | None = None
    try:
        if HANDLE_BACKEND:
            root = _open_repository_root()
            try:
                parent = _hold_below(root, names[:-1], label=label, create=True)
                try:
                    _refuse_existing(parent, names[-1], label=label)
                    descriptor = os.open(names[-1], _CREATE_FILE, 0o644, dir_fd=parent)
                finally:
                    os.close(parent)
            finally:
                os.close(root)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            _refuse_existing(None, str(output), label=label)
            descriptor = os.open(output, _CREATE_FILE | _O_BINARY, 0o644)
        try:
            _write_all(descriptor, payload)
        finally:
            os.close(descriptor)
    except AdmissionError:
        raise
    except FileExistsError:
        refusal = _refuse(label, "already exists; remove it to start a new cycle")
    except (OSError, ValueError):
        refusal = _refuse(label, "cannot be written")
    if refusal is not None:
        raise refusal


def _refuse_existing(handle: int | None, name: str, *, label: str) -> None:
    """Nothing may sit at the disposition's name: a link is refused as a link, anything else as existing."""
    try:
        if handle is None:
            existing = os.lstat(name)
        else:
            existing = os.stat(name, dir_fd=handle, follow_symlinks=False)
    except FileNotFoundError:
        return
    if _is_link(existing):
        raise AdmissionError(f"{label} path crosses a link that is not followed")
    raise AdmissionError(f"{label} already exists; remove it to start a new cycle")


def _open_disposition(path: Path, *, label: str) -> int:
    """The disposition's descriptor, reached from the root handle where one exists.

    Without the handle backend it is inspected and opened by pathname, the
    opened object held to the inspected one by `fstat`; the gap between the
    two is the platform's stated limitation.
    """
    names = _runtime_names(path, label=label)
    refusal: AdmissionError | None = None
    descriptor = -1
    try:
        if HANDLE_BACKEND:
            root = _open_repository_root()
            try:
                descriptor = _open_file_below(root, names, label=label)
            finally:
                os.close(root)
        else:
            info = os.lstat(path)
            if _is_link(info):
                raise AdmissionError(f"{label} path crosses a link that is not followed")
            descriptor, _held = _open_inspected(
                None, str(path), info, flags=os.O_RDONLY | _O_BINARY | _O_CLOEXEC
            )
    except AdmissionError:
        raise
    except _Swapped:
        refusal = _refuse(label, "changed during admission")
    except (OSError, ValueError):
        refusal = _refuse(label, "cannot be read")
    if refusal is not None:
        raise refusal
    return descriptor


# ---------------------------------------------------------------------------
# Registry validation
# ---------------------------------------------------------------------------


def _bounded_text(
    item: dict[str, Any], key: str, *, label: str, index: int, confidential: bool
) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > TEXT_BOUND:
        raise _refuse(label, f"has no valid {key}", index=index, confidential=confidential)
    return value


def _validate_item(
    item: Any, *, label: str, index: int, confidential: bool
) -> tuple[str, str, str]:
    """(id, dedupe_key, status) of a valid item, or a refusal.

    The refusal names the item's index for the public registry and nothing
    for a private overlay.
    """
    if not isinstance(item, dict):
        raise _refuse(label, "must be an object", index=index, confidential=confidential)
    if set(item) - ITEM_FIELDS:
        raise _refuse(label, "carries an unsupported field", index=index, confidential=confidential)
    for required in ("id", "kind", "dedupe_key", "status", "title", "rule"):
        if required not in item:
            raise _refuse(
                label, f"lacks the {required} field", index=index, confidential=confidential
            )
    item_id = item["id"]
    if not isinstance(item_id, str) or not ITEM_ID.fullmatch(item_id):
        raise _refuse(label, "has no valid id", index=index, confidential=confidential)
    dedupe_key = item["dedupe_key"]
    if not isinstance(dedupe_key, str) or not DEDUPE_KEY.fullmatch(dedupe_key):
        raise _refuse(label, "has no valid dedupe_key", index=index, confidential=confidential)
    # `isinstance` before `in`: an unhashable value -- a list where a word
    # belongs -- raises `TypeError` out of a set membership test, which is a
    # refusal without a label.
    kind = item["kind"]
    if not isinstance(kind, str) or kind not in ITEM_KINDS:
        raise _refuse(label, "has an invalid kind", index=index, confidential=confidential)
    status = item["status"]
    if not isinstance(status, str) or status not in ITEM_STATUSES:
        raise _refuse(label, "has an invalid status", index=index, confidential=confidential)
    _bounded_text(item, "title", label=label, index=index, confidential=confidential)
    _bounded_text(item, "rule", label=label, index=index, confidential=confidential)
    if status == "deferred":
        if "reopen_condition" not in item:
            raise _refuse(
                label,
                "is deferred without a reopen_condition",
                index=index,
                confidential=confidential,
            )
        _bounded_text(item, "reopen_condition", label=label, index=index, confidential=confidential)
    elif "reopen_condition" in item:
        raise _refuse(
            label,
            "carries a reopen_condition without deferred status",
            index=index,
            confidential=confidential,
        )
    return item_id, dedupe_key, status


def _validate_registry(
    document: dict[str, Any],
    *,
    schema: str,
    label: str,
    document_fields: frozenset[str],
    confidential: bool = False,
) -> list[dict[str, Any]]:
    if set(document) - document_fields:
        raise _refuse(label, "carries an unsupported field", confidential=confidential)
    if document.get("schema") != schema:
        raise _refuse(label, "has an unsupported schema", confidential=confidential)
    items = document.get("items")
    if not isinstance(items, list):
        raise _refuse(label, "items must be a list", confidential=confidential)

    ids: set[str] = set()
    keys: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        item_id, dedupe_key, _status = _validate_item(
            item, label=label, index=index, confidential=confidential
        )
        if item_id in ids:
            raise _refuse(label, "contains a duplicate item id", confidential=confidential)
        if dedupe_key in keys:
            raise _refuse(label, "contains a duplicate semantic key", confidential=confidential)
        ids.add(item_id)
        keys.add(dedupe_key)
        validated.append(item)
    return validated


def load_registries(overlay_path: Path | None) -> Registries:
    """The public registry and, only when a path was GIVEN, the overlay.

    Both are read through descriptors reached from the repository root
    handle (or, without the handle backend, the registry by pathname and the
    overlay not at all). The root handle is held for the whole load and
    closed after it.
    """
    root = _open_repository_root() if HANDLE_BACKEND else -1
    try:
        public_doc, public_digest = _read_document(_open_public_registry(root), label="public registry")
        if public_doc.get("visibility") != "public":
            raise AdmissionError("public registry must declare public visibility")
        public_items = _validate_registry(
            public_doc,
            schema=PUBLIC_SCHEMA,
            label="public registry",
            document_fields=PUBLIC_DOCUMENT_FIELDS,
        )
        statuses = {("public", item["id"]): item["status"] for item in public_items}

        private_items: list[dict[str, Any]] = []
        private_digest: str | None = None
        if overlay_path is not None:
            descriptor = _judge_overlay(overlay_path, label="private overlay", root=root)
            overlay_doc, private_digest = _read_document(
                descriptor, label="private overlay", confidential=True
            )
            if overlay_doc.get("classification") != "private":
                raise _refuse("private overlay", "must declare private classification", confidential=True)
            private_items = _validate_registry(
                overlay_doc,
                schema=OVERLAY_SCHEMA,
                label="private overlay",
                document_fields=OVERLAY_DOCUMENT_FIELDS,
                confidential=True,
            )
            # A collision with the public registry is a fact about the overlay's
            # content -- which public id or key it repeats -- so it is refused
            # with the same sentence as any other content refusal.
            if {item["id"] for item in public_items} & {item["id"] for item in private_items}:
                raise _refuse("private overlay", "repeats a public item id", confidential=True)
            public_keys = {item["dedupe_key"] for item in public_items}
            if public_keys & {item["dedupe_key"] for item in private_items}:
                raise _refuse("private overlay", "repeats a public semantic key", confidential=True)
            statuses.update({("private", item["id"]): item["status"] for item in private_items})
    finally:
        if root != -1:
            os.close(root)

    return Registries(
        public_items=tuple(public_items),
        public_digest=public_digest,
        private_items=tuple(private_items),
        private_digest=private_digest,
        statuses=statuses,
    )


# ---------------------------------------------------------------------------
# The local cycle disposition
# ---------------------------------------------------------------------------


def initialize_disposition(output: Path, *, cycle_id: str, registries: Registries) -> int:
    """Write a fresh disposition with every loaded item `pending`; return the count.

    Only the item identifier, its source and the two digests are written. The
    title, rule, reopen condition and semantic key of an overlay item never
    reach this file, and nothing else from the overlay does either. The file
    is created exclusively, relative to a parent reached from the root handle
    without following a link where the handle backend exists.
    """
    _runtime_names(output, label="cycle disposition")
    if not isinstance(cycle_id, str) or not CYCLE_ID.fullmatch(cycle_id):
        raise AdmissionError("--cycle-id must be a short identifier")
    rows = [
        {"id": item["id"], "source": source, "disposition": "pending", "reason": ""}
        for source, items in (
            ("public", registries.public_items),
            ("private", registries.private_items),
        )
        for item in items
    ]
    record = {
        "schema": DISPOSITION_SCHEMA,
        "cycle_id": cycle_id,
        "public_registry_sha256": registries.public_digest,
        "private_overlay_sha256": registries.private_digest,
        "items": rows,
    }
    payload = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    _create_disposition(output, payload, label="cycle disposition")
    return len(rows)


def validate_disposition(path: Path, *, registries: Registries) -> tuple[int, int]:
    """Refuse unless the disposition covers the loaded items, resolved, with reasons.

    Measured, and only this: the document has the closed field set and
    schema; it binds the digests of the registry and overlay bytes that were
    just loaded; its rows cover exactly the loaded items, each row carries
    exactly the row fields, a disposition from the vocabulary, and a
    non-empty reason where the disposition is resolved; `defer` sits only on
    an item whose registry status is deferred; and no row is `pending` or
    `requires_decision`. Nothing here can tell whether a person or a model
    read an obligation, understood it or weighed it, and nothing here claims
    to.

    Returns (public rows, private rows) on admission. Refusals name public
    item ids, which are public; for private rows they say only that at least
    one is unresolved -- not how many, which is a fact about the overlay --
    and a malformed row is named by its index only while no overlay is
    loaded.
    """
    label = "cycle disposition"
    record, _digest = _read_document(_open_disposition(path, label=label), label=label)
    if set(record) - DISPOSITION_FIELDS:
        raise AdmissionError("cycle disposition carries an unsupported field")
    if record.get("schema") != DISPOSITION_SCHEMA:
        raise AdmissionError("cycle disposition has an unsupported schema")
    cycle_id = record.get("cycle_id")
    if not isinstance(cycle_id, str) or not CYCLE_ID.fullmatch(cycle_id):
        raise AdmissionError("cycle disposition has no valid cycle_id")
    if record.get("public_registry_sha256") != registries.public_digest:
        raise AdmissionError("cycle disposition is stale against the public registry")
    if record.get("private_overlay_sha256") != registries.private_digest:
        raise AdmissionError("cycle disposition does not bind the supplied overlay set")

    confidential = registries.private_digest is not None
    expected = set(registries.statuses)
    rows = record.get("items")
    if not isinstance(rows, list):
        raise AdmissionError("cycle disposition items must be a list")

    seen: set[tuple[str, str]] = set()
    public_blockers: list[str] = []
    private_blockers = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise _refuse(label, "must be an object", index=index, confidential=confidential)
        if set(row) != ROW_FIELDS:
            raise _refuse(
                label, "does not carry exactly the row fields", index=index, confidential=confidential
            )
        source = row["source"]
        item_id = row["id"]
        if (
            not isinstance(source, str)
            or source not in ROW_SOURCES
            or not isinstance(item_id, str)
            or not ITEM_ID.fullmatch(item_id)
        ):
            raise _refuse(label, "has invalid identity", index=index, confidential=confidential)
        identity = (source, item_id)
        if identity in seen:
            raise AdmissionError("cycle disposition contains a duplicate obligation")
        if identity not in expected:
            raise AdmissionError(
                "cycle disposition does not exactly cover loaded standing obligations"
            )
        seen.add(identity)
        public_id = item_id if source == "public" else None

        disposition = row["disposition"]
        if not isinstance(disposition, str) or disposition not in ALL_DISPOSITIONS:
            raise _row_refusal(
                "has an invalid disposition", index=index, public_id=public_id, confidential=confidential
            )
        reason = row["reason"]
        if not isinstance(reason, str) or len(reason) > TEXT_BOUND:
            raise _row_refusal(
                "has no valid reason", index=index, public_id=public_id, confidential=confidential
            )
        if disposition != "pending" and not reason.strip():
            raise _row_refusal(
                "needs a reason", index=index, public_id=public_id, confidential=confidential
            )
        if disposition == "defer" and registries.statuses[identity] != "deferred":
            raise _row_refusal(
                "defers an obligation that is not deferred",
                index=index,
                public_id=public_id,
                confidential=confidential,
            )
        if disposition in BLOCKING_DISPOSITIONS:
            if source == "public":
                public_blockers.append(f"{item_id}: {disposition}")
            else:
                private_blockers += 1

    if seen != expected:
        raise AdmissionError("cycle disposition does not exactly cover loaded standing obligations")
    if public_blockers or private_blockers:
        parts = list(public_blockers)
        if private_blockers:
            parts.append("overlay items unresolved")
        raise AdmissionError("development admission refused: " + ", ".join(parts))
    public_rows = sum(1 for source, _ in seen if source == "public")
    return public_rows, len(seen) - public_rows


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


class _QuietParser(argparse.ArgumentParser):
    """An argument error names no argument VALUE.

    argparse echoes stray positionals and bad values in its own error text,
    which would print an overlay path handed in the wrong position. The
    generic message is enough to send a caller to `--help`.
    """

    def error(self, message: str) -> None:
        print("REFUSE: invalid arguments; see --help. No argument value was echoed.",
              file=sys.stderr)
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = _QuietParser(
        description="Validate and disposition Forge standing development obligations.",
        epilog=ADMISSION_BOUNDARY,
        add_help=True,
    )
    # `action="append"` so that a repeated option is SEEN. argparse's default
    # keeps the last value silently, so `--overlay A --overlay B` read B and
    # never digest-bound A; `_single` below refuses the repetition by name.
    parser.add_argument(
        "--overlay",
        type=Path,
        action="append",
        default=None,
        help=(
            "Explicit external overlay. The only way an overlay is ever read: it "
            "is never discovered. It must resolve outside this repository."
        ),
    )
    parser.add_argument(
        "--init",
        type=Path,
        action="append",
        default=None,
        help="Initialize a gitignored cycle disposition.",
    )
    parser.add_argument(
        "--cycle-id", action="append", default=None, help="Cycle identifier used with --init."
    )
    parser.add_argument(
        "--check-disposition",
        type=Path,
        action="append",
        default=None,
        help="Validate a completed gitignored cycle disposition.",
    )
    return parser


def _single(values: list[Any] | None, option: str) -> Any:
    """The one value an option was given, or a refusal naming the option."""
    if values is None:
        return None
    if len(values) != 1:
        raise AdmissionError(f"{option} may be given once")
    return values[0]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        overlay = _single(args.overlay, "--overlay")
        init = _single(args.init, "--init")
        check = _single(args.check_disposition, "--check-disposition")
        cycle_id = _single(args.cycle_id, "--cycle-id")
        if init is not None and check is not None:
            raise AdmissionError("--init and --check-disposition are mutually exclusive")
        registries = load_registries(overlay)
        if init is not None:
            initialize_disposition(
                init, cycle_id="" if cycle_id is None else cycle_id, registries=registries
            )
            print(
                "Standing obligations loaded; local cycle disposition initialized "
                f"with {len(registries.public_items)} public item(s) pending"
                + (", plus the overlay's." if overlay is not None else ".")
            )
        elif check is not None:
            public_rows, _private_rows = validate_disposition(check, registries=registries)
            print(
                "Standing-obligation development admission: PASS "
                f"({public_rows} public item(s) dispositioned"
                + (", plus the overlay's)." if overlay is not None else ").")
            )
        else:
            print(
                "Standing-obligation registries: PASS "
                f"({len(registries.public_items)} public item(s)"
                + (", plus an overlay)." if overlay is not None else ").")
            )
        if overlay is not None:
            print(OVERLAY_NOTICE)
        print(ADMISSION_BOUNDARY)
        return 0
    except AdmissionError as exc:
        print(f"REFUSE: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Anything the handlers above did not foresee still fails closed, and
        # still names no value: the class name is diagnostic enough and a
        # message could carry a path.
        print(
            f"REFUSE: unexpected failure ({type(exc).__name__}); no input was echoed.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
