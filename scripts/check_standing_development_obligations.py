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

WHERE AN OVERLAY MAY LIVE. Outside this repository at every step: the path as
given, every component the walk reaches, every link it follows, and the final
resolution. The walk judges each component by `lstat` where it sits. A
symlink is followed one hop at a time and judged at its own location; any
other reparse point -- a Windows directory junction, a mount point, a cloud
placeholder, anything the platform flags as a reparse point that is not a
symlink -- is refused rather than followed, because this script does not
claim to know where such a link leads; nothing beyond such a link is
consulted, not even by resolution. Beside the lexical comparison, every
walked location and the final resolution are compared BY IDENTITY (device and
inode; volume serial and file index on Windows) against EVERY directory of
the repository, so another spelling of the same directory -- `\\?\C:\...`, a
mapped or substituted drive letter, an administrative share, a double leading
slash, a bind mount of the root OR OF ANY DIRECTORY BELOW IT -- is still the
repository. The identities come from the one traversal this script performs,
of the repository's own directories: no symlink followed, no file opened, no
name read into any output, nothing selected.

THE BYTES ARE THE OBJECT THAT WAS JUDGED. The walk records the identity of the
entry it ends at. The file is then opened ONCE, judged by `fstat` on that
descriptor, and refused unless the opened object is that very entry: a path,
a link or a file swapped between the walk and the open reaches a different
object and is refused as changed during admission. The digest is taken from
the bytes that were read through that descriptor and parsed. What this does
not see: a hard link, which gives one object two names; and a replacement
that keeps the same identity, which no platform exposes.

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
from typing import Any, NamedTuple

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
#: A symlink chain longer than this is refused rather than followed.
SYMLINK_HOPS_BOUND = 40
#: Directories the identity traversal will record before refusing to judge.
DIRECTORY_SCAN_BOUND = 250_000

#: What the walk concludes about one path component from its `lstat`.
SYMLINK = "symlink"
PLAIN = "plain"
UNSUPPORTED_LINK = "unsupported"
#: FILE_ATTRIBUTE_REPARSE_POINT, spelled here so that no platform's `stat`
#: module can leave the classifier with a zero mask and every reparse point
#: looking plain. Only Windows sets `st_file_attributes` at all.
_REPARSE_POINT_ATTRIBUTE = 0x400

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


#: No entry was seen, or the platform exposed no identity for it. An inode of
#: zero is never accepted as an identity, so nothing can be "the same" as it.
_NO_IDENTITY = _Identity(0, 0)


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


def _read_bytes_bounded(
    path: Path,
    *,
    label: str,
    confidential: bool = False,
    expected: _Identity | None = None,
) -> bytes:
    """The file's bytes, read through ONE descriptor, or a labelled refusal.

    One open, `fstat` on that descriptor, then a bounded read from it: a
    `stat` followed by a separate `read_bytes` is two opens, and a FIFO swapped
    in between would hang the caller's own run. `O_NONBLOCK` keeps the open
    itself from blocking on a FIFO where the platform has it.

    When an `expected` identity is given, the opened object must BE the entry
    the walk ended at: same device and inode, and an inode the platform
    actually exposed. Measured by an external review of the merged head: a
    path checked and then opened is two operations, and a link retargeted
    between them opened a file whose location nobody had judged.

    The refusal is raised AFTER the handler has been left. `raise ... from
    None` only suppresses the display of `__context__`; the original
    `OSError`, with the filename in it, would still hang off the exception
    object for any caller that looks. Constructing the refusal inside the
    handler and raising outside it leaves no context at all.
    """
    refusal: AdmissionError | None = None
    raw = b""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError):
        refusal = _refuse(label, "cannot be read")
    else:
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) and confidential:
                # A FIFO, a directory, a device: what it is stays with the
                # caller when the input is private.
                refusal = _refuse(label, "cannot be read")
            elif not stat.S_ISREG(info.st_mode):
                refusal = _refuse(label, "is not a regular file")
            elif expected is not None and expected.inode == 0:
                refusal = _refuse(label, "identity cannot be established")
            elif expected is not None and _identity_of(info) != expected:
                refusal = _refuse(label, "changed during admission")
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
    path: Path,
    *,
    label: str,
    confidential: bool = False,
    expected: _Identity | None = None,
) -> tuple[dict[str, Any], str]:
    """The parsed JSON object and the SHA-256 of the bytes it was parsed from.

    ONE read. The digest is taken from the same bytes that were parsed, so a
    file replaced between a load and a later digest cannot bind a disposition
    to bytes nobody validated.

    `UnicodeDecodeError` quotes the offending byte, `JSONDecodeError` quotes a
    position, `RecursionError` comes out of a deeply nested document, and a
    repeated key is refused by the pairs hook. None of them travels further
    than this function, and none is left as the refusal's `__context__`.
    """
    raw = _read_bytes_bounded(path, label=label, confidential=confidential, expected=expected)
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
# Where a path leads, judged one component at a time
# ---------------------------------------------------------------------------


def _lexical_absolute(path: Path) -> Path:
    """The path as given, made absolute, with NO symlink followed.

    POSIX keeps a double leading slash as a root of its own, so `//home/...`
    is a different anchor from `/home/...` to a lexical comparison and the
    same directory to the kernel. Measured: an in-repository path spelled
    with two leading slashes was outside for every walked component and was
    caught only by the final resolution -- and a symlink TARGET spelled that
    way would have hopped through the repository unjudged. Collapsed here;
    the identity comparison in `_names_the_root` catches the spellings this
    does not.
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


def _link_kind(info: os.stat_result) -> str:
    """Symlink, plain entry, or a reparse point this script does not follow.

    `Path.is_symlink()` is `S_ISLNK` and nothing else: on Windows a directory
    junction, a mount point and every other reparse point report False, so a
    walk built on it stepped through a junction into the repository and out
    again without noticing either hop. Measured by an external review of the
    merged head. Here every reparse point that is not a symlink is refused
    rather than followed -- this script does not claim to know where a
    junction, a mount point or a cloud placeholder leads -- and an entry
    whose reparse attribute is set but whose tag the platform does not expose
    is refused the same way, so an uninspectable state fails closed.
    """
    if stat.S_ISLNK(info.st_mode):
        return SYMLINK
    attributes = getattr(info, "st_file_attributes", 0)
    if attributes & _REPARSE_POINT_ATTRIBUTE:
        return UNSUPPORTED_LINK
    return PLAIN


_WIN32_FILE_PREFIX = "\\\\?\\"
_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/].*", re.DOTALL)


def _windows_link_target(raw: str) -> str | None:
    r"""A Windows symlink target as a path the walk can judge, or None.

    `os.readlink` returns the substitute name, which carries the `\\?\`
    prefix for an absolute target. Behind that prefix only a drive-letter
    path is judged; a `\\?\UNC\` share, a `\\?\Volume{...}` GUID, a
    `\\?\GLOBALROOT` device and every other namespace spelling are refused
    rather than judged, because the lexical rule cannot see the repository
    through them. Without the prefix a drive-letter path or a relative
    target is judged, and a `\\server\share`, `\\.\device`, drive-relative
    (`C:name`) or root-relative (`\name`) spelling is refused.
    """
    if raw.startswith(_WIN32_FILE_PREFIX):
        text = raw[len(_WIN32_FILE_PREFIX):]
        return text if _DRIVE_PATH.fullmatch(text) else None
    if _DRIVE_PATH.fullmatch(raw):
        return raw
    if raw and ":" not in raw and raw[0] not in "\\/":
        return raw
    return None


def _link_target(link: Path) -> Path | None:
    """Where a symlink points, as an absolute lexical path from the link's own directory."""
    raw = os.readlink(link)
    if os.name == "nt":
        judged = _windows_link_target(raw)
        if judged is None:
            return None
        raw = judged
    return _lexical_absolute(Path(os.path.join(str(link.parent), raw)))


def _walk(path: Path, *, label: str) -> tuple[list[Path], _Identity, bool]:
    """Every location the walk touches, what it ends at, and whether it got there.

    COMPONENT BY COMPONENT, never collapsed. The first version placed each hop
    at `realpath(parent)`, and `realpath` follows a directory symlink all the
    way through: for `outside/a -> repo/.nornyx/runtime/dir -> outside/final`
    the parent of `outside/a/overlay.json` collapsed straight to
    `outside/final`, and the in-repository directory link in the middle was
    never seen. Measured by an external review on the merged head: PASS.

    So the walk is its own: it takes the given path one component at a time
    and judges each by `lstat` where it sits. A plain entry is stepped into.
    A symlink is followed one hop: the walk records where the link sits,
    reads the target, and continues from the target's components followed by
    the rest of the original path. Any other reparse point refuses. Every
    prefix reached this way is recorded, so a link inside the tree is judged
    wherever it sits in the chain -- directory or file, first hop or third --
    and a real directory inside the tree that the chain passes through is
    recorded too. The entry the walk ends at -- the last plain component --
    is returned by identity, so the read that follows can be held to the very
    object that was judged.

    A reparse point that is not a symlink stops the walk: the locations
    reached so far and a `False` third value are returned rather than a
    refusal raised here, so that the caller judges those locations FIRST. An
    unsupported link that sits inside the repository is refused for sitting
    there -- the rule broken first -- and one outside it for not being
    followed. Measured on a Windows runner: the first version raised at the
    junction and named the wrong rule for an in-repository junction.
    """
    locations: list[Path] = []
    start = _lexical_absolute(path)
    remaining = list(start.parts[1:])
    walked = Path(start.parts[0])
    hops = 0
    final = _NO_IDENTITY
    while remaining:
        walked = walked / remaining.pop(0)
        locations.append(walked)
        try:
            info = os.lstat(walked)
        except OSError:
            # Absent, or not stat-able: nothing to follow here, and nothing
            # seen. The open that follows the walk refuses on its own terms,
            # and an entry that appears between the two is not the one seen.
            final = _NO_IDENTITY
            continue
        kind = _link_kind(info)
        if kind == PLAIN:
            final = _identity_of(info)
            continue
        if kind == UNSUPPORTED_LINK:
            return locations, _NO_IDENTITY, False
        hops += 1
        if hops > SYMLINK_HOPS_BOUND:
            # The same words as a loop the interpreter detects itself: which
            # step noticed is not the property.
            raise AdmissionError(f"{label} path cannot be resolved")
        target = _link_target(walked)
        if target is None:
            raise AdmissionError(f"{label} path cannot be resolved")
        remaining = list(target.parts[1:]) + remaining
        walked = Path(target.parts[0])
        final = _NO_IDENTITY
    return locations, final, True


_DIRECTORY_IDENTITIES: frozenset[_Identity] | None = None


class _ScanBound(Exception):
    """The identity traversal passed its bound; refused rather than judged partially."""


def _repository_directory_identities() -> frozenset[_Identity]:
    r"""The identity of every directory in the repository, the root included.

    THE ONE TRAVERSAL THIS SCRIPT PERFORMS, and it is of the repository's own
    tree: directory entries only, judged by `lstat`; no symlink or other
    reparse point followed; no file opened; no name read into any output;
    nothing selected. Comparing against the root's identity alone was not
    enough: an alias of a directory BELOW the root -- a bind mount, a mapped
    or substituted drive rooted at a subdirectory -- has that directory's
    identity at its mount point and external identities above it, so the
    root was never among the candidates. Measured by an external review of
    the PR head and reproduced with a real bind mount of `.nornyx/runtime`
    at `/tmp/alias`: an in-repository overlay was read through the alias.
    Bounded, and refused rather than judged when the bound is passed; cached
    for the process, so a run pays for it once.
    """
    global _DIRECTORY_IDENTITIES
    if _DIRECTORY_IDENTITIES is not None:
        return _DIRECTORY_IDENTITIES
    identities: set[_Identity] = set()
    pending: list[Path] = [ROOT]
    refusal: AdmissionError | None = None
    try:
        identities.add(_identity_of(os.lstat(ROOT)))
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISDIR(info.st_mode) or _link_kind(info) != PLAIN:
                        continue
                    identities.add(_identity_of(info))
                    if len(identities) > DIRECTORY_SCAN_BOUND:
                        raise _ScanBound()
                    pending.append(Path(entry.path))
    except _ScanBound:
        refusal = AdmissionError("repository is too large to judge by identity")
    except OSError:
        refusal = AdmissionError("repository directories cannot be judged by identity")
    if refusal is not None:
        raise refusal
    _DIRECTORY_IDENTITIES = frozenset(identities)
    return _DIRECTORY_IDENTITIES


def _inside_by_identity(location: Path, identities: frozenset[_Identity], checked: set[Path]) -> bool:
    r"""Whether `location` or an ancestor of it IS a repository directory, by identity.

    The lexical rule compares spellings, and one directory has several: on
    Windows `\\?\C:\...`, a mapped or substituted drive letter, an
    administrative share; on POSIX a bind mount or a double leading slash.
    Identity -- device and inode, volume serial and file index -- names the
    directory itself, wherever it is spelled from. Judged by `lstat`, so no
    link is followed here: a followed symlink's target components are already
    among the walked locations, and an unfollowed link is not looked through.
    Where the platform exposes no identity for an entry (inode 0) nothing is
    claimed for it and the lexical rule stands alone.
    """
    for candidate in (location, *location.parents):
        if candidate in checked:
            continue
        checked.add(candidate)
        try:
            identity = _identity_of(os.lstat(candidate))
        except (OSError, ValueError):
            continue
        if identity.inode != 0 and identity in identities:
            return True
    return False


def _confine_outside(path: Path, *, label: str) -> _Identity:
    """Refuse a path naming anything inside this repository; return what the walk ended at.

    The path as given (after lexical normalisation), every link it passes
    through, every directory the chain crosses, and -- for a chain the walk
    followed to its end -- its final resolution are all judged, lexically and
    by identity against every directory of the repository. A chain the walk
    stopped at (a reparse point it does not follow) is judged as far as it was
    walked and no further: nothing beyond the unfollowed link is consulted. A symlink inside the repository
    that points outside is still a path inside the repository -- and one
    that could be committed -- so it is refused; a path outside the
    repository that resolves inside it is content inside the repository
    under another name; and a chain that merely passes through the tree is
    refused for the same reason as the first.

    `resolve()` raises `RuntimeError` on a symlink loop on some interpreter
    versions and `OSError` on others, and both spell the path in their
    message. Neither is allowed out, and neither is left as context.
    """
    refusal: AdmissionError | None = None
    inside = False
    followed = False
    final = _NO_IDENTITY
    try:
        locations, final, followed = _walk(path, label=label)
        identities = _repository_directory_identities()
        checked: set[Path] = set()
        candidates = list(locations)
        if followed:
            # Only a chain the walk followed to its end is resolved; an
            # unfollowed link is not looked through, not even by resolution.
            candidates.append(path.resolve(strict=False))
        for location in candidates:
            inside = inside or _is_within(location, ROOT) or _inside_by_identity(
                location, identities, checked
            )
    except AdmissionError:
        raise
    except (OSError, RuntimeError, ValueError):
        refusal = _refuse(label, "path cannot be resolved")
    if refusal is not None:
        raise refusal
    if inside:
        raise AdmissionError(f"{label} must remain outside the Forge repository")
    if not followed:
        raise AdmissionError(f"{label} path crosses a link that is not followed")
    return final


def _require_runtime_file(path: Path, *, label: str) -> _Identity:
    """The disposition lives under the gitignored runtime root, and only there.

    Returns the identity of the entry at the resolved path, so the read that
    follows can be held to the object that was judged; no identity when
    nothing is there yet, which is what `--init` expects.
    """
    refusal: AdmissionError | None = None
    inside = False
    final = _NO_IDENTITY
    try:
        resolved = path.resolve(strict=False)
        inside = _is_within(_lexical_absolute(path), RUNTIME_ROOT) and _is_within(
            resolved, RUNTIME_ROOT
        )
        if inside:
            try:
                final = _identity_of(os.lstat(resolved))
            except OSError:
                final = _NO_IDENTITY
    except (OSError, RuntimeError, ValueError):
        refusal = _refuse(label, "path cannot be resolved")
    if refusal is not None:
        raise refusal
    if not inside:
        raise AdmissionError(f"{label} must be under .nornyx/runtime/")
    return final


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
    """The public registry and, only when a path was GIVEN, the overlay."""
    public_doc, public_digest = _read_document(PUBLIC_REGISTRY, label="public registry")
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
        judged = _confine_outside(overlay_path, label="private overlay")
        overlay_doc, private_digest = _read_document(
            overlay_path, label="private overlay", confidential=True, expected=judged
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
    reach this file, and nothing else from the overlay does either.
    """
    _require_runtime_file(output, label="cycle disposition")
    if not isinstance(cycle_id, str) or not CYCLE_ID.fullmatch(cycle_id):
        raise AdmissionError("--cycle-id must be a short identifier")
    if output.exists() or output.is_symlink():
        raise AdmissionError("cycle disposition already exists; remove it to start a new cycle")
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
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    except (OSError, ValueError):
        raise AdmissionError("cycle disposition cannot be written") from None
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
    judged = _require_runtime_file(path, label=label)
    record, _digest = _read_document(path, label=label, expected=judged)
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
