"""Validate and disposition cross-session Forge development obligations.

WHAT THIS IS. A procedural admission check. A new model, tool, workstation or
developer loads the public standing-obligation registry, optionally an
external overlay the caller supplies BY PATH, writes a local cycle disposition
naming every loaded item, and runs this script until it stops refusing. The
disposition is bound by content digest to the exact registry and overlay
bytes it was written against, so a registry that moves after the disposition
was written makes the disposition stale rather than silently honoured.

WHAT PASSING MEANS, AND ONLY THIS. Passing standing-development admission
means that the applicable standing obligations were loaded, each given a
deliberate disposition, and bound by content digest to the exact registry
and overlay bytes used for that development cycle. It does not authorize the
development cycle itself, and it confers no human, organizational, merge,
publication, release, deployment or other consequential authority. Every
deterministic Forge and Nornyx gate, every evidence requirement and every
real human or organizational authority the repository already requires
remains controlling after admission exactly as before it.

THE OVERLAY IS NEVER DISCOVERED. There is no default overlay path, no
environment variable, no directory scan and no search of the working
directory or the home directory: the only way an overlay reaches this script
is the `--overlay` argument. An overlay must resolve OUTSIDE this repository,
both as the path given and after symlinks are followed, and nothing from it
reaches stdout, stderr, the disposition or any evidence except the opaque
item identifiers the caller chose, the item count, and a SHA-256 of the
file's bytes. Every refusal this script can produce names a label and, where
useful, an item INDEX; none carries a value, a key name, a path or a byte
from any input. The loaders raise their refusals outside the handler that
caught the underlying error, so the refusal carries no `__context__` at all,
not merely a suppressed one; and a failure no handler foresaw still exits 2
with the exception's class name and nothing else.

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
#: label, and the label is not the decision.
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

#: Printed after every PASS. The sentence is the boundary, stated where a
#: reader of the output will see it rather than only in a document.
ADMISSION_BOUNDARY = (
    "Admission is procedural: it records that the loaded standing obligations "
    "were dispositioned and digest-bound for this cycle. It authorizes nothing "
    "and confers no merge, publication, release, deployment, approval or other "
    "authority."
)
OVERLAY_NOTICE = (
    "External overlay: supplied explicitly, validated and digest-bound; its path "
    "and contents are not emitted."
)


class AdmissionError(ValueError):
    """A standing-obligation input or disposition is invalid.

    Every message is composed from a label and, at most, an item index. No
    message carries a value, key name, path or byte from any input.
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


def _read_bytes_bounded(path: Path, *, label: str) -> bytes:
    """The file's bytes, read through ONE descriptor, or a labelled refusal.

    One open, `fstat` on that descriptor, then a bounded read from it: a
    `stat` followed by a separate `read_bytes` is two opens, and a FIFO swapped
    in between would hang the caller's own run. `O_NONBLOCK` keeps the open
    itself from blocking on a FIFO where the platform has it.

    The refusal is raised AFTER the handler has been left. `raise ... from
    None` only suppresses the display of `__context__`; the original
    `OSError`, with the filename in it, would still hang off the exception
    object for any caller that looks. Assigning a message and raising outside
    the `except` leaves no context at all.
    """
    refusal: str | None = None
    raw = b""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError):
        refusal = f"{label} cannot be read"
    else:
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                refusal = f"{label} is not a regular file"
            elif info.st_size > DOCUMENT_BYTES_BOUND:
                refusal = f"{label} exceeds the size bound"
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
                    refusal = f"{label} exceeds the size bound"
        except OSError:
            refusal = f"{label} cannot be read"
        finally:
            os.close(descriptor)
    if refusal is not None:
        raise AdmissionError(refusal)
    return raw


def _read_document(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    """The parsed JSON object and the SHA-256 of the bytes it was parsed from.

    ONE read. The digest is taken from the same bytes that were parsed, so a
    file replaced between a load and a later digest cannot bind a disposition
    to bytes nobody validated.

    `UnicodeDecodeError` quotes the offending byte, `JSONDecodeError` quotes a
    position, `RecursionError` comes out of a deeply nested document, and a
    repeated key is refused by the pairs hook. None of them travels further
    than this function, and none is left as the refusal's `__context__`.
    """
    raw = _read_bytes_bounded(path, label=label)
    refusal: str | None = None
    value: Any = None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_refuse_duplicate_keys)
    except _DuplicateKey:
        refusal = f"{label} repeats a key inside one object"
    except (ValueError, RecursionError):
        refusal = f"{label} is not a UTF-8 JSON document"
    if refusal is not None:
        raise AdmissionError(refusal)
    if not isinstance(value, dict):
        raise AdmissionError(f"{label} must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _lexical_absolute(path: Path) -> Path:
    """The path as given, made absolute, with NO symlink followed."""
    return Path(os.path.abspath(path))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _link_locations(path: Path, *, label: str) -> list[Path]:
    """Where each link in the chain physically sits, the path as given first.

    A chain `outside/a -> repo/.nornyx/runtime/b -> outside/c` is outside at
    both ends, so a rule that judges only the given path and its final
    resolution accepts it -- while the middle hop is a file inside the tree
    that names the overlay and could be committed. Each hop is placed at the
    real path of its directory, so a link reached through a directory symlink
    into the tree is judged where it actually lives.
    """
    current = _lexical_absolute(path)
    locations: list[Path] = []
    for _ in range(SYMLINK_HOPS_BOUND):
        parent = Path(os.path.realpath(current.parent))
        locations.append(parent / current.name)
        if not current.is_symlink():
            return locations
        target = os.readlink(current)
        current = Path(os.path.normpath(os.path.join(str(parent), target)))
    # The same words as a loop the interpreter detects itself: which step
    # noticed is not the property.
    raise AdmissionError(f"{label} path cannot be resolved")


def _within_repository(path: Path, *, label: str) -> bool:
    """Whether `path` names anything inside this repository.

    The path as given (after lexical normalisation), every link it passes
    through, and its final resolution are all judged. A symlink inside the
    repository that points outside is still a path inside the repository --
    and one that could be committed -- so it is refused; a path outside the
    repository that resolves inside it is content inside the repository under
    another name; and a chain that merely passes through the tree is refused
    for the same reason as the first.

    `resolve()` raises `RuntimeError` on a symlink loop on some interpreter
    versions and `OSError` on others, and both spell the path in their
    message. Neither is allowed out, and neither is left as context.
    """
    refusal: str | None = None
    inside = False
    try:
        for location in _link_locations(path, label=label):
            inside = inside or _is_within(location, ROOT)
        inside = inside or _is_within(path.resolve(strict=False), ROOT)
    except AdmissionError:
        raise
    except (OSError, RuntimeError, ValueError):
        refusal = f"{label} path cannot be resolved"
    if refusal is not None:
        raise AdmissionError(refusal)
    return inside


def _require_runtime_file(path: Path, *, label: str) -> None:
    """The disposition lives under the gitignored runtime root, and only there."""
    refusal: str | None = None
    inside = False
    try:
        inside = _is_within(_lexical_absolute(path), RUNTIME_ROOT) and _is_within(
            path.resolve(strict=False), RUNTIME_ROOT
        )
    except (OSError, RuntimeError, ValueError):
        refusal = f"{label} path cannot be resolved"
    if refusal is not None:
        raise AdmissionError(refusal)
    if not inside:
        raise AdmissionError(f"{label} must be under .nornyx/runtime/")


# ---------------------------------------------------------------------------
# Registry validation
# ---------------------------------------------------------------------------


def _bounded_text(item: dict[str, Any], key: str, *, label: str, index: int) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > TEXT_BOUND:
        raise AdmissionError(f"{label} item {index} has no valid {key}")
    return value


def _validate_item(item: Any, *, label: str, index: int) -> tuple[str, str, str]:
    """(id, dedupe_key, status) of a valid item, or a refusal naming its index."""
    if not isinstance(item, dict):
        raise AdmissionError(f"{label} item {index} must be an object")
    if set(item) - ITEM_FIELDS:
        raise AdmissionError(f"{label} item {index} carries an unsupported field")
    for required in ("id", "kind", "dedupe_key", "status", "title", "rule"):
        if required not in item:
            raise AdmissionError(f"{label} item {index} lacks the {required} field")
    item_id = item["id"]
    if not isinstance(item_id, str) or not ITEM_ID.fullmatch(item_id):
        raise AdmissionError(f"{label} item {index} has no valid id")
    dedupe_key = item["dedupe_key"]
    if not isinstance(dedupe_key, str) or not DEDUPE_KEY.fullmatch(dedupe_key):
        raise AdmissionError(f"{label} item {index} has no valid dedupe_key")
    # `isinstance` before `in`: an unhashable value -- a list where a word
    # belongs -- raises `TypeError` out of a set membership test, which is a
    # refusal without a label.
    kind = item["kind"]
    if not isinstance(kind, str) or kind not in ITEM_KINDS:
        raise AdmissionError(f"{label} item {index} has an invalid kind")
    status = item["status"]
    if not isinstance(status, str) or status not in ITEM_STATUSES:
        raise AdmissionError(f"{label} item {index} has an invalid status")
    _bounded_text(item, "title", label=label, index=index)
    _bounded_text(item, "rule", label=label, index=index)
    if status == "deferred":
        if "reopen_condition" not in item:
            raise AdmissionError(f"{label} item {index} is deferred without a reopen_condition")
        _bounded_text(item, "reopen_condition", label=label, index=index)
    elif "reopen_condition" in item:
        raise AdmissionError(
            f"{label} item {index} carries a reopen_condition without deferred status"
        )
    return item_id, dedupe_key, status


def _validate_registry(
    document: dict[str, Any],
    *,
    schema: str,
    label: str,
    document_fields: frozenset[str],
) -> list[dict[str, Any]]:
    if set(document) - document_fields:
        raise AdmissionError(f"{label} carries an unsupported field")
    if document.get("schema") != schema:
        raise AdmissionError(f"{label} has an unsupported schema")
    items = document.get("items")
    if not isinstance(items, list):
        raise AdmissionError(f"{label} items must be a list")

    ids: set[str] = set()
    keys: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        item_id, dedupe_key, _status = _validate_item(item, label=label, index=index)
        if item_id in ids:
            raise AdmissionError(f"{label} contains a duplicate item id")
        if dedupe_key in keys:
            raise AdmissionError(f"{label} contains a duplicate semantic key")
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
        if _within_repository(overlay_path, label="private overlay"):
            raise AdmissionError("private overlay must remain outside the Forge repository")
        overlay_doc, private_digest = _read_document(overlay_path, label="private overlay")
        if overlay_doc.get("classification") != "private":
            raise AdmissionError("private overlay must declare private classification")
        private_items = _validate_registry(
            overlay_doc,
            schema=OVERLAY_SCHEMA,
            label="private overlay",
            document_fields=OVERLAY_DOCUMENT_FIELDS,
        )
        if {item["id"] for item in public_items} & {item["id"] for item in private_items}:
            raise AdmissionError("public registry and private overlay contain duplicate item ids")
        public_keys = {item["dedupe_key"] for item in public_items}
        if public_keys & {item["dedupe_key"] for item in private_items}:
            raise AdmissionError(
                "public registry and private overlay contain duplicate semantic keys"
            )
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
    """Refuse unless every loaded item is deliberately dispositioned.

    Returns (public rows, private rows) on admission. Refusals name public
    item ids, which are public; for private rows only a count is named.
    """
    _require_runtime_file(path, label="cycle disposition")
    record, _digest = _read_document(path, label="cycle disposition")
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

    expected = set(registries.statuses)
    rows = record.get("items")
    if not isinstance(rows, list):
        raise AdmissionError("cycle disposition items must be a list")

    seen: set[tuple[str, str]] = set()
    public_blockers: list[str] = []
    private_blockers = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise AdmissionError(f"cycle disposition item {index} must be an object")
        if set(row) != ROW_FIELDS:
            raise AdmissionError(f"cycle disposition item {index} does not carry exactly the row fields")
        source = row["source"]
        item_id = row["id"]
        if (
            not isinstance(source, str)
            or source not in ROW_SOURCES
            or not isinstance(item_id, str)
            or not ITEM_ID.fullmatch(item_id)
        ):
            raise AdmissionError(f"cycle disposition item {index} has invalid identity")
        identity = (source, item_id)
        if identity in seen:
            raise AdmissionError("cycle disposition contains a duplicate obligation")
        if identity not in expected:
            raise AdmissionError(
                "cycle disposition does not exactly cover loaded standing obligations"
            )
        seen.add(identity)

        disposition = row["disposition"]
        if not isinstance(disposition, str) or disposition not in ALL_DISPOSITIONS:
            raise AdmissionError(f"cycle disposition item {index} has an invalid disposition")
        reason = row["reason"]
        if not isinstance(reason, str) or len(reason) > TEXT_BOUND:
            raise AdmissionError(f"cycle disposition item {index} has no valid reason")
        if disposition != "pending" and not reason.strip():
            raise AdmissionError(f"cycle disposition item {index} needs a reason")
        if disposition == "defer" and registries.statuses[identity] != "deferred":
            raise AdmissionError(
                f"cycle disposition item {index} defers an obligation that is not deferred"
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
            parts.append(f"{private_blockers} overlay item(s) unresolved")
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
            count = initialize_disposition(
                init, cycle_id="" if cycle_id is None else cycle_id, registries=registries
            )
            print(
                "Standing obligations loaded; local cycle disposition initialized "
                f"with {count} pending item(s)."
            )
        elif check is not None:
            public_rows, private_rows = validate_disposition(check, registries=registries)
            print(
                "Standing-obligation development admission: PASS "
                f"({public_rows} public, {private_rows} overlay item(s) dispositioned)."
            )
        else:
            print(
                "Standing-obligation registries: PASS "
                f"({len(registries.public_items)} public, "
                f"{len(registries.private_items)} overlay item(s))."
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
