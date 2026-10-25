"""What crosses the run-act gate's boundary, as data: the input stage Forge
writes for a gated run, the released output set Forge imports from one, and
the provenance a produced-application manifest records for a gated build.

THE PATH THIS SERVES (FD-021, the first-runnable architecture adopted on
2026-10-23). A provider started through the run-act gate (A-052) reads only a
read-only input stage Forge prepared, writes only into the gate's own run
directory, and what it produced comes back to Forge only as the gate's
RELEASE: a flat directory of items named by identifier, and a manifest of JSON
lines naming each item's identifier, name, size and SHA-256. Forge imports a
release only if it is complete against the completeness list the provider
was told to write and holds no credential-pattern hit; anything incomplete,
extra, linked or unreadable is refused. Verification of what was imported is
static only, and the manifest Forge then seals records where it came from.

THIS MODULE IS PURE. `layer.domain`: bytes and mappings in, text, records and
reasons out. No filesystem, no clock, no process and no interpreter state.
The adapter that reads and writes the directories is `gate_handoff`.

THE CREDENTIAL PATTERN IS FORGE-OWNED DATA, AND NEVER A CALLER'S CHOICE. The
gate searches what it holds with a seed pattern; Forge scans every released
byte again with its own copy of that pattern, `IMPORT_PATTERN`, held here in
code. No caller, workspace, released output or environment variable selects
it: the import takes no pattern argument, and every import record and gated
manifest must record exactly this pattern -- its identifier, its expressions
and their digest -- or it is refused. Changing it is a reviewed change to this
file, and may not make it weaker than the gate's current pattern. That
pattern, `sk-[A-Za-z0-9_-]{20,}`, is known to match ordinary words that end in
`sk` before a hyphen ("task-", "risk-", "desk-"); a correction has been
decided but is not built and is not effective, so nothing here depends on it.
Until an approved correction is effective, such a match -- a known false
positive included -- FAILS CLOSED: nothing is imported. The pattern is applied
by Python's `re` with `re.ASCII`; the gate applies its own with .NET's
engine; for this pattern, ASCII classes, a literal and a quantifier, the two
agree. `CredentialPattern` exists to describe and record a pattern; building
one selects nothing.

WHAT IT DOES NOT ESTABLISH. That a release came from the gate, that the
gate's cycle completed, or that the check of the gate's package passed: the
cycle identifier and the check's result digest are CITED by the act that ran
the gate and are recorded as cited, not verified (`PROVENANCE_BASIS`). The
release manifest's digest is compared with the digest the act cites; the
cited value itself comes from a journal this module does not read.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Collection, Iterable, Mapping, Sequence

STAGE_INTENT_SCHEMA = "nornyx.forge.gate_stage_intent.v1"
STAGE_MANIFEST_SCHEMA = "nornyx.forge.gate_stage_manifest.v1"
STAGE_REJECTION_SCHEMA = "nornyx.forge.gate_stage_rejection.v1"
IMPORT_INTENT_SCHEMA = "nornyx.forge.gate_import_intent.v1"
IMPORT_RECORD_SCHEMA = "nornyx.forge.gate_import_record.v1"
PROVENANCE_SCHEMA = "nornyx.forge.gate_provenance.v1"

#: The completeness list the provider writes at its workspace's root: every
#: other file it leaves there, one relative POSIX path per LF-terminated line.
COMPLETENESS_LIST = ".forge-tree.txt"

#: A role, as `provider_gate` validates one (a test holds the two equal).
ROLE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,63}\Z")
#: A stage's directory name inside the role's input zone: `s` and 16 hex.
STAGE_NAME = re.compile(r"\As[0-9a-f]{16}\Z")
#: A gate cycle's identifier, and a released item's: one plain name each.
CYCLE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
ITEM_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
#: A layout's file names: one plain segment.
_LAYOUT_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")

_SHA256 = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
#: One path segment Forge accepts from a release or writes into a stage:
#: ASCII letters, digits, `.`, `_` and `-`. No space, no `~` (an 8.3 short
#: name's mark), no `:` (a named stream or a drive), no separator, nothing
#: outside ASCII, so no two spellings Windows folds together can differ here.
_PATH_SEGMENT = re.compile(r"\A[A-Za-z0-9._-]{1,100}\Z")
_PATH_LIMIT = 400
_DEPTH_LIMIT = 32
#: Windows device names, reserved with any extension and in any case.
DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{n}" for n in range(10)} | {f"LPT{n}" for n in range(10)}
)
#: Directories that are never product, in any case, at any depth: version
#: control and Forge's own governance directory, whatever else a caller adds.
ALWAYS_RESERVED = frozenset({".git", ".nornyx"})

MANIFEST_LIMIT = 4_000_000
LIST_LIMIT = 1_000_000
ITEM_LIMIT = 2000


class GateReleaseRefused(ValueError):
    """Bytes or a record this model refuses. The message names the rule broken
    and, for released input, never quotes a matched credential."""


def sha256_text(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(document: Any) -> str:
    """The one encoding every record here is written in, with a final LF."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("a key is repeated")
    return dict(pairs)


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON value")


def strict_json(text: str) -> Any:
    """JSON with no repeated key and no NaN/Infinity; ValueError otherwise."""
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_no_constant)


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# Paths: one spelling per file, or a refusal
# ---------------------------------------------------------------------------

def segment_problem(segment: str) -> str | None:
    """Why one path segment is refused, or None."""
    if not _PATH_SEGMENT.match(segment):
        return "is not 1-100 ASCII letters, digits, '.', '_' or '-'"
    if set(segment) == {"."}:
        return "is a dot segment"
    if segment.endswith("."):
        return "ends in '.', which Windows drops, so two names would be one file"
    if segment.split(".", 1)[0].upper() in DEVICE_NAMES:
        return "is a Windows device name"
    return None


def workspace_path_problem(path: Any, reserved: Collection[str] = ()) -> str | None:
    """Why `path` -- a relative POSIX path -- is not one file Forge accepts.

    `reserved` names directories that are never product (compared without
    regard to case, at any depth), in addition to `ALWAYS_RESERVED`.
    """
    if not isinstance(path, str) or not path or len(path) > _PATH_LIMIT:
        return f"is not a path of 1 to {_PATH_LIMIT} characters"
    segments = path.split("/")
    if len(segments) > _DEPTH_LIMIT:
        return f"is deeper than {_DEPTH_LIMIT} segments"
    folded = {name.casefold() for name in ALWAYS_RESERVED} | {
        name.casefold() for name in reserved}
    for segment in segments:
        problem = segment_problem(segment)
        if problem:
            return f"has a segment that {problem}"
        if segment.casefold() in folded:
            return f"is inside {segment!r}, a directory that is never product"
    return None


def collision_problems(paths: Iterable[str]) -> list[str]:
    """Paths that would be one file on a case-insensitive file system, and a
    path that is both a file and a directory of another."""
    problems: list[str] = []
    seen: dict[str, str] = {}
    listed = sorted(paths)
    for path in listed:
        key = path.casefold()
        if key in seen:
            problems.append(f"{path!r} and {seen[key]!r} differ only in case")
        else:
            seen[key] = path
    directories = {"/".join(path.casefold().split("/")[:i])
                   for path in listed for i in range(1, path.count("/") + 1)}
    for path in listed:
        if path.casefold() in directories:
            problems.append(f"{path!r} is a file and also a directory of another path")
    return problems


# ---------------------------------------------------------------------------
# The credential pattern: Forge's own copy, as data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CredentialPattern:
    """A named set of expressions. A match of any one in a released item is a
    hit. Validated when built; `record()` is what an import records."""

    id: str
    expressions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _LAYOUT_NAME.match(self.id):
            raise GateReleaseRefused("a credential pattern's id is not one plain name")
        if (not isinstance(self.expressions, tuple) or not self.expressions
                or len(self.expressions) > 16):
            raise GateReleaseRefused("a credential pattern holds 1 to 16 expressions, as a tuple")
        for expression in self.expressions:
            if (not isinstance(expression, str) or not expression or len(expression) > 1000
                    or not expression.isascii()):
                raise GateReleaseRefused(
                    "a credential pattern's expression is not 1-1000 ASCII characters")
            try:
                compiled = re.compile(expression, re.ASCII)
            except re.error as error:
                raise GateReleaseRefused(
                    f"a credential pattern's expression does not compile: {error}") from error
            if compiled.search("") is not None:
                raise GateReleaseRefused(
                    "a credential pattern's expression matches the empty text, so it would "
                    "hit everything")

    @property
    def digest(self) -> str:
        return sha256_text(canonical({"id": self.id, "expressions": list(self.expressions)})
                           .encode("ascii"))

    def record(self) -> dict[str, Any]:
        return {"id": self.id, "expressions": list(self.expressions), "digest": self.digest}


#: Forge's copy of the gate's current seed pattern, as the gate holds it. Its
#: known false positives are described in the module docstring; it is the
#: default because it is the pattern the gate applies today.
GATE_SEED_PATTERN = CredentialPattern(
    id="d3g-seed-current",
    expressions=(r"sk-[A-Za-z0-9_-]{20,}",),
)

#: THE ONE PATTERN AN IMPORT SCANS WITH. Forge-owned, in code, never selected
#: by a caller, a workspace, a release or the environment, and never weaker
#: than the gate's current pattern (A-055). A record naming any other is
#: refused.
IMPORT_PATTERN = GATE_SEED_PATTERN


def scan_texts(data: bytes) -> tuple[str, ...]:
    """The texts a pattern is applied to for one item's bytes.

    Encoding-independent for an ASCII pattern, so the scan is at least as
    wide as the gate's: the bytes read one byte to a character (every
    ASCII-compatible encoding, valid or not), and read as UTF-16LE at both
    alignments, undecodable units replaced.
    """
    texts = [data.decode("latin-1")]
    for start in (0, 1):
        body = data[start:]
        body = body[: len(body) - (len(body) % 2)]
        if body:
            texts.append(body.decode("utf-16-le", errors="replace"))
    return tuple(texts)


def credential_hits(data: bytes, pattern: CredentialPattern) -> int:
    """How many of `pattern`'s expressions match anywhere in `data`, read as
    `scan_texts` reads it. The match itself is never returned."""
    texts = scan_texts(data)
    return sum(1 for expression in pattern.expressions
               if any(re.search(expression, text, re.ASCII) for text in texts))


# ---------------------------------------------------------------------------
# The released output set
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReleaseLayout:
    """How a release names its parts, as data the act supplies: the manifest's
    file name, an optional release-record file name that must then be present,
    and the prefix (ending in a backslash) that marks a name as a path in the
    provider's workspace. Validated when built."""

    manifest_name: str
    workspace_prefix: str
    record_name: str | None = None

    def __post_init__(self) -> None:
        names = [self.manifest_name] + ([self.record_name] if self.record_name is not None else [])
        for name in names:
            if not isinstance(name, str) or not _LAYOUT_NAME.match(name) or segment_problem(name):
                raise GateReleaseRefused("a release layout's file name is not one plain name")
        if (self.record_name is not None
                and self.record_name.casefold() == self.manifest_name.casefold()):
            raise GateReleaseRefused("a release layout names one file twice")
        prefix = self.workspace_prefix
        if (not isinstance(prefix, str) or not prefix.endswith("\\")
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}\\", prefix)):
            raise GateReleaseRefused(
                "a release layout's workspace prefix is not one plain name and a backslash")

    def reserved_entries(self) -> tuple[str, ...]:
        return (self.manifest_name,) + ((self.record_name,) if self.record_name else ())


@dataclass(frozen=True)
class ReleaseRow:
    id: str
    name: str
    size: int
    digest: str


def parse_release_manifest(data: bytes, layout: ReleaseLayout) -> list[ReleaseRow]:
    """The manifest's rows, failing closed. One JSON object per LF-terminated
    line with exactly `id`, `name`, `size` and `digest` (lower-case hex), each
    identifier and name once; strict UTF-8 with no byte-order mark and no CR.
    A manifest with no row is the single line ending `\\n`."""
    if not isinstance(data, bytes) or len(data) > MANIFEST_LIMIT:
        raise GateReleaseRefused(f"the release manifest is not bytes of at most {MANIFEST_LIMIT}")
    if data.startswith(b"\xef\xbb\xbf"):
        raise GateReleaseRefused("the release manifest begins with a byte-order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateReleaseRefused("the release manifest is not UTF-8") from error
    if "\r" in text:
        raise GateReleaseRefused("the release manifest holds a CR")
    if text == "\n":
        return []
    if not text.endswith("\n"):
        raise GateReleaseRefused("the release manifest's last line is not terminated")
    rows: list[ReleaseRow] = []
    ids: set[str] = set()
    names: set[str] = set()
    reserved = {name.casefold() for name in layout.reserved_entries()}
    for number, line in enumerate(text[:-1].split("\n"), start=1):
        try:
            entry = strict_json(line)
        except (ValueError, RecursionError) as error:
            raise GateReleaseRefused(f"release manifest line {number} is not one JSON value") \
                from error
        if not isinstance(entry, dict) or set(entry) != {"id", "name", "size", "digest"}:
            raise GateReleaseRefused(
                f"release manifest line {number} does not hold exactly id, name, size, digest")
        ident, name, size, digest = entry["id"], entry["name"], entry["size"], entry["digest"]
        if not isinstance(ident, str) or not ITEM_ID.match(ident) or segment_problem(ident):
            raise GateReleaseRefused(f"release manifest line {number} has an unusable id")
        if ident.casefold() in reserved:
            raise GateReleaseRefused(
                f"release manifest line {number} names an item the release layout reserves")
        if (not isinstance(name, str) or not name or len(name) > 512
                or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)):
            raise GateReleaseRefused(f"release manifest line {number} has an unusable name")
        if not _integer(size) or size < 0:
            raise GateReleaseRefused(f"release manifest line {number} has an unusable size")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise GateReleaseRefused(
                f"release manifest line {number} has a digest that is not 64 lower-case hex")
        if ident.casefold() in ids:
            raise GateReleaseRefused(f"release manifest names item {ident!r} twice")
        if name.casefold() in names:
            raise GateReleaseRefused(f"release manifest line {number} repeats a name")
        ids.add(ident.casefold())
        names.add(name.casefold())
        rows.append(ReleaseRow(ident, name, size, digest))
        if len(rows) > ITEM_LIMIT:
            raise GateReleaseRefused(f"the release manifest lists more than {ITEM_LIMIT} items")
    return rows


def workspace_path_of(name: str, layout: ReleaseLayout) -> str | None:
    """The workspace path a released name stands for, or None when the name
    is not a workspace name (a stream or extract the gate kept). The name is
    taken only in the gate's spelling: backslash separators, no forward slash."""
    if not name.startswith(layout.workspace_prefix):
        return None
    return name[len(layout.workspace_prefix):].replace("\\", "/")


def name_problem(name: str, layout: ReleaseLayout, reserved: Collection[str]) -> str | None:
    """Why a released name is refused, or None."""
    if "/" in name:
        return "uses '/', which is not the gate's separator, so one file could have two names"
    path = workspace_path_of(name, layout)
    if path is None:
        problem = segment_problem(name)
        return None if problem is None else f"is not a workspace path and {problem}"
    return workspace_path_problem(path, reserved)


def parse_completeness_list(data: bytes) -> list[str]:
    """The paths a provider listed: strict UTF-8, no byte-order mark, no CR,
    every line LF-terminated and non-empty, each path once."""
    if not isinstance(data, bytes) or len(data) > LIST_LIMIT:
        raise GateReleaseRefused(f"the completeness list is not bytes of at most {LIST_LIMIT}")
    if data.startswith(b"\xef\xbb\xbf"):
        raise GateReleaseRefused("the completeness list begins with a byte-order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateReleaseRefused("the completeness list is not UTF-8") from error
    if "\r" in text:
        raise GateReleaseRefused("the completeness list holds a CR")
    if not text:
        return []
    if not text.endswith("\n"):
        raise GateReleaseRefused("the completeness list's last line is not terminated")
    paths = text[:-1].split("\n")
    if any(not path for path in paths):
        raise GateReleaseRefused("the completeness list holds an empty line")
    if len(set(paths)) != len(paths):
        raise GateReleaseRefused("the completeness list names a path twice")
    if COMPLETENESS_LIST in paths:
        raise GateReleaseRefused("the completeness list names itself; it lists every OTHER file")
    return paths


def completeness_problems(listed: Sequence[str], held: Collection[str]) -> list[str]:
    """The listed paths not held, and the held paths not listed. The list
    itself is held and never listed."""
    expected = set(listed)
    present = set(held) - {COMPLETENESS_LIST}
    problems = [f"{path!r} is listed and was not released" for path in sorted(expected - present)]
    problems += [f"{path!r} was released and is not listed" for path in sorted(present - expected)]
    return problems


# ---------------------------------------------------------------------------
# Records Forge writes
# ---------------------------------------------------------------------------

def render_intent(schema: str, fields: Mapping[str, Any]) -> str:
    return canonical({"schema": schema, **fields})


def render_stage_manifest(*, role: str, stage: str, files: Mapping[str, tuple[int, str]],
                          sources: Mapping[str, Any]) -> str:
    """The stage's manifest: exactly what was written, by stage path, size and
    digest, and what each was rendered from."""
    if not ROLE.match(role) or not STAGE_NAME.match(stage):
        raise GateReleaseRefused("a stage manifest needs a valid role and stage name")
    document = {
        "schema": STAGE_MANIFEST_SCHEMA,
        "role": role,
        "stage": stage,
        "files": {path: {"size": size, "digest": digest}
                  for path, (size, digest) in sorted(files.items())},
        "sources": dict(sources),
    }
    text = canonical(document)
    validate_stage_manifest(text)
    return text


_STAGE_SOURCE_KEYS = frozenset({
    "brd", "generated_contract", "runtime_contract", "requirements", "instructions",
    "verified_import",
})


def validate_stage_manifest(text: Any) -> dict[str, Any]:
    if not isinstance(text, str) or len(text) > MANIFEST_LIMIT:
        raise GateReleaseRefused("a stage manifest is text of bounded size")
    try:
        document = strict_json(text)
    except (ValueError, RecursionError) as error:
        raise GateReleaseRefused("a stage manifest is not JSON") from error
    if not isinstance(document, dict) or set(document) != {
            "schema", "role", "stage", "files", "sources"}:
        raise GateReleaseRefused("a stage manifest holds exactly schema, role, stage, files, sources")
    if canonical(document) != text or document["schema"] != STAGE_MANIFEST_SCHEMA:
        raise GateReleaseRefused("a stage manifest is not in its schema's canonical encoding")
    if not isinstance(document["role"], str) or not ROLE.match(document["role"]):
        raise GateReleaseRefused("a stage manifest's role is not a role")
    if not isinstance(document["stage"], str) or not STAGE_NAME.match(document["stage"]):
        raise GateReleaseRefused("a stage manifest's stage is not s<16 hex>")
    files = document["files"]
    if not isinstance(files, dict) or not files or len(files) > ITEM_LIMIT:
        raise GateReleaseRefused("a stage manifest lists 1 to 2000 files")
    for path, entry in files.items():
        if workspace_path_problem(path):
            raise GateReleaseRefused(f"a stage manifest lists an unusable path {path[:80]!r}")
        if (not isinstance(entry, dict) or set(entry) != {"size", "digest"}
                or not _integer(entry["size"]) or entry["size"] < 0
                or not isinstance(entry["digest"], str) or not _SHA256.match(entry["digest"])):
            raise GateReleaseRefused(f"a stage manifest's entry for {path[:80]!r} is malformed")
    if collision_problems(files):
        raise GateReleaseRefused("a stage manifest lists two paths that would be one file")
    sources = document["sources"]
    if not isinstance(sources, dict) or set(sources) != _STAGE_SOURCE_KEYS:
        raise GateReleaseRefused(f"a stage manifest's sources are exactly {sorted(_STAGE_SOURCE_KEYS)}")
    for key in ("brd", "generated_contract", "runtime_contract", "instructions"):
        if not isinstance(sources[key], str) or not _SHA256.match(sources[key]):
            raise GateReleaseRefused(f"a stage manifest's {key} source is not a sha256 digest")
    if (not isinstance(sources["requirements"], str)
            or not _SHA256.match(sources["requirements"])):
        raise GateReleaseRefused("a stage manifest's requirements source is not a sha256 digest")
    verified = sources["verified_import"]
    if verified is not None and (not isinstance(verified, str) or not _SHA256.match(verified)):
        raise GateReleaseRefused("a stage manifest's verified import is null or a sha256 digest")
    return document


_ITEM_KINDS = ("workspace", "gate_item")


def render_import_record(*, cycle_id: str, release_manifest_digest: str,
                         release_record_digest: str | None, completeness_list_digest: str,
                         items: Sequence[Mapping[str, Any]],
                         workspace_subject_digest: str) -> str:
    """The record of a passed import: what was released, where each item now
    is, the completeness list, the pattern the scan used and the workspace's
    subject digest by the trusted verifier's rule."""
    document = {
        "schema": IMPORT_RECORD_SCHEMA,
        "state": "COMPLETE",
        "cycle_id": cycle_id,
        "release_manifest": release_manifest_digest,
        "release_record": release_record_digest,
        "completeness_list": completeness_list_digest,
        "credential_pattern": IMPORT_PATTERN.record(),
        "credential_hits": 0,
        "items": [dict(item) for item in sorted(items, key=lambda entry: entry["id"])],
        "workspace_subject_digest": workspace_subject_digest,
    }
    text = canonical(document)
    validate_import_record(text)
    return text


_RECORD_KEYS = frozenset({
    "schema", "state", "cycle_id", "release_manifest", "release_record", "completeness_list",
    "credential_pattern", "credential_hits", "items", "workspace_subject_digest",
})
_ITEM_KEYS = frozenset({"id", "name", "kind", "path", "size", "digest"})


def validate_pattern_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"id", "expressions", "digest"}:
        raise GateReleaseRefused("a credential pattern record holds exactly id, expressions, digest")
    expressions = value["expressions"]
    if not isinstance(expressions, list) or not all(isinstance(e, str) for e in expressions):
        raise GateReleaseRefused("a credential pattern record's expressions are a list of text")
    pattern = CredentialPattern(value["id"], tuple(expressions))
    if pattern.record() != value:
        raise GateReleaseRefused("a credential pattern record's digest is not its own")
    if value != IMPORT_PATTERN.record():
        raise GateReleaseRefused(
            "a credential pattern record names a pattern other than Forge's import pattern; "
            "no other pattern is accepted")
    return value


def validate_import_record(text: Any) -> dict[str, Any]:
    """An import record, failing closed: exact keys, canonical encoding,
    zero hits, every item's kind, path and digest of its one form."""
    if not isinstance(text, str) or len(text) > MANIFEST_LIMIT:
        raise GateReleaseRefused("an import record is text of bounded size")
    try:
        document = strict_json(text)
    except (ValueError, RecursionError) as error:
        raise GateReleaseRefused("an import record is not JSON") from error
    if not isinstance(document, dict) or set(document) != _RECORD_KEYS:
        raise GateReleaseRefused(f"an import record holds exactly {sorted(_RECORD_KEYS)}")
    if canonical(document) != text or document["schema"] != IMPORT_RECORD_SCHEMA:
        raise GateReleaseRefused("an import record is not in its schema's canonical encoding")
    if document["state"] != "COMPLETE" or document["credential_hits"] != 0 or isinstance(
            document["credential_hits"], bool):
        raise GateReleaseRefused("an import record is COMPLETE with zero hits, or it is not one")
    if not isinstance(document["cycle_id"], str) or not CYCLE_ID.match(document["cycle_id"]):
        raise GateReleaseRefused("an import record's cycle id is not one plain name")
    for key in ("release_manifest", "completeness_list", "workspace_subject_digest"):
        if not isinstance(document[key], str) or not _SHA256.match(document[key]):
            raise GateReleaseRefused(f"an import record's {key} is not a sha256 digest")
    record = document["release_record"]
    if record is not None and (not isinstance(record, str) or not _SHA256.match(record)):
        raise GateReleaseRefused("an import record's release_record is null or a sha256 digest")
    validate_pattern_record(document["credential_pattern"])
    items = document["items"]
    if not isinstance(items, list) or not items or len(items) > ITEM_LIMIT:
        raise GateReleaseRefused("an import record lists 1 to 2000 items")
    ids: set[str] = set()
    paths: list[str] = []
    for item in items:
        if not isinstance(item, dict) or set(item) != _ITEM_KEYS:
            raise GateReleaseRefused(f"an import record's item holds exactly {sorted(_ITEM_KEYS)}")
        if not isinstance(item["id"], str) or not ITEM_ID.match(item["id"]) or item["id"].casefold() in ids:
            raise GateReleaseRefused("an import record's item id is unusable or repeated")
        ids.add(item["id"].casefold())
        if item["kind"] not in _ITEM_KINDS or not isinstance(item["name"], str):
            raise GateReleaseRefused("an import record's item kind or name is unusable")
        if item["kind"] == "workspace":
            if workspace_path_problem(item["path"]):
                raise GateReleaseRefused("an import record's workspace path is unusable")
            paths.append(item["path"])
        elif item["path"] != item["id"]:
            raise GateReleaseRefused("an import record's gate item is kept under its own id")
        if (not _integer(item["size"]) or item["size"] < 0
                or not isinstance(item["digest"], str) or not _SHA256.match(item["digest"])):
            raise GateReleaseRefused("an import record's item size or digest is unusable")
    if items != sorted(items, key=lambda entry: entry["id"]):
        raise GateReleaseRefused("an import record's items are not in id order")
    if COMPLETENESS_LIST not in paths or collision_problems(paths):
        raise GateReleaseRefused(
            "an import record's workspace holds its completeness list and no two paths that "
            "would be one file")
    return document


# ---------------------------------------------------------------------------
# The provenance a gated build's manifest records
# ---------------------------------------------------------------------------

#: Which fields Forge verified and which it took, unverified, from the act's
#: citation. Carried in every provenance so no reader has to infer it.
PROVENANCE_BASIS: Mapping[str, Sequence[str]] = {
    "verified_by_forge": (
        "stage_manifest", "release_manifest_against_the_cited_digest", "import_record",
        "completeness_list", "credential_pattern", "run_act_sha256_is_the_pinned_value",
    ),
    "cited_by_the_act_not_verified": ("cycle_id", "check_d3g_result"),
}
#: What a gated build's verification was: static only, its tests not run.
GATE_VERIFICATION = "static_only"
GATE_TEST_EXECUTION = "not_run"

_PROVENANCE_KEYS = frozenset({
    "schema", "cycle_id", "run_act_sha256", "stage_manifest", "release_manifest",
    "import_record", "completeness_list", "check_d3g_result", "credential_pattern",
    "verification", "test_execution", "basis",
})


def gate_provenance(*, cycle_id: str, run_act_sha256: str, stage_manifest: str,
                    release_manifest: str, import_record: str, completeness_list: str,
                    check_d3g_result: str, credential_pattern: Mapping[str, Any]) -> dict[str, Any]:
    document = {
        "schema": PROVENANCE_SCHEMA,
        "cycle_id": cycle_id,
        "run_act_sha256": run_act_sha256,
        "stage_manifest": stage_manifest,
        "release_manifest": release_manifest,
        "import_record": import_record,
        "completeness_list": completeness_list,
        "check_d3g_result": check_d3g_result,
        "credential_pattern": dict(credential_pattern),
        "verification": GATE_VERIFICATION,
        "test_execution": GATE_TEST_EXECUTION,
        "basis": {key: list(value) for key, value in PROVENANCE_BASIS.items()},
    }
    validate_gate_provenance(document)
    return document


def validate_gate_provenance(value: Any) -> dict[str, Any]:
    """A provenance's shape and closed values. Whether its run-act digest is
    the pinned one is the issuer's and the handoff gate's to check: the pin
    belongs to an adapter this domain module may not import."""
    if not isinstance(value, dict) or set(value) != _PROVENANCE_KEYS:
        raise GateReleaseRefused(f"a gate provenance holds exactly {sorted(_PROVENANCE_KEYS)}")
    if value["schema"] != PROVENANCE_SCHEMA:
        raise GateReleaseRefused(f"a gate provenance's schema is {PROVENANCE_SCHEMA}")
    if not isinstance(value["cycle_id"], str) or not CYCLE_ID.match(value["cycle_id"]):
        raise GateReleaseRefused("a gate provenance's cycle id is not one plain name")
    if not isinstance(value["run_act_sha256"], str) or not _HEX64.match(value["run_act_sha256"]):
        raise GateReleaseRefused("a gate provenance's run-act digest is not 64 lower-case hex")
    for key in ("stage_manifest", "release_manifest", "import_record", "completeness_list",
                "check_d3g_result"):
        if not isinstance(value[key], str) or not _SHA256.match(value[key]):
            raise GateReleaseRefused(f"a gate provenance's {key} is not a sha256 digest")
    validate_pattern_record(value["credential_pattern"])
    if value["verification"] != GATE_VERIFICATION or value["test_execution"] != GATE_TEST_EXECUTION:
        raise GateReleaseRefused("a gated build's verification is static only, its tests not run")
    if value["basis"] != {key: list(item) for key, item in PROVENANCE_BASIS.items()}:
        raise GateReleaseRefused("a gate provenance states its basis exactly")
    return value


__all__ = [
    "ALWAYS_RESERVED",
    "COMPLETENESS_LIST",
    "CYCLE_ID",
    "CredentialPattern",
    "GATE_SEED_PATTERN",
    "GATE_TEST_EXECUTION",
    "IMPORT_PATTERN",
    "GATE_VERIFICATION",
    "GateReleaseRefused",
    "IMPORT_RECORD_SCHEMA",
    "ITEM_ID",
    "PROVENANCE_BASIS",
    "ROLE",
    "ReleaseLayout",
    "ReleaseRow",
    "STAGE_MANIFEST_SCHEMA",
    "STAGE_NAME",
    "collision_problems",
    "completeness_problems",
    "credential_hits",
    "gate_provenance",
    "name_problem",
    "parse_completeness_list",
    "parse_release_manifest",
    "render_import_record",
    "render_stage_manifest",
    "scan_texts",
    "validate_gate_provenance",
    "validate_import_record",
    "validate_stage_manifest",
    "workspace_path_of",
    "workspace_path_problem",
]
