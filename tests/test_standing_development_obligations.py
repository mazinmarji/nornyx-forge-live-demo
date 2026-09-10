"""Standing development obligations: the registry, the disposition, the overlay.

Three properties, and the boundary of each is stated beside it.

1. REGISTRY VALIDITY. The public registry parses, declares itself public,
   and carries no duplicate identifier or semantic key -- within itself, and
   across itself and a supplied overlay. Every malformed or unsupported shape
   refuses; nothing is coerced.

2. DISPOSITION DISCIPLINE. A cycle disposition is bound by content digest to
   the exact registry and overlay bytes it was written against, must cover
   the loaded items exactly, carries a closed field set and a closed
   disposition vocabulary, and refuses while any item is `pending` or
   `requires_decision`. Passing means only that. It authorizes nothing.

3. OVERLAY CONFIDENTIALITY, mechanically: an overlay is read only when a
   path is GIVEN; it must resolve outside this repository; and its path and
   contents never reach stdout, stderr, the disposition, or an exception
   message -- including the failure paths, which is where leaks live:
   invalid UTF-8, a symlink loop, a missing file under a telling directory
   name, a duplicate collision, an unknown field, a stray argument.

NOT PROVED HERE, said plainly. Nothing makes a person or a model run the
checker; a free-text `reason` a developer types is not inspected; an
identifier an overlay author chooses is bounded in shape, not judged in
meaning; and the checker is repository content, so a commit can change it.
The last is visibility rather than prevention: the checker and the registry
are governed inputs, so such a change moves the evidence digest, and a test
below pins that they are.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_standing_development_obligations.py"
PUBLIC = ROOT / "docs" / "governance" / "STANDING_DEVELOPMENT_OBLIGATIONS.json"
PROCEDURE = ROOT / "docs" / "governance" / "STANDING_DEVELOPMENT_OBLIGATIONS.md"
RUNTIME = ROOT / ".nornyx" / "runtime"

#: Strings that exist nowhere in this repository. If one of them appears in
#: any output, file or message the checker produces, overlay content leaked.
SENTINEL_TITLE = "SENTINEL-PRIVATE-TITLE-7f3a"
SENTINEL_RULE = "SENTINEL-PRIVATE-RULE-9c1d"
SENTINEL_CONDITION = "SENTINEL-PRIVATE-CONDITION-2e8b"
SENTINEL_KEY = "sentinel-private-key-5a2c"
SENTINEL_DIR = "SENTINEL-OVERLAY-DIR-b4d6"
SENTINEL_FIELD = "SENTINEL-PRIVATE-FIELD-1c9e"
SENTINEL_VALUE = "SENTINEL-PRIVATE-VALUE-3d7a"
SENTINELS = (
    SENTINEL_TITLE, SENTINEL_RULE, SENTINEL_CONDITION, SENTINEL_KEY,
    SENTINEL_DIR, SENTINEL_FIELD, SENTINEL_VALUE,
)

#: The sentence the mechanism must state wherever it is invoked from.
BOUNDARY_PHRASE = "does not authorize the development cycle"
#: The measured claim, stated wherever PASS is described: nothing about the
#: reader is established, only the disposition file's state.
MEASURED_PHRASE = "establishes nothing about whether anyone read"
#: The ONE sentence a refusal about a private overlay's content may carry.
GENERIC = "private overlay is not valid; no detail is reported for private input"


def _load_module():
    spec = importlib.util.spec_from_file_location("standing_obligations", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def module():
    return _load_module()


def _overlay_document(**overrides) -> dict:
    item = {
        "id": "PRV-001",
        "kind": "deferred_capability",
        "dedupe_key": SENTINEL_KEY,
        "status": "deferred",
        "title": SENTINEL_TITLE,
        "rule": SENTINEL_RULE,
        "reopen_condition": SENTINEL_CONDITION,
    }
    document = {
        "schema": "nornyx.forge.private_standing_overlay.v1",
        "classification": "private",
        "items": [item],
    }
    document.update(overrides)
    return document


def _write_overlay(tmp_path: Path, document=None, *, name: str = "overlay.json") -> Path:
    """An overlay OUTSIDE the repository, under a directory whose name is a sentinel."""
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir(exist_ok=True)
    path = directory / name
    payload = _overlay_document() if document is None else document
    path.write_text(json.dumps(payload), encoding="utf-8", newline="\n")
    return path


def _run(*args: str, cwd: Path = ROOT, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd, env=env, check=False, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )


def _assert_no_leak(text: str, *paths: Path) -> None:
    for sentinel in SENTINELS:
        assert sentinel not in text, f"overlay content leaked: {sentinel!r}"
    for path in paths:
        assert str(path) not in text, "the overlay path leaked"
        assert path.name not in text or path.name == "overlay.json", "the overlay name leaked"
    assert "Traceback" not in text, "a traceback escaped; its frames can carry values"


@contextmanager
def _runtime_disposition():
    """A unique disposition path under the gitignored runtime root, removed after."""
    RUNTIME.mkdir(parents=True, exist_ok=True)
    path = RUNTIME / f"test-standing-{uuid.uuid4().hex}.json"
    try:
        yield path
    finally:
        if path.is_symlink() or path.exists():
            path.unlink()


def _complete(path: Path, module, registries) -> dict:
    """Give every pending row a resolved disposition and return the record."""
    record = json.loads(path.read_text(encoding="utf-8"))
    for row in record["items"]:
        status = registries.statuses[(row["source"], row["id"])]
        row["disposition"] = "defer" if status == "deferred" else "considered"
        row["reason"] = "Read for the test cycle."
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    return record


def _refusal(module, call) -> str:
    try:
        call()
    except module.AdmissionError as exc:
        return str(exc)
    raise AssertionError("the input was accepted")


def _descriptor(path: Path, *, flags: int = 0) -> int:
    """A read descriptor for a test's own file, for the readers that take one."""
    return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | flags)


@contextmanager
def _root(module):
    """The repository root handle, closed after."""
    handle = module._open_repository_root()
    try:
        yield handle
    finally:
        os.close(handle)


def _between_inspection_and_open(module, monkeypatch, name: str, action) -> list[str]:
    """Run `action` once, after the entry called `name` is inspected and before it is opened.

    Inspection and open are both relative to the held directory. What the
    action changes under that name is what the open then meets, and the open
    refuses unless it meets the very entry that was inspected. Returns the
    list the hook appends to when it fires, so a test can hold that it did.
    """
    original = module._inspect
    fired: list[str] = []

    def inspect(handle, entry, *, label):
        info = original(handle, entry, label=label)
        if entry == name and not fired:
            fired.append(entry)
            action()
        return info

    monkeypatch.setattr(module, "_inspect", inspect)
    return fired


#: Symlink fixtures cannot be built on a Windows workstation without elevation,
#: so those tests are declared skips there, keyed by identity in the census
#: exactly as tests/test_special_files.py declares its own. Every CI test job
#: runs Linux and executes them.
posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="symlink fixtures cannot be built on a Windows workstation without elevation",
)
handle_backend_only = pytest.mark.skipif(
    os.name != "posix",
    reason="the handle backend does not exist on Windows, where a private overlay is refused before any judgment",
)


def _symlink(target: Path, link: Path) -> None:
    os.symlink(target, link)


# ---------------------------------------------------------------------------
# 1. Registry validity
# ---------------------------------------------------------------------------


def test_public_registry_is_valid_and_semantically_unique(module):
    registries = module.load_registries(None)
    assert registries.private_items == ()
    assert registries.private_digest is None
    ids = [item["id"] for item in registries.public_items]
    keys = [item["dedupe_key"] for item in registries.public_items]
    assert len(ids) == len(set(ids))
    assert len(keys) == len(set(keys))
    assert registries.public_digest == hashlib.sha256(PUBLIC.read_bytes()).hexdigest()
    document = json.loads(PUBLIC.read_text(encoding="utf-8"))
    assert document["visibility"] == "public"
    assert set(document) == {"schema", "visibility", "items"}


def test_the_public_registry_states_that_admission_is_not_authority(module):
    """The boundary is itself a standing obligation, dispositioned every cycle."""
    keys = {item["dedupe_key"]: item for item in module.load_registries(None).public_items}
    assert "admission-is-not-authority" in keys
    rule = keys["admission-is-not-authority"]["rule"].lower()
    assert "does not authorize" in rule and "authority" in rule


def _as_public(module, document, label="public registry"):
    """The same document validated as a PUBLIC one: specific diagnostics."""
    return module._validate_registry(
        document, schema=module.OVERLAY_SCHEMA, label=label,
        document_fields=module.OVERLAY_DOCUMENT_FIELDS,
    )


def test_duplicate_semantic_key_within_a_registry_is_refused_without_naming_it(module, tmp_path):
    second = dict(_overlay_document()["items"][0], id="PRV-002")
    document = _overlay_document(items=[_overlay_document()["items"][0], second])
    overlay = _write_overlay(tmp_path, document)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)
    # The public registry keeps the specific diagnostic; the overlay does not.
    assert _refusal(module, lambda: _as_public(module, document)) == (
        "public registry contains a duplicate semantic key")


def test_duplicate_item_id_within_a_registry_is_refused(module, tmp_path):
    second = dict(_overlay_document()["items"][0], dedupe_key="another-private-key")
    document = _overlay_document(items=[_overlay_document()["items"][0], second])
    overlay = _write_overlay(tmp_path, document)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)
    assert _refusal(module, lambda: _as_public(module, document)) == (
        "public registry contains a duplicate item id")


def test_private_overlay_cannot_duplicate_public_semantics(module, tmp_path):
    """A collision with the public registry names WHICH public key the overlay
    repeats, which is a fact about the overlay: the same one sentence."""
    public = json.loads(PUBLIC.read_text(encoding="utf-8"))
    item = dict(_overlay_document()["items"][0], dedupe_key=public["items"][0]["dedupe_key"])
    overlay = _write_overlay(tmp_path, _overlay_document(items=[item]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)


def test_private_overlay_cannot_reuse_a_public_id(module, tmp_path):
    public = json.loads(PUBLIC.read_text(encoding="utf-8"))
    item = dict(_overlay_document()["items"][0], id=public["items"][0]["id"])
    overlay = _write_overlay(tmp_path, _overlay_document(items=[item]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)


def _item(**overrides) -> dict:
    item = dict(_overlay_document()["items"][0])
    item.update(overrides)
    for key in [key for key, value in item.items() if value is None]:
        del item[key]
    return item


MALFORMED_OVERLAYS = [
    ("schema is a sentinel string", _overlay_document(schema=SENTINEL_VALUE)),
    ("schema absent", {k: v for k, v in _overlay_document().items() if k != "schema"}),
    ("classification absent",
     {k: v for k, v in _overlay_document().items() if k != "classification"}),
    ("classification is not private", _overlay_document(classification=SENTINEL_VALUE)),
    ("unknown top-level field", _overlay_document(**{SENTINEL_FIELD: SENTINEL_VALUE})),
    ("items is not a list", _overlay_document(items=SENTINEL_VALUE)),
    ("item is not an object", _overlay_document(items=[SENTINEL_VALUE])),
    ("unknown item field", _overlay_document(items=[_item(**{SENTINEL_FIELD: SENTINEL_VALUE})])),
    ("invalid kind", _overlay_document(items=[_item(kind=SENTINEL_VALUE)])),
    ("invalid status", _overlay_document(items=[_item(status=SENTINEL_VALUE)])),
    ("id is a sentence", _overlay_document(items=[_item(id=SENTINEL_TITLE + " with spaces")])),
    ("id is lowercase", _overlay_document(items=[_item(id="prv-001")])),
    ("id is too long", _overlay_document(items=[_item(id="P" + "A" * 70)])),
    ("id is not a string", _overlay_document(items=[_item(id=1)])),
    ("dedupe_key is uppercase", _overlay_document(items=[_item(dedupe_key=SENTINEL_KEY.upper())])),
    ("dedupe_key has spaces", _overlay_document(items=[_item(dedupe_key="a private key")])),
    ("title absent", _overlay_document(items=[_item(title=None)])),
    ("rule empty", _overlay_document(items=[_item(rule="   ")])),
    ("rule oversized", _overlay_document(items=[_item(rule="x" * 2001)])),
    ("deferred without reopen_condition",
     _overlay_document(items=[_item(reopen_condition=None)])),
    ("active with reopen_condition", _overlay_document(items=[_item(status="active")])),
    ("document is a list", [_overlay_document()]),
    ("document is a string", SENTINEL_VALUE),
]


@pytest.mark.parametrize("label, document", MALFORMED_OVERLAYS, ids=[c[0] for c in MALFORMED_OVERLAYS])
def test_a_malformed_overlay_is_refused_without_echoing_anything(module, tmp_path, label, document):
    """Every unsupported shape fails closed, and the refusal carries no value.

    Sentinels sit in the very field being refused -- the schema string, the
    unknown key's NAME, the invalid kind -- because a refusal that quotes what
    it rejected is the most natural leak there is.
    """
    overlay = _write_overlay(tmp_path, document)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC, "a content refusal about private input carries no detail"
    _assert_no_leak(message, overlay)
    completed = _run("--overlay", str(overlay))
    assert completed.returncode == 2, completed.stderr
    assert completed.stdout == "", "a refused overlay must not reach a PASS line"
    assert completed.stderr == f"REFUSE: {GENERIC}\n"
    _assert_no_leak(completed.stdout + completed.stderr, overlay)


def test_an_oversized_overlay_is_refused(module, tmp_path):
    """Over the bound is a size class; for private input it is not said."""
    padding = {"schema": "nornyx.forge.private_standing_overlay.v1", "classification": "private",
               "items": [dict(_item(), rule="x" * 1500)] * 800}
    overlay = _write_overlay(tmp_path, padding)
    assert overlay.stat().st_size > module.DOCUMENT_BYTES_BOUND
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)
    assert _refusal(module, lambda: module._read_bytes_bounded(
        _descriptor(overlay), label="public registry")) == "public registry exceeds the size bound"


# ---------------------------------------------------------------------------
# 3. Where an overlay may live, and what a bad path may say
# ---------------------------------------------------------------------------


def test_an_overlay_inside_the_repository_is_refused(module):
    RUNTIME.mkdir(parents=True, exist_ok=True)
    decoy = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    decoy.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    try:
        message = _refusal(module, lambda: module.load_registries(decoy))
        assert "outside the Forge repository" in message
        _assert_no_leak(message, decoy)
        relative = decoy.relative_to(ROOT)
        completed = _run("--overlay", str(relative))
        assert completed.returncode == 2
        _assert_no_leak(completed.stdout + completed.stderr, decoy, relative)
    finally:
        decoy.unlink()


@posix_only
def test_an_overlay_symlink_that_resolves_into_the_repository_is_refused(module, tmp_path):
    """A link outside the tree pointing into it is refused for being a link; its target is never consulted."""
    RUNTIME.mkdir(parents=True, exist_ok=True)
    inside = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    inside.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    link = tmp_path / SENTINEL_DIR / "link.json"
    link.parent.mkdir()
    try:
        _symlink(inside, link)
        message = _refusal(module, lambda: module.load_registries(link))
        assert message == "private overlay path crosses a link that is not followed"
        _assert_no_leak(message, link, inside)
    finally:
        inside.unlink()


@posix_only
def test_an_overlay_symlink_inside_the_repository_pointing_outside_is_refused(module, tmp_path):
    """The path as GIVEN is inside the tree, whatever it points at.

    A link inside the repository is a file that can be committed and that
    names its target, so the lexical rule refuses it even though the bytes
    behind it live outside.
    """
    outside = _write_overlay(tmp_path)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    link = RUNTIME / f"link-{uuid.uuid4().hex}.json"
    try:
        _symlink(outside, link)
        message = _refusal(module, lambda: module.load_registries(link))
        assert "outside the Forge repository" in message
        _assert_no_leak(message, link, outside)
    finally:
        link.unlink()


@posix_only
def test_a_symlink_loop_overlay_is_refused_without_a_traceback(tmp_path):
    """No loop is ever entered: the first link is refused for being a link, on every interpreter.

    Measured on the pathname walk: `Path.resolve` raised `RuntimeError` with
    the path in its message on CPython 3.11 and returned the unresolved path
    on 3.13, so which step refused was interpreter-dependent. Nothing
    resolves a path now; the refusal is one sentence and the path is in
    neither it nor a traceback.
    """
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    first, second = directory / "a.json", directory / "b.json"
    _symlink(second, first)
    _symlink(first, second)
    completed = _run("--overlay", str(first))
    assert completed.returncode == 2, completed.stderr
    assert completed.stderr == "REFUSE: private overlay path crosses a link that is not followed\n"
    _assert_no_leak(completed.stdout + completed.stderr, first, second)


@pytest.mark.parametrize("shape", ["missing file", "directory"])
def test_a_missing_or_directory_overlay_is_refused_without_naming_it(tmp_path, shape):
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    target = directory / "overlay.json"
    if shape == "directory":
        target.mkdir()
    completed = _run("--overlay", str(target))
    assert completed.returncode == 2, completed.stderr
    assert completed.stderr.startswith("REFUSE: private overlay")
    _assert_no_leak(completed.stdout + completed.stderr, target)


def test_invalid_utf8_overlay_bytes_are_refused_without_echoing_a_byte(tmp_path):
    """`UnicodeDecodeError` quotes the offending byte and its position."""
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    target = directory / "overlay.json"
    target.write_bytes(b"\xff\xfe" + SENTINEL_TITLE.encode("ascii") + b"\x80")
    completed = _run("--overlay", str(target))
    assert completed.returncode == 2, completed.stderr
    assert completed.stderr == f"REFUSE: {GENERIC}\n"
    output = completed.stdout + completed.stderr
    _assert_no_leak(output, target)
    assert "0xff" not in output.lower() and "position" not in output
    # The specific diagnostic still exists, for a document that is public.
    module = _load_module()
    assert _refusal(module, lambda: module._read_document(
        _descriptor(target), label="public registry")) == "public registry is not a UTF-8 JSON document"


def test_a_path_with_an_embedded_nul_is_refused(module):
    message = _refusal(module, lambda: module.load_registries(Path("over\0lay.json")))
    assert message.startswith("private overlay")
    assert "\0" not in message and "over" not in message.replace("overlay", "")


# ---------------------------------------------------------------------------
# 2. The disposition
# ---------------------------------------------------------------------------


def test_the_disposition_must_live_under_the_runtime_root(module, tmp_path):
    registries = module.load_registries(None)
    outside = tmp_path / "disposition.json"
    message = _refusal(module, lambda: module.initialize_disposition(
        outside, cycle_id="TEST", registries=registries))
    assert ".nornyx/runtime/" in message
    assert not outside.exists()
    message = _refusal(module, lambda: module.validate_disposition(outside, registries=registries))
    assert ".nornyx/runtime/" in message


@posix_only
def test_a_disposition_symlink_under_the_runtime_root_pointing_outside_is_refused(module, tmp_path):
    registries = module.load_registries(None)
    outside = tmp_path / "disposition.json"
    RUNTIME.mkdir(parents=True, exist_ok=True)
    link = RUNTIME / f"link-{uuid.uuid4().hex}.json"
    try:
        _symlink(outside, link)
        message = _refusal(module, lambda: module.initialize_disposition(
            link, cycle_id="TEST", registries=registries))
        assert message == "cycle disposition path crosses a link that is not followed"
        assert not outside.exists()
        message = _refusal(module, lambda: module.validate_disposition(link, registries=registries))
        assert message == "cycle disposition path crosses a link that is not followed"
    finally:
        link.unlink()


def test_init_refuses_to_overwrite_an_existing_disposition(module):
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        before = path.read_bytes()
        message = _refusal(module, lambda: module.initialize_disposition(
            path, cycle_id="TEST", registries=registries))
        assert "already exists" in message
        assert path.read_bytes() == before


def test_init_carries_only_opaque_identifiers_and_digests(module, tmp_path):
    """What the disposition holds from the overlay: the id, the source, a digest."""
    overlay = _write_overlay(tmp_path)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        count = module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        raw = path.read_text(encoding="utf-8")
        _assert_no_leak(raw, overlay)
        record = json.loads(raw)
        assert set(record) == module.DISPOSITION_FIELDS
        assert record["private_overlay_sha256"] == hashlib.sha256(overlay.read_bytes()).hexdigest()
        assert record["public_registry_sha256"] == hashlib.sha256(PUBLIC.read_bytes()).hexdigest()
        assert count == len(record["items"]) == len(registries.public_items) + 1
        for row in record["items"]:
            assert set(row) == module.ROW_FIELDS
            assert row["disposition"] == "pending" and row["reason"] == ""
        assert {"id": "PRV-001", "source": "private", "disposition": "pending", "reason": ""} in record["items"]
        assert b"\r" not in path.read_bytes()


def test_pending_refuses_and_a_completed_disposition_admits(module, tmp_path):
    overlay = _write_overlay(tmp_path)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "pending" in message
        _complete(path, module, registries)
        assert module.validate_disposition(path, registries=registries) == (
            len(registries.public_items), 1)


@pytest.mark.parametrize(
    "label", ["approved", "authorized", "decided", "resolved", "done", "accepted", "", "PENDING"],
)
def test_relabelling_requires_decision_does_not_manufacture_the_decision(module, label):
    """The vocabulary is closed. A word outside it is not a disposition."""
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        record["items"][0]["disposition"] = "requires_decision"
        record["items"][0]["reason"] = "An authority outside this cycle must act."
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "requires_decision" in message
        record["items"][0]["disposition"] = label
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "invalid disposition" in message


@pytest.mark.parametrize("where", ["row", "document"])
def test_a_fabricated_authority_field_is_refused(module, where):
    """`approved_by: founder` beside a row is not read, not ignored: refused."""
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        if where == "row":
            record["items"][0]["approved_by"] = "founder"
        else:
            record["human_approval"] = "granted"
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "unsupported field" in message or "exactly the row fields" in message
        assert "founder" not in message and "granted" not in message


def test_defer_is_refused_for_an_obligation_that_is_not_deferred(module, tmp_path):
    """Deferring an ACTIVE invariant would be ignoring it under a resolved label."""
    overlay = _write_overlay(tmp_path)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        private = next(row for row in record["items"] if row["source"] == "private")
        assert private["disposition"] == "defer", "the deferred overlay item may be deferred"
        active = next(row for row in record["items"] if row["source"] == "public")
        assert registries.statuses[("public", active["id"])] == "active"
        active["disposition"] = "defer"
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "not deferred" in message


def test_a_disposition_goes_stale_when_the_registry_or_overlay_changes(module, tmp_path, monkeypatch):
    # The registry is read below the root handle, so the copy that will move
    # lives under the gitignored runtime root and is named by its components.
    RUNTIME.mkdir(parents=True, exist_ok=True)
    registry_copy = RUNTIME / f"registry-{uuid.uuid4().hex}.json"
    registry_copy.write_bytes(PUBLIC.read_bytes())
    monkeypatch.setattr(module, "PUBLIC_REGISTRY", registry_copy)
    monkeypatch.setattr(module, "_PUBLIC_REGISTRY_NAMES", (".nornyx", "runtime", registry_copy.name))
    overlay = _write_overlay(tmp_path)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        _complete(path, module, registries)
        module.validate_disposition(path, registries=registries)

        # The registry moves by one byte that changes no item.
        registry_copy.write_bytes(registry_copy.read_bytes() + b"\n")
        message = _refusal(module, lambda: module.validate_disposition(
            path, registries=module.load_registries(overlay)))
        assert "stale against the public registry" in message

        registry_copy.write_bytes(PUBLIC.read_bytes())
        overlay.write_bytes(overlay.read_bytes() + b"\n")
        message = _refusal(module, lambda: module.validate_disposition(
            path, registries=module.load_registries(overlay)))
        assert "does not bind the supplied overlay set" in message
        _assert_no_leak(message, overlay)
    registry_copy.unlink()


def test_the_overlay_set_must_match_between_init_and_check(module, tmp_path):
    overlay = _write_overlay(tmp_path)
    with_overlay = module.load_registries(overlay)
    without = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=with_overlay)
        _complete(path, module, with_overlay)
        message = _refusal(module, lambda: module.validate_disposition(path, registries=without))
        assert "does not bind the supplied overlay set" in message
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=without)
        _complete(path, module, without)
        message = _refusal(module, lambda: module.validate_disposition(path, registries=with_overlay))
        assert "does not bind the supplied overlay set" in message


@pytest.mark.parametrize("mutation", ["row removed", "row added", "row duplicated", "source swapped"])
def test_coverage_must_be_exact(module, tmp_path, mutation):
    overlay = _write_overlay(tmp_path)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        rows = record["items"]
        if mutation == "row removed":
            rows.pop()
        elif mutation == "row added":
            rows.append(dict(rows[0], id="FGR-SDO-999"))
        elif mutation == "row duplicated":
            rows.append(dict(rows[0]))
        else:
            rows[-1]["source"] = "public"
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "exactly cover" in message or "duplicate obligation" in message
        _assert_no_leak(message, overlay)


@pytest.mark.parametrize(
    "reason", ["", "   ", "x" * 2001, 7], ids=["empty", "blank", "oversized", "not a string"],
)
def test_a_reason_is_required_and_bounded(module, reason):
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        record["items"][0]["reason"] = reason
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "reason" in message
        assert "x" * 50 not in message


def test_admission_is_re_evaluated_on_every_check(module):
    """There is no stored admission to reuse: a PASS is the state of the file NOW."""
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        module.validate_disposition(path, registries=registries)
        record["items"][-1]["disposition"] = "pending"
        record["items"][-1]["reason"] = ""
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "pending" in message


def test_refusals_name_public_ids_and_no_count_for_private_rows(module, tmp_path):
    """A refusal says an overlay item is unresolved, not how many there are."""
    two = _overlay_document(items=[_item(), _item(id="PRV-002", dedupe_key="another-private-key")])
    overlay = _write_overlay(tmp_path, two)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "FGR-SDO-001: pending" in message
        assert "overlay items unresolved" in message
        assert "2 overlay" not in message and "PRV-001" not in message and "PRV-002" not in message
        _assert_no_leak(message, overlay)


@pytest.mark.parametrize(
    "cycle_id", ["", " ", "x" * 65, "has space", SENTINEL_TITLE + " sentence"],
    ids=["empty", "blank", "oversized", "space", "sentence"],
)
def test_cycle_id_is_a_bounded_token(module, cycle_id):
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        message = _refusal(module, lambda: module.initialize_disposition(
            path, cycle_id=cycle_id, registries=registries))
        assert "--cycle-id" in message
        assert not path.exists()
        _assert_no_leak(message)


# ---------------------------------------------------------------------------
# 3. The command line: output, discovery, arguments
# ---------------------------------------------------------------------------


def test_private_overlay_content_and_path_are_not_emitted_on_any_path(module, tmp_path):
    overlay = _write_overlay(tmp_path)
    with _runtime_disposition() as path:
        transcripts = []
        completed = _run("--overlay", str(overlay))
        assert completed.returncode == 0, completed.stderr
        transcripts.append(completed)
        completed = _run("--overlay", str(overlay), "--init", str(path), "--cycle-id", "CLI-1")
        assert completed.returncode == 0, completed.stderr
        transcripts.append(completed)
        completed = _run("--overlay", str(overlay), "--check-disposition", str(path))
        assert completed.returncode == 2
        transcripts.append(completed)
        _complete(path, module, module.load_registries(overlay))
        completed = _run("--overlay", str(overlay), "--check-disposition", str(path))
        assert completed.returncode == 0, completed.stderr
        transcripts.append(completed)
        for completed in transcripts:
            _assert_no_leak(completed.stdout + completed.stderr, overlay)
        assert "PASS" in transcripts[-1].stdout
        assert module.OVERLAY_NOTICE in transcripts[-1].stdout


def test_the_pass_output_states_the_admission_boundary(module):
    with _runtime_disposition() as path:
        completed = _run("--init", str(path), "--cycle-id", "CLI-2")
        assert completed.returncode == 0, completed.stderr
        assert module.ADMISSION_BOUNDARY in completed.stdout
        _complete(path, module, module.load_registries(None))
        completed = _run("--check-disposition", str(path))
        assert completed.returncode == 0, completed.stderr
        assert module.ADMISSION_BOUNDARY in completed.stdout
        assert "authorizes nothing" in completed.stdout
    completed = _run("--help")
    assert completed.returncode == 0
    # argparse re-wraps the epilog at the terminal width.
    assert "authorizes nothing" in " ".join(completed.stdout.split())


def test_no_overlay_is_discovered_from_cwd_home_or_environment(module, tmp_path):
    """Decoys everywhere a discovering checker might look; none is read."""
    for relative in ("overlay.json", "private-overlay.json", ".nornyx/overlay.json",
                     ".nornyx/runtime/overlay.json", "STANDING_DEVELOPMENT_OBLIGATIONS.json"):
        decoy = tmp_path / relative
        decoy.parent.mkdir(parents=True, exist_ok=True)
        decoy.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    env = dict(os.environ)
    env.update({
        "HOME": str(tmp_path), "USERPROFILE": str(tmp_path),
        "FORGE_STANDING_OVERLAY": str(tmp_path / "overlay.json"),
        "NORNYX_STANDING_OVERLAY": str(tmp_path / "overlay.json"),
        "STANDING_OVERLAY": str(tmp_path / "overlay.json"),
        "OVERLAY": str(tmp_path / "overlay.json"),
    })
    with _runtime_disposition() as path:
        completed = _run("--init", str(path), "--cycle-id", "CLI-3", cwd=tmp_path, env=env)
        assert completed.returncode == 0, completed.stderr
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["private_overlay_sha256"] is None
        assert all(row["source"] == "public" for row in record["items"])
        assert "overlay" not in completed.stdout.lower()
        _assert_no_leak(completed.stdout + completed.stderr)


def test_a_stray_argument_is_refused_without_being_echoed(tmp_path):
    overlay = _write_overlay(tmp_path)
    completed = _run(str(overlay))
    assert completed.returncode == 2
    assert completed.stderr.startswith("REFUSE: invalid arguments")
    _assert_no_leak(completed.stdout + completed.stderr, overlay)
    completed = _run("--overlay")
    assert completed.returncode == 2
    _assert_no_leak(completed.stdout + completed.stderr, overlay)


def test_the_parser_has_no_overlay_default(module):
    args = module.build_parser().parse_args([])
    assert args.overlay is None and args.init is None and args.check_disposition is None


# ---------------------------------------------------------------------------
# Closures from the in-session adversarial review of the first repaired head
# ---------------------------------------------------------------------------


def _raw_overlay(tmp_path: Path, text: str, *, name: str = "overlay.json") -> Path:
    """An overlay written as TEXT, for shapes `json.dumps` cannot produce."""
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


_VALID_ITEM_TEXT = json.dumps(_overlay_document()["items"][0])


@pytest.mark.parametrize(
    "label, text",
    [
        ("classification shadowed",
         '{"schema": "nornyx.forge.private_standing_overlay.v1", "classification": "'
         + SENTINEL_VALUE + '", "classification": "private", "items": [' + _VALID_ITEM_TEXT + "]}"),
        ("items shadowed with a smuggled field",
         '{"schema": "nornyx.forge.private_standing_overlay.v1", "classification": "private", '
         '"items": [{"' + SENTINEL_FIELD + '": "' + SENTINEL_VALUE + '", "approved_by": "founder"}], '
         '"items": [' + _VALID_ITEM_TEXT + "]}"),
        ("item field repeated",
         '{"schema": "nornyx.forge.private_standing_overlay.v1", "classification": "private", '
         '"items": [{"id": "PRV-001", "id": "PRV-001", "kind": "deferred_capability", '
         '"dedupe_key": "' + SENTINEL_KEY + '", "status": "deferred", "title": "' + SENTINEL_TITLE
         + '", "rule": "' + SENTINEL_RULE + '", "reopen_condition": "' + SENTINEL_CONDITION + '"}]}'),
    ],
)
def test_a_repeated_json_key_is_refused_rather_than_last_wins(module, tmp_path, label, text):
    """`json.loads` keeps the last value of a repeated key and says nothing.

    Measured on the first repaired head: a shadowed `classification`, a
    shadowed `items` carrying `approved_by`, and a repeated row field all
    passed, because the closed field sets only ever saw the survivor.
    """
    overlay = _raw_overlay(tmp_path, text)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)
    # The pairs hook is what refuses; pinned by name on the public path.
    assert _refusal(module, lambda: module._read_document(
        _descriptor(overlay), label="public registry")) == "public registry repeats a key inside one object"
    completed = _run("--overlay", str(overlay))
    assert completed.returncode == 2
    _assert_no_leak(completed.stdout + completed.stderr, overlay)


def test_a_repeated_key_in_a_disposition_row_cannot_hide_a_stop(module):
    """The row a person reads said `requires_decision`; the survivor said `considered`."""
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        text = json.dumps(record)
        first_row = json.dumps(record["items"][0])
        shadowed = first_row[:-1] + ', "disposition": "requires_decision", "disposition": "considered"}'
        assert first_row in text
        path.write_text(text.replace(first_row, shadowed, 1), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "repeats a key" in message


@pytest.mark.parametrize(
    "field, value",
    [
        ("id", "PRV-001\n"),
        ("id", "FGR-SDO-001\n"),
        ("dedupe_key", "development-cycle-standing-obligation-admission\n"),
        ("dedupe_key", SENTINEL_KEY + "\r"),
    ],
    ids=["id with newline", "public id plus newline", "public key plus newline", "key with CR"],
)
def test_a_trailing_line_break_does_not_satisfy_an_identifier_grammar(module, tmp_path, field, value):
    """`$` matches before a final newline; `fullmatch` does not.

    Measured on the first repaired head: `PRV-001` plus a newline was
    accepted and written into the disposition, and a public id plus a
    newline walked past the cross-registry duplicate check.
    """
    document = _overlay_document(items=[_item(**{field: value})])
    overlay = _write_overlay(tmp_path, document)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)
    assert _refusal(module, lambda: _as_public(module, document)) == (
        f"public registry item 0 has no valid {field}")


def test_a_cycle_id_with_a_trailing_newline_is_refused(module):
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        message = _refusal(module, lambda: module.initialize_disposition(
            path, cycle_id="TEST\n", registries=registries))
        assert "--cycle-id" in message
        assert not path.exists()


@posix_only
def test_a_symlink_chain_that_passes_through_the_repository_is_refused(module, tmp_path):
    """Outside at both ends, inside in the middle: the middle hop is committable.

    Measured on the first repaired head: `outside/a -> repo/.nornyx/runtime/b
    -> outside/c` passed, because only the given path and the final
    resolution were judged. No link is followed now: the chain is refused at
    its first link, and the middle hop is never consulted.
    """
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    final = _write_overlay(tmp_path, name="good.json")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    middle = RUNTIME / f"hop-{uuid.uuid4().hex}.json"
    first = directory / "hop1.json"
    try:
        _symlink(final, middle)
        _symlink(middle, first)
        message = _refusal(module, lambda: module.load_registries(first))
        assert message == "private overlay path crosses a link that is not followed"
        _assert_no_leak(message, first, middle, final)
    finally:
        middle.unlink()


@posix_only
def test_a_link_reached_through_a_directory_symlink_into_the_repository_is_refused(module, tmp_path):
    """A directory link on the way is refused as a link before anything below it is consulted."""
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    final = _write_overlay(tmp_path, name="good.json")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    inside = RUNTIME / f"dir-{uuid.uuid4().hex}"
    inside.mkdir()
    try:
        _symlink(final, inside / "out.json")
        _symlink(inside, directory / "dirlink")
        given = directory / "dirlink" / "out.json"
        message = _refusal(module, lambda: module.load_registries(given))
        assert message == "private overlay path crosses a link that is not followed"
        _assert_no_leak(message, given, final)
    finally:
        (inside / "out.json").unlink()
        inside.rmdir()


@posix_only
def test_a_fifo_overlay_is_refused_without_blocking(tmp_path):
    """One open, non-blocking, `fstat` on the descriptor: a FIFO is refused, not read."""
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    fifo = directory / "overlay.json"
    os.mkfifo(fifo)
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--overlay", str(fifo)],
        cwd=ROOT, check=False, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=30,
    )
    assert completed.returncode == 2
    # What the object IS -- a FIFO, a directory -- stays with the caller when
    # the input is private; a public document is told.
    assert completed.stderr == "REFUSE: private overlay cannot be read\n"
    _assert_no_leak(completed.stdout + completed.stderr, fifo)
    module = _load_module()
    assert _refusal(module, lambda: module._read_bytes_bounded(
        _descriptor(fifo, flags=os.O_NONBLOCK), label="cycle disposition")) == (
        "cycle disposition is not a regular file")


@pytest.mark.parametrize(
    "label, document",
    [
        ("kind is a list", _overlay_document(items=[_item(kind=[SENTINEL_VALUE])])),
        ("status is an object", _overlay_document(items=[_item(status={SENTINEL_FIELD: 1})])),
    ],
)
def test_an_unhashable_value_is_refused_with_a_label(module, tmp_path, label, document):
    """`x not in frozenset` raises `TypeError` on a list; that is not a refusal."""
    overlay = _write_overlay(tmp_path, document)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    _assert_no_leak(message, overlay)
    public = _refusal(module, lambda: _as_public(module, document))
    assert public in ("public registry item 0 has an invalid kind",
                      "public registry item 0 has an invalid status")


@pytest.mark.parametrize("field", ["source", "disposition"])
def test_an_unhashable_row_value_is_refused_with_a_label(module, field):
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        record["items"][0][field] = [SENTINEL_VALUE]
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "invalid identity" in message or "invalid disposition" in message
        assert SENTINEL_VALUE not in message


def test_a_deeply_nested_document_is_refused_with_a_label(module, tmp_path):
    """`RecursionError` out of the JSON parser is not a `ValueError`."""
    overlay = _raw_overlay(tmp_path, "[" * 200_000 + SENTINEL_VALUE)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == GENERIC
    assert _refusal(module, lambda: module._read_document(
        _descriptor(overlay), label="public registry")) == "public registry is not a UTF-8 JSON document"
    completed = _run("--overlay", str(overlay))
    assert completed.returncode == 2
    assert "unexpected failure" not in completed.stderr
    _assert_no_leak(completed.stdout + completed.stderr, overlay)


def test_a_repeated_option_is_refused_rather_than_last_wins(tmp_path):
    """`--overlay A --overlay B` read B and never bound A."""
    good = _write_overlay(tmp_path, name="good.json")
    bad = _write_overlay(tmp_path, _overlay_document(schema=SENTINEL_VALUE), name="bad.json")
    for order in ((bad, good), (good, bad)):
        completed = _run("--overlay", str(order[0]), "--overlay", str(order[1]))
        assert completed.returncode == 2
        assert "--overlay may be given once" in completed.stderr
        _assert_no_leak(completed.stdout + completed.stderr, good, bad)
    with _runtime_disposition() as path:
        completed = _run("--init", str(path), "--init", str(path), "--cycle-id", "X")
        assert completed.returncode == 2 and "--init may be given once" in completed.stderr
        assert not path.exists()


@pytest.mark.parametrize("shape", ["invalid utf-8", "missing file", "symlink loop"])
def test_a_refusal_carries_no_context_or_cause(module, tmp_path, shape):
    """`from None` hides `__context__` from a traceback; it does not remove it.

    The original `OSError` or `UnicodeDecodeError` -- filename or byte inside
    -- would still hang off the refusal for any caller that looked. The
    loaders raise outside the handler instead, so there is nothing to find.
    """
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    target = directory / "overlay.json"
    if shape == "invalid utf-8":
        target.write_bytes(b"\xff" + SENTINEL_TITLE.encode("ascii"))
    elif shape == "symlink loop":
        if os.name != "posix":
            target.write_bytes(b"\xff")
        else:
            other = directory / "other.json"
            _symlink(other, target)
            _symlink(target, other)
    try:
        module.load_registries(target)
    except module.AdmissionError as exc:
        assert exc.__context__ is None and exc.__cause__ is None
        _assert_no_leak(repr(exc), target)
    else:
        raise AssertionError("the overlay was accepted")


# ---------------------------------------------------------------------------
# Closures from the Codex review of the merged head
# ---------------------------------------------------------------------------


@posix_only
def test_a_directory_symlink_chain_through_the_repository_is_refused(module, tmp_path):
    """`outside/a -> repo/.nornyx/runtime/dir -> outside/final`, given `outside/a/overlay.json`.

    Measured by the Codex review on the merged head: PASS. `realpath` of the
    parent followed the directory link all the way to `outside/final`, so the
    in-repository directory link in the middle was never judged. No link is
    followed now: `outside/a` is refused for being one, and the middle hop
    is never consulted.
    """
    final = tmp_path / "final"
    final.mkdir()
    (final / "overlay.json").write_text(
        json.dumps(_overlay_document()), encoding="utf-8", newline="\n"
    )
    RUNTIME.mkdir(parents=True, exist_ok=True)
    middle = RUNTIME / f"dirlink-{uuid.uuid4().hex}"
    outside = tmp_path / SENTINEL_DIR
    outside.mkdir()
    try:
        _symlink(final, middle)
        _symlink(middle, outside / "a")
        given = outside / "a" / "overlay.json"
        message = _refusal(module, lambda: module.load_registries(given))
        assert message == "private overlay path crosses a link that is not followed"
        _assert_no_leak(message, given, middle, final)
        completed = _run("--overlay", str(given))
        assert completed.returncode == 2
        _assert_no_leak(completed.stdout + completed.stderr, given, middle, final)
    finally:
        middle.unlink()


def test_no_successful_output_carries_an_overlay_derived_count(module, tmp_path):
    """The overlay's item count is a fact about the overlay, and is not printed.

    Two overlays of different sizes must produce byte-identical PASS output on
    every successful path, so nothing about the size survives into a log.
    """
    one = _write_overlay(tmp_path, name="one.json")
    three = _write_overlay(
        tmp_path,
        _overlay_document(items=[
            _item(),
            _item(id="PRV-002", dedupe_key="second-private-key"),
            _item(id="PRV-003", dedupe_key="third-private-key"),
        ]),
        name="three.json",
    )
    outputs = []
    for overlay in (one, three):
        transcript = []
        completed = _run("--overlay", str(overlay))
        assert completed.returncode == 0, completed.stderr
        transcript.append(completed.stdout)
        with _runtime_disposition() as path:
            completed = _run("--overlay", str(overlay), "--init", str(path), "--cycle-id", "N")
            assert completed.returncode == 0, completed.stderr
            transcript.append(completed.stdout)
            _complete(path, module, module.load_registries(overlay))
            completed = _run("--overlay", str(overlay), "--check-disposition", str(path))
            assert completed.returncode == 0, completed.stderr
            transcript.append(completed.stdout)
        outputs.append(transcript)
    assert outputs[0] == outputs[1], "the output differs with the overlay's size"
    for text in outputs[0]:
        assert "plus" in text and module.OVERLAY_NOTICE in text
        assert "3" not in text.replace("SHA-256", "")


def test_a_reason_is_not_inspected_and_the_document_says_so(module):
    """A `reason` can carry any sentence; the checker neither reads nor endorses it.

    Measured by the Codex review on the merged head: a reason reading
    `Approved by the founder; release is authorized` passed. That is the
    stated limitation, and the wording that used to say nothing potentially
    misleading rides along is narrowed to the closed field sets it measures.
    """
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        for row in record["items"]:
            row["reason"] = "Approved by the founder; release is authorized."
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        module.validate_disposition(path, registries=registries)
    text = " ".join(PROCEDURE.read_text(encoding="utf-8").split())
    assert "neither reads nor endorses" in text


# ---------------------------------------------------------------------------
# Closures from the second Codex review, on the PR head
# ---------------------------------------------------------------------------


@posix_only
def test_a_double_slash_spelling_of_an_in_repository_path_is_refused(module):
    """`//home/.../repo/...` is the repository to the kernel and a different anchor to a lexical rule.

    Measured on the merged head: an in-repository path spelled with two
    leading slashes was outside to every walked component. The spelling is
    collapsed before the walk, and every directory held is compared by
    identity as well, so the shape refuses under either rule.
    """
    decoy = _in_repository_decoy()
    try:
        spelled = Path("//" + str(decoy).lstrip("/"))
        message = _refusal(module, lambda: module.load_registries(spelled))
        assert message == "private overlay must remain outside the Forge repository"
        _assert_no_leak(message, decoy)
    finally:
        decoy.unlink()


def test_an_alternate_spelling_of_the_repository_is_caught_by_identity(module, monkeypatch, tmp_path):
    r"""The lexical rule compares spellings; identity names the directory.

    Measured against the pure name comparison: with it switched off, an
    in-repository overlay is still refused, because a directory the walk
    holds on the way to it IS a repository directory by device and inode.
    Off the repository nothing matches. This is the backstop for a bind
    mount on POSIX, and for `\\?\C:\...`, a mapped drive or an
    administrative share on a platform that gains a handle backend.
    """
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with _root(module) as root:
        identities = module._repository_directory_identities(root)
    for directory in (ROOT, ROOT / "docs", ROOT / "docs" / "governance", RUNTIME):
        assert module._identity_of(os.lstat(directory)) in identities, directory
    assert module._identity_of(os.lstat(tmp_path)) not in identities
    decoy = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    decoy.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    monkeypatch.setattr(module, "_is_within", lambda path, parent: False)
    try:
        message = _refusal(module, lambda: module.load_registries(decoy))
        assert message == "private overlay must remain outside the Forge repository"
        _assert_no_leak(message, decoy)
        assert module.load_registries(_write_overlay(tmp_path)).private_digest is not None
    finally:
        decoy.unlink()


def test_an_alias_rooted_below_the_repository_root_is_inside(module, monkeypatch, tmp_path):
    """A bind mount or mapped drive of a SUBDIRECTORY has no root among its ancestors.

    Measured by the Codex review on the PR head, and reproduced with a real
    bind mount of `.nornyx/runtime` at `/tmp/alias`: the checker read an
    in-repository overlay through the alias and printed PASS, because the
    identity comparison was against the root alone and the alias's ancestors
    are the mounted child and external directories. Every repository
    directory's identity is compared now, for every directory the walk
    holds. Simulated here without a mount -- a mount needs a privilege the
    census must not depend on -- by placing the alias directory's identity
    in the repository's identity set, exactly as a mount point's would be
    there.
    """
    overlay = _write_overlay(tmp_path)
    alias = module._identity_of(os.lstat(overlay.parent))
    with _root(module) as root:
        real = module._repository_directory_identities(root)
    assert alias not in real
    monkeypatch.setattr(module, "_repository_directory_identities", lambda root: real | {alias})
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == "private overlay must remain outside the Forge repository"
    _assert_no_leak(message, overlay)


@posix_only
def test_the_identity_traversal_follows_no_link_and_is_bounded(module, monkeypatch, tmp_path):
    """The one traversal is of the repository's own directories, and no further.

    A link inside the tree to a directory outside it is not followed, so the
    outside directory's identity never enters the set and an overlay beside
    it stays admissible; a link to the root is not followed either, so the
    traversal cannot loop. Past its bound the traversal refuses rather than
    judging partially.
    """
    RUNTIME.mkdir(parents=True, exist_ok=True)
    outward = RUNTIME / f"outward-{uuid.uuid4().hex}"
    upward = RUNTIME / f"upward-{uuid.uuid4().hex}"
    try:
        _symlink(tmp_path, outward)
        _symlink(ROOT, upward)
        with _root(module) as root:
            identities = module._repository_directory_identities(root)
        assert module._identity_of(os.lstat(tmp_path)) not in identities
        overlay = _write_overlay(tmp_path)
        assert module.load_registries(overlay).private_digest is not None
        monkeypatch.setattr(module, "DIRECTORY_SCAN_BOUND", 1)
        message = _refusal(module, lambda: module.load_registries(overlay))
        assert message == "repository is too large to judge by identity"
    finally:
        outward.unlink()
        upward.unlink()


def _entry_like(name: str, info):
    """A directory entry as the traversal sees one: a name, and an `lstat` result or its failure."""

    class Entry:
        def __init__(self) -> None:
            self.path = name
            self.name = name

        def stat(self, *, follow_symlinks: bool = True):
            if isinstance(info, BaseException):
                raise info
            return info

    return Entry()


def test_a_stat_failure_during_the_identity_traversal_refuses(module, monkeypatch, tmp_path):
    """An entry the traversal cannot inspect refuses the whole judgment, not that entry alone.

    Measured by the fourth Codex review on the PR head: a failed `lstat` of a
    repository entry was skipped, so that directory and everything below it
    were missing from the identity set, and an alias of it -- a bind mount, a
    mapped drive -- carried an in-repository overlay past the identity
    comparison. Reproduced with a directory whose full name is too long to
    `lstat` and a bind mount of it: the traversal completed with one identity
    fewer, and the overlay was read through the alias and accepted. A failure
    is a refusal now, the same one a failed scan gives; the traversal lists
    from a descriptor, so the failing entry is supplied to it by name.
    """
    RUNTIME.mkdir(parents=True, exist_ok=True)
    marked = RUNTIME / f"unstat-{uuid.uuid4().hex}"
    marked.mkdir()
    overlay = _write_overlay(tmp_path)
    runtime_identity = module._identity_of(os.lstat(RUNTIME))
    real_scandir = os.scandir

    def failing_view(handle):
        listing_runtime = module._identity_of(os.fstat(handle)) == runtime_identity
        with real_scandir(handle) as entries:
            for entry in entries:
                if listing_runtime and entry.name == marked.name:
                    yield _entry_like(entry.name, OSError(errno.EIO, "input/output error"))
                else:
                    yield entry

    monkeypatch.setattr(os, "scandir", failing_view)
    try:
        message = _refusal(module, lambda: module.load_registries(overlay))
        assert message == "repository directories cannot be judged by identity"
        _assert_no_leak(message, marked, overlay)
    finally:
        monkeypatch.setattr(os, "scandir", real_scandir)
        marked.rmdir()


def test_the_identity_traversal_scans_each_directory_once_whatever_its_aliases(module, monkeypatch):
    """One scan per directory identity, so the bound limits the work and not only the set.

    Measured by the fourth Codex review on the PR head: an alias of a
    directory inside the tree added nothing to the identity set but was
    traversed again in full, so the scan bound counted identities while the
    work grew with every alias. Reproduced with three bind mounts of `docs/`
    under `.nornyx/runtime/`: twelve more scans, the bound -- set to exactly
    the unique count -- never crossed. An identity already seen is not
    opened again, so the traversal performs exactly one scan per identity,
    the root included. Simulated here without a mount by listing one
    directory under three more names that carry its `lstat` result: the
    names do not exist, so had the traversal tried to open one, the judgment
    would have refused rather than passed.
    """
    RUNTIME.mkdir(parents=True, exist_ok=True)
    aliased = RUNTIME / f"aliased-{uuid.uuid4().hex}"
    (aliased / "below").mkdir(parents=True)
    alias_names = [f"alias-{index}-{uuid.uuid4().hex}" for index in range(3)]
    runtime_identity = module._identity_of(os.lstat(RUNTIME))
    real_scandir = os.scandir
    scans: list[int] = []

    def aliased_view(handle):
        scans.append(handle)
        listing_runtime = module._identity_of(os.fstat(handle)) == runtime_identity
        with real_scandir(handle) as entries:
            for entry in entries:
                yield entry
                if listing_runtime and entry.name == aliased.name:
                    info = entry.stat(follow_symlinks=False)
                    for alias in alias_names:
                        yield _entry_like(alias, info)

    monkeypatch.setattr(os, "scandir", aliased_view)
    try:
        with _root(module) as root:
            identities = module._repository_directory_identities(root)
            assert module._identity_of(os.lstat(aliased)) in identities
            assert module._identity_of(os.lstat(aliased / "below")) in identities
            assert len(scans) == len(identities), "a directory was scanned more than once"
            monkeypatch.setattr(module, "DIRECTORY_SCAN_BOUND", len(identities))
            scans.clear()
            assert module._repository_directory_identities(root) == identities
            assert len(scans) == len(identities)
    finally:
        monkeypatch.setattr(os, "scandir", real_scandir)
        (aliased / "below").rmdir()
        aliased.rmdir()


def _in_repository_decoy() -> Path:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    decoy = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    decoy.write_text(json.dumps(_overlay_document(items=[_item(id="PRV-EVIL")])),
                     encoding="utf-8", newline="\n")
    return decoy


@posix_only
def test_a_file_replaced_by_an_in_repository_link_after_the_walk_is_refused(module, tmp_path, monkeypatch):
    """A link put at the name between inspection and open is met by `O_NOFOLLOW`, not followed."""
    overlay = _write_overlay(tmp_path)
    decoy = _in_repository_decoy()

    def swap():
        overlay.unlink()
        _symlink(decoy, overlay)

    try:
        fired = _between_inspection_and_open(module, monkeypatch, overlay.name, swap)
        message = _refusal(module, lambda: module.load_registries(overlay))
        assert fired, "the swap never ran"
        assert message == "private overlay path cannot be resolved"
        _assert_no_leak(message, overlay, decoy)
    finally:
        decoy.unlink()


def test_a_file_replaced_by_another_after_the_walk_is_refused(module, tmp_path, monkeypatch):
    """Same name, different object: the open relative to the held directory meets the other and refuses.

    Needs no link, so it runs on every platform with the handle backend.
    """
    overlay = _write_overlay(tmp_path)
    other = _write_overlay(tmp_path, _overlay_document(items=[_item(id="PRV-OTHER")]), name="other.json")
    fired = _between_inspection_and_open(module, monkeypatch, overlay.name, lambda: os.replace(other, overlay))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert fired, "the swap never ran"
    assert message == "private overlay changed during admission"
    _assert_no_leak(message, overlay, other)


def test_a_file_that_appears_only_after_the_walk_is_refused(module, tmp_path, monkeypatch):
    """Nothing at the name when it was inspected: refused there, and nothing that appears later is consulted.

    The same holds for the disposition: an absent one is refused at its
    inspection, before any open, so a file written after that inspection is
    never read.
    """
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    overlay = directory / "overlay.json"
    fired = _between_inspection_and_open(module, monkeypatch, overlay.name, lambda: overlay.write_text(
        json.dumps(_overlay_document()), encoding="utf-8", newline="\n"))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == "private overlay path cannot be resolved"
    assert not fired and not overlay.exists(), "an absent entry was stepped past"
    _assert_no_leak(message, overlay)

    registries = module.load_registries(None)
    with _runtime_disposition() as path:

        def appear():
            module.initialize_disposition(path, cycle_id="TEST", registries=registries)
            _complete(path, module, registries)

        fired = _between_inspection_and_open(module, monkeypatch, path.name, appear)
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert message == "cycle disposition cannot be read"
        assert not fired and not path.exists()


def test_the_disposition_read_is_bound_to_the_judged_object_too(module, tmp_path, monkeypatch):
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        _complete(path, module, registries)
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(path.read_bytes())
        fired = _between_inspection_and_open(module, monkeypatch, path.name, lambda: os.replace(replacement, path))
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert fired, "the swap never ran"
        assert message == "cycle disposition changed during admission"


def _many(count: int, **last) -> list[dict]:
    items = [_item(id=f"PRV-{index:03d}", dedupe_key=f"private-key-{index:03d}") for index in range(count)]
    if last:
        items[-1] = _item(id=f"PRV-{count - 1:03d}", dedupe_key=f"private-key-{count - 1:03d}", **last)
    return items


def _private_content_defects(tmp_path: Path) -> list[tuple[str, Path]]:
    """Materially different defects: index, count, size, nesting, duplicate position."""
    nested = dict(_item(), title={SENTINEL_FIELD: {SENTINEL_FIELD: [SENTINEL_VALUE]}})
    duplicate_late = _many(300)
    duplicate_late[299] = dict(duplicate_late[299], id="PRV-000")
    shapes = [
        ("invalid kind at index 0 of 1", json.dumps(_overlay_document(items=[_item(kind=SENTINEL_VALUE)]))),
        ("invalid kind at index 42 of 43", json.dumps(_overlay_document(items=_many(43, kind=SENTINEL_VALUE)))),
        ("unknown field in the 7th of 7 items",
         json.dumps(_overlay_document(items=_many(7, **{SENTINEL_FIELD: SENTINEL_VALUE})))),
        ("duplicate id at position 299 of 300", json.dumps(_overlay_document(items=duplicate_late))),
        ("value nested three deep where a title belongs", json.dumps(_overlay_document(items=[nested]))),
        ("oversized", json.dumps(_overlay_document(items=[dict(_item(), rule="x" * 1500)] * 800))),
        ("nested past the parser's depth", "[" * 200_000 + SENTINEL_VALUE),
        ("document is a list", json.dumps([_overlay_document()])),
    ]
    written = []
    for index, (label, text) in enumerate(shapes):
        path = _raw_overlay(tmp_path, text, name=f"shape-{index}.json")
        written.append((label, path))
    raw = tmp_path / SENTINEL_DIR / "shape-utf8.json"
    raw.write_bytes(b"\xff\xfe" + SENTINEL_TITLE.encode("ascii") + b"\x80")
    written.append(("invalid UTF-8", raw))
    return written


def test_private_content_refusals_are_one_sentence_whatever_the_defect(module, tmp_path):
    """Index, count, size class, field, nesting, duplicate position: none is said.

    Measured by the Codex review on the PR head: `private overlay item 42 has
    an invalid kind` put a lower bound of forty-three on the overlay's item
    count, and the size-bound refusal put its byte size above a megabyte.
    Every content refusal about private input is now the same sentence, on
    the module and the command line alike, so two overlays that fail for
    materially different reasons leave byte-identical stderr.
    """
    transcripts = {}
    for label, path in _private_content_defects(tmp_path):
        message = _refusal(module, lambda: module.load_registries(path))
        assert message == GENERIC, label
        completed = _run("--overlay", str(path))
        assert completed.returncode == 2 and completed.stdout == "", label
        _assert_no_leak(completed.stderr, path)
        transcripts[label] = completed.stderr
    assert len(set(transcripts.values())) == 1, transcripts
    assert transcripts["invalid kind at index 0 of 1"] == f"REFUSE: {GENERIC}\n"
    assert not re.search(r"\d", GENERIC)


def test_disposition_row_refusals_carry_no_index_while_an_overlay_is_loaded(module, tmp_path):
    """A row index is a lower bound on the overlay's item count.

    With an overlay loaded a malformed PRIVATE row refuses generically, a
    malformed PUBLIC row is named by its public id, and neither carries an
    index; with no overlay loaded the index is a fact about the public rows
    only and is still said.
    """
    overlay = _write_overlay(tmp_path, _overlay_document(items=_many(3)))
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        record = _complete(path, module, registries)
        rows = record["items"]
        private_rows = [row for row in rows if row["source"] == "private"]
        assert len(private_rows) == 3
        private_rows[-1]["disposition"] = SENTINEL_VALUE
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert message == "cycle disposition is not valid; no detail is reported for private input"
        _assert_no_leak(message, overlay)
        private_rows[-1]["disposition"] = "considered"
        rows[0]["reason"] = ""
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert message == f"cycle disposition item {rows[0]['id']} needs a reason"
        assert not re.search(r"\d+ ", message.replace(rows[0]["id"], ""))
        rows[0]["reason"] = "Read."
        del rows[-1]["reason"]
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert message == "cycle disposition is not valid; no detail is reported for private input"
    public_only = module.load_registries(None)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=public_only)
        record = _complete(path, module, public_only)
        del record["items"][3]["reason"]
        path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        message = _refusal(module, lambda: module.validate_disposition(path, registries=public_only))
        assert message == "cycle disposition item 3 does not carry exactly the row fields"


def _section(text: str, heading: str, next_heading_prefix: str) -> str:
    start = text.index(heading)
    end = text.find(next_heading_prefix, start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def test_the_admission_claim_is_the_measured_one_everywhere(module):
    """PASS claims exactly what `validate_disposition` measures, and no deliberation.

    Measured by the Codex review on the PR head: the checker cannot tell
    whether a disposition was deliberate, read or prepared for this cycle --
    a reused one passes, a relabelled one passes, and `considered` beside a
    reason of `x` passes -- while five surfaces said each item was "given a
    deliberate disposition". Every surface now states the measured result
    and says what is not established, and none claims deliberation.
    """
    surfaces = {
        "checker": SCRIPT.read_text(encoding="utf-8"),
        "registry": PUBLIC.read_text(encoding="utf-8"),
        "AGENTS.md": (ROOT / "AGENTS.md").read_text(encoding="utf-8"),
        "procedure": PROCEDURE.read_text(encoding="utf-8"),
        "skill": (ROOT / "skills" / "build-app" / "SKILL.md").read_text(encoding="utf-8"),
        "CLAUDE.md": _section((ROOT / "CLAUDE.md").read_text(encoding="utf-8"),
                              "# Nornyx Forge operating instructions", "\n## "),
        "VALIDATION.md": _section((ROOT / "docs" / "VALIDATION.md").read_text(encoding="utf-8"),
                                  "## Standing development admission", "\n## "),
        "A-031": _section((ROOT / "docs" / "requirements" / "ASSUMPTIONS.md").read_text(encoding="utf-8"),
                          "## A-031 ", "\n## A-"),
    }
    for name, text in surfaces.items():
        flat = " ".join(text.split())
        if name == "A-031":
            # The assumption records the history: it may QUOTE the old
            # wording as the thing that was measured away, and may not make
            # the claim.
            assert "each given a deliberate disposition" not in flat
            assert "deliberate disposition and bound" not in flat
        else:
            assert not re.search(r"deliberat", flat, re.IGNORECASE), f"{name} claims deliberation"
        assert not re.search(r"(each|every)[^.]{0,40}(read and|read,) (understood|weighed)", flat), name
    for name in ("checker", "registry", "AGENTS.md", "procedure", "CLAUDE.md", "VALIDATION.md", "A-031"):
        assert MEASURED_PHRASE in " ".join(surfaces[name].split()), f"{name} lacks the measured claim"
    assert MEASURED_PHRASE in " ".join(module.ADMISSION_BOUNDARY.split())
    rule = next(item for item in module.load_registries(None).public_items
                if item["dedupe_key"] == "admission-is-not-authority")["rule"]
    assert MEASURED_PHRASE in rule and "covers exactly" in rule and BOUNDARY_PHRASE in rule
    with _runtime_disposition() as path:
        completed = _run("--init", str(path), "--cycle-id", "CLI-4")
        assert completed.returncode == 0, completed.stderr
        assert MEASURED_PHRASE in " ".join(completed.stdout.split())


def test_a_mechanically_written_or_reused_disposition_passes_and_the_documents_say_so(module):
    """What is NOT measured, demonstrated: no reading, no fresh cycle.

    Every row set to `considered` with a reason of `x` passes; the same file
    copied under another `cycle_id` passes. Both are stated as limitations
    rather than left for a reader to discover.
    """
    registries = module.load_registries(None)
    with _runtime_disposition() as first, _runtime_disposition() as second:
        module.initialize_disposition(first, cycle_id="FIRST", registries=registries)
        record = json.loads(first.read_text(encoding="utf-8"))
        for row in record["items"]:
            row["disposition"], row["reason"] = "considered", "x"
        first.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        assert module.validate_disposition(first, registries=registries) == (len(record["items"]), 0)
        record["cycle_id"] = "SECOND"
        second.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        assert module.validate_disposition(second, registries=registries) == (len(record["items"]), 0)
    procedure = " ".join(PROCEDURE.read_text(encoding="utf-8").split())
    assert "nothing binds it to a cycle" in procedure
    assert "written mechanically passes" in procedure


# ---------------------------------------------------------------------------
# Closures from the sixth Codex review: held descriptors, and no second lookup
# ---------------------------------------------------------------------------


@posix_only
def test_every_lookup_in_a_judgment_is_relative_to_a_held_directory(module, monkeypatch, tmp_path):
    """No pathname is looked up twice: after the one anchor, every `stat` and `open` is relative to a held directory.

    The property the sixth Codex review measured as absent from the pathname
    walk. The only absolute lookup a judgment makes is its anchor, the
    filesystem root; the repository root is reached from it through held
    directories and bound to the file this code was loaded from by an
    identity taken at import, and everything else is relative to a
    descriptor already held, so a swap under a name already inspected
    changes nothing the judgment will look at. The seventh Codex review
    measured two further anchors -- the repository root opened by pathname,
    and `os.stat(__file__)` evaluated through that same pathname -- and a
    checkout path substituted after the load satisfied both; neither exists
    now.
    """
    overlay = _write_overlay(tmp_path)
    anchors = {os.sep}
    absolute: list[tuple[str, str]] = []
    watching: list[int] = []
    real_stat, real_open = os.stat, os.open

    def stat(path, *args, **kwargs):
        if watching and kwargs.get("dir_fd") is None and str(path) not in anchors:
            absolute.append(("stat", str(path)))
        return real_stat(path, *args, **kwargs)

    def open_(path, flags, *args, **kwargs):
        if watching and kwargs.get("dir_fd") is None and str(path) not in anchors:
            absolute.append(("open", str(path)))
        return real_open(path, flags, *args, **kwargs)

    def judged(call):
        watching.append(1)
        try:
            return call()
        finally:
            watching.pop()

    monkeypatch.setattr(os, "stat", stat)
    monkeypatch.setattr(os, "open", open_)
    try:
        registries = judged(lambda: module.load_registries(overlay))
        with _runtime_disposition() as path:
            judged(lambda: module.initialize_disposition(path, cycle_id="TEST", registries=registries))
            _complete(path, module, registries)
            judged(lambda: module.validate_disposition(path, registries=registries))
    finally:
        monkeypatch.setattr(os, "stat", real_stat)
        monkeypatch.setattr(os, "open", real_open)
    assert absolute == [], absolute


@posix_only
@pytest.mark.parametrize("shape", ["directory component", "final file"])
def test_a_plain_entry_swapped_for_a_link_between_inspection_and_open_is_refused(
    module, tmp_path, monkeypatch, shape
):
    """The open is relative to the held directory and never follows: a link swapped in is met as a link.

    Measured by the sixth Codex review on the PR head, against the pathname
    walk: a plain directory inspected, then swapped for `outside/a ->
    repo/.nornyx/runtime/middle -> outside/final` before the next lookup,
    was followed by that lookup, and the overlay was accepted with the
    in-repository hop never judged. Here the same swap meets `O_NOFOLLOW` on
    the open that follows the inspection, relative to the directory already
    held, and the judgment refuses without consulting the link.
    """
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    final = tmp_path / "final"
    final.mkdir()
    (final / "overlay.json").write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    middle = RUNTIME / f"middle-{uuid.uuid4().hex}"
    _symlink(final, middle)
    if shape == "directory component":
        plain = directory / "a"
        plain.mkdir()
        (plain / "overlay.json").write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
        given = plain / "overlay.json"

        def swap():
            os.rename(plain, directory / "a-moved")
            _symlink(middle, plain)
    else:
        plain = directory / "overlay.json"
        plain.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
        given = plain

        def swap():
            plain.unlink()
            _symlink(middle / "overlay.json", plain)
    try:
        fired = _between_inspection_and_open(module, monkeypatch, plain.name, swap)
        try:
            module.load_registries(given)
        except module.AdmissionError as exc:
            assert fired, "the swap never ran"
            assert str(exc) == "private overlay path cannot be resolved"
            assert exc.__context__ is None and exc.__cause__ is None
            _assert_no_leak(str(exc), given, middle, final)
        else:
            raise AssertionError("a chain through the repository was followed")
    finally:
        middle.unlink()


@posix_only
def test_a_component_that_cannot_be_inspected_refuses_the_path(module, monkeypatch, tmp_path):
    """A failed inspection is a refusal, not a component stepped past.

    Measured by the fifth Codex review against the pathname walk, and held
    over the descriptor walk too: one failed `stat` of a component, relative
    to the held directory, refuses the whole judgment with the one sentence,
    and nothing after it is looked at.
    """
    overlay = _write_overlay(tmp_path)
    real_stat = os.stat
    failed: list[str] = []

    def once_failing(path, *args, **kwargs):
        if kwargs.get("dir_fd") is not None and path == SENTINEL_DIR and not failed:
            failed.append(path)
            raise OSError(errno.EIO, "input/output error")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", once_failing)
    try:
        message = _refusal(module, lambda: module.load_registries(overlay))
    finally:
        monkeypatch.setattr(os, "stat", real_stat)
    assert failed, "the failing inspection was never reached"
    assert message == "private overlay path cannot be resolved"
    _assert_no_leak(message, overlay)


@posix_only
def test_a_queued_directory_swapped_for_a_link_before_its_scan_is_refused(module, monkeypatch, tmp_path):
    """The traversal opens each directory relative to its parent, without following, before it lists it.

    Measured by the sixth Codex review on the PR head: a repository directory
    swapped for a symlink to an external tree after it was queued and before
    it was scanned was followed by `scandir`; the external tree's identities
    entered the repository set, and a legitimate external overlay beneath it
    was refused as inside. Here the open that precedes the scan meets the
    link, and the whole judgment refuses.
    """
    RUNTIME.mkdir(parents=True, exist_ok=True)
    marked = RUNTIME / f"marked-{uuid.uuid4().hex}"
    marked.mkdir()
    external = tmp_path / "external"
    (external / "child").mkdir(parents=True)
    real_open = os.open
    swapped: list[str] = []

    def racing_open(path, flags, *args, **kwargs):
        if path == marked.name and kwargs.get("dir_fd") is not None and not swapped:
            swapped.append(path)
            marked.rmdir()
            _symlink(external, marked)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    try:
        with _root(module) as root:
            message = _refusal(module, lambda: module._repository_directory_identities(root))
    finally:
        monkeypatch.setattr(os, "open", real_open)
        if marked.is_symlink():
            marked.unlink()
        else:
            marked.rmdir()
    assert swapped, "the swap never ran"
    assert message == "repository directories cannot be judged by identity"
    _assert_no_leak(message, marked, external)


def test_the_disposition_is_created_exclusively_and_never_through_a_link(module, monkeypatch, tmp_path):
    """Exclusive create relative to a held parent: no truncation, no write through a link.

    Measured by the sixth Codex review on the PR head: a check followed by a
    truncating write let a second initializer overwrite the first cycle's
    disposition, and a parent swapped to a symlink after the runtime
    judgment put the disposition outside the runtime root. Here the create
    is `O_CREAT | O_EXCL | O_NOFOLLOW`: the second initializer refuses and
    the first file survives; and a parent swapped for a link after it was
    held is not written through -- the file goes into the directory that was
    held, wherever that directory is now named, never through the link.
    """
    registries = module.load_registries(None)
    with _runtime_disposition() as path:
        original = module._refuse_existing
        raced: list[str] = []

        def racing(handle, name, *, label):
            original(handle, name, label=label)
            if not raced:
                raced.append(name)
                path.write_text('{"first": "cycle"}\n', encoding="utf-8", newline="\n")

        monkeypatch.setattr(module, "_refuse_existing", racing)
        message = _refusal(module, lambda: module.initialize_disposition(
            path, cycle_id="TEST", registries=registries))
        monkeypatch.setattr(module, "_refuse_existing", original)
        assert raced, "the race never ran"
        assert message == "cycle disposition already exists; remove it to start a new cycle"
        assert path.read_text(encoding="utf-8") == '{"first": "cycle"}\n', "the first cycle was truncated"
    if os.name != "posix":
        return
    RUNTIME.mkdir(parents=True, exist_ok=True)
    parent = RUNTIME / f"parent-{uuid.uuid4().hex}"
    elsewhere = RUNTIME / f"elsewhere-{uuid.uuid4().hex}"
    elsewhere.mkdir()
    output = parent / "disposition.json"
    held = module._hold_below
    swapped: list[str] = []

    def swapping(handle, names, *, label, create=False):
        descriptor = held(handle, names, label=label, create=create)
        if names and names[-1] == parent.name and not swapped:
            swapped.append(parent.name)
            os.rename(parent, elsewhere / "moved")
            _symlink(elsewhere, parent)
        return descriptor

    monkeypatch.setattr(module, "_hold_below", swapping)
    try:
        module.initialize_disposition(output, cycle_id="TEST", registries=registries)
        assert swapped, "the swap never ran"
        assert not (elsewhere / "disposition.json").exists(), "the write went through the link"
        assert (elsewhere / "moved" / "disposition.json").exists(), "the file is not in the directory held"
    finally:
        monkeypatch.setattr(module, "_hold_below", held)
        if parent.is_symlink():
            parent.unlink()
        elif parent.exists():
            parent.rmdir()
        for entry in sorted(elsewhere.rglob("*"), reverse=True):
            entry.unlink() if entry.is_file() else entry.rmdir()
        elsewhere.rmdir()


@posix_only
def test_a_hard_linked_overlay_is_refused(module, tmp_path):
    """A regular file with more than one name is refused: the object is judged, not the name it was handed by.

    A hard link gives one object a name outside the tree and, possibly, one
    inside it; no path rule and no directory identity can see the other
    name, so the object is refused for having one. The in-repository shape
    can be built only where the temporary directory shares a filesystem
    with the checkout; where it does not, the outside shape holds the rule.
    """
    overlay = _write_overlay(tmp_path)
    other = overlay.parent / "other-name.json"
    os.link(overlay, other)
    try:
        message = _refusal(module, lambda: module.load_registries(overlay))
        assert message == "private overlay has more than one name"
        _assert_no_leak(message, overlay, other)
    finally:
        other.unlink()
    assert module.load_registries(overlay).private_digest is not None
    decoy = _in_repository_decoy()
    alias = overlay.parent / "alias.json"
    try:
        try:
            os.link(decoy, alias)
        except OSError:
            return
        message = _refusal(module, lambda: module.load_registries(alias))
        assert message == "private overlay has more than one name"
        _assert_no_leak(message, alias, decoy)
    finally:
        decoy.unlink()
        if alias.exists():
            alias.unlink()


@posix_only
def test_a_link_is_refused_where_it_sits_and_nothing_beyond_it_is_consulted(module, monkeypatch, tmp_path):
    """Inside the tree a link is refused for sitting there; outside it, for being a link; its target is never read.

    Nothing is followed: `os.readlink` and `Path.resolve` are never called
    during a judgment, so what a link points at is not consulted, not even
    to refuse it.
    """
    outside = _write_overlay(tmp_path)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    inside_link = RUNTIME / f"link-{uuid.uuid4().hex}.json"
    _symlink(outside, inside_link)
    decoy = _in_repository_decoy()
    outside_link = tmp_path / SENTINEL_DIR / "link.json"
    _symlink(decoy, outside_link)
    consulted: list[tuple[str, str]] = []
    real_resolve, real_readlink = Path.resolve, os.readlink

    def resolve(self, *args, **kwargs):
        consulted.append(("resolve", str(self)))
        return real_resolve(self, *args, **kwargs)

    def readlink(path, *args, **kwargs):
        consulted.append(("readlink", str(path)))
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(os, "readlink", readlink)
    try:
        first = _refusal(module, lambda: module.load_registries(inside_link))
        second = _refusal(module, lambda: module.load_registries(outside_link))
        assert module.load_registries(outside).private_digest is not None
    finally:
        monkeypatch.setattr(Path, "resolve", real_resolve)
        monkeypatch.setattr(os, "readlink", real_readlink)
        inside_link.unlink()
        decoy.unlink()
    assert first == "private overlay must remain outside the Forge repository"
    assert second == "private overlay path crosses a link that is not followed"
    assert consulted == [], consulted
    _assert_no_leak(first + second, inside_link, outside_link, decoy)


def test_without_the_handle_backend_a_private_overlay_is_refused_and_public_admission_stands(
    module, monkeypatch, tmp_path
):
    """Where no handle-based judgment exists, the overlay is refused outright; the public cycle still runs.

    A pathname inspected and then used again is a race the sixth Codex review
    measured. Rather than admit an overlay over it, a platform without
    `openat`, `O_NOFOLLOW` and `scandir` on a handle refuses the overlay with
    a sentence that names the platform and nothing else -- whatever the
    path's shape -- until a separately reviewed HANDLE-based backend exists.
    Public-registry admission stays: init, complete, check, with the
    disposition created exclusively by pathname.
    """
    monkeypatch.setattr(module, "HANDLE_BACKEND", False)
    overlay = _write_overlay(tmp_path)
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert message == "private overlay is not admitted on this platform without a handle-based backend"
    _assert_no_leak(message, overlay)
    assert _refusal(module, lambda: module.load_registries(tmp_path / "SENTINEL-ABSENT.json")) == message
    registries = module.load_registries(None)
    assert registries.private_digest is None
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        again = _refusal(module, lambda: module.initialize_disposition(
            path, cycle_id="TEST", registries=registries))
        assert again == "cycle disposition already exists; remove it to start a new cycle"
        _complete(path, module, registries)
        assert module.validate_disposition(path, registries=registries) == (len(registries.public_items), 0)
    if os.name != "posix":
        return
    RUNTIME.mkdir(parents=True, exist_ok=True)
    link = RUNTIME / f"link-{uuid.uuid4().hex}.json"
    _symlink(tmp_path / "elsewhere.json", link)
    try:
        refused = _refusal(module, lambda: module.initialize_disposition(
            link, cycle_id="TEST", registries=registries))
        assert refused == "cycle disposition path crosses a link that is not followed"
        assert not (tmp_path / "elsewhere.json").exists()
    finally:
        link.unlink()


def test_the_identity_snapshot_is_taken_for_every_judgment(module, monkeypatch, tmp_path):
    """No identity set outlives the judgment it was taken for: two judgments, four censuses.

    Each judgment takes the census twice -- before the walk, and again once
    the overlay is held -- and keeps neither for the next judgment. Exactly
    twice: a draft of the second census was evaluated once per directory
    held, which this count caught.
    """
    overlay = _write_overlay(tmp_path)
    taken: list[int] = []
    real = module._repository_directory_identities

    def counting(root):
        taken.append(root)
        return real(root)

    monkeypatch.setattr(module, "_repository_directory_identities", counting)
    module.load_registries(overlay)
    assert len(taken) == 2
    module.load_registries(overlay)
    assert len(taken) == 4


@posix_only
def test_the_repository_root_handle_is_bound_to_the_running_checker(module, monkeypatch, tmp_path):
    """The root handle is refused unless the directory it holds contains the file this code was loaded from.

    The identity it must contain was taken at import (`_LOADED_CHECKER`);
    what `__file__` says at judgment time takes no part, so a pathname
    substituted after the load has nothing to satisfy.
    """
    with _root(module) as root:
        assert module._identity_of(os.fstat(root)) == module._identity_of(os.lstat(ROOT))
    assert module._LOADED_CHECKER == module._identity_of(os.stat(SCRIPT))
    elsewhere = tmp_path / "elsewhere.py"
    elsewhere.write_text("# not the checker\n", encoding="utf-8")
    monkeypatch.setattr(module, "__file__", str(elsewhere))
    with _root(module) as root:
        assert module._identity_of(os.fstat(root)) == module._identity_of(os.lstat(ROOT))
    monkeypatch.setattr(module, "_LOADED_CHECKER", module._identity_of(os.stat(elsewhere)))
    assert _refusal(module, module._open_repository_root) == "repository root cannot be established"
    monkeypatch.setattr(module, "_LOADED_CHECKER", None)
    assert _refusal(module, module._open_repository_root) == "repository root cannot be established"
    monkeypatch.setattr(module, "_LOADED_CHECKER", module._identity_of(os.stat(SCRIPT)))
    monkeypatch.setattr(module, "_OWN_SCRIPT", ("scripts", "SENTINEL-ABSENT-CHECKER.py"))
    assert _refusal(module, module._open_repository_root) == "repository root cannot be established"


@posix_only
def test_a_substituted_repository_root_is_refused(tmp_path):
    """A checkout path replaced after the checker was loaded is refused, whichever way it is replaced.

    The seventh Codex review measured the anchor following a link: the root
    was opened by pathname without `O_NOFOLLOW` and compared against
    `os.stat(__file__)` evaluated through the same substituted path, so a
    counterfeit tree's checker compared equal to itself and a fabricated
    public registry was read (reproduced, with a hard-linked variant). Here
    the checker is loaded from a copy at `parent/real`, so its ROOT is that
    path and its loaded identity is the copy's, and the path is then
    replaced three ways: `parent` swapped for a link to a counterfeit tree;
    `real` swapped by rename for a counterfeit plain directory; and a
    counterfeit whose checker is a hard link to the loaded file. Each is
    refused, and the checkout put back is held again.
    """
    base = tmp_path / "SENTINEL-SUBSTITUTED-ROOT"
    parent = base / "parent"
    real = parent / "real"
    relatives = (
        ("scripts", "check_standing_development_obligations.py"),
        ("docs", "governance", "STANDING_DEVELOPMENT_OBLIGATIONS.json"),
    )
    for relative in relatives:
        real.joinpath(*relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT.joinpath(*relative), real.joinpath(*relative))
    checker = real.joinpath(*relatives[0])
    spec = importlib.util.spec_from_file_location("standing_obligations_copy", checker)
    assert spec is not None and spec.loader is not None
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)
    assert copy.ROOT == real
    assert copy._LOADED_CHECKER == copy._identity_of(os.stat(checker))
    with _root(copy) as root:
        assert copy._identity_of(os.fstat(root)) == copy._identity_of(os.lstat(real))
    assert copy.load_registries(None).public_items  # control: the copy's registry, through the anchor

    moved = base / "moved"
    os.rename(parent, moved)  # the loaded checkout is renamed away; the loaded file is now below `moved`
    loaded = moved.joinpath("real", *relatives[0])

    def counterfeit(name: str, *, link_to: Path | None) -> Path:
        tree = base / name / "real"
        for relative in relatives:
            tree.joinpath(*relative).parent.mkdir(parents=True, exist_ok=True)
        if link_to is None:
            tree.joinpath(*relatives[0]).write_bytes(loaded.read_bytes() + b"\n# SENTINEL-COUNTERFEIT\n")
        else:
            os.link(link_to, tree.joinpath(*relatives[0]))
        shutil.copyfile(PUBLIC, tree.joinpath(*relatives[1]))
        return base / name

    try:
        os.symlink(counterfeit("linked", link_to=None), parent)
        assert _refusal(copy, copy._open_repository_root) == "repository path crosses a link that is not followed"
        assert _refusal(copy, lambda: copy.load_registries(None)) == "repository path crosses a link that is not followed"
        parent.unlink()

        os.rename(counterfeit("plain", link_to=None), parent)
        assert _refusal(copy, copy._open_repository_root) == "repository root cannot be established"
        shutil.rmtree(parent)

        os.rename(counterfeit("hard", link_to=loaded), parent)
        assert os.stat(loaded).st_nlink == 2
        assert _refusal(copy, copy._open_repository_root) == "repository root cannot be established"
        shutil.rmtree(parent)
        assert os.stat(loaded).st_nlink == 1
    finally:
        if parent.is_symlink():
            parent.unlink()
        elif parent.exists():
            shutil.rmtree(parent)
        os.rename(moved, parent)
    with _root(copy) as root:
        assert copy._identity_of(os.fstat(root)) == copy._identity_of(os.lstat(real))


@handle_backend_only
def test_a_mount_change_spanning_the_walk_is_refused(module, monkeypatch, tmp_path):
    """A directory bound into the checkout while the walk ran is in the second census, and the overlay held below it refuses.

    The seventh Codex review measured the census going stale: taken before
    the walk, it did not contain an external directory bind-mounted onto a
    mount point inside the checkout after it was taken, so the overlay below
    that directory was accepted although it was by then reachable inside the
    repository (reproduced with a real bind mount). The census is taken
    again once the overlay is held, and every directory held on the way must
    be absent from both. A mount needs a privilege the suite must not depend
    on, so the second census is supplied here with the external directory's
    identity in it, as a bind mount would have put it there; the control
    with the same census twice admits the overlay.
    """
    overlay = _write_overlay(tmp_path)
    external = module._identity_of(os.stat(overlay.parent))
    with _root(module) as root:
        before = module._repository_directory_identities(root)
    assert external not in before
    censuses: list[int] = []

    def supplied(root):
        censuses.append(root)
        return before if len(censuses) == 1 else before | {external}

    monkeypatch.setattr(module, "_repository_directory_identities", supplied)
    refusal = _refusal(module, lambda: module.load_registries(overlay))
    assert refusal == "private overlay must remain outside the Forge repository"
    assert SENTINEL_DIR not in refusal
    assert len(censuses) == 2

    censuses.clear()
    monkeypatch.setattr(module, "_repository_directory_identities", lambda root: (censuses.append(root), before)[1])
    assert module.load_registries(overlay).private_items
    assert len(censuses) == 2


# ---------------------------------------------------------------------------
# Structural: what the checker source may and may not do
# ---------------------------------------------------------------------------


FORBIDDEN_ATTRIBUTES = frozenset({
    "environ", "getenv", "glob", "rglob", "iterdir", "walk", "listdir", "scandir",
    "expanduser", "home", "cwd", "getcwd",
})
ALLOWED_IMPORTS = frozenset({
    "__future__", "argparse", "hashlib", "json", "os", "re", "stat", "sys",
    "pathlib", "typing",
})


def _checker_tree() -> ast.Module:
    return ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))


def test_the_checker_reads_no_environment_and_scans_no_directory():
    """A LINT over the obvious spellings, not a proof of absence.

    An in-session adversarial review appended fifteen evasions to a scratch
    copy -- `getattr(os, "env" + "iron")`, `vars(os)["environ"]`,
    `open("/proc/self/environ")`, `__import__("sub" + "process")`, a print of
    the overlay path -- and thirteen passed this test and the two beside it.
    What holds the property is the behavioural sweep: decoys on every route
    in `test_no_overlay_is_discovered_from_cwd_home_or_environment` and the
    sentinel checks over every output on the paths they exercise. This test
    refuses the spellings a maintainer would reach for first, and no more.
    """
    tree = _checker_tree()
    traversal = next(node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)
                     and node.name == "_repository_directory_identities")
    inside_traversal = {id(node) for node in ast.walk(traversal)}
    capability = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "HANDLE_BACKEND"
                              for target in node.targets))
    inside_capability = {id(node) for node in ast.walk(capability)}
    offenders = []
    allowed_scans = 0
    named_capabilities = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTES:
            # The ONE directory traversal, of the repository's own tree for
            # its directories' identities, lives in that one function and
            # nowhere else; it opens no file and selects nothing. The only
            # other spelling of `scandir` is the platform capability check,
            # which asks whether it works on a descriptor and calls nothing.
            if node.attr == "scandir" and id(node) in inside_traversal:
                allowed_scans += 1
                continue
            if node.attr == "scandir" and id(node) in inside_capability:
                named_capabilities += 1
                continue
            offenders.append(f"{node.attr} at line {node.lineno}")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_ATTRIBUTES:
            offenders.append(f"{node.id} at line {node.lineno}")
    assert offenders == [], f"the checker can discover an overlay through: {offenders}"
    assert allowed_scans == 1, "the identity traversal is one scandir in one function"
    assert named_capabilities == 1, "the capability check names scandir once and calls it never"


def test_the_checker_imports_only_the_standard_library_allowlist():
    imported = set()
    for node in ast.walk(_checker_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= ALLOWED_IMPORTS, sorted(imported - ALLOWED_IMPORTS)
    assert "subprocess" not in imported and "importlib" not in imported


#: Names an f-string hole may carry inside a refusal: the label, an index, a
#: constant detail or a required-field name passed in from a literal, the
#: option name, or a PUBLIC item id. Nothing read from an input.
REFUSAL_NAMES = frozenset({
    "label", "index", "required", "key", "option", "subject", "detail", "public_id",
})
#: The two helpers every refusal may be built through, and the position of
#: the DETAIL argument each takes, which must be a literal or label-only.
REFUSAL_BUILDERS = {"_refuse": 1, "_row_refusal": 0}


def _label_only(argument: ast.expr, allowed_names: frozenset = REFUSAL_NAMES) -> bool:
    """A constant, an allowed name, or an f-string whose every hole is an allowed name.

    A bare allowed name is how `_row_refusal` forwards the literal detail it
    was given; the call sites that give it are judged by the same rule.
    """
    if isinstance(argument, ast.Constant):
        return True
    if isinstance(argument, ast.Name):
        return argument.id in allowed_names
    if not isinstance(argument, ast.JoinedStr):
        return False
    for value in argument.values:
        if isinstance(value, ast.FormattedValue):
            inner = value.value
            if not (isinstance(inner, ast.Name) and inner.id in allowed_names):
                return False
    return True


def _acceptable_refusal_call(call: ast.Call) -> bool:
    """`AdmissionError(<label-only>)`, or a builder whose detail is label-only."""
    callee = call.func
    if not isinstance(callee, ast.Name):
        return False
    if callee.id == "AdmissionError":
        return bool(call.args) and _label_only(call.args[0])
    position = REFUSAL_BUILDERS.get(callee.id)
    if position is None:
        return False
    if len(call.args) <= position or not _label_only(call.args[position]):
        return False
    return all(isinstance(keyword.value, (ast.Name, ast.Constant)) for keyword in call.keywords)


def test_every_refusal_is_composed_from_labels_and_indexes_only():
    """No `AdmissionError` message interpolates a value from an input.

    Every construction of an `AdmissionError` anywhere in the module must be
    label-only; every call to a refusal builder must pass a literal or
    label-only detail; every assignment to `refusal` must be `None` or such a
    call -- the loaders build a refusal inside a handler and raise outside
    it, so that the refusal carries no context -- and every `raise` must be
    `raise refusal`, an acceptable call, or the ONE composed message, the
    blocker list, pinned as exactly one site so a second composed message is
    a reviewed change rather than a quiet one. A lint over shapes, not a
    proof: a value smuggled through a name in REFUSAL_NAMES would pass it.
    """
    tree = _checker_tree()
    offenders = []
    composed = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "AdmissionError":
                argument = node.args[0] if node.args else None
                if argument is None or _label_only(argument):
                    continue
                if isinstance(argument, ast.JoinedStr):
                    offenders.append(f"AdmissionError at line {node.lineno}")
                else:
                    composed += 1
            elif node.func.id in REFUSAL_BUILDERS and not _acceptable_refusal_call(node):
                offenders.append(f"{node.func.id} with a non-literal detail at line {node.lineno}")
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "refusal" for target in node.targets
        ):
            value = node.value
            if isinstance(value, ast.Constant) and value.value is None:
                continue
            if isinstance(value, ast.Call) and _acceptable_refusal_call(value):
                continue
            offenders.append(f"refusal assigned at line {node.lineno}")
        elif isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc
            if isinstance(exc, ast.Name) and exc.id == "refusal":
                continue
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                if exc.func.id in REFUSAL_BUILDERS or exc.func.id == "AdmissionError":
                    continue  # judged above as a Call
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id in (
                "SystemExit", "_DuplicateKey", "_ScanBound", "_Swapped"
            ):
                continue  # internal signals, caught inside the module; none carries input
            offenders.append(f"raise of an unreviewed shape at line {node.lineno}")
    assert offenders == [], f"refusals interpolate something other than a label: {offenders}"
    assert composed == 1, "exactly one composed refusal (the blocker list) is expected"


def test_public_entrypoints_require_standing_admission_and_state_the_boundary():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    skill = (ROOT / "skills" / "build-app" / "SKILL.md").read_text(encoding="utf-8")
    procedure = PROCEDURE.read_text(encoding="utf-8")
    needle = "check_standing_development_obligations.py"
    assert needle in agents
    assert "AGENTS.md" in claude and needle in claude
    assert needle in skill
    for text in (agents, procedure):
        assert BOUNDARY_PHRASE in text, "the boundary sentence is missing"
    for text in (claude, skill):
        assert "authority" in text and "admission" in text.lower()


def test_runtime_disposition_directory_is_gitignored():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".nornyx/runtime/" in gitignore


def test_the_registry_and_checker_are_governed_inputs_and_agents_md_is_not():
    """Changing either moves the evidence digest. AGENTS.md does not.

    Stated rather than implied: the root `AGENTS.md` is not in the governed
    input set (`CLAUDE.md` is), so an edit to it moves no digest. The
    substantive rules therefore live in the governed procedure document and
    the registry, and AGENTS.md points at them. Widening the subject scope is a
    change to `governed_subject.py`, which this mechanism does not make.
    """
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from nornyx_forge.governed_subject import REPOSITORY_SCOPE  # noqa: PLC0415
        from nornyx_forge.subject_observer import observe_governed_paths  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    paths = set(observe_governed_paths(ROOT, REPOSITORY_SCOPE))
    assert "docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.json" in paths
    assert "docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.md" in paths
    assert "scripts/check_standing_development_obligations.py" in paths
    assert "tests/test_standing_development_obligations.py" in paths
    assert "CLAUDE.md" in paths
    assert "AGENTS.md" not in paths
