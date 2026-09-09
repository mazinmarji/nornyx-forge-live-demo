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
import hashlib
import importlib.util
import json
import os
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


#: Symlink fixtures cannot be built on a Windows workstation without elevation,
#: so those tests are declared skips there, keyed by identity in the census
#: exactly as tests/test_special_files.py declares its own. Every CI test job
#: runs Linux and executes them.
posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="symlink fixtures cannot be built on a Windows workstation without elevation",
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


def test_duplicate_semantic_key_within_a_registry_is_refused_without_naming_it(module, tmp_path):
    second = dict(_overlay_document()["items"][0], id="PRV-002")
    overlay = _write_overlay(tmp_path, _overlay_document(items=[_overlay_document()["items"][0], second]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert "duplicate semantic key" in message
    _assert_no_leak(message, overlay)


def test_duplicate_item_id_within_a_registry_is_refused(module, tmp_path):
    second = dict(_overlay_document()["items"][0], dedupe_key="another-private-key")
    overlay = _write_overlay(tmp_path, _overlay_document(items=[_overlay_document()["items"][0], second]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert "duplicate item id" in message
    _assert_no_leak(message, overlay)


def test_private_overlay_cannot_duplicate_public_semantics(module, tmp_path):
    public = json.loads(PUBLIC.read_text(encoding="utf-8"))
    item = dict(_overlay_document()["items"][0], dedupe_key=public["items"][0]["dedupe_key"])
    overlay = _write_overlay(tmp_path, _overlay_document(items=[item]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert "duplicate semantic keys" in message
    _assert_no_leak(message, overlay)


def test_private_overlay_cannot_reuse_a_public_id(module, tmp_path):
    public = json.loads(PUBLIC.read_text(encoding="utf-8"))
    item = dict(_overlay_document()["items"][0], id=public["items"][0]["id"])
    overlay = _write_overlay(tmp_path, _overlay_document(items=[item]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert "duplicate item ids" in message
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
    _assert_no_leak(message, overlay)
    completed = _run("--overlay", str(overlay))
    assert completed.returncode == 2, completed.stderr
    assert completed.stdout == "", "a refused overlay must not reach a PASS line"
    _assert_no_leak(completed.stdout + completed.stderr, overlay)


def test_an_oversized_overlay_is_refused(module, tmp_path):
    padding = {"schema": "nornyx.forge.private_standing_overlay.v1", "classification": "private",
               "items": [dict(_item(), rule="x" * 1500)] * 800}
    overlay = _write_overlay(tmp_path, padding)
    assert overlay.stat().st_size > module.DOCUMENT_BYTES_BOUND
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert "size bound" in message
    _assert_no_leak(message, overlay)


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
    RUNTIME.mkdir(parents=True, exist_ok=True)
    inside = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    inside.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    link = tmp_path / SENTINEL_DIR / "link.json"
    link.parent.mkdir()
    try:
        _symlink(inside, link)
        message = _refusal(module, lambda: module.load_registries(link))
        assert "outside the Forge repository" in message
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
    """`Path.resolve` raises with the path in its message; none of it may escape.

    Measured on CPython 3.11: `RuntimeError: Symlink loop from '<path>'`, a
    class the first checker did not catch, so the traceback printed the path.
    Measured on CPython 3.13: `resolve(strict=False)` no longer raises on a
    loop, and the `OSError` from the read that follows names the path too.
    """
    directory = tmp_path / SENTINEL_DIR
    directory.mkdir()
    first, second = directory / "a.json", directory / "b.json"
    _symlink(second, first)
    _symlink(first, second)
    completed = _run("--overlay", str(first))
    assert completed.returncode == 2, completed.stderr
    # WHICH step refuses is interpreter-dependent and not the property. On
    # 3.11 `resolve(strict=False)` raises on the loop, so resolution refuses;
    # on 3.13 it returns the unresolved path and the read refuses with ELOOP.
    # Either way the refusal is one label and the path is in neither.
    assert completed.stderr.startswith("REFUSE: private overlay")
    assert "cannot be resolved" in completed.stderr or "cannot be read" in completed.stderr
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
    assert "UTF-8 JSON" in completed.stderr
    output = completed.stdout + completed.stderr
    _assert_no_leak(output, target)
    assert "0xff" not in output.lower() and "position" not in output


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
        assert ".nornyx/runtime/" in message
        assert not outside.exists()
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
    registry_copy = tmp_path / "registry.json"
    registry_copy.write_bytes(PUBLIC.read_bytes())
    monkeypatch.setattr(module, "PUBLIC_REGISTRY", registry_copy)
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


def test_refusals_name_public_ids_and_only_a_count_for_private_rows(module, tmp_path):
    overlay = _write_overlay(tmp_path)
    registries = module.load_registries(overlay)
    with _runtime_disposition() as path:
        module.initialize_disposition(path, cycle_id="TEST", registries=registries)
        message = _refusal(module, lambda: module.validate_disposition(path, registries=registries))
        assert "FGR-SDO-001: pending" in message
        assert "1 overlay item(s) unresolved" in message
        assert "PRV-001" not in message
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
    assert "authorizes nothing" in completed.stdout


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
        assert "0 overlay" not in completed.stdout or "overlay item(s)" in completed.stdout
        assert module.OVERLAY_NOTICE not in completed.stdout
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
    assert "repeats a key" in message
    _assert_no_leak(message, overlay)
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
    overlay = _write_overlay(tmp_path, _overlay_document(items=[_item(**{field: value})]))
    message = _refusal(module, lambda: module.load_registries(overlay))
    assert f"no valid {field}" in message
    _assert_no_leak(message, overlay)


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
    resolution were judged.
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
        assert "outside the Forge repository" in message
        _assert_no_leak(message, first, middle, final)
    finally:
        middle.unlink()


@posix_only
def test_a_link_reached_through_a_directory_symlink_into_the_repository_is_refused(module, tmp_path):
    """The link's REAL directory is inside the tree, whatever its target."""
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
        assert "outside the Forge repository" in message
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
    assert "not a regular file" in completed.stderr
    _assert_no_leak(completed.stdout + completed.stderr, fifo)


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
    assert "invalid kind" in message or "invalid status" in message
    _assert_no_leak(message, overlay)


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
    assert "UTF-8 JSON" in message
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
    offenders = []
    for node in ast.walk(_checker_tree()):
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTES:
            offenders.append(f"{node.attr} at line {node.lineno}")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_ATTRIBUTES:
            offenders.append(f"{node.id} at line {node.lineno}")
    assert offenders == [], f"the checker can discover an overlay through: {offenders}"


def test_the_checker_imports_only_the_standard_library_allowlist():
    imported = set()
    for node in ast.walk(_checker_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= ALLOWED_IMPORTS, sorted(imported - ALLOWED_IMPORTS)
    assert "subprocess" not in imported and "importlib" not in imported


def _label_only(argument: ast.expr, allowed_names: set) -> bool:
    """A constant, or an f-string whose every hole is one of the allowed names."""
    if isinstance(argument, ast.Constant):
        return True
    if not isinstance(argument, ast.JoinedStr):
        return False
    for value in argument.values:
        if isinstance(value, ast.FormattedValue):
            inner = value.value
            if not (isinstance(inner, ast.Name) and inner.id in allowed_names):
                return False
    return True


def test_every_refusal_is_composed_from_labels_and_indexes_only():
    """No `AdmissionError` message interpolates a value from an input.

    Two shapes are admitted: `raise AdmissionError(<label-only string>)`, and
    `raise AdmissionError(refusal)` where EVERY assignment to `refusal` in the
    module is itself label-only -- the loaders assign a message inside a
    handler and raise outside it, so that the refusal carries no context. The
    one composed message -- the blocker list -- is the exception, and it is
    pinned as exactly one site so a second composed message is a reviewed
    change rather than a quiet one.
    """
    allowed_names = {"label", "index", "required", "key", "option"}
    tree = _checker_tree()
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "refusal" for target in node.targets):
            if isinstance(node.value, ast.Constant) and node.value.value is None:
                continue
            if not _label_only(node.value, allowed_names):
                offenders.append(f"refusal assigned at line {node.lineno}")
    composed = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
            continue
        callee = node.exc.func
        if not (isinstance(callee, ast.Name) and callee.id == "AdmissionError"):
            continue
        argument = node.exc.args[0]
        if isinstance(argument, ast.Name) and argument.id == "refusal":
            continue
        if _label_only(argument, allowed_names):
            continue
        if isinstance(argument, ast.JoinedStr):
            offenders.append(f"line {node.lineno}")
            continue
        composed += 1
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
