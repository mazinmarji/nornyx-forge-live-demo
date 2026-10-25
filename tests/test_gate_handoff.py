"""Forge's side of the run-act gate's boundary, on disk (A-055): the input
stage, the fail-closed import of a released output set, static-only
verification, and the gated build's sealed manifest.

WHAT WOULD FALSIFY IT: a stage written over an existing one, or holding
anything Forge did not render; a release imported while it is incomplete,
holds an extra entry, a link, a junction, a hard link, a named data stream, a
name two spellings could reach, a credential-pattern hit, or bytes that are
not what its manifest says; anything written before every check passed; an
interrupted import or stage read back as complete; a destination reused; a
static-only verification that runs a produced test, or that passes as an
acceptance; a gated manifest that binds no runtime contract or no
provenance, or that the handoff gate offers.

The release here is built by the test: the gate's real bytes are not run
(no VM act, no run act). Windows is the SUBJECT of the junction and named-
stream tests, which skip elsewhere and run in the windows-runtime job.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from test_produced_app_handoff import AT, CASEY, PLATFORM, reference_application

from nornyx_forge import gates, greenfield_verifier, provider_gate
from nornyx_forge.capsule import create_document
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.contract_generator import RUNTIME_CONTRACT_PATH
from nornyx_forge.experience import fail, start_experience
from nornyx_forge.experience_journey import SYSTEM_ACTOR

try:
    from nornyx_forge import gate_handoff as handoff
    from nornyx_forge import gate_release_model as model
    from nornyx_forge import produced_app_handoff as app_handoff
    from nornyx_forge import produced_app_manifest as pam
except ImportError as missing:  # red first: on a parent without the modules
    _ABSENT = str(missing)

    class _Missing:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"the gate handoff does not exist here: {_ABSENT}")

    handoff = model = app_handoff = pam = _Missing()  # type: ignore[assignment]

WINDOWS = os.name == "nt"
windows_only = pytest.mark.skipif(not WINDOWS, reason="Windows is the subject: NTFS junctions "
                                  "and named data streams exist only there")
BRD = "# BRD\n\n## BRD-001 Cases\n\nTrack support cases.\n"
CYCLE = "c0123456789abcdef"
KEY = "sk-" + "Fak3" * 6


def _layout():
    return model.ReleaseLayout(manifest_name="hold-manifest.jsonl", workspace_prefix="ws\\",
                               record_name="release-record.json")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _application() -> dict[str, bytes]:
    files = {path: text.encode("utf-8") for path, text in reference_application(
        {"BRD-001": "Track support cases."}).items()}
    files["BRD.md"] = BRD.encode("utf-8")
    return files


def _tree_list(files: dict[str, bytes]) -> bytes:
    return "".join(f"{path}\n" for path in sorted(files) if path != model.COMPLETENESS_LIST).encode()


def build_release(base: Path, files: dict[str, bytes] | None = None, *, cycle: str = CYCLE,
                  listing: bytes | None = None, gate_items: dict[str, bytes] | None = None,
                  names: dict[str, str] | None = None) -> tuple[Path, str]:
    """A release as the gate lays one out: items named by id, a JSON-lines
    manifest of id, name, size and digest, and a release record. Returns the
    directory and the manifest digest the act would cite."""
    files = dict(_application() if files is None else files)
    if model.COMPLETENESS_LIST not in files:
        files[model.COMPLETENESS_LIST] = _tree_list(files) if listing is None else listing
    release = base / "release" / cycle
    release.mkdir(parents=True)
    rows = []
    entries = [("ws\\" + path.replace("/", "\\"), data) for path, data in sorted(files.items())]
    entries += sorted((gate_items or {"gate-stdout.txt": b"provider said hello\n"}).items())
    for number, (name, data) in enumerate(entries, start=1):
        ident = f"i{number:04d}"
        (release / ident).write_bytes(data)
        rows.append({"id": ident, "name": (names or {}).get(name, name), "size": len(data),
                     "digest": _sha(data)})
    manifest = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows).encode()
    (release / "hold-manifest.jsonl").write_bytes(manifest)
    (release / "release-record.json").write_bytes(json.dumps({"cycle": cycle}).encode())
    return release, _sha(manifest)


def _import(base: Path, release: Path, digest: str, **change: Any):
    arguments = {"cycle_id": CYCLE, "layout": _layout(), "expected_manifest_sha256": digest}
    arguments.update(change)
    return handoff.import_release(release, base / "verify" / CYCLE, **arguments)


@pytest.fixture
def verify_root(tmp_path: Path) -> Path:
    (tmp_path / "verify").mkdir()
    return tmp_path / "verify"


# ---------------------------------------------------------------------------
# The import: the passing path, and what it records
# ---------------------------------------------------------------------------

def test_a_complete_release_is_imported_and_recorded(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "COMPLETE", outcome.reasons
    destination = verify_root / CYCLE
    record = model.validate_import_record(outcome.record)
    assert record["cycle_id"] == CYCLE
    assert record["release_manifest"] == "sha256:" + digest
    assert record["credential_pattern"] == model.GATE_SEED_PATTERN.record()
    assert record["credential_hits"] == 0
    files = _application()
    files[model.COMPLETENESS_LIST] = _tree_list(files)
    assert dict(outcome.workspace_files) == files
    for path, data in files.items():
        assert (destination / "workspace" / path).read_bytes() == data
    assert record["workspace_subject_digest"] == pam.subject_digest(
        {path: "sha256:" + _sha(data) for path, data in files.items()})
    gate_item = [item for item in record["items"] if item["kind"] == "gate_item"]
    assert len(gate_item) == 1 and (destination / "items" / gate_item[0]["id"]).read_bytes() == \
        b"provider said hello\n"
    assert sorted(os.listdir(destination)) == ["import-intent.json", "import-record.json",
                                               "items", "workspace"]
    again = handoff.load_import(destination)
    assert again.state == "COMPLETE" and again.record == outcome.record


def test_a_known_false_positive_refuses_the_import_and_nothing_is_written(
        tmp_path: Path, verify_root: Path):
    """Founder precaution (A-055): the gate's current pattern hits an ordinary
    kebab-case identifier, and until an approved correction is effective that
    hit FAILS CLOSED -- nothing is imported."""
    files = _application()
    files["app/views.py"] = b'PANEL = "task-management-dashboard-v2"\n'
    release, digest = build_release(tmp_path, files)
    refused = _import(tmp_path, release, digest)
    assert refused.state == "REFUSED"
    assert any("d3g-seed-current" in reason for reason in refused.reasons)
    assert os.listdir(verify_root) == []


@pytest.mark.parametrize("supplied", [
    "weaker", "empty", "caller-chosen", "none"])
def test_no_caller_can_supply_the_import_pattern(supplied: str, tmp_path: Path,
                                                  verify_root: Path):
    """Founder precaution (A-055): the pattern is Forge-owned; the import takes
    no pattern, so a weaker, empty or caller-chosen one is refused outright."""
    release, digest = build_release(tmp_path)
    offered = {
        "weaker": model.CredentialPattern("weaker", (r"sk-[A-Za-z0-9_-]{99,}",)),
        "empty": (),
        "caller-chosen": model.CredentialPattern("mine", (r"NEVER-MATCHES-ANYTHING-XYZ",)),
        "none": None,
    }[supplied]
    with pytest.raises(TypeError):
        _import(tmp_path, release, digest, pattern=offered)
    assert os.listdir(verify_root) == []


def test_the_environment_does_not_select_the_import_pattern(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("FORGE_CREDENTIAL_PATTERN", "NORNYX_FORGE_IMPORT_PATTERN",
                 "FORGE_IMPORT_PATTERN"):
        monkeypatch.setenv(name, "NEVER-MATCHES-ANYTHING-XYZ")
    files = _application()
    files["app/config.py"] = f"K = '{KEY}'\n".encode()
    release, digest = build_release(tmp_path, files)
    assert _import(tmp_path, release, digest).state == "REFUSED"
    source = Path(handoff.__file__).read_text(encoding="utf-8") + Path(
        model.__file__).read_text(encoding="utf-8")
    assert "os.environ" not in source and "getenv" not in source


def test_the_record_binds_exactly_the_forge_owned_pattern(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    outcome = _import(tmp_path, release, digest)
    record = model.validate_import_record(outcome.record)
    assert record["credential_pattern"] == model.IMPORT_PATTERN.record() ==         model.GATE_SEED_PATTERN.record()
    # A record rewritten to name another pattern, its intent too, is refused.
    other = model.CredentialPattern("weaker", (r"sk-[A-Za-z0-9_-]{99,}",)).record()
    destination = verify_root / CYCLE
    for name in ("import-record.json", "import-intent.json"):
        document = json.loads((destination / name).read_text())
        document["credential_pattern"] = other
        (destination / name).write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    assert handoff.load_import(destination).state == "REFUSED"


# ---------------------------------------------------------------------------
# The import: every refusal, with nothing written
# ---------------------------------------------------------------------------

def _plant(change):
    return change


def _extra_entry(release: Path) -> None:
    (release / "i9999").write_bytes(b"x")


def _missing_item(release: Path) -> None:
    (release / "i0001").unlink()


def _directory_entry(release: Path) -> None:
    (release / "nested").mkdir()


def _symlinked_item(release: Path) -> None:
    target = release.parent / "elsewhere.py"
    target.write_bytes((release / "i0001").read_bytes())
    (release / "i0001").unlink()
    os.symlink(target, release / "i0001")


def _hard_linked_item(release: Path) -> None:
    os.link(release / "i0001", release.parent / "second-name")


def _resized_item(release: Path) -> None:
    (release / "i0002").write_bytes((release / "i0002").read_bytes() + b"#")


def _same_size_other_bytes(release: Path) -> None:
    data = bytearray((release / "i0002").read_bytes())
    data[0] ^= 1
    (release / "i0002").write_bytes(bytes(data))


def _record_missing(release: Path) -> None:
    (release / "release-record.json").unlink()


def _key_in_gate_item(release: Path) -> None:
    raise NotImplementedError  # built through gate_items below


RELEASE_REFUSALS = {
    "an extra entry": _extra_entry,
    "a missing item": _missing_item,
    "a directory": _directory_entry,
    "a symbolic link": _symlinked_item,
    "a hard link": _hard_linked_item,
    "an item of another size": _resized_item,
    "an item of other bytes": _same_size_other_bytes,
    "no release record": _record_missing,
}


@pytest.mark.parametrize("label", sorted(RELEASE_REFUSALS))
def test_a_tampered_release_is_refused_and_nothing_is_written(
        label: str, tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    RELEASE_REFUSALS[label](release)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED" and outcome.reasons, label
    assert os.listdir(verify_root) == []


def _files_with(**extra: bytes) -> dict[str, bytes]:
    files = _application()
    files.update({path.replace("__", "/"): data for path, data in extra.items()})
    return files


CONTENT_REFUSALS: dict[str, dict[str, Any]] = {
    "a key in a workspace file": {"files": _files_with(**{"app__config.py": f"K = '{KEY}'\n".encode()})},
    "a key in a gate item": {"gate_items": {"gate-stdout.txt": f"token {KEY}\n".encode()}},
    "a UTF-16 key": {"files": _files_with(**{"app__notes.txt": f"k={KEY}".encode("utf-16-le")})},
    "a file the list does not name": {"listing": b"BRD.md\n"},
    "a listed file that was not released": {"listing": _tree_list(_application()) + b"gone.py\n"},
    "a list naming itself": {"listing": _tree_list(_application()) + b".forge-tree.txt\n"},
    "a list with a CR": {"listing": _tree_list(_application()).replace(b"\n", b"\r\n")},
    "no completeness list": {"names": {"ws\\.forge-tree.txt": "ws\\tree.txt"}},
    "a .git directory": {"files": _files_with(**{".git__config": b"[core]\n"})},
    "a .nornyx directory": {"files": _files_with(**{".nornyx__contracts__x.nyx": b"x\n"})},
    "a cache directory": {"files": _files_with(**{"__pycache____x.txt": b"x\n"})},
    "a .pytest_cache directory": {"files": _files_with(**{".pytest_cache__README.md": b"x\n"})},
    "a case collision": {"files": _files_with(**{"app__Cases.py": b"X = 2\n"})},
    "a file that is also a directory": {"files": _files_with(**{"app": b"x\n"})},
    "a forward slash": {"names": {"ws\\app\\cases.py": "ws\\app/cases.py"}},
    "a climb": {"names": {"ws\\app\\cases.py": "ws\\..\\cases.py"}},
    "a trailing dot": {"names": {"ws\\app\\cases.py": "ws\\app\\cases.py."}},
    "a named-stream spelling": {"names": {"ws\\app\\cases.py": "ws\\app\\cases.py:evil"}},
    "a device name": {"names": {"ws\\app\\cases.py": "ws\\app\\NUL.py"}},
    "a non-ASCII name": {"names": {"ws\\app\\cases.py": "ws\\app\\casés.py"}},
    "a gate item with a path": {"gate_items": {"logs\\stdout.txt": b"x\n"}},
}


@pytest.mark.parametrize("label", sorted(CONTENT_REFUSALS))
def test_untrusted_content_is_refused_and_nothing_is_written(
        label: str, tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path, **CONTENT_REFUSALS[label])
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED" and outcome.reasons, label
    assert os.listdir(verify_root) == []
    assert not any(KEY in reason for reason in outcome.reasons), "a refusal quoted the match"


def test_the_manifest_must_be_the_one_the_act_cites(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    for cited in ("0" * 64, digest.upper(), "sha256:" + digest, digest[:-1]):
        outcome = _import(tmp_path, release, cited)
        assert outcome.state == "REFUSED", cited
    assert os.listdir(verify_root) == []


def test_the_release_must_be_named_for_the_cycle(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest, cycle_id="c-other").state == "REFUSED"
    for bad in ("", "../c", "c/d", "c d", "c." , None):
        assert _import(tmp_path, release, digest, cycle_id=bad).state == "REFUSED", bad


def test_an_import_needs_a_fresh_absent_destination(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    (verify_root / CYCLE).mkdir()
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED" and "fresh" in outcome.reasons[0]
    assert os.listdir(verify_root / CYCLE) == []


def test_a_destination_inside_the_release_is_refused(tmp_path: Path):
    release, digest = build_release(tmp_path)
    (release / "inner").mkdir()
    outcome = handoff.import_release(release / "inner" / "dest", release / "inner" / "x",
                                     cycle_id=CYCLE, layout=_layout(),
                                     expected_manifest_sha256=digest)
    assert outcome.state == "REFUSED"
    inside = handoff.import_release(release, release / "inner" / "dest", cycle_id=CYCLE,
                                    layout=_layout(), expected_manifest_sha256=digest)
    assert inside.state == "REFUSED" and "inside the release" in " ".join(inside.reasons)


def test_a_destination_reached_through_a_link_into_the_release_is_refused(
        tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    os.symlink(release, tmp_path / "into-release", target_is_directory=True)
    outcome = handoff.import_release(release, tmp_path / "into-release" / "dest",
                                     cycle_id=CYCLE, layout=_layout(),
                                     expected_manifest_sha256=digest)
    assert outcome.state == "REFUSED"
    assert sorted(os.listdir(release))[-1] == "release-record.json"
    assert "dest" not in os.listdir(release)


def test_a_release_that_changes_while_it_is_read_is_refused(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    release, digest = build_release(tmp_path)
    real = handoff.read_held
    calls = []

    def read_and_plant(path, limit=handoff.MAX_FILE_BYTES):
        calls.append(path)
        if len(calls) == 3:
            (release / "i9999").write_bytes(b"planted while the import read")
        return real(path, limit=limit)

    monkeypatch.setattr(handoff, "read_held", read_and_plant)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED" and "changed" in " ".join(outcome.reasons)
    assert os.listdir(verify_root) == []


# ---------------------------------------------------------------------------
# Bounds: each file kind read under its own limit, and every aggregate bound
# enforced before the work it bounds (Codex P2 4368336127, P2 4368336129)
# ---------------------------------------------------------------------------

def _many_small_files(count: int, size: int, stem: str = "f") -> dict[str, bytes]:
    return {f"data/{stem}{n:04d}.txt": (b"%04d" % n) + b"x" * (size - 4) for n in range(count)}


def test_a_large_valid_release_whose_record_exceeds_a_subject_files_bound_is_imported(
        tmp_path: Path, verify_root: Path):
    """Codex P2 4368336127: 1,951 files of 70 bytes (136,570 bytes) give an
    import record over 500,000 bytes. The record is Forge's own metadata and
    is read under its own bound, so the import completes and reads back."""
    files = _many_small_files(1951, 70, stem="a_module_named_for_what_it_does_in_full_")
    assert sum(len(data) for data in files.values()) == 136_570
    release, digest = build_release(tmp_path, files)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "COMPLETE", outcome.reasons
    assert len(outcome.record.encode("utf-8")) > handoff.MAX_FILE_BYTES
    again = handoff.load_import(verify_root / CYCLE)
    assert again.state == "COMPLETE", again.reasons
    assert len(again.workspace_files) == 1952  # the files and the completeness list


def test_every_forge_written_file_is_read_under_its_own_kinds_bound(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    """The class: no read of a Forge-written record, intent or manifest uses
    the subject file's 500,000-byte default, and no read of an imported or
    staged file is allowed more than the size Forge recorded for it."""
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    real = handoff.read_held
    limits: dict[str, int] = {}

    def recording(path, limit=None):
        assert limit is not None, f"{path} was read under the default bound"
        limits[str(Path(path).resolve())] = limit
        return real(path, limit=limit)

    monkeypatch.setattr(handoff, "read_held", recording)
    loaded = handoff.load_import(verify_root / CYCLE)
    assert loaded.state == "COMPLETE", loaded.reasons
    destination = (verify_root / CYCLE).resolve()
    assert limits[str(destination / "import-record.json")] == handoff.RECORD_READ_LIMIT
    assert limits[str(destination / "import-intent.json")] == handoff.RECORD_READ_LIMIT
    for path, data in loaded.workspace_files.items():
        assert limits[str(destination / "workspace" / path)] == len(data), path
    workspace, zone, records = _stage_dirs(tmp_path / "s")
    limits.clear()
    staged = handoff.stage_inputs(workspace, zone, records, role="codex")
    assert staged.state == "WRITTEN", staged.reasons
    manifest_path = (records / f"{staged.stage}.manifest.json").resolve()
    assert limits[str(manifest_path)] == len(staged.manifest.encode("utf-8"))
    limits.clear()
    assert handoff.verify_stage(zone, staged.manifest) == []
    document = model.validate_stage_manifest(staged.manifest)
    for path, entry in document["files"].items():
        assert limits[str((zone / staged.stage / path).resolve())] == entry["size"], path


def _counting_item_reads(monkeypatch: pytest.MonkeyPatch, release: Path) -> list[int]:
    """Bytes returned by every read of a released item (not the manifest or
    the release record), in order."""
    real = handoff.read_held
    returned: list[int] = []

    def counting(path, limit=None):
        data, reason = real(path, limit=limit)
        if Path(path).parent == release and Path(path).name.startswith("i"):
            returned.append(0 if data is None else len(data))
        return data, reason

    monkeypatch.setattr(handoff, "read_held", counting)
    return returned


def _sized_release_files(total: int) -> dict[str, bytes]:
    """Workspace files whose released items -- with the completeness list and
    the gate's stdout item that `build_release` adds -- total `total` bytes."""
    stdout = len(b"provider said hello\n")
    count = 21
    names = [f"data/f{n:02d}.bin" for n in range(count)]
    listing = len("".join(f"{name}\n" for name in sorted(names)).encode())
    remaining = total - stdout - listing
    sizes = [handoff.MAX_FILE_BYTES] * (remaining // handoff.MAX_FILE_BYTES)
    if remaining % handoff.MAX_FILE_BYTES:
        sizes.append(remaining % handoff.MAX_FILE_BYTES)
    assert len(sizes) <= count
    files = {name: b"z" * size for name, size in zip(names, sizes)}
    for name in names[len(sizes):]:
        files[name] = b""
    return files


def test_a_release_over_the_aggregate_bound_is_refused_before_any_item_is_read(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    """Codex P2 4368336129: the aggregate bound was checked only after every
    item had been read, scanned and kept. The manifest's declared sizes are
    summed first, so an over-bound release reads no item at all."""
    release, digest = build_release(tmp_path, _sized_release_files(handoff.MAX_TOTAL_BYTES + 1))
    returned = _counting_item_reads(monkeypatch, release)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED"
    assert any("byte bound" in reason for reason in outcome.reasons), outcome.reasons
    assert returned == [], "an item was read although the declared sizes exceed the bound"
    assert os.listdir(verify_root) == []


def test_an_item_larger_than_its_declared_size_is_refused_unread(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    """A manifest that understates its sizes passes the declared sum, so each
    item is read under its OWN declared size: an item larger than its row says
    is refused without a byte of it being read or kept, and the release's
    10.5 MB is never read."""
    files = _sized_release_files(handoff.MAX_TOTAL_BYTES + handoff.MAX_FILE_BYTES)
    release, digest = build_release(tmp_path, files)
    manifest = (release / "hold-manifest.jsonl").read_bytes().decode()
    rows = [json.loads(line) for line in manifest.splitlines()]
    for row in rows:
        row["size"] = 1  # understated: each row now lies about its size
    lying = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows).encode()
    (release / "hold-manifest.jsonl").write_bytes(lying)
    returned = _counting_item_reads(monkeypatch, release)
    outcome = _import(tmp_path, release, _sha(lying))
    assert outcome.state == "REFUSED"
    assert any("larger than 1 bytes" in reason for reason in outcome.reasons), outcome.reasons
    assert sum(returned) == 0, "bytes of an item larger than its declared size were read"
    assert os.listdir(verify_root) == []


def test_the_running_total_stops_reading_at_the_bound(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    """The second bound, for an item that grows between its listing and its
    read: the running total of bytes actually read refuses as soon as it
    passes the bound, and nothing after that item is read."""
    release, digest = build_release(tmp_path, _sized_release_files(handoff.MAX_TOTAL_BYTES))
    returned = _counting_item_reads(monkeypatch, release)
    real = handoff.read_held

    def growing(path, limit=None):
        data, reason = real(path, limit=limit)
        if data is not None and len(returned) == 3:
            return data + b"g" * handoff.MAX_TOTAL_BYTES, reason  # as if it grew
        return data, reason

    monkeypatch.setattr(handoff, "read_held", growing)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED"
    assert "nothing more is read" in outcome.reasons[0], outcome.reasons
    assert len(returned) == 3, "an item after the one that passed the bound was read"
    assert os.listdir(verify_root) == []


def test_a_release_at_exactly_the_aggregate_bound_is_imported(tmp_path: Path,
                                                              verify_root: Path):
    """The negative control: exactly MAX_TOTAL_BYTES released is within it."""
    release, digest = build_release(tmp_path, _sized_release_files(handoff.MAX_TOTAL_BYTES))
    released = sum(path.stat().st_size for path in release.iterdir()
                   if path.name.startswith("i"))
    assert released == handoff.MAX_TOTAL_BYTES
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "COMPLETE", outcome.reasons


def test_a_manifest_over_the_item_count_is_refused_before_any_item_is_read(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    release, digest = build_release(tmp_path, _many_small_files(model.ITEM_LIMIT + 1, 8))
    returned = _counting_item_reads(monkeypatch, release)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED" and "more than" in " ".join(outcome.reasons)
    assert returned == []


# ---------------------------------------------------------------------------
# Interruption, crash and tamper after the intent
# ---------------------------------------------------------------------------

def test_an_interrupted_import_is_incomplete_forever_and_never_read_as_one(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    release, digest = build_release(tmp_path)
    real = handoff._write_new
    writes = []

    def crash_on_the_fourth(path, data):
        writes.append(path)
        if len(writes) == 4:
            raise OSError(28, "No space left on device")
        real(path, data)

    monkeypatch.setattr(handoff, "_write_new", crash_on_the_fourth)
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "INCOMPLETE" and "unusable" in outcome.reasons[-1]
    monkeypatch.setattr(handoff, "_write_new", real)
    destination = verify_root / CYCLE
    assert (destination / "import-intent.json").exists()
    assert not (destination / "import-record.json").exists()
    assert handoff.load_import(destination).state == "INCOMPLETE"
    # The same destination is never reused; a fresh one imports.
    assert _import(tmp_path, release, digest).state == "REFUSED"
    fresh = handoff.import_release(release, verify_root / "fresh", cycle_id=CYCLE,
                                   layout=_layout(), expected_manifest_sha256=digest)
    assert fresh.state == "COMPLETE", fresh.reasons


def test_a_crash_before_the_record_is_written_leaves_no_import(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    release, digest = build_release(tmp_path)
    real = handoff._write_new

    def no_record(path, data):
        if Path(path).name == "import-record.json":
            raise OSError(5, "Input/output error")
        real(path, data)

    monkeypatch.setattr(handoff, "_write_new", no_record)
    assert _import(tmp_path, release, digest).state == "INCOMPLETE"
    assert handoff.load_import(verify_root / CYCLE).state == "INCOMPLETE"


@pytest.mark.parametrize("damage", ["torn record", "changed file", "extra file", "removed file",
                                    "intent of another cycle", "empty directory"])
def test_a_destination_changed_after_import_is_refused(damage: str, tmp_path: Path,
                                                       verify_root: Path):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    destination = verify_root / CYCLE
    if damage == "torn record":
        record = destination / "import-record.json"
        record.write_bytes(record.read_bytes()[:40])
    elif damage == "changed file":
        (destination / "workspace" / "app" / "cases.py").write_bytes(b"X = 'other'\n")
    elif damage == "extra file":
        (destination / "workspace" / "app" / "planted.py").write_bytes(b"import os\n")
    elif damage == "removed file":
        (destination / "workspace" / "BRD.md").unlink()
    elif damage == "empty directory":
        (destination / "workspace" / "app" / "planted").mkdir()
    else:
        intent = destination / "import-intent.json"
        intent.write_bytes(intent.read_bytes().replace(CYCLE.encode(), b"c-other"))
    assert handoff.load_import(destination).state == "REFUSED"


def test_a_destination_that_is_not_an_import_is_refused(tmp_path: Path):
    (tmp_path / "empty").mkdir()
    assert handoff.load_import(tmp_path / "empty").state == "REFUSED"
    assert handoff.load_import(tmp_path / "absent").state == "REFUSED"


# ---------------------------------------------------------------------------
# Windows is the subject: junctions and named data streams
# ---------------------------------------------------------------------------

def _junction(link: Path, target: Path) -> None:
    import _winapi  # noqa: PLC0415 - Windows only

    _winapi.CreateJunction(str(target), str(link))


@windows_only
def test_a_junction_in_a_release_is_refused(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    (tmp_path / "outside").mkdir()
    _junction(release / "i9999", tmp_path / "outside")
    assert _import(tmp_path, release, digest).state == "REFUSED"
    assert os.listdir(verify_root) == []


@windows_only
def test_a_release_directory_that_is_a_junction_is_refused(tmp_path: Path, verify_root: Path):
    real, digest = build_release(tmp_path / "real")
    (tmp_path / "release").mkdir()
    _junction(tmp_path / "release" / CYCLE, real)
    outcome = handoff.import_release(tmp_path / "release" / CYCLE, verify_root / CYCLE,
                                     cycle_id=CYCLE, layout=_layout(),
                                     expected_manifest_sha256=digest)
    assert outcome.state == "REFUSED" and "reparse" in outcome.reasons[0]


@windows_only
def test_a_named_stream_on_a_released_item_is_refused(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    with open(f"{release / 'i0002'}:hidden", "wb") as stream:
        stream.write(f"carried past the digest {KEY}".encode())
    assert handoff.named_streams(release / "i0002") == [":hidden:$DATA"]
    outcome = _import(tmp_path, release, digest)
    assert outcome.state == "REFUSED" and "named data stream" in " ".join(outcome.reasons)
    assert os.listdir(verify_root) == []


@windows_only
def test_a_named_stream_on_the_release_directory_is_refused(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    with open(f"{release}:hidden", "wb") as stream:
        stream.write(b"x")
    assert _import(tmp_path, release, digest).state == "REFUSED"


@windows_only
def test_a_named_stream_planted_after_import_is_refused_on_reading(tmp_path: Path,
                                                                   verify_root: Path):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    with open(f"{verify_root / CYCLE / 'workspace' / 'BRD.md'}:hidden", "wb") as stream:
        stream.write(b"x")
    assert handoff.load_import(verify_root / CYCLE).state == "REFUSED"


@windows_only
def test_a_named_stream_planted_in_a_stage_is_found(tmp_path: Path):
    workspace, zone, records = _stage_dirs(tmp_path)
    outcome = handoff.stage_inputs(workspace, zone, records, role="codex")
    assert outcome.state == "WRITTEN"
    with open(f"{zone / outcome.stage / 'BRD.md'}:hidden", "wb") as stream:
        stream.write(b"x")
    assert any("named data stream" in problem
               for problem in handoff.verify_stage(zone, outcome.manifest))


def test_named_streams_are_enumerated_or_reported_unenumerable(tmp_path: Path):
    (tmp_path / "plain.txt").write_bytes(b"x")
    assert handoff.named_streams(tmp_path / "plain.txt") == []
    assert handoff.named_streams(tmp_path) == []
    if WINDOWS:
        assert handoff.named_streams(tmp_path / "absent") is None


# ---------------------------------------------------------------------------
# The input stage
# ---------------------------------------------------------------------------

def _stage_dirs(base: Path) -> tuple[Path, Path, Path]:
    workspace, zone, records = base / "workspace", base / "zi" / "codex", base / "records"
    workspace.mkdir(parents=True)
    zone.mkdir(parents=True)
    records.mkdir()
    (workspace / "BRD.md").write_bytes(BRD.encode())
    # Workspace content that is NOT on the allowlist is never staged.
    (workspace / "notes.txt").write_bytes(b"private\n")
    return workspace, zone, records


def test_a_stage_holds_exactly_what_forge_rendered(tmp_path: Path):
    workspace, zone, records = _stage_dirs(tmp_path)
    outcome = handoff.stage_inputs(workspace, zone, records, role="codex")
    assert outcome.state == "WRITTEN", outcome.reasons
    assert model.STAGE_NAME.match(outcome.stage)
    assert os.listdir(zone) == [outcome.stage]
    document = model.validate_stage_manifest(outcome.manifest)
    assert sorted(document["files"]) == sorted([
        "BRD.md", "INSTRUCTIONS.md", "contract/brd_contract.nyx",
        "contract/runtime-contract.json", "requirements/requirements.json",
        "requirements/traceability.md"])
    stage = zone / outcome.stage
    assert (stage / "BRD.md").read_bytes() == BRD.encode()
    assert document["sources"]["runtime_contract"] == "sha256:" + _sha(
        (stage / "contract" / "runtime-contract.json").read_bytes())
    assert document["sources"]["verified_import"] is None
    assert handoff.verify_stage(zone, outcome.manifest) == []
    assert sorted(os.listdir(records)) == [f"{outcome.stage}.intent.json",
                                           f"{outcome.stage}.manifest.json"]
    assert (records / f"{outcome.stage}.manifest.json").read_text() == outcome.manifest
    assert "notes.txt" not in json.dumps(document)


def test_the_staged_contracts_are_the_ones_the_build_renders(tmp_path: Path):
    """The stage's contracts are the flow's own renderings of the same BRD."""
    workspace, zone, records = _stage_dirs(tmp_path)
    outcome = handoff.stage_inputs(workspace, zone, records, role="codex")
    stage = zone / outcome.stage
    brd = (stage / "BRD.md").read_bytes()
    assert "sha256:" + _sha((stage / "contract" / "brd_contract.nyx").read_bytes()) == \
        app_handoff.rendered_contract_digest(brd)
    assert "sha256:" + _sha((stage / "contract" / "runtime-contract.json").read_bytes()) == \
        app_handoff.rendered_runtime_contract_digest(brd)


@pytest.mark.parametrize("problem", ["occupied zone", "another role's zone", "bad role",
                                     "no BRD", "records in the zone", "zone is a symlink"])
def test_a_stage_is_refused_with_nothing_written(problem: str, tmp_path: Path):
    workspace, zone, records = _stage_dirs(tmp_path)
    role = "codex"
    if problem == "occupied zone":
        (zone / ("s" + "0" * 16)).mkdir()  # a stage an earlier cycle left
    elif problem == "another role's zone":
        role = "claude"
    elif problem == "bad role":
        role = "co dex"
    elif problem == "no BRD":
        (workspace / "BRD.md").unlink()
    elif problem == "records in the zone":
        records = zone
    else:
        os.rename(zone, tmp_path / "zi" / "real")
        os.symlink(tmp_path / "zi" / "real", zone, target_is_directory=True)
    before = sorted(os.listdir(tmp_path / "zi" / "real" if problem == "zone is a symlink" else zone))
    outcome = handoff.stage_inputs(workspace, zone, records, role=role)
    assert outcome.state == "REFUSED" and outcome.manifest is None, problem
    after = sorted(os.listdir(tmp_path / "zi" / "real" if problem == "zone is a symlink" else zone))
    assert after == before
    if records != zone:
        assert os.listdir(records) == []


def test_an_interrupted_stage_is_rejected_retained_and_blocks_the_next(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace, zone, records = _stage_dirs(tmp_path)
    real = handoff._write_new
    writes = []

    def crash_on_the_third(path, data):
        writes.append(path)
        if len(writes) == 3:
            raise OSError(28, "No space left on device")
        real(path, data)

    monkeypatch.setattr(handoff, "_write_new", crash_on_the_third)
    outcome = handoff.stage_inputs(workspace, zone, records, role="codex")
    monkeypatch.setattr(handoff, "_write_new", real)
    assert outcome.state == "REJECTED" and outcome.manifest is None
    assert os.listdir(zone) == [outcome.stage]  # retained, never removed by Forge
    assert (records / f"{outcome.stage}.rejected.json").exists()
    assert not (records / f"{outcome.stage}.manifest.json").exists()
    again = handoff.stage_inputs(workspace, zone, records, role="codex")
    assert again.state == "REFUSED" and "not empty" in again.reasons[0]


@pytest.mark.parametrize("change", ["extra", "changed", "removed", "second stage",
                                    "empty directory"])
def test_a_changed_stage_is_found(change: str, tmp_path: Path):
    workspace, zone, records = _stage_dirs(tmp_path)
    outcome = handoff.stage_inputs(workspace, zone, records, role="codex")
    stage = zone / outcome.stage
    if change == "extra":
        (stage / "extra.md").write_bytes(b"x")
    elif change == "changed":
        (stage / "INSTRUCTIONS.md").write_bytes(b"do something else\n")
    elif change == "removed":
        (stage / "BRD.md").unlink()
    elif change == "empty directory":
        (stage / "contract" / "planted").mkdir()
    else:
        (zone / ("s" + "f" * 16)).mkdir()
    assert handoff.verify_stage(zone, outcome.manifest)


def test_a_repair_stage_carries_the_verified_import(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    workspace, zone, records = _stage_dirs(tmp_path / "s")
    outcome = handoff.stage_inputs(workspace, zone, records, role="codex",
                                   verified=verify_root / CYCLE)
    assert outcome.state == "WRITTEN", outcome.reasons
    document = model.validate_stage_manifest(outcome.manifest)
    loaded = handoff.load_import(verify_root / CYCLE)
    assert document["sources"]["verified_import"] == loaded.record_digest
    assert {path.removeprefix("verified/") for path in document["files"]
            if path.startswith("verified/")} == set(loaded.workspace_files)
    # An incomplete import is never staged.
    (verify_root / CYCLE / "import-record.json").unlink()
    workspace2, zone2, records2 = _stage_dirs(tmp_path / "t")
    assert handoff.stage_inputs(workspace2, zone2, records2, role="codex",
                                verified=verify_root / CYCLE).state == "REFUSED"


def test_the_instructions_name_the_completeness_list():
    assert model.COMPLETENESS_LIST in handoff.PROVIDER_INSTRUCTIONS
    assert "python -m app" in handoff.PROVIDER_INSTRUCTIONS


# ---------------------------------------------------------------------------
# Static-only verification
# ---------------------------------------------------------------------------

def test_the_static_only_mode_names_the_verifiers_own_values():
    assert gates.GREENFIELD_STATIC_ONLY_MODE == greenfield_verifier.STATIC_ONLY_MODE
    assert gates.GREENFIELD_STATIC_ONLY_DETAIL == greenfield_verifier.STATIC_ONLY_DETAIL


def _marked_application() -> dict[str, bytes]:
    """The reference application with a test module that fails the moment
    anything imports it: a collection error is the observable proof that
    produced code ran."""
    files = _application()
    files["tests/test_cases.py"] += b"\n\nraise RuntimeError('PRODUCED-CODE-RAN')\n"
    return files


def test_static_only_verification_runs_every_static_gate_and_no_produced_code(
        tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path, _marked_application())
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    result = handoff.verify_import_static(verify_root / CYCLE)
    assert result.passed, result.findings
    # No runner, no executor, no completion: nothing was started on the subject.
    assert result.provenance["test_execution"] == {
        "status": "not_run", "mode": "static_only",
        "final_subject_digest": result.provenance["subject"]["digest"]}
    # The positive control: in the full mode the same subject's tests are
    # collected, the planted module is imported and collection fails.
    results, provenance = gates.trusted_greenfield_gates(verify_root / CYCLE / "workspace")
    test_gate = next(r for r in results if r.name == "greenfield:test-execution")
    assert not test_gate.passed and "executor pytest exit 2" in test_gate.detail, test_gate.detail
    assert "completion" in provenance["test_execution"]


def test_a_static_only_result_is_never_an_acceptance(tmp_path: Path, verify_root: Path):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    results, provenance = gates.trusted_greenfield_gates(verify_root / CYCLE / "workspace",
                                                         static_only=True)
    test_gate = next(r for r in results if r.name == "greenfield:test-execution")
    assert not test_gate.passed and not all(r.passed for r in results)
    assert all(r.passed for r in results if r is not test_gate)
    assert "--static-only" in results[0].command


def _doctored(monkeypatch: pytest.MonkeyPatch, change) -> None:
    """Run the real verifier and change its output before the parent reads it."""
    real = gates.subprocess.run

    def run(command, *args, **kwargs):
        completed = real(command, *args, **kwargs)
        if "--project-root" in command:
            payload = json.loads(completed.stdout)
            command = change(list(command), payload)
            completed = subprocess.CompletedProcess(completed.args, completed.returncode,
                                                    json.dumps(payload), completed.stderr)
        return completed

    monkeypatch.setattr(gates.subprocess, "run", run)


def test_a_static_record_where_tests_were_to_run_is_refused(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"

    def as_static(command, payload):
        payload["test_execution"] = {"status": "not_run", "mode": "static_only",
                                     "final_subject_digest": payload["subject"]["digest"]}
        payload["gates"][-1] = {"id": "test-execution", "passed": False,
                                "detail": gates.GREENFIELD_STATIC_ONLY_DETAIL}
        payload["status"] = "fail"
        return command

    _doctored(monkeypatch, as_static)
    results, _ = gates.trusted_greenfield_gates(verify_root / CYCLE / "workspace")
    assert [r.name for r in results] == ["greenfield:trusted-verifier-identity"]
    assert "static-only" in results[0].detail


def test_a_full_record_where_static_only_was_asked_is_refused(
        tmp_path: Path, verify_root: Path, monkeypatch: pytest.MonkeyPatch):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"

    def as_full(command, payload):
        payload["test_execution"] = {"status": "not_run",
                                     "final_subject_digest": payload["subject"]["digest"]}
        payload["gates"][-1] = {"id": "test-execution", "passed": False, "detail": "x"}
        return command

    _doctored(monkeypatch, as_full)
    results, _ = gates.trusted_greenfield_gates(verify_root / CYCLE / "workspace",
                                                static_only=True)
    assert [r.name for r in results] == ["greenfield:trusted-verifier-identity"]


def test_static_verification_of_an_incomplete_import_is_refused(tmp_path: Path,
                                                                verify_root: Path):
    release, digest = build_release(tmp_path)
    assert _import(tmp_path, release, digest).state == "COMPLETE"
    (verify_root / CYCLE / "import-record.json").unlink()
    ran = []
    result = handoff.verify_import_static(verify_root / CYCLE,
                                          runner=lambda *a, **k: ran.append(a) or ([], {}))
    assert not result.passed and ran == []


# ---------------------------------------------------------------------------
# The gated build's manifest, sealed, and never offered
# ---------------------------------------------------------------------------

def _gated_build(base: Path) -> dict[str, Any]:
    """Stage, a simulated provider's release, import and static verification,
    and a sealed store, as the gated path composes them. Returns the issuance
    inputs."""
    workspace, zone, records = _stage_dirs(base / "forge")
    staged = handoff.stage_inputs(workspace, zone, records, role="codex")
    assert staged.state == "WRITTEN", staged.reasons
    # The simulated provider reads the BRD from the stage and returns it unchanged.
    files = _application()
    files["BRD.md"] = (zone / staged.stage / "BRD.md").read_bytes()
    release, digest = build_release(base, files)
    (base / "verify").mkdir()
    imported = handoff.import_release(release, base / "verify" / CYCLE, cycle_id=CYCLE,
                                      layout=_layout(), expected_manifest_sha256=digest)
    assert imported.state == "COMPLETE", imported.reasons
    verification = handoff.verify_import_static(base / "verify" / CYCLE)
    assert verification.passed, verification.findings
    project = base / "project"
    project.mkdir()
    store = CapsuleStore(project / "capsule", seal_dir=base / "seals")
    document = create_document("proj-1", "Portal", CASEY, AT)
    store.initialize(document, experience=start_experience(CASEY, AT))
    document = store.load()
    tip = document["digest_chain"][-1]
    brd_digest = hashlib.sha256(BRD.encode()).hexdigest()
    return {
        "destination": base / "verify" / CYCLE, "store_root": store.root,
        "document": {**document, "authoritative": {**document["authoritative"],
                                                   "provider": {"name": "codex"}}},
        "lifecycle": {"evidence": {"BUILD": [{"kind": "brd_requirements", "passed": True,
                                              "ref": f"capsule/{tip}/brd/{brd_digest}"}]}},
        "sealed_revision": store.revision(), "platform": PLATFORM,
        "stage_manifest": staged.manifest, "verification": verification,
        "run_act_sha256": provider_gate.PINNED_RUN_ACT_SHA256,
        "check_d3g_result": "sha256:" + "5" * 64,
        "_store": store,
    }


def test_a_gated_build_is_issued_a_manifest_with_its_provenance_and_runtime_contract(
        tmp_path: Path):
    inputs = _gated_build(tmp_path)
    store = inputs.pop("_store")
    issued = handoff.issue_gate_manifest(**inputs)
    assert issued.findings == () and issued.text is not None, issued.findings
    manifest = pam.validate_pam(issued.text)
    stage = model.validate_stage_manifest(inputs["stage_manifest"])
    record = model.validate_import_record(handoff.load_import(inputs["destination"]).record)
    provenance = manifest["gate_provenance"]
    assert provenance["cycle_id"] == CYCLE
    assert provenance["run_act_sha256"] == provider_gate.PINNED_RUN_ACT_SHA256
    assert provenance["stage_manifest"] == "sha256:" + _sha(inputs["stage_manifest"].encode())
    assert provenance["import_record"] == handoff.load_import(inputs["destination"]).record_digest
    assert provenance["release_manifest"] == record["release_manifest"]
    assert provenance["completeness_list"] == record["completeness_list"]
    assert provenance["credential_pattern"] == model.GATE_SEED_PATTERN.record()
    assert provenance["verification"] == "static_only"
    assert provenance["check_d3g_result"] == inputs["check_d3g_result"]
    assert manifest["runtime_contract"] == {
        "path": RUNTIME_CONTRACT_PATH, "digest": stage["sources"]["runtime_contract"],
        "basis": "rendered_by_forge_from_the_accepted_brd"}
    assert manifest["generated_contract"]["digest"] == stage["sources"]["generated_contract"]
    assert manifest["subject"]["digest"] == record["workspace_subject_digest"]
    # Sealed like any manifest, and never offered.
    state = fail(store.load_experience(), SYSTEM_ACTOR, "a transition to commit beside", AT)
    store.save_produced_application(state, issued.text, "reached GOVERN")
    assert store.sealed().files["pam.json"] == issued.text
    readiness = app_handoff.assess_readiness(
        store, inputs["destination"] / "workspace", platform=PLATFORM,
        eligibility=lambda provider, platform: app_handoff.GovernedEligibility(
            provider=provider, platform=platform, eligible=True, confinement="injected",
            reason="a unit test's verdict"))
    assert not readiness.offered
    assert any("run-act gate" in reason for reason in readiness.reasons)


GATED_REFUSALS = {
    "another run-act digest": {"run_act_sha256": "0" * 64},
    "a check result of another shape": {"check_d3g_result": "5" * 64},
    "a failed static verification": "failed",
    "another stage": "another stage",
    "a BRD the provider changed": "changed brd",
    "an incomplete import": "incomplete",
    "a scope bound to another BRD": "other scope",
}


@pytest.mark.parametrize("label", sorted(GATED_REFUSALS))
def test_a_gated_manifest_is_refused(label: str, tmp_path: Path):
    inputs = _gated_build(tmp_path)
    inputs.pop("_store")
    change = GATED_REFUSALS[label]
    if isinstance(change, dict):
        inputs.update(change)
    elif change == "failed":
        inputs["verification"] = handoff.StaticVerification(False, ("x",), {})
    elif change == "another stage":
        inputs["stage_manifest"] = inputs["stage_manifest"].replace(
            json.loads(inputs["stage_manifest"])["sources"]["brd"], "sha256:" + "0" * 64)
    elif change == "changed brd":
        brd = inputs["destination"] / "workspace" / "BRD.md"
        brd.write_bytes(brd.read_bytes() + b"\n## BRD-002 More\n\nMore.\n")
    elif change == "incomplete":
        (inputs["destination"] / "import-record.json").unlink()
    else:
        tip = inputs["document"]["digest_chain"][-1]
        inputs["lifecycle"] = {"evidence": {"BUILD": [{"kind": "brd_requirements",
                                                       "passed": True,
                                                       "ref": f"capsule/{tip}/brd/{'0' * 64}"}]}}
    issued = handoff.issue_gate_manifest(**inputs)
    assert issued.text is None and issued.findings, label


def test_the_module_starts_no_process_of_its_own():
    source = Path(handoff.__file__).read_text(encoding="utf-8")
    for forbidden in ("import subprocess", "import multiprocessing", "import runpy",
                      "importlib", "os.system", "os.startfile", "os.exec", "os.spawn",
                      "CreateProcess", "LogonUser", "SetFileSecurity", "SetNamedSecurityInfo",
                      "icacls"):
        assert forbidden not in source, forbidden
    assert sys.modules[handoff.__name__] is handoff
