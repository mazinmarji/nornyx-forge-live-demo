"""The deterministic Windows payload: its manifest, its self-check, and the
builder that makes it.

Five groups. The VERIFIER (`nornyx_forge.windows_payload`) over synthetic
folders, with a named refusal for each guard: a changed byte (past the first
MiB too), a size, a missing, unlisted or renamed file, bytecode, an empty
directory, a link, a reparse point (through a status that carries the Windows
attribute), a hard link (the manifest's too), a FIFO, a name or a pair of
names the rule refuses, an edited manifest, an unexpected identity, and the
crashes it must turn into refusals. The BUILDER over a synthetic git
repository: the copy is the commit, every input is read from the commit, the
builder's own files must be the commit's even under an index flag or a clean
filter, replace refs and git variables reach nothing, the
marker carries no wall clock, and two builds at different clocks are the same
bytes. The PINS and the LOCK. The WHEEL-TAG CENSUS. The SHAPE of the
`windows-payload` CI job, read as structure.

What these tests cannot show: that the real closure installs from the
network and rebuilds identically (the `windows-payload` job's measurement),
and any Windows behaviour -- nothing here runs on Windows, and the reparse
attribute is reached through a constructed status, not a junction.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
import types
import zipfile
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_windows_bundle as builder  # noqa: E402
from build_windows_bundle import BundleError  # noqa: E402

from nornyx_forge import windows_payload  # noqa: E402
from nornyx_forge.windows_payload import (  # noqa: E402
    PAYLOAD_MANIFEST,
    PayloadError,
    build_manifest,
    check_name,
    check_names,
    payload_files,
    payload_identity,
    render_manifest,
    verify,
)

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

COMMIT = "0123456789abcdef0123456789abcdef01234567"
FIELDS = {"version": "0.0.0", "source_commit": COMMIT, "source_date_epoch": 1700000000,
          "target": "cp313-win_amd64", "lock_sha256": "a" * 64,
          "installer": {"name": "uv", "version": "0.0.0"},
          "interpreter": {"version": "3.13.0", "archive_url": "https://example.invalid/e.zip",
                          "archive_sha256": "b" * 64}}
BIG = (1 << 20) + 4096


def _folder(root: Path, files: dict[str, bytes]) -> Path:
    for relative, data in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def _seal(root: Path) -> Path:
    (root / PAYLOAD_MANIFEST).write_bytes(render_manifest(build_manifest(root, **FIELDS)))
    return root


def _sealed(tmp_path: Path) -> Path:
    return _seal(_folder(tmp_path / "payload", {
        "src/nornyx_forge/x.py": b"print('x')\n", ".nornyx/contracts/a.nyx": b"a\n",
        "python/python.exe": b"MZ", "pylib/dep/__init__.py": b"", "Forge.cmd": b"@echo off\n",
        "pylib/dep/big.bin": bytes(BIG)}))


def _manifest(root: Path) -> dict:
    return json.loads((root / PAYLOAD_MANIFEST).read_text(encoding="utf-8"))


def _rewrite(root: Path, change, reseal: bool = False) -> None:
    """Edit the manifest; with `reseal`, recompute its identity too, so the
    guard under test -- not the identity check -- is what refuses."""
    manifest = _manifest(root)
    change(manifest)
    if reseal:
        manifest["payload_sha256"] = payload_identity(manifest)
    (root / PAYLOAD_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")


def _flip_last_byte(path: Path) -> None:
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 0x01]))


# ---------------------------------------------------------------------------
# The verifier: a named refusal for each guard
# ---------------------------------------------------------------------------

def test_a_sealed_folder_verifies_and_its_identity_is_its_content(tmp_path: Path):
    root = _sealed(tmp_path)
    manifest = _manifest(root)
    assert verify(root) == {"payload_sha256": manifest["payload_sha256"], "files_compared": 6}
    body = {key: value for key, value in manifest.items() if key != "payload_sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert manifest["payload_sha256"] == hashlib.sha256(canonical).hexdigest()
    sizes = {path: size for path, size, _digest in manifest["files"]}
    assert sizes["pylib/dep/big.bin"] == BIG and sizes["python/python.exe"] == 2
    assert [entry[0] for entry in manifest["files"]][:2] == [".nornyx/contracts/a.nyx",
                                                             "Forge.cmd"]


@pytest.mark.parametrize("victim", ["src/nornyx_forge/x.py", "pylib/dep/big.bin"],
                         ids=["small-file", "past-the-first-MiB"])
def test_one_changed_byte_is_refused_by_name(tmp_path: Path, victim: str):
    root = _sealed(tmp_path)
    _flip_last_byte(root / victim)
    with pytest.raises(PayloadError, match=f"changed: {re.escape(victim)}"):
        verify(root)


def test_a_manifest_that_lies_about_a_size_is_refused(tmp_path: Path):
    root = _sealed(tmp_path)

    def shrink(manifest: dict) -> None:
        entry = next(entry for entry in manifest["files"] if entry[0] == "python/python.exe")
        entry[1] = 1

    _rewrite(root, shrink, reseal=True)
    with pytest.raises(PayloadError, match="changed: python/python.exe"):
        verify(root)


def test_a_missing_unlisted_or_renamed_file_is_refused_by_name(tmp_path: Path):
    root = _sealed(tmp_path)
    (root / "pylib" / "dep" / "__init__.py").unlink()
    _folder(root, {"src/nornyx_forge/planted.py": b"import os\n"})
    with pytest.raises(PayloadError) as refused:
        verify(root)
    assert "missing: pylib/dep/__init__.py" in str(refused.value)
    assert "unlisted: src/nornyx_forge/planted.py" in str(refused.value)
    root = _sealed(tmp_path / "nested")
    _folder(root, {f"src/{PAYLOAD_MANIFEST}": b"{}"})
    with pytest.raises(PayloadError, match=f"unlisted: src/{re.escape(PAYLOAD_MANIFEST)}"):
        verify(root)
    root = _sealed(tmp_path / "second")
    (root / "src" / "nornyx_forge" / "x.py").rename(root / "src" / "nornyx_forge" / "X.py")
    with pytest.raises(PayloadError, match=r"missing: src/nornyx_forge/x\.py.*"
                                           r"unlisted: src/nornyx_forge/X\.py"):
        verify(root)


@pytest.mark.parametrize("planted", ["src/nornyx_forge/__pycache__/x.cpython-313.pyc",
                                     "pylib/dep/__pycache__/__init__.cpython-313.pyc",
                                     "pylib/dep/stray.pyc", "python/__pycache__/any.dll"])
def test_bytecode_anywhere_is_refused_nothing_is_exempt(tmp_path: Path, planted: str):
    """Python runs a `__pycache__` file whose header matches the source in
    preference to the source, so a skipped directory would be unverified code."""
    root = _sealed(tmp_path)
    _folder(root, {planted: b"\0"})
    with pytest.raises(PayloadError, match="bytecode"):
        verify(root)


def _plant(manifest: dict, listed: str) -> None:
    manifest["files"] = sorted(manifest["files"] + [[listed, 1, "c" * 64]],
                               key=lambda entry: entry[0].encode("utf-8"))


MANIFEST_GUARDS = [
    ("entry-removed", lambda m: m["files"].pop(), False, "not the digest of its own content"),
    ("field-added", lambda m: m.update(extra=1), True, "exactly the fields"),
    ("schema", lambda m: m.update(schema="other"), True, "schema"),
    ("commit", lambda m: m.update(source_commit="HEAD"), True, "40-hex source commit"),
    ("commit-prefix", lambda m: m.update(source_commit=COMMIT + "x"), True, "40-hex"),
    ("epoch-bool", lambda m: m.update(source_date_epoch=True), True, "source_date_epoch"),
    ("epoch-negative", lambda m: m.update(source_date_epoch=-1), True, "source_date_epoch"),
    ("order", lambda m: m["files"].reverse(), True, "byte order"),
    ("duplicate", lambda m: m["files"].insert(1, list(m["files"][0])), True, "unique"),
    ("lists-itself", lambda m: m.update(files=sorted(
        m["files"] + [[PAYLOAD_MANIFEST, 1, "c" * 64]], key=lambda e: e[0].encode())), True,
     "list the manifest"),
    ("size-negative", lambda m: m["files"][0].__setitem__(1, -1), True, "malformed entry"),
    ("size-bool", lambda m: m["files"][0].__setitem__(1, True), True, "malformed entry"),
    ("digest-prefix", lambda m: m["files"][0].__setitem__(2, "c" * 64 + "ff"), True,
     "malformed entry"),
    ("lock-prefix", lambda m: m.update(lock_sha256="a" * 64 + "0"), True, "lock_sha256"),
    ("version-path", lambda m: m.update(version="..\\..\\evil"), True, "version"),
    ("target-path", lambda m: m.update(target="cp313/../x"), True, "target"),
    ("archive-file-url", lambda m: m["interpreter"].update(archive_url="file:///etc/passwd"),
     True, "https"),
    ("interpreter-field", lambda m: m["interpreter"].pop("version"), True, "interpreter"),
    ("installer-field", lambda m: m["installer"].update(extra="x"), True, "installer"),
    ("installer-token", lambda m: m["installer"].update(version="bad/version"), True,
     "installer"),
    ("case-collision", lambda m: _plant(m, "FORGE.cmd"), True, "one path on Windows"),
    ("directory-case-collision", lambda m: _plant(m, "src/NORNYX_FORGE/y.py"), True,
     "one path on Windows"),
    ("file-and-directory", lambda m: _plant(m, "FORGE.CMD/x"), True, "one path on Windows"),
]


@pytest.mark.parametrize("change, reseal, message",
                         [row[1:] for row in MANIFEST_GUARDS],
                         ids=[row[0] for row in MANIFEST_GUARDS])
def test_each_manifest_guard_refuses_by_name(tmp_path: Path, change, reseal, message):
    root = _sealed(tmp_path)
    _rewrite(root, change, reseal=reseal)
    with pytest.raises(PayloadError, match=message):
        verify(root)


def test_a_repeated_key_a_non_json_constant_or_an_oversized_manifest_is_refused(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _sealed(tmp_path)
    text = (root / PAYLOAD_MANIFEST).read_text(encoding="utf-8")
    (root / PAYLOAD_MANIFEST).write_text('{"version": "x",' + text[1:], encoding="utf-8")
    with pytest.raises(PayloadError, match="repeats a key"):
        verify(root)
    (root / PAYLOAD_MANIFEST).write_text(text.replace('"source_date_epoch": 1700000000',
                                                      '"source_date_epoch": NaN'),
                                         encoding="utf-8")
    with pytest.raises(PayloadError, match="non-JSON constant"):
        verify(root)
    (root / PAYLOAD_MANIFEST).write_text(text, encoding="utf-8")
    monkeypatch.setattr(windows_payload, "MAX_MANIFEST_BYTES", 100)
    with pytest.raises(PayloadError, match="larger than 100 bytes"):
        verify(root)
    (root / PAYLOAD_MANIFEST).unlink()
    with pytest.raises(PayloadError, match="not a sealed payload"):
        verify(root)


UNSAFE_NAMES = [
    ("../outside.py", "'..'"), ("/etc/passwd", "absolute"), ("src\\x.py", "<>"),
    ("C:/x.py", "<>"), ("src//x.py", "empty"), ("src/./x.py", "'.'"),
    ("src/__pycache__/x.py", "bytecode"), ("src/x.pyc", "bytecode"), ("src/x.pyo", "bytecode"),
    ("src/x\n.py", "control"), ("src/x\x7f.py", "control"), ("", "non-empty"),
    ("src/con", "device"), ("src/AUX.py", "device"), ("src/nul.txt", "device"),
    ("src/COM1.py", "device"), ("src/lpt9", "device"), ("src/con .txt", "device"),
    ("src/a.", "dot or a space"), ("src/b ", "dot or a space"), ("src/a|b", "<>"),
    ("src/a?b", "<>"), ("src/a*b", "<>"), ('src/a"b', "<>"), ("src/a<b", "<>"),
    ("x" * 161, "longer than"), ("src/caf\u0065\u0301.py", "NFC"),
    ("src/\udcff.py", "UTF-8"), ("src/" + "\U0001F600" * 79, "longer than"),
    ("src/pkg/__PYCACHE__/m.py", "bytecode"), ("src/m.PYC", "bytecode"),
    ("src/m.Pyo", "bytecode"), ("src/a>b", "<>"), ("src/PRN", "device"),
    ("src/com\u00b9.txt", "device"), ("src/lpt\u00b3", "device"), ("src/CONIN$", "device"),
    ("src/conout$.log", "device"), ("src/COM0", "device"), ("src/lpt0.x", "device"),
]


@pytest.mark.parametrize("unsafe, reason", UNSAFE_NAMES, ids=[repr(n)[:30] for n, _ in UNSAFE_NAMES])
def test_the_name_rule_refuses_what_windows_cannot_hold(tmp_path: Path, unsafe: str, reason: str):
    """One rule (`check_name`): the manifest check, the walk and the builder's
    copy all apply it, so a name is refused at the build and at every check."""
    assert reason in (check_name(unsafe) or ""), (unsafe, check_name(unsafe))
    root = _sealed(tmp_path)

    def plant(manifest: dict) -> None:
        manifest["files"] = sorted(manifest["files"] + [[unsafe, 0, "0" * 64]],
                                   key=lambda entry: entry[0].encode("utf-8", "surrogateescape"))

    _rewrite(root, plant, reseal=True)
    with pytest.raises(PayloadError, match="cannot be a payload path"):
        verify(root)


def test_the_name_rule_admits_ordinary_names():
    for name in ("src/nornyx_forge/cli.py", "pylib/numpy.libs/x.dll", "Forge.cmd",
                 "pylib/console.py", "pylib/auxiliary.py", "python/python313._pth",
                 "src/caf\u00e9.py", "x" * 160, "src/" + "\U0001F600" * 78,
                 "pylib/pycache_tools.py", "pylib/compiler.pyx"):
        assert check_name(name) is None, name


@pytest.mark.parametrize("paths, message", [
    (["src/a.py", "src/A.py"], "'src/A.py' and 'src/a.py' are one name on Windows"),
    (["src/d/x", "src/D/y"], "'src/D' and 'src/d' are one name on Windows"),
    (["src/a", "src/A/b"], "'src/A' and 'src/a' are one name on Windows"),
    (["src/a", "src/a/b"], "'src/a' is both a file and a directory"),
    (["pylib/Foo/a.py", "pylib/foo/b.py"], "'pylib/foo' and 'pylib/Foo' are one name"),
    (["pylib/\u00c9cole/a.py", "pylib/\u00e9cole/b.py"], "are one name"),
    (["src/stra\u00dfe.py", "src/STRASSE.py"], "are one name"),
], ids=["files", "directories", "file-and-directory", "same-spelling", "pylib", "accented",
        "casefold-not-lower"])
def test_paths_and_directories_that_are_one_name_on_windows_are_refused(
        paths: list[str], message: str):
    """Every path AND every directory that holds one, folded for case."""
    found = check_names(paths)
    assert len(found) == 1 and message in found[0], found
    assert check_names(["src/a.py", "src/b.py", "src/d/x", "src/d/y"]) == []


def test_a_non_utf8_name_on_disk_is_refused_by_name(tmp_path: Path):
    root = _sealed(tmp_path)
    (root / "src").joinpath(os.fsdecode(b"bad\xff.py")).write_bytes(b"")
    with pytest.raises(PayloadError, match="not valid UTF-8"):
        verify(root)


def test_a_link_anywhere_including_the_root_and_the_manifest_is_refused(tmp_path: Path):
    root = _sealed(tmp_path)
    outside = _folder(tmp_path / "outside", {"secret.txt": b"s"})
    os.symlink(outside / "secret.txt", root / "src" / "linked.txt")
    with pytest.raises(PayloadError, match="src/linked.txt is a link"):
        verify(root)
    (root / "src" / "linked.txt").unlink()
    os.symlink(outside, root / "pylib" / "linked-dir")
    with pytest.raises(PayloadError, match="pylib/linked-dir is a link"):
        payload_files(root)
    (root / "pylib" / "linked-dir").unlink()
    os.symlink(root, tmp_path / "root-link")
    with pytest.raises(PayloadError, match="root-link is a link"):
        verify(tmp_path / "root-link")
    real = root / PAYLOAD_MANIFEST
    real.rename(tmp_path / "manifest.json")
    os.symlink(tmp_path / "manifest.json", real)
    with pytest.raises(PayloadError, match="not a regular file"):
        verify(root)


def _reparse_status(real: os.stat_result) -> types.SimpleNamespace:
    """A status as Windows reports a junction: a directory mode, and the
    reparse attribute, which `Path.is_symlink()` does not read."""
    return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0x400,
                                 st_size=0, st_dev=real.st_dev, st_ino=real.st_ino,
                                 st_nlink=1)


@pytest.mark.parametrize("target", ["src", "pylib/dep", "."], ids=["child", "deep", "root"])
def test_a_reparse_point_is_refused_through_the_one_link_predicate(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str):
    root = _sealed(tmp_path)
    marked = os.path.normpath(os.path.join(root, target))
    real_lstat = os.lstat

    def lstat(path, *arguments, **options):
        status = real_lstat(path, *arguments, **options)
        return _reparse_status(status) if os.path.normpath(path) == marked else status

    monkeypatch.setattr(windows_payload.os, "lstat", lstat)
    with pytest.raises(PayloadError, match="link or reparse point"):
        verify(root)
    assert windows_payload.is_link(_reparse_status(real_lstat(root)))


def test_a_hard_link_is_refused(tmp_path: Path):
    root = _sealed(tmp_path)
    os.link(root / "Forge.cmd", tmp_path / "elsewhere.cmd")
    with pytest.raises(PayloadError, match="hard link"):
        verify(root)


def test_a_fifo_is_refused(tmp_path: Path):
    root = _sealed(tmp_path)
    os.mkfifo(root / "src" / "pipe")
    with pytest.raises(PayloadError, match="src/pipe is neither a regular file"):
        verify(root)


def test_a_file_swapped_between_the_walk_and_its_read_is_refused(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The walk's view of one file names another inode than the file opened:
    what is hashed must be what the walk saw."""
    root = _sealed(tmp_path)
    real_lstat = os.lstat

    def lstat(path, *arguments, **options):
        status = real_lstat(path, *arguments, **options)
        if os.fspath(path).endswith("Forge.cmd"):
            return types.SimpleNamespace(st_mode=status.st_mode, st_dev=status.st_dev,
                                         st_ino=status.st_ino + 1, st_nlink=1,
                                         st_size=status.st_size)
        return status

    monkeypatch.setattr(windows_payload.os, "lstat", lstat)
    with pytest.raises(PayloadError, match="Forge.cmd changed between the walk and its read"):
        verify(root)


def test_a_deep_or_unreadable_folder_is_refused_not_crashed(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _sealed(tmp_path)
    _folder(root, {"src/a/b/c/d/e/f.py": b""})
    monkeypatch.setattr(windows_payload, "MAX_DEPTH", 3)
    with pytest.raises(PayloadError, match="deeper than 3 levels"):
        verify(root)
    monkeypatch.setattr(windows_payload, "MAX_DEPTH", 32)
    real_scandir = os.scandir

    def scandir(path):
        if os.fspath(path).endswith("pylib"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real_scandir(path)

    monkeypatch.setattr(windows_payload.os, "scandir", scandir)
    with pytest.raises(PayloadError, match="cannot read the folder: .*Permission denied"):
        verify(root)


def test_an_expected_identity_refuses_a_resealed_folder(tmp_path: Path):
    """Without an identity carried from outside, a folder rewritten and
    resealed verifies: that is what tamper-evident without an anchor means.
    With one, it is refused."""
    root = _sealed(tmp_path)
    expected = _manifest(root)["payload_sha256"]
    assert verify(root, expected_payload_sha256=expected)["payload_sha256"] == expected
    (root / "src" / "nornyx_forge" / "x.py").write_bytes(b"print('other')\n")
    (root / PAYLOAD_MANIFEST).unlink()
    _seal(root)
    assert verify(root)["payload_sha256"] != expected
    with pytest.raises(PayloadError, match=f"not the expected {expected}"):
        verify(root, expected_payload_sha256=expected)


def test_the_command_line_verifies_expects_and_refuses(tmp_path: Path,
                                                       capsys: pytest.CaptureFixture):
    root = _sealed(tmp_path)
    expected = _manifest(root)["payload_sha256"]
    assert windows_payload.main(["verify", str(root), "--expect", expected]) == 0
    assert json.loads(capsys.readouterr().out)["payload_sha256"] == expected
    assert windows_payload.main(["verify", str(root), "--expect", "0" * 64]) == 1
    assert "not the expected" in capsys.readouterr().err
    (root / "Forge.cmd").write_bytes(b"x")
    assert windows_payload.main(["verify", str(root)]) == 1
    assert "changed: Forge.cmd" in capsys.readouterr().err


def test_the_verifier_loads_the_standard_library_only():
    """`python -m nornyx_forge.windows_payload` runs the package's
    `__init__` first, so the whole import path is checked, in a child with no
    site directory, and every module it loaded must be the standard library's."""
    code = ("import json, sys; sys.path.insert(0, sys.argv[1]); "
            "import nornyx_forge.windows_payload; "
            "print(json.dumps(sorted(name for name in sys.modules "
            "if name.split('.')[0] not in sys.stdlib_module_names "
            "and name.split('.')[0] not in ('nornyx_forge', '__main__'))))")
    completed = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(ROOT / "src")],
                               capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert json.loads(completed.stdout) == []


def test_an_empty_directory_is_refused(tmp_path: Path):
    """An empty directory is not inert: it makes an import of that name
    succeed as a namespace package."""
    root = _sealed(tmp_path)
    (root / "src" / "optdep").mkdir()
    with pytest.raises(PayloadError, match="src/optdep is an empty directory"):
        verify(root)
    (root / "src" / "optdep" / "inner").mkdir()
    with pytest.raises(PayloadError, match="src/optdep/inner is an empty directory"):
        verify(root)


def test_a_hard_linked_manifest_is_refused(tmp_path: Path):
    root = _sealed(tmp_path)
    os.link(root / PAYLOAD_MANIFEST, tmp_path / "twin.json")
    with pytest.raises(PayloadError, match="the manifest is its own file"):
        verify(root)


def test_a_fifo_swapped_in_after_the_walk_is_refused_without_blocking(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The walk saw a regular file; the open finds a FIFO. A blocking open
    would wait for a writer forever; the open does not block, and the check
    after it refuses."""
    root = _sealed(tmp_path)
    target = root / "src" / "nornyx_forge" / "x.py"
    regular = os.lstat(target)
    target.unlink()
    os.mkfifo(target)
    real_lstat = os.lstat

    def lstat(path, *arguments, **options):
        return regular if os.fspath(path) == os.fspath(target) else real_lstat(path)

    monkeypatch.setattr(windows_payload.os, "lstat", lstat)
    outcome: list = []

    def run() -> None:
        try:
            verify(root)
        except PayloadError as error:
            outcome.append(str(error))

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(10)
    if worker.is_alive():
        os.close(os.open(target, os.O_WRONLY | os.O_NONBLOCK))
        worker.join(10)
        raise AssertionError("verify blocked opening a FIFO")
    assert outcome and "changed between the walk and its read" in outcome[0], outcome


def test_the_manifest_is_opened_as_the_file_the_walk_saw_and_read_within_its_cap(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _sealed(tmp_path)
    manifest = os.fspath(root / PAYLOAD_MANIFEST)
    real_lstat = os.lstat

    def swapped(path, *arguments, **options):
        status = real_lstat(path)
        if os.fspath(path) != manifest:
            return status
        return types.SimpleNamespace(st_mode=status.st_mode, st_dev=status.st_dev,
                                     st_ino=status.st_ino + 1, st_nlink=1, st_size=10)

    monkeypatch.setattr(windows_payload.os, "lstat", swapped)
    with pytest.raises(PayloadError, match="changed while it was opened"):
        verify(root)

    def understated(path, *arguments, **options):
        status = real_lstat(path)
        if os.fspath(path) != manifest:
            return status
        return types.SimpleNamespace(st_mode=status.st_mode, st_dev=status.st_dev,
                                     st_ino=status.st_ino, st_nlink=1, st_size=10)

    monkeypatch.setattr(windows_payload.os, "lstat", understated)
    monkeypatch.setattr(windows_payload, "MAX_MANIFEST_BYTES", 100)
    with pytest.raises(PayloadError, match="larger than 100 bytes"):
        verify(root)


def test_the_depth_bound_is_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(windows_payload, "MAX_DEPTH", 3)
    root = _seal(_folder(tmp_path / "at-bound", {"src/a/b/f.py": b""}))
    assert verify(root)["files_compared"] == 1
    with pytest.raises(PayloadError, match="deeper than 3 levels"):
        payload_files(_folder(tmp_path / "past-bound", {"src/a/b/c/f.py": b""}))


@pytest.mark.parametrize("content", [b"{not json", b"\xff\xfe\x00", b"[" * 100000],
                         ids=["not-json", "not-utf8", "deeply-nested"])
def test_a_manifest_that_cannot_be_read_is_refused_on_the_command_line(
        tmp_path: Path, content: bytes):
    """Through the real entry point, as a child: exit 1, a refusal, and no
    traceback."""
    root = _sealed(tmp_path)
    (root / PAYLOAD_MANIFEST).write_bytes(content)
    completed = subprocess.run(
        [sys.executable, "-m", "nornyx_forge.windows_payload", "verify", str(root)],
        capture_output=True, timeout=60, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    error = completed.stderr.decode("utf-8", "replace")
    assert completed.returncode == 1 and "payload refused" in error, error
    assert "Traceback" not in error, error


@pytest.mark.parametrize("expected", ["prefix", "upper", "empty"])
def test_an_expected_identity_must_match_exactly(tmp_path: Path, expected: str):
    root = _sealed(tmp_path)
    identity = _manifest(root)["payload_sha256"]
    given = {"prefix": identity[:63], "upper": identity.upper(), "empty": ""}[expected]
    with pytest.raises(PayloadError, match="not the expected"):
        verify(root, expected_payload_sha256=given)


# ---------------------------------------------------------------------------
# The builder: a payload is a function of a commit
# ---------------------------------------------------------------------------

def _git(repo: Path, *arguments: str, committed: str = "2026-01-02T03:04:05Z") -> str:
    environment = {**os.environ, "GIT_AUTHOR_DATE": "2025-06-07T08:09:10Z",
                   "GIT_COMMITTER_DATE": committed}
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *arguments],
        cwd=str(repo), capture_output=True, check=True, env=environment, timeout=60,
    ).stdout.decode("utf-8")


#: The fixture commit's committer time; its author time is a year earlier,
#: so a build that took the author's time would carry another epoch.
COMMITTED = 1767323045


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository carrying the copy set, the builder's own files, a lock,
    one ignored file of local state, and one commit whose author and
    committer times differ."""
    root = _folder(tmp_path / "repo", {
        "pyproject.toml": b'[project]\nname = "x"\nversion = "1.2.3"\n',
        "README.md": b"readme\r\n", "BRD.md": b"brd\n", "src/nornyx_forge/__init__.py": b"",
        "src/nornyx_forge/windows_payload.py": b"# stand-in\n",
        "scripts/build_windows_bundle.py": b"# stand-in\n",
        ".nornyx/contracts/a.nyx": b"contract\n", ".gitignore": b".nornyx/runtime/\n",
        "scripts/windows_installer/lock.txt": b"x==1 \\\n    --hash=sha256:" + b"0" * 64 + b"\n",
        "notes.txt": b"not in the copy set\n"})
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "fixture")
    _folder(root, {".nornyx/runtime/disposition.json": b'{"local": true}\n'})
    return root


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A", "-f")
    _git(repo, "commit", "-q", "-m", message)


def test_the_copy_is_the_commit_and_an_ignored_file_never_rides_along(repo: Path, tmp_path: Path):
    (repo / "BRD.md").write_bytes(b"an uncommitted edit\n")
    builder.copy_tree(repo, tmp_path / "dist")
    copied = sorted(path.relative_to(tmp_path / "dist").as_posix()
                    for path in (tmp_path / "dist").rglob("*") if path.is_file())
    assert copied == [".nornyx/contracts/a.nyx", "BRD.md", "README.md", "pyproject.toml",
                      "src/nornyx_forge/__init__.py", "src/nornyx_forge/windows_payload.py"]
    assert (tmp_path / "dist" / "README.md").read_bytes() == b"readme\r\n", "blob bytes, verbatim"
    assert (tmp_path / "dist" / "BRD.md").read_bytes() == b"brd\n", "the blob, not the edit"


def test_a_tracked_excluded_name_is_left_out(repo: Path, tmp_path: Path):
    _folder(repo, {"src/nornyx_forge/__pycache__/x.cpython-313.pyc": b"\0",
                   "src/.venv/pyvenv.cfg": b"home = /x\n",
                   "src/node_modules/x.js": b"x\n"})
    _commit(repo, "tracked developer state")
    builder.copy_tree(repo, tmp_path / "dist")
    for name in ("__pycache__", ".venv", "node_modules"):
        assert not list((tmp_path / "dist").rglob(name)), name


def test_a_link_in_the_copy_set_is_refused_not_followed(repo: Path, tmp_path: Path):
    os.symlink("/etc/hostname", repo / "src" / "link")
    _commit(repo, "link")
    with pytest.raises(BundleError, match="'src/link' is a 120000 blob entry"):
        builder.copy_tree(repo, tmp_path / "dist")


@pytest.mark.parametrize("names, message", [
    (["src/con.py"], "device"), (["src/a|b.py"], "<>"), (["src/x."], "dot or a space"),
    (["src/A.py", "src/a.py"], "one name on Windows"),
    (["src/d/x", "src/D/y"], "one name on Windows"),
    (["src/a", "src/A/b"], "one name on Windows"),
    (["src/Foo/a.py", "src/foo/b.py"], "one name on Windows")],
    ids=["device", "character", "trailing-dot", "case-collision", "directory-case",
         "file-and-directory", "folded-directories"])
def test_a_committed_name_windows_cannot_hold_is_refused_at_the_copy(
        repo: Path, tmp_path: Path, names: list[str], message: str):
    _folder(repo, {name: b"" for name in names})
    _commit(repo, "hostile names")
    with pytest.raises(BundleError, match=message):
        builder.copy_tree(repo, tmp_path / "dist")
    assert not (tmp_path / "dist").exists(), "nothing is written before the names are checked"


def test_an_uncommitted_or_commitless_tree_is_refused(repo: Path, tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch):
    commit = builder.require_clean_commit(repo)
    assert re.fullmatch(r"[0-9a-f]{40}", commit)
    assert builder.source_date_epoch(repo, commit) == COMMITTED, "the committer's time"
    (repo / "README.md").write_bytes(b"edited\n")
    with pytest.raises(BundleError, match="working tree differs"):
        builder.require_clean_commit(repo)
    _git(repo, "checkout", "--", "README.md")
    _folder(repo, {"src/untracked.py": b""})
    with pytest.raises(BundleError, match="working tree differs"):
        builder.require_clean_commit(repo)
    # Git must not find a repository enclosing the temporary directory.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    with pytest.raises(BundleError, match="names no commit"):
        builder.require_clean_commit(_folder(tmp_path / "bare", {"a": b""}))


#: Written out, not read from the builder: the set the check covers is what
#: this test pins.
BUILDER_FILES = ("scripts/build_windows_bundle.py", "src/nornyx_forge/__init__.py",
                 "src/nornyx_forge/windows_payload.py")


def test_the_builder_checks_exactly_its_own_files():
    assert builder.BUILDER_FILES == BUILDER_FILES


@pytest.mark.parametrize("flag", ["--skip-worktree", "--assume-unchanged"])
@pytest.mark.parametrize("name", BUILDER_FILES)
def test_a_builder_file_hidden_by_an_index_flag_is_refused(repo: Path, flag: str, name: str):
    _git(repo, "update-index", flag, "--", name)
    (repo / name).write_bytes(b"# edited, and git status does not say so\n")
    assert _git(repo, "status", "--porcelain") == ""
    with pytest.raises(BundleError, match=f"{re.escape(name)} is not the file"):
        builder.require_clean_commit(repo)


def test_a_builder_file_hidden_by_a_clean_filter_is_refused(repo: Path, tmp_path: Path):
    """A clean filter that answers with the committed bytes hides a same-size
    edit from `git status` and from `git hash-object`; the raw bytes do not."""
    name = "src/nornyx_forge/windows_payload.py"
    saved = tmp_path / "committed.py"
    saved.write_bytes((repo / name).read_bytes())
    _git(repo, "config", "filter.hide.clean", f"cat {saved}")
    (repo / ".git" / "info" / "attributes").write_text(f"{name} filter=hide\n",
                                                        encoding="utf-8")
    (repo / name).write_bytes(b"# stand-ix\n")
    assert _git(repo, "status", "--porcelain") == ""
    with pytest.raises(BundleError, match=f"{re.escape(name)} is not the file"):
        builder.require_clean_commit(repo)


def test_a_checkout_that_converts_line_endings_still_builds(repo: Path):
    """A Windows checkout with `core.autocrlf` holds the builder's files with
    CRLF; the comparison with the commit normalizes line endings and nothing
    else."""
    commit = builder.require_clean_commit(repo)
    _git(repo, "config", "core.autocrlf", "true")
    name = "scripts/build_windows_bundle.py"
    (repo / name).unlink()
    _git(repo, "-c", "core.autocrlf=true", "checkout", "--", name)
    assert (repo / name).read_bytes().endswith(b"\r\n"), "git wrote CRLF"
    assert builder.require_clean_commit(repo) == commit
    _git(repo, "update-index", "--skip-worktree", "--", name)
    (repo / name).write_bytes(b"# stand-ix\r\n")
    with pytest.raises(BundleError, match="is not the file"):
        builder.require_clean_commit(repo)


def test_replace_refs_and_git_variables_do_not_reach_the_build(
        repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    commit = builder.require_clean_commit(repo)
    lock_blob = _git(repo, "rev-parse", "HEAD:scripts/windows_installer/lock.txt").strip()
    evil = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=str(repo),
                          input=b"evilpkg==6.6.6\n", capture_output=True, check=True,
                          timeout=60).stdout.decode("ascii").strip()
    _git(repo, "replace", lock_blob, evil)
    assert builder.load_lock(repo, commit, {"lock": "lock.txt"}).startswith(b"x==1")
    other = _folder(tmp_path / "other", {"a": b""})
    _git(other, "init", "-q")
    _git(other, "add", "-A")
    _git(other, "commit", "-q", "-m", "other")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert builder.require_clean_commit(repo) == commit


def test_a_build_that_loaded_another_verifier_is_refused(repo: Path,
                                                        monkeypatch: pytest.MonkeyPatch):
    builder.require_clean_commit(repo)
    monkeypatch.setattr(builder, "_payload_module",
                        types.SimpleNamespace(__file__=str(repo / "elsewhere.py")))
    with pytest.raises(BundleError, match="verifier was loaded from"):
        builder.require_clean_commit(repo)


def test_a_commit_missing_part_of_the_copy_set_is_refused(repo: Path, tmp_path: Path):
    _git(repo, "rm", "-q", "BRD.md")
    _git(repo, "commit", "-q", "-m", "no BRD")
    with pytest.raises(BundleError, match=r"carries none of \['BRD.md'\]"):
        builder.copy_tree(repo, tmp_path / "dist")


def test_the_pins_and_the_lock_are_read_from_the_commit(repo: Path):
    pins_text = json.dumps(_pins("c" * 64)).encode("utf-8")
    _folder(repo, {builder.PINS_PATH: pins_text})
    _commit(repo, "pins")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    for name in (builder.PINS_PATH, "scripts/windows_installer/lock.txt"):
        _git(repo, "update-index", "--skip-worktree", "--", name)
    (repo / builder.PINS_PATH).write_bytes(json.dumps(
        {**_pins("d" * 64), "lock": "evil.txt"}).encode("utf-8"))
    (repo / "scripts" / "windows_installer" / "lock.txt").write_bytes(b"evilpkg==6.6.6\n")
    pins = builder.load_pins(repo, commit)
    assert pins["interpreter"]["archive_sha256"] == "c" * 64 and pins["lock"] == "lock.txt"
    assert builder.load_lock(repo, commit, pins).startswith(b"x==1 \\\n")


def _quiet_build(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("copy_tree", "install_dependencies", "write_bundle_marker",
                 "write_launcher", "verify_bundle"):
        monkeypatch.setattr(builder, name, lambda *a, **k: None)


def test_main_refuses_a_build_that_names_no_commit(monkeypatch: pytest.MonkeyPatch,
                                                   tmp_path: Path):
    """Red against the optional provenance this replaced: a build whose git
    named no commit used to record `null` and succeed."""
    _quiet_build(monkeypatch)
    monkeypatch.setattr(builder, "_source_commit", lambda root: None)
    with pytest.raises(BundleError, match="names no commit"):
        builder.main(["--dist", str(tmp_path / "dist")])


class _Clock:
    def __init__(self, moment: float) -> None:
        self.moment = moment

    def now(self, tz=None):
        import datetime as real  # noqa: PLC0415
        return real.datetime.fromtimestamp(self.moment, tz)


def test_the_marker_carries_no_wall_clock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Red against `built_at`: the same marker written at two wall clocks
    must be the same bytes."""
    written = []
    for moment in (1_000_000_000, 2_000_000_000):
        monkeypatch.setattr(builder, "datetime", _Clock(moment), raising=False)
        builder.write_bundle_marker(tmp_path, mode=builder.SELF_CONTAINED,
                                    interpreter_sha256="ab" * 32, source_commit=COMMIT)
        written.append((tmp_path / builder.BUNDLE_MARKER).read_bytes())
    assert written[0] == written[1]
    assert json.loads(written[0])["source_commit"] == COMMIT


def _embed_zip(path: Path) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("python313._pth", "python313.zip\nimport site\n")
        for name in ("python.exe", "pythonw.exe", "python313.zip"):
            archive.writestr(name, "not a real interpreter: " + name)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pins(sha: str) -> dict:
    return {"schema": builder.PINS_SCHEMA, "lock": "lock.txt",
            "installer": {"name": "uv", "version": "0.0.0"},
            "target": {"python_version": "3.13", "python_platform": "x86_64-pc-windows-msvc",
                       "wheel_platform": "win_amd64", "abi": "cp313"},
            "interpreter": {"version": "3.13.0", "archive_url": "https://example.invalid/e.zip",
                            "archive_sha256": sha}}


def _fake_library(dist: Path, pins: dict, lock: bytes, extra: dict | None = None) -> None:
    """A one-distribution library; an `extra` key ending in `/` is an empty
    directory."""
    extra = extra or {}
    _folder(dist / "pylib", {"dep/__init__.py": b"VALUE = 1\n",
                             "dep-1.0.dist-info/WHEEL": b"Tag: py3-none-any\n",
                             "dep-1.0.dist-info/RECORD": b"dep/__init__.py,,\n",
                             **{key: value for key, value in extra.items()
                                if not key.endswith("/")}})
    for key in extra:
        if key.endswith("/"):
            (dist / "pylib" / key).mkdir(parents=True)


def _host_install(dist: Path, python_exe: str) -> None:
    raise AssertionError("the self-contained payload was installed for the builder's "
                         "interpreter, not from the lock for the target")


def _unreached(*_arguments, **_options) -> None:
    raise AssertionError("the build went on past an archive that is not the pinned one")


def _listing(root: Path) -> list[tuple[str, int, bytes]]:
    return sorted((path.relative_to(root).as_posix(), path.stat().st_mtime_ns // 10**9,
                   path.read_bytes() if path.is_file() else b"<dir>")
                  for path in [root, *root.rglob("*")])


def _payload_build(monkeypatch: pytest.MonkeyPatch, repo: Path, tmp_path: Path,
                   library=_fake_library) -> str:
    sha = _embed_zip(tmp_path / "embed.zip")
    monkeypatch.setattr(builder, "ROOT", repo)
    # `raising=False`: the same test runs, red, against a builder without pins.
    monkeypatch.setattr(builder, "load_pins", lambda *a: _pins(sha), raising=False)
    monkeypatch.setattr(builder, "install_locked_dependencies", library, raising=False)
    monkeypatch.setattr(builder, "install_dependencies", _host_install)
    monkeypatch.setattr(builder, "verify_bundle", lambda dist: None)
    return sha


def test_two_builds_at_different_wall_clocks_are_the_same_bytes(
        monkeypatch: pytest.MonkeyPatch, repo: Path, tmp_path: Path):
    """The network install replaced, and nothing else: the commit, the lock
    and the archive fixed, and the wall clock moved between the builds. The
    manifest, every file and every time are equal, every time is the
    committer's, and the manifest binds what the pins name."""
    sha = _payload_build(monkeypatch, repo, tmp_path)
    builds = []
    for name in ("first", "second"):
        builder.main(["--dist", str(tmp_path / name), "--python-embed",
                      str(tmp_path / "embed.zip"), "--python-embed-sha256", sha])
        builds.append(tmp_path / name)
        time.sleep(1.1)
    first, second = (_listing(build) for build in builds)
    assert first == second
    assert {moment for _path, moment, _data in first} == {COMMITTED}
    sealed = _manifest(builds[0])
    assert verify(builds[0], expected_payload_sha256=sealed["payload_sha256"])
    assert sealed["version"] == "1.2.3" and sealed["source_date_epoch"] == COMMITTED
    assert sealed["lock_sha256"] == hashlib.sha256(
        (repo / "scripts" / "windows_installer" / "lock.txt").read_bytes()).hexdigest()
    assert sealed["source_commit"] == _git(repo, "rev-parse", "HEAD").strip()
    assert sealed["target"] == "cp313-win_amd64"
    assert sealed["installer"] == {"name": "uv", "version": "0.0.0"}
    assert sealed["interpreter"] == {"version": "3.13.0", "archive_sha256": sha,
                                     "archive_url": "https://example.invalid/e.zip"}
    assert "built_at" not in (builds[0] / builder.BUNDLE_MARKER).read_text(encoding="utf-8")


def _plant_bytecode(dist: Path) -> None:
    _folder(dist, {"src/nornyx_forge/__pycache__/x.pyc": b"\0"})


def _change_and_reseal(dist: Path) -> None:
    """A self-consistent folder with another identity: only the identity
    carried from the seal can tell."""
    (dist / "BRD.md").write_bytes(b"changed after the seal\n")
    manifest = json.loads((dist / PAYLOAD_MANIFEST).read_text(encoding="utf-8"))
    (dist / PAYLOAD_MANIFEST).unlink()
    fields = {key: manifest[key] for key in FIELDS}
    (dist / PAYLOAD_MANIFEST).write_bytes(render_manifest(build_manifest(dist, **fields)))


@pytest.mark.parametrize("change", [_plant_bytecode, _change_and_reseal],
                         ids=["bytecode", "resealed"])
def test_a_sealed_folder_the_import_check_changed_is_refused(
        monkeypatch: pytest.MonkeyPatch, repo: Path, tmp_path: Path, change):
    sha = _payload_build(monkeypatch, repo, tmp_path)
    monkeypatch.setattr(builder, "verify_bundle", change)
    with pytest.raises(BundleError, match="the import check changed the sealed folder"):
        builder.main(["--dist", str(tmp_path / "dist"), "--python-embed",
                      str(tmp_path / "embed.zip"), "--python-embed-sha256", sha])


def test_the_build_refuses_an_archive_for_another_cpython(
        monkeypatch: pytest.MonkeyPatch, repo: Path, tmp_path: Path):
    archive = tmp_path / "embed.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("python314._pth", "python314.zip\n")
        for name in ("python.exe", "pythonw.exe"):
            handle.writestr(name, "x")
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (tmp_path / "unused").mkdir()
    _payload_build(monkeypatch, repo, tmp_path / "unused")
    monkeypatch.setattr(builder, "load_pins", lambda *a: _pins(sha))
    with pytest.raises(BundleError, match="holds python314._pth"):
        builder.main(["--dist", str(tmp_path / "dist"), "--python-embed", str(archive),
                      "--python-embed-sha256", sha])


def test_the_archive_extracted_is_the_bytes_that_were_hashed(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """The digest is checked over bytes read once; a file replaced on disk
    after that read is not what is extracted."""
    checked = tmp_path / "checked.zip"
    sha = _embed_zip(checked)
    hashed = checked.read_bytes()
    with zipfile.ZipFile(checked, "w") as archive:
        archive.writestr("python313._pth", "python313.zip\n")
        for name in ("python.exe", "pythonw.exe"):
            archive.writestr(name, "REPLACED after the digest was checked")
    real_read_bytes = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes",
                        lambda self: hashed if self == checked else real_read_bytes(self))
    builder.install_python(tmp_path / "dist", checked, sha)
    assert (tmp_path / "dist" / "python" / "python.exe").read_bytes().startswith(b"not a real")


def test_an_archive_for_another_cpython_is_refused_by_its_path_file(tmp_path: Path):
    archive = tmp_path / "other.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("python314._pth", "python314.zip\n")
        for name in ("python.exe", "pythonw.exe"):
            handle.writestr(name, "x")
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(BundleError, match="holds python314._pth, not the python313._pth"):
        builder.install_python(tmp_path / "dist", archive, sha, "cp313")
    builder.install_python(tmp_path / "unchecked", archive, sha)


@pytest.mark.parametrize("extra, message", [
    ({"dep/__pycache__/__init__.cpython-313.pyc": b"\0"}, "bytecode"),
    ({"dep/aux.py": b""}, "device"),
    ({"dep/Mod.py": b"", "dep/mod.py": b""}, "one path on Windows"),
    ({"Dep/x.py": b""}, "one path on Windows"),
    ({"dep/empty/": b""}, "empty directory"),
], ids=["bytecode", "device-name", "case-collision", "directory-case", "empty-directory"])
def test_the_build_refuses_to_seal_a_folder_the_payload_rules_refuse(
        monkeypatch: pytest.MonkeyPatch, repo: Path, tmp_path: Path, extra: dict, message: str):
    def library(dist: Path, pins: dict, lock: bytes) -> None:
        _fake_library(dist, pins, lock, extra)

    sha = _payload_build(monkeypatch, repo, tmp_path, library)
    with pytest.raises(BundleError, match=f"cannot be sealed.*{message}"):
        builder.main(["--dist", str(tmp_path / "dist"), "--python-embed",
                      str(tmp_path / "embed.zip"), "--python-embed-sha256", sha])


# ---------------------------------------------------------------------------
# The pins: refused when they are not what was pinned
# ---------------------------------------------------------------------------

def test_an_interpreter_archive_other_than_the_pinned_one_is_refused(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _quiet_build(monkeypatch)
    monkeypatch.setattr(builder, "require_clean_commit", lambda root: COMMIT, raising=False)
    monkeypatch.setattr(builder, "load_pins", lambda *a: _pins("c" * 64), raising=False)
    monkeypatch.setattr(builder, "install_python", _unreached)
    with pytest.raises(BundleError, match="not the pinned interpreter archive"):
        builder.main(["--dist", str(tmp_path / "dist"), "--python-embed",
                      str(tmp_path / "e.zip"), "--python-embed-sha256", "d" * 64])
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("change, message", [
    (lambda p: p["interpreter"].update(version="3.14.0"), "must agree"),
    (lambda p: p["target"].update(abi="cp312"), "must agree"),
    (lambda p: p["interpreter"].update(archive_url="http://example.invalid/e.zip"), "https"),
    (lambda p: p.update(lock="../lock.txt"), "not a file beside it"),
    (lambda p: p["installer"].update(name="pip"), "drives uv"),
    (lambda p: p.pop("target"), "not a complete pin set"),
    (lambda p: p["installer"].update(version=""), "empty or non-string"),
], ids=["interpreter-3.14", "abi", "http", "lock-path", "installer", "missing", "empty"])
def test_pins_that_do_not_agree_with_themselves_are_refused(change, message: str):
    pins = _pins("c" * 64)
    assert builder.check_pins(json.loads(json.dumps(pins))) == pins
    change(pins)
    with pytest.raises(BundleError, match=message):
        builder.check_pins(pins)


def test_an_installer_reporting_another_version_is_refused(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """This checks the version uv REPORTS: the binary's hash pin holds only
    where uv is installed from `build-tools.txt`."""
    pins = _pins("c" * 64)
    monkeypatch.setattr(builder.shutil, "which", lambda name: None)
    with pytest.raises(BundleError, match="uv is not on PATH"):
        builder.install_locked_dependencies(tmp_path, pins, b"")
    monkeypatch.setattr(builder.shutil, "which", lambda name: "/opt/uv")
    monkeypatch.setattr(builder, "_uv_version", lambda uv: "0.0.1")
    with pytest.raises(BundleError, match=r"uv reports version 0\.0\.1, not the pinned 0\.0\.0"):
        builder.install_locked_dependencies(tmp_path, pins, b"")


def _captured_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, library: dict) -> list:
    calls = []
    monkeypatch.setattr(builder.shutil, "which", lambda name: "/opt/uv")
    monkeypatch.setattr(builder, "_uv_version", lambda uv: "0.0.0")

    def install(command, **options):
        lock = Path(command[command.index("-r") + 1])
        calls.append((command, options, lock.read_bytes()))
        _folder(tmp_path / "pylib", library)

    monkeypatch.setattr(builder.subprocess, "run", install)
    return calls


def test_uv_is_told_the_target_isolated_and_its_host_outputs_are_pruned(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("UV_COMPILE_BYTECODE", "1")
    monkeypatch.setenv("UV_INDEX_URL", "https://example.invalid/simple")
    monkeypatch.setenv("uv_link_mode", "symlink")
    calls = _captured_install(monkeypatch, tmp_path, {
        "dep/__init__.py": b"VALUE = 1\n", "dep-1.0.dist-info/WHEEL": b"Tag: py3-none-any\n",
        "dep-1.0.dist-info/RECORD": (b"dep/__init__.py,sha256=x,10\n"
                                     b"bin/dep,sha256=y,30\n"
                                     b"dep-1.0.dist-info/RECORD,,\n"),
        "bin/dep": b"#!/host/python\n", ".lock": b""})
    builder.install_locked_dependencies(tmp_path, _pins("c" * 64), b"x==1\n")
    command, options, lock = calls[0]
    joined = " ".join(command)
    for flag in ("--python-platform x86_64-pc-windows-msvc", "--python-version 3.13",
                 "--only-binary :all:", "--require-hashes", "--no-config", "--no-cache",
                 "--link-mode copy", "--no-python-downloads"):
        assert flag in joined, flag
    assert "--no-deps" not in joined, "the closure must be checked against the lock"
    assert lock == b"x==1\n", "uv reads the committed lock's bytes"
    assert not [key for key in options["env"] if key.upper().startswith("UV_")]
    assert sorted(path.name for path in (tmp_path / "pylib").iterdir()) == [
        "dep", "dep-1.0.dist-info"]
    assert (tmp_path / "pylib" / "dep-1.0.dist-info" / "RECORD").read_bytes() == (
        b"dep/__init__.py,sha256=x,10\ndep-1.0.dist-info/RECORD,,\n")


@pytest.mark.parametrize("record, message", [
    (b"dep/__init__.py,,\n\nbin/dep,,\n", "holds a blank row"),
    (b"dep/__init__.py,,\n\xff,,\n", "is not UTF-8")], ids=["blank", "not-utf8"])
def test_a_record_the_pruner_cannot_read_is_refused_by_name(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record: bytes, message: str):
    _captured_install(monkeypatch, tmp_path, {
        "dep/__init__.py": b"", "dep-1.0.dist-info/WHEEL": b"Tag: py3-none-any\n",
        "dep-1.0.dist-info/RECORD": record, "bin/dep": b""})
    with pytest.raises(BundleError, match=f"dep-1.0.dist-info/RECORD {message}"):
        builder.install_locked_dependencies(tmp_path, _pins("c" * 64), b"")


def test_the_install_refuses_a_library_the_census_refuses(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _captured_install(monkeypatch, tmp_path, {
        "old/_x.pyd": b"", "old-1.0.dist-info/WHEEL": b"Tag: cp312-cp312-win_amd64\n",
        "old-1.0.dist-info/RECORD": b"old/_x.pyd,,\n"})
    with pytest.raises(BundleError, match="not built for cp313 win_amd64: old-1.0.dist-info"):
        builder.install_locked_dependencies(tmp_path, _pins("c" * 64), b"")


def test_the_pins_name_the_target_the_lock_resolves_for():
    """Static consistency of the committed pins: the lock's header names the
    pins' target, the build tools pin uv at the pins' version, and the archive
    is the one the recorded run measured. That the lock RESOLVES for the
    target is not shown here: the CI build, which installs it for the target,
    is that measurement."""
    directory = ROOT / "scripts" / "windows_installer"
    pins = builder.check_pins(json.loads((directory / "pins.json").read_text(encoding="utf-8")))
    lock = (directory / pins["lock"]).read_text(encoding="utf-8")
    command = next(line for line in lock.splitlines() if "uv pip compile" in line)
    target = pins["target"]
    for flag in (f"--python-platform {target['python_platform']}",
                 f"--python-version {target['python_version']}", "--only-binary :all:",
                 "--generate-hashes", "--extra demo", f"-o scripts/windows_installer/{pins['lock']}"):
        assert flag in command, flag
    tools = (directory / pins["installer"]["requirements"]).read_text(encoding="utf-8")
    assert f"\nuv=={pins['installer']['version']} \\\n    --hash=sha256:" in tools
    record = (ROOT / "docs" / "governance" / "EMBEDDED_INTERPRETER_RUN.md").read_text(
        encoding="utf-8")
    assert f"`{pins['interpreter']['archive_sha256']}`" in record, (
        "the pinned archive is the one the recorded run measured")
    assert pins["interpreter"]["archive_url"].endswith(
        f"/{pins['interpreter']['version']}/python-{pins['interpreter']['version']}-embed-amd64.zip")


def _locked(text: str) -> dict[str, tuple[str, int]]:
    """{name: (version, hashes)} from a uv-compiled lock, refusing any line
    outside its strict shape: comments, `name==version \\`, and hash lines."""
    locked: dict[str, tuple[str, int]] = {}
    current = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            current = None
            continue
        requirement = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+) \\", line)
        hashed = re.fullmatch(r"    --hash=sha256:[0-9a-f]{64}( \\)?", line)
        if requirement and current is None:
            current = canonicalize_name(requirement.group(1))
            assert current not in locked, f"{current} is locked twice"
            locked[current] = (requirement.group(2), 0)
        elif hashed and current is not None:
            locked[current] = (locked[current][0], locked[current][1] + 1)
            if not hashed.group(1):
                current = None
        else:
            raise AssertionError(f"a lock line outside its shape: {line!r}")
    return locked


def test_the_lock_is_hashed_and_covers_what_the_project_declares():
    directory = ROOT / "scripts" / "windows_installer"
    pins = builder.check_pins(json.loads((directory / "pins.json").read_text(encoding="utf-8")))
    locked = _locked((directory / pins["lock"]).read_text(encoding="utf-8"))
    assert locked and all(hashes > 0 for _version, hashes in locked.values())
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    for line in project["dependencies"] + project["optional-dependencies"]["demo"]:
        requirement = Requirement(line)
        name = canonicalize_name(requirement.name)
        assert name in locked, f"{name} is declared and not locked"
        assert requirement.specifier.contains(locked[name][0], prereleases=True), (
            f"{name}=={locked[name][0]} does not satisfy {requirement.specifier}")


# ---------------------------------------------------------------------------
# The wheel-tag census
# ---------------------------------------------------------------------------

def _distribution(pylib: Path, name: str, tags: list[str], files: list[str]) -> None:
    info = f"{name}-1.0.dist-info"
    _folder(pylib, {**{path: b"" for path in files},
                    f"{info}/WHEEL": "".join(f"Tag: {tag}\n" for tag in tags).encode(),
                    f"{info}/RECORD": "".join(f"{path},,\n" for path in files).encode()})


def _census(pylib: Path) -> list[str]:
    return builder.wheel_tag_census(pylib, abi="cp313", platform="win_amd64")


def test_the_census_accepts_the_target_abi_the_stable_abi_and_pure_wheels(tmp_path: Path):
    _distribution(tmp_path, "native", ["cp313-cp313-win_amd64"], ["native/_x.cp313-win_amd64.pyd"])
    _distribution(tmp_path, "stable", ["cp39-abi3-win_amd64"], ["stable/_y.pyd"])
    _distribution(tmp_path, "pure", ["py2-none-any", "py3-none-any"], ["pure/__init__.py"])
    _distribution(tmp_path, "tool", ["py3-none-win_amd64"], ["tool/tool.exe"])
    assert _census(tmp_path) == []


@pytest.mark.parametrize("tags, files, problem", [
    (["cp312-cp312-win_amd64"], ["old/_x.pyd"], "do not fit cp313 win_amd64"),
    (["cp313-cp313-manylinux_2_28_x86_64"], ["linux/_x.so"], "another platform"),
    (["cp314-abi3-win_amd64"], ["newer/_x.pyd"], "do not fit"),
    (["py3-none-win_amd64"], ["noabi/_x.pyd"], "not built for cp313"),
    (["py3-none-any"], ["pure/_x.pyd"], "not built for cp313"),
    ([], ["untagged/__init__.py"], "do not fit"),
], ids=["older-abi", "linux", "newer-stable-abi", "pyd-without-abi", "pyd-in-pure-wheel",
        "no-tag"])
def test_the_census_names_a_native_file_not_built_for_the_target(
        tmp_path: Path, tags: list[str], files: list[str], problem: str):
    _distribution(tmp_path, "dist", tags, files)
    found = _census(tmp_path)
    assert found and any(problem in line for line in found), found


def test_the_census_names_a_native_module_no_distribution_installed(tmp_path: Path):
    _distribution(tmp_path, "pure", ["py3-none-any"], ["pure/__init__.py"])
    _folder(tmp_path, {"stray/_z.cp313-win_amd64.pyd": b"", "stray/libq.so.1": b""})
    assert _census(tmp_path) == [
        "stray/_z.cp313-win_amd64.pyd: listed in no installed distribution's RECORD",
        "stray/libq.so.1: a native library for another platform"]


def test_the_census_names_a_record_row_for_a_file_the_library_does_not_hold(tmp_path: Path):
    _distribution(tmp_path, "dep", ["py3-none-any"], ["dep/__init__.py"])
    record = tmp_path / "dep-1.0.dist-info" / "RECORD"
    record.write_bytes(record.read_bytes() + b"bin/dep,sha256=y,30\n../../outside,,\n")
    _folder(tmp_path.parent, {"outside.txt": b"x"})
    record.write_bytes(record.read_bytes() + b"../outside.txt,,\n"
                       + str(tmp_path.parent / "outside.txt").encode() + b",,\n")
    found = _census(tmp_path)
    assert "dep-1.0.dist-info/RECORD lists ../outside.txt, which the library does not hold" in found
    assert any(str(tmp_path.parent / "outside.txt") in line for line in found), found
    assert "dep-1.0.dist-info/RECORD lists bin/dep, which the library does not hold" in found
    assert "dep-1.0.dist-info/RECORD lists ../../outside, which the library does not hold" in found


# ---------------------------------------------------------------------------
# The rebuild job: its structure, not its outcome
# ---------------------------------------------------------------------------

def _job() -> dict:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"))
    return workflow["jobs"]["windows-payload"]


def test_the_rebuild_job_can_fail_and_nothing_in_it_is_optional():
    """A neutered job would still contain every command, so what is pinned is
    structure: no `continue-on-error` and no `if` on the job or a step, the
    escape spellings listed below in no step, both checkouts without
    credentials, and every action pinned by commit. It refuses those
    enumerated forms; it does not refuse every way a step could swallow a
    failure (a pipe into `tee`, an `&&` list, another shell). The job's own
    commands catching a difference is the CI run's measurement."""
    job = _job()
    assert job["runs-on"] == "ubuntu-24.04" and job.get("timeout-minutes")
    for holder in [job, *job["steps"]]:
        for key in ("continue-on-error", "if"):
            assert key not in holder, f"{key} on {holder.get('name', 'the job')}"
    for step in job["steps"]:
        script = str(step.get("run", ""))
        for escape in ("|| true", "|| :", "set +e", "|| exit 0", "; true"):
            assert escape not in script, f"{escape!r} in {step.get('name')}"
    checkouts = [step for step in job["steps"] if str(step.get("uses", "")).startswith(
        "actions/checkout@")]
    assert [step["with"]["path"] for step in checkouts] == ["first", "second"]
    assert all(step["with"]["persist-credentials"] is False for step in checkouts)
    assert all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])
               for step in job["steps"] if "uses" in step), "actions pinned by commit"


def test_the_rebuild_job_varies_what_must_not_matter_and_compares_the_bytes():
    steps = {step.get("name"): str(step.get("run", "")) for step in _job()["steps"]}
    fetch = steps["Fetch the pinned interpreter archive"]
    assert "timeout=" in fetch
    assert 'raise SystemExit(f"not the pinned archive' in fetch, "a mismatch must fail"
    assert "--require-hashes --no-deps -r first/scripts/windows_installer/build-tools.txt" in (
        steps["Install the pinned installer"])
    first = steps["Build the payload from the first checkout"]
    assert 'python first/scripts/build_windows_bundle.py --dist "$RUNNER_TEMP/payload-first"' in (
        first)
    second = steps["Build it again from the second checkout, varying what must not matter"]
    for varied in ('python -m venv "$RUNNER_TEMP/second-python"',
                   '"$RUNNER_TEMP/second-python/bin/python" second/scripts/build_windows_bundle.py',
                   'UV_CACHE_DIR="$RUNNER_TEMP/warm-cache" UV_COMPILE_BYTECODE=1',
                   "UV_INDEX_URL=https://example.invalid/simple",
                   'printf \'\\n# changed in the cache, which the build must not read\\n\' >> "$changed"',
                   '--dist "$RUNNER_TEMP/payload-second"'):
        assert varied in second, varied
    compare = steps["Compare the two payloads byte for byte"]
    for needed in ("cmp payload-first/forge-payload.json payload-second/forge-payload.json",
                   "diff -r --no-dereference payload-first payload-second",
                   "cmp first.list second.list",
                   'PYTHONPATH="$GITHUB_WORKSPACE/first/src" python -m '
                   "nornyx_forge.windows_payload verify payload-first",
                   'PYTHONPATH="$GITHUB_WORKSPACE/second/src" python -m '
                   "nornyx_forge.windows_payload verify payload-second"):
        assert needed in compare, needed
    listings = re.findall(r"find \. -printf '([^']*)'", compare)
    assert listings == ["%P %y %T@\\n"] * 2, listings
    for field in ("%s", "%n", "%b", "%k"):
        assert all(field not in listing for listing in listings), (
            f"{field} in a listing compares file-system bookkeeping, not the payload: "
            "an ext4 directory's size depends on the entries created and removed in it")
    assert "upload-artifact" not in json.dumps(_job()), "the job publishes nothing"
