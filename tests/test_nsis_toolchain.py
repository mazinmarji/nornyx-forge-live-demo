"""The installer compiler: NSIS built from pinned source, and what comes out.

`scripts/windows_installer/build_nsis_toolchain.py` fetches the NSIS source
archive and the build packages, refuses anything that is not the pinned bytes,
runs one container build with no network, and compares two such builds. The
tests here hold each refusal to its own named failure and the build to its own
shape, in four groups:

* THE PINS: the committed pin file and package lock are complete and agree.
* THE INPUTS: the archive and the packages are refused on a wrong size, hash or
  MD5 before anything is written, and a hostile archive member is refused by
  name before anything is extracted.
* THE BUILD: the container command has no network and no writable input; the
  script that runs inside it refuses a package set other than the locked one, a
  compiler that reports another version, and a MinGW runtime import; two builds
  compare by path and by byte.
* THE CORROBORATION AND THE SMOKE INSTALLER: the comparison of the archive with
  the upstream Git tree, and the small installer the Windows job runs.

The workflow's jobs are read as data (their structure, not their outcome), and
the wording of the documents is held to what the pins support: a trust-on-first-
use ceiling, not authenticated upstream provenance.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import http.client
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "windows_installer"
sys.path.insert(0, str(INSTALLER))

import build_nsis_toolchain as tc  # noqa: E402

PINS, LOCK = tc.load_pins()
EPOCH = PINS["build"]["source_date_epoch"]
ROOT_DIR = PINS["source"]["root"]
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
JOBS = ("nsis-toolchain", "nsis-toolchain-verify", "nsis-smoke-build", "nsis-smoke-windows")
CORROBORATION = "nsis-source-corroboration"


def _pins() -> dict:
    return copy.deepcopy(PINS)


def _lock() -> dict:
    return copy.deepcopy(LOCK)


# ---------------------------------------------------------------------------
# The pins
# ---------------------------------------------------------------------------

def test_the_committed_pins_and_lock_load_and_agree():
    pins, lock = tc.load_pins()
    assert pins["source"]["version"] == "3.13" and pins["build"]["version_output"] == "v3.13"
    assert lock["image"] == pins["container"]["image"]
    assert lock["snapshot"] == pins["container"]["snapshot"]
    assert pins["container"]["image"].count("@sha256:") == 1, "the image is pinned by digest"


def test_the_epoch_is_the_pinned_commit_time():
    assert EPOCH == 1790522672
    assert PINS["source"]["git"]["commit_time"] == "2026-09-27T15:24:32Z"


PIN_MUTATIONS = {
    "a source size that is not a number": lambda p, k: p["source"].update(size="1819771"),
    "a source hash that is not a SHA-256": lambda p, k: p["source"].update(sha256="abc"),
    "an MD5 that is not an MD5": lambda p, k: p["source"].update(md5="0" * 31),
    "a plain-http source location": lambda p, k: p["source"].update(
        url=p["source"]["url"].replace("https://", "http://")),
    "a plain-http fallback location": lambda p, k: p["source"]["fallback_urls"].append(
        "http://example.org/x.tar.bz2"),
    "a root that does not match the version": lambda p, k: p["source"].update(root="nsis-src"),
    "a Git object id of the wrong length": lambda p, k: p["source"]["git"].update(commit="a" * 39),
    "an epoch other than the commit time": lambda p, k: p["build"].update(
        source_date_epoch=EPOCH + 1),
    "a reported version other than the source version": lambda p, k: p["build"].update(
        version_output="v3.12"),
    "build arguments without the target": lambda p, k: p["build"]["scons_args"].remove(
        "TARGET_ARCH=x86"),
    "a compiler installed where makensis cannot find its data": lambda p, k: p["build"][
        "scons_args"].remove("PREFIX_BIN=/out/nsis/Bin"),
    "build arguments without the relocatable layout": lambda p, k: p["build"][
        "scons_args"].remove("NSIS_CONFIG_CONST_DATA_PATH=no"),
    "another pin schema": lambda p, k: p.update(schema="nornyx.forge.other.v1"),
    "another lock schema": lambda p, k: k.update(schema="nornyx.forge.other.v1"),
    "a lock with no signed-index record": lambda p, k: k.pop("signed_indexes"),
    "a signed-index record for a suite that is not used": lambda p, k: k["signed_indexes"].update(
        extra={}),
    "a signed-index record missing a suite": lambda p, k: k["signed_indexes"].pop("noble"),
    "an InRelease digest that is not a SHA-256": lambda p, k: k["signed_indexes"]["noble"].update(
        inrelease_sha256="abc"),
    "a signed-index record without its indexes": lambda p, k: k["signed_indexes"]["noble"].update(
        indexes={}),
    "an index with a size that is not a number": lambda p, k: k["signed_indexes"]["noble"][
        "indexes"]["main/binary-amd64/Packages.xz"].update(size="1"),
    "an index hash that is not a SHA-256": lambda p, k: k["signed_indexes"]["noble"]["indexes"][
        "main/binary-amd64/Packages.xz"].update(sha256="abc"),
    "an index for a component that is not used": lambda p, k: k["signed_indexes"]["noble"][
        "indexes"].update({"restricted/binary-amd64/Packages.xz": {"size": 1, "sha256": "a" * 64}}),
    "an image pinned by tag": lambda p, k: (p["container"].update(image="ubuntu:noble"),
                                            k.update(image="ubuntu:noble")),
    "a snapshot that is not a timestamp": lambda p, k: (
        [package.update(url=package["url"].replace(k["snapshot"], "latest"))
         for package in k["packages"]],
        p["container"].update(snapshot="latest"), k.update(snapshot="latest")),
    "a package hash that is not a SHA-256": lambda p, k: k["packages"][0].update(sha256="abc"),
    "outputs with one pin": lambda p, k: p.update(outputs={"makensis_sha256": "a" * 64}),
    "outputs with a short hash": lambda p, k: p.update(
        outputs={"makensis_sha256": "a" * 64, "data_tree_sha256": "b" * 63}),
    "a lock for another image": lambda p, k: k.update(image="ubuntu@sha256:" + "c" * 64),
    "a lock for another snapshot": lambda p, k: k.update(snapshot="20200101T000000Z"),
    "a lock for another package list": lambda p, k: k.update(install=["scons"]),
    "a package named twice": lambda p, k: k["packages"].append(copy.deepcopy(k["packages"][0])),
    "a package with an extra field": lambda p, k: k["packages"][0].update(extra="x"),
    "a package size of zero": lambda p, k: k["packages"][0].update(size=0),
    "a package URL outside the snapshot pool": lambda p, k: k["packages"][0].update(
        url=k["packages"][0]["url"].replace(
            f"https://snapshot.ubuntu.com/ubuntu/{k['snapshot']}/", "https://archive.ubuntu.com/ubuntu/")),
    "a package URL that is not a deb": lambda p, k: k["packages"][0].update(
        url=k["packages"][0]["url"][:-len(".deb")] + ".tar"),
    "a package URL that does not name the package": lambda p, k: k["packages"][0].update(
        url=k["packages"][0]["url"].rsplit("/", 1)[0] + "/other_1_amd64.deb"),
    "a POSIX-thread MinGW package": lambda p, k: k["packages"].append(
        {**copy.deepcopy(k["packages"][0]), "name": "gcc-mingw-w64-i686-posix",
         "url": k["packages"][0]["url"].rsplit("/", 1)[0] + "/gcc-mingw-w64-i686-posix_1_amd64.deb"}),
    "a requested package that is nowhere": lambda p, k: (
        p["container"]["install"].append("zzz"), k["install"].append("zzz")),
    "a base entry that is not three fields": lambda p, k: k["base"].append("only-two fields"),
}


@pytest.mark.parametrize("name", sorted(PIN_MUTATIONS))
def test_a_pin_set_that_is_incomplete_or_inconsistent_is_refused(name):
    pins, lock = _pins(), _lock()
    PIN_MUTATIONS[name](pins, lock)
    with pytest.raises(tc.ToolchainError):
        tc.check_pins(pins, lock)


def test_pinned_outputs_in_the_right_shape_are_accepted():
    pins = _pins()
    pins["outputs"] = {"makensis_sha256": "a" * 64, "data_tree_sha256": "b" * 64}
    tc.check_pins(pins, _lock())


def test_expected_packages_put_the_locked_version_in_place_of_the_image_s_in_byte_order():
    lock = {"base": ["Zlib all 1", "b amd64 2", "a+ amd64 1"],
            "packages": [{"name": "b", "architecture": "amd64", "version": "3"},
                         {"name": "c", "architecture": "all", "version": "1"}]}
    assert tc.expected_packages(lock) == ["Zlib all 1", "a+ amd64 1", "b amd64 3", "c all 1"]
    real = tc.expected_packages(LOCK)
    assert real == sorted(real, key=lambda line: line.encode("utf-8"))
    assert len({line.split(" ")[0] for line in real}) == len(real), "one version per package"
    assert len(real) == len(LOCK["base"]) + len(
        [p for p in LOCK["packages"] if f"{p['name']} " not in
         {row.split(" ")[0] + " " for row in LOCK["base"]}])


# ---------------------------------------------------------------------------
# The inputs: fetching
# ---------------------------------------------------------------------------

class _Response:
    """A body that is read in pieces, as a socket is: each read continues where the
    last one stopped, and nothing is ever returned beyond what was asked for."""

    def __init__(self, data: bytes) -> None:
        self.data, self.asked, self.position = data, [], 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, amount: int = -1) -> bytes:
        self.asked.append(amount)
        if amount < 0:
            amount = len(self.data)
        chunk = self.data[self.position:self.position + amount]
        self.position += len(chunk)
        return chunk


def _opener(mapping: dict, log: list | None = None):
    def opener(url, timeout):
        item = mapping[url]
        if isinstance(item, Exception):
            raise item
        response = _Response(item)
        if log is not None:
            log.append(response)
        return response
    return opener


DATA = b"pinned archive bytes" * 50
GOOD = {"size": len(DATA), "sha256": hashlib.sha256(DATA).hexdigest(),
        "md5": hashlib.md5(DATA, usedforsecurity=False).hexdigest()}


def test_bytes_that_are_the_pinned_ones_are_kept_and_the_location_returned(tmp_path):
    dest = tmp_path / "out" / "source.tar.bz2"
    url = tc.fetch_verified(["https://a/x"], dest=dest, opener=_opener({"https://a/x": DATA}),
                            **GOOD)
    assert url == "https://a/x" and dest.read_bytes() == DATA
    assert not dest.with_name(dest.name + ".partial").exists()


@pytest.mark.parametrize("name", ["short", "long", "other bytes", "other md5"])
def test_wrong_bytes_are_refused_and_leave_nothing_at_the_destination(tmp_path, name):
    served = {"short": DATA[:-1], "long": DATA + b"x", "other bytes": b"x" + DATA[1:],
              "other md5": DATA}[name]
    pins = dict(GOOD, md5="0" * 32) if name == "other md5" else dict(GOOD)
    dest = tmp_path / "source.tar.bz2"
    with pytest.raises(tc.ToolchainError):
        tc.fetch_verified(["https://a/x"], dest=dest, opener=_opener({"https://a/x": served}),
                          **pins)
    assert not dest.exists() and not list(tmp_path.iterdir()), "nothing was written"


def test_each_refusal_names_its_own_cause(tmp_path):
    for served, pins, words in ((DATA[:-1], GOOD, "not the pinned"), (b"x" + DATA[1:], GOOD,
                                "SHA-256"), (DATA, dict(GOOD, md5="0" * 32), "MD5")):
        with pytest.raises(tc.ToolchainError, match=words):
            tc.fetch_verified(["https://a/x"], dest=tmp_path / "f", opener=_opener(
                {"https://a/x": served}), **pins)


def test_at_most_one_byte_beyond_the_pinned_size_is_read(tmp_path):
    log: list = []
    with pytest.raises(tc.ToolchainError):
        tc.fetch_verified(["https://a/x"], dest=tmp_path / "f", opener=_opener(
            {"https://a/x": DATA * 1000}, log), **GOOD)
    asked = log[0].asked
    assert all(0 < amount <= GOOD["size"] + 1 for amount in asked), "an unbounded read"
    assert log[0].position == GOOD["size"] + 1, "it stopped one byte past the pinned size"


def test_a_location_that_cannot_be_read_or_gives_other_bytes_is_passed_over_for_the_next(tmp_path):
    mapping = {"https://down/x": OSError("unreachable"), "https://html/x": b"<html>blocked</html>",
               "https://up/x": DATA}
    url = tc.fetch_verified(["https://down/x", "https://html/x", "https://up/x"],
                            dest=tmp_path / "f", opener=_opener(mapping), **GOOD)
    assert url == "https://up/x" and (tmp_path / "f").read_bytes() == DATA


def test_when_no_location_gives_the_pinned_bytes_the_fetch_says_what_each_gave(tmp_path):
    mapping = {"https://liar/x": b"other" * 100, "https://down/x": OSError("no route")}
    with pytest.raises(tc.ToolchainError, match="no location gave the pinned bytes") as raised:
        tc.fetch_verified(["https://liar/x", "https://down/x"], dest=tmp_path / "g",
                          opener=_opener(mapping), **GOOD)
    assert "https://liar/x gave 500 bytes" in str(raised.value) and "no route" in str(raised.value)
    assert not (tmp_path / "g").exists()


def test_a_transfer_that_outlasts_its_time_budget_is_abandoned(tmp_path, monkeypatch):
    clock = iter([0.0, 0.0, 1000.0, 2000.0, 3000.0])
    monkeypatch.setattr(tc.time, "monotonic", lambda: next(clock))
    with pytest.raises(tc.ToolchainError, match="time budget"):
        tc.fetch_verified(["https://slow/x"], dest=tmp_path / "f", budget=10,
                          opener=_opener({"https://slow/x": DATA}), **GOOD)


def test_packages_are_kept_only_when_each_matches_the_lock_and_into_an_empty_folder(tmp_path):
    one, two = b"first package", b"second package"
    lock = {"packages": [
        {"url": "https://snapshot/x/a_1_amd64.deb", "size": len(one),
         "sha256": hashlib.sha256(one).hexdigest()},
        {"url": "https://snapshot/x/b_1_all.deb", "size": len(two),
         "sha256": hashlib.sha256(two).hexdigest()}]}
    mapping = {"https://snapshot/x/a_1_amd64.deb": one, "https://snapshot/x/b_1_all.deb": two}
    names = tc.fetch_debs(lock, tmp_path / "debs", opener=_opener(mapping))
    assert names == ["a_1_amd64.deb", "b_1_all.deb"]
    assert sorted(p.name for p in (tmp_path / "debs").iterdir()) == names
    with pytest.raises(tc.ToolchainError, match="not empty"):
        tc.fetch_debs(lock, tmp_path / "debs", opener=_opener(mapping))
    mapping["https://snapshot/x/b_1_all.deb"] = two + b"!"
    with pytest.raises(tc.ToolchainError):
        tc.fetch_debs(lock, tmp_path / "debs2", opener=_opener(mapping))
    assert not (tmp_path / "debs2" / "b_1_all.deb").exists()


# ---------------------------------------------------------------------------
# The inputs: unpacking
# ---------------------------------------------------------------------------

def _tar(path: Path, entries: list[tuple]) -> Path:
    with tarfile.open(path, "w:bz2") as archive:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.mtime = 0o777, 1_000_000_000
            if kind == "file":
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
                continue
            info.type = {"dir": tarfile.DIRTYPE, "symlink": tarfile.SYMTYPE,
                         "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE,
                         "chardev": tarfile.CHRTYPE, "blockdev": tarfile.BLKTYPE}[kind]
            info.linkname = payload or ""
            archive.addfile(info)
    return path


GOOD_ENTRIES = [(ROOT_DIR, "dir", None), (f"{ROOT_DIR}/sub", "dir", None),
                (f"{ROOT_DIR}/sub/a.txt", "file", b"alpha\r\n"), (f"{ROOT_DIR}/b", "file", b"")]


def test_a_clean_archive_is_unpacked_with_plain_modes_and_the_pinned_time(tmp_path):
    archive = _tar(tmp_path / "a.tar.bz2", GOOD_ENTRIES)
    count = tc.safe_extract(archive, tmp_path / "src", root=ROOT_DIR, epoch=EPOCH)
    assert count == 2
    assert (tmp_path / "src" / ROOT_DIR / "sub" / "a.txt").read_bytes() == b"alpha\r\n"
    for path in (tmp_path / "src" / ROOT_DIR / "sub" / "a.txt", tmp_path / "src" / ROOT_DIR / "b"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o644, "the archive's 0777 is not kept"
        assert path.stat().st_mtime == EPOCH
    folder = tmp_path / "src" / ROOT_DIR / "sub"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o755 and folder.stat().st_mtime == EPOCH


UNSAFE = {
    "an absolute name": ("/etc/cron.d/x", "file", b"x"),
    "a name that climbs out": (f"{ROOT_DIR}/../escape", "file", b"x"),
    "a name with a backslash": (f"{ROOT_DIR}\\x", "file", b"x"),
    "a name with a dot component": (f"{ROOT_DIR}/./x", "file", b"x"),
    "a name with an empty component": (f"{ROOT_DIR}//x", "file", b"x"),
    "a file outside the single root": ("other-root/x", "file", b"x"),
    "a symbolic link": (f"{ROOT_DIR}/link", "symlink", "/etc"),
    "a hard link": (f"{ROOT_DIR}/hard", "hardlink", f"{ROOT_DIR}/b"),
    "a named pipe": (f"{ROOT_DIR}/pipe", "fifo", None),
    "a character device": (f"{ROOT_DIR}/tty", "chardev", None),
    "a block device": (f"{ROOT_DIR}/disk", "blockdev", None),
    "a repeated name": (f"{ROOT_DIR}/b", "file", b"the same name again"),
    "a name that differs only in case": (f"{ROOT_DIR}/B", "file", b"differs only in case"),
    "a folder spelled two ways": (f"{ROOT_DIR}/SUB/other", "file", b"x"),
    "a member below a file": (f"{ROOT_DIR}/b/under", "file", b"x"),
}


@pytest.mark.parametrize("name", sorted(UNSAFE))
def test_a_hostile_member_refuses_the_whole_archive_before_anything_is_written(tmp_path, name):
    archive = _tar(tmp_path / "a.tar.bz2", [*GOOD_ENTRIES, UNSAFE[name]])
    with pytest.raises(tc.ToolchainError, match="member|appears twice"):
        tc.safe_extract(archive, tmp_path / "src", root=ROOT_DIR, epoch=EPOCH)
    assert not (tmp_path / "src").exists() or not any((tmp_path / "src").iterdir()), \
        "members before the bad one were written"
    assert not (tmp_path / "escape").exists() and not (tmp_path / "x").exists()


def test_each_refusal_says_what_is_wrong_with_the_member(tmp_path):
    for name, words in (("a symbolic link", "not a regular file or folder"),
                        ("an absolute name", "absolute"),
                        ("a name that climbs out", "plain relative path"),
                        ("a file outside the single root", "outside the single root")):
        archive = _tar(tmp_path / "a.tar.bz2", [*GOOD_ENTRIES, UNSAFE[name]])
        with pytest.raises(tc.ToolchainError, match=words):
            tc.safe_extract(archive, tmp_path / "src", root=ROOT_DIR, epoch=EPOCH)


def test_the_root_name_is_only_ever_a_folder(tmp_path):
    archive = _tar(tmp_path / "a.tar.bz2", [(ROOT_DIR, "file", b"a file where the root belongs")])
    with pytest.raises(tc.ToolchainError, match="not a folder"):
        tc.safe_extract(archive, tmp_path / "src", root=ROOT_DIR, epoch=EPOCH)


def test_a_sparse_member_is_refused():
    info = tarfile.TarInfo(f"{ROOT_DIR}/sparse")
    info.sparse = [(0, 1)]
    assert tc._member_problem(info, ROOT_DIR)
    plain = tarfile.TarInfo(f"{ROOT_DIR}/plain")
    assert tc._member_problem(plain, ROOT_DIR) is None


def test_too_many_members_too_much_data_and_a_used_folder_are_refused(tmp_path, monkeypatch):
    archive = _tar(tmp_path / "a.tar.bz2", GOOD_ENTRIES)
    monkeypatch.setattr(tc, "_MAX_MEMBERS", 3)
    with pytest.raises(tc.ToolchainError, match="members"):
        tc.safe_extract(archive, tmp_path / "one", root=ROOT_DIR, epoch=EPOCH)
    monkeypatch.undo()
    monkeypatch.setattr(tc, "_MAX_UNPACKED", 3)
    with pytest.raises(tc.ToolchainError, match="unpacks to"):
        tc.safe_extract(archive, tmp_path / "two", root=ROOT_DIR, epoch=EPOCH)
    monkeypatch.undo()
    (tmp_path / "used").mkdir()
    (tmp_path / "used" / "stale").write_text("x", encoding="utf-8")
    with pytest.raises(tc.ToolchainError, match="not empty"):
        tc.safe_extract(archive, tmp_path / "used", root=ROOT_DIR, epoch=EPOCH)


# ---------------------------------------------------------------------------
# The build: the container command
# ---------------------------------------------------------------------------

def _argv(pins=None) -> list[str]:
    return tc.docker_argv(pins or PINS, debs=Path("/w/debs"), src=Path("/w/src"),
                          out=Path("/w/out"), expected=Path("/w/expected-packages.txt"))


def test_the_container_has_no_network_the_pinned_image_and_one_writable_mount():
    argv = _argv()
    assert argv[:2] == ["docker", "run"]
    assert argv[argv.index("--network") + 1] == "none"
    assert "--privileged" not in argv
    assert PINS["container"]["image"] in argv and "@sha256:" in PINS["container"]["image"]
    mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "-v"]
    writable = [m for m in mounts if not m.endswith(":ro")]
    assert writable == ["/w/out:/out"], "only the output folder is writable"
    assert {m.rsplit(":", 2)[1] for m in mounts if m.endswith(":ro")} == {
        "/debs", "/src", "/work/build-inside.sh", "/work/expected-packages.txt"}
    assert not any("docker.sock" in m for m in mounts)


def test_the_build_command_carries_the_pinned_epoch_environment_and_arguments():
    argv = _argv()
    environment = {argv[i + 1].split("=", 1)[0]: argv[i + 1].split("=", 1)[1]
                   for i, value in enumerate(argv) if value == "-e"}
    assert environment["SOURCE_DATE_EPOCH"] == str(EPOCH)
    assert environment["TZ"] == "UTC" and environment["LC_ALL"] == "C.UTF-8"
    assert environment["NSIS_SRC_ROOT"] == ROOT_DIR
    assert environment["NSIS_VERSION_OUTPUT"] == "v3.13"
    image_at = argv.index(PINS["container"]["image"])
    assert argv[image_at + 1:image_at + 4] == ["sh", "-eu", "/work/build-inside.sh"]
    assert argv[image_at + 4:] == PINS["build"]["scons_args"]


def test_the_driver_refuses_a_failed_build_a_missing_compiler_and_a_used_output(tmp_path):
    class Done:
        def __init__(self, code):
            self.returncode = code

    out = tmp_path / "out"
    with pytest.raises(tc.ToolchainError, match="exited 3"):
        tc.build(PINS, tmp_path / "w", out, run=lambda *a, **k: Done(3))
    with pytest.raises(tc.ToolchainError, match="no makensis"):
        tc.build(PINS, tmp_path / "w", tmp_path / "out2", run=lambda *a, **k: Done(0))
    used = tmp_path / "used"
    used.mkdir()
    (used / "x").write_text("x", encoding="utf-8")
    with pytest.raises(tc.ToolchainError, match="not empty"):
        tc.build(PINS, tmp_path / "w", used, run=lambda *a, **k: Done(0))

    def make(argv, **kwargs):
        target = Path(argv[argv.index("-v") + 1].split(":")[0]) / "nsis"
        for index, value in enumerate(argv):
            if value == "-v" and argv[index + 1].endswith(":/out"):
                target = Path(argv[index + 1].split(":")[0]) / "nsis"
        target.mkdir(parents=True)
        (target / "Bin").mkdir()
        (target / "Bin" / "makensis").write_bytes(b"x")
        return Done(0)

    tc.build(PINS, tmp_path / "w", tmp_path / "out3", run=make)


def test_a_compiler_that_is_a_link_is_not_a_compiler(tmp_path):
    class Done:
        returncode = 0

    def make(argv, **kwargs):
        out = Path(next(argv[i + 1] for i, value in enumerate(argv) if value == "-v"
                        and argv[i + 1].endswith(":/out")).split(":")[0])
        (out / "nsis" / "Bin").mkdir(parents=True)
        (out / "elsewhere").write_bytes(b"x")
        (out / "nsis" / tc.COMPILER).symlink_to(out / "elsewhere")
        return Done()

    with pytest.raises(tc.ToolchainError, match="no makensis"):
        tc.build(PINS, tmp_path / "w", tmp_path / "out", run=make)


# ---------------------------------------------------------------------------
# The build: the script that runs inside the container
# ---------------------------------------------------------------------------

SCRIPT = INSTALLER / "build-inside.sh"
# These tests run a POSIX shell script with stand-in tools; the CI test job is Linux.


class _Sandbox:
    """build-inside.sh over scratch folders and stand-in tools, so the script's
    own decisions (not the tools') produce the exit code."""

    def __init__(self, root: Path, *, installed: str, expected: str, version: str = "v3.13",
                 objdump_names: str = "", uid: str = "0", pe: bool = False,
                 builds: bool = True, before: str = "", rounds_needed: int = 0,
                 objdump_code: int = 0):
        self.root = root
        for name in ("debs", "src", "work", "out", "bin"):
            (root / name).mkdir()
        (root / "debs" / "a.deb").write_bytes(b"deb")
        (root / "src" / "nsis-x").mkdir()
        (root / "src" / "nsis-x" / "SConstruct").write_text("x", encoding="utf-8")
        (root / "work" / "expected-packages.txt").write_text(expected, encoding="utf-8")
        tools = {
            "id": f'echo {uid}',
            "dpkg": 'echo dpkg "$@" >> "$TRACE"',
            # `dpkg-deb -W` of the one stand-in file: the line the lock's list would hold.
            "dpkg-deb": "echo 'newpkg all 2'",
            # Until `rounds_needed` configure passes have been traced the image still
            # holds `before`; after that, `installed`. With none needed it is `installed`.
            "dpkg-query": (
                f"n=0; [ -f \"$TRACE\" ] && n=$(grep -c -- --configure \"$TRACE\"); "
                f"if [ \"$n\" -ge {rounds_needed} ]; "
                f"then printf '%s' '{installed}'; else printf '%s' '{before}'; fi"),
            # Root hands the folders to the build user; the stand-in only records it.
            "chown": 'echo chown "$@" >> "$TRACE"',
            # Records how the build user is made, then runs what it was given, as the
            # real one would after dropping its options (all of which start with --).
            "setpriv": ('echo setpriv "$@" >> "$TRACE"; '
                        'while [ "${1#--}" != "$1" ]; do shift; done; exec "$@"'),
            "scons": ((('mkdir -p "$NSIS_OUT/nsis/Bin"; '
                        f'printf \'#!/bin/sh\\n[ "$1" = -VERSION ] && echo {version}; exit 0\\n\' '
                        '> "$NSIS_OUT/nsis/Bin/makensis"; chmod +x "$NSIS_OUT/nsis/Bin/makensis"; '
                        + ('printf MZ > "$NSIS_OUT/nsis/plugin.dll"; ' if pe else ""))
                       if builds else "") + 'echo scons "$@" >> "$TRACE"'),
            "i686-w64-mingw32-objdump": (
                f"printf '%s' '{objdump_names}'; exit {objdump_code}"),
        }
        for name, body in tools.items():
            tool = root / "bin" / name
            tool.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
            tool.chmod(0o755)

    def run(self) -> subprocess.CompletedProcess:
        environment = {
            "PATH": f"{self.root / 'bin'}:/usr/bin:/bin", "TRACE": str(self.root / "trace"),
            "NSIS_DEBS": str(self.root / "debs"), "NSIS_SRC": str(self.root / "src"),
            "NSIS_WORK": str(self.root / "work"), "NSIS_OUT": str(self.root / "out"),
            "NSIS_BUILD": str(self.root / "build"), "NSIS_SRC_ROOT": "nsis-x",
            "NSIS_VERSION_OUTPUT": "v3.13"}
        return subprocess.run(["sh", "-eu", str(SCRIPT), "VERSION=3.13", "install-data"],
                              capture_output=True, text=True, env=environment, timeout=60)


INSTALLED = "base amd64 1 ii \nnewpkg all 2 ii \ngone amd64 3 rc \n"
EXPECTED = "base amd64 1\nnewpkg all 2\n"


def test_a_locked_install_builds_and_passes_the_scons_arguments_through(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED).run()
    assert result.returncode == 0, result.stderr
    trace = (tmp_path / "trace").read_text(encoding="utf-8")
    assert "scons VERSION=3.13 install-data" in trace
    assert "dpkg" not in trace, "everything was installed already, so dpkg was never asked"


def _dpkg_calls(tmp_path: Path) -> list[list[str]]:
    trace = (tmp_path / "trace").read_text(encoding="utf-8")
    return [line.split() for line in trace.splitlines() if line.startswith("dpkg ")]


def test_files_not_yet_installed_are_unpacked_by_absolute_path_and_then_configured(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED,
                      before="base amd64 1 ii \n", rounds_needed=1).run()
    assert result.returncode == 0, result.stderr
    calls = _dpkg_calls(tmp_path)
    assert calls[0][:3] == ["dpkg", "--force-confold", "--unpack"]
    assert calls[1] == ["dpkg", "--force-confold", "--configure", "--pending"]
    files = [argument for call in calls for argument in call if argument.endswith(".deb")]
    assert files == [str(tmp_path / "debs" / "a.deb")], "only the locked file, only by absolute path"
    assert all(argument.startswith("/") for argument in files)


def test_a_file_dpkg_refuses_in_one_round_is_taken_in_the_next(tmp_path):
    """A package whose Pre-Depends is unpacked but not configured is refused by dpkg
    until a later round, so the install does not stop at one pass."""
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED,
                      before="base amd64 1 ii \n", rounds_needed=2).run()
    assert result.returncode == 0, result.stderr
    unpacks = [call for call in _dpkg_calls(tmp_path) if "--unpack" in call]
    assert len(unpacks) == 2


def test_a_package_that_never_installs_is_given_up_after_six_rounds_and_then_refused(tmp_path):
    result = _Sandbox(tmp_path, installed="base amd64 1 ii \n", expected=EXPECTED).run()
    assert result.returncode == 1 and "not the locked set" in result.stderr
    unpacks = [call for call in _dpkg_calls(tmp_path) if "--unpack" in call]
    assert len(unpacks) == 6


@pytest.mark.parametrize(("installed", "why"), [
    (INSTALLED + "extra amd64 9 ii \n", "a package the lock does not name"),
    ("base amd64 1 ii \n", "a locked package that did not install"),
    ("base amd64 1 ii \nnewpkg all 3 ii \n", "a locked package at another version"),
    ("base amd64 1 ii \nnewpkg amd64 2 ii \n", "a locked package for another architecture"),
])
def test_an_installed_set_other_than_the_locked_one_is_refused_before_the_build(
        tmp_path, installed, why):
    result = _Sandbox(tmp_path, installed=installed, expected=EXPECTED).run()
    assert result.returncode == 1, why
    assert "not the locked set" in result.stderr
    trace = tmp_path / "trace"
    assert not trace.exists() or "scons" not in trace.read_text(encoding="utf-8"), "built anyway"


def test_a_compiler_that_reports_another_version_is_refused(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED, version="v3.12").run()
    assert result.returncode == 1 and "not 'v3.13'" in result.stderr


def test_a_windows_binary_that_imports_a_mingw_runtime_dll_is_refused(tmp_path):
    (tmp_path / "c").mkdir()
    clean = _Sandbox(tmp_path / "c", installed=INSTALLED, expected=EXPECTED, pe=True)
    assert clean.run().returncode == 0, "a PE that imports only system DLLs passes"
    (tmp_path / "d").mkdir()
    dirty = _Sandbox(tmp_path / "d", installed=INSTALLED, expected=EXPECTED, pe=True,
                     objdump_names="\tDLL Name: libwinpthread-1.dll\n").run()
    assert dirty.returncode == 1 and "imports a MinGW runtime DLL" in dirty.stderr


def test_a_build_that_leaves_no_compiler_is_refused_by_name(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED, builds=False).run()
    assert result.returncode == 1 and "/nsis/Bin/makensis" in result.stderr


def test_the_compile_and_the_built_compiler_run_as_a_user_with_no_capability(tmp_path):
    """The scripts in the source archive, and the program they build, never run as
    root: both go through setpriv, as a fixed ordinary uid, with the bounding and
    inheritable capability sets emptied and no way to gain privilege."""
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED).run()
    assert result.returncode == 0, result.stderr
    trace = (tmp_path / "trace").read_text(encoding="utf-8")
    runs = [line for line in trace.splitlines() if line.startswith("setpriv ")]
    assert len(runs) == 3, "scons, makensis -VERSION and makensis -HDRINFO"
    for line in runs:
        for needed in ("--reuid=65534", "--regid=65534", "--clear-groups", "--bounding-set=-all",
                       "--inh-caps=-all", "--no-new-privs"):
            assert needed in line, (needed, line)
    assert "scons VERSION=3.13 install-data" in trace
    assert f"chown -R 65534:65534 {tmp_path / 'build'} {tmp_path / 'out' / 'nsis'}" in trace


def test_an_objdump_that_fails_stops_the_build_instead_of_passing_the_file(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED, pe=True,
                      objdump_code=1).run()
    assert result.returncode != 0, "a scan that could not read a file must not pass it"


def test_a_gcc_runtime_import_is_reported_but_is_not_a_refusal(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED, pe=True,
                      objdump_names="\tDLL Name: libgcc_s_dw2-1.dll\n\tDLL Name: KERNEL32.dll\n"
                      ).run()
    assert result.returncode == 0, result.stderr
    assert "note: " in result.stdout and "imports a GCC runtime DLL" in result.stdout


def test_the_script_refuses_to_run_as_anyone_but_root(tmp_path):
    result = _Sandbox(tmp_path, installed=INSTALLED, expected=EXPECTED, uid="1000").run()
    assert result.returncode == 1 and "must run as root" in result.stderr


def test_the_compiler_sits_where_makensis_looks_for_its_data_in_every_place_that_says_so():
    """makensis takes its data folder to be the parent of the folder it runs from, so
    the compiler is installed one folder down; the pins, the script and the workflow
    must all name that place, and the data folder is then the tree itself."""
    folder = tc.COMPILER.rsplit("/", 1)[0]
    assert f"PREFIX_BIN=/out/nsis/{folder}" in PINS["build"]["scons_args"]
    assert "PREFIX=/out/nsis" in PINS["build"]["scons_args"]
    code = SCRIPT.read_text(encoding="utf-8")
    assert f"$OUT/nsis/{tc.COMPILER}" in code and "$OUT/nsis/makensis" not in code
    assert f"nsis/{tc.COMPILER}" in _scripts("nsis-smoke-build")


def test_the_script_never_updates_the_package_lists_or_reaches_the_network():
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for banned in ("apt-get update", "apt update", "curl ", "wget ", "pip ", "git ", "http://",
                   "https://"):
        assert banned not in code, banned
    assert "apt-get" not in code and "apt " not in code, "apt cannot install this set of local files"
    assert "--unpack" in code and "--configure --pending" in code and "cmp -s" in code
    assert 'DEBS="${NSIS_DEBS:-/debs}"' in code, "the files are named by an absolute folder"


# ---------------------------------------------------------------------------
# What came out: the tree digest, the legs and the pinned outputs
# ---------------------------------------------------------------------------

def _independent_digest(files: dict[str, bytes]) -> str:
    lines = sorted(f"{path}\0{hashlib.sha256(data).hexdigest()}\n".encode()
                   for path, data in files.items())
    return hashlib.sha256(b"".join(lines)).hexdigest()


def _tree(root: Path, files: dict[str, bytes], executable: tuple = (tc.COMPILER,)) -> Path:
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if relative in executable else 0o644)
    return root


FILES = {tc.COMPILER: b"ELF compiler", "Stubs/lzma-x86-unicode": b"stub", "Include/b.nsh": b"b",
         "Include/a.nsh": b"a", "Plugins/x86-unicode/System.dll": b"system"}


def _leg(base: Path, name: str, files: dict[str, bytes] | None = None,
         executable: tuple = (tc.COMPILER,)) -> Path:
    folder = base / name
    _tree(folder / "nsis", files or FILES, executable)
    (folder / "files.json").write_text(json.dumps(tc.describe_tree(folder / "nsis")),
                                       encoding="utf-8")
    return folder


def test_the_tree_digest_is_over_paths_and_bytes_in_byte_order(tmp_path):
    tree = _tree(tmp_path / "t", FILES)
    assert tc.tree_digest(tree) == _independent_digest(FILES)
    other = _tree(tmp_path / "u", dict(reversed(list(FILES.items()))))
    assert tc.tree_digest(other) == tc.tree_digest(tree), "creation order does not matter"
    assert tc.tree_digest(_tree(tmp_path / "v", {**FILES, "Include/a.nsh": b"A"})) != \
        tc.tree_digest(tree), "a byte changes it"
    moved = {("Include/c.nsh" if k == "Include/a.nsh" else k): v for k, v in FILES.items()}
    assert tc.tree_digest(_tree(tmp_path / "w", moved)) != tc.tree_digest(tree), "a path changes it"
    assert tc.tree_digest(_tree(tmp_path / "x", {k: v for k, v in FILES.items()
                                                 if k != "Include/a.nsh"})) != tc.tree_digest(tree)
    non_ascii = {"Ünï/é": b"1", "a": b"2", "Z": b"3"}
    assert tc.tree_digest(_tree(tmp_path / "y", non_ascii)) == _independent_digest(non_ascii)


def test_a_link_a_pipe_or_a_set_id_file_anywhere_in_the_tree_or_as_its_root_is_refused(tmp_path):
    def fresh(name):
        return _tree(tmp_path / name, FILES)

    tree = fresh("link-to-a-file")
    (tree / "Include" / "link.nsh").symlink_to(tree / tc.COMPILER)
    with pytest.raises(tc.ToolchainError, match="not a regular file"):
        tc.tree_digest(tree)
    tree = fresh("link-to-a-folder")
    (tree / "linked").symlink_to(tree / "Include", target_is_directory=True)
    with pytest.raises(tc.ToolchainError, match="not a regular file or folder"):
        tc.describe_tree(tree)
    tree = fresh("pipe")
    os.mkfifo(tree / "Include" / "pipe")
    with pytest.raises(tc.ToolchainError, match="not a regular file or folder"):
        tc.describe_tree(tree)
    tree = fresh("setuid-file")
    (tree / "Include" / "a.nsh").chmod(0o4755)
    with pytest.raises(tc.ToolchainError, match="set-user-id"):
        tc.describe_tree(tree)
    tree = fresh("setgid-folder")
    (tree / "Include").chmod(0o2755)
    with pytest.raises(tc.ToolchainError, match="set-user-id or set-group-id"):
        tc.describe_tree(tree)
    tree = fresh("sticky-file")
    (tree / "Include" / "a.nsh").chmod(0o1644)
    with pytest.raises(tc.ToolchainError, match="sticky"):
        tc.describe_tree(tree)
    real = fresh("real")
    root_link = tmp_path / "root-link"
    root_link.symlink_to(real, target_is_directory=True)
    with pytest.raises(tc.ToolchainError, match="not a folder"):
        tc.describe_tree(root_link)
    with pytest.raises(tc.ToolchainError, match="not a folder"):
        tc.tree_digest(root_link)


def _container_output(base: Path, name: str = "out") -> Path:
    out = base / name
    _tree(out / "nsis", FILES)
    return out


def test_the_export_copies_a_clean_output_into_a_new_folder_with_its_description(tmp_path):
    out = _container_output(tmp_path)
    description = tc.export_tree(out, tmp_path / "artifact")
    assert (tmp_path / "artifact" / "files.json").is_file()
    for row in description["files"]:
        copy = tmp_path / "artifact" / "nsis" / row["path"]
        assert hashlib.sha256(copy.read_bytes()).hexdigest() == row["sha256"]
        assert stat.S_IMODE(copy.stat().st_mode) == (0o755 if row["executable"] else 0o644)
    recorded, actual = tc.load_leg(tmp_path / "artifact")
    assert recorded == actual == description


@pytest.mark.parametrize("plant", ["link", "pipe", "file", "folder"])
def test_the_export_refuses_anything_beside_the_tree_in_the_output_folder(tmp_path, plant):
    out = _container_output(tmp_path)
    if plant == "link":
        (out / "files.json").symlink_to(tmp_path / "somewhere-on-the-host")
    elif plant == "pipe":
        os.mkfifo(out / "files.json")
    elif plant == "file":
        (out / "extra").write_text("x", encoding="utf-8")
    else:
        (out / "extra").mkdir()
    with pytest.raises(tc.ToolchainError, match="not exactly"):
        tc.export_tree(out, tmp_path / "artifact")
    assert not (tmp_path / "artifact").exists() and not (tmp_path / "somewhere-on-the-host").exists()


def test_the_export_refuses_a_tree_that_is_itself_a_link_or_holds_one(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    _tree(tmp_path / "elsewhere", FILES)
    (out / "nsis").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    with pytest.raises(tc.ToolchainError, match="not a folder"):
        tc.export_tree(out, tmp_path / "artifact")
    inside = _container_output(tmp_path, "out2")
    (inside / "nsis" / "Include" / "link").symlink_to("/etc/hostname")
    with pytest.raises(tc.ToolchainError, match="not a regular file"):
        tc.export_tree(inside, tmp_path / "artifact2")


def test_the_export_never_writes_through_a_link_that_is_already_there(tmp_path):
    out = _container_output(tmp_path)
    target = tmp_path / "a-host-file"
    target.write_text("keep", encoding="utf-8")
    (tmp_path / "artifact").symlink_to(target)
    with pytest.raises(tc.ToolchainError, match="already exists"):
        tc.export_tree(out, tmp_path / "artifact")
    assert target.read_text(encoding="utf-8") == "keep"
    (tmp_path / "dangling").symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(tc.ToolchainError, match="already exists"):
        tc.export_tree(out, tmp_path / "dangling")
    assert not (tmp_path / "does-not-exist").exists()


def test_the_export_refuses_an_output_folder_that_is_a_link(tmp_path):
    real = _container_output(tmp_path, "real-out")
    (tmp_path / "out").symlink_to(real, target_is_directory=True)
    with pytest.raises(tc.ToolchainError, match="not a folder"):
        tc.export_tree(tmp_path / "out", tmp_path / "artifact")
    assert not (tmp_path / "artifact").exists()


def test_the_tree_digest_and_the_description_sort_by_bytes_not_by_path_parts(tmp_path):
    """`a-b` sorts before `a/b` as bytes and after it as path parts."""
    files = {tc.COMPILER: b"c", "a-b": b"1", "a/b": b"2", "a.c": b"3"}
    tree = _tree(tmp_path / "t", files)
    assert tc.tree_digest(tree) == _independent_digest(files)
    assert [row["path"] for row in tc.describe_tree(tree)["files"]] == sorted(
        files, key=lambda path: path.encode("utf-8"))


def test_a_relative_path_is_refused_for_the_smoke_container_too(tmp_path):
    with pytest.raises(tc.ToolchainError, match="not absolute"):
        tc.smoke_argv(PINS, tree=Path("nsis"), nsi=tmp_path / "x.nsi", out_dir=tmp_path,
                      command=["x"])


def test_the_description_records_each_file_the_compiler_and_the_executable_bit(tmp_path):
    description = tc.describe_tree(_tree(tmp_path / "t", FILES))
    assert [row["path"] for row in description["files"]] == sorted(FILES)
    assert description["makensis_sha256"] == hashlib.sha256(FILES[tc.COMPILER]).hexdigest()
    assert {row["path"] for row in description["files"] if row["executable"]} == {tc.COMPILER}
    assert description["data_tree_sha256"] == _independent_digest(FILES)
    with pytest.raises(tc.ToolchainError, match="no makensis"):
        tc.describe_tree(_tree(tmp_path / "u", {"Include/a.nsh": b"a"}))


def _measured(leg: Path) -> dict:
    description = json.loads((leg / "files.json").read_text(encoding="utf-8"))
    return {"makensis_sha256": description["makensis_sha256"],
            "data_tree_sha256": description["data_tree_sha256"]}


def test_equal_legs_fail_until_the_outputs_are_pinned_and_print_what_to_pin(tmp_path):
    a, b = _leg(tmp_path, "a"), _leg(tmp_path, "b")
    pins = _pins()
    pins["outputs"] = None
    with pytest.raises(tc.ToolchainError, match="NOT PINNED") as raised:
        tc.verify_legs(a, b, pins)
    printed = json.loads(str(raised.value).split("Measured: ", 1)[1])
    assert printed == _measured(a)


def test_equal_legs_that_equal_the_pinned_outputs_pass(tmp_path):
    a, b = _leg(tmp_path, "a"), _leg(tmp_path, "b")
    pins = _pins()
    pins["outputs"] = _measured(a)
    assert tc.verify_legs(a, b, pins) == _measured(a)


def test_equal_legs_that_are_not_the_pinned_outputs_fail(tmp_path):
    a, b = _leg(tmp_path, "a"), _leg(tmp_path, "b")
    for field in ("makensis_sha256", "data_tree_sha256"):
        pins = _pins()
        pins["outputs"] = dict(_measured(a), **{field: "0" * 64})
        with pytest.raises(tc.ToolchainError, match="not the pinned outputs"):
            tc.verify_legs(a, b, pins)


def test_legs_that_differ_fail_by_name_whatever_the_pins_say(tmp_path):
    pins = _pins()
    a = _leg(tmp_path, "a")
    pins["outputs"] = _measured(a)
    cases = {
        "a byte": ({**FILES, "Plugins/x86-unicode/System.dll": b"systeM"}, (tc.COMPILER,),
                   "Plugins/x86-unicode/System.dll: bytes differ"),
        "a size": ({**FILES, "Include/a.nsh": b"aa"}, (tc.COMPILER,), "Include/a.nsh: bytes differ"),
        "a missing file": ({k: v for k, v in FILES.items() if k != "Include/b.nsh"},
                           (tc.COMPILER,), "Include/b.nsh: only in the first"),
        "an extra file": ({**FILES, "Include/z.nsh": b"z"}, (tc.COMPILER,),
                          "Include/z.nsh: only in the second"),
        "an executable bit": (FILES, (tc.COMPILER, "Include/a.nsh"),
                              "Include/a.nsh: executable bit differs"),
    }
    for label, (files, executable, message) in cases.items():
        b = _leg(tmp_path, f"b-{label.replace(' ', '-')}", files, executable)
        with pytest.raises(tc.ToolchainError, match=re.escape(message)):
            tc.verify_legs(a, b, pins)


def test_a_files_json_that_does_not_describe_its_tree_is_refused(tmp_path):
    pins = _pins()
    a = _leg(tmp_path, "a")
    pins["outputs"] = _measured(a)
    b = _leg(tmp_path, "b")
    (b / "nsis" / "Include" / "a.nsh").write_bytes(b"tampered after description")
    with pytest.raises(tc.ToolchainError, match="does not describe the downloaded tree"):
        tc.verify_legs(a, b, pins)
    c = _leg(tmp_path, "c")
    (c / "nsis" / "Include" / "extra.nsh").write_bytes(b"added after description")
    with pytest.raises(tc.ToolchainError, match="does not describe"):
        tc.verify_legs(a, c, pins)
    d = _leg(tmp_path, "d")
    recorded = json.loads((d / "files.json").read_text(encoding="utf-8"))
    recorded["data_tree_sha256"] = "0" * 64
    (d / "files.json").write_text(json.dumps(recorded), encoding="utf-8")
    with pytest.raises(tc.ToolchainError, match="does not describe"):
        tc.verify_legs(a, d, pins)


def test_a_leg_cannot_vouch_for_its_own_compiler_digest(tmp_path):
    """The digests compared with the pins are those of the downloaded bytes: a
    files.json that claims another compiler hash, in both legs and in the pins, passes
    nothing."""
    lie = "f" * 64
    legs = []
    for name in ("a", "b"):
        leg = _leg(tmp_path, name)
        recorded = json.loads((leg / "files.json").read_text(encoding="utf-8"))
        recorded["makensis_sha256"] = lie
        (leg / "files.json").write_text(json.dumps(recorded), encoding="utf-8")
        legs.append(leg)
    pins = _pins()
    pins["outputs"] = {"makensis_sha256": lie, "data_tree_sha256": _measured(_leg(tmp_path, "c"))[
        "data_tree_sha256"]}
    with pytest.raises(tc.ToolchainError, match="does not describe the downloaded tree"):
        tc.verify_legs(legs[0], legs[1], pins)
    honest = _leg(tmp_path, "honest-a"), _leg(tmp_path, "honest-b")
    pins["outputs"] = _measured(honest[0])
    assert tc.verify_legs(*honest, pins)["makensis_sha256"] == hashlib.sha256(
        FILES[tc.COMPILER]).hexdigest()


def test_a_compiler_tree_is_checked_against_the_pinned_outputs_and_an_unpinned_run_is_by_request(
        tmp_path):
    tree = _tree(tmp_path / "t", FILES)
    pins = _pins()
    pins["outputs"] = None
    with pytest.raises(tc.ToolchainError, match="not pinned"):
        tc.check_tree(tree, pins)
    assert "UNPINNED" in tc.check_tree(tree, pins, allow_unpinned=True)
    pins["outputs"] = {"makensis_sha256": hashlib.sha256(FILES[tc.COMPILER]).hexdigest(),
                       "data_tree_sha256": _independent_digest(FILES)}
    assert "is the pinned one" in tc.check_tree(tree, pins)
    assert "is the pinned one" in tc.check_tree(tree, pins, allow_unpinned=True)
    for field in pins["outputs"]:
        wrong = dict(pins, outputs=dict(pins["outputs"], **{field: "0" * 64}))
        for allowed in (False, True):
            with pytest.raises(tc.ToolchainError, match="not the pinned one"):
                tc.check_tree(tree, wrong, allow_unpinned=allowed)


# ---------------------------------------------------------------------------
# The corroboration: the archive against the upstream Git tree
# ---------------------------------------------------------------------------

def test_files_compare_as_identical_line_end_only_different_or_on_one_side():
    blob = tc.git_blob_id
    members = {"same": b"a\nb\n", "crlf": b"a\r\nb\r\n", "edited": b"changed", "new": b"only here"}
    blobs = {"same": blob(b"a\nb\n"), "crlf": blob(b"a\nb\n"), "edited": blob(b"original"),
             "gone": blob(b"only there")}
    assert tc.compare_with_git(members, blobs) == {
        "identical": 1, "crlf_only": 1, "different": ["edited"], "tarball_only": ["new"],
        "git_only": ["gone"]}


def test_a_git_blob_id_is_the_id_git_computes():
    assert tc.git_blob_id(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert tc.git_blob_id(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def _rss(size=PINS["source"]["size"], md5=PINS["source"]["md5"]) -> str:
    return ('<media:content url="https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/'
            f'nsis-3.13-src.tar.bz2/download" filesize="{size}"><media:hash algo="md5">{md5}'
            "</media:hash></media:content>")


def test_the_published_size_and_md5_must_be_the_pinned_ones():
    tc.check_published_md5(_rss(), PINS)
    for text, words in ((_rss(size=1), "lists size"), (_rss(md5="0" * 32), "lists size"),
                        ("<nothing/>", "does not show"),
                        (_rss().replace("-src.tar.bz2", "-other.tar.bz2"), "does not show")):
        with pytest.raises(tc.ToolchainError, match=words):
            tc.check_published_md5(text, PINS)


def _fixture_world(tmp_path: Path):
    """A tiny archive, the Git facts that describe it, and pins that pin both."""
    payload = {f"{ROOT_DIR}/a.nsh": b"x\r\ny\r\n", f"{ROOT_DIR}/b.c": b"int b;\n"}
    archive = _tar(tmp_path / "a.tar.bz2", [(name, "file", data) for name, data in payload.items()])
    blobs = {"a.nsh": tc.git_blob_id(b"x\ny\n"), "b.c": tc.git_blob_id(b"int b;\n")}
    git = _pins()["source"]["git"]
    git["comparison"] = {"identical": 1, "crlf_only": 1, "different": [], "tarball_only": [],
                         "git_only": []}
    base = f"https://api.github.com/repos/{git['repository']}/git"
    answers = {
        f"{base}/ref/tags/{git['tag']}": {"object": {"sha": git["tag_object"]}},
        f"{base}/tags/{git['tag_object']}": {"object": {"sha": git["commit"]}},
        f"{base}/commits/{git['commit']}": {"tree": {"sha": git["tree"]},
                                            "committer": {"date": git["commit_time"]}},
        f"{base}/trees/{git['tree']}?recursive=1": {
            "sha": git["tree"], "truncated": False,
            "tree": [{"path": p, "sha": s, "type": "blob"} for p, s in blobs.items()]
                    + [{"path": "dir", "sha": "0" * 40, "type": "tree"}]},
    }
    pins = _pins()
    pins["source"]["git"] = git
    return pins, archive, answers


def _against(pins, archive, answers, rss=None):
    return tc.against_tag(pins, get_json=lambda url: copy.deepcopy(answers[url]),
                          get_text=lambda url: rss if rss is not None else _rss(), archive=archive)


def test_a_source_that_still_compares_as_pinned_is_corroborated(tmp_path):
    pins, archive, answers = _fixture_world(tmp_path)
    assert _against(pins, archive, answers) == pins["source"]["git"]["comparison"]


def test_a_moved_tag_a_truncated_tree_a_changed_file_or_a_changed_listing_fails_closed(tmp_path):
    pins, archive, answers = _fixture_world(tmp_path)
    git = pins["source"]["git"]
    base = f"https://api.github.com/repos/{git['repository']}/git"

    moved = copy.deepcopy(answers)
    moved[f"{base}/tags/{git['tag_object']}"]["object"]["sha"] = "f" * 40
    moved[f"{base}/commits/{'f' * 40}"] = moved[f"{base}/commits/{git['commit']}"]
    with pytest.raises(tc.ToolchainError, match="no longer names the pinned"):
        _against(pins, archive, moved)

    truncated = copy.deepcopy(answers)
    truncated[f"{base}/trees/{git['tree']}?recursive=1"]["truncated"] = True
    with pytest.raises(tc.ToolchainError, match="truncated"):
        _against(pins, archive, truncated)

    edited = copy.deepcopy(answers)
    edited[f"{base}/trees/{git['tree']}?recursive=1"]["tree"][1]["sha"] = tc.git_blob_id(b"other")
    with pytest.raises(tc.ToolchainError, match="no longer compares"):
        _against(pins, archive, edited)

    with pytest.raises(tc.ToolchainError, match="lists size"):
        _against(pins, archive, answers, rss=_rss(md5="0" * 32))

    extra = copy.deepcopy(answers)
    extra[f"{base}/trees/{git['tree']}?recursive=1"]["tree"].append(
        {"path": "added", "sha": "1" * 40, "type": "blob"})
    with pytest.raises(tc.ToolchainError, match="no longer compares"):
        _against(pins, archive, extra)


def test_the_pinned_comparison_is_the_one_measured_for_the_archive_this_pin_names():
    comparison = PINS["source"]["git"]["comparison"]
    assert comparison["identical"] + comparison["crlf_only"] + len(comparison["different"]) == 835
    assert comparison["different"] == ["Docs/src/bin/halibut/version.c"]
    assert comparison["tarball_only"] == ["ChangeLog"] and comparison["git_only"] == []


# ---------------------------------------------------------------------------
# The smoke installer
# ---------------------------------------------------------------------------

MANIFEST = b'<requestedExecutionLevel level="asInvoker" uiAccess="false"/>'


def _pe(manifest: bytes = MANIFEST, *, magic: bytes = b"MZ", signature: bytes = b"PE\0\0",
        extra: bytes = b"") -> bytes:
    blob = bytearray(magic + b"\0" * 62)
    blob[0x3C:0x40] = (0x80).to_bytes(4, "little")
    blob += b"\0" * (0x80 - len(blob))
    return bytes(blob + signature + b"\0" * 20 + manifest + extra)


@pytest.mark.parametrize(("blob", "words"), [
    (_pe(), None),
    (_pe(magic=b"ZM"), "MZ"),
    (_pe(signature=b"XX\0\0"), "PE signature"),
    (_pe(b"<other/>"), "asInvoker"),
    (_pe(extra=b'level="requireAdministrator"'), "requireAdministrator"),
    (_pe(extra=b'level="highestAvailable"'), "highestAvailable"),
    (_pe(extra=b'uiAccess="true"'), 'uiAccess="true"'),
])
def test_an_executable_is_a_pe_that_asks_for_no_privilege(tmp_path, blob, words):
    path = tmp_path / "x.exe"
    path.write_bytes(blob)
    if words is None:
        tc.check_executable(path)
    else:
        with pytest.raises(tc.ToolchainError, match=re.escape(words)):
            tc.check_executable(path)


class _Run:
    """A stand-in for `docker run` of the compiler, built from what the real pair
    does: the container sees only its mounts; `-VERSION` prints; a compile writes
    its OutFile into the mounted output folder and, like makensis, CANNOT create
    that folder (FOPEN of a path whose directory is missing fails with "Can't open
    output file"); and it prints warnings in the forms NSIS 3.13 prints them."""

    def __init__(self, version=b"v3.13\n", code=0, text=b"", writes=True, blob=None):
        self.version, self.code, self.text, self.writes = version, code, text, writes
        self.blob = _pe() if blob is None else blob
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "-v"]
        smoke = Path(next(m for m in mounts if m.endswith(":/smoke"))[:-len(":/smoke")])
        command = argv[argv.index(PINS["container"]["image"]) + 1:]
        if command[1:] == ["-VERSION"]:
            return subprocess.CompletedProcess(argv, 0, self.version, b"")
        name = next(a for a in command if a.startswith("-DOUT_FILE=/smoke/")).rsplit("/", 1)[1]
        if not smoke.is_dir():
            return subprocess.CompletedProcess(argv, 1, b"", b"Can't open output file\n")
        if self.writes:
            (smoke / name).write_bytes(self.blob)
        return subprocess.CompletedProcess(argv, self.code, self.text, b"")


def test_the_smoke_installer_compiles_inside_the_pinned_image_with_no_network_and_a_fixed_data_folder(
        tmp_path):
    run = _Run()
    tree = tmp_path / "leg" / "nsis"
    tree.mkdir(parents=True)
    out = tmp_path / "does" / "not" / "exist" / "smoke.exe"
    assert tc.compile_smoke(tree, PINS, out, run=run) == 0
    assert out.is_file(), "the output folder was created for makensis, which cannot"
    version_call, compile_call = run.calls
    for argv, _ in run.calls:
        assert argv[:2] == ["docker", "run"] and argv[argv.index("--network") + 1] == "none"
        assert argv[argv.index("--cap-drop") + 1] == "ALL" and "--read-only" in argv
        assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
        assert PINS["container"]["image"] in argv and "--privileged" not in argv
        mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "-v"]
        assert f"{tree.resolve()}:/nsis:ro" in mounts, "the built tree is mounted read-only"
        assert [m for m in mounts if not m.endswith(":ro")] == [f"{out.parent.resolve()}:/smoke"]
        assert not any("docker.sock" in m for m in mounts)
        environment = {argv[i + 1].split("=", 1)[0]: argv[i + 1].split("=", 1)[1]
                       for i, value in enumerate(argv) if value == "-e"}
        assert environment["NSISDIR"] == "/nsis" and environment["HOME"] == "/tmp"
        assert environment["SOURCE_DATE_EPOCH"] == str(EPOCH) and environment["TZ"] == "UTC"
    image_at = version_call[0].index(PINS["container"]["image"])
    assert version_call[0][image_at + 1:] == ["/nsis/Bin/makensis", "-VERSION"]
    command = compile_call[0][compile_call[0].index(PINS["container"]["image"]) + 1:]
    for needed in ("-NOCONFIG", "-NOCD", "-WX", "-DOUT_FILE=/smoke/smoke.exe",
                   "/work/nsis-smoke.nsi"):
        assert needed in command, needed


@pytest.mark.parametrize(("run", "words"), [
    (_Run(version=b"v3.09\n"), "reports 'v3.09'"),
    (_Run(version=b"v3.13 beta\n"), "reports"),
    (_Run(code=1, text=b"Error: bad"), "exited 1"),
    (_Run(writes=False), "exited 0"),
    (_Run(text=b"warning: unused variable\n"), "printed warnings"),
    (_Run(blob=_pe(b"<other/>")), "asInvoker"),
])
def test_a_wrong_compiler_a_failed_compile_a_warning_or_a_bad_executable_is_refused(
        tmp_path, run, words):
    with pytest.raises(tc.ToolchainError, match=words):
        tc.compile_smoke(tmp_path, PINS, tmp_path / "smoke.exe", run=run)


#: Warnings as NSIS 3.13 prints them: inline with and without a code, and the summary.
REAL_WARNINGS = [
    b"warning: unused variable \"x\" (Var.nsi:3)\n",
    b"warning 6000: something with a code (a.nsi:9)\n",
    b"  Warning: indented and capitalised\n",
    b"\n1 warning:\n  unused variable \"x\"\n",
    b"\n2 warnings:\n  one\n  two\n",
]


@pytest.mark.parametrize("text", REAL_WARNINGS)
def test_a_warning_in_any_form_nsis_prints_it_is_refused(tmp_path, text):
    with pytest.raises(tc.ToolchainError, match="printed warnings"):
        tc.compile_smoke(tmp_path, PINS, tmp_path / "smoke.exe", run=_Run(text=b"Processed\n" + text))


def test_text_that_merely_mentions_warnings_is_not_one(tmp_path):
    chatter = b"Processed 1 file, 0 packets, no warnings were treated as errors\n"
    assert tc.compile_smoke(tmp_path, PINS, tmp_path / "smoke.exe", run=_Run(text=chatter)) == 0


def test_the_compile_asks_the_compiler_to_treat_warnings_as_errors(tmp_path):
    run = _Run()
    tc.compile_smoke(tmp_path, PINS, tmp_path / "smoke.exe", run=run)
    assert "-WX" in run.calls[1][0]


GOOD_RESULT = ("nsis=v3.13\r\nsystem_call=ok\r\nelevated=1\r\nnsexec_exit=7\r\n"
               "nsexec_output=smoke\r\n\r\n")


def test_the_smoke_result_is_judged_field_by_field_and_by_exit_code():
    tc.check_smoke_result(GOOD_RESULT, 10, elevated=True, pins=PINS)
    tc.check_smoke_result(GOOD_RESULT.replace("elevated=1", "elevated=0"), 0, elevated=False,
                          pins=PINS)
    wrong = {
        "the System plug-in failing": (GOOD_RESULT.replace("system_call=ok", "system_call=fail"), 10),
        "an unreadable token": (GOOD_RESULT.replace("elevated=1", "elevated=unknown"), 10),
        "nsExec returning another code": (GOOD_RESULT.replace("nsexec_exit=7", "nsexec_exit=0"), 10),
        "nsExec returning no output": (GOOD_RESULT.replace("smoke", ""), 10),
        "another compiler version": (GOOD_RESULT.replace("v3.13", "v3.09"), 10),
        "no refusal exit code": (GOOD_RESULT, 0),
        "a missing field": (GOOD_RESULT.replace("system_call=ok\r\n", ""), 10),
    }
    for label, (text, code) in wrong.items():
        with pytest.raises(tc.ToolchainError):
            tc.check_smoke_result(text, code, elevated=True, pins=PINS)
        assert label
    with pytest.raises(tc.ToolchainError):
        tc.check_smoke_result(GOOD_RESULT.replace("elevated=1", "elevated=0"), 10,
                              elevated=False, pins=PINS)


def test_running_the_smoke_installer_checks_the_file_then_the_result(tmp_path):
    exe = tmp_path / "smoke.exe"
    exe.write_bytes(_pe())

    def runner(text: str | None, code: int):
        def run(argv, **kwargs):
            result = Path(next(a for a in argv if a.startswith("/RESULT=")).split("=", 1)[1])
            if text is not None:
                result.write_text(text, encoding="utf-8")
            return subprocess.CompletedProcess(argv, code)
        return run

    tc.run_smoke(exe, tmp_path / "w1", PINS, elevated=True, run=runner(GOOD_RESULT, 10))
    with pytest.raises(tc.ToolchainError, match="wrote no result"):
        tc.run_smoke(exe, tmp_path / "w2", PINS, elevated=True, run=runner(None, 0))
    with pytest.raises(tc.ToolchainError, match="exited 0, expected 10"):
        tc.run_smoke(exe, tmp_path / "w3", PINS, elevated=True, run=runner(GOOD_RESULT, 0))
    exe.write_bytes(_pe(b"<other/>"))
    with pytest.raises(tc.ToolchainError, match="asInvoker"):
        tc.run_smoke(exe, tmp_path / "w4", PINS, elevated=True, run=runner(GOOD_RESULT, 10))


SMOKE = (INSTALLER / "nsis-smoke.nsi").read_text(encoding="utf-8")


def test_the_smoke_script_uses_what_the_installer_uses_and_names_the_exit_codes_the_driver_reads():
    code = "\n".join(line for line in SMOKE.splitlines() if not line.lstrip().startswith(";"))
    for needed in ("Target x86-unicode", "Unicode true", "RequestExecutionLevel user",
                   "SetCompressor /SOLID lzma", 'ReserveFile /plugin System.dll',
                   "ReserveFile /plugin nsExec.dll", "advapi32::GetTokenInformation",
                   "nsExec::ExecToStack", "LogicLib.nsh", "FileFunc.nsh",
                   'cmd.exe" /c echo smoke& exit /b 7'):
        assert needed in code, needed
    assert "requireAdministrator" not in code and "highestAvailable" not in code
    for call in ("System::Call 'kernel32::GetCurrentProcess() p .r0'",
                 "System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r1) i .r2'",
                 "System::Call 'advapi32::GetTokenInformation(p r1, i 20, p r3, i 4, *i .r4) i .r5'",
                 "System::Call '*$3(i .r6)'", "${If} $5 <> 0",
                 "System::Call 'shell32::IsUserAnAdmin() i .r7'"):
        assert call in code, call
    exits = {int(n) for n in re.findall(r"SetErrorLevel (\d+)", code)}
    assert tc.SMOKE_EXIT_ELEVATED in exits and 0 in exits
    assert re.search(r"\$Elevated == \"1\"\s+SetErrorLevel " + str(tc.SMOKE_EXIT_ELEVATED), code)
    assert re.search(r"\$\{If\} \$7 <> 0\s+StrCpy \$Elevated \"1\"", code), \
        "an administrator is elevated for this purpose whether or not the token says so"
    assert tc.SMOKE_EXEC_EXIT == "7"


def test_what_the_smoke_script_writes_is_what_the_driver_reads_and_nothing_else():
    written = set(re.findall(r'FileWrite \$0 "(\w+)=', SMOKE))
    source = (INSTALLER / "build_nsis_toolchain.py").read_text(encoding="utf-8")
    read = set(re.findall(r'"(\w+)": ', source.split("def check_smoke_result", 1)[1].split(
        "wanted_exit", 1)[0]))
    assert written == read == {"nsis", "system_call", "elevated", "nsexec_exit", "nsexec_output"}


# ---------------------------------------------------------------------------
# The workflow, read as data
# ---------------------------------------------------------------------------

def _steps(job: str) -> list[dict]:
    return WORKFLOW["jobs"][job]["steps"]


def _scripts(job: str) -> str:
    return "\n".join(str(step.get("run", "")) for step in _steps(job))


@pytest.mark.parametrize("job", JOBS)
def test_no_toolchain_job_is_optional_privileged_or_unpinned(job):
    body = WORKFLOW["jobs"][job]
    assert body["runs-on"] in ("ubuntu-24.04", "windows-latest") and body.get("timeout-minutes")
    assert body["permissions"] == {"contents": "read"}
    for holder in [body, *body["steps"]]:
        for key in ("continue-on-error", "if", "env"):
            assert key not in holder, f"{key} on {holder.get('name', job)}"
    for step in body["steps"]:
        script = str(step.get("run", ""))
        for escape in ("|| true", "|| :", "set +e", "|| exit 0", "; true", "secrets.", "sudo "):
            assert escape not in script, f"{escape!r} in {step.get('name')}"
        if "uses" in step:
            assert re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
    checkouts = [s for s in body["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 1 and checkouts[0]["with"]["persist-credentials"] is False


def test_the_toolchain_jobs_use_no_cache_no_secret_and_no_privileged_trigger():
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in text and "workflow_run" not in text
    assert set(WORKFLOW[True]) == {"push", "pull_request", "workflow_dispatch"}, \
        "the triggers a fork pull request can start are these"
    assert WORKFLOW["permissions"] == {"contents": "read"}
    for job in (*JOBS, CORROBORATION):
        body = json.dumps(WORKFLOW["jobs"][job])
        for banned in ("actions/cache", "secrets.", "GITHUB_TOKEN", "apt-get update", "apt update",
                       "pull_request_target"):
            assert banned not in body, f"{banned} in {job}"
    assert "apt-get update" not in "\n".join(
        line for line in SCRIPT.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#"))


def test_the_source_is_compared_with_the_upstream_tag_when_someone_dispatches_the_workflow():
    """Only the archive's own size, SHA-256 and MD5 are checked on every commit. The
    live tag and SourceForge's listing are compared by this job, which runs when the
    workflow is dispatched by hand and at no other time."""
    job = WORKFLOW["jobs"][CORROBORATION]
    assert job["if"] == "github.event_name == 'workflow_dispatch'"
    assert job["permissions"] == {"contents": "read"}
    assert "build_nsis_toolchain.py against-tag" in _scripts(CORROBORATION)
    assert all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])
               for step in job["steps"] if "uses" in step)
    for other in JOBS:
        assert "against-tag" not in _scripts(other), "no commit's CI depends on those services"


def test_the_two_build_legs_are_separate_runners_over_one_set_of_pins():
    job = WORKFLOW["jobs"]["nsis-toolchain"]
    assert job["strategy"]["matrix"] == {"leg": ["a", "b"]} and job["strategy"]["fail-fast"] is False
    names = [step.get("name") for step in job["steps"]]
    order = ["Check the pins", "Fetch and verify the source and the build packages",
             "Pull the pinned image", "Build NSIS in the container, with no network",
             "Copy the output to a folder this job owns, and describe it"]
    assert [n for n in names if n in order] == order
    scripts = _scripts("nsis-toolchain")
    for command in ("check", "fetch --work", "build --work", "describe --from"):
        assert f"build_nsis_toolchain.py {command}" in scripts, command
    assert "nsis-toolchain.json" in scripts, "the image is read from the pins, not restated"
    upload = [s for s in job["steps"] if str(s.get("uses", "")).startswith(
        "actions/upload-artifact@")]
    assert [s["with"]["name"] for s in upload] == ["nsis-toolchain-${{ matrix.leg }}"]
    assert upload[0]["with"]["if-no-files-found"] == "error"
    assert upload[0]["with"]["path"].endswith("/nsis-artifact"), \
        "what is uploaded is the host-owned copy, never the folder the container wrote"
    assert "--from \"$RUNNER_TEMP/nsis-out\" --to \"$RUNNER_TEMP/nsis-artifact\"" in scripts


def test_the_verify_job_needs_both_legs_and_compares_them():
    job = WORKFLOW["jobs"]["nsis-toolchain-verify"]
    assert job["needs"] == "nsis-toolchain"
    downloads = [s["with"] for s in job["steps"] if str(s.get("uses", "")).startswith(
        "actions/download-artifact@")]
    assert {d["name"] for d in downloads} == {"nsis-toolchain-a", "nsis-toolchain-b"}
    assert 'verify --a "$RUNNER_TEMP/leg-a" --b "$RUNNER_TEMP/leg-b"' in _scripts(
        "nsis-toolchain-verify")
    assert {d["path"].rsplit("/", 1)[1] for d in downloads} == {"leg-a", "leg-b"}


def test_the_smoke_build_checks_the_tree_refuses_an_unpinned_one_unless_told_and_runs_in_the_image():
    build = WORKFLOW["jobs"]["nsis-smoke-build"]
    assert build["needs"] == "nsis-toolchain"
    scripts = _scripts("nsis-smoke-build")
    assert scripts.index("check-tree") < scripts.index("compile-smoke"), \
        "the tree is checked before the compiler in it is started"
    assert scripts.index("chmod +x") > scripts.index("check-tree")
    assert "docker pull" in scripts and scripts.index("docker pull") < scripts.index("compile-smoke")
    # `--allow-unpinned` is how this job runs while nsis-toolchain.json holds no output
    # pins. Once they are pinned the flag is gone, so the check is no longer optional.
    if PINS["outputs"] is None:
        assert "check-tree --allow-unpinned" in scripts
    else:
        assert "--allow-unpinned" not in scripts, \
            "the outputs are pinned, so the pin check must be unconditional"
    for step in build["steps"]:
        assert "build_nsis_toolchain.py makensis" not in str(step.get("run", ""))
    windows = WORKFLOW["jobs"]["nsis-smoke-windows"]
    assert windows["needs"] == "nsis-smoke-build" and windows["runs-on"] == "windows-latest"
    assert "run-smoke" in _scripts("nsis-smoke-windows")
    assert "--expect elevated" in _scripts("nsis-smoke-windows")


def _subcommands(source: str) -> set[str]:
    return set(re.findall(r'commands\.add_parser\("([a-z-]+)"', source))


def test_every_command_the_workflow_runs_exists_and_every_command_is_run_by_some_job():
    source = (INSTALLER / "build_nsis_toolchain.py").read_text(encoding="utf-8")
    defined = _subcommands(source)
    used = set()
    for job in (*JOBS, CORROBORATION):
        for command in re.findall(r"build_nsis_toolchain\.py ([a-z-]+)", _scripts(job)):
            used.add(command)
    assert used <= defined, f"the workflow runs {used - defined}, which is not a command"
    assert defined == used, f"commands no job runs: {defined - used}"


def test_the_workflow_files_it_names_exist():
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for match in set(re.findall(r"scripts/windows_installer/[A-Za-z0-9_.-]+", text)):
        assert (ROOT / match).exists(), match


# ---------------------------------------------------------------------------
# Every pin is read, and every pin the code reads exists
# ---------------------------------------------------------------------------

def _written(document: object, found: set | None = None) -> set[str]:
    found = set() if found is None else found
    if isinstance(document, dict):
        for key, value in document.items():
            found.add(key)
            _written(value, found)
    elif isinstance(document, list):
        for item in document:
            _written(item, found)
    return found


def _read_keys(source: str, function: str | None = None) -> set[str]:
    tree = ast.parse(source)
    scope = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function] \
        if function else [tree]
    keys = set()
    for node in (n for body in scope for n in ast.walk(body)):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                and isinstance(node.slice.value, str):
            keys.add(node.slice.value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "get" and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            keys.add(node.args[0].value)
    return keys


def coverage_gaps(written: set, read: set, declared_unread: set) -> tuple[set, set]:
    """(written but never read nor declared, read but never written)."""
    return written - read - declared_unread, read - written


#: Pin fields that are evidence for a reader and are read by no code.
DECLARED_UNREAD = {"note", "name", "release_page", "md5_published_at", "image_tag_when_pinned",
                   "image_created", "source_date_epoch_basis", "environment"}


def test_the_coverage_check_sees_a_planted_dead_write_and_a_planted_phantom_read():
    assert coverage_gaps({"a", "dead"}, {"a"}, set()) == ({"dead"}, set())
    assert coverage_gaps({"a"}, {"a", "phantom"}, set()) == (set(), {"phantom"})
    assert coverage_gaps({"a", "note"}, {"a"}, {"note"}) == (set(), set())


def test_every_pin_is_read_by_the_code_or_declared_unread_and_every_pin_read_exists():
    toolchain = (INSTALLER / "build_nsis_toolchain.py").read_text(encoding="utf-8")
    resolver = (INSTALLER / "resolve_nsis_debs.py").read_text(encoding="utf-8")
    # `leg` is a matrix name. TZ and LC_ALL are variable names handed to the container
    # wholesale (`**build["environment"]`), which the code reads as a unit.
    pin_keys = _written(PINS) - {"leg", "TZ", "LC_ALL"}
    dead, _ = coverage_gaps(pin_keys, _read_keys(toolchain) | _read_keys(resolver),
                            DECLARED_UNREAD)
    assert dead == set(), f"written in the pin file and read nowhere: {dead}"
    read_by_validation = _read_keys(toolchain, "check_pins") | _read_keys(toolchain, "_check_lock")
    lock_keys = _written(LOCK)
    # Suite and index names are data inside signed_indexes, not field names.
    lock_keys -= set(LOCK["signed_indexes"]) | {name for record in LOCK["signed_indexes"].values()
                                                for name in record["indexes"]}
    _, phantom = coverage_gaps(pin_keys | lock_keys, read_by_validation, set())
    assert phantom == set(), f"read from the pins and written nowhere: {phantom}"
    #: Keys of the GitHub API's answers, which `against_tag` reads beside the pins'.
    api_keys = {"object", "sha", "tree", "committer", "date", "truncated", "path", "type"}
    _, phantom = coverage_gaps(pin_keys, _read_keys(toolchain, "against_tag") - api_keys, set())
    assert phantom == set(), f"against_tag reads a pin that is not in the file: {phantom}"
    _, phantom = coverage_gaps(lock_keys | pin_keys | {"comparison"}, _read_keys(toolchain, "_check_lock")
                               | _read_keys(toolchain, "expected_packages"), set())
    assert phantom == set()
    dead_lock, _ = coverage_gaps(lock_keys, _read_keys(toolchain, "_check_lock")
                                 | _read_keys(toolchain, "expected_packages")
                                 | _read_keys(toolchain, "fetch_debs"), {"note", "schema"})
    assert dead_lock == set(), f"the lock writes what nothing reads: {dead_lock}"
    assert set(DECLARED_UNREAD) & _read_keys(toolchain) <= {"name", "environment"}, \
        "a field declared unread is read after all; remove it from the declaration"


# ---------------------------------------------------------------------------
# The documents claim a trust-on-first-use ceiling and nothing stronger
# ---------------------------------------------------------------------------

def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("`", "")).lower()


def _between(text: str, start: str, end: str | None) -> str:
    chunk = text.split(start, 1)[1]
    return chunk.split(end, 1)[0] if end else chunk


def _documents() -> dict[str, str]:
    assumptions = (ROOT / "docs/requirements/ASSUMPTIONS.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    validation = (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    module = ast.get_docstring(ast.parse((INSTALLER / "build_nsis_toolchain.py").read_text(
        encoding="utf-8")))
    return {
        "A-042": _between(assumptions, "## A-042 ", "\n## A-043 "),
        "the pin file's note": PINS["note"],
        "the builder's docstring": module,
        "the README paragraph": _between(readme, "**The installer compiler is built from pinned "
                                         "source", "`--smoke` reports"),
        "the validation table": _between(validation, "## Installer compiler built from pinned "
                                         "source (A-042)", "## Requires a normal"),
        "the changelog entry": _between(changelog, "- The installer compiler is built from pinned "
                                        "source (A-042).", "\n\n"),
    }


#: What the source pin may be called, said in the words the admission fixed.
FULL_CLAIM = (
    "trust-on-first-use", "not authenticated upstream provenance",
    "no upstream cryptographic release signature is available to forge",
    "exact byte identity", "not publisher identity", "corroboration",
    "consistency checks", "not cryptographic provenance",
    "not an independent authenticated provenance channel", "fails closed",
    "new governed admission")
SHORT_CLAIM = ("trust-on-first-use", "not authenticated upstream provenance")
#: Wordings that would claim more than a pin of unauthenticated material can.
OVERCLAIMS = (
    r"(?<!not )(?<!no )\b(?:established|verified|confirmed|proven|authenticated) upstream "
    r"provenance",
    r"(?<!not )(?<!no )\b(?:established|verified|confirmed|proven) provenance",
    r"\bprovenance (?:is |was |has been |have been |are )?(?:established|verified|confirmed|proven)",
    r"\bpublisher (?:is |was |has been )?(?:verified|authenticated|established|confirmed)",
    r"\bcryptographically (?:verified|authenticated|signed)",
    r"\bsigned (?:upstream|by (?:the )?(?:upstream|nsis))",
    r"\bindependently (?:verified|authenticated)",
)


def test_the_full_claim_is_made_where_the_pin_is_stated_and_the_short_claim_elsewhere():
    documents = _documents()
    for name in ("A-042", "the pin file's note", "the builder's docstring"):
        flat = _flat(documents[name])
        for phrase in FULL_CLAIM:
            assert phrase in flat, f"{name} does not say {phrase!r}"
    for name in ("the README paragraph", "the validation table", "the changelog entry"):
        flat = _flat(documents[name])
        for phrase in SHORT_CLAIM:
            assert phrase in flat, f"{name} does not say {phrase!r}"


def _what_this_change_wrote() -> dict[str, str]:
    found = dict(_documents())
    for path in (INSTALLER / "build_nsis_toolchain.py", INSTALLER / "resolve_nsis_debs.py",
                 INSTALLER / "nsis-toolchain.json", INSTALLER / "nsis-build-debs.json",
                 INSTALLER / "nsis-smoke.nsi", INSTALLER / "build-inside.sh",
                 ROOT / ".github/workflows/ci.yml", ROOT / "tests/test_resolve_nsis_debs.py"):
        found[path.name] = path.read_text(encoding="utf-8")
    return found


def _every_document() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
            for path in sorted(ROOT.rglob("*.md"))
            if not {".git", ".nornyx", ".venv", "node_modules"} & set(path.relative_to(ROOT).parts)}


def test_nothing_that_speaks_of_the_pin_claims_authenticated_or_verified_provenance():
    for name, text in _what_this_change_wrote().items():
        flat = _flat(text)
        for pattern in OVERCLAIMS:
            assert re.search(pattern, flat) is None, f"{name} matches {pattern}"
    # Any other document may use "cryptographically verified" of something else;
    # none may use the provenance wordings.
    for name, text in _every_document().items():
        flat = _flat(text)
        for pattern in OVERCLAIMS[:4]:
            assert re.search(pattern, flat) is None, f"{name} matches {pattern}"


@pytest.mark.parametrize("sentence", [
    "The source provenance established by the SHA-256.",
    "This gives verified upstream provenance.",
    "Authenticated upstream provenance of the archive.",
    "the provenance was verified",
    "The publisher is verified by the Git tag.",
    "The archive is cryptographically verified.",
    "It is signed upstream.",
])
def test_the_overclaim_patterns_catch_the_wordings_they_exist_for(sentence):
    flat = _flat(sentence)
    assert any(re.search(pattern, flat) for pattern in OVERCLAIMS), sentence


@pytest.mark.parametrize("sentence", [
    "a trust-on-first-use ceiling, not authenticated upstream provenance",
    "it is not an independent authenticated provenance channel",
    "no upstream cryptographic release signature is available to Forge",
    "Not established: who published the source",
])
def test_the_overclaim_patterns_let_the_admitted_wording_through(sentence):
    flat = _flat(sentence)
    assert not any(re.search(pattern, flat) for pattern in OVERCLAIMS), sentence


def test_the_documents_name_what_is_not_established_and_agree_with_the_pins_numbers():
    text = _documents()["A-042"]
    flat = _flat(text)
    assert "not established" in flat and "another distribution" in flat
    assert "who published the source" in flat and "not publisher identity" in flat
    comparison = PINS["source"]["git"]["comparison"]
    assert f"of the 836 files in the archive {comparison['identical']} are byte-identical" in flat
    assert f"{comparison['crlf_only']} differ only by crlf" in flat
    assert f"({PINS['source']['size']:,})" in text
    assert f"({len(LOCK['packages'])} over {len(LOCK['base'])})" in text
    assert f"over {len(LOCK['packages'])} packages" in _documents()["the changelog entry"]
    assert f"chose exactly the same {len(LOCK['packages'])} packages" in flat
    assert "A-042" in _documents()["the README paragraph"]


def test_the_closure_gate_names_every_nsis_job_that_is_per_commit_evidence_and_not_the_dispatch_only_one():
    contract = (ROOT / "docs" / "governance" / "RELEASE_CONTRACT_V1.md").read_text(encoding="utf-8")
    gate = contract.split("\n## The closure gate\n", 1)[1].split("\n## ", 1)[0]
    lines = re.findall(r"Remote CI \(([^)]*)\)", gate)
    assert len(lines) == 1
    names = {item.strip() for item in lines[0].split(",")}
    assert set(JOBS) <= names, sorted(set(JOBS) - names)
    assert CORROBORATION not in names
    # A build that fails or is cancelled must fail the gate: the jobs that need
    # another are named with the one they need, because a job whose needed job
    # fails is skipped, not failed.
    for job in JOBS:
        needs = WORKFLOW["jobs"][job].get("needs") or []
        assert set([needs] if isinstance(needs, str) else needs) <= names, job
        assert "if" not in WORKFLOW["jobs"][job] and "continue-on-error" not in WORKFLOW["jobs"][job]
    assert WORKFLOW["jobs"][CORROBORATION]["if"] == "github.event_name == 'workflow_dispatch'"


def test_the_boundary_touch_is_named_with_the_measurement_that_no_existing_digest_changes():
    text = _documents()["A-042"]
    flat = _flat(text)
    assert "boundary touch: the canonical text rule" in flat
    assert "git ls-tree -r --name-only 0a274a7 | grep -c -i -e" in flat
    assert "none of the 342 tracked paths" in flat and "no existing digest changes" in flat
    assert "architecture.canonical_text_rule" in text
    assert "architecture.canonical_text_rule" in _documents()["the changelog entry"]
    assert "CANONICAL_TEXT_SUFFIXES" in _documents()["the changelog entry"]


_CITATION = re.compile(r"`(?:(tests/[\w/]+\.py)::)?(test_\w+)`")


def _defined_tests() -> dict[str, set[str]]:
    found = {}
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        found[f"tests/{path.name}"] = set(re.findall(
            r"^def (test_\w+)\(", path.read_text(encoding="utf-8"), re.M))
    return found


def test_every_test_a_document_cites_for_this_change_exists_where_it_is_said_to_be():
    """The validation table and A-042 cite tests by bare name or as `path::name`. A
    bare name must be defined in one of the two new modules; a path must be a module
    that defines that name. A name that exists nowhere, or only in another module,
    is false evidence."""
    defined = _defined_tests()
    mine = defined["tests/test_nsis_toolchain.py"] | defined["tests/test_resolve_nsis_debs.py"]
    for name in ("the validation table", "A-042"):
        text = _documents()[name]
        cited = _CITATION.findall(text)
        assert name != "the validation table" or cited, "the table cites no test at all"
        for path, test in cited:
            if path:
                assert test in defined.get(path, set()), f"{name}: {path}::{test} does not exist"
            else:
                assert test in mine, f"{name} cites {test}, which neither new module defines"


@pytest.mark.parametrize(("pieces", "expected"), [
    (("", "test_alpha"), [("", "test_alpha")]),
    (("tests/test_x.py::", "test_alpha"), [("tests/test_x.py", "test_alpha")]),
])
def test_the_citation_pattern_reads_both_spellings(pieces, expected):
    # Assembled here so that this file does not itself cite a test by name.
    text = "see " + "`" + "".join(pieces) + "`"
    assert _CITATION.findall(text) == expected


# ---------------------------------------------------------------------------
# Gaps a mutation sweep found
# ---------------------------------------------------------------------------

def test_a_package_of_the_locked_size_but_other_bytes_is_refused_when_no_md5_is_pinned(tmp_path):
    served = b"X" + DATA[1:]
    with pytest.raises(tc.ToolchainError, match="SHA-256"):
        tc.fetch_verified(["https://a/x"], size=GOOD["size"], sha256=GOOD["sha256"], md5=None,
                          dest=tmp_path / "f", opener=_opener({"https://a/x": served}))
    assert not (tmp_path / "f").exists()


def test_a_relative_mount_is_refused_because_docker_would_take_it_for_a_volume():
    with pytest.raises(tc.ToolchainError, match="not absolute"):
        tc.docker_argv(PINS, debs=Path("debs"), src=Path("/w/src"), out=Path("/w/out"),
                       expected=Path("/w/e.txt"))
    with pytest.raises(tc.ToolchainError, match="not absolute"):
        tc.docker_argv(PINS, debs=Path("/w/debs"), src=Path("/w/src"), out=Path("/w/out"),
                       expected=Path("/w/e.txt"), script=Path("build-inside.sh"))


def test_the_container_cannot_gain_privileges():
    argv = _argv()
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--user") + 1] == "0", "root inside the container is what dpkg needs"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    added = [argv[i + 1] for i, value in enumerate(argv) if value == "--cap-add"]
    assert added == list(tc.BUILD_CAPABILITIES), "only what dpkg needs is added back"
    assert not {"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "MKNOD"} & set(added)


def test_a_named_container_can_be_killed_and_a_build_that_times_out_is_killed(tmp_path):
    assert "--name" not in _argv()
    argv = tc.docker_argv(PINS, debs=Path("/w/debs"), src=Path("/w/src"), out=Path("/w/out"),
                          expected=Path("/w/e.txt"), name="nsis-build-7")
    assert argv[argv.index("--name") + 1] == "nsis-build-7"
    calls = []

    def slow(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(command, 1)
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(tc.ToolchainError, match="killed"):
        tc.build(PINS, tmp_path / "w", tmp_path / "out", run=slow)
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "kill", name]


def test_the_package_list_is_sorted_by_the_script_before_it_is_compared(tmp_path):
    shuffled = "newpkg all 2 ii \nbase amd64 1 ii \n"
    result = _Sandbox(tmp_path, installed=shuffled, expected=EXPECTED).run()
    assert result.returncode == 0, result.stderr


#: The values this pin set was admitted with. Changing any of them is a change to
#: the pinned source, its metadata or the build environment, which needs a new
#: governed admission of the pins and is meant to cost an edit here as well.
ADMITTED = {
    "source.sha256": "a8ffe024602d46b6d766f9e1ce30c324ad2a24daeacd3efc2642d436a0c157ac",
    "source.size": 1819771,
    "source.md5": "3f992d176c50fb653cf0230eed38cfea",
    "source.url": "https://downloads.sourceforge.net/project/nsis/NSIS%203/3.13/"
                  "nsis-3.13-src.tar.bz2",
    "git.tag_object": "3255586f67626dd397760cd7a68daa9847284020",
    "git.commit": "a4ba28e60bd9e7c271cd2bfc1558889ce3355653",
    "git.tree": "47846c554e07eb21197179b01a48a0d27f618723",
    "container.image": "ubuntu@sha256:"
                       "f610ab94648195aa356059f5b41d6085c9d4d903c072430cdd1af7bdb646106b",
    "container.snapshot": "20261002T000000Z",
    "source.version": "3.13",
    "source.root": "nsis-3.13-src",
    "source.fallback_urls": [
        "https://cfhcable.dl.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13-src.tar.bz2",
        "https://pilotfiber.dl.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13-src.tar.bz2"],
    "git.repository": "nsis-dev/nsis",
    "git.tag": "v313",
    "git.commit_time": "2026-09-27T15:24:32Z",
    "container.install": ["binutils-mingw-w64-i686", "g++", "g++-mingw-w64-i686-win32", "gcc",
                          "gcc-mingw-w64-i686-win32", "mingw-w64-i686-dev", "python3", "scons",
                          "zlib1g-dev"],
    "build.scons_args": [
        "VERSION=3.13", "VER_MAJOR=3", "VER_MINOR=13", "VER_REVISION=0", "VER_BUILD=0",
        "TARGET_ARCH=x86", "UNICODE=yes", "XGCC_W32_PREFIX=i686-w64-mingw32-",
        "NSIS_CONFIG_CONST_DATA_PATH=no", "PREFIX=/out/nsis", "PREFIX_BIN=/out/nsis/Bin",
        "SKIPUTILS=Library/RegTool,MakeLangId,Makensisw,NSIS Menu,SubStart,VPatch/Source/GenPat,"
        "zip2exe", "SKIPDOC=all", "install-compiler", "install-conf", "install-data",
        "install-utils"],
    "build.epoch": 1790522672,
    "outputs": {
        "makensis_sha256": "7c345d2f0172ec3e84025ca3dc511235e06629c0e241fbf503f8144af2563597",
        "data_tree_sha256": "0d012c89739c075d780a12bbfe105bfa3873a5ae63699b44f974b2ef96f6e62d"},
}
#: SHA-256 of what the lock says a build trusts (see `_lock_digest`).
ADMITTED_LOCK = "426558bbc2a932cb85c9ff0d80bba20497e45e04b744e0fc59c3d333609a979a"


def test_the_pins_are_the_values_they_were_admitted_with():
    source, git = PINS["source"], PINS["source"]["git"]
    found = {
        "source.sha256": source["sha256"], "source.size": source["size"],
        "source.md5": source["md5"], "source.url": source["url"],
        "source.version": source["version"], "source.root": source["root"],
        "source.fallback_urls": source["fallback_urls"],
        "git.repository": git["repository"], "git.tag": git["tag"],
        "git.tag_object": git["tag_object"], "git.commit": git["commit"],
        "git.commit_time": git["commit_time"], "git.tree": git["tree"],
        "container.image": PINS["container"]["image"],
        "container.snapshot": PINS["container"]["snapshot"],
        "container.install": PINS["container"]["install"],
        "build.scons_args": PINS["build"]["scons_args"],
        "build.epoch": PINS["build"]["source_date_epoch"],
        "outputs": PINS["outputs"],
    }
    assert found == ADMITTED


def _lock_digest(lock: dict) -> str:
    """Everything in the lock a build trusts: the packages with their sizes, hashes
    and URLs, what the image holds, what was asked for, and the signed indexes."""
    lines = [f"{p['name']} {p['version']} {p['size']} {p['sha256']} {p['url']}\n"
             for p in lock["packages"]]
    lines += [f"base {row}\n" for row in lock["base"]]
    lines += [f"install {name}\n" for name in lock["install"]]
    lines += [f"signed {suite} {json.dumps(lock['signed_indexes'][suite], sort_keys=True)}\n"
              for suite in sorted(lock["signed_indexes"])]
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def test_the_lock_is_the_package_set_it_was_admitted_with():
    assert _lock_digest(LOCK) == ADMITTED_LOCK
    changed = _lock()
    changed["packages"][0]["sha256"] = "0" * 64
    assert _lock_digest(changed) != ADMITTED_LOCK


# ---------------------------------------------------------------------------
# The command line and the fetch step as a whole
# ---------------------------------------------------------------------------

def test_the_fetch_step_verifies_the_archive_unpacks_it_and_writes_the_expected_list(
        tmp_path, monkeypatch):
    asked = {}

    def fake_fetch(urls, *, size, sha256, md5, dest, **kwargs):
        asked.update(urls=urls, size=size, sha256=sha256, md5=md5)
        _tar(dest, GOOD_ENTRIES)
        return urls[0]

    def fake_debs(lock, dest, **kwargs):
        dest.mkdir()
        (dest / "a.deb").write_bytes(b"x")
        return ["a.deb"]

    monkeypatch.setattr(tc, "fetch_verified", fake_fetch)
    monkeypatch.setattr(tc, "fetch_debs", fake_debs)
    tc.fetch_inputs(PINS, LOCK, tmp_path / "work")
    source = PINS["source"]
    assert asked == {"urls": [source["url"], *source["fallback_urls"]], "size": source["size"],
                     "sha256": source["sha256"], "md5": source["md5"]}
    assert (tmp_path / "work" / "src" / ROOT_DIR / "sub" / "a.txt").read_bytes() == b"alpha\r\n"
    assert (tmp_path / "work" / "expected-packages.txt").read_text(encoding="utf-8") == (
        "\n".join(tc.expected_packages(LOCK)) + "\n")
    assert (tmp_path / "work" / "debs" / "a.deb").exists()


@pytest.mark.parametrize("error", [
    OSError("no route"), IndexError("empty"), KeyError("object"), tarfile.ReadError("bad archive"),
    http.client.IncompleteRead(b"x"), subprocess.TimeoutExpired("docker", 1)])
def test_an_input_that_cannot_be_read_is_a_refusal_not_a_traceback(monkeypatch, capsys, error):
    def unreachable(pins):
        raise error

    monkeypatch.setattr(tc, "against_tag", unreachable)
    assert tc.main(["against-tag"]) == 1
    assert "could not read what it needs" in capsys.readouterr().err


def test_the_check_command_validates_the_pins_and_says_how_many_packages_it_locked(capsys):
    assert tc.main(["check"]) == 0
    assert f"{len(LOCK['packages'])} packages locked" in capsys.readouterr().out


def test_the_describe_command_copies_the_output_and_writes_the_description(tmp_path, capsys):
    out = _container_output(tmp_path)
    assert tc.main(["describe", "--from", str(out), "--to", str(tmp_path / "x" / "artifact")]) == 0
    written = json.loads((tmp_path / "x" / "artifact" / "files.json").read_text(encoding="utf-8"))
    assert written == tc.describe_tree(out / "nsis")
    assert written["makensis_sha256"] in capsys.readouterr().out
    (out / "extra-link").symlink_to(tmp_path)
    assert tc.main(["describe", "--from", str(out), "--to", str(tmp_path / "y")]) == 1
    assert not (tmp_path / "y").exists()


def test_the_verify_command_exits_non_zero_for_legs_that_are_not_the_pinned_outputs(
        tmp_path, capsys):
    a, b = _leg(tmp_path, "a"), _leg(tmp_path, "b")
    assert tc.main(["verify", "--a", str(a), "--b", str(b)]) == 1
    error = capsys.readouterr().err
    assert error.startswith("toolchain refused: ") and _measured(a)["makensis_sha256"] in error
    c = _leg(tmp_path, "c", {**FILES, "Include/a.nsh": b"different"})
    assert tc.main(["verify", "--a", str(a), "--b", str(c)]) == 1
    assert "Include/a.nsh: bytes differ" in capsys.readouterr().err


def test_the_check_tree_command_exits_non_zero_while_unpinned_unless_told_and_for_a_wrong_tree(
        tmp_path, capsys):
    tree = _tree(tmp_path / "t", FILES)
    code = tc.main(["check-tree", "--tree", str(tree)])
    output = capsys.readouterr()
    assert code == 1 and "not pinned" in output.err + output.out or PINS["outputs"] is not None
    if PINS["outputs"] is None:
        assert tc.main(["check-tree", "--allow-unpinned", "--tree", str(tree)]) == 0
        assert "UNPINNED" in capsys.readouterr().out
    else:
        assert code == 1 and "not the pinned one" in output.err
        assert tc.main(["check-tree", "--allow-unpinned", "--tree", str(tree)]) == 1
