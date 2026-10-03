"""The tool that wrote the NSIS build-package lock, and the lock it wrote.

`resolve_nsis_debs.py` is not `apt`. It reads the same signed indexes and
applies the same rules for the cases the closure meets, so the lock it writes is
a candidate that the install inside the container must confirm. These tests pin
the parts a wrong answer would hide in: Debian's version order, the relationship
grammar, the closure (what is chosen, what is left to the image, what is
refused as ambiguous), and the signed chain from `InRelease` to a package's
hash. The lock itself is read back and checked against the pins that name it.

The version order is compared with a table, not with the host's `dpkg`: the
table was produced by `dpkg --compare-versions` and is kept so the test needs
no Debian tool.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "windows_installer"))

import resolve_nsis_debs as rd  # noqa: E402


def _stanza(name, version, depends="", *, provides="", breaks="", conflicts="", arch="amd64"):
    stanza = {"Package": name, "Version": version, "Architecture": arch,
              "Filename": f"pool/main/{name[0]}/{name}/{name}_{version}_{arch}.deb",
              "Size": "100", "SHA256": hashlib.sha256(f"{name}{version}".encode()).hexdigest()}
    for key, value in (("Depends", depends), ("Provides", provides), ("Breaks", breaks),
                       ("Conflicts", conflicts)):
        if value:
            stanza[key] = value
    return stanza


def _installed(*stanzas):
    return {s["Package"]: dict(s, Status="install ok installed") for s in stanzas}


# ---------------------------------------------------------------------------
# Debian's version order
# ---------------------------------------------------------------------------

#: (left, right, sign of left - right), from `dpkg --compare-versions`.
VERSION_TABLE = [
    ("1.0", "1.0-1", -1), ("1.0~rc1", "1.0", -1), ("1.0~rc1-1", "1.0-1", -1),
    ("1:0.9", "2.0", 1), ("0:1.0", "1.0", 0), ("2.39-0ubuntu8.5", "2.39-0ubuntu8.10", -1),
    ("9.2", "9.10", -1), ("1.0a", "1.0", 1), ("1.0.1", "1.0", 1), ("10", "9", 1),
    ("13.3.0-6ubuntu2~24.04", "13.3.0-6ubuntu2~24.04.1", -1),
    ("1.2.3-1ubuntu1+b1", "1.2.3-1ubuntu1", 1), ("1.2.3-1ubuntu1~24.04.2", "1.2.3-1ubuntu1", -1),
    ("1.0-1.1", "1.0-1", 1), ("2.41.90.20240122-1ubuntu1+11.4", "2.41.90.20240122-1ubuntu1", 1),
    ("1:1.3.dfsg-3.1ubuntu2.2", "1:1.3.dfsg-3.1ubuntu2", 1),
]


@pytest.mark.parametrize(("left", "right", "sign"), VERSION_TABLE)
def test_versions_order_as_dpkg_orders_them(left, right, sign):
    result = rd.compare_versions(left, right)
    assert (result > 0) - (result < 0) == sign
    flipped = rd.compare_versions(right, left)
    assert (flipped > 0) - (flipped < 0) == -sign


# ---------------------------------------------------------------------------
# The relationship grammar
# ---------------------------------------------------------------------------

def test_a_relationship_field_parses_into_groups_of_alternatives():
    groups = rd.parse_relation("libc6 (>= 2.38), libgcc-s1:any, a | b (<< 2.0)\n , c (= 1:3)")
    assert groups == [[("libc6", ">=", "2.38")], [("libgcc-s1", None, None)],
                      [("a", None, None), ("b", "<<", "2.0")], [("c", "=", "1:3")]]


@pytest.mark.parametrize("field", ["foo [amd64]", "foo <!nocheck>", "foo (>= 1) [linux-any]",
                                   "Foo", "foo (!! 1)"])
def test_a_restriction_this_tool_does_not_read_is_refused_not_ignored(field):
    with pytest.raises(rd.ResolveError):
        rd.parse_relation(field)


def test_the_deprecated_single_angle_operators_are_read_not_taken_for_restrictions():
    assert rd.parse_relation("foo (< 2), bar (> 1)") == [[("foo", "<", "2")], [("bar", ">", "1")]]


def test_a_package_meets_a_dependency_by_name_or_by_what_it_provides():
    plain = _stanza("libfoo", "2.0")
    virtual = _stanza("foo-impl", "1.0", provides="foo-api (= 3), other")
    assert rd.satisfied_by(("libfoo", ">=", "1.0"), plain)
    assert not rd.satisfied_by(("libfoo", ">=", "3.0"), plain)
    assert rd.satisfied_by(("foo-api", None, None), virtual)
    assert rd.satisfied_by(("foo-api", "=", "3"), virtual)
    assert not rd.satisfied_by(("foo-api", ">=", "4"), virtual)
    assert rd.satisfied_by(("other", None, None), virtual)
    assert not rd.satisfied_by(("other", ">=", "1"), virtual), "an unversioned provide meets no version"


def test_control_paragraphs_join_continuation_lines_and_refuse_a_stray_one():
    text = "Package: a\nDepends: b,\n c\n\nPackage: d\nVersion: 1\n"
    assert rd.parse_stanzas(text) == [{"Package": "a", "Depends": "b,\nc"},
                                      {"Package": "d", "Version": "1"}]
    with pytest.raises(rd.ResolveError):
        rd.parse_stanzas(" orphan continuation\n")
    with pytest.raises(rd.ResolveError):
        rd.parse_stanzas("not a field\n")


# ---------------------------------------------------------------------------
# The closure
# ---------------------------------------------------------------------------

def test_the_closure_adds_what_the_image_lacks_and_leaves_what_it_holds():
    archive = rd.Archive([_stanza("app", "1", "lib (>= 1), base-thing"), _stanza("lib", "2"),
                          _stanza("base-thing", "9")])
    installed = _installed(_stanza("base-thing", "9"))
    chosen = rd.resolve(archive, installed, ["app"])
    assert sorted(chosen) == ["app", "lib"], "base-thing is already in the image at a good version"


def test_a_requested_package_already_installed_at_the_same_version_is_not_added_again():
    archive = rd.Archive([_stanza("tool", "1")])
    assert rd.resolve(archive, _installed(_stanza("tool", "1")), ["tool"]) == {}


def test_a_dependency_the_image_cannot_meet_upgrades_the_image_package():
    archive = rd.Archive([_stanza("app", "1", "libc (>= 2.5)"), _stanza("libc", "2.5"),
                          _stanza("libc", "2.1")])
    chosen = rd.resolve(archive, _installed(_stanza("libc", "2.1")), ["app"])
    assert chosen["libc"]["Version"] == "2.5"


def test_an_upgrade_that_breaks_a_pinned_sibling_pulls_the_sibling_along():
    archive = rd.Archive([
        _stanza("app", "1", "libx (>= 2)"), _stanza("libx", "2", "libx-base (= 2)"),
        _stanza("libx-base", "2"), _stanza("libx-base", "1")])
    installed = _installed(_stanza("libx", "1", "libx-base (= 1)"), _stanza("libx-base", "1"))
    chosen = rd.resolve(archive, installed, ["app"])
    assert chosen["libx"]["Version"] == "2" and chosen["libx-base"]["Version"] == "2"


def test_the_first_alternative_the_snapshot_offers_is_taken_when_none_is_installed():
    archive = rd.Archive([_stanza("app", "1", "first | second"), _stanza("second", "1")])
    assert sorted(rd.resolve(archive, {}, ["app"])) == ["app", "second"]
    archive = rd.Archive([_stanza("app", "1", "first | second"), _stanza("first", "1"),
                          _stanza("second", "1")])
    assert sorted(rd.resolve(archive, {}, ["app"])) == ["app", "first"]


def test_a_requested_alternative_meets_the_group_so_the_other_is_not_pulled_in():
    archive = rd.Archive([_stanza("meta", "1", "gcc-posix | gcc-win32"), _stanza("gcc-posix", "1"),
                          _stanza("gcc-win32", "1")])
    chosen = rd.resolve(archive, {}, ["gcc-win32", "meta"])
    assert sorted(chosen) == ["gcc-win32", "meta"], "the win32 variant was asked for by name"


def test_a_virtual_package_with_one_provider_is_resolved_and_with_several_is_refused():
    one = rd.Archive([_stanza("app", "1", "mail-agent"),
                      _stanza("postfix", "1", provides="mail-agent")])
    assert sorted(rd.resolve(one, {}, ["app"])) == ["app", "postfix"]
    two = rd.Archive([_stanza("app", "1", "mail-agent"),
                      _stanza("postfix", "1", provides="mail-agent"),
                      _stanza("exim", "1", provides="mail-agent")])
    with pytest.raises(rd.ResolveError, match="exim.*postfix|name one"):
        rd.resolve(two, {}, ["app"])


def test_a_dependency_the_snapshot_does_not_offer_is_refused_by_name():
    archive = rd.Archive([_stanza("app", "1", "ghost (>= 1)")])
    with pytest.raises(rd.ResolveError, match="ghost"):
        rd.resolve(archive, {}, ["app"])
    with pytest.raises(rd.ResolveError, match="no package named missing"):
        rd.resolve(archive, {}, ["missing"])


def test_a_closure_that_breaks_or_conflicts_is_refused():
    archive = rd.Archive([_stanza("app", "1", "lib"), _stanza("lib", "1", breaks="old (<< 2)")])
    with pytest.raises(rd.ResolveError, match="breaks old"):
        rd.resolve(archive, _installed(_stanza("old", "1")), ["app"])
    archive = rd.Archive([_stanza("app", "1", "lib"), _stanza("lib", "1", conflicts="other")])
    with pytest.raises(rd.ResolveError, match="conflicts other"):
        rd.resolve(archive, _installed(_stanza("other", "5")), ["app"])
    archive = rd.Archive([_stanza("app", "1", "lib"), _stanza("lib", "1", breaks="old (<< 2)")])
    assert "lib" in rd.resolve(archive, _installed(_stanza("old", "2")), ["app"]), \
        "a Breaks on versions the image does not hold is not a conflict"


def test_two_listings_of_one_version_with_different_hashes_are_refused():
    first, second = _stanza("a", "1"), _stanza("a", "1")
    second["SHA256"] = "0" * 64
    with pytest.raises(rd.ResolveError, match="two different SHA-256"):
        rd.Archive([first, second])


def test_the_highest_version_wins_and_the_status_file_reads_only_installed_packages():
    archive = rd.Archive([_stanza("a", "1.0"), _stanza("a", "1.10"), _stanza("a", "1.9")])
    assert archive.best(("a", None, None))["Version"] == "1.10"
    assert archive.best(("a", "<<", "1.10"))["Version"] == "1.9"
    status = ("Package: kept\nVersion: 1\nStatus: install ok installed\n\n"
              "Package: gone\nVersion: 1\nStatus: deinstall ok config-files\n")
    assert list(rd.installed_from_status(status)) == ["kept"]


# ---------------------------------------------------------------------------
# The signed chain
# ---------------------------------------------------------------------------

RELEASE = """Origin: Ubuntu
SHA256:
 aa11 12 main/binary-amd64/Packages.xz
 bb22 7 universe/binary-amd64/Packages.xz
Acquire-By-Hash: yes
"""


def test_the_release_file_hash_section_is_read_and_a_missing_one_refused():
    assert rd.release_hashes(RELEASE) == {"main/binary-amd64/Packages.xz": (12, "aa11"),
                                          "universe/binary-amd64/Packages.xz": (7, "bb22")}
    with pytest.raises(rd.ResolveError):
        rd.release_hashes("Origin: Ubuntu\nMD5Sum:\n x 1 y\n")


def test_an_index_is_refused_unless_the_signed_list_states_this_size_and_hash():
    data = b"index bytes"
    listed = {"main/binary-amd64/Packages.xz": (len(data), hashlib.sha256(data).hexdigest())}
    name = "main/binary-amd64/Packages.xz"
    assert rd.checked_index(data, name, listed) == data
    with pytest.raises(rd.ResolveError):
        rd.checked_index(data + b"x", name, listed)
    with pytest.raises(rd.ResolveError):
        rd.checked_index(b"index byteS", name, listed)
    with pytest.raises(rd.ResolveError):
        rd.checked_index(data, "main/binary-arm64/Packages.xz", listed)


STATUS = ("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 871920D1991BC93C Ubuntu\n"
          "[GNUPG:] VALIDSIG F6ECB3762474EDA9D21B7022871920D1991BC93C 2026-10-01 1 0 4 0 1 10 01 "
          "F6ECB3762474EDA9D21B7022871920D1991BC93C\n")


def _gpgv_stub(tmp_path: Path, *, code: int, status: str, body: str) -> list[str]:
    stub = tmp_path / "gpgv_stub.py"
    stub.write_text(
        "import sys\n"
        "import os\n"
        "os.write(int(sys.argv[sys.argv.index('--status-fd') + 1]), "
        f"{status!r}.encode())\n"
        f"sys.stdout.write({body!r})\nsys.stderr.write('gpgv: human-readable text\\n')\n"
        f"sys.exit({code})\n",
        encoding="utf-8")
    return [sys.executable, str(stub)]


def test_a_valid_archive_signature_returns_the_cleartext(tmp_path):
    stub = _gpgv_stub(tmp_path, code=0, status=STATUS, body=RELEASE)
    assert rd.verify_inrelease(tmp_path / "InRelease", tmp_path / "keyring", stub) == RELEASE
    assert rd.parse_gpgv_status(STATUS) == {"F6ECB3762474EDA9D21B7022871920D1991BC93C"}


def test_a_signature_gpgv_refuses_or_a_key_that_is_not_the_archives_is_refused(tmp_path):
    refused = _gpgv_stub(tmp_path, code=2, status="gpgv: BAD signature", body="")
    with pytest.raises(rd.ResolveError, match="refused"):
        rd.verify_inrelease(tmp_path / "InRelease", tmp_path / "keyring", refused)
    stranger = STATUS.replace("F6ECB3762474EDA9D21B7022871920D1991BC93C",
                              "0123456789ABCDEF0123456789ABCDEF01234567")
    wrong_key = _gpgv_stub(tmp_path, code=0, status=stranger, body=RELEASE)
    with pytest.raises(rd.ResolveError, match="not all Ubuntu archive keys"):
        rd.verify_inrelease(tmp_path / "InRelease", tmp_path / "keyring", wrong_key)
    no_signature = _gpgv_stub(tmp_path, code=0, status="", body=RELEASE)
    with pytest.raises(rd.ResolveError, match="not all Ubuntu archive keys"):
        rd.verify_inrelease(tmp_path / "InRelease", tmp_path / "keyring", no_signature)


# ---------------------------------------------------------------------------
# The lock
# ---------------------------------------------------------------------------

def test_a_deprecated_strict_looking_operator_means_what_dpkg_says():
    """dpkg reads `<` as `<=` and `>` as `>=`; only `<<` and `>>` are strict."""
    package = _stanza("x", "2")
    assert rd.satisfied_by(("x", "<", "2"), package) and rd.satisfied_by(("x", ">", "2"), package)
    assert not rd.satisfied_by(("x", "<<", "2"), package)
    assert not rd.satisfied_by(("x", ">>", "2"), package)
    assert rd.satisfied_by(("x", "<", "3"), package) and not rd.satisfied_by(("x", ">", "3"), package)


RELEASE_FILE = ("Origin: Ubuntu\nSuite: noble-updates\nCodename: noble\n"
                "Date: Thu, 01 Oct 2026 22:07:47 UTC\n")


def test_a_signed_release_file_must_be_for_the_suite_and_codename_asked_for_and_not_after_the_snapshot():
    ask = dict(suite="noble-updates", codename="noble", snapshot="20261002T000000Z")
    assert rd.check_release_identity(RELEASE_FILE, **ask) == "Thu, 01 Oct 2026 22:07:47 UTC"
    for text, words in ((RELEASE_FILE.replace("Suite: noble-updates", "Suite: noble-security"),
                         "not 'noble-updates'"),
                        (RELEASE_FILE.replace("Codename: noble", "Codename: jammy"), "jammy"),
                        (RELEASE_FILE.replace("Thu, 01 Oct 2026", "Sat, 03 Oct 2026"), "after the snapshot"),
                        (RELEASE_FILE.replace("Date: Thu, 01 Oct 2026 22:07:47 UTC\n", ""), "no readable Date"),
                        (RELEASE_FILE.replace("22:07:47 UTC", "not a time"), "no readable Date")):
        with pytest.raises(rd.ResolveError, match=words):
            rd.check_release_identity(text, **ask)


def test_the_archive_fetch_records_the_signed_chain_it_used(tmp_path, monkeypatch):
    import lzma

    index = lzma.compress(b"Package: a\nVersion: 1\nArchitecture: amd64\n\n")
    listing = ("SHA256:\n " + hashlib.sha256(index).hexdigest() + f" {len(index)} "
               "main/binary-amd64/Packages.xz\n")
    release = RELEASE_FILE.replace("noble-updates", "noble") + listing

    def fake_get(url, limit=1 << 28):
        return index if url.endswith("Packages.xz") else release.encode()

    monkeypatch.setattr(rd, "_get", fake_get)
    monkeypatch.setattr(rd, "verify_inrelease", lambda path, keyring, gpgv=None: release)
    archive, record = rd.fetch_archive("20261002T000000Z", ["noble"], ["main"], tmp_path / "k",
                                       tmp_path)
    assert sorted(archive.versions) == ["a"]
    assert record == {"noble": {
        "inrelease_sha256": hashlib.sha256(release.encode()).hexdigest(),
        "date": "Thu, 01 Oct 2026 22:07:47 UTC",
        "indexes": {"main/binary-amd64/Packages.xz": {
            "size": len(index), "sha256": hashlib.sha256(index).hexdigest()}}}}
    monkeypatch.setattr(rd, "verify_inrelease",
                        lambda path, keyring, gpgv=None: release.replace("Suite: noble", "Suite: x"))
    with pytest.raises(rd.ResolveError, match="not 'noble'"):
        rd.fetch_archive("20261002T000000Z", ["noble"], ["main"], tmp_path / "k", tmp_path)


def test_a_registry_answer_larger_than_its_bound_is_refused(monkeypatch):
    class Big:
        def __init__(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, amount=-1):
            return self.data[:amount]

    answers = iter([b'{"token": "t"}', b"x" * ((1 << 20) + 5)])
    monkeypatch.setattr(rd, "_get", lambda url, limit=0: next(answers))
    monkeypatch.setattr(rd.urllib.request, "urlopen", lambda request, timeout: Big(b"x" * ((1 << 20) + 5)))
    with pytest.raises(rd.ResolveError, match="larger than"):
        rd.fetch_image_status("ubuntu@sha256:" + "a" * 64)


def test_the_lock_carries_the_signed_chain_it_was_made_from():
    pins = {"container": {"image": "ubuntu@sha256:" + "a" * 64, "snapshot": "20260101T000000Z",
                          "install": ["app"]}}
    signed = {"noble": {"inrelease_sha256": "b" * 64, "date": "x", "indexes": {}}}
    assert rd.build_lock(pins, {}, {}, signed)["signed_indexes"] == signed
    assert rd.build_lock(pins, {}, {})["signed_indexes"] == {}


def test_the_lock_names_each_chosen_package_with_the_index_size_and_hash():
    pins = {"container": {"image": "ubuntu@sha256:" + "a" * 64, "snapshot": "20260101T000000Z",
                          "install": ["app"]}}
    chosen = {"app": _stanza("app", "1.2")}
    chosen["app"]["Size"] = "4242"
    lock = rd.build_lock(pins, chosen, _installed(_stanza("zed", "1", arch="all"),
                                                 _stanza("alpha", "2")))
    assert lock["base"] == ["alpha amd64 2", "zed all 1"], "sorted, one string per package"
    assert lock["packages"] == [{
        "name": "app", "architecture": "amd64", "version": "1.2", "size": 4242,
        "url": "https://snapshot.ubuntu.com/ubuntu/20260101T000000Z/pool/main/a/app/app_1.2_amd64.deb",
        "sha256": chosen["app"]["SHA256"]}]
    assert lock["install"] == ["app"] and lock["snapshot"] == "20260101T000000Z"


def test_the_lock_lists_packages_in_name_order_whatever_order_they_were_chosen_in():
    pins = {"container": {"image": "ubuntu@sha256:" + "a" * 64, "snapshot": "20260101T000000Z",
                          "install": ["b"]}}
    chosen = {"zeta": _stanza("zeta", "1"), "alpha": _stanza("alpha", "1"), "mid": _stanza("mid", "1")}
    lock = rd.build_lock(pins, chosen, {})
    assert [p["name"] for p in lock["packages"]] == ["alpha", "mid", "zeta"]


def test_the_committed_lock_is_the_shape_the_resolver_writes():
    lock = json.loads((ROOT / "scripts/windows_installer/nsis-build-debs.json").read_text(
        encoding="utf-8"))
    names = [package["name"] for package in lock["packages"]]
    assert names == sorted(names) and len(names) == len(set(names))
    assert lock["base"] == sorted(lock["base"])
    assert lock["schema"] == rd.LOCK_SCHEMA and lock["note"] == rd.LOCK_NOTE
    assert set(lock) == {"schema", "note", "image", "snapshot", "install", "signed_indexes",
                         "base", "packages"}
    for package in lock["packages"]:
        assert package["architecture"] in ("amd64", "all")
        assert package["url"].endswith(f"_{package['architecture']}.deb")
