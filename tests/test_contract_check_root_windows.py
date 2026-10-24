"""The governance check's configured scratch root, judged on Windows (A-054).

`trusted_contract_check(..., scratch_root=...)` places the private snapshot
of the generated contract under a root Forge names explicitly instead of the
inherited `%TEMP%`. On Windows the root is accepted only when its owner is
this process's TokenUser or TokenOwner and its DACL is protected and grants
to nothing but SYSTEM, Administrators and that owner; anything else, and any
failure to read the owner, the DACL or the token, is `not_run` with no child
started. These are properties of Windows security descriptors, so every test
that reads one runs only on Windows; off Windows each is a declared skip in
the census, and the windows-runtime CI job runs this module and refuses a
skip. One test runs everywhere: the decision over synthesised reads, which
is the same code on every platform.

These tests show the root's checks, not isolation. A configured root can
protect against OTHER principals under these access conditions and does not
protect against the same principal; whether a provider's principal can write,
rename or plant in it is measured outside Forge, not here -- every process in these
tests runs as one user. Codex P1 4356060742 stays OPEN.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from nornyx_forge import gates as gate_module
from nornyx_forge.contract_generator import generate_brd_contract
from nornyx_forge.requirements import parse_brd

windows_only = pytest.mark.skipif(sys.platform != "win32",
                                  reason="Windows security descriptors are the subject")

BRD = (
    "# Business Requirements\n\n"
    "## BRD-001 Purpose\n\nKeep a list of support cases.\n\n"
    "## BRD-002 Functional requirements\n\n"
    "### BRD-F-001 Open a case\n\nA support agent opens a case with a title.\n"
)
SYSTEM, ADMINISTRATORS, USERS = "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"


def _project(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "project"
    root.mkdir()
    (root / "BRD.md").write_text(BRD, encoding="utf-8")
    contract = generate_brd_contract(root, parse_brd(root / "BRD.md"))
    return root, "sha256:" + hashlib.sha256(contract.read_bytes()).hexdigest()


def _set_dacl(path: Path, sddl: str) -> None:
    """Apply the DACL of `sddl` to `path` as a PROTECTED DACL (or a NULL one).
    Needs only WRITE_DAC, which the owner holds: no elevation."""
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL)]
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    assert advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None), ctypes.get_last_error()
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        assert advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                                  ctypes.byref(dacl), ctypes.byref(defaulted))
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        status = advapi32.SetNamedSecurityInfoW(str(path), 1, 0x4 | 0x80000000, None, None,
                                                dacl, None)
        assert status == 0, f"SetNamedSecurityInfoW failed: {status}"
    finally:
        kernel32.LocalFree(descriptor)


def _owner(path: Path) -> str:
    owner, _protected, _aces = gate_module._windows_root_security(path)
    return owner


def _declared_root(tmp_path: Path, extra: str = "") -> Path:
    """A root with the executor's declared zone shape: protected, SY and BA full control, plus
    the owner (the owner IS Administrators where the token owner is)."""
    root = tmp_path / "zf"
    root.mkdir()
    owner = _owner(root)
    _set_dacl(root, f"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner}){extra}")
    return root


def _no_child(monkeypatch: pytest.MonkeyPatch) -> list:
    started: list = []

    def refuse(*args, **kwargs):
        started.append(args)
        raise AssertionError("a child was started for a refused scratch root")

    monkeypatch.setattr(gate_module.subprocess, "run", refuse)
    return started


def _refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scratch_root: object,
             expected: str) -> None:
    project, digest = _project(tmp_path)
    started = _no_child(monkeypatch)
    gate = gate_module.trusted_contract_check(project, digest, scratch_root=scratch_root)
    assert gate.passed is False and gate.command == ()
    assert gate.provenance["outcome"] == "not_run"
    assert started == []
    assert expected in gate.detail, gate.detail


@windows_only
def test_the_owner_read_is_the_token_user_or_the_token_owner(tmp_path: Path):
    user, token_owner = gate_module._windows_token_sids()
    for sid in (user, token_owner):
        assert gate_module._SID_SHAPE.fullmatch(sid), sid
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    assert _owner(fresh) in {user, token_owner}


@windows_only
def test_the_declared_dacl_passes_and_the_real_check_runs_under_it(tmp_path: Path):
    scratch_root = _declared_root(tmp_path)
    owner, protected, aces = gate_module._windows_root_security(scratch_root)
    assert protected is True
    assert {sid for _type, sid in aces} <= {SYSTEM, ADMINISTRATORS, owner}
    project, digest = _project(tmp_path)
    gate = gate_module.trusted_contract_check(project, digest, scratch_root=scratch_root)
    assert gate.passed is True, gate.detail
    snapshot = Path(gate.command[5])
    assert os.path.normcase(snapshot.parent.parent) == os.path.normcase(scratch_root.resolve())
    assert gate.provenance["invocation"]["scratch_placement"] == "configured-root"
    assert list(scratch_root.iterdir()) == []


@windows_only
def test_an_added_builtin_users_ace_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scratch_root = _declared_root(tmp_path, extra="(A;OICI;FA;;;BU)")
    _refused(tmp_path, monkeypatch, scratch_root, USERS)


@windows_only
def test_a_deny_ace_is_outside_the_declared_shape_and_refused(tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch):
    scratch_root = _declared_root(tmp_path, extra="(D;OICI;FA;;;WD)")
    _refused(tmp_path, monkeypatch, scratch_root, "outside SYSTEM, Administrators and its owner")


@windows_only
def test_an_inherited_unprotected_dacl_is_refused(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch):
    scratch_root = tmp_path / "inherits"
    scratch_root.mkdir()
    _refused(tmp_path, monkeypatch, scratch_root, "not protected")


@windows_only
def test_a_null_dacl_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scratch_root = tmp_path / "null-dacl"
    scratch_root.mkdir()
    _set_dacl(scratch_root, "D:PNO_ACCESS_CONTROL")
    _refused(tmp_path, monkeypatch, scratch_root, "NULL DACL")


@windows_only
def test_a_junction_to_a_declared_root_is_refused(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch):
    import _winapi  # noqa: PLC0415 - junctions need no privilege

    target = _declared_root(tmp_path)
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    _refused(tmp_path, monkeypatch, junction, "is a link or reparse point")


@windows_only
def test_a_root_reached_through_a_junction_ancestor_is_refused(tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch):
    import _winapi  # noqa: PLC0415

    target = _declared_root(tmp_path)
    alias = tmp_path / "alias"
    _winapi.CreateJunction(str(tmp_path), str(alias))
    _refused(tmp_path, monkeypatch, alias / target.name, "is a link or reparse point")


@windows_only
def test_a_foreign_owner_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The Windows directory is owned by TrustedInstaller on every host: an
    owner that is neither the token user nor the token owner, read for real."""
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    _refused(tmp_path, monkeypatch, system_root, "neither this process's token user")


@windows_only
def test_administrators_ownership_without_an_administrators_token_owner_is_refused(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """No owner is accepted by name, BA included: the owner must be one of
    THIS token's two. A token naming neither the real owner nor BA refuses
    the declared root."""
    scratch_root = _declared_root(tmp_path)
    monkeypatch.setattr(gate_module, "_windows_token_sids",
                        lambda: ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001"))
    _refused(tmp_path, monkeypatch, scratch_root, "neither this process's token user")


@windows_only
@pytest.mark.parametrize("failing", ["_windows_root_security", "_windows_token_sids"])
def test_an_unreadable_descriptor_or_token_fails_closed(tmp_path: Path,
                                                        monkeypatch: pytest.MonkeyPatch,
                                                        failing: str):
    scratch_root = _declared_root(tmp_path)

    def unsupported(*_args):
        raise OSError(50, "The request is not supported")

    monkeypatch.setattr(gate_module, failing, unsupported)
    _refused(tmp_path, monkeypatch, scratch_root, "could not be read")


@windows_only
@pytest.mark.parametrize("spelling", [
    "{root}::$INDEX_ALLOCATION", "{root}:stream", "\\\\?\\{root}", "{root}.", "{root} ",
    "{root}\\.", "{root}\\..\\zf", "{slashed}", "\\\\localhost\\C$\\{bare}",
])
def test_a_stream_namespace_or_aliasing_spelling_is_refused(tmp_path: Path,
                                                            monkeypatch: pytest.MonkeyPatch,
                                                            spelling: str):
    """One spelling rule for every name: a drive path in backslashes, with no
    stream, namespace prefix, UNC host, dot component or trailing dot or
    space, any of which can name the same directory by another spelling."""
    scratch_root = str(_declared_root(tmp_path))
    text = spelling.format(root=scratch_root, slashed=scratch_root.replace("\\", "/"),
                           bare=scratch_root[3:])
    _refused(tmp_path, monkeypatch, text, "scratch root")



def test_the_windows_decision_over_synthesised_reads(monkeypatch: pytest.MonkeyPatch):
    """Runs on every platform: the owner and DACL decision is plain code over
    what the two reads return, so it is driven here with what they would
    return for each shape -- including the declared shape passing and an
    owner matched only by name refused."""
    me, admins = "S-1-5-21-1-2-3-1001", ADMINISTRATORS
    declared = [(0, SYSTEM), (0, ADMINISTRATORS), (0, me)]
    shapes = [
        ((me, True, declared), (me, me), ""),
        ((admins, True, declared[:2]), (me, admins), ""),
        ((admins, True, declared[:2]), (me, me), "neither this process's token user"),
        (("S-1-5-21-9-9-9-500", True, declared), (me, me), "neither this process's token user"),
        ((me, True, None), (me, me), "NULL DACL"),
        ((me, False, declared), (me, me), "not protected"),
        ((me, True, [*declared, (0, USERS)]), (me, me), USERS),
        ((me, True, [*declared, (1, "S-1-1-0")]), (me, me), "type 1"),
        ((me, True, [*declared, (5, None)]), (me, me), "type 5"),
    ]
    for read, token, expected in shapes:
        monkeypatch.setattr(gate_module, "_windows_root_security", lambda _path, r=read: r)
        monkeypatch.setattr(gate_module, "_windows_token_sids", lambda t=token: t)
        refusal = gate_module._windows_root_refusal(Path("unused"))
        assert (expected in refusal) if expected else refusal == "", (read, token, refusal)

    def unreadable(_path):
        raise OSError(50, "The request is not supported")

    monkeypatch.setattr(gate_module, "_windows_root_security", unreadable)
    assert "could not be read" in gate_module._windows_root_refusal(Path("unused"))
