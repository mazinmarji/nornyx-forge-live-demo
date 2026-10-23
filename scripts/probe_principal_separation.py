"""The v2 control-plane producer: it MEASURES principal separation.

WHY THIS IS A SEPARATE MODULE, and not an edit to `probe_control_plane.py`.
That file is pinned by historical evidence:
`docs/governance/control_plane_authority_measurement.json` records the git blob
of the probe that took the 2026-09-08 measurement, and
`test_the_recorded_c3_measurement_translates_to_the_verdict_it_states` compares
that pin against the shipped module. Editing the v1 producer moves the blob and
orphans the record -- and the repair the test names is RE-MEASURING, not editing
the row. Re-measuring needs Windows and a Codex principal, which this slice does
not have and does not claim. So v1 stays byte-identical and keeps its evidence,
and the new competence lives here. (Measured: an in-place edit moved the blob
from 8516e476 to 6fdd0b93 and reddened that test; this module exists because of
that measurement, not in anticipation of it.)

WHAT IS NEW HERE, AND IT IS EXACTLY ONE THING. v1 records the PROBE's principal
and stops, so "are these two principals different" was never asked and
`separated` was never derivable -- every v1 record maps to `inconclusive` or
`allowed`, never to the `denied` that `control_plane_authority` requires. This
module reads the SURFACE OWNER's principal too, collects the out-of-band
authority channels v1 already measures, and emits a v2 record carrying those
MEASUREMENTS. It does not carry the word: `derive_principal_separation` in
`nornyx_forge.provider_contract` computes it, and there is no flag, field or
parameter by which a caller states one. A `principal_separated` key on a v2
record is refused by the translation rather than read.

WHAT IT DOES NOT DO. It moves no provider row and makes nothing eligible. On
Windows the owner's principal is read from its token where THIS caller may read
it -- normally only when the owner runs as the same user -- and that read can
only ever show the two principals to be the SAME: a same-user run derives
`not_separated`. A read that is denied, unsupported or fails in any way leaves
the owner unread, and an unread owner derives `unknown`, never `separated`
(A-034 limit 3). A cross-user probe is expected to be denied, so this read
alone can never show distinct principals on Windows.

THE OWNER ATTESTATION, AND WHY IT IS ALWAYS `unverified`. With
`--owner-attestation-from-runtime-record`, the record also carries what Forge
said about its own principal when it created its runtime record, tied to the
surface's instance token and pid and to the digest of the v1 measurement. Its
status is `unverified` in every record this producer writes, and no path
produces anything else. A provider-side principal cannot certify its own
confinement: whatever this probe observes about the channel from its own side
-- what it may write, own or override -- is the confined party judging itself,
and every attempt to clear a channel that way was reversible by that party.
Binding is established only by measurement from OUTSIDE: of the attestation
channel's ACLs, and of refusal measured from the provider principal. Until
then the attestation is `unverified` (A-050). It never feeds
`owner_principal_read` or `principal_distinct`, so it cannot move the derived
word, and the translation does not read it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import probe_control_plane as v1  # noqa: E402

from nornyx_forge.provider_contract import (  # noqa: E402
    CONTROL_PLANE_PROBE_V2_SCHEMA,
    channels_from_artefacts,
    derive_principal_separation,
)

SCHEMA = CONTROL_PLANE_PROBE_V2_SCHEMA

#: The shape of a string SID. A token read returning anything else is a failed
#: read, never a principal.
SID_SHAPE = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+")

#: The one source an owner attestation may come from: the runtime record Forge
#: writes about itself. Restated rather than imported, because importing the
#: runtime module drags its server stack into a probe; held equal to
#: `nornyx_forge.windows_runtime.RUNTIME_SCHEMA` by a test.
ATTESTATION_SOURCE = "forge_runtime_record"
RUNTIME_RECORD_SCHEMA = "nornyx.forge.windows_runtime.v1"

#: Every key an attestation carries, so a record with any other key -- a
#: `principal_distinct` slipped in beside it, say -- is refused, not read.
ATTESTATION_KEYS = frozenset({
    "source", "trusted", "status", "refusal", "attested_principal", "instance",
    "runtime_record_sha256", "v1_measurement_sha256", "limit",
})

#: The one status an attestation has in this producer. There is no other value
#: and no code path that writes one: `bound`, and a channel this probe judged
#: clear, were removed rather than guarded, and the validator refuses both.
ATTESTATION_STATUS = "unverified"

#: Keys an earlier draft of this producer wrote, named so the validator can
#: refuse them by name: each claimed an assurance a self-observation cannot give.
RETIRED_ATTESTATION_KEYS = ("bound", "channel_writable_by_this_principal")

#: What the attestation is not, carried in every one so it travels with the value.
ATTESTATION_LIMIT = (
    "unverified: what Forge said about its own principal. A provider-side principal "
    "cannot certify its own confinement, so nothing observed from this probe's side "
    "binds it; binding is established only by measurement from outside -- of the "
    "attestation channel's ACLs, and of refusal measured from the provider principal. "
    "It feeds neither owner_principal_read nor principal_distinct and cannot move the "
    "derived word (A-050)")


def _windows_owner_sid(pid: int) -> str:
    """The token user of process `pid`, as a string SID. Windows only.

    `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `OpenProcessToken
    (TOKEN_QUERY)` + `GetTokenInformation(TokenUser)` +
    `ConvertSidToStringSidW`. RAISES on every failure: `PermissionError` for
    ERROR_ACCESS_DENIED, `OSError` for anything else, including running off
    Windows. The caller turns every one of them into an unread owner.
    """
    if sys.platform != "win32":
        raise OSError("the token read is available only on Windows")
    import ctypes  # noqa: PLC0415 - Windows only
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    def failed(step: str) -> OSError:
        code = ctypes.get_last_error()
        if code == 5:  # ERROR_ACCESS_DENIED
            return PermissionError(code, f"{step} denied")
        return OSError(code, f"{step} failed")

    process = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not process:
        raise failed("OpenProcess")
    try:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            raise failed("OpenProcessToken")
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if not size.value:
                raise failed("GetTokenInformation")
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise failed("GetTokenInformation")
            # TOKEN_USER begins with SID_AND_ATTRIBUTES, which begins with the PSID.
            sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
                raise failed("ConvertSidToStringSidW")
            try:
                return str(text.value)
            finally:
                kernel32.LocalFree(text)
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(process)


def owner_principal(pid: Any, *, probe_pid: int,
                    platform_name: str = sys.platform) -> dict[str, Any]:
    """The surface owner's OS principal, or a stated reason it was not read.

    `read` IS THE LOAD-BEARING FIELD, and it is false far more often than true.
    A principal that was not read is not "probably different": the derivation
    turns an unread owner into `unknown`, never into separation. So every
    failure here records a refusal to answer rather than an answer.

    POSIX is implemented and measured: `/proc/<pid>` is owned by the process's
    real uid, so `os.stat` answers it with no subprocess and no capability the
    probe might be denied.

    WINDOWS reads the owner's token user (`_windows_owner_sid`). What that read
    can establish is one-sided, and this is the whole of its honest content:
    a confined Codex principal is the caller most likely to be DENIED it, and a
    denial is an ACL fact that must never be converted into a separation claim.
    So a denied, failed or unsupported read is an unread owner (`unknown`), and
    a SUCCESSFUL read -- which normally means the same user -- lets the
    comparison show the two principals are the same (`not_separated`). Measured
    on the hosted Windows runner for the same-user case only; the cross-user
    case is not measured anywhere (A-034 limit 3).
    """
    base = {"read": False, "platform": platform_name, "sid": None, "uid": None}
    if pid is None:
        return base | {"detail": "the surface disclosed no pid whose owner could be read"}
    if not isinstance(pid, int) or isinstance(pid, bool):
        return base | {"detail": f"the surface disclosed a pid of type {type(pid).__name__}, "
                                 "not an integer; no owner could be read"}
    if int(pid) == int(probe_pid):
        return base | {"detail": f"self process: the surface pid {pid} is this probe's own "
                                 "pid, so the owner is this caller and the comparison "
                                 "measures nothing"}
    if platform_name == "win32":
        try:
            sid = _windows_owner_sid(int(pid))
        except PermissionError as error:
            return base | {"detail": "the owner's token user was denied to this principal: "
                                     f"{error.__class__.__name__}; an unread owner is "
                                     "`unknown`, never `separated`"}
        except Exception as error:  # noqa: BLE001 - every failure is an unread owner
            return base | {"detail": "the owner's token user could not be read: "
                                     f"{error.__class__.__name__}; an unread owner is "
                                     "`unknown`, never `separated`"}
        if not isinstance(sid, str) or not SID_SHAPE.fullmatch(sid):
            return base | {"detail": "the owner's token read returned no SID; an unread "
                                     "owner is `unknown`, never `separated`"}
        return {"read": True, "platform": platform_name, "sid": sid, "uid": None,
                "detail": f"the surface pid {pid} runs as {sid}, read from its token"}
    try:
        uid = os.stat(f"/proc/{int(pid)}").st_uid
    except PermissionError as error:
        return base | {"detail": "the owner's uid was denied to this principal: "
                                 f"{error.__class__.__name__}"}
    except OSError as error:
        return base | {"detail": f"the owner's uid could not be read: {error.__class__.__name__}"}
    return {"read": True, "platform": platform_name, "sid": None, "uid": uid,
            "detail": f"the surface pid {pid} is owned by uid {uid}"}


def separation_evidence(owner: dict[str, Any], principal: dict[str, Any],
                        artefacts: list[dict[str, Any]],
                        attestation: dict[str, Any] | None = None) -> dict[str, Any]:
    """The measurements the domain reads. NOT the word.

    This block carries no separation word and no outcome: whether each
    principal was read, whether they differ WHEN BOTH WERE, and what each
    required channel answered. A producer that emitted the word could be edited
    to emit a different one and a reader would have no way to tell.

    INCOMPARABLE AXES ARE NOT A COMPARISON. One side a uid and the other a SID
    is two reads and no comparison, so `owner_principal_read` goes false and
    the derivation answers `unknown` rather than treating "different shapes" as
    "different principals".

    A WINDOWS READ MAY ONLY SHOW SAMENESS. Two equal SIDs are `principal_distinct
    = False`. Two DIFFERENT SIDs are withheld: `owner_principal_read` goes
    false and `comparison_withheld` says why, so the derivation answers
    `unknown`. A token read that succeeded across users is a fact about the
    owner's process ACL, not evidence of separation, and admitting a
    cross-user comparison waits for its channel and run binding to be
    measured and for a later change that says so (A-034 limit 3, A-050).

    THE ATTESTATION IS CARRIED AND NOT READ. It is placed beside the
    measurements for a later reader and nothing above consults it: it cannot
    set `owner_principal_read`, `principal_distinct` or any channel.
    """
    probe_read = principal.get("sid") is not None or principal.get("uid") is not None
    owner_read = bool(owner.get("read"))
    distinct: bool | None = None
    withheld: str | None = None
    if owner_read and probe_read:
        if owner.get("uid") is not None and principal.get("uid") is not None:
            distinct = owner["uid"] != principal["uid"]
        elif owner.get("sid") is not None and principal.get("sid") is not None:
            if owner["sid"] == principal["sid"]:
                distinct = False
            else:
                owner_read = False
                withheld = ("the owner's token read names a different SID; a Windows "
                            "comparison may show only sameness here, so the owner is "
                            "treated as unread and the derivation answers `unknown`")
        else:
            owner_read = False
    evidence: dict[str, Any] = {
        "owner_principal_read": owner_read,
        "probe_principal_read": bool(probe_read),
        "principal_distinct": distinct,
        "comparison_withheld": withheld,
        "owner_principal": owner,
        # A SUMMARY, not evidence. The translation derives the channel map
        # from `artefacts` and only checks this against it; a disagreement
        # refuses the record. `required_channels` used to sit here too and was
        # removed: nothing validated it, so it documented the criterion while
        # being free to contradict it.
        "channels": {a["name"]: a["outcome"] for a in artefacts},
    }
    if attestation is not None:
        evidence["owner_principal_attestation"] = attestation
    return evidence


def record_digest(record: dict[str, Any]) -> str:
    """A record's digest, over its canonical JSON: sorted keys, no spaces."""
    blob = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


#: The v1 fields a v2 record drops, so they are outside the measurement digest.
_V1_FIELDS_V2_DROPS = ("principal_separated", "not_confinement_reason")


def measurement_digest(record: dict[str, Any]) -> str:
    """The digest of the v1 MEASUREMENT a record carries, the same whether it is
    computed from the v1 record or from the v2 record made from it.

    Every v1 field the v2 record keeps unchanged, under the v1 schema: the v1
    record without the two fields v2 drops, or the v2 record without its
    `separation_evidence` and with the v1 schema back. That is what makes the
    binding RECOMPUTABLE from the v2 record alone, so a validator can hold a
    stored attestation to it rather than take its word."""
    body = {key: value for key, value in record.items()
            if key not in _V1_FIELDS_V2_DROPS and key != "separation_evidence"}
    body["schema"] = v1.SCHEMA
    return record_digest(body)


#: A digest as this producer writes one.
SHA256_SHAPE = re.compile(r"sha256:[0-9a-f]{64}")


#: A runtime record is a few hundred bytes; anything past this is not one.
RUNTIME_RECORD_LIMIT = 1 << 20

#: The identity a held record must keep, compared field by field.
_IDENTITY = ("st_dev", "st_ino", "st_size", "st_mtime_ns")


class _RecordChanged(Exception):
    """The file checked is not the file read, or the path no longer names it."""


@dataclass(frozen=True)
class HeldRecord:
    """The runtime record OPENED AND HELD before anything is checked about it.

    `fd` is the one descriptor every check and the read go through.
    `dir_fd` is the record's folder, held the same way, where the platform can
    open a directory (POSIX); it is None on Windows. `opened` is the `fstat` of
    `fd`, taken once, which every later identity check compares against.
    """

    path: Path
    name: str
    fd: int
    dir_fd: int | None
    opened: os.stat_result


def _same(a: os.stat_result, b: os.stat_result) -> bool:
    return all(getattr(a, key) == getattr(b, key) for key in _IDENTITY)


def _hold_record(path: Path) -> HeldRecord:
    """Open the record, and its folder where possible, BEFORE checking either.

    The `lstat` refuses a link by name (Forge writes a regular file); the open
    uses `O_NOFOLLOW` and `O_NONBLOCK` where the platform has them, and on
    POSIX goes through the held folder (`dir_fd`), so the name checked after
    the read is checked in the folder the file was opened from. The held descriptor's own `fstat` must
    show a regular file within the size bound and the identity the name had,
    or the record is refused. Raises `ValueError` for a link, a non-regular
    or oversized file, `_RecordChanged` for an identity mismatch, and `OSError`
    for a failed open.
    """
    named = os.lstat(path)
    if stat.S_ISLNK(named.st_mode):
        raise ValueError("the runtime record path is a link; only the file Forge wrote is read")
    # Refused before any open, too, so nothing but a regular file is ever
    # opened; the held descriptor's own `fstat` is checked again below.
    if not stat.S_ISREG(named.st_mode):
        raise ValueError("the runtime record path is not a regular file")
    if named.st_size > RUNTIME_RECORD_LIMIT:
        raise ValueError("the runtime record is larger than any runtime record")
    flags = os.O_RDONLY
    for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, flag, 0)
    dir_fd: int | None = None
    if os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY"):
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = (os.open(path.name, flags, dir_fd=dir_fd) if dir_fd is not None
              else os.open(path, flags))
    except BaseException:
        if dir_fd is not None:
            os.close(dir_fd)
        raise
    held = HeldRecord(path=path, name=path.name, fd=fd, dir_fd=dir_fd, opened=os.fstat(fd))
    try:
        if not stat.S_ISREG(held.opened.st_mode):
            raise ValueError("the runtime record path is not a regular file")
        if held.opened.st_size > RUNTIME_RECORD_LIMIT:
            raise ValueError("the runtime record is larger than any runtime record")
        if not _same(held.opened, named):
            raise _RecordChanged
    except BaseException:
        _release(held)
        raise
    return held


def _release(held: HeldRecord) -> None:
    os.close(held.fd)
    if held.dir_fd is not None:
        os.close(held.dir_fd)


def _read_held(held: HeldRecord) -> bytes:
    """Every byte of the held record, through its descriptor, and then a check
    that the name still names it: in the held folder on POSIX, by path on
    Windows (where the held file cannot be renamed while it is open)."""
    os.lseek(held.fd, 0, os.SEEK_SET)
    chunks, total = [], 0
    while True:
        chunk = os.read(held.fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > held.opened.st_size:
            raise _RecordChanged
    data = b"".join(chunks)
    if len(data) != held.opened.st_size or not _same(os.fstat(held.fd), held.opened):
        raise _RecordChanged
    named = (os.stat(held.name, dir_fd=held.dir_fd, follow_symlinks=False)
             if held.dir_fd is not None else os.lstat(held.path))
    if not _same(named, held.opened):
        raise _RecordChanged
    return data


def _attested_principal(value: Any) -> dict[str, Any] | None:
    """The `attested_principal` block of a runtime record, or None if it is
    not exactly one readable SID or uid with a platform."""
    if not isinstance(value, dict) or not isinstance(value.get("platform"), str):
        return None
    sid, uid = value.get("sid"), value.get("uid")
    sid_ok = isinstance(sid, str) and SID_SHAPE.fullmatch(sid) is not None
    uid_ok = isinstance(uid, int) and not isinstance(uid, bool) and uid >= 0
    if sid_ok == uid_ok or (sid is not None and not sid_ok) or (uid is not None and not uid_ok):
        return None
    return {"platform": value["platform"], "sid": sid if sid_ok else None,
            "uid": uid if uid_ok else None}


def owner_attestation(runtime_record: Path, v1_record: dict[str, Any]) -> dict[str, Any]:
    """What Forge said about its own principal, tied to this run. UNVERIFIED.

    THE ONE SOURCE is the runtime record Forge writes when it starts, whose
    `attested_principal` Forge reads from its own token. There is no argument
    by which this caller states a principal: a self-report from the probe's
    side is not an input this function has.

    RECORDED, OR REFUSED BY NAME. The record is OPENED AND HELD first (with its
    folder, on POSIX), and every check goes through what is held: it is a
    regular file, not a link, within the size bound; it is read through the
    held descriptor; and the name still names that file afterwards. Its
    attested principal is RECORDED only when it parses as a Forge runtime
    record, carries the SAME instance token and pid as the surface the v1
    record measured, and carries exactly one readable principal. Any failure
    records the refusal and no principal.

    EITHER WAY THE STATUS IS `unverified`, and there is no other. A
    provider-side principal cannot certify its own confinement: whether this
    probe can write, own or override the channel is the confined party
    judging itself, and each attempt to clear a channel that way was one that
    party could reverse. So nothing here asks that question, and binding is
    left to measurement from outside -- of the channel's ACLs, and of refusal
    measured from the provider principal. `trusted` is False as well. Nothing
    in this module or the translation derives anything from an attestation.
    """
    base: dict[str, Any] = {
        "source": ATTESTATION_SOURCE, "trusted": False, "status": ATTESTATION_STATUS,
        "refusal": None, "attested_principal": None, "instance": None,
        "runtime_record_sha256": None,
        "v1_measurement_sha256": measurement_digest(v1_record),
        "limit": ATTESTATION_LIMIT,
    }

    def refused(reason: str) -> dict[str, Any]:
        return base | {"refusal": reason}

    path = Path(runtime_record)
    # HELD FIRST, THEN CHECKED AND READ THROUGH WHAT IS HELD (Codex P2
    # 4357318302), so the bytes recorded are the file the checks were about.
    try:
        held = _hold_record(path)
    except _RecordChanged:
        return refused("the runtime record changed while it was checked and read")
    except ValueError as error:
        return refused(str(error))
    except PermissionError:
        return refused("the runtime record was denied to this principal")
    except OSError as error:
        return refused(f"the runtime record could not be read: {error.__class__.__name__}")
    try:
        data = _read_held(held)
    except _RecordChanged:
        return refused("the runtime record changed while it was checked and read")
    except OSError as error:
        return refused(f"the runtime record could not be read: {error.__class__.__name__}")
    finally:
        _release(held)
    base["runtime_record_sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
    try:
        record = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        return refused("the runtime record is not JSON")
    if not isinstance(record, dict) or record.get("schema") != RUNTIME_RECORD_SCHEMA:
        return refused(f"the runtime record is not a {RUNTIME_RECORD_SCHEMA} record")
    subject = v1_record.get("subject")
    surface = subject.get("surface") if isinstance(subject, dict) else None
    surface = surface if isinstance(surface, dict) else {}
    instance, expected = record.get("instance"), surface.get("instance")
    if not isinstance(instance, str) or not instance:
        return refused("the runtime record carries no instance token")
    if not isinstance(expected, str) or not expected:
        return refused("the v1 record's surface carries no instance token to bind to")
    if instance != expected:
        return refused("the runtime record's instance token is not the measured surface's")
    base["instance"] = instance
    pid, surface_pid = record.get("pid"), surface.get("pid")
    if (not isinstance(pid, int) or isinstance(pid, bool) or not isinstance(surface_pid, int)
            or isinstance(surface_pid, bool) or pid != surface_pid):
        return refused("the runtime record's pid is not the measured surface's pid")
    attested = _attested_principal(record.get("attested_principal"))
    if attested is None:
        return refused("the runtime record carries no readable attested principal")
    return base | {"attested_principal": attested}


def to_v2(record: dict[str, Any], *, probe_pid: int | None = None,
          platform_name: str = sys.platform,
          runtime_record: Path | None = None) -> dict[str, Any]:
    """Build a v2 record from a validated v1 record.

    The v1 record is produced and validated by its own module first, unchanged,
    so the two schemas cannot drift in everything they share. Then the fields v2
    replaces are swapped: `principal_separated` is REMOVED rather than
    recomputed, because in v2 the word is the domain's to derive and a record
    carrying one would invite a reader to trust the field instead of the rule.

    `runtime_record`, when given, adds the unverified owner attestation; the
    derived word is the same with or without it.
    """
    if record.get("schema") != v1.SCHEMA:
        raise ValueError(f"expected a {v1.SCHEMA} record, got {record.get('schema')!r}")
    pid = record.get("subject", {}).get("surface", {}).get("pid")
    owner = owner_principal(pid, probe_pid=probe_pid if probe_pid is not None else os.getpid(),
                            platform_name=platform_name)
    attestation = (owner_attestation(runtime_record, record)
                   if runtime_record is not None else None)
    v2 = dict(record)
    v2["schema"] = SCHEMA
    v2.pop("principal_separated", None)
    v2.pop("not_confinement_reason", None)
    v2["separation_evidence"] = separation_evidence(
        owner, record["subject"]["principal"], record.get("artefacts", []), attestation)
    validate_v2_record(v2)
    return v2


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and SHA256_SHAPE.fullmatch(value) is not None


def validate_attestation(attestation: Any) -> None:
    """Refuse an attestation this producer would never have written, judging
    EVERY field it claims (Codex P2 4357541667).

    FIRST, ANY CLAIM OF ASSURANCE. An attestation carrying `bound`, or a
    channel this probe judged clear, is refused by name: this producer never
    writes either, because a provider-side principal cannot certify its own
    confinement. Its status is `unverified` and `trusted` is False, or it is
    refused. Then, field by field:
    - exactly the producer's keys; its one source; the fixed `limit` text,
      byte for byte;
    - `v1_measurement_sha256` a digest, always (it is computed before anything
      can fail); `runtime_record_sha256` a digest or None (None only before the
      record was read);
    - `instance` None or a non-empty string, and set only once the record was
      read, so never beside a None runtime digest;
    - a RECORDED principal comes with no refusal, an instance, the record's
      digest and exactly the normalised principal; with no principal there is
      a non-empty refusal.

    What only the record can settle -- that the instance is the record's own
    surface's, and that the v1 digest is the record's own measurement -- is
    checked by `validate_v2_record`, which recomputes it. The runtime digest is
    of a file the record does not carry, so its shape is all that can be held.
    """
    if not isinstance(attestation, dict):
        raise ValueError("separation_evidence.owner_principal_attestation must be an object")
    claimed = [key for key in RETIRED_ATTESTATION_KEYS if key in attestation]
    if claimed:
        raise ValueError(f"an owner attestation may not carry {claimed}: it is never bound "
                         "and no channel is cleared by this producer, because a "
                         "provider-side principal cannot certify its own confinement")
    if attestation.get("status") != ATTESTATION_STATUS:
        raise ValueError(f"an owner attestation's status is {ATTESTATION_STATUS!r} in this "
                         f"producer, never {attestation.get('status')!r}")
    if set(attestation) != ATTESTATION_KEYS:
        raise ValueError("an owner attestation carries exactly "
                         f"{sorted(ATTESTATION_KEYS)}, not {sorted(attestation)}")
    if attestation["trusted"] is not False:
        raise ValueError("an owner attestation is never trusted by this producer; "
                         f"`trusted` is {attestation['trusted']!r}")
    if attestation["source"] != ATTESTATION_SOURCE:
        raise ValueError(f"an owner attestation comes from {ATTESTATION_SOURCE!r} only, not "
                         f"{attestation['source']!r}; a principal stated from the probe's "
                         "side is refused")
    if attestation["limit"] != ATTESTATION_LIMIT:
        raise ValueError("owner_principal_attestation.limit is not this producer's limit text")
    if not _is_digest(attestation["v1_measurement_sha256"]):
        raise ValueError("owner_principal_attestation.v1_measurement_sha256 is not a digest")
    runtime_digest = attestation["runtime_record_sha256"]
    if runtime_digest is not None and not _is_digest(runtime_digest):
        raise ValueError("owner_principal_attestation.runtime_record_sha256 is not a digest")
    instance = attestation["instance"]
    if instance is not None and (not isinstance(instance, str) or not instance):
        raise ValueError("owner_principal_attestation.instance is a non-empty string or None")
    if instance is not None and runtime_digest is None:
        raise ValueError("an owner attestation names an instance only after reading the "
                         "record, so never without the record's digest")
    principal = attestation["attested_principal"]
    if principal is not None:
        if (attestation["refusal"] is not None or instance is None or runtime_digest is None
                or _attested_principal(principal) is None
                or principal != _attested_principal(principal)):
            raise ValueError("a recorded attested principal comes with an instance, the "
                             "record's digest, no refusal, and exactly the normalised principal")
    elif not isinstance(attestation["refusal"], str) or not attestation["refusal"]:
        raise ValueError("an owner attestation with no principal carries its refusal")


def validate_v2_record(record: dict[str, Any]) -> None:
    """Refuse a v2 record this module should never have emitted.

    The producer checking its OWN output, which is not the same as the
    translation checking it: this catches a producer bug before a record is
    written, where the translation catches a record that reaches a consumer
    however it was made. Both exist because neither subsumes the other.

    It deliberately calls the DOMAIN's reader rather than re-deriving anything:
    a second copy of the channel rule here would drift from the one that
    decides, and the weaker copy would simply pass.
    """
    if record.get("schema") != SCHEMA:
        raise ValueError(f"a v2 record carries schema {SCHEMA!r}, not {record.get('schema')!r}")
    if "principal_separated" in record or "not_confinement_reason" in record:
        raise ValueError(
            "a v2 record may not carry `principal_separated` or "
            "`not_confinement_reason`; in v2 the word is derived, and a stated one is "
            "the caller assertion this schema exists to remove")
    evidence = record.get("separation_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("a v2 record carries `separation_evidence` as an object")
    for field in ("owner_principal_read", "probe_principal_read"):
        if not isinstance(evidence.get(field), bool):
            raise ValueError(f"separation_evidence.{field} must be a bool")
    if evidence.get("principal_distinct") is not None and not isinstance(
            evidence.get("principal_distinct"), bool):
        raise ValueError("separation_evidence.principal_distinct must be a bool or None")
    withheld = evidence.get("comparison_withheld")
    if withheld is not None and (not isinstance(withheld, str) or not withheld):
        raise ValueError("separation_evidence.comparison_withheld is a non-empty reason or None")
    if withheld is not None and (
            evidence["owner_principal_read"] or evidence.get("principal_distinct") is not None):
        raise ValueError("a withheld comparison leaves the owner unread and no distinctness")
    # THE WINDOWS INVARIANT, on any record this producer validates: two read
    # SIDs are compared only for SAMENESS. A record whose owner was read with a
    # SID other than the probe's, distinct or not, is one it never writes.
    owner = evidence.get("owner_principal")
    subject = record.get("subject")
    probe = subject.get("principal") if isinstance(subject, dict) else None
    if (evidence["owner_principal_read"] and isinstance(owner, dict) and isinstance(probe, dict)
            and owner.get("sid") is not None and probe.get("sid") is not None
            and (owner["sid"] != probe["sid"]
                 or evidence.get("principal_distinct") is not False)):
        raise ValueError("a Windows owner read may only show sameness: equal SIDs and "
                         "principal_distinct False, or the comparison is withheld")
    if "owner_principal_attestation" in evidence:
        attestation = evidence["owner_principal_attestation"]
        validate_attestation(attestation)
        surface = subject.get("surface") if isinstance(subject, dict) else None
        expected = surface.get("instance") if isinstance(surface, dict) else None
        if attestation["instance"] is not None and attestation["instance"] != expected:
            raise ValueError("owner_principal_attestation.instance is not this record's own "
                             "surface instance")
        if attestation["v1_measurement_sha256"] != measurement_digest(record):
            raise ValueError("owner_principal_attestation.v1_measurement_sha256 is not the "
                             "digest of this record's own v1 measurement")
    # The domain's reader: raises on a duplicate channel, a bad mechanism, an
    # unreadable refusal, or a summary that disagrees with the artefacts.
    channels_from_artefacts(record)


def derived_word(record: dict[str, Any]) -> str:
    """What the domain derives from this record. For operator display only.

    The authoritative consumer is
    `nornyx_forge.provider_contract.confinement_probe_from_surface_record`,
    which re-derives it from the record rather than reading anything printed
    here.
    """
    evidence = record["separation_evidence"]
    return derive_principal_separation(
        principal_distinct=(evidence["principal_distinct"]
                            if evidence["owner_principal_read"]
                            and evidence["probe_principal_read"] else None),
        channels=channels_from_artefacts(record),
        bearer_acquired=record["bearer_acquired_through_surface"],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Take a v2 control-plane probe that MEASURES principal separation. "
                    "It moves no provider row and makes nothing eligible.")
    parser.add_argument("--from-v1-record", required=True,
                        help="Path to a validated v1 record to convert, measuring the "
                             "owner principal on this host")
    parser.add_argument("--out", default=None, help="Write the v2 record here (JSON, LF)")
    parser.add_argument("--owner-attestation-from-runtime-record", default=None,
                        metavar="PATH",
                        help="Forge's runtime record for the measured surface; its "
                             "self-attested principal is tied to this run and recorded "
                             "UNVERIFIED. It does not change the derived word")
    args = parser.parse_args(argv)

    record = json.loads(Path(args.from_v1_record).read_text(encoding="utf-8"))
    v1.validate_record(record)
    runtime_record = args.owner_attestation_from_runtime_record
    v2 = to_v2(record, runtime_record=Path(runtime_record) if runtime_record else None)
    blob = json.dumps(v2, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(blob, encoding="utf-8", newline="\n")
    print(blob, end="")
    print(f"derived principal_separated: {derived_word(v2)}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - operator entry point
    raise SystemExit(main())
