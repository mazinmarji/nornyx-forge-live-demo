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

WHAT IT DOES NOT DO. It moves no provider row, makes nothing eligible, and
takes no Windows measurement. On Windows the owner's principal is not read at
all (A-034 limit 3), so a v2 record taken there derives `unknown` -- which is
the honest answer and not a denial.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
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

    WINDOWS IS DELIBERATELY NOT IMPLEMENTED, and this is the honest gap of the
    slice. Reading an owner's token user needs `OpenProcess` +
    `OpenProcessToken` + `GetTokenInformation`, and a confined Codex principal
    is the caller most likely to be DENIED that -- an ACL fact that must not be
    converted into a separation claim. Shipping untested ctypes under the word
    the whole criterion turns on is the substitution A-034 refuses.
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
        return base | {"detail": "reading the owner's token user is not implemented on "
                                 "Windows in this slice; an unread owner is `unknown`, "
                                 "never `separated` (A-034 limit 3)"}
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
                        artefacts: list[dict[str, Any]]) -> dict[str, Any]:
    """The measurements the domain reads. NOT the word.

    This block carries no separation word and no outcome: whether each
    principal was read, whether they differ WHEN BOTH WERE, and what each
    required channel answered. A producer that emitted the word could be edited
    to emit a different one and a reader would have no way to tell.

    INCOMPARABLE AXES ARE NOT A COMPARISON. One side a uid and the other a SID
    is two reads and no comparison, so `owner_principal_read` goes false and
    the derivation answers `unknown` rather than treating "different shapes" as
    "different principals".
    """
    probe_read = principal.get("sid") is not None or principal.get("uid") is not None
    owner_read = bool(owner.get("read"))
    distinct: bool | None = None
    if owner_read and probe_read:
        if owner.get("uid") is not None and principal.get("uid") is not None:
            distinct = owner["uid"] != principal["uid"]
        elif owner.get("sid") is not None and principal.get("sid") is not None:
            distinct = owner["sid"] != principal["sid"]
        else:
            owner_read = False
    return {
        "owner_principal_read": owner_read,
        "probe_principal_read": bool(probe_read),
        "principal_distinct": distinct,
        "owner_principal": owner,
        # A SUMMARY, not evidence. The translation derives the channel map
        # from `artefacts` and only checks this against it; a disagreement
        # refuses the record. `required_channels` used to sit here too and was
        # removed: nothing validated it, so it documented the criterion while
        # being free to contradict it.
        "channels": {a["name"]: a["outcome"] for a in artefacts},
    }


def to_v2(record: dict[str, Any], *, probe_pid: int | None = None,
          platform_name: str = sys.platform) -> dict[str, Any]:
    """Build a v2 record from a validated v1 record.

    The v1 record is produced and validated by its own module first, unchanged,
    so the two schemas cannot drift in everything they share. Then the fields v2
    replaces are swapped: `principal_separated` is REMOVED rather than
    recomputed, because in v2 the word is the domain's to derive and a record
    carrying one would invite a reader to trust the field instead of the rule.
    """
    if record.get("schema") != v1.SCHEMA:
        raise ValueError(f"expected a {v1.SCHEMA} record, got {record.get('schema')!r}")
    pid = record.get("subject", {}).get("surface", {}).get("pid")
    owner = owner_principal(pid, probe_pid=probe_pid if probe_pid is not None else os.getpid(),
                            platform_name=platform_name)
    v2 = dict(record)
    v2["schema"] = SCHEMA
    v2.pop("principal_separated", None)
    v2.pop("not_confinement_reason", None)
    v2["separation_evidence"] = separation_evidence(
        owner, record["subject"]["principal"], record.get("artefacts", []))
    validate_v2_record(v2)
    return v2


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
    args = parser.parse_args(argv)

    record = json.loads(Path(args.from_v1_record).read_text(encoding="utf-8"))
    v1.validate_record(record)
    v2 = to_v2(record)
    blob = json.dumps(v2, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(blob, encoding="utf-8", newline="\n")
    print(blob, end="")
    print(f"derived principal_separated: {derived_word(v2)}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - operator entry point
    raise SystemExit(main())
