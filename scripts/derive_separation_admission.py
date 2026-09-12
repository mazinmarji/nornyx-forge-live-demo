"""Derive the separation verdicts this repository's recorded evidence supports.

NOT A MEASUREMENT, and the distinction is the whole reason this script is
separate from `probe_control_plane.py`. That module OBSERVES a live surface
over a socket from a real principal. This one observes nothing: it reads
records already in the tree and applies `separation_from_channel_facts` to
them, so a reader can re-derive the admission verdict from the machine-readable
record instead of taking a document's word for it.

It takes no host, opens no socket, starts no process and reads no environment.
Run it with `--check` to assert the committed derivation still matches what the
records say; run it bare to rewrite that file.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nornyx_forge.provider_contract import (  # noqa: E402
    CONFINEMENT_PROPERTIES,
    CONTROL_PLANE_PROPERTY,
    PROVIDER_CONFINEMENT,
    SEPARATION_CHANNELS,
    ProviderError,
    assess_confinement,
    confinement_measurement_from_surface_record,
    control_plane_authority_outcome,
    governed_build_eligibility,
    separation_from_channel_facts,
)

SCHEMA = "nornyx.forge.separation_admission_derivation.v1"
C3_RECORD = ROOT / "docs" / "governance" / "control_plane_authority_measurement.json"
CODEX_RECORD = ROOT / "docs" / "governance" / "codex_confinement_measurement.json"
OUT = ROOT / "docs" / "governance" / "codex_separation_admission.json"


def _blob(path: Path) -> str:
    """The git object id of `path` as committed, or None outside a checkout."""
    try:
        done = subprocess.run(["git", "hash-object", str(path)], cwd=ROOT,
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None if done.returncode == 0 else None


def derive() -> dict:
    c3 = json.loads(C3_RECORD.read_text(encoding="utf-8"))
    codex = json.loads(CODEX_RECORD.read_text(encoding="utf-8"))

    arms = {}
    for name, record in c3["records"].items():
        verdict, reason = separation_from_channel_facts(record["artefacts"])
        channels = {a["name"]: a["outcome"] for a in record["artefacts"]
                    if a["name"] in SEPARATION_CHANNELS}
        arms[name] = {
            "principal_sid": record["subject"]["principal"].get("sid"),
            "platform_recorded": record["subject"]["principal"].get("platform"),
            "classification": record["classification"],
            "claimed_principal_separated": record["principal_separated"],
            "channels": {n: channels.get(n) for n in sorted(SEPARATION_CHANNELS)},
            "derived_principal_separated": verdict,
            "derivation_reason": reason,
            "control_plane_authority_outcome": control_plane_authority_outcome(
                record["classification"], principal_separated=verdict),
        }

    translated = confinement_measurement_from_surface_record(
        c3["records"]["sandboxed_subject"], provider="codex")
    served_platform = sorted(PROVIDER_CONFINEMENT["codex"])[0]
    against_served = assess_confinement("codex", served_platform, translated)

    filesystem = {}
    for prop in CONFINEMENT_PROPERTIES:
        if prop == CONTROL_PLANE_PROPERTY:
            continue
        probes = [p for p in codex["probes"] if p["property"] == prop]
        filesystem[prop] = {
            "required": CONFINEMENT_PROPERTIES[prop],
            "observations": len(probes),
            "outcomes": sorted({p["outcome"] for p in probes}),
            "cli_versions": sorted({p.get("cli_version") for p in probes if p.get("cli_version")}),
            "platform": codex["platform"],
            "satisfied_on_its_own_platform": bool(probes) and all(
                p["attempt_observed"] and p["outcome"] == CONFINEMENT_PROPERTIES[prop]
                for p in probes),
        }

    eligibility = governed_build_eligibility("codex", served_platform)
    return {
        "schema": SCHEMA,
        "kind": "derivation over recorded evidence; NOT a new measurement",
        "derived_from": {
            "control_plane_authority_measurement.json": {
                "blob": _blob(C3_RECORD), "platform": c3["platform"],
                "measured_at_commit": c3["measured_at_commit"],
            },
            "codex_confinement_measurement.json": {
                "blob": _blob(CODEX_RECORD), "platform": codex["platform"],
                "measured_at_commit": codex["measured_at_commit"],
            },
        },
        "channels": dict(SEPARATION_CHANNELS),
        "arms": arms,
        "filesystem_properties": filesystem,
        "control_plane_property": {
            "translated_platform": translated.platform,
            "translated_outcome": translated.probes[0].outcome,
            "required_outcome": CONFINEMENT_PROPERTIES[CONTROL_PLANE_PROPERTY],
            "satisfied": translated.probes[0].outcome
            == CONFINEMENT_PROPERTIES[CONTROL_PLANE_PROPERTY],
        },
        "platform_binding": {
            "served_platform_word": served_platform,
            "control_plane_evidence_platform": translated.platform,
            "binds": translated.platform == served_platform,
            "assessment_against_served_platform_establishes": against_served.establishes,
            "assessment_reason": against_served.reason,
        },
        "admission": {
            "row": PROVIDER_CONFINEMENT["codex"][served_platform],
            "governed_build_eligible": eligibility.eligible,
            "blockers": [
                "control_plane_authority is not satisfied: the confined principal "
                "ACQUIRED process_vm_read on Forge's surface, so it is not separated "
                "from the authority-bearing surface (C3-F4)",
                "browser_handler_cmdline was not measured closed for the confined "
                "principal: not_applicable covers four causes indistinguishably (C3-F5)",
                "the control-plane evidence binds platform 'win32' and the eligibility "
                "decision is made for 'windows'; the two do not combine",
                "the measured boundary is the `codex sandbox` entry point and the "
                "shipped adapter invokes `codex exec --sandbox workspace-write`; "
                "equivalence is not demonstrated",
                "no ConfinementProbe carries the provider version it was taken under, "
                "so no promotion can rest on version-matched evidence",
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="assert the committed derivation matches the records")
    args = parser.parse_args(argv)
    try:
        derived = derive()
    except ProviderError as error:
        print(f"the recorded evidence could not be derived from: {error}", file=sys.stderr)
        return 2
    text = json.dumps(derived, indent=2, sort_keys=False) + "\n"
    if args.check:
        if not OUT.exists():
            print(f"{OUT.relative_to(ROOT)} does not exist", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT.relative_to(ROOT)} is not what the records derive; "
                  "re-run this script without --check", file=sys.stderr)
            return 1
        print(f"{OUT.relative_to(ROOT)} matches the recorded evidence")
        return 0
    # `newline=""` so the bytes are the same on every platform: without it the
    # platform chooses, and the same derivation digests differently on Windows
    # and Linux -- which would make `--check` a test of the host.
    OUT.write_text(text, encoding="utf-8", newline="")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
