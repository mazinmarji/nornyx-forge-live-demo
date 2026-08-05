"""Assert the governance contracts fail only for want of a human approval.

The invariant this gate protects is narrow and deliberate: a governance contract
may be blocked *only* because an accountable human has not approved it. Any other
diagnostic — a schema break, a stale revision, expired or mismatched evidence — is
a defect and fails this check.

It holds in both directions. Before approval the contracts fail with approval
diagnostics only; after a real human approval record is supplied they validate
outright. Either is acceptable; anything else is not.

The check never creates, infers, or backdates an approval.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOVERNANCE_CONTRACTS = (
    ".nornyx/contracts/runtime_network.nyx",
    ".nornyx/contracts/architecture_governance.nyx",
)

# Diagnostics that mean "a human has not approved this yet", and nothing else.
APPROVAL_CODES = frozenset(
    {
        "AN_APPROVAL_RECORD_MISSING",
        "EVIDENCE_REQUIRED_MISSING",
        "APPROVAL_EVIDENCE_MISSING",
    }
)
# Evidence ids that mean "a human has not approved this yet". Matched exactly
# rather than by substring, so an unrelated diagnostic cannot slip through by
# happening to mention one of these words.
APPROVAL_SUBJECTS = ("approval_record",)


def _diagnostics(output: str) -> list[dict]:
    """Parse the concatenated JSON objects the Nornyx CLI prints."""
    decoder = json.JSONDecoder()
    found: list[dict] = []
    index = 0
    text = output.strip()
    while index < len(text):
        try:
            value, offset = decoder.raw_decode(text, index)
        except ValueError:
            index += 1
            continue
        if isinstance(value, dict):
            found.append(value)
        index = offset
    return found


def _check(contract: str, executable: str, as_of: str | None = None) -> dict:
    command = [executable, "check", contract]
    if as_of:
        command += ["--as-of", as_of]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    diagnostics = _diagnostics(completed.stdout + completed.stderr)
    offending = [
        item
        for item in diagnostics
        if item.get("level") == "error"
        and not (
            item.get("code") in APPROVAL_CODES
            and any(
                subject in str(item.get("message", "")) for subject in APPROVAL_SUBJECTS
            )
        )
    ]
    return {
        "contract": contract,
        "returncode": completed.returncode,
        "validates": completed.returncode == 0,
        "approval_blocked": completed.returncode != 0 and not offending,
        "unexpected_diagnostics": offending,
    }


def _regenerate(as_of: str | None) -> int:
    """Run the documented review-time refresh: rebuild evidence, then rebind.

    Machine evidence has a real, finite freshness window because Nornyx 1.11.0
    offers no way to express a non-expiring one — see
    docs/governance/EVIDENCE_FRESHNESS.md. Regenerating is the honest way to get
    a healthy baseline at an arbitrary instant, and it is one command.
    """

    refresh = str(ROOT / "scripts" / "refresh_governance_evidence.py")
    for stage in ([refresh] + (["--as-of", as_of] if as_of else []), [refresh, "--sync-contracts"]):
        completed = subprocess.run(
            [sys.executable, *stage], cwd=ROOT, text=True, capture_output=True, check=False
        )
        if completed.returncode:
            print(completed.stdout + completed.stderr)
            return completed.returncode
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--has-approval",
        action="store_true",
        help="Exit 0 only if every governance contract already validates",
    )
    parser.add_argument(
        "--as-of",
        help="Evaluate at an explicit instant. The committed machine evidence "
        "carries a finite window, so a distant instant needs --regenerate too",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Run the documented review-time refresh before checking. Nornyx "
        "has no non-expiring representation for machine evidence, so this is "
        "how the baseline is made healthy at an arbitrary instant",
    )
    args = parser.parse_args()

    executable = shutil.which("nornyx")
    if not executable:
        print(json.dumps({"status": "fail", "error": "nornyx CLI not installed"}, indent=2))
        return 2

    if args.regenerate and _regenerate(args.as_of) != 0:
        print(json.dumps({"status": "fail", "error": "regeneration failed"}, indent=2))
        return 2

    results = [
        _check(contract, executable, args.as_of) for contract in GOVERNANCE_CONTRACTS
    ]

    if args.has_approval:
        # Used by CI to decide whether the strict-authorization path can run.
        return 0 if all(item["validates"] for item in results) else 1

    healthy = all(item["validates"] or item["approval_blocked"] for item in results)
    report = {
        "schema": "nornyx.forge.pre_approval_baseline.v1",
        "status": "pass" if healthy else "fail",
        "statement": (
            "Governance contracts must fail only because a human approval record "
            "is absent. Any other diagnostic is a defect."
        ),
        "evaluated_at": args.as_of or "now",
        "human_approval_present": all(item["validates"] for item in results),
        "contracts": results,
    }
    print(json.dumps(report, indent=2))
    return 0 if healthy else 2


if __name__ == "__main__":
    raise SystemExit(main())
