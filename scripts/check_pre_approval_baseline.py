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
APPROVAL_SUBJECT = "approval_record"


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


def _check(contract: str, executable: str) -> dict:
    completed = subprocess.run(
        [executable, "check", contract],
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
            and APPROVAL_SUBJECT in str(item.get("message", ""))
        )
    ]
    return {
        "contract": contract,
        "returncode": completed.returncode,
        "validates": completed.returncode == 0,
        "approval_blocked": completed.returncode != 0 and not offending,
        "unexpected_diagnostics": offending,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--has-approval",
        action="store_true",
        help="Exit 0 only if every governance contract already validates",
    )
    args = parser.parse_args()

    executable = shutil.which("nornyx")
    if not executable:
        print(json.dumps({"status": "fail", "error": "nornyx CLI not installed"}, indent=2))
        return 2

    results = [_check(contract, executable) for contract in GOVERNANCE_CONTRACTS]

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
        "human_approval_present": all(item["validates"] for item in results),
        "contracts": results,
    }
    print(json.dumps(report, indent=2))
    return 0 if healthy else 2


if __name__ == "__main__":
    raise SystemExit(main())
