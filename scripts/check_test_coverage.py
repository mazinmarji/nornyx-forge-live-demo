"""Run the suite and refuse to pass over tests that silently did not run.

A green CI run reported success while executing 139 of 202 tests. `nornyx` lived
only in the `demo` extra and the test job installed `[dev]`, so every
`@needs_nornyx` test skipped — the approval wiring, injection, materialization,
expiry and pre-approval-baseline controls were asserted by nothing, and the job
that was supposed to be guarding them said `success`.

Installing the extra fixes today's instance. This script fixes the class: a skip
is only acceptable if it was declared in advance, and anything else fails the
run. A test that does not execute proves nothing, and the failure mode is silent
by construction — pytest reports skips as a number nobody reads.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Skips that are a deliberate part of the design, with the reason each is
#: allowed. Matched as a substring of the skip message, so the reason a test
#: gives has to say which of these it is.
EXPECTED_SKIPS = {
    "set FORGE_DOCKER_TESTS=1": (
        "The live container build downloads packages, which BRD-004 forbids for "
        "the default offline run. CI exercises it in the container-launch job "
        "instead, so it is covered — just not here."
    ),
}


def classify(report: Path) -> tuple[int, int, list[str]]:
    """Split a junit report into (total, expected skips, unexpected skips).

    Separated from the run so the gate itself is testable: a guard whose failure
    path has never executed is a guess about what it would do.
    """

    root = ET.parse(report).getroot()
    unexpected: list[str] = []
    allowed = 0
    total = 0
    for case in root.iter("testcase"):
        total += 1
        skipped = case.find("skipped")
        if skipped is None:
            continue
        message = (skipped.get("message") or "") + (skipped.text or "")
        if any(marker in message for marker in EXPECTED_SKIPS):
            allowed += 1
            continue
        unexpected.append(
            f"{case.get('classname', '?')}::{case.get('name', '?')} — {message.strip()}"
        )
    return total, allowed, unexpected


def main() -> int:
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "report.xml"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"--junitxml={report}"],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if not report.exists():
            print("pytest produced no report; treating as failure")
            return completed.returncode or 1

        total, allowed, unexpected = classify(report)

    print(f"collected {total}, expected skips {allowed}, unexpected skips {len(unexpected)}")
    if unexpected:
        print("\nThese tests did not run, and were not declared as expected skips:\n")
        for entry in unexpected:
            print(f"  {entry}")
        print(
            "\nA skipped test asserts nothing. Either install what it needs, or "
            "add its reason to EXPECTED_SKIPS with why it is acceptable."
        )
        return 2
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
