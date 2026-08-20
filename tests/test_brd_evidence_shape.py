"""BRD-F-005, measured on the shipped path instead of assumed.

The requirement says every stage and policy decision is recorded with mission
ID, timestamp, actor, capability, decision, reason, and subject revision. An
independent review measured the shipped `demo --offline` path and found three
of those seven fields on 2 of 14 events and one on none of them.

Nothing checked it. `parse_brd` reads headings, so it knows BRD-F-005 exists
and nothing about whether it holds; the requirements suite runs on synthetic
fixtures, and `grep` for the real ids returns only prose. A requirement that no
test references is a requirement whose failure is invisible.

THIS DOES NOT ASSERT THE REQUIREMENT IS MET. It pins what is actually recorded,
in both directions:

  - the three universal fields must stay universal, so the stream cannot
    quietly lose the identity it does carry;
  - the four partial fields must not fall BELOW what was measured, so the gap
    cannot widen while BRD.md's disclosure goes stale.

Closing the gap makes this fail, which is the intended direction: the numbers
here and the table in BRD.md move together or the suite says so.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

#: Fields BRD-F-005 names, and the count measured on the shipped path at the
#: head that introduced this test. A count is a floor, never an equality: a
#: run that records MORE is an improvement and must not be a failure.
MEASURED_PRESENCE = {
    "mission_id": 14,
    "timestamp": 14,
    "actor": 14,
    "capability": 2,
    "decision": 2,
    "reason": 2,
    "subject_revision": 0,
}

UNIVERSAL = ("mission_id", "timestamp", "actor")


def _shipped_events(tmp_path: Path) -> list[dict]:
    """Run the demonstration the way the CLI does, in a copy.

    In a copy because the run writes into `evidence/runtime/`, and a probe that
    appends to the repository's own evidence has already broken a downstream
    measurement here once.
    """
    from mutation_workspace import faithful_copy, isolated_env  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    lock = ROOT / ".nornyx/runtime"
    if not (lock / "nornyx.agentic_network.lock").exists():
        pytest.skip(
            "no runtime lock in this tree, so the shipped demonstration path "
            "cannot reach the boundary. The lock needs a human approval and is "
            "gitignored; this measurement is unavailable to a reader, which is "
            "itself the honest state rather than something to work around"
        )
    import shutil  # noqa: PLC0415

    shutil.copytree(lock, tree / ".nornyx/runtime", dirs_exist_ok=True)

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "nornyx_forge.cli", "demo", "--offline"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=1800,
    )
    stream = tree / "evidence/runtime/events.jsonl"
    assert completed.returncode == 0, (
        f"the shipped demonstration did not complete: {completed.stderr[-400:]}"
    )
    assert stream.exists(), "the run produced no event stream"
    return [
        json.loads(line)
        for line in stream.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_the_stream_is_not_empty(tmp_path: Path):
    """Guard the guard. Zero events satisfies every floor below."""
    events = _shipped_events(tmp_path)
    assert len(events) >= 10, f"only {len(events)} events; the run did very little"


@pytest.mark.parametrize("field", UNIVERSAL)
def test_the_universally_recorded_fields_stay_universal(field: str, tmp_path: Path):
    """These three hold for every event today and must keep holding.

    They are what makes an event attributable at all. Losing one would be a
    regression BRD.md's disclosure does not cover, because that table describes
    the fields that are MISSING.
    """
    events = _shipped_events(tmp_path)
    present = sum(1 for event in events if event.get(field) not in (None, "", [], {}))
    assert present == len(events), (
        f"{field} is recorded on {present} of {len(events)} events; it was on "
        "all of them, so the evidence stream has lost identity it used to carry"
    )


@pytest.mark.parametrize(
    "field", ["capability", "decision", "reason", "subject_revision"]
)
def test_the_partially_recorded_fields_do_not_get_worse(field: str, tmp_path: Path):
    """A floor, so the disclosed gap cannot widen unnoticed.

    Deliberately not an equality. If someone populates `subject_revision`, this
    must fail LOUDLY and be raised along with BRD.md's table -- an improvement
    that silently passed would leave the published gap describing a state the
    system had already left.
    """
    events = _shipped_events(tmp_path)
    present = sum(1 for event in events if event.get(field) not in (None, "", [], {}))
    floor = MEASURED_PRESENCE[field]
    assert present >= floor, (
        f"{field} is now recorded on {present} of {len(events)} events, below "
        f"the {floor} measured when BRD-F-005's gap was disclosed: the gap has "
        "widened and the disclosure in BRD.md understates it"
    )


def test_the_disclosure_in_the_brd_matches_what_is_measured(tmp_path: Path):
    """The published table and the run must agree.

    BRD.md carries the numbers as a disclosure. A disclosure nothing checks is
    the exact shape this repository exists to refuse -- a claim about
    measurement that no measurement supports.
    """
    events = _shipped_events(tmp_path)
    text = (ROOT / "BRD.md").read_text(encoding="utf-8")
    total = len(events)
    disagreements = []
    for field, floor in sorted(MEASURED_PRESENCE.items()):
        present = sum(
            1 for event in events if event.get(field) not in (None, "", [], {})
        )
        row = f"`{field}` | {present}/{total}"
        if row not in text:
            disagreements.append(f"{field}: measured {present}/{total}, not in BRD.md")
    assert disagreements == [], (
        "BRD-F-005's disclosed table does not match the run it describes: "
        + "; ".join(disagreements)
    )
