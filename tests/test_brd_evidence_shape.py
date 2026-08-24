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
import re
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

    # NO LOCK PRECONDITION. This used to `pytest.skip` when
    # `.nornyx/runtime/nornyx.agentic_network.lock` was absent, saying "the
    # shipped demonstration path cannot reach the boundary ... this measurement
    # is unavailable to a reader". Nine cases skipped on that, and three
    # documents called it HUMAN-BLOCKED.
    #
    # IT IS NOT TRUE. Measured on a copy of the 216 tracked files -- exactly
    # what a clean clone holds, no `.nornyx/runtime/` at all:
    #
    #     demo --offline    EXIT 0, status pass, complete
    #     nornyx_evidence   {"status": "fallback",
    #                        "load_error": "RUNTIME_LOCK_MISSING"}
    #
    # The lock's absence lands in the deterministic fallback, exactly as
    # CLAUDE.md documents, and the run completes. Copying the lock in when one
    # exists changes only the `load_error` string
    # (RUNTIME_LOCK_MISSING -> AuthorizerLoadError: CONTRACT_INVALID); both
    # land in the same fallback, because without an approval the authorizer
    # does not load either way.
    #
    # `HUMAN_BLOCKED` is the one category no autonomous run may close, and
    # inflating it with a conservative skip predicate is the mirror image of
    # the substitution this repository exists to police: claiming a blocker
    # that is not there rather than a control that is not there.
    #
    # The lock is still copied when one happens to exist, so a deployment that
    # HAS an approval measures the governed path rather than the fallback.
    lock = ROOT / ".nornyx/runtime"
    if (lock / "nornyx.agentic_network.lock").exists():
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
    """The disclosed gap, pinned EXACTLY, so it cannot widen or narrow unnoticed.

    This was `present >= floor` while calling itself a check that fails loudly
    on an improvement. Those are contradictory: `>=` fails only on a DECREASE,
    so an improvement passed silently -- and for `subject_revision`, whose
    measured presence is 0, the assertion was `present >= 0`, which cannot fail
    for any input at all. A review found it among the nine cases this module
    declares human-blocked: one of them could never have failed anyway.

    Equality does what the previous docstring described. BRD.md publishes these
    counts, so a change in EITHER direction leaves the published table wrong,
    and both must be a red test rather than one.
    """
    events = _shipped_events(tmp_path)
    present = sum(1 for event in events if event.get(field) not in (None, "", [], {}))
    floor = MEASURED_PRESENCE[field]
    assert present == floor, (
        f"{field} is now recorded on {present} of {len(events)} events against "
        f"the {floor} measured when BRD-F-005's gap was disclosed. Either the "
        "gap widened and BRD.md understates it, or it narrowed and BRD.md "
        "still publishes a gap the system has already closed. Update the table "
        "and this number together."
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


def test_the_disclosed_table_is_well_formed_without_a_runtime_lock():
    """The part of BRD-F-005's claim a READER can check, with no lock at all.

    Every other test in this module needs the shipped demonstration to run,
    which needs a runtime lock, which needs a human approval. A review measured
    the consequence: nine undeclared skips turning the census red on every
    clean checkout while this repository claimed all gates green.

    Declaring the skips is honest but not sufficient -- BRD.md said the module
    "pins the measured shape, so the gap cannot widen silently", and a test
    that skips for every reader pins nothing for them. So this one runs
    everywhere and checks what can be checked statically: that the disclosure
    exists, that it names EXACTLY the seven fields BRD-F-005 requires, and that
    each row's count is a fraction of one consistent total.

    It cannot tell whether the numbers match a real run -- that is what the
    lock-bound sibling does, and its limits are stated rather than implied.
    """
    text = (ROOT / "BRD.md").read_text(encoding="utf-8")
    assert "PARTIALLY MET" in text, (
        "BRD-F-005's disclosure is gone; the requirement is unmet and the "
        "document no longer says so"
    )

    rows = dict(re.findall(r"\|\s*`([a-z_]+)`\s*\|\s*(\d+)/(\d+)\s*\|", text)
                and [(m[0], (int(m[1]), int(m[2])))
                     for m in re.findall(
                         r"\|\s*`([a-z_]+)`\s*\|\s*(\d+)/(\d+)\s*\|", text)])
    assert set(rows) == set(MEASURED_PRESENCE), (
        "the disclosed table does not name exactly the fields BRD-F-005 "
        f"requires: table={sorted(rows)} requirement={sorted(MEASURED_PRESENCE)}"
    )

    totals = {total for _present, total in rows.values()}
    assert len(totals) == 1, (
        f"the rows disagree about how many events were measured: {totals}"
    )
    total = totals.pop()
    for field, (present, _t) in sorted(rows.items()):
        assert 0 <= present <= total, f"{field}: {present}/{total} is not a fraction"
        assert present == MEASURED_PRESENCE[field], (
            f"{field}: the table says {present} and this module's pinned floor "
            f"says {MEASURED_PRESENCE[field]}. The two move together or one of "
            "them is stale."
        )
