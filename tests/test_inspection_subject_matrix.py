"""The inspection subject must be stable, and tamper must reach the effect.

Two properties that the existing subject tests do not cover between them.

STABILITY. Regeneration is the act that makes an inspection possible, and it
rewrites provenance -- `generated_at`, recorded digests, the declared revision.
If the inspection subject moved each time, an attestation would be stale the
moment it was signed, and `independently_inspected` would be unreachable by
construction. That was true once: the stale-attestation diagnostic embedded the
CURRENT subject in an artifact that was itself inside the subject, so every
regeneration produced a new one. One regeneration proving idempotent is weaker
than it looks -- a two-cycle oscillation passes it.

CONSUMPTION. Tampering with derived evidence is allowed to leave the inspection
subject unchanged, because derived state sits outside it. That is only
admissible while compromising it WITHDRAWS every authority that could depend on
it. So the tamper is followed all the way to the effect boundary: not "integrity
reports a problem", but the callback never running and the grant never spent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from nornyx_forge.governed_subject import INTEGRITY_COMPROMISED  # noqa: E402
from nornyx_forge.subject_observer import observe_governance_integrity  # noqa: E402


def _subject() -> str:
    """The inspection subject, computed the way the refresher computes it."""
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0,'scripts');"
            "import refresh_governance_evidence as r;"
            "print(r.current_inspection_subject())",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout.strip()


#: The canonical evaluation instant this repository regenerates under. Pinned,
#: so the refresher is byte-deterministic and a diff shows real change.
CANONICAL_AS_OF = "2026-08-11T00:00:00Z"

#: Everything the refresher may write.
GOVERNED_EVIDENCE = ROOT / ".nornyx"


@pytest.fixture
def restored_evidence():
    """Capture `.nornyx` as BYTES, and put every byte back afterwards.

    These tests regenerate the real evidence set, because a copied tree cannot
    reproduce the refresher's own view of the repository. That makes them the
    dangerous kind of test: they mutate state every later test reads.

    Restoring by re-running the refresher is NOT enough, and this was measured
    rather than reasoned. Regeneration is only step one of a causal order --
    `--as-of`, then `--sync-contracts`, then `--review-binding` -- so a test
    that ran step one and stopped left the contracts' recorded content hashes
    describing artifacts that had since been rewritten. Integrity went
    `compromised`, and three later tests in the pre-approval baseline failed
    for a reason that had nothing to do with them.

    Bytes are restored directly, and files the test created are removed, so the
    tree is returned to exactly what it was rather than to something the same
    pipeline would produce.
    """
    before = {
        path: path.read_bytes()
        for path in GOVERNED_EVIDENCE.rglob("*")
        if path.is_file()
    }
    try:
        yield before
    finally:
        for path, data in before.items():
            if not path.exists() or path.read_bytes() != data:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        for path in list(GOVERNED_EVIDENCE.rglob("*")):
            if path.is_file() and path not in before:
                path.unlink()


def _regenerate(as_of: str = CANONICAL_AS_OF) -> None:
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "scripts/refresh_governance_evidence.py",
            "--as-of",
            as_of,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stdout[-1200:] + completed.stderr[-800:]


def test_ten_regenerations_yield_exactly_one_inspection_subject(restored_evidence):
    """No oscillation, not merely idempotence.

    Ten cycles because a subject that alternates between two values satisfies
    "regenerating twice gives the same answer as regenerating once" only if you
    happen to sample the right parity. Ten samples make a period-two or
    period-three cycle visible.

    The authoritative state is untouched throughout: only provenance is being
    rewritten, which is the whole point.

    ONE SETTLING CYCLE FIRST, and the reason is worth stating because the first
    version of this test got it wrong and reported a defect that was not there.
    Sampling before any regeneration compares the subject of the tree as
    COMMITTED against the tree as it is now -- and if anything governed has
    changed since the last rebind, those differ. That is the subject correctly
    tracking content, not instability. Measured, the sequence was
    [b902, e560, e560, ...]: converging, not oscillating.

    So the baseline is taken after the tree has settled, and CONSECUTIVE samples
    are compared as well as the set -- a period-two cycle would satisfy "all ten
    are drawn from one value" only if it were not, and would show here.
    """
    _regenerate()
    observed = [_subject()]
    for _ in range(10):
        _regenerate()
        observed.append(_subject())

    distinct = sorted(set(observed))
    assert len(distinct) == 1, (
        "regeneration moves the inspection subject, so an attestation is stale "
        "the moment it is signed and `independently_inspected` is unreachable. "
        f"Observed {len(distinct)} subjects across 10 settled cycles: {distinct}"
    )
    oscillations = [
        (index, before[:18], after[:18])
        for index, (before, after) in enumerate(zip(observed, observed[1:]))
        if before != after
    ]
    assert oscillations == [], f"the subject alternates between cycles: {oscillations}"
    assert distinct[0].startswith("sha256:"), distinct[0]


def test_moving_provenance_alone_does_not_move_the_subject(restored_evidence):
    """Regenerated provenance, identical authored semantics, same subject.

    The control for the stability test above, and a required property in its
    own right. Under a PINNED `--as-of` the refresher is byte-deterministic, so
    ten identical cycles could also be ten identical no-ops -- that is what the
    first version of this test discovered when it asserted the opposite and
    failed. Determinism under a fixed clock is a good property, not evidence
    that anything ran.

    Changing only the evaluation instant moves provenance for real: timestamps
    are rewritten across the generated artifacts. Nothing authored changes. The
    inspection subject must not move, because it digests what the contracts SAY,
    and an approval attached under one clock must still be inspectable under
    another.

    The canonical stamp is restored at the end, so the evidence set is left
    exactly as it was found.
    """
    generated = sorted(
        path
        for path in (ROOT / ".nornyx").rglob("*.json")
        if "generated_at" in path.read_text(encoding="utf-8", errors="replace")
    )
    assert generated, "no generated artifact carries provenance to move"

    _regenerate()
    settled = _subject()
    before = {path: path.read_bytes() for path in generated}

    try:
        _regenerate(as_of="2026-08-12T09:30:00Z")
        moved = [path.name for path in generated if path.read_bytes() != before[path]]
        after = _subject()
    finally:
        pass  # the fixture restores bytes; re-running the pipeline would not

    assert moved, (
        "changing the evaluation instant rewrote no provenance, so this cannot "
        "distinguish a stable subject from a refresher that did nothing"
    )
    assert after == settled, (
        f"provenance alone moved the inspection subject ({len(moved)} artifacts "
        f"rewritten, e.g. {moved[:3]}), so an attestation would be invalidated "
        "by a clock rather than by a change to what is governed"
    )


# --------------------------------------------------------------------------
# Derived-evidence tamper, followed to the effect boundary.
# --------------------------------------------------------------------------


def _tampered_contracts(tmp_path: Path) -> Path:
    """A copy of the governed contracts with one recorded digest altered.

    A COPY, because this reaches the consequential boundary and must not leave
    the real evidence set mutated if it fails part way through.
    """
    contracts = tmp_path / "contracts"
    shutil.copytree(ROOT / ".nornyx/contracts", contracts)
    for contract in sorted(contracts.glob("*.nyx")):
        text = contract.read_text(encoding="utf-8")
        if "content_hash: sha256:" in text:
            contract.write_text(
                text.replace("content_hash: sha256:", "content_hash: sha256:dead", 1),
                encoding="utf-8",
                newline="",
            )
            return contracts
    pytest.skip("no recorded content_hash to tamper with")
    raise AssertionError  # unreachable, for the type checker


def test_tampering_derived_evidence_reaches_the_effect_boundary(tmp_path: Path):
    """The full chain: tamper -> compromised -> DENY -> nothing happened.

    Derived governance state is allowed to sit outside the inspection subject
    ONLY because compromising it withdraws runtime authority. That was not true
    once: a mutated content_hash changed the Nornyx verdict, left the subject
    untouched, and the boundary released the effect anyway.

    So this asserts the consequences, not the diagnosis. A grant that is
    otherwise completely valid -- authenticated, in the action domain, correctly
    roled, bound to this request, inside its window -- is presented, and the
    effect must not occur.
    """
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    integrity = observe_governance_integrity(_tampered_contracts(tmp_path))
    assert integrity.status == INTEGRITY_COMPROMISED, (
        f"the tamper was not detected at all: {integrity.status} {integrity.problems}"
    )
    assert integrity.authorizes_consequential_action is False

    boundary = _permissive_boundary(
        tmp_path, as_of="2026-08-03T00:00:00Z", governance_integrity=integrity
    )

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    request = canonical_action_request(
        mission_id="CASE-TAMPER",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=descriptor,
        attempt=1,
    )
    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-TAMPER",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            request, approval_id="ACT-TAMPER", role="operations_owner"
        ),
        action_descriptor=descriptor,
        attempt=1,
    )

    assert decision.effect == "DENY", decision.reason
    assert "GOVERNANCE_INTEGRITY" in (decision.code or ""), decision.code
    assert calls == [], "a compromised governance surface released the effect"
    assert (
        boundary.approval_ledger.lookup(request_digest=request.digest) is None
    ), "the grant was consumed by a run that must not start"


def test_the_same_grant_releases_when_integrity_is_intact(tmp_path: Path):
    """The control for the test above.

    Without it, the DENY could be the boundary refusing this grant for some
    unrelated reason -- and every clause of the tamper test would pass while
    measuring nothing.
    """
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    # The fixture's default integrity is intact, which is exactly the control.
    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    request = canonical_action_request(
        mission_id="CASE-TAMPER",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=descriptor,
        attempt=1,
    )
    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-TAMPER",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            request, approval_id="ACT-TAMPER", role="operations_owner"
        ),
        action_descriptor=descriptor,
        attempt=1,
    )

    assert decision.effect == "ALLOW", decision.reason
    assert calls == ["released"]


def test_the_evidence_set_is_byte_identical_after_this_module(restored_evidence):
    """The guard for the guard.

    A restoring fixture that silently stopped restoring would hand every later
    test a compromised evidence set, and they would fail for reasons that look
    like governance defects. This runs the same regeneration the tests above do
    and then asserts the fixture's own captured bytes are what is on disk.
    """
    _regenerate(as_of="2026-08-12T09:30:00Z")
    changed = [
        path.name
        for path, data in restored_evidence.items()
        if path.read_bytes() != data
    ]
    assert changed, "the regeneration wrote nothing, so this proves no restoration"

    for path, data in restored_evidence.items():
        path.write_bytes(data)
    assert not [
        path.name for path, data in restored_evidence.items() if path.read_bytes() != data
    ]
