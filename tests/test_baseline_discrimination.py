"""An experiment whose baseline already shows the outcome measures nothing.

Lens C found two live assertions in this state. Both look like proofs and both
are currently satisfied by the unmutated tree:

`tests/test_subject_completeness.py`

    assert not verdict_changed or subject_moved or integrity == "compromised"

`_integrity()` is `--verify`'s `integrity_state` against the REAL root. Measured
on the unmutated tree at this head it is already `"compromised"`, because
governed files were committed without regenerating evidence. The third disjunct
is therefore unconditionally true and all eight parametrised cases pass without
measuring anything.

`tests/test_artifact_authority.py`

    assert report["integrity_state"] == "compromised"

runs in a `faithful_copy`, which copies tracked files verbatim and does NOT
regenerate evidence -- so the copy inherits the stale set and already reports
`compromised` before the forgery is applied.

Neither is a catalogue owner, so no kill count moved. That is what makes it
dangerous: `scripts/check_test_coverage.py` reports the suite green over two
proofs that have quietly stopped asking their question.

THIS IS THE REPOSITORY'S OWN FG10 -- "a workspace whose baseline already fails
is refused" -- applied to the two places that never enforced it. The rule the
mutation kernel already lives by, stated for ordinary tests:

    a value that is present BEFORE the attack cannot be evidence that the
    attack caused it

The fix is not to stop asserting `compromised`. It is to require the baseline
to differ, so the assertion measures a TRANSITION rather than a state that was
already there.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from mutation_validity import IndiscriminateBaseline, require_discriminating_baseline

ROOT = Path(__file__).resolve().parents[1]


def test_a_baseline_already_showing_the_outcome_is_refused():
    """The exact live shape: baseline `compromised`, attack expects `compromised`."""
    with pytest.raises(IndiscriminateBaseline) as refusal:
        require_discriminating_baseline(
            "integrity refuses a decision-changing mutation",
            baseline="compromised",
            expected="compromised",
            what="--verify integrity_state",
        )
    assert "already" in str(refusal.value).lower()


def test_a_baseline_that_differs_is_permitted():
    """The control. Without it the refusal above could be 'refuses everything'."""
    require_discriminating_baseline(
        "integrity refuses a decision-changing mutation",
        baseline="intact",
        expected="compromised",
        what="--verify integrity_state",
    )


def test_the_refusal_names_the_measurement_and_both_values():
    """A refusal that does not say what to fix gets suppressed rather than fixed.

    The operator has to learn that evidence needs regenerating, not merely that
    a test failed.
    """
    with pytest.raises(IndiscriminateBaseline) as refusal:
        require_discriminating_baseline(
            "forging a review record",
            baseline="compromised",
            expected="compromised",
            what="--verify integrity_state",
        )
    message = str(refusal.value)
    assert "forging a review record" in message
    assert "--verify integrity_state" in message
    assert "compromised" in message


def test_the_disjunction_that_hid_this_is_reproduced_and_refused():
    """Reproduce the vacuity as arithmetic, so the shape itself is pinned.

    `A or B or C` with `C` already true is green for every value of `A` and `B`.
    Stated as an executable specimen because "the assertion still passes" was
    exactly the signal that made this invisible for as long as it survived.
    """
    already_true = "compromised" == "compromised"  # noqa: PLR0133  the point
    outcomes = [
        (verdict_changed, subject_moved)
        for verdict_changed in (True, False)
        for subject_moved in (True, False)
    ]
    vacuous = [
        (a, b) for a, b in outcomes
        if (not a or b or already_true)
    ]
    assert len(vacuous) == len(outcomes) == 4, (
        "the disjunction is supposed to be satisfied for every combination "
        "once the third term is already true -- if it is not, this specimen no "
        "longer reproduces the defect it exists to pin"
    )

    with pytest.raises(IndiscriminateBaseline):
        require_discriminating_baseline(
            "the same shape, guarded",
            baseline="compromised", expected="compromised",
            what="--verify integrity_state",
        )


CALL_SITES = {
    "tests/test_subject_completeness.py": "test_a_decision_changing_mutation_is_always_caught",
    "tests/test_artifact_authority.py": (
        "test_forging_a_derived_authenticated_artifact_cannot_mint_assurance"
    ),
}


@pytest.mark.parametrize(("relative", "function"), sorted(CALL_SITES.items()))
def test_the_two_live_sites_consult_the_guard(relative: str, function: str):
    """Structural, not textual.

    Asserting the source "contains require_discriminating_baseline" would be
    satisfied by the word appearing in a comment -- the same substitution this
    module exists to refuse. This walks the function and looks for a real call.
    """
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    found = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function
    ]
    assert len(found) == 1, f"{relative}: expected exactly one {function}"

    calls = {
        node.func.id
        for node in ast.walk(found[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "require_discriminating_baseline" in calls, (
        f"{relative}::{function} no longer establishes that its baseline can "
        "distinguish the outcome it asserts, so it can pass without measuring"
    )
