"""Nothing may leave the semantic projection without an authority classification.

`contract_semantics_digest` is what an inspection binds to, and it is a
PROJECTION: `semantic_projection` strips `GENERATED_KEYS` at any depth and
removes `GENERATED_BLOCKS` wholesale. Everything stripped is, by construction,
invisible to an attestation.

That is safe only while every exclusion falls into exactly one of two classes:

    A  IT CANNOT CHANGE A NORNYX GOVERNANCE DECISION.
       Provenance -- when a thing was written, which commit it came from. An
       attestation over content should survive re-stamping, or authenticated
       inspection is unreachable by construction.

    B  IT IS DERIVED STATE WHOSE TAMPER IS CAUGHT BEFORE AUTHORITY.
       It can change a decision, and it is excluded anyway -- admissible only
       because the integrity channel withdraws runtime authority when it is
       altered. `tests/test_inspection_subject_matrix.py` follows exactly that
       to DENY, callback zero, ledger unchanged.

There is no third class. An exclusion that is neither is a hole: it changes what
Nornyx decides and no attestation can see it.

THE HAZARD THIS MODULE EXISTS FOR is future, not present. Adding one name to
`GENERATED_BLOCKS` silently removes an entire authored block from inspection
binding, in a one-line diff that looks like housekeeping. The classification
below is required to be TOTAL, so that diff fails until someone states which
class the new exclusion is in and proves it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nornyx_forge.governed_subject import (  # noqa: E402
    GENERATED_BLOCKS,
    GENERATED_KEYS,
    contract_semantics,
    semantic_projection,
)

#: Class A -- provenance. Stripping it is what makes an attestation survive
#: regeneration; binding it would make every inspection stale on the next
#: `--as-of`, which is the defect that once made `independently_inspected`
#: unreachable.
PROVENANCE_ONLY = {
    "generated_at": "when the tool wrote the artifact",
    "expires_at": "the window the tool stamped, re-derived every regeneration",
    "subject_revision": "the revision the tool recorded, rewritten on adoption",
    "revision_binding": "the tool's own record of what it bound to",
    "scope_hash": "recomputed from the scope definition, which IS bound",
    "governed_subject_digest": "recomputed from governed input, which IS bound",
    "governed_revision_digest": "recomputed from governed input, which IS bound",
    "source_commit": "git provenance; authority is content, never the commit",
}

#: Class B -- derived state that CAN change a decision, excluded only because
#: tampering with it is caught by the integrity channel before any authority is
#: exercised. Each entry names the test that follows the tamper to the effect.
DERIVED_GUARDED_BY_INTEGRITY = {
    "content_hash": (
        "a recorded evidence digest; altering it changes the Nornyx verdict, and "
        "tests/test_inspection_subject_matrix.py::"
        "test_tampering_derived_evidence_reaches_the_effect_boundary follows that "
        "tamper to DENY, callback 0, ledger unchanged, grant unconsumed"
    ),
    "governance_evidence": (
        "the wholly tool-written evidence block; the authored requirement it "
        "serves, `evidence.required`, stays in the projection, and the recorded "
        "contents are covered by the same integrity channel as content_hash"
    ),
}


def test_every_exclusion_carries_an_authority_classification():
    """The guard. A new exclusion fails until someone says which class it is in.

    Total by construction: the classification must cover the exclusion sets
    exactly. An unclassified exclusion is a block or key that has left the
    inspection binding with nobody stating why that is safe.
    """
    excluded = set(GENERATED_KEYS) | set(GENERATED_BLOCKS)
    classified = set(PROVENANCE_ONLY) | set(DERIVED_GUARDED_BY_INTEGRITY)

    unclassified = sorted(excluded - classified)
    assert unclassified == [], (
        "these are stripped from the semantic projection with no authority "
        "classification, so they are invisible to every attestation and nobody "
        f"has stated why that is safe: {unclassified}"
    )

    stale = sorted(classified - excluded)
    assert stale == [], (
        "these are classified as exclusions but are no longer excluded, so the "
        f"classification describes a projection that no longer exists: {stale}"
    )


def test_the_two_classes_do_not_overlap():
    """A key cannot be both harmless and dangerous-but-guarded.

    Overlap would let an exclusion be justified twice and proven neither time:
    a reader checking class A stops, a reader checking class B stops, and the
    behavioural proof class B demands never gets written.
    """
    both = sorted(set(PROVENANCE_ONLY) & set(DERIVED_GUARDED_BY_INTEGRITY))
    assert both == [], both


def test_every_classification_states_a_reason():
    """An entry with an empty reason is an unclassified exclusion in disguise."""
    for name, reason in {**PROVENANCE_ONLY, **DERIVED_GUARDED_BY_INTEGRITY}.items():
        assert reason and len(reason) > 20, (
            f"{name} is classified without a reason anyone can check"
        )


def test_the_guard_fails_when_a_block_is_excluded_without_classification():
    """Load-bearing, proven by simulating the diff it exists to catch.

    Someone adds `"identity"` to GENERATED_BLOCKS -- one line, looks like
    housekeeping -- and an entire authored block leaves inspection binding. The
    classification set is not extended, so the audit fails.

    Simulated against the real sets rather than by mutating the source, because
    the property is about the RELATIONSHIP between the two, and that is what is
    reproduced here.
    """
    excluded = set(GENERATED_KEYS) | set(GENERATED_BLOCKS) | {"identity"}
    classified = set(PROVENANCE_ONLY) | set(DERIVED_GUARDED_BY_INTEGRITY)
    assert sorted(excluded - classified) == ["identity"], (
        "the audit would not notice a newly excluded block"
    )


# --------------------------------------------------------------------------
# The projection itself, exercised rather than described.
# --------------------------------------------------------------------------


def test_the_projection_strips_generated_keys_at_every_depth():
    """A key excluded only at the top level would be a hole one nesting deep."""
    document = {
        "authored": "kept",
        "generated_at": "2026-01-01",
        "nested": {
            "authored": "kept",
            "content_hash": "sha256:dead",
            "deeper": [{"source_commit": "abc", "authored": "kept"}],
        },
    }
    projected = semantic_projection(document)

    flattened = repr(projected)
    for key in ("generated_at", "content_hash", "source_commit"):
        assert key not in flattened, f"{key} survived the projection"
    assert projected["authored"] == "kept"
    assert projected["nested"]["authored"] == "kept"
    assert projected["nested"]["deeper"][0]["authored"] == "kept"


def test_the_projection_removes_generated_blocks_entirely():
    """And keeps the authored requirement the block serves."""
    document = {
        "evidence": {"required": ["approval_record"]},
        "governance_evidence": {"records": [{"content_hash": "sha256:dead"}]},
    }
    projected = semantic_projection(document)

    assert "governance_evidence" not in projected
    assert projected["evidence"]["required"] == ["approval_record"]


def test_the_projection_is_insensitive_to_key_order():
    """Otherwise a reformat would read as a governance change.

    A projection that moved on key order would make every harmless edit look
    like a security event, and readers would learn to ignore the signal.
    """
    first = semantic_projection({"b": 1, "a": {"d": 2, "c": 3}})
    second = semantic_projection({"a": {"c": 3, "d": 2}, "b": 1})
    assert first == second
    assert list(first) == sorted(first)


@pytest.mark.parametrize("field", sorted(PROVENANCE_ONLY))
def test_a_provenance_field_cannot_reach_the_semantics(field: str):
    """Class A, asserted per member rather than as a group claim.

    Changing a provenance value must leave `contract_semantics` identical. If
    one of these ever became authoritative, its entry would have to move to
    class B and acquire a behavioural proof -- and this is what forces that.
    """
    base = {"c.nyx": {"authored": "value", field: "before"}}
    moved = {"c.nyx": {"authored": "value", field: "after"}}
    assert contract_semantics(base) == contract_semantics(moved), (
        f"{field} is classified as provenance but changing it moves the "
        "contract semantics, so it is authoritative and unbound"
    )


def test_an_authored_change_does_move_the_semantics():
    """The control for the parametrized test above.

    Without it, `contract_semantics` returning a constant would satisfy every
    provenance case and the whole class-A proof would be vacuous.
    """
    base = {"c.nyx": {"authored": "value"}}
    changed = {"c.nyx": {"authored": "other"}}
    assert contract_semantics(base) != contract_semantics(changed)
