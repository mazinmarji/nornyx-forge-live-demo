"""The assurance vocabulary, in ONE place, derived rather than re-listed.

Three review rounds have now found the same defect in three modules, and the
reason is that each module carried its own words. `test_documented_claims` had
a four-entry subject list; `test_recorded_measurements` had a thirteen-entry
field set; `test_execution_mode_truth` had a retired four-pattern table. A
review measured eleven of the thirteen field names this system actually emits
walking straight through the four-entry list at their affirmative value --
including `production_approval: approved`, the field's own root.

So the vocabulary lives here and every guard imports it. Two copies of a
concept drift; the drift is invisible, because the weaker copy simply passes.

THE POLARITY IS INVERTED ON PURPOSE. The set of ways to ASSERT something in
English is unbounded, which is why every round found another spelling. The set
of values this system emits WHEN A PROPERTY IS ABSENT is small and closed. So
the guards do not ask "is this a claim?"; they ask "is this one of the values
that means the property is absent?" -- and anything else is a positive
measurement that must be anchored, withdrawn, or removed.
"""

from __future__ import annotations

#: Fields `--verify` emits. A row naming one of these is reporting a
#: measurement, whatever document it appears in and whatever encloses it.
VERIFIABLE_FIELDS = frozenset({
    "status", "integrity_state", "governed_input_match", "evidence_manifest_match",
    "governed_input_digest", "inspection_subject_digest", "inspection_subject_match",
    "assurance_state", "independent", "authenticated_reviewers",
    "required_inspectors_complete", "problems", "stale_artifacts",
})

#: Fields the DEMONSTRATION EVIDENCE emits, which are the ones a reader is most
#: likely to see quoted in a document.
EVIDENCE_FIELDS = frozenset({
    "human_review", "production_approval", "assurance_mode", "event_count",
})

#: Every field name whose affirmative value is a claim about this repository.
CLAIM_FIELDS = VERIFIABLE_FIELDS | EVIDENCE_FIELDS

#: THE ASSURANCE SUBSET, and the distinction matters because two different
#: guards ask two different questions.
#:
#: `find_overclaims` asks "does this document claim an assurance this
#: repository does not hold" -- a claim about REVIEW, APPROVAL and
#: INDEPENDENCE. `governed_input_match true` is not that; it is an integrity
#: MEASUREMENT, and a measurement in a document is governed by the anchor rule
#: instead: it may be recorded against the commit where it was taken.
#:
#: Folding the two together was measured wrong in the harmless direction: a
#: pinned transcript showing `problems []` and `governed_input_match true`
#: beside an honest `assurance_state not_independently_inspected` was flagged
#: as an overclaim, when what those rows need is an anchor, not a retraction.
ASSURANCE_FIELDS = frozenset({
    "assurance_state", "independent", "authenticated_reviewers",
    "required_inspectors_complete", "human_review", "production_approval",
})

#: Values meaning "this property is ABSENT". The standing truth here, and so
#: sayable without an anchor.
ABSENT_SHAPES = frozenset({
    "false", "[]", "{}", "0", "none", "null", "not_performed", "not_granted",
    "not_independently_inspected", "absent", "unavailable", "no", "",
    "deterministic_fallback", "not_derived_here", "not_established",
    # A document REPORTING A FAILURE is disclosing, not claiming.
    "fail", "failed", "compromised", "unverifiable", "invalid",
})

#: Fields where EMPTY is the reassuring value, so empty is the claim and a
#: count is the disclosure. `problems []` asserts; `problems 12` admits.
EMPTY_IS_THE_CLAIM = frozenset({"problems", "stale_artifacts"})

#: Values that assert an assurance verdict, used for keys this system does not
#: emit -- an invented field name carrying one of these is still a claim.
VERDICT_VALUES = frozenset({
    "granted", "approved", "passed", "pass", "performed", "complete",
    "completed", "established", "verified", "certified", "accepted",
    "cleared", "signed_off", "adopted", "authorized", "authorised", "yes",
    "true", "independently_inspected", "fully_assured", "intact",
})

#: The MORPHEMES of the concepts this repository governs. Roots rather than
#: spellings: a reviewer can invent `human_approval`, `approval_state`,
#: `prod_approve` or `authorisation`, and every one contains a root here.
#:
#: BOUND, stated: a field naming an assurance concept with no shared morpheme
#: is not reached. That is a smaller gap than a word list leaves, and it is
#: recorded rather than assumed away.
ASSURANCE_ROOTS = (
    "approval", "approve", "approv", "authoriz", "authoris", "inspect",
    "review", "attest", "assur", "independen", "sign_off", "signoff",
)


def settles_to(value: str) -> str:
    """The comparable head of a displayed value.

    The first whitespace-delimited token, without trailing punctuation and
    without a withdrawal marker. A real row reads
    `status  fail          (claimed: pass)`; the parenthetical records what a
    withdrawn document had asserted, and folding it into the value made an
    honest disclosure look like a claim.
    """
    head = value.split("[")[0].strip()
    return (head.split() or [""])[0].strip(".,;:\"'`").lower()


def is_a_claim(key: str, value: str, *, fields=None) -> bool:
    """Does this `key value` pair assert something this repository cannot hold?

    `fields` selects WHICH field set counts as known -- `CLAIM_FIELDS` for the
    transcript anchor rule, `ASSURANCE_FIELDS` for the overclaim guard. See the
    note on `ASSURANCE_FIELDS`.
    """
    known = CLAIM_FIELDS if fields is None else fields
    settled = settles_to(value)
    if key in EMPTY_IS_THE_CLAIM and key in known:
        return settled in {"[]", "{}", "0", "none", ""}
    if key in known:
        return settled not in ABSENT_SHAPES
    return settled in VERDICT_VALUES and any(
        root in key.lower() for root in ASSURANCE_ROOTS
    )
