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
    "not_independently_inspected", "absent", "unavailable", "no",
    # `""` IS NOT HERE ANY MORE. It was, and it was the mechanism of a
    # demonstrated forgery: any value that could not be parsed collapsed to the
    # empty string and was then read as "this property is absent". An
    # unreadable value on a known field is a CLAIM, which is what
    # `find_overclaims`' own no-recognisable-value branch already concluded --
    # the divergence between the two was the defect.
    "deterministic_fallback", "not_derived_here", "not_established",
    # `assurance_mode: autonomous_demonstration` is what the shipped evidence
    # emits, and it is the standing truth here -- an autonomous run is exactly
    # what this is. It was missing, and BOOTSTRAP.md was flagged for stating it.
    # A review asked directly what honest value the system emits that is not in
    # this set; this was one.
    "autonomous_demonstration",
    # A document REPORTING A FAILURE is disclosing, not claiming.
    "fail", "failed", "compromised", "unverifiable", "invalid",
})

#: Fields where EMPTY is the reassuring value, so empty is the claim and a
#: count is the disclosure. `problems []` asserts; `problems 12` admits.
EMPTY_IS_THE_CLAIM = frozenset({"problems", "stale_artifacts"})

#: NEGATIVELY NAMED FIELDS, by morpheme rather than by name.
#:
#: `EMPTY_IS_THE_CLAIM` listed two members of a class that cannot be
#: enumerated: polarity is a property of the NAME, and names are unbounded --
#: the same unboundedness the value inversion was adopted to escape. A review
#: measured six invented ones passing untouched:
#:
#:     not_independently_inspected  false
#:     outstanding_approvals        0
#:     missing_attestations         []
#:     assurance_gap                none
#:     blocking_findings            []
#:     unreviewed_changes           0
#:
#: `not_independently_inspected false` is the sharpest: `false` is an absent
#: shape, and under a negatively named field it is the AFFIRMATIVE.
#:
#: Morphemes close the class in the direction that matters. A field whose name
#: says it counts something MISSING, OUTSTANDING or BLOCKING is claiming
#: something when it reports none.
NEGATION_MORPHEMES = (
    "not_", "no_", "missing", "outstanding", "gap", "blocking",
    "unmet", "unresolved", "unreviewed", "pending", "remaining", "deficien",
)


def reads_as_negative(key: str) -> bool:
    """Does this field's NAME say that empty is the good answer?

    A NEGATION MORPHEME AND AN ASSURANCE ONE. The morpheme alone reaches too
    far: a mutation-campaign result table lists `SURVIVED 0` beside
    `UNPROVEN 0`, and a rule keyed on negation flagged the second and not the
    first -- the same kind of claim, picked apart by which word it happened to
    use. Flagging arbitrary members of a class is what this module exists to
    stop doing.

    Requiring both keeps the cases a review actually built --
    `not_independently_inspected`, `outstanding_approvals`,
    `missing_attestations`, `assurance_gap`, `unreviewed_changes` -- and leaves
    unrelated counters alone.

    THE BOUND, stated: a negatively named field with NO assurance morpheme is
    not reached. `blocking_findings` and `unmet_requirements` are real cases
    that fall in that gap. Closing it would mean deciding polarity for every
    identifier in every table, which is the unbounded problem again.
    """
    lowered = key.lower()
    if lowered in EMPTY_IS_THE_CLAIM:
        return True
    negated = any(
        lowered.startswith(root) or ("_" + root) in lowered
        for root in NEGATION_MORPHEMES
    )
    return negated and any(root in lowered for root in ASSURANCE_ROOTS)

#: Values that assert an assurance verdict, used for keys this system does not
#: emit -- an invented field name carrying one of these is still a claim.
VERDICT_VALUES = frozenset({
    "granted", "approved", "passed", "pass", "performed", "complete",
    "completed", "established", "verified", "certified", "accepted",
    "cleared", "signed_off", "adopted", "authorized", "authorised", "yes",
    # "closed" as an assurance verdict -- "independent inspection: closed" is a
    # completion claim. Narrow risk of a false positive on "the issue is
    # closed", which is bounded here because a verdict only decides when the
    # subject is an assurance FIELD.
    "closed",
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


#: A withdrawal marker, removed by EXACT match. `value.split("[")[0]` was used
#: for this and did something else entirely: it discarded the WHOLE value when
#: the value STARTED with a bracket. `["alice","bob","carol"]` became `""`, and
#: `""` was a member of `ABSENT_SHAPES`, so every bracketed value on every
#: field answered "this property is absent". `[...]` is exactly how `--verify`
#: renders its list-valued fields, so the forger's rendering was the tool's own.
_MARKERS = ("[FALSE]", "[WITHDRAWN]")


def tokens_of(value: str) -> list:
    """Every comparable token in a displayed value, in order."""
    import re as _re  # noqa: PLC0415

    settled = value
    for marker in _MARKERS:
        settled = settled.replace(marker, " ")
    # THE PARENTHETICAL IS PART OF THE VALUE. It used to be deleted, on the
    # reasoning that `status  fail  (claimed: pass)` is a withdrawn document
    # recording what it HAD asserted, and reading `pass` out of it turns an
    # honest retraction into a claim.
    #
    # A review measured what that costs, and the two cases are STRUCTURALLY
    # IDENTICAL:
    #
    #     status               fail        (claimed: pass)
    #     production_approval  not_granted (granted by the Change Advisory
    #                                       Board, ref CAB-2026-0412)
    #
    # Honest head, opposing parenthetical, both times. Six rows in that shape --
    # production_approval, human_review, assurance_state, independent,
    # authenticated_reviewers, required_inspectors_complete -- all returned
    # `is_a_claim False`, and a reader takes away exactly the parenthetical.
    #
    # Nothing structural separates a retraction from a live claim here, so the
    # deletion cannot be made safe by refining it. A retraction is MARKED, with
    # the `[FALSE]` / `[WITHDRAWN]` markers this module already strips above,
    # rather than inferred from the fact that it is in brackets.

    return [
        token.strip(".,;:\"'`").lower()
        for token in _re.findall(r"\[\]|\{\}|[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+", settled)
    ]


def settles_to(value: str) -> str:
    """The FIRST comparable token of a displayed value.

    Retained because some callers want the head specifically. It is no longer
    what decides a claim -- see `is_a_claim`. A review wrote

        production_approval   not_granted at R3; granted 2026-08-18 by the board

    where the head is an absent shape and everything a human reads comes after
    it. Judging by the head alone admitted five such rows in one fence.
    """
    found = tokens_of(value)
    return found[0] if found else ""


def is_a_claim(key: str, value: str, *, fields=None) -> bool:
    """Does this `key value` pair assert something this repository cannot hold?

    `fields` selects WHICH field set counts as known -- `CLAIM_FIELDS` for the
    transcript anchor rule, `ASSURANCE_FIELDS` for the overclaim guard. See the
    note on `ASSURANCE_FIELDS`.
    """
    known = CLAIM_FIELDS if fields is None else fields
    found = tokens_of(value)
    if reads_as_negative(key):
        # Empty is the claim here, whatever the field is called and whether or
        # not this system emits it. An invented `unmet_requirements []` asserts
        # exactly what `problems []` asserts.
        return bool(found) and all(
            token in {"[]", "{}", "0", "none", "false", ""} for token in found
        )
    if key in known:
        # ANY TOKEN, NOT THE HEAD. A claim is present if the value asserts
        # anywhere in it; the value is honest only if EVERY token is an absent
        # shape. Comparing the head alone let an author write an honest head
        # and append the claim, and an empty value (which is what a discarded
        # bracketed list became) read as absent.
        if any(token in VERDICT_VALUES for token in found):
            return True
        return not (found and all(token in ABSENT_SHAPES for token in found))
    # THE HEAD NOUN, matching what `find_overclaims` asks.
    #
    # This matched the root against the WHOLE key while the sibling guard
    # matched it against the head noun, so the single shared constant was asked
    # two different questions by the two guards it exists to keep in step --
    # the drift this module was written to prevent, inside the module itself.
    # Measured: `ASSURANCE_MOVED true` and `trusted_approvers_loaded=true` were
    # claims to one guard and mechanism to the other.
    #
    # An English compound is named by its LAST element: `human_approval` is an
    # approval, `assurance_moved` is a movement. THE BOUND, restated honestly
    # because the previous wording understated it: the assurance morpheme must
    # be the FINAL segment of the identifier, so `approval_status: granted` is
    # not reached here. It is reached by the transcript rule when it sits in a
    # run, and that gap is real.
    head_noun = key.lower().rsplit("_", 1)[-1]
    return any(token in VERDICT_VALUES for token in found) and any(
        root in head_noun for root in ASSURANCE_ROOTS
    )
