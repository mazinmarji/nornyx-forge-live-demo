# Task 11A — what has ordinary-test coverage and no mutation representation

> **SUPERSEDED IN PART.** This document states that seven historical classes
> (H13-H19) are attacked by nothing and that Task 11 remains open for them.
> That was true when written and is no longer: `tests/test_mutation_catalogue.py`
> now carries direct attacks for H14 through H19, and H13 is recorded as
> `OBSOLETE_HISTORICAL_ATTACK`. The catalogue is the authority.
>
> The reasoning below -- why ordinary-test coverage is not mutation coverage --
> stands unchanged and is why the attacks were built.
>
> **The inventory is stale AND SO ARE THE TOTALS.** This marker used to say
> "only the inventory is stale", which exempted the campaign figures below
> from staleness -- and those figures are withdrawn. MUTATION_CAMPAIGN.md
> withdraws every total predating the corrected proof kernel as unsound,
> and LENS_C_CLOSURE.md says they are not to be adjusted, carried forward,
> **or cited**. A marker that narrows staleness to the part that happens
> not to be quoted is the same defect one level up.

Ordinary-test coverage is not hostile-mutation coverage. An ordinary test shows
the system behaves correctly on a hostile INPUT. A mutation shows the named
CONTROL is what produces that behaviour — that removing it revives the defect.
A control can be dead code while its test passes for an unrelated reason, and
only the second kind of evidence can tell.

Seven historical classes are covered by ordinary tests and attacked by nothing.
None of them is claimed as mutation-proved.

## The record

### H13 — inspection subject self-reference · P1
- **Security property** evidence ABOUT a subject never becomes part of it
- **Ordinary test owner** `tests/test_task8_closure.py`
- **What the ordinary test proves** that the stale-attestation diagnostic, as
  currently written, does not embed the current subject digest
- **Mutation representation** none
- **Mutation required?** **YES**
- **Rationale** the control is a specific choice about what the diagnostic
  carries. Re-adding the subject to it is a one-line edit, and nothing
  demonstrates the test fails when it is made. The property is a fixed-point
  condition, which is exactly the kind that passes for the wrong reason.

### H14 — independent review self-reports pass · P1
- **Security property** independence is derived from authenticated identities
- **Ordinary test owner** `tests/test_independent_inspection.py`
- **What the ordinary test proves** that derivation consults the reviewer trust
  store and signed attestations on the paths it exercises
- **Mutation representation** none
- **Mutation required?** **YES**
- **Rationale** this is the class that produced forged
  `authenticated_inspections` records in a commit. The defect it guards —
  independence read off the artifact being judged — is precisely a control that
  can be bypassed while its test still passes, and no attack demonstrates the
  derivation refuses when the authentication step is removed.

### H15 — verifier governed-dependency deletion · P2
- **Security property** a missing governed module is a refusal, not a crash
- **Ordinary test owner** `tests/test_absence_is_not_success.py`
- **What the ordinary test proves** that deleting a governed module the tool
  imports yields a governance finding rather than a traceback
- **Mutation representation** none
- **Mutation required?** **YES**
- **Rationale** the ordinary test does apply a hostile input, which is closer to
  attack evidence than most. It still does not show that
  `_refuse_missing_governed_module` is the cause: replacing its call with
  `raise exc` is a single edit and no case proves the named test then fails.

### H16 — git unavailable read as a clean tree · P1
- **Security property** an unanswerable question is not an answer of "clean"
- **Ordinary test owner** `tests/test_absence_is_not_success.py`
- **What the ordinary test proves** that an unreachable git produces a refusal
- **Mutation required?** **YES**
- **Rationale** the historical defect was `except Exception: return []`, and the
  current control is a `raise SystemExit` inside an `OSError` handler. Reverting
  it is one line. This is the fourth instance of "required evidence absent read
  as successful empty verification" in this repository, which is the strongest
  possible argument for attacking it rather than trusting it.

### H17 — missing review_binding read as verified · P1
- **Security property** nothing to verify against is not a passing verification
- **Ordinary test owner** `tests/test_absence_is_not_success.py`
- **Mutation representation** none
- **Mutation required?** **YES**
- **Rationale** same family as H16, same reason.

### H18 — evidence recomputation removed · P1
- **Security property** assurance is recomputed over what is on disk
- **Ordinary test owner** `tests/test_evidence_integrity_verifier.py`
- **What the ordinary test proves** that `verify()` reports problems for
  tampered artifacts
- **Mutation representation** none
- **Mutation required?** **YES**
- **Rationale** "recomputes rather than reads back a stored verdict" is a claim
  about mechanism, not about output. A `verify()` that returned a cached pass
  would satisfy any test whose fixtures happen to agree with the cache, and only
  removing the recomputation shows which one is running.

### H19 — scope completeness / governed deletion · P1
- **Security property** a declared member that is absent refuses, never shrinks
- **Ordinary test owner** `tests/test_subject_scope.py`
- **What the ordinary test proves** that a tree missing a required contract
  raises `SUBJECT_SCOPE_INCOMPLETE`
- **Mutation representation** none
- **Mutation required?** **YES**
- **Rationale** the completeness guard is one `if missing:` block. This
  programme has already found one case where disabling a single guard changed
  nothing because a second route enforced the property — so whether this guard
  is load-bearing is an open question, not an assumption.

## Disposition

**MUTATION REQUIRED = YES for all seven.**

**Task 11 therefore REMAINS OPEN for H13–H19.** *(It does not. See the
marker above: TASK11_REPLAY.md records every catalogue attack reaching a
terminal classification, and the live constants in
`tests/test_mutation_catalogue.py` are 41 attacks across 17 root
properties with `NOT_YET_KILLED` empty. The paragraph is kept as the record
of the condition that was set.)*

~~The campaign result stands as reported for the 35 admitted attacks across~~
~~11 root properties.~~ **Withdrawn.** That total predates the corrected
proof kernel, and the root-property figure was the required MINIMUM set
(`REQUIRED_ROOT_PROPERTIES`, 11) rather than the catalogue's own count.
The second half of the sentence -- that the campaign does not extend to
these seven classes -- was true when written and is now contradicted by the
replay, which covers them. Neither half should be cited.

Every one of the seven has a named control in production source and a
single-edit reversion available, so there is no class here where a mutation
would add no materially independent assurance. That answer would have been
convenient; it is not the true one.
