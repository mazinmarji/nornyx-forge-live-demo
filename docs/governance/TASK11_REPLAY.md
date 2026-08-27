# Task 11 — re-derived from zero through the corrected proof kernel

    Verified tree           6d1f3b2
    Status                  every catalogue attack reached a terminal classification
    Recorded by             a LATER commit than the one verified

This supersedes `TASK11_CLOSURE.md`, whose closure was withdrawn, and every
aggregate published before it. It is a RE-DERIVATION, not an update: no earlier
total was carried forward, adjusted, or consulted while producing this one.

## Result

    catalogue entries                41      across 17 root properties
      killed validly                 37
      defence in depth                4      SURFACE-GUARD-A/B/C/D
      compound                        2      H05-DIRECT, SURFACE-WHOLE-CHAIN

Re-derived a second time after an independent review found two defects in the
criteria that produce it. The intermediate figure this document briefly should
have carried -- 40 = 36 + 4 -- was wrong, and it was wrong because I retired a
VALID kill:

  H19 was moved to NOT_YET_KILLED on my measurement that its mutation raises
  FileNotFoundError rather than shrinking the subject. That was true of the
  member my probe deleted -- a CONTRACT, read eagerly, so the mutant died
  before the scope check ran -- and false of the attack. Measured against a
  required ROOT, the same registered mutation gives:

      PRISTINE   verified False   SUBJECT_SCOPE_INCOMPLETE   digest ""
      MUTANT     verified TRUE    reason None                digest sha256:c91fc64

  A smaller governed set, verified, with a minted identity: the recorded
  defect exactly. H19 is a valid single-mutation kill and is restored.

Two criteria were also decided partly on DIAGNOSTIC STRINGS with inverted
polarity -- absence of `REVIEWER_IS_THE_BUILDER` or of "performs process
execution" read as the control being gone. A review drove a presentation-only
rename to a full KILLED_VALIDLY with no control removed. H14 and H07 now
decide on security state alone (`assurance_state`, and the gate's verdict).
The recorded kills were sound either way -- their registered mutations do
violate the properties -- but the kernel certifying them was not.
## The number is the same as the dead one, and that needs saying

The withdrawn total was also `41 = 37 + 4`. It is reported here anyway, because
suppressing a re-derived result for looking familiar would be its own dishonesty.

What was wrong before was never the arithmetic. It was that the kernel behind it
could credit a kill over a broken baseline, on a missing test node, or from a
failure in an unrelated test. Those defects were corrected IN THE CATALOGUE
during remediation -- H05 recorded as compound, H13 reclassified
OBSOLETE_HISTORICAL_ATTACK, H06 and H07 baselines repaired -- and the catalogue
moved 39 -> 41 on the way. What this replay establishes is that all 41 entries
now pass a protocol that WOULD REJECT THEM if those defects were still present.

The counts and the `defence_in_depth` flags are catalogue DATA, not
measurements. The measurement is that every entry's proof passes under the
corrected kernel. The aggregate means something only because of the second.

## Two proof shapes, and why they need different protocols

    VICTIM-TEST          19 attacks   tests/test_historical_reproof.py
      signal             a named test's pass -> fail
      needs attribution  YES -- a test failure is a PROXY for the property, so
                         it can be misattributed to the wrong node, phase, or
                         assertion

    DIRECT-OBSERVABLE    22 attacks   test_domain_collapse_mutations.py (14)
                                      test_semantic_binding_theorem.py  (8)
      signal             the system's own output changes
      needs attribution  NOT APPLICABLE -- there is no test node whose failure
                         could be misread; the property is observed directly

Exact-node, execution-phase and intended-property attribution exist to stop a
proxy standing in for the property. Where the property is measured directly
those steps have no referent, and demanding them would be cargo cult. The steps
that DO apply are enforced in both shapes.

    step                        victim-test        direct-observable
    exact node identity         require_exact_node          n/a
    pristine baseline           require_pristine_baseline   pristine matrix test
    baseline discriminates      require_pristine_baseline   inline: before != expected
    production mutation scope   require_production_..._scope  measured: src/ only
    clause reached              require_baseline_clause_..  semantic effect
    mutation validity           check_mutation              check_mutation + 4 refusal tests
    same node / phase           require_caused_failure      n/a
    intended property           require_caused_failure      observable identity
    healthy mutant              (implied by phase)          MEASURED, see below

## The healthy-mutant check, which had no equivalent and was added

The direct-observable shape has its own way to be fooled: an observable can
reach the value the attack expects because the mutant BROKE THE RUN, not because
the control was removed. That is this shape's analogue of phase attribution, and
nothing was checking it. Measured on the frozen tree:

    COLLAPSE (14)   identical observable key sets, no crash text in any reason,
                    and every observable a real security value (ALLOW / DENY /
                    True / False) rather than an error default
                    -> 14/14 healthy

    BINDING (8)     `attacked_b == attacked_a` would also hold if the mutation
                    degenerated the projection into a constant, which would hide
                    EVERY difference and prove nothing. Each mutated projection
                    was checked to still distinguish some OTHER field pair
                    -> 8/8 targeted, none degenerate

## Verification state of the tree this was measured on

<!-- verify-measured-at: 6d1f3b2 -->

```
status                       pass
integrity_state              intact
governed_input_match         True
evidence_manifest_match      True
problems                     0

assurance_state              not_independently_inspected
independent                  False
authenticated_reviewers      []
```

Nothing here establishes independent inspection, human approval, or production
authorization. A re-derived kill total is evidence about the test suite's
discrimination. It is not assurance, and it is not a substitute for review.

## Measurement errors made while producing this record

Recorded because a derivation that hides its own false starts is asking to be
trusted rather than checked.

1. A grep for kernel FUNCTION NAMES showed 22 attacks calling none of them,
   which reads as "54% unproven". They use the direct-observable shape with
   inline equivalents. Reporting the grep would have been a false alarm.

2. A first health check counted `calls` and `spent` moving as collateral damage
   and called 10 of 14 attacks non-surgical. Those are the consequential-effect
   observables -- an unauthorized action actually executing IS the security
   consequence a domain collapse demonstrates. The check was demanding that the
   collapse be inconsequential.

3. The first binding probe called `_apply()` outside the module's restoring
   fixture, left `.nornyx/contracts/runtime_network.nyx` modified in the real
   tree, and so broke the anchors of every later attack -- producing a
   meaningless "2/8 targeted". The tree was restored with `git checkout --`,
   confirmed by `--verify` rc=0 and 25 passing tests, and the measurement redone
   with an explicit snapshot restored before every step and in a `finally`.

   `conftest.py::_governed_tree_is_left_as_found` exists to catch exactly this.
   It was evaded by running the probe outside pytest, which is worth knowing:
   the guard protects the suite, not ad-hoc scripts run beside it.
