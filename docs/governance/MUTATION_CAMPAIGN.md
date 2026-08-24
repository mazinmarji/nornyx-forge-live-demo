# Mutation campaign — rebuilt under the admission protocol

> **SUPERSEDED — the totals in this document are WITHDRAWN.**
>
> Three documents at this head reported the campaign differently and none said
> so: this one, `COVERAGE_STATEMENT.md`, and `TASK11_CLOSURE.md` (itself now
> withdrawn). An operator reading `docs/governance/` could not tell whether
> Task 11 was open or closed.
>
> The executable catalogue in `tests/test_mutation_catalogue.py` is the only
> authority on attacks, kills and dispositions. Where this document and the
> catalogue disagree, the catalogue is right and this document is stale.
>
> The numbers here are NOT being replaced with corrected numbers. Defects found
> after they were computed -- kills credited without exact-node, exact-phase or
> intended-property attribution, and `killed_by` names with no executable body
> -- mean every total predating the corrected proof kernel is unsound. New
> totals may be published only after the whole catalogue is replayed through
> that kernel. Until then this section is history, not a claim.

Task 11, re-run from zero after the Task-14 review found that three of the
previous campaign's kills were invalid. The numbers below are read out of the
catalogue and the suite, not restated from the earlier report.

Head: `a402e7a`. Full gate at that head: 1019 collected, 0 failures, 9 expected
skips, 0 unexpected skips, 0 unexpected xfails, architecture 0, security 0.

## Result

```
attacks                                35
kills                                  31
defence-in-depth                        4
root properties                        11

SURVIVED                                0
INVALID_MUTATION                        0
ADMITTED_ATTACK_INVALID_BASELINE        0
INVALID_TEST_TARGET                     0
INVALID_MUTATION_ENVIRONMENT            0
UNPROVEN                                0

HUMAN_BLOCKED_MEASUREMENTS               2
CLASSES_WITH_NO_MUTATION_REPRESENTATION  7
```

The baseline count is named `ADMITTED_ATTACK_INVALID_BASELINE` because it counts
only attacks that ENTERED the protocol. Two questions below never did, and
reporting them as `INVALID_BASELINE = 0` alongside a description of their
failing baselines would have been the same sentence meaning two things.

`CLASSES_WITH_NO_MUTATION_REPRESENTATION` is H13-H19, recorded in
[COVERAGE\_STATEMENT.md](COVERAGE_STATEMENT.md). Task 11 remains open for them.

`35 = 31 + 4`, with `compound` as metadata on one of the kills rather than a
fourth category. Not `31 + 4 + 1`: that reading counts `SURFACE-WHOLE-CHAIN`
twice.

| owner | attacks |
| --- | --- |
| `tests/test_domain_collapse_mutations.py` | 14 |
| `tests/test_semantic_binding_theorem.py` | 8 |
| `tests/test_historical_reproof.py` | 13 |

Defence-in-depth: `SURFACE-GUARD-A`, `-B`, `-C`, `-D` — four independent routes
that each stop an absent or empty governance surface reporting `intact`. Each is
removed alone and the property survives; `SURFACE-WHOLE-CHAIN` removes all four
together and kills it.

## What makes these admissible now

Every attempt passes six steps in order, and a step that fails ends the attempt
with the named outcome. None of them may be reported as a kill:

1. the named test node **exists** — `INVALID_TEST_TARGET`
2. the named test **passes pristine** — `INVALID_BASELINE`
3. the mutation applies to an **executable** node — `INVALID_MUTATION`
4. the **mutant is what loads** — `INVALID_MUTATION_ENVIRONMENT`
5. the intended **semantic property changed** — `INVALID_MUTATION`
6. the same node runs and **fails on an assertion** — `KILLED_VALIDLY`

Step 2 is the one that was missing, and it is the one that mattered: three
classes were credited kills for a workspace where their proofs already failed.

Step 6 is stricter than before. A non-zero exit is not evidence that a control
was reached — an `ImportError` exits non-zero too, and a kill was collected that
way. The verdict now reads a JUnit report, because `<failure>` and `<error>` are
different elements while "1 failed" and "1 error" are the same shape of
sentence.

## What the rebuild changed

The previous campaign reported "34 attacks, 31 kills, 0 survivors, 0 invalid".
At least three of those kills were invalid. What differs now:

- **The workspace is faithful.** `faithful_copy` writes every tracked file plus
  real git metadata. The old copy took an allowlist and omitted `docs/`,
  `README.md`, `BRD.md`, `.github/` and `.git`, so H05, H07 and H10 already
  failed unmutated.
- **Prose-only mutations are refused.** The inert-span test asks where the
  anchor STARTS; an anchor beginning on code and running into a docstring
  satisfied it while changing only prose, and docstrings are AST nodes so the
  AST-inequality check passed too. `executable_projection` compares the two
  programs with comments and docstrings removed.
- **Mutant origin is measured, not grepped.** The old proof searched for
  `sys.path.insert(0`, which matches an unrelated line at the top of nearly
  every test module here. Origin is now read from `module.__file__`, with paths
  compared as paths — Windows returns the same directory in two spellings, and
  a substring test calls that an escape.
- **A fourth enforcement route was found by the campaign itself.** Making
  `GovernanceIntegrityState` perform the constructor refusal its docstring
  described added route D, and the compound attack stopped reaching the unsafe
  state. The test declined to credit a kill on the grounds that the inventory
  must be incomplete. It was.

## What this campaign does NOT cover

Seven historical classes — H13 through H19 — have **no attack representation**.
They are covered by ordinary test modules, which is not nothing and is not the
same claim. `COVERED_BUT_UNATTACKED` names them with a reason each, so "19
classes re-proved" and "35 attacks" cannot be read as the same ground.

### HUMAN_BLOCKED_MEASUREMENTS = 2

Neither has entered the admitted mutation protocol, so neither is counted as
KILLED, DEFENCE_IN_DEPTH, SURVIVED or INVALID_BASELINE. They are not attacks
that failed admission; they are questions that cannot yet be asked.

**D1 — does `load_authorizer` re-reading contract and lock permit a G1/G2 mix?**
`NornyxActionBoundary.__init__` calls `load_authorizer(contract, lock,
validation_as_of=…)` on EVERY construction. The injected subject and integrity
verdict are frozen at bootstrap. Whether a contract edited after bootstrap can
change what is permitted, while the frozen verdict still certifies the pre-edit
state, is unanswered.

**D2 — is the zone crossing authorized at every risk level, behaviourally?**
`canonical_action_request` pins `destination=zone.external_customer` on every
request. The crossing is now evaluated whenever the capability is allowed rather
than only for high risk, and that change is asserted STRUCTURALLY. The
behavioural half — that the authorizer actually returns a decision for the
crossing at low and medium risk — is not.

**Why neither can be measured yet.** Both need `load_authorizer` to succeed,
and it does not:

```
AuthorizerLoadError: CONTRACT_INVALID: The contract fails governance
validation: AN_APPROVAL_RECORD_MISSING, APPROVAL_EVIDENCE_MISSING,
EVIDENCE_REQUIRED_MISSING
```

Three attempts were made and all three discarded — a copied tree has no runtime
lock, a copy plus the real lock has no generated evidence, and the real tree's
contract does not validate. In every case the pristine baseline failed, so no
mutation could have changed a verdict and any classification would have been
harness evidence rather than security evidence.

**Evidence regeneration required before they can be measured**: the complete
established chain, in causal order, until `--verify` reports `status: pass`,
`integrity_state: intact`, `problems: []` and `governed_input_match: true`. Only
then does a contract exist that a mutation could move.

### Resolution attempted. They are HUMAN_BLOCKED, not INVALID_BASELINE.

<!-- classification: D1 = HUMAN_BLOCKED -->
<!-- classification: D2 = HUMAN_BLOCKED -->

The evidence set was regenerated in causal order — build, `--sync-contracts`,
`--review-binding`. What `--verify` returned is recorded below as a MEASUREMENT
AT A NAMED COMMIT, never as a standing claim about the current head.

That distinction is the whole of Lens C's P1-1. This paragraph used to read
"`--verify` **reports**" — present tense, unanchored — and it was already false
when it was committed. `docs/` is inside `GOVERNED_INPUT_PATHS`, so writing the
paragraph that describes a regeneration moves the digest that regeneration
produced. Regenerate, then document, and the document invalidates itself. The
commit that introduced these lines (`94fe40b`) does not describe its own
governed inputs; measured, not inferred.

To learn what THIS head does, run it — do not read it here:

```
python scripts/refresh_governance_evidence.py --verify
```

<!-- verify-measured-at: 341e177 -->

```
status                 pass
integrity_state        intact
problems               []
governed_input_match   True
evidence_manifest_match True

assurance_state        not_independently_inspected
independent            False
authenticated_reviewers []
```

Those last three are the honest state of the real repository: no reviewer trust
store exists, so no inspection can be authenticated, and none is claimed.

**The authorizer still does not load.** Regeneration was necessary and was not
sufficient:

```
AuthorizerLoadError: CONTRACT_INVALID: The contract fails governance
validation: AN_APPROVAL_RECORD_MISSING, APPROVAL_EVIDENCE_MISSING,
EVIDENCE_REQUIRED_MISSING
```

`runtime_network.nyx` declares `approval_record` in `required_evidence`, and no
adopted approval exists. All three codes trace to one precondition: a genuine
human approval record. The two refresher flags that would satisfy it —
`--wire-approvals` and `--adopt-approval` — put an ADOPTED HUMAN APPROVAL into
the contracts, and there is none to adopt.

So D1 and D2 are blocked on a human approval, not on effort or evidence, and
are classified HUMAN_BLOCKED_MEASUREMENTS = 2. That outcome is distinct from
INVALID_BASELINE, which describes an attack that ENTERED the protocol and failed
step 2; these never entered it. Full record and the commands to run once a
genuine approval exists: HUMAN_BLOCKED_MEASUREMENTS.md. Reaching 0 was available only by creating, inferring, simulating or
backdating an approval record, which is precisely what must never happen, and
the reviewer who first recorded this called it correctly: *irreducible without a
genuine human approval_record; correct behaviour for an autonomous
demonstration.*

Neither question is claimed as proven, and neither is claimed as absent. Both
become measurable the moment a real approval is adopted by a human, and the
protocol they must then pass is the same six steps as every other attack.
