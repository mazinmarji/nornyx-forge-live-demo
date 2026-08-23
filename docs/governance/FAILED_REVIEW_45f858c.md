# Failed internal review — 45f858c

`45f858c260113d96f7f970da1e42431cdbe08bf7` is a **failed pre-candidate head**, not a
review candidate. No tag was created for it and none should be.

Three fresh internal red teams ran against this exact SHA, each independently
confirming `git rev-parse HEAD` first and working only in temporary copies. The
repository was not modified by any of them; `git status --porcelain` was empty
before and after.

The gate at this head reported 938 collected, 9 expected skips, 0 unexpected, 0
xfail, GATE PASS, integrity intact, `governed_input_match` true. **That position
was not sound.** Five P1 findings were confirmed. The Task-10/11/12/13
conclusions are invalidated as *current evidence*; their implementations remain
in the tree and may still be useful, but their claimed proof status must be
re-established after remediation.

    Lens A   P1 2   P2 4   P3 6      authority / trust / integrity
    Lens B   P1 3   P2 6   P3 9      proof system / false greens / meta-controls
    Lens C   P1 0   P2 2   P3 2      architecture / packaging / evidence / claims
    dedup    P1 5   P2 12  P3 17

Three of the five P1s are defects in the proof system itself — work written by
the builder to establish that the other controls were sound. The mutation
catalogue reported "34 attacks, 31 kills, 0 survivors, 0 invalid" at this head.
At least three of those kills were invalid.

---

## P1 findings

### P1-1 — stale authority snapshot / split-brain state
- **Lens** A · **Severity** P1 · **Confirmed by builder** yes
- **Root property** authority conclusions must describe the governed state that
  the same request is judged against
- **Affected control** `subject_bootstrap.bootstrap_security_context`,
  `RuntimeSecurityContext`, `subject_observer.observe_governance_integrity`,
  `NornyxActionBoundary.__init__`
- **Reproduction** copy the tree to `<T>`; `ctx = bootstrap_security_context(<T>)`;
  sign a grant for `canonical_action_request(subject_revision=<startup digest>)`;
  then edit `<T>/.nornyx/contracts/runtime_network.nyx` (or tamper a recorded
  `content_hash`); fire the same grant through a boundary built from `ctx` and
  through one built from a fresh `bootstrap_security_context(<T>)`.
- **Observed** subject digest and integrity verdict are frozen at import while
  the contracts and lock they certify are re-opened at every boundary
  construction. Builder measurement: startup `intact / authorizes=True`;
  after tampering, a cold observation of the same tree reports `compromised /
  authorizes=False` while the warm context still reports `intact /
  authorizes=True`. Lens A drove this to `ALLOW, calls=1, spent=True` where a
  cold start gives `DENY, calls=0`, and reproduced it through the real HTTP
  surface across two `POST /api/cases`.
- **Expected** a context must never combine authority conclusions derived from
  governed state G1 with request-time governance semantics read from a
  materially different G2 — either freeze the semantics it authorizes, or
  re-establish both together and refuse on drift.
- **Disposition** CLOSED — see Remediation progress

### P1-2 — one SQLite trigger defeats single use
- **Lens** A · **Severity** P1 · **Confirmed by builder** yes
- **Root property** one grant releases at most one consequential effect
- **Affected control** `nornyx_runtime._assert_ledger_structure`, `ApprovalLedger.consume`
- **Reproduction** `ApprovalLedger.provision(<root>/evidence/runtime/action_approvals.sqlite3,
  established_at="2026-08-01T00:00:00Z")`; then
  `CREATE TRIGGER t BEFORE INSERT ON consumed_approvals BEGIN SELECT RAISE(IGNORE); END`;
  present one valid grant through `evaluate_and_execute` repeatedly.
- **Observed** builder measurement: 5 runs, each `effect=ALLOW calls=1
  ledger_row=None`; total 5 callbacks from one grant; `rows in
  consumed_approvals = 0`; `ledger.available=True` and `established_at` intact
  throughout, so continuity checks pass. An `AFTER INSERT … DELETE` trigger
  behaves identically. `_assert_ledger_structure` asks `PRAGMA index_list` /
  `index_info` — what the engine will *constrain* — and never what it will *do*
  with the write, while its own comment claims SQLite metadata is authoritative
  "because it describes what the engine will ENFORCE".
- **Expected** a hostile ledger structure must DENY before the callback, with an
  exact `LEDGER_STRUCTURE_INVALID`-class diagnostic, and the grant must not be
  treated as validly consumed.
- **Precondition** write access to the ledger file. `docker-compose.yml`
  bind-mounts `./evidence/runtime` read-write and the ledger lives inside it.
- **Disposition** CLOSED — see Remediation progress

### P1-3 — mutation kills credited without a pristine baseline
- **Lens** B · **Severity** P1 · **Confirmed by builder** yes
- **Root property** an attack may be classified only when its named proof passes
  in the exact pristine mutation environment
- **Affected control** `tests/test_historical_reproof.py` — `_plain_copy`,
  `_mutated_tree`, `test_removing_the_control_revives_the_defect`
- **Reproduction** for each entry in `DIRECT`, build `_plain_copy(...)` with **no
  mutation applied** and run the entry's named test under `_isolated_env`.
- **Observed** builder measurement across all eight direct classes:

      H01 rc=0   H02 rc=0   H05 rc=1 *   H06 rc=0
      H07 rc=1 * H08 rc=0   H09 rc=0     H10 rc=1 *

  H05 (`FileNotFoundError` — `.github` absent), H07 (`shutil.copy2` of
  `README.md`/`BRD.md`, absent), H10 (`git ls-files` returned 128 — no `.git`)
  already fail unmutated, so their kills were credited for a broken workspace.
  Lens B closed the loop: replacing H07's mutation with a **docstring-only** edit
  that leaves `if not is_dynamic: return None` intact also reports `1 passed`.
- **Cause** `_plain_copy` copies only `src, tests, scripts, .nornyx` plus four
  root files, omitting `docs/`, `README.md`, `BRD.md`, `.github/` and `.git`;
  and the kill criterion was `returncode != 0` with no baseline. `item.expect` is
  declared on every `SecurityClass` and never read.
- **Expected** `INVALID_BASELINE` as a first-class outcome; final acceptance
  requires `INVALID_BASELINE = 0`.
- **Disposition** CLOSED — see Remediation progress

### P1-4 — a missing test node counts as a kill
- **Lens** B · **Severity** P1 · **Confirmed by builder** no (accepted on Lens B
  evidence; mechanism independently legible in the code at
  `test_historical_reproof.py:517-521`)
- **Root property** the named killing test must be proven to exist and to run
- **Reproduction** copy the repo to temp; delete
  `tests/test_governance_integrity_authority.py::test_a_compromised_runtime_releases_nothing`;
  run the H02 case of `test_removing_the_control_revives_the_defect`.
- **Observed** `pytest module::missing_node` exits **4** and prints
  `ERROR: not found: …`, which contains neither `"no tests ran"` nor
  `"INTERNALERROR"`, so the guard does not fire and a kill is credited. H02
  reports KILLED with its only proof deleted and the integrity gate fully
  intact; collection 937 against floor 895; `REQUIRED_MODULES` still satisfied
  because the module still contributes other tests.
- **Expected** the catalogue must distinguish TEST FAILED / TEST NOT FOUND /
  COLLECTION ERROR / ENVIRONMENT ERROR, and never classify the last three as
  killed.
- **Disposition** CLOSED — see Remediation progress

### P1-5 — non-strict xfail can silence security proofs
- **Lens** B · **Severity** P1 · **Confirmed by builder** no (accepted; the
  absence of `xfail_strict` is directly checkable in `pyproject.toml`)
- **Root property** a security proof cannot be turned off without the census
  noticing
- **Affected control** `scripts/check_test_coverage.py` xfail carve-out,
  `pyproject.toml [tool.pytest.ini_options]`
- **Reproduction** copy to temp; disable the integrity gate in
  `nornyx_runtime.py`; mark the four integrity proofs
  `@pytest.mark.xfail(reason="…")`; run the census.
- **Observed** pytest exit 0; JUnit shows `<skipped type="pytest.xfail">`; the
  census reports total 12, expected skips 0, unexpected skips `[]`, module seen;
  gate PASS. The carve-out's stated justification is that xfails are strict —
  `xfail_strict` is set nowhere and no test asserts it.
- **Expected** `xfail_strict = true`, a closed allowlist of expected xfails
  (ideally empty), an unapproved xfail failing the gate, and a meta-test that
  fails if the setting is removed or flipped.
- **Disposition** CLOSED — see Remediation progress

---

## P2 findings

| ID | Lens | Root property | Observed | Confirmed |
| --- | --- | --- | --- | --- |
| A-P2-1 | A | governing contract and subject must describe one tree | caller-supplied `root` selects the contract while subject/integrity describe the packaged root; reachable from `nornyx-forge demo --offline` | Lens A |
| A-P2-2 | A | a released effect must leave evidence | effect callable raising leaves the grant spent, no evidence, no case record | Lens A |
| A-P2-3 | A | health must report the authority in force | `/api/health` re-reads trust at request time and ignores signer `status`; reports available authority that does not exist | Lens A |
| A-P2-4 | A | zone crossing must be authorized where claimed | every action is canonically pinned to `zone.external_customer`, but low/medium never evaluate `ZoneCrossingRequest` | Lens A |
| B-P2-1 | B | the attack catalogue cannot shrink silently | 6 of 14 domain-collapse mutations deletable, landing exactly on `MINIMUM_ATTACKS = 28` | Lens B |
| B-P2-2 | B | critical proofs cannot be deleted | 43 tests across six modules deletable, landing exactly on floor 895; includes the dirty-tree gate the floor was raised for | Lens B |
| B-P2-3 | B | a kill must be caused by the mutation | re-aiming H06 at an unrelated rename credits a kill via an ImportError | Lens B |
| B-P2-4 | B | mutations must change executable semantics | `check_python_mutation` admits docstring-only changes when the anchor starts on code | Lens B |
| B-P2-5 | B | mutant origin must be proven | the origin check is a grep that matches `sys.path.insert(0, ROOT/"tests")`, unrelated to production isolation | Lens B |
| B-P2-6 | B | the accounting cannot be restated at will | marking all 14 domain attacks `defence_in_depth` yields 34 = 17 + 17 with every catalogue test green | Lens B |
| C-P2-1 | C | capability acquisition must fail closed on unknown spellings | `builtins.__import__`, `__builtins__["__import__"]`, `sys.modules.get` all bypass both gates | builder |
| C-P2-2 | C | the API must not hold process capability | `constraint.api_no_commands` is a substring test defeated by `"sub" + "process"` | builder |

**All twelve closed.**

| ID | Disposition |
| --- | --- |
| B-P2-1 | CLOSED - attacks pinned BY NAME in `REQUIRED_ATTACK_IDS`, plus a case that reproduces the six-attack deletion and shows the floor still passing while the identity check does not |
| B-P2-2 | CLOSED - `REQUIRED_MODULE_MINIMUMS`, a per-module no-silent-shrink floor. Presence is not coverage |
| B-P2-3 | CLOSED - the verdict reads a JUnit report, so an errored mutant is INVALID_MUTATION rather than a kill |
| B-P2-4 | CLOSED - `executable_projection` refuses a mutant that is byte-identical once comments and docstrings are removed |
| B-P2-5 | CLOSED - mutant origin is measured from `__file__`; the grep is gone. The property held, so this replaced a vacuous proof rather than closing a bypass |
| B-P2-6 | CLOSED - `DEFENCE_IN_DEPTH_ATTACKS` names which attacks carry the claim; 34/31/3 are asserted against written constants instead of a tautology |
| C-P2-1 | CLOSED - every route that yields a module answers the acquisition question |
| C-P2-2 | CLOSED - `api_no_commands` is the AST capability analysis, not a substring test |
| A-P2-1 | CLOSED - the context records `established_root` and the boundary refuses a root that carries its own contract and is not it. Scoped: a scratch root supplies no policy, and the scoping has its own test |
| A-P2-2 | CLOSED - one `_emit_evidence`, used by both paths. A failed release records `effect_release` (released, not completed, outcome unknown) and NOT `tool_invoked`, which is a success terminal |
| A-P2-3 | CLOSED - the report reads the frozen snapshot and counts `active_signers`; one `ACTIVE_SIGNER_STATUS` shared with the authenticator |
| A-P2-4 | CLOSED - every request pins the external destination, so the crossing is evaluated at every risk level. Risk selects which capability is exercised, not whether a trust boundary is real |

---

## P3 findings

**All seventeen closed.** Each receives FIXED or
ACCEPTED_NON_BLOCKING_WITH_RATIONALE before any freeze.

**Closed**

| Finding | Disposition |
| --- | --- |
| A: `GovernanceIntegrityState` docstring claims a constructor refusal that does not exist | FIXED — the refusal is now performed. `intact` with zero verified claims is "nothing was checked" reported as sound, and it authorizes consequential action |
| A: `_canonical` is not injective | FIXED — non-string mapping keys are refused rather than coerced, so `{1: …}` and `{"1": …}` can no longer share a `payload_digest`. The deliberate `100`/`100.0` collapse is kept and pinned |
| A: the integrity-compromised refusal produces no evidence | FIXED — writes a refusal record in its own schema. Not a Nornyx stream: the authorizer was never consulted on that path, so there is no verdict to report |
| A: `governance_approval_trust` has no runtime consumer | FIXED as a side effect of P1-1 — `assurance_state` now reads both frozen domains, so the field is consumed rather than merely held |
| B: the semantic-binding suite mutates the real contracts in place | MITIGATED — a session guard compares `git status --porcelain` across the run and fails loudly on anything the suite leaves behind. The in-place mutation remains; its failure mode is no longer silent. Verified by a probe test that dirties a tracked file |
| C: `_dynamically_imported_module`'s docstring overstates its coverage | FIXED — the docstring now describes the routes actually recognised, which grew when C-P2-1 closed |
| C: `_unstaged_governed_paths`' docstring misstates the digest source | FIXED — the digest reads the working tree, not the index, and an assertion pins it so a "simplification" to the index fails loudly |
| B: `classify()` counts collection errors toward the total and marks the module seen | FIXED — a `<testcase>` carrying `<error>` is not a test. A module that failed to import inflated the count, satisfied REQUIRED_MODULES and would have met its per-module floor. Errored runs now fail the gate |
| B: `EXPECTED_9C_IDS` is derived from the thing it checks | FIXED — the eight attacks are written out by name, with a guard refusing a declaration that mentions the catalogue again |
| B: gutting a false-green self-attack body to `pass` keeps 9/9 green | FIXED — each named function is parsed and must carry an assertion or expected-refusal block. Verified by gutting FG03 in a copy |
| B: two catalogue self-attacks assert that invented names do not exist | FIXED — both phantoms now run the real delegation check, with a control proving a genuine entry still passes |
| B: `MINIMUM_ATTACKS`' own guard weakens as campaigns shrink | FIXED — the floor is no longer the control. `REQUIRED_ATTACK_IDS` has total coverage, demonstrated against a floor of 1 |
| B: `expect`/`severity`/`side_effects` recorded and never compared | FIXED — severity drawn from a closed vocabulary, expect required present and distinct, and each declared side effect mapped to a token its killing test must actually assert |
| B: H13–H19 have no attack representation in the "authoritative" inventory | FIXED by making the claim honest rather than by inventing attacks. `delegated_to` was one field doing two jobs: H11/H12 point at mutation catalogues, H13–H19 at ordinary test modules, and both read as "re-proved elsewhere". `COVERED_BUT_UNATTACKED` now names the seven, so "19 classes" and "35 attacks" can no longer be read as the same ground |
| A: `governance_approval_trust`, `reviewer_store`, `builder_identities` are bootstrap state with no consumer | PARTIALLY FIXED — `governance_approval_trust` gained a consumer via P1-1. `reviewer_store` and `builder_identities` remain, and the standing decision not to add `ReviewerTrustStore` to `RuntimeSecurityContext` for structural symmetry is unchanged |
| A: the trust-domain guard is opt-in for unlabelled stores | ACCEPTED_NON_BLOCKING_WITH_RATIONALE, on measured evidence. Making the clause total was implemented and reverted: it broke thirteen call sites across five modules, and two were security proofs whose MECHANISM it changed — removing the frozen store to show a decision moves stops proving that if a domain refusal arrives first. Trading a latent affordance for a real reduction in what two H01 proofs measure is a bad trade. Bounded instead by asserting the property the clause relies on:  takes the domain as a required keyword, and no site under  builds a store without one. That test immediately found the single production site that did — the authenticator's own fallback store — which is now labelled with the asking authority. Two independently correct changes were kept: absence is decided before domain, so an unprovisioned store refuses as ABSENT rather than as a mismatch; and the shared boundary fixture names ACTION explicitly |
| A: the "trust resolved once" closure is not total on the unresolvable-root branch | FIXED - that branch left both approval domains as None while the rooted branch froze two stores, so the closure held on one path out of two. None is the absence of a field, indistinguishable from never-established. The domains never depended on the root, so the branch now resolves them and a consumer gets a store that says it is unavailable and why. The control asserts nothing was granted by doing so |

**Open AT THAT HEAD -- SUPERSEDED, and kept as the record of what the review
found.**

> Every item below appears in the Closed table above with a disposition of
> FIXED, PARTIALLY FIXED, or ACCEPTED_NON_BLOCKING_WITH_RATIONALE. This
> list is what `45f858c` looked like to the reviewers, not what is
> outstanding now. A review found this file stating twice that all
> twenty-nine findings were closed and twice that all twenty-nine were
> open, with no supersession marker and no date -- the same defect this
> repository recorded as C-P2-3, recurring inside a single file. An
> operator reading `docs/governance/` to find what is outstanding was
> handed the answer twice, in opposite directions.

- **Lens A (6)** — `GovernanceIntegrityState` docstring claims a constructor
  refusal that does not exist; `_canonical` is not injective (`{1:…}` and
  `{'1':…}` share a `payload_digest`); the integrity-compromised refusal
  produces no evidence at all; `governance_approval_trust`, `reviewer_store` and
  `builder_identities` are bootstrap state with no runtime consumer; the
  "trust resolved once" closure is not total on the unresolvable-root branch;
  the trust-domain guard is opt-in for unlabelled stores.
- **Lens B (9)** — `EXPECTED_9C_IDS` is derived from the thing it checks, making
  the equality a tautology; `total == kills + defence` is likewise tautological
  and 34/31/3 appear only in prose; two catalogue "self-attacks" assert that
  invented names do not exist; `MINIMUM_ATTACKS`' own guard weakens as campaigns
  shrink; gutting a false-green self-attack body to `pass` keeps 9/9 green;
  `expect`/`severity`/`side_effects` are recorded and never compared to observed
  behaviour; H13–H19 have no attack representation in the "authoritative"
  inventory; the semantic-binding suite mutates the real contracts in place and
  a hard kill leaves them mutated; `classify()` counts collection errors toward
  the total and marks the errored module seen.
- **Lens C (2)** — `_dynamically_imported_module`'s docstring overstates its
  coverage; `_unstaged_governed_paths`' docstring misstates the digest source
  (the implementation is safer than documented, which is its own hazard).

---

## What the builder got wrong

The mutation catalogue proved that the controls written were load-bearing. It
could not report that the harness was crediting kills it never earned, because
the harness had no baseline — the one discipline enforced on every other
campaign and omitted from the campaign written last. The reported figures at
this head ("31 kills, 0 survivors, 0 invalid") were not trustworthy for at least
three classes, and the builder reported them as settled.

The three lenses were instructed to assume the newest controls were defective.
That instruction is what produced these findings; a review told to confirm
remediation would have returned green.


---

## Remediation progress

### P1-3 — CLOSED, and it exposed a real survivor

The workspace is no longer an allowlist. `tests/mutation_workspace.py` copies
every file `git ls-files` reports and initialises real git metadata, so a
pristine proof can pass; measured, all eight direct classes now pass their
named test before any mutation, where three previously failed.

The admission protocol is enforced in order, each failure carrying its own
outcome and none reportable as a kill: node exists (INVALID_TEST_TARGET),
pristine baseline passes (INVALID_BASELINE), mutation reaches executable code
(INVALID_MUTATION), mutant is what loads (INVALID_MUTATION_ENVIRONMENT, read
from the module rather than grepped), semantic effect present, then the same
node runs and fails.

**With a valid baseline, H05 SURVIVES.** Seven of eight kill validly. The
control credited to H05 -- the approval-wiring loop recording a missing contract
and continuing -- is not what
`test_the_verifier_refuses_missing_governed_content_without_crashing` proves;
disabling it leaves that test passing. Either an earlier refusal reaches the
same outcome first (defence in depth, as with H03/H04) or the control is not
load-bearing. **RESOLVED — Case A, defence in depth.** Measured: the single-clause mutation
produced output byte-identical to pristine, because `FileNotFoundError` IS an
`OSError` and the `except OSError` clause immediately below independently
catches the same absence. Removing BOTH clauses returns the historical traceback
(rc=1, `FileNotFoundError` propagating out of `verify`). H05 was a
MIS-SPECIFIED ATTACK, not an unproven control; it is now a compound attack over
both routes and kills validly. **DISPOSITION: CLOSED.**

### P1-4 — CLOSED

Node existence is asked of pytest directly and the exit code is read rather than
the prose: 4 and 5 are INVALID_TEST_TARGET, never a kill. A deleted or renamed
proof can no longer be mistaken for a failing one.

### P1-5 — CLOSED

`xfail_strict = true` is configured and parsed from the real file rather than
asserted about in prose, so an XPASS fails the run. The census no longer skips
xfails past the gate: they are counted against `EXPECTED_XFAILS`, which is
intentionally empty, and an undeclared one fails in its own vocabulary. Ten
tests, including the unstrict control — without it the strict test measures
nothing.

### P1-2 — CLOSED

The ledger schema is closed over what may be PRESENT. `PRAGMA index_list`
reports what the engine will constrain, not what it will do with the write, and
one `BEFORE INSERT … RAISE(IGNORE)` trigger made every consumption a silent
no-op: five callbacks from one grant, zero rows, every uniqueness and continuity
check still passing.

Closed asymmetrically, and that is the finding within the finding. The first fix
also *required* `ledger_identity`, which refused a ledger with no establishment
record as unusable — true, and the wrong state: that case is already modelled as
`LEDGER_CONTINUITY_UNKNOWN`, a denial that names the unanswered question. The
symmetric version was caught by two execution-semantics tests failing on a
clause they were not written to reach. An extra object is an outage; a missing
establishment record is a denial; neither may be reported as the other.

### P1-1 — CLOSED

Measured before patching, per instruction; the table is
[AUTHORITY\_VALUE\_FLOW.md](AUTHORITY_VALUE_FLOW.md).

The result reframed the finding. `RuntimeSecurityContext` is **uniformly
frozen** — every authority-bearing field is a bootstrap snapshot, which is the
intended model, so staleness alone was not the defect. The defect was a *second
consumer of the same question that read live*: `assurance_state()` re-opened the
trust store while the boundary answered from the snapshot.

Measured, bootstrapping against no store and provisioning one afterwards:

```
boundary   action_signers=[]  available=False        -- refuses
reported   consequential_authority="available"       -- claims it can
DANGEROUS_DIVERGENCE  true
```

Reporting is now a view of the snapshot, so the two cannot drift: after the fix
`DANGEROUS_DIVERGENCE false` and `INCOHERENT false`. The snapshot gained an
explicit `unusable` flag so absent and broken stay distinguishable without
reopening the file — three states preserved, not two.

Scope, stated plainly: only the reporting path re-read. The action boundary
takes `frozen_action_trust` from the context on the serving path, so this was a
truthfulness defect and is **not** reported as an action-release bypass.

One sub-question is left explicitly open rather than closed quietly:
`load_authorizer` re-reads the runtime contract and lock at every boundary
construction. Three attempts to measure whether that can change what is
permitted all produced INVALID_BASELINE — the authorizer does not load in a
copied tree (no lock, no generated evidence) and the current runtime contract
does not pass governance validation. No classification was made. It is deferred
to the gate that regenerates evidence in causal order, and recorded in
[AUTHORITY_VALUE_FLOW.md](AUTHORITY_VALUE_FLOW.md) §4.

### What was open AT `45f858c` -- superseded

All twelve P2s and all seventeen P3s were open **at that failed
pre-candidate head**. Their dispositions are in the Closed tables above.
This heading read "### Still OPEN" and was the last thing in the file, so
the document's final word said twenty-nine findings remained -- including
five controls its own body documents as repaired.
