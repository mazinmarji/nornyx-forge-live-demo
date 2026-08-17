# Task 11 — CLOSURE WITHDRAWN

**This document previously declared Task 11 CLOSED. That declaration is withdrawn.**
Three independent Task-14 lenses against head 729a900 returned P1=7, P2=15.

The sharpest finding is about this file. `docs` is inside
`GOVERNED_INPUT_PATHS`, so committing this document moved the governed input
digest -- and it was committed WITHOUT re-running the causal regeneration chain
it claims to report. The document asserting `--verify` passes was the sole
reason `--verify` failed:

```
status                  fail          (claimed: pass)
integrity_state         compromised   (claimed: intact)
problems                12            (claimed: [])
governed_input_match    False         (claimed: True)
evidence_manifest_match False         (claimed: True)
```

Nine of the fourteen gate claims below were true when measured; the five false
ones are exactly the `--verify` block. That is what made it dangerous: an
operator spot-checking architecture, security, the baseline, the tree and the
1048-test census gets five confirmations, and `--verify` is the only local
control that sees the problem. `scripts/check_test_coverage.py` -- the gate the
README offers for verification -- cannot.

Second-order consequence, measured: because the real tree reports `compromised`,
`tests/test_subject_completeness.py:176` and `:185` became TAUTOLOGIES. All
eight parametrisations pass while measuring nothing. That is this repository's
own FG10 class, unenforced on the one test that reads the real tree.

The numbers below are retained as the record of what was measured, with the
false lines marked. Task 11 is OPEN.

---

## Original closure record (numbers as measured; --verify block FALSE)

Every value below is recomputed from the authoritative catalogue at closure, not
carried forward from an earlier report. Environment: CPython 3.12.10 on
Windows-11, nornyx 1.11.0, crewai 1.15.4, pytest 8.4.2.

## Catalogue

```
ROOT_PROPERTIES                17
ATTACK_REPRESENTATIONS         41
KILLED_VALIDLY                 37
DEFENCE_IN_DEPTH                4
COMPOUND                        1   (metadata on one kill, not a category)

41 = 37 + 4
```

Set identity holds, not merely counts: the catalogue's attack IDs equal
`REQUIRED_ATTACK_IDS` exactly, with nothing on either side. Every historical
class lands in **exactly one** terminal bucket, pinned by
`test_every_historical_class_has_exactly_one_terminal_disposition` — because a
class falling out of every bucket is how `NOT_YET_KILLED = 0` could be true while
a property went unrepresented.

## Terminal dispositions

| Bucket | Classes |
| --- | --- |
| `KILLED_VALIDLY` (direct) | 14 classes, one mutation each |
| `KILLED_VALIDLY_COMPOUND` | H03, H04 — four measured routes, minimal compound |
| `OBSOLETE_HISTORICAL_ATTACK` | H13 — precondition traced and gone |
| delegated to dedicated catalogues | H11 (domain collapse), H12 (semantic projection) |

## Machine-actionable non-terminal categories

```
SURVIVED                        0
NOT_YET_KILLED                  0
AIM_UNPROVEN                    0
INVALID_MUTATION                0
INVALID_BASELINE                0
INVALID_TEST_TARGET             0
INVALID_TEST_AIM                0
INVALID_MUTATION_ENVIRONMENT    0
UNPROVEN_MACHINE_ACTIONABLE     0
```

## Reported separately, and not green proof

```
HUMAN_BLOCKED_MEASUREMENTS      2
  D1  load_authorizer re-reading contract and lock — G1/G2 mix
  D2  zone crossing authorized at every risk level, behaviourally
```

Both need a genuine adopted human approval before their baseline can load. The
commands, expected baseline, expected mutation and classification procedure are
recorded in [HUMAN\_BLOCKED\_MEASUREMENTS.md](HUMAN_BLOCKED_MEASUREMENTS.md).
**NO SYNTHETIC APPROVAL FOR ASSURANCE CLOSURE.**

## Closure evidence

```
pytest                      rc=0, collected 1048    [true]
expected skips              9
unexpected skips            0
unexpected xfails           0
census                      GATE: PASS
ruff (whole tree)           clean
compileall                  clean
architecture                clean
security                    clean
pre-approval baseline       clean
working tree                clean

--verify
  status                    pass   [FALSE]
  integrity_state           intact   [FALSE]
  problems                  []   [FALSE]
  governed_input_match      True   [FALSE]
  evidence_manifest_match   True   [FALSE]
  assurance_state           not_independently_inspected
  independent               False
  authenticated_reviewers   []
  human approval            absent

behaviour
  low risk                  ALLOW, callback ran
  high risk                 DENY, callback did not run,
                            HUMAN_APPROVAL_REQUIRED
```

## What made this campaign different from the one it replaced

The previous campaign reported "34 attacks, 31 kills, 0 survivors, 0 invalid".
At least three of those kills were invalid. Six admission steps became nine, and
each addition came from a defect that had already produced a false result:

- **pristine baseline** — three classes were credited kills in a workspace where
  their proofs already failed;
- **assertion failure, not exit code** — an `ImportError` exits non-zero too;
- **mutant origin measured, not grepped** — the old proof matched a line present
  in nearly every test module;
- **executable projection** — an anchor running into a docstring changed only
  prose;
- **branch-body reachability** — statement reachability said "reached" for a
  branch that never ran;
- **provenance with a per-run nonce** — a marker echoed as source text by
  `--tb=long` was read as a clause that had executed.

Five classes had their aim or mutation corrected by measurement rather than by
argument: H14 and H17 were aimed from a test name, H18 from a helper name, H15
twice, and H13 three times. In two cases the comfortable reading was "defence in
depth" and it was wrong both times — H15 was a test that never reached the
control, H18 a mutation that never reached it.

Two classes turned out to have controls with **no executable proof at all**: H15
(no test deleted a governed module) and H13 (no test combined a stale attestation
with two regenerations). Both proofs were written.

## What this campaign does not claim

- H13 is retired, not defeated. Its historical consequence cannot occur under the
  current derivation graph, and that is traced rather than inferred from survival.
- Seven classes' worth of coverage detail, and every disposition rationale, is
  in the catalogue source rather than summarised here.
- Nothing above is independent assurance. `assurance_state` is
  `not_independently_inspected` and no reviewer trust store exists.
