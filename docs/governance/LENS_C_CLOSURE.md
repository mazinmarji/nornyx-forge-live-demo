# Lens C — closure record

    Verified tree           990caea
    Verification status     exact-tree assurance cycle PASS
    Recorded by             a LATER commit than the one verified

## What this document does and does not say

It says that the tree at `990caea` passed a complete assurance cycle. It says
nothing whatever about the commit that contains this file.

That distinction is not pedantry, it is the finding this record exists because
of. `docs/` is inside `GOVERNED_INPUT_PATHS`, so writing a document that
describes a verified tree MOVES the digest of that tree. The commit carrying
this file therefore cannot be the commit it certifies -- and three earlier
governance documents made exactly that mistake, asserting in the present tense
that `--verify` passed while the act of asserting it was the reason it failed.
Measured, not argued: `94fe40b` and `16aed3e`, the commits that introduced those
transcripts, both ship evidence that does not describe them.

The containing commit is whichever commit added this file:

```bash
git log --diff-filter=A --format='%h %s' -- docs/governance/LENS_C_CLOSURE.md
```

It has its own evidence, regenerated in that same commit, and its own gates. It
did not undergo the cycle below, and no reader should treat it as if it had.

## The cycle, as measured at 990caea

<!-- verify-measured-at: 990caea -->

```
full pytest suite            RC=0, zero failures
census                       RC=0, GATE: PASS
  collected                  1115
  expected skips             9
  unexpected skips           0
  unexpected xfails          0

ruff (whole tree)            rc=0
compileall                   rc=0
architecture                 rc=0
security                     rc=0
pre-approval baseline        rc=0
repository validation        rc=0
evidence binding             rc=0

--verify
  status                     pass
  integrity_state            intact
  governed_input_match       True
  evidence_manifest_match    True
  problems                   0

evidence self-consistency    recorded digest == actual digest
grandfather dependence       NONE -- 990caea is not in the baseline
working tree                 clean, 0 porcelain lines

assurance_state              not_independently_inspected
independent                  False
authenticated_reviewers      []
```

The last three lines are as important as the rest. Nothing here establishes
independent inspection, human approval, or production authorization. The cycle
proves the tree is internally consistent and its proofs discriminate; it does
not confer assurance that only a human can confer.

## Findings closed at this head

| id | finding | closed by |
|----|---------|-----------|
| C-P1-1 | governance documents asserted `--verify` passed while it failed; the claims were false when written, not merely stale | measurements anchored with `verify-measured-at`, admitted only when the named commit's evidence actually describes it |
| C-P1-2 | two live integrity proofs had become tautologies -- `compromised` was already true before any attack | `require_discriminating_baseline`; the forgery proof settles its copy first and was measured transitioning `intact -> compromised` |
| C-P2-1 | `ARCHITECTURE.md` named five of seven process-start sites, omitting the two nearest the trust boundary | corrected, and pinned bidirectionally so padding the list also fails |
| C-P2-2 | `README.md` claimed the documented workflow "launches the application, and prints" the URLs and required "strict Nornyx/CrewAI execution" | measured: the `--strict-nornyx` demo exits 2; backend is `sequential` both configured and observed; three pins, the README one an equivalence rather than a ban |
| C-P2-3 | three campaign documents disagreed at one head with no supersession marker | superseded, pointing at the executable catalogue; no new totals published |
| C-P2-4 | `CLAUDE.md` carried a success criterion no autonomous run could ever satisfy | split into contract/integrity validation and production-approval readiness, the latter explicitly unmet |

## Two things deliberately left open

**The census `F`.** A `check_test_coverage.py` run showed a failure marker at
roughly 39% during this work. It was observed ONCE, in a run that was killed
mid-flight while `tests/test_evidence_binding.py` was being edited. It has not
reproduced on any stable exact-tree run since, including the census recorded
above. A race against the concurrent edit was hypothesised and never
demonstrated, so it is recorded here as an untested hypothesis and NOT as the
cause. The honest statement is: observed once, not reproduced, cause unknown.

**Task 11.** Every historical mutation total predating the corrected proof
kernel is dead evidence, including `41 = 37 + 4`. They are not adjusted, carried
forward, or cited. A new aggregate may exist only after every attack has been
replayed through the full admission protocol to a terminal classification.
