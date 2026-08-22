# Lens C — closure record

    Verified tree           990caea
    Verification status     cycle PASS WITH ONE ROW WITHDRAWN -- see below
    Recorded by             a LATER commit than the one verified

## What this document does and does not say

It says that the tree at `990caea` was CLAIMED to have passed an assurance
cycle WITH ONE ROW WITHDRAWN: the full-pytest row below is struck, because a review archived this
SHA into a clean directory and measured `1 failed`. The header said "complete"
while the body withdrew its central row, and the header is unfenced so nothing
in the suite ever read it. It says nothing whatever about the commit that
contains this file.

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

Split deliberately. Only `--verify` output sits inside the anchored block,
because only those fields can be recomputed at that commit and compared.
A review built an anchored block carrying `collected 999999` and
`authenticated_reviewers ["alice","bob","carol"]` next to
`integrity_state intact`, and both checks admitted it. Everything a machine
cannot recheck at that SHA now lives OUTSIDE the fence.

<!-- verify-measured-at: 990caea -->

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

REPORTED, NOT MACHINE-VERIFIED BY THE ANCHOR. Observed when the cycle ran,
recorded on that basis alone. Re-run them to confirm; do not read them as
bound to the SHA above.

WITHDRAWN, AND THE LABEL ABOVE WAS NOT ENOUGH. "Not machine-verified" discloses
that nothing re-checks these numbers. It does not disclose that the first one
is FALSE for any reader who checks the commit out, which is a different and
worse thing. An independent review archived 990caea into a clean directory and
measured `1 failed`: `test_the_strict_backend_actually_fails_closed_in_this_
repository` asserted `CONTRACT_INVALID`, which appears only once a runtime lock
exists, and the lock is gitignored and unobtainable without a human approval.
The RC=0 recorded here was true in the author's working tree and nowhere else.

That defect is fixed at a later head -- both the assertion and its twin in
`tests/test_approval_reachability.py` now establish the CAUSE of the refusal
rather than matching a diagnostic string -- but it was present at the commit
this block names, so the row below is struck rather than restated.

    full pytest suite            WITHDRAWN -- 1 failed on a clean checkout of
                                 this SHA; RC=0 held only in the author's tree
    census                       RC=0, GATE PASS, 1115 collected
    expected / unexpected skips  9 / 0, unexpected xfails 0
    ruff, compileall             clean
    architecture, security       clean
    pre-approval, repo validation clean
    evidence binding             clean
    evidence self-consistency    recorded digest == actual digest
    grandfather dependence       NONE -- 990caea is not in the baseline
    working tree                 clean, 0 porcelain lines

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
