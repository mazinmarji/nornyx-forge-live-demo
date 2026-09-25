# Assurance tiers

This document states, before work begins, how much proof a change is required to
carry. It establishes nothing about any change, and it is not evidence that any
tier was applied.

## Activation boundary

This document canonizes the assurance-tier model and the review-entry semantics.
It is not yet a step of standing-development admission: the admission mechanism
does not currently require a development cycle to load this document or to
declare a tier. Making pre-work tier declaration mandatory requires a separate,
admitted repository-changing tranche that wires this document into the
controlling development procedure. This document neither authorizes nor
performs that wiring.

## Why this document exists

The hardening programme that produced `RELEASE_CONTRACT_V1.md` ran fifteen review
rounds, and every round found something real. That contract fixed the *termination*
problem: a frozen, explicit contract replaced "keep attacking until a capable
reviewer cannot find another P1".

It did not fix the *proportionality* problem. Under a single standard, a
documentation correction and an irreversible one-shot operation carry the same
ceremony. The observable cost is not that the rigor is wasted — the rounds found
genuine defects — but that the same rigor applied everywhere makes the expensive
work indistinguishable from the cheap work, and so the cheap work gets expensive
rather than the expensive work getting safer.

This document states, before work begins, how much proof a change has to carry.

**It cannot be used to lower a bar that something else sets.** A tier selects a
recipe; it never overrides `RELEASE_CONTRACT_V1.md`, `CLOSURE_PROTOCOL.md`,
`HUMAN_BLOCKED_MEASUREMENTS.md`, a deterministic gate, an evidence requirement, or
any human or organizational authority. Where a tier and one of those disagree, the
other wins and this document is wrong.

## The rule

> Escalate assurance because of what the step can permanently break, not because
> the previous step happened to be difficult.

A milestone declares its tier **before** work begins. Declaring it afterwards is
choosing the recipe once the result is known, which is not a control.

## The tiers

### Tier G — genesis, irreversible, privileged, authority-changing, one-shot, authorization-consuming

For anything that can permanently alter authority or trust state, or that cannot be
retried: the first record in a chain, a privileged provisioning act, a checkpoint
or host mutation, retirement of a capability, anything consuming a one-shot
authorization.

Required:

- the production entry point rehearsed end to end against a local fixture, not a
  unit test of its parts;
- adversarial review by a reader who did not build it;
- fail-closed tests for every refusal path the operation can take;
- mutation testing where executable guards decide the outcome;
- exact-byte review: path, SHA-256, byte count, scope;
- explicit human authorization naming those exact bytes;
- the authorization consumed by the invocation, whether it succeeds, refuses, or
  fails after mutation begins.

### Tier H — high-impact but recoverable

For work whose failure is visible and correctable: measurement logic a decision
rests on, architecture acceptance, instrumentation, analysis that feeds a claim.

Required: behavioural tests including the negative paths, targeted adversarial
review, an independent reviewer, exact-head acceptance. Mutation testing only where
a guard decides the outcome — **not** as a ritual over every line.

### Tier N — normal governed engineering

For ordinary reversible work: documentation, reporting, inventory disposition,
implementation that changes no authority.

Required: the repository's ordinary CI, review and evidence discipline. Escalate
only when a trigger fires.

## Escalation triggers

When a trigger below fires, the milestone is re-tiered to the **highest applicable
tier**, the highest tier any firing trigger requires, and the move is recorded.

**Property triggers.** These are Tier G's own properties. Work found to have any of
them is Tier G, whether it was declared N or H:

| Property the work is found to have | Tier |
|---|---|
| irreversible: it writes to state that cannot be restored from the repository | G |
| authorization-consuming: it can consume an authorization | G |
| genesis: it is the first record in a chain that later records depend on | G |
| privileged: it is a privileged act, such as privileged provisioning | G |
| one-shot: it cannot be retried | G |
| authority-changing: it can alter an authorization, or permanently alter authority or trust state | G |

**Tier H is never a terminal tier for work that has a Tier G property.** Moving such
work one step up from N would leave it at H, below the floor its own properties
set, and without the exact-byte authorization, refusal tests and rehearsal that
Tier G requires.

**A Tier G property is blocking whenever it is found, including after acceptance.**
It is never batched as a non-blocking finding: an acceptance at a lower tier lapses,
and the milestone re-enters the review-entry gate at Tier G.

**Process triggers.** These say the declared tier is proving too little, not that
the work has a Tier G property. Either one moves the milestone up one tier:

1. a deterministic gate cannot express the property, so a human reading is the
   only check;
2. two review rounds find defects in the same structural class.

Where both kinds fire, the higher result stands: a process trigger never lowers
the tier a property trigger requires.

## The review-entry gate

Independent acceptance review does not start while the architecture or decision
surface is still moving.

Measured reason: a review that participates in design cannot be the review that
falsifies it, and no round can be known to be the last, because each round's
repairs create the next round's subject. Before review is entered:

- the architecture and decision surface are frozen;
- every proof obligation is in a terminal state — proved, deliberately deferred and
  named, or explicitly NOT ESTABLISHED;
- the real entry point has been rehearsed where the tier requires it;
- every active mutant carries a terminal disposition;
- the deterministic finalize sequence has run;
- candidate hashes are frozen.

A finite obligation ledger is what makes a review round the last one. Without it,
each round is a draw from an unknown distribution.

## Stopping rules

**One repair cycle, not another fifteen.** `RELEASE_CONTRACT_V1.md` governs, with
`CLOSURE_PROTOCOL.md` for the specimen and revert control: a finding
proven to violate a property that `RELEASE_CONTRACT_V1.md` names gets a root fix, a permanent specimen, a revert
control, and a re-run of the affected review. The assurance philosophy is not
redesigned because a third reviewer found something in its own scope.

**Non-blocking findings are batched.** After acceptance with non-blocking findings,
bytes change before execution only if a finding touches an irreversible assertion,
an authority or security boundary, or a known unmeasured execution path. Everything
else becomes a named deferred item. Re-opening accepted bytes for an improvement
invalidates the acceptance and buys nothing.

**Absence is never self-justifying.** Anything leaving a measured set — a mutant, an
obligation, a specimen — carries an explicit terminal disposition. A shrinking count
is not evidence of improvement unless the reason each item left is recorded.

**The complexity alarm.** Stop feature work and simplify when assurance or support
code materially exceeds the mechanism it governs, or when three review cycles find
defects in the same structural class. The response is lower complexity, not lower
assurance.

## What this document does not do

It does not authorize anything. It does not establish that any milestone was
correctly tiered, that a declared tier was honoured, or that a rehearsal was
faithful. Those are claims a reviewer checks against evidence, and this document is
not evidence for them.

It sets no schedule and predicts no duration. A tier is a floor on proof, never a
budget for it.
