# Forge Hardening v1 — the frozen release contract

## Why this document exists

The hardening programme ran fifteen review rounds over more than a week, and
every round found something real. That looks like evidence the system is
defective. It is better read as evidence that the *completion rule* was wrong.

The rule in force was, in effect:

> Keep attacking until a capable reviewer cannot find another P1 or P2.

A capable reviewer can always find one. Not by inventing false findings — the
findings were genuine — but by defining a deeper property than the one measured
last time: another serialization, another alias, another notion of
completeness, an attack on the harness, an attack on the proof that the harness
reaches the code, an attack on the proof that discovered attacks became
specimens. Each level is real, and there is always another level. That is
research, and research does not terminate on a release schedule.

This document replaces that rule with one that terminates:

> Forge satisfies a frozen, explicit contract, and no known P1 or P2 violates
> that contract.

## What is frozen

Four things. Each is frozen by a mechanical check, not by this sentence —
a claim typed beside a corpus nobody parses is AC03, and this document is not
exempt from the classes it names.

| Frozen | Where it lives | What checks it |
|---|---|---|
| Claims, and explicit non-claims | `docs/ASSURANCE_BOUNDARY.md`, `README.md` | `tests/test_documented_claims.py` |
| False-green corpus (42) | `tests/test_false_green_audit.py` `INVENTORY` | `test_the_inventory_is_exactly_the_declared_set`, both directions |
| Attack classes (7) | `tests/attack_classes.py` `ATTACK_CLASSES` | `test_the_attack_corpus_is_exactly_the_frozen_set`, both directions |
| Human-blocked preconditions | `docs/governance/HUMAN_BLOCKED_MEASUREMENTS.md` | `scripts/check_pre_approval_baseline.py` |

The claims are referenced, not restated. A second copy of the claim list in this
file would drift from the first, and the drift would be invisible — which is
the same mechanism as AC03 one level up.

### The attack classes, frozen at seven

    AC01  a rule that matches a SPELLING rather than deciding the property
    AC02  a fix that nothing fails without
    AC03  a claim measured in prose beside a table nobody parses
    AC04  a widening applied to discovery and not to inspection
    AC05  a gate that raises where it is relied on to report
    AC06  a coarse process exit read as the named subject's verdict
    AC07  a support range declared, and measured at one point in it

This list is a restatement for readers. `ATTACK_CLASSES` is authoritative, and
the two cannot disagree silently: `test_the_attack_corpus_is_exactly_the_frozen_set`
compares them in both directions.

## Severity, frozen

**P1** — a demonstrated violation of a property this contract names, reproduced
on the exact head under test.

**P2** — a demonstrated violation of such a property that requires a
precondition an attacker does not control, or whose blast radius is confined to
a single declared surface.

**P3 and below** — everything else. Explicitly including:

- a stronger property that Forge could have but never claimed;
- a new attack class that no reviewer has shown to violate a frozen property;
- a defect in a control's *depth* where the control still decides its stated
  property correctly.

**A reviewer may not raise a P1 by proposing a new product requirement.** If a
reviewer believes the frozen contract is too weak, that is a finding about the
contract, filed against v1.1 — not a defect in the release that satisfies it.
Weakening the contract to make a finding go away is forbidden by the same rule
that forbids weakening a policy to make an implementation pass; strengthening
it is a decision for a human, taken deliberately, between versions.

## What v1 does NOT close, and never could

Production approval readiness is out of reach of any autonomous run, and this
contract does not quietly absorb it.

Two external authorities are absent, and they are different from each other:

- **No genuine human approval record exists.** Three diagnostics stand on
  its absence:
  `AN_APPROVAL_RECORD_MISSING`, `APPROVAL_EVIDENCE_MISSING`,
  `EVIDENCE_REQUIRED_MISSING`.
- **No authenticated independent inspection exists.** Two more stand on
  its absence:
  `CHANGE_EVIDENCE_MISSING`, `SOD_EVIDENCE_PRODUCER_UNKNOWN`.

Five diagnostics, and `EXPECTED_PRE_APPROVAL_DIAGNOSTICS` in
`scripts/check_pre_approval_baseline.py` is the authority for the list.
Creating, adopting, inferring or backdating either authority is forbidden by
`docs/governance/HUMAN_BLOCKED_MEASUREMENTS.md`, permanently and without
exception.

So v1 closes as:

    HARDENED REFERENCE BASELINE — HUMAN APPROVAL STILL REQUIRED

and never as "approved", "production ready", or "released". A contract that let
a satisfied checklist stand in for an absent human decision would be the exact
substitution this repository was built to detect, committed by the document that
declares the repository finished.

## The closure gate

    Full local gate suite                       PASS
    Permanent hostile corpus (42 FG + 7 AC)     PASS
    Census: no unexpected skip or xfail         PASS
    Frozen contract                             satisfied

    Fresh bounded review A                      P1 = 0, P2 = 0
    Fresh bounded review B                      P1 = 0, P2 = 0
    Fresh bounded review C                      P1 = 0, P2 = 0

    Remote CI (3.10 / 3.11 / 3.12 / 3.13,
      container-launch, demo-contract,
      strict-authorization, hostile-probe)      PASS

    Exact candidate head frozen                 review/candidate-<sha7>
    ------------------------------------------------------------------
    FORGE HARDENING v1 — hardened reference baseline

## One repair cycle, not another fifteen

If a bounded review returns a genuine P1 or P2:

```
finding
    -> proven to violate a property THIS contract names
    -> root fix
    -> permanent specimen + revert control        (CLOSURE_PROTOCOL.md)
    -> re-run the affected review
```

The review is re-run. The assurance philosophy is not redesigned, and the other
two reviews are not restarted merely because a third found something in its own
scope. Redesigning the protocol on every finding is what made the previous
programme unbounded.

## Disposition of anything found after the freeze

Nothing found after the freeze retroactively unmakes v1. It is filed:

| Kind | Goes to |
|---|---|
| Violates a frozen property | v1.1, by the repair cycle above |
| Exploitable against a declared surface | security issue |
| A deeper property Forge never claimed | assurance research |
| A better control for a property already held | future enhancement |

The distinction that matters: **hardening Forge** is a project that finishes.
**Researching near-formal assurance for governed agentic software** is a project
that does not. The second produced most of the value of these fifteen rounds and
should continue — but it is not a precondition for the first.
