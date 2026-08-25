# Closure protocol — what it takes for a finding to be closed

Fifteen review rounds found real defects in every round. That is not a signal
that the system is failing; it is a signal that an observed exploit was being
converted into a *fix* without being converted into a *permanent executable
specimen*. The fix worked. Nothing failed without it. The next lens found the
same class one spelling over.

This document is the rule that ends that loop. It is binding on every finding
from this point forward.

## The rule

> A discovered escape is not remediated until the exact hostile behaviour is a
> permanent specimen, and a control proves that reverting the fix makes that
> specimen fail.

Concretely, the sequence is:

```
observed attack
    -> canonical hostile specimen        (committed, named, collected)
    -> root fix
    -> production-path proof             (the real caller consumes it)
    -> revert control goes RED           (one fix at a time, measured)
    -> specimen stays forever
```

What it replaces:

```
observed attack -> temporary probe -> fix -> probe discarded
```

Three of round 14's P1s existed for exactly that reason, and one of them was
proven by a reviewer replacing a repaired function's body with `return True`
and watching every control stay green.

## No finding may live only in narrative

No finding discovered from this point forward may exist only in reviewer notes,
scratch probes, or a commit message. If it can be reproduced, it becomes an
executable permanent specimen **before** it is considered closed. A measurement
quoted in prose is a claim; a specimen is a control.

This applies to the negative direction too: the over-reach case — the thing
that must keep working — belongs in the same table as the escape. Every
specimen table in this repository that pointed one way was later found to have
an unpinned opposite.

## Classify before patching

When a new finding arrives, decide first which of these it is:

1. **A genuinely new root mechanism.** Add the class to
   `tests/attack_classes.py`, and its executable class probe to
   `tests/test_attack_classes.py`. The registry module is not collected by
   pytest, so a table placed there is parsed by nothing -- this document
   said otherwise, and a contributor following it would have produced
   exactly the local patch this protocol exists to prevent.
2. **Another un-specimenized member of a class already known.** Do NOT write a
   local patch. Expand the class: widen the probe so it enumerates the new
   member and every sibling the same reasoning reaches, and fix them together.

The second is the common case. The largest single class — a rule matching a
spelling rather than the property — was rediscovered round after round
because each instance was repaired where it was found. Its instances are
listed in the registry; no count is stated here, because a count typed
beside a list nobody parses is AC03, and this document is not exempt from
the classes it names.

## Measuring progress

Not by number of review rounds. By whether the permanent hostile corpus has
reached closure under fresh independent lenses: three lenses, exact head, no
reuse of prior conclusions, all returning P1=0 and P2=0.

## Where the corpus lives

| Corpus | Where |
|---|---|
| False-green classes and their executable reproductions | `tests/test_false_green_audit.py` (`INVENTORY`) |
| Attack classes, their mechanisms and instances | `tests/attack_classes.py` |
| The class probes themselves | `tests/test_attack_classes.py` |
| Historical defect reproofs | `tests/test_historical_reproof.py` |
| Mutation catalogue | `tests/test_mutation_catalogue.py` |
| Screen specimens | `tests/test_false_green_audit.py` specimen tables |
| Evidence-ledger specimens | `tests/test_evidence.py` |

A class that is not in one of these is not closed, whatever a commit message
says about it.
