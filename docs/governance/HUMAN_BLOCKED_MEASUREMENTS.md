# HUMAN_BLOCKED_MEASUREMENTS = 2

Two measurements cannot be executed by any machine action, because the
authorizer they depend on will not load until a genuine human approval has been
adopted. They are recorded here rather than counted anywhere else.

**They are not `INVALID_BASELINE`.** That outcome describes an attack that
entered the admission protocol and failed step 2. These never entered it: the
precondition is external, and no amount of machine work changes that.

They do not count as green proof. They also do not block machine remediation —
everything else proceeds, and these two stay explicitly open as an external
prerequisite for later assurance.

## Permanent rule

**NO SYNTHETIC APPROVAL FOR ASSURANCE CLOSURE.**

An approval record may never be created, inferred, simulated, backdated or
adopted in order to make a measurement executable, to close a finding, or to
turn a report green. A measurement that requires a human decision is blocked
until a human makes it. Manufacturing the precondition would not produce the
evidence the measurement is for — it would produce a number with nothing behind
it, which is the exact failure this whole programme has been correcting.

Evidence state AS MEASURED AT THE COMMIT NAMED BELOW. It is not a claim about
the current head, and the phrasing it replaced — "current evidence state, which
is valid and honest as it stands" — was a standing assertion that no later
commit could keep true. Run `--verify` to learn the state of this head.

<!-- verify-measured-at: 341e177 -->

```
status                 pass
integrity_state        intact
problems               []
governed_input_match   true
assurance_state        not_independently_inspected
human approval         absent
production authorization absent
```

---

## D1 — does `load_authorizer` re-reading contract and lock permit a G1/G2 mix?

**Question.** `NornyxActionBoundary.__init__` calls `load_authorizer(contract,
lock, validation_as_of=…)` on EVERY construction, while the injected subject and
integrity verdict are frozen at bootstrap. Can a contract edited after bootstrap
change what is permitted, while the frozen verdict still certifies the pre-edit
state — policy from governed state G2 judging an identity from G1?

**Required human prerequisite.** A genuine adopted human approval record.
`runtime_network.nyx` declares `approval_record` in `required_evidence`, and
without it `load_authorizer` raises `AuthorizerLoadError: CONTRACT_INVALID:
AN_APPROVAL_RECORD_MISSING, APPROVAL_EVIDENCE_MISSING, EVIDENCE_REQUIRED_MISSING`.

**Why no machine action may satisfy it.** The two refresher flags that would
clear those codes — `--wire-approvals` and `--adopt-approval` — put an ADOPTED
HUMAN APPROVAL into the contracts. There is none to adopt, and creating one is
forbidden by the rule above. Evidence regeneration was run in full and is
necessary but not sufficient: at `341e177` it produced `status: pass`,
`integrity: intact`, `problems: []`, and the authorizer still did not load.
The blocker is the absent human approval, which no regeneration can supply.

**Exact commands once a genuine approval exists.**

```
python scripts/refresh_governance_evidence.py --adopt-approval
python scripts/refresh_governance_evidence.py --verify
python -c "import sys; sys.path.insert(0,'src'); \
from pathlib import Path; \
from nornyx_forge.subject_bootstrap import bootstrap_security_context; \
from nornyx_forge.nornyx_runtime import NornyxActionBoundary; \
ctx=bootstrap_security_context(Path('.')); \
b=NornyxActionBoundary(Path('.'), runtime_subject=ctx.runtime_subject, \
governance_integrity=ctx.governance_integrity, \
frozen_action_trust=ctx.action_approval_trust, \
established_root=ctx.established_root); \
print(b.authorizer is not None, b.load_error)"
```

**Expected baseline.** `authorizer is not None`, and a boundary built from a warm
context returns a decision for a valid high-risk grant. If the authorizer does
not load, the attempt is `INVALID_BASELINE` and must not be classified.

**Expected mutation.** In a `faithful_copy` workspace with the real lock carried
across: edit `.nornyx/contracts/runtime_network.nyx` AFTER bootstrap, in a way
that changes what the policy permits rather than only its bytes, then build a
SECOND boundary from the SAME warm context.

**Expected classification procedure.** The six admission steps. Node exists;
pristine baseline passes; the edit reaches an authoritative construct
(`check_structured_mutation`, since a `.nyx` is parsed rather than executed);
the mutant tree is what loads; the semantic effect is present — the parsed
contract differs in a decision-bearing field; the same probe runs. Then:

- decision unchanged → the lock binds the contract, and the frozen verdict is
  never asked to certify a state the authorizer did not read. Record as
  **KILLED_VALIDLY** for the lock-binding property.
- decision changed → **SURVIVED**, and a candidate P1: policy from G2 judged an
  identity from G1.

---

## D2 — is the zone crossing authorized at every risk level, behaviourally?

**Question.** `canonical_action_request` pins
`destination=zone.external_customer` on every request regardless of risk. The
crossing is now evaluated whenever the capability is allowed, rather than only
for high risk. That change is asserted STRUCTURALLY. Does the authorizer
actually return a `ZoneCrossingRequest` decision at low and medium risk?

**Required human prerequisite.** The same adopted human approval. Without a
loading authorizer there is no decision to observe: the boundary falls back and
denies high risk outright, and the fallback evaluates no zone crossing at all.

**Why no machine action may satisfy it.** Identical to D1.

**Exact commands once a genuine approval exists.**

```
python -m pytest tests/test_action_binding.py -k zone -q
python -c "…drive evaluate_and_execute at risk in (low, medium, high) and read \
the recorded evidence stream for trust_zone_crossed…"
```

**Expected baseline.** For each risk level, the authorizer loads and the evidence
stream is written. A run whose authorizer is absent is `INVALID_BASELINE`.

**Expected mutation.** Restore the historical condition — evaluate the crossing
only under `capability.allowed and high_risk` — in a copy.

**Expected classification procedure.** The same six steps, then compare the
recorded event streams at low and medium risk. The structural test in
`tests/test_action_binding.py` is explicitly labelled as structural and is not
evidence for this question.

- low/medium stream loses its crossing decision under the mutation →
  **KILLED_VALIDLY**.
- streams identical → **SURVIVED**: the crossing is claimed on every request and
  evaluated on none of the low-risk ones, which is the finding A-P2-4 named.
