# Authority value flow: what is frozen, what is live

Produced before any P1-1 patch, by measurement. Every classification below is
what the value *did* when its underlying source was changed after one bootstrap
— never what the code appears to read.

Method: bootstrap one `RuntimeSecurityContext`, mutate one source, then read
every authority-bearing value twice — **warm** (the long-lived context that
real requests are served from) and **cold** (a fresh bootstrap). FROZEN means
the warm value did not move. LIVE means it did. Sources are restored
byte-exactly and the restore is asserted.

Harness: `faithful_copy` workspace, `PYTHONPATH` isolation, probes retained in
the session scratchpad.

## 1. Values held on `RuntimeSecurityContext`

| VALUE | SOURCE | ESTABLISHED WHEN | FROZEN / LIVE | OBJECT-BYTES DIGEST | CONSUMER | PER REQUEST? |
|---|---|---|---|---|---|---|
| `runtime_subject.governed_subject_digest` | governed tree bytes under `SubjectScope` | bootstrap | **FROZEN** | `sha256:4fc822cae24fac06…` | action boundary subject binding | no — one object, injected |
| `runtime_subject.governed_revision_digest` | git revision of the governed tree | bootstrap | **FROZEN** | `sha256:73379c1a5127a27b…` | subject binding, evidence | no |
| `runtime_subject.subject_verified` | observation success | bootstrap | **FROZEN** | — | `consequential_authority_available` | no |
| `governance_integrity.status` | recorded evidence digests vs artifacts | bootstrap | **FROZEN** | — | action boundary integrity gate | no |
| `governance_integrity.problems` | same | bootstrap | **FROZEN** | — | refusal text | no |
| `governance_approval_trust` | `FORGE_APPROVER_TRUST_STORE` → `domains.governance` | bootstrap | **FROZEN** | `sha256:e3b0c44298fc1c14…` (empty store) | `verify_governance_approval` | no |
| `action_approval_trust` | same file → `domains.action` | bootstrap | **FROZEN** | `sha256:e3b0c44298fc1c14…` | `authenticate_action_grant` | no |
| `authority_config` | caller-supplied | bootstrap | **FROZEN** | — | subject scope, evidence | no |
| `trust.approval_ledger` | resolved root | bootstrap | **FROZEN** | — | `ApprovalLedger` location | no |

**Measured, per source mutated after bootstrap:**

| SOURCE MUTATED | WARM MOVED | COLD MOVED | WARM `authorizes` | COLD `authorizes` |
|---|---|---|---|---|
| `src/demo_app/main.py` (governed byte) | *nothing* | `subject_digest`, `revision_digest` | `true` | `true` |
| `.nornyx/contracts/evidence/architecture_approval_record.json` | *nothing* | `integrity_status`, `integrity_problems` | `true` | `true` |
| `.nornyx/contracts/runtime_network.nyx` | *nothing* | `subject_digest` | `true` | `true` |

On the middle row a cold read reports `compromised` and a direct
`observe_governance_integrity` agrees, while the warm context still reports
`intact`. That is the reviewer's A-P1-1 observation, reproduced.

## 2. The finding, stated precisely

The context is **uniformly frozen**. There is no mixed model *inside* it: every
authority-bearing field is a bootstrap snapshot, which is the intended design
(*long-lived authority consumers receive immutable trust snapshots*).

Staleness alone is therefore not the defect. The defect is a **second consumer
of the same question that reads live**:

| CONSUMER | READS | FROZEN / LIVE |
|---|---|---|
| `NornyxActionBoundary` (releases effects) | `context.action_approval_trust` | FROZEN |
| `assurance_state()` (tells the interface what the deployment can do) | `ApprovalTrustDomains.load()` | **LIVE** |

Measured — store edited after startup:

```
FROZEN_MOVED      false
ASSURANCE_MOVED   true
INCOHERENT        true
```

And in the dangerous direction — bootstrap with **no** store, then provision one:

```
frozen_after_provision      action_signers=[]   action_available=false
assurance_after_provision   consequential_authority="available"
                            trusted_approvers_loaded=true
DANGEROUS_DIVERGENCE        true
```

The deployment reports that it can release consequential effects while the
boundary that would release them holds an empty action trust domain and will
refuse. One question, asked twice, answered two ways — and the answer an
operator sees is the one that is not enforced.

Severity is bounded by what re-reads: only the reporting path does. The action
boundary never re-opens the store, so this is a **truthfulness** defect, not an
action-release bypass. It is not reported as one.

## 3. The model chosen

**Immutable snapshot, with no second reader.**

1. `RuntimeSecurityContext` stays the single point where authority is
   established. Already true for every value in §1.
2. Every consumer of an authority question reads *that object*. No runtime path
   re-derives an authority value from its source.
3. Reporting is a *view of the snapshot*, so what the interface says and what
   the boundary enforces cannot disagree.
4. The snapshot keeps three distinct states per domain — provisioned, absent,
   unusable — because collapsing them would trade this defect for a different
   one: "nobody is trusted" and "the trust material is broken" authorize the
   same amount and mean different things to an operator.

Rejected: making the boundary read live. It reintroduces exactly the defect the
frozen store was added to close — editing the file between two requests changed
who the second one trusted, measured previously as one context serving request 1
with `test-approval-01` and request 2 with `attacker-key`.

## 4. One question left open, deliberately

`observe_governance_integrity` has exactly one caller — `bootstrap_security_
context` — so the integrity verdict has no second reader and cannot drift.

`NornyxActionBoundary.__init__` is different: it calls
`load_authorizer(contract, lock, validation_as_of=…)` on **every construction**.
That is a live read of the runtime contract and its lock. Whether a contract
edited after bootstrap can change what the authorizer permits — while the frozen
integrity verdict still certifies the pre-edit state — is a real question and it
is **not answered here**.

It could not be answered honestly yet. Three attempts, all discarded:

| attempt | result | why discarded |
|---|---|---|
| copied tree, direct boundary | both halves `DENY` | no runtime lock in the copy → deterministic fallback, not the authorizer |
| copied tree + real lock | `authorizer_loaded false` | copy lacks generated evidence: `AN_APPROVAL_RECORD_MISSING` |
| real tree, byte-exact tamper/restore | `authorizer_loaded false` | the runtime contract does not currently pass governance validation |

In each case the pristine baseline failed, so no mutation could have changed a
verdict and any classification would have been harness evidence rather than
security evidence. `INVALID_BASELINE` is the recorded outcome, not SURVIVED and
not KILLED.

**Deferred to the gate that regenerates evidence in causal order**, which is
where a contract that genuinely validates first exists. Until then the observed
behaviour is the safe direction: a contract failing validation yields
`AuthorizerLoadError`, `load_error` is set, and the fallback denies every
high-risk action unconditionally.

The restore was verified byte-exact and `git status --porcelain` was identical
before and after.
