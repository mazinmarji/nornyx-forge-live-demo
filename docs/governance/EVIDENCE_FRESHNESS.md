# Evidence freshness, and what actually expires

An earlier release of this repository claimed "the public baseline no longer
expires". That claim was false. It rested on
`MACHINE_EVIDENCE_EXPIRES = "2099-01-01T00:00:00Z"` — a finite date far enough
away to look like forever. This document records what Nornyx 1.11.0 actually
supports, what this repository does as a result, and how to keep the baseline
healthy at any instant.

## Three different clocks

| Thing | Expires? | Representation |
|---|---|---|
| Authority **declaration** (`approvals[].expires_at`) | No | `null` |
| Machine **evidence** (`governance_evidence`, `architecture_evidence`) | Yes, finite window | timestamp, regenerated at review time |
| Agent **authorization intervals** (`agent_identities`, `agentic_network`) | Yes, finite window | timestamp, regenerated at review time |
| Human **approval** (`approval_record`) | Yes, P7D cap | timestamp, never touched by tooling |

## What Nornyx supports, verified against the CLI

**Authority declarations genuinely do not expire.** `expires_at: null` on an
approval declaration is accepted, and stays accepted at 2100 and 2200. This is
the correct semantics: a declaration says *who may approve and over what scope*.
It is not an approval, and it has no reason to decay. The baseline now carries
`null` rather than a distant date. `tests/test_expiry_semantics.py` asserts this
against the real CLI.

**Machine evidence has no non-expiring representation.** This is a capability
gap in Nornyx 1.11.0, and the schema and the evaluator disagree about it:

- `nornyx/schemas/governance_evidence_v1.schema.json` declares
  `expires_at: {"oneOf": [timestamp, null]}` — advertising that null is valid.
- `nornyx/governance/structural.py` parses `generated_at` and `expires_at`
  unconditionally in its freshness check and raises `EVIDENCE_TIME_INVALID`
  when either is absent.

So a record that the schema accepts is rejected by the evaluator. Writing
`expires_at: null` on six governance evidence records produces six
`EVIDENCE_TIME_INVALID` diagnostics.

Architecture evidence does not even advertise the option:
`architecture_evidence_v1.schema.json` requires `expires_at` and gives it no null
branch. There is no per-record or per-module freshness exemption either;
`maximum_age` governs only the approval-record P7D cap.

**Agent authorization intervals must be bounded.** `expires_at: null` on an
`agent_identities` entry is refused with `GOVERNANCE_BLOCK_SCHEMA_INVALID` and
`AN_AUTHORIZATION_INTERVAL_INVALID`. That refusal is correct — an agent's
authority is exactly the kind that should lapse — so it is not treated as a gap.

## What this repository does

Machine evidence and authorization intervals carry an honest finite window
(`MACHINE_EVIDENCE_WINDOW_DAYS`, 365 days from the generating run). No magic
constant pretends otherwise.

The baseline is kept healthy by **regenerating it at review time**, which is one
command:

```bash
python scripts/check_pre_approval_baseline.py --regenerate
```

That rebuilds the evidence artifacts, rebinds the contracts to them, and then
asserts the contracts fail *only* for want of a human approval. It works at any
instant; `--as-of` evaluates at an explicit one:

```bash
python scripts/check_pre_approval_baseline.py --regenerate --as-of 2200-01-01T00:00:00Z
```

`tests/test_expiry_semantics.py` proves this at 2100 and 2200: after
regeneration the only remaining diagnostics are the three that say a human has
not approved the contracts, identical to the set produced today.

## What is deliberately not regenerated

Human approval records. They are never generated, refreshed, extended, or
rebound by any tooling in this repository, and Nornyx caps their window at P7D.
Authority genuinely decays, and re-approval is a human act.

`require_approval_matches_head()` additionally refuses to run any approval-bound
operation when a human approval exists and the governed tree has drifted from
the commit it pins — so regeneration cannot quietly restamp content that an
approval covers.
