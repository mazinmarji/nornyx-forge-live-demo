# Changelog

## Unreleased — hardening from adversarial review

- Approval records are emitted by the YAML serializer instead of hand-formatted
  text. Interpolating artifact-controlled fields let a crafted `status` close
  the record, forge the managed end-marker, and append a rogue approval that
  then survived the documented cleanup. Fields must now be plain single-line
  scalars, and any `approval_record` outside the managed markers is refused
  rather than tolerated.
- `--materialize-approval-window` has an inverse. Withdrawing an approval left
  the authority declarations pinned to the short reviewer window, which re-rotted
  the baseline once that date passed; the placeholder is now restored.
- `--review-binding` is guarded like every other write path. It is the document
  a human reads before approving, and it was still reporting a stale approval as
  granted while `HEAD` had diverged.
- A corrupt or unwritable approval ledger is a governed refusal rather than a
  raw `sqlite3` error surfacing as a 500. A ledger that cannot record a claim
  cannot promise single use, so the effect is withheld.
- `--sync-contracts` validates the timestamps it interpolates. It is a second
  writer into the same records, and the values come verbatim out of the human
  artifact, so a crafted `expires_at` reached a raw f-string and appended a
  forged approval while the run reported `synced` and exit 0. Both writers now
  assert the single-managed-approval invariant.
- `--verify` re-parses the contracts instead of only re-hashing artifacts.
  Hashing an artifact says nothing about the contract that references it, so a
  contract carrying a second `approval_record` still reported `pass`.
- The capability an action approval is validated against is the one the risk
  level actually exercises, not the one the caller names in the request. A
  high-risk act labelled `execute_low_risk_action` matched a grant bound to that
  label on every field — the digest covers the same mislabelled request — and
  released the effect. The mismatch now withholds without spending the grant.
- Runtime producer version is read from the package rather than hardcoded.
- An action approval is validated against the execution context, not against the
  caller's description of it. Checking that `request.capability` matched the
  exercised capability fixed one field and left the rest: every other field the
  approval was compared against still came from the caller-supplied request, so a
  valid unspent approval for mission A released mission B's callback. The runtime
  now builds the canonical `ActionRequest` itself — mission, request id,
  capability, governed revision and destination all derived from the execution
  context — and validates the approval against that. A supplied request is a
  claim that gets checked field by field; on mismatch the action is denied, the
  approval is neither validated as releasable nor consumed, the callback is never
  invoked, and the exact mismatch is recorded in runtime evidence.
  `evaluate_and_execute` takes an `action_descriptor`, which is the only part a
  caller can still determine, because nothing else can know what an opaque
  callable is meant to do.
- A request id is derived from its mission (`REQ-<mission_id>`), so the same id
  presented under a different mission is a different request and matches no
  approval issued for either.
- CI builds the image and launches the application for real. The live launch was
  opt-in and therefore usually unrun, leaving BRD-005 asserted by
  `docker compose config`, which only parses YAML.
- An approval is honored only when the governed tree still holds the approved
  content. `require_approval_matches_head()` proved the approved revision equals
  `git rev-parse HEAD`, which says which commit is checked out and nothing about
  the files on disk — and every governed operation reads the files. An
  uncommitted edit to a contract or to governed source was therefore inspected,
  bound into evidence, and reported as approved content. Tracked governed inputs
  must now be unmodified in both index and working tree, and untracked files
  inside governed paths are refused; only the tool's own regenerated outputs may
  differ, because it rewrites them before anything is inspected.
- Adopting an approval is one atomic operation, `--adopt-approval`. The steps
  rewrite the contracts, so run separately each would see the previous one's
  output as drift; the alternative — exempting `.nyx` files from the check —
  would have cut the hole in the file the check exists to protect.
- `--materialize-approval-window` no longer globs `*human_approval.json`, so a
  file merely named like an approval can no longer set the authority window, and
  no longer interpolates `expires_at` through a raw f-string. Both canonical
  artifacts now go through one validator shared with indexing, wiring and
  revision pinning: JSON object, human producer, required fields, safe scalars,
  timezone-aware ISO-8601 timestamps, `generated_at` before `expires_at`, the
  P7D cap, and agreement between records where both exist.

### Corrected claim — the baseline does expire, and here is what does not

0.3.0 said "the public baseline no longer expires". That was false. It rested on
`MACHINE_EVIDENCE_EXPIRES = "2099-01-01T00:00:00Z"` — a finite date far enough
away to look like forever. At 2100 the baseline produced `EVIDENCE_STALE`,
`ARCH_EVIDENCE_STALE` and `APPROVAL_EXPIRED`.

What Nornyx 1.11.0 actually supports, verified against the real CLI:

- **Authority declarations genuinely do not expire.** `expires_at: null` is
  accepted and stays accepted at 2100 and 2200. The baseline now carries that.
- **Machine evidence has no non-expiring representation.** The schema declares
  `expires_at: {"oneOf": [timestamp, null]}` but the freshness evaluator raises
  `EVIDENCE_TIME_INVALID` when it is absent, so the schema advertises something
  the evaluator refuses. Architecture evidence does not offer it at all. This is
  recorded as a Nornyx capability gap rather than papered over.
- **Agent authorization intervals must be bounded**, which is correct — an
  agent's authority is exactly the kind that should lapse.

So machine evidence and authorization intervals carry an honest finite window,
and the guarantee is regeneration rather than permanence:
`check_pre_approval_baseline.py --regenerate`. Tests prove it restores a healthy
pre-approval baseline at 2100 and 2200, and a separate test proves an
un-regenerated far-future check still fails — otherwise the window would be
decorative. See `docs/governance/EVIDENCE_FRESHNESS.md`.

Human approval expiry is unchanged: never generated, never extended, P7D cap.

## 0.3.0

### Breaking — capability contract

The single `execute_high_risk_action` capability is replaced by two:

| Before | After |
|---|---|
| `execute_high_risk_action` (risk `high`, gated) | `request_high_risk_action` (risk `medium`, ungated) |
| | `execute_high_risk_effect` (risk `high`, gated) |

Proposing an action and releasing its effect are now distinct. An execution
agent may always prepare a proposal; it obtains the effect capability only
through a separate, action-bound human approval (`high_risk_action_authority`).

Previously a capability named `execute_*` was *allowed* before execution
authority existed, and only the later trust-zone crossing refused the effect —
so the evidence read as though execution had been authorized when only the
request had. The runtime now records the request decision and the effect
decision separately.

Any contract, lock, or evidence referencing `execute_high_risk_action` as a
capability name must be regenerated. The *action* name `execute_high_risk_action`
is unchanged; only the capability that carries it was split.

### Governance

- Authority declarations carry a far-future baseline placeholder instead of a
  dated window. A declaration says who may approve and over what scope; it is
  not itself an approval, and a dated value expired the public baseline.
  `--materialize-approval-window` sets the real window from the signing instant
  when an approval instance is inserted. Nornyx still enforces the P7D cap.
- Machine-generated evidence is bound by content hash and subject revision
  rather than a wall clock, so the reviewer-ready baseline no longer rots.
  Human approval remains short-lived, because authority genuinely decays.
- Runtime action approvals are bound to one exact consequential request:
  approval id, request id, subject revision, capability, request digest,
  destination, human approver and role, validity window, and single use. A
  grant for one action cannot release another.
- Human approvals are never generated, upgraded, backdated, or overwritten by
  tooling; a non-human producer is refused outright.
- An approved subject revision no longer silently rebinds to `HEAD`.
- Evidence synchronisation preserves per-record validity instead of applying one
  index-wide window.
- The `architect` versus `architecture_reviewer` ambiguity is resolved: the
  required role is the one a reviewer signs as, and separation-of-duties and the
  change record follow it.

### Tests and tooling

- Absent, valid, expired, not-yet-valid, and over-long approval windows are all
  proven against the real Nornyx gate, using a labelled synthetic fixture that
  needs no real approval.
- The pre-approval baseline is asserted healthy at future instants, so it cannot
  quietly rot.
- CI asserts the true pre-approval state instead of assuming contracts validate;
  the strict path reports not-applicable until an approval exists.
- Nested generated runtime evidence is gitignored.
- Tool version metadata is read from the package so it cannot drift.

## 0.2.0

Initial public reference implementation.
