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
