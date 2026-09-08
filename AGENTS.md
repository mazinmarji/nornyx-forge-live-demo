# Forge Agent Instructions

These instructions apply to any model, agent, or developer changing Nornyx
Forge. Provider-specific instructions may add procedure but may not weaken this
file.

## Standing development admission

Before planning or editing a development cycle that can change code, tests,
contracts, governance, executable workflows, or public claims:

1. Read `docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.md`.
2. Validate `docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.json`.
3. If the caller explicitly supplies an external overlay, pass it only through
   `--overlay`. Do not search for one. The overlay must remain outside this
   repository and must not be copied, quoted, summarized, logged, committed, or
   converted into public Forge evidence.
4. Initialize `.nornyx/runtime/development-cycle-disposition.json`, read every
   loaded standing item, and replace every `pending` state with an explicit
   disposition and reason.
5. Run `scripts/check_standing_development_obligations.py` against the completed
   disposition. Do not begin repository-changing work if it refuses admission.

A `requires_decision` disposition is a stop, not permission to continue. A
deferred item or trigger is not development authority.

## Existing authority remains controlling

After standing admission, follow the repository's existing bounded-work,
deterministic-gate, evidence, review, approval, and publication rules. Standing
admission cannot create human authority, weaken a failing gate, or turn a model
judgment into evidence.

Never publish an external pull request, merge, release, deploy, or perform
another consequential external action without the authority already required by
the repository and the user.
