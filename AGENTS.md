# Forge Agent Instructions

These instructions apply to any model, agent, or developer changing Nornyx
Forge. Provider-specific instructions may add procedure but may not weaken this
file. The substantive rules live in the governed procedure document and the
public registry named below; this file points at them and is not itself a
governed input.

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

## What admission means

Passing standing-development admission means only that a local cycle
disposition covers exactly the loaded public-registry and overlay items, gives
every one of them a disposition from the resolved vocabulary, carries a
non-empty reason beside each, and is bound by SHA-256 to the exact registry
and overlay bytes it was checked against. It establishes nothing about whether
anyone read, understood or weighed an obligation: a disposition written
mechanically passes, and so does one reused from an earlier cycle under a new
`cycle_id`. Reading every loaded item is the obligation step 4 states; it is
not measured. It does not authorize the development cycle itself, and it
confers no human, organizational, merge, publication, release, deployment or
other consequential authority. A cycle that carries a private overlay draws
whatever authority it has from the repository's existing rules and from the
caller, separately; the overlay governs that cycle and creates none.

## Existing authority remains controlling

After standing admission, follow the repository's existing bounded-work,
deterministic-gate, evidence, review, approval, and publication rules. Standing
admission cannot create human authority, weaken a failing gate, or turn a model
judgment into evidence.

Never publish an external pull request, merge, release, deploy, or perform
another consequential external action without the authority already required by
the repository and the user.
