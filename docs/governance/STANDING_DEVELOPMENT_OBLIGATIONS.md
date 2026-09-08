# Standing Development Obligations

This document defines Forge's cross-session development-admission mechanism.
It exists so a new model, tool, workstation, or developer receives the same
standing obligations before changing Forge.

The machine-readable public source is
`docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.json`.

This mechanism is procedural governance. It is not a product roadmap, an
authorization record, a release decision, an approval, or evidence that a
deferred capability has been implemented.

## Development-cycle admission

Before planning or editing a Forge development cycle that can change code,
tests, contracts, governance, executable workflows, or public claims:

1. Load the public standing-obligation registry.
2. Load an external overlay only when the caller explicitly supplies one.
   Forge must not search for, infer, or discover an overlay.
3. Initialize a cycle disposition under `.nornyx/runtime/`.
4. Read every loaded item and replace each `pending` disposition with a
   deliberate disposition and reason.
5. Run the checker again. Development admission is refused while an item is
   unresolved, requests a decision, is duplicated, or is bound to stale input.

A read-only inspection that proposes no repository change is not a development
cycle for this mechanism.

Example:

```bash
python scripts/check_standing_development_obligations.py \
  --init .nornyx/runtime/development-cycle-disposition.json \
  --cycle-id FGR-DEV-001

# edit only the gitignored disposition file, then:
python scripts/check_standing_development_obligations.py \
  --check-disposition .nornyx/runtime/development-cycle-disposition.json
```

When a caller has a private or otherwise non-public overlay, it must remain
outside the Forge repository:

```bash
python scripts/check_standing_development_obligations.py \
  --overlay /outside/forge/private-overlay.json \
  --init .nornyx/runtime/development-cycle-disposition.json \
  --cycle-id FGR-DEV-001
```

The checker validates such an overlay without printing its path or contents.
It refuses an overlay that resolves inside the Forge repository. Overlay
content must never be copied, quoted, summarized, committed, or incorporated
into public Forge evidence. Only opaque item identifiers may be carried into
the gitignored local disposition.

## Dispositions

Every loaded item receives one of these explicit cycle dispositions:

- `considered` — relevant and accounted for in the proposed cycle.
- `unchanged` — reviewed; the cycle does not change its standing state.
- `defer` — deliberately remains deferred under its existing authority.
- `not_applicable` — reviewed and not applicable to this cycle.
- `requires_decision` — the cycle must stop until the required authority acts.

`pending` is generated only by `--init` and always refuses admission.
`requires_decision` also refuses admission; changing the label is not the
decision.

## Duplicate prevention

Each standing item has both an immutable `id` and a semantic `dedupe_key`.
The checker refuses duplicate IDs or semantic keys within one registry and
across the public registry and a supplied overlay. New records should reference
existing items when they carry the same obligation rather than restating them
under another name.

## Relationship to existing controls

Passing this admission check means only that the standing items were loaded and
explicitly dispositioned against the exact registry digests. It does not mean
the proposed development is correct, approved, safe, production-ready, or
eligible to merge or publish.

`CLAUDE.md`, the Forge Skill, deterministic repository/test/architecture/
security/evidence gates, Nornyx semantics, and real human or organizational
authority remain independently controlling.
