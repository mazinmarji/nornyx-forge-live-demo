# Standing Development Obligations

This document defines Forge's cross-session development-admission mechanism.
It exists so a new model, tool, workstation, or developer receives the same
standing obligations before changing Forge, and so a caller with private
obligations of its own can carry them into a Forge development cycle without
any of them entering this public repository.

The machine-readable public source is
`docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.json`. The checker is
`scripts/check_standing_development_obligations.py`. Both are governed
inputs: a change to either moves the governed input digest the evidence set
binds, which is visibility, not prevention.

This mechanism is procedural governance. It is not a product roadmap, an
authorization record, a release decision, an approval, or evidence that a
deferred capability has been implemented.

## What passing means, and what it does not

Passing standing-development admission means only that the applicable
standing obligations were loaded, each given a deliberate disposition, and
bound by content digest to the exact registry and overlay bytes used for that
development cycle. It does not authorize the development cycle itself, and it
confers no human, organizational, merge, publication, release, deployment or
other consequential authority.

The distinction is load-bearing for a private caller. An external overlay
governs a development cycle whose authority, if any, comes separately from
the repository's existing rules and from the caller; the overlay cannot
create authority for one, and neither can the admission result. `CLAUDE.md`,
the Forge Skill, the deterministic
repository, test, architecture, security and evidence gates, Nornyx
semantics, and real human or organizational authority remain controlling
after admission exactly as before it.

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
outside the Forge repository and is passed only through `--overlay`:

```bash
python scripts/check_standing_development_obligations.py \
  --overlay /outside/forge/private-overlay.json \
  --init .nornyx/runtime/development-cycle-disposition.json \
  --cycle-id FGR-DEV-001
```

The same `--overlay` must accompany the later `--check-disposition` run: the
disposition binds the overlay's digest, and a check without the overlay, or
with a different one, is refused.

## The external overlay

Forge does not know who owns an overlay or what organization it serves. The
path it is given is used for the run and is neither retained nor emitted;
the checker necessarily learns it for as long as the run lasts, and no
longer. The overlay is a JSON object with exactly three
fields: `schema`, which must be `nornyx.forge.private_standing_overlay.v1`;
`classification`, which must be `private`; and `items`, a list of standing
items in the same shape as the public registry's. Each item carries exactly
`id`, `kind`, `dedupe_key`, `status`, `title` and `rule`, plus
`reopen_condition` when and only when `status` is `deferred`. Any other
field, at either level, is refused.

What the checker establishes about an overlay, mechanically, and what it does
not:

- **Never discovered.** There is no default path, no environment variable,
  no scan of the working directory or the home directory. The only route is
  `--overlay`, given once: a repeated option is refused rather than last
  wins. `tests/test_standing_development_obligations.py` plants decoys on
  every such route and holds that none is read; a structural lint over the
  checker's source refuses the obvious spellings and is a lint, not a proof.
- **Outside the repository, at every step.** An overlay path that names
  anything inside this repository is refused: the path as given after
  lexical normalisation, every component the walk reaches, every link it
  passes through -- file or directory, judged where that link sits and then
  followed component by component -- and its final resolution. A link
  inside the tree pointing out, a path outside the tree resolving in, a
  chain that merely hops through the tree, and a directory link that hops
  through the tree are all refused. A hard link is outside what a path rule
  can see; see the limitations.
- **Not emitted.** No refusal names a value, a key, a path or a byte from
  the overlay; refusals name a label and, at most, an item index. The
  loaders raise their refusal outside the handler that caught the underlying
  error, so the refusal carries no `__context__` at all. Invalid UTF-8, a
  symlink loop, a deeply nested document, a repeated JSON key and an
  unhashable value where a word belongs all refuse by label, and a stray or
  repeated argument is refused without being echoed. The PASS output states
  that an overlay was supplied, and nothing else about it -- not even its
  item count, which is a fact about the overlay; a refusal says that overlay
  items are unresolved, not how many.
- **Read once, through one descriptor.** The file is opened once without
  blocking, judged by `fstat` on that descriptor, read within a size bound,
  and digested from the bytes that were parsed. A FIFO is refused rather
  than read.
- **A repeated key is refused.** `json.loads` keeps the last value of a
  repeated key silently, so a shadowed field would show a reader one thing
  and the checker another. Every document is parsed with a pairs hook that
  refuses the repetition.
- **Not copied.** The local disposition carries, from an overlay, only each
  item's `id`, its `source`, and the SHA-256 of the overlay's bytes. The
  title, rule, reopen condition and semantic key never reach it.
- **Bounded, not judged.** An item `id` is a short upper-case token
  (`[A-Z0-9][A-Z0-9-]{2,63}`, matched in full, so a trailing line break
  does not satisfy it), so it cannot be a sentence; whether the token an
  overlay author chooses is itself sensitive is that author's
  responsibility. The free-text `reason` a developer writes beside a
  disposition is not inspected, and must not quote overlay content.

The gitignored disposition and the overlay stay on the developer's machine.
Nothing here synchronizes with, caches, publishes, or derives public Forge
state from a private overlay, and nothing here turns one into evidence.

## Dispositions

Every loaded item receives one of these explicit cycle dispositions:

- `considered` — relevant and accounted for in the proposed cycle.
- `unchanged` — read; the cycle does not change its standing state.
- `defer` — deliberately remains deferred under its existing authority.
  Admitted only for an item whose registry `status` is already `deferred`:
  deferring an active obligation would be ignoring it under a resolved
  label.
- `not_applicable` — read; not applicable to this cycle.
- `requires_decision` — the cycle must stop until the required authority acts.

`pending` is generated only by `--init` and always refuses admission.
`requires_decision` also refuses admission. The vocabulary is closed: any
other string is refused as not a disposition, and changing the word is not
the decision -- the authority an item is waiting for acts outside this
mechanism, and no edit to the disposition file stands in for it.

Every resolved disposition needs a non-empty reason. A row carries exactly
`id`, `source`, `disposition` and `reason`; a row or document carrying any
other field -- an `approved_by`, a `human_approval` -- is refused rather than
ignored, so no FIELD rides along that a later reader could mistake for
something the checker accepted. The `reason` is the one place free text
lives, and it is not inspected: it can carry any sentence, including one
asserting an approval or an authorization, and the checker neither reads nor
endorses it. A reason is the developer's note to the next reader, never a
claim the checker accepted, and a reader must not take it for one.

## Duplicate prevention

Each standing item has both an immutable `id` and a semantic `dedupe_key`.
The checker refuses duplicate IDs or semantic keys within one registry and
across the public registry and a supplied overlay. New records should reference
existing items when they carry the same obligation rather than restating them
under another name.

## Binding and staleness

The disposition records the SHA-256 of the public registry bytes and of the
overlay bytes it was initialized against. A registry or overlay that changes
by one byte afterwards makes the disposition stale, and the check refuses
until a new cycle is initialized. There is no stored admission: every check
re-reads the disposition and re-derives the verdict, so a row edited back to
`pending` after a PASS refuses on the next check.

## Limitations, stated rather than implied

- **Nothing makes anyone run it.** A model or a person who edits the
  repository without invoking the checker is outside what it measures. The
  entry points (`AGENTS.md`, `CLAUDE.md`, the `build-app` Skill) instruct;
  they do not enforce. This is admission procedure, not a sandbox.
- **Repository content can change the checker or the registry.** Both are
  governed inputs, so the change moves the governed input digest and the
  evidence set has to be regenerated in the same commit for the evidence
  binding to hold -- which makes the change visible in review, and no more
  than that. A candidate change that replaces the registry with a weaker
  one is a reviewable diff, not a refused one.
- **`AGENTS.md` is not a governed input.** The root `AGENTS.md` is outside
  the governed input set (`CLAUDE.md` is inside it), so an edit to it moves
  no digest. The substantive rules therefore live here and in the registry,
  and `AGENTS.md` points at them. Widening the subject scope is a change to
  the governed subject that this mechanism does not make.
- **The local disposition can be edited after a PASS.** Each check
  re-evaluates it, so the PASS is a statement about the file at that moment,
  not a token that survives the edit. Nothing prevents a developer from
  passing, editing, and proceeding without checking again.
- **The overlay is confidential only as far as the caller keeps it so.** The
  checker refuses an in-repository path and emits nothing from the file; it
  cannot stop a caller from committing the file elsewhere, quoting it in a
  reason, or naming it in a commit message.
- **A shadowed interpreter environment is out of scope.** The checker is run
  with whatever Python and `scripts/` directory the caller has; a hostile
  module placed beside it is the same trust as the checker itself.
- **A hard link is invisible to a path rule.** A file outside the tree that
  is a hard link to a file inside it is accepted, because nothing about its
  path names the tree. The checker judges paths and links, not inodes; a
  caller who hard-links an overlay into a checkout has placed it there.
- **The disposition binds the registry and the overlay, not the checker.** A
  change to the checker's own bytes does not stale a disposition; a checker
  cannot meaningfully certify itself. Its change is visible through the
  governed input digest, as above.
- **The structural lint proves less than its name.** The test that reads the
  checker's source for environment and directory access refuses the obvious
  spellings; an in-session adversarial review walked thirteen of fifteen
  evasions past it. What holds the discovery property is the behavioural
  sweep under planted decoys, which sees only the routes it exercises.
