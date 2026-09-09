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

Passing standing-development admission means only that a local cycle
disposition covers exactly the loaded public-registry and overlay items,
gives every one of them a disposition from the resolved vocabulary, carries a
non-empty reason beside each, and is bound by SHA-256 to the exact registry
and overlay bytes it was checked against. That is the whole of what the
checker measures. It establishes nothing about whether anyone read,
understood or weighed an obligation: a disposition written mechanically
passes, and so does one reused from an earlier cycle under a new `cycle_id`,
because the `cycle_id` is a label the developer chose and nothing binds it to
a cycle. Reading every loaded item is the obligation the procedure below
states; it is not measured. It does not authorize the development cycle
itself, and it confers no human, organizational, merge, publication, release,
deployment or other consequential authority.

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
   resolved disposition and a reason. The reading is the developer's
   obligation; the checker sees only the file that results.
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
  wins. The one traversal the checker performs is of the repository's own
  directories, for their identities (below): it follows no link, opens no
  file, reads no name into any output and selects nothing.
  `tests/test_standing_development_obligations.py` plants decoys on
  every such route and holds that none is read; a structural lint over the
  checker's source refuses the obvious spellings, allows that one traversal
  in that one function and nowhere else, and is a lint, not a proof.
- **Outside the repository, at every step.** An overlay path that names
  anything inside this repository is refused: the path as given after
  lexical normalisation, every component the walk reaches, every link it
  follows, and its final resolution. The walk judges each component by
  `lstat` where it sits. A symlink -- file or directory, first hop or third
  -- is judged at its own location and then followed one hop, so a link
  inside the tree pointing out, a path outside the tree resolving in, a
  chain that merely hops through the tree, and a directory link that hops
  through the tree are all refused. Any other reparse point -- a Windows
  directory junction, a mount point, a cloud placeholder, an entry whose
  reparse tag the platform does not expose -- is refused rather than
  followed, wherever it sits and wherever it leads: the checker does not
  claim to know where such a link goes, so an uninspectable state fails
  closed, and nothing beyond such a link is consulted, not even by
  resolution -- a chain the walk stops at is judged as far as it was walked
  and refused for the link. `tests/test_standing_obligations_windows.py` builds real
  junctions in the windows-runtime CI job and holds the refusal on the
  platform it concerns; a Windows symlink target is judged only behind a
  drive letter, and a share, volume-GUID, device or NT-namespace spelling
  of a target is refused rather than judged.
- **Judged by identity as well as by name.** One directory has several
  spellings: `\\?\C:\...`, a mapped or substituted drive letter or an
  administrative share on Windows, a bind mount or a double leading slash on
  POSIX. Beside the lexical comparison, every walked location and the final
  resolution are compared by file identity -- device and inode, volume
  serial and file index on Windows -- against every directory of the
  repository, so an alternate spelling of the repository, or of any
  directory below its root, is still the repository. Comparing against the
  root alone was not enough: an alias rooted at a subdirectory has that
  directory's identity at its mount point and external identities above it,
  and a real bind mount of `.nornyx/runtime` was measured to admit an
  in-repository overlay before every directory was compared. The identities
  are judged by `lstat`, so no link is followed for them. Where the platform
  exposes no identity, nothing is claimed and the lexical rule stands alone.
  A hard link, and an alias of a single file, are outside what either rule
  can see; see the limitations.
- **The bytes read are the object that was judged.** The walk records the
  identity of the entry it ends at; the file is then opened once, judged by
  `fstat` on that descriptor, read within a size bound, and digested from
  the bytes that were parsed. Unless the opened object is the very entry the
  walk ended at, the read is refused as changed during admission: a link
  retargeted, a file replaced or a path swapped between the walk and the
  open reaches a different object, and is not read. A FIFO is refused
  rather than read.
- **Not emitted, and refused without detail.** No refusal names a value, a
  key, a path or a byte from the overlay. A refusal about the overlay's
  CONTENT is one sentence -- the overlay is not valid, and no detail is
  reported for private input -- whatever the defect: a malformed item at
  index 0 or at index 42, an unknown field, a duplicate at the end of three
  hundred items, an oversized file, a document nested past the parser's
  depth, invalid UTF-8 all leave byte-identical stderr, so no index, count,
  size class, field, value or position of the private document is
  summarised. A refusal about the overlay's PATH says where the rule was
  broken -- inside the repository, unreadable, unresolvable, a link not
  followed, changed during admission -- and never what the path is. The
  loaders raise their refusal outside the handler that caught the
  underlying error, so the refusal carries no `__context__` at all. The
  PASS output states that an overlay was supplied, and nothing else about
  it -- not even its item count, which is a fact about the overlay; a
  refusal about the disposition says that overlay items are unresolved, not
  how many, and names a malformed row by its public id or, while an overlay
  is loaded, not at all. The public registry keeps its specific
  diagnostics, because the public registry is public; a developer whose
  private overlay is refused diagnoses it against the schema above.
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
- `defer` — remains deferred under its existing authority. Admitted only for
  an item whose registry `status` is already `deferred`: deferring an active
  obligation would be ignoring it under a resolved label.
- `not_applicable` — read; not applicable to this cycle.
- `requires_decision` — the cycle must stop until the required authority acts.

Each word is the developer's assertion about the cycle. The checker verifies
that the word is in the vocabulary and that a reason sits beside it; it does
not, and cannot, verify the assertion. `pending` is generated only by
`--init` and always refuses admission. `requires_decision` also refuses
admission. The vocabulary is closed: any other string is refused as not a
disposition, and changing the word is not the decision -- the authority an
item is waiting for acts outside this mechanism, and no edit to the
disposition file stands in for it.

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
`pending` after a PASS refuses on the next check. The `cycle_id` is bound to
nothing: it is the developer's label for the file, and a disposition that
passed for one cycle passes again under another label. Freshness is the
developer's obligation, not a measurement.

## Limitations, stated rather than implied

- **Nothing makes anyone run it.** A model or a person who edits the
  repository without invoking the checker is outside what it measures. The
  entry points (`AGENTS.md`, `CLAUDE.md`, the `build-app` Skill) instruct;
  they do not enforce. This is admission procedure, not a sandbox.
- **Nothing measures reading.** A disposition written mechanically -- every
  row `considered`, every reason `x` -- passes, and so does one reused from
  an earlier cycle. The checker measures the file's state and claims no
  more; "read every loaded item" is an instruction to the developer.
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
- **A hard link, or an alias of a single file, is invisible to a path rule
  and to identity.** A file outside the tree that is a hard link to a file
  inside it, or a bind mount of that one file, is accepted, because nothing
  about its path names the tree and no directory of the tree is among its
  ancestors. The checker judges paths, links and the identity of
  directories, not the other names a file may have; a caller who hard-links
  or mounts an overlay into a checkout has placed it there.
- **The identity traversal is bounded.** A repository with more than the
  bound's number of directories is refused rather than judged partially, so
  a very large checkout needs the bound raised, visibly, in the checker.
- **The identity bound sees a different object, not a different content.**
  A replacement that keeps the same device and inode -- a file rewritten in
  place between the walk and the open -- is the same object to every
  platform and is read. The digest still binds the bytes that were read.
- **A junction is refused, not judged.** A legitimate overlay reached
  through a Windows junction, a mount point or a cloud-placeholder file is
  refused with the same sentence as a hostile one; the caller places the
  file where no such link is on its path.
- **The disposition binds the registry and the overlay, not the checker.** A
  change to the checker's own bytes does not stale a disposition; a checker
  cannot meaningfully certify itself. Its change is visible through the
  governed input digest, as above.
- **The structural lint proves less than its name.** The test that reads the
  checker's source for environment and directory access refuses the obvious
  spellings; an in-session adversarial review walked thirteen of fifteen
  evasions past it. What holds the discovery property is the behavioural
  sweep under planted decoys, which sees only the routes it exercises. The
  lint over refusal construction is the same kind of thing: it holds the
  shapes it names.
