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
  directories, for their identities (below), through descriptors: each
  directory is listed from its handle and each child directory is opened
  relative to it without following a link. It follows no link, opens no
  file, reads no name into any output and selects nothing; it scans each
  directory once, whatever else the directory is called; and when any entry
  cannot be judged, or is not the entry looked at a moment before, it
  refuses the run rather than judging from a partial set.
  `tests/test_standing_development_obligations.py` plants decoys on
  every such route and holds that none is read; a structural lint over the
  checker's source refuses the obvious spellings, allows that one traversal
  in that one function and nowhere else, and is a lint, not a proof.
- **Outside the repository, at every component, judged through held
  descriptors.** An overlay path that names anything inside this repository
  is refused: the path as given after lexical normalisation, and every
  component of it. Where the handle backend exists (POSIX) the walk starts
  at the filesystem root and, for each component, judges its spelling
  against the repository root, looks at it relative to the directory
  already held without following a link, refuses it if it is a link of any
  kind, opens it relative to the held directory without following, refuses
  it unless it is the very entry just inspected, and compares the directory
  now held by identity against every directory of the repository. No link
  is followed, wherever it points: a link inside the tree pointing out, a
  link outside the tree pointing in, a chain that hops through the tree and
  a loop are all refused for the first link met, and what a link points at
  is never consulted, not even to refuse it. No pathname is looked up
  twice: after the one anchor, the filesystem root, every `stat` and `open`
  a judgment makes is relative to a descriptor it holds, so a component
  swapped between the moment it is looked at and the next lookup, the shape
  the sixth external review measured as followed by the pathname walk, meets
  `O_NOFOLLOW` on the open and is refused. The repository root itself is
  reached from that anchor through held directories, following no link, and
  is held only once the directory contains the file the checker was loaded
  from, by an identity taken at import and by one name: a checkout path
  substituted after the load -- an ancestor swapped for a link to a
  counterfeit tree, the directory swapped by rename, a counterfeit carrying
  a hard link to the loaded file, the shapes the seventh external review
  measured as anchored when the root was opened by pathname and compared
  against `os.stat(__file__)` through that same pathname -- is refused
  rather than anchored.
  `Path.resolve` takes part in no security decision. Where no handle
  backend exists -- Windows, whose `os` has no `openat`, no `O_NOFOLLOW`
  and no `scandir` on a handle -- a private overlay is refused outright,
  with one sentence, whatever the path's shape;
  `tests/test_standing_obligations_windows.py` holds that in the
  windows-runtime CI job, with real junctions built and never walked.
- **Judged by identity as well as by name.** One directory has several
  spellings: a bind mount or a double leading slash on POSIX, `\\?\C:\...`,
  a mapped or substituted drive letter or an administrative share on
  Windows. Beside the lexical comparison, every directory the walk holds is
  compared by file identity -- device and inode -- against every directory
  of the repository, so an alternate spelling of the repository, or of any
  directory below its root, is still the repository. Comparing against the
  root alone was not enough: an alias rooted at a subdirectory has that
  directory's identity at its mount point and external identities above it,
  and a real bind mount of `.nornyx/runtime` was measured to admit an
  in-repository overlay before every directory was compared. The identities
  are gathered through descriptors with no link followed, and the set is
  taken before the walk and again once the overlay is held, every directory
  held on the way absent from both: a directory bound into the checkout
  while the walk ran, the shape the seventh external review measured as
  admitted against a census taken only before the walk, is in the second
  set and refuses the overlay held below it, and no set outlives the
  judgment it was taken for. Where the platform exposes no identity, nothing is claimed and
  the lexical rule stands alone. An alias of a single file made by a bind
  mount is outside what either rule can see; see the limitations.
- **The bytes read are the object that was judged.** The final component
  is opened relative to the last held directory without following a link,
  refused unless it is the entry just looked at, and the descriptor so
  opened is the only object read: `fstat` on it, a bounded read from it,
  and the digest from the very bytes that were parsed. A regular file with
  more than one name -- a hard link -- is refused: the checker judges the
  object, not the name it was handed by. A FIFO is refused rather than read.
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
  followed, changed during admission, more than one name, not admitted on
  this platform -- and never what the path is. The
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
- **A hard link is refused; an alias of a single file made by a bind mount
  is not seen.** A regular file with more than one name is refused whichever
  name it is given by, so an overlay hard-linked into a checkout is refused
  rather than read, and a legitimately hard-linked overlay is refused too.
  A bind mount of a single file keeps one name and one identity and is
  outside what a path rule or a directory identity can see; a caller who
  mounts an overlay into a checkout has placed it there.
- **A mount change is seen only when it spans the walk.** The census is
  taken before the walk and again once the overlay is held. A directory
  bound into the checkout between the two is in the second census and
  refuses the overlay held below it; one bound and unbound between the two,
  or bound after the judgment, is not seen, and a caller with the privilege
  to mount has placed the overlay wherever it then appears.
- **The repository root is the loaded checker's, by identity.** The root is
  reached from the filesystem root through held directories with no link
  followed, and must contain the file the checker was loaded from, by the
  identity taken at import and by one name. A checkout path substituted
  after the load is refused, however it was substituted; a checker loaded
  from a counterfeit in the first place is the caller's code, as the
  shadowed-interpreter limitation says; and a checkout whose own checker
  file has a second name -- a hard link, however it came to be -- is refused
  until the second name is gone.
- **The identity traversal is bounded, and fails closed.** A repository with
  more than the bound's number of directories is refused rather than judged
  partially, so a very large checkout needs the bound raised, visibly, in
  the checker. The bound counts directories traversed, each identity once,
  so an alias of a directory inside the tree adds no work. An entry the
  traversal cannot `lstat` -- a transient filesystem error, an entry renamed
  under it, a name too long to reach -- refuses the run for the same reason:
  a directory left out of the set is one an alias could reach unjudged, so
  the run is repeated rather than judged from a partial set. Each directory
  is opened relative to its parent without following a link and refused
  unless it is the entry looked at, so a directory swapped for a link before
  its scan refuses the run rather than being listed through the link.
- **The identity bound sees a different object, not a different content.**
  A replacement that keeps the same device and inode -- a file rewritten in
  place between the walk and the open -- is the same object to every
  platform and is read. The digest still binds the bytes that were read.
- **A symlink anywhere on an overlay's path is refused.** Nothing is
  followed, so an overlay reached through a symlinked directory -- `/tmp` on
  macOS, a linked home -- must be given by a path with no link on it. The
  refusal names the link, and not the path or what it points at.
- **On Windows the private overlay is refused, not judged.** Windows has no
  handle-relative lookups in `os`, and the pathname walk that stood in for
  them was measured to follow a component swapped between being looked at
  and being used. Rather than admit an overlay over that race, the checker refuses
  `--overlay` on that platform with one sentence, whatever the path's
  shape, until a separately reviewed HANDLE-based backend exists.
  Public-registry admission stays available there: the disposition is
  created by pathname under an exclusive create, which refuses a second
  initializer and a link at the name, and the gap between inspecting that
  pathname and creating under it is the platform's remaining race.
- **A held directory that is renamed stays the directory that was judged.**
  The disposition is created relative to the directory held, which was
  reached from the repository root without following a link. A directory
  renamed after it was held keeps its identity, so the file is created in it
  wherever it is then named, and never through a link put in its old place;
  a caller who moves a directory of `.nornyx/runtime` out of the checkout
  mid-run has moved the judged object.
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
