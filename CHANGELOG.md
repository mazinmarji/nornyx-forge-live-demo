# Changelog

## Unreleased — hardening from adversarial review

- Standing development obligations (PR #51, reconciled with main and
  repaired). A public-safe, provider-neutral mechanism for carrying standing
  development obligations across sessions, models, workstations and
  developers: a machine-readable registry
  (`docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.json`), a procedure
  document, a deterministic checker
  (`scripts/check_standing_development_obligations.py`), a root `AGENTS.md`,
  and wiring into `CLAUDE.md` and the `build-app` Skill. A cycle disposition
  under the gitignored `.nornyx/runtime/` names every loaded item, is bound by
  SHA-256 to the exact registry and overlay bytes, and refuses while any item
  is `pending` or `requires_decision`, duplicated, uncovered or stale. An
  external overlay is read only from `--overlay` -- never discovered -- must
  resolve outside this repository as given and after symlinks are followed,
  and contributes to the disposition only its item identifiers and a digest.
  WHAT PASSING MEANS is now stated in the registry itself (FGR-SDO-005), in
  every entry point and in the checker's own output: a local disposition
  covers exactly the loaded obligations, gives each a resolved disposition
  and a non-empty reason, and is digest-bound for the cycle, and nothing
  else -- nothing about whether anyone read an item, and no human,
  organizational, merge, publication, release, deployment or other
  consequential authority follows from it; a private overlay governs a
  cycle whose authority comes separately and creates none.
  The repair cycle found and closed, on the first head: every refusal now
  names a label and at most an item index, exception chaining from the
  loaders is severed, and the two failure paths that DID carry a value are
  pinned -- a symlink-loop overlay made `Path.resolve` raise `RuntimeError`
  with the path in its message on CPython 3.11, uncaught, and
  `UnicodeDecodeError` quotes the offending byte; a stray positional argument
  was echoed by argparse; unknown fields in a registry, an overlay or a
  disposition were ignored and are refused, so a fabricated `approved_by`
  cannot ride along; `defer` was accepted on an ACTIVE invariant, which is
  ignoring it under a resolved label, and is refused unless the item's
  registry status is already `deferred`; `--init` overwrote a completed
  disposition and refuses one that exists; the disposition was written with
  platform line endings; the procedure document used a participle the
  overclaim sweep reads as a claim; and the registry put `governance` and
  `Nornyx` on one line, which the operator-surface sweep reads as a
  governance-mode claim. Eighty-two tests hold the mechanism, twenty-three of
  them malformed-overlay shapes with sentinels in the refused field and a
  sentinel sweep over stdout, stderr, the disposition and every refusal.
  The first head of PR #51 also shipped stale evidence: it added governed
  inputs without regenerating the set, so `--verify` reported every artifact
  stale, seven mutation proofs in `tests/test_subject_completeness.py`
  became tautologies, and the evidence-binding check reported the commit.
  History was preserved on instruction, so the commit is recorded in
  `docs/governance/EVIDENCE_BINDING_BASELINE.json` as the seventh made after
  the defect was known, with the pinned count in
  `tests/test_evidence_binding.py` raised deliberately; the merge and every
  later commit regenerate the evidence in the same commit, except the fifth
  reconciliation merge (a1f9995), recorded as the eighth: its regeneration
  refused to run under a checkout git reported as dubiously owned and the
  commit step did not fail closed, so it shipped main's evidence and the
  commit after it regenerated the set over that tree. Collection
  3308 -> 3395 across 114 modules; the recorded-measurements floor follows
  the new governance document to 184.
  An in-session read-only adversarial review of the first repaired head --
  bounded review evidence, not an independent inspection -- found no P1 and
  three P2s, each contradicting a stated claim, each reproduced and closed:
  a repeated JSON key let a disposition row read `requires_decision` to a
  person and `considered` to the checker, and let a shadowed `items` carry
  `approved_by` past the closed field set (every document is now parsed
  with a pairs hook that refuses repetition); `$`-anchored identifier
  grammars admitted a trailing newline, so `PRV-001` plus a line break was
  written into the disposition and a public id plus a line break walked
  past the cross-registry duplicate check (matched in full now); and a
  symlink chain hopping through `.nornyx/runtime/` was accepted because
  only its two ends were judged (every link is now judged at the directory
  where it really sits). Also closed from that review: a repeated
  `--overlay` was last-wins and is refused; an unhashable value where a
  word belongs, and a deeply nested document, raised `TypeError` and
  `RecursionError` past the labelled refusals; the read was two opens and a
  FIFO swapped between them would have hung the caller; and `from None`
  only hid the loaders' `__context__`, which still carried the filename --
  refusals are now raised outside the handler and pinned to carry none.
  Stated rather than fixed: a hard link is invisible to a path rule, the
  disposition does not bind the checker's own bytes, and the structural
  lint over the source is a lint that thirteen of fifteen evasions walked
  past; the discovery property rests on the behavioural sweep.
  A Codex review of the merged head (bounded automated review evidence)
  found one P1 and three P2s, each reproduced and closed: a DIRECTORY link
  chain -- `outside/a` to an in-repository directory link to
  `outside/final` -- passed, because the walk placed each hop at the
  realpath of its parent and `realpath` follows a directory link straight
  through; the walk is now component by component, every link judged where
  it sits and then followed, pinned by that shape. The PASS line printed the
  overlay's item count, which is a summary of the overlay: no successful
  output now carries an overlay-derived count, refusals say overlay items
  are unresolved without saying how many, and two overlays of different
  sizes are pinned to byte-identical output. Two document claims were wider
  than their tests and are narrowed: "nothing rides along" is now "no
  FIELD rides along", with the uninspected `reason` named as the place an
  approval sentence can sit unread; and "Forge learns nothing about where
  the file lives" is now "neither retains nor emits", since the path
  necessarily enters through the argument.
  A second Codex review, of the PR head after the third merge of main
  (bounded automated review evidence), found one P1 and three P2s, each
  reproduced and closed. On Windows a directory junction is a plain
  directory to `Path.is_symlink()`, so an overlay path shaped
  `outside/junction -> repo/junction -> outside` was accepted at both hops:
  the walk now classifies every component from its `lstat`, follows a
  symlink one hop and refuses every other reparse point -- a junction, a
  mount point, a cloud placeholder, an entry whose tag the platform does
  not expose -- rather than following it, judges a Windows symlink target
  only behind a drive letter, and compares every walked location by file
  identity against the repository root as well as by name. Real junctions
  are built and refused in the windows-runtime job by the new
  `tests/test_standing_obligations_windows.py`, and the identity comparison
  also closed a POSIX shape measured while repairing it: a symlink target
  spelled with a double leading slash hopped through the repository outside
  to every walked component. The path was checked and then opened, two
  operations, so a link retargeted between them opened a file nobody had
  judged: the walk now records the identity of the entry it ends at and the
  one open is refused unless `fstat` names that entry, pinned by a
  retargeted directory link, a retargeted file link, a file replaced by an
  in-repository link, a file replaced by another and a file that appears
  only after the walk, for the disposition as for the overlay. A malformed
  private item said `item 42`, a lower bound on the overlay's size, and an
  oversized one said so: every content refusal about private input is now
  one sentence, byte-identical across defects at different indices, counts,
  sizes, nesting depths and duplicate positions; a malformed disposition
  row is named by its public id or, while an overlay is loaded, not at all;
  the public registry keeps its specific diagnostics. And every surface
  said each item was "given a deliberate disposition", which nothing
  measures: PASS now states the measured result -- exact coverage, a
  resolved vocabulary word and a non-empty reason per row, matching digests
  -- and that nothing is established about whether anyone read an item or
  whether the `cycle_id` names a cycle, in the checker's output, the
  registry, `AGENTS.md`, `CLAUDE.md`, the Skill, the procedure document,
  `docs/VALIDATION.md` and A-031, held there by test. The standing module
  collects 106 -> 142, the Windows module adds 7 (six junction proofs and
  the one test that holds the job to running them), and the suite 3486 ->
  3529 across 115 modules.
  A third Codex review, of the reconciled head, found one P1 and one P2
  against those repairs, each reproduced and closed. The identity backstop
  compared against the repository root alone, so an alias rooted at a
  subdirectory -- a bind mount or mapped drive of `.nornyx/runtime/` --
  admitted an in-repository overlay (reproduced with a real bind mount:
  PASS); every directory of the repository is compared now, from the one
  traversal the checker performs, of its own tree, following no link,
  opening nothing and refusing past a bound. And a chain the walk stopped at
  for an unfollowed reparse point was still resolved through it before the
  refusal; nothing beyond such a link is consulted now, pinned by a spy on
  `Path.resolve`.
  A fourth Codex review, of the head carrying those repairs, found one P1
  and one P2 against the new traversal, each reproduced and closed. An entry
  the traversal could not `lstat` was skipped, so a directory and everything
  below it could be missing from the identity set and an alias of it would
  admit an in-repository overlay (reproduced with a directory too long to
  `lstat` and a bind mount of it: read through the alias, PASS); the
  traversal refuses whole now and caches no partial set. And an alias of a
  directory inside the tree was deduplicated in the set but traversed again
  in full, so the scan bound counted identities while the work grew with
  every alias (reproduced with three bind mounts of `docs/`: twelve scans
  more, the bound never crossed); an identity already seen is not enqueued
  now, one scan per directory.
  A fifth Codex review, of the head carrying those repairs, found two P1s
  of the same class in two other places, each reproduced and closed. The
  overlay walk stepped past a component whose `lstat` failed, so one failed
  `lstat` of an outside link made the walk treat it as plain, the next
  `lstat` resolved the whole chain in the kernel, and a chain through the
  repository was accepted with its in-repository link never judged
  (reproduced with that chain and one failing `lstat`: accepted). And the
  identity comparison skipped a candidate whose `lstat` failed -- for an
  alias of a repository directory, the one candidate whose identity would
  match -- so an in-repository overlay was accepted through the alias
  (reproduced: accepted). Neither failure is caught now; each reaches
  confinement's one refusal, which names no path, and nothing is opened.
  Every `lstat` the confinement judgment performs -- in the repository
  traversal, the walk and the comparison -- refuses on failure.
  A sixth Codex review, of the head carrying those repairs, found three
  findings of one class the earlier rounds had not covered: a pathname
  inspected and then used again. A plain directory swapped for a link chain
  between being looked at and the next lookup was followed by that lookup
  (reproduced: accepted, the in-repository hop unjudged); disposition
  creation was check-then-write, so a parent swapped to a symlink after the
  runtime judgment put the file outside the runtime root and two
  initializers overwrote each other (reproduced, both); and a queued
  repository directory swapped for a link before its scan was listed
  through the link (reproduced: an external tree's identities entered the
  set and a legitimate overlay was refused as inside). Re-checking a
  pathname cannot close that class, so the confinement was REDESIGNED
  around held descriptors on POSIX: every component is inspected and opened
  relative to the directory already held, without following a link, and
  refused unless it is the entry just looked at; no link of any kind is
  followed, and nothing a link points at is consulted; the descriptor so
  opened is the only object read, and a file with more than one name is
  refused; the identity traversal opens each directory relative to its
  parent the same way and its snapshot is taken for every judgment; the
  disposition is created exclusively relative to a parent reached from the
  root handle, and the root handle is refused unless it contains the
  running checker; `Path.resolve` takes part in no security decision. Where
  no handle backend exists -- Windows -- a private overlay is refused
  outright with one sentence, and public-registry admission stays, with an
  exclusive create by pathname and the parent race stated as that
  platform's limitation. The standing module collects 149 -> 131, its
  subject having changed; the Windows module stays at 7.
  A seventh Codex review, of the redesigned head after its sixth
  reconciliation, found two P1s in what the redesign had kept by pathname:
  the root anchor opened the repository root by pathname without
  `O_NOFOLLOW` and compared the checker below it against
  `os.stat(__file__)` evaluated through the same pathname, so a checkout
  path substituted after the load put a counterfeit on both sides
  (reproduced: an ancestor swapped for a link to a counterfeit tree, and a
  counterfeit carrying a hard link to the loaded file, each reading a
  fabricated public registry); and the directory census was taken once,
  before the walk, so an external directory bound into the checkout after
  it had no identity in it and the overlay below it was admitted
  (reproduced with a real bind mount). The loaded file's identity is taken
  at import now; the root is reached from the filesystem root through held
  directories, following no link, and must contain that file by that
  identity and by one name; the census is taken again once the overlay is
  held, and every directory held on the way must be absent from both. The
  standing module collects 131 -> 133; the Windows module stays at 7.
  Not claimed, and recorded as such in A-031: that anyone runs the check;
  that anyone read an item; that a `cycle_id` names a cycle; that an alias
  of a single file, a same-identity rewrite, or a mount change made and
  unmade within a judgment or after it is seen (a hard link is refused, not
  judged); that a link of any kind is followed rather than refused; that a private overlay
  is judged at all where no handle backend exists; that a free-text `reason` is
  free of overlay content; that an identifier an
  overlay author chose is not itself telling; that a commit cannot change the
  checker or the registry (both are governed inputs, so the change moves the
  evidence digest and no more); or that the root `AGENTS.md`, outside the
  governed input set, is bound by any digest. Passing admission is not
  approval and not authority over anything.

- A wholesale rollback of the authority store is now DETECTED while the Forge
  process that wrote the newer seal is still running, and the disclosure says
  exactly how far that reaches. The seal catches a store that moved away from
  it and a seal that moved away from its store; it caught neither when both
  moved together, and that was measured through the shipped surface rather than
  deduced: with the store directory and the seal directory copied back from a
  byte-for-byte snapshot of an earlier state, `GET /api/state` answered `200`
  at the earlier stage, the restore route answered "there is nothing to
  restore", and a second build ran the project to GOVERN again at a new
  revision with the first GOVERN reachable from nowhere Forge can read. The
  same move erases a recorded provider breach for the actor who caused it.
  `ProcessWitness` in `capsule_store` holds, in memory only, the snapshot this
  process last sealed or last found clean; `assert_sealed` asks that question
  after every check the seal itself can make, and a seal that is not the held
  one raises `CapsuleSealReplaced` carrying the WITNESS's snapshot, so the
  human restore route puts back what this process wrote rather than what the
  actor left.
  THE CURRENCY WORD DOES NOT MOVE. `not_independently_anchored` stays, byte for
  byte and pinned by exact equality, because four durable witnesses were built
  and attacked as the same operating-system user -- a counter beside the seal,
  a mirror in a second Forge-owned directory, an append-only log in a third
  place, and filesystem hardening of the seal file -- and every one was rolled
  back with the set it was meant to anchor or undone by the same user. Two of
  them catch only a FORGETFUL actor; NTFS has no append-only attribute, so
  `open(log, "w")` truncates the last line. `icacls /deny` did not even stop
  replacement: `os.replace` and `os.remove` both succeeded through it, and the
  owner's implicit `WRITE_DAC` then removed the ACE. A-029 states each result
  per candidate. What the witness earns is a SEPARATE,
  smaller field: `authority.continuity` is `"process"` or absent, with
  `authority.held_since` naming the interval, meaning only that no load
  THROUGH THIS APPLICATION INSTANCE has found a seal other than the one that
  instance last wrote or found clean.
  THE VALUE WORD IS `"process"` AND THE BOUND IS THE APPLICATION INSTANCE,
  which is narrower and is the claim: `create_app` builds one witness, and a
  second `create_app` in the same operating-system process holds nothing and
  begins its own interval. Measured in one pid: the first instance refused the
  rolled-back store `409` while a second answered `200` at the earlier stage.
  The shipped composition makes one instance per process, so the two coincide
  there. A fresh instance resets it -- on the shipped path that means
  restarting Forge, a same-user act -- so this RAISES THE COST of
  a silent rollback and is not a guarantee; an anchor that survives a restart
  needs authority outside the restoration domain, which is not synthesized
  here. A-029 states the limit and
  `test_a_rollback_across_a_restart_is_the_disclosed_limit` pins it in the
  affirmative, reading that disclosure, so the cross-restart case cannot be
  closed without rewriting it in the same commit.
  ONLY THE SURFACE CARRIES THE WITNESS. `nornyx-forge build --project-dir`
  builds its store with the seal and no witness, so a build launched through
  the developer CLI reads a wholesale rolled-back store as honest while the
  surface refuses the same store; that is measured, unchanged, and now stated
  as A-029 residue (3), because a short-lived process that performs one
  `load()` holds no interval worth reporting.
- The control-plane admission criterion now applies to a real record, and the
  first such record was taken from a CONFINED Codex principal. Nothing in the
  shipped source constructed a `ConfinementProbe`, so nothing converted a valid
  `nornyx.forge.control_plane_probe.v1` record into one, and the outcome a
  probe carried was hand-authored, its mechanism an unvalidated free string,
  and `control_plane_authority_outcome` -- the mapping and its separation guard
  -- had no production consumer and was ADVISORY. A-028 said so in those words.
  `confinement_probe_from_surface_record` and
  `confinement_measurement_from_surface_record` in `provider_contract.py` close
  it. The outcome is DERIVED through that mapping and there is no parameter by
  which a caller states one; the platform comes from the record's subject and
  the revision from `subject.tree_git_sha`, never from an argument. The
  refusals are named and never a silent downgrade to `inconclusive` -- which is
  a measurement result, and putting it on a parsing failure is how an
  unreadable record comes to look like an honest one: a foreign schema; a
  transport that is not `loopback_socket`; a request row that ANSWERED under any
  mechanism but `observed_surface_record`, and the positive control's request
  likewise; a classification that disagrees with its own request log in EITHER
  direction, with allowlist membership derived from a restated constant and
  never from a row's stored flag, because a forged record laundering a gated 2xx
  would simply mark that row allowlisted; any classification outside
  `_V1_DERIVABLE_STATES` and any separation word outside
  `_V1_SEPARATION_VALUES` -- BY MEMBERSHIP of those allow-lists, which is what
  catches `unreachable` and `separated`, the two values that producer can never
  write and which are exactly the ones that would answer `denied`; a request row
  whose route is not a pair of strings or whose status is neither absent nor an
  integer; a subject naming no platform; and a measurement whose subject names
  no revision. It does NOT re-derive the classification: a second copy of
  the producer's rule in `layer.domain` would drift, and the weaker copy simply
  passes -- so the boundary is stated instead, and what the producer owns is
  named rather than assumed.
  What the closure makes visible is the honest content of the slice: every
  state a v1 producer can derive, crossed with every separation word it may
  record, maps to `inconclusive` or `allowed` and NEVER to `denied`, so no
  record that harness can write satisfies `control_plane_authority`. That is a
  property of the PRODUCER, not of the criterion, and it is asserted over the
  whole cross-product by
  `test_no_record_this_producer_can_write_satisfies_the_property`.
  The measurement (`docs/governance/CONTROL_PLANE_AUTHORITY_MEASUREMENT.md`,
  Windows, codex-cli 0.153.4, both probe records embedded verbatim in its JSON)
  ran the probe as a confined process through `codex sandbox` -- the CLI's own
  restricted-token entry point, no model in the loop -- against a live SERVED
  onboarding surface on a real loopback socket, paired with an identical
  UNSANDBOXED control run against the same instance. The shipped invocation
  `codex_worker.py` constructs was NOT measured and cannot be: `codex exec`
  carries a prompt, not a command, so a model would decide whether the probe
  ran, and PA-01 measured that decision going both ways with every canary
  pristine. Over a complete 133-cell matrix with the deadline unexpired the
  confined caller reached the four allowlisted pairs, was refused 401 on all 129
  gated cells, acquired no bearer through the surface, and its bearered positive
  control answered 200 in the same run in which the bare one answered 401 --
  `admitted_nuisance`. It ran as a DIFFERENT OS account from the surface's owner
  (distinct SIDs, read by `whoami /user` inside each process and confirmed
  independently by git's own `safe.directory` refusal, which printed both), and
  the record still says `principal_separated: unknown`, because a v1 producer
  may never say otherwise. So the mapping answers `inconclusive`,
  `control_plane_authority` stays unmet, Codex's row stays `declared`, and both
  providers stay ineligible. NOTHING MOVED, and the reason is a measured limit
  of the harness rather than a judgement about the sandbox.
  The finding that matters most is not the classification: separating the
  accounts does NOT close the channel the separation guard exists for. Of the
  two channels A-027 concedes a same-user caller, the confined process KEPT
  Forge's process memory -- `OpenProcess(PROCESS_VM_READ)` on the surface's pid
  returned it a handle -- while the `Win32_Process` query the browser-handler
  channel needs COMPLETED for the unconfined control (15 command lines) and did
  NOT COMPLETE for it. That differential is real and was taken in the same run
  on the same host; the MECHANISM of the failure is not measured, because the
  producer's `not_applicable` covers a denied launch, a missing executable, a
  timeout and a non-zero exit indistinguishably, so it is not a denial and is
  not read as one. The memory reading was falsified before it was recorded --
  the same call against a SYSTEM process was denied with error 5, so the
  instrument discriminates, and a separate control read 64 bytes at a MAPPED
  address in the launching user's process and recovered a planted marker
  verbatim -- but BOTH falsifications are operator observations OUTSIDE the
  record, stated as such rather than implied to be evidence. Locating a secret
  in that address space was not attempted and is not claimed.
  Taking the measurement also found a defect in the C2 harness that only a
  confined principal exposes: at the parent revision the sandboxed run raised
  `PermissionError: [WinError 5]` out of `_browser_history` through
  `Path.exists()` -- exit 1, a traceback, NO record, well inside the deadline --
  because `Path.exists()` swallows "not found" and RE-RAISES a permission
  error. The harness's stated contract is a record and an exit code, so its
  exit-code enumeration in `--help`, in the README and in A-028 was false for
  exactly the caller it exists to measure. `_presence` now answers True / False
  / None, a denied check is `refused` and never `not_applicable` (a path this
  caller may not stat is not a path that is absent), and a backstop in `probe()`
  turns any remaining `OSError` into an outcome rather than an ending, keeping a
  PermissionError (`refused`) apart from any other (`not_applicable`). That
  separation is the BACKSTOP's; `_presence` itself still folds every `OSError`
  into the denial wording, which round 2 measured and did not repair, because
  repairing it would edit the module this measurement ran and break the blob
  identity the record binds. Carried as an open finding in A-028.
  Measured under mutation: accepting a non-socket transport, accepting a
  control-plane fact labelled by inference, taking a stated outcome instead of
  deriving one, accepting a classification that disagrees with its own log, and
  flipping the recorded verdict to eligible are each red; restoring each is
  green.
  Three census rows move -- `tests/test_codex_confinement_admission.py` 66 ->
  106 (floor 60 -> 96), `tests/test_control_plane_authority.py` 68 -> 73 (62 ->
  66), and `tests/test_recorded_measurements.py` 189 -> 194 (171 -> 175),
  because the new governance document joins its parametrised sweep -- so
  `MINIMUM_COLLECTED` is 3035 and the windows-runtime job's arithmetic floor is
  262. A-028, `docs/VALIDATION.md` and the contract's own docstring record what
  C3 establishes and what it does not.

  ROUND 2 closed eight findings from three independent read-only lanes, and
  every one of them was the same defect: a LABEL standing where a MEASUREMENT
  belonged. Nothing shipped was false; the guards claimed over those values were
  not there. `_V1_DERIVABLE_STATES` and `_V1_SEPARATION_VALUES` existed only in
  docstrings while the real guards were deny-lists of one, safe by a coincidence
  nothing enforced -- measured: a fifth state added to the contract's vocabulary
  and mapped `denied` let a hand-written record reach
  `control_plane_authority` MET with every gate green. They are membership
  guards now, held to the producer's own tuples with their COMPLEMENTS pinned,
  and both C3 cross-product tests are DERIVED from those tuples instead of eight
  typed-out cells, so the same mutation now reddens the tests that assert the
  claim rather than only three neighbours. The A-028 closure gate was a
  substring scan a COMMENT satisfied; it is now an `ast` walk that looks for a
  real call to `ConfinementProbe`. The comment on `attempt_observed` claimed it
  was derived and not declared, yet replacing it with a literal `True` passed
  all 97 tests; a record whose log answered nothing now asserts False. The emitted platform and the bound revision were compared only
  with values copied from the same field; they are compared with literals as
  well. `probe_module_blob` and `parent_revision` were read by nothing; the blob
  is recomputed from the shipped module's bytes and the parent must be a commit
  reachable from HEAD. And the measurement document said its table was
  "re-derived on every commit" while NOTHING read it -- five byte-exact
  falsifications left 291 tests green -- so every row of its three tables is now
  held to a value derived from the record or computed by running the code, and
  the measured counts are held across four documents and the contract's own
  docstring. The document also stopped reading `not_applicable` back as a
  denial: the differential between the arms is real and stated, the mechanism is
  not measured and is no longer claimed. What remains prose is listed as prose,
  in the document's own "What is anchored" section and in A-028.

- The Windows runtime harness no longer turns an ordinary record-publish
  transient into a `TypeError`. `write_record` publishes by whole-file replace
  -- stage a file, `os.replace` it onto the record's name -- so a reader that
  lands in that window finds either no record at that name or one that does not
  parse; `read_record` answers None for the first and refuses the second, and
  the harnesses' `record()` collapses both to None. Two wait loops in
  `tests/test_windows_runtime.py` SUBSCRIPTED that read, so a transient raised
  `TypeError: 'NoneType' object is not subscriptable` instead of taking another
  turn. That is what failed the `windows-runtime` job on `main` at `dabaade`, in
  `test_w5_the_browser_opens_only_after_the_server_answered_with_its_own_token`.
  Both loops now treat None as "not settled yet", which is what a wait loop is
  for, and the assertions in that module and in
  `tests/test_windows_host_runtime.py` that read a field off a fresh record go
  through `_settled`, which says what it saw rather than raising out of a
  subscript. What any test ASSERTS is unchanged; only the handling of the
  transient is. Nothing in `src/` changed: the publish window is inherent to a
  whole-file replace, and the readers are already told about it. `_read_record`
  in `scripts/build_windows_bundle.py` does not carry the same shape: it never
  raises, and both of its pollers are behind an `isinstance` check.
  Pinned by
  `test_a_read_inside_the_publish_window_does_not_break_the_two_channel_waits`,
  which replaces the WRITER with an adversary that holds the window open for
  0.3 s and shows both findings inside it -- the name unused, then half a
  record -- and then runs the two tests that own those waits against it, whole.
  It is decided rather than raced: the browser publish is held until the
  earlier waits are done with it, because they tolerate None too and so ABSORB
  the window if they are still running (measured -- the first version of this
  pin let them, and the mutation row it exists for stayed green); and how many
  readable `ready` records the harness had actually read before the window
  opened is counted and asserted, so a hold that stops working reports itself
  instead of going quiet. Measured under mutation: restoring either subscript
  is red with that exact `TypeError`; letting the publish through unwindowed,
  or opening the window before the harness is polling, is red on the window
  assertion; removing `_settled`'s guard is red on the raises check.
  `tests/test_windows_runtime.py` collects 96 -> 97, so its floor is
  `band(97) = 88`, `MINIMUM_COLLECTED` is 2991, and the `windows-runtime` job's
  derived floor is 257 -- its six modules now carry 270 (14/15/23/53/68/97).

- The admission criterion `control_plane_reachability` is retired and replaced
  by `control_plane_authority` (Tranche C, slice C1). The retired property
  asked whether a provider could open a loopback connection at all -- a PROXY
  for authority acquisition, sound while Forge's control plane was
  unauthenticated. A-027 gated that plane, which makes reachability IRRELEVANT
  rather than ABSENT, and PA-01 found no sandbox setting that removes it; so
  the criterion demanded the absence of something still present that nothing
  can remove, and no provider could ever satisfy it -- for a reason about the
  proxy rather than about any provider. The replacement asks the thing the
  proxy stood for: whether a process confined as Forge's adapter confines it
  can acquire or move Forge authority THROUGH the control plane, on the surface
  Forge actually serves, decided by that surface's own record and never by the
  caller's exit code. Its competent observer is a new mechanism,
  `observed_surface_record`; `observed_listener_record` is refused for it by
  name, because a controlled test listener has no gate, no routes and no
  authority to move -- it can answer "did anything arrive at me", not "did
  anything move Forge". `control_plane_authority_outcome` is the one mapping
  from an observed state to a probe outcome, in the vocabulary
  `scripts/probe_control_plane.py` already derives. An `unreachable` state
  answers `denied` and `authority_reachable` answers `allowed`, at every
  separation word; `reachable_unadmitted` and `admitted_nuisance` answer
  `denied` ONLY when the record says the principal is SEPARATED from the
  surface's owner, and `inconclusive` everywhere else, because both are read
  off a REACHED surface's request log and A-027 concedes a same-user caller two
  channels that log never sees; an `inconclusive` state, or no record at all,
  answers `inconclusive` and never `denied`. The
  states are restated in the contract rather than imported and held equal to
  the harness's by a test. The retired name is kept as DATA in
  `RETIRED_PROPERTIES` rather than deleted, because
  `docs/governance/codex_confinement_measurement.json` is a historical artifact
  that spells its probes with it: such a probe still validates and votes on
  nothing. The replacement was held to a strictly-stronger obligation measured
  over the repository's own recorded probes: the retired criterion's REQUIRED
  outcome entails the successor's (no connection, no admission); the entailment
  runs one way, so a reachability that was ALLOWED entails nothing; it yields a
  STATE and never a probe, so no listener record is re-labelled as an
  observation of a surface nobody watched; and consequently the retired
  evidence, even at its most favourable, still does not ADMIT the new property,
  which asks for strictly more evidence than the old one did. What the
  replacement genuinely widens is the set of worlds that can satisfy it, and
  that widening is guarded by the separation conditional, not free --
  `reachable_unadmitted` and `admitted_nuisance` are BOTH conditional, over
  both of the states the widening opens. The first head of this slice guarded
  only `admitted_nuisance`; criterion review measured that the other half
  established the property at `not_separated` and at `unknown`, from a record
  C2 can produce, for an unconfined caller running as the surface's own OS
  principal, so the guard was extended rather than the claim reworded. NO
  provider moved: `governed_build_eligibility`'s rule, `assess_confinement`'s
  unanimity rule and `PROVIDER_CONFINEMENT` are untouched, both providers
  remain ineligible, and each refusal names a missing measurement rather than
  an approval -- Codex because no record of Forge's own gated surface from a
  Codex principal exists, Claude because nothing about it was ever measured.
  `docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md` and its JSON were
  deliberately not edited (A-028, A-024).
- Control-plane probe harness (Tranche C, slice C2). A measurement tool and
  importable module, `scripts/probe_control_plane.py`, that observes a live
  onboarding surface over a real loopback socket as a local stranger would --
  it imports no app to enumerate routes -- and writes a
  `nornyx.forge.control_plane_probe.v1` record. It drives the seven HTTP
  methods across the composed route census (a documented path list a test
  holds equal, in process, to the served composition `assemble` plus
  `attach_runtime_routes`, and whose methods it holds equal to the session
  census's own), records every request's method, path, status, body length,
  whether the body echoed the request and which headers the probe
  synthesised, attempts the artefact reads a same-user caller could make
  (`OpenProcess(PROCESS_VM_READ)` on the surface pid, the browser handler
  command line via `Get-CimInstance`, the browser history stores, the runtime
  record, log and seal directory) -- each degrading to `not_applicable` with a
  reason off Windows or where the facility is absent, never to a pass -- and
  derives THREE states plus `inconclusive` (`reachable_unadmitted` /
  `admitted_nuisance` / `authority_reachable`; `unreachable` is not in its
  vocabulary, because deriving it needs a positive control from a separated
  principal that only a later slice can supply, and a record claiming it is
  refused by name) from the unauthenticated request log alone, under two
  rules: allowlist membership is derived from the constant and a row whose
  stored flag disagrees is refused; and a state that would count as
  confinement requires every cell of the 133-cell matrix answered, while a
  gated 2xx dominates at any coverage. Each fact carries its mechanism, kept
  apart: `observed_surface_record` for a socket-observed fact, `inferred_acl`
  for a filesystem or capability inference. The record is a self-report: its
  `transport` is a declaration, and the validator refuses a non-socket
  declaration and a socket fact mislabelled as an inference but cannot tell a
  `TestClient`-built log with self-declared socket labels from a socket one
  (measured: such a record is accepted); what holds the label honest is the
  producer, which has no in-process path, pinned by an AST test. The
  validator also refuses a stored classification, reason or coverage block
  that disagrees with the record's own log, a surface-absent record claiming
  a state, a `principal_separated` outside the three-word vocabulary
  (`separated` / `not_separated` / `unknown`, read through `is_separated`)
  and `separated` from C2 by name, an absent or incomplete subject block, a
  surface that is not the expected instance or an instance match declared
  rather than computed, a memory-handle artefact claimed `observed` on the
  probe's own pid, a positive control claiming admission without a recorded
  request, an artefact reporting a pass, a host identity in the clear, and a
  bearer or raw nonce (channel nonces are sha256 prefixes only). An artefact
  carries one of THREE outcomes and a refusal is not an observation:
  `observed` is a capability this caller acquired, `refused` a facility that
  exists and denied it, `not_applicable` that there was nothing to try;
  `capability_acquired()` is the only sanctioned way to read one as evidence
  of a capability, and the validator refuses a record whose own detail records
  a denial under the acquired word. Redaction folds every spelling of home --
  long, resolved, and the Windows long and 8.3 short forms, expanded on the
  path values first -- to `~` and removes the login and machine name, matching
  each RAW and JSON-ESCAPED because the whole-record backstop runs over a
  `json.dumps` blob whose separators are doubled; the principal's Windows SID
  is retained on purpose and disclosed as what it is (A-028).
  `powershell.exe` and `whoami.exe` are resolved absolutely under
  `%SystemRoot%` or from a DRIVE-ABSOLUTE `PATH` entry, never from the working
  directory and never from an entry the current drive completes; `OpenProcess`
  is called with `use_last_error` and typed arguments, a pid that names no
  process is `not_applicable` and ERROR_ACCESS_DENIED is `refused`; `--host`
  must be loopback (refused by name otherwise, and `localhost` normalised to
  127.0.0.1 so the resolver cannot choose the destination); an `--out` inside
  the repository working tree is refused; the whole run is bounded by a
  `--deadline` that clamps every operation it starts, the subject binding's
  `git` and `whoami` calls included, and ANY expiry is `inconclusive` with the
  reason and a count of the reads it cut off, a black-holed surface ending
  that way; `main()` exits 0 for
  `admitted_nuisance` or `reachable_unadmitted` (no authority reached by this
  caller, NOT a confinement verdict), 2 for `authority_reachable`, 3 for
  `inconclusive`, 4 when refused or invalid. Run in-process against the
  served composition on a real port, the probe classifies itself
  `admitted_nuisance` with `principal_separated: not_separated`, records why
  that is NOT confinement for a caller that is the surface's own OS principal
  (A-027), answers all 133 cells, and finds its memory-handle artefact
  `not_applicable` because the surface pid is its own; a separate
  cross-process witness -- the CLI in a child process against the same live
  surface -- acquires the handle on Windows and finds the facility absent
  elsewhere, and exits 0. Running it against a browser-granted surface opens
  the owner's browser once per run (one reopen mint; the explicit pull
  answers 429). `tests/test_control_plane_authority.py` pins the in-process
  route table (C9), the wire census with what it can and cannot distinguish,
  the self-probe classification (R10), the validator refusals (M6, M8), the
  classifier's derivation rules, the redaction, the subject binding, the
  artefact producers, the host rule, the deadline, the exit codes and the
  no-provider/no-synchronous-launch property; it runs on every CI platform
  (the off-Windows arm witnessed by the Linux matrix, not the development
  host), its Windows-only facilities degrading to `not_applicable`, and joins
  the windows-runtime CI job (floor re-derived 188 -> 256 over six modules
  carrying 269 tests -- 14/15/23/53/68/96 -- by the arithmetic pin that job's
  own floor test states: the total, less the SMALLEST module, plus one. 249
  was a stale draft of this number from when the module collected 61, and it
  disagreed with the shipped floor for two review rounds).
  THE THIRD REVIEW ROUND closed eleven findings, each by measurement. A
  hostile listener answering `/api/runtime` with `pid` as a list reached
  `int(pid)` and ended the run in a traceback printing the host's paths; the
  identity body is type-checked where it is recorded, a malformed `pid` or
  `instance` records the surface unreachable with the reason instead, and
  every refusal `main()` can reach is exit 4 on ONE stderr line with home
  folded and any remaining path fragment replaced -- pinned with nine hostile
  bodies through a real loopback listener. The development host's own 8.3
  profile spelling, committed in two docstrings as the EXAMPLE of the form
  redaction removes, is a placeholder now, and a lexical sweep anchored on
  `probe.__file__` holds both the probe and its test module against this
  host's login and machine name (as path segments, and in their 8.3 forms).
  The whole-record redaction backstop missed a JSON-escaped home path, which
  is the only shape it ever sees; it matches both now. `deadline_exceeded`
  was set only inside the matrix loop, so a run whose reads were cut short
  afterwards looked complete; the flag is set wherever the clock expires,
  `artefacts_truncated` counts what was cut off and the validator recomputes
  it, and any expiry is `inconclusive` -- the choice between the two candidate
  repairs, taken as both and written down. `Deadline.budget` is arithmetic a
  test reads. `OpenProcess` denied with ERROR_ACCESS_DENIED, and a present
  file this principal could not open, both recorded `observed`, the word for
  the capability they are the absence of. `--out` was documented against
  writing into the tree and refused by nobody. The surface-absent rule's test
  gained a `match=` and the one shape only that rule catches; a dead disjunct
  and an unasserted `echoed` field are gone.
  This slice changes NO admission criterion and runs NO provider:
  `CONFINEMENT_PROPERTIES`, `PROPERTY_EVIDENCE_MECHANISMS`,
  `governed_build_eligibility`, `control_plane_session.py` and
  `windows_runtime.py` were untouched by IT -- the entry above records the
  criterion and mechanism that slice C1 has since changed -- both providers
  stay ineligible after both slices, and the bearer gate remains a constraint
  on the surface, not a confinement of any caller (A-028 DRAFT).
- The runtime's session file is visible only when it is complete, and the
  Windows host harness waits for a bearer it can PARSE. The windows-runtime CI
  job failed once at PR #46's head with a `401` on the first bearered
  `POST /api/project`, one child ever started and its record `ready`. The
  cause was a write in two steps: `write_session_file` created the FINAL name
  with `O_EXCL` and wrote the payload afterwards, and `HostRuntime.wait_for`
  returned as soon as that name EXISTED, so a reader landing between the
  create and the content parsed nothing, got `None` from `.token`, and sent
  its first request bare — out of exactly the wait that had just returned.
  Tranche B closed this race class for the harnesses' EXISTENCE wait and left
  the CONTENT window open; the bundle smoke was immune only because it polls
  until the token parses. The payload is now staged as `<name>.tmp` beside the
  target — created with `O_EXCL` at mode `0600`, flushed and fsynced — and
  moved onto the final name by an operation that REFUSES an existing target
  (`os.rename` on Windows, `os.link` then unlink on POSIX), so the final path
  never holds partial content and the pre-existing-file semantics are
  unchanged: a file already there is left as found, the person is told by
  path, and this run's bearer is written nowhere — exactly, because a target
  already there is refused BEFORE the staging file is created, so no bearer
  reaches any disk for that case. The check is not the refusal: the move
  still is, and a target that appears after the check is refused by it just
  the same. A staging name already taken is reported as the different fact it
  is rather than as "the target already exists"; the move retries a Windows
  sharing violation on the sibling `write_record`'s own 20 × 50 ms, because
  the file is polled by exactly the readers that cause one; the staging file
  this call made never outlives it, on success or failure; and a file that
  took the staging name AFTER a successful move is left alone rather than
  deleted. ONE RESIDUAL, stated in A-027 rather than implied: a hard kill
  between the fsync and the move leaves `<name>.tmp` holding a live bearer in
  the fenced directory, because a `finally` does not run when a process dies.
  Both harness waits now poll `.token` rather than the path, with a failure
  message that says whether the file existed and whether it parsed. TESTS:
  nine, mutation-checked — the final path never observable with partial
  content under a 200 ms pause between create and content (reverting to
  create-then-write is red on the first observation inside the window), the
  move refusing a target already there, no staging file outliving a placement
  either way, both waits held against a writer that deliberately exposes an
  empty file (existence-only waits are red with `None` for a bearer),
  `os.open` never reached for a target already there, two sharing violations
  survived with the two pauses they cost, a foreign staging file surviving a
  successful move, and every placement failure naming the file it could not
  use. The windows-runtime job's collected-count floor is now DERIVED from a
  live collection of the modules its own command names, rather than restated
  in prose — the prose had gone false, and nothing was reading it. Nothing
  about the fence, the mode, the after-readiness ordering or the shipped
  launchers changed; no shipped launcher passes `--session-file` at all.
- Control-plane session capability (Tranche B). The onboarding surface is
  local and unauthenticated, and A-024 measured that a Codex worker confined
  to the project workspace still reaches loopback and its POST is accepted
  under the Host rule -- so any local process could drive the authority-moving
  routes as if it were the person. It now admits an authority-moving request
  only when it carries this run's bearer. A per-run token is minted in
  `create_app` (the real composition root, not `assemble`) and enforced by a
  pure ASGI middleware (`nornyx_forge.control_plane_session.SessionGate`,
  `layer.domain`, no web framework) installed so it wraps every route,
  including the operational routes attached afterwards; everything but four
  allowlisted routes (`GET /`, `GET /api/runtime`, `POST /api/session/redeem`,
  `POST /api/runtime/reopen`) is refused `401` with a fixed body unless the
  `Authorization: Bearer` matches, compared with `hmac.compare_digest`. The
  token and the bootstrap nonce live only in Forge's process memory and the
  page's JavaScript closure: no cookie, no web storage, no session file on any
  default path, and no secret in any log, record, URL path, environment, prompt
  or argv Forge controls (the browser handler's command line receives the
  fragment URL; A-027 states the bound) -- because the measured
  `CodexSandboxUsers` ACLs give a confined
  provider read over the profile, the runtime dir and the seal dir (A-027).
  The launcher opens the page at `/#<nonce>`; the fragment is never sent to a
  server, the page redeems it once for the token, and a reload loses the
  session by design (a Reconnect button asks the owning process to open a
  fresh page; the second launcher uses the same reopen route; the console
  composition has no runtime routes, so reopen is 404 there and the page
  says so). The two unauthenticated POSTs carry Origin/`Sec-Fetch-Site`
  checks, a navigation POST is refused `403`, and a `forge_session*` cookie
  is refused `400` on gated requests while the allowlisted routes ignore
  cookies (round 3 below); the
  FastAPI docs and schema routes are off, `access_log` is off on every launch
  path, and the validation-error handler echoes nothing. The workers pass the
  provider an explicit environment stripped of `FORGE_*`. The bundle smoke and
  the runtime tests read the token from an explicit `--session-file` the
  shipped launchers never pass. `PROVIDER_CONFINEMENT`,
  `CONFINEMENT_PROPERTIES` and `governed_build_eligibility` are untouched;
  both providers stay ineligible; no Experience stage, CONFIRM, READY, seal,
  lock, token or port semantics changed. The non-HTTP authority paths, the
  same-user provider, and the shipped `codex exec` confinement are out of
  scope and disclosed in A-027.
- Tranche B repair round, closing the first review's findings. Credentials
  are compared as bytes after an alphabet check, so a non-ASCII bearer or
  nonce is the fixed `401`/`404` instead of a `500` with a traceback in the
  runtime log (security F-1, measured); the gate's own decision cannot raise;
  `Authorization` is accepted only as `Bearer <credential>` — one space, no
  surrounding or embedded whitespace, no second field — with the scheme name
  matched case-insensitively as RFC 6750 requires (F-5);
  a websocket handshake is closed before accept and non-HTTP scopes other
  than `lifespan` are dropped (F-4). On the browser-open FAILURE branch the
  record, log and notice no longer carry the fragment URL: they name the
  fragmentless URL and scrub the nonce from the exception text (architecture
  P1-1, measured: a nonce read from the record redeemed for the token). The
  bootstrap nonce lives in two independent slots, each single-use, and the
  second is a QUEUE rather than one slot: `launch` holds ONE nonce, replaced
  by the next launch mint, while `reopen` holds up to `REOPEN_PENDING_BOUND`
  = `floor(NONCE_TTL_S / REOPEN_INTERVAL_S) + 1` = 13, the most nonces the
  reopen route's own rate limit can leave outstanding within one TTL -- so
  under that limit no unexpired reopen nonce is evicted by another caller's
  reopen either. A local process calling reopen therefore invalidates neither
  the person's pending launch bootstrap nor a Reconnect nonce their own page
  minted; reopen refuses `409` on a `--no-browser` run and
  a joining launcher told `409`/`429` notifies with the fragmentless URL (F-3,
  P3-2). `--session-file` is fenced like `--runtime-dir` -- absolute, in an
  existing directory, outside the project, the runtime directory, the seal
  directory and the user profile -- before anything is created, written only
  after readiness with mode `0600` where the OS honours a mode, and the
  bundle smoke's comment now says where its file lands and why that is
  acceptable for the smoke alone (F-2, P3-1). Evidence made to pin the
  prose: a route census over the COMPOSED surface against a hardcoded
  allowlist with state bytes, lifecycle and stop checked; every partial
  bearer refused behaviourally; a declared response-header set on every
  response; Origin full-serialization specimens; `access_log=False` on the
  Windows runtime pinned by Config and by the log; the session file's
  after-readiness ordering pinned; and INV-B2's provider leg driven through
  the REAL `DevelopmentFlow` with a fake provider executable resolved by
  name, whose received environment, argv, cwd and workspace are read back.
  A-027 now scopes "no argv" to argv Forge controls, discloses the browser
  handler's command line, the two-slot design and the residual reopen
  nuisance, the `--session-file` reachability and fence, and that fragment
  preservation through ShellExecute is unmeasured until the operator run.
- Tranche B round 3, closing the second review's findings. TESTS: no launch
  that must return is called synchronously any more -- each is held to a
  watched deadline (`_returns`) that reads the record such a launch would
  write if it became a server, so a fence-removed or lock-broken regression
  is a red test within about a second rather than a hang (test P1-1/P1-2;
  measured: the `[profile]` session-file case assumed pytest's temp root lay
  under the profile, true on the workstation and false on the Linux matrix,
  where the unfenced launch served forever and the CI run had to be
  cancelled); that case now relocates the profile so it CONTAINS the
  candidate and asserts it; the composed route census FAILS on any live
  route it cannot probe (a `Mount`, a `WebSocketRoute`) instead of skipping
  it (P2-1); the Windows host suite sends an un-bearered and a wrong-bearer
  stop to the real child and requires `401` with the record still `ready`,
  the process alive, and the log free of request lines and tracebacks
  (P2-2); the runaway recovery posts stop with the bearer (P3-2); the
  source-grep tests read the IMPORTED package (P4-2); the web-storage pin
  says it is lexical (P3-1). RUNTIME: a `forge_session*` cookie is refused
  `400` on GATED requests only and ignored on the four allowlisted pairs --
  cookies are host-scoped, so a listener on another loopback port could set
  one for `127.0.0.1` and the previous rule let it deny the person `GET /`
  (security N-1); an owner whose browser adapter raises answers reopen `503`
  with a fixed body, and the joining launcher tells the person with the
  fragmentless URL instead of reading a `200` as success (N-2, architecture
  P4-3); the readiness, reopen and join branches catch EVERY exception class
  and scrub it, so no class can carry the fragment URL into a traceback
  (specimen: a handler's own exception class); the session file is created
  exclusively, and a file already there is left as found, told by path, and
  not removed at stop (P4-2); the fence resolves the runtime directory
  itself (P4-1). PAGE: a `Content-Security-Policy` meta (`default-src
  'none'`, inline script and style, same-origin connect only, no base, no
  form action), Reconnect branches for `429` and `503` (N-4, N-7), and the
  `replaceState` comment scoped to the address bar and the session-history
  entry (architecture P3). DOCS: the sentence that said the console path
  uses the reopen route is corrected -- the console composition has no
  runtime routes (N-3); A-027 discloses the browser's persistent history
  store as a channel beside the handler command line, bounded by the nonce's
  single use and TTL and NOT by principal separation on this host, the
  single reopen slot shared with the person's Reconnect, and that
  `--no-browser` reopen polling is unbounded but stateless (N-4, N-5, P3).
- Tranche B round 4, closing the third review's findings and the CI failure.
  CI: the windows-runtime job failed on a TEST listener that did one `recv`
  and answered -- `http.client` sends a POST's head and body in separate
  sends, and a close with the body unread is a RST that discards the
  client's received response on Windows (10054; reproduced at 1 in 300).
  Every listener script now reads the whole request through one helper,
  proved with a forced two-segment request and 200 exchanges with no reset.
  SECURITY (P2-1, blocking): `\\?\`, `\\.\`, `//?/` and UNC spellings
  bypassed the `--session-file` fence and the pre-existing `--runtime-dir`
  fence -- `Path.resolve()` keeps the prefix, so the plain roots are never
  among the parents; measured end to end, `\\?\<profile>\stolen.json`
  launched ready and wrote the bearer inside the profile. Both fences now
  refuse those spellings by name before resolution (the session-file fence
  refuses every double-separator spelling, UNC included; the runtime-dir
  fence refuses the namespace prefixes on the runtime AND the project
  directory), pinned per root over real launches that create nothing, plus
  8.3, junction, trailing-dot and trailing-space specimens. The reopen slot
  is a bounded QUEUE (P3-1): a local caller's reopen no longer evicts the
  nonce the person's Reconnect just minted; the depth is derived from the
  rate limit and the TTL (13) and the two constants are pinned together.
  `_provider_env()` also drops a bare `FORGE` (P4-3); the redeem 200 is
  `Cache-Control: no-store` (P4-4); a browser adapter whose `__str__` raises
  can no longer throw from inside the scrubbing `except` (P4-4). ARCHITECTURE:
  `control_plane_session.py` is in the gate's `forbidden` map for `fastapi`,
  `starlette`, `uvicorn`, `subprocess` (F1; an injected `import fastapi` had
  passed), the refusal bodies are read-only views (F5), the composed census
  covers near-miss and unrouted paths (F4), and the continuation lines left
  misaligned by the `authed_client` rename are aligned (F6). TESTS: the
  constant-time pin is an AST walk over BOTH `verify` and `redeem` (P1; two
  lexical pins had let a swapped `==` through), the console start link is
  read from stdout with `uvicorn.run` replaced (P1; printing the bearer had
  passed), `NONCE_TTL_S` is pinned through `create_app`'s own session under
  an injected clock (P2), the `[seal]` fence case fences against a seal
  directory of its own (P4), and the test harnesses wait for the session
  file as well as the `ready` record (a measured `401` on a first request
  sent before the after-readiness write). DOCS: A-027 measures the history
  stores' DACLs instead of inferring them (P3-3: the sandbox group reads
  `%LOCALAPPDATA%` and not the two stores), joins the reopen trigger with the
  two channels it feeds (F2, P3-2), softens the Origin claim to browser
  provenance (P4-2), lists what `/api/runtime` discloses (P4-1), names the
  profile root as the one environment-derived fence root (F3), and discloses
  the UNC-alias residual of the runtime-dir fence.
- Tranche B round 5, rebased onto the provider-adapter parity slice and
  closing the fourth review's findings. TESTS (blocking, P2): the two
  POST-RESOLUTION fence refusals had no witness -- deleting
  `_double_separator(resolved)` in the session-file fence, or the second
  `_namespace_prefixed(runtime_dir)` in `launch`, left the whole runtime
  module green, because no plain path on this host resolves to a prefixed
  one while the docstrings said spellings are refused "before resolving, and
  again after". The CALLER-SUPPLIED candidate's resolution is now a seam
  (`resolve=Path.resolve`, threaded from `launch` into the fence; the fenced
  roots are still resolved for real and `main` passes no seam, pinned), and a
  test presents the resolution a substituted drive or junction chain onto a
  UNC share would give -- red for both blocks on both platforms. The AST
  constant-time pin also reads comparisons written as CALLS (`__eq__`,
  `__ne__`, `__contains__`, `operator.eq/ne/contains`): `candidate.__eq__(...)`
  in `verify` and in `redeem` had each survived the whole module. Queue
  pruning is measured on the queue's LENGTH (re-appending expired entries had
  survived), `NEAR_MISS_PATHS` asserts its own count, the console start
  link's FRAGMENT is read on stderr and the log records as well as the
  bearer, and the join path's `_said` site has its first specimen (a browser
  adapter whose `__str__` raises: exit 3, the fixed notice, no traceback).
  ARCHITECTURE: the bundle smoke awaited nothing before reading the session
  file the runtime writes AFTER readiness -- the race the two test harnesses
  closed in round 4, left in the shipped smoke -- so it read None and sent
  three bare requests; it now waits inside the record wait's own deadline and
  records `session_file` as a REQUIRED observation, so a bearer that never
  arrived is named once instead of surfacing as three unexplained 401s. The
  dead `reopen_interval` parameter is deleted in favour of the module
  constant it always held; the last two raw `str(exc)` sites are guarded with
  `_said`; the host harness's dead-child check is a sibling `if` again, so a
  child that records ready and dies no longer spins to 240 s (pinned in
  seconds, on every platform); and an embedded NUL in either caller-supplied
  path is the fixed "Forge could not start" rather than a `ValueError`
  traceback. DOCS: A-027 and VALIDATION carry the UNC residual on BOTH fence
  operands (a UNC alias of the PROJECT with a plain runtime directory passes
  and creates the runtime directory inside the project, measured), the
  console path's live nonce on stdout, the smoke's session file under
  `%LOCALAPPDATA%\Temp` on its four conditions, and the seam the
  post-resolution witnesses use.
- Tranche B round 6, closing round 5's CI failure and the fifth review's
  findings. SECURITY (blocking): an embedded NUL in a caller-supplied path is
  now refused EXPLICITLY and FIRST in every fence — the session file, the
  runtime directory and the project directory — before the spelling checks,
  before `resolve` and before any root comparison, with a fixed notice that
  echoes no path. It had been caught in an `except ValueError`, which made the
  ANSWER a property of the interpreter: `ntpath.realpath` non-strict RETURNS a
  NUL-bearing path (leaving an 8.3 segment unexpanded), and on CPython ≤ 3.12
  `Path.resolve` raises only because of the trailing `p.stat()` it adds in
  non-strict mode, which 3.13 no longer does — so on 3.13 the fence compared
  an UNRESOLVED spelling against its roots and the profile refusal answered
  first. That is an ordering hole, not only the windows-latest test failure it
  produced; and on ≤ 3.12 a NUL in `--project-dir` was a traceback, because
  that operand was resolved while building the fence list, outside every
  `try`. The console launcher's comment claiming its start-link nonce "stays
  off disk" is replaced by what is true — the nonce is single use and
  TTL-bounded and is not the bearer — and by the disclosure that a redirected
  console puts it in a file, from which review redeemed it for that run's
  bearer (A-027); a lexical pin holds the sentence gone. TESTS: the smoke's
  session-file wait is ordered by an EVENT rather than by
  `time.monotonic()`, whose 15.6 ms resolution on Windows ≤ 3.12 put 46 of 300
  readings of a 0.3 s wait under 0.3 and failed that module 2 of 9 unmutated
  runs; the "no second budget" claim beside it now has a witness; the fenced
  roots of `_session_file_refusal` are witnessed as resolved for real and
  never through the candidate seam (`launch`'s own roots were not, and are
  witnessed in round 7); the constant-time AST pin reads a comparison method
  REFERENCED rather than only called, so `checker = candidate.__eq__` and
  `getattr(candidate, "__eq__")` are caught, and it states that it is a
  spelling pin and cannot prove constant time; the two `_said` sites added in
  round 5 get their first specimens; and `_provider_env`'s stripping is pinned
  in the provider suite — which the windows-runtime CI job did NOT run when
  this was written, and runs from round 7 on.
  DOCS: the smoke contract says eight and is checked against its tuple, the
  VALIDATION smoke row carries the wait, and `Bearer` is described as it is
  handled — the scheme name matched case-insensitively, nothing else lax
  (round 6 credited that rule to RFC 6750; round 7 corrects the attribution).
- Tranche B round 7, closing the sixth review's findings. SECURITY
  (blocking): `--bundle-root` is `launch`'s FOURTH caller-supplied path and
  was outside the NUL rule while that rule's own docstring claimed "every
  fence". It is refused now with the other three, before anything is created:
  `verify_launched_bundle` resolves the launched folder outside every `try`
  and is reached from a `try` that catches only `RuntimeRefusal`, so on
  CPython ≤ 3.12 a NUL there was a traceback — and it runs AFTER
  `runtime_dir.mkdir()`, so that refusal had already created the runtime
  directory it was refusing. The rule now ENUMERATES the four paths it
  quantifies over (and the three flags that are not paths) instead of
  asserting a universal, and names both resolutions that catch nothing rather
  than one. TESTS: the constant-time pin reads the IMPORT, not only the use —
  `from operator import eq as _same` with `_same(candidate, ...)` survived all
  98 tests because the only node carrying the word `eq` was the `ast.alias`,
  which the detector never looked at — and the binding is forbidden at every
  scope of `control_plane_session`, since a per-method AST pin cannot see a
  module-scope alias at all. `launch`'s own fenced roots get the
  aliasing-resolver witness `_session_file_refusal` got in round 6: routing
  the seal directory and the candidate project through the candidate seam had
  survived all 87 tests of that module. The NUL case now crosses FOUR
  operands, both resolutions and both profile placements. CI: the
  windows-runtime job runs `tests/test_provider_execution.py`, which round 6's
  entry above said it already did. DOCS: `Bearer`'s case-insensitivity is
  attributed to RFC 7235 §2.1, which makes every auth scheme name
  case-insensitive and which RFC 6750 inherits; the console comment says the
  windowless launcher prints no start link and puts no nonce on any stream —
  it does present the fragmentless URL — rather than "no link at all"; and the
  NUL test states the mutant mechanism that was MEASURED (`Path.is_dir`
  swallows the `ValueError`, so a fence without the rule ADMITS the path and
  the runtime becomes a server) instead of a raise that does not happen.
- Post-PR-18 hardening: the two non-blocking findings of the independent
  review of PR-18, closed before the next programme tranche. N1: the
  bundle builder's `--smoke` said `pass` whenever a stopped runtime record
  existed, while the launcher's exit code, the three route statuses, the
  instance-token comparison on `/api/runtime` and the stop outcome were
  recorded and never judged (measured at the base: exit code 7, HTTP 500
  on every route, a foreign token and a failed stop still produced
  `pass`). The smoke now records every observation its contract names
  and derives `result` from them through one verdict function,
  `evaluate_smoke_observations` (report schema v2): the launcher returned
  0; the record reached `ready` with the runtime's schema, a token and a
  port; `/api/runtime` answered 200 with a JSON object of that schema
  whose instance IS the recorded one; `/api/state` answered 200 with a
  usable state object; `/` answered 200 as HTML; the stop route answered
  200 with `stopping` for that instance; and the record then reached
  `stopped` for the same instance. Anything else -- including an
  observation that is absent or made twice -- is a `fail` that names the
  observation, and `--smoke` refuses by that name. This strengthens the
  instrument the operator's embedded-interpreter run will be measured
  with; it performs no such run and creates no operator evidence. N3:
  the loopback Host rule PR-18 installed on the Windows runtime's
  composition now belongs to `onboarding_serve.assemble`, the one
  composition every production launch path serves, so the console
  `onboard` path and the Windows launcher inherit one and the same rule
  (`127.0.0.1` and `localhost`, nothing wider); the runtime's own copy is
  gone, and a repository-wide census pins that no composition under
  `src/` omits it. A Host check is not authentication: A-015's
  single-person, loopback, unauthenticated trust boundary is unchanged,
  and the two tests that used the test client's default `testserver`
  Host now carry a loopback base URL rather than the rule being widened
  for them. No Experience stage, CONFIRM, READY, eligibility, confinement
  vocabulary, declaration, admission, seal, lock, token or port semantics
  changed; both providers remain governed-ineligible; the real
  embedded-Python operator run remains NOT PERFORMED. Three in-session
  read-only inspections then hardened the smoke against a hostile listener
  on its scratch port -- a nested body or record is invalid rather than a
  raise, the scratch never outlives a raise, the record is kept as five
  bounded fields, an over-long token is refused, every exchange ends
  within twice its time budget (a watchdog plus the receive timeout,
  measured), a body short of its declared length is refused -- and gave
  its exception paths and bounds tests.
- The Windows folder bundle is a runtime a basic user can double-click
  (PR-18). At b1780ee `Forge.cmd` ran `onboard` through `os.execvp`, which
  on Windows spawns the server and returns at once, hardcoded an
  interpreter a developer bundle does not carry, opened no browser, and let
  a second launch die on a bind error nobody could see. Now
  `nornyx_forge.windows_runtime` (entered through the standard-library-only
  `windows_launch`) refuses unless the launched folder is the code that is
  running, refuses a self-contained bundle started on a foreign interpreter,
  takes the project directory as an explicit absolute argument, holds one
  runtime per project under an operating-system file lock, binds a loopback
  port before the server exists (the preferred port when free, otherwise
  one the system hands out), and opens the browser only after a thread has
  read the server's own instance token back through the socket, within a
  bounded timeout that fails visibly. A second double-click opens the
  running page; the same project served from another folder is refused; a
  stale record identifies nothing; an unrelated occupant of the port costs
  a port, never a process. Failures are message boxes under `pythonw` and a
  launch-failure trail. The record, lock and log are operational state
  under the profile, outside every project, never read by the onboarding
  surface, and pinned unable to reach a governance answer. The builder
  writes `forge-bundle.json` naming the bundle's kind, a self-contained
  launcher that names no fallback interpreter, a developer launcher that
  says it carries none, refuses an embeddable archive without
  `pythonw.exe`, and can run the built folder's own launcher (`--smoke`).
  The page gained a "Stop Forge" control. A `windows-runtime` CI job runs
  the Windows-hosted tests on `windows-latest` under a skip census. The
  real embedded-interpreter run stays the operator's act (A-017); the
  console flash of `cmd.exe`, the git prerequisite, and the developer
  launcher's quoting limit are disclosed in A-023. Three in-session
  read-only inspections then hardened it: both launchers turn off
  `cmd.exe`'s current-directory command lookup before naming any command
  (a planted `pyw.cmd` in the launch directory had run in place of the
  Python launcher); the browser adapter parses the URL and accepts only a
  loopback authority; the runtime answers only to a loopback Host header;
  a joining launch retries the lock and treats a finished run's record as
  provisional; notices quote and cut what they echo from disk or a socket;
  the readiness-timeout notice is raised from the main thread; the stop
  route validates its actor as the surface does; an out-of-range port and
  a runtime directory inside the project or the seals are refusals; and a
  crash after the import guard is still a message box and a trail entry.
- Declared is not eligible: the governed basic-user build executes an
  engineering provider only when Forge has established that the provider is
  confined to the project subject, and today that is neither of them
  (independent review of 89910b8, R1). The seal had narrowed what a
  provider could do to the authority store, but the default Claude provider
  runs with general shell capability and no filesystem confinement as the
  same operating-system user whose files hold the seal, so the anchor and
  the actor it constrains shared a trust domain. The Provider Contract now
  carries, as data, what Forge has established about each adapter's
  confinement -- Claude `none`, Codex `declared` (a sandbox flag passed to a
  CLI, not independently established) -- and `governed_build_eligibility`
  decides from that table alone. `/api/build` refuses an ineligible provider
  before the lifecycle moves and before any flow is constructed, tries no
  other provider, changes no execution mode, and the page lists the reason;
  the served surface passes no other decision. The rest of the journey is
  unchanged. Two anchor states are kept apart (R2): a store Forge ever
  sealed carries a committed marker, so a protected store whose seal is
  missing is TAMPERED with nothing to restore from, while a store with
  neither is the legacy case, reported unsealed. The seal's currency is
  reported as not independently anchored and monotonic external anchoring
  is deferred rather than claimed (R3).
- The authority store is sealed against the provider that builds beside
  it (P17-B1). The capsule store lives under the basic-user project
  directory and `/api/build` hands that directory to the engineering
  provider as a writable workspace, so a worker with Write or Bash could
  rewrite `experience.json` or `capsule.json`, recompute the one-link
  digest chain, and commit the result inside the store's own repository.
  Measured at 47bd370 through the build seam and through the real
  `DevelopmentFlow` worker seam: a forged READY was rendered mid-build,
  persisted, and read back after a restart, and a committed forgery left a
  clean tree; forged capsule authority was rendered the same way. Now
  `CapsuleStore` records a seal -- the revision and the exact bytes of both
  authority files -- in a Forge-owned directory outside every project
  after each of its own commits, and checks the store against it on every
  load: revision, working tree, bytes. While a build runs the surface
  answers every read from the authority it sealed when the build began and
  refuses every write; when the flow returns it checks the seal before
  translating the result, restores the sealed authority when the store
  moved, and records the run as a failure that names what moved. A forgery
  left for a later process is TAMPERED on every route until a person
  restores the sealed authority explicitly. The seal is out of a
  workspace-write sandbox's reach and within the same operating-system
  user's reach; A-022 states that bound and withdraws the earlier claim
  that detection "belongs to git history". Three in-session reviews of the
  repair were applied before this entry was final: the served page's script
  had stopped parsing (a statement inserted between an `if` and its `else`),
  which no API test could see and a structural pin now holds; the developer
  CLI's `build --project-dir` read the capsule unsealed and now reads it
  under the same seal; a worker that replaced the store's `.git` with a
  plain file crashed the restoration and left the store stuck, and the
  rebuild now removes what it finds by shape; a damaged or foreign seal
  file was reported as an absent project and is now the TAMPERED finding
  with nothing to restore from; a seal that cannot be written is the
  store's refusal, not a traceback; creating a project is refused while a
  build has the store sealed (a worker that deleted the store mid-build
  could otherwise have a client re-create it and overwrite the seal); and a
  store whose directory the worker removed outright is rebuilt from the
  seal rather than tripping on the missing working directory. Also: a
  build thread that fails to start releases the build lock and the seal,
  so the next build is not refused as already running.
- The basic-user journey is orchestrated through the Experience Contract
  (PR-17). Measured at 9a16851 through the real onboarding app: creating a
  project, confirming its intent and provider, deriving the BRD, starting a
  build and receiving its result -- accepted or not -- and restarting the
  server all left the lifecycle `absent`, with no `experience.json` on disk
  and no lifecycle route; the contract and its tests existed and nothing a
  user did reached them. Now project creation starts a persisted lifecycle
  at DISCOVER through `start_experience`, in the same first store revision
  as the capsule, and the surface offers semantic actions -- start
  tracking, confirm scope, start build, retry, mark ready -- that
  `experience_journey` maps onto the one canonical transition each names.
  No route takes a stage from the client. Confirming a capsule proposal is
  not the lifecycle's CONFIRM: that is an explicit human act with three
  named prerequisites (confirmed intent, confirmed provider, derived BRD),
  refused by the contract for any other actor kind. The build enters BUILD
  through `advance` under the person who started it and requires a
  recorded lifecycle at a pre-build stage, or one already at BUILD with no
  run in progress, which is re-run without a second transition; on
  completion the surface, as a system actor, records TEST from the translated `flow_run` evidence and
  GOVERN from the translated `gate_results`, both through
  `experience_build.flow_evidence` and nothing a worker wrote, and stops
  there. A flow that raised, returned nothing usable, or was not accepted
  is recorded as a failure of the stage the workflow is at, in the
  contract's words, and is retried only through the contract's retry.
  READY is offered only when the persisted GOVERN evidence would satisfy
  the contract and is entered only by a human presenting exactly that
  evidence, read back from the store; a build whose acceptance profile ran
  no Nornyx gate -- which is the shipped greenfield profile -- ends
  honestly at GOVERN, because the translator produces no governance
  validation for it and nothing here supplies one. A capsule from before
  this change stays `absent` until a human starts tracking it at DISCOVER;
  no stage is inferred from its files. One in-process lock serialises every
  read and write of the store -- capsule and lifecycle alike, the build
  thread included, because both files share one git repository and every
  save stages the whole tree (a review measured a concurrent proposal
  committing a half-saved lifecycle as its own) -- so a repeated or stale
  request is judged against the current persisted state, and the build
  status is published only after the lifecycle it produced is persisted. A
  completed run is persisted whole or recorded as one failure at BUILD,
  never left at TEST, from which the contract declares no way back. A
  store refusal reaches the browser in the store's own words; only a
  missing store is reported as "no project". The page shows the persisted stage, its status, the actions
  the contract allows, what still blocks the others, the build status for
  this server session, and each refusal verbatim; its script names no
  stage and decides nothing. The trust boundary is unchanged: loopback
  only, the human unauthenticated (A-015), provider output still only
  proposed content.

- The governance evidence tool asks git under policy-neutral configuration,
  not the reader's. Binding every git question to the governed tree's own
  repository (the entry below) established which repository answers; an
  independent review of that change measured that it did not establish the
  configuration git answers under. In a fresh clone holding a governed,
  untracked `src/untracked.py`, nine reader-controlled routes -- the
  `GIT_CONFIG_COUNT` family, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`,
  `GIT_CONFIG_SYSTEM`, an `XDG_CONFIG_HOME` config and its ignore file, a
  `HOME` gitconfig and its ignore file, an include -- each left the root
  resolving correctly while `git ls-files --others --exclude-standard` named
  nothing, and the dirty-tree gate reported the tree clean. A reader
  attributes file naming a clean filter hid a modified governed file the same
  way. Every git question now runs through one runner: the `GIT_CONFIG_*`
  family is dropped by prefix, `GIT_ATTR_SOURCE` is dropped with the
  steering variables (found under review: it reads attributes from a commit
  instead of the working tree), the system gitconfig and system attributes
  file are switched off, the global gitconfig is pointed at the empty
  device, git's messages are pinned untranslated, and `core.excludesFile`,
  `core.attributesFile`, `core.fsmonitor` and `core.longpaths` are pinned on
  the command line, which outranks every environment route. `HOME` is left
  alone. The repository's own `.git/config`, `.gitattributes` and
  `.gitignore` still apply. Git failures remain refusals, and a genuine
  change to the governed tree is still reported. Two consequences found under
  review are handled and disclosed in A-021: severing the global file also
  severed `core.longpaths`, under which git on Windows answered NOTHING,
  exit 0, for a governed path beyond MAX_PATH, so the key is pinned on; and a
  checkout owned by another user can no longer be verified, because the
  reader's `safe.directory` allowance is out of reach -- the tool now reports
  that refusal in git's words instead of calling the repository absent and
  its provenance `git:unbound`.
- A historical claim corrected: the previous entry said that with no
  repository above the tree, git's silent no-index fallback read the tree as
  clean. That reproduces on git 2.55 (since 2.51, `diff --no-index` takes the
  first two paths as directories and the rest as limits, so a thirteen-path
  `git diff` outside a repository exits 0 printing nothing) and does not on
  git 2.43, where the same command is a usage error and the tool refused --
  which is what the independent review measured. The established defect is
  the enclosing foreign repository; the no-repository outcome was a property
  of the git version. The tool's own docstrings, the tests and A-021 now say
  so; the merged pull request's description is left as written.
- The governance evidence tool asks git about the governed tree and nothing
  else. Every git question ran with the tree as working directory and trusted
  whatever repository git discovered walking upward, so a tree with no `.git`
  of its own -- the archive the anchored-measurement harness extracts -- was
  answered for by whichever repository enclosed the temp directory, and, when
  none did, by whatever the reader's git does outside a repository (see the
  correction above). Measured on one archive extracted byte for byte into
  three places: the verdict changed with the enclosing repository while the
  files did not. The tool now refuses a tree that is not the root of the
  repository git resolves, refuses one git cannot place at all rather than
  leaving the answer to git, and drops the environment variables that re-aim
  git. The harness commits each extraction to a repository of its own before
  re-running `--verify` there.
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
