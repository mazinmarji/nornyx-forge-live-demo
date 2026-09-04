# Documented assumptions

Assumptions recorded during the autonomous demonstration run, as required by
`CLAUDE.md`. Each entry states the ambiguity, the resolution taken, and the BRD
requirement it serves. None of these invent a regulatory or business requirement.

Run subject: identified by content, not by commit. See `governed_revision_digest` and `governed_subject_digest` in the current evidence set. A commit hash stood here and went stale the moment the next commit landed, which is a small instance of exactly why A-011 was superseded: a document cannot name the revision it is part of.
Assurance mode: `autonomous_demonstration` — `human_review: not_performed`.

## A-001 Foundation selection

**Ambiguity.** BRD-F-007 permits `certified`, `target`, `scout`, or `greenfield`
foundations. No target repository was supplied by the user.

**Resolution.** Used the bundled **certified** foundation, per `ONE_PROMPT.md`
("Use the bundled certified foundation unless the user supplied a target
repository"). Repo Scout was not run against GitHub because a qualifying
foundation was already present and network scouting was not required to satisfy
the BRD. `qualify_local` returned verdict `GO` with score `88.3`.

**Serves.** BRD-F-007.

## A-002 Revision binding corrected to the real repository revision

**Ambiguity.** The committed contracts and runtime code were bound to
`git:e9f554892ba8d070bfa14acf75896e032d3c75ec`, which does not correspond to any
commit in this repository (`HEAD` is `8a8fea6ac5068a6a359dfc407489264576329054`).

**Resolution.** Rebound every `subject_revision` and `revision_binding.revision`
to the actual `HEAD`. Nornyx requires exact revision binding
(`exact_revision_binding`), so a placeholder revision is a defect, not a style
choice. The stale value is retained nowhere.

**Serves.** BRD-F-005, BRD-005.

## A-003 Governance evidence artifacts are machine-produced and labelled as such

**Ambiguity.** Nornyx `evidence_integrity` requires every `governance_evidence`
record to reference a real local artifact whose sha256 matches. The repository
shipped with `records: []`, so no artifacts existed.

**Resolution.** Generated the artifacts deterministically with
`scripts/refresh_governance_evidence.py` and bound each record to the real file
hash. Every artifact states its producer type. The architecture conformance
artifact embeds the actual output of `scripts/check_architecture.py`; it is not a
hand-written claim.

**Serves.** BRD-F-005.

## A-004 Human approval evidence was not produced

**Ambiguity.** Nornyx requires an `approval_record` whose producer is
`type: human` and whose `status` is `pass` before an `agentic_network` contract
validates. No human approval exists in autonomous-demonstration mode.

**Resolution.** **No approval record was fabricated.** An honest
`approval_record` documenting the *absence* of approval is recorded in the
architecture contract with `status: observed`; Nornyx correctly refuses to count
a non-passing record as satisfying the requirement. The runtime contract has no
approval record at all. This is a declared hard stop, not a defect to route
around — see `docs/ASSURANCE_BOUNDARY.md` and the run report.

**Serves.** BRD-F-004, BRD-005 ("the final report does not claim human
approval"), and `CLAUDE.md` ("Do not modify Nornyx policies merely to make a
failing implementation pass").

## A-005 Governance change is declared `proposed`, not `approved`

**Ambiguity.** The `changes[]` lifecycle in the architecture contract requires a
status and a legal transition. `approved -> in_progress` would assert that the
governance change was approved.

**Resolution.** Declared `status: proposed` with transition `draft -> proposed`.
An autonomous run may propose a governance change; it may not approve one.

**Serves.** BRD-F-004.

## A-006 Independent review is machine review, not human review

**Ambiguity.** `separation_of_duties` requires an `independent_review_record`.

**Resolution.** The record describes read-only AI inspectors that are
independent of the builder and cannot modify the implementation. It explicitly
carries `human_review: not_performed`. Independence here means *the reviewer is
not the builder*; it does not mean a human reviewed the work.

**Serves.** BRD-005, `CLAUDE.md` ("a builder may not approve its own patch").

## A-007 Separation-of-duties roles are declared policy, not attested events

**Ambiguity.** `separation_of_duties.assignments` requires a named author and at
least one named human approver.

**Resolution.** Declared the role separation the project intends
(`human:repository_maintainer` authors, `human:architecture_reviewer`
approves). This declares *who would be accountable*; it does not assert that
either party acted.

The approver read `human:architect` until this correction: a principal that
appeared nowhere else in the repository, in the one document a reader consults
to find out who may approve. The contract declares `architecture_reviewer`, and
records that requiring `architect` while listing `architecture_reviewer` as
eligible once left a reviewer-signed approval readable two ways. Naming the
retired term here restored exactly that ambiguity, in prose, where nothing
resolves an identifier and no test would have caught it.
No evidence record claims an approval occurred.

**Serves.** BRD-004.

## A-008 Evaluation instant is real by default, pinnable for determinism

**Ambiguity.** Nornyx enforces temporal validity against an evaluation instant.
The runtime path previously hardcoded `RUNTIME_AS_OF = 2026-08-01T12:00:00Z`,
while `nornyx check` used the live clock. Two problems followed: an approval
issued after the pin would be judged against a moment *before* it was made, and
the seven-day approval expiry could never actually elapse.

**Resolution.** `RUNTIME_AS_OF` is replaced by `runtime_as_of()` in
`src/nornyx_forge/nornyx_runtime.py`:

- it defaults to the **real current time**, so approvals and decisions are judged
  against when they actually happen;
- a run that needs determinism pins the instant through
  `RuntimeContext.for_test(root, at=...)`, an explicit argument. The
  `FORGE_RUNTIME_AS_OF` environment variable this assumption originally
  described has been **removed**: a review proved it could revive an expired
  approval and backdate its ledger record. The same applies to
  `FORGE_RUNTIME_REVISION`, which could re-aim an approval onto a revision it
  was never issued for;
- a pinned value must be an explicit timezone-aware ISO-8601 timestamp. A naive
  or malformed value **raises** rather than falling back to the live clock, so a
  bad pin can never widen a validity window;
- every Nornyx step — `check`, `generate`, `lock`, `lock-check` — now receives
  the same explicit instant. Previously `check` used the live clock while the
  lock steps used the pin, so the two could disagree about validity.

No temporal rule was relaxed. The `P7D` agentic-network approval cap and the
non-human `denied_actor_types` remain exactly as the Nornyx module defines them,
and `tests/test_evaluation_time.py` asserts both are still present in the
installed package.

**Serves.** BRD-F-003 (reproducible demonstrations), BRD-F-005.

## A-011 Subject revision is read from the contract — SUPERSEDED by R1

**Ambiguity.** The governed revision was duplicated as a constant in code and as
`subject_revision` in the contract, so the two could silently drift — and did.

**Resolution at the time.** `runtime_revision()` read `subject_revision` from
`.nornyx/contracts/runtime_network.nyx`, making the contract the single source of
truth.

**Why it no longer holds.** The resolution was still commit identity, and a
contract cannot contain the hash of the commit that contains it — so
`declared == actual` was false at every commit and passed only in an uncommitted
working tree, which the same system refuses as dirty. Worse, letting the contract
declare the revision meant the artifact under governance named the identity it
would be judged against.

`runtime_revision()` is deleted. Identity is now content, not a commit:
`governed_revision_digest` anchors the revision and `governed_subject_digest`
covers the complete settled authority state, both computed by
`nornyx_forge.governed_subject` over a code-owned `SubjectScope`. Git survives
as provenance only, and reaches no decision.

Retained rather than removed so the reasoning stays traceable: this entry
records an assumption that was made, acted on, and then found wrong.

**Serves.** BRD-F-005.

## A-009 Docker is optional for the launch path

**Ambiguity.** BRD-005 requires `docker compose up --build` to start the
application "when Docker and demo dependencies are available".

**Resolution.** The launch falls back to the documented `uvicorn` command when
the Docker daemon is unreachable, matching `scripts/bootstrap.py`. The report
states which path was used.

**Serves.** BRD-004, BRD-005.

## A-010 Pre-existing lint defects were repaired

**Ambiguity.** `ruff` is a gate in `src/nornyx_forge/gates.py`, and the shipped
tree failed it with three findings (two unused imports, one unsorted import
block).

**Resolution.** Applied `ruff check --fix`. These are defect repairs inside the
declared goal scope; no gate, rule, or policy was weakened to accommodate them.

**Serves.** BRD-005.

## A-012 Trust stores are operator-supplied and live outside the governed tree

**Ambiguity.** The BRD requires independent review and human approval to be
verifiable, but does not say where the verifying keys come from. Any answer
inside the repository is circular: content that authorizes itself.

**Resolution.** Two separate stores, both holding public keys only, both located
by environment variable and read from outside the governed tree —
`FORGE_APPROVER_TRUST_STORE` for action approvals and
`FORGE_REVIEWER_TRUST_STORE` for inspection attestations. Editing the repository
therefore cannot add a trusted approver or reviewer.

They are deliberately not interchangeable. Each declares its own schema and is
refused if handed the other, because an approver signs "this effect may be
released" and a reviewer signs "I inspected this content"; one key satisfying
both would let whoever authorizes a payment also certify that the code releasing
it had been reviewed.

Absence is an ordinary state, distinct from malformation. With no store present
nothing authenticates, and the honest outcome is
`assurance_state: not_independently_inspected` — which is this repository's
current position. A malformed store raises rather than degrading into an empty
one, since "no trusted reviewers" and "the store could not be read" must not
produce the same silence.

**Not established.** How the keys inside a store were vetted. This repository
verifies signatures against whatever store the operator supplies; it makes no
claim about that store's provenance. Recorded in `docs/ASSURANCE_BOUNDARY.md`.

**Serves.** BRD-002, BRD-005.

## A-013 Signing capability is excluded from the runtime image

**Ambiguity.** The BRD requires attestations to be issuable, and also requires
the running application to be governed. Those pull in opposite directions if the
same artifact does both.

**Resolution.** Issuers live in `scripts/` (`issue_action_approval.py`,
`issue_inspection_attestation.py`); the Dockerfile copies `pyproject.toml`,
`README.md`, `src`, `.nornyx` and `BRD.md`, and never `scripts`. The image
therefore contains verification material and no signing capability at all.
Private keys are read from an operator-supplied path at signing time and are
never written into the repository. A test asserts the Dockerfile still omits
`scripts/` and that no signing primitive appears in the runtime module.

**Serves.** BRD-002, BRD-005.

## A-014 The approval ledger is provisioned, never self-created

**Ambiguity.** BRD-002 requires a human approval to release a consequential
effect at most once. It does not say what should happen when the state recording
that "at most once" is absent.

**Resolution.** Absence is a refusal, not an empty answer. The ledger is created
by an explicit operator command (`nornyx-forge provision-ledger`); the boundary
opens it and never creates it. A missing ledger denies consequential acts, a
corrupt one raises as unavailable, and re-provisioning leaves an existing
ledger untouched. A ledger whose consumption history has gone BACKWARDS -- a
restored backup -- is refused as `LEDGER_ROLLED_BACK`, because at-most-once
cannot be promised by state that a restore can undo.

Two clauses that used to stand here were measured false, and BOTH ARE NOW
CLOSED. They are kept as history because the paragraph was written in the
present tense and a review measured it still describing repaired defects as
live -- a disclosure that outlives its defect misleads in the opposite
direction to a claim that outruns its evidence, and neither is acceptable.

*Was:* an UNWRITABLE ledger did not raise as unavailable, because
`BEGIN IMMEDIATE` succeeds on a read-only SQLite database, so the pre-flight
passed and the refusal arrived at the INSERT carrying no code. **Closed:** the
pre-flight now performs a real INSERT with an unconditional ROLLBACK, and the
refusal carries `APPROVAL_LEDGER_UNWRITABLE`. Measured: construction raises,
coded.

*Was:* "the boundary opens it and never creates it" was true of intent and not
of effect, because `sqlite3.connect` creates an empty file. **Closed:**
`_connect` opens with `mode=rw` via a URI, in both places, so consuming against
a deleted ledger creates nothing. Measured: nothing was created.

Previously `CREATE TABLE IF NOT EXISTS` ran at every construction, so deleting
the file produced an empty ledger in which nothing had been spent — every grant
ever consumed became replayable. Deleting a file is not an authorization
decision.

**Operational consequence.** A fresh deployment must provision the ledger before
it can release any consequential effect. That is deliberate: the alternative is a
deployment that silently begins with no replay history and cannot tell the
difference between "nothing has happened yet" and "the record is gone".

**Serves.** BRD-002.

## A-015 The onboarding surface trusts its loopback, and says so

**Ambiguity.** The basic-user programme adds a local web surface whose requests
carry an actor the capsule judges by KIND. Nothing authenticates that the
person at the browser is the project's human.

**Resolution.** The surface binds `127.0.0.1` only (pinned by test against the
literal), the trust boundary is stated in the module's own docstring and in
this register, and no route claims authentication anywhere. Authenticating the
human is a separately-scoped future slice; until it lands, the boundary is the
same one the CLI beside it has always had — the machine's logged-in user.

**Serves.** The founder's basic-user strategy, correction C2.

## A-016 A fresh user project is greenfield, never certified

**Ambiguity.** The build trigger must pick a repo mode for a directory that
holds only a capsule and a derived BRD.

**Resolution.** `greenfield`, hardcoded at the trigger. A fresh project is not
a certified foundation, and selecting the honest mode is what the mode
vocabulary exists for; a user who wants a certified base uses the developer
CLI, where the choice is explicit.

**Serves.** BRD-F-007's mode vocabulary, applied truthfully.

## A-017 The Windows bundle assumes a builder-supplied interpreter

**Ambiguity.** A user machine has no Python; the bundle must carry one, but
downloading an interpreter during a governed build would put an unverified
artifact inside the deliverable.

**Resolution.** The builder embeds only an interpreter zip the OPERATOR
supplies together with its expected sha256; a mismatch refuses the build, and
the builder never downloads. Developer-mode bundles (no interpreter) exist so
the layout is provable without one. The embedded-interpreter path is tested
against synthetic zips; a real embed run is an operator act.

**Serves.** the FORGE_ROOT doctrine extended to packaging: nothing ambient,
nothing unverified, selects what ships.

## A-018 The live model-driven build is the founder's acceptance act

**Ambiguity.** The end-to-end journey ends in a build that invokes a real
provider CLI, spending the founder's model quota; an autonomous run could
execute it uninvited.

**Resolution.** Everything up to the build gate was observed live on the
served surface (recorded 2026-08-30: create → propose → confirm → reopen →
provider → rendered governance → minimized sharing preview → derived BRD →
model-actor refusal). The build itself was deliberately not run by the
autonomous session: spending the founder's provider quota is the founder's
decision, and the acceptance run stays theirs. No claim of a live model-driven
build exists anywhere in the programme's records.

**Serves.** the claim discipline itself — experimentally observed stays
distinct from not yet proven.

## A-019 A greenfield project is the subject, never its verifier

**Ambiguity.** A generated project needs tests, architecture, and security
acceptance, but it does not contain Forge's repository verification scripts and
the provider can modify every file in its workspace.

**Resolution.** `repo_mode="greenfield"` selects a deterministic profile in
trusted `DevelopmentFlow` code. Forge reads and digests the installed standalone
verifier, reads a private snapshot once through a digest-checking in-memory
bootstrap, executes those same bytes through the active absolute Python
environment entrypoint under isolated Python, and constructs an environment with
no project-controlled PATH or Python import variables. Static checks stream
bounded project bytes; project tests execute only from a private subject copy in
a separate resource-limited process with project `conftest.py` hooks and discovery
configuration disabled. The runner and executor are each digest-checked and
executed from the same in-memory bytes. Executor completion state is not exposed
through `__main__`; static inspection refuses hard exits, reflection, and pytest
lifecycle control, including constant-folded or opaque `getattr` acquisition of
interpreter capabilities. Both `sys.argv` and `sys.orig_argv` are scrubbed before
subject collection. The audit hook confines writes and process authority,
validates both endpoints of a hard link and the destination of a symbolic link,
and permits the external completion write only from the executor thread that
owns it. Audit, trace, profile, asynchronous-generator, and interpreter-monitoring
callback registration are refused statically; the mutable `sys` registration
entrypoints are also replaced before project imports begin.
A trusted supervisor outside the pytest interpreter requires a complete
executed-test record, the expected executor digest and a normal-completion
sentinel, bounds retained output, and performs a final subject census. Scripted
model checks have a read-only tool surface and are
followed by a final trusted rerun. Profile and verifier identity,
origin, version/revision and digests, plus the final subject digest, travel with
every gate and the acceptance event. The provenance is structural/tamper-evident;
it is not a signature, proof of installer identity, or a sandbox against every
possible host effect in arbitrary test code. On POSIX the environment entrypoint
may be a venv symlink and is therefore preserved for execution; its resolved base
target is separately checked against the project boundary and recorded. Resolving
the entrypoint itself would silently leave the environment that provides pytest.
Linux distributions whose absolute Python executable depends on a colocated
shared library (including GitHub Actions setup-python) need one additional host
fact: Forge derives `<sys.base_prefix>/lib`, verifies that it is an external
directory, passes it explicitly through the trusted verifier command, and uses
it as the child's sole `LD_LIBRARY_PATH`. The inherited value is ignored because
it is provider-influenceable. The POSIX process budget is 64 tasks above the
real user id's ambient count, measured from `/proc` immediately before the
limit is applied. `RLIMIT_NPROC` is charged per user id host-wide, not per
process tree: an absolute ceiling of 64 sat below what the GitHub runner
service user already held, so the verifier's own runner failed with `EAGAIN`
on every interpreter of the matrix while the same suite passed on a quiet
workstation. A host where that count cannot be measured fails closed.

The budget SHIFTS the ceiling; it does not widen it. The soft and hard limits
are both set to the budgeted value, so the subject cannot raise it back, and
the recorded policy is named `additional_processes` with a
`process_budget` of `ambient-real-uid-tasks-plus-fixed-increment` rather than
`active_processes`, because a key naming a total while the code enforces an
increment is the substitution this repository refuses. The Windows Job Object
keeps `active_processes`, which really is a total for that job.

Two limits of the mechanism are disclosed rather than papered over. First, the
count is read immediately before the limit is applied and is not atomic with
it: tasks belonging to the same user id may start or exit in between. A task
that EXITS in the gap leaves the ceiling correspondingly further above the
live count, so the subject may create a few more than the increment; a task
that STARTS in the gap consumes budget and can only make the verifier refuse
its own work, which is fail-closed. The gap cannot lift the ceiling, because
the ceiling is a number fixed at the moment of application. Second, the
baseline is host state: anything already running under that user id raises it,
so a provider that leaves background processes behind raises the absolute
number of tasks the user id may hold. Neither makes the subject's allowance
unbounded, which is the property being claimed.

**Serves.** BRD-004's architecture/security boundaries and BRD-005 acceptance
criteria for generated application subjects.

## A-020 Windows distribution is EXE-first

**Decision.** The Windows distribution target is `ForgeSetup.exe`, EXE-first.
MSI is not the current target. A folder plus `Forge.cmd` remains the interim v1
delivery.

**Scope.** This records the already-decided distribution direction only. It does
not implement packaging, signing, release CI, or the installer.

**Serves.** programme traceability for the post-PR-18 Windows distribution work.

## A-021 A governed tree answers for itself, or not at all

**Decision.** Every git question the governance evidence tool asks is about
the tree at its own root. A tree that is not the root of the repository git
resolves for it is refused, not measured against that repository. A tree git
cannot place in any repository is refused by the gates that need git and
recorded as `git:unbound` for provenance, rather than left to whatever the
reader's git does outside a repository. (This decision first said that git's
no-index fallback had read such a tree as clean. That was measured on git
2.55.0.windows.5, where `diff --no-index` limits by pathspec since git 2.51
and a thirteen-path `git diff` outside a repository exits 0 printing
nothing; an independent review measured git 2.43.0, where the same command
is a usage error and the tool at f114074 refused. The established defect is
the enclosing foreign repository; the no-repository outcome was
version-dependent, and the refusal makes it irrelevant.) The environment
variables that re-aim git (`GIT_DIR`, `GIT_WORK_TREE` and their kin) are
dropped from every git call. The anchored-measurement harness therefore
commits each archive extraction to a repository of its own before re-running
`--verify` in it.

Which repository answers is not the same question as which configuration it
answers under. Measured at b999537 in a fresh clone holding a governed,
untracked `src/untracked.py`: under nine reader-controlled configuration
routes (`GIT_CONFIG_COUNT`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`,
`GIT_CONFIG_SYSTEM`, an `XDG_CONFIG_HOME` config and its ignore file, a
`HOME` gitconfig and its ignore file, an include) the root resolved to the
governed tree every time and the untracked file was reported under none of
them, because each supplied a `core.excludesFile` naming it. A reader
attributes file naming a clean filter hid a modified governed file the same
way. Every git question the tool asks therefore runs through one runner
under a policy-neutral environment: the `GIT_CONFIG_*` family dropped by
prefix, `GIT_ATTR_SOURCE` dropped with the steering variables (it reads
attributes from a commit instead of the working tree, and was measured to
hide a change when an older commit carried `*.py ident`), the system
gitconfig switched off, the global gitconfig pointed at the empty device,
the system attributes file switched off, git's messages pinned untranslated,
and `core.excludesFile`, `core.attributesFile`, `core.fsmonitor` and
`core.longpaths` pinned on the command line. `HOME` is not redirected: with
the global file named explicitly git derives no configuration file from it,
and the two default files it would still derive, the ignore and attributes
files, are the ones pinned. The repository's own `.git/config`,
`.gitattributes` and `.gitignore` still apply, because they are governed
content this repository relies on deliberately -- `.gitattributes` normalises
line endings, so a CRLF-only edit to a governed file is reported clean by
git while it does move the byte digest, which is a pre-existing property of
the repository's policy and not of the reader's machine. This is not
hostile-host isolation: the `git` binary on `PATH`, the reader's ability to
write into the governed tree or its `.git`, and reader control of the
process environment beyond git's configuration are outside what it
establishes.

Three limits of the neutral environment are disclosed rather than papered
over. `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` exist from git 2.32 (its
release notes; no older git was available to measure): on an older git the
reader's global file is read after all, and only the pinned keys are certain
to outrank it. A checkout owned by another user can no longer be verified at
all, because the reader's `safe.directory` allowance lives in the
configuration this severs; git refuses, and the tool now reports git's
refusal in git's words rather than an absent repository (measured under
review with `GIT_TEST_ASSUME_DIFFERENT_OWNER=1`, which made the tool say git
could not name the repository and provenance say `git:unbound` for a bound
tree). And `core.longpaths` is pinned on because severing the global file
otherwise made a governed path beyond MAX_PATH on Windows an empty, exit-0
answer with a warning on stderr; a warning beside an empty exit-0 answer from
any other cause, an unreadable directory for instance, is still not read as a
refusal.

**Scope.** The extraction's HEAD is a fixture commit, not the anchored commit.
That is provenance: the archive is what anchors the measurement, and at this
baseline `--verify` asks git only whether the working tree agrees with what
git holds, never which commit that is. Should `--verify` ever compare HEAD
against the revision the evidence records, the fixture commit fails that
comparison loudly rather than letting a reader's HEAD stand in for the anchor.
For a checkout whose root is its own repository, run without steering
variables, `--verify` reports what it reported before; a checkout run under
`GIT_DIR` or its kin now answers from its own repository instead of the one
those variables name, and that difference is the repair.

**Serves.** the anchored-measurement convention in
`tests/test_recorded_measurements.py`, the absence-is-not-success control in
`tests/test_absence_is_not_success.py`, and the success criterion in
`CLAUDE.md` that evidence is named for what it is.

## A-022 The basic-user journey projects the Experience Contract; it is not a second workflow

**Ambiguity.** The onboarding surface performed every step of the basic
journey -- project creation, proposal confirmation, provider confirmation,
BRD derivation, a governed build and its result -- without the Experience
Contract, so a project's lifecycle stayed `absent` however far the user got
(measured at 9a16851 through the real application, success and failure
paths, and across a restart). Wiring the surface to the contract raises
four questions the contract does not answer by itself: what the human
scope confirmation requires, which actor performs the evidence-driven
transitions, what READY may claim, and what a capsule from before the
wiring means.

**Resolution.** Every lifecycle advancement the surface records comes from
the contract's own `start_experience`, `advance`, `fail` and `retry`, under
the actor and evidence rules those functions already enforce; the surface
maps a closed set of semantic actions onto fixed transitions and never
accepts a stage from a client. The scope confirmation (lifecycle CONFIRM)
requires a confirmed intent, a confirmed provider and a derived BRD --
exactly the inputs the build consumes and the things the build and BRD
routes already refuse by name -- and no more: the contract's optional
stages are not entered, because nothing on this surface implements them.
BUILD is entered under the person who pressed the button; TEST and GOVERN
are recorded by a system actor from `flow_evidence()` over the completed
flow result, and the automatic path stops at GOVERN. READY is a human act
presenting the gate-results and governance-validation references that
GOVERN recorded, read back from the persisted lifecycle. On the shipped
greenfield acceptance profile no gate runs the Nornyx CLI, so the
translator yields no governance validation and READY is unreachable for a
real basic-user build; the journey ends at GOVERN and the page says why.
That is the honest outcome of a profile that never asks the governance
question, and it is left as it is rather than improved. A capsule with no
recorded lifecycle is reported absent, offers only a human "start
tracking" that begins at DISCOVER, and has no stage inferred from its
files. Four limits are disclosed. The contract does not freeze capsule
content after CONFIRM, so a proposal confirmed and a BRD re-derived after
the scope confirmation are built without the lifecycle re-confirming them
(every such input is still human-confirmed capsule content); the contract
declares a `brd_requirements` evidence kind that no stage requires, and
whether CONFIRM should consume one -- and what its reference would denote
-- is a domain decision this slice does not take. A server that dies
mid-build leaves the lifecycle at BUILD/active, where the next session
reports that no build is running and re-runs it from BUILD without a
second transition and without recording a failure nothing observed; the
person who starts that re-run is therefore not recorded, because the
contract records transitions, not runs, and BUILD's `entered` stays the
first presser. A completed run is recorded whole or not at all: the
surface asks the contract for every evidence step in memory first and
persists TEST then GOVERN only when both are licensed, and otherwise
records one failure at BUILD in the contract's words for the refused step
-- because the contract declares no edge back from TEST, so a failure
persisted there could never be re-run (measured under review with a flow
that reported itself accepted while a gate failed, a shape the real
`DevelopmentFlow` cannot produce because its `accepted` is the conjunction
of its gates).

The store is inside the provider's workspace, and that was an authority
hole (P17-B1, adjudicated a merge blocker). The capsule store lives under
the project directory; `/api/build` hands that directory to the selected
provider as its writable workspace -- Claude with Edit, Write and Bash,
Codex under a workspace-write sandbox -- and both digest chains are one
link deep, so a worker that has read the domain modules can rewrite a
state and recompute the final link, and can commit the result inside the
store's own git repository with the store's identity. Measured at 47bd370
through the production build seam and through the real `DevelopmentFlow`
worker seam: the worker's forged READY was rendered by `/api/state` while
the build ran, persisted, and read back after a restart; a committed
forgery left a clean tree and changed nothing; forged capsule authority
(intent, provider) was rendered the same way. An earlier version of this
entry said detection of such an edit "belongs to the store's git
history". That was insufficient: mutable git history inside the
provider's workspace is not an anchor when the provider can write the
repository, and the claim is withdrawn.

What is established now. The store keeps a seal -- the revision and the
exact bytes of the two authority files -- in a directory OUTSIDE every
project (`~/.nornyx/forge/seals`, beside the reviewer trust store), written
by Forge after each of its own commits and by nothing else. Every load
checks the store against the seal first: the revision, the working tree
(a dirty tree, an extra file) and each file's bytes, so a dirty forgery
and a committed forgery are the same finding, and a clean tree at a new
commit is not trusted authority. While a build runs, every read is
answered from the authority Forge sealed when the build began and every
write is refused, so a forgery on disk is never rendered and no action
can consume it. When the flow returns, the store is checked against that
seal before the result is translated; a store that moved is reset to the
sealed authority, the run is recorded as a failure that names what moved,
and the provider's result is not consulted. A forgery left for a later
process is the TAMPERED finding on every route until a person restores
the sealed authority through one explicit action, which records the
restoration on the lifecycle. Confirmed capsule authority is covered by
the same seal as the lifecycle. The legitimate journey is unchanged.

What the seal does not establish, stated rather than implied away. It is
Forge-owned persistence, not a signature: it is out of a workspace-write
sandbox's reach, so a Codex worker cannot touch it, and it is within the
same operating-system user's reach, so a Claude worker with Bash could.
That is the local trust boundary of A-015 -- the machine's logged-in
user -- and the seal narrows what a provider can do inside it without
claiming to hold against that user. A store with neither a seal marker nor
a seal -- one from before sealing existed -- is reported `unsealed` and is
sealed by Forge's next save; a store that carries the marker and has lost
its seal is the TAMPERED finding with nothing to restore from; a seal that
is unreadable, of another schema, or written for another store anchors
nothing and is that finding too.

Declared is not eligible (independent review of 89910b8, findings R1 to
R3). The seal narrowed what a provider could do to the store, but the
default Claude provider and the seal occupy the same operating-system trust
domain: Claude runs on this path with general shell capability and no
filesystem confinement as the user whose files hold the anchor, so a
validation mechanism cannot establish independence from an actor that can
replace the validation state. The governed basic-user path therefore
executes an engineering provider only when Forge itself can establish that
the provider is confined to the project subject. The Provider Contract
carries that as data: a closed confinement vocabulary (`none`, `declared`,
`established`) and one row per declared provider, and
`governed_build_eligibility` decides from that table and nothing else --
not the request, not the capsule, not the project directory, not the
provider's own account. Claude's confinement is `none`; Codex's is
`declared`, because the workspace-write sandbox is a flag the adapter
passes to a CLI and Forge has not independently established it; nothing is
`established`. Both providers are therefore declared, registered and
selectable, and neither is eligible for the governed build: `/api/build`
refuses before the lifecycle moves and before any flow is constructed, in
the contract's words, tries no other provider, changes no execution mode,
and the page lists the same reason as the blocker. A basic-user journey
whose creation, proposals, human confirmations, BRD derivation and
lifecycle orchestration all work while a real external-provider build is
refused is the intended result of this baseline; the authority invariant
is not weakened to keep a build executable. The deterministic flow the
tests install at the injectable seam carries its own eligibility because it
executes no provider; the served surface passes nothing and uses the
contract's decision, which is pinned. Promotion of any provider to
`established` is future work that requires Forge to verify a confinement,
not to be told about one. The developer CLI's `build --project-dir` is a
terminal path outside the governed basic-user surface: it constructs the
flow over the same store-bearing directory and does not consult the
eligibility decision, which is the "selectable elsewhere" the decision
leaves open; a developer who runs it accepts R1's exposure at their own
console, and it is named here rather than implied away.

Two anchor states that were one are now kept apart. A store Forge has ever
sealed carries a committed marker naming its seal, so a protected store
whose seal is missing is the TAMPERED finding with nothing to restore from
-- no authority is inferred from its files, and recovery is outside this
surface -- while a store with neither marker nor seal is the legacy case
from before sealing existed, reported `unsealed` and sealed by Forge's
next save. The marker's trustworthiness depends on the eligibility gate,
and the dependency runs one way. Measured: removing the marker alone,
uncommitted or committed, is still caught, because the seal outside the
project names it; a protected store reads as legacy only when the marker
AND the seal are both gone, and the seal is outside any workspace. So the
precondition for that fall-open is the same-operating-system-user write the
whole design concedes -- exactly what an unconfined provider holds -- and
the marker is trustworthy at this baseline because no provider executes on
the governed path at all. A later slice
that makes any provider eligible must revisit this before it does so, or it
silently reopens R2. Nor is the marker a freshness mechanism: a store
restored wholesale to an earlier state carries its marker back with it. The
seal establishes what Forge last wrote, not that it is the latest thing
Forge wrote: an actor who can replace the store, its marker and its seal
together with an earlier consistent set is not detected by any of them, so
the surface reports the seal's currency as `not_independently_anchored`
and monotonic external anchoring is deferred rather than claimed. Not
claimed anywhere: sandboxing of any provider, an authenticated human
identity, cryptographic provenance, A-018, or PR-18.

The injectable seam is a composition-time act and nothing else. `create_app`
takes `eligibility` beside `flow_factory`; a test that installs a
deterministic flow -- one that answers in the flow's shape and executes no
engineering agent -- passes an eligibility that says so, because the gate
exists to keep an unconfined provider off the authority store and that flow
has none. No request, capsule content, project file or provider output
reaches either parameter; the served composition passes neither, so the
shipped surface decides by the contract alone, and that is pinned by test.
A flow injected at the seam without its own eligibility is still gated by
the contract's decision. A process the provider
leaves running after the flow returns is caught at the next load, not
while it writes. The seal is written after the store's commit, so a process
that dies between the two leaves Forge's own newest commit reading as a
breach at the next load; that fails closed, and a restoration then returns
the store to the previous sealed revision, losing that one transition
rather than trusting anything unsealed. A breach found when the sealed
lifecycle is already failed is restored and reported for the session but
cannot be recorded on the lifecycle, which admits one failure per stage.
The developer CLI's `build --project-dir` reads the capsule under the same
seal. The domain modules' own docstrings still say a full-chain rebuild is
"git history's to catch"; that sentence is true of the chain and was never
enough for a repository the provider can write, which is what the seal is
for. Whether the seal should be strengthened beyond this boundary is a
decision for a later slice, not this one.

The capsule and the lifecycle are two files in one git repository, and
every save stages the whole tree. Measured under review with the two
written under separate serialisation: a lifecycle save paused after its
file landed, a concurrent proposal's `git add -A` swept `experience.json`
into the proposal's own commit, and the lifecycle save then found nothing
left to commit. One in-process store lock now serialises every read and
write of the store, the build thread's included; it is held around store
access only, never around the build.

**Scope.** This wires the existing contract; it changes no stage, edge,
actor or evidence rule. READY means what the contract establishes and
nothing beyond it: not deployment, not production approval, not an
authenticated independent inspection, not a human approval record. The
trust boundary of A-015 is unchanged and A-018 has not occurred.

**Serves.** the founder's basic-user strategy, the progress-authority rule
of the Experience Contract, and the claim discipline in `CLAUDE.md`.

## A-023 The Windows launcher manages execution and creates no authority

**Ambiguity.** The interim Windows delivery is a folder and `Forge.cmd`
(A-020). At b1780ee that launcher ran `onboard` through `os.execvp`, which
on Windows spawns the server and returns at once (measured: the launcher
exited in 5.5 s while its server survived detached); it hardcoded
`python\python.exe`, so a developer bundle's launcher could not start at all
("the system cannot find the path specified"); it opened no browser; a
second launch on the same port died on WinError 10048 with nothing a person
could see; and no record of a running instance existed anywhere. Turning the
folder into a runtime a basic user can double-click raises questions the
programme had deferred -- which Forge runs, on which interpreter, over which
project, once or twice, on which port, when the browser may open, how a
failure is shown, and how any of that state relates to governance.

**Resolution.** The launcher may manage execution mechanics; it may not
create, infer, weaken or replace governance authority. Concretely:

*Which Forge.* `Forge.cmd` passes its own folder as the bundle root and the
runtime refuses unless `resolve_packaged_root()` -- derived from where the
running package's file actually is -- names the same folder. The launch
directory, PATH, PYTHONPATH, an environment variable and another installed
`nornyx_forge` therefore select nothing: a shadowed import is a refusal,
not a substitution. The embedded interpreter's path file lists the bundle's
`src` before its `pylib` and admits no site directory at all; the developer
bundle's bootstrap places the same two directories first under isolated
mode.

*Which interpreter.* A bundle is one of two kinds, recorded in
`forge-bundle.json`. A self-contained bundle carries the interpreter the
operator supplied with its expected SHA-256 (A-017, unchanged: the builder
verifies the digest before extracting, refuses a mismatch, refuses an
archive without both `python.exe` and `pythonw.exe`, and never downloads),
and its launcher runs `python\pythonw.exe` and nothing else -- no fallback
to a Python installed on the computer, and the runtime itself refuses a
self-contained bundle started on a foreign interpreter. A developer bundle
carries no interpreter, says so in its launcher, and runs on an installed
Python through the Windows `py` launcher. The two kinds are never mistaken
for each other; a forged marker can only make a launch refuse or run a
developer bundle on the interpreter it was given.

*Which project.* The launcher passes `%USERPROFILE%\ForgeProject`
explicitly, the runtime refuses a relative path, and the working directory
is never consulted. That location is kept rather than replaced: it is user
data (a BRD, a capsule, a built application), which belongs under the
person's profile and not under application data. The profile is the one
ambient input that selects a LOCATION, and it is the same input the seal
directory (`~/.nornyx/forge/seals`) and the runtime directory
(`~/.nornyx/forge/runtime`) already derive from: it selects the person's own
places, never which Forge runs and never another person's project without
the operating system having changed the user. PATH is consulted too, and
only to refuse: `shutil.which("git")` decides whether a machine without
Git for Windows is refused by name, and the developer launcher finds the
installed Python through the `py` launcher (`where pyw`, then `pyw -3`,
whose own selection reads `PY_PYTHON` and `py.ini`) -- a choice of
interpreter for the developer arrangement only, never of Forge code, which
the bootstrap places first under isolated mode. Both launchers set
`NoDefaultCurrentDirectoryInExePath` before running anything, because
`cmd.exe` otherwise resolves a command from the launch directory before
PATH (measured under review: a `pyw.cmd` planted in the working directory
ran in place of the Python launcher). Two spellings of the same NTFS
directory are one runtime key (case-folded) and, once the store exists,
one seal (resolved). The runtime directory may not lie inside the project
directory or the seal directory; a launch that asks for that is refused.

*Once.* One runtime per project, held by an exclusive byte-range lock on a
file under the runtime directory for the life of the process. The operating
system releases it however the process ends, so it is the liveness oracle;
identity is an instance token the process generates, records, and serves on
`/api/runtime`. A recorded pid is informational and never consulted for
either. A second double-click on the same Forge over the same project finds
the lock held, reads the record, confirms the token on the recorded port,
and opens the running page; the same project served by a Forge in another
folder is a visible refusal, never a silent substitution; a holder that
does not answer within the readiness timeout is a visible failure; a record
whose lock nobody holds identifies nothing and is overwritten. Nothing is
ever terminated: an unrelated occupant of the preferred port costs a
different port, an answer on the recorded port without this runtime's
schema and token is not this runtime, and the occupant is left alone.

*Which port.* The socket is bound by the runtime before the server exists
-- the preferred port when free, otherwise one the operating system hands
out -- and handed to the server, so there is no window between "checked"
and "bound". The record and `/api/runtime` say which port was taken; the
browser is sent to that port and no other.

*When the browser opens.* Only after a thread inside the server process has
round-tripped a request through the bound socket and read its own instance
token back, within a bounded readiness timeout. A timeout records a failure,
tells the person, and stops the server. A browser that cannot be opened
leaves the runtime ready and tells the person the address; it manufactures
no failure and no success. Opening the browser is the one process the
runtime causes to start, and it is started by the declared launcher adapter
against a loopback address only.

*How failure is shown.* Under `pythonw` there is no console, so a refusal
-- an incomplete bundle, a foreign interpreter, git absent from PATH, a
relative project, a corrupted runtime record beside a held lock, a
readiness timeout, an assembly failure -- is a Windows message box, and
every refusal is appended to a launch-failure trail under the runtime
directory. A folder whose code does not import at all (a partial copy) is
caught one layer earlier by a standard-library-only entry that says so. A
console launch keeps its console. No telemetry, no reporting service, no
remote control plane exists.

*Operational state is not governance state.* The record (schema
`nornyx.forge.windows_runtime.v1`: instance token, port, pid, interpreter,
bundle root and mode, project, status, timestamps, browser outcome, log
path), the lock and the log live under the runtime directory, outside every
project and outside the seal directory beside it. They answer one question
-- is the local Windows runtime running? -- and the onboarding surface never
reads them; a forged record or marker changes nothing `/api/state` reports,
which is pinned. `/api/runtime` and `/api/runtime/stop` are operational
routes on the same loopback, single-person, unauthenticated surface as
everything else (A-015); stopping is a person's act, validated as the
surface validates every actor, and a model actor is refused. The runtime's
composition answers only to a loopback Host header, because a page that
rebinds a name to 127.0.0.1 would otherwise reach the surface (measured
under review); the developer's console `onboard` path composes the same
surface without that check and is unchanged by this slice. Nothing here
advances an Experience stage, creates or implies an
approval, makes a provider eligible, validates a contract, or stands in for
an inspection. The PR-17 result is unchanged and was re-measured through a
real Windows runtime: both declared providers remain refused before BUILD,
the lifecycle stays at CONFIRM, and no fallback is tried. Process isolation
added here for launch mechanics is not evidence of provider confinement,
which is a separate property nobody has established.

**What remains, stated rather than implied away.** Double-clicking
`Forge.cmd` still opens a console window for the instant `cmd.exe` takes to
start `pythonw.exe` detached; the interim delivery is not "no console",
it is "no console to keep or read". The bundle ships no git and the capsule
store needs one, so a machine without Git for Windows on PATH is refused by
name at launch rather than failing inside the page; bundling git belongs to
the distribution tranche. The developer launcher's bootstrap cannot survive
a bundle path containing a single quote. `pythonw.exe` on the profile's
default browser association is the mechanism for opening the page; an
account with no browser association sees the address in a message box. The
real embedded-interpreter run remains the operator's act, because no
embeddable archive is supplied by the repository and the builder never
fetches one; `build_windows_bundle.py --smoke` measures that run and
records it when the operator performs it. Windows-hosted automated evidence
in this repository runs the runtime as a real child process from a real
bundle folder on the runner's own CPython -- the developer arrangement --
and is labelled as exactly that.

**Scope.** Not an installer, not signing, not release publication, not
auto-update, not a Windows service, not provider confinement or admission,
not A-018, not R3 monotonic anchoring, not P17-03.

**Serves.** the founder's basic-user strategy's Windows-first delivery, the
FORGE_ROOT doctrine extended to the launcher, and the claim discipline in
`CLAUDE.md`.
