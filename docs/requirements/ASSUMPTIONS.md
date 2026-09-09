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
Since the post-PR-18 hardening the served composition also refuses any Host
header other than `127.0.0.1` or `localhost`, installed once in
`onboarding_serve.assemble` and inherited by every launch path. That is a
Host-header check against a page that rebinds a name to loopback; it is not
authentication of the person, and this boundary is unchanged by it.

**Partly superseded by A-027.** For authority-moving routes, "trusts its
loopback" no longer holds: since Tranche B those routes admit only a request
carrying this run's bearer, so a local process that reaches loopback is refused.
The boundary A-015 describes -- the machine's logged-in user, unauthenticated at
the browser -- is otherwise unchanged, and A-027 states exactly what the bearer
does and does not defend against.

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
silently reopens R2 -- and that is no longer a request that a human
remember. The basis is `capsule_store.MARKER_TRUST_BASIS`
(`no_provider_executes_on_the_governed_path`), and
`test_the_marker_trust_basis_cannot_survive_an_eligible_provider` is a
BICONDITIONAL over the eligibility decision: if any provider is eligible that
constant may no longer read that literal, and while none is it must still
read exactly that literal.

Both directions, because round 2 measured what one direction alone was worth.
As a bare implication guarded by `if eligible:` the interlock could be SPENT
IN ADVANCE -- executed, with nothing eligible and the constant drifted to
`tidied_up_by_a_refactor`, the suite exited 0, and it exited 0 again with a
provider then made eligible, because the implication was already satisfied.
Any earlier commit that renamed or tidied the constant would have retired the
control silently, and this paragraph would have gone quietly false exactly as
before. A second, different defect in the same test: with
`PROVIDER_CONFINEMENT` emptied, `eligible` is `[]` whatever the eligibility
decision says, the guarded branch never runs, and the node passed BY VACUITY.
The rows of that table are now pinned by name, and both branches assert. A
third: the node's only other assertion scanned the module docstring for the
NAME `MARKER_TRUST_BASIS`, which was present while the VALUE was not, so
prose and constant could still drift; it now pins the value, and the
docstring carries the literal.

What that control does and does not do, stated at its true size because the
surrounding prose twice claimed more. It does not "turn red the day a real
confinement measurement licenses a provider" on its own: it turns red on a
promotion made while this constant still reads that literal, and the second
assertion is what stops the literal being retired in advance to make that
cheap. It licenses nothing -- no code path consults `MARKER_TRUST_BASIS` to
permit anything; its only readers are its definition, `__all__` and that
test. And it RECORDS a human decision as a code change rather than
establishing anything: editing the constant says a person considered the
marker, not that the marker holds.

Forge's own recovery path was the cheapest way to remove one of the two.
`_rebuild` -- the fallback restoration, reachable from the shipped surface
whenever a worker destroyed or replaced the store's repository -- wiped
everything but the store marker and the two authority files BEFORE it
rewrote them, so `.forge-seal` was deleted while the worker's forged bytes
were still on disk. Measured on this baseline with a `SystemExit` at the
`git init` call: the directory held `['.forge-capsule', 'capsule.json',
'experience.json']`, `protected()` was False, the forged `stage == "READY"`
was still there, and a load whose seal file had also gone returned it as a
legacy store. Not a window but a permanent state, and it reduced the
attacker's remaining cost to the single same-user deletion the paragraph
above already concedes -- with Forge's recovery having paid the other half.
The rebuild now writes the seal marker FIRST and unconditionally, then the
sealed bytes, then the store marker, and wipes afterwards, so no instant of
it holds forged authority under an absent marker. The marker write is
unconditional because `protected()` only asks whether a file of that name
exists: a marker naming another store's seal would otherwise survive the
recovery that exists to correct it.

THE MARKER GOES FIRST, and the ordering that first closed the permanent
fall-open did not put it there -- it wrote the sealed bytes and only then the
marker, which is a window two statements wide rather than a permanent state,
but the same fall-open. `snapshot.files` is `capsule.json` then
`experience.json`, so a death BETWEEN THE TWO left the worker's forged
`experience.json` -- an authority file by the module's own definition -- on
disk with the marker still gone. Measured under review at that head:
`protected()` False and a load whose seal file had also gone returning the
forged `stage == "READY"` again. Two independent reviewers found it; the
design brief that specified the order was where it came from, not the build.
The marker names the STORE and not the bytes, so writing it before them costs
nothing. Three of the four crash rows in
`test_a_crash_inside_the_rebuild_never_leaves_the_store_readable_as_legacy`
vary the marker state at ONE instant (`git init`), which is after both halves
of the first repair and therefore could not see this; the fourth varies the
INSTANT instead, and reverting the hoist alone turns exactly that row red.
What that row asserts is the property and not the bytes: mid-rebuild the
second authority file is not yet the sealed content, and what must hold is
that whatever is on disk sits under a marker naming this store's seal, so a
sealless load refuses instead of reading it as legacy. Nor is the marker a
freshness mechanism: a store
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
rather than trusting anything unsealed. Measured through both authority
routes and through `/api/state`, and now pinned by
`test_a_commit_that_landed_before_its_seal_fails_closed` -- it had no
coverage at all before, only the legacy never-sealed case did. What that
measurement also found is that the refusal MISDESCRIBED it. The seal
compares a revision, a working tree and file bytes; the refusal said the
store "was written outside this adapter" and the human restore route wrote
"modified outside Forge" into permanent lifecycle history. Both are claims
about an ACTOR, and this specimen is a Forge crash with no external actor
anywhere in it. Both now state what was measured and name the identity
SUPPLIED with the request that asked for the restoration.

SUPPLIED, NOT ESTABLISHED, and round 2 is why the word changed. This slice
first wrote that the record names "the one actor this route does establish:
the human who restored". It establishes nothing of the kind: `actor.ident` is
taken verbatim from the request body and validated only for shape by
`_IDENT`, on a surface whose own trust boundary says in as many words that it
does not authenticate humans and whose page supplies the value from a
free-text field. Driven: a POST naming `ceo@nornyx.example` returns 200 and
that string goes into permanent lifecycle history. So a slice whose thesis
was that it says only what it measured removed two unmeasured actor claims
and put a third in their place. The record now says who ASKED, as the request
stated it. Whoever moved the store is still not known, and git metadata
cannot say -- a writer inside the store commits with the store's own
identity, which the suite's own attacker uses -- so no trust is derived from
author, committer or parentage; they may describe and may never license a
load. Around a BUILD the record does go further and attributes the movement
to the provider; that attribution has a basis this route lacks (the directory
was handed to the provider for exactly that interval) and it is still an
attribution rather than a measurement, recorded below as such. The verdict is unchanged: untrusted, restorable, and
the cost of failing closed is still the transition, the stage's
one-failure-per-stage allowance, and a permanent history entry -- now one
that blames nobody. The revision that entry reports is the one the store
stands at when the restoration returns, not the one it was reset to;
recording the failure is itself a commit, and the payload was measured
naming a revision the store had already moved past. A breach found when the sealed
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

WHAT THE SEAL RE-PROOF DID NOT MEASURE, carried forward rather than closed.
Every "death" reproduced above was a Python exception, not a SIGKILL or a
power loss: whether `os.replace(tmp, path)` in `seal()` can leave a torn or
absent seal on NTFS under a hard kill is unmeasured, and if it can, the
precondition for the rebuild fall-open gets cheaper rather than harder. All
of it was measured on Windows 11 only -- `_remove_tree`'s read-only retry and
`git clean -fdxq` on POSIX are untested here. `store_lock` serialises
in-process readers only, so whether two Forge processes can hold one store
concurrently, and therefore whether the rebuild's remaining instants are
reachable WITHOUT a crash, is unmeasured. `save` does not call
`assert_sealed()`; only the two loads and the restore route do, and whether
any reachable sequence reaches `save` or `protect` on an unverified store --
the developer CLI's `build --project-dir` in particular -- was not traced.
`git reset --hard` returning non-zero falls through to `_rebuild` silently,
and whether a file lock from an antivirus or an indexer can produce a PARTIAL
reset that then passes `seal_problems` was not tested. One claim was left
standing deliberately: the build thread still records that "the provider
modified the project's authority store during the build". That attribution
has a basis the crash case lacks -- the directory was handed to a provider
for exactly that interval -- but it is still an attribution rather than a
measurement, and it is named here rather than repaired outside this slice.
Detection of a wholesale rollback of store, marker and seal to an earlier
consistent set is unchanged and still deferred; nothing here anchors
freshness.

WHAT ROUND 2 CHANGED, after three independent read-only reviews of the
re-proof above. Four repairs and two follow-ups, each mutation-proved in an
isolated copy outside any repository of the programme, with the imported
module's `__file__` printed beside every verdict:

- THE REBUILD'S REMAINING WINDOW IS CLOSED. `_write_seal_marker()` is hoisted
  above the authority-byte loop, and a FOURTH crash instant --
  between-the-two-authority-writes -- was added to the parametrisation.
  Reverting the hoist alone reddens exactly that row and leaves the other
  three green, which is what makes the row the thing that demands the fix.
  Driven as well as tested: a CHILD PROCESS killed with `os._exit(9)` at that
  instant, forging a READY that is self-consistent to the digest chain, and
  the directory read afterwards by a fresh process.

      the reviewed head's rebuild, verbatim
        on disk  ['.forge-capsule', 'capsule.json', 'experience.json']
        protected() False   sealless load  RETURNED stage='READY'
      the hoist reverted, nothing else
        on disk  ['.forge-capsule', 'capsule.json']
        protected() False   sealless load  CapsuleStoreError
      as shipped
        on disk  ['.forge-capsule', '.forge-seal', 'capsule.json']
        protected() True    sealless load  CapsuleSealMissing

  The middle row is the honest nuance and is stated rather than rounded off.
  With the hoist reverted but `_write_fresh` in place, the forged
  `experience.json` has already been unlinked at that instant, so the store is
  refused by a DIFFERENT mechanism -- an absent file, not the marker -- and
  `protected()` is still False. The marker invariant is what is violated
  there, which is exactly what the test asserts, and it is why the test
  asserts the marker rather than the outcome. The reachable READY read belongs
  to the reviewed head's ordering, the top row.
- THE INTERLOCK IS A BICONDITIONAL AND NO LONGER VACUOUS, and pins the
  docstring's VALUE rather than the constant's name. Three defects, described
  in the marker paragraph above.
- THE RESTORE ROUTE SAYS "SUPPLIED", NOT "ESTABLISHED". Described above.
- THE AUTHORITY PAYLOAD IS NOT BYTE-IDENTICAL, and the re-proof's own commit
  message says otherwise. That message reads "The authority payload is
  untouched and `not_independently_anchored` has not moved." Measured, the
  second half is true and the first is not: this slice deliberately changed
  `last_restoration.revision` -- it is the D-5 repair recorded above, and the
  same commit boasts of it three paragraphs earlier. What is true is narrower
  and is the claim that stands from here, diffed against 3b25d87: the
  payload's KEY SETS are unchanged in both shapes it has (`anchor`,
  `currency`, `last_restoration` at rest; the same three plus `build` while a
  build runs); `currency` is the same literal in both revisions and has not
  moved; and `last_restoration.revision` changed on purpose. A commit message
  cannot be corrected without discarding the reviewed head, so the correction
  lives here rather than there; where the two disagree, this paragraph is the
  claim and that sentence is the error it replaces.
- THE RECOVERY PATH NO LONGER WRITES THROUGH A PLANTED LINK. Measured under
  review at the reviewed head, and IDENTICAL at its parent, so not a
  regression of either: the rebuild wrote the authority files with a bare
  `write_text` while the wipe preserves those names regardless of SHAPE, and
  a hardlink -- no privilege needed on NTFS -- planted at an authority path
  made a restoration overwrite a file OUTSIDE the store with the sealed
  bytes. Every write `_rebuild` makes now goes through `_write_fresh`, which
  removes the entry first. Pinned at all four preserved names by
  `test_the_rebuild_writes_no_bytes_outside_the_store_through_a_planted_link`.
- THE BUILD-PATH ATTRIBUTION IS SCOPED. `onboarding_app`'s module docstring
  covered both routes in one paragraph and said "a store that moved outside
  Forge is restored"; that attribution is defensible around a build and has
  no basis at rest, and the paragraph now says which is which.

WHAT ROUND 2 DID NOT REPAIR, and is not claimed to have:

- `actor.ident` is still an unauthenticated self-assertion. The wording is
  corrected; the surface still does not authenticate humans, and A-015's
  local trust boundary is unchanged. What bounds it is shape only:
  `_IDENT` is `^[A-Za-z0-9][A-Za-z0-9._@ -]{0,119}$`, which admits any
  plausible identity and forbids `;`, so the value cannot forge an extra
  problem inside the `"; ".join(problems)` it is interpolated into.
- `_write_document` and `_write_experience` on the ORDINARY save path still
  write through a planted link. That is unchanged from the parent and outside
  this slice; `save` does not call `assert_sealed()` either, so it is not
  protected by that. Only the recovery path is hardened.
- The SYMLINK variant of the same planting is unverified on this host
  (WinError 1314 without the privilege); only the hardlink variant was
  driven. `_write_fresh` unlinks a symlink rather than following it, but that
  branch is reasoned, not measured here. CI runs ubuntu-latest, where the
  symlink is unprivileged.
- The interlock still LICENSES NOTHING and establishes nothing about the
  marker. It forces a promotion to state a new basis in the same commit.
- Everything in the paragraph above this one stands, with one narrowing. The
  between-authority-writes instant was driven BOTH as a `SystemExit` in the
  test and as an `os._exit(9)` in a child process, which skips `finally` and
  every unwind -- so that instant is no longer exception-only, and a fresh
  process read the directory afterwards. Every OTHER death here is still a
  Python exception; `os._exit` is not a power loss or an external SIGKILL, so
  whether `os.replace(tmp, path)` in `seal()` can leave a torn or absent seal
  on NTFS remains unmeasured. The measurements are still Windows-only,
  `store_lock` is still in-process, and the build thread's provider
  attribution is still an attribution.

ROUND 3 found that one of round 2's two repairs REOPENED what the other one
closed, three lines apart, and that a third had been silently doing nothing
all along:

- THE MARKER'S OWN WRITE WAS NOT ATOMIC, so hoisting it first bought nothing
  at the one instant that mattered. `_write_fresh` -- added by round 2 to stop
  the recovery path writing through a planted link -- removed the entry and
  THEN wrote it. `_rebuild` calls it on the seal marker before anything else.
  Between those two statements the store therefore held the worker's forged
  authority under NO marker: exactly the fall-open the hoist exists to close,
  put back inside the hoisted statement. Measured on the reviewed head, in
  both forms, with the honest reset route made unreachable:

      a crash inside the marker's own write
        on disk  ['.forge-capsule', 'capsule.json', 'experience.json']
        protected() False   sealless load  RETURNED stage='READY'
      an ordinary OSError at the same instant (ENOSPC)
        restore() raised CapsuleStoreError, whose own docstring reads
        "The store cannot satisfy the request. Nothing was partially written."
        on disk  ['.forge-capsule', 'capsule.json', 'experience.json']
        protected() False   sealless load  RETURNED stage='READY'
      as shipped by round 3, both forms, WITH A FILE AT THE DESTINATION
        the marker on disk is the OLD one or the NEW one, never neither

  THAT LINE READ "as shipped, both forms" AND WAS FALSE AS WRITTEN. It is true
  only of a FILE destination. Round 4 measured a directory and a junction at
  the same name reproducing the whole defect above, and the qualification --
  not the claim -- is what survives; see ROUND 4 below.

  That entry list is verbatim the one `_rebuild`'s docstring quotes as the
  PRE-REPAIR defect. The second row is the worse of the two and is why it is
  a separate test: it is DURABLE rather than a window, it needs no crash --
  a full disk, or a real-time scanner holding the create -- and the surface
  reports a clean refusal whose exception promises that nothing was partially
  written, when what it had in fact done was remove the store's second factor.

  `_write_fresh` now writes a finished file to a sibling and `os.replace`s it
  into place, which is `seal()`'s idiom eighty lines down and for the reason
  stated there. It keeps everything the removal bought -- measured, a planted
  hardlink at an authority path: `os.replace` SUCCEEDED and the file outside
  the store kept its own bytes on the old inode -- and only a directory still
  needs removing first, because a rename cannot replace one. The temp name
  carries 64 random bits, because unlike `seal()`'s fixed sibling it is a name
  INSIDE the store, which is the hostile directory; a predictable one could be
  pre-planted as a link and become the write primitive this closes.

  Pinned by two new rows, and only by them:
  `...readable_as_legacy[intact-inside-the-marker-write]` and
  `test_an_oserror_inside_the_marker_write_does_not_permanently_strip_the_marker`.
  `intact` is the marker state that shows it, because it is the one where
  Forge's OWN recovery is what makes the marker absent. The instrument is
  delimited by `_write_seal_marker` rather than by a filename, so it reaches
  a remove-then-write and a write-then-rename at the same instant; if a later
  implementation writes the marker some third way the arming never fires,
  `restore()` does not raise, and the row goes red at `pytest.raises` rather
  than passing for the wrong reason.

- A JUNCTION WAS NEVER REMOVED BY THE WIPE -- only claimed to be, by
  `_rebuild`'s own first paragraph, which lists a junction among the shapes it
  takes. Measured by calling `_remove_tree` at 07d67c7 on a planted junction:
  it RETURNED NORMALLY and the junction was still there afterwards. `rmtree`
  refuses a junction with `Cannot call rmtree on a symbolic link`, and it
  reports that refusal by calling the error handler with its own CHECK,
  `os.path.islink` -- not a removal. The clear-and-retry handler dutifully
  re-ran the check, the check answered False, and `rmtree` returned having
  deleted nothing and RAISED NOTHING. Not a refusal: a silent no-op, for as
  long as that helper has existed. `os.rmdir` removes the link and leaves the
  target untouched (measured, target contents intact), and that is what the
  helper now does, before `rmtree` is reached.

  The review reported this as `_remove_tree` REFUSING a junction with
  `PermissionError [Errno 13]`. That error is real and was reproduced, but it
  comes one statement later, from `write_text` meeting the directory the
  no-op left standing. The distinction is the finding: a refusal is loud and a
  no-op is not, and the wipe -- which has no write after it to raise -- was
  getting the silent one.

- A READ-ONLY DESTINATION NO LONGER DENIES THE RECOVERY PERMANENTLY. This is
  the P2 of round 3, and the measurement corrected the expectation that
  writing-then-renaming would dissolve it: `os.replace` over a destination
  carrying `attrib +R` raises `PermissionError [WinError 5]`, exactly as the
  unlink it replaced did. One `attrib +R` on `.forge-seal` -- a command the
  same-user writer A-015 concedes -- would otherwise disable the product's
  human recovery route for good. `_replace_fresh` clears the bit and retries
  once, which is the remedy `_remove_tree` already applies to git's read-only
  objects. GUARDED ON `st_nlink`, because `os.chmod` through one name of a
  hardlink clears the bit on EVERY name -- measured: a read-only file outside
  the store became writable through a link planted inside it. A name the store
  does not solely own is left alone and the refusal stands.

  All four shapes driven through the real `restore()` on both trees, with each
  plant asserted to have landed before the call (an unasserted plant made the
  junction row read as a clean success once, and proved nothing):

      shape planted in the store        07d67c7        as shipped
      .forge-seal read-only             WinError 5     RESTORED
      junction at capsule.json          Errno 13       RESTORED, victim intact
      held handle on capsule.json       WinError 32    WinError 5   (still denied)
      read-only HARDLINK, capsule.json  WinError 5     WinError 5   (still denied)

  Two of the four closed. In every row of both columns the marker survived and
  `protected()` stayed True, so each denial is a refusal and none of them is a
  fall-open. The last row is the `st_nlink` guard doing its job: the file
  outside the store was NOT made writable and kept its bytes.

- `shutil.rmtree(onerror=...)` is deprecated in 3.12 and removed in 3.14, and
  round 2 made it newly reachable from every write the recovery path makes.
  `onexc` under a version guard, since `requires-python` allows 3.10.

- THE BETWEEN-AUTHORITY-WRITES INSTRUMENT MATCHED A FILENAME, and its own
  comment claimed it did not -- "patched on the Path method rather than on the
  store's write helper so the same instrument reaches an implementation that
  writes either way". It matched `capsule/experience.json` by equality, which
  reaches only an implementation that writes the destination IN PLACE. The
  repair above made the rebuild write a finished file and rename it, and that
  row failed at `pytest.raises` the first time it ran. It now matches the
  destination or a sibling whose name extends it. Recorded because the comment
  was the thing that was false, and because the row failed LOUDLY rather than
  passing -- which is the property that made the fix findable and is now
  stated in both marker-write rows too.

- THE ROUND 2 FALSIFICATION TABLE IS SUPERSEDED, NOT WRONG, and the review's
  correction to it conflated two of its rows. The review reported that "the
  parent-`_rebuild` mutation" reddens SEVEN where round 2's message says four.
  Round 2's message lists TWO rebuild substitutions, with two counts:
  "9522606's _rebuild verbatim  4 red" and "the 3b25d87 rebuild order
  verbatim  7 red". They are different bodies. The first (post-rebase,
  `d836e1d`) writes the marker AFTER the authority bytes but still before
  `git init`, so the three at-git-init rows find the marker present and stay
  green; only the between-authority-writes row and the planted links go red.
  The second (`5e4148b`, the base this slice sits on) wipes FIRST and never
  calls `_write_seal_marker` at all, which is what reddens every crash row.
  Measured on this tree, against round 3's larger set, both bodies extracted
  as bytes from `git cat-file` and substituted verbatim:

      substitution                     round 2's set     round 3's set
      d836e1d's _rebuild                    4                 6
      5e4148b's rebuild order               7                 9
      the hoist reverted                    1                 3

  `3b25d87`'s and `5e4148b`'s `_rebuild` bodies were compared before that row
  was written and are BYTE-IDENTICAL, so round 2's figure and this one measure
  the same substitution across the rebase. Both round-2 figures reproduce
  exactly once the two rows round 3 adds are set aside, so nothing in that
  table was wrong -- it simply had two fewer rows to redden.

  The review's detail was right about the first body in one respect --
  `[.forge-seal]` stays green because `_write_seal_marker` is not part of the
  substituted body, and it does -- and wrong about the crash rows, which
  belong to the second. Round 2's counts were correct for round 2's test set,
  and both rows bite harder now only because there are two more rows to bite.
  The hoist row moves for a reason worth stating: reverting the hoist puts the
  sealed bytes on disk BEFORE the marker write, so both new rows correctly
  report that they can no longer reach the state they exist to measure, rather
  than passing over its absence. A commit message cannot be corrected without
  discarding the head it describes, so the correction lives here; where they
  disagree, this paragraph is the measurement.

WHAT ROUND 3 DID NOT REPAIR, and is not claimed to have:

- A HELD HANDLE ON A DESTINATION STILL DENIES THE RESTORE. `os.replace` raises
  the same `PermissionError [WinError 5]` while any process holds the file
  open -- a still-running worker, an editor, AV, the indexer -- and no `chmod`
  can help, because it is not a permission. It fails CLOSED and it is not
  permanent: it lasts exactly as long as the handle, and the next `restore()`
  succeeds. The review that found it said "for good", which is true of the
  read-only case above and not of this one.
- THE READ-ONLY RETRY IS DELIBERATELY NOT APPLIED TO A SHARED INODE. A
  read-only hardlink planted at an authority path still denies the restore,
  because clearing the bit would reach outside the store. Fails closed. The
  capability given up is small -- a same-user attacker can already run
  `attrib -R` on its own file -- and it is given up anyway rather than
  reasoned away.
- A JUNCTION AT AN AUTHORITY PATH is removed by the wipe now, but a junction
  is still refused rather than followed anywhere `os.replace` meets one
  (`PermissionError [WinError 5]`, measured, with the target's contents
  intact). Fails closed.
- A DEATH BETWEEN THE TEMP WRITE AND THE RENAME CAN LEAVE A STRAY
  `<name>.<hex>.tmp` IN THE STORE. The `OSError` path removes it; a process
  death cannot be helped by any `finally`, exactly as `seal()`'s own
  `.json.tmp` cannot. `_rebuild`'s wipe takes it, since the temp name is in no
  keep set, so it cannot reach a rebuilt store; on the ordinary `_mark_sealed`
  path a survivor would be committed by the following `git add -A`. Its
  content is the marker JSON, it is not an authority file, and the seal
  covers what it covers -- but it is a new artifact this idiom can leave and
  the previous one could not, so it is stated rather than implied.
- SYMLINKS ARE STILL UNVERIFIED ON THIS HOST (WinError 1314 without the
  privilege), for the replace as for round 2's unlink. CI runs
  ubuntu-latest, where the symlink is unprivileged.
- EVERY MEASUREMENT ABOVE IS WINDOWS-ONLY AND EXCEPTION-DRIVEN. `os.replace`
  is assumed atomic on NTFS on the strength of the platform's contract, not
  measured against a power loss or an external SIGKILL -- the same limit round
  2 recorded for `seal()`, now load-bearing in one more place.

ROUND 4 found that round 3 closed ONE SHAPE of the invariant and left TWO
open, which is the second consecutive round in which a repair to this function
left a shape out:

- A DIRECTORY OR A JUNCTION AT `.forge-seal` REPRODUCED THE WHOLE ROUND-3
  DEFECT. `os.replace` cannot replace either, so `_write_fresh` removes them
  first -- and round 3 removed them where the old code did, BEFORE the temp
  existed. `_write_seal_marker` is `_rebuild`'s first statement, so the marker
  was absent again while the worker's forged authority sat on disk. Measured at
  889542a with nothing patched but `Path.write_text` -- the fault model of
  round 3's own `OSError` row -- with the honest reset route made unreachable
  and the plant asserted to have landed:

      shape at .forge-seal   form      protected()   sealless load
      directory              OSError   False         RETURNED stage='READY'
      directory              crash     False         RETURNED stage='READY'
      junction               OSError   False         RETURNED stage='READY'
      junction               crash     False         RETURNED stage='READY'
      file                   both      True          REFUSED CapsuleSealMissing

  On disk in every red row: `['.forge-capsule', 'capsule.json',
  'experience.json']` -- verbatim the entry list `_rebuild`'s docstring quotes
  as the PRE-REPAIR defect. The `OSError` form is durable, needs no crash, and
  is reported behind a refusal whose own docstring promises that nothing was
  partially written. And it is a DEGRADATION FORGE ITSELF CAUSES: before the
  call the planted shape already made `protected()` True and already made a
  sealless load refuse, so the restoration removed a factor it found in place.
  That before-state is now asserted in the rows, which is what makes them
  measure a degradation rather than an absence.

  THE REPAIR IS A TWO-LINE REORDER: the removal moves INSIDE the `try`, after
  the finished temp exists. Everything that can raise has then already
  happened. Re-measured on the shipped tree, same instrument:

      directory  OSError  protected() True   REFUSED CapsuleSealMissing
      directory  crash    protected() True   REFUSED CapsuleSealMissing
      junction   OSError  protected() True   REFUSED CapsuleSealMissing
      junction   crash    protected() True   REFUSED CapsuleSealMissing

  A concurrent observer counting the marker's absence STRICTLY INSIDE
  `_write_fresh`, over 300 writes per shape:

      shape        889542a         as shipped
      file         0 / 2518        0 / 2556
      directory    1706 / 4204     663 / 4032
      junction     1475 / 2544     581 / 2087

- WHAT IS NOT CLOSED, AND IS NOT CLAIMED CLOSED. A CRASH-ONLY MICRO-WINDOW
  SURVIVES for a directory and a junction: the removal and the rename are two
  adjacent syscalls with no I/O between them, and a death in that gap leaves
  the marker name absent with the forgery on disk. It is INHERENT, not
  deferred: `os.replace` cannot replace a directory, so no ordering of those
  two calls removes it -- only giving the destination a different shape would,
  and the destination's shape is the attacker's choice. What the reorder buys
  is that the DURABLE form disappears entirely (no `OSError`, no full disk, no
  scanner can reach it) and the window narrows to roughly a third. The rows
  added here kill at the first write the marker's write makes, which is the
  instant that reaches both implementations; they do NOT reach that
  two-syscall gap and do not pretend to. The residue is stated in
  `_write_fresh`, in `_write_seal_marker`, and here.

- TWO SHIPPED CLAIMS WERE FALSE AS WRITTEN AND ARE NOW QUALIFIED.
  `_write_seal_marker` said "the marker on disk is the old one or the new one
  at every instant -- never neither", and the round-3 block above said "as
  shipped, both forms" of the same. Both are true of a FILE destination and
  false of the other two, which is exactly the shape the repair had missed.
  The claim now states which destination it holds for, and names the residue
  for the other two in the same paragraph. A false claim about a security
  property is the blocking category under the founder's split merge bar, and
  it is recorded here rather than quietly edited, because the sentence had
  been strengthened past its measurement in the same commit that measured it.

- NOTHING DEMANDED EITHER SHAPE. Before this round, `forge-seal` intersected
  with `mkdir|mklink|junction` across the whole repository returned nothing:
  no test anywhere planted a directory or a junction at the marker. That is
  why round 3's repair could reopen for two shapes what it closed for one, and
  it is the same absence round 3 recorded about its own instant. Four rows now
  demand it -- two shapes by two forms -- and reverting the reorder turns all
  FOUR red, with every other row in the module green:

      test_a_failure_inside_the_marker_write_leaves_a_directory_marker_standing[crash]
      test_a_failure_inside_the_marker_write_leaves_a_directory_marker_standing[oserror]
      test_a_crash_inside_the_marker_write_leaves_a_junction_marker_standing
      test_an_oserror_inside_the_marker_write_leaves_a_junction_marker_standing

  The substituted body is round 3's ordering verbatim; the diff against the
  shipped one is the two-line reorder and nothing else. The instrument is
  self-checking in the way round 3 established: it is delimited by
  `_write_seal_marker` rather than by a filename, so an implementation that
  writes the marker some third way never arms it, `restore()` does not raise,
  and the rows go red at `pytest.raises` instead of passing over the absence.

- FORGE'S OWN CRASH MANUFACTURED A TAMPER FINDING AGAINST AN UNTOUCHED STORE,
  and that is repaired rather than only disclosed. A stray `<name>.<hex>.tmp`
  left by a death between the temp write and the rename -- the survivor the
  round-3 list above already conceded -- made the cleanliness check report
  `["the working tree is not clean: ?? .forge-seal.<hex>.tmp"]`, and every
  later load refused with `CapsuleSealError`. Fail-closed and repairable, but
  the product was reporting TAMPERED about a store nobody had touched, on
  account of its own crash, and the human restore it invites costs the
  lifecycle a transition. `_tree_changes` now drops one line shape: an
  UNTRACKED file, in the store root, whose name carries Forge's own temp
  suffix.

  THE WIDENING THAT COSTS, STATED. The exemption is NOT a claim that the file
  is Forge's -- the name is the only evidence and any writer in the store can
  forge a name. What it says is only that such a file is not BY ITSELF a
  tamper finding, and an attacker can therefore keep one inert file in the
  store root out of the cleanliness report. It can carry no authority: nothing
  in the module reads the store by pattern, and the authority files, the store
  marker and the seal marker are each read by exact name with their bytes
  compared to the seal regardless of what else is present. A tracked file of
  that name that was modified or deleted is still a finding, an untracked file
  of any other name is still a finding, and one below the store root is still
  a finding -- all three measured. The matcher and the name-builder are one
  constant apart and are pinned against each other in both directions, because
  two descriptions of one rule is where this repository keeps finding rot;
  drift would fail SAFE (an unrecognised stray goes back to being a finding)
  and is pinned anyway.

WHAT ROUND 4 DID NOT REPAIR, and is not claimed to have:

- `_replace_fresh`'s `st_nlink == 1` GUARD IS CHECK-THEN-ACT. Between the
  `os.stat` and the `os.chmod` a same-user worker can create a hardlink to the
  destination, and the read-only attribute is then cleared on a file outside
  the store. Attribute only -- no write reaches the outside file, because the
  rename that follows swaps the directory entry -- and the guard still blocks
  the case it was built for. REASONED, NOT MEASURED: the window was not driven
  on this tree, and it is recorded as reasoning rather than as a measurement.
- THERE IS NO `fsync`, on the temp file or on the containing directory.
  `os.replace` orders the directory ENTRY, not the data behind it, so a POWER
  LOSS -- not a process death, which the rows above do drive -- can leave a
  truncated or empty `.forge-seal`. The resulting state is fail-closed: the
  marker is present and does not name this store's seal, so `seal_problems`
  reports it and the load refuses. Unmeasured, like every other power-loss
  claim in this section.
- `os.replace` OVER A CONCURRENTLY-OPEN DESTINATION STILL RAISES
  `PermissionError [WinError 5]`, and the single chmod retry cannot help,
  because it is not a permission. Round 3 recorded this for a held handle and
  called it an attacker-shaped case; it is not. MEASURED HERE WITH NO ATTACKER
  AT ALL: an ordinary observer thread doing nothing but `Path.exists()` on the
  destination denied 5, 9 and 11 of 300 marker writes across three runs. Any
  indexer, scanner or editor touching the file is enough. It fails CLOSED and
  lasts only as long as the handle, and the next `restore()` succeeds -- but
  it is reachable in normal operation, not only under attack.
- THE JUNCTION ROWS DO NOT RUN ON CI. A junction is an NTFS directory-shaped
  reparse point that `is_symlink()` reports False for; POSIX has no equivalent
  (a symlink to a directory answers True and takes a different branch), so the
  plant cannot be built on the Linux test jobs. Both are declared skips, the
  first this slice has declared. The property is not weakened: the two
  DIRECTORY rows take the identical branch of `_write_fresh` and execute on
  every platform, so deleting the reorder cannot hide behind the exemption.
- THE SKIP CENSUS CANNOT DECLARE A PARAMETRISED ROW.
  `check_test_coverage.EXPECTED_SKIPS` is keyed by node id, and
  `test_every_declared_exemption_names_a_test_that_exists` resolves that key
  by looking for `def <name>(` in the module source -- which no `[...]` id
  satisfies. So a platform-dependent parametrised row must be restructured
  into whole functions to be declarable, which is what the junction rows here
  did. Recorded rather than repaired: widening a guard so that it admits an
  entry of its author's own shape is the move this file exists to police, and
  the restructuring cost nothing.
- SYMLINKS REMAIN UNVERIFIED ON THIS HOST, unchanged from round 3, and every
  measurement in this round is Windows-only and exception-driven for the same
  reasons stated there.

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
surface validates every actor, and a model actor is refused. The served
composition answers only to a loopback Host header (`127.0.0.1` or
`localhost`), because a page that rebinds a name to 127.0.0.1 would
otherwise reach the surface (measured under review). That rule was first
installed on the Windows runtime's composition alone, which left the
console `onboard` path -- the same surface -- without it: finding N3 of
the independent PR-18 review, non-blocking at merge because the governed
Windows entry was protected. Since the post-PR-18 hardening the rule
belongs to `onboarding_serve.assemble`, the composition both launch paths
serve, and the runtime adds no copy of its own; a repository-wide census
pins that no composition under `src/` omits it. It is a Host-header
check, not authentication: the trust boundary stays A-015's. Nothing here
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
records it when the operator performs it. Its `pass` had meant only that
a stopped record existed while the route statuses, the instance-token
comparison and the stop outcome were recorded and never judged -- finding
N1 of the independent PR-18 review, non-blocking at merge because no
operator smoke evidence had been recorded. Since the post-PR-18 hardening
`result` is derived from the recorded observations by one verdict
function and a failure names the observation; the instrument is stronger,
and the run it measures HAS NOW BEEN PERFORMED ONCE, at the founder's
request, on one host, and is recorded in
`docs/governance/EMBEDDED_INTERPRETER_RUN.md`. Both properties above are
still true: the repository supplies no embeddable archive, and the
builder fetches none -- the archive stayed an operator input passed on
the command line, and nothing was added to the tree. The recorded smoke
result is `fail`, and the run failed twice over for two different
reasons. Driven by a CPython 3.12 builder it never reached the smoke at
all: `verify_bundle` refused the folder, because `install_dependencies`
resolves the closure with the builder's own interpreter while
`install_python` accepts an operator archive of any version and nothing
requires the two to agree -- 75 `cp312`-tagged extensions cannot load on
the 3.13.15 the archive carries. Driven by a 3.13 builder the same
command passed `verify_bundle`, and the runtime genuinely started on the
bundle's own `pythonw.exe` and recorded itself ready three seconds in --
and then the smoke did not terminate. `Forge.cmd` detaches the runtime
with `start ""`, which creates the grandchild with handle inheritance on,
so the grandchild is handed duplicates of the pipes
`subprocess.run(capture_output=True)` is draining at the moment it is
created -- and the 120 s timeout does not bound the wait for an EOF that
cannot arrive; the smoke resumed only when that detached process was
killed. THE REPAIR THAT FOLLOWS IS NOT "REDIRECT THE LAUNCHER'S STDIO":
redirection was tried on the same host, with and without `/b`, and the
run still hung, because the duplication has already happened by the time
the grandchild could redirect anything. Giving the PARENT files instead
of pipes, on a launcher line otherwise unchanged, removed the hang
outright. So the repair belongs on the driving side -- do not hold
captured pipes across a detaching launcher -- and the arms that settle it
are recorded in `docs/governance/EMBEDDED_INTERPRETER_RUN.md`. Nothing
had caught it, because `smoke_bundle` is
exercised only against a scripted runtime with `subprocess.run`, `_get`
and `_post_json` all replaced, and no workflow runs `--smoke` -- the real
path had never been executed, which is precisely what NOT PERFORMED was
concealing. The stop route and the stopped record stay unmeasured: that
route requires a person's act at the computer, and no autonomous run may
assert one. Windows-hosted automated evidence
in this repository runs the runtime as a real child process from a real
bundle folder on the runner's own CPython -- the developer arrangement --
and is labelled as exactly that.

**Scope.** Not an installer, not signing, not release publication, not
auto-update, not a Windows service, not provider confinement or admission,
not A-018, not R3 monotonic anchoring, not P17-03.

**Serves.** the founder's basic-user strategy's Windows-first delivery, the
FORGE_ROOT doctrine extended to the launcher, and the claim discipline in
`CLAUDE.md`.

## A-024 Provider confinement is two properties, and Forge measured one of them

**Assumption.** A provider is confined enough for the governed basic-user
build only when it can neither rewrite Forge's authority on disk nor reach
Forge's authority-bearing control plane. Filesystem confinement alone is not
the property; it is half of it.

**Why it is stated as an assumption rather than derived.** Before PA-01 the
repository treated "confined to the project workspace" as one thing, and
`PROVIDER_CONFINEMENT` carried one value per provider to say whether Forge had
established it. That framing quietly assumed the workspace boundary was where
authority lived. It is not. The onboarding surface is local, unauthenticated,
and carries routes that move authority, and it is reachable by anything that
can open a socket to loopback. A provider held out of the filesystem and let
into that surface has acquired the authority regardless.

**Measured at 7ce306b1** (`docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md`),
Windows 11, codex-cli 0.128.0, through the CLI's own `codex sandbox windows`
entry point so no model decided whether the forbidden operation was attempted:

- Codex's sandbox REFUSES every write outside the declared workspace -- the
  real seal directory, a sibling, Forge material, its own configuration home,
  and an escape through a junction proved live first -- while permitting the
  intended in-workspace write. That is real OS enforcement, and the repository
  may no longer say Forge has established nothing about it.
- Codex's sandbox does NOT confine loopback egress. A confined process reached
  a controlled listener on 127.0.0.1 and its POST was accepted under the Host
  rule the real surface applies. No configuration was found that closes it.

**Consequence.** `codex` stays `declared` and both providers stay ineligible.
The criterion is now data (`CONFINEMENT_PROPERTIES`) rather than prose, the
measurement is a recorded artifact, and a test holds the table and the evidence
to each other in both directions -- so promoting the row without qualifying
evidence fails, and a measurement that genuinely closed the gap would pass.

**The second property was renamed by A-028's slice C1, and this entry keeps its
own vocabulary.** The assumption above names two properties, and the second one
-- "reach Forge's authority-bearing control plane" -- was a PROXY, sound while
that plane was unauthenticated. A-027 gated it, which makes reachability
irrelevant rather than absent, so `control_plane_reachability: denied` became a
criterion nothing could ever satisfy for a reason about the proxy rather than
about any provider. It is retired in favour of `control_plane_authority` --
whether the provider's principal can acquire or move Forge authority THROUGH
that plane, decided by the surface's own record -- under an obligation A-028
states and tests: the retired criterion's required outcome still entails the
new one's, the entailment runs one way, and it does not by itself ADMIT the new
property, which asks for an observation of Forge's own gated surface that no
measurement in this repository has taken. The consequence above is unchanged in
every particular: `codex` stays `declared`, both providers stay ineligible, and
what is unmet is now named `control_plane_authority`. The measurement recorded
in this entry is neither restated nor re-labelled -- it keeps the words it was
taken in, and the retired name stays in the vocabulary so it does.

**A second assumption, learned from the verifier rather than the sandbox.** A
criterion expressed as data is not yet a criterion that cannot be satisfied
dishonestly. The first verifier admitted three routes to "established" that
required no such property to hold: satisfaction by `any(...)`, which resolves a
contradiction by keeping its convenient half; one global list of evidence
mechanisms, which let a CLIENT's return code testify to whether a LISTENER was
reached; and probes with no provider on them, so evidence gathered against one
provider would answer for another. So the assumption is stated explicitly:
**an admission verifier must require unanimity among observers competent for
the specific property, and the evidence must name the subject it measured.**
A counterexample dominates a compliant observation; a non-authoritative
observation is silent rather than exculpatory; and a record's header may not
re-subject the observations beneath it.

**A third, about evidence integrity.** A decoding failure must not be
converted into silent evidence mutation. `errors="replace"` was the repair
that looked right: it ends the crash and turns malformed bytes into U+FFFD,
which then reach evidence as ordinary text while the run reports success.
Strict decoding, with the failure recorded as the result, is the fail-closed
form.

**What this does NOT assume.** Nothing about POSIX: Linux and macOS were not
measured, junction semantics are not symlink semantics, and the Windows result
does not travel. Nothing about model behaviour: two production-path runs left
every canary pristine because the model executed nothing at all, including the
control, and both are recorded as inconclusive rather than counted. Nothing
about Claude, which was not measured and keeps the row it had.

**Scope.** Not an admission, not a control-plane authenticator, not a Claude
sandbox, not A-018.

**Serves.** the governed build's fail-closed decision, and the claim discipline
in `CLAUDE.md` that forbids substituting a label for the thing measured.

## A-025 A decoding failure must not become silent evidence mutation

**Assumption.** Text that reaches a `WorkerResult` is what the provider
actually emitted, or the result says it could not be read. There is no third
option in which unreadable bytes arrive as ordinary characters.

**Why it needs stating.** `subprocess.run(..., text=True)` with no encoding
named decodes with the locale codec, which is cp1252 on this project's Windows
hosts while both provider CLIs emit UTF-8. Not only the basic-user target: the
DEVELOPER host reproduces it too -- `locale.getpreferredencoding(False)` is
cp1252, `sys.flags.utf8_mode` is 0 and `PYTHONUTF8` is unset there -- so the
defect is not confined to the delivery environment and a developer would not
have been protected from it. Measured against the shipped `ClaudeCodeWorker`
at 7ce306b, on real byte sequences those CLIs produce:

- a right single quote (U+2019) decoded to `before â€™ after` -- mojibake
  carried verbatim into the result with `success=True`;
- a right double quote (U+201D) carries byte 0x9d, unmapped in cp1252, so the
  reader thread raised, `stdout` came back `None`, and `result.stdout.strip()`
  became an `AttributeError` ESCAPING `run()` -- an exception where the
  Provider Contract requires a WorkerResult and permits one only for an
  invalid task;
- genuinely malformed UTF-8 (`\x80`, `\xe2\x80`, `\xff\xfe`) decoded into
  PLAUSIBLE text (`before € after`, `before â€ after`, `before ÿþ after`) and
  was reported as a SUCCESSFUL run. Not a replacement character anyone would
  notice -- confident wrong text.

**And `errors="replace"` is not the repair.** It ends the crash and converts
malformed bytes to U+FFFD, which then travel into evidence as ordinary
characters while the run still reports success. That is the same defect as the
mojibake case, one step better disguised: the failure mode is evidence which is
not what the provider emitted, and replacement makes it harder to notice rather
than less true.

**Consequence.** Decoding is strict. Valid UTF-8 is preserved exactly; a stream
that fails to decode yields a `WorkerResult` that is not successful whatever the
process exited with, names the decode failure and its byte offset, and
identifies the payload by length and SHA-256 rather than rendering it -- on the
timeout branch as well as the completed-process branch, so unreadable output
from a run that outlived its budget can still be correlated with the bytes
emitted. `run()` still never raises. Both directions are pinned by test,
because asserting only "does not raise" would pass on an adapter that silently
mangles every quotation mark -- and the fingerprint is pinned as a fingerprint,
the digest recomputed from the emitted bytes, because review showed a constant
digest satisfying a `"sha256:" in output` check, and a latin-1 rendering of the
payload satisfying a `"\ufffd" not in output` check. Both are red now.

Two consequences of capturing bytes are stated rather than left implicit.
First, `text=True` also performed universal-newline translation, so a
carriage return the provider emits now survives into the result exactly as
emitted instead of being folded into `\n` -- except at the very ends, which
`.strip()` removes on the success path (`output = stdout.strip() or
stderr.strip()`) exactly as it would remove a leading or trailing space. So
the rule is precisely that the result is the provider's bytes with only the
ends stripped, not a claim that carriage-return translation has been
reintroduced under a different name; canonical evidence files escape the
byte that does survive, and `test_a_carriage_return_survives_exactly_as_emitted`
pins it. Second, the
cp1252 shapes above are observable only where the locale codec is not UTF-8.
The CI test matrix runs on Linux under a UTF-8 locale, where the same
strict-decode regression is still caught -- there the malformed specimens
raise out of `run()` -- but the mojibake and the escaping `AttributeError`
are not reproduced; those were measured on this Windows host. No CI job
exercises this module's decode path on Windows: `tests/test_provider_contract.py`
runs only in the Linux matrix, and the `windows-runtime` job imports the
module without ever calling `run()`. The specimens cover both streams,
because the adapter refuses the run when either fails to decode.

**Scope.** `claude_worker.py` only, brought to the rule `codex_worker.py`
already applies: the Codex half of this defect was found and repaired first,
under the PA-01 measurement recorded in A-024. The one point where the two
adapters were not identical -- the Codex timeout branch recording reason and
offset only, where the Claude timeout branch and both adapters'
completed-process branches fingerprint a failed stream with length and
SHA-256 -- was an OPEN ITEM here. **CLOSED by the provider-adapter parity
slice** that follows this entry: the Codex timeout branch now fingerprints a
stream that failed to decode exactly as the other three branches already do,
mirrored test for test in `tests/test_codex_provider.py` against the same
`tests/provider_specimens.py` helpers the Claude suite uses. No provider
confinement, eligibility or admission change: `PROVIDER_CONFINEMENT["claude"]`
stays `none`. Reading a provider's bytes correctly says nothing about what
that provider may reach.

**Addendum (provider-adapter parity slice).** Four further points, measured
and closed at the same head, kept here because they are the same claim
discipline applied to what was left asymmetric or unguarded once the timeout
branches matched:

- **The readable sibling was being dropped.** When one stream failed to
  decode and the other decoded cleanly, the completed-process branch of
  BOTH adapters reported only the failed stream's fingerprint and the
  decode-failure sentence -- the sibling's own text, which the timeout
  branch already keeps by appending `out + err` unconditionally, never
  reached the result. Both completed-process branches now append the
  decoded text the same way, so a readable sibling's words are not lost
  merely because something else in the same run could not be read.
- **`_decode` and `_fingerprint` accepted a `str` and silently did nothing
  with it.** Both helpers carried a dead branch, `isinstance(raw, str)`,
  returning the text unexamined as `problem=None`. Every real call site only
  ever hands these functions bytes or `None`, so the branch never executed
  in this adapter's own path; it is removed, both helpers are annotated
  `bytes | None`, and a `str` argument now raises `TypeError` rather than
  being reported as verified UTF-8 without the check ever running.
- **`session_id` was carried through unvalidated.** The raw parsed JSON value
  reached `WorkerResult.session_id` whatever shape it was -- a dict, an
  oversized string, or a JSON `\ud800` escape that `json.loads` turns into a
  Python string holding a lone surrogate code point, which
  `nornyx_forge.util.canonical_json` can serialize but a downstream
  UTF-8 encode of that JSON text cannot. Both adapters now accept a session
  identifier only as a non-empty `str` of at most 200 characters (the
  character rule was tightened twice more in the rounds below); anything
  else becomes `None`, the same absence a stream that never mentioned a
  session already records.
- **A host-specific path was reaching committed evidence.** Unrelated to
  decoding, found in the same slice:
  `scripts/refresh_governance_evidence.py`'s independent-review record named
  the absent default reviewer trust store (`Path.home() / ".nornyx" /
  "forge_reviewer_trust.json"`) by its full path in `verdict_basis`, so a
  clean regeneration on any two machines produced governance evidence
  differing by whichever account and computer ran it. The generator now
  renders that path home-relative before it reaches an emitted artifact;
  `ReviewerTrustStore.source` itself is untouched.

**Addendum (parity repair round).** Three further points, closing the first
of the model-only bounded reviews of the slice above (three read-only model
inspectors, each attacking one commit -- a builder-arranged check, and
nothing more than that is asserted for any of these rounds):

- **`json.loads` over unbounded provider stdout could raise `RecursionError`,
  not merely `json.JSONDecodeError`.** Measured directly: text deep enough in
  nested brackets or braces (no closing bracket required) exhausts CPython's
  own recursion guard before it ever notices the document is incomplete. Both
  adapters call `json.loads` on provider-controlled stdout --
  `claude_worker.py` on the whole payload, `codex_worker.py` per JSONL line --
  and the Provider Contract requires a `WorkerResult` for that ending too,
  never an exception. Both now catch `RecursionError` alongside `ValueError`
  (which already covers `json.JSONDecodeError`); `session_id` becomes `None`,
  the same absence an ordinary parse failure already records. A sibling
  defect in the same functions, pre-existing and unrelated to JSON: `OSError`
  raised by `subprocess.run` itself (an executable path that is a directory,
  or a file `available()`'s `shutil.which` check accepted but the OS loader
  then refuses -- measured directly with a zero-byte file carrying an
  executable extension, `OSError: [WinError 193] %1 is not a valid Win32
  application` on Windows) is now caught the same way, reported as the
  `unavailable` class (127) rather than escaping `run()`.
- **The session-identifier character class admitted control and bidi
  characters.** `_validated_session_id` bounded the length and refused
  surrogate code points, but a NUL byte, an embedded newline, or a bidi
  override character such as U+202E (which can make a rendered string
  display in an order its characters do not actually hold) all passed
  through as an accepted identifier. Both adapters then additionally
  required `value.isprintable()` and no whitespace character in `value`;
  the two checks are both needed because `isprintable()` alone accepts an
  ordinary ASCII space. Tightened once more in the round below.
- **The store-path rendering recognised only ONE exact spelling of home,
  and rendered a store outside home verbatim.** A lowercase drive letter or
  account name, or a Windows 8.3 short name landing on the same directory as
  the long form `Path.home()` returns, did not match a plain substring
  check, and a `FORGE_REVIEWER_TRUST_STORE` pointed outside home reached
  `verdict_basis` as a raw path -- the same class of leak the original fix
  closed for the default location, reopened for every other spelling of it.
  The generator now compares under `os.path.normcase` against `Path.home()`,
  its resolved form, and (Windows only) its 8.3 short name where the volume
  generates one; renders a home-relative path with FORWARD SLASHES ALWAYS,
  so a Windows and a Linux regeneration of the same evidence agree byte for
  byte; and renders a store path outside every known form of home by its
  CONFIGURATION NAME (`<FORGE_REVIEWER_TRUST_STORE>`). This round's first
  form of that rule searched composed prose for something path-shaped and
  fell back to a regular expression that truncated at a space or a
  parenthesis and missed a UNC path -- corrected in the round below, where
  the claim is restated to what is now true.

**Addendum (parity repair round three).** Closing the second model-only
bounded review (the same three read-only inspectors, attacking the round
above); two of its findings would have turned the Linux CI matrix red, and
the rest are the same claim discipline again:

- **Redaction is at the source now, and the claim is exactly this.** The
  store path is a value the generator holds (`reviewer_store_path()`, the
  same resolution `ReviewerTrustStore.load()` performs), so `_store_display`
  computes its rendering from that value -- `~/...` when it begins with a
  known spelling of home followed by a separator or the end, the
  configuration name otherwise -- and `_redact_store_path` composes every
  message that can reach `verdict_basis` by replacing that exact value.
  There is no path-shaped search and no regular-expression fallback. What is
  tested: a path with a space (`C:\Users\John Doe\...`), one with
  parentheses (`D:\Program Files (x86)\...`), a UNC path in both spellings,
  and a POSIX path with a space are each replaced whole, every occurrence;
  the boundary holds (`C:\Users\DevuserX` is not `C:\Users\Devuser`); the
  case rule is the platform's own `os.path.normcase`, and BOTH of its
  behaviours are exercised on every host by substituting `ntpath.normcase`
  and `posixpath.normcase` -- Windows folds case, POSIX does not, because
  `/home/Devuser` and `/home/devuser` are different directories there and
  folding them would render another account's store as the reader's. What is
  NOT claimed: that the message could never carry a path spelled differently
  from the resolved value. The store's own messages are all built from that
  value, and the committed-evidence sweep below is the backstop.
- **The committed-evidence sweep searched for the reader's login name as a
  bare substring.** On ubuntu-latest `getpass.getuser()` is `runner`, and
  `architecture_conformance_report.json` legitimately contains
  `module.gate_runner` -- red on every CI interpreter over a file that
  leaked nothing. The sweep now matches the login and machine name only as
  PATH SEGMENTS (a separator before -- the one that ends `Users` or `home`
  serves, so neither word is named -- and a separator, dot, quote,
  whitespace or the end after; or the machine half
  of a Windows `account.MACHINE` profile folder), in both the raw and the
  JSON-escaped (doubled-backslash) spellings, plus generic host-path shapes
  (`X:\Users\`, any drive letter, `/home/`, `/Users/`). Its power is pinned
  by known-positive controls (the JSON-escaped Windows shape, the raw
  Windows shape, the POSIX shape) and its silence by a known-negative one
  (`runner` inside `gate_runner`, `ann` inside `cannot`, a URL), and the
  same sweep is run with the CI runner's identity on every host.
- **The session identifier is an ASCII identifier.** A character-category
  rule admitted strong right-to-left LETTERS (U+05D0 is printable and
  contains no whitespace), which reorder a rendering just as an override
  does, and no category rule can tell such a letter from an ordinary one.
  Both adapters now require, identically: `str`, non-empty, at most 200
  characters, `isascii()`, `isprintable()`, and no whitespace -- every
  character in `!`..`~`. Every session identifier either CLI has been
  observed to emit is a UUID-shaped run of ASCII letters, digits and
  hyphens, well inside the rule. This narrows what `session_present` means
  in the frozen equivalence projection; it is recorded as section 11 of
  `docs/governance/PROVIDER_EQUIVALENCE_PREREG.md`, in the amendment's own
  commit, which PRECEDES the slice commit that applies the rule, as the
  freeze protocol requires (see the pre-registration amendment paragraph
  at the end of this entry).
- **A NUL in provider output made the next invocation unrunnable.** A
  literal NUL is valid UTF-8 and both adapters carry it into `output`
  exactly as emitted (correctly). `development_flow` then composed the
  repair `goal` from that output, and `subprocess.run` refuses a NUL in any
  argument with `ValueError` before a process exists -- measured on both
  adapters: `a\x00b` on a failing provider's stdout raised out of the repair
  step. Two repairs, kept apart. Both adapters catch `ValueError` from
  `subprocess.run` (argument, working directory or executable; raised on
  every platform) and report a WorkerResult in the `error` class, and catch
  it from `shutil.which` in `available()` -- which raises for a bare name
  carrying a NUL ON WINDOWS ONLY (measured on CPython 3.12); on POSIX the
  same lookup returns None and that catch is never entered -- answering
  False there, so `run()` reports the ordinary `unavailable` class on every
  host; and the flow escapes
  C0 control characters other than tab, newline and carriage return -- as
  `\xNN`, legibly -- at the ONE place it composes provider text into a new
  goal (`compose_repair_goal`), while the ledger's record of what the gates
  said stays verbatim. The composition is Forge-authored text, so it is
  Forge's to sanitise; the provider's record is not.
- **A missing workspace was blamed on the executable.** `subprocess.run`
  with a `cwd` that is missing or a file raises `NotADirectoryError`, an
  `OSError` the adapters reported as `unavailable` (127) under the sentence
  for an executable that could not be started. Both adapters now check
  `os.path.isdir(workspace)` before spawning and report a WorkerResult in
  the `error` class that names the workspace; `OSError` at spawn stays 127
  and stays about the executable. The window between the check and the
  spawn is not closed and is stated in the code.
- **Provider text is delimited from Forge's account.** On the two branches
  that keep a decoded stream's text beside the adapter's own account (a
  timeout, a sibling stream that failed to decode), a provider could append
  a forged second integrity sentence and a reader had no way to tell where
  the adapter stopped speaking. Both adapters now write a fixed delimiter
  line before any provider text; everything after its first occurrence is
  provider-authored and may contain anything, including a forged copy of the
  delimiter; nothing in Forge parses that prose -- the failure class is
  derived from `success` and `returncode` alone. No delimiter is written when
  there is no provider text.
- **The specimen's power is pinned, and its rationale corrected.** The
  deep-nesting specimen's constant was justified by `sys.getrecursionlimit()`
  (1000); the guard that actually fires is the C-level recursion check
  inside CPython's C json scanner, measured by bisection on CPython 3.12.10
  at depth 2997 (array) and 2998 (object) with the Python limit at 1000.
  Both adapters' tests now assert `json.loads(deep_nested_json(shape))`
  raises `RecursionError` on the running interpreter before handing the
  text to an adapter, so an interpreter that parsed the specimen would turn
  the test red. The object-shape specimen closes its braces; the earlier
  docstring said no closing bracket ever appears.
- **Two pre-existing limits, disclosed rather than closed** -- open items
  for the provider-execution tranche, not this slice: `WorkerResult.output`
  has no ceiling (an arbitrarily large stream is retained in memory whole,
  and a `MemoryError` there is not caught); and `timeout_seconds` bounds
  the provider process, not wall time -- after the kill, `subprocess.run`
  keeps collecting for as long as a GRANDCHILD of the provider LIVES, not
  merely while it holds the inherited pipe. Measured on the Windows host
  with a 2 s budget against a grandchild that sleeps 5 s: 5.2 s of wall
  time when the grandchild keeps its standard handles, and 5.1 s when it
  closes all three of them first -- the same overrun, so releasing the
  handles a grandchild can name does not end the wait; its exit does. (An
  earlier measurement of the same shape, 6.2 s against 2 s, described the
  cause as the pipe being held; the control corrects the cause, not the
  fact.) Both were recorded in the maintenance census before this round and
  are repeated here so that A-025 does not read as though the adapters
  bound what they do not. The round-five addendum below gathers these two
  with two more into one open-items list.

**Addendum (parity repair round four).** Closing the third model-only
bounded review (the same three read-only inspectors, attacking the round
above). Nothing here changes confinement, eligibility or the Provider
Contract:

- **The composed repair goal is bounded, and was not.** `ProviderTask.
  validate` refuses a goal above 8000 characters by raising `ProviderError`
  out of the routed worker's `run`, which `acceptance()` does not catch --
  so an over-long composed goal ended the flow with an exception rather
  than a repair attempt. That exposure PRE-DATES this slice: four failing
  gates quoting 2500 characters each were already more than 8000. The
  round-three escaping made it more likely: each control character becomes
  four (`\xNN`), so ONE failing gate whose 2500-character tail is
  control-heavy was enough, from provider-controlled text (for the
  `application-builder` gate at attempt 1, measured: 1789 or more of the
  2500 characters being C0 controls). `compose_repair_goal` now bounds the goal
  twice. Each gate's ESCAPED tail is held to 2500 characters, keeping its
  end (where the verdict is) behind a marker that names how many characters
  were left out, so one gate can neither crowd the others out nor alone
  exceed the bound; then the whole goal is held to 7000 characters, keeping
  its start (the gates in the order they failed) behind the same kind of
  marker on its own line. 7000 sits under the contract's 8000 with headroom
  for a longer opening sentence, and the relation is pinned against the
  contract's own validation by test. The markers appear in the composed
  goal only: the ledger's `repair_requested` record still holds each
  failing gate's full 2500-character tail, un-escaped and uncut. Specimens:
  a real provider flooding stdout with 2500 NUL characters composes to a
  goal the routed worker runs without raising, and four ordinary failing
  gates compose to exactly the bound; both un-capped forms are shown to be
  refused by the contract as it stands.
- **An argument list too long for the operating system was reported as an
  absent executable.** Windows bounds a command line at 32767 characters;
  `CreateProcess` refuses a longer one with `ERROR_FILENAME_EXCED_RANGE`
  (206), which CPython raises as `FileNotFoundError` with errno 2 -- the
  absent-executable errno -- and both adapters reported that as
  `unavailable` (127) under the sentence for an executable that could not
  be started. Measured on this Windows host: a 33000-character argument
  fails that way and a 32000-character one runs; a 1 MB goal on either
  adapter fails the same way. A POSIX `execve` refuses with `E2BIG`. Both
  adapters now recognise the two (`winerror` 206, or `errno` `E2BIG`) at
  the `OSError` catch and report a WorkerResult in the `error` class whose
  sentence names the command line's length, the argument count and the
  goal's length; every other `OSError` there stays `unavailable` and stays
  about the executable. This bullet first ended "the routed path cannot
  reach this: the contract refuses a goal above 8000 characters first" --
  true of the goal, false of the invocation; corrected in the round-five
  addendum below.
- **Two sentences were broader than the measurement.** The adapters'
  docstrings said Forge's account is ALWAYS the part before the first
  delimiter; that holds on the two delimited failure branches only -- on
  the success path `output` is the provider's text from its first
  character, by design, and a delimiter-shaped line there is the provider's
  own. And every sentence saying `shutil.which` raises `ValueError` for a
  NUL is now qualified: Windows only (measured on CPython 3.12); POSIX
  returns None, and the catch in `available()` is not exercised there. The
  catch stays.
- **The 8.3 short-name test asked the function under test for its own
  precondition.** It skipped whenever `_short_path_name` returned None, so
  a `_short_path_name` that always returned None turned the test into a
  skip on a volume that generates short names. The test now asks
  `GetShortPathNameW` directly and FAILS wherever the API yields a short
  form the function does not return; it skips only where the API is absent
  or yields none.
- **Pinned behaviourally rather than by grep.** That the flow composes the
  repair goal only through `compose_repair_goal` is proven by driving
  `acceptance()` with a spy in that function's place and a stub worker: the
  spy must be called with the failing gates, and the worker must receive
  exactly what the spy returned; the one source scan that remains -- the
  opening sentence spelled once across all of `src/` -- is a question a
  grep can honestly answer. The two adapters' session rules are held
  identical over one shared specimen table of accepted and refused values,
  and their bound equal, rather than inferred from mirrored suites.

**Addendum (parity repair round five).** Closing the fourth model-only
bounded review (the same three read-only inspectors, attacking the round
above; two found nothing blocking and left notes, the third returned one
prose finding). Nothing here changes confinement, eligibility or the
Provider Contract:

- **"The routed path cannot reach the argument-length branch" was false.**
  Five sentences said it -- both adapters' module docstrings, the comments
  at their `OSError` catch, and the round-four bullet above -- on the ground
  that `ProviderTask.validate` refuses a goal above 8000 characters first.
  `validate` bounds the GOAL. It bounds neither `allowed_tools` (each tool
  must be a non-empty string without a comma; no length, no count) nor the
  workspace path (a non-empty string). Measured through the real
  `ProviderRoutedWorker` on this Windows host: a 12-character goal and 90
  tools whose joined list is 36449 characters ends in the `error` class (2)
  on both adapters -- `command-line length: 37047 characters across 9
  arguments, the goal alone 12 characters: [WinError 206]` on Claude,
  `37392 characters across 11 arguments` on Codex. The behaviour was right;
  the claim was not. All five sentences now say what `validate` bounds and
  what it does not, and the reachability is pinned by one routed specimen
  run on both adapters
  (`test_a_routed_task_reaches_the_argument_length_branch_through_its_tool_list`):
  a 12-character goal beside 150 tools of 1000 characters, a joined list of
  150149 characters -- above the 32767-character line Windows accepts and,
  as ONE argument, above Linux's `MAX_ARG_STRLEN` (131072), so both CI
  platforms refuse it by construction. The class and the sentence's three
  fragments are asserted, not the number. Not measured on macOS, which is
  not in the CI matrix and bounds the total rather than one argument.
- **The reported length could sit below the bound it explained.** The
  number in the sentence was a sum of the raw arguments plus one separator
  each. Windows counts the ONE quoted line `subprocess.list2cmdline` builds
  -- exactly what `Popen` hands `CreateProcess` -- against 32767, terminator
  included, and quoting is not free: every quote inside an argument gains a
  backslash and the argument gains surrounding quotes. Measured: a goal of
  17000 double quotes was reported as `17590 characters` while the line was
  34591 (Codex: 17840 against 34841). Both adapters' `_command_line_length`
  now count `len(list2cmdline(command)) + 1` on Windows -- the quoted line
  plus the terminating NUL the bound includes -- and keep the per-argument
  sum, in characters, elsewhere; the docstring says which is measured where,
  and that the POSIX figure is a character count under a kernel that counts
  bytes. Pinned in both adapter suites without a skip
  (`test_the_reported_command_line_length_is_the_line_the_platform_counts`,
  once per suite): the rule is computed in the test for the running
  platform and held against the function on a quote-heavy vector, then
  against the sentence of a real refusal -- 140000 double quotes as the
  goal, refused by both CI platforms -- over the command the result carries.
  Corrected in round six: the round-five sentence could still name a
  sub-bound length when 206 came from the executable path -- `CreateProcess`
  answers the same 206 for an over-long executable path, measured as an
  existing 333-character `.cmd` shim, run with a 10-character goal,
  reported in the `error` class as `738 characters across 9 arguments` on
  Claude and `988 characters across 11 arguments` on Codex (the Codex line
  carries the workspace path, 187 characters in that measurement, as
  `--cd`; the Claude line carries none) -- so round six gates the arm on
  the computed line exceeding 32767 (`WINDOWS_COMMAND_LINE_LIMIT`, held
  against two real spawns: a 32766-character line accepted, 32767 refused
  with 206) and sends a sub-bound 206 to the executable arm, `unavailable`
  (127). Corrected in round seven: round six had recorded that specimen as
  `343 characters`, the 333-character path and the 10-character goal
  summed by hand -- a quantity neither adapter ever emitted. The figures
  above come from running the round-five tree (`git archive 6ea2a09`)
  against the specimen in round seven; the current tree reports the same
  specimen on both adapters as `unavailable` (127) under
  `executable could not be started: [WinError 206]`.
- **Open items, gathered in one place.** None is closed here; the first two
  are restated from the round-three addendum above so that the list is in
  one place:
  - `WorkerResult.output` has no ceiling: an arbitrarily large stream is
    retained in memory whole, and a `MemoryError` there is not caught.
  - `timeout_seconds` bounds the provider process, not wall time: after the
    kill, `subprocess.run` keeps collecting for as long as a grandchild of
    the provider lives.
  - Pre-existing and host-dependent, recorded from the round-five review's
    measurement: a workspace path long enough to pass `os.path.isdir` and
    still be refused by `CreateProcess` (12117 characters with long paths
    enabled, `[WinError 267] The directory name is invalid`) lands in the
    `OSError` arm as `unavailable` (127) under the executable's sentence --
    a second way into the check-to-spawn window the round-three bullet
    leaves open.
  - Pre-existing and host-measured (round-six review; confirmed through
    both adapters by the round-seven builder): a `.cmd` or `.bat`
    executable is run through the command processor, so its line is
    refused BELOW `WINDOWS_COMMAND_LINE_LIMIT` -- from a count of 32737
    up to 32767 with `[WinError 122] The data area passed to a system call
    is too small` (errno 22), which the classifier does not read, so the
    refusal lands as `unavailable` (127) under the executable's sentence
    rather than as a length refusal, while at 32736 the process spawns and
    `cmd.exe` itself answers `The command line is too long.` (exit 1), and
    from 32768 the 206 arm holds as for a `.exe`. Only a `.exe` target is
    refused exactly at the bound, which is the case the constant's comment
    names as measured.
  - C1 controls and bidi formatting characters in composed prompts:
    `compose_repair_goal` escapes the C0 controls other than tab, newline
    and carriage return; U+0080..U+009F and the bidi controls (U+202A..
    U+202E, U+2066..U+2069) pass into the composed goal as they are.
    Carried in the pull request since round three; durable here now.

**Pre-registration amendment.** The provider-adapter parity slice narrows
what `session_present` means in the frozen equivalence projection
(`docs/governance/PROVIDER_EQUIVALENCE_PREREG.md`, section 5): a session
identifier counts as present only when it passed validation as an ASCII
identifier. That narrowing is recorded as section 11 of the
pre-registration in its own commit, which precedes the slice commit that
applies it, as the freeze protocol requires; the amendment is
builder-proposed under the founder's standing instruction and not
founder-ratified.

**Serves.** the Provider Contract's rule that failure is a WorkerResult and
never an exception, and the claim discipline in `CLAUDE.md` that forbids
substituting a label for the thing measured -- here, text for bytes.

## A-026 A clean checkout is not evidence of what was executed

**Assumption.** A measurement of this repository names the tree it measured
only when the RUNNING code has been shown to come from that tree. Checking out
a clean copy establishes what the files say; it does not establish what Python
imported.

**The mechanism, reproduced rather than reasoned about.** An editable install
writes an absolute path into
`site-packages/__editable__.nornyx_forge_live_demo-<version>.pth`, and that
path is prepended to `sys.path` for every interpreter using that environment,
whatever directory it runs from. Measured: with the working directory inside a
freshly cloned copy of the subject and `PYTHONPATH` unset,
`nornyx_forge.__file__` and `importlib.util.find_spec("nornyx_forge").origin`
both resolved to `<main checkout>/src/nornyx_forge/__init__.py`. The clone
supplied the TEST FILES; a different checkout supplied the CODE UNDER TEST.
Nothing in the run reported this, and the run would have looked identical had
the two trees disagreed.

**Consequence for the census.** `check_test_coverage.py` reports how many
tests executed in a tree, so a run whose subject is unproved does not measure
the tree it names -- however clean that tree is. Such a run is
NON-AUTHORITATIVE, not "slightly contaminated": the distinction is whether the
subject was established, and an unestablished subject is not weak evidence but
absent evidence.

**What makes a measurement authoritative instead.** A fresh clone at the exact
head, a fresh virtual environment built from a base interpreter that never
carried another checkout's editable install, the repository's own supported
install into it, and -- before any test runs -- a check that both
`nornyx_forge.__file__` and `find_spec(...).origin` resolve under the subject
and that no `sys.path` entry reaches another checkout. A `.pth` file is not
itself the fault; the question is only what source it binds to.

**Where the authority for this repository actually sits.** CI satisfies this by
construction rather than by care: `actions/checkout@v4` puts exactly one copy of
the repository on a clean runner, `pip install -e '.[demo,dev]'` binds the
editable install to that copy, and there is no second checkout for a `.pth` to
name. That is why a census claim rests on the exact-head CI run across all four
supported interpreters, and a local run is corroboration -- most usefully on
Windows, which the CI test matrix does not cover.

**Scope.** A measurement-provenance rule. It changes no product behaviour, no
confinement or eligibility state, and no gate threshold.

**Serves.** the same claim discipline as A-021 -- a governed tree answers for
itself -- extended to the interpreter that runs it, because a tree cannot
answer for code that was loaded from somewhere else.

## A-027 The onboarding surface admits only this run's bearer, held off disk

**Assumption.** No HTTP request may move authority on the onboarding surface --
persisted state, the lifecycle, provider selection, `BRD.md`, or the runtime --
unless it carries a secret minted for this run and given only to the person's
page. Loopback reachability is not admission.

**Why it needs stating.** A-024 measured the second half of provider
confinement and found it open: a Codex worker confined to the project workspace
still reaches loopback, and its POST is accepted under the Host rule, which
defends against a browser rebinding a name and does nothing against a local
process. A-015 disclosed the surface as "trusts its loopback"; that is true of
the machine's logged-in user and was never meant to admit a confined provider.
So a per-run capability is added: a bearer token minted in `create_app` (the
real composition root -- nine test modules and `attach_runtime_routes` compose
or extend the app, and `assemble` is not where it is minted), required by a
middleware gate on every route but four, and deliberately excluded from
everything the provider can read.

**The token stays off disk, and the reason is measured.** Read-only probes on
this host (Windows 11 Home, the development workstation) found an EXPLICIT
`CodexSandboxUsers:(OI)(CI)(RX)` ACE on `~/.nornyx`, written by the Codex
installation whose sandbox principals are that group's members;
`~/.nornyx/forge`, the seal directory, `%LOCALAPPDATA%` and `%APPDATA%` inherit
read, and `%LOCALAPPDATA%\Temp` is modify. A secret on any of those paths is a
secret a confined Codex worker can read. Chromium persists `localStorage` and
`sessionStorage` as plaintext under `%LOCALAPPDATA%`; a cookie set by one
loopback port is sent to every loopback port and can be discarded from another;
`os.open(..., 0o600)` sets no ACL on Windows; and uvicorn's access logger walks
to the root logger, which the Windows runtime gives a file handler, so a
credential in a URL PATH would land in `<key>.log` for good. Therefore the
token lives ONLY in Forge's process memory (`app.state.session`) and the page's
JavaScript closure, the bootstrap nonce travels in a URL fragment (never sent
to a server, never logged), Forge sets no cookie anywhere, the access log is
off, the FastAPI docs and schema routes are off, and the validation-error
handler echoes nothing. The only file that ever carries the token is the
explicit `--session-file` the bundle smoke and the runtime tests pass; the
shipped launchers pass none, and a test pins that a launch without it writes
only a record, a lock and a log.

**What is established.** A request without this run's bearer, on any route the
gate does not allowlist -- known path or not, and any route attached after
composition -- is refused `401` with a fixed body that echoes nothing, and
moves nothing; comparison is constant-time, and it is `hmac.compare_digest`
on both call sites by an AST walk over the imported methods, not by a grep --
two lexical pins in a row let a swapped-operand `==` through (third review,
test P1). The four allowlisted routes are the
static page, the operational `/api/runtime` identity, the nonce redemption, and
`/api/runtime/reopen`, and the two unauthenticated POSTs carry browser-
provenance checks (Origin serialized against the Host, `Sec-Fetch-Site`, a
navigation POST refused) so that no other browser context can make the
human's browser move authority. `/api/runtime` stays unauthenticated by
design -- a launcher probes it before it holds anything to present -- and it
discloses to ANY local process exactly the served identity and nothing more:
the record schema, the instance token (an identity a probe compares, not a
credential anything verifies), the bundle root, the bundle mode, the project
directory, the port, the pid, the interpreter path and the start time. None
of it moves authority and none of it is a secret; that it names the
interpreter and the project directory to any local caller is the disclosure
(third review, P4-1). Every unrouted or near-miss path (`/nope`, `//api/state`,
`/api/runtime/`, `/API/RUNTIME`, `/api/runtime/../state` as spelled) is the
same fixed `401`, never a router `404` that would enumerate the surface. Forge reads no cookie and the page sends none
(`credentials: "omit"`): a `forge_session*` cookie on a GATED request is
refused `400` as an ambient credential this surface never issued, and the four
allowlisted pairs IGNORE cookies. The scope matters: cookies are host-scoped,
not port-scoped, so a listener on another loopback port can set
`forge_session` for `127.0.0.1`, and the earlier rule, which judged `GET /` by
it, let such a listener deny the person their own page (measured under the
second review; the page's own calls were never affected). Each run mints a
fresh token and nonce; the previous run's are dead. The workers pass the
provider an explicit environment stripped of `FORGE_*` and of a bare `FORGE`
(a `startswith("FORGE_")` rule let the bare name through; third review,
P4-3), and that is measured on
the PROCESS, not read from the source: a fake provider executable resolved by
name through the real build route and the real `DevelopmentFlow` received
exactly that environment, and neither secret in its argv, its cwd or its
workspace. The token and nonce appear in no argv Forge controls (the worker
command lines, the launchers, the server), in no environment, prompt,
workspace file, runtime record, runtime log, launch-failures trail,
`/api/runtime`, unauthenticated page or response header -- on the browser-open
FAILURE branch as well as on success: the record, the log and the notice are
composed from the fragmentless URL and scrubbed of the target and the nonce,
because every exception source (the adapter's own refusal, the
`OSError.filename` that `os.startfile` raises) embeds the URL it was given,
fragment included -- measured under review before the repair, when a nonce
read from the record redeemed for the token. One argv Forge does NOT control
carries the nonce: the browser handler's. `os.startfile` hands the fragment
URL to ShellExecute, which places it on the default browser's command line
(`--single-argument %1`), readable by any process of the same user for the
life of that command line. The bound is principal separation -- a provider
under a different OS principal cannot read another user's command lines --
and it is already conceded for the same-user provider, which can read Forge's
memory in any case. A SECOND channel Forge does not control sits beside it:
the browser's own persistent history store. `history.replaceState` clears the
fragment from the address bar and from the session-history entry, and from
nothing else; the browser's on-disk history records the navigated URL,
fragment included, when the navigation commits, and `replaceState` does not
reach back into that record. The bound is the nonce's own: single-use,
consumed by the page's redeem in the same page load, and dead after 120 s if
never redeemed. WHO CAN READ THOSE STORES was overstated here as an inference
and is now measured (third review, P3-3; `icacls`, this host, 2026-09-07).
`%LOCALAPPDATA%` and `%LOCALAPPDATA%\Microsoft` do carry the inherited
`CodexSandboxUsers:(I)(OI)(CI)(RX)` ACE. The inheritance is BROKEN one level
down: `%LOCALAPPDATA%\Google` and `%LOCALAPPDATA%\Microsoft\Edge` each carry
an explicit DACL of exactly `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`
and the user, all `(OI)(CI)(F)`, with no inherited entry and no
`CodexSandboxUsers`; and the two history stores measured --
`...\Google\Chrome\User Data\Default\History` and
`...\Microsoft\Edge\User Data\Default\History` -- inherit exactly that: SYSTEM,
Administrators and the user, `(I)(F)`, nothing else. So on this host the
sandbox group reads the containing directory and does NOT reach either
measured store. Other browsers, other profiles and other hosts are
unmeasured; the handler command-line channel stands as stated, bounded by
principal separation alone. AND THESE TWO CHANNELS ARE NOT PASSIVE:
`/api/runtime/reopen` is an unauthenticated, on-demand trigger that any local
process may pull once per 10 s, and each pull mints a fresh nonce and places
it on exactly those channels -- the handler's command line at once, and the
browser's history when the page commits. The bound on what such a caller
gains is therefore NOT "a visible nuisance, not authority", which an earlier
revision of this entry said; it is the nonce's: single use, a 120 s TTL, and
the race against the page's own redeem, which fires in the same page load. A
same-user process that wins that race by reading the command line before the
page redeems holds the token -- which the same-user provider already holds by
reading Forge's memory, the boundary this entry concedes below; a reader of
the history store after the page redeemed holds a dead nonce. That is the
residual, stated as one, with its trigger.

**Hardened under the first review round, and the residuals.** Credentials are
compared as bytes after an alphabet check, so a non-ASCII bearer or nonce is
the fixed `401`/`404` rather than a `500` with a traceback in the runtime log
(measured before the repair: about 2 KB per request, no rotation); the gate's
own decision cannot raise; `Authorization` is accepted only as exactly
`Bearer <credential>`; a websocket handshake is closed before acceptance and
any non-HTTP scope other than `lifespan` is dropped; the Origin check compares
the full serialization, so from a BROWSER a prefix of the port or a suffix on
the host is refused. That check is browser provenance, not caller
authentication: a browser sets `Origin` and `Host` itself and a page cannot
forge them, which is what keeps another browser context from driving the two
unauthenticated POSTs; a non-browser process sets both headers to whatever it
likes and passes it (third review, P4-2, measured). What such a caller
reaches is what those two routes give anyone -- redeem needs a nonce it does
not have, reopen returns no secret -- and admission to everything else is the
bearer. `TrustedHost` splits the header on `:`, so `Host: 127.0.0.1:8888.evil`
is admitted by it; the Origin check then compares against that Host string,
which is one more reason it is not the admission. The bootstrap nonce has two
independent slots, `launch` (minted once at readiness, replaced only by the
next launch mint) and `reopen` (minted by the reopen route), every nonce
single-use with a 120 s TTL, so a local process calling `/api/runtime/reopen`
cannot invalidate the launch bootstrap the person's page is about to redeem.
The reopen slot is a QUEUE, not one nonce: a single reopen nonce let any local
caller's reopen invalidate the one the person's own Reconnect had just minted
(third review, P3-1, measured: Reconnect `200`, local reopen at t+11 s `200`,
the person's redeem `404`). Reopen nonces now queue up to
`REOPEN_PENDING_BOUND`, which is derived, not chosen: one mint per 10 s
interval against a 120 s TTL inclusive of its expiry instant admits at most
floor(120/10)+1 = 13 outstanding nonces, so under the rate limit no unexpired
nonce is ever evicted; a direct mint past the bound evicts the oldest; a test
joins the two constants. Reopen refuses `409` on a run started with
`--no-browser`, and a second launcher told `409` or `429` says so to the
person with the fragmentless URL instead of returning in silence. RESIDUAL,
disclosed: a local process may still call reopen once per 10 s and pop a
browser window on the human's Forge, and each call mints a nonce onto the two
channels described above -- the bound is the nonce's, stated there. The reopen
RATE-LIMIT slot is still ONE, shared by the joining launcher, the page's
Reconnect and any local caller: a caller holding it busy makes the person's
Reconnect answer `429`, which the page reports as such, and the person retries
or opens the page by hand; what such a caller can no longer do is kill the
nonce a Reconnect that got through had minted. On a run started with
`--no-browser`, reopen answers a fixed `409` before the rate limit, so polling
it is unbounded and stateless: no nonce is minted, no state moves, no log line
is written per call. When the owner's browser adapter raises -- whatever the
exception's class; each is caught, rendered through a guard so that an
exception whose own `__str__` raises cannot throw from inside the handler, and
scrubbed -- reopen answers `503` with a fixed body and the joining launcher
tells the person with the fragmentless URL; a `200` there was read as success
and returned in silence (measured under the second review). The redeem
response, the one that carries the token, is `Cache-Control: no-store`.
`--session-file`
is reachable by an operator through `Forge.cmd %*`; it is refused unless
absolute, in an existing directory, and outside the project directory, the
runtime directory, the seal directory and the user profile -- the roots the
measured ACEs reach -- decided before anything is created. Three of those
roots are fixed by the launch (the project and the runtime directory from
argv, the seal directory a constant) and ONE is environment-derived: the user
profile is `Path.home()`, which is `USERPROFILE` (or `HOME`), so that fence
is exactly as good as that variable, and the smoke relocates it on purpose.
The candidate's SPELLING is judged before it is resolved: a path beginning
with a double separator -- a Windows namespace prefix (`\\?\`, `\\.\`, their
`//?/` spellings) or a UNC share, `\\localhost\C$\...` included -- is refused
by name, because `Path.resolve()` keeps those prefixes and the plain roots are
then never among the candidate's parents (third review, P2-1, measured end to
end before the repair: `--session-file \\?\<profile>\stolen.json` launched
READY and wrote the bearer inside the profile; the UNC spelling was admitted
by the fence function as well). An 8.3 short name resolves to its long form
and a trailing dot or space stays inside its root, so each is caught by the
root it lives under (measured on this host). The `--runtime-dir` fence,
pre-existing and bypassed the same way, now refuses the namespace prefixes on
the runtime directory AND on the project directory (a prefixed project would
make the project root a spelling no plain runtime directory can be under);
it does NOT refuse a UNC runtime directory, because a profile on a share is a
configuration this launch has not measured, so a UNC alias of a fenced root
is a disclosed residual of THAT fence -- and the residual is on BOTH of its
operands, not the runtime directory alone, which is what the first
disclosure said. The round-4 security review measured the other direction on
a scratch project: a UNC ALIAS OF THE PROJECT (`\\localhost\C$\...\project`)
passed with a plain `--runtime-dir`, because the project fence root is then a
spelling no plain runtime directory is under, and the runtime directory was
created INSIDE the project -- the exact placement the fence exists to
prevent. Both operands are namespace-prefix-refused and neither is
UNC-refused; the two clauses are one residual with two spellings, and it is
bounded the same way in both: `--runtime-dir` and `--project-dir` are the
LAUNCHER's argv, a share on `C$` needs Administrators, and creating a share
is an administrative act -- so a confined local process cannot reach this. The
POST-RESOLUTION half of both fences -- the refusal that reads what a plain
spelling RESOLVED to, rather than how it was spelled -- is witnessed through a
resolution seam rather than by a real alias: no plain path on this host
resolves to a doubled-separator path, and `subst`/`net use` change the host
rather than the scratch. Round-4 test review measured what that cost: with no
witness at all, deleting either block left the whole module green while the
docstrings claimed spellings are refused "before resolving, and again after".
The seam applies to the CALLER-supplied candidate only; every fenced root is
resolved for real. The file is
written only after readiness, with mode `0600` where the OS honours a mode
(Windows sets no ACL from a mode, which is why the fence is the protection
there), and removed at stop. It is created EXCLUSIVELY: a file already at the
path -- stale, or planted -- is left as found, neither overwritten nor
removed at stop, the person is told by path, and this run's bearer is written
nowhere, so a stale file authenticates nothing, visibly. "Written nowhere" is
exact and is kept so: a target already there is refused BEFORE the staging
file below is created, so the ordinary pre-existing case puts no bearer on
any disk. The check is not the refusal, though -- the move is, and a target
that appears after the check is refused by it just the same. It is also
VISIBLE ONLY COMPLETE: the payload is staged as `<name>.tmp` beside the
target and moved onto the final name by an operation that refuses an existing
target (`os.rename` on Windows, `os.link` on POSIX), so a reader that finds
the path reads a whole record or nothing, where the previous shape created
the final name and wrote afterwards and a reader arriving between the two
parsed no bearer and sent its first request bare -- measured on the
windows-runtime CI job as a `401` on the first bearered `POST /api/project`,
with one child ever started and its record `ready`. The staging file this run
made is removed before the call returns whether it succeeded or failed, and
only while the name still holds THAT file: after a successful move the name
is free for anyone, and deleting whatever took it would be deleting another
launch's bearer. ONE RESIDUAL, stated rather than implied: a hard kill --
`TerminateProcess`, a power loss -- between the fsync and the move leaves
`<name>.tmp` holding a live bearer, because a `finally` does not run when a
process dies. It is bounded by that window and by the directory, which is the
fenced one; the protection there is the fence, exactly as it is for the target
itself. The fence resolves
every root itself rather than trusting its caller to. The protection of a
location that passes the
fence is the operator's choice. The bundle smoke's own session file lands
under `tempfile.mkdtemp()` -- `%LOCALAPPDATA%\Temp`, which the read-only ACE
probe above records as Modify for `CodexSandboxUsers` -- and the fence admits
it only because the smoke relocates its child's profile into its scratch. That
is stated HERE and not only in a source comment, because it is a bearer on a
provider-writable path and a reader of this document should not have to find
it in the builder. It is acceptable for the smoke ALONE, on four counts, each
of which has to hold: no provider runs during it; the runtime it
authenticates to serves a throwaway scratch project; the token is minted per
RUN, so the file can only ever hold a bearer for a runtime that is being
stopped moments later; and the file and the scratch are removed at stop. None
of those holds for a shipped launch, which is why no shipped launcher passes
`--session-file` at all. The console `onboard` path is disclosed on the same
terms and is NOT the same thing: it prints the start link, whose fragment is a
LIVE launch nonce, to stdout. A console redirected to a file therefore puts
that nonce on disk for its 120 s TTL, wherever the redirection points -- which
may be a path the measured ACEs reach. It is bounded by the nonce's single use
and that TTL, and it is not the bearer: redeeming it needs the surface, over
loopback, before it expires or the person's own page consumes it. The bearer
itself is never printed and never logged, which a test reads on stdout,
stderr and the log records alike. UNMEASURED until the operator run (Tranche I/J): that the fragment
survives `os.startfile` -> ShellExecute -> the default browser intact. The
witness will be the page's own redeem succeeding in a real browser the
launcher opened; until then the bootstrap is established over the seam (the
URL handed to the adapter carries the fragment) and not end to end.

**What B does NOT establish, stated rather than implied away.**
`PROVIDER_CONFINEMENT`, `CONFINEMENT_PROPERTIES` and `governed_build_eligibility`
are untouched; both providers stay ineligible and the governed build still
executes no provider, so this capability is not yet load-bearing for any real
build. It does not defend against an unconfined SAME-USER provider: Claude runs
on this path as the machine's user with general shell capability and can read
Forge's process memory and the browser's, so B changes nothing for Claude's
eligibility (the A-015 boundary -- the logged-in user -- is unchanged). Its
value against Codex is CONDITIONAL on the provider actually running under the
restricted token: A-024 measured `codex sandbox windows`, not the shipped
`codex exec --sandbox workspace-write` path, whose production runs were
inconclusive, and that measurement is Tranche C's, not made here. Authority
also moves WITHOUT HTTP, and B closes none of it: the build thread turns gate
results over the provider's own workspace into TEST/GOVERN through
`experience_build.flow_evidence`; a broken seal makes `restored()` record a
system failure; `brd_present()` reads the workspace; and `CapsuleStore.restore()`
re-seals whatever is on disk after a reset, a TOCTOU an actor who can write the
workspace could exploit. Those are owned by Tranches D and F. A compromised
browser or extension can read the page's token; that is out of scope, as is a
hostile host. No sandboxing, authenticated human identity, cryptographic
provenance, freshness anchor, provider admission, or A-018 is claimed.

**Scope.** A control-plane session capability. It changes no Experience stage,
no CONFIRM or READY semantics, no confinement vocabulary, declaration or
admission, and no seal, lock or port behaviour.

**Serves.** the loopback half of A-024's measured gap, the claim discipline in
`CLAUDE.md`, and the trust boundary A-015 discloses -- narrowed for
authority-moving routes, not redrawn.

## A-028 DRAFT A control-plane probe is a measurement, not an admission

**Status: DRAFT (Tranche C, slices C2 and C1).** The first part of this entry
describes a measurement HARNESS and the one measurement it makes of the harness
against itself: slice C2 adds no confinement property, moves no provider row,
and is limited to what it observes and, more importantly, to what it does not.
The part headed **"The criterion change (slice C1)"**, near the end, is
separate and later: it records the one admission criterion Tranche C replaces,
why the thing it replaced had become a broken instrument rather than a high
bar, and what the replacement had to prove before it was allowed to be one. C1
moves no provider row either. The part headed **"The record-to-probe
translation and the first confined measurement (slice C3)"** is later again: it
ships the translation that makes the criterion's semantics apply to a real
record, and takes that record from a Codex-sandboxed principal against a live
Forge surface. C3 moves no provider row either, and the reason it does not is
recorded there rather than asserted.

**Assumption.** Whether a local process can acquire or move Forge authority
through the onboarding control plane is a question that must be answered by
OBSERVING the surface over a real socket, as a stranger would, and recording the
result in a record that binds its subject and names the mechanism behind each
fact -- not by reading a caller's own account of itself, and not from an
in-process client that authenticates deliberately. `scripts/probe_control_plane.py`
is that observer. It takes a live surface (a port, an optional expected instance,
an optional session file for a positive control), drives the seven HTTP methods
across the composed route census and the four allowlisted pairs from THIS
process, attempts the artefact reads a same-user caller could make, and writes a
`nornyx.forge.control_plane_probe.v1` record whose classification is derived from
the unauthenticated request log alone.

**Why it needs stating.** A-027 makes loopback reachability irrelevant by
requiring this run's bearer on every authority-moving route, but it does not make
reachability ABSENT, and A-024 measured that a confined Codex worker still
reaches loopback. So the honest question is not "can a local process connect"
(it can) but "what can a local process, running as the surface's own OS
principal, actually do to the surface" -- and the only witness competent to
answer is the surface, over a socket. A record that answered from a caller's exit
code, or from an in-process `TestClient`, would be the substitution A-024's
verifier was rebuilt to refuse.

**What C2 establishes, and only this.** The probe's documented path list is held
equal, IN PROCESS, to the route table of the served composition (`assemble` plus
`attach_runtime_routes`), the same composition the live fixture launches; a
route the census cannot probe -- a mount, a websocket route -- reddens the check
rather than hiding in it. Over a real socket, the four allowlisted pairs answer
and every other documented cell is refused 401 without the bearer; this proves
the gate's coverage over the documented cells, not the route table, because a
gated route and an unrouted path both answer the fixed 401 by design and the
wire cannot tell them apart. Run in-process as the unconfined local caller
against that live surface, the probe classifies ITSELF `admitted_nuisance`: it
reaches the four allowlisted pairs, every other cell refuses it, and it moves no
authority state. The state is derived from the request log alone, under two
rules: allowlist membership comes from the constant and never from a row's
stored flag (a row that disagrees is refused); and a state that would count as
confinement requires every cell of the 133-cell matrix answered, while a gated
2xx dominates at any coverage -- so a partial log, a surface that stops
answering or a probe that runs out of deadline is `inconclusive` with the
reason, never a state. C2 derives THREE states plus `inconclusive`;
`unreachable` is not in the record's vocabulary, because deriving it needs a
positive control from a separated principal proving the same instance was up
while this caller could not connect, which only a later slice can supply, and
the validator refuses a record that claims it. The record says
`principal_separated: not_separated` -- a three-word vocabulary (`separated` /
`not_separated` / `unknown`) read through one helper that answers True / False /
None and raises on anything else, so the field cannot be truth-tested by
accident -- and says in one field why `admitted_nuisance` is not confinement
for such a caller: a same-user process can read the browser handler's command
line and Forge's process memory (A-027). The record binds its subject: the
probe's own pid and interpreter, the imported `nornyx_forge` source, the tree's
git SHA, the principal read from inside the probe, and the surface's instance,
pid and port; the instance match is computed and recomputed by the validator,
and a surface that is not the expected instance is refused as not-the-subject.
Because the in-process self-probe IS the surface's process, its
`OpenProcess(PROCESS_VM_READ)` artefact is `not_applicable` with the reason
`self process`; a separate cross-process witness -- the same module through
its CLI, in a child process, against the same live surface -- acquires that
handle on Windows (the capability A-027 concedes to a same-user caller) and
finds the facility absent elsewhere. Each fact carries its mechanism, kept
apart: a socket-observed fact is `observed_surface_record`; a filesystem or
process-capability fact is `inferred_acl`. An artefact carries one of THREE
outcomes, and a refusal is not an observation: `observed` is a capability this
caller acquired, `refused` is a facility that exists and denied this caller,
`not_applicable` is that there was nothing to try. One helper,
`capability_acquired()`, is the only sanctioned way to read an artefact as
evidence of a capability, and it is True for `observed` alone; the validator
refuses a record whose own detail records a denial under the acquired word,
and a `refused` that does not say it was refused. An authenticated positive
control, reading this run's bearer from an operator-supplied session file,
makes a real bearered `GET /api/state` that answers 200 in the same run in
which the bare one answered 401, which proves the surface was live and the
harness not vacuous; that it was made and what it answered are recorded, the
token is not, and it never moves the classification.

**The deadline bounds the whole run, and any expiry is `inconclusive`.** It is
checked between requests, before every artefact read, and it clamps each
operation's own timeout to what is left of it -- the two subject-binding
subprocesses (`git rev-parse`, `whoami /user`) included, which is what makes
"the whole probe" true rather than "the request matrix". Whenever the clock
expires, at any point, `deadline_exceeded` is true, `artefacts_truncated`
counts the reads it cut off (recomputed by the validator from the artefacts
themselves), and the classification is `inconclusive` at whatever coverage was
reached. That last is a CHOICE between two repairs and is recorded as one: a
run whose matrix completed and whose artefact reads were then cut short could
otherwise look exactly like a complete one. Keeping the state and renaming the
flag would leave a reader to decide which missing evidence mattered, and this
record exists so that nobody has to.

**What the record retains of the host, stated rather than implied.** It names
no host in the clear: every spelling of home -- long, resolved, and on Windows
the long and 8.3 short forms -- folds to `~`, and the login and machine name
are removed wherever they occur; the validator refuses a record that still
names any of them, matching each raw AND JSON-escaped, because the check runs
over a `json.dumps` blob in which every separator is doubled. Two things are
worth saying exactly. FIRST, the record RETAINS the principal's Windows SID
(`subject.principal.sid`, `S-1-5-21-...`), deliberately: a subject binding
whose principal is redacted binds nothing. A SID is a machine-and-account
identifier -- it names the account the probe ran as, and its `S-1-5-21-<three
32-bit values>` prefix identifies the machine or domain that issued it. It is
not a login, not a password and not a credential, and it authenticates nobody
by itself; it is retained because A-026 asks what principal ran, and a record
that will not say is not a subject binding. SECOND, on the live run the
folding of home did NOT do the work the phrase "folds every spelling of home"
suggests: the fixture RELOCATES the profile, so the paths in the record are not
under the run's real home at all, and what removed the identity from them was
the login and machine-name token removal. The folding is exercised on this
host's real home by its own pin. Both mechanisms are present; neither is being
credited with the other's work.

**The tool decides its destination, not its spelling.** `--host` must be
loopback, decided without name resolution -- and `localhost` is NORMALISED to
127.0.0.1 before a socket is opened. Admitting a NAME and then connecting by it
would leave the destination to the resolver and to a `hosts` file an
administrator can write, so a rule whose whole purpose is that this tool cannot
be turned on another machine would have decided the spelling only. In the same
spirit, the two system executables it runs are resolved absolutely under
`%SystemRoot%` or from a DRIVE-ABSOLUTE `PATH` entry: on Windows `\tools` is
"absolute" and means `tools` from the root of the CURRENT drive, which the
working directory chooses, so a root-relative entry is skipped like a relative
one. `--out` is refused when it resolves inside this repository's working tree:
a record written there is a measurement sitting where the evidence cycle will
commit it as source.

**The record is a self-report, and the validator's bound is stated.** Its
`transport: loopback_socket` is a declaration the producer makes about itself.
The validator refuses a record that declares a non-socket transport and one
that labels a socket fact as an inference; it CANNOT tell a log built in
process (a `TestClient`) and labelled as a socket log from one that opened a
socket, and this is measured rather than implied away: such a record is
accepted. What holds the label honest is the producer, `probe()`, which has
exactly one transport and no in-process path -- a property of the module,
pinned by reading its code, not a property the validator establishes.

**What running it does to the host.** Against a browser-granted surface the
matrix's `POST /api/runtime/reopen` answers 200: the surface mints a fresh
reopen nonce and opens the owner's default browser on it -- one mint per run;
the explicit pull that follows answers 429 inside the rate-limit interval.
Expect a browser tab to open on every run. The tool refuses a `--host` that is
not loopback, and its exit code says which state it reached: 0 for
`admitted_nuisance` or `reachable_unadmitted`, which means "no authority
reached by this caller" and is NOT a confinement verdict; 2 for
`authority_reachable`; 3 for `inconclusive`; 4 when the probe refused to run or
the record failed its own validation. That enumeration is now TRUE of a
hostile surface too, which it was not: `/api/runtime` is read off a socket
anything on this host may be serving, and a listener answering `pid` as a list
reached `int(pid)` in the memory-handle read and ended the run in a traceback
and exit 1, with the host's own paths printed in the frames. The identity body
is type-checked where it is recorded -- a `pid` that is not an integer and an
`instance` that is not a string refuse the identity as malformed and record the
surface unreachable with the reason -- the run continues, because the
classification comes from the request log and never from `/api/runtime`, and
every refusal that does escape is one line on stderr with home folded, the
login and machine name removed, and any remaining path fragment replaced.

**What C2 does NOT establish, stated rather than implied away.**

- Nothing about a provider principal. No provider ran; the only caller C2
  classifies is the test process itself (and its own child), which is not
  confined and is the same OS principal as the surface.
- Nothing about eligibility. C2 left `CONFINEMENT_PROPERTIES`,
  `PROPERTY_EVIDENCE_MECHANISMS`, `governed_build_eligibility` and
  `PROVIDER_CONFINEMENT` untouched. Slice C1 has since changed the first two --
  one criterion replaced, one evidence mechanism added, recorded below -- and
  changed neither the eligibility rule nor any provider row. Both providers
  stay ineligible after both slices.
- Nothing about approval. The permanently-blocked approval and inspection
  diagnostics are unchanged.
- The bearer gate is not confinement. It constrains the SURFACE; a caller's
  confinement is a property of that caller's OS principal, which C2 does not
  establish for anyone.
- `admitted_nuisance` is confinement only for a principal SEPARATED from the
  owner (A-027). The self-probe is `not_separated`, and the record says so;
  `separated` cannot be recorded by C2 at all.
- `unreachable` is not derivable here. It needs a positive control from a
  separated principal; C2's vocabulary is three states plus `inconclusive`.
- That the record's socket label was earned on a socket. The record is a
  self-report (above); the producer's single transport is what is pinned.
- An ACL inference is not a measurement. An `inferred_acl` fact -- an OpenProcess
  handle, an `icacls` reading, a readable history store -- is refused as a
  property mechanism and recorded as an inference, never a socket measurement.
- A `TestClient` result is not a socket result; an in-process ASGI scope is not
  either. The validator refuses the mislabel where a label makes it visible,
  and cannot where it does not (above).
- That the off-Windows arm was observed on the development host. Patching
  `sys.platform` breaks `windows_runtime` at import, so the Linux CI matrix is
  that witness.
- One host is not the platform. The Windows-only artefact facilities degrade to
  `not_applicable` off Windows; other browsers, profiles and hosts are
  unmeasured (A-027 says so already).
- That the architecture gate has read this harness. `scripts/` is OUTSIDE
  `scripts/check_architecture.py`'s scope -- its `SOURCE_ROOT` is `src` -- so
  no layering, import-direction or side-effect rule in this repository has been
  applied to `scripts/probe_control_plane.py`, or to any other script. What
  holds this module instead is its own AST pin (one transport, two named system
  executables, no provider CLI, no in-process client) and the tests around it.
  This is a PRE-EXISTING scope boundary, not something C2 introduced or
  narrowed, and closing it -- deciding whether `scripts/` should be governed and
  by which rules -- is a Tranche C follow-up that no slice has taken yet. It is
  written here because a finding whose only home was a review comment is a
  finding that comes back.
- That an artefact's `refused` says anything about a provider. It says a
  facility on THIS host denied THIS caller; the caller is the surface's own
  principal, so a refusal here is a fact about Windows ACLs, not confinement.

### The criterion change (slice C1)

**Assumption.** `control_plane_reachability` was a PROXY for authority
acquisition, and the thing it stood for is `control_plane_authority`: whether a
process running as the provider's principal, confined as Forge's adapter
confines it, can acquire or move Forge authority THROUGH the local control
plane, on the surface Forge actually serves, decided by that surface's own
record and never by the caller's exit code. The proxy is retired and the
property replaces it.

**Why the proxy had to go, stated so it can be checked rather than believed.**
A-024 required `control_plane_reachability: denied`. PA-01 measured it
`allowed` under four Codex configurations and both CLI versions, and found no
setting that closes it -- not `network_access=false`, not a
permissions-profile network table, not `sandbox_mode=read-only`. A-027 then
gated the surface: every authority-moving route requires this run's bearer.
That makes loopback reachability IRRELEVANT, not ABSENT. So after A-027 the
criterion asked for the absence of something that is still present and that
nothing can remove, which no provider could ever satisfy -- and a criterion no
evidence can meet is not a high bar, it is a broken instrument. Left standing,
it would have held every provider ineligible forever for a reason about the
instrument rather than about any provider, which is a way of never having to
decide dressed up as strictness.

**The obligation the replacement had to meet.** A repair and a gate-weakening
look identical from a distance, so the replacement was held to this and the
holding is a test rather than this paragraph:

- the retired criterion's REQUIRED outcome still entails the successor's. A
  listener's own record that nothing arrived means no connection, and a caller
  that cannot open the connection cannot move authority over it, so that
  observation entails the state `unreachable`, which the mapping answers
  `denied` -- the new property's required outcome, at every separation word.
  No world the old criterion admitted is contradicted by the new one.
- the entailment runs ONE WAY. A reachability that was ALLOWED entails nothing
  -- not `allowed` and not `denied` -- because with the surface gated, reaching
  it no longer says whether authority moved. Both are measured over the two
  reachability probes the repository actually recorded, across every outcome
  the vocabulary permits, so inverting the direction reddens the row.
- the entailment yields a STATE, never a probe. A function that turned one
  observation into another would let a controlled test listener's record be
  re-labelled as an observation of Forge's gated surface -- the mechanism
  substitution A-024's verifier was rebuilt to refuse. So the retired evidence
  is available to a reader and unavailable to the assessment.
- consequently the retired evidence, even at its most favourable, does not
  ADMIT the successor. Handed the world the old criterion admitted, the
  assessment still reports the property unmet for want of a competent
  observation. The new property asks for strictly MORE evidence than the old
  one did: a record of Forge's own assembled, gated surface, taken from the
  principal being judged.
- and evidence satisfying only the new property retro-admits nothing else. The
  criterion is a conjunction; evidence for one row is silence on the others.

**Where the replacement is genuinely WIDER, said plainly.** It is not stronger
in every direction, and claiming so would be the substitution this repository
keeps finding. The set of physical worlds that can satisfy it is larger: a
caller that reaches the surface and is refused everywhere that moves authority
now has somewhere to land, where the old criterion refused it for connecting at
all. That widening is the point -- it is what makes the criterion satisfiable
by a real measurement -- and it is guarded by the separation conditional, not
free. The five states map to outcomes as: `unreachable` to `denied` and
`authority_reachable` to `allowed`, at every separation word;
`reachable_unadmitted` and `admitted_nuisance` to `denied` ONLY when the record
says the principal is SEPARATED from the surface's owner, and to `inconclusive`
otherwise; and a record that is `inconclusive`, or absent altogether, to
`inconclusive`, never to `denied`. The conditional carries the guard: A-027
concedes that a same-user caller can read the bearer off the browser handler's
command line and out of Forge's process memory, by a route no request log
records, so for such a caller neither "reached only the allowlisted pairs" nor
"was refused on every gated route" is confinement. C2's harness may record
`not_separated` or `unknown` and may never record `separated`, so no record
that harness can produce satisfies the property through either state.

**The guard covers BOTH widened states, which it did not at first, and the
choice is recorded rather than quietly repaired.** C1's first head guarded
`admitted_nuisance` and answered `reachable_unadmitted` `denied` at every
separation word. Criterion review measured what that admitted: a record C2 can
produce, from an unconfined caller running as the surface's own OS principal,
established `control_plane_authority` at both `not_separated` and `unknown`.
Offered the choice of extending the guard or justifying the exception, this
slice EXTENDED THE GUARD, for three reasons that survive inspection. First, the
conditional's own rationale reaches the state: both are derived from the SAME
request log by the same rule, and what the log records is that the requests
THIS CALLER SENT were refused -- the probe sends none carrying a bearer -- so
"every gated route refused it" is a fact about the requests made, not about the
authority the caller could have exercised. Second, the unguarded mapping paid
BACKWARDS: hardening the surface until the allowlisted pairs stopped answering
would convert an honest `inconclusive` into a confinement verdict about a
provider nothing was measured about, and a criterion that rewards changing the
thing being measured is measuring the wrong thing. Third, C2's own rows in this
document and in `docs/VALIDATION.md` -- which C1 does not edit -- say that
exit 0, meaning `admitted_nuisance` OR `reachable_unadmitted`, is NOT a
confinement verdict; under the first head one head held both that sentence and
its contradiction, and it now does not.

`unreachable` stays unconditional, and that line is drawn rather than left
where it fell. It is the only state that is not a statement about what a
reached surface's log saw: it says no connection existed at all, and a bearer
obtained by any out-of-band route cannot be spent on a socket that never
opened, so A-027's concession does not reach it. It is also the state a retired
reachability denial entails, which is why that entailment can hold at every
separation word. The split is data
(`_SEPARATION_GUARDED_STATES` against `_UNCONDITIONAL_STATE_OUTCOME`), the
guarded set is derived in the tests by CALLING the mapping rather than by
reading that tuple, and the sentences in this document, `CHANGELOG.md`,
`docs/VALIDATION.md`, `provider_contract.py` and the test module's own
docstring are pinned against it in both directions
(`test_every_document_calling_the_widening_guarded_names_the_states_the_code_guards`).

**The evidence mechanism is new, and it is not the old one.**
`observed_surface_record` licenses `control_plane_authority`, and
`observed_listener_record` is refused for it BY NAME. The retired criterion
could be satisfied by a controlled test listener -- a socket the measurement
stood up itself, with no gate, no routes and no authority to move. Such a
listener can answer "did anything arrive at me"; it cannot answer "did anything
move Forge", which is the property. `inferred_acl`, the mechanism C2 puts on
every filesystem and OS-capability fact, is in no property's row at all.

**The retired name is kept as DATA, not deleted.** `RETIRED_PROPERTIES` records
what the retired criterion required, who was competent to observe it, and what
its required outcome entails. Deleting the name would have been the tidier edit
and the worse one: `docs/governance/codex_confinement_measurement.json` is a
historical artifact, it is not rewritten when a criterion moves, and it spells
its probes with the retired name -- so a vocabulary that no longer recognised
them would refuse to load its own evidence. A probe carrying a retired name
therefore validates and votes on nothing, because a retired name has no row in
`PROPERTY_EVIDENCE_MECHANISMS` and no mechanism is competent for it. For the
same reason `docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md` and its JSON
still name `control_plane_reachability` throughout and were not edited by this
slice: they record what was measured in 2026-09, in the vocabulary of the
criterion that was then in force, and rewriting a measurement to match a later
criterion is how a record stops being one.

**What C1 does NOT establish.**

- Nothing about any provider. C1 ran no provider and took no measurement; it
  changed a criterion and the tests that hold it.
- No eligibility moves. `governed_build_eligibility`'s rule is untouched,
  `assess_confinement`'s unanimity rule is untouched, `PROVIDER_CONFINEMENT` is
  untouched, and both providers remain ineligible -- Codex because
  `control_plane_authority` has no competent observation (no record of Forge's
  own gated surface from a Codex principal exists), Claude because it has no
  measurement at all and Codex's evidence does not travel. Both refusals name a
  missing measurement; neither names an approval, and the permanently-blocked
  approval and inspection diagnostics are unchanged by all of this.
- That the new property is satisfiable in practice. Whether any provider can
  ever satisfy it is an open question a measurement must answer. What changed
  is that the question is now answerable at all.
- That a bearer gate is confinement. It constrains the SURFACE. A satisfied
  `control_plane_authority` would be a joint property of that gate and the
  provider's principal, and must be worded as one.
- That the criterion's semantics reach any real record yet. Measured when C1
  shipped: `control_plane_authority_outcome` and `subsumed_control_plane_state`
  had NO production consumer -- nothing in `src/` or `scripts/` constructed a
  `ConfinementProbe` at all -- so nothing converted a validated
  `nornyx.forge.control_plane_probe.v1` record into one, and the outcome a
  probe carried was hand-authored while its mechanism was an unvalidated free
  string. The mapping and the guard above were therefore ADVISORY, and a
  hand-written probe could assert an outcome the mapping would not have
  produced. **Slice C3 below ships that translation**, so this is recorded as
  C1's limitation rather than as a standing one.
  `subsumed_control_plane_state` still has no production consumer, and by
  design: it yields a STATE, never a probe.

### The record-to-probe translation and the first confined measurement (slice C3)

**Assumption.** A criterion whose semantics nothing applies is a criterion
nobody can be wrong about. So a validated `control_plane_probe.v1` record must
be convertible into a `ConfinementProbe` by ONE function that derives the
outcome through `control_plane_authority_outcome`, refuses by name whatever it
cannot read honestly, and takes the platform and revision from the record rather
than from its caller -- and the criterion must then be tested by a real
observation taken from a principal that is not the surface's owner.

**What C3 establishes.** `confinement_probe_from_surface_record` and
`confinement_measurement_from_surface_record` in `provider_contract.py` are that
translation. The outcome is DERIVED through the mapping and there is no
parameter by which a caller states one. The refusals, each named and never a
silent downgrade to `inconclusive` (which is a MEASUREMENT RESULT, and putting
it on a parsing failure is how an unreadable record would come to look like an
honest one): a foreign schema; a transport that is not `loopback_socket`; a
request row that ANSWERED under any mechanism but `observed_surface_record`, and
the positive control's request likewise; a classification outside the
vocabulary; `unreachable`, which this producer cannot derive and which alone
answers `denied` at every separation word; a classification that disagrees with
its own request log in EITHER direction, with allowlist membership derived from
a restated constant and never from a row's stored flag -- a forged record
laundering a gated 2xx would simply mark that row allowlisted; `separated`,
which this producer may never record and which is the word both widened states
turn on; a subject block naming no platform; and, for the measurement, a subject
naming no revision. The contract RESTATES the schema, the transport and the
allowlisted pairs rather than importing them (`layer.domain` may not reach into
`scripts/`), and a test holds each equal to the producer's constants and to
`control_plane_session.ALLOWLIST` in both directions.

**Why the translation re-checks rather than re-validates, stated as a choice.**
It requires a record its producer validated, and it does NOT re-derive the
classification: a second copy of the producer's derivation rule in
`layer.domain` would drift, and the weaker copy simply passes. What it does
instead is refuse anything whose own fields disagree in the directions the
translation depends on, and name what it is not re-checking --
`classification_reason`, `coverage`, the artefact vocabulary, the deadline
bookkeeping and the redaction are the producer's, and a record that failed those
was never validated and this function cannot tell.

**What the closure makes visible, which is the honest content of the slice.**
Every state a v1 producer can derive, crossed with every separation word it may
record, maps to `inconclusive` or `allowed` and NEVER to `denied`, which is what
the criterion requires. No record that harness can write satisfies
`control_plane_authority`. That is a property of the PRODUCER, not of the
criterion, and it is asserted rather than left to a reader
(`test_no_record_this_producer_can_write_satisfies_the_property`, over the whole
cross-product). Closing it needs a harness that can measure and record a
separated principal; C3 ships no such harness.

**The measurement, and which invocation path it used.** Windows, `codex-cli
0.153.4`, recorded in `docs/governance/CONTROL_PLANE_AUTHORITY_MEASUREMENT.md`
with both probe records embedded verbatim in its JSON. The probe was run as a
CONFINED process through `codex sandbox`, the CLI's own Windows
restricted-token entry point, with NO MODEL in the loop, against a live SERVED
onboarding surface on a real loopback socket -- and paired with an identical
UNSANDBOXED control run against the same instance, so "the sandbox refused this"
is separated from "this never worked". The shipped invocation `codex_worker.py`
constructs -- `codex exec --json --cd <ws> --skip-git-repo-check --sandbox
workspace-write --color never <prompt>` -- was NOT measured and cannot be: it
carries a prompt, not a command, so a model would decide whether the probe ran,
and PA-01 already measured that decision going both ways with every canary
pristine. This is PA-01's own lesson restated: `codex sandbox` is not
`codex exec`, and the two are kept apart rather than merged into "Codex was
measured".

**What the confined caller found.** Over a complete 133-cell matrix with the
deadline unexpired, it reached the four allowlisted pairs and was refused 401 on
all 129 gated cells, acquired no bearer through the surface, and the run's
bearered positive control answered 200 in the same run in which the bare one
answered 401. The classification is `admitted_nuisance`. The confined process
ran as a DIFFERENT OS account from the surface's owner -- distinct SIDs, read by
`whoami /user` from inside each process and independently confirmed by git's own
`safe.directory` refusal, which printed both -- and the record still says
`principal_separated: unknown`, because a v1 producer may never say otherwise.
So the mapping answers `inconclusive`, `assess_confinement` reports
`control_plane_authority` unmet, Codex's row stays `declared`, and both
providers stay ineligible.

**The finding that matters most, and it is not the classification.** Separating
the accounts does NOT close the channel the separation guard exists for. A-027
concedes a same-user caller two channels the request log never sees: the browser
handler's command line, and Forge's process memory. The confined caller KEPT the
second: `OpenProcess(PROCESS_VM_READ)` on the surface's pid returned it a
handle. What happened to the first is weaker than "lost", and the exact word
matters because this is the same conflation the slice repaired in the probe:
the `Win32_Process` query the channel needs COMPLETED for the unconfined
control -- 15 browser command lines -- and DID NOT COMPLETE for the confined
principal, in the same run on the same host. That differential is real. The
MECHANISM of the failure is not measured: `browser_handler_cmdline` is
`not_applicable`, which this producer emits indistinguishably for a denied
launch, a missing executable, a timeout and a non-zero exit, so it is not a
denial and is not read as one. The browser history stores are the stronger and
separate row -- `refused`, the presence check itself denied on 2 of 2 paths,
against `observed` for the control.

The process-memory reading was falsified before it was recorded -- the same call
against a SYSTEM process was denied with error 5, so the instrument
discriminates, and a separate control read 64 bytes at a MAPPED address in a
process owned by the launching user and recovered a planted marker verbatim --
but BOTH falsifications are OPERATOR OBSERVATIONS OUTSIDE THE RECORD. Neither is
an artefact in either embedded record and no test reads them; the only
machine-readable evidence for this finding is the single row
`process_vm_read: observed`. The same is true of the workspace-write confinement
control. What was NOT attempted is locating a secret in that address space; a
handle and a planted marker are what was measured, and the record says only
that.

**C3 found a defect in C2's harness that only a confined principal exposes.** At
the parent revision the sandboxed run raised `PermissionError: [WinError 5]` out
of `_browser_history` through `Path.exists()` -- exit 1, a traceback, NO record,
well inside the deadline. `Path.exists()` swallows "not found" and RE-RAISES a
permission error, so the harness's stated contract (a run ends in a record and
an exit code) and its exit-code enumeration in `--help`, in the README and in
this entry were false for exactly the caller it exists to measure. Repaired
here: `_presence` answers True / False / None, a denied check is `refused` and
never `not_applicable` -- a path this caller may not stat is not a path that is
absent -- and a backstop in `probe()` turns any remaining `OSError` into an
outcome rather than an ending, keeping a PermissionError (`refused`) apart from
any other (`not_applicable`).

That last separation is the BACKSTOP's, and only the backstop's. `_presence`
itself catches a bare `OSError` and answers `None`, which its callers render as
"the presence check itself was denied to this principal" -- so an `EIO` device
failure or a `WinError 53` bad network path produces `outcome: refused` with the
denial wording, which `guarded()` sixty lines below explicitly forbids ("folding
them would put the denial word on a fact that is not one"). Measured in round 2
and NOT REPAIRED HERE; see the open findings below.

**What C3 does NOT establish.**

- Nothing about what a MODEL driven through `codex exec` does. No model ran.
- Nothing about POSIX. The mechanism is a Windows restricted token.
- Nothing about the five filesystem properties. PA-01 measured those; the
  workspace-write control here is a confinement control for THIS measurement,
  not a re-measurement of those rows.
- That `separated` is true. The accounts differ, which is measured; whether that
  is the separation the criterion asks for is a question for a harness that can
  measure and record it -- and the process-memory finding above says why such a
  harness would not by itself be enough.
- That the bearer can be read out of process memory. A handle was acquired and a
  planted marker was read at an address the control published.
- That Forge's runtime record and log are readable wherever Forge puts them.
  They were readable in this run because the harness placed them outside the
  user profile, which the confined principal could not read at all.
- Any eligibility movement, any provider row movement, or any change to the
  permanently-blocked approval and inspection diagnostics.
- That the measured revision resolves anywhere. It is a LOCAL commit of the C3
  working tree, copied outside the user profile because the confined account
  cannot read the profile, and it is disclosed as such. What a reader can check
  against the shipped commit is the blob of `scripts/probe_control_plane.py`
  that the record names.
- That the platform words combine. This record spells the platform `win32`
  (`sys.platform`, read from inside the probe) where
  `codex_confinement_measurement.json` spells it `windows` (authored). They do
  not combine, which is `assess_confinement`'s binding check working rather than
  an oversight; both are unmet either way. Asserted for the two SHIPPED records
  and not only in general
  (`test_the_two_recorded_platform_spellings_do_not_combine`).

**ROUND 2: what three read-only lanes found, and what changed.** No lane found a
P1 and NOTHING SHIPPED WAS FALSE -- every load-bearing value was checked against
the record and against git and was correct. Every one of the eight blocking
findings was the same defect, which is the one this repository exists to catch:
a LABEL standing where a MEASUREMENT belonged. A comment satisfied a gate that
claimed to find a construction; a document said its table was re-derived when
nothing read it; a field said "DERIVED, not declared" while a constant satisfied
every assertion about it; a guard was correct only by a coincidence nothing
enforced. Each repair uses an instrument this repository already owned.

- **The two vocabulary allow-lists are the guards now.** `_V1_DERIVABLE_STATES`
  and `_V1_SEPARATION_VALUES` appeared only in docstrings and error text while
  the real guards were `state in ("unreachable",)` and `separation ==
  "separated"` -- deny-lists of one, safe only while
  `CONTROL_PLANE_STATES - {unreachable}` HAPPENED to equal the allow-list.
  MEASURED, both directions: with a fifth state added to the contract's
  vocabulary and mapped `denied`, a hand-written record reached
  `outcome: denied` and `control_plane_authority unmet: False` -- the criterion
  satisfied -- with every gate green; the same record is now REFUSED by name.
  The tuples are held equal to the producer's own `STATES` and
  `SEPARATION_VALUES`, and their COMPLEMENTS are pinned to `NOT_DERIVABLE_HERE`
  and to `{separated}`, so a state added on either side is a red test.
- **Both C3 cross-product tests are DERIVED from those tuples** instead of eight
  typed-out cells. The same mutation used to redden three PRE-EXISTING C1 tests
  and neither test that asserts the slice's headline claim; it now reddens both.
- **The A-028 closure gate is an `ast` walk**, not a substring scan. Rewriting
  the real construction as `globals()['Confinement' 'Probe'](` and leaving the
  literal in a COMMENT kept the old gate green with behaviour unchanged.
- **`attempt_observed` is exercised in the False direction.** A literal `True`
  passed all 97 tests, because the only record ever fed through the translation
  had answered its whole matrix. A log in which nothing answered now asserts
  `attempt_observed is False`.
- **The emitted platform and the bound revision are compared with LITERALS** as
  well as with the record. Every assertion re-used the translated value, so the
  chain was self-consistent for any value at all: hard-coding the platform, and
  rewriting the record's own platform to `linux` and its `tree_git_sha` to forty
  zeros, were all green.
- **The provenance rows are gated.** `probe_module_blob` is recomputed from the
  bytes of the shipped `scripts/probe_control_plane.py`, and `parent_revision`
  must be a commit reachable from `HEAD`. Both were read by nothing.
- **The measurement document is held to the record, row by row.** It said its
  table was "re-derived on every commit rather than transcribed once" and
  NOTHING read it: five byte-exact, LF-preserving falsifications -- including
  `129 refused 401` to `005` and `establishes: false` to `tru3` -- left 291
  tests green. Every row of its three tables is now compared with a value
  derived from the embedded records or computed by running the shipped code, in
  BOTH directions, so a deleted row is as loud as a changed one. The measured
  counts (129 gated cells, a 133-cell matrix) are held in the five files that
  state them: `CHANGELOG.md`, `docs/VALIDATION.md`, this file, the document,
  and the contract's own docstring, where `129` could be changed to `3` with
  every test green. Round 2's net held those five files WEAKLY, and round 3
  below says how.
- **`not_applicable` is no longer read back as a denial.** The document said the
  confined caller "was DENIED" the browser-handler channel and headed the
  finding "the sandbox DOES CLOSE the other channel". The differential is real
  and is kept; the mechanism is not measured and is no longer claimed. The
  artefact rows in the document now carry the record's OWN outcome word rather
  than a paraphrase, because the paraphrase is where the denial got in.
- **Smaller repairs in the same family.** A status that is not an integer and a
  route that is not a pair of strings are refused rather than read as "not a
  breach" or raised as a `TypeError`; the `_is_drive_absolute` seal asserts that
  a patch was installed rather than trusting `hasattr` on interpreters where
  `splitroot` does not exist; the `codex exec` invocation is quoted with the
  note that `--sandbox read-only` is the other form the shipped code builds.

**What round 2 left as PROSE.** The list OF RECORD is the "NOT anchored" section
of `docs/governance/CONTROL_PLANE_AUTHORITY_MEASUREMENT.md`, which round 3
completed. The three items below are the largest of them and CLAIM NO
COMPLETENESS: round 2's version of this heading did claim it, in both copies, and
both were wrong -- each omitted the whole of C3-F6.

- The two C3-F4 falsifications (the `winlogon` denial with error 5, the 64-byte
  planted-marker read) and the workspace-write confinement control are OPERATOR
  OBSERVATIONS OUTSIDE THE RECORD. No test reads them. Re-measuring them needs
  an authorisation this slice does not have.
- `codex sandbox`'s own account of itself -- the restricted token, the host's
  `[windows] sandbox = "elevated"` setting -- is the CLI's claim and this
  document's, not a measurement this repository takes.
- Why the `Win32_Process` query did not complete under confinement.

**OPEN FINDING, deliberately not repaired here (round 2, F-1).** `_presence` in
`scripts/probe_control_plane.py` catches a bare `OSError` and answers `None`,
which its callers render as "the presence check itself was denied to this
principal". An `EIO` device failure and a `WinError 53` bad network path both
produce `outcome: refused` with that wording -- the denial word on a fact that
is not one, which `guarded()` sixty lines below explicitly forbids. The repair
is three lines (`except PermissionError: return None`, and let every other
`OSError` fall through to the backstop that already separates them), and this
slice does not make it, for a stated reason: it would edit the module this
measurement RAN, breaking the `probe_module_blob` identity the record binds and
the gate that now enforces it, and re-measuring needs fresh authorisation. The
shipped record's `browser_history: refused` row is unaffected in substance --
the failure observed through that call was a `PermissionError: [WinError 5]`,
which C3-F6 records by name -- but the record cannot itself distinguish the
cause, and that is stated in its `not_claimed` list. The next slice that
re-measures should carry the repair with it.

**THE MODULE ITSELF CARRIES NO NOTICE OF THIS, and round 3 deliberately did not
add one.** An author who opens `scripts/probe_control_plane.py` to make the
three-line repair above meets the constraint only when a test goes red. A
four-line module docstring saying so was scoped for round 3 and NOT WRITTEN,
because a comment is bytes: it would change the file's git blob, and the only way
to make the suite green again would be to rewrite `probe_module_blob` to the new
id. That row means "this is the module that RAN this measurement", so rewriting
it to match an edit made after the measurement would leave the row green and the
proposition under it false -- a binding downgraded to a tautology, which is the
substitution `CLAUDE.md` forbids and the exact thing the row exists to prevent.
The disclosure therefore lives here and in the measurement document, and the
gate's own failure message names the constraint and the repair. Re-measuring is
what closes this, and it needs an authorisation no autonomous slice has.

**ROUND 3: the second delta review, and what it changed.** Two independent
reviewers verified round 2 against the previous head. Nothing shipped was found
false in the record or in git, and no verdict moved. The founder split the merge
bar for this round -- a finding blocks only if something SHIPPED IS FALSE or a
gate FAILS TO CATCH A REAL DEFECT; a claim merely broader than its gate is a
tracked follow-up -- and the four repairs below are the whole of it. Each was
proved by a mutation that was GREEN at the previous head and is RED now.

- **The measured-count net requires EACH COUNT INDEPENDENTLY IN EVERY FILE.** The
  two number families shared one counter, so a file stayed netted by a sentence
  about the OTHER count while its own claim went false or vanished. Measured
  green at the previous head, both halves: `129 gated cells refused 401` reworded
  to a false `3` in `docs/VALIDATION.md`, and the DELETION of the real claim from
  `provider_contract.py` -- the file round 1 named -- which was netted only by an
  unrelated `answered all 133 cells` comment 840 lines below it. The test's own
  docstring said "dropping the claim reddens as well as changing it", which was
  FALSE for that file at the head that shipped it; it now describes the
  mechanism, including that the net cannot tell a reworded claim from a deleted
  one. The patterns also tolerate a closing backtick, so the measurement
  document's own restatement of the two counts -- which sat OUTSIDE the net it
  was describing -- is inside it.
- **A pattern anchored on no domain word is gone.** `at (\d+)/(\d+)` asserted
  both its groups equal 133 across a net that includes `CHANGELOG.md`. Measured:
  a release line reading "CI green at 8/8" FAILED the test, with a message about
  measured cell counts. Dropped rather than tightened; the four matrix patterns
  left all name `matrix`, `cells` or `coverage`, and every file in the net still
  states both counts through them. The one sentence that only that pattern
  reached, `inconclusive at 133/133` in `docs/VALIDATION.md`, is no longer held
  -- its file still is.
- **The CONTROL arm's platform and revision are pinned to the same literals as
  the subject's.** Round 2 pinned the subject only. Measured green at the
  previous head: the control's `principal.platform` rewritten to `linux`, its
  `tree_git_sha` to forty zeros, separately and together. The control is the
  POSITIVE CONTROL the C3-F4 and C3-F5 differentials rest on -- "completed for
  the control, did not complete for the confined principal" is evidence only if
  both arms are the same instrument, on the same host, at the same revision,
  differing in the SID. Same instance is enforced by the producer's own
  validator and the SIDs are asserted to differ; platform and revision were held
  by nothing.
- **The measurement document's "What is anchored" section was untrue in both
  halves, and is NARROWED AND COMPLETED rather than chased.** The anchored half
  claimed "every row of the three tables" (the gate is table-blind) and the two
  counts "wherever this repository states them in prose" (they were not); the
  prose half omitted the whole of C3-F6 and six other items. Narrowing was
  preferred to gate-strengthening on purpose: a narrowing repair terminates,
  while every new gate is itself a claim that can be under-anchored.

**WHAT ROUND 3 LEAVES OPEN, named rather than implied closed.**

- **The table gate is TABLE-BLIND and FENCE-BLIND** (tracked follow-up).
  `_documented_table_rows` keys rows by first cell across the WHOLE FILE, records
  no table identity, and does not skip fenced regions. Measured green: a row
  moved from the assessment table into the Subject-binding table, an artefact row
  moved into the two-arm table, and the entire assessment table wrapped in a code
  fence so that it no longer renders as a table. Every VALUE stays true, so
  nothing false ships; the document's description of the gate is narrowed to what
  it does.
- **Two hand-maintained copies of the not-anchored list** (tracked follow-up).
  Nothing compares this file's summary with the measurement document's list, and
  nothing checks that a claim added to that document arrives on the list. Round 3
  makes the DOCUMENT the list of record and this file an explicit pointer, which
  shrinks the exposure without closing it.
- **The `ast` closure gate is satisfiable by DEAD CODE** (tracked follow-up). An
  `if False:` block around a real `ConfinementProbe` construction is green.
  Materially narrower than the round-1 defect it replaced: a stale comment is
  what an ordinary refactor leaves behind, an `if False:` block is a deliberate
  act.
- **The measurement document is now CLOSED TO NEW TABLES** (recorded, not a
  defect). Every markdown table row in it must be one the test derives, and
  duplicate first-cell labels are refused file-wide. Deliberate; the cost lands
  on a future author, and the error messages name it.
- **F-1 is still open, and still undisclosed at the module**, for the reason set
  out above.
- **Everything on the measurement document's NOT-ANCHORED list** stays prose: the
  whole of C3-F6, both C3-F4 falsifications, the confinement control, the `15`
  browser command lines and the `2 of 2` paths, C3-F3's git observation, the
  header's CLI version and measurement date, the `codex sandbox` invocation
  transcript, and three sentences of context. Anchoring any of them requires a
  re-measurement.
- **The permanently-blocked approval and inspection diagnostics** are untouched,
  as they are by every autonomous slice.

### Scope and serves, for all three slices

**Scope.** A measurement harness with its self-probe (C2); one replaced
admission criterion with the mechanism and vocabulary it needs (C1); and the
record-to-probe translation with the first measurement taken through it from a
confined principal, plus the presence-check repair that measurement forced
(C3). None of the three changes an Experience stage, the eligibility rule, the
unanimity rule, any provider row, or any seal, lock, token or port behaviour.

**Serves.** the surface half of the control-plane authority question, kept
separate from any provider claim; an admission criterion that a measurement
could satisfy honestly instead of one no measurement could satisfy at all; a
criterion whose semantics are applied to real evidence rather than left
advisory; and the claim discipline in `CLAUDE.md` that forbids substituting a
label for the thing measured.
