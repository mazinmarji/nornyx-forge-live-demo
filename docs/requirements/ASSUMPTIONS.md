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
and the run it measures remains NOT PERFORMED. Windows-hosted automated evidence
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
nowhere, so a stale file authenticates nothing, visibly. The fence resolves
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
