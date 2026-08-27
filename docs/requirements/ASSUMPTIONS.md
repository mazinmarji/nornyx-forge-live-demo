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
