# Documented assumptions

Assumptions recorded during the autonomous demonstration run, as required by
`CLAUDE.md`. Each entry states the ambiguity, the resolution taken, and the BRD
requirement it serves. None of these invent a regulatory or business requirement.

Run subject revision: `git:8a8fea6ac5068a6a359dfc407489264576329054`
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
(`human:repository_maintainer` authors, `human:architect` approves). This
declares *who would be accountable*; it does not assert that either party acted.
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
- a run that needs determinism pins the instant with the `FORGE_RUNTIME_AS_OF`
  environment variable or an explicit argument;
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

## A-011 Subject revision is read from the contract

**Ambiguity.** The governed revision was duplicated as a constant in code and as
`subject_revision` in the contract, so the two could silently drift — and did.

**Resolution.** `runtime_revision()` reads `subject_revision` from
`.nornyx/contracts/runtime_network.nyx`, making the contract the single source of
truth. With no contract present it returns `git:unbound` so evidence is honestly
labelled instead of claiming a binding that does not exist.

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
