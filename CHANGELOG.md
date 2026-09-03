# Changelog

## Unreleased — hardening from adversarial review

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
