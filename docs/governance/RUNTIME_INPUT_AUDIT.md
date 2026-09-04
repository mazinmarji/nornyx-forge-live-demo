# Runtime external-input audit (R1 step 1)

Every external input reachable from `src/`, classified as authority-bearing or
not. An input is authority-bearing if mutating it can change a consequential
authorization decision. Non-authoritative inputs need a stated reason and a
negative test proving mutation cannot alter authorization.

Scanned for: `read_text` / `read_bytes` / `open(` / `json.load` / `yaml.safe_load`
/ `tomllib` / `importlib.resources` / `getenv` / `os.environ` / `sqlite3.connect`.

## Authority-bearing — must be covered or immutably bootstrapped

| Input | Site | Disposition |
| --- | --- | --- |
| `.nyx` contract read | `nornyx_runtime.py` | Covered by `SubjectScope.required_contracts`. The reader itself (`runtime_revision`) is removed in R1 step 2. |
| Approval ledger path from env | `nornyx_runtime.py` (`FORGE_APPROVAL_LEDGER`) | **Closed (R3).** Resolved once into `TrustConfiguration` at `bootstrap_security_context`, frozen, and injected. |
| Approval ledger SQLite | `nornyx_runtime.py` (`ApprovalLedger`) | **Closed (R3).** `CREATE TABLE IF NOT EXISTS` on every construction meant deleting the file emptied the ledger and made every spent grant replayable. Provisioning is now a separate operator command (`nornyx-forge provision-ledger`); a missing ledger denies, a corrupt one raises as unavailable. |
| Trust store path from env | `approval_trust.py` (`FORGE_APPROVER_TRUST_STORE`) | **Closed (R3).** Resolved once into `TrustConfiguration` and injected into the boundary. |
| Trust store contents | `approval_trust.py` | Deliberately outside the tree, so not subject content. Its *resolution* must be immutable (R3); its contents are the trust anchor. |
| Reviewer trust store path from env | `reviewer_trust.py` (`FORGE_REVIEWER_TRUST_STORE`) | **Closed (R3).** Resolved once into `TrustConfiguration`. The evidence tool still loads by path directly — it is a build-time utility outside the runtime trust boundary, not a request-serving surface. |
| Reviewer trust store contents | `reviewer_trust.py` | Outside the tree by design, so not subject content — editing the repository cannot add a trusted reviewer. Absence is an ordinary state (nothing authenticates); malformation raises, so the two cannot be confused. |
| Builder identity from env | `reviewer_trust.py` (`FORGE_BUILDER_IDENTITY`) | **Closed (R2/R3).** It replaced the identity independence was measured against, so naming another builder excused the real one. It is a union now — ambient input adds an excluded identity and can never remove one — and the resolved set is frozen into `TrustConfiguration`. |
| Application root from env | removed (`FORGE_ROOT`) | **Closed (R1).** The application derives its root structurally through `resolve_packaged_root()`. No reader remains under `src/`; the vestigial setters in `scripts/smoke_http.py` are removed too, since a variable nothing reads still tells a reader it matters. |
| Policy fallback toggle | no reader under `src/` | **Closed (R1/R5).** `FORGE_ALLOW_POLICY_FALLBACK` has NO READER: a repository-wide grep returns retirement comments only, and the line numbers this row used to cite (`agentic.py`) do not contain the name. Retired vocabulary, not ambient authority. The `allow_policy_fallback` ARGUMENT that remained on `run_case` was accepted and discarded, and is deleted. |
| `reviews.json` | `development_flow.py` | **Closed (R4).** Two claims came off a gitignored, builder-written file: acceptance was gated on `builder_self_approval is False` (the builder certifying their own independence), and `independent_ai_review` was `bool(reviews)` (a non-empty list of subprocesses standing in for a verdict). Neither is read now. The gate checks completeness and outcome only, and reports `independent_ai_review: not_established`. |
| CrewAI backend toggles | no reader under `src/` | **Closed (R5).** `FORGE_USE_CREWAI_KICKOFF` / `FORGE_STRICT_CREWAI` have NO READER either, and the cited lines do not contain them. The backend is selected from `RuntimeAuthorityConfig.execution_backend`, and selecting `crewai` where CrewAI cannot be imported RAISES rather than downgrading under an unchanged label. |

## Non-authoritative — reason required, negative test owed

| Input | Site | Why non-authoritative |
| --- | --- | --- |
| Case store JSON | `store.py` | Application data. Cannot reach an authorization decision: the boundary derives risk from the canonical request, not from stored cases. Negative test owed. |
| Build summary JSON | `main.py` | Presentation only, served at `/api/build`. **R4** must prove forging it changes no authorization or assurance result. |
| Evidence ledger | `evidence.py` | Append-only output, downstream of decisions. Note: lens 2 found `validate()` does not detect truncation — R7. |
| `GITHUB_TOKEN`, network | `repo_qualifier.py`, `repo_scout.py` | Build-time repository qualification. Not reachable from the consequential runtime path. Negative test owed. |
| BRD / requirements text | `requirements.py`, `util.py` | Build-time authoring inputs; BRD.md is covered by both scopes as subject content. |
| Telemetry env defaults | `agentic.py`, `development_flow.py` | `setdefault` on CrewAI/OTel telemetry switches. No authorization path. |
| `--bundle-root` argument | `windows_runtime.py` | The launcher's own folder, passed explicitly. Not trusted: the runtime refuses unless `resolve_packaged_root()` names the same directory, so the argument can only agree with the structural root or cause a refusal. Pinned by `tests/test_windows_runtime.py`. |
| `forge-bundle.json` marker | `windows_runtime.py` | Names which KIND of folder this is (self-contained or developer). A forged marker can only make a launch refuse or run a developer bundle on the interpreter it was given; it reaches no project state. Negative test held. |
| Runtime record, lock and log under `~/.nornyx/forge/runtime` | `windows_runtime.py` | Operational: is the local Windows runtime running, on which port, with which token. Written by the lock's owner, read by a later launch, never by the onboarding surface. A forged record changes nothing `/api/state` reports, which is pinned. |
| `USERPROFILE` (through `Path.home()`) | `windows_runtime.py`, `windows_launch.py`, `capsule_store.py` (seal directory), `Forge.cmd` (project directory) | The person's own places. Selects where their project, seals and runtime state live; selects neither which Forge runs nor another person's project without the operating system having changed the user. Disclosed in A-023 as the one ambient input that selects a location. |
| `--project-dir`, `--runtime-dir`, `--port`, `--no-browser`, `--readiness-timeout` | `windows_runtime.py` | Explicit console decisions; relative directories are refused, and a runtime directory inside the project or the seal directory is refused. The port is a preference the operating system may override, recorded rather than assumed. |
| `PATH` | `windows_runtime.py` (`shutil.which("git")`), `Forge.cmd` developer launcher (`where pyw`, `pyw -3`, which itself reads `PY_PYTHON*` and `py.ini`) | Refusal-only in the runtime: an absent git refuses the launch by name and selects nothing. In the developer launcher it selects the installed Python for the developer arrangement -- never Forge code, which the bootstrap places first under `-I`. Both launchers set `NoDefaultCurrentDirectoryInExePath` so the launch directory is not searched before PATH (measured: a planted `pyw.cmd` otherwise ran). A self-contained launcher names one full path and consults PATH for nothing. |

## Findings that change R1 scope

All three findings recorded here are closed. Retained rather than deleted:
the reasoning is why the current design looks as it does, and a resolved finding
that vanishes teaches nothing.

1. **`FORGE_ROOT` was ambient authority over subject identity.** Closed by
   `resolve_packaged_root()`, which derives the root structurally. Nothing under
   `src/` reads the variable, and the setters that remained in tooling are gone.

2. **Two env vars steered governance behaviour.**
   `FORGE_ALLOW_POLICY_FALLBACK` and `FORGE_STRICT_CREWAI` are closed by
   `RuntimeAuthorityConfig`, which names the policy and execution backends at the
   command boundary and is bound into the subject digest. Neither has a reader.

3. **Trust store and ledger paths were read per use.** Closed by
   `TrustConfiguration`, resolved once at `bootstrap_security_context` and
   injected into the boundary.

4. **The established context had no production caller.** `bootstrap_security_
   context()` was reached only from tests, so every real flow ran with
   `security_context=None` and the boundary resolved its own trust anchors per
   use — the exact per-use resolution finding 3 claims to have closed. Closed by
   establishing one context at application import (`demo_app.agentic`), binding
   it at the HTTP surface, and defaulting `run_case` to it. Proven by identity
   rather than equality in `tests/test_production_security_context.py`: two
   independently bootstrapped contexts over an unchanged tree compare equal on
   every digest, so an equality assertion would pass on the architecture being
   prevented.

5. **Deleting the replay ledger restored spent grants.** A recreated table is
   correct in every respect except that it has forgotten, so schema checking
   could not see it. Closed by recording `established_at` when the history
   begins and refusing any grant issued before it: DELETING the history now
   makes outstanding grants *unusable* rather than reusable. Restoring a backup
   is a different case that the anchor cannot see -- it is caught by the
   consumption high-water mark instead. See the residual below.

## Residual exposure — replay continuity under ledger write access

Stated rather than implied, because the limit of a control is part of what it is.

`established_at` is stored in the ledger it anchors, so it defeats DELETION and
cannot defeat RESTORATION. A file that is gone is re-provisioned at a later
epoch and every outstanding grant then predates it. A file restored from a
backup brings the old epoch back alongside the emptied rows, and that pair is
indistinguishable from a ledger set up early and not yet used — so the anchor
agrees the grant is fresh and releases it again.

This section previously claimed the opposite. An independent review measured
one human approval releasing **five** effects across ordinary backup restores,
and I reproduced it: no adversary, no write access beyond copying a file back,
and the documented recovery command (`nornyx-forge provision-ledger`) does not
detect it, because preserving the original instant on re-provision is
deliberate and separately tested.

What catches restoration is a consumption **high-water mark** kept beside the
ledger rather than in it (`<ledger>.highwater`). Consumption rows only ever
accumulate, so a ledger holding fewer rows than were recorded against it has
lost history, and `consume` refuses with `LEDGER_ROLLED_BACK`.

**Ordering is no longer the mechanism, and this paragraph used to say it was.**
It read: "The mark is read before the row count, never after, so a
concurrent consumption cannot make a legitimate grant look like a
rollback." At this head the order is the opposite -- rows are counted
first, at `nornyx_runtime.py`'s `count(*) FROM consumed_approvals`, and the
witness is read after it. The runtime source flags the old argument as
superseded in as many words: it "was sound about ORDERING and silent about
what actually broke".

What protects the comparison now is that **both values are read inside the
single `ATTACH`ed transaction that writes them**, under `BEGIN IMMEDIATE`
with a rollback journal, where they are required to be EQUAL. Ordering
within that transaction cannot matter, because nothing else can interleave.

This mattered as more than pedantry: an engineer restructuring
`_commit_consumption` for performance could have PRESERVED the documented
property -- read the mark first -- by splitting the two reads onto separate
connections, and reintroduced the defect the source records as measured at
8 of 45 kill points. The document would have licensed the regression.

What remains open, named precisely:

- Restoring the **whole runtime directory** carries the sidecar back with the
  ledger, and both agree again.
- Deleting the sidecar does **not** disable the check. This section used to
  say it did. Measured at this head: roll the ledger back, delete the sidecar,
  then replay a spent grant — `claimed False`, `LEDGER_CONTINUITY_UNKNOWN`. A
  missing witness fails **closed**. The runtime's own note beside
  `LEDGER_WATERMARK_SUFFIX` records the same measurement, and
  `test_deleting_the_sidecar_after_a_rollback_still_refuses` pins it.

Both need write access to the runtime directory, which is the exposure this
section already described. What changed is that the ordinary operator action —
restore the ledger file from a backup — now fails closed.

That residual is **closed**, and this paragraph is kept as the record of what
it used to claim. It described a process death between a consumption row
committing and the mark write beside it — a two-step write performed by
`_record_consumptions`. Measured at this head: `_record_consumptions` and
`_recorded_consumptions` have **zero call sites in `src/`**, and `consume`
commits the row and the mark in one `ATTACH`ed transaction through
`_commit_consumption`. The WAL precondition it named is enforced rather than
assumed — both stores in WAL gives `LEDGER_CONTINUITY_MIGRATION_REQUIRED`
and no release.

What remains open is stated in the runtime source and measured in both
directions: restoring the **whole runtime directory** carries both stores back
together, they agree at the old count, and a grant spent after the backup
releases again. That is the honest limit of a two-store design against an
adversary who can restore the directory, and
`test_a_whole_directory_restore_is_the_disclosed_limit` pins it in the
affirmative so that closing it later forces this paragraph to be rewritten.

| Scenario | Before | Now |
| --- | --- | --- |
| Ledger deleted, documented provisioning re-run, old grant presented | released the effect a second time | `GRANT_PREDATES_LEDGER`, and a **fresh** approval issued after the new epoch works normally. The route out is plain `provision-ledger`. Measured at this head: spend a grant, delete only the ledger file, run the real CLI — rc 0, rows 0, mark 0, a new epoch — then the old grant gives `GRANT_PREDATES_LEDGER` and a fresh one releases. `ApprovalLedger.provision` mints a fresh mark when the ledger file is absent, which is what makes this recoverable. |
| Ledger deleted **and an empty file recreated** before provisioning | as above | `LEDGER_ROLLED_BACK` on a fresh approval, because the mark beside it still records history the rows no longer have. This is the state the row above used to describe, and the one that needs `provision-ledger --reset-replay-history`. |
| Ledger **restored from a backup**, spent grant presented | released it again, once per restore | `LEDGER_ROLLED_BACK` |
| Redeploy onto ephemeral storage | silently empty history | outstanding grants refused until reissued |
| Approval carrying no issuance instant | continuity check skipped entirely | `GRANT_ISSUANCE_UNKNOWN` |
| Ledger with no, or more than one, establishment row | first row silently chosen | `LEDGER_CONTINUITY_UNKNOWN` |
| Whole runtime directory rolled back | released it again | **still released** — stated bound, not covered |

**Line numbers removed from every citation.** A review measured 8 of 12
`file:line` references pointing at something other than what they cited --
`nornyx_runtime.py` at a docstring, `approval_trust.py` at a constant while the
env read was 266 lines away, `reviewer_trust.py` at `return reviewers`. This
document's own Corrections section already called stale citations a defect for
two other rows, so it was doing the thing it names.

Line numbers in prose go stale on the next edit and nothing checks them, which
makes them a claim the repository cannot keep. The file is cited instead: a
reviewer greps for the symbol, and a grep does not drift.

## Corrections from an independent review

**The two rows without a Closed disposition read as live holes, and are not.**
`FORGE_ALLOW_POLICY_FALLBACK`, `FORGE_USE_CREWAI_KICKOFF` and
`FORGE_STRICT_CREWAI` have NO READER anywhere in `src/`: a repository-wide
grep returns only retirement comments. The line numbers those rows cite are
stale and point at unrelated code. Finding 2 in this same document already
says neither has a reader, so the table contradicted its own body. Treat both
rows as CLOSED -- retired vocabulary, not ambient authority.

**`FORGE_MAX_REPAIR_ATTEMPTS` was missing from a table claiming to be**
**exhaustive.** It is read at `src/nornyx_forge/development_flow.py:228` as
`int(os.getenv("FORGE_MAX_REPAIR_ATTEMPTS", "3"))`, and it is ambient
authority over a declared bound: BOOTSTRAP.md permits "at most three repair
attempts per failed goal", with an exhausted budget as a hard stop. An
environment variable that raises that ceiling changes a governed limit.

Unlike the process-start enumeration in `docs/ARCHITECTURE.md`, nothing
measures this table in either direction, so "every external input reachable
from src/" remains an author's claim rather than a checked one. Recorded as a
known bound rather than asserted as complete.
