# Architecture

## Components

- `nornyx_forge.cli`: operator surface and the toolchain's application layer — each
  command body composes a sequence, and no other module coordinates that.
- `repo_scout` / `repo_qualifier`: foundation discovery and qualification.
- `development_flow`: CrewAI Flow orchestration of in-session or scripted Claude Code work and deterministic gates.
- `contract_generator` / `requirements`: deterministic BRD parsing and BRD-to-Nornyx repository-harness generation.
- `claude_worker`: optional bounded `claude -p` execution bridge for scripted mode.
- `gates`: deterministic gate-profile selection and execution. Certified Forge
  repositories retain the repository profile; `repo_mode="greenfield"` selects
  the Forge-owned greenfield profile in trusted flow code.
- `greenfield_verifier`: standalone inspection of an untrusted generated
  project. Forge digests its installed bytes, reads a private copy once through a
  digest-checking in-memory bootstrap, executes those same bytes with an absolute
  Python environment entrypoint in isolated mode, and supplies no inherited
  `PATH`, `PYTHONPATH`, or `PYTHONHOME`. Static checks stream bounded subject
  files without retaining the corpus. Tests run in a separate process over a
  private subject copy under an OS memory/process limit, with project `conftest.py`
  hooks and project discovery configuration disabled. The trusted runner and
  pytest executor are also read once, digest-checked, and executed from those
  in-memory bytes rather than reopened as Python pathnames. Executor state is
  closure-held and removed from `__main__`; an irreversible audit hook restricts
  writes to the pytest temp root and refuses process starts. Link operations are
  destination-aware, and the one external completion write is bound to its
  executor thread. Both ordinary and original interpreter argument vectors are
  scrubbed before collection. Interpreter audit/trace/profile callback
  registration is statically refused and its mutable `sys` entrypoints are
  disabled before project imports. Whole-subject static inspection refuses hard exits,
  direct, constant-folded, and opaque reflection, pytest lifecycle control, and
  other capabilities that could reach the supervisor. A trusted supervisor outside the
  pytest interpreter validates the complete executed-test record and its normal
  completion sentinel, drains only a bounded output tail, and the verifier
  re-censuses the original subject before verdict. Project code runs from the
  private copy, never the original project cwd, and never determines verifier,
  runner, or executor resolution. On POSIX the absolute environment entrypoint
  is deliberately not canonicalized through its symlink: doing so would discard
  the virtual environment that owns pytest. Its separately resolved base target
  is checked against the project boundary and recorded in provenance. Linux
  shared-library builds such as `actions/setup-python` also receive a loader
  directory derived from the trusted interpreter's `sys.base_prefix`; inherited
  `LD_LIBRARY_PATH` remains excluded so project state cannot select native code.
  On POSIX the process budget is applied above the real user id's ambient task
  count, because `RLIMIT_NPROC` is charged to every process and thread that
  user holds host-wide rather than to this process tree: an absolute ceiling of
  64 refused the verifier's own runner on GitHub-hosted runners, whose service
  user already exceeds it. A host whose task count cannot be measured fails
  closed.
- `app_launcher`: bounded adapter that starts the application server process.
- `nornyx_runtime`: official Nornyx authorization path with an explicitly labeled offline fallback.
- `approval_trust`: Ed25519 verification of action-specific human approvals. A leaf
  by construction — it holds no signing key and reaches no effect code.
- `reviewer_trust`: Ed25519 verification of inspection attestations, and the
  derivation of independence from authenticated reviewer identity. A separate
  component from `approval_trust`, not a corner of it: an approver key releases
  an effect, a reviewer key certifies an inspection, and modelling them together
  would make it structurally unremarkable for one key to do both. Also a leaf —
  verification only, no signing, no dependencies.
- `policy`: deterministic fallback decisions used only when official runtime dependencies are unavailable.
- `evidence`: append-only mission records and validation.
- `src/demo_app`: FastAPI customer-operations UI and runtime Flow.

Every first-party module under `src/` is declared in
`.nornyx/contracts/architecture_governance.nyx`. That is enforced rather than
intended: `scripts/check_architecture.py` is driven by what is on disk, so a
module the contract does not model fails the gate instead of being skipped by it.

## Dependency direction

```text
UI/API -> agentic flow -> governed actions -> Nornyx policy boundary
     |                            |-> evidence
     |-> case store (declared, direct)
```

The UI does not reach execution or governance directly. It DOES read and write
the case store directly, and that edge is declared: `component.api depends_on
component.persistence` in the architecture contract, and `module.api depends_on
module.persistence`.

This paragraph used to say "the UI does not call persistence or execution
actions directly", which was false about persistence -- `demo_app.main` imports
`JsonStore` on line 19 and always has. Three artifacts disagreed: this document
forbade the edge, the contract's policy list denied it, and the contract's own
component graph declared it. The graph and the code agreed; the prose did not.

The edge is kept rather than routed through the application layer, deliberately.
The governance boundary is EXECUTION, not storage: the case store holds case
records and is not a route to a consequential effect. Making `demo_app.agentic`
the persistence gateway would move file I/O into the module that owns the action
boundary, which is worse for the property that actually matters.

The runtime flow cannot grant human or production approval.

The build trust boundary is separate from that runtime authority boundary. A
provider may change the generated project's application source, tests, and BRD
until the greenfield profile passes. It may not select the profile or supply the
verifier. `DevelopmentFlow` selects the profile from its trusted `repo_mode`;
`gates` resolves the Forge-owned verifier and interpreter; the standalone
verifier inspects project bytes and runs the project's tests only from a private
copy after the static checks pass. The static profile intentionally refuses
interpreter-control and reflection capabilities before arbitrary Python is
executed; this is a bounded greenfield acceptance profile, not a general-purpose
host sandbox. Scripted reviewers receive a read-only tool
surface, and the trusted profile runs again after them, so a stale pre-review
result cannot authorize changed bytes. Local evidence-ledger validity is also a
verdict gate before `ALLOW` is recorded. Acceptance is the conjunction of these
recorded gate results. Provider prose and project-local verifier-looking files
are not verdict inputs.

Greenfield provenance is structural and tamper-evident, not authenticated. Each
gate and the acceptance event bind the profile ID/digest, verifier absolute
origin/digest, executed verifier/runner/executor byte-snapshot digests, Forge
package version/source revision, subject digest, isolated commands, resource
limits, trusted working directory, and environment policy. Those facts make the judge
falsifiable and expose file changes. They do not prove who installed Forge, who
controlled that installation, or that a cryptographic signer approved it.

Two rules keep that from eroding. `demo_app.main` may not import `nornyx_forge`
at all, checked by path so that no contract edit can grant the edge — the action
boundary stays the only route to a consequential effect. And nothing may depend
on the console entrypoint declared in `pyproject.toml`: it reaches across the
toolchain by design, so anything importing it would inherit that reach and could
carry a dependency between two modules that may not depend on each other.

Process execution is confined to the adapter layer, which is what makes the list
of places this system can start a process short enough to read: `gates`,
`greenfield_verifier`, `policy`, `repo_qualifier`, `claude_worker`, `app_launcher`,
`nornyx_cli_adapter`, `subject_observer`, `codex_worker`, and `capsule_store`, which
invokes git to give the project capsule its revision binding.

The last two were missing from this sentence, and they are the two that matter
most: `nornyx_cli_adapter` invokes the `nornyx` CLI -- the governance authority
itself -- and `subject_observer` invokes `git`, which is where revision binding
gets its revision. A reader checking "what can start a process here" against
this paragraph would have audited five call sites and missed the two closest to
the trust boundary.

The list is now measured rather than remembered:
`tests/test_documented_claims.py::test_the_process_start_sites_match_the_documented_list`
parses `src/` for every process-starting call and fails if this sentence and the
code disagree in either direction.

## Execution modes

See [`CLAUDE_CODE_AND_CREWAI.md`](CLAUDE_CODE_AND_CREWAI.md) for the recommended in-session mode, optional scripted mode, and deterministic CI mode.
