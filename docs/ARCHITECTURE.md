# Architecture

## Components

- `nornyx_forge.cli`: operator surface and the toolchain's application layer — each
  command body composes a sequence, and no other module coordinates that.
- `repo_scout` / `repo_qualifier`: foundation discovery and qualification.
- `development_flow`: CrewAI Flow orchestration of in-session or scripted Claude Code work and deterministic gates.
- `contract_generator` / `requirements`: deterministic BRD parsing and BRD-to-Nornyx repository-harness generation.
- `claude_worker`: optional bounded `claude -p` execution bridge for scripted mode.
- `gates`: deterministic gate execution.
- `app_launcher`: bounded adapter that starts the application server process.
- `nornyx_runtime`: official Nornyx authorization path with an explicitly labeled offline fallback.
- `approval_trust`: Ed25519 verification of action-specific human approvals. A leaf
  by construction — it holds no signing key and reaches no effect code.
- `policy`: deterministic fallback decisions used only when official runtime dependencies are unavailable.
- `evidence`: append-only mission records and validation.
- `src/demo_app`: FastAPI customer-operations UI and runtime Flow.

Every first-party module under `src/` is declared in
`.nornyx/contracts/architecture_governance.nyx`. That is enforced rather than
intended: `scripts/check_architecture.py` is driven by what is on disk, so a
module the contract does not model fails the gate instead of being skipped by it.

## Dependency direction

```text
UI/API -> application service -> agentic flow -> governed actions -> persistence
                         |-> evidence
                         |-> Nornyx policy boundary
```

The UI does not call persistence or execution actions directly. The runtime flow cannot grant human or production approval.

Two rules keep that from eroding. `demo_app.main` may not import `nornyx_forge`
at all, checked by path so that no contract edit can grant the edge — the action
boundary stays the only route to a consequential effect. And nothing may depend
on the console entrypoint declared in `pyproject.toml`: it reaches across the
toolchain by design, so anything importing it would inherit that reach and could
carry a dependency between two modules that may not depend on each other.

Process execution is confined to the adapter layer, which is what makes the list
of places this system can start a process short enough to read: `gates`,
`policy`, `repo_qualifier`, `claude_worker`, and `app_launcher`.

## Execution modes

See [`CLAUDE_CODE_AND_CREWAI.md`](CLAUDE_CODE_AND_CREWAI.md) for the recommended in-session mode, optional scripted mode, and deterministic CI mode.
