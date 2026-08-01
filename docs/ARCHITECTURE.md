# Architecture

## Components

- `nornyx_forge.cli`: entrypoint and operator surface.
- `repo_scout` / `repo_qualifier`: foundation discovery and qualification.
- `development_flow`: CrewAI Flow orchestration of in-session or scripted Claude Code work and deterministic gates.
- `contract_generator`: deterministic BRD-to-Nornyx repository-harness generation.
- `claude_worker`: optional bounded `claude -p` execution bridge for scripted mode.
- `nornyx_runtime`: official Nornyx authorization path with an explicitly labeled offline fallback.
- `policy`: deterministic fallback decisions used only when official runtime dependencies are unavailable.
- `evidence`: append-only mission records and validation.
- `src/demo_app`: FastAPI customer-operations UI and runtime Flow.

## Dependency direction

```text
UI/API -> application service -> agentic flow -> governed actions -> persistence
                         |-> evidence
                         |-> Nornyx policy boundary
```

The UI does not call persistence or execution actions directly. The runtime flow cannot grant human or production approval.

## Execution modes

See [`CLAUDE_CODE_AND_CREWAI.md`](CLAUDE_CODE_AND_CREWAI.md) for the recommended in-session mode, optional scripted mode, and deterministic CI mode.
