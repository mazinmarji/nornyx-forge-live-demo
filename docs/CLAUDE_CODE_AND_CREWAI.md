# Claude Code and CrewAI execution modes

Nornyx Forge separates engineering reasoning, orchestration, and governance:

- **Claude Code** performs requirements, architecture, implementation, repair, and bounded inspection.
- **Nornyx Forge Skill** is the preferred Claude Code entry point and orchestrates the governed transformation workflow.
- **CrewAI Flow** defines the development and application state machines.
- **Forge deterministic machinery** runs repository, architecture, security, evidence, and conformance checks.
- **Nornyx** supplies contracts, authorization, architecture rules, gates, and evidence semantics.

The Skill is not an authority source. A model statement cannot replace a deterministic validation result, human approval, external independent confirmation, certification, or runtime enforcement.

See [`FORGE_SKILL_BOUNDARY.md`](FORGE_SKILL_BOUNDARY.md).

## Recommended: Skill-first interactive mode

After cloning the repository, start Claude Code with the local plugin:

```bash
claude --plugin-dir .
```

Then invoke:

```text
/nornyx-forge:build-app BRD.md
```

The current session invokes Agent subagents directly and writes `.nornyx/in-session/reviews.json`. No Anthropic Console API key and no nested Claude process are required.

The test, architecture, and security subagents provide bounded in-session review separation. They do **not** constitute external independent review merely because they are separate subagents in the same Claude Code session.

## One-prompt bootstrap

`ONE_PROMPT.md` exists for users starting outside a repository clone. It clones Forge and then enters the same `build-app` Skill path. It is a convenience layer, not an alternative assurance mechanism.

## Optional: scripted Claude Code workers

`--worker-mode claude-code` invokes bounded `claude -p` workers. This is useful for a local personal runner but may consume programmatic/Agent SDK allowance. It does not change the authority boundary: model workers remain engineering actors, not governance authority.

## Deterministic mode

`--worker-mode deterministic` runs all non-model gates and the live application scenario without Claude. It exists for CI and reproducibility and is explicitly labeled as fallback when the official Nornyx runtime package is unavailable.

Deterministic execution is important because it demonstrates which properties do not depend on a model choosing to follow instructions.

## CrewAI Claude Code skills

The public CrewAI Claude Code skills can improve CrewAI authoring guidance, but they are not required by this repository and do not replace CrewAI's runtime model connection for ordinary `Agent` objects. This demo uses Flow methods and Claude Code workers, so the default workflow does not require a CrewAI model API key.

## Enforcement principle

Prompts and Skills may tell a model what it should do. Forge/Nornyx controls determine what the governed system may claim or execute on the surfaces they mechanically control.

A gate may claim only the exact property it mechanically measures.
