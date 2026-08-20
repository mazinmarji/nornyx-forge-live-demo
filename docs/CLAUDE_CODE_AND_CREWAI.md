# Claude Code and CrewAI execution modes

Nornyx Forge separates orchestration from reasoning and governance:

- **CrewAI Flow** defines the development and application state machines.
- **Claude Code** performs requirements, architecture, implementation, repair,
  and SELF-REPORTED review. It does NOT perform independent inspection: that
  requires three Ed25519 attestations against `FORGE_REVIEWER_TRUST_STORE`
  (`docs/ASSURANCE_BOUNDARY.md`), and none exists here. README.md retracts the
  same claim; this line kept it, and the overclaim guard's patterns did not
  match this phrasing.
- **Nornyx** supplies contracts, authorization, architecture rules, gates, and evidence binding.

## Recommended: interactive in-session mode

Paste `ONE_PROMPT.md` into Claude Code. The current session invokes Agent
subagents directly and writes `.nornyx/in-session/reviews.json`. No Anthropic
Console API key and no nested Claude process are required.

## Optional: scripted Claude Code workers

`--worker-mode claude-code` invokes bounded `claude -p` workers. This is useful
for a local personal runner but may consume programmatic/Agent SDK allowance.

## Deterministic mode

`--worker-mode deterministic` runs all non-model gates and the live application
scenario without Claude. It exists for CI and reproducibility and is explicitly
labeled as fallback when the official Nornyx runtime package is unavailable.

## CrewAI Claude Code skills

The public CrewAI Claude Code skills can improve CrewAI authoring guidance, but
they are not required by this repository and do not replace CrewAI's runtime
model connection for ordinary `Agent` objects. This demo uses Flow methods and
Claude Code workers, so the default workflow does not require a CrewAI model API
key.
