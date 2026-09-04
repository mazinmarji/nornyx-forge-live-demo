# Nornyx Forge Live Demo

**Claude Code is the engineer. Nornyx Forge is the governed transformation and conformance system around it. Nornyx supplies the authority semantics underneath it.**

Nornyx Forge is a public reference implementation for demonstrating three Nornyx value claims:

1. **Software-development governance** — requirements, goals, permissions, tests, repair budgets, evidence, and release gates are explicit and revision-bound.
2. **Architecture governance** — declared modules and layers, and the architecture evidence set, are checked before acceptance. Interfaces and trust boundaries are DECLARED but not checked: `architecture_governance.nyx` carries `interfaces: []` and empty boundary lists, and `scripts/check_architecture.py` reads only `modules` and `layers`. The previous wording named them as checked.
3. **Delivery speed** — Repo Scout reuses a suitable foundation, deterministic gates catch defects early, and bounded repair loops reduce uncontrolled re-iteration.

## Preferred entry point: the Claude Code Skill

After cloning the repository, start Claude Code with the local plugin:

```bash
claude --plugin-dir .
```

Then invoke Forge through the Skill:

```text
/nornyx-forge:build-app BRD.md
```

The Skill is the preferred human-facing interface. Claude Code performs the reasoning, repository analysis, architecture, implementation, review, and repair work. The Skill does **not** become the governance authority: deterministic Forge/Nornyx controls remain responsible for the properties they mechanically validate.

See [`docs/FORGE_SKILL_BOUNDARY.md`](docs/FORGE_SKILL_BOUNDARY.md) for the exact separation between model reasoning, Forge conformance, Nornyx governance semantics, and human or organizational authority.

## What runs

- **Claude Code** performs repository analysis, architecture, implementation, review, and repair.
- **Nornyx Forge Skill** orchestrates the engineering workflow and invokes the required deterministic gates.
- **CrewAI Flow** coordinates the development workflow (`nornyx-forge build`)
  without requiring a CrewAI model API key. The live application runs the
  SEQUENTIAL backend by default and says so: `demonstration_authority()` names
  `execution_backend="sequential"`, and the evidence reports `framework:
  "CrewAI Flow-compatible sequential execution"`. Selecting `crewai` refuses
  rather than downgrading if CrewAI cannot execute, so the label always
  describes what actually ran.
- **Nornyx** checks the generated BRD contract, the architecture contract, the
  runtime network, and the control/evidence boundary. Today `forge_control.nyx`
  and the generated BRD contract PASS; `architecture_governance.nyx` and
  `runtime_network.nyx` do NOT. `runtime_network.nyx` fails because no human
  approval record exists. `architecture_governance.nyx` fails for that reason
  AND for a second, different external one: it additionally requires an
  AUTHENTICATED INDEPENDENT INSPECTION, reported as `CHANGE_EVIDENCE_MISSING`
  and `SOD_EVIDENCE_PRODUCER_UNKNOWN`. An earlier sentence gave ONE cause for
  both, so a reader was told a single human signature clears them; it does not.
  Reading an approval-blocked result as "validates" is the substitution this
  repository keeps finding, so the word is not used for it here.
- **FastAPI** serves the live governed customer-operations application and dashboard.

The default is an **autonomous demonstration**, not a production approval. Human review is not performed and the evidence says so explicitly. In-session model reviewers are bounded review evidence; they are not external independent confirmation or human approval.

## Bootstrap from outside a clone

[`ONE_PROMPT.md`](ONE_PROMPT.md) remains a convenience for users starting in an arbitrary directory. It clones this repository, loads the Forge instructions, and then executes the same `build-app` Skill. It is not a second assurance path.

The recommended path inside an existing clone is the Skill invocation above.

The current Claude Code session and its subagents finish with:

```bash
python scripts/bootstrap.py --autonomous --worker-mode in-session
```

The optional fully scripted mode uses bounded `claude -p` workers:

```bash
python scripts/bootstrap.py --autonomous --worker-mode claude-code
```

## What the Skill cannot replace

A prompt or Skill can direct Claude to analyze, design, code, test, and repair. It cannot create authority merely by saying that something is approved, verified, safe, production-ready, or governed.

Forge therefore keeps the following outside model discretion:

- deterministic repository, architecture, security, evidence, and Nornyx validation;
- mechanically bounded assurance claims;
- approval and evidence-integrity checks;
- runtime action-boundary enforcement integration;
- any real human or organizational authority required by the governed contract.

If Claude's interpretation conflicts with a deterministic result, the deterministic result controls and the conflict must be reported.

## Fast local verification without Claude or external APIs

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e '.[demo,dev]'
python scripts/check_test_coverage.py
python scripts/validate_repository.py
```

## Windows folder bundle (interim basic-user delivery)

The interim Windows delivery is a folder and `Forge.cmd` (A-020; the eventual
target is `ForgeSetup.exe`, which does not exist yet). A person double-clicks
`Forge.cmd`; the runtime starts under their profile's `ForgeProject`, opens
their default browser on the local onboarding page once the server has
answered for itself, and stops from the page's "Stop Forge" button. A second
double-click opens the running page rather than a second server. That is the
design the tests hold; the double-click itself and the browser opening on the
operator's embeddable interpreter are operator evidence, and
`docs/VALIDATION.md` says which parts have and have not been observed.

```bash
python scripts/build_windows_bundle.py --python-embed <embeddable zip> --python-embed-sha256 <sha256> --smoke
```

Without `--python-embed` the result is a DEVELOPER bundle that carries no
interpreter and runs on an installed Python; its launcher says so. The
builder never downloads an interpreter: the operator supplies the archive and
its digest, and a mismatch refuses the build (A-017). Git for Windows must be
on the PATH: the project capsule is a git repository, and a launch without
git is refused by name. Runtime state (a record, a lock, a log) lives under
`~/.nornyx/forge/runtime` and is operational only; it decides nothing about
any project's governance (A-023). The governed build still refuses both
declared providers on this baseline, exactly as on every other surface.

## Full live mode

Prerequisites:

- Git
- Python 3.10–3.13
- Docker Desktop or Docker Engine
- Claude Code installed and authenticated

Then start Claude Code with the local plugin and invoke:

```text
/nornyx-forge:build-app BRD.md
```

The current session uses its Agent subagents directly, records their review
findings, and runs the in-session bootstrap without a separate model API key.
Those findings are a SELF-REPORTED OBSERVATION, not an independent
inspection: independence requires an attestation signed by a reviewer who is
not the builder, verified against a trust store outside this repository.
Without one the evidence set reports `assurance_state:
not_independently_inspected`, which is its current state.

The workflow generates `.nornyx/generated/brd_contract.nyx` and creates evidence
under `.nornyx/runs/`.

**On a fresh clone it then stops, and that is correct.** `scripts/bootstrap.py`
appends `--strict-nornyx` whenever `--skip-install` is absent, and on this
branch strict mode refuses, because no human approval record exists. Measured:

```
$ python -m nornyx_forge.cli demo --offline --strict-nornyx
{"status": "blocked", "reason": "nornyx_runtime_unavailable",
 "detail": "AuthorizerLoadError: CONTRACT_INVALID: AN_APPROVAL_RECORD_MISSING,
            APPROVAL_EVIDENCE_MISSING, EVIDENCE_REQUIRED_MISSING"}
exit 2
```

> **What a reader actually sees.** The diagnostic above is what a tree with a
> prepared runtime lock reports. `.nornyx/runtime/` is gitignored and the lock
> CANNOT be produced without a human approval (`prepare_runtime.py` exits 2),
> so on a clean checkout the proximate refusal is
> `RuntimeError: RUNTIME_LOCK_MISSING`. Same absence, reported at a different
> depth: no approval exists, so the lock cannot be prepared, so the authorizer
> cannot load. The exit code (2), `status: blocked` and
> `reason: nornyx_runtime_unavailable` are identical either way.

`bootstrap.run()` raises `SystemExit` on a nonzero return, so the launch step
below is **not reached** on the path this section documents. Declining to
execute governed actions without an approval is the system working; the earlier
version of this paragraph claimed the workflow "launches the application, and
prints" the URLs, and that was false.

Where the launch does happen -- with `--skip-install`, so no `--strict-nornyx`,
and with Docker present and `--no-launch` absent -- `bootstrap.py` runs
`docker compose up --build -d` and prints:

- Application: `http://localhost:8000`
- Governance dashboard: `http://localhost:8000/dashboard`
- API documentation: `http://localhost:8000/docs`

The **`demo` command** runs `sequential`, and reports
`configured_execution_backend: sequential` alongside
`observed_execution_backend: sequential`. **CrewAI is not requested by the
`demo` command**, and the previous wording "strict Nornyx/CrewAI execution"
said otherwise.

That sentence used to read "sequential on both paths ... `cli.py` requests it
unconditionally", which is false in two ways a review measured. `cli.py` names
`execution_backend` exactly once, inside `demo`; and `bootstrap.py` runs
`cli build` on BOTH paths before the demo, so under either reading of "both
paths" one of them is `crewai_flow`. The paragraph below says so, and the two
could not both be true.

The `build` step is different, and this section used to be wrong about it.
`bootstrap.py` runs `python -m nornyx_forge.cli build` on both paths, and
`cli.py` constructs `DevelopmentFlow` with NO config -- so
`RuntimeAuthorityConfig()` applies, whose defaults are
`execution_backend='crewai'` and `policy_backend='nornyx'`. Measured, that
path runs a real kickoff: `build-summary.json` records
`execution_backend: crewai_flow`. A review found this; the AST guard was
blind to it because it only reads explicit literals.

## Public repository modes

The BRD-to-build workflow supports:

- `certified`: use the bundled, Nornyx-ready foundation.
- `target`: qualify a user-provided public repository.
- `scout`: search GitHub and rank compatible repositories.
- `greenfield`: start without an upstream foundation.

Repo Scout never treats stars or README claims as proof. It generates a scored suitability report and separates metadata evidence from build/runtime evidence.

## Assurance boundary

The live demo uses cooperative controls over declared surfaces. It does not claim mandatory sandbox enforcement, runtime truth attestation, or production approval. A gate may claim only the exact property it mechanically measures. See [`docs/ASSURANCE_BOUNDARY.md`](docs/ASSURANCE_BOUNDARY.md), [`docs/FORGE_SKILL_BOUNDARY.md`](docs/FORGE_SKILL_BOUNDARY.md), and [`docs/CLAUDE_CODE_AND_CREWAI.md`](docs/CLAUDE_CODE_AND_CREWAI.md).

## Source of truth

Nornyx semantics and current supported CrewAI adapter behavior are sourced from:

- https://github.com/mazinmarji/nornyx
- https://github.com/crewAIInc/crewAI
- https://github.com/crewAIInc/skills

## Validation

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the exact locally verified and CI-delegated checks.

## License

MIT.
