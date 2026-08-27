# Publishing this repository

The repository is prepared for `mazinmarji/nornyx-forge-live-demo`.

## GitHub CLI

```bash
gh auth login
gh repo create mazinmarji/nornyx-forge-live-demo \
  --public \
  --source . \
  --remote origin \
  --push \
  --description "One-prompt Nornyx-governed BRD-to-running application demonstration"
```

## Existing empty repository

```bash
git remote add origin https://github.com/mazinmarji/nornyx-forge-live-demo.git
git push -u origin main
```

The description deliberately does not say "CrewAI application". This text is
copied into the public repository metadata, and the shipped `demo` path runs
`sequential`: `observed_execution_backend: sequential`, framework reported as
"CrewAI Flow-compatible sequential execution". CrewAI genuinely executes on the
`build` path, which is a different claim and is made where it is true.

After publication, confirm that GitHub Actions completes both `test` and
`demo-contract`.

Neither validates STRICT NORNYX execution: `demo-contract` runs the demo
non-strict, and the `strict-authorization` job reports that strict
authorization stays inactive. That much has always been true.

CrewAI is a different matter, and the two sentences that used to stand here
were both false. `cli.py` names `execution_backend` exactly once, at line 164,
inside the `demo` command -- not unconditionally. `build_app` passes NO config,
so `RuntimeAuthorityConfig()` applies with its defaults (`policy_backend
"nornyx"`, `execution_backend "crewai"`), and `cli build` runs a real kickoff:
`build-summary.json` records `execution_backend: crewai_flow`. And the `test`
job runs the full suite through `check_test_coverage.py`, which includes
`test_authority_config.py`'s `("crewai", "crewai_flow")` case asserting the
backend DERIVED from the driver -- measured `4 passed, 9 deselected`, not
skipped, because CI installs `.[demo,dev]` and so installs CrewAI.

So: the `test` job does validate that CrewAI really executes. What no job
validates is strict Nornyx authorization, which needs a human approval that
does not exist here.

The wording this replaces -- describing "strict Nornyx/CrewAI execution" as
validated by those jobs -- was retracted in README.md and survived here because
the guard scanned only README and docs/. The replacement then over-corrected
into the opposite falsehood, which is what an independent review measured.
