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
  --description "One-prompt Nornyx-governed BRD-to-running CrewAI application demonstration"
```

## Existing empty repository

```bash
git remote add origin https://github.com/mazinmarji/nornyx-forge-live-demo.git
git push -u origin main
```

After publication, confirm that GitHub Actions completes both `test` and
`demo-contract`. Neither validates strict Nornyx execution and neither
validates CrewAI: `demo-contract` runs the demo non-strict, the
`strict-authorization` job reports that strict authorization stays inactive,
and `cli.py` requests `execution_backend="sequential"` unconditionally. The
wording this replaces -- describing "strict Nornyx/CrewAI execution" as
validated by those jobs -- was retracted in README.md and survived here
because the guard scanned only README and docs/.
