# Governance Evidence Assessment — Nornyx Forge Sponsor Self-Assessment

**Status:** G2 sponsor self-assessment under Governance Evidence Assessment v0.1  
**Conflict of interest:** sponsor-owned subject; no preferential treatment is permitted  
**Methodology:** `docs/GOVERNANCE_EVIDENCE_ASSESSMENT.md` v0.1  
**Assessment date:** 2026-08-21  
**Assessor:** project-sponsor self-assessment, prepared from public repository/API evidence  
**Repository:** `mazinmarji/nornyx-forge-live-demo`  
**Target commit:** `db5089e8d8373ebaae1c3ff8ca0864fe92c328dc`  
**Observation surfaces:** O1 repository content; O2 GitHub branch/platform state available to the assessor; O3 GitHub Actions execution metadata  

## Scope and limits

This assessment measures governance evidence of the **Nornyx Forge repository itself**. It does not award credit merely because Forge uses Nornyx or because Forge demonstrates governance capabilities for generated applications.

Forge is a public reference/canary and experimental assessment surface, not a production approval system. The repository's own assurance boundary is controlling for what this assessment may infer.

No aggregate score, grade, ranking, certification, or compliance verdict is produced.

## Summary

| Dimension | Result | Confidence | Main reason |
|---|---|---:|---|
| D1 — Governance source of truth | **PASS** | HIGH | BRD, `.nornyx` contracts, generated/evidence locations, and assurance/validation boundaries are explicit and versioned. |
| D2 — Change and approval control | **PARTIAL** | HIGH | Human approval is structurally required for strict Nornyx authorization, but GitHub reports `main` is not protected, so repository-change review is not platform-required by the observed branch state. |
| D3 — Revision binding and drift detection | **PASS** | HIGH | CI validates contracts/evidence digests and verifies the pre-approval baseline; strict runtime lock activation is intentionally unavailable until real human approval exists. |
| D4 — Agent/tool authority and capability control | **PARTIAL** | HIGH | High-risk action prevention and strict authorization paths exist, but current default/fallback control is cooperative and the repository explicitly does not establish mandatory interception or independent agent authentication. |
| D5 — Evidence integrity and provenance | **PARTIAL** | HIGH | Governance evidence digests are verified, but the repository explicitly does not prove runtime observations are true or independently authenticate producers/approvers. |
| D6 — CI/CD and supply-chain governance | **PARTIAL** | HIGH | CI is broad and a recent PR candidate passed it, but `main` is unprotected and the assessment cannot establish the CI jobs are platform-required before merge. |
| D7 — Enforcement-claim honesty and coverage | **PASS** | HIGH | README and assurance-boundary docs explicitly distinguish cooperative controls, fallback behavior, missing human approval, and non-production claims. |

**Non-PASS findings:** D2, D4, D5, D6. This satisfies G2's requirement for at least three honest non-PASS findings on a sponsor-owned subject.

---

## D1 — Governance source of truth

**Result:** PASS  
**Confidence:** HIGH  
**Evidence class / observability:** E2 / O1

### Evidence

- `README.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` identifies the BRD-to-build workflow, `.nornyx/generated/brd_contract.nyx`, `.nornyx/runs/` evidence location, and the Nornyx/CrewAI source references.
- `.nornyx/contracts/@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` contains versioned governance contracts.
- `docs/ASSURANCE_BOUNDARY.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` defines what the repository can and cannot claim.
- `docs/VALIDATION.md` and `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` identify the validation paths rather than relying on README assertions alone.

### Reasoning

The repository makes the distinction among input requirements, governance contracts, generated artifacts, evidence, and assurance limits discoverable and versioned. This is sufficient for the repository-visible source-of-truth property assessed here.

### Limits

A PASS here does not mean there is one monolithic governance file or that external Nornyx/CrewAI repositories are controlled by Forge. It means the Forge repository's own governing/derived artifact roles are explicit enough to reproduce the assessment.

---

## D2 — Change and approval control

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E4 / O1 + O2

### Evidence

- `docs/ASSURANCE_BOUNDARY.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` states that strict Nornyx authorization requires a human-produced `approval_record` and that an autonomous run cannot manufacture it.
- `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` has a pre-approval baseline job and only enables strict authorization steps when a real human approval exists.
- GitHub branch observation for `main` on 2026-08-21 reports `protected: false` and no required status checks.

### Reasoning

Forge has meaningful *application/governance* approval controls: strict Nornyx authorization remains unreachable without accountable human approval. But the methodology also assesses changes to the repository itself. The observed `main` branch has no platform protection, so pull-request review and CI are not demonstrated as mandatory before repository changes land.

### Improvement that would change the result

Platform-enforced branch/ruleset evidence requiring appropriate review and critical CI checks would strengthen this dimension. That would be repository hygiene, not a reason to expand the product roadmap.

---

## D3 — Revision binding and drift detection

**Result:** PASS  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 / O1 + O3

### Evidence

- `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` checks the control contract, regenerates and checks the BRD contract, verifies the pre-approval baseline, verifies governance evidence artifacts against declared digests, and runs architecture/security gates.
- The same workflow states that full history is fetched because evidence binding names the governed subject revision and a shallow clone cannot prove the referenced revision exists in repository history.
- `docs/ASSURANCE_BOUNDARY.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` explains that no runtime lock is produced before human approval and that this is the intended fail-closed state, not drift.
- PR #12 candidate `db548e3a8c68e755618514646d70f49d0c90da18`, which was merged into the target commit, completed CI run `32406629851` successfully.

### Reasoning

The repository binds evidence to governed revision/history and verifies digest consistency. The current absence of a strict runtime lock is explicitly caused by missing human approval and is tested as the expected pre-approval state; it is not silently treated as a valid strict-authorization state.

### Limits

The observed CI execution is attached to the PR head that became part of the target merge, not a separately observed post-merge run on `db5089...`.

---

## D4 — Agent/tool authority and capability control

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 / O1

### Evidence

- `README.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` says the demo uses cooperative controls over declared surfaces and is not production approval.
- `docs/ASSURANCE_BOUNDARY.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` says the repository does not establish mandatory interception of every Claude Code or CrewAI operation or independent authentication of agents/approvers.
- The assurance boundary records that when strict Nornyx authorization cannot load, the default `FORGE_ALLOW_POLICY_FALLBACK=false` path fails closed; when fallback is explicitly allowed, high-risk actions remain denied but decisions are labelled `source: deterministic_fallback` rather than Nornyx authorization.
- `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` runs demonstration scenarios that prevent the high-risk action and has a separate strict-authorization path only when human approval exists.

### Reasoning

There are real deny paths and explicit capability boundaries, but the repository accurately describes them as cooperative/declared-surface controls. It does not establish mandatory interception across every execution surface or independently authenticated agent identity, so a whole-repository PASS would overstate coverage.

### Improvement that would change the result

A specific claim could reach a stronger result if the assessed execution surface were independently enforced, identity-authenticated, and demonstrably non-bypassable for the declared scope. This is not currently required by the Forge experiment.

---

## D5 — Evidence integrity and provenance

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 / O1

### Evidence

- `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` runs `python scripts/refresh_governance_evidence.py --verify` and states that governance evidence artifacts must match declared digests.
- `docs/ASSURANCE_BOUNDARY.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` explicitly says the repository does not prove that every recorded runtime observation is true and does not independently authenticate agents or approvers.
- The same document requires strict human approval evidence to be `producer: human` and rejects AI/autonomous actors as approval producers, but that is a structural declaration boundary rather than independent authentication of the human identity.

### Reasoning

Forge has meaningful integrity controls: evidence artifacts are digest-checked and absence of approval is represented honestly. Provenance remains incomplete for independent assurance because runtime truth and producer identity are not established out-of-band.

### Improvement that would change the result

Cryptographically verified or independently controlled evidence production/authentication for the claimed surface would be required for a stronger finding.

---

## D6 — CI/CD and supply-chain governance

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 + E4 / O1 + O2 + O3

### Evidence

- `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` runs on push and pull request, tests Python 3.10–3.13, validates repository structure, runs tests/compile checks, validates governance contracts/evidence/architecture/security, executes the high-risk deny demonstration, smoke-tests the application, and builds the package.
- PR #12 head `db548e3a8c68e755618514646d70f49d0c90da18` completed CI run `32406629851` successfully.
- GitHub branch observation for `main` reports `protected: false` with no required status checks.

### Reasoning

The CI content and recent execution evidence are substantial. However, the platform state does not establish that CI must pass before changes can reach `main`. Under the methodology's distinction between a workflow file and platform-enforced governance, this remains PARTIAL.

### Improvement that would change the result

Require the critical CI job(s) through GitHub branch/ruleset controls, then reassess using O2 platform evidence.

---

## D7 — Enforcement-claim honesty and coverage

**Result:** PASS  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 / O1

### Evidence

- `README.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` says the default is an autonomous demonstration, not a production approval, and points to the assurance boundary.
- `docs/ASSURANCE_BOUNDARY.md@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` says Forge does not establish mandatory interception, independent agent/approver authentication, runtime truth, production readiness, regulatory compliance, or human approval.
- The same document distinguishes strict Nornyx authorization from deterministic fallback and requires fallback decisions to be labelled accordingly.
- `.github/workflows/ci.yml@db5089e8d8373ebaae1c3ff8ca0864fe92c328dc` tests the pre-approval state explicitly instead of fabricating a passing approval and separately tests the high-risk deny behavior.

### Reasoning

Forge makes unusually explicit distinctions between what is demonstrated, what is cooperative, what is unavailable before human approval, and what is not established at all. The evidence and wording are aligned; the repository does not convert a demo into a production or independent-assurance claim.

---

## G2 sponsor-self-assessment conclusion

Forge demonstrates strong claim-boundary honesty and revision/evidence discipline. The main non-PASS findings are platform-level repository change control, mandatory agent/tool enforcement coverage, independent evidence provenance, and platform-required CI.

The self-assessment does not authorize remediation, new runtime controls, an assessment engine, or product expansion. G2's purpose is to show that the methodology produces real non-PASS findings on sponsor-owned assets before G3 is applied to named third-party repositories.