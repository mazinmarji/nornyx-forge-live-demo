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
| `.nyx` contract read | `nornyx_runtime.py:77` | Covered by `SubjectScope.required_contracts`. The reader itself (`runtime_revision`) is removed in R1 step 2. |
| Approval ledger path from env | `nornyx_runtime.py` (`FORGE_APPROVAL_LEDGER`) | **Closed (R3).** Resolved once into `TrustConfiguration` at `bootstrap_security_context`, frozen, and injected. |
| Approval ledger SQLite | `nornyx_runtime.py` (`ApprovalLedger`) | **Closed (R3).** `CREATE TABLE IF NOT EXISTS` on every construction meant deleting the file emptied the ledger and made every spent grant replayable. Provisioning is now a separate operator command (`nornyx-forge provision-ledger`); a missing ledger denies, a corrupt one raises as unavailable. |
| Trust store path from env | `approval_trust.py` (`FORGE_APPROVER_TRUST_STORE`) | **Closed (R3).** Resolved once into `TrustConfiguration` and injected into the boundary. |
| Trust store contents | `approval_trust.py:181` | Deliberately outside the tree, so not subject content. Its *resolution* must be immutable (R3); its contents are the trust anchor. |
| Reviewer trust store path from env | `reviewer_trust.py` (`FORGE_REVIEWER_TRUST_STORE`) | **Closed (R3).** Resolved once into `TrustConfiguration`. The evidence tool still loads by path directly — it is a build-time utility outside the runtime trust boundary, not a request-serving surface. |
| Reviewer trust store contents | `reviewer_trust.py:175` | Outside the tree by design, so not subject content — editing the repository cannot add a trusted reviewer. Absence is an ordinary state (nothing authenticates); malformation raises, so the two cannot be confused. |
| Builder identity from env | `reviewer_trust.py` (`FORGE_BUILDER_IDENTITY`) | **Closed (R2/R3).** It replaced the identity independence was measured against, so naming another builder excused the real one. It is a union now — ambient input adds an excluded identity and can never remove one — and the resolved set is frozen into `TrustConfiguration`. |
| Application root from env | removed (`FORGE_ROOT`) | **Closed (R1).** The application derives its root structurally through `resolve_packaged_root()`. No reader remains under `src/`; the vestigial setters in `scripts/smoke_http.py` are removed too, since a variable nothing reads still tells a reader it matters. |
| Policy fallback toggle | `agentic.py:319,377`, `development_flow.py` | **R1/R5.** `FORGE_ALLOW_POLICY_FALLBACK` permits a deterministic fallback for the governance path. Authority-relevant ambient state. |
| `reviews.json` | `development_flow.py` | **Closed (R4).** Two claims came off a gitignored, builder-written file: acceptance was gated on `builder_self_approval is False` (the builder certifying their own independence), and `independent_ai_review` was `bool(reviews)` (a non-empty list of subprocesses standing in for a verdict). Neither is read now. The gate checks completeness and outcome only, and reports `independent_ai_review: not_established`. |
| CrewAI backend toggles | `agentic.py:324,345`, `development_flow.py:383,395` | **R5.** `FORGE_USE_CREWAI_KICKOFF` / `FORGE_STRICT_CREWAI` silently select a degraded backend while the product claim stays "CrewAI". |

## Non-authoritative — reason required, negative test owed

| Input | Site | Why non-authoritative |
| --- | --- | --- |
| Case store JSON | `store.py:19` | Application data. Cannot reach an authorization decision: the boundary derives risk from the canonical request, not from stored cases. Negative test owed. |
| Build summary JSON | `main.py:41` | Presentation only, served at `/api/build`. **R4** must prove forging it changes no authorization or assurance result. |
| Evidence ledger | `evidence.py:41,71` | Append-only output, downstream of decisions. Note: lens 2 found `validate()` does not detect truncation — R7. |
| `GITHUB_TOKEN`, network | `repo_qualifier.py:35`, `repo_scout.py:20` | Build-time repository qualification. Not reachable from the consequential runtime path. Negative test owed. |
| BRD / requirements text | `requirements.py:44`, `util.py:26` | Build-time authoring inputs; BRD.md is covered by both scopes as subject content. |
| Telemetry env defaults | `agentic.py:29-32`, `development_flow.py:19-22` | `setdefault` on CrewAI/OTel telemetry switches. No authorization path. |

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
