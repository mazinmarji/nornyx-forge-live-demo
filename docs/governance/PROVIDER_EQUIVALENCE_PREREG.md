# Provider Equivalence Proof V1 — pre-registration

    Status        FROZEN as the first commit of the equivalence slice.
                  Git history is the ordering proof: this commit contains no
                  equivalence test, and every equivalence test lands after it.
    Authorship    Builder-drafted under the founder's standing instruction that
                  cross-adapter equivalence is "a separate, pre-registered
                  proof". The founder may amend before tests are written;
                  after the freeze, any change is a recorded amendment with
                  its own commit, never an edit that pretends to have always
                  been there.
    Instrument    The Provider Contract (src/nornyx_forge/provider_contract.py)
                  and both adapters (src/nornyx_forge/providers.py,
                  src/nornyx_forge/claude_worker.py,
                  src/nornyx_forge/codex_worker.py) exactly as they stand at
                  the parent commit of this one.

## 1. The claim under proof, exactly

> Forge treats its two contract-conformant providers identically: for the same
> task and the same observed ending, both adapters produce results that are
> equal under the declared projection, and every consumer of provider results
> or provider identity that exists at this head reaches identical decisions
> for both providers.

## 2. What is explicitly NOT under proof

- **LLM-behavioral equivalence.** Whether the Codex and Claude models produce
  comparably good engineering output is non-deterministic and
  environment-dependent; it stays in the category *not yet proven*. No test in
  this slice runs a real model, and no wording anywhere may imply behavioral
  parity.
- **Lifecycle-driven equivalence.** Measured at the parent commit, no module
  outside src/nornyx_forge/providers.py and
  src/nornyx_forge/provider_contract.py consumes a provider result; the
  capsule records provider *selection* as an object with exactly one `name`
  key and never stores result content, and the Experience Contract never
  reads provider results at all. Equivalence over a provider-driven
  end-to-end journey becomes provable only when such wiring exists, in a
  later slice. This document proves the seam and the consumers that exist.

## 3. The frozen task set

Four `ProviderTask` fixtures, identical for both adapters:

    T1  minimal valid task (one tool, one turn)
    T2  goal at the maximum accepted length
    T3  multi-tool allowlist ("Read", "Write", "Bash")
    T4  tight 1-second timeout (drives the timeout ending)

## 4. The frozen ending set

Every member of the failure vocabulary, produced through each worker's REAL
subprocess handling via per-provider fake executables that emit each CLI's
NATIVE conventions — Claude's JSON `session_id` object, Codex's JSONL
`thread.started` event:

    ok           exit 0 with a native session event
    unavailable  absent executable, the 127 convention
    timeout      a fake that genuinely outlives the 1s budget, the 124 convention
    error        the same chosen nonzero exit for both

## 5. The projection (what "equal" means)

Two provider results are equivalent if and only if ALL of the following are
equal: `success`, `failure_class`, `returncode`, session PRESENCE (both have
one, or neither does), `role`, and `goal`.

## 6. Allowed differences, named in advance

The `provider` field. The `command` vector (each CLI's own conventions). The
`output` text. The session identifier's VALUE (never its presence). Timing.

## 7. Forbidden differences — each gets a hostile specimen

- Same ending, different `failure_class`.
- Same ending, different `success`.
- One adapter recording a session where the other records absence.
- A consumer decision that differs by provider.

Each specimen must be CAUGHT by the harness — a proof whose checks cannot
fail is a tautology, so the specimens exist to show the checks going red on
doctored inputs. Note that result validation alone cannot catch the first
specimen: a result claiming `failure_class` "timeout" over returncode 5
validates, because validation checks success/class agreement, not
class/returncode consistency. The harness's projection comparison is
therefore load-bearing, not implied.

## 8. Consumer-neutrality obligations (scoped to what exists)

- **The one normalizer.** Both adapters' raw worker results pass through the
  same `result_from_worker`; for each ending, the projected normalized
  results must be equal.
- **Capsule provider recording.** The capsule accepts both declared names
  through the same validator with the same acceptance shape, and refuses an
  undeclared name with the same refusal, regardless of which declared names
  exist. Selection is symmetric.
- **The registry.** `get_provider` serves both names through the same
  identity validation and refuses undeclared names identically.
- **Absence statement.** No other consumer exists at the parent commit
  (measured by search over src/, recorded in section 2), so no further
  consumer obligation can be discharged yet — and none is claimed.

## 9. Success / failure criteria

PASS: every (task × ending) projection equality holds across the adapter
pair; the allowed-difference set is exact (fields outside it are equal); all
hostile specimens are caught; consumer-neutrality obligations hold. The
hostile specimens are the load-bearing-proof mechanism for this slice: they
assert the harness's own checks fail on doctored inputs, which is the same
discipline revert controls apply to source guards, applied in-suite.

FAIL: any forbidden difference reproduces. A FAIL is a finding against an
adapter or the contract, filed and fixed forward — never against these
criteria. The criteria do not move after the freeze.

## 10. The claim licensed by a PASS, verbatim

> "Contract-level provider equivalence is deterministically tested for the
> two shipped adapters across the frozen task and ending sets, and every
> consumer of provider results or provider identity that exists at this head
> is tested neutral between them. Behavioral equivalence of the underlying
> models is not claimed, and lifecycle-driven equivalence is not yet
> provable because no lifecycle consumer of provider results exists yet."
