"""Basic-user readable summaries for refusals and failures.

A DERIVED, deterministic rendering for the person using the onboarding page.
It never replaces, weakens or stands in for the verbatim reason Forge already
produces: the caller shows this summary ABOVE the verbatim text, never instead
of it, and no decision is taken here. These are pure functions over data Forge
has already computed -- an eligibility verdict's own fields, or the failure
detail Forge itself wrote -- so the plain words and the technical words can
never disagree about what happened.

The product need: eligibility reasons cite commits and measurement
documents, and a build failure is reported in the contract's words without
naming, in plain terms, which check stopped the build. This module renders
the plain line a basic user reads first; the technical reason stays exactly
as it was, beneath it.

`layer.domain`: no I/O, no process state, and no import from the served
surface -- the caller supplies the already-computed data.
"""

from __future__ import annotations

from typing import Any, Mapping

#: How the gate that decides whether a confirmed provider may run the governed
#: build is NAMED to a person. The decision itself is
#: `provider_contract.governed_build_eligibility`; this is only its plain name.
ELIGIBILITY_CHECK = "the provider-eligibility check"


def eligibility_summary(verdict: Mapping[str, Any]) -> str:
    """One plain sentence for a provider the eligibility gate refused.

    Rendered from the verdict's own fields -- the provider and the platform it
    was decided for -- never from the commit hashes or measurement-document
    names the verbatim reason carries. The caller keeps that verbatim reason
    and shows it beneath this line.
    """
    provider = (str(verdict.get("provider") or "").strip() or "the chosen")
    platform = (str(verdict.get("platform") or "").strip() or "this platform")
    return (
        f"The build cannot start yet: Forge has not cleared the {provider} "
        f"provider to run on {platform}. This is {ELIGIBILITY_CHECK}; the "
        f"technical reason is shown below."
    )


def build_failure_headline(detail: str | None) -> dict[str, str | None]:
    """A plain summary and the failing check's name for a recorded failure.

    `detail` is the failure text Forge wrote -- the `history` detail that
    `experience_journey.journey_view` surfaces as `failure`. The match keys on
    the tokens Forge's own failures carry: the evidence KIND a refused advance
    names (`flow_run`, `gate_results`), and the two fixed prefixes
    `experience_journey.build_error` and `build_outcome` write. A failure with
    no recognised token still gets an honest, non-empty summary.

    THE SUMMARY CLAIMS NO MORE THAN THE EVIDENCE KIND CARRIES. `flow_run`'s
    `passed` is the flow's own aggregate `accepted` flag, which folds the
    build's tests, gates, reviews and evidence-ledger checks into one value,
    and `gate_results` passes only when every recorded gate did. Neither says
    WHICH check failed, so neither summary names one: a run whose tests
    passed but whose review or ledger check failed is refused with the same
    `flow_run` text, and calling that a test failure would be false.

    Both values are `None` when there is no failure, so every journey shape can
    carry the two fields and the page renders them without testing for absence.
    """
    text = (detail or "").strip()
    if not text:
        return {"summary": None, "check": None}
    if "flow_run" in text:
        return {
            "summary": (
                "The build was not accepted, so the workflow stopped. Acceptance "
                "covers the build's tests, gates, reviews and evidence record "
                "together, so this does not say which of them failed."
            ),
            "check": "the build's acceptance (flow_run)",
        }
    if "gate_results" in text:
        return {
            "summary": (
                "The build's recorded gate results did not clear, so the "
                "workflow stopped."
            ),
            "check": "the build's gate results (gate_results)",
        }
    if text.startswith("the build did not complete"):
        return {
            "summary": "The build did not finish; it stopped before producing a result.",
            "check": "the build run",
        }
    if text.startswith("the build produced no usable evidence"):
        return {
            "summary": "The build finished but produced no usable evidence to check.",
            "check": "the build's evidence",
        }
    if text.startswith("refused"):
        return {
            "summary": "A governance check refused the build before it could advance.",
            "check": "the build's governance checks",
        }
    return {"summary": "The build did not succeed.", "check": "the build"}
