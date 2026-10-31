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

import re
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
    `experience_journey.journey_view` surfaces as `failure`. STRUCTURE FIRST:
    the fixed prefix `experience_journey` writes decides the kind of failure,
    and an evidence kind (`flow_run`, `gate_results`) is read only from the two
    structured refusals `experience.advance` writes -- a kind that "was not
    presented", or presented evidence that "reports failure". A kind's name
    appearing anywhere else, in an exception or a malformed gate record, is
    data inside the message and decides nothing, so it cannot produce a
    summary that contradicts the failure's own prefix. A failure with no
    recognised structure still gets an honest, non-empty summary.

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
    refusal = _structured_refusal(text)
    if refusal is not None:
        return refusal
    if text.startswith("refused"):
        return {
            "summary": "A governance check refused the build before it could advance.",
            "check": "the build's governance checks",
        }
    return {"summary": "The build did not succeed.", "check": "the build"}


#: The plain name of each evidence kind a build refusal can name.
_KIND_CHECKS = {
    "flow_run": "the build's acceptance (flow_run)",
    "gate_results": "the build's gate results (gate_results)",
}

#: What it means, in plain words, for each kind to report failure. `flow_run`'s
#: `passed` is the flow's aggregate `accepted`, so its summary names no check.
_KIND_FAILED = {
    "flow_run": (
        "The build was not accepted, so the workflow stopped. Acceptance "
        "covers the build's tests, gates, reviews and evidence record "
        "together, so this does not say which of them failed."
    ),
    "gate_results": "Not every recorded gate passed, so the workflow stopped.",
}

#: What it means for each kind to be absent from the advance.
_KIND_MISSING = {
    "flow_run": "The build's acceptance result was not presented, so the workflow stopped.",
    "gate_results": "The build's gate results were not presented, so the workflow stopped.",
}

#: The two refusals `experience.advance` writes about evidence, as
#: `build_outcome` records them under its "refused" prefix -- anchored, so a
#: kind's name elsewhere in the text matches neither.
_REFUSED_FAILED = re.compile(
    r"refused: the presented '(flow_run|gate_results)' evidence \([^()]*\) reports failure"
)
_REFUSED_MISSING = re.compile(
    r"refused: advancing into [A-Z]+ requires evidence of kind "
    r"'(flow_run|gate_results)', which was not presented"
)


def _structured_refusal(text: str) -> dict[str, str | None] | None:
    """The headline for a structured evidence refusal, or `None` for any other text."""
    failed = _REFUSED_FAILED.match(text)
    if failed:
        kind = failed.group(1)
        return {"summary": _KIND_FAILED[kind], "check": _KIND_CHECKS[kind]}
    missing = _REFUSED_MISSING.match(text)
    if missing:
        kind = missing.group(1)
        return {"summary": _KIND_MISSING[kind], "check": _KIND_CHECKS[kind]}
    return None
