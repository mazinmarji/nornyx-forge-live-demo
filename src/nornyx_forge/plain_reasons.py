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
from typing import Any, Mapping, Sequence

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

    THE SUMMARY CLAIMS NO MORE THAN THE RECORD CARRIES. `flow_run`'s
    `passed` is the flow's own aggregate `accepted` flag, which folds the
    build's tests, gates, reviews and evidence-ledger checks into one value,
    and `gate_results` passes only when every recorded gate did. Neither says
    WHICH check failed. What does is the acceptance note (A-064) that
    `with_acceptance_note` appends to a rejected run's refusal: when it is the
    last thing in a `flow_run` refusal and is consistent, the summary names
    the first failing check and any requirement it found untested. Without a
    consistent note -- every failure recorded before A-064, or a note that
    does not parse -- the summary names no check, exactly as before: a run
    whose tests passed but whose review or ledger check failed is refused with
    the same `flow_run` text, and calling that a test failure would be false.

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
        if kind == "flow_run":
            noted = _noted_rejection(text, failed.end())
            if noted is not None:
                return noted
        return {"summary": _KIND_FAILED[kind], "check": _KIND_CHECKS[kind]}
    missing = _REFUSED_MISSING.match(text)
    if missing:
        kind = missing.group(1)
        return {"summary": _KIND_MISSING[kind], "check": _KIND_CHECKS[kind]}
    return None


# ---------------------------------------------------------------------------
# A-064: a rejected run names its first failing check.
# ---------------------------------------------------------------------------

#: The plain name of every gate Forge itself names with a FIXED string. The
#: keys are the only gate names that can reach a person's summary or a
#: receipt: a gate named any other way -- a repository-mode gate is named by
#: its own command line -- is recorded as `unlisted`, and its name and detail
#: go nowhere. This table is vocabulary, not policy: it decides no gate.
GATE_PLAIN_NAMES: Mapping[str, str] = {
    "greenfield:project-structure": "the project structure check",
    "greenfield:requirements-traceability": "the requirements traceability check",
    "greenfield:source-compilation": "the source compilation check",
    "greenfield:test-semantics": "the test semantics check",
    "greenfield:architecture-boundary": "the architecture boundary check",
    "greenfield:security-static": "the static security check",
    "greenfield:test-execution": "the isolated test run",
    "greenfield:nornyx-contract-check": "the Nornyx governance check",
    "greenfield:contract-truth": "the contract truth check",
    "greenfield:trusted-verifier-identity": "the trusted verifier identity check",
    "greenfield:provenance-stability": "the verifier provenance check",
    "build-evidence-ledger-valid-before-verdict": "the build evidence record check (before the verdict)",
    "build-evidence-ledger-valid-after-verdict": "the build evidence record check (after the verdict)",
    "in-session AI review records complete": "the in-session review records check",
    "requirements": "the requirements check",
    "foundation": "the foundation check",
    "solution-architect": "the solution architect's run",
    "application-builder": "the application builder's run",
    "review-worker:completed": "an AI reviewer's run",
    "review-worker:verdict": "an AI reviewer's verdict",
}

#: The gate whose detail names requirements the tests do not reference.
TRACEABILITY_GATE = "greenfield:requirements-traceability"

#: A well-formed BRD requirement identifier, as the verifier defines it
#: (`greenfield_verifier.brd_requirement_identity`). Restated rather than
#: imported: the verifier is not a dependency of this layer. A test pins the
#: two equal.
REQUIREMENT_ID = re.compile(r"BRD-[A-Z0-9]+(?:-[A-Z0-9]+)*")

#: Requirement identifiers named in a summary, at most; the rest are counted.
_MAX_IDS = 5
_MAX_ID_LENGTH = 32
#: The persisted reason's bound (`experience.fail`).
_REASON_LIMIT = 500

_REVIEW_GATE = re.compile(r"\Areview-worker:[a-z0-9_-]{1,40}:(completed|verdict)\Z")

_IDS = r"BRD-[A-Z0-9]+(?:-[A-Z0-9]+)*(?:,BRD-[A-Z0-9]+(?:-[A-Z0-9]+)*){0,4}"
_ACCEPTANCE_NOTE = re.compile(
    r" \[acceptance: first-failing=([a-z0-9:_-]{1,64}|in-session-review-records); "
    r"others-not-passed=(\d{1,4}); "
    r"untraced=(-|" + _IDS + r"(?:,\+\d{1,4})?|\+\d{1,4})\]\Z"
)


def _gate_token(name: Any) -> str:
    """The token a gate is recorded under: its fixed name, or `unlisted`."""
    if not isinstance(name, str):
        return "unlisted"
    review = _REVIEW_GATE.match(name)
    if review:
        return f"review-worker:{review.group(1)}"
    if name == "in-session AI review records complete":
        return "in-session-review-records"
    return name if name in GATE_PLAIN_NAMES else "unlisted"


def _untraced_ids(detail: Any) -> list[str]:
    """Well-formed requirement identifiers in the traceability gate's detail."""
    seen: list[str] = []
    for found in REQUIREMENT_ID.findall(detail if isinstance(detail, str) else ""):
        if len(found) <= _MAX_ID_LENGTH and found not in seen:
            seen.append(found)
    return seen


def _note(token: str, others: int, untraced: str) -> str:
    return f" [acceptance: first-failing={token}; others-not-passed={others}; untraced={untraced}]"


def with_acceptance_note(reason: str, gates: Sequence[Mapping[str, Any]]) -> str:
    """`reason`, followed by what the rejected run's own gates say about it.

    The note is built from closed vocabulary only: the first failing gate's
    fixed name (or `unlisted`, or `none` when every gate passed), how many
    other gates did not pass, and -- for the traceability gate alone -- the
    well-formed requirement identifiers its detail names. No gate's name or
    detail is copied. The reason comes first and is never altered; when the
    note would cross the persisted bound it gives way: first its identifiers
    become a count, then it is left out.
    """
    failing = [gate for gate in gates if gate.get("passed") is not True]
    if not failing:
        candidates = [_note("none", 0, "-")]
    else:
        first = failing[0]
        token = _gate_token(first.get("name"))
        others = min(len(failing) - 1, 9999)
        ids = _untraced_ids(first.get("detail")) if token == TRACEABILITY_GATE else []
        if ids:
            shown = ",".join(ids[:_MAX_IDS])
            more = len(ids) - _MAX_IDS
            listed = shown + (f",+{min(more, 9999)}" if more > 0 else "")
            candidates = [_note(token, others, listed),
                          _note(token, others, f"+{min(len(ids), 9999)}"),
                          _note(token, others, "-")]
        else:
            candidates = [_note(token, others, "-")]
    for note in candidates:
        if len(reason) + len(note) <= _REASON_LIMIT:
            return reason + note
    return reason


def _plain_name(token: str) -> str | None:
    if token == "in-session-review-records":
        return GATE_PLAIN_NAMES["in-session AI review records complete"]
    return GATE_PLAIN_NAMES.get(token)


def _noted_rejection(text: str, start: int) -> dict[str, str | None] | None:
    """The headline a consistent acceptance note licenses, or `None`.

    Read only from the end of a `flow_run` refusal, after the contract's own
    words. Anything inconsistent -- an unknown token, a count beside `none`,
    identifiers on a gate other than traceability -- licenses nothing, and
    the caller falls back to the aggregate wording.
    """
    note = _ACCEPTANCE_NOTE.search(text, start)
    if note is None:
        return None
    token, others_text, untraced = note.groups()
    others = int(others_text)
    if token == "none":
        if others or untraced != "-":
            return None
        return {
            "summary": ("Every recorded check passed, but the build was not accepted, "
                        "so the workflow stopped. This summary does not say what "
                        "withheld acceptance."),
            "check": _KIND_CHECKS["flow_run"],
        }
    if untraced != "-" and token != TRACEABILITY_GATE:
        return None
    tail = f" {others} other check{'s' if others != 1 else ''} also did not pass." if others else ""
    if token == "unlisted":
        if untraced != "-":
            return None
        return {
            "summary": ("The build was not accepted, so the workflow stopped. The first "
                        "check that failed is one this summary does not name." + tail),
            "check": _KIND_CHECKS["flow_run"],
        }
    plain = _plain_name(token)
    if plain is None:
        return None
    sentence = (f"The build was not accepted, so the workflow stopped. The first check "
                f"that failed is {plain}.")
    if untraced != "-":
        parts = untraced.split(",")
        more = int(parts.pop()[1:]) if parts[-1].startswith("+") else 0
        if parts:
            named = ", ".join(parts) + (f" and {more} more" if more else "")
            noun = "requirement" if len(parts) == 1 and not more else "requirements"
            sentence += f" The tests do not cover {noun} {named}."
        else:
            sentence += f" The tests do not cover {more} requirement{'s' if more != 1 else ''}."
    return {"summary": sentence + tail, "check": plain}
