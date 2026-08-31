"""The experience-sharing preview: minimized, displayed, never transmitted.

WHAT THIS IS FOR. The target state lets a user REVIEW privacy-minimized
experience-sharing information — and the founder's correction C5 fixes the
other half: the sharing layer is design-only and TRANSMIT-NEVER until a
separate founder decision authorizes a receiving backend. This module is
the review half with the never-transmit half built in structurally: it
derives a preview and returns it to be displayed, it imports nothing that
can reach a network, and non-transmission is recorded IN the payload as
data — never implied by an absence someone could misread.

MINIMIZATION IS A CLOSED REGISTRY, both directions: only the fields in
SHARED_FIELDS may appear, and every one of them is a count, a stage name
from the closed stage vocabulary, a provider name from the closed provider
vocabulary, a boolean, or a fingerprint — never free text. The project
name and the user's own words (intent, requirements, decisions) are
exactly what a sharing payload could leak, so the derivation never reads
their values beyond hashing the project identity, and a guard refuses any
payload in which capsule free text survives verbatim.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

#: Every key a sharing preview may EVER carry. Growing this tuple is the
#: single deliberate act that widens what Forge would ever share -- a diff
#: to review, not a field to discover in an incident.
SHARED_FIELDS = (
    "schema",
    "project_fingerprint",
    "provider",
    "stage",
    "proposals_opened",
    "proposals_confirmed",
    "proposals_rejected",
    "authority_confirmations",
    "lifecycle_recorded",
    "transmission",
)

SHARING_SCHEMA = "nornyx.forge.sharing_preview.v1"

#: The transmission state, as data. C5: there is no receiving backend and
#: no authorization for one; a payload that failed to SAY so could be
#: mistaken for one that was sent.
TRANSMISSION_STATE = {
    "authorized": False,
    "reason": (
        "no founder decision authorizes a receiving backend; the sharing "
        "layer is review-only and this payload was never sent anywhere"
    ),
}


class SharingError(Exception):
    """A payload or input this module refuses."""


def _free_text_values(document: Mapping[str, Any]) -> list[str]:
    """The capsule strings a sharing payload could leak: the user's words."""
    values: list[str] = [str(document.get("project_id", ""))]
    authoritative = document.get("authoritative", {})
    values.append(str(authoritative.get("project_name", "")))
    intent = authoritative.get("intent")
    if isinstance(intent, str):
        values.append(intent)
    for row in document.get("proposed", []):
        if isinstance(row.get("value"), str):
            values.append(row["value"])
    return [value for value in values if len(value) >= 4]


def assert_minimized(payload: Mapping[str, Any], document: Mapping[str, Any]) -> None:
    """Refuse any payload that could carry the user's words at all.

    A first draft swept the serialized payload for the capsule's free-text
    VALUES verbatim — and its own specimen walked through it, because a leak
    of a FRAGMENT of the user's words matches no whole value. The rule is
    now shape-closed instead of sweep-based: every string the payload
    carries must come from a closed vocabulary or match a closed shape, so
    there is no field in which arbitrary text can ride, whole or fragmented.
    The verbatim sweep is kept as a second net behind the shapes.
    """
    import json  # noqa: PLC0415 - serialization for the sweep only
    import re  # noqa: PLC0415 - the fingerprint shape

    from .capsule import PROVIDERS  # noqa: PLC0415 - closed vocabulary
    from .experience import STAGES  # noqa: PLC0415 - closed vocabulary

    unregistered = sorted(set(payload) - set(SHARED_FIELDS))
    if unregistered:
        raise SharingError(
            f"the payload carries fields outside the shared registry: "
            f"{unregistered}"
        )
    shape_errors: list[str] = []
    if payload.get("schema") != SHARING_SCHEMA:
        shape_errors.append("schema is not the sharing schema constant")
    if not re.fullmatch(r"[0-9a-f]{16}", str(payload.get("project_fingerprint", ""))):
        shape_errors.append("project_fingerprint is not a 16-hex fingerprint")
    if payload.get("provider") not in (None, *PROVIDERS):
        shape_errors.append("provider is outside the closed provider vocabulary")
    if payload.get("stage") not in (None, *STAGES):
        shape_errors.append("stage is outside the closed stage vocabulary")
    for field in ("proposals_opened", "proposals_confirmed", "proposals_rejected",
                  "authority_confirmations"):
        if not isinstance(payload.get(field), int) or isinstance(payload.get(field), bool):
            shape_errors.append(f"{field} is not a count")
    if not isinstance(payload.get("lifecycle_recorded"), bool):
        shape_errors.append("lifecycle_recorded is not a boolean")
    if payload.get("transmission") != TRANSMISSION_STATE:
        shape_errors.append(
            "transmission does not carry the exact never-sent state"
        )
    if shape_errors:
        raise SharingError(
            "minimization failed: " + "; ".join(shape_errors)
        )
    serialized = json.dumps(payload, sort_keys=True)
    for value in _free_text_values(document):
        if value in serialized:
            raise SharingError(
                "minimization failed: capsule free text survives verbatim in "
                "the sharing payload"
            )


def sharing_preview(
    document: Mapping[str, Any],
    experience: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Derive the reviewable payload from capsule and lifecycle state.

    Counts, closed-vocabulary names, booleans, one fingerprint. The
    fingerprint is a digest of the project identity so two payloads from
    the same project are linkable WITHOUT the identity being readable.
    Absent lifecycle state is recorded as absent, never invented.
    """
    if not isinstance(document, Mapping) or "authoritative" not in document:
        raise SharingError("a sharing preview needs a capsule document")
    proposals = document.get("proposed", [])
    provider = document["authoritative"].get("provider")
    payload: dict[str, Any] = {
        "schema": SHARING_SCHEMA,
        "project_fingerprint": hashlib.sha256(
            str(document.get("project_id", "")).encode("utf-8")
        ).hexdigest()[:16],
        "provider": provider["name"] if isinstance(provider, Mapping) else None,
        "stage": experience.get("stage") if experience else None,
        "proposals_opened": len(proposals),
        "proposals_confirmed": sum(
            1 for row in proposals if row.get("status") == "confirmed"
        ),
        "proposals_rejected": sum(
            1 for row in proposals if row.get("status") == "rejected"
        ),
        "authority_confirmations": max(len(document.get("digest_chain", [])) - 1, 0),
        "lifecycle_recorded": experience is not None,
        "transmission": dict(TRANSMISSION_STATE),
    }
    assert_minimized(payload, document)
    return payload
