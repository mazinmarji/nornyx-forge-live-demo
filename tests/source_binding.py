"""Bind a test capsule's confirmed requirements to a source specification.

Since A-060, a BRD is derived only from a capsule whose confirmed intent and
requirements are bound to a confirmed source specification. Tests whose
subject is something else -- the lifecycle, the build route, the receipt --
bind the plainest source there is: the confirmed words themselves, one per
line, each requirement recorded as verbatim. That keeps every such test
about its own subject; `test_source_provenance.py` is where the binding is
the subject.

Both helpers are idempotent: a capsule already bound is returned unchanged,
so one can stand in front of every derivation without moving a capsule that
needs no move. Two forms, for the two ways the suite builds a capsule:
directly through the capsule module, or through the onboarding routes.
"""

from __future__ import annotations

from typing import Any, Mapping

from nornyx_forge.capsule import Actor, confirm, propose
from nornyx_forge.source_provenance import binding_problems

DEFAULT_HUMAN = {"kind": "human", "ident": "casey"}


def plain_source(authoritative: Mapping[str, Any]) -> str:
    """The confirmed intent and requirement texts, one per line."""
    lines = []
    if isinstance(authoritative.get("intent"), str):
        lines.append(authoritative["intent"])
    lines.extend(row["text"] for row in authoritative.get("requirements") or [])
    return "\n".join(line for line in lines if _encodable(line)) or "Specification."


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def verbatim_records(authoritative: Mapping[str, Any]) -> list[dict[str, str]]:
    return [{"requirement": row["id"], "kind": "verbatim", "excerpt": row["text"], "change": ""}
            for row in authoritative.get("requirements") or []]


def _needs(region: Mapping[str, Any]) -> list[str]:
    """The fields to (re)confirm so that `region` is bound, in order."""
    if not binding_problems({"authoritative": region}):
        return []
    source = (region.get("source_specification") or {}).get("text")
    fields = []
    if source is None or any(row["text"] not in source for row in region.get("requirements") or []):
        fields.append("source_specification")
    if region.get("requirements"):
        fields.append("requirement_sources")
    return fields


def _value(field: str, region: Mapping[str, Any]) -> Any:
    if field == "source_specification":
        return {"text": plain_source(region)}
    return verbatim_records(region)


def bound(document: Mapping[str, Any]) -> dict:
    """A hand-built document (one with no digest chain) with its region bound
    in place: for the tests that hand the derivation a bare
    `{"authoritative": ...}` mapping and judge only its rendering."""
    region = dict(document["authoritative"])
    region["source_specification"] = {"text": plain_source(region)}
    if region.get("requirements"):
        region["requirement_sources"] = verbatim_records(region)
    return {**document, "authoritative": region}


def bind_document(document: dict, human: Actor, at: str, *, proposer: Actor | None = None) -> dict:
    """The document with its confirmed words confirmed as their own source."""
    author = proposer or human
    for field in _needs(document["authoritative"]):
        document, proposal_id = propose(document, field, _value(field, document["authoritative"]),
                                        author, at)
        document = confirm(document, proposal_id, human, at)
    return document


def bind_via_routes(client: Any, human: Mapping[str, str] = DEFAULT_HUMAN,
                    proposer: Mapping[str, str] | None = None) -> None:
    """The same binding, proposed and confirmed through the onboarding routes.

    Does nothing where there is no project or no confirmed intent to bind."""
    author = proposer or human
    state = client.get("/api/state").json()
    region = state.get("authoritative")
    if not state.get("initialized") or not isinstance(region, Mapping) or "intent" not in region:
        return
    for field in _needs(region):
        response = client.post("/api/proposals", json={"field": field,
                                                       "value": _value(field, region),
                                                       "actor": author})
        assert response.status_code == 200, response.text
        proposal_id = response.json()["proposal_id"]
        response = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": human})
        assert response.status_code == 200, response.text
        region = client.get("/api/state").json()["authoritative"]


def confirm_source_via_routes(client: Any, text: str, human: Mapping[str, str] = DEFAULT_HUMAN,
                              proposer: Mapping[str, str] | None = None) -> None:
    """Confirm `text` as the source without reading the state first: for a
    test whose confirmed words the state route cannot serve."""
    response = client.post("/api/proposals", json={"field": "source_specification",
                                                   "value": {"text": text},
                                                   "actor": proposer or human})
    assert response.status_code == 200, response.text
    response = client.post(f"/api/proposals/{response.json()['proposal_id']}/confirm",
                           json={"actor": human})
    assert response.status_code == 200, response.text
