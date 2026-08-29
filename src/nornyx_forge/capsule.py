"""The Forge Project Capsule: canonical project state with an authority split.

WHAT THIS IS FOR. Forge is becoming usable through more than one AI provider.
Provider output is capable prose from an untrusted author, and the one thing a
multi-provider Forge must never do is let that prose *become* project authority
because it was well-formatted. The capsule is the mechanism: every document has
three regions with different trust, and the region boundaries are enforced
here, in one pure module, rather than by the goodwill of each caller.

    authoritative   what the project HAS DECIDED. Written only by `confirm`,
                    which requires a HUMAN actor, and covered by a digest
                    chain so out-of-band edits are detectable.
    proposed        where ALL model and system output lands. Schema-validated
                    at the door -- untrusted is not unvalidated -- but carrying
                    no authority until a human confirms it.
    derived         regenerable renderings. Never authority, never digested,
                    never a source for `authoritative`.

The split is C1/C2 of the Forge evolution review made mechanical: a model may
*propose* anything the schema admits; only a human confirmation moves content
across the authority line; and the line is a data-structure property a test can
revert-prove, not a convention.

PURITY. This module is `layer.domain` and touches nothing outside its
arguments: no filesystem, no clock, no process, no randomness. Timestamps and
identifiers arrive as parameters. Persistence and git binding live in
`capsule_store` (`layer.adapter`), because a domain object that could reach the
filesystem could re-resolve its own state, and the whole point of the digest
chain is that state cannot change without the change being visible here.

WHAT THE DIGEST CHAIN DOES AND DOES NOT ESTABLISH. Each confirmation appends
sha256(previous_digest + canonical(authoritative)) to a chain stored in the
document. `verify_integrity` recomputes it, so a hand edit to the authoritative
region -- or to the chain itself -- fails closed as TAMPERED. It is a
tamper-EVIDENCE mechanism against out-of-band edits, not a signature: an
attacker who can rewrite the whole file can rebuild the whole chain. Detecting
that requires the store's git history or an external anchor, and this module
does not claim otherwise.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

SCHEMA_VERSION = 1

#: Actor kinds, closed. `human` is the only kind `confirm` accepts, and the
#: check is on this field -- not on the actor's name, which anyone can spell.
ACTOR_KINDS = ("human", "model", "system")

#: Providers the capsule may record. Closed on purpose: a third provider is
#: deferred until the Codex<->Claude equivalence proof exists, and widening
#: this tuple is the deliberate act that records the decision to add one.
PROVIDERS = ("codex", "claude")

_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@ -]{0,119}$")
_ISO_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_REQUIREMENT_ID = re.compile(r"^RQ-\d{1,6}$")
_DECISION_ID = re.compile(r"^DC-\d{1,6}$")
#: Relative, forward-slash, .nyx, and no traversal. The dot is permitted in
#: names but ".." as a path SEGMENT is refused below, which is the property;
#: refusing the substring would also refuse "a..b.nyx", a legal name.
_CONTRACT_REF = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.nyx$")
_PROPOSAL_ID = re.compile(r"^P-\d{1,6}$")
_DERIVED_KEY = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")


class CapsuleError(Exception):
    """Base for every capsule refusal."""


class CapsuleValidationError(CapsuleError):
    """The value does not satisfy the schema. Nothing was changed."""


class CapsuleTransitionError(CapsuleError):
    """The operation is not permitted from this state or by this actor."""


class CapsuleTamperError(CapsuleError):
    """The authoritative region does not match its digest chain."""


@dataclass(frozen=True)
class Actor:
    """Who did something, and what KIND of author they are.

    The kind is the load-bearing field. Authority decisions in this module test
    `kind == "human"` and nothing else about the actor: names are spellings,
    and this codebase does not decide properties by spelling.
    """

    kind: str
    ident: str

    def validate(self) -> None:
        if self.kind not in ACTOR_KINDS:
            raise CapsuleValidationError(
                f"actor kind {self.kind!r} is not one of {ACTOR_KINDS}"
            )
        if not isinstance(self.ident, str) or not _IDENT.match(self.ident):
            raise CapsuleValidationError(f"actor ident {self.ident!r} is not acceptable")


# --------------------------------------------------------------------------
# Field schema: a CLOSED registry of validators.
#
# Closed sets, not counts, and validators, not type names: a count is unchanged
# when one member is swapped for another, and a type name admits every value of
# the type. Each validator raises CapsuleValidationError with the exact reason.
# --------------------------------------------------------------------------

def _require_str(value: Any, field: str, max_len: int) -> None:
    if not isinstance(value, str):
        raise CapsuleValidationError(f"{field} must be a string")
    if not value.strip():
        raise CapsuleValidationError(f"{field} must not be empty")
    if len(value) > max_len:
        raise CapsuleValidationError(f"{field} exceeds {max_len} characters")
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
        raise CapsuleValidationError(f"{field} contains control characters")


def _validate_project_name(value: Any) -> None:
    _require_str(value, "project_name", 120)
    if "\n" in value:
        raise CapsuleValidationError("project_name must be a single line")


def _validate_intent(value: Any) -> None:
    _require_str(value, "intent", 4000)


def _validate_requirements(value: Any) -> None:
    if not isinstance(value, list):
        raise CapsuleValidationError("requirements must be a list")
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {"id", "text"}:
            raise CapsuleValidationError(
                "each requirement must be an object with exactly {id, text}"
            )
        if not isinstance(row["id"], str) or not _REQUIREMENT_ID.match(row["id"]):
            raise CapsuleValidationError(f"requirement id {row['id']!r} must match RQ-<n>")
        if row["id"] in seen:
            raise CapsuleValidationError(f"requirement id {row['id']} is duplicated")
        seen.add(row["id"])
        _require_str(row["text"], f"requirement {row['id']} text", 2000)


def _validate_decisions(value: Any) -> None:
    if not isinstance(value, list):
        raise CapsuleValidationError("decisions must be a list")
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {"id", "text", "decided_by", "at"}:
            raise CapsuleValidationError(
                "each decision must be an object with exactly {id, text, decided_by, at}"
            )
        if not isinstance(row["id"], str) or not _DECISION_ID.match(row["id"]):
            raise CapsuleValidationError(f"decision id {row['id']!r} must match DC-<n>")
        if row["id"] in seen:
            raise CapsuleValidationError(f"decision id {row['id']} is duplicated")
        seen.add(row["id"])
        _require_str(row["text"], f"decision {row['id']} text", 2000)
        _require_str(row["decided_by"], f"decision {row['id']} decided_by", 120)
        _validate_at(row["at"], f"decision {row['id']} at")


def _validate_contract_refs(value: Any) -> None:
    """Relative .nyx paths with no traversal and no absolute form.

    The capsule names governance artifacts; it must not be able to name a path
    outside its project. Segment-wise refusal of ".." is the property -- a
    substring test would also refuse legal names containing consecutive dots.
    """
    if not isinstance(value, list):
        raise CapsuleValidationError("authority_contract_refs must be a list")
    for ref in value:
        if not isinstance(ref, str) or not _CONTRACT_REF.match(ref):
            raise CapsuleValidationError(
                f"contract ref {ref!r} must be a relative path to a .nyx file"
            )
        if any(segment == ".." for segment in ref.split("/")):
            raise CapsuleValidationError(f"contract ref {ref!r} traverses upward")


def _validate_provider(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"name"}:
        raise CapsuleValidationError("provider must be an object with exactly {name}")
    if value["name"] not in PROVIDERS:
        raise CapsuleValidationError(
            f"provider {value['name']!r} is not one of {PROVIDERS}"
        )


def _validate_limitations(value: Any) -> None:
    if not isinstance(value, list):
        raise CapsuleValidationError("limitations must be a list")
    for index, item in enumerate(value):
        _require_str(item, f"limitation[{index}]", 2000)


#: THE closed registry. A field outside it cannot be proposed, confirmed, or
#: smuggled in by load: `validate_document` rejects unknown keys in every
#: region, so growing this dict is the single deliberate act that widens the
#: capsule -- reviewable in a diff, not discoverable in an incident.
AUTHORITATIVE_FIELDS: Mapping[str, Callable[[Any], None]] = {
    "project_name": _validate_project_name,
    "intent": _validate_intent,
    "requirements": _validate_requirements,
    "decisions": _validate_decisions,
    "authority_contract_refs": _validate_contract_refs,
    "provider": _validate_provider,
    "limitations": _validate_limitations,
}

_PROPOSAL_STATUSES = ("open", "confirmed", "rejected")


def _validate_at(value: Any, field: str = "at") -> None:
    if not isinstance(value, str) or not _ISO_AT.match(value):
        raise CapsuleValidationError(f"{field} must be an ISO-8601 UTC/offset timestamp")


# --------------------------------------------------------------------------
# Canonicalisation and the digest chain
# --------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    """One byte-stable encoding, so a digest is about content, not formatting."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _chain_digest(previous: str, authoritative: Mapping[str, Any]) -> str:
    payload = previous + "|" + canonical_json(authoritative)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


GENESIS = "0" * 64


def verify_integrity(document: Mapping[str, Any]) -> None:
    """Fail closed if the authoritative region and its chain disagree.

    Recomputes the final link from the recorded previous link and the current
    authoritative content. An edit to the authoritative region, to the final
    digest, or a truncation of the chain all surface here as TAMPERED.
    """
    chain = document.get("digest_chain")
    if not isinstance(chain, list) or not chain:
        raise CapsuleTamperError("the digest chain is missing")
    previous = chain[-2] if len(chain) > 1 else GENESIS
    expected = _chain_digest(previous, document.get("authoritative", {}))
    if chain[-1] != expected:
        raise CapsuleTamperError(
            "the authoritative region does not match its digest chain; the "
            "capsule was modified outside `confirm` and is not trusted"
        )


# --------------------------------------------------------------------------
# Document validation
# --------------------------------------------------------------------------

_TOP_LEVEL_KEYS = {
    "schema_version", "project_id", "created",
    "authoritative", "digest_chain", "proposed", "derived", "history",
}


def validate_document(document: Mapping[str, Any]) -> None:
    """Every region satisfies its schema; every key set is closed.

    Validation is structural only. It deliberately does NOT verify the digest
    chain -- `verify_integrity` does, separately -- so a caller can distinguish
    "malformed" from "tampered": the second is the graver finding and must not
    hide inside the first.
    """
    if not isinstance(document, Mapping):
        raise CapsuleValidationError("the capsule document must be an object")
    unknown = set(document) - _TOP_LEVEL_KEYS
    if unknown:
        raise CapsuleValidationError(f"unknown top-level keys: {sorted(unknown)}")
    missing = _TOP_LEVEL_KEYS - set(document)
    if missing:
        raise CapsuleValidationError(f"missing top-level keys: {sorted(missing)}")

    if document["schema_version"] != SCHEMA_VERSION:
        raise CapsuleValidationError(
            f"schema_version {document['schema_version']!r} is not {SCHEMA_VERSION}"
        )
    if not isinstance(document["project_id"], str) or not _IDENT.match(document["project_id"]):
        raise CapsuleValidationError("project_id is not acceptable")

    created = document["created"]
    if not isinstance(created, dict) or set(created) != {"by", "kind", "at"}:
        raise CapsuleValidationError("created must be an object with exactly {by, kind, at}")
    Actor(kind=created["kind"], ident=created["by"]).validate()
    _validate_at(created["at"], "created.at")

    authoritative = document["authoritative"]
    if not isinstance(authoritative, dict):
        raise CapsuleValidationError("authoritative must be an object")
    unknown = set(authoritative) - set(AUTHORITATIVE_FIELDS)
    if unknown:
        raise CapsuleValidationError(
            f"authoritative carries undeclared fields: {sorted(unknown)}"
        )
    for field, value in authoritative.items():
        AUTHORITATIVE_FIELDS[field](value)

    chain = document["digest_chain"]
    if not isinstance(chain, list) or not chain or not all(
        isinstance(link, str) and re.fullmatch(r"[0-9a-f]{64}", link) for link in chain
    ):
        raise CapsuleValidationError("digest_chain must be a non-empty list of sha256 hex")

    proposals = document["proposed"]
    if not isinstance(proposals, list):
        raise CapsuleValidationError("proposed must be a list")
    seen_ids: set[str] = set()
    for row in proposals:
        _validate_proposal_row(row, seen_ids)

    derived = document["derived"]
    if not isinstance(derived, dict):
        raise CapsuleValidationError("derived must be an object")
    for key, value in derived.items():
        if not isinstance(key, str) or not _DERIVED_KEY.match(key):
            raise CapsuleValidationError(f"derived key {key!r} is not acceptable")
        if not isinstance(value, str) or len(value) > 20000:
            raise CapsuleValidationError(f"derived[{key}] must be a string under 20000 chars")

    history = document["history"]
    if not isinstance(history, list):
        raise CapsuleValidationError("history must be a list")
    for event in history:
        if not isinstance(event, dict) or set(event) != {"event", "by", "kind", "at", "detail"}:
            raise CapsuleValidationError(
                "each history event must be an object with exactly "
                "{event, by, kind, at, detail}"
            )
        Actor(kind=event["kind"], ident=event["by"]).validate()
        _validate_at(event["at"], "history.at")
        _require_str(event["event"], "history.event", 60)
        _require_str(event["detail"], "history.detail", 500)


def _validate_proposal_row(row: Any, seen_ids: set[str]) -> None:
    expected = {"proposal_id", "field", "value", "author", "kind", "at", "status", "resolved"}
    if not isinstance(row, dict) or set(row) != expected:
        raise CapsuleValidationError(
            "each proposal must be an object with exactly "
            "{proposal_id, field, value, author, kind, at, status, resolved}"
        )
    if not isinstance(row["proposal_id"], str) or not _PROPOSAL_ID.match(row["proposal_id"]):
        raise CapsuleValidationError(f"proposal id {row['proposal_id']!r} must match P-<n>")
    if row["proposal_id"] in seen_ids:
        raise CapsuleValidationError(f"proposal id {row['proposal_id']} is duplicated")
    seen_ids.add(row["proposal_id"])
    if row["field"] not in AUTHORITATIVE_FIELDS:
        raise CapsuleValidationError(
            f"proposal targets undeclared field {row['field']!r}"
        )
    AUTHORITATIVE_FIELDS[row["field"]](row["value"])
    Actor(kind=row["kind"], ident=row["author"]).validate()
    _validate_at(row["at"], "proposal.at")
    if row["status"] not in _PROPOSAL_STATUSES:
        raise CapsuleValidationError(f"proposal status {row['status']!r} is not permitted")
    resolved = row["resolved"]
    if row["status"] == "open":
        if resolved is not None:
            raise CapsuleValidationError("an open proposal must carry resolved: null")
    else:
        if not isinstance(resolved, dict) or set(resolved) != {"by", "kind", "at"}:
            raise CapsuleValidationError(
                "a resolved proposal must record {by, kind, at}"
            )
        Actor(kind=resolved["kind"], ident=resolved["by"]).validate()
        _validate_at(resolved["at"], "resolved.at")


# --------------------------------------------------------------------------
# Transitions. Pure: document in, new document out; inputs never mutated.
# --------------------------------------------------------------------------

def _copy(document: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(document))


def create_document(project_id: str, project_name: str, created_by: Actor, at: str) -> dict[str, Any]:
    """A new capsule. Creation is a human act.

    A project exists because a person decided it should; a model or a pipeline
    proposing a project is a proposal like any other and has no capsule to put
    it in yet. `kind == "human"` is therefore required at the root, for the
    same reason `confirm` requires it at every step after.
    """
    created_by.validate()
    if created_by.kind != "human":
        raise CapsuleTransitionError("a capsule is created by a human actor")
    if not isinstance(project_id, str) or not _IDENT.match(project_id):
        raise CapsuleValidationError(f"project_id {project_id!r} is not acceptable")
    _validate_at(at)
    _validate_project_name(project_name)

    authoritative = {"project_name": project_name}
    document = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "created": {"by": created_by.ident, "kind": created_by.kind, "at": at},
        "authoritative": authoritative,
        "digest_chain": [_chain_digest(GENESIS, authoritative)],
        "proposed": [],
        "derived": {},
        "history": [{
            "event": "created", "by": created_by.ident, "kind": created_by.kind,
            "at": at, "detail": f"project {project_name!r}",
        }],
    }
    validate_document(document)
    return document


def propose(
    document: Mapping[str, Any], field: str, value: Any, author: Actor, at: str
) -> tuple[dict[str, Any], str]:
    """Any actor may propose. The value is validated NOW, at the door.

    Untrusted is not unvalidated: a proposal that does not satisfy the field
    schema is refused before it is stored, so the proposed region never
    accumulates shapes the schema cannot account for. What validation does NOT
    do is confer authority -- a valid proposal is still only a proposal.
    """
    author.validate()
    _validate_at(at)
    if field not in AUTHORITATIVE_FIELDS:
        raise CapsuleValidationError(f"proposal targets undeclared field {field!r}")
    AUTHORITATIVE_FIELDS[field](value)

    updated = _copy(document)
    proposal_id = f"P-{len(updated['proposed']) + 1}"
    updated["proposed"].append({
        "proposal_id": proposal_id, "field": field, "value": value,
        "author": author.ident, "kind": author.kind, "at": at,
        "status": "open", "resolved": None,
    })
    updated["history"].append({
        "event": "proposed", "by": author.ident, "kind": author.kind, "at": at,
        "detail": f"{proposal_id} -> {field}",
    })
    validate_document(updated)
    return updated, proposal_id


def confirm(
    document: Mapping[str, Any], proposal_id: str, confirmed_by: Actor, at: str
) -> dict[str, Any]:
    """The ONLY path into the authoritative region, and it is human-gated.

    Three refusals, in order of importance:

      * a non-human actor cannot confirm -- this is the authority line itself,
        and it tests the actor's KIND, not their name;
      * the proposal must exist and be open -- confirming twice, or confirming
        a rejection, is a state error, not an idempotent no-op, because a
        second "yes" the user never gave must not be synthesizable;
      * the value is re-validated against the CURRENT schema, so a proposal
        stored under an older, looser rule cannot slide in unchecked.

    On success the digest chain is extended, which is what makes out-of-band
    edits to the result detectable.
    """
    confirmed_by.validate()
    _validate_at(at)
    if confirmed_by.kind != "human":
        raise CapsuleTransitionError(
            "only a human actor may confirm a proposal into the authoritative "
            f"region; got kind={confirmed_by.kind!r}"
        )
    verify_integrity(document)

    updated = _copy(document)
    row = next(
        (item for item in updated["proposed"] if item["proposal_id"] == proposal_id),
        None,
    )
    if row is None:
        raise CapsuleTransitionError(f"no proposal {proposal_id!r} exists")
    if row["status"] != "open":
        raise CapsuleTransitionError(
            f"proposal {proposal_id} is {row['status']}, not open"
        )
    AUTHORITATIVE_FIELDS[row["field"]](row["value"])

    updated["authoritative"][row["field"]] = row["value"]
    updated["digest_chain"].append(
        _chain_digest(updated["digest_chain"][-1], updated["authoritative"])
    )
    row["status"] = "confirmed"
    row["resolved"] = {"by": confirmed_by.ident, "kind": confirmed_by.kind, "at": at}
    updated["history"].append({
        "event": "confirmed", "by": confirmed_by.ident, "kind": confirmed_by.kind,
        "at": at, "detail": f"{proposal_id} -> {row['field']}",
    })
    validate_document(updated)
    verify_integrity(updated)
    return updated


def reject(
    document: Mapping[str, Any], proposal_id: str, rejected_by: Actor, at: str
) -> dict[str, Any]:
    """Close a proposal without authority ever changing. Any actor kind may."""
    rejected_by.validate()
    _validate_at(at)
    updated = _copy(document)
    row = next(
        (item for item in updated["proposed"] if item["proposal_id"] == proposal_id),
        None,
    )
    if row is None:
        raise CapsuleTransitionError(f"no proposal {proposal_id!r} exists")
    if row["status"] != "open":
        raise CapsuleTransitionError(
            f"proposal {proposal_id} is {row['status']}, not open"
        )
    row["status"] = "rejected"
    row["resolved"] = {"by": rejected_by.ident, "kind": rejected_by.kind, "at": at}
    updated["history"].append({
        "event": "rejected", "by": rejected_by.ident, "kind": rejected_by.kind,
        "at": at, "detail": proposal_id,
    })
    validate_document(updated)
    return updated


def set_derived(
    document: Mapping[str, Any], key: str, value: str, author: Actor, at: str
) -> dict[str, Any]:
    """Write a regenerable rendering. Deliberately outside the digest chain.

    Derived content is a PROJECTION for display; it carries no authority and is
    excluded from integrity on purpose, so nothing downstream can mistake
    "the rendering changed" for "the decision changed". The inverse mistake --
    reading a rendering AS the decision -- is prevented by the render layer
    (PR-6), not here; this module only guarantees the regions cannot mix.
    """
    author.validate()
    _validate_at(at)
    if not isinstance(key, str) or not _DERIVED_KEY.match(key):
        raise CapsuleValidationError(f"derived key {key!r} is not acceptable")
    if not isinstance(value, str) or len(value) > 20000:
        raise CapsuleValidationError("derived values must be strings under 20000 chars")
    updated = _copy(document)
    updated["derived"][key] = value
    updated["history"].append({
        "event": "derived", "by": author.ident, "kind": author.kind, "at": at,
        "detail": key,
    })
    validate_document(updated)
    return updated
