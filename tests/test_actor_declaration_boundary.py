"""Tranche G: what a self-declared actor establishes, and what it does not.

THE DEFECT THIS MODULE HOLDS CLOSED. `POST /api/runtime/stop` used to refuse a
non-human caller with "stopping Forge is a person's act at this computer". The
sentence claimed two things. "At this computer" is backed -- loopback bind,
Host rule, per-run bearer. "A person" was backed by nothing measurable:
`actor.kind` is request-body text, and `Actor.validate` only asks that it names
one of three closed strings. Measured over a real loopback socket at this
slice's parent revision, a plain script presenting the bearer and declaring
`{"kind": "human", "ident": "attacker-script"}` was answered 200 and actually
stopped Forge, while an HONEST `kind: model` was refused 409. The check filters
exactly the callers who were not the threat.

AND IT WAS NEVER ONE ROUTE. ELEVEN routes read a self-declared actor, and the
capsule and experience digest chains RECORD the unauthenticated ident as
authority provenance -- a fabricated human is stamped into permanent history
that `verify_integrity` and `verify_experience` afterwards pass over. Fixing
the stop route alone would leave the same defect in ten other costumes, which
is the fix-one-miss-three shape this repository keeps meeting.

AND THE TWELFTH COSTUME WAS NOT A ROUTE AT ALL. A sweep of every speakable
literal in the package -- run because a route census can only find routes --
turned up `experience_journey._NEXT["READY"]`: "the build's gate results and
governance validation licensed it and A PERSON CONFIRMED IT". Not a refusal.
The page's own account of what READY MEANS, telling the reader as settled fact
the thing the stop route was being repaired for claiming. That is why
`CLAIM_SCANNED` below is not the three modules the work order named, and why
the guard is written over string literals rather than over route handlers.

SO THE ENUMERATION IS DERIVED, NOT LISTED. `actor_reading_routes` walks the
COMPOSED routing table (`create_app` + `attach_runtime_routes`), resolves each
endpoint's type hints, and keeps every route whose payload model declares an
`ActorPayload` field. A twelfth route is enumerated the day it is added, not
the day somebody remembers to extend a list. `EXPECTED_ACTOR_ROUTES` below is
NOT that enumeration's source: it is a WITNESS AGAINST THE ENUMERATOR GOING
BLIND, and it is here because the first draft of this walker returned ZERO --
`from __future__ import annotations` had made every annotation a string, and a
derived check that finds nothing passes every "none of them is X" assertion it
makes. A derivation with no floor under it is not a measurement.

WHAT EACH GUARD BELOW MEASURES, said plainly, because one of them is a text
search and a grep is not a measurement:

  * `test_every_route_reading_a_declared_actor_is_bearer_gated` -- derived from
    the routing table and `ALLOWLIST`. A real property of the composition.
  * `test_the_stop_refusal_claims_only_the_session_holder` and
    `test_the_bearer_and_not_the_actor_is_what_admits_a_stop` -- drive the real
    routes and read the bodies they return. Measurements of behaviour.
  * `test_a_declared_human_that_is_not_one_moves_authority_and_is_recorded` --
    drives the pure domain and the gated surface. A measurement of behaviour;
    it asserts the defect STILL EXISTS, because narrowing a claim does not
    repair a mechanism and a test that pretended otherwise would be the
    substitution this module exists to refuse.
  * `test_no_served_module_reasserts_a_personhood_claim` -- AST-derived, over
    the string literals a module can SAY (docstrings excluded, comments absent
    from an AST by construction), plus one lexical check on the retired
    sentence. Its first draft was a plain substring search and it flagged three
    DISCLAIMERS, because the claim is a substring of the sentence denying it;
    the fix was to split claim from prose STRUCTURALLY rather than to tune the
    phrase list until it agreed. It runs five controls -- three specimens that
    return a claim must redden, a specimen that only denies it and the
    declared-kind vocabulary must not -- and `speakable_strings` states what it
    still cannot see. IT IS THE WEAKER HALF: a phrase list is defeated by a
    thesaurus, and this one was. See the next entry.
  * `test_the_ready_line_defers_to_the_record_and_claims_nobody` -- the
    AFFIRMATIVE pin at the one site the phrase list had left unguarded.
    Measured, at this module's parent revision: rewriting `_NEXT["READY"]` from
    "this run's session holder confirmed it" to "A HUMAN CONFIRMED IT" left
    every guard here GREEN, 6 passed, because no phrase covered the synonym and
    nothing anywhere pinned the wording. A list can only enumerate what a claim
    might be spelled as; a pin states what the sentence must say. Both are kept,
    and the pin is the one that closes the class.
  * `test_the_personhood_limit_is_the_disclosed_boundary` -- reads A-030 out of
    the assumptions register, in the A-029 pattern, so a later slice cannot
    close the case without rewriting the words that admit it.
"""

from __future__ import annotations

import ast
import typing
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from session_client import authed_client, bearer_header

from nornyx_forge import experience as experience_contract
from nornyx_forge.capsule import (
    Actor,
    confirm,
    create_document,
    propose,
    validate_document,
    verify_integrity,
)
from nornyx_forge.control_plane_session import ALLOWLIST
from nornyx_forge.experience_journey import journey_view
from nornyx_forge.onboarding_app import ActorPayload, create_app
from nornyx_forge.windows_runtime import attach_runtime_routes

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
ASSUMPTIONS = ROOT / "docs" / "requirements" / "ASSUMPTIONS.md"

HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
#: A caller that is demonstrably not a person, declaring that it is.
IMPOSTOR = {"kind": "human", "ident": "attacker-script"}

#: The eleven, as the enumerator returned them at this slice's parent
#: revision. A FLOOR under the derivation, never its source: see the module
#: docstring on the walker that returned zero.
EXPECTED_ACTOR_ROUTES = frozenset({
    ("POST", "/api/build"),
    ("POST", "/api/journey/confirm-scope"),
    ("POST", "/api/journey/ready"),
    ("POST", "/api/journey/restore"),
    ("POST", "/api/journey/retry"),
    ("POST", "/api/journey/start"),
    ("POST", "/api/project"),
    ("POST", "/api/proposals"),
    ("POST", "/api/proposals/{proposal_id}/confirm"),
    ("POST", "/api/proposals/{proposal_id}/reject"),
    ("POST", "/api/runtime/stop"),
})

#: The modules that are SERVED, plus the smoke that drives them. Each is read
#: as source by the claim guard.
CLAIM_SCANNED = (
    "src/nornyx_forge/windows_runtime.py",
    "src/nornyx_forge/onboarding_app.py",
    "src/nornyx_forge/onboarding_serve.py",
    "src/nornyx_forge/capsule.py",
    "src/nornyx_forge/experience.py",
    # THE PAGE'S OWN WORDS, and the reason this tuple is not the three modules
    # the work order named. A sweep of every speakable literal in the package
    # found `_NEXT["READY"]` telling the reader "a person confirmed it" -- the
    # retired refusal in another costume, and worse than a refusal, because it
    # is the surface stating as settled fact what it never established. No route
    # census would have caught it: it is not a route.
    "src/nornyx_forge/experience_journey.py",
    "scripts/build_windows_bundle.py",
)

#: The sentence the stop route actually returned at this slice's parent, kept
#: verbatim as the positive control for the detector below. If the detector
#: cannot find a claim in THIS, it is measuring nothing.
THE_SENTENCE = "stopping Forge is a person's act at this computer"

#: Claim shapes this repository HAS emitted, or would emit next. Closed on
#: purpose. Applied to `speakable_strings`, not to whole files: the phrases are
#: substrings of the sentences that DENY them, so applying them to prose
#: measures spelling rather than claims.
#:
#: THE HUMAN HALF IS HERE BECAUSE THE PERSON HALF ALONE WAS DEFEATED BY A
#: SYNONYM. Measured: with only the `person` phrases below, rewriting
#: `_NEXT["READY"]` to "...licensed it and A HUMAN CONFIRMED IT" left this
#: module GREEN, 6 passed -- at the one site that had no affirmative pin under
#: it. And the criterion this tuple states about itself ("shapes this
#: repository HAS emitted") was satisfied by the human half at the moment it
#: was written: three live routes -- retry, restore and build -- were returning
#: "<what> is a human act on this surface", the retired sentence one synonym
#: away, while its docstring twin had already been repaired.
#:
#: `"is a human act"` and not `"a human act"`, and that is a measurement rather
#: than a preference. The bare phrase is a prefix of "a human actOR" and flags
#: three literals that are not claims at all -- "a capsule is created by a
#: human actor", "only a human actor may confirm...", "an experience is started
#: by a human actor" -- each of which names the DECLARED KIND, which is the
#: data model's own vocabulary and the exact thing A-030 says is all that is
#: established. The anchored form flags none of them. Tuning a list until the
#: disclaimers pass is what the extractor split exists to make unnecessary;
#: anchoring a phrase so it stops matching a different word is not that.
#:
#: NOT HERE, deliberately: "a person may". The page said "a person may restore
#: it" and that sentence is now gone, but its defect was an implicature of
#: exclusivity, not a false claim -- a person may indeed restore it, and so may
#: anything else declaring `human`. Adding a phrase for a shape that is not
#: actually false would be tuning this list to one edit rather than to the
#: defect. A-030 records the change instead.
FORBIDDEN_CLAIMS = (
    "a person's act",
    "is a person's",
    "proves a person",
    "a person stopped",
    "a person confirmed",
    "a person approved",
    "a person started",
    "authenticates the person",
    "authenticates the human",
    "authenticated the human",
    "establishes that a person",
    "confirms a person",
    # The synonym family, mirroring the shapes above.
    "a human's act",
    "is a human's",
    "is a human act",
    "a human action",
    "proves a human",
    "a human stopped",
    "a human confirmed",
    "a human approved",
    "a human started",
    "establishes that a human",
    "confirms a human",
)

#: The synonym specimen that stayed GREEN against the person-only list, kept
#: verbatim as the second positive control. A list extended without a control
#: over the extension is a list nobody falsified.
THE_SYNONYM = (
    "READY has been recorded: the build's gate results and governance "
    "validation licensed it and a human confirmed it."
)

#: What three live routes returned before this repair, kept as the third
#: positive control for the same reason.
THE_ROUTE_SYNONYM = "starting a build is a human act on this surface"


def _composed() -> FastAPI:
    """The real served composition, in the shape the shipped launcher builds:
    the onboarding app with the runtime routes attached on top."""
    application = create_app(ROOT / "does-not-exist" / "capsule", CONTRACTS,
                             seal_dir=ROOT / "does-not-exist" / "seals")
    attach_runtime_routes(application,
                          identity={"schema": "s", "instance": "i", "port": 0},
                          request_stop=lambda: None)
    return application


def _declares_an_actor(annotation: object) -> bool:
    if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
        return False
    return any(field.annotation is ActorPayload
               for field in annotation.model_fields.values())


def actor_reading_routes(application: FastAPI) -> set[tuple[str, str]]:
    """Every (method, path) whose endpoint takes a payload declaring an actor.

    Derived from the routing table. `typing.get_type_hints` rather than
    `inspect.signature`: the served modules use `from __future__ import
    annotations`, so a signature's annotations are STRINGS and comparing them
    to `ActorPayload` matches nothing -- which is how the first draft of this
    function found zero routes and passed every check built on it.
    """
    found: set[tuple[str, str]] = set()
    for route in application.routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        try:
            hints = typing.get_type_hints(endpoint)
        except Exception:  # noqa: BLE001 - an unresolvable hint is not a route census
            continue
        if not any(_declares_an_actor(annotation)
                   for name, annotation in hints.items() if name != "return"):
            continue
        for method in getattr(route, "methods", None) or ():
            if method in ("HEAD", "OPTIONS"):
                continue
            found.add((method, route.path))
    return found


# ---------------------------------------------------------------------------
# G1  the enumerate-and-pin interlock
# ---------------------------------------------------------------------------

def test_every_route_reading_a_declared_actor_is_bearer_gated():
    """THE INTERLOCK. Derived from the composition, so it cannot go stale.

    Two claims, and the order matters. First the enumerator found the routes
    it is supposed to find -- without this the assertion below is vacuous, and
    a vacuous "none of them is in ALLOWLIST" is exactly the false green this
    module was written after. Then: not one of them is allowlisted, so the
    per-run bearer is a hard precondition for every route that reads a
    self-declared actor.

    Adding a twelfth actor-reading route reddens the first assertion, which is
    the point: the adder is made to look at this file and at A-030 rather than
    inheriting the gate by accident.
    """
    routes = actor_reading_routes(_composed())
    assert routes, (
        "the enumerator found NO actor-reading route, which would make every "
        "assertion below vacuous. Suspect the walker before the surface.")
    assert routes == EXPECTED_ACTOR_ROUTES, (
        "the set of routes reading a self-declared actor moved. Added: "
        f"{sorted(routes - EXPECTED_ACTOR_ROUTES)}; gone: "
        f"{sorted(EXPECTED_ACTOR_ROUTES - routes)}. A new one inherits the "
        "session gate but NOT the discipline: read A-030, make sure it claims "
        "nothing about personhood, then record it here.")
    allowlisted = sorted(route for route in routes if route in ALLOWLIST)
    assert allowlisted == [], (
        "these routes read a self-declared actor AND are allowlisted, so an "
        f"unauthenticated local caller reaches them: {allowlisted}")


def speakable_strings(source: str) -> list[str]:
    """Every string literal in a module that is NOT a docstring.

    THE SPLIT THIS FUNCTION EXISTS FOR. A plain substring search over the file
    cannot tell a claim from its denial: the first draft of this guard flagged
    "nothing here authenticates the person", "Nothing here establishes that a
    person made the call" and 'never "a person stopped Forge"' -- three
    DISCLAIMERS, matched because the claim is a substring of the sentence
    denying it. Tuning the phrase list until those passed would have been
    tuning a detector until it agreed with me.

    So the split is structural instead of lexical. A docstring is prose ABOUT
    the code and may say "nothing here authenticates a person" as often as it
    is true. Every other literal is a candidate for something the surface SAYS
    -- a refusal body, a log line, a recorded field. Comments never appear in
    an AST at all, so they are excluded by construction and for the same
    reason.

    WHAT THIS DOES NOT DO, stated rather than implied: it does not prove a
    literal reaches a caller (a module constant and a returned refusal body
    look alike here), and it does not detect a claim assembled at runtime from
    pieces. It is a real structural property, narrower than "no personhood
    claim exists in any wording", and it is the narrow one that is checkable.
    """
    speakable: list[str] = []
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docstrings):
            speakable.append(node.value)
    return speakable


def test_no_served_module_reasserts_a_personhood_claim():
    """NOTHING THE SURFACE CAN SAY CLAIMS A PERSON, and prose may still deny it.

    Two guards over the served modules and the smoke that drives them.

    (1) STRUCTURAL, over `speakable_strings`: no non-docstring literal contains
    a claim phrase. This is where the stop route's sentence lived, and it is
    where a reinstated one would live.

    (2) LEXICAL, over the whole file including its prose: the exact sentence
    the route used to return may not reappear anywhere in these six files, in
    any role. A-030 carries the quote for the record; nothing in the code needs
    to.

    ALL CONTROLS ARE RUN, because a detector nobody falsified is a detector
    nobody measured. THREE positive controls -- synthetic modules that RETURN
    the retired sentence, the SYNONYM that defeated the person-only list, and
    the sentence three live routes were still speaking -- each of which must be
    caught. TWO negative controls -- a module that only DISCUSSES the claim in
    a docstring, and the declared-kind vocabulary "a human actOR" -- neither of
    which may be, or the guard is back to being unable to tell a claim from its
    denial, or from a different word that merely starts the same way.

    The synonym control is the one this round exists for. With the person-only
    list, `_NEXT["READY"]` rewritten to "a human confirmed it" left this module
    6 passed. A phrase list is defeated by a thesaurus, which is why the
    affirmative pin below it is the half that actually closes the class.
    """
    # POSITIVE CONTROLS, on known-positive specimens.
    for label, sentence in (("the retired sentence", THE_SENTENCE),
                            ("the synonym", THE_SYNONYM),
                            ("the route synonym", THE_ROUTE_SYNONYM)):
        claiming = 'def act():\n    return {"refused": %r}\n' % sentence
        assert [phrase for phrase in FORBIDDEN_CLAIMS
                for literal in speakable_strings(claiming) if phrase in literal], (
            f"the detector cannot find {label} in a module that RETURNS it; "
            "FORBIDDEN_CLAIMS or the extractor has drifted from the defect")
    # NEGATIVE CONTROL, on a known-negative specimen: the same words, as prose.
    denying = ('"""Nothing here establishes that a person made the call, and no\n'
               'refusal calls stopping a person\'s act."""\n'
               'def stop():\n    return {"stopping": True}\n')
    assert [phrase for phrase in FORBIDDEN_CLAIMS
            for literal in speakable_strings(denying) if phrase in literal] == [], (
        "the detector flags a DISCLAIMER, so it cannot tell a claim from its "
        "denial and every verdict it reaches is about spelling")
    # NEGATIVE CONTROL, on the declared-kind vocabulary. These name the FIELD
    # VALUE the surface requires, which is the one thing A-030 says IS
    # established; "a human act" bare is a prefix of them and flags all three.
    for kind_vocabulary in ("a capsule is created by a human actor",
                            "only a human actor may confirm a proposal into the "
                            "authoritative region; got kind=",
                            "an experience is started by a human actor"):
        speaking = 'def act():\n    raise Error(%r)\n' % kind_vocabulary
        assert [phrase for phrase in FORBIDDEN_CLAIMS
                for literal in speakable_strings(speaking) if phrase in literal] == [], (
            "the detector flags the DECLARED-KIND vocabulary, so it is matching "
            f"a longer word that starts the same way: {kind_vocabulary!r}")

    offending: list[tuple[str, str, str]] = []
    for name in CLAIM_SCANNED:
        source = (ROOT / name).read_text(encoding="utf-8")
        assert source, f"{name} read as empty, so nothing was scanned"
        for literal in speakable_strings(source):
            for phrase in FORBIDDEN_CLAIMS:
                if phrase in literal:
                    offending.append((name, phrase, literal[:120]))
        assert THE_SENTENCE not in source, (
            f"{name} carries the refusal sentence A-030 retired, verbatim. If "
            "it is being quoted, quote it in the assumptions register; if it "
            "is being returned, read A-030 first.")
    assert offending == [], (
        "a personhood claim is back in something a served module can say. What "
        "the surface may claim is the session holder, this computer, this "
        f"logged-in user -- never a person (A-030): {offending}")


# ---------------------------------------------------------------------------
# G2  the refusal claims only what is measured
# ---------------------------------------------------------------------------

def test_the_stop_refusal_claims_only_the_session_holder():
    """Driven against the real route, reading the body it returns.

    An honest `kind: model` is still declined -- the check is kept, because it
    costs nothing and preserves the never-upgrade-an-actor posture. What the
    refusal may no longer do is call the act a person's.
    """
    application = FastAPI()
    calls: list[str] = []
    attach_runtime_routes(application, identity={"schema": "s", "instance": "abc", "port": 1},
                          request_stop=lambda: calls.append("stop"))
    client = TestClient(application)

    refused = client.post("/api/runtime/stop", json={"actor": MODEL})
    assert refused.status_code == 409
    said = refused.json()["refused"]
    assert "holder of this run's session" in said, said
    assert "same user" in said, said
    assert "a person's act" not in said, said
    assert calls == []

    # And the impostor -- this test, a program -- is admitted, with a success
    # body that claims nothing about who asked.
    accepted = client.post("/api/runtime/stop", json={"actor": IMPOSTOR})
    assert accepted.status_code == 200
    assert accepted.json() == {"stopping": True, "instance": "abc"}
    assert calls == ["stop"]


def test_the_bearer_and_not_the_actor_is_what_admits_a_stop(tmp_path: Path):
    """WHICH CHECK IS THE GATE, measured rather than asserted from the docs.

    On the gated composition the stop route is refused 401 without the bearer
    however honest the declared actor is, and admitted with it however
    dishonest. That asymmetry IS A-030's claim, and it is the reason the
    refusal names the session holder.
    """
    application = create_app(tmp_path / "capsule", CONTRACTS, seal_dir=tmp_path / "seals")
    attach_runtime_routes(application, identity={"schema": "s", "instance": "abc", "port": 1},
                          request_stop=lambda: None)
    assert ("POST", "/api/runtime/stop") not in ALLOWLIST

    unauthenticated = TestClient(application)
    for actor in (HUMAN, MODEL, IMPOSTOR):
        answer = unauthenticated.post("/api/runtime/stop", json={"actor": actor})
        assert answer.status_code == 401, (actor, answer.text)
        assert answer.json() == {"refused": "no session for this Forge instance"}

    with_bearer = unauthenticated.post("/api/runtime/stop", json={"actor": IMPOSTOR},
                                       headers=bearer_header(application))
    assert with_bearer.status_code == 200, with_bearer.text


def _ready_state(ident: str) -> dict:
    """A persisted lifecycle at READY, marked by `ident`, through the real
    contract. Nothing is hand-assembled: every stage is a real `advance`, so
    the record this returns is the record the page reads."""
    at = "2026-09-09T00:00:00Z"
    marker = Actor(kind="human", ident=ident)
    system = Actor(kind="system", ident="forge")
    ref = experience_contract.EvidenceRef
    flow = (ref(kind="flow_run", ref="run-1", passed=True),)
    gates = (ref(kind="gate_results", ref="gates-1", passed=True),
             ref(kind="governance_validation", ref="nornyx-1", passed=True))

    state = experience_contract.start_experience(marker, at)
    for stage, actor, evidence in (("CONFIRM", marker, ()), ("BUILD", marker, ()),
                                   ("TEST", system, flow), ("GOVERN", system, gates),
                                   ("READY", marker, gates)):
        state = experience_contract.advance(state, stage, actor, at, evidence)
    return state


def test_the_ready_line_defers_to_the_record_and_claims_nobody():
    """THE AFFIRMATIVE HALF, at the one site that had only a phrase list.

    A forbidden-phrase list is defeated by a thesaurus. Measured: with the
    person-only list, rewriting this very sentence to "a human confirmed it"
    left the module 6 passed. So the sentence is pinned in the affirmative --
    the wording it must carry, not merely the wordings it must avoid -- and
    the pin reddens on ANY rewriting of the clause, a synonym included.

    WHAT THE PAGE MAY SAY HERE, and why it is this. `journey_view` renders
    from the PERSISTED lifecycle and takes no request, no session and no
    bearer. It literally cannot know who is reading, so "this run's session
    holder confirmed it" -- which stood here for one round -- was false of
    every reader of a project reopened after a restart, which is the ordinary
    case. What the projection does read is the record, and `advance` writes an
    ident into `entered` and `history` on every transition. So the sentence
    points at the record and interprets nothing: the ident is an
    unauthenticated self-declaration (A-030) and the sentence claims no more
    about it than that it was recorded.

    THE THIRD ASSERTION IS THE LOAD-BEARING ONE. The same text renders for two
    DIFFERENT marking idents, which is what makes any claim about who acted
    unbackable at this site: it is a constant, and a constant cannot be about
    a particular actor or a particular run.
    """
    document = {"authoritative": {"intent": "x", "provider": {"name": "codex"}}}
    state = _ready_state("president-lincoln")

    # VACUITY PRECONDITION. Every assertion below is about the READY text, and
    # a state that is not at READY renders a different constant against which
    # each "not in" passes for free.
    assert state["stage"] == "READY", state["stage"]
    view = journey_view(state, document, True, build_running=False)
    assert view["stage"] == "READY" and view["actions"] == [], view
    said = view["next"]

    # (1) THE WORDING IT MUST CARRY. Reddens on deletion and on rewording.
    assert "the ident recorded in this project's history confirmed it" in said, said
    assert "not deployment, not production approval, not an independent " \
           "inspection" in said, said

    # (2) THE RECORD IT DEFERS TO IS ACTUALLY THERE. Without this the sentence
    # would point at nothing, which is the failure one level down from
    # pointing at something untrue.
    assert state["history"][-1]["by"] == "president-lincoln", state["history"][-1]
    assert state["history"][-1]["to"] == "READY", state["history"][-1]
    assert state["entered"]["by"] == "president-lincoln", state["entered"]

    # (3) AND IT IS A CONSTANT, so it can be about no one. A different marker
    # renders the identical sentence.
    other = _ready_state("casey")
    assert other["history"][-1]["by"] == "casey", other["history"][-1]
    assert journey_view(other, document, True, build_running=False)["next"] == said, (
        "the READY line varies with the recorded actor, so it is now making a "
        "claim ABOUT that actor -- which is the claim this site keeps growing")

    # (4) AND IT CLAIMS NOBODY. The phrase list is applied to the rendered
    # text, so the two guards cannot drift apart, and the run scoping that
    # stood here for one round is named explicitly because no phrase catches it.
    assert [phrase for phrase in FORBIDDEN_CLAIMS if phrase in said] == [], said
    for unbackable in ("this run's session", "session holder", "a person", "a human"):
        assert unbackable not in said, (unbackable, said)


# ---------------------------------------------------------------------------
# G3  the record, which is the wider half
# ---------------------------------------------------------------------------

def test_a_declared_human_that_is_not_one_moves_authority_and_is_recorded(tmp_path: Path):
    """THE DEFECT, ASSERTED TO STILL EXIST. This is deliberate.

    Tranche G narrowed a CLAIM; it repaired no mechanism, because repairing
    this one needs an external authority the programme may not synthesize. A
    test that showed the impostor being refused would be describing a Forge
    that does not exist. So: a fabricated ident moves the human-gated authority
    line and lands in the chain-covered record, and `verify_integrity` passes
    over it afterwards -- the chain protects the record from later edits and
    vouched for nothing when it was written.

    If this ever goes red because the impostor is refused, the repair is real
    and A-030 must be rewritten in the same commit.
    """
    at = "2026-09-09T00:00:00Z"
    impostor = Actor(kind="human", ident="president-lincoln")

    document = create_document("proj-1", "Support Portal", impostor, at)
    assert document["created"]["by"] == "president-lincoln"
    assert document["created"]["kind"] == "human"

    proposed, proposal_id = propose(document, "intent", "do a thing",
                                    Actor(kind="model", ident="builder-model"), at)
    confirmed = confirm(proposed, proposal_id, impostor, at)
    assert confirmed["authoritative"]["intent"] == "do a thing"
    resolved = confirmed["proposed"][0]["resolved"]
    assert resolved["by"] == "president-lincoln", (
        "the unauthenticated ident is the recorded authority provenance")

    verify_integrity(confirmed)
    validate_document(confirmed)

    state = experience_contract.start_experience(impostor, at)
    assert state["entered"]["by"] == "president-lincoln"
    assert state["history"][-1]["by"] == "president-lincoln"
    experience_contract.verify_experience(state)

    # And the honest non-human is still declined, which is the whole of what
    # the kind rule buys.
    with pytest.raises(Exception, match="human"):
        confirm(proposed, proposal_id, Actor(kind="model", ident="builder-model"), at)

    # Through the gated surface, not only the domain: the same impostor.
    client = authed_client(create_app(tmp_path / "capsule", CONTRACTS,
                                      seal_dir=tmp_path / "seals"))
    created = client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": IMPOSTOR})
    assert created.status_code == 200, created.text
    served = client.get("/api/state")
    assert served.status_code == 200, served.text


# ---------------------------------------------------------------------------
# G4  the affirmative limit pin (A-029's pattern)
# ---------------------------------------------------------------------------

def test_the_personhood_limit_is_the_disclosed_boundary():
    """THE LIMIT, PINNED IN THE AFFIRMATIVE, in A-029's pattern.

    The behaviour above is the disclosed limit. This reads the register and
    asserts the words that admit it are present, so a slice that closes the
    case -- or one that quietly deletes the admission and leaves the mechanism
    -- has to rewrite the disclosure in the same commit.

    Falsified before it was kept: with A-030's paragraph removed this reddens.
    """
    disclosed = ASSUMPTIONS.read_text(encoding="utf-8")
    assert "## A-030" in disclosed, "A-030 is gone; the limit is disclosed nowhere"
    required = (
        "PERSONHOOD CANNOT BE ESTABLISHED ON THIS SURFACE WITHOUT",
        "EXTERNAL AUTHORITY",
        "unauthenticated SELF-DECLARATION",
        "filters exactly the callers that were never the threat",
        "a session holder, at this computer, as the logged-in",
        "RECORD the unauthenticated ident as authority",
        "not a gap awaiting a later slice",
    )
    missing = [phrase for phrase in required if phrase not in disclosed]
    assert missing == [], (
        "A-030 no longer says what the code relies on it saying. A slice that "
        f"closed this case must rewrite the disclosure, not drop it: {missing}")

    # The neighbours A-030 corrects must point at it, or the register disagrees
    # with itself about whether any route ever claimed authentication.
    assert "RESOLVED BY A-030" in disclosed, (
        "A-023 recorded this as an open finding; its resolution must be stated "
        "where the finding is, not only where the repair is")
    assert "was literally FALSE when written" in disclosed, (
        "A-015's 'no route claims authentication anywhere' was false while the "
        "stop route claimed it; the correction must stay beside the sentence")
