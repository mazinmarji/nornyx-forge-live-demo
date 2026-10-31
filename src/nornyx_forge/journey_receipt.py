"""The journey receipt: one machine-readable, verifiable record of a project's journey.

WHAT IT IS. `nornyx.forge.journey_receipt.v1` is a JSON document that says,
for one project, what Forge has recorded: the project's identifier and store
revision, the digests of its confirmed requirements and of `BRD.md`, the
lifecycle's stages and outcomes, the evidence references each stage was
admitted on, the confirmed provider and the Provider Contract's verdict on it,
the governed build's outcome -- including the exact refusal -- and whether any
recorded build was real or came from a simulation. It is generic: any
workflow outside the onboarding page can read and check it without the
browser's bearer.

WHAT IT REFUSES TO SAY. No receipt states that a runnable application exists.
Forge records no runnable verification of a produced application, so
`runnable_application` is `false` in every receipt this version writes, and
the verifier refuses any receipt that says otherwise.

HOW REAL AND SIMULATED ARE TOLD APART, FROM RECORDED FACTS ONLY. The shipped
build route refuses an ineligible provider before the lifecycle moves (the
409 in `onboarding_app.trigger_build`). So when the confirmed provider is
ineligible under THIS Forge version's Provider Contract on the receipt's
platform, and the lifecycle nevertheless reached BUILD, the shipped surface
could not have admitted that build: it came from a flow at the injectable
seam, which is how every simulated journey is driven. That is classified
`simulated` -- a word about where a build came from, unrelated to the
lifecycle's optional SIMULATE stage. Where the provider IS eligible and the
lifecycle reached BUILD, Forge records no build-admission attestation, so the
receipt says `unattested` and claims no real execution. A worker's or flow's
own words decide nothing: a flow at the seam can call itself `sequential`.
"Reached BUILD" is read from how far the lifecycle went, not from one event,
and a lifecycle whose recorded walk breaks the Experience Contract -- an
illegal transition, a disallowed actor, a stage entered without the evidence
it requires -- is refused rather than described.

WHAT THE DIGEST PROVES, AND WHAT IT DOES NOT. `integrity.body_sha256` is the
SHA-256 of the body's canonical JSON. Anyone can recompute it after an edit,
so it proves only that the body was not changed since the digest was
computed -- never who computed it. A receipt is VERIFIED only against an
anchor its holder does not control: the body re-derived from the project's
store, which must be SEALED (its seal lives outside the project, A-029) and
read for a platform the VERIFIER names, never the receipt; or a digest
obtained out of band. Without an anchor the verifier can say a receipt is
consistent, and says no more.

THE ALLOWLIST. Every exported value is chosen here by name. Actor identities,
the project name, requirement and BRD text, failure prose, filesystem paths
and the control-plane bearer never enter a receipt: actors are reduced to
their kind, failure details and evidence references Forge did not write (or
that carry a backend outside Forge's own vocabulary) to a SHA-256, and
requirements to the capsule's digest chain tip. The project IDENTIFIER is
exported as typed; A-058 says so.

NOTHING EXECUTES. Exporting reads the store and `BRD.md`; verifying reads
the receipt and, when asked, the store. Neither constructs a flow, calls a
provider or runs provider-produced code, and neither changes any eligibility,
confinement or authentication decision. The store's own git calls are the
store's, with the bound A-058 states.

`layer.application`: it composes the store, the journey's BRD reading and the
Provider Contract's verdict into a record, and decides nothing those modules
do not already decide.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from . import __version__
from .brd_authoring import BrdAuthoringError, brd_from_capsule
from .capsule import CapsuleError
from .capsule_store import CapsuleStore, CapsuleStoreError
from .experience import STAGE_ACTORS, STAGE_EVIDENCE, TRANSITIONS
from .experience_build import FLOW_BRD_REF, FLOW_REF, GATE_REF, NORNYX_GATE_REF, SCOPE_REF
from .experience_journey import BrdState
from .plain_reasons import build_failure_headline
from .provider_contract import ProviderError, governed_build_eligibility

RECEIPT_SCHEMA = "nornyx.forge.journey_receipt.v1"
EXPORTER = "nornyx_forge.journey_receipt"
CANONICALIZATION = "json-sorted-keys-compact-utf8"
AUTHENTICITY_NOTE = "not_established_by_this_digest"

#: The evidence-reference formats Forge itself writes. A reference in any
#: other form is withheld (exported as `null` beside its digest), because a
#: string Forge did not write could carry anything.
_KNOWN_REFS = (SCOPE_REF, GATE_REF, NORNYX_GATE_REF)
#: A flow reference carries the flow's OWN backend label, which a seam flow
#: chooses freely; only Forge's own backend words are exported verbatim.
_FLOW_REFS = (FLOW_REF, FLOW_BRD_REF)
_KNOWN_BACKENDS = frozenset({"sequential", "crewai", "crewai_flow"})
#: The shape of a platform word `served_platform` can produce.
_PLATFORM_WORD = re.compile(r"\A[a-z0-9][a-z0-9:._-]{0,39}\Z")
#: The exporter's clock, in the one form it writes. It is the exporter's own
#: statement: integrity covers it, and no anchor does (A-058).
_UTC_INSTANT = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
#: Fields a verified receipt still does not anchor to anything outside itself.
NOT_ANCHORED = ("body.generated_at",)
#: The largest receipt file read, so a hostile file cannot exhaust the reader.
_MAX_RECEIPT_BYTES = 8 * 1024 * 1024
#: The stages at or past BUILD: a lifecycle that reached any of them reached BUILD.
_BUILD_OR_LATER = frozenset({"BUILD", "TEST", "GOVERN", "SIMULATE", "REVIEW", "READY"})

_BASIS = {
    "none": "no governed build is recorded for this project",
    "refused": ("the Provider Contract refuses the confirmed provider on this platform, "
                "so the governed build is refused and no build is recorded"),
    "simulated": ("a build is recorded, but this Forge version's Provider Contract refuses "
                  "the confirmed provider (or none is confirmed) on this platform, so the "
                  "shipped build surface could not have admitted it; it came from a flow "
                  "at the injectable seam"),
    "unattested": ("a build is recorded and the confirmed provider is eligible, but Forge "
                   "records no build-admission attestation; this receipt does not "
                   "establish that a real provider executed"),
}
_RUNNABLE_NOTE = ("; no receipt establishes a runnable application, because Forge records "
                  "no runnable verification of a produced application")


class ReceiptError(Exception):
    """A receipt that cannot be written or read honestly: the refusal, in words."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> bytes:
    """The bytes the digest is taken over: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def body_digest(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body)).hexdigest()


def receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    """The receipt as written to disk: canonical JSON and a final newline."""
    return canonical_json(receipt) + b"\n"


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ReceiptError("the receipt repeats a key, so two readers could read it two ways")
    return dict(pairs)


def read_receipt(path: Path) -> dict[str, Any]:
    """A receipt file, read no further than the size limit, then parsed."""
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(_MAX_RECEIPT_BYTES + 1)
    except OSError as error:
        raise ReceiptError(f"the receipt cannot be read: {error}") from None
    return parse_receipt(data)


def parse_receipt(data: bytes) -> dict[str, Any]:
    """A receipt file's bytes, read only if they are the one canonical writing.

    Refuses a repeated key and any bytes that are not exactly what
    `receipt_bytes` writes for what they parse to, so every reader sees the
    same receipt the digest was computed over."""
    if len(data) > _MAX_RECEIPT_BYTES:
        raise ReceiptError(f"the receipt is larger than {_MAX_RECEIPT_BYTES} bytes")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except RecursionError:
        raise ReceiptError("the receipt is nested too deeply to read") from None
    except (UnicodeDecodeError, ValueError) as error:
        raise ReceiptError(f"the receipt is not readable JSON: {error}") from None
    try:
        canonical = receipt_bytes(value)
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReceiptError(f"the receipt cannot be written canonically: {error}") from None
    if canonical != data:
        raise ReceiptError("the receipt's bytes are not its canonical writing")
    if not isinstance(value, dict):
        raise ReceiptError("a receipt is a JSON object")
    return value


def _integrity(body: Any) -> dict[str, Any]:
    return {"algorithm": "sha256", "canonicalization": CANONICALIZATION,
            "body_sha256": body_digest(body), "authenticity": AUTHENTICITY_NOTE}


# ---------------------------------------------------------------------------
# Reading the project
# ---------------------------------------------------------------------------

def measure_brd(path: Path, document: Mapping[str, Any],
                render: Callable[[Mapping[str, Any]], str] = brd_from_capsule) -> BrdState:
    """What `BRD.md` IS, measured against the capsule beside it.

    The onboarding surface's reading, kept in one place so the page and the
    receipt cannot disagree about it (`onboarding_app.brd_state` delegates
    here and passes its own `brd_from_capsule`, so the seam its tests observe
    is unchanged). `derived` is an EQUALITY against the pure renderer over the
    confirmed region; the digest follows the flow parser's convention -- the
    SHA-256 of the decoded text, without the `sha256:` prefix `parse_brd`
    puts on it. A file that exists and cannot be decoded is present and not
    derived, not absent.
    """
    path = Path(path)
    if not path.exists():
        return BrdState.absent()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return BrdState.stale(None)
    digest = _sha256(text)
    try:
        rendered = render(document)
    except BrdAuthoringError:
        # No confirmed intent to render: whatever is in the file, the
        # capsule did not author it.
        return BrdState.stale(digest)
    return BrdState.matching(digest) if text == rendered else BrdState.stale(digest)


def _load_project(project_dir: Path, seal_dir: Path) -> tuple[dict, dict | None, str, str]:
    """The capsule, the lifecycle (or None when none is recorded), the store's
    revision and whether it is sealed. A store that no longer matches its seal
    refuses here, in the store's own words."""
    store = CapsuleStore(Path(project_dir) / "capsule", seal_dir=Path(seal_dir))
    document = store.load()
    try:
        lifecycle: dict | None = store.load_experience()
    except CapsuleStoreError as error:
        if "experience state" not in str(error):
            raise
        lifecycle = None
    seal = "sealed" if store.sealed() is not None else "unsealed"
    return document, lifecycle, store.revision(), seal


# ---------------------------------------------------------------------------
# The Experience Contract's walk, checked over the exported events
# ---------------------------------------------------------------------------

def walk_problems(events: list[Mapping[str, Any]], stage: str | None, status: str | None,
                  evidence: list[Mapping[str, Any]]) -> list[str]:
    """Where a recorded walk breaks the Experience Contract, in words.

    Every transition must be one the contract's table allows from where the
    walk stood, by an actor kind it allows into that stage; failures and
    retries stay where they are; the stage and status are where the walk
    ended; and each stage entered carries its required evidence, passed."""
    problems: list[str] = []
    if not events:
        return ["journey: a recorded lifecycle has no events"]
    first = events[0]
    if (first["event"], first["from"], first["to"]) != ("started", None, "DISCOVER"):
        problems.append("journey: the walk does not start at DISCOVER")
    if first["actor_kind"] != "human":
        problems.append("journey: a lifecycle is started by a human")
    current, current_status = "DISCOVER", "active"
    for index, event in enumerate(events[1:], start=1):
        kind, origin, target = event["event"], event["from"], event["to"]
        if origin != current:
            problems.append(f"journey: event {index} leaves {origin!r}, not {current!r}")
        if kind == "advanced":
            if current_status != "active":
                problems.append(f"journey: event {index} advances a failed workflow")
            if target not in TRANSITIONS.get(current, ()):
                problems.append(f"journey: {current} -> {target} is not a contract transition")
            elif event["actor_kind"] not in STAGE_ACTORS.get(target, ()):
                problems.append(f"journey: a {event['actor_kind']} may not advance into {target}")
            current, current_status = target, "active"
        elif kind in ("failed", "retried"):
            if target != current:
                problems.append(f"journey: a {kind} event must stay at {current}")
            if kind == "failed" and current_status != "active":
                problems.append(f"journey: event {index} fails a workflow already failed")
            if kind == "retried" and (current_status != "failed"
                                      or event["actor_kind"] not in ("human", "system")):
                problems.append(f"journey: event {index} retries without a failure, or by an "
                                "actor that may not resume the workflow")
            current_status = "failed" if kind == "failed" else "active"
        else:
            problems.append(f"journey: event {index} is not a recorded event kind")
    if (stage, status) != (current, current_status):
        problems.append(f"journey: the walk ends at {current}/{current_status}, "
                        f"not {stage}/{status}")
    entered = {event["to"] for event in events if event["event"] == "advanced"}
    for item in evidence:
        if item["stage"] not in entered:
            problems.append(f"evidence: {item['stage']} was never entered")
    for target in entered:
        for kind in STAGE_EVIDENCE.get(target, ()):
            if not any(item["stage"] == target and item["kind"] == kind and item["passed"]
                       for item in evidence):
                problems.append(f"evidence: {target} was entered without a passed {kind}")
    return problems


def reached_build(events: list[Mapping[str, Any]], stage: str | None) -> bool:
    """Whether the lifecycle got as far as BUILD, from every stage it stood in."""
    return stage in _BUILD_OR_LATER or any(
        event["to"] in _BUILD_OR_LATER for event in events if event["to"] is not None)


# ---------------------------------------------------------------------------
# Building the body
# ---------------------------------------------------------------------------

def _evidence_ref(ref: str) -> str | None:
    if any(pattern.match(ref) for pattern in _KNOWN_REFS):
        return ref
    for pattern in _FLOW_REFS:
        match = pattern.match(ref)
        if match and ref.split("/")[1] in _KNOWN_BACKENDS:
            return ref
    return None


def build_outcome(provider: Mapping[str, Any]) -> tuple[str, str | None]:
    """The governed build's outcome for a provider verdict, as the route decides it."""
    if provider["name"] is None:
        return "no_provider", None
    if not provider["eligible"]:
        return "refused", provider["reason"]
    return "admissible", None


def classify(outcome: str, recorded: bool) -> str:
    """Real or simulated, from the verdict and the record alone (module docstring)."""
    if not recorded:
        return "refused" if outcome == "refused" else "none"
    return "unattested" if outcome == "admissible" else "simulated"


def _verdict(name: str, platform: str) -> dict[str, Any]:
    """The Provider Contract's verdict in the receipt's own field names."""
    verdict = governed_build_eligibility(name, platform)
    return {"name": verdict.provider, "platform": verdict.platform,
            "eligible": verdict.eligible, "confinement": verdict.confinement,
            "reason": verdict.reason}


def _provider(document: Mapping[str, Any], platform: str) -> dict[str, Any]:
    confirmed = document["authoritative"].get("provider")
    if confirmed is None:
        return {"name": None, "platform": platform, "eligible": None,
                "confinement": None, "reason": None}
    return _verdict(confirmed["name"], platform)


def build_body(*, document: Mapping[str, Any], lifecycle: Mapping[str, Any] | None,
               brd: BrdState, revision: str, seal: str, platform: str,
               generated_at: str) -> dict[str, Any]:
    """The allowlisted projection. Every value below is chosen by name.

    Raises `ReceiptError` for a lifecycle whose recorded walk breaks the
    Experience Contract: such a record is refused, never described."""
    if not _PLATFORM_WORD.match(platform):
        raise ReceiptError(f"{platform!r} is not a platform word")
    chain = document["digest_chain"]
    if lifecycle is None:
        journey = {"tracking": "absent", "stage": None, "status": None,
                   "lifecycle_digest": None, "events": [], "failure": None}
        evidence: list[dict[str, Any]] = []
    else:
        events = [{
            "event": event["event"], "from": event["from"], "to": event["to"],
            "actor_kind": event["kind"], "at": event["at"],
            "detail_sha256": _sha256(event["detail"]) if event["detail"] else None,
        } for event in lifecycle["history"]]
        failure = None
        if lifecycle["status"] == "failed":
            detail = next((event["detail"] for event in reversed(lifecycle["history"])
                           if event["event"] == "failed"), "")
            headline = build_failure_headline(detail)
            failure = {"summary": headline["summary"], "check": headline["check"]}
        lifecycle_chain = lifecycle.get("chain") or []
        journey = {"tracking": "recorded", "stage": lifecycle["stage"],
                   "status": lifecycle["status"],
                   "lifecycle_digest": lifecycle_chain[-1] if lifecycle_chain else None,
                   "events": events, "failure": failure}
        evidence = [{
            "stage": stage, "kind": item["kind"], "ref": _evidence_ref(item["ref"]),
            "ref_sha256": _sha256(item["ref"]), "passed": item["passed"],
        } for stage, items in lifecycle["evidence"].items() for item in items]
        broken = walk_problems(events, journey["stage"], journey["status"], evidence)
        if broken:
            raise ReceiptError("the recorded lifecycle breaks the Experience Contract, so it "
                               "is refused rather than described: " + "; ".join(broken))
    provider = _provider(document, platform)
    outcome, refusal = build_outcome(provider)
    recorded = reached_build(journey["events"], journey["stage"])
    execution = classify(outcome, recorded)
    return {
        "forge": {"version": __version__, "exporter": EXPORTER},
        "generated_at": generated_at,
        "project": {"project_id": document["project_id"], "store_revision": revision,
                    "requirements_digest": chain[-1], "requirements_revisions": len(chain),
                    "seal": seal},
        "brd": {"present": brd.present, "derived": brd.derived, "digest": brd.digest},
        "journey": journey,
        "evidence": evidence,
        "provider": provider,
        "build": {"outcome": outcome, "refusal": refusal, "recorded": recorded},
        "classification": {"execution": execution, "runnable_application": False,
                           "basis": _BASIS[execution] + _RUNNABLE_NOTE},
    }


def export_receipt(project_dir: Path, *, seal_dir: Path, platform: str,
                   clock: Callable[[], str] | None = None) -> dict[str, Any]:
    """The receipt for one project, read from its sealed store and `BRD.md`.

    `platform` is the word the governed-build decision is made for; the
    command line passes this host's (`onboarding_app.served_platform`)."""
    document, lifecycle, revision, seal = _load_project(Path(project_dir), Path(seal_dir))
    brd = measure_brd(Path(project_dir) / "BRD.md", document)
    body = build_body(document=document, lifecycle=lifecycle, brd=brd, revision=revision,
                      seal=seal, platform=platform,
                      generated_at=(clock or _now_iso)())
    return {"schema": RECEIPT_SCHEMA, "body": body, "integrity": _integrity(body)}


# ---------------------------------------------------------------------------
# Verifying
# ---------------------------------------------------------------------------

_STR = (str,)
_OPT_STR = (str, type(None))
_HEX = "hex64"
_OPT_HEX = "hex64?"
_SHAPE: dict[str, Any] = {
    "schema": _STR,
    "body": {
        "forge": {"version": _STR, "exporter": _STR},
        "generated_at": _STR,
        "project": {"project_id": _STR, "store_revision": _STR, "requirements_digest": _HEX,
                    "requirements_revisions": (int,), "seal": _STR},
        "brd": {"present": (bool,), "derived": (bool,), "digest": _OPT_HEX},
        "journey": {"tracking": _STR, "stage": _OPT_STR, "status": _OPT_STR,
                    "lifecycle_digest": _OPT_HEX,
                    "events": [{"event": _STR, "from": _OPT_STR, "to": _OPT_STR,
                                "actor_kind": _STR, "at": _STR, "detail_sha256": _OPT_HEX}],
                    "failure": ({"summary": _OPT_STR, "check": _OPT_STR}, None)},
        "evidence": [{"stage": _STR, "kind": _STR, "ref": _OPT_STR, "ref_sha256": _HEX,
                      "passed": (bool,)}],
        "provider": {"name": _OPT_STR, "platform": _STR, "eligible": (bool, type(None)),
                     "confinement": _OPT_STR, "reason": _OPT_STR},
        "build": {"outcome": _STR, "refusal": _OPT_STR, "recorded": (bool,)},
        "classification": {"execution": _STR, "runnable_application": (bool,), "basis": _STR},
    },
    "integrity": {"algorithm": _STR, "canonicalization": _STR, "body_sha256": _HEX,
                  "authenticity": _STR},
}


def _is_hex64(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _shape_problems(value: Any, spec: Any, where: str) -> list[str]:
    if isinstance(spec, tuple) and len(spec) == 2 and isinstance(spec[0], dict) and spec[1] is None:
        return [] if value is None else _shape_problems(value, spec[0], where)
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            return [f"{where} must be an object"]
        problems = []
        if set(value) != set(spec):
            extra, missing = sorted(set(value) - set(spec)), sorted(set(spec) - set(value))
            problems.append(f"{where} has keys outside the schema {extra} "
                            f"and lacks required keys {missing}")
        for key in spec.keys() & value.keys():
            problems += _shape_problems(value[key], spec[key], f"{where}.{key}")
        return problems
    if isinstance(spec, list):
        if not isinstance(value, list):
            return [f"{where} must be a list"]
        return [p for i, item in enumerate(value)
                for p in _shape_problems(item, spec[0], f"{where}[{i}]")]
    if spec == _HEX:
        return [] if _is_hex64(value) else [f"{where} must be a SHA-256 hex digest"]
    if spec == _OPT_HEX:
        return [] if value is None or _is_hex64(value) else [
            f"{where} must be a SHA-256 hex digest or null"]
    # bool is an int in Python; an integer field must not accept one.
    if spec == (int,) and isinstance(value, bool):
        return [f"{where} must be an integer"]
    return [] if isinstance(value, spec) else [f"{where} has the wrong type"]


@dataclass(frozen=True)
class ReceiptVerdict:
    """The verifier's answer, as data.

    `consistent`: the shape, the digest and Forge's own rules hold. `verified`:
    consistent AND anchored -- by a sealed store re-derived for a platform the
    verifier named, or by an out-of-band digest. A consistent receipt with no
    anchor is not verified, because anyone can write one."""

    consistent: bool
    verified: bool
    problems: tuple[str, ...]
    anchors: tuple[str, ...]
    live_comparison: str
    checks: tuple[str, ...] = field(default_factory=tuple)

    @property
    def authenticity(self) -> str:
        return "established" if self.verified else "not_established"

    def as_dict(self) -> dict[str, Any]:
        return {"verified": self.verified, "consistent": self.consistent,
                "authenticity": self.authenticity, "anchors": list(self.anchors),
                "not_anchored": list(NOT_ANCHORED),
                "live_comparison": self.live_comparison, "problems": list(self.problems),
                "checks": list(self.checks)}


def _consistency_problems(body: Mapping[str, Any]) -> list[str]:
    """What the body must say given the rest of the body and Forge's own rules."""
    problems = []
    if body["forge"]["version"] != __version__ or body["forge"]["exporter"] != EXPORTER:
        problems.append(f"the receipt was written by forge version {body['forge']['version']!r} "
                        f"({body['forge']['exporter']!r}); this verifier is {__version__!r} and "
                        "judges only its own version's rules")
        return problems
    provider = body["provider"]
    if not _PLATFORM_WORD.match(provider["platform"]):
        problems.append(f"provider: {provider['platform']!r} is not a platform word")
        return problems
    if provider["name"] is None:
        if any(provider[key] is not None for key in ("eligible", "confinement", "reason")):
            problems.append("provider: no provider is named, so no eligibility may be stated")
    else:
        try:
            expected = _verdict(provider["name"], provider["platform"])
        except ProviderError as error:
            problems.append(f"provider: {error}")
            expected = None
        if expected is not None and expected != dict(provider):
            problems.append("provider: the stated eligibility is not the Provider Contract's "
                            f"verdict for {provider['name']!r} on {provider['platform']!r}")
    outcome, refusal = build_outcome(provider)
    build = body["build"]
    if (build["outcome"], build["refusal"]) != (outcome, refusal):
        problems.append(f"build: the outcome must be {outcome!r} with refusal {refusal!r}, "
                        "as the build route decides it from this verdict")
    journey = body["journey"]
    events = journey["events"]
    if build["recorded"] != reached_build(events, journey["stage"]):
        problems.append("build: 'recorded' disagrees with how far the journey reached")
    execution = classify(build["outcome"], build["recorded"])
    classification = body["classification"]
    if classification["runnable_application"] is not False:
        problems.append("classification: no receipt may state a runnable application")
    if classification["execution"] != execution or (
            classification["basis"] != _BASIS.get(execution, "") + _RUNNABLE_NOTE):
        problems.append(f"classification: the execution class must be {execution!r} "
                        "with its fixed basis")
    brd = body["brd"]
    if brd["derived"] and not (brd["present"] and brd["digest"]):
        problems.append("brd: a derived BRD must be present and carry a digest")
    if not brd["present"] and (brd["derived"] or brd["digest"] is not None):
        problems.append("brd: an absent BRD carries neither a digest nor a derivation")
    if not _UTC_INSTANT.match(body["generated_at"]):
        problems.append("generated_at: not a UTC timestamp in the form 2026-01-31T12:00:00Z")
    if (journey["status"] == "failed") != (journey["failure"] is not None):
        problems.append("journey: a failure summary is carried exactly when the workflow failed")
    elif journey["failure"] is not None and not journey["failure"]["summary"]:
        problems.append("journey: a failed workflow carries a non-empty plain summary")
    if journey["tracking"] == "recorded":
        problems += walk_problems(events, journey["stage"], journey["status"], body["evidence"])
    elif journey["tracking"] != "absent" or events or body["evidence"] or journey["stage"]:
        problems.append("journey: an absent lifecycle has no stage, events or evidence")
    for item in body["evidence"]:
        if item["ref"] is not None and (
                _evidence_ref(item["ref"]) is None or _sha256(item["ref"]) != item["ref_sha256"]):
            problems.append(f"evidence: the reference at {item['stage']} is not one Forge writes, "
                            "or does not match its digest")
    return problems


def verify_receipt(receipt: Any, *, project_dir: Path | None = None,
                   seal_dir: Path | None = None, platform: str | None = None,
                   expect_sha256: str | None = None) -> ReceiptVerdict:
    """Check a receipt. Runs no provider and no flow.

    Always: the exact shape, the digest, and consistency with Forge's own
    rules. With `project_dir`, `seal_dir` and `platform` (the VERIFIER's
    platform word, never the receipt's): the body is re-derived from the
    project's store, which must be sealed, and compared. With
    `expect_sha256`: the digest is compared to one obtained out of band.
    Only those two are anchors; `verified` needs one of them.
    """
    checks: list[str] = []
    anchors: list[str] = []
    problems = _shape_problems(receipt, _SHAPE, "receipt")
    if isinstance(receipt, dict) and receipt.get("schema") != RECEIPT_SCHEMA:
        problems.append(f"receipt: the schema is not {RECEIPT_SCHEMA!r}")
    if problems:
        return ReceiptVerdict(False, False, tuple(problems), (), "not_performed")
    checks.append("shape")
    body = receipt["body"]
    integrity = receipt["integrity"]
    if (integrity["algorithm"], integrity["canonicalization"]) != ("sha256", CANONICALIZATION) \
            or integrity["authenticity"] != AUTHENTICITY_NOTE:
        problems.append("integrity: unsupported algorithm, canonicalization or authenticity note")
    try:
        recomputed = body_digest(body)
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        return ReceiptVerdict(False, False, (f"integrity: the body cannot be written "
                                             f"canonically: {error}",), (), "not_performed")
    if integrity["body_sha256"] != recomputed:
        problems.append("integrity: the body does not match its digest")
    else:
        checks.append("digest")
    problems += _consistency_problems(body)
    consistent = not problems
    if consistent:
        checks.append("consistency")
    if expect_sha256 is not None:
        if expect_sha256.lower() == integrity["body_sha256"]:
            anchors.append("out_of_band_digest")
        else:
            problems.append("integrity: the digest does not match the out-of-band digest")
    live = "not_performed"
    if project_dir is not None:
        live, found = _live_comparison(body, Path(project_dir), seal_dir, platform)
        problems += found
        if live == "matched":
            anchors.append("sealed_store")
    verified = consistent and not problems and bool(anchors)
    return ReceiptVerdict(consistent, verified, tuple(problems), tuple(anchors), live,
                          tuple(checks))


def _live_comparison(body: Mapping[str, Any], project_dir: Path, seal_dir: Path | None,
                     platform: str | None) -> tuple[str, list[str]]:
    if seal_dir is None or platform is None:
        return "refused", ["live comparison: it needs the seal directory and the verifier's "
                           "own platform word, never the receipt's"]
    if body["provider"]["platform"] != platform:
        return "refused", [f"live comparison: the receipt was made for "
                           f"{body['provider']['platform']!r}; this verifier decides for "
                           f"{platform!r}"]
    try:
        document, lifecycle, revision, seal = _load_project(project_dir, Path(seal_dir))
        expected = build_body(document=document, lifecycle=lifecycle,
                              brd=measure_brd(project_dir / "BRD.md", document),
                              revision=revision, seal=seal, platform=platform,
                              generated_at=body["generated_at"])
    except (CapsuleError, ReceiptError, OSError) as error:
        return "refused", [f"live comparison: the project's store refused: {error}"]
    if seal != "sealed":
        return "unanchored", ["live comparison: the project's store carries no seal, so it "
                              "anchors nothing"]
    differing = sorted(key for key in expected if expected[key] != body.get(key))
    if differing:
        return "refused", ["live comparison: the receipt disagrees with the sealed project "
                           f"in {differing}"]
    return "matched", []


__all__ = [
    "RECEIPT_SCHEMA",
    "ReceiptError",
    "ReceiptVerdict",
    "body_digest",
    "build_body",
    "canonical_json",
    "classify",
    "export_receipt",
    "measure_brd",
    "parse_receipt",
    "read_receipt",
    "reached_build",
    "receipt_bytes",
    "verify_receipt",
    "walk_problems",
]
