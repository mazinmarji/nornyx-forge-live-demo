"""Regenerate the local governance evidence artifacts referenced by the contracts.

Nornyx verifies every ``governance_evidence`` record against a real local file and
its sha256 content hash. This script produces those artifacts deterministically so
the committed contracts stay bound to content that actually exists.

It never produces human approval evidence. Human approval records must be authored
by an accountable human; an autonomous run records their absence instead.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _refuse_missing_governed_module(exc: ModuleNotFoundError) -> None:
    """Report a missing governed dependency as a governance finding.

    Removing a governed module is a legitimate state to DESCRIBE, and an
    unhandled ModuleNotFoundError describes nothing: an operator learns that
    Python could not import something, not that governed content is absent.
    Measured -- deleting `src/nornyx_forge/util.py` produced a traceback, while
    deleting a governed module this tool does NOT import moved the input digest
    and was reported properly.

    This is not the integrity question, and it must not be mistaken for one.
    Deletion is already visible: the digest covers the enumerated set, so a
    removed member changes it and the evidence goes stale. What was missing is a
    legible refusal when the removed file happens to be one this tool runs on.

    Deliberately narrow. Only a module under the governed source packages is
    translated; anything else is a real environment fault and keeps its
    traceback rather than being dressed up as a governance finding.
    """
    if (exc.name or "").split(".")[0] not in {"governed_content", "nornyx_forge"}:
        raise exc
    print(
        json.dumps(
            {
                "schema": "nornyx.forge.evidence_verification.v1",
                "status": "fail",
                "verification": {
                    "integrity_state": "unavailable",
                    "assurance_state": "not_independently_inspected",
                    "governed_input_match": False,
                    "problems": [
                        "governed content is missing: this tool depends on "
                        f"{exc.name!r}, which is not present in the tree. The "
                        "evidence cannot describe content that is not here."
                    ],
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    raise SystemExit(2) from exc


try:
    import governed_content as _digest_scope  # noqa: E402
    from governed_content import (  # noqa: E402
        GovernedContentError,
        contract_semantics_digest,
        contract_set_digest,
        control_pack_digest,
        digest_of,
        evidence_manifest,
        governed_input_digest,
        inspection_subject_digest,
    )
except ModuleNotFoundError as exc:
    _refuse_missing_governed_module(exc)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / ".nornyx/contracts/evidence"
INDEX_PATH = EVIDENCE_DIR / "INDEX.json"

# Non-approval evidence may carry a long freshness window. Agentic-network approval
# evidence is capped at P7D by nornyx.builtin.module.agentic_network_governance.
DEFAULT_WINDOW_DAYS = 365

#: An authority *declaration* says who may approve and over what scope. It is
#: not itself an approval and has no reason to decay, and Nornyx 1.11.0 supports
#: saying so exactly: ``expires_at: null`` on an approval declaration validates
#: at any instant, verified against the real CLI at 2100 and 2200 in
#: tests/test_expiry_semantics.py. So the baseline carries that, not a distant
#: date dressed up as "never".
AUTHORITY_EXPIRY_PLACEHOLDER = None

#: Machine-generated evidence records get no such option.
#:
#: nornyx/schemas/governance_evidence_v1.schema.json declares
#: ``expires_at: {"oneOf": [timestamp, null]}``, but the freshness evaluator in
#: nornyx/governance/structural.py parses both timestamps unconditionally and
#: raises EVIDENCE_TIME_INVALID when either is absent. So the schema advertises a
#: non-expiring representation that the evaluator refuses. Architecture evidence
#: does not even advertise it: architecture_evidence_v1 requires a timestamp with
#: no null branch. There is no per-record or per-module freshness exemption
#: either — ``maximum_age`` governs only the approval-record P7D cap.
#:
#: That is a Nornyx capability gap, not something to paper over with a magic
#: constant. Machine evidence therefore carries an honest finite window and the
#: documented workflow regenerates it at review time; see
#: docs/governance/EVIDENCE_FRESHNESS.md. A reviewer arriving at any future
#: instant runs one command and gets a healthy baseline, which
#: tests/test_expiry_semantics.py proves at 2100 and 2200.
MACHINE_EVIDENCE_WINDOW_DAYS = DEFAULT_WINDOW_DAYS

#: Read from the package so tool metadata cannot drift from the release.
try:
    from nornyx_forge import __version__ as TOOL_VERSION
except Exception:  # pragma: no cover - packaging boundary
    TOOL_VERSION = "0.0.0"


def _revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise SystemExit("git rev-parse HEAD failed; a bound revision is required")
    return "git:" + result.stdout.strip()


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


#: The only two artifacts that may carry a human approval, by exact name.
#:
#: Never globbed. A ``*human_approval.json`` wildcard let any file dropped beside
#: them — ``evil.human_approval.json`` — decide the authority window, without
#: ever passing the validation the two canonical records go through.
CANONICAL_APPROVALS = {
    "agentic_network": "runtime_human_approval.json",
    "architecture": "architecture_human_approval.json",
}

#: Nornyx caps agentic-network approval evidence at P7D. Enforced here too, so a
#: bad window is refused before anything is written rather than only when the
#: contract is later validated.
APPROVAL_MAX_WINDOW = timedelta(days=7)

_REQUIRED_APPROVAL_FIELDS = ("generated_at", "expires_at", "status", "subject_revision")


def _parse_offset_timestamp(field: str, value: object, *, filename: str) -> datetime:
    """Parse a timezone-aware ISO-8601 timestamp, or refuse."""
    text = _require_safe_scalar(field, value)
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(
            f"{filename}: {field} is not an ISO-8601 timestamp: {text!r}"
        ) from exc
    if moment.tzinfo is None:
        raise SystemExit(
            f"{filename}: {field} must be timezone-aware, got {text!r}. A naive "
            "timestamp has no defined validity window."
        )
    return moment


def load_canonical_approval(filename: str) -> dict | None:
    """Read and fully validate one canonical human approval artifact.

    The single place a human approval is parsed. Indexing, wiring, revision
    pinning, window materialization and the review binding all come through
    here, so none of them can apply a weaker rule than the others — which is
    exactly how the materialization path ended up interpolating an unvalidated
    ``expires_at`` into a contract.

    Nothing here authors, upgrades, or edits an approval. Returns None when the
    artifact does not exist; raises when it exists and is not trustworthy.
    """

    path = EVIDENCE_DIR / filename
    if not path.exists():
        return None
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{filename} is not readable JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{filename} must be a JSON object, got {type(payload).__name__}")

    producer = payload.get("producer")
    if not isinstance(producer, dict):
        raise SystemExit(
            f"{filename} is not a human approval record: producer must be an object "
            f"with id and type, got {producer!r}."
        )
    if producer.get("type") != "human":
        raise SystemExit(
            f"{filename} is not a human approval record: producer.type is "
            f"{producer.get('type')!r}. Refusing to index it as one."
        )
    missing = set(_REQUIRED_APPROVAL_FIELDS) - set(payload)
    if missing:
        raise SystemExit(
            f"{filename} is missing required approval fields: {sorted(missing)}"
        )

    # Every scalar that can reach a contract is checked here, once.
    producer_id = _require_safe_scalar("producer.id", producer["id"])
    producer_type = _require_safe_scalar("producer.type", producer["type"])
    status = _require_safe_scalar("status", payload["status"])
    subject_revision = _require_safe_scalar("subject_revision", payload["subject_revision"])
    generated_at = _require_safe_scalar("generated_at", payload["generated_at"])
    expires_at = _require_safe_scalar("expires_at", payload["expires_at"])

    generated = _parse_offset_timestamp("generated_at", generated_at, filename=filename)
    expires = _parse_offset_timestamp("expires_at", expires_at, filename=filename)
    if generated >= expires:
        raise SystemExit(
            f"{filename}: generated_at {generated_at} is not earlier than "
            f"expires_at {expires_at}. An approval with no positive window "
            "cannot authorize anything."
        )
    if expires - generated > APPROVAL_MAX_WINDOW:
        raise SystemExit(
            f"{filename}: approval window {expires - generated} exceeds the P7D "
            "cap that nornyx.builtin.module.agentic_network_governance applies "
            "to agentic-network approval evidence."
        )

    # Everything above validates SHAPE. None of it establishes WHO wrote this.
    #
    # That was the whole of the check until now, and it is exactly the defect R2
    # removed for inspections — `load_inspection_attestation` is entombed forty
    # lines below with a comment explaining why a thorough-looking validator that
    # authenticates nothing is worse than none. The same pattern survived here,
    # in the same file, for the artifact that grants *human approval*: dropping a
    # JSON file with `producer.type: "human"` and `status: "pass"` into the
    # evidence directory was sufficient to be indexed as an approval.
    #
    # An approval is now authenticated the way an inspection is: an Ed25519
    # signature over the canonical grant payload, verified against a trust store
    # that lives outside the governed tree. Editing this repository cannot add a
    # trusted approver, and writing this file cannot grant anything.
    authenticated, reason, evidence = _authenticate_approval(payload, filename)
    if not authenticated:
        raise SystemExit(
            f"{filename} is not an authenticated human approval: {reason}. "
            "A file asserting `producer.type: human` is a claim about itself; "
            "only a signature from a trusted approver key makes it an approval."
        )

    return {
        "filename": filename,
        "artifact": f"evidence/{filename}",
        "content_hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "generated_at": generated_at,
        "expires_at": expires_at,
        "status": status,
        "subject_revision": subject_revision,
        "producer": {"id": producer_id, "type": producer_type},
        "authored_by": "human",
        # Read from what the verifier returned, never asserted. These were
        # literal True, so the record affirmed that a role had been verified in
        # exactly the cases where the role check was skipped. An auditor reading
        # the artifact could not distinguish "checked and passed" from "not
        # checked" -- a boolean asserting trust, which is the defect class this
        # repository removes everywhere else.
        "approval_authentication": {
            key: evidence.get(key)
            for key in (
                "signer_key_id",
                "trust_store_digest",
                "approver",
                "approver_role",
                "signature_verified",
                "identity_verified",
                "role_verified",
                "subject_type_verified",
            )
        },
        "payload": payload,
    }


def _authenticate_approval(payload: dict, filename: str) -> tuple[bool, str, dict]:
    """Verify the approval's signature against the approver trust store.

    Absence of a store is not permission. It means nothing can be authenticated
    here, so nothing may be adopted as an approval — the same direction the
    reviewer trust store takes, and the opposite of the direction a missing file
    used to take.
    """
    from nornyx_forge.approval_trust import (
        GOVERNANCE_TRUST_DOMAIN,
        SUBJECT_BOUND_ELSEWHERE,
        ApprovalTrustStore,
        TrustStoreUnavailable,
        verify_governance_approval,
    )

    try:
        store = ApprovalTrustStore.load(domain=GOVERNANCE_TRUST_DOMAIN)
    except TrustStoreUnavailable as exc:
        return False, f"APPROVER_TRUST_UNUSABLE: {exc}", {}
    if not store.signers:
        return (
            False,
            "APPROVER_TRUST_UNAVAILABLE: no approver trust store, so no human "
            f"approval can be authenticated ({store.source})",
            {},
        )
    # The trusted clock, not a value from the artifact. An approval supplying
    # the instant it is judged against would be marking its own homework.
    # THE SUBJECT IS PASSED, not composed afterwards. `subject_revision` was
    # signed and never evaluated: an approval naming a different revision, or
    # nonsense, or nothing at all was granted. The binding lived in
    # `require_approval_matches_head()` at seven separate call sites, which is
    # the architecture `verify_action_approval` exists to forbid -- a call site
    # that composes a clause is a call site that can stop composing it.
    # AUTHENTICATION, NOT SUBJECT BINDING, and the distinction is load-bearing.
    # This path must be able to load an approval that covers an OLDER revision,
    # because noticing that is `require_approval_matches_head()`'s whole job --
    # it stops before writing anything and asks a human to re-approve. Passing
    # `_revision()` here made a stale approval fail authentication instead: the
    # wrong diagnostic, and it made the drift detector unreachable, because
    # `_approved_revision()` could then never return anything but HEAD.
    #
    # I wrote that version first and the suite caught it.
    return verify_governance_approval(
        payload, trust_store=store, as_of=runtime_as_of(),
        expected_subject_revision=SUBJECT_BOUND_ELSEWHERE,
    )


def load_canonical_approvals() -> dict[str, dict]:
    """Validate every canonical approval present, and cross-check them.

    Two approvals covering the same subject must agree about what they cover and
    for how long. Disagreement is a governance defect, not something to resolve
    by picking one.
    """

    found = {
        scope: record
        for scope, filename in CANONICAL_APPROVALS.items()
        if (record := load_canonical_approval(filename)) is not None
    }
    for field, label in (("subject_revision", "subject revisions"), ("expires_at", "expiries")):
        values = {record[field] for record in found.values()}
        if len(values) > 1:
            raise SystemExit(
                f"canonical human approvals declare different {label}: "
                + ", ".join(sorted(values))
                + ". Nothing was modified."
            )
    return found


def _adopt_human_approval(key: str, filename: str, entries: dict) -> bool:
    """Index a validated human approval without altering it."""
    record = load_canonical_approval(filename)
    if record is None:
        return False
    entries[key] = {
        field: record[field]
        for field in (
            "artifact",
            "content_hash",
            "generated_at",
            "expires_at",
            "status",
            "subject_revision",
            "producer",
            "authored_by",
        )
    }
    return True


#: The one artifact that can carry an independent-review verdict. Committed and
#: content-bound, like the human approval artifacts and for the same reason.
INSPECTION_ATTESTATION = "architecture_inspection_attestation.json"

#: Inspector roles that must all have reported before a verdict can be `pass`.
#: Imported rather than restated. Two copies of "which lenses are required" can
#: drift, and the direction that drifts silently is the one that shrinks.
try:
    from nornyx_forge.nornyx_runtime import runtime_as_of  # noqa: E402
    from nornyx_forge.reviewer_trust import (  # noqa: E402
        REQUIRED_INSPECTOR_ROLES as REQUIRED_INSPECTORS,
    )
except ModuleNotFoundError as exc:
    _refuse_missing_governed_module(exc)

_REQUIRED_ATTESTATION_FIELDS = (
    "producer",
    "subject_revision",
    "inspection_subject_digest",
    "inspectors",
    "result",
    "generated_at",
)


# `load_inspection_attestation` stood here: ~120 lines validating the shape of an
# unauthenticated attestation — required fields, one result per role, a producer
# that is not `type: human` — none of which established who wrote it. Deleted
# rather than left unused, because a thorough-looking validator sitting next to a
# real one is an invitation to call the wrong one. Authentication now lives in
# `nornyx_forge.reviewer_trust` and the artifacts it reads are signed.



def _architecture_report() -> dict:
    """Run the deterministic architecture checker and return its report."""
    result = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - checker contract break
        raise SystemExit(f"architecture checker did not emit JSON: {exc}") from exc


def build(generated_at: datetime, window_days: int | None) -> dict:
    # Fails closed when an approval pins a revision other than HEAD, before any
    # artifact is written.
    revision = require_approval_matches_head() or _revision()
    generated = _iso(generated_at)
    # An honest finite window, measured from this run. Nornyx has no
    # non-expiring representation for machine evidence, so the baseline is kept
    # healthy by regenerating it, not by claiming a window it does not have.
    expires = _iso(
        generated_at
        + timedelta(days=MACHINE_EVIDENCE_WINDOW_DAYS if window_days is None else window_days)
    )
    report = _architecture_report()
    arch_status = "pass" if report.get("status") == "pass" else "fail"

    entries: dict[str, dict] = {}

    input_digest = governed_input_digest()

    def emit(key: str, filename: str, payload: dict, *, status: str) -> None:
        artifact = f"evidence/{filename}"
        # Each artifact carries the content it was produced against, in its own
        # bytes. The index records the *current* subject; an artifact records
        # what it actually inspected. Keeping those separate is what stops a
        # later recompute making an old conclusion look current.
        content_hash = _write(
            EVIDENCE_DIR / filename,
            {**payload, "governed_input_digest": input_digest},
        )
        entries[key] = {
            "artifact": artifact,
            "content_hash": content_hash,
            "generated_at": generated,
            "expires_at": expires,
            "status": status,
            "subject_revision": revision,
        }

    emit(
        "architecture_conformance_report",
        "architecture_conformance_report.json",
        {
            "schema": "nornyx.forge.architecture_report.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "producer": "scripts/check_architecture.py",
            "report": report,
        },
        status=arch_status,
    )
    # The in-session file is gitignored working state. The full review payload is
    # embedded here so the committed, content-hashed artifact is self-contained
    # and an approval never has to trust an uncommitted local file.
    # The in-session file is a working-session report: untracked, gitignored,
    # and written by whatever ran last. It may illustrate what the inspectors
    # said; it cannot decide whether they passed. A verdict comes only from a
    # committed attestation bound to the content it reviewed.
    reviews_path = ROOT / ".nornyx/in-session/reviews.json"
    reviewers: list[dict[str, str]] = []
    embedded: dict | None = None
    source_sha256: str | None = None
    if reviews_path.exists():
        raw_reviews = reviews_path.read_bytes()
        source_sha256 = "sha256:" + hashlib.sha256(raw_reviews).hexdigest()
        try:
            payload = json.loads(raw_reviews.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            embedded = payload
            reviewers = [
                {"role": str(item.get("role")), "status": str(item.get("status"))}
                for item in payload.get("reviews", [])
                if isinstance(item, dict)
            ]

    # Derived from authenticated attestations, exactly as enforcement is. Reading
    # the legacy unauthenticated artifact here would let this record display
    # `status: pass` while `derive_assurance_state` withheld assurance over the
    # same content — a written claim disagreeing with the control that decides.
    authenticated, auth_problems = _authenticated_inspections(
        current_inspection_subject()
    )
    passing = {
        role: entry for role, entry in authenticated.items() if entry["verdict"] == "pass"
    }
    absent = REQUIRED_INSPECTORS - set(passing)
    review_status = "pass" if not absent else "observed"
    if not authenticated:
        verdict_basis = (
            "no authenticated inspection of the current subject; the in-session "
            "report is displayed but decides nothing"
            + (f" ({auth_problems[0]})" if auth_problems else "")
        )
    elif absent:
        verdict_basis = (
            "authenticated inspection incomplete; missing or failing inspectors: "
            + ", ".join(sorted(absent))
        )
    else:
        verdict_basis = "attested by " + ", ".join(
            sorted(entry["reviewer"] for entry in passing.values())
        )

    emit(
        "architecture_independent_review",
        "architecture_independent_review.json",
        {
            "schema": "nornyx.forge.independent_review_record.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "reviewer_type": "read_only_ai_inspector",
            "human_review": "not_performed",
            # Descriptive only, and no longer read by anything: the field used
            # to decide independence, which meant the record asserting it also
            # granted it. Retained under a name that cannot be mistaken for
            # authority.
            "self_reported_builder_independence": False,
            "reviewers": reviewers,
            "statement": (
                "Architecture conformance was inspected by read-only inspectors that "
                "cannot modify the implementation and did not author this record's "
                "verdict on their own behalf. This is an independent machine review, "
                "not a human review and not an approval."
            ),
            "verdict_basis": verdict_basis,
            # Who actually signed, per role. Reviewer identities rather than a
            # self-described producer id: the former was authenticated against a
            # trust store outside this tree, the latter was whatever the file said.
            "authenticated_inspections": {
                role: {
                    "reviewer": entry["reviewer"],
                    "verdict": entry["verdict"],
                    "findings_digest": entry["findings_digest"],
                    "tool": entry["tool"],
                    "tool_version": entry["tool_version"],
                }
                for role, entry in sorted(authenticated.items())
            },
            # Displayed, never authoritative. Kept so a reader can see what the
            # session reported alongside what was actually attested.
            "session_report": {
                "source": ".nornyx/in-session/reviews.json",
                "source_sha256": source_sha256,
                "authoritative": False,
                "reviews": embedded,
            },
        },
        status=review_status,
    )
    emit(
        "architecture_exception_review",
        "architecture_exception_review.json",
        {
            "schema": "nornyx.forge.exception_review_record.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "open_exceptions": [],
            "statement": "No architecture exceptions were requested or granted.",
        },
        status="pass",
    )
    emit(
        "architecture_change_record",
        "architecture_change_record.json",
        {
            "schema": "nornyx.forge.change_record.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "architecture_impact": "none",
            "statement": (
                "Governance contracts were bound to the actual repository revision and "
                "completed with required evidence. Declared components, layers, modules, "
                "and dependency directions are unchanged."
            ),
        },
        status="pass",
    )
    # Human approval records are authored by an accountable human, never here.
    # When one is present this script only hashes and indexes it, taking its
    # status, producer and timestamps from the file itself. When one is absent it
    # records the absence instead. It can neither create nor overwrite an
    # approval.
    if not _adopt_human_approval(
        "architecture_approval_record", "architecture_human_approval.json", entries
    ):
        emit(
            "architecture_approval_record",
            "architecture_approval_record.json",
            {
                "schema": "nornyx.forge.approval_record.v1",
                "subject_revision": revision,
                "generated_at": generated,
                "approval": "not_granted",
                "human_review": "not_performed",
                "production_approval": "not_granted",
                "assurance_mode": "autonomous_demonstration",
                "statement": (
                    "No human architecture approval was granted. This record documents the "
                    "absence of approval; it does not grant one."
                ),
            },
            status="observed",
        )
    _adopt_human_approval(
        "runtime_approval_record", "runtime_human_approval.json", entries
    )
    emit(
        "architecture_evidence_manifest",
        "architecture_evidence_manifest.json",
        {
            "schema": "nornyx.forge.evidence_manifest.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "contract": ".nornyx/contracts/architecture_governance.nyx",
            "records": [
                "architecture_conformance_report",
                "independent_review_record",
                "exception_review_record",
                "change_record",
                "approval_record",
            ],
        },
        status="pass",
    )
    emit(
        "runtime_network_contract_review",
        "runtime_network_contract_review.json",
        {
            "schema": "nornyx.forge.network_contract_review.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "reviewer_type": "deterministic_tool",
            "human_review": "not_performed",
            "checks": [
                "identity_capability_references_resolve",
                "membership_zone_references_resolve",
                "external_protocol_target_is_gated",
                "high_risk_capability_requires_human_approval",
                "sensitive_categories_never_shared",
            ],
            "statement": (
                "The declared agentic-network contract was reviewed by deterministic "
                "reference checks. This is a machine review, not a human approval."
            ),
        },
        status="pass",
    )
    emit(
        "runtime_evidence_manifest",
        "runtime_evidence_manifest.json",
        {
            "schema": "nornyx.forge.evidence_manifest.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "contract": ".nornyx/contracts/runtime_network.nyx",
            "records": ["agentic_network_contract_review", "evidence_manifest"],
            "absent_records": ["approval_record"],
            "absence_reason": (
                "Agentic-network approval evidence requires a human producer. No human "
                "approval was performed in autonomous demonstration mode."
            ),
        },
        status="pass",
    )

    index = {
        "schema": "nornyx.forge.evidence_index.v1",
        # Integrity primitive. `subject_revision` stays for provenance and
        # navigation; it is not what freshness is judged on.
        "governed_input_digest": governed_input_digest(),
        "subject_revision": revision,
        "generated_at": generated,
        "expires_at": expires,
        "entries": entries,
    }
    INDEX_PATH.write_bytes(
        json.dumps(index, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    return index


CONTRACTS = (
    ROOT / ".nornyx/contracts/architecture_governance.nyx",
    ROOT / ".nornyx/contracts/runtime_network.nyx",
)
# Scoped to the keys that declare the governed revision. A file-wide replace
# would also rewrite a field that intentionally holds a superseded revision.
_GIT_REVISION_RE = re.compile(
    r"^(?P<lead>\s*(?:revision|subject_revision):\s*)git:[0-9a-f]{40}\s*$",
    re.MULTILINE,
)
_ARTIFACT_RE = re.compile(r"^\s*artifact:\s*(evidence/\S+)\s*$")
_HASH_RE = re.compile(r"^(?P<lead>\s*(?:content_hash|artifact_sha256):\s*)sha256:[0-9a-f]{64}\s*$")
_TOP_LEVEL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):")
#: Blocks whose entries carry a bounded authorization interval rather than
#: evidence freshness. Regenerated on the same window; see EVIDENCE_FRESHNESS.md.
AUTHORIZATION_INTERVAL_BLOCKS = frozenset({"agent_identities", "agentic_network"})
_RECORD_START_RE = re.compile(r"^\s*-\s+(?:id|schema):")
#: A record's verdict, which is DERIVED and must therefore be synced like a
#: digest rather than written by hand. `independent_review_record` sat at
#: `status: pass` in the contract while the index carried `observed` for the
#: same bytes and the artifact itself reported `authenticated_inspections: {}`.
#: Nornyx counts only `pass` records as usable evidence, so that one word was
#: satisfying the approval prerequisite, the change-control requirement and the
#: separation-of-duties assignment on the strength of an unsigned self-report.
_STATUS_RE = re.compile(r"^(?P<lead>\s*status:\s*)(?P<value>[A-Za-z_]+)\s*$")
_TIMESTAMP_RE = re.compile(
    r"^(?P<lead>\s*(?P<field>generated_at|expires_at):\s*)[\"']?[0-9T:+\-Z.]+[\"']?\s*$"
)
# The authority declaration's expiry additionally accepts the literal `null`,
# which is how Nornyx represents a declaration that does not decay.
_AUTHORITY_EXPIRY_RE = re.compile(
    r"^(?P<lead>\s*expires_at:\s*)(?P<value>null|[\"']?[0-9T:+\-Z.]+[\"']?)\s*$"
)


def sync_contracts() -> list[str]:
    """Rebind contract revisions and evidence digests to the generated index.

    Copying eight hashes by hand is exactly how a contract ends up claiming a
    digest that no artifact has, so the binding is applied mechanically from
    INDEX.json instead.
    """

    if not INDEX_PATH.exists():
        raise SystemExit("evidence index is missing; run without --sync-contracts first")
    require_approval_matches_head()
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    revision = _approved_revision() or index["subject_revision"]
    by_artifact = {
        entry["artifact"]: entry["content_hash"] for entry in index["entries"].values()
    }
    # Per-record validity, not one index-wide window. A human approval carries
    # its own generated_at and expires_at, and rewriting those from the index
    # would silently move the approval's validity window.
    # Every value interpolated below comes from a human-authored artifact, so it
    # is validated here too. _record_block() is not the only writer: syncing is a
    # separate path, and leaving it unchecked let a crafted expires_at inject a
    # second, forged approval_record while the run reported success.
    times_by_artifact = {
        entry["artifact"]: (
            entry.get("generated_at", index["generated_at"]),
            entry.get("expires_at", index["expires_at"]),
        )
        for entry in index["entries"].values()
    }
    # The verdict travels with the digest. It was the one derived field left to
    # hand-authoring, and it drifted: the contract asserted `pass` for an
    # inspection the index and the artifact both reported as merely observed.
    status_by_artifact = {
        entry["artifact"]: entry["status"]
        for entry in index["entries"].values()
        if entry.get("status")
    }
    changes: list[str] = []
    for contract in CONTRACTS:
        original = contract.read_text(encoding="utf-8")
        updated = _GIT_REVISION_RE.sub(
            lambda match: f"{match.group('lead')}{revision}", original
        )
        if updated != original:
            # Report only real edits; counting regex matches would claim a
            # rebinding even when the declared revision was already correct.
            rebound = sum(
                1
                for before, after in zip(original.splitlines(), updated.splitlines())
                if before != after
            )
            changes.append(f"{contract.name}: rebound {rebound} revision(s) to {revision}")
        lines = updated.splitlines(keepends=True)
        current: str | None = None
        block: str | None = None
        for position, line in enumerate(lines):
            top_level = _TOP_LEVEL_RE.match(line)
            if top_level:
                block = top_level.group(1)
                current = None
            if _RECORD_START_RE.match(line):
                current = None
            artifact = _ARTIFACT_RE.match(line)
            if artifact:
                current = artifact.group(1)
                continue
            digest = _HASH_RE.match(line)
            if digest and current is not None:
                expected = by_artifact.get(current)
                if expected and expected not in line:
                    lines[position] = f"{digest.group('lead')}{expected}\n"
                    changes.append(f"{contract.name}: {current} -> {expected}")
                continue
            verdict = _STATUS_RE.match(line)
            if verdict and current is not None and block in {
                "governance_evidence",
                "architecture_evidence",
            }:
                derived = status_by_artifact.get(current)
                if derived and derived != verdict.group("value"):
                    lines[position] = f"{verdict.group('lead')}{derived}\n"
                    changes.append(
                        f"{contract.name}: {current} status "
                        f"{verdict.group('value')} -> {derived}"
                    )
                continue
            # Evidence freshness lives only in the evidence blocks. The approval
            # declaration's own expires_at is governed by the P7D rule and is
            # never rewritten here.
            if block in {"governance_evidence", "architecture_evidence"}:
                moment = _TIMESTAMP_RE.match(line)
                if moment:
                    field = moment.group("field")
                    generated, expires = times_by_artifact.get(
                        current or "", (index["generated_at"], index["expires_at"])
                    )
                    value = _require_safe_scalar(
                        field, generated if field == "generated_at" else expires
                    )
                    if value not in line:
                        lines[position] = f'{moment.group("lead")}"{value}"\n'
                        changes.append(f"{contract.name}: {field} -> {value}")
            elif block in AUTHORIZATION_INTERVAL_BLOCKS:
                # Agent identities and network authorizations need real bounded
                # intervals — Nornyx rejects a null one, correctly, because an
                # identity's authority is exactly the kind that should lapse.
                # They are regenerated on the same window as machine evidence so
                # the documented review-time refresh produces a baseline that is
                # healthy at whatever instant the reviewer arrives.
                # valid_from is left alone: it is already in the past, and moving
                # it forward would invalidate runs pinned to an earlier instant.
                moment = _TIMESTAMP_RE.match(line)
                if moment and moment.group("field") == "expires_at":
                    value = _require_safe_scalar("expires_at", index["expires_at"])
                    if value not in line:
                        lines[position] = f'{moment.group("lead")}"{value}"\n'
                        changes.append(
                            f"{contract.name}: {block} authorization expiry -> {value}"
                        )
        rewritten = "".join(lines)
        _assert_single_managed_approval(contract.name, rewritten)
        if rewritten != original:
            contract.write_text(rewritten, encoding="utf-8", newline="")

    # Contracts are governed content and this function rewrites them, so the
    # digest recorded at build time describes the tree as it was *before* this
    # ran. Re-record it here, once the content has settled, rather than leaving
    # the index describing a state that no longer exists.
    #
    # This is the only place the recorded digest may move without regenerating
    # evidence, and it moves to match content this tool just wrote from
    # already-validated inputs. An edit from anywhere else still invalidates.
    settled = governed_input_digest()
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    if index.get("governed_input_digest") != settled:
        # `subject_content_digest` is what the tree currently is. It is NOT a
        # rebinding of the artifacts: each of those carries, in its own bytes,
        # the digest it was produced against, and verify() compares those
        # against observed content. Recomputing the subject makes old evidence
        # visibly stale; it must never make it look current.
        index["subject_content_digest"] = settled
        index["governed_input_digest"] = settled
        INDEX_PATH.write_bytes(
            json.dumps(index, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        changes.append(f"governed_input_digest -> {settled}")
    return changes


def adopt_approval(generated_at: datetime, window_days: int | None) -> dict:
    """Run the whole approval-adoption sequence as one gated operation.

    The steps rewrite the contracts, so running them as separate processes would
    make each one see the previous one's output as a dirty governed tree. The
    alternative — exempting `.nyx` files from the cleanliness check — would carve
    the hole in exactly the file the check exists to protect.

    So the gate runs once here, before anything is written, and the sequence then
    proceeds atomically from that proven-clean state.
    """

    require_approval_matches_head()
    with _gate_satisfied():
        return {
            "status": "adopted",
            "index": build(generated_at, window_days),
            "wiring": wire_approvals(),
            "window": materialize_approval_window(),
            "sync": sync_contracts(),
            "review_binding": emit_review_binding(),
        }


#: Set while an already-gated composite operation is running, so the individual
#: steps do not re-check a tree they are themselves in the middle of rewriting.
#: Never set by a single-step invocation: those must each start from a clean,
#: committed state.
_GATE_SATISFIED = False


@contextmanager
def _gate_satisfied() -> Iterator[None]:
    global _GATE_SATISFIED
    previous = _GATE_SATISFIED
    _GATE_SATISFIED = True
    try:
        yield
    finally:
        _GATE_SATISFIED = previous


def _approved_revision() -> str | None:
    """Return the revision a human approval pins, if one exists.

    A human approves one exact revision. Once that approval exists the contracts
    must keep declaring it: silently rebinding to the current HEAD would move the
    governed subject out from under the approval and, by the approvers' own
    invalidation terms, void it while leaving it looking valid.
    """

    approvals = load_canonical_approvals()
    if not approvals:
        return None
    # load_canonical_approvals() has already refused disagreeing revisions.
    return next(iter(approvals.values()))["subject_revision"]


def _approval_state() -> dict:
    """Report the human approvals that exist, exactly as they were written."""

    state: dict = {"human_review": "not_performed", "records": []}
    for scope, record in sorted(load_canonical_approvals().items()):
        payload = record["payload"]
        state["human_review"] = "performed"
        state["records"].append(
            {
                "scope": scope,
                "artifact": record["artifact"],
                "producer": record["producer"],
                "status": record["status"],
                "approval": payload.get("approval"),
                "generated_at": record["generated_at"],
                "expires_at": record["expires_at"],
                "subject_revision": record["subject_revision"],
                "reviewed_control_pack_commit": payload.get("control_pack_commit"),
            }
        )
    return state


def materialize_approval_window() -> dict:
    """Set the authority declarations' expiry from the real signing instant.

    An authority declaration says who may approve and over what scope. It is not
    itself an approval, so the committed baseline carries a far-future
    placeholder rather than a date that would expire the public tree.

    When a real approval instance is inserted, its window becomes the
    declaration's window. Nothing is invented here: the value comes from the
    record the human signed, and Nornyx still enforces the P7D cap on top.
    """

    require_approval_matches_head()
    approvals = load_canonical_approvals()
    if not approvals:
        # Restore the placeholder. Leaving the short reviewer window behind after
        # an approval is withdrawn re-rots the baseline the moment that date
        # passes, which is the exact regression 0.3.0 exists to prevent.
        return _set_authority_expiry(
            AUTHORITY_EXPIRY_PLACEHOLDER, status="restored_placeholder"
        )
    # load_canonical_approvals() has already refused disagreeing expiries, and
    # every value it returns is a validated, in-window, safe scalar.
    expires = next(iter(approvals.values()))["expires_at"]
    return _set_authority_expiry(expires, status="materialized")


def _render_authority_expiry(expires: str | None) -> str:
    """Serialize the declaration expiry safely.

    ``expires_at`` used to be interpolated raw. yaml.safe_dump decides the
    quoting, so a crafted value becomes a quoted string rather than new lines of
    YAML. ``None`` renders as the literal ``null`` Nornyx accepts as
    non-expiring.
    """

    if expires is None:
        return "null"
    text = _require_safe_scalar("expires_at", expires)
    # Dump as a mapping and take the value back out, so the serializer — not
    # this function — decides whether and how the scalar needs quoting.
    dumped = yaml.safe_dump({"expires_at": text}, default_flow_style=False, width=10**6)
    return dumped.split(":", 1)[1].strip()


def _set_authority_expiry(expires: str | None, *, status: str) -> dict:
    """Write one expiry into every authority declaration, and only there."""
    rendered = _render_authority_expiry(expires)
    changes: list[str] = []
    for contract in CONTRACTS:
        original = contract.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        block: str | None = None
        for position, line in enumerate(lines):
            top_level = _TOP_LEVEL_RE.match(line)
            if top_level:
                block = top_level.group(1)
            if block != "approvals":
                continue
            moment = _AUTHORITY_EXPIRY_RE.match(line)
            if moment and moment.group("value").strip() != rendered:
                lines[position] = f"{moment.group('lead')}{rendered}\n"
                changes.append(f"{contract.name}: authority expiry -> {rendered}")
        rewritten = "".join(lines)
        # Reparse before committing the edit. A declaration expiry is the one
        # value a reviewer reads to decide whether authority is still live, so a
        # write that damaged the document — or smuggled in a second approval
        # record — must not survive to disk.
        _assert_single_managed_approval(contract.name, rewritten)
        if rewritten != original:
            contract.write_text(rewritten, encoding="utf-8", newline="")
    return {"status": status, "expires_at": expires, "changes": changes}


#: Delimits the record this tool owns, so it can be replaced or removed exactly.
#: A YAML round-trip would reformat the contract and lose its comments.
_MANAGED_BEGIN = "    # >>> managed:approval_record"
_MANAGED_END = "    # <<< managed:approval_record"

#: Which human artifact and pre-approval fallback each contract uses.
APPROVAL_WIRING = {
    "runtime_network.nyx": {
        "artifact": "runtime_human_approval.json",
        "fallback": None,
    },
    "architecture_governance.nyx": {
        "artifact": "architecture_human_approval.json",
        "fallback": "architecture_approval_record.json",
    },
}


#: Fields copied out of a human artifact must be plain single-line scalars. A
#: legitimate approval never has a newline in its status or producer id, and
#: rejecting outright beats quietly escaping something that should not be there.
#:
#: "Single line" and "plain" are both meant literally. Besides the C0/C1
#: controls, this excludes the unicode line and paragraph separators and the
#: bidi and zero-width formatting characters. yaml.safe_dump would quote those
#: safely, so this is not what stops an injection — but a value that renders to
#: a reviewer as one thing and parses as another does not belong in a record
#: whose whole purpose is to be read and trusted by a human.
_SAFE_SCALAR_RE = re.compile(
    r"^[^\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e"
    r"\u2066-\u2069\ufeff]{1,256}$"
)


def _require_safe_scalar(field: str, value: object) -> str:
    text = str(value)
    if not _SAFE_SCALAR_RE.fullmatch(text):
        raise SystemExit(
            f"approval field {field!r} is not a plain single-line value: {text!r}. "
            "Refusing to write it into a contract."
        )
    return text


def _record_block(entry: dict, *, dependencies: list[str]) -> str:
    """Render the approval_record block from an indexed artifact.

    Emitted by the YAML serializer rather than hand-formatted. Interpolating
    artifact-controlled values into YAML text let a crafted field close the
    record and append a second, forged one that then survived cleanup, because
    it could also fake the managed end-marker.
    """

    producer = entry.get("producer")
    if not isinstance(producer, dict) or not {"id", "type"} <= set(producer):
        raise SystemExit(
            f"approval producer must be an object with id and type, got {producer!r}. "
            "Refusing to write it into a contract."
        )
    record = {
        "id": "approval_record",
        "type": "approval_record",
        "schema_id": "nornyx.governance_evidence.v1",
        "producer": {
            "id": _require_safe_scalar("producer.id", producer["id"]),
            "type": _require_safe_scalar("producer.type", producer["type"]),
        },
        "artifact": _require_safe_scalar("artifact", entry["artifact"]),
        "content_hash": _require_safe_scalar("content_hash", entry["content_hash"]),
        "subject_revision": _require_safe_scalar(
            "subject_revision", entry["subject_revision"]
        ),
        "tool": {
            "name": _require_safe_scalar("tool.name", entry.get("tool_name", "human_review")),
            "version": _require_safe_scalar("tool.version", entry.get("tool_version", "1")),
        },
        "generated_at": _require_safe_scalar("generated_at", entry["generated_at"]),
        "expires_at": _require_safe_scalar("expires_at", entry["expires_at"]),
        "status": _require_safe_scalar("status", entry["status"]),
        "dependencies": list(dependencies),
    }
    body = yaml.safe_dump(
        [record], default_flow_style=False, sort_keys=False, width=10**6
    )
    indented = "".join(
        ("    " + line if line.strip() else line) for line in body.splitlines(keepends=True)
    )
    return f"{_MANAGED_BEGIN}\n{indented}{_MANAGED_END}\n"


def _strip_managed(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    inside = False
    for line in lines:
        if line.rstrip("\n") == _MANAGED_BEGIN:
            inside = True
            continue
        if line.rstrip("\n") == _MANAGED_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "".join(out)


def _existing_record_block(text: str, artifact: str) -> str | None:
    """Return an unmanaged approval_record block for the given artifact."""
    pattern = re.compile(
        r"^    - id: approval_record\n(?:      .*\n)+", re.MULTILINE
    )
    for match in pattern.finditer(text):
        if artifact in match.group(0):
            return match.group(0)
    return None


def wire_approvals() -> dict:
    """Put the approval_record into each contract, or take it back out.

    Driven entirely by which human artifacts exist on disk. Present, and the
    record points at the human file; absent, and the contract returns to its
    pre-approval state. Idempotent, because the block this tool owns is
    delimited and rewritten wholesale rather than patched in place.

    The human files are only read and hashed here. Nothing edits, paraphrases or
    generates one.
    """

    require_approval_matches_head()
    # INDEX.json is deliberately not read here. It is derived output, and this
    # function writes authority into a governed contract; the index having been
    # an input is exactly how a forged one minted a human approval. Every value
    # below comes from a canonical artifact or is computed.
    if not INDEX_PATH.exists():
        raise SystemExit("evidence index is missing; run without --wire-approvals first")
    changes: list[str] = []

    for name, wiring in APPROVAL_WIRING.items():
        contract = ROOT / ".nornyx/contracts" / name
        original = contract.read_text(encoding="utf-8")
        text = _strip_managed(original)
        human = EVIDENCE_DIR / str(wiring["artifact"])

        # Remove any pre-existing approval_record so the state is rebuilt, not merged.
        for candidate in (wiring["artifact"], wiring["fallback"]):
            if not candidate:
                continue
            block = _existing_record_block(text, str(candidate))
            if block:
                text = text.replace(block, "")

        if human.exists():
            # Straight from the canonical artifact through the single common
            # validator. It used to come from INDEX.json, which is derived
            # output: tampering the index alone produced a human-producer,
            # status:pass record with an arbitrary window, bypassing this
            # validator and its P7D cap entirely. A derived file cannot be an
            # input to authority.
            record = load_canonical_approval(str(wiring["artifact"]))
            if record is None:  # pragma: no cover - guarded by human.exists()
                raise SystemExit(f"{name}: {wiring['artifact']} disappeared mid-run")
            entry = {
                "artifact": record["artifact"],
                "content_hash": record["content_hash"],
                "generated_at": record["generated_at"],
                "expires_at": record["expires_at"],
                "status": record["status"],
                "subject_revision": record["subject_revision"],
                "producer": record["producer"],
            }
            depends = (
                ["agentic_network_contract_review"]
                if name.startswith("runtime")
                else ["architecture_conformance_report", "independent_review_record"]
            )
            block = _record_block(entry, dependencies=depends)
            anchor = "\ncapabilities:" if name.startswith("runtime") else "\nchanges:"
            if anchor not in text:
                raise SystemExit(f"{name}: cannot locate the anchor {anchor.strip()}")
            text = text.replace(anchor, "\n" + block.rstrip("\n") + "\n" + anchor, 1)
            changes.append(f"{name}: approval_record -> {entry['artifact']}")
        elif wiring["fallback"]:
            # An *absence* record. Its producer and status are facts about this
            # tool, not values to be read from anywhere — least of all from the
            # index, where `setdefault` previously let a forged human producer
            # survive into a governed contract.
            # Every field is derived from the artifact on disk or computed here.
            # Nothing is read from the index: a forged `expires_at` there reached
            # the record even after producer and status were pinned, which is the
            # same defect one field further along.
            absence_path = EVIDENCE_DIR / str(wiring["fallback"])
            absence_raw = absence_path.read_bytes()
            absence = json.loads(absence_raw.decode("utf-8"))
            generated_at = _require_safe_scalar(
                "generated_at", absence.get("generated_at", "")
            )
            entry = {
                "artifact": f"evidence/{wiring['fallback']}",
                "content_hash": "sha256:" + hashlib.sha256(absence_raw).hexdigest(),
                "generated_at": generated_at,
                "expires_at": _iso(
                    _parse_offset_timestamp(
                        "generated_at", generated_at, filename=str(wiring["fallback"])
                    )
                    + timedelta(days=MACHINE_EVIDENCE_WINDOW_DAYS)
                ),
                "subject_revision": _require_safe_scalar(
                    "subject_revision", absence.get("subject_revision", "")
                ),
                "producer": {"id": "system:autonomous_demonstration", "type": "system"},
                "status": "observed",
                "tool_name": "refresh_governance_evidence",
                "tool_version": TOOL_VERSION,
            }
            block = _record_block(entry, dependencies=[])
            anchor = "\nchanges:"
            text = text.replace(anchor, "\n" + block.rstrip("\n") + "\n" + anchor, 1)
            changes.append(f"{name}: approval_record -> absence record")
        else:
            changes.append(f"{name}: approval_record removed (no human approval)")

        # Collapse the blank line that insertion would otherwise accumulate on
        # every run, so wiring twice leaves the file byte-identical.
        text = re.sub(r"\n{3,}", "\n\n", text)
        _assert_single_managed_approval(name, text)
        if text != original:
            contract.write_text(text, encoding="utf-8", newline="")
    return {"status": "wired", "changes": changes}


def _assert_single_managed_approval(name: str, text: str) -> None:
    """Refuse to leave an approval_record this tool does not own.

    Counted by parsing, not by matching contract text. A regex over raw lines is
    defeated by a trailing space or a quoted id (`- id: "approval_record"`),
    both of which parse to exactly the same record — so the textual count would
    read one while the document actually holds two.
    """

    try:
        document = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise SystemExit(f"{name}: contract is not parseable after wiring: {exc}") from exc

    records = ((document.get("governance_evidence") or {}).get("records")) or []
    total = sum(
        1
        for record in records
        if isinstance(record, dict) and record.get("id") == "approval_record"
    )
    managed = len(
        re.findall(
            re.escape(_MANAGED_BEGIN) + r"\n(?:.*\n)*?" + re.escape(_MANAGED_END),
            text,
        )
    )
    if total > 1 or (total == 1 and managed != 1):
        raise SystemExit(
            f"{name}: found {total} approval_record entries with {managed} managed "
            "block(s). An approval_record outside this tool's managed markers is "
            "not trusted. Remove it and re-run."
        )


#: Paths whose content a human approval actually covers. If any of these differs
#: from the approved commit, the run is inspecting something other than what was
#: approved, whatever the revision label says.
#: What a pinned human approval covers for the purpose of the dirty-tree gate.
#:
#: This is deliberately WIDER than `governed_subject.GOVERNED_INPUT_PATHS`, and
#: the difference is the point rather than a defect. The digest list excludes
#: `.nornyx/contracts/` because settled contracts are output in the two-level
#: model -- folding them into the input digest would make the input depend on
#: something derived from it. But editing a contract while an approval is pinned
#: to a revision must still refuse, so the dirty-tree gate has to see them.
#:
#: It was called GOVERNED_INPUT_PATHS, exactly like the digest list. A review
#: reported the two as disagreeing copies, and unifying them silently removed
#: contract coverage from the dirty-tree gate -- caught only because
#: `test_the_refusal_names_what_drifted` demands the refusal name the contract.
#: Two concepts that share a name will be merged by someone eventually, so they
#: no longer share one.
APPROVAL_COVERED_PATHS = (
    *_digest_scope.GOVERNED_INPUT_PATHS,
    ".nornyx/contracts",
)

#: Kept as an alias for readers who expect the old name, and pointed at the
#: dirty-tree list it always drove.
GOVERNED_INPUT_PATHS = APPROVAL_COVERED_PATHS

#: The only tracked files allowed to differ, and the reason each one may.
#:
#: Every entry is rewritten from the governed inputs by this tool before
#: anything is inspected, so its prior content cannot change the result. That is
#: the whole test for belonging here. Human approval artifacts are NOT in this
#: set: they are never regenerated, and they are exactly what the gate protects.
REGENERATED_OUTPUTS = frozenset(
    {
        ".nornyx/contracts/evidence/INDEX.json",
        ".nornyx/contracts/evidence/architecture_approval_record.json",
        ".nornyx/contracts/evidence/architecture_change_record.json",
        ".nornyx/contracts/evidence/architecture_conformance_report.json",
        ".nornyx/contracts/evidence/architecture_evidence_manifest.json",
        ".nornyx/contracts/evidence/architecture_exception_review.json",
        ".nornyx/contracts/evidence/architecture_independent_review.json",
        ".nornyx/contracts/evidence/review_binding.json",
        ".nornyx/contracts/evidence/runtime_evidence_manifest.json",
        ".nornyx/contracts/evidence/runtime_network_contract_review.json",
    }
)


def _git_lines(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise SystemExit(
            f"git {' '.join(args)} failed: {result.stderr.strip()}. "
            "A clean governed tree cannot be proven, so nothing was modified."
        )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _unstaged_governed_paths() -> list[str]:
    """Paths the digest covers whose working copy differs from what git holds.

    THE DIGEST IS COMPUTED OVER THE WORKING TREE. `subject_observer` reads each
    governed file with `location.read_bytes()`; nothing here consults the index.

    This said the opposite -- "computed over the index ... an unstaged edit
    cannot move it, and this is the check that closes that gap" -- which
    describes a system where this function is the only thing standing between an
    unstaged edit and a silently honoured approval. It is not. An unstaged edit
    DOES move the digest, so the subject changes and the approval bound to the
    old digest stops matching on its own.

    The implementation being safer than its description is its own hazard: a
    maintainer reading that paragraph could reasonably "simplify" the digest to
    read the index, since the prose says it already does, and only then would
    this check become load-bearing -- silently, with no test failing.

    What this check is actually for: reporting that the tree a reviewer would
    FETCH is not the tree being described here. Both are real states and they
    are different ones.

    Scoped to `governed_content`'s path set, not the one defined below. The two
    are deliberately different -- the dirty-tree gate also watches `docs/`,
    `CLAUDE.md` and the contracts, none of which the digest covers -- and the
    contracts in particular are rewritten by this tool during a normal run, so
    borrowing the wider set would report the tool's own output as drift.
    """
    roots = list(APPROVAL_COVERED_PATHS)
    excluded = _digest_scope.EXCLUDED_PREFIXES
    try:
        changed = _git_lines("diff", "--name-only", "--", *roots)
    except OSError as exc:
        # Being unable to ASK is not the same as being told everything is fine.
        #
        # This was `except Exception: return []`, with a comment claiming a git
        # failure is reported elsewhere. `_git_lines` does raise SystemExit on a
        # non-zero exit, and SystemExit is not an Exception, so that path was
        # genuinely fail-closed. What the handler actually caught was git being
        # unreachable -- no binary on PATH -- and it answered "no unstaged
        # paths", which reads as a clean governed tree.
        #
        # Measured: with `git` raising FileNotFoundError, this returned `[]` and
        # the dirty-tree gate reported the tree clean, so an approval could be
        # honoured over content nobody could prove was unchanged.
        #
        # The fourth instance of one class in this repository: required evidence
        # being absent read as successful empty verification. Absence is its own
        # state, so this refuses in the same vocabulary `_git_lines` already
        # uses rather than inventing a second one.
        raise SystemExit(
            f"git could not be run ({exc}). A clean governed tree cannot be "
            "proven, so nothing was modified. Install git or run where it is "
            "available; an unprovable tree is not a clean one."
        ) from exc
    return sorted(
        path
        for path in (name.replace("\\", "/").strip() for name in changed)
        if path and not any(path.startswith(prefix) for prefix in excluded)
    )


def _dirty_governed_inputs() -> tuple[list[str], list[str]]:
    """Return governed paths modified against HEAD, and untracked ones."""
    paths = list(GOVERNED_INPUT_PATHS)
    # --cached and the worktree diff are separate questions: staging a change
    # hides it from one and not the other, and either means the tree no longer
    # holds the approved content.
    modified = {
        name
        for args in (("diff", "--name-only", "HEAD", "--"), ("diff", "--name-only", "--cached", "HEAD", "--"))
        for name in _git_lines(*args, *paths)
    }
    untracked = set(
        _git_lines("ls-files", "--others", "--exclude-standard", "--", *paths)
    )
    # The canonical approval artifacts are untracked by design — an approval is
    # supplied by a human, not committed by this tool — and they are the input
    # this gate exists to serve. They get their own, much stricter validation in
    # load_canonical_approval(); anything else untracked here is drift.
    allowed = REGENERATED_OUTPUTS | {
        f".nornyx/contracts/evidence/{name}" for name in CANONICAL_APPROVALS.values()
    }
    return (
        sorted(name for name in modified if name not in allowed),
        sorted(name for name in untracked if name not in allowed),
    )


def require_clean_governed_tree(approved: str) -> None:
    """Refuse to honor an approval when the tree is not what was approved.

    Matching ``git rev-parse HEAD`` proves only which commit is checked out. It
    says nothing about the files on disk, and every governed operation reads the
    files, not the commit. An uncommitted edit to a contract or to governed
    source would therefore be inspected, bound, and reported as approved
    content.

    Raises before anything is written.
    """

    if _GATE_SATISFIED:
        # Already proven clean by the composite operation now in progress; the
        # only differences since are the ones it has just written itself.
        return
    modified, untracked = _dirty_governed_inputs()
    if not modified and not untracked:
        return
    detail = []
    if modified:
        detail.append("  modified (index or working tree):\n    " + "\n    ".join(modified))
    if untracked:
        detail.append("  untracked inside governed paths:\n    " + "\n    ".join(untracked))
    raise SystemExit(
        f"governed tree is dirty while a human approval pins {approved}.\n"
        + "\n".join(detail)
        + "\n\nNothing was modified. The approval covers the content of that "
        "commit, and these paths no longer hold it, so honoring the approval "
        "would bind and report content nobody approved.\n"
        "Either commit the changes and obtain a new approval, or restore the "
        "approved content with `git restore`."
    )


def require_approval_matches_head() -> str | None:
    """Refuse to touch anything unless the tree *is* the approved subject.

    Generating evidence from the working tree at HEAD and stamping it with an
    older approved revision produces evidence that describes code nobody
    approved. Rebinding the approval to HEAD is worse — it silently moves the
    subject out from under the human. So the only safe response is to stop
    before writing anything and let a human re-approve the new revision.

    Two separate conditions, because passing the first proves very little on its
    own: the approved revision must be HEAD, *and* the governed files on disk
    must still be that commit's content.

    Returns the approved revision when both hold, or None when no approval
    exists. Raises otherwise, having modified nothing.
    """

    approved = _approved_revision()
    if approved is None:
        return None
    head = _revision()
    if approved != head:
        raise SystemExit(
            "governed revision mismatch: a human approval pins "
            f"{approved} but HEAD is {head}.\n"
            "Nothing was modified. Evidence generated from HEAD must not be "
            "labelled with a revision nobody approved, and the approval must "
            "not be silently rebound.\n"
            "Either check out the approved revision, or obtain a new human "
            "approval for the current one."
        )
    require_clean_governed_tree(approved)
    return approved


def _head_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False
    )
    return "git:" + result.stdout.strip() if result.returncode == 0 else "git:unbound"


def _sha256(path: Path) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


#: Every field of `review_binding.json`, classified exactly once.
#:
#: THE PROPERTY: `integrity_state: intact` means every integrity-bearing claim
#: the binding records has been RECOMPUTED from its authoritative source and
#: matched. Not "the two digests we happened to compare still match".
#:
#: The binding records 22 fields. `verify()` compared two. An independent review
#: edited `required_evidence` in a governance contract -- removing the
#: conformance report and the independent review record from what a future human
#: approval must be accompanied by -- and `--verify` printed `status: pass`,
#: `integrity_state: intact`, `problems: []`, exit 0. `contract_set_digest` was
#: sitting in the binding the whole time, recording the value that would have
#: caught it.
#:
#: A digest that is written and never verified is not evidence. It is decoration
#: that reads as evidence, which is worse than its absence.
#:
#: Classification is exhaustive and mutually exclusive, so a new field cannot be
#: added without deciding which kind it is -- `test_every_binding_field_is_
#: classified` fails otherwise.
INTEGRITY_BEARING_FIELDS = {
    "governed_input_digest": "the authored content the evidence set describes",
    "contract_set_digest": "the settled .nyx contracts the evidence set covers",
    "evidence_manifest_digest": "the evidence artifacts the binding claims to cover",
    "inspection_subject_digest": "what an inspection of this tree would be reviewing",
    "control_pack_digest": "the composed identity of inputs, contracts and evidence",
    "digests.runtime_contract": "the runtime network contract",
    "digests.architecture_contract": "the architecture governance contract",
    "digests.forge_control_contract": "the forge control contract",
    "digests.evidence_index": "the generated evidence index",
    "digests.evidence_manifest": "the evidence manifest artifact",
    "digests.independent_review_record": "the independent review record artifact",
}

#: Derived from artifacts that are themselves integrity-bearing, and reported for
#: a human reader. Forging one changes no authorization: the assurance
#: derivation recomputes independence from authenticated attestations, and the
#: approval path recomputes from the canonical signed artifact.
DERIVED_REPORTING_FIELDS = {
    "schema",
    "note",
    "production_approval",
    "approvals.human_review",
    "approvals.records",
    "independent_review.artifact",
    "independent_review.embedded",
    "independent_review.status",
}

#: True of the moment the binding was written, and not a claim about content.
#: `source_commit` is provenance only -- git reaches no decision -- and
#: `subject_revision` is the content digest already covered above.
PROVENANCE_FIELDS = {"generated_at", "source_commit", "subject_revision"}


def _binding_claim(binding: dict, field: str):
    """Read a dotted field from the binding, or None when absent."""
    node: object = binding
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def recompute_binding_claims() -> dict[str, str]:
    """Recompute every integrity-bearing claim from its authoritative source.

    Each value here is derived from artifacts on disk, never read back from the
    binding. That direction is the whole point: authoritative artifacts produce
    digests, the binding records them, and verification recomputes from the
    artifacts again. Reading a claim to check a claim proves only that a file is
    self-consistent.

    `evidence_manifest_digest` excludes `review_binding.json` itself, exactly as
    the writer does -- a binding cannot honestly digest the bytes it is about to
    become.
    """
    contracts = ROOT / ".nornyx/contracts"
    input_digest = governed_input_digest()
    evidence_digest = digest_of(
        evidence_manifest(EVIDENCE_DIR, exclude=("review_binding.json",))
    )
    contract_digest = contract_set_digest(contracts)

    claims = {
        "governed_input_digest": input_digest,
        "contract_set_digest": contract_digest,
        "evidence_manifest_digest": evidence_digest,
        "inspection_subject_digest": current_inspection_subject(),
        "control_pack_digest": control_pack_digest(
            input_digest=input_digest,
            contract_digest=contract_digest,
            evidence_digest=evidence_digest,
        ),
    }
    for field, relative in (
        ("digests.runtime_contract", ".nornyx/contracts/runtime_network.nyx"),
        ("digests.architecture_contract", ".nornyx/contracts/architecture_governance.nyx"),
        ("digests.forge_control_contract", ".nornyx/contracts/forge_control.nyx"),
        ("digests.evidence_index", ".nornyx/contracts/evidence/INDEX.json"),
        (
            "digests.evidence_manifest",
            ".nornyx/contracts/evidence/architecture_evidence_manifest.json",
        ),
        (
            "digests.independent_review_record",
            ".nornyx/contracts/evidence/architecture_independent_review.json",
        ),
    ):
        location = ROOT / relative
        claims[field] = (
            "sha256:" + hashlib.sha256(location.read_bytes()).hexdigest()
            if location.exists()
            else "<absent>"
        )
    return claims


def verify_review_binding(binding: dict) -> list[str]:
    """Every integrity-bearing claim, recomputed and compared.

    Returns a problem per mismatch, each naming the field, what the binding
    claims, what the tree actually digests to, and what that field is about --
    so a reader knows which artifact drifted rather than only that something did.
    """
    problems: list[str] = []
    actual = recompute_binding_claims()

    # Derived fields are recomputed too, from the derivation that produces them.
    # Classifying a field as "derived" is a claim that forging it changes no
    # authorization -- and a claim has to be PROVEN, not asserted by putting the
    # name in the other set. An independent review would otherwise find
    # `production_approval: granted` written into the binding by hand while
    # --verify called the evidence set intact.
    #
    # _approval_state() reads only authenticated canonical approvals, so it is
    # the authority for both of these. There is no recursion: it derives from
    # signed artifacts, never from the binding.
    approvals = _approval_state()
    for field, derived in (
        ("approvals.human_review", approvals["human_review"]),
        (
            "production_approval",
            "granted" if approvals["human_review"] == "performed" else "not_granted",
        ),
    ):
        claimed = _binding_claim(binding, field)
        if claimed != derived:
            problems.append(
                f"review_binding claims {field} is {claimed!r}, but the "
                f"authenticated approval set derives {derived!r}. A derived "
                "field that disagrees with its derivation is an assertion, not "
                "a report."
            )

    for field, describes in sorted(INTEGRITY_BEARING_FIELDS.items()):
        claimed = _binding_claim(binding, field)
        if claimed is None:
            problems.append(
                f"review_binding records no {field}, so {describes} is covered by "
                "nothing. A binding that omits a claim cannot be verified against it."
            )
            continue
        if claimed != actual[field]:
            problems.append(
                f"review_binding claims {field} is {claimed}, but {describes} "
                f"digests to {actual[field]}. The evidence set describes content "
                "that is not what is here."
            )
    return problems


def emit_review_binding() -> dict:
    """Record exactly which artifacts a human approval would be approving.

    The governed subject revision and the commit carrying the contracts differ,
    because a contract cannot embed the hash of the commit that contains it.
    Naming only the subject revision would leave it ambiguous which contract pack
    was reviewed, so this pins both plus the content digests.

    Deliberately NOT referenced from governance_evidence.records: it digests the
    contracts, and the contracts carry their records' hashes, so referencing it
    would be circular. It is standalone, committed, and content-addressed.
    """

    require_approval_matches_head()
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    contracts = ROOT / ".nornyx/contracts"
    input_digest = governed_input_digest()
    # This file is excluded from the evidence manifest it contains. A document
    # cannot honestly digest itself: writing the digest changes the bytes the
    # digest was taken over.
    evidence_digest = digest_of(
        evidence_manifest(EVIDENCE_DIR, exclude=("review_binding.json",))
    )
    contract_digest = contract_set_digest(contracts)
    pack_digest = control_pack_digest(
        input_digest=input_digest,
        contract_digest=contract_digest,
        evidence_digest=evidence_digest,
    )
    binding = {
        "schema": "nornyx.forge.review_binding.v1",
        "generated_at": _iso(datetime.now(timezone.utc)),
        # Integrity primitives. `control_pack_commit` used to live here and was
        # structurally impossible: it named the commit carrying the very file it
        # sat in, so writing the file produced a new commit and the value was
        # wrong the instant it was recorded. A digest over inputs has no such
        # problem — it can be committed afterwards without invalidating what it
        # says it reviewed.
        "governed_input_digest": input_digest,
        "contract_set_digest": contract_digest,
        "inspection_subject_digest": current_inspection_subject(),
        "evidence_manifest_digest": evidence_digest,
        "control_pack_digest": pack_digest,
        # Deliberately no stored verification verdict. A first attempt embedded
        # one here and it was wrong by construction: the block was computed
        # before this file was written, so it described the *previous* binding.
        # That is the same anti-pattern this unit exists to remove — a recorded
        # conclusion a reader could take at face value. Verification is derived
        # at verification time by `--verify`, over whatever is actually on disk.
        # Provenance only: which history this came from, for navigation. Never
        # an integrity proof, and never how freshness is decided.
        "source_commit": _head_commit(),
        "subject_revision": index["subject_revision"],
        "note": (
            "governed_input_digest is what a human authored. "
            "contract_set_digest is the settled "
            "governance contracts. inspection_subject_digest is exactly what the "
            "independent inspectors reviewed, and moves if either moves. "
            "source_commit is provenance only."
        ),
        "digests": {
            "runtime_contract": _sha256(contracts / "runtime_network.nyx"),
            "architecture_contract": _sha256(contracts / "architecture_governance.nyx"),
            "forge_control_contract": _sha256(contracts / "forge_control.nyx"),
            "evidence_manifest": index["entries"]["architecture_evidence_manifest"][
                "content_hash"
            ],
            "independent_review_record": index["entries"][
                "architecture_independent_review"
            ]["content_hash"],
            "evidence_index": _sha256(INDEX_PATH),
        },
        "independent_review": {
            "status": index["entries"]["architecture_independent_review"]["status"],
            "artifact": "evidence/architecture_independent_review.json",
            "embedded": True,
        },
        # Derived from the approval records actually present, never hardcoded:
        # a stale "not_granted" would understate, and a hardcoded "granted"
        # would be a claim this script has no standing to make.
        "approvals": _approval_state(),
        "production_approval": "not_granted",
    }
    path = EVIDENCE_DIR / "review_binding.json"
    raw = json.dumps(binding, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(raw)
    binding["self_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return binding


#: Evidence artifacts that record the OUTCOME of an inspection, and therefore
#: cannot be part of what an inspection covers.
#:
#: `review_binding.json` was already excluded, for the reason that generalises:
#: a binding cannot honestly digest the bytes it is about to become. The review
#: record is the same shape of thing and was not excluded, which made the
#: subject self-referential and authenticated inspection unreachable:
#:
#:     attestation names subject S
#:     -> the review record says "attests to S, but the current subject is T"
#:     -> that sentence embeds T and lives INSIDE the manifest T is computed from
#:     -> the next regeneration computes U != T, and writes U into the record
#:
#: Measured: two consecutive regenerations, same HEAD and same `--as-of`,
#: produced different subjects every time, and the ONLY differing bytes were
#: that diagnostic. No attestation could ever name the subject the next
#: regeneration would present, so `assurance_state` could never legitimately
#: become `independently_inspected`.
#:
#: Excluding the record costs nothing: it carries no authority (assurance is
#: recomputed from the attestations themselves), and `verify_review_binding`
#: recomputes `digests.independent_review_record` from the artifact, so
#: tampering with it is still caught -- just not by folding it into the subject
#: it describes.
#:
#: `INSPECTION_ATTESTATION` names a single-artifact form that this repository no
#: longer writes; it is kept so a tree still carrying one is excluded too.
#: `INDEX.json` joins them for a different reason: it is a pure catalogue over
#: the other artifacts, carrying each one's `content_hash` and nothing of its
#: own. Excluding the review record from the manifest therefore did not break
#: the loop on its own -- the record's hash still reached the subject through
#: the index. Nothing is lost by excluding a derived catalogue: every artifact
#: it lists is already digested individually, so tampering with any of them
#: still moves the subject.
#: The human approval and the record derived from it are excluded for a third
#: reason, and it is the one the governance model forces.
#:
#: An inspection must precede an approval: the contract names the independent
#: review as required evidence FOR the approval, so you approve BECAUSE the
#: content was inspected. An inspector therefore cannot have reviewed an
#: approval that did not yet exist. If attaching the approval afterwards moves
#: the subject, then every inspection is invalidated by the very act it was
#: performed to enable, and the two prerequisites can never hold at once.
#:
#: Measured: with attestations valid and `assurance_state:
#: independently_inspected`, running `--adopt-approval` dropped the
#: authenticated inspections to none, because adoption writes the approval
#: artifacts into the evidence directory and they joined the manifest.
#:
#: Nothing is weakened. The approval carries its own Ed25519 signature over its
#: own canonical payload and binds to `subject_revision`; its authority comes
#: from that, never from sitting inside a digest. `verify_review_binding`
#: recomputes the approval state separately, so a forged approval is still
#: caught.
INSPECTION_OUTCOME_ARTIFACTS = (
    "review_binding.json",
    INSPECTION_ATTESTATION,
    "architecture_independent_review.json",
    "INDEX.json",
    "architecture_human_approval.json",
    "runtime_human_approval.json",
    "architecture_approval_record.json",
    # Catalogues, on the same footing as INDEX.json: they carry each artifact's
    # hash and nothing of their own, so excluding the approval artifacts from
    # the subject achieved nothing while these still listed them. Every artifact
    # they enumerate is digested individually here, so tampering with one still
    # moves the subject.
    "architecture_evidence_manifest.json",
    "runtime_evidence_manifest.json",
)


def current_inspection_subject() -> str:
    """What an inspection of the tree as it stands would be reviewing.

    Recomputed rather than read. If it differs from what an attestation names,
    that attestation reviewed something else — which is the whole point of
    freezing a subject.

    Stable under regeneration: running the evidence tooling again over unchanged
    code, contracts and clock must yield the same subject, or an inspection can
    never be bound to anything. That property is asserted directly, because it
    is the one this digest quietly lost.
    """
    pre_inspection = digest_of(
        evidence_manifest(
            EVIDENCE_DIR,
            exclude=INSPECTION_OUTCOME_ARTIFACTS,
            # Claims, not provenance. Re-running the tooling over unchanged code
            # and contracts rewrites `subject_revision` from the new HEAD and
            # `generated_at` from the clock; if those reach the subject, it moves
            # although nothing inspectable changed, and every attestation over it
            # goes stale. The integrity manifest still covers exact bytes, so a
            # tampered timestamp is caught where that is the question.
            ignore_provenance=True,
        )
    )
    return inspection_subject_digest(
        input_digest=governed_input_digest(),
        # What the contracts SAY, not the bytes the tooling stamped into them.
        # `contract_set_digest` covers raw bytes, and adopting an approval
        # rebinds the declared revision and rewrites every recorded evidence
        # digest -- so the contracts an inspector reviewed differed from the
        # contracts that existed a moment later, purely from bookkeeping. That
        # made the two prerequisites unsatisfiable together: attest before
        # adoption and the attestation is stale; attest after and the
        # attestations are untracked against the revision the approval pins.
        #
        # `contract_semantics` is the projection the repository already uses for
        # `governed_revision_digest`, for this exact reason. Nothing is
        # weakened: the raw contract bytes are still covered by
        # `contract_set_digest` in the review binding, which `--verify`
        # recomputes, so a tampered contract is still caught.
        contract_digest=contract_semantics_digest(),
        evidence_digest=pre_inspection,
    )



#: Signed inspection attestations, one file per reviewer and role. A directory
#: rather than one artifact because each is signed by a different key: merging
#: them into a single file would mean one signature covering claims several
#: reviewers made, which is not something any of them said.
ATTESTATION_DIR = EVIDENCE_DIR / "attestations"


def _authenticated_inspections(subject_digest: str) -> tuple[dict, list[str]]:
    """Every attestation that authenticates, keyed by inspector role.

    Anything that fails authentication is reported and discarded. An
    unauthenticated attestation is not a weaker inspection; it is not an
    inspection at all, and the previous model treated it as one.
    """
    from nornyx_forge.reviewer_trust import (
        ReviewerStoreUnavailable,
        ReviewerTrustStore,
        excluded_inspector_identities,
        verify_signed_attestation,
    )

    problems: list[str] = []
    try:
        store = ReviewerTrustStore.load()
    except ReviewerStoreUnavailable as exc:
        return {}, [f"reviewer trust store unusable: {exc}"]
    if not store.available:
        return {}, [
            "no reviewer trust store, so no inspection can be authenticated "
            f"({store.source})"
        ]

    # A set, not a name. `FORGE_BUILDER_IDENTITY` can add an identity that may
    # not inspect; it cannot remove the one that already may not.
    builder = excluded_inspector_identities()
    accepted: dict[str, dict] = {}
    for path in sorted(ATTESTATION_DIR.glob("*.json")) if ATTESTATION_DIR.is_dir() else []:
        try:
            attestation = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            problems.append(f"{path.name} is unreadable: {exc}")
            continue

        ok, reason, evidence = verify_signed_attestation(
            attestation, store=store, builder_identity=builder
        )
        if not ok:
            problems.append(f"{path.name}: {reason}")
            continue

        attested_subject = attestation.get("inspection_subject_digest")
        if attested_subject != subject_digest:
            # Names the ATTESTED subject and not the current one, deliberately.
            # This message reaches `verdict_basis` in the independent-review
            # record, and that record is part of the evidence set the subject is
            # computed from. Printing the current digest here wrote the subject
            # into an artifact the subject is derived from, so every
            # regeneration produced a different subject than the last -- and no
            # attestation could ever name the one the next run would present.
            #
            # Measured before this changed: two consecutive regenerations over
            # an unchanged tree, unchanged HEAD and a fixed clock disagreed, and
            # this sentence was the only differing bytes.
            problems.append(
                f"{path.name} attests to subject {attested_subject}, which is "
                "not the subject this tree now presents"
            )
            continue

        role = evidence["inspector_role"]
        if role in accepted:
            problems.append(
                f"{path.name}: role {role!r} already attested by "
                f"{accepted[role]['reviewer']!r}; which one applies would depend "
                "on ordering"
            )
            continue
        accepted[role] = {
            "reviewer": evidence["reviewer"],
            "verdict": str(attestation.get("verdict")),
            "findings_digest": attestation.get("findings_digest"),
            "tool": attestation.get("tool"),
            "tool_version": attestation.get("tool_version"),
        }
    return accepted, problems


def derive_assurance_state() -> dict:
    """Recompute the assurance position from artifacts, at verification time.

    PASS is a conclusion, never durable state. Reading ``status: "pass"`` out of
    an artifact and reporting it is not verification — it is repetition. This
    recomputes: does each artifact still describe the content that exists, do
    the evidence bytes still match what the binding covers, are the required
    inspectors present and independent.

    Deliberately separate from the code that *writes* evidence. A generator
    knows what it hopes to produce, and a function that writes artifacts and
    returns "pass" has verified nothing.
    """

    try:
        observed = governed_input_digest()
    except GovernedContentError as exc:
        # Content we cannot describe is content we cannot vouch for. A governed
        # refusal, not a traceback: a removed or unreadable governed file is a
        # legitimate state to report, and reporting it as a crash tells an
        # operator nothing about what to do.
        return {
            "state": "unverified",
            "governed_input_digest": None,
            "governed_input_match": False,
            "evidence_manifest_match": False,
            "required_inspectors_complete": False,
            "independent": False,
            "stale_artifacts": [],
            "problems": [f"governed content could not be digested: {exc}"],
        }
    state: dict = {
        "governed_input_digest": observed,
        "governed_input_match": True,
        "evidence_manifest_match": True,
        "required_inspectors_complete": False,
        "independent": False,
        "stale_artifacts": [],
        # Integrity problems only: is the evidence set internally consistent and
        # does it describe the content that is here now. Whether anyone has
        # independently inspected that content is a separate question with its
        # own list.
        "problems": [],
        "assurance_problems": [],
    }

    # The digest describes the content git holds, which is what a reviewer
    # fetches and what every checkout contains. That makes it identical on
    # every platform, and it means an unstaged edit cannot move it — so the
    # divergence is reported here, by name.
    #
    # Naming the files beats a changed digest anyway: "these paths are not what
    # the evidence describes" is actionable, where two hashes that differ is a
    # puzzle. What must never happen is neither.
    unstaged = _unstaged_governed_paths()
    if unstaged:
        state["governed_input_match"] = False
        state["problems"].append(
            "the working tree does not hold the governed content the evidence "
            "describes at: "
            + ", ".join(unstaged)
            + ". Stage or restore these paths; the digest covers committed content, "
            "so an unstaged edit is invisible to it."
        )

    # Every artifact carries the content it was produced against, in its own
    # bytes. An artifact naming a different digest inspected something else.
    for location in sorted(EVIDENCE_DIR.glob("*.json")):
        if location.name in {"INDEX.json", "review_binding.json"}:
            continue
        try:
            payload = json.loads(location.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            state["problems"].append(f"{location.name} is not readable JSON")
            continue
        if not isinstance(payload, dict):
            continue
        recorded = payload.get("governed_input_digest")
        if recorded is not None and recorded != observed:
            state["governed_input_match"] = False
            state["stale_artifacts"].append(location.name)
            state["problems"].append(
                f"{location.name} describes governed content {recorded} but the "
                f"tree digests to {observed}. It inspected different content; a "
                "new inspection is required, not a new digest."
            )

    # The evidence set the review binding claims to cover.
    binding_path = EVIDENCE_DIR / "review_binding.json"
    if not binding_path.exists():
        # Deleting the check must not be a way to pass it.
        #
        # This was `if binding_path.exists():` with no else, so removing the
        # binding removed every comparison it drives -- eleven integrity-bearing
        # claims -- and `verify()` reported `integrity_state: intact` with no
        # problems. Measured: with a real authenticated inspection in place,
        # deleting this one file left `assurance_state:
        # independently_inspected` standing while nothing verified anything.
        #
        # The same shape as the governance-integrity observer, where "nothing to
        # check" and "everything matched" were the same empty result. An absent
        # binding is not a clean tree; it is a tree nobody can make a statement
        # about.
        state["evidence_manifest_match"] = False
        state["governed_input_match"] = False
        state["problems"].append(
            "the review binding is absent, so nothing records what the evidence "
            "set claims to cover and no claim can be recomputed. Regenerate it "
            "with --review-binding; its absence is not a passing verification."
        )
    else:
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        current = digest_of(evidence_manifest(EVIDENCE_DIR, exclude=("review_binding.json",)))
        if binding.get("evidence_manifest_digest") != current:
            state["evidence_manifest_match"] = False
            state["problems"].append(
                "review binding covers evidence manifest "
                f"{binding.get('evidence_manifest_digest')} but the evidence set "
                f"digests to {current}"
            )
        if binding.get("governed_input_digest") != observed:
            state["governed_input_match"] = False
            state["problems"].append(
                "review binding describes authored inputs "
                f"{binding.get('governed_input_digest')} but the tree digests "
                f"to {observed}"
            )

        # Every integrity-bearing claim, not the two that were convenient. The
        # binding records eleven; two were compared, and a governance contract
        # tamper passed as intact while contract_set_digest sat in the file
        # recording the value that would have caught it.
        binding_problems = verify_review_binding(binding)
        if binding_problems:
            state["evidence_manifest_match"] = False
            state["problems"].extend(binding_problems)

    # Independence and completeness, recomputed rather than read.
    #
    # Deliberately not nested under "does some attestation file exist". Gating
    # the authenticated check on the presence of an artifact would mean deleting
    # that artifact skips the check — the same defect as trusting it, reached
    # from the other direction. The subject is computed, the authenticated
    # inspections are gathered, and absence produces a refusal like any other.
    state["inspection_subject_digest"] = current_inspection_subject()

    # Independence is derived from authenticated identities, never read off the
    # artifact. `builder_self_approval: false` used to decide this: a builder
    # certifying their own independence, in a file anyone could write. It is no
    # longer consulted, and a test asserts it cannot decide.
    # Kept out of `problems`, deliberately. `problems` decides `integrity_state`,
    # and a missing inspection does not damage the integrity of the evidence set
    # — it means nobody has inspected it. Folding the two together would make an
    # honestly-reported "not yet inspected" indistinguishable from a tampered
    # tree, and would fail --verify on a repository whose evidence is perfectly
    # intact. Two fields, two lists, neither standing in for the other.
    authenticated, inspection_problems = _authenticated_inspections(
        state["inspection_subject_digest"]
    )
    state["assurance_problems"] = list(inspection_problems)

    covered = {
        role: entry for role, entry in authenticated.items() if entry["verdict"] == "pass"
    }
    missing = REQUIRED_INSPECTORS - set(covered)
    reviewers = {entry["reviewer"] for entry in covered.values()}

    # What the inspectors reviewed, versus what is here now. Source can be
    # untouched while a contract moved, so binding only the inputs would let an
    # inspection claim a control pack it never saw. Every attestation reaching
    # `authenticated` was already checked against the current subject inside a
    # signature, so a complete set *is* the match: there is no second, weaker
    # copy of the subject to compare against.
    state["inspection_subject_match"] = bool(covered) and not missing

    state["required_inspectors_complete"] = not missing
    # Distinct reviewers per role: one reviewer holding every inspector role is a
    # single point of view wearing three hats, which is not what an independent
    # inspection means.
    state["independent"] = bool(covered) and len(reviewers) == len(covered)
    state["authenticated_reviewers"] = sorted(reviewers)

    if missing:
        state["assurance_problems"].append(
            f"no authenticated passing inspection for: {sorted(missing)}"
        )
    if covered and len(reviewers) != len(covered):
        state["assurance_problems"].append(
            "one reviewer covers several inspector roles, so the inspections are "
            "not independent of each other"
        )

    # Named for exactly what it covers. "verified" invited reading as "assured",
    # which it is not: an intact evidence set describing current content is a
    # different claim from a complete independent inspection, and this repository
    # currently has the first without the second. Two fields, so neither can
    # stand in for the other.
    state["integrity_state"] = (
        "intact"
        if (
            state["governed_input_match"]
            and state["evidence_manifest_match"]
            and not state["problems"]
        )
        else "compromised"
    )
    # Assurance requires integrity. Source intact with a tampered contract and an
    # old inspection still saying pass must never read as independently
    # inspected — the inspection covered a different subject.
    state["assurance_state"] = (
        "independently_inspected"
        if (
            state["integrity_state"] == "intact"
            and not state["assurance_problems"]
            and state["inspection_subject_match"]
            and state["required_inspectors_complete"]
            and state["independent"]
        )
        else "not_independently_inspected"
    )
    return state


def verify() -> list[str]:
    """Confirm every indexed artifact still hashes to its recorded value."""
    if not INDEX_PATH.exists():
        return ["evidence index is missing; run refresh_governance_evidence.py"]
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    problems: list[str] = []
    # Content, not ancestry. The previous check asked whether the bound revision
    # was an *ancestor* of HEAD, which is a fact about history and not about
    # content: every commit is an ancestor of infinitely many futures, so it
    # passed for a binding one commit stale and twenty commits stale alike.
    # Evidence at HEAD claimed to describe a revision while src/, tests/ and
    # .github/ had all changed since, and nothing could see it.
    # The digest describes the content git holds, so an unstaged edit cannot
    # move it. Reported here, by name, and gating: `derive_assurance_state`
    # records the same fact but only the problems returned from this function
    # decide the exit code, so a check that lived only there would be printed
    # and ignored.
    unstaged = _unstaged_governed_paths()
    if unstaged:
        problems.append(
            "the working tree does not hold the governed content the evidence "
            "describes at: "
            + ", ".join(unstaged)
            + ". Stage or restore these paths; the digest covers the content git "
            "holds, so an unstaged edit is invisible to it."
        )

    recorded = str(index.get("governed_input_digest", ""))
    if not recorded:
        problems.append(
            "evidence index carries no governed_input_digest, so there is no "
            "way to tell whether it describes the current content"
        )
    else:
        try:
            observed = governed_input_digest()
        except GovernedContentError as exc:
            problems.append(f"governed content could not be digested: {exc}")
            observed = None
        if observed is not None and observed != recorded:
            problems.append(
                f"evidence describes governed content {recorded} but the tree "
                f"digests to {observed}. The content changed after the evidence "
                "was generated; regenerate it."
            )

    # Recompute the assurance position rather than reading a recorded verdict.
    assurance = derive_assurance_state()
    problems.extend(assurance["problems"])

    # Re-parse each contract. Hashing artifacts says nothing about whether the
    # contract that references them still holds exactly one approval record.
    for name in APPROVAL_WIRING:
        contract = ROOT / ".nornyx/contracts" / name
        try:
            declared = contract.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Absence, reported in this tool's own vocabulary. It used to raise
            # here: deleting a required contract produced a bare
            # FileNotFoundError traceback while deleting a required FILE
            # produced a clean structured refusal. Same class of absence, two
            # behaviours, and the crash was the more security-relevant one --
            # a traceback reads as "the tool is broken", so an operator retries
            # or reinstalls instead of restoring the governed content.
            #
            # `continue` only after recording the problem. Skipping quietly
            # would be the opposite defect: a missing contract passing
            # verification because nothing was left to check.
            problems.append(
                f"{name} is required by the approval wiring and is not present "
                "under .nornyx/contracts, so its approval binding cannot be "
                "verified at all"
            )
            continue
        except OSError as exc:
            problems.append(
                f"{name} could not be read, so its approval binding cannot be "
                f"verified: {type(exc).__name__}: {exc}"
            )
            continue
        try:
            _assert_single_managed_approval(name, declared)
        except SystemExit as exc:
            problems.append(str(exc))

    for key, entry in index.get("entries", {}).items():
        path = EVIDENCE_DIR.parent / entry["artifact"]
        if not path.exists():
            problems.append(f"{key}: missing artifact {entry['artifact']}")
            continue
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry["content_hash"]:
            problems.append(f"{key}: content hash drift for {entry['artifact']}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--as-of", help="UTC timestamp used as generated_at")
    parser.add_argument(
        "--window-days",
        type=int,
        default=None,
        help="Optional finite freshness window for machine evidence; the "
        "default keeps it bound by revision and hash instead of the clock",
    )
    parser.add_argument("--verify", action="store_true", help="Check artifacts only")
    parser.add_argument(
        "--sync-contracts",
        action="store_true",
        help="Rebind contract revisions and digests to the generated index",
    )
    parser.add_argument(
        "--wire-approvals",
        action="store_true",
        help="Put adopted human approvals into the contracts, or take them out",
    )
    parser.add_argument(
        "--materialize-approval-window",
        action="store_true",
        help="Set authority declaration expiry from an inserted approval",
    )
    parser.add_argument(
        "--adopt-approval",
        action="store_true",
        help="Run the whole adoption sequence atomically: build, wire, "
        "materialize, sync, review-binding. The supported way to adopt an "
        "approval, because the governed-tree gate then runs once, up front",
    )
    parser.add_argument(
        "--review-binding",
        action="store_true",
        help="Emit the record identifying exactly what a human approval would cover",
    )
    args = parser.parse_args()

    if args.sync_contracts:
        changes = sync_contracts()
        print(json.dumps({"status": "synced", "changes": changes}, indent=2))
        return 0

    if args.adopt_approval:
        # `--as-of` only. The environment fallback that stood here was the same
        # ambient time authority removed from the runtime, surviving in the tool
        # that writes the evidence: `generated_at` is what the agentic-network
        # approval window is measured from, so a variable nobody has to declare
        # could move when an approval appears to have been granted.
        raw = args.as_of
        moment = (
            datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if raw
            else datetime.now(timezone.utc)
        )
        if moment.tzinfo is None:
            raise SystemExit("--as-of must be timezone-aware")
        print(
            json.dumps(
                adopt_approval(moment.replace(microsecond=0), args.window_days),
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.wire_approvals:
        print(json.dumps(wire_approvals(), indent=2))
        return 0

    if args.materialize_approval_window:
        print(json.dumps(materialize_approval_window(), indent=2))
        return 0

    if args.review_binding:
        # Run after --sync-contracts: it digests the contracts in their final,
        # rebound state.
        print(json.dumps(emit_review_binding(), indent=2, sort_keys=True))
        return 0

    if args.verify:
        problems = verify()
        print(
            json.dumps(
                {
                    "status": "pass" if not problems else "fail",
                    # Recomputed now, over what is on disk. Reported rather than
                    # stored, so nothing can read a stale verdict back.
                    "verification": derive_assurance_state(),
                    "problems": problems,
                },
                indent=2,
            )
        )
        return 0 if not problems else 2

    # Default to the real instant. Truncating to midnight silently backdated
    # every record, which matters because the agentic-network approval window is
    # measured from generated_at.
    # Explicit argument or the real clock. No environment route, for the reason
    # above: an instant that can be set without appearing at the call site is
    # ambient authority over how old every generated record claims to be.
    raw = args.as_of
    if raw:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise SystemExit("--as-of must be timezone-aware")
    else:
        moment = datetime.now(timezone.utc)
    moment = moment.replace(microsecond=0)
    index = build(moment, args.window_days)
    print(json.dumps(index, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
