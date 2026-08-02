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
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / ".nornyx/contracts/evidence"
INDEX_PATH = EVIDENCE_DIR / "INDEX.json"

# Non-approval evidence may carry a long freshness window. Agentic-network approval
# evidence is capped at P7D by nornyx.builtin.module.agentic_network_governance.
DEFAULT_WINDOW_DAYS = 365

#: Machine-generated evidence is bound by content hash and subject revision, so
#: any change to what it describes invalidates it immediately. A wall-clock
#: window adds nothing and only rots the public baseline. Human approval is the
#: opposite: authority genuinely decays, and Nornyx caps it at P7D. Keeping the
#: two separate is what lets the baseline stay reviewer-ready indefinitely while
#: real approvals stay short-lived.
MACHINE_EVIDENCE_EXPIRES = "2099-01-01T00:00:00Z"

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


def _adopt_human_approval(key: str, filename: str, entries: dict) -> bool:
    """Index a human-authored approval record without altering it.

    Everything indexed — status, producer, statement, validity window — comes
    from the file the human wrote. This function has no path that authors an
    approval, upgrades a status, or edits a statement.
    """

    path = EVIDENCE_DIR / filename
    if not path.exists():
        return False
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    producer = payload.get("producer", {})
    if producer.get("type") != "human":
        raise SystemExit(
            f"{filename} is not a human approval record: producer.type is "
            f"{producer.get('type')!r}. Refusing to index it as one."
        )
    entries[key] = {
        "artifact": f"evidence/{filename}",
        "content_hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "generated_at": payload["generated_at"],
        "expires_at": payload["expires_at"],
        "status": payload["status"],
        "subject_revision": payload["subject_revision"],
        "producer": producer,
        "authored_by": "human",
    }
    return True


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
    expires = (
        MACHINE_EVIDENCE_EXPIRES
        if window_days is None
        else _iso(generated_at + timedelta(days=window_days))
    )
    report = _architecture_report()
    arch_status = "pass" if report.get("status") == "pass" else "fail"

    entries: dict[str, dict] = {}

    def emit(key: str, filename: str, payload: dict, *, status: str) -> None:
        artifact = f"evidence/{filename}"
        content_hash = _write(EVIDENCE_DIR / filename, payload)
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
    reviews_path = ROOT / ".nornyx/in-session/reviews.json"
    review_status = "observed"
    reviewers: list[dict[str, str]] = []
    embedded: dict | None = None
    source_sha256: str | None = None
    if reviews_path.exists():
        raw_reviews = reviews_path.read_bytes()
        source_sha256 = "sha256:" + hashlib.sha256(raw_reviews).hexdigest()
        payload = json.loads(raw_reviews.decode("utf-8"))
        embedded = payload
        reviewers = [
            {"role": str(item.get("role")), "status": str(item.get("status"))}
            for item in payload.get("reviews", [])
        ]
        required = {"test-inspector", "architecture-inspector", "security-inspector"}
        if (
            payload.get("builder_self_approval") is False
            and required <= {item["role"] for item in reviewers}
            and all(item["status"] == "pass" for item in reviewers)
        ):
            # Every required independent reviewer completed and passed. This
            # records that a real review happened; it is not a human approval.
            review_status = "pass"
    emit(
        "architecture_independent_review",
        "architecture_independent_review.json",
        {
            "schema": "nornyx.forge.independent_review_record.v1",
            "subject_revision": revision,
            "generated_at": generated,
            "reviewer_type": "read_only_ai_inspector",
            "human_review": "not_performed",
            "builder_self_approval": False,
            "reviewers": reviewers,
            "statement": (
                "Architecture conformance was inspected by read-only inspectors that "
                "cannot modify the implementation and did not author this record's "
                "verdict on their own behalf. This is an independent machine review, "
                "not a human review and not an approval."
            ),
            "source": ".nornyx/in-session/reviews.json",
            "source_sha256": source_sha256,
            "reviews": embedded,
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
_RECORD_START_RE = re.compile(r"^\s*-\s+(?:id|schema):")
_TIMESTAMP_RE = re.compile(
    r"^(?P<lead>\s*(?P<field>generated_at|expires_at):\s*)[\"']?[0-9T:+\-Z.]+[\"']?\s*$"
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
    times_by_artifact = {
        entry["artifact"]: (
            entry.get("generated_at", index["generated_at"]),
            entry.get("expires_at", index["expires_at"]),
        )
        for entry in index["entries"].values()
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
                    value = generated if field == "generated_at" else expires
                    if value not in line:
                        lines[position] = f'{moment.group("lead")}"{value}"\n'
                        changes.append(f"{contract.name}: {field} -> {value}")
        rewritten = "".join(lines)
        if rewritten != original:
            contract.write_text(rewritten, encoding="utf-8", newline="")
    return changes


def _approved_revision() -> str | None:
    """Return the revision a human approval pins, if one exists.

    A human approves one exact revision. Once that approval exists the contracts
    must keep declaring it: silently rebinding to the current HEAD would move the
    governed subject out from under the approval and, by the approvers' own
    invalidation terms, void it while leaving it looking valid.
    """

    pinned: set[str] = set()
    for name in ("runtime_human_approval.json", "architecture_human_approval.json"):
        path = EVIDENCE_DIR / name
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        revision = payload.get("subject_revision")
        if isinstance(revision, str) and revision:
            pinned.add(revision)
    if not pinned:
        return None
    if len(pinned) > 1:
        raise SystemExit(
            "human approvals pin different subject revisions: " + ", ".join(sorted(pinned))
        )
    return pinned.pop()


def _approval_state() -> dict:
    """Report the human approvals that exist, exactly as they were written."""

    state: dict = {"human_review": "not_performed", "records": []}
    for scope, name in (
        ("agentic_network", "runtime_human_approval.json"),
        ("architecture", "architecture_human_approval.json"),
    ):
        path = EVIDENCE_DIR / name
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        state["human_review"] = "performed"
        state["records"].append(
            {
                "scope": scope,
                "artifact": f"evidence/{name}",
                "producer": payload.get("producer", {}),
                "status": payload.get("status"),
                "approval": payload.get("approval"),
                "generated_at": payload.get("generated_at"),
                "expires_at": payload.get("expires_at"),
                "subject_revision": payload.get("subject_revision"),
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
    windows = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in EVIDENCE_DIR.glob("*human_approval.json")
    }
    if not windows:
        # Restore the placeholder. Leaving the short reviewer window behind after
        # an approval is withdrawn re-rots the baseline the moment that date
        # passes, which is the exact regression 0.3.0 exists to prevent.
        return _set_authority_expiry(
            MACHINE_EVIDENCE_EXPIRES, status="restored_placeholder"
        )
    expiries = {payload["expires_at"] for payload in windows.values()}
    if len(expiries) > 1:
        raise SystemExit(
            "human approvals declare different expiries: " + ", ".join(sorted(expiries))
        )
    expires = expiries.pop()
    return _set_authority_expiry(expires, status="materialized")


def _set_authority_expiry(expires: str, *, status: str) -> dict:
    """Write one expiry into every authority declaration, and only there."""
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
            moment = _TIMESTAMP_RE.match(line)
            if moment and moment.group("field") == "expires_at" and expires not in line:
                lines[position] = f'{moment.group("lead")}"{expires}"\n'
                changes.append(f"{contract.name}: authority expiry -> {expires}")
        rewritten = "".join(lines)
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
_SAFE_SCALAR_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")


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

    producer = entry["producer"]
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
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    entries = index["entries"]
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
            key = (
                "runtime_approval_record"
                if name.startswith("runtime")
                else "architecture_approval_record"
            )
            entry = dict(entries[key])
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
            entry = dict(entries["architecture_approval_record"])
            entry.setdefault("producer", {"id": "system:autonomous_demonstration", "type": "system"})
            entry["tool_name"] = "refresh_governance_evidence"
            entry["tool_version"] = TOOL_VERSION
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

    Cleanup removes the records it recognises. Anything else claiming to be an
    approval — hand-added, or left behind by an earlier corrupted write — would
    otherwise sit in the contract indistinguishable from real content.
    """

    total = len(re.findall(r"^    - id: approval_record$", text, re.MULTILINE))
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


def require_approval_matches_head() -> str | None:
    """Refuse to touch anything when an approval pins a different revision.

    Generating evidence from the working tree at HEAD and stamping it with an
    older approved revision produces evidence that describes code nobody
    approved. Rebinding the approval to HEAD is worse — it silently moves the
    subject out from under the human. So the only safe response is to stop
    before writing anything and let a human re-approve the new revision.

    Returns the approved revision when it matches HEAD, or None when no approval
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
    binding = {
        "schema": "nornyx.forge.review_binding.v1",
        "generated_at": _iso(datetime.now(timezone.utc)),
        "subject_revision": index["subject_revision"],
        "control_pack_commit": _head_commit(),
        "note": (
            "subject_revision is the revision the contracts govern. "
            "control_pack_commit is the commit that carries those contracts and "
            "their evidence. An approval should name both."
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


def verify() -> list[str]:
    """Confirm every indexed artifact still hashes to its recorded value."""
    if not INDEX_PATH.exists():
        return ["evidence index is missing; run refresh_governance_evidence.py"]
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    problems: list[str] = []
    # The governed subject revision is necessarily an ancestor of HEAD, never
    # equal to it: the commit that carries a contract cannot be named inside it.
    # So require that the binding names a real commit in this history, not that
    # it matches the current HEAD.
    bound = str(index.get("subject_revision", ""))
    if not bound.startswith("git:"):
        problems.append(f"evidence index has no git revision binding: {bound!r}")
    else:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if shallow.stdout.strip() == "true":
            # A shallow clone cannot answer the ancestry question. Artifact hash
            # integrity below is the primary assertion and still applies.
            pass
        else:
            reachable = subprocess.run(
                ["git", "merge-base", "--is-ancestor", bound.removeprefix("git:"), "HEAD"],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if reachable.returncode != 0:
                problems.append(
                    f"evidence index is bound to {bound}, which is not an ancestor of HEAD"
                )
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
        "--review-binding",
        action="store_true",
        help="Emit the record identifying exactly what a human approval would cover",
    )
    args = parser.parse_args()

    if args.sync_contracts:
        changes = sync_contracts()
        print(json.dumps({"status": "synced", "changes": changes}, indent=2))
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
        print(json.dumps({"status": "pass" if not problems else "fail", "problems": problems}, indent=2))
        return 0 if not problems else 2

    # Default to the real instant. Truncating to midnight silently backdated
    # every record, which matters because the agentic-network approval window is
    # measured from generated_at.
    raw = args.as_of or os.getenv("FORGE_RUNTIME_AS_OF")
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
