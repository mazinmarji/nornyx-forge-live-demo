"""Untrusted text must not acquire stronger meaning by where it is used.

Three findings, one principle. Caller-supplied text was being promoted into
semantics it never earned:

* a ``mission_id`` became a filesystem path, so ``x/../CASE-HONEST`` overwrote
  another mission's decision evidence and ``../../../../pwned`` escaped the
  repository entirely;
* a ``risk`` label became a classification, so ``"HIGH-RISK"`` — unrecognised —
  fell through to the low-risk path, skipped the trust-zone crossing and the
  approval requirement, and ran the callable;
* a diagnostic's human-readable *message* became a gate decision, so a reworded
  message would break the gate and an unrelated error mentioning the right
  phrase would satisfy it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_pre_approval_baseline import (  # noqa: E402
    EXPECTED_PRE_APPROVAL_DIAGNOSTICS,
    UnstructuredCheckerOutput,
    _diagnostics,
)
from test_governance_failure import _permissive_boundary  # noqa: E402

from nornyx_forge.nornyx_runtime import (  # noqa: E402
    RISK_LEVEL_UNKNOWN,
    RISK_LEVELS,
    NornyxActionBoundary,
    UnknownRiskLevel,
    evidence_storage_key,
    normalize_risk,
)

# --------------------------------------------------------------------------
# P2-A1 — an identifier is data, never a path
# --------------------------------------------------------------------------

HOSTILE_IDS = [
    "x/../CASE-HONEST",
    "../../../../pwned",
    "/absolute/path",
    "..\\..\\victim",
    "C:\\Windows\\system32\\evil",
    "a/b\\c/../d",
    "....//....//escape",
    "CASE\u2044slash",  # unicode fraction slash
    "CASE\x00null",
]


@pytest.mark.parametrize("mission_id", HOSTILE_IDS)
def test_a_hostile_identifier_cannot_leave_the_evidence_directory(
    mission_id: str, tmp_path: Path
):
    evidence = tmp_path / "evidence/runtime/nornyx"
    evidence.mkdir(parents=True)
    target = (evidence / f"{evidence_storage_key(mission_id)}.report.json").resolve()
    assert target.parent == evidence.resolve(), mission_id
    assert evidence.resolve() in target.parents, mission_id


def test_sanitising_alone_would_have_created_collisions():
    """Closing traversal must not open overwriting.

    Replacing separators maps `a/b` and `a_b` onto one name, so a second mission
    could silently replace the first mission's evidence — including the record of
    a refused high-risk effect. The digest of the original identifier is what
    keeps them apart.
    """
    assert evidence_storage_key("a/b") != evidence_storage_key("a_b")
    assert evidence_storage_key("x/../y") != evidence_storage_key("x_.._y")

    collided = {evidence_storage_key(value) for value in ("a/b", "a_b", "a\\b", "a.b")}
    assert len(collided) == 4, "distinct identifiers must not share a storage key"


def test_the_storage_key_is_stable_bounded_and_derived_from_the_original():
    long_id = "M" * 500
    key = evidence_storage_key(long_id)
    assert len(key) <= 64 + 2 + 16
    assert evidence_storage_key(long_id) == key, "must be deterministic"
    assert hashlib.sha256(long_id.encode()).hexdigest()[:16] in key

    assert evidence_storage_key("") == evidence_storage_key("")
    assert evidence_storage_key("").startswith("unnamed--")


def test_the_real_identifier_survives_in_the_payload(tmp_path: Path):
    """A filename is storage identity; governance identity stays in the data.

    Driven through the official path, which is the one that writes evidence —
    the fallback records nothing, so a fallback boundary would prove nothing.
    """
    boundary = _permissive_boundary(tmp_path)
    boundary.evaluate_and_execute(
        mission_id="x/../CASE-HONEST", risk="low", action=lambda: "done"
    )
    evidence = (tmp_path / "evidence/runtime/nornyx").resolve()
    written = list(evidence.glob("*.report.json"))
    assert written, "no evidence was written"

    # The invariant is containment, not the absence of a substring. A name may
    # legitimately contain dots — `x_.._CASE-HONEST` is one component and cannot
    # traverse anywhere. What matters is where the file actually landed.
    for path in written:
        assert path.resolve().parent == evidence, path
        assert "/" not in path.name and "\\" not in path.name, path


def test_one_mission_cannot_overwrite_another(tmp_path: Path):
    boundary = _permissive_boundary(tmp_path)
    boundary.evaluate_and_execute(mission_id="CASE-HONEST", risk="low", action=lambda: "a")
    boundary.evaluate_and_execute(
        mission_id="x/../CASE-HONEST", risk="low", action=lambda: "b"
    )
    written = list((tmp_path / "evidence/runtime/nornyx").glob("*.report.json"))
    assert len(written) == 2, "a crafted id overwrote another mission's evidence"


# --------------------------------------------------------------------------
# P2-A2 — an unclassified act is not a low-risk act
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label",
    ["HIGH-RISK", "high_risk", "severe", "urgent", "unknown", "", "  ", "High\n!", "elevated"],
)
def test_an_unrecognised_risk_label_is_refused(label: str, tmp_path: Path):
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    ran: list[int] = []
    decision, result = boundary.evaluate_and_execute(
        mission_id="CASE-1", risk=label, action=lambda: ran.append(1) or "ran"
    )
    assert decision.effect == "DENY", label
    assert decision.code == RISK_LEVEL_UNKNOWN, label
    assert result is None
    assert ran == [], f"{label!r} reached the callable"


@pytest.mark.parametrize("label", [None, 3, True, 0.5, ["high"], {"risk": "high"}])
def test_a_non_string_risk_is_refused(label: object, tmp_path: Path):
    """Types other than str can reach this boundary through the library API."""
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    ran: list[int] = []
    decision, _ = boundary.evaluate_and_execute(
        mission_id="CASE-1", risk=label, action=lambda: ran.append(1) or "ran"
    )
    assert decision.effect == "DENY"
    assert decision.code == RISK_LEVEL_UNKNOWN
    assert ran == []


def test_an_unknown_risk_consumes_no_approval(tmp_path: Path):
    """Refused before anything could be spent finding out."""
    from nornyx_forge.nornyx_runtime import ApprovalLedger

    ledger_path = tmp_path / "ledger.sqlite3"
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    boundary.approval_ledger = ApprovalLedger(ledger_path)
    boundary.evaluate_and_execute(
        mission_id="CASE-1", risk="HIGH-RISK", action=lambda: "ran",
        action_approval={"granted": True, "approval_id": "ACT-1"},
    )
    import sqlite3

    rows = sqlite3.connect(ledger_path).execute(
        "SELECT COUNT(*) FROM consumed_approvals"
    ).fetchone()[0]
    assert rows == 0


@pytest.mark.parametrize("label", sorted(RISK_LEVELS))
def test_every_declared_level_is_accepted(label: str):
    assert normalize_risk(label) == label
    assert normalize_risk(f"  {label.upper()}  ") == label


def test_the_vocabulary_is_closed_and_has_no_aliases():
    """Friendly labels belong upstream, where a mistranslation is a display bug."""
    assert RISK_LEVELS == {"low", "medium", "high", "critical"}
    for alias in ("hi", "HIGH RISK", "crit", "danger", "p0"):
        with pytest.raises(UnknownRiskLevel):
            normalize_risk(alias)


def test_the_unknown_risk_code_is_distinct_from_missing_approval(tmp_path: Path):
    """Different facts, different remedies."""
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    unknown, _ = boundary.evaluate_and_execute(
        mission_id="A", risk="severe", action=lambda: "ran"
    )
    known, _ = boundary.evaluate_and_execute(
        mission_id="B", risk="high", action=lambda: "ran"
    )
    assert unknown.code == RISK_LEVEL_UNKNOWN
    assert known.code == "HUMAN_APPROVAL_REQUIRED"
    assert unknown.code != known.code


# --------------------------------------------------------------------------
# P2-A3 — classify by structure, never by prose
# --------------------------------------------------------------------------


def _diag(code: str, path: str, source: str, message: str = "anything") -> str:
    return json.dumps(
        {"level": "error", "code": code, "path": path, "source_id": source,
         "message": message}
    )


def _classify(payload: str) -> list[dict]:
    """The gate's own classification, over synthetic checker output."""
    diagnostics = _diagnostics(payload)
    return [
        item
        for item in diagnostics
        if item.get("level") == "error"
        and (str(item.get("code")), str(item.get("path")), str(item.get("source_id")))
        not in EXPECTED_PRE_APPROVAL_DIAGNOSTICS
    ]


def test_the_expected_triple_is_accepted():
    payload = _diag(
        "AN_APPROVAL_RECORD_MISSING",
        "governance_evidence.records",
        "agentic_network_foundation.v1",
    )
    assert _classify(payload) == []


def test_rewording_the_message_does_not_break_the_gate():
    """Codes are the stable vocabulary; message text is not."""
    payload = _diag(
        "APPROVAL_EVIDENCE_MISSING",
        "approvals[0].required_evidence",
        "human_approval.v1",
        message="Completely different wording, no magic phrase at all.",
    )
    assert _classify(payload) == []


def test_the_right_code_at_the_wrong_path_is_not_an_approval_gap():
    payload = _diag(
        "EVIDENCE_REQUIRED_MISSING",
        "architecture_evidence[0]",
        "evidence_integrity.v1",
    )
    assert _classify(payload), "a different path was accepted as an approval gap"


def test_a_message_mentioning_approval_record_cannot_launder_another_error():
    """The exact defect: prose deciding what a diagnostic meant."""
    payload = _diag(
        "SCHEMA_INVALID",
        "governance_evidence.records",
        "evidence_integrity.v1",
        message="something about approval_record went wrong",
    )
    assert _classify(payload), "message text satisfied the gate"


def test_an_unexpected_error_alongside_an_expected_one_still_fails():
    payload = (
        _diag(
            "AN_APPROVAL_RECORD_MISSING",
            "governance_evidence.records",
            "agentic_network_foundation.v1",
        )
        + _diag("EVIDENCE_STALE", "governance_evidence.records[2].expires_at", "evidence_integrity.v1")
    )
    assert len(_classify(payload)) == 1


def test_unstructured_output_fails_rather_than_being_skipped():
    """The parser used to walk past anything it could not decode.

    So a crash banner followed by an acceptable diagnostic classified as a clean
    approval-only block. For an assurance gate, output it cannot account for is a
    reason to fail.
    """
    payload = (
        "INTERNAL VALIDATOR CRASHED\n"
        + _diag(
            "AN_APPROVAL_RECORD_MISSING",
            "governance_evidence.records",
            "agentic_network_foundation.v1",
        )
    )
    with pytest.raises(UnstructuredCheckerOutput):
        _diagnostics(payload)


def test_the_gate_reports_unstructured_output_rather_than_passing(tmp_path: Path):
    """End to end: a checker that prints noise must not yield a healthy baseline."""
    fake = tmp_path / ("nornyx.bat" if sys.platform == "win32" else "nornyx")
    if sys.platform == "win32":
        fake.write_text("@echo INTERNAL VALIDATOR CRASHED\r\n@exit /b 1\r\n", encoding="utf-8")
    else:
        fake.write_text("#!/bin/sh\necho INTERNAL VALIDATOR CRASHED\nexit 1\n", encoding="utf-8")
        fake.chmod(0o755)

    import check_pre_approval_baseline as gate

    result = gate._check(str(gate.GOVERNANCE_CONTRACTS[0]), str(fake))
    assert result["approval_blocked"] is False
    assert result["unexpected_diagnostics"], "noise was accepted as an approval gap"


def test_no_assurance_gate_classifies_by_message_text():
    """The invariant, asserted against the source rather than assumed."""
    source = (ROOT / "scripts/check_pre_approval_baseline.py").read_text(encoding="utf-8")
    assert 'item.get("message"' not in source
    assert "APPROVAL_SUBJECTS" not in source


def test_generic_evidence_missing_cannot_masquerade_as_approval_absence():
    """`EVIDENCE_REQUIRED_MISSING` alone means *some* record is absent.

    Only the full triple makes it specific to the human-approval gap.
    """
    codes_alone = {code for code, _, _ in EXPECTED_PRE_APPROVAL_DIAGNOSTICS}
    assert "EVIDENCE_REQUIRED_MISSING" in codes_alone
    payload = _diag(
        "EVIDENCE_REQUIRED_MISSING",
        "governance_evidence.records",
        "some_other_module.v1",
    )
    assert _classify(payload), "a different source module was accepted"


def test_the_real_contracts_still_classify_as_approval_blocked():
    """The gate must still recognise the state this repository is actually in."""
    if shutil.which("nornyx") is None:
        pytest.skip("nornyx CLI is not installed")
    import check_pre_approval_baseline as gate

    for contract in gate.GOVERNANCE_CONTRACTS:
        result = gate._check(contract, shutil.which("nornyx"))
        assert result["validates"] or result["approval_blocked"], result
        assert result["unexpected_diagnostics"] == [], result
