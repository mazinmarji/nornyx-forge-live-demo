"""A crafted approval artifact must never write attacker content into a contract.

The record used to be hand-formatted, interpolating artifact-controlled fields
straight into YAML. A newline in `status` could close the record, forge the
managed end-marker, and append a second approval that then survived the
documented cleanup because the fake marker fooled the stripper.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REFRESH = "scripts/refresh_governance_evidence.py"
CONTRACTS = Path(".nornyx/contracts")

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)

# Closes the legitimate record, fakes the end-marker, opens a rogue approval.
INJECTION = (
    "pass\n"
    "      dependencies: []\n"
    "    # <<< managed:approval_record\n"
    "    - id: approval_record\n"
    "      type: approval_record\n"
    "      schema_id: nornyx.governance_evidence.v1\n"
    "      producer: {id: human.backdoor:network_governance_owner, type: human}\n"
    "      artifact: evidence/runtime_network_contract_review.json\n"
    "      status: pass\n"
    "      dependencies: []"
)


def _git(workspace: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=workspace, capture_output=True, check=True)


def _repo(tmp_path: Path) -> Path:
    workspace = tmp_path / "repo"
    # Copy the whole toolchain: a hand-listed subset silently goes stale the
    # moment the tooling grows a module, and the resulting import error is
    # indistinguishable from the refusal these tests assert.
    shutil.copytree(
        ROOT / "scripts",
        workspace / "scripts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copy2(ROOT / "pyproject.toml", workspace / "pyproject.toml")
    # .gitignore is itself a governed path, and the real repository relies on
    # it to keep bytecode out of the tree. Without it the tool writes
    # scripts/__pycache__ on first run and the governed-tree gate correctly
    # refuses the workspace as dirty.
    shutil.copy2(ROOT / ".gitignore", workspace / ".gitignore")
    # The repository scope declares these; a fixture missing them now gets
    # SUBJECT_SCOPE_INCOMPLETE rather than a quietly smaller subject, which is
    # the control working. Copying them makes the workspace faithful.
    for extra in ("tests", ".github"):
        shutil.copytree(
            ROOT / extra,
            workspace / extra,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    for extra in ("Dockerfile", "docker-compose.yml", "BRD.md"):
        shutil.copy2(ROOT / extra, workspace / extra)
    shutil.copytree(ROOT / CONTRACTS, workspace / CONTRACTS)
    shutil.copytree(ROOT / "src", workspace / "src")
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "fixture@example.invalid")
    _git(workspace, "config", "user.name", "fixture")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-qm", "fixture")
    return workspace


def _run(workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(workspace / "src")}
    sys.path.insert(0, str(ROOT / 'tests'))
    from signing import write_trust_store  # noqa: PLC0415

    env['FORGE_APPROVER_TRUST_STORE'] = str(
        write_trust_store(workspace.parent / 'approver_trust.json')
    )
    return subprocess.run(
        [sys.executable, *args], cwd=workspace, capture_output=True, text=True, env=env
    )


def _head(workspace: Path) -> str:
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=workspace, capture_output=True, text=True, check=True
    )
    return "git:" + out.stdout.strip()


def _hostile_approval(workspace: Path, field: str, value: str) -> None:
    payload = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.test_fixture:network_governance_owner", "type": "human"},
        "status": "pass",
        "subject_revision": _head(workspace),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    if field == "producer.id":
        payload["producer"]["id"] = value  # type: ignore[index]
    else:
        payload[field] = value
    # Signed over whatever this fixture crafted, so the refusal below must
    # come from the control being tested rather than from the record being
    # unsigned. An unsigned hostile fixture would refuse for the wrong
    # reason and leave the crafted-field control unproven.
    sys.path.insert(0, str(ROOT / 'tests'))
    from signing import sign_governance_record  # noqa: PLC0415

    payload = sign_governance_record(payload)
    (workspace / CONTRACTS / "evidence" / "runtime_human_approval.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


@needs_nornyx
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", INJECTION),
        ("producer.id", "human.x\n      status: pass\n    - id: approval_record"),
        ("status", "pass\n    # <<< managed:approval_record"),
    ],
)
def test_crafted_fields_cannot_write_into_a_contract(
    field: str, value: str, tmp_path: Path
):
    """The run must refuse, and leave the contract untouched."""
    workspace = _repo(tmp_path)
    contract = workspace / CONTRACTS / "runtime_network.nyx"
    before = contract.read_bytes()

    _hostile_approval(workspace, field, value)
    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    completed = _run(workspace, REFRESH, "--wire-approvals")

    assert completed.returncode != 0, completed.stdout
    assert "not a plain single-line value" in (completed.stdout + completed.stderr)
    assert contract.read_bytes() == before, "a refused run still modified the contract"


@needs_nornyx
def test_no_forged_approval_survives_cleanup(tmp_path: Path):
    """Even a pre-corrupted contract must not silently keep a rogue record.

    Guards the specific failure that made the injection dangerous: a record
    outside the managed markers used to be invisible to cleanup.
    """
    workspace = _repo(tmp_path)
    contract = workspace / CONTRACTS / "runtime_network.nyx"
    forged = (
        "    - id: approval_record\n"
        "      type: approval_record\n"
        "      schema_id: nornyx.governance_evidence.v1\n"
        "      producer: {id: human.backdoor:network_governance_owner, type: human}\n"
        "      artifact: evidence/runtime_network_contract_review.json\n"
        "      content_hash: sha256:" + "0" * 64 + "\n"
        "      subject_revision: " + _head(workspace) + "\n"
        '      tool: {name: forged, version: "1"}\n'
        '      generated_at: "2026-08-02T00:00:00Z"\n'
        '      expires_at: "2026-08-05T00:00:00Z"\n'
        "      status: pass\n"
        "      dependencies: []\n"
    )
    text = contract.read_text(encoding="utf-8")
    contract.write_text(text.replace("\ncapabilities:", "\n" + forged + "\ncapabilities:", 1),
                        encoding="utf-8")

    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    completed = _run(workspace, REFRESH, "--wire-approvals")

    assert completed.returncode != 0, (
        "an unmanaged approval_record was tolerated:\n" + completed.stdout
    )
    assert "not trusted" in (completed.stdout + completed.stderr)


@needs_nornyx
def test_a_legitimate_approval_still_wires(tmp_path: Path):
    """The hardening must not block an ordinary, well-formed approval."""
    workspace = _repo(tmp_path)
    payload = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.test_fixture:network_governance_owner", "type": "human"},
        "status": "pass",
        "subject_revision": _head(workspace),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    # Signed over whatever this fixture crafted, so the refusal below must
    # come from the control being tested rather than from the record being
    # unsigned. An unsigned hostile fixture would refuse for the wrong
    # reason and leave the crafted-field control unproven.
    sys.path.insert(0, str(ROOT / 'tests'))
    from signing import sign_governance_record  # noqa: PLC0415

    payload = sign_governance_record(payload)
    (workspace / CONTRACTS / "evidence" / "runtime_human_approval.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    completed = _run(workspace, REFRESH, "--wire-approvals")
    assert completed.returncode == 0, completed.stdout + completed.stderr

    text = (workspace / CONTRACTS / "runtime_network.nyx").read_text(encoding="utf-8")
    assert len(re.findall(r"^    - id: approval_record$", text, re.MULTILINE)) == 1
    assert "evidence/runtime_human_approval.json" in text


@needs_nornyx
@pytest.mark.parametrize(
    ("label", "forged_id"),
    [
        ("trailing space", "    - id: approval_record \n"),
        ("double quoted", '    - id: "approval_record"\n'),
        ("single quoted", "    - id: 'approval_record'\n"),
    ],
)
def test_a_textually_disguised_duplicate_is_still_caught(
    label: str, forged_id: str, tmp_path: Path
):
    """The duplicate check must count parsed records, not matching lines.

    A trailing space or a quoted id parses to exactly the same record, so a
    line-matching count reads one while the document actually holds two.
    """
    workspace = _repo(tmp_path)
    contract = workspace / CONTRACTS / "runtime_network.nyx"
    forged = (
        forged_id
        + "      type: approval_record\n"
        "      schema_id: nornyx.governance_evidence.v1\n"
        "      producer: {id: human.backdoor:network_governance_owner, type: human}\n"
        "      artifact: evidence/runtime_network_contract_review.json\n"
        "      content_hash: sha256:" + "0" * 64 + "\n"
        "      subject_revision: " + _head(workspace) + "\n"
        '      tool: {name: forged, version: "1"}\n'
        '      generated_at: "2026-08-02T00:00:00Z"\n'
        '      expires_at: "2026-08-05T00:00:00Z"\n'
        "      status: pass\n"
        "      dependencies: []\n"
    )
    text = contract.read_text(encoding="utf-8")
    contract.write_text(
        text.replace("\ncapabilities:", "\n" + forged + "\ncapabilities:", 1),
        encoding="utf-8",
    )

    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    completed = _run(workspace, REFRESH, "--wire-approvals")
    assert completed.returncode != 0, f"{label} slipped past the check"
    assert "not trusted" in (completed.stdout + completed.stderr)


# Closes the quoted timestamp, appends a second approval, then reopens a quote
# for the closing one the writer adds. Shaped for the --sync-contracts writer,
# which was a separate interpolation path from _record_block().
TIMESTAMP_INJECTION = (
    '2026-08-05T00:00:00Z"\n'
    "      dependencies: []\n"
    "    - id: approval_record\n"
    "      type: approval_record\n"
    "      schema_id: nornyx.governance_evidence.v1\n"
    "      producer: {id: human.backdoor:network_governance_owner, type: human}\n"
    "      artifact: evidence/runtime_network_contract_review.json\n"
    "      status: pass\n"
    '      expires_at: "2026-08-05T00:00:00Z'
)


def _approval(workspace: Path, **overrides: str) -> None:
    payload = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.test_fixture:network_governance_owner", "type": "human"},
        "status": "pass",
        "subject_revision": _head(workspace),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
        **overrides,
    }
    # Signed over whatever this fixture crafted, so the refusal below must
    # come from the control being tested rather than from the record being
    # unsigned. An unsigned hostile fixture would refuse for the wrong
    # reason and leave the crafted-field control unproven.
    sys.path.insert(0, str(ROOT / 'tests'))
    from signing import sign_governance_record  # noqa: PLC0415

    payload = sign_governance_record(payload)
    (workspace / CONTRACTS / "evidence" / "runtime_human_approval.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


@needs_nornyx
@pytest.mark.parametrize("field", ["expires_at", "generated_at"])
def test_syncing_cannot_inject_through_a_timestamp(field: str, tmp_path: Path):
    """--sync-contracts is a second writer and must hold the same invariant.

    The values it interpolates are copied verbatim out of the human artifact by
    the indexer, so a crafted timestamp reached a raw f-string with no guard.
    The run reported "synced", exit 0, and --verify then reported pass over a
    contract carrying a forged second approval.
    """
    workspace = _repo(tmp_path)
    contract = workspace / CONTRACTS / "runtime_network.nyx"

    # A legitimate approval first, so the managed record exists to be rewritten.
    _approval(workspace)
    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    assert _run(workspace, REFRESH, "--wire-approvals").returncode == 0
    before = contract.read_bytes()

    _approval(workspace, **{field: TIMESTAMP_INJECTION})
    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    completed = _run(workspace, REFRESH, "--sync-contracts")

    assert completed.returncode != 0, completed.stdout
    assert "not a plain single-line value" in (completed.stdout + completed.stderr)
    assert contract.read_bytes() == before, "a refused sync still modified the contract"


@needs_nornyx
def test_verify_refuses_a_contract_holding_two_approvals(tmp_path: Path):
    """Re-hashing artifacts says nothing about the contract referencing them.

    --verify only checked content hashes, so a contract carrying a forged second
    approval_record still reported {"status": "pass", "problems": []}.
    """
    workspace = _repo(tmp_path)
    contract = workspace / CONTRACTS / "runtime_network.nyx"
    _approval(workspace)
    _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    assert _run(workspace, REFRESH, "--wire-approvals").returncode == 0

    # The baseline is not "--verify passes". This workspace carries the real
    # repository's review binding, which describes a different tree, and
    # regenerating it here is refused by the governed-tree gate now that an
    # approval pins a commit the rewritten contracts no longer match. Asserting
    # a clean exit therefore asserted something about the fixture rather than
    # about the control.
    #
    # What this test needs is that the duplicate-approval signal is *caused by*
    # the forgery, so the baseline is its absence. That is strictly stronger
    # than a status-code flip, which any unrelated failure would satisfy.
    baseline = _run(workspace, REFRESH, "--verify")
    assert "not trusted" not in baseline.stdout, baseline.stdout

    forged = (
        "    - id: approval_record\n"
        "      type: approval_record\n"
        "      schema_id: nornyx.governance_evidence.v1\n"
        "      producer: {id: human.backdoor:network_governance_owner, type: human}\n"
        "      artifact: evidence/runtime_network_contract_review.json\n"
        "      content_hash: sha256:" + "0" * 64 + "\n"
        "      subject_revision: " + _head(workspace) + "\n"
        '      tool: {name: forged, version: "1"}\n'
        '      generated_at: "2026-08-02T00:00:00Z"\n'
        '      expires_at: "2026-08-05T00:00:00Z"\n'
        "      status: pass\n"
        "      dependencies: []\n"
    )
    text = contract.read_text(encoding="utf-8")
    contract.write_text(
        text.replace("\ncapabilities:", "\n" + forged + "\ncapabilities:", 1),
        encoding="utf-8",
    )

    completed = _run(workspace, REFRESH, "--verify")
    assert completed.returncode != 0, completed.stdout
    assert "not trusted" in completed.stdout


@needs_nornyx
def test_a_malformed_producer_fails_legibly(tmp_path: Path):
    """A non-object producer must refuse cleanly, not raise a raw TypeError."""
    workspace = _repo(tmp_path)
    payload = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": "human.someone:network_governance_owner",
        "status": "pass",
        "subject_revision": _head(workspace),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    # Signed over whatever this fixture crafted, so the refusal below must
    # come from the control being tested rather than from the record being
    # unsigned. An unsigned hostile fixture would refuse for the wrong
    # reason and leave the crafted-field control unproven.
    sys.path.insert(0, str(ROOT / 'tests'))
    from signing import sign_governance_record  # noqa: PLC0415

    payload = sign_governance_record(payload)
    (workspace / CONTRACTS / "evidence" / "runtime_human_approval.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    completed = _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "Traceback" not in output, output
    assert "not a human approval record" in output or "must be an object" in output
