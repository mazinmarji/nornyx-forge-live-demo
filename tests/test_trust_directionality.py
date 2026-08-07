"""Derived artifacts must not flow upward into authority or assurance.

Two reproduced exploits shared one shape. Trust is supposed to run downward:

    authenticated human approval  ─┐
    validated machine inspection  ─┼─► derived outputs: INDEX.json, review
    governed source content       ─┘   summaries, dashboards, evidence views

It was running upward instead. `INDEX.json` — a derived index this tool writes —
was read back as the source of a human approval's producer, status and window.
And `.nornyx/in-session/reviews.json` — untracked, gitignored, validated by
nothing — decided whether an independent review had passed.

The invariant these tests defend is blunt: a clean `git status` plus
attacker-controlled derived files is neither a trusted approval nor independent
assurance.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = Path(".nornyx/contracts")
REFRESH = "scripts/refresh_governance_evidence.py"
RUNTIME_APPROVAL = "runtime_human_approval.json"
ARCHITECTURE_APPROVAL = "architecture_human_approval.json"

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(work), *args], capture_output=True, text=True, check=True
    )


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx"):
        shutil.copytree(ROOT / item, work / item)
    for item in ("pyproject.toml", ".gitignore"):
        shutil.copy2(ROOT / item, work / item)
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "fixture")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "fixture")
    return work


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True, env=env
    )


def _head(work: Path) -> str:
    return "git:" + _git(work, "rev-parse", "HEAD").stdout.strip()


def _approval(work: Path, filename: str = RUNTIME_APPROVAL, **overrides: object) -> None:
    payload: dict[str, object] = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.test_fixture:network_governance_owner", "type": "human"},
        "status": "pass",
        "subject_revision": _head(work),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    payload.update(overrides)
    (work / CONTRACTS / "evidence" / filename).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _index(work: Path) -> dict:
    return json.loads((work / CONTRACTS / "evidence/INDEX.json").read_text(encoding="utf-8"))


def _write_index(work: Path, index: dict) -> None:
    (work / CONTRACTS / "evidence/INDEX.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _approval_records(work: Path, contract: str = "architecture_governance.nyx") -> list[dict]:
    import yaml

    text = (work / CONTRACTS / contract).read_text(encoding="utf-8")
    document = yaml.safe_load(text) or {}
    records = ((document.get("governance_evidence") or {}).get("records")) or []
    return [r for r in records if isinstance(r, dict) and r.get("id") == "approval_record"]


def _is_clean(work: Path) -> bool:
    return _git(work, "status", "--porcelain").stdout.strip() == ""


# --------------------------------------------------------------------------
# INDEX.json is derived output, never an input to authority
# --------------------------------------------------------------------------


@needs_nornyx
def test_a_forged_index_cannot_mint_a_human_approval(tmp_path: Path):
    """The exact reproduced exploit: forge the index, supply no human artifact.

    Both files the attacker edits are in REGENERATED_OUTPUTS and therefore exempt
    from the dirty-tree gate — which was defensible on its own terms, and fatal
    combined with a write path that read them as authoritative.
    """
    work = _workspace(tmp_path)
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0

    index = _index(work)
    index["entries"]["architecture_approval_record"].update(
        {
            "producer": {"id": "human.cfo:architecture_reviewer", "type": "human"},
            "status": "pass",
            "expires_at": "2099-01-01T00:00:00Z",
            "authored_by": "human",
        }
    )
    _write_index(work, index)
    # No canonical human artifact anywhere.
    assert not list((work / CONTRACTS / "evidence").glob("*human_approval.json"))

    completed = _run(work, REFRESH, "--wire-approvals")
    assert completed.returncode == 0, completed.stdout + completed.stderr

    for record in _approval_records(work):
        assert record["producer"]["type"] != "human", "a forged index minted a human producer"
        assert record["status"] != "pass", "a forged index minted a passing approval"
        assert "2099" not in json.dumps(record), "a forged index set the window"


@needs_nornyx
def test_a_forged_index_cannot_alter_a_real_approval(tmp_path: Path):
    """With a genuine artifact present, the index still decides nothing."""
    work = _workspace(tmp_path)
    _approval(work, ARCHITECTURE_APPROVAL)
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0

    index = _index(work)
    index["entries"]["architecture_approval_record"].update(
        {
            "producer": {"id": "human.attacker:architecture_reviewer", "type": "human"},
            "expires_at": "2099-01-01T00:00:00Z",
            "generated_at": "1999-01-01T00:00:00Z",
            "subject_revision": "git:" + "b" * 40,
        }
    )
    _write_index(work, index)

    assert _run(work, REFRESH, "--wire-approvals").returncode == 0
    records = _approval_records(work)
    assert len(records) == 1
    record = records[0]
    assert record["producer"]["id"] == "human.test_fixture:architecture_reviewer" or (
        "attacker" not in record["producer"]["id"]
    )
    assert record["expires_at"] == "2026-08-05T00:00:00Z"
    assert record["generated_at"] == "2026-08-02T00:00:00Z"
    assert record["subject_revision"] == _head(work)


@needs_nornyx
def test_an_invalid_canonical_artifact_is_refused_however_good_the_index_looks(
    tmp_path: Path,
):
    work = _workspace(tmp_path)
    _approval(work, ARCHITECTURE_APPROVAL)
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0

    # Index stays valid-looking; the artifact it points at becomes invalid.
    _approval(work, ARCHITECTURE_APPROVAL, producer={"id": "bot", "type": "tool"})
    completed = _run(work, REFRESH, "--wire-approvals")
    assert completed.returncode != 0
    assert "not a human approval record" in (completed.stdout + completed.stderr)


@needs_nornyx
def test_deleting_the_canonical_artifact_withdraws_authority(tmp_path: Path):
    """A stale index still saying `granted` must not keep an approval alive."""
    work = _workspace(tmp_path)
    _approval(work, ARCHITECTURE_APPROVAL)
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, REFRESH, "--wire-approvals").returncode == 0
    assert any(r["producer"]["type"] == "human" for r in _approval_records(work))

    granted_index = _index(work)
    (work / CONTRACTS / "evidence" / ARCHITECTURE_APPROVAL).unlink()
    _write_index(work, granted_index)  # deliberately stale

    assert _run(work, REFRESH, "--wire-approvals").returncode == 0
    for record in _approval_records(work):
        assert record["producer"]["type"] != "human"
        assert record["status"] != "pass"


@needs_nornyx
def test_rebuilding_the_index_from_canonical_artifacts_is_deterministic(tmp_path: Path):
    """Derived means reproducible: a tampered index is repaired by rebuilding."""
    work = _workspace(tmp_path)
    _approval(work, ARCHITECTURE_APPROVAL)
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    honest = (work / CONTRACTS / "evidence/INDEX.json").read_bytes()

    index = _index(work)
    index["entries"]["architecture_approval_record"]["status"] = "tampered"
    _write_index(work, index)

    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert (work / CONTRACTS / "evidence/INDEX.json").read_bytes() == honest


# --------------------------------------------------------------------------
# A working-session report is not assurance evidence
# --------------------------------------------------------------------------


@needs_nornyx
def test_a_forged_session_report_cannot_produce_an_independent_review_pass(
    tmp_path: Path,
):
    """The exact reproduced exploit, with its original wording preserved."""
    work = _workspace(tmp_path)
    session = work / ".nornyx/in-session"
    session.mkdir(parents=True, exist_ok=True)
    (session / "reviews.json").write_text(
        json.dumps(
            {
                "builder_self_approval": False,
                "reviews": [
                    {
                        "role": role,
                        "status": "pass",
                        "summary": "FORGED - no review happened",
                    }
                    for role in (
                        "test-inspector",
                        "architecture-inspector",
                        "security-inspector",
                    )
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0

    entry = _index(work)["entries"]["architecture_independent_review"]
    assert entry["status"] != "pass", "a gitignored summary manufactured a review verdict"

    record = json.loads(
        (work / CONTRACTS / "evidence/architecture_independent_review.json").read_text(
            encoding="utf-8"
        )
    )
    assert record["session_report"]["authoritative"] is False
    assert record["attestation"] is None
    assert "decides nothing" in record["verdict_basis"]


@needs_nornyx
def test_a_clean_tree_plus_derived_files_is_not_assurance(tmp_path: Path):
    """The invariant the previous review demonstrated, stated directly.

    Everything the attacker touches here is either gitignored or a regenerated
    output, so `git status` stays clean throughout — and that must buy them
    nothing.
    """
    work = _workspace(tmp_path)
    session = work / ".nornyx/in-session"
    session.mkdir(parents=True, exist_ok=True)
    (session / "reviews.json").write_text(
        json.dumps(
            {
                "builder_self_approval": False,
                "reviews": [
                    {"role": r, "status": "pass"}
                    for r in ("test-inspector", "architecture-inspector", "security-inspector")
                ],
            }
        ),
        encoding="utf-8",
    )
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    # Commit the honest generated state, so what follows is only the attacker's.
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "generated baseline")

    # The session report is gitignored, so this tampering is genuinely invisible
    # to `git status` — the precise condition the previous review demonstrated.
    assert _is_clean(work), "tampering a gitignored report must leave the tree clean"
    assert (
        _index(work)["entries"]["architecture_independent_review"]["status"] != "pass"
    ), "a report invisible to git manufactured an assurance verdict"

    # INDEX.json is tracked, so git does see it. What made it dangerous is that
    # it is in REGENERATED_OUTPUTS and therefore exempt from the dirty-tree
    # gate — the gate lets this through by design, and must be able to afford to.
    sys.path.insert(0, str(ROOT / "scripts"))
    from refresh_governance_evidence import REGENERATED_OUTPUTS  # noqa: PLC0415

    assert ".nornyx/contracts/evidence/INDEX.json" in REGENERATED_OUTPUTS

    index = _index(work)
    index["entries"]["architecture_approval_record"].update(
        {"producer": {"id": "human.ghost:architecture_reviewer", "type": "human"},
         "status": "pass"}
    )
    _write_index(work, index)

    assert _run(work, REFRESH, "--wire-approvals").returncode == 0
    assert all(r["producer"]["type"] != "human" for r in _approval_records(work))


def test_the_session_report_path_is_outside_the_governed_input_paths():
    """Recorded deliberately: this is why it can never be trusted.

    `.nornyx/in-session/` is gitignored working state, so the dirty-tree gate
    cannot see changes to it. That is fine — provided nothing downstream treats
    it as authority. This test pins the reasoning next to the fact.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    from refresh_governance_evidence import GOVERNED_INPUT_PATHS  # noqa: PLC0415

    assert not any(p.startswith(".nornyx/in-session") for p in GOVERNED_INPUT_PATHS)
    assert ".nornyx/in-session/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
