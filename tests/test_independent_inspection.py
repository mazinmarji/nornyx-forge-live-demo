"""An independent inspection is a claim about a subject, and both must hold.

`status: "pass"` in an artifact establishes nothing. What establishes an
independent inspection is: every required inspector reported, each one passed,
the builder did not sign off on their own work, and all of that was about the
subject that exists now.

The subject is not the source alone. Source can be untouched while a `.nyx`
contract has moved, so an inspection bound only to authored inputs would claim
to cover a control pack it never saw:

    inspection_subject_digest =
        H(governed_input_digest + contract_set_digest + pre_inspection_evidence)

Once that is frozen, anything moving it makes the inspection stale — and
recomputing the current digest must never update the attestation to match.
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
ATTESTATION = "architecture_inspection_attestation.json"

REQUIRED = ("test-inspector", "architecture-inspector", "security-inspector")


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(work), *args], capture_output=True, text=True, check=True
    )


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx", "tests", ".github"):
        shutil.copytree(
            ROOT / item,
            work / item,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    for item in ("pyproject.toml", ".gitignore", "Dockerfile", "docker-compose.yml", "BRD.md"):
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


def _settle(work: Path) -> None:
    """Generate machine evidence and let the contracts settle."""
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, REFRESH, "--sync-contracts").returncode == 0


def _current_subject(work: Path) -> str:
    """Ask the tool itself what an inspection here would be reviewing."""
    completed = _run(
        work,
        "-c",
        "import json,sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(r.current_inspection_subject())",
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _attest(
    work: Path,
    *,
    subject: str | None = None,
    inspectors: list[dict] | None = None,
    builder_self_approval: bool = False,
    producer: dict | None = None,
) -> None:
    """Write an inspection attestation, honest by default."""
    payload = {
        "schema": "nornyx.forge.inspection_attestation.v1",
        "producer": producer or {"id": "inspector.read_only_suite", "type": "tool"},
        "subject_revision": "git:" + _git(work, "rev-parse", "HEAD").stdout.strip(),
        "inspection_subject_digest": subject or _current_subject(work),
        "inspectors": inspectors
        if inspectors is not None
        else [{"role": role, "result": "pass", "findings": []} for role in REQUIRED],
        "result": "pass",
        "builder_self_approval": builder_self_approval,
        "generated_at": "2026-08-02T01:00:00Z",
    }
    (work / CONTRACTS / "evidence" / ATTESTATION).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # The attestation joins the final evidence set, so the review binding is
    # regenerated over it. That is the chain order: contracts settle, the
    # subject freezes, inspectors report, and only then does the package that
    # says what was reviewed get written.
    assert _run(work, REFRESH, "--review-binding").returncode == 0


def _assurance(work: Path) -> dict:
    """Recompute the assurance position, as --verify does."""
    completed = _run(
        work,
        "-c",
        "import json,sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(json.dumps(r.derive_assurance_state()))",
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _inspected(work: Path) -> bool:
    return _assurance(work)["assurance_state"] == "independently_inspected"


# --------------------------------------------------------------------------


def test_a_complete_independent_inspection_over_the_current_subject_passes(
    tmp_path: Path,
):
    """The control must permit the case it exists to recognise."""
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work)

    state = _assurance(work)
    assert state["assurance_state"] == "independently_inspected", state["problems"]
    assert state["inspection_subject_match"] is True
    assert state["required_inspectors_complete"] is True
    assert state["independent"] is True


@pytest.mark.parametrize(
    ("label", "inspectors"),
    [
        (
            "a required inspector is missing",
            [{"role": r, "result": "pass", "findings": []} for r in REQUIRED[:2]],
        ),
        (
            "a required inspector reports failure",
            [
                {"role": r, "result": "fail" if r == "security-inspector" else "pass",
                 "findings": []}
                for r in REQUIRED
            ],
        ),
        (
            "a fake inspector stands in for a required role",
            [
                {"role": "test-inspector", "result": "pass", "findings": []},
                {"role": "architecture-inspector", "result": "pass", "findings": []},
                {"role": "vibes-inspector", "result": "pass", "findings": []},
            ],
        ),
        (
            "a required role reports twice",
            [
                *[{"role": r, "result": "pass", "findings": []} for r in REQUIRED],
                {"role": "architecture-inspector", "result": "fail", "findings": []},
            ],
        ),
    ],
)
def test_an_incomplete_inspection_is_not_an_independent_one(
    label: str, inspectors: list[dict], tmp_path: Path
):
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work, inspectors=inspectors)

    state = _assurance(work)
    assert state["assurance_state"] == "not_independently_inspected", label
    assert state["required_inspectors_complete"] is False, label


def test_a_duplicate_role_cannot_be_resolved_by_ordering(tmp_path: Path):
    """`fail` then `pass` previously reported pass — order deciding assurance."""
    work = _workspace(tmp_path)
    _settle(work)
    _attest(
        work,
        inspectors=[
            {"role": "test-inspector", "result": "pass", "findings": []},
            {"role": "security-inspector", "result": "pass", "findings": []},
            {"role": "architecture-inspector", "result": "fail", "findings": []},
            {"role": "architecture-inspector", "result": "pass", "findings": []},
        ],
    )
    state = _assurance(work)
    assert state["assurance_state"] == "not_independently_inspected"
    assert any("more than once" in problem for problem in state["problems"])


def test_the_builder_cannot_satisfy_the_independent_role(tmp_path: Path):
    """Self-approval is the thing independence means the absence of."""
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work, builder_self_approval=True)

    state = _assurance(work)
    assert state["independent"] is False
    assert state["assurance_state"] == "not_independently_inspected"


def test_a_human_producer_is_refused_for_a_machine_inspection(tmp_path: Path):
    """A human decision belongs in an approval, which is governed differently."""
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work, producer={"id": "human.someone", "type": "human"})

    completed = _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    assert completed.returncode != 0
    assert "human" in (completed.stdout + completed.stderr)


# --------------------------------------------------------------------------
# The subject freezes; anything moving it makes the inspection stale
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        (
            "authored input changes",
            lambda w: (w / "src/nornyx_forge/util.py").write_bytes(
                (w / "src/nornyx_forge/util.py").read_bytes() + b"\n# x\n"
            ),
        ),
        (
            "a contract changes, source untouched",
            lambda w: (w / CONTRACTS / "forge_control.nyx").write_text(
                (w / CONTRACTS / "forge_control.nyx").read_text(encoding="utf-8") + "\n# x\n",
                encoding="utf-8",
            ),
        ),
        (
            "findings are altered after attestation",
            lambda w: (w / CONTRACTS / "evidence/architecture_conformance_report.json").write_text(
                (w / CONTRACTS / "evidence/architecture_conformance_report.json").read_text(
                    encoding="utf-8"
                ).replace("\n}", '\n, "tampered": true}', 1),
                encoding="utf-8",
            ),
        ),
    ],
)
def test_moving_the_subject_makes_the_inspection_stale(
    label: str, mutate, tmp_path: Path
):
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work)
    assert _inspected(work), f"{label}: the fixture must start inspected"

    mutate(work)
    # Staged, because "the content changed" means the content git holds changed.
    # The digest is computed over the index so it is identical on every
    # platform; an unstaged edit is drift from governed content, which
    # verification reports separately and by name.
    _git(work, "add", "-A")

    state = _assurance(work)
    assert state["assurance_state"] == "not_independently_inspected", label
    assert state["inspection_subject_match"] is False, label


def test_sync_contracts_after_inspection_makes_it_stale(tmp_path: Path):
    """The hard rule: recomputing the current digest never updates the attestation.

    sync_contracts legitimately rewrites contracts, which moves the subject. It
    must make the old inspection visibly stale rather than quietly current — the
    exact distinction that separates recording current state from rebinding an
    old conclusion.
    """
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work)
    attested_before = json.loads(
        (work / CONTRACTS / "evidence" / ATTESTATION).read_text(encoding="utf-8")
    )
    assert _inspected(work)

    # Change an authored input, then let the tool settle contracts again.
    target = work / "src/nornyx_forge/util.py"
    target.write_bytes(target.read_bytes() + b"\n# moved\n")
    _git(work, "add", "-A")
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, REFRESH, "--sync-contracts").returncode == 0

    state = _assurance(work)
    assert state["assurance_state"] == "not_independently_inspected"
    assert state["inspection_subject_match"] is False

    # And the attestation itself is untouched: no rebinding happened.
    attested_after = json.loads(
        (work / CONTRACTS / "evidence" / ATTESTATION).read_text(encoding="utf-8")
    )
    assert attested_after == attested_before, "the tool rebound the attestation"


def test_regenerating_the_digest_alone_leaves_the_inspection_stale(tmp_path: Path):
    """Recomputing what the content *is* is not re-establishing what was concluded."""
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work)

    target = work / "pyproject.toml"
    target.write_bytes(target.read_bytes() + b"\n# drift\n")
    _git(work, "add", "-A")
    assert _run(work, REFRESH, "--sync-contracts").returncode == 0

    state = _assurance(work)
    assert state["assurance_state"] == "not_independently_inspected"


def test_a_fresh_inspection_over_the_new_subject_restores_assurance(tmp_path: Path):
    """Staleness is recoverable by inspecting again, never by editing a digest."""
    work = _workspace(tmp_path)
    _settle(work)
    _attest(work)

    target = work / "src/nornyx_forge/util.py"
    target.write_bytes(target.read_bytes() + b"\n# new work\n")
    _git(work, "add", "-A")
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, REFRESH, "--sync-contracts").returncode == 0
    assert not _inspected(work)

    _attest(work)  # inspectors run again over the subject as it now stands
    assert _inspected(work)
