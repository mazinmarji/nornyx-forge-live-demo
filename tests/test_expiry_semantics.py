"""What expires, what does not, and which of those Nornyx can actually express.

An earlier release claimed the baseline "no longer expires" while carrying
`expires_at: "2099-01-01T00:00:00Z"`. These drive the real CLI to pin down what
1.11.0 supports, so the claim and the implementation cannot drift apart again.

See docs/governance/EVIDENCE_FRESHNESS.md.
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
CONTRACTS = Path(".nornyx/contracts")
GOVERNANCE = ("runtime_network.nyx", "architecture_governance.nyx")

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)

# The three diagnostics that mean "no human has approved this yet". A healthy
# pre-approval baseline produces these and nothing else, at any instant.
#: What a contract may legitimately be blocked by before anyone with standing
#: has attested to it. Two prerequisites are absent, not one: no accountable
#: human approval, and no authenticated independent inspection.
#:
#: The last three appeared when the contract stopped recording
#: `independent_review_record` as `status: pass` regardless of whether anything
#: had signed it. They are not a regression -- they are the second missing
#: prerequisite, which that stamp had been concealing. Neither prerequisite can
#: be satisfied from inside this repository, which is what makes every code here
#: an acceptable reason to be blocked.
APPROVAL_GAP_CODES = {
    "AN_APPROVAL_RECORD_MISSING",
    "APPROVAL_EVIDENCE_MISSING",
    "EVIDENCE_REQUIRED_MISSING",
    "CHANGE_EVIDENCE_MISSING",
    "EVIDENCE_DEPENDENCY_UNSATISFIED",
    "SOD_EVIDENCE_PRODUCER_UNKNOWN",
}

FAR_FUTURE = ["2100-01-01T00:00:00Z", "2200-01-01T00:00:00Z"]


def _workspace(tmp_path: Path) -> Path:
    """A throwaway clone, so regeneration never touches the real tree."""
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx", "tests", ".github"):
        shutil.copytree(
            ROOT / item,
            work / item,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    # The repository scope declares these root files; a fixture missing them
    # now gets SUBJECT_SCOPE_INCOMPLETE rather than a quietly smaller subject.
    # Derived from the scope, not listed here. Seven fixtures each kept
    # their own copy of this list and all seven broke the moment the scope
    # gained a required file -- SUBJECT_SCOPE_INCOMPLETE, which is the scope
    # correctly refusing to call a smaller subject verified.
    sys.path.insert(0, str(ROOT / 'tests'))
    from governed_workspace import copy_governed_workspace  # noqa: PLC0415

    copy_governed_workspace(work)
    subprocess.run(["git", "init", "-q"], cwd=work, check=True, capture_output=True)
    for key, value in (("user.email", "fixture@example.invalid"), ("user.name", "fixture")):
        subprocess.run(["git", "config", key, value], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=work, check=True, capture_output=True)
    return work


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True, env=env
    )


def _codes(work: Path, contract: str, as_of: str) -> set[str]:
    completed = subprocess.run(
        ["nornyx", "check", str(CONTRACTS / contract), "--as-of", as_of],
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    return set(re.findall(r'"code":\s*"([A-Z_]+)"', completed.stdout + completed.stderr))


@needs_nornyx
def test_the_authority_declaration_genuinely_does_not_expire():
    """`expires_at: null` on a declaration is a real non-expiring representation.

    Not a distant date standing in for one. A declaration names who may approve
    and over what scope; it is not itself an approval and has no reason to decay.
    """
    import yaml

    for contract in GOVERNANCE:
        text = (ROOT / CONTRACTS / contract).read_text(encoding="utf-8")
        declarations = yaml.safe_load(text)["approvals"]
        assert declarations, f"{contract} declares no authority"
        for declaration in declarations:
            assert declaration["expires_at"] is None, (
                f"{contract} authority {declaration.get('id')!r} expires at "
                f"{declaration['expires_at']!r}, not the non-expiring "
                "representation Nornyx accepts"
            )


@needs_nornyx
@pytest.mark.parametrize("as_of", FAR_FUTURE)
def test_no_approval_expiry_diagnostic_at_far_future_instants(as_of: str, tmp_path: Path):
    """The declaration must still be live long after any sentinel date."""
    work = _workspace(tmp_path)
    for contract in GOVERNANCE:
        assert "APPROVAL_EXPIRED" not in _codes(work, contract, as_of)


@needs_nornyx
def test_no_sentinel_date_survives_anywhere_in_the_contracts():
    """The 2099 placeholder is gone, in every block that used to carry it."""
    for contract in (*GOVERNANCE, "forge_control.nyx"):
        text = (ROOT / CONTRACTS / contract).read_text(encoding="utf-8")
        assert "2099-01-01" not in text, f"{contract} still carries the sentinel"


@needs_nornyx
@pytest.mark.parametrize("as_of", FAR_FUTURE)
def test_regeneration_restores_a_healthy_baseline_at_any_instant(as_of: str, tmp_path: Path):
    """The documented workflow, driven end to end at 2100 and 2200.

    Nornyx has no non-expiring representation for machine evidence, so this is
    the honest guarantee the project makes instead: one command produces a
    baseline whose only remaining diagnostics are the ones that say a human has
    not approved it.
    """
    work = _workspace(tmp_path)

    completed = _run(
        work, "scripts/check_pre_approval_baseline.py", "--regenerate", "--as-of", as_of
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    report = json.loads(completed.stdout)
    assert report["status"] == "pass"
    assert report["human_approval_present"] is False
    for entry in report["contracts"]:
        assert entry["approval_blocked"] is True, entry
        assert entry["unexpected_diagnostics"] == [], entry

    # And directly against the CLI, so the assertion does not rest on our own
    # checker agreeing with itself.
    for contract in GOVERNANCE:
        assert _codes(work, contract, as_of) <= APPROVAL_GAP_CODES


#: A calendar date, with or without a time. The `T` used to be REQUIRED and
#: the match ANCHORED at position 0, and a review measured what that cost:
#: four ways a far-future date evaded the sweep -- inside prose
#: ("valid until 2099-..."), behind a leading space, as a plain
#: "2099-01-01" with no `T`, and as a dictionary KEY, which was never
#: visited at all.
#:
#: The predecessor was a substring scan that caught all four. Replacing it
#: with a shape walk removed a real false positive and introduced these
#: four false negatives WITHOUT SAYING SO, which is the trade this
#: repository refuses: a narrowing that is not stated is indistinguishable
#: from a repair.
_ISO = re.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _timestamps(payload) -> list:
    """Every ISO-8601-looking value in a nested structure, by shape.

    By shape rather than by key name: a field called `valid_until` carries a
    date just as much as one called `expires_at`, and enumerating key names
    would be the same enumeration this repository keeps having to unwind.
    """
    found = []
    if isinstance(payload, dict):
        # KEYS TOO. Only values were visited, so a date used as a key -- which
        # is how a per-day map is written -- was invisible to the whole sweep.
        for key, value in payload.items():
            found.extend(_timestamps(key))
            found.extend(_timestamps(value))
    elif isinstance(payload, list):
        for value in payload:
            found.extend(_timestamps(value))
    elif isinstance(payload, str):
        # `search`, not `match`: a date reached by reading a sentence is still
        # a date, and anchoring at position 0 meant a leading space hid one.
        for hit in _ISO.finditer(payload):
            found.append(payload[hit.start():])
    return found


@needs_nornyx
def test_machine_evidence_carries_a_real_finite_window(tmp_path: Path):
    """No magic constant. The window is a genuine interval from the run."""
    work = _workspace(tmp_path)
    assert _run(work, "scripts/refresh_governance_evidence.py", "--as-of",
                "2026-08-03T00:00:00Z").returncode == 0

    index = json.loads((work / CONTRACTS / "evidence" / "INDEX.json").read_text(encoding="utf-8"))
    assert index["generated_at"] == "2026-08-03T00:00:00Z"
    assert index["expires_at"] == "2027-08-03T00:00:00Z"
    # THE FIELDS, NOT A SUBSTRING OF THE BLOB. This read
    # `"2099" not in json.dumps(index)`, which searches every character of the
    # serialised index -- INCLUDING the content hashes. A SHA-256 digest
    # containing the digit run `2099` fails it, and one did: the clean-checkout
    # census reported
    #
    #     '2099' is contained here: ad6552d2412099818"}, ...
    #
    # a hash, not a date. Whether it fires depends on the digests, so it
    # differs between trees and between commits -- a flake that arrives with
    # unrelated content changes and points at the wrong thing when it does.
    #
    # The property is that no DATE FIELD carries the retired far-future
    # constant. That is what is asserted now, over the timestamp fields
    # themselves, so a digest cannot trip it and a real 2099 date cannot hide
    # in a field this does not read.
    stamps = _timestamps(index)
    assert stamps, "no timestamp fields found; this would assert nothing"
    magic = sorted(value for value in stamps if value.startswith("2099"))
    assert magic == [], (
        "machine evidence carries the retired far-future constant in a date "
        f"field: {magic}"
    )


@needs_nornyx
def test_the_stale_baseline_is_detected_rather_than_hidden(tmp_path: Path):
    """Honesty runs both ways: an un-regenerated far-future check must fail.

    If this passed, the finite window would be decorative and the regeneration
    workflow would prove nothing.
    """
    work = _workspace(tmp_path)
    assert _run(work, "scripts/refresh_governance_evidence.py", "--as-of",
                "2026-08-03T00:00:00Z").returncode == 0
    assert _run(work, "scripts/refresh_governance_evidence.py", "--sync-contracts").returncode == 0

    completed = _run(work, "scripts/check_pre_approval_baseline.py", "--as-of", FAR_FUTURE[0])
    assert completed.returncode != 0, "a stale baseline reported healthy"
    assert "EVIDENCE_STALE" in completed.stdout
