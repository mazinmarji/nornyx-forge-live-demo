"""`integrity_state: intact` must mean every recorded claim was recomputed.

`review_binding.json` records 22 fields. `verify()` compared **two**.

An independent review edited `required_evidence` in a governance contract —
removing the conformance report and the independent review record from what a
future human approval must be accompanied by — and `--verify` printed
`status: pass`, `integrity_state: intact`, `problems: []`, exit 0.
`contract_set_digest` was sitting in the binding the entire time, holding the
value that would have caught it. A digest written and never verified is not
evidence; it is decoration that reads as evidence.

THE PROPERTY:

    integrity_state: intact  ==  every integrity-bearing claim the binding
                                 records has been recomputed from its
                                 authoritative source and matched

The direction matters and is asserted below: authoritative artifacts produce
digests, the binding records them, verification recomputes **from the artifacts
again**. Reading a claim to check a claim proves only that one file is
self-consistent, which is what the forger already arranged.

Classification is exhaustive, so a field added later cannot sit unclassified and
therefore unchecked.
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
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

BINDING = ".nornyx/contracts/evidence/review_binding.json"
REFRESH = "scripts/refresh_governance_evidence.py"


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    """A settled workspace whose evidence describes its own content."""
    from governed_workspace import copy_governed_workspace

    work = tmp_path_factory.mktemp("integrity") / "repo"
    copy_governed_workspace(work)
    for command in (
        ["init", "-q"],
        ["config", "user.email", "fixture@example.invalid"],
        ["config", "user.name", "fixture"],
    ):
        subprocess.run(["git", "-C", str(work), *command], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(work), "add", "-A"], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-qm", "fixture"], capture_output=True, check=True
    )
    _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    _run(work, REFRESH, "--sync-contracts")
    _run(work, REFRESH, "--review-binding")
    return work


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    return subprocess.run(
        [sys.executable, *args],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _verify(work: Path) -> dict:
    completed = _run(work, REFRESH, "--verify")
    start = completed.stdout.find("{")
    assert start >= 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout[start:])["verification"]


def _restore(work: Path):
    """Put the governed tree back exactly as the fixture settled it."""
    for item in (".nornyx/contracts", "docs", "src"):
        target = work / item
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(ROOT / item, target, ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", "*.egg-info"
        ))


# --------------------------------------------------------------------------
# The benign control. Without it every refusal below could be "refuses always".
# --------------------------------------------------------------------------


def test_a_settled_workspace_verifies_intact(workspace: Path):
    state = _verify(workspace)
    assert state["integrity_state"] == "intact", state["problems"]
    assert state["problems"] == []


# --------------------------------------------------------------------------
# Each integrity-bearing claim, attacked at its authoritative source
# --------------------------------------------------------------------------

TAMPERS = [
    (
        "governance contract",
        ".nornyx/contracts/architecture_governance.nyx",
        "architecture governance contract",
    ),
    ("runtime contract", ".nornyx/contracts/runtime_network.nyx", "runtime network contract"),
    ("forge control contract", ".nornyx/contracts/forge_control.nyx", "forge control contract"),
    (
        "independent review record",
        ".nornyx/contracts/evidence/architecture_independent_review.json",
        "independent review record",
    ),
]


@pytest.mark.parametrize(
    ("label", "relative", "describes"), TAMPERS, ids=[case[0] for case in TAMPERS]
)
def test_tampering_a_bound_artifact_is_refused(
    workspace: Path, label: str, relative: str, describes: str
):
    """The exact class that passed as `intact` on the invalidated candidate."""
    target = workspace / relative
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n# tampered\n")
        state = _verify(workspace)
        assert state["integrity_state"] == "compromised", (
            f"{label}: tampering an artifact the binding covers was reported intact"
        )
        assert state["problems"], f"{label}: compromised with no diagnostic"
        assert any(describes in problem for problem in state["problems"]), (
            f"{label}: refused, but no problem names {describes}: {state['problems']}"
        )
    finally:
        target.write_bytes(original)


def test_forging_the_binding_itself_is_refused(workspace: Path):
    """A derived field that disagrees with its derivation is an assertion.

    Classifying a field as "derived, therefore harmless" is a CLAIM, and a claim
    has to be proven rather than settled by putting the name in the other set.
    `production_approval: granted` written into the binding by hand must not
    survive, even though nothing downstream reads it for a decision.
    """
    target = workspace / BINDING
    original = target.read_bytes()
    try:
        binding = json.loads(original.decode("utf-8"))
        binding["production_approval"] = "granted"
        binding["approvals"]["human_review"] = "performed"
        target.write_bytes(
            json.dumps(binding, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        state = _verify(workspace)
        assert state["integrity_state"] == "compromised"
        assert any("production_approval" in p for p in state["problems"])
        assert any("authenticated approval set derives" in p for p in state["problems"])
    finally:
        target.write_bytes(original)


def test_a_binding_missing_a_claim_is_refused(workspace: Path):
    """Deleting a claim must not be a way to stop it being checked."""
    target = workspace / BINDING
    original = target.read_bytes()
    try:
        binding = json.loads(original.decode("utf-8"))
        del binding["contract_set_digest"]
        target.write_bytes(
            json.dumps(binding, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        state = _verify(workspace)
        assert state["integrity_state"] == "compromised"
        assert any("records no contract_set_digest" in p for p in state["problems"])
    finally:
        target.write_bytes(original)


# --------------------------------------------------------------------------
# The classification itself
# --------------------------------------------------------------------------


def test_every_binding_field_is_classified_exactly_once():
    """A field nobody classified is a field nobody verifies.

    This is the anti-drift control: adding a claim to the binding without
    deciding what kind it is fails here rather than silently joining the set of
    things `--verify` ignores.
    """
    import refresh_governance_evidence as evidence  # noqa: PLC0415

    binding = json.loads((ROOT / BINDING).read_text(encoding="utf-8"))

    present: set[str] = set()

    def walk(node: dict, prefix: str = "") -> None:
        for key, value in node.items():
            path = f"{prefix}{key}"
            if isinstance(value, dict) and path not in {"approvals", "independent_review", "digests"}:
                walk(value, path + ".")
            elif isinstance(value, dict):
                for inner in value:
                    present.add(f"{path}.{inner}")
            else:
                present.add(path)

    walk(binding)

    classified = (
        set(evidence.INTEGRITY_BEARING_FIELDS)
        | evidence.DERIVED_REPORTING_FIELDS
        | evidence.PROVENANCE_FIELDS
    )
    unclassified = present - classified
    assert unclassified == set(), (
        "review_binding carries fields no classification covers, so nothing "
        f"verifies them: {sorted(unclassified)}"
    )

    overlap = (
        (set(evidence.INTEGRITY_BEARING_FIELDS) & evidence.DERIVED_REPORTING_FIELDS)
        | (set(evidence.INTEGRITY_BEARING_FIELDS) & evidence.PROVENANCE_FIELDS)
        | (evidence.DERIVED_REPORTING_FIELDS & evidence.PROVENANCE_FIELDS)
    )
    assert overlap == set(), f"a field is classified twice: {sorted(overlap)}"


def test_recomputation_reads_artifacts_not_the_binding():
    """No self-reference: the check must not consult what it is checking.

    Recomputing a claim by reading the claim proves the file agrees with itself,
    which is exactly what a forger arranges. Structural, because a future edit
    could reintroduce it without failing any behavioural test here.
    """
    import ast

    source = (ROOT / "scripts/refresh_governance_evidence.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "recompute_binding_claims"
    )
    # The property is that it does not READ the binding. Naming
    # review_binding.json to EXCLUDE it from the manifest digest is the opposite
    # -- that is what stops a binding being folded into a digest it will go on to
    # contain. An earlier version of this test flagged the name anywhere in the
    # function and failed on that exclusion, which would have proved only that
    # the test could not tell reading from excluding.
    readers = {"read_text", "read_bytes", "load", "loads", "open"}
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name not in readers:
            continue
        mentions = any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and "review_binding" in child.value
            for child in ast.walk(node)
        )
        assert not mentions, (
            "recompute_binding_claims reads review_binding.json, so it would "
            "verify the binding against itself"
        )

    assert "binding" not in {
        argument.arg for argument in function.args.args
    }, "recompute_binding_claims takes the binding as input"
