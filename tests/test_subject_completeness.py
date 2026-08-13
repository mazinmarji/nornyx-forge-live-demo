"""Every decision-changing mutation must be caught by something that gates assurance.

The inspection subject digests what the contracts SAY -- `contract_semantics_digest`
-- rather than their exact bytes. That was necessary: binding it to bytes made
authenticated inspection unreachable, because adopting an approval rewrites the
declared revision and every recorded evidence digest, so an inspection was
invalidated by the act it exists to enable.

Trading bytes for meaning is only safe if nothing decision-changing falls
through the gap. THE PROPERTY:

    a governed mutation that changes a Nornyx governance verdict must either
      (1) move the inspection subject, or
      (2) be rejected by an integrity control that gates assurance

and (2) has to be demonstrated, not assumed. A control that reports a problem
while `assurance_state` still says `independently_inspected` is not a gate.

Measured on the real tree, which matters: an earlier version of this matrix ran
against a hand-assembled workspace where Nornyx could not resolve its pack, so
every contract failed at PACK_PATH_OUTSIDE_ROOT, no mutation could change a
verdict, and the matrix reported "invariant holds" while measuring nothing.
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
ARCH = ".nornyx/contracts/architecture_governance.nyx"
RUNTIME = ".nornyx/contracts/runtime_network.nyx"
REFRESH = "scripts/refresh_governance_evidence.py"

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)


def _subject() -> str:
    completed = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0,'scripts');"
         "import refresh_governance_evidence as r;"
         "print(r.current_inspection_subject())"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout.strip()


def _verdict(relative: str) -> str:
    """Nornyx's decision as its set of diagnostic codes.

    The codes, not the exit status: a contract that is blocked before and after
    a mutation can still be blocked for different reasons, and that is a changed
    decision.
    """
    completed = subprocess.run(
        [shutil.which("nornyx") or "nornyx", "check", relative,
         "--as-of", "2026-08-03T00:00:00Z"],
        cwd=ROOT, capture_output=True, text=True,
    )
    codes = sorted(set(re.findall(r'"code":\s*"([A-Z_]+)"', completed.stdout)))
    return f"rc={completed.returncode} {','.join(codes)}"


def _integrity() -> str:
    completed = subprocess.run(
        [sys.executable, REFRESH, "--verify"], cwd=ROOT, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    start = completed.stdout.find("{")
    assert start >= 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout[start:])["verification"]["integrity_state"]


#: One representative per authoritative field class. `None` means "append",
#: used for the comment-only case.
MUTATIONS = [
    ("evidence record status", ARCH, "status: observed", "status: pass"),
    ("required evidence list", ARCH,
     "- independent_review_record", "- runtime_evidence_manifest"),
    # The bare role name first occurs in a COMMENT explaining why eligibility
    # was narrowed, so this case had been mutating prose and passing
    # vacuously -- found by _refuse_comment_target the moment it existed,
    # having survived every run before that. Pinned to the semantic field.
    ("separation of duties role", ARCH,
     "required_roles: [architecture_reviewer]", "required_roles: [operations_owner]"),
    # Was `ui_direct_persistence_access`. That token was retired -- it denied
    # an edge the same contract declares -- and the only surviving occurrence
    # is a comment recording why. A probe aimed at a comment changes no
    # governance verdict, so it passes vacuously: the assertion below is
    # satisfied by `not verdict_changed` alone. Retargeted to a token that is
    # still a live policy term, and _refuse_comment_target keeps it that way.
    ("architecture constraint", ARCH,
     "api_direct_command_execution", "api_direct_command_execution_disabled"),
    ("capability declaration", RUNTIME,
     "execute_high_risk_effect", "execute_high_risk_effect_renamed"),
    ("declared name", RUNTIME,
     "GovernedCustomerOperationsRuntime", "GovernedCustomerOperationsRuntimeX"),
    ("comment only", ARCH, None, "\n# completeness probe\n"),
]


@pytest.fixture(scope="module")
def baseline():
    return (
        _subject(),
        {ARCH: _verdict(ARCH), RUNTIME: _verdict(RUNTIME)},
        {name: (ROOT / name).read_bytes() for name in (ARCH, RUNTIME)},
    )


def _refuse_comment_target(label: str, text: str, find: str) -> None:
    """A probe whose target has drifted into a comment proves nothing.

    `str.replace(find, replace, 1)` hits the FIRST occurrence. When a term is
    retired from a policy list but left in a comment explaining the removal,
    that first occurrence silently becomes the comment -- the mutation then
    changes no governance verdict, and the assertion in the caller is satisfied
    by `not verdict_changed` without measuring anything.

    That happened here, so the drift is now an error rather than a green tick.
    """
    offset = text.index(find)
    line = text.rfind(chr(10), 0, offset) + 1
    prefix = text[line:offset]
    assert not prefix.lstrip().startswith("#"), (
        f"{label}: the first occurrence of {find!r} is inside a comment, so "
        "this case mutates prose and cannot change a governance decision. "
        "Point it at a live semantic term."
    )


@needs_nornyx
@pytest.mark.parametrize(
    ("label", "relative", "find", "replace"),
    MUTATIONS,
    ids=[case[0] for case in MUTATIONS],
)
def test_a_decision_changing_mutation_is_always_caught(
    baseline, label: str, relative: str, find: str | None, replace: str
):
    """Either the subject moves, or integrity refuses. Never neither.

    Mutates the real tree and restores it from the original bytes, because a
    copied tree could not reproduce Nornyx's own evaluation.
    """
    base_subject, base_verdicts, _bytes = baseline
    target = ROOT / relative
    original = target.read_bytes()
    text = original.decode("utf-8")
    mutated = text + replace if find is None else text.replace(find, replace, 1)
    assert mutated != text, f"{label}: the mutation changed nothing, so it tests nothing"
    if find is not None:
        _refuse_comment_target(label, text, find)

    try:
        target.write_text(mutated, encoding="utf-8", newline="")
        verdict_changed = _verdict(relative) != base_verdicts[relative]
        subject_moved = _subject() != base_subject
        integrity = _integrity()
    finally:
        target.write_bytes(original)

    assert not verdict_changed or subject_moved or integrity == "compromised", (
        f"{label}: the Nornyx verdict changed, the inspection subject did not "
        "move, and integrity reported no problem. A mutation that changes a "
        "governance decision would survive an attested inspection."
    )
    if verdict_changed and not subject_moved:
        # Allowed only by the second branch, and only because the branch is
        # proven to gate assurance -- see the test below, which is what makes
        # this an acceptable outcome rather than a hole.
        assert integrity == "compromised", label


@needs_nornyx
def test_the_tree_is_restored_after_the_matrix(baseline):
    """The matrix mutates the real repository, so it must leave no trace.

    Compared against the bytes captured when this module started, not against
    `git status`. Git cleanliness is a claim about the whole working tree and
    would fail on an unrelated uncommitted change -- reporting that the matrix
    leaked when it had not, which is a false accusation in either direction.
    """
    _base_subject, _base_verdicts, original = baseline
    for name, blob in original.items():
        assert (ROOT / name).read_bytes() == blob, (
            f"the completeness matrix left {name} modified"
        )
    assert _subject() == _base_subject, "the subject did not return to its baseline"


@pytest.mark.parametrize(
    ("label", "find", "replace"),
    [
        ("evidence record status", b"status: observed", b"status: pass"),
        ("recorded evidence digest", b"content_hash: sha256:", b"content_hash: sha256:dead"),
    ],
)
def test_the_integrity_fallback_actually_gates_assurance(
    tmp_path: Path, label: str, find: bytes, replace: bytes
):
    """The second branch is only acceptable if it withdraws assurance.

    `status` and `content_hash` live in the block the semantic projection
    strips, so mutating them changes a Nornyx decision without moving the
    inspection subject. That is tolerable ONLY because integrity verification
    refuses and `assurance_state` falls back to `not_independently_inspected`.

    A control that reports a problem while assurance still reads
    `independently_inspected` would not be a gate, and the matrix above would be
    resting on nothing. So this builds a workspace that genuinely REACHES
    `independently_inspected` and proves the state is lost. Measuring it on the
    real repository would prove nothing: that tree has no reviewer trust
    material, so it never holds the state this test is about.
    """
    sys.path.insert(0, str(ROOT / "tests"))
    from inspection import ATTESTATION_RELATIVE, authenticate_inspection  # noqa: PLC0415

    work = _attested_workspace(tmp_path)
    reviewers = authenticate_inspection(work, tmp_path / "store")
    assert (work / ATTESTATION_RELATIVE).is_dir()
    # Signing is not recording. The review record only carries the attestations
    # after a regeneration that sees them, and the subject does not move doing
    # it -- which is the idempotence this whole design rests on.
    assert _workspace_run(
        work, reviewers, REFRESH, "--as-of", "2026-08-02T00:00:00Z"
    ).returncode == 0
    assert _workspace_run(work, reviewers, REFRESH, "--review-binding").returncode == 0
    assert _workspace_verify(work, reviewers)["assurance_state"] == "independently_inspected", (
        "the fixture never reached the state this test is about"
    )

    contract = work / ARCH
    original = contract.read_bytes()
    try:
        contract.write_bytes(original.replace(find, replace, 1))
        state = _workspace_verify(work, reviewers)
    finally:
        contract.write_bytes(original)

    assert state["integrity_state"] == "compromised", label
    assert state["assurance_state"] == "not_independently_inspected", (
        f"{label}: integrity reported a problem but assurance survived it, so "
        "the fallback the completeness matrix relies on is not a gate"
    )


def _attested_workspace(tmp_path: Path) -> Path:
    """A settled repository whose subject is stable and ready to be attested."""
    sys.path.insert(0, str(ROOT / "tests"))

    work = tmp_path / "repo"
    work.mkdir(parents=True)
    archive = tmp_path / "tree.tar"
    subprocess.run(
        ["git", "-C", str(ROOT), "archive", "-o", str(archive), "HEAD"], check=True
    )
    shutil.unpack_archive(str(archive), str(work), format="tar")
    archive.unlink()
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

    for step in (["--as-of", "2026-08-02T00:00:00Z"], ["--sync-contracts"], ["--review-binding"]):
        assert _workspace_run(work, None, REFRESH, *step).returncode == 0
    subprocess.run(["git", "-C", str(work), "add", "-A"], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-qm", "settled"], capture_output=True, check=True
    )
    # A second pass so every artifact names the revision that holds it. From
    # here the subject is stable, which is what makes an attestation bindable.
    assert _workspace_run(work, None, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    return work


def _workspace_run(work: Path, reviewers, *args: str):
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    env["FORGE_REVIEWER_TRUST_STORE"] = str(
        reviewers.store if reviewers is not None else work / "no-such-store.json"
    )
    env["FORGE_BUILDER_IDENTITY"] = "builder.nornyx_forge"
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )


def _workspace_verify(work: Path, reviewers) -> dict:
    completed = _workspace_run(work, reviewers, REFRESH, "--verify")
    start = completed.stdout.find("{")
    assert start >= 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout[start:])["verification"]
