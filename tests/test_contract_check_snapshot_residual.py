"""RESIDUAL DOCUMENTATION for Codex P1 4356060742, which is OPEN (A-054).

THIS MODULE IS NOT A PROOF OF ISOLATION, and nothing in it shows the snapshot
race prevented. It runs the attack class the P1 reports, for real, and records
that it still succeeds. Eight of its tests are STRICT EXPECTED FAILURES
(`xfail(strict=True, raises=ResidualObserved)`), each declared by identity in
`EXPECTED_XFAILS` in `scripts/check_test_coverage.py`:

- each one fails ONLY by raising `ResidualObserved`, which it raises only
  after it has OBSERVED the vulnerability -- the attack ran, and the gate
  passed substituted bytes or let a planted file change its verdict unseen;
- any other failure (the attack did not run, a fixture broke) is an ordinary
  failure, not the expected one;
- if the vulnerability stops being observable, the test returns normally, the
  strict xfail XPASSES, and the run fails. A residual that disappears must be
  looked at and its entry removed in a diff, never left to pass quietly.

THE ATTACK CLASS. Forge writes the bound bytes of the generated contract to a
private snapshot, starts the Nornyx CLI on it BY PATH, and afterwards reads
the snapshot back through one descriptor and compares identity and digest. A
process running as the SAME USER can act between Forge's write and the
child's read, and undo it before Forge's read-back:

  A. rename the snapshot aside, put bytes Nornyx passes in its place, and
     rename the original back afterwards (the original inode returns);
  B. rewrite the snapshot in place with bytes Nornyx passes, and write the
     original bytes back afterwards (the inode never changes);
  C. plant a file beside the snapshot that Nornyx reads from the contract's
     directory -- `nornyx.profiles.lock`, or a `.nornyx/profiles` pack for the
     profile the generated contract selects -- and remove it afterwards.

Each attacker step is a REAL separate process of this user, started at the
instant the attack needs; that interleaving is injected so the race is
deterministic. Every variant runs twice: under the inherited temporary
directory, and under A-054's configured scratch root owned by that same user.
A Forge-owned root can protect against OTHER principals, under the access
conditions A-054 states; it does not protect against an attacker under the
same principal, and these tests are where that is shown rather than said.

The P1 is closable only after an independent measurement establishes
principal separation AND attack-class probes show the substitution path
prevented or refused, before any real provider is admitted. Two tests here
are ordinary: a planted pack for a module the contract does not select does
not change the verdict.
That is a measurement of what Nornyx reads, not a defence.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from nornyx_forge import gates as gate_module
from nornyx_forge.contract_generator import generate_brd_contract
from nornyx_forge.requirements import parse_brd

BRD = (
    "# Business Requirements\n\n"
    "## BRD-001 Purpose\n\nKeep a list of support cases.\n\n"
    "## BRD-002 Functional requirements\n\n"
    "### BRD-F-001 Open a case\n\nA support agent opens a case with a title.\n"
)
#: Valid YAML that Nornyx refuses: the project has no name.
REFUSED = "nornyx: '0.2'\nproject: {}\n"


class ResidualObserved(Exception):  # noqa: N818 - it names an observation, not an error
    """Raised only once a test has OBSERVED the open vulnerability."""


residual = pytest.mark.xfail(
    strict=True, raises=ResidualObserved,
    reason="Codex P1 4356060742 is OPEN: a same-user process can substitute the snapshot "
           "or plant beside it; closable only after measured principal separation and refusing probes")

#: The attacker, run as a separate process of this same user. The `-in` steps
#: record what the child is about to read, outside the scratch directory.
ATTACKER = r"""
import hashlib, json, os, sys, stat
step, scratch, payload, witness = sys.argv[1:5]
snapshot = os.path.join(scratch, "brd_contract.nyx")
aside = os.path.join(scratch, ".aside")
def seen():
    with open(witness, "w", encoding="utf-8") as stream:
        data = open(snapshot, "rb").read()
        json.dump({"digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                   "listing": sorted(os.listdir(scratch))}, stream)
if step == "rename-in":
    os.rename(snapshot, aside)
    with open(snapshot, "wb") as stream:
        stream.write(open(payload, "rb").read())
    seen()
elif step == "rename-out":
    os.chmod(snapshot, stat.S_IWRITE | stat.S_IREAD)
    os.remove(snapshot)
    os.rename(aside, snapshot)
elif step == "rewrite-in":
    os.chmod(snapshot, stat.S_IWRITE | stat.S_IREAD)
    with open(aside, "wb") as stream:
        stream.write(open(snapshot, "rb").read())
    with open(snapshot, "r+b") as stream:
        stream.truncate(0)
        stream.write(open(payload, "rb").read())
    seen()
elif step == "rewrite-out":
    with open(snapshot, "r+b") as stream:
        stream.truncate(0)
        stream.write(open(aside, "rb").read())
    os.remove(aside)
    os.chmod(snapshot, stat.S_IREAD)
elif step == "plant-in":
    target = os.path.join(scratch, payload)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as stream:
        stream.write("planted: [unterminated\n")
    seen()
elif step == "plant-out":
    target = os.path.join(scratch, payload)
    os.remove(target)
    parent = os.path.dirname(target)
    while parent != scratch:
        os.rmdir(parent)
        parent = os.path.dirname(parent)
"""

LOCK = "nornyx.profiles.lock"
PROFILE = ".nornyx/profiles/agentic_repo_harness.yaml"
UNSELECTED_MODULE = ".nornyx/modules/planted/module.yaml"
INHERITED, SAME_USER_ROOT = "inherited-temp", "configured-root-same-user"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _project(tmp_path: Path, text: str | None) -> tuple[Path, str, Path]:
    """A project whose bound contract is `text` (or Forge's generated one),
    and a file holding the generated contract, which Nornyx passes."""
    root = tmp_path / "project"
    root.mkdir()
    (root / "BRD.md").write_text(BRD, encoding="utf-8")
    contract = generate_brd_contract(root, parse_brd(root / "BRD.md"))
    passing = tmp_path / "passing.nyx"
    passing.write_bytes(contract.read_bytes())
    if text is not None:
        contract.write_text(text, encoding="utf-8", newline="")
    return root, _digest(contract.read_bytes()), passing


def _attack_around_the_child(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, variant: str,
                             payload: str) -> tuple[list[str], Path]:
    """Run the attacker's `<variant>-in` step between Forge's snapshot write
    and the child, and its `<variant>-out` step between the child's exit and
    Forge's read-back. Returns the steps that ran and the witness file."""
    real = gate_module.subprocess.run
    steps: list[str] = []
    witness = tmp_path / "witness.json"

    def attacker(step: str, scratch: str) -> None:
        real([sys.executable, "-I", "-c", ATTACKER, step, scratch, payload, str(witness)],
             check=True)
        steps.append(step)

    def attacked(command, **kwargs):
        if len(command) != 6 or command[4] != "check":
            return real(command, **kwargs)
        scratch = str(Path(command[5]).parent)
        attacker(f"{variant}-in", scratch)
        completed = real(command, **kwargs)
        attacker(f"{variant}-out", scratch)
        return completed

    monkeypatch.setattr(gate_module.subprocess, "run", attacked)
    return steps, witness


def _same_user_root(parent: Path) -> Path:
    """A root the check ACCEPTS on this host, owned by this same user."""
    root = parent / "zf"
    root.mkdir(parents=True)
    if sys.platform == "win32":
        from test_contract_check_root_windows import _owner, _set_dacl  # noqa: PLC0415

        _set_dacl(root, f"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{_owner(root)})")
    else:
        root.chmod(0o700)
    return root


def _check(parent: Path, placement: str, root: Path, digest: str):
    if placement == INHERITED:  # the call exactly as main makes it
        return gate_module.trusted_contract_check(root, digest)
    gate = gate_module.trusted_contract_check(root, digest, scratch_root=_same_user_root(parent))
    assert gate.provenance["invocation"]["scratch_placement"] == "configured-root", gate.detail
    return gate


def _substitution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str,
                  placement: str) -> None:
    """Variants A and B. The bound bytes are a contract Nornyx REFUSES."""
    root, digest, passing = _project(tmp_path, REFUSED)
    steps, witness = _attack_around_the_child(monkeypatch, tmp_path, variant, str(passing))
    gate = _check(tmp_path, placement, root, digest)
    assert steps == [f"{variant}-in", f"{variant}-out"], "the attack did not run"
    seen = json.loads(witness.read_text(encoding="utf-8"))
    substituted = _digest(passing.read_bytes())
    assert seen["digest"] == substituted != digest, "the child was not shown other bytes"
    if gate.passed and gate.provenance["subject"]["checked_digest"] == digest:
        raise ResidualObserved(
            f"{variant} ABA under {placement}: the gate recorded a PASS for the refused "
            f"contract {digest}; the child read {substituted}, and the read-back saw the "
            "original bytes and inode")


def _plant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted: str,
           placement: str) -> tuple[bool, object]:
    """Variant C. The bound bytes are Forge's own contract, which passes when
    nothing is planted. Returns whether the planted file changed the verdict
    with nothing recorded about it, and the gate."""
    root, digest, _ = _project(tmp_path, None)
    honest = _check(tmp_path / "honest", placement, root, digest)
    assert honest.passed is True, honest.detail
    steps, witness = _attack_around_the_child(monkeypatch, tmp_path, "plant", planted)
    gate = _check(tmp_path / "attacked", placement, root, digest)
    assert steps == ["plant-in", "plant-out"], "the attack did not run"
    seen = json.loads(witness.read_text(encoding="utf-8"))
    assert seen["digest"] == digest, "the plant variant must leave the snapshot alone"
    assert planted.split("/")[0] in seen["listing"], "nothing was planted beside the snapshot"
    # No detection exists today. A repair that detects a plant would record it
    # in the provenance under a key it names, not in prose.
    detected = gate.provenance.get("scratch_tampering_detected") is True
    return (gate.passed is not True and not detected), gate


def _planted_changes_the_verdict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                 planted: str, placement: str) -> None:
    changed, gate = _plant(tmp_path, monkeypatch, planted, placement)
    if changed:
        raise ResidualObserved(
            f"{planted} planted beside the snapshot under {placement} turned the honest PASS "
            f"into {gate.provenance.get('outcome')} and the gate did not say so: "
            f"{gate.detail[:300]}")


@residual
def test_residual_rename_aba_passes_substituted_bytes_under_inherited_temp(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _substitution(tmp_path, monkeypatch, "rename", INHERITED)


@residual
def test_residual_rename_aba_passes_substituted_bytes_under_a_same_user_root(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _substitution(tmp_path, monkeypatch, "rename", SAME_USER_ROOT)


@residual
def test_residual_rewrite_aba_passes_substituted_bytes_under_inherited_temp(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _substitution(tmp_path, monkeypatch, "rewrite", INHERITED)


@residual
def test_residual_rewrite_aba_passes_substituted_bytes_under_a_same_user_root(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _substitution(tmp_path, monkeypatch, "rewrite", SAME_USER_ROOT)


@residual
def test_residual_planted_lock_changes_the_verdict_unseen_under_inherited_temp(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _planted_changes_the_verdict(tmp_path, monkeypatch, LOCK, INHERITED)


@residual
def test_residual_planted_lock_changes_the_verdict_unseen_under_a_same_user_root(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _planted_changes_the_verdict(tmp_path, monkeypatch, LOCK, SAME_USER_ROOT)


@residual
def test_residual_planted_profile_changes_the_verdict_unseen_under_inherited_temp(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _planted_changes_the_verdict(tmp_path, monkeypatch, PROFILE, INHERITED)


@residual
def test_residual_planted_profile_changes_the_verdict_unseen_under_a_same_user_root(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _planted_changes_the_verdict(tmp_path, monkeypatch, PROFILE, SAME_USER_ROOT)


@pytest.mark.parametrize("placement", [INHERITED, SAME_USER_ROOT])
def test_a_planted_pack_for_an_unselected_module_does_not_change_the_verdict(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, placement: str):
    """A measurement, not a defence: the contract selects no module, so a
    module pack planted beside the snapshot is not read into the verdict."""
    changed, gate = _plant(tmp_path, monkeypatch, UNSELECTED_MODULE, placement)
    assert changed is False and gate.passed is True, gate.detail
