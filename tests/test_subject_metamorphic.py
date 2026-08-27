"""A revision anchor and an authority subject are not the same value.

Collapsing them is the mistake this file exists to prevent from recurring.

The first design projected tool-generated fields out of the contracts and called
the result the authority subject. An audit then mutated each excluded field and
re-ran Nornyx: seven of them changed its verdict — `content_hash`, `status`, the
records list, `subject_revision`, `revision_binding.revision`, and both time
fields pushed adversarially. A digest omitting those cannot claim to identify
what will execute.

So there are two values with different jobs:

    governed_revision_digest   which authored revision produced the generated
                               governance state; excludes it, deliberately
    governed_subject_digest    the complete settled state that will execute;
                               excludes nothing Nornyx evaluates

The metamorphic property, checked here against the real Nornyx verdict rather
than against an assumption about which fields "look generated":

    if mutating a field changes the Nornyx verdict
        -> the subject digest MUST change
        -> the revision anchor MAY stay the same

    if the mutation is to authored governance semantics
        -> BOTH must change
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from nornyx_forge.governed_subject import REPOSITORY_SCOPE, RuntimeAuthorityConfig
from nornyx_forge.subject_bootstrap import establish_subject

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = Path(".nornyx/contracts")
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", "*.pyc", "*.egg-info", "evidence"
)
CONFIG = RuntimeAuthorityConfig("nornyx", "crewai")
AS_OF = "2026-08-20T00:00:00Z"

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)


def _tree() -> Path:
    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(ROOT, work, ignore=IGNORE)
    return work


def _digests(root: Path) -> tuple[str, str]:
    subject = establish_subject(root, scope=REPOSITORY_SCOPE, config=CONFIG)
    assert subject.subject_verified, subject.unavailable_reason
    return subject.governed_revision_digest, subject.governed_subject_digest


def _verdict(root: Path) -> dict[str, list[str]]:
    """Nornyx's own answer, which is the authority on what is authoritative."""
    out: dict[str, list[str]] = {}
    for name in ("runtime_network.nyx", "architecture_governance.nyx"):
        done = subprocess.run(
            [shutil.which("nornyx") or "nornyx", "check", str(root / CONTRACTS / name),
             "--as-of", AS_OF],
            cwd=root, capture_output=True, text=True,
        )
        decoder, codes, index = json.JSONDecoder(), [], 0
        text = (done.stdout + done.stderr).strip()
        while index < len(text):
            if text[index].isspace():
                index += 1
                continue
            try:
                value, index = decoder.raw_decode(text, index)
            except ValueError:
                break
            if isinstance(value, dict) and value.get("level") == "error":
                codes.append(value.get("code"))
        out[name] = sorted(codes)
    return out


def _edit(root: Path, name: str, mutate) -> bool:
    path = root / CONTRACTS / name
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    before = copy.deepcopy(document)
    mutate(document)
    if document == before:
        return False
    path.write_bytes(yaml.safe_dump(document, sort_keys=False).encode("utf-8"))
    return True


def _records(document: dict) -> list:
    return document.get("governance_evidence", {}).get("records", [])


def _hash(d):
    for record in _records(d):
        record["content_hash"] = "sha256:" + "0" * 64


def _status(d):
    for record in _records(d):
        record["status"] = "fail"


def _drop(d):
    d.get("governance_evidence", {})["records"] = []


def _revision(d):
    if "governance_evidence" in d:
        d["governance_evidence"]["subject_revision"] = "git:" + "e" * 40


def _expired(d):
    for record in _records(d):
        record["expires_at"] = "2026-08-10T00:00:00Z"  # before AS_OF


def _future(d):
    for record in _records(d):
        record["generated_at"] = "2030-01-01T00:00:00Z"  # after AS_OF


def _semantics(d):
    """Authored governance: widen a layer rule."""
    for layer in d.get("architecture", {}).get("layers", []):
        if layer["id"] == "layer.adapter":
            layer["may_depend_on"] = ["layer.domain", "layer.interface"]


EXCLUDED_FROM_THE_ANCHOR = [
    ("records[*].content_hash", _hash),
    ("records[*].status", _status),
    ("records (dropped)", _drop),
    ("governance_evidence.subject_revision", _revision),
    ("records[*].expires_at -> past", _expired),
    ("records[*].generated_at -> future", _future),
]


@needs_nornyx
@pytest.mark.parametrize(("label", "mutate"), EXCLUDED_FROM_THE_ANCHOR)
def test_anything_nornyx_judges_is_inside_the_subject(label: str, mutate):
    """The load-bearing property, measured rather than assumed.

    The reference is Nornyx's verdict, not a belief about which fields are
    "merely generated" — that belief is exactly what the exclusion audit
    falsified.
    """
    baseline_tree = _tree()
    baseline_verdict = _verdict(baseline_tree)
    _, baseline_subject = _digests(baseline_tree)

    work = _tree()
    changed = False
    for name in ("runtime_network.nyx", "architecture_governance.nyx"):
        changed |= _edit(work, name, mutate)
    assert changed, f"{label}: the mutation altered nothing, so it proves nothing"

    _, subject = _digests(work)
    if _verdict(work) != baseline_verdict:
        assert subject != baseline_subject, (
            f"{label}: Nornyx's verdict changed but the authority subject did not"
        )


def test_authored_semantics_move_both_values():
    """The inverse. A contract edit is a change to the revision *and* the state."""
    baseline_revision, baseline_subject = _digests(_tree())

    work = _tree()
    assert _edit(work, "architecture_governance.nyx", _semantics)
    revision, subject = _digests(work)

    assert revision != baseline_revision
    assert subject != baseline_subject


def test_stamping_generated_values_leaves_the_anchor_still(tmp_path: Path):
    """The fixed point the commit-hash model could never have.

    A contract cannot contain the hash of the commit containing it, so
    `declared == actual` was false at every commit. Content identity has no such
    problem: stamping generated values must leave the anchor untouched, or
    settling the contracts would move the revision that produced them.
    """
    baseline_revision, _ = _digests(_tree())

    work = _tree()
    for mutate in (_hash, _revision, _future):
        for name in ("runtime_network.nyx", "architecture_governance.nyx"):
            _edit(work, name, mutate)

    revision, _ = _digests(work)
    assert revision == baseline_revision
