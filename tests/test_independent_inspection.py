"""An independent inspection is a claim about a subject, and both must hold.

Two things have to be true at once, and the old version of this file only
checked one of them.

The subject half was right: an inspection is bound to
``H(governed_input_digest + contract_set_digest + pre_inspection_evidence)``,
so anything moving that digest makes the inspection stale, and recomputing the
current digest must never rebind old PASS evidence to it. Those tests survive
here unchanged in intent.

The identity half was missing entirely. The attestation was unauthenticated, so
independence was read off the artifact — a builder asserting their own
non-self-approval. Authentication is now a precondition, which changes what this
file has to do: every attestation is signed by an ephemeral reviewer key through
the real issuer, and read back through the production verifier. Nothing here
hand-writes an attestation, because a hand-written one no longer means anything.

The authentication controls themselves live in `test_reviewer_authentication.py`.
This file assumes them and tests what the assurance derivation does with the
result.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from issue_inspection_attestation import (  # noqa: E402
    build_attestation,
    sign_attestation,
)

CONTRACTS = Path(".nornyx/contracts")
REFRESH = "scripts/refresh_governance_evidence.py"
ATTESTATIONS = CONTRACTS / "evidence" / "attestations"

REQUIRED = ("test-inspector", "architecture-inspector", "security-inspector")
BUILDER = "builder.nornyx_forge"


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(work), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )


class Reviewers:
    """Three distinct reviewers, one per required role.

    Ephemeral: generated per test, never written to the repository, and the
    private halves exist only in memory. The trust store holds public keys and
    sits outside the governed tree, so no edit to the workspace can add a
    trusted reviewer — which is the property the store exists to have.
    """

    def __init__(self, tmp_path: Path):
        self.private: dict[str, bytes] = {}
        entries = []
        for index, role in enumerate(REQUIRED):
            key = Ed25519PrivateKey.generate()
            name = f"reviewer.{role.split('-')[0]}"
            self.private[role] = key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            entries.append(
                {
                    "key_id": f"rev-{index}",
                    "reviewer": name,
                    "roles": [role],
                    "public_key": key.public_key()
                    .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                    .decode("utf-8"),
                    "status": "active",
                }
            )
        self.names = {role: entry["reviewer"] for role, entry in zip(REQUIRED, entries)}
        self.key_ids = {role: entry["key_id"] for role, entry in zip(REQUIRED, entries)}
        self.store = tmp_path / "reviewer_trust.json"
        self.store.write_text(
            json.dumps(
                {"schema": "nornyx.forge.reviewer_trust_store.v1", "reviewers": entries},
                indent=2,
            ),
            encoding="utf-8",
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
    # Derived from the scope, not listed here. Seven fixtures each kept
    # their own copy of this list and all seven broke the moment the scope
    # gained a required file -- SUBJECT_SCOPE_INCOMPLETE, which is the scope
    # correctly refusing to call a smaller subject verified.
    sys.path.insert(0, str(ROOT / 'tests'))
    from governed_workspace import copy_governed_workspace  # noqa: PLC0415

    copy_governed_workspace(work)
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "fixture")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "fixture")
    return work


def _run(work: Path, reviewers: Reviewers | None, *args: str):
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    if reviewers is not None:
        env["FORGE_REVIEWER_TRUST_STORE"] = str(reviewers.store)
    else:
        # Explicitly nowhere, so an operator's real store cannot leak in and
        # make a negative case pass for the wrong reason.
        env["FORGE_REVIEWER_TRUST_STORE"] = str(work / "no-such-store.json")
    env["FORGE_BUILDER_IDENTITY"] = BUILDER
    return subprocess.run(
        [sys.executable, *args],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


def _settle(work: Path) -> None:
    """Generate machine evidence and let the contracts settle."""
    assert _run(work, None, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, None, REFRESH, "--sync-contracts").returncode == 0


def _current_subject(work: Path) -> str:
    """Ask the tool itself what an inspection here would be reviewing."""
    completed = _run(
        work,
        None,
        "-c",
        "import sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(r.current_inspection_subject())",
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _attest(
    work: Path,
    reviewers: Reviewers,
    *,
    subject: str | None = None,
    roles: tuple[str, ...] = REQUIRED,
    verdicts: dict[str, str] | None = None,
    reviewer_override: dict[str, str] | None = None,
    role_override: dict[str, str] | None = None,
) -> None:
    """Sign real attestations, honest by default.

    Signed through `scripts/issue_inspection_attestation.py` — the reviewer-side
    tool an actual reviewer runs. A fixture that produced signatures its own way
    would prove the fixture works.
    """
    subject = subject if subject is not None else _current_subject(work)
    target = work / ATTESTATIONS
    target.mkdir(parents=True, exist_ok=True)

    for role in roles:
        signing_role = (role_override or {}).get(role, role)
        attestation = build_attestation(
            inspection_subject_digest=subject,
            reviewer=(reviewer_override or {}).get(role, reviewers.names[role]),
            reviewer_key_id=reviewers.key_ids[role],
            inspector_role=signing_role,
            verdict=(verdicts or {}).get(role, "pass"),
            findings=[],
            tool="claude-opus",
            tool_version="5",
        )
        signed = sign_attestation(attestation, reviewers.private[role])
        (target / f"{role}.json").write_bytes(
            json.dumps(signed, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )

    # The attestations join the final evidence set, so the review binding is
    # regenerated over them. That is the chain order: contracts settle, the
    # subject freezes, inspectors report, and only then does the package saying
    # what was reviewed get written.
    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0


def _assurance(work: Path, reviewers: Reviewers | None) -> dict:
    """Recompute the assurance position, as --verify does."""
    completed = _run(
        work,
        reviewers,
        "-c",
        "import json,sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(json.dumps(r.derive_assurance_state()))",
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _inspected(work: Path, reviewers: Reviewers | None) -> bool:
    return _assurance(work, reviewers)["assurance_state"] == "independently_inspected"


@pytest.fixture
def settled(tmp_path: Path) -> tuple[Path, Reviewers]:
    work = _workspace(tmp_path)
    _settle(work)
    return work, Reviewers(tmp_path)


# --------------------------------------------------------------------------
# What a complete inspection requires
# --------------------------------------------------------------------------


def test_a_complete_authenticated_inspection_over_the_current_subject_passes(settled):
    work, reviewers = settled
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", state["problems"]
    assert state["problems"] == []
    assert state["assurance_problems"] == []
    assert state["required_inspectors_complete"] is True
    assert state["independent"] is True
    assert state["authenticated_reviewers"] == sorted(reviewers.names.values())


def test_an_inspection_nobody_can_authenticate_establishes_nothing(settled):
    """Same files, no trust store. The artifacts alone must decide nothing."""
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True

    state = _assurance(work, None)
    assert state["assurance_state"] == "not_independently_inspected"
    assert any("no reviewer trust store" in p for p in state["assurance_problems"])
    assert state["independent"] is False


def test_an_incomplete_inspection_is_not_an_independent_one(settled):
    """Two of three roles. A missing lens is a missing lens."""
    work, reviewers = settled
    _attest(work, reviewers, roles=REQUIRED[:2])

    state = _assurance(work, reviewers)
    assert state["required_inspectors_complete"] is False
    assert state["assurance_state"] == "not_independently_inspected"


def test_a_failing_inspector_is_not_a_passing_inspection(settled):
    work, reviewers = settled
    _attest(work, reviewers, verdicts={"security-inspector": "fail"})

    state = _assurance(work, reviewers)
    assert state["required_inspectors_complete"] is False
    assert state["assurance_state"] == "not_independently_inspected"


def test_one_reviewer_cannot_cover_every_role(tmp_path: Path):
    """Three lenses from one identity is one lens applied three times.

    The value of separate inspectors is that they disagree. A single reviewer
    authorized for all three roles satisfies the count while removing the
    property the count was standing in for.
    """
    work = _workspace(tmp_path)
    _settle(work)
    reviewers = Reviewers(tmp_path)

    # Re-issue the store with a single reviewer holding all three roles.
    key = Ed25519PrivateKey.generate()
    reviewers.store.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.reviewer_trust_store.v1",
                "reviewers": [
                    {
                        "key_id": "rev-solo",
                        "reviewer": "reviewer.solo",
                        "roles": list(REQUIRED),
                        "public_key": key.public_key()
                        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        .decode("utf-8"),
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    private = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    for role in REQUIRED:
        reviewers.private[role] = private
        reviewers.names[role] = "reviewer.solo"
        reviewers.key_ids[role] = "rev-solo"
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["required_inspectors_complete"] is True, state["problems"]
    assert state["independent"] is False, (
        "one identity signing all three roles was counted as three independent "
        "inspections"
    )
    assert state["assurance_state"] == "not_independently_inspected"


def test_a_duplicate_role_cannot_be_resolved_by_ordering(settled):
    """Two attestations for one role: which applies must not depend on filename."""
    work, reviewers = settled
    _attest(work, reviewers)
    duplicate = work / ATTESTATIONS / "aaa-first.json"
    duplicate.write_bytes((work / ATTESTATIONS / "security-inspector.json").read_bytes())

    state = _assurance(work, reviewers)
    assert any("already attested" in p for p in state["assurance_problems"])


def test_the_builder_cannot_satisfy_an_inspector_role(tmp_path: Path):
    """Even holding a trusted key issued in their own name.

    This asserted a disjunction -- identity mismatch OR builder -- and the
    fixture overrode only the *claimed* reviewer name, so the record was signed
    by `reviewer.security`'s key while claiming to be the builder. Identity
    mismatch fired, the builder branch was never reached, and an independent
    review deleted the builder check entirely with this test still green.

    So the store now genuinely vouches for the builder: the key belongs to them,
    the signature is theirs, the claimed name matches. Every other check passes,
    which leaves exactly one control able to produce the refusal.
    """
    work = _workspace(tmp_path)
    _settle(work)
    reviewers = Reviewers(tmp_path)

    # Re-issue the security-inspector slot in the builder's own name.
    store = json.loads(reviewers.store.read_text(encoding="utf-8"))
    for entry in store["reviewers"]:
        if "security-inspector" in entry["roles"]:
            entry["reviewer"] = BUILDER
    reviewers.store.write_text(json.dumps(store, indent=2), encoding="utf-8")
    reviewers.names["security-inspector"] = BUILDER

    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "not_independently_inspected"
    assert any("REVIEWER_IS_THE_BUILDER" in p for p in state["assurance_problems"]), (
        "the refusal did not come from the independence derivation: "
        + repr(state["assurance_problems"])
    )
    assert not any(
        "REVIEWER_IDENTITY_MISMATCH" in p for p in state["assurance_problems"]
    ), "identity mismatch fired, so this proves the identity binding, not independence"


# --------------------------------------------------------------------------
# Staleness: the inspection is bound to the subject it actually saw
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "relative", "content"),
    [
        ("authored source", "src/nornyx_forge/late_addition.py", b"X = 1\n"),
        ("a governed contract", ".nornyx/contracts/runtime_network.nyx", None),
    ],
)
def test_moving_the_subject_makes_the_inspection_stale(
    settled, label: str, relative: str, content: bytes | None
):
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True, label

    target = work / relative
    if content is None:
        # A DECLARED value, not a comment. The subject is computed from what the
        # contracts say rather than their exact bytes, because adopting an
        # approval rewrites the declared revision and every recorded evidence
        # digest -- and binding an inspection to those bytes made the two
        # prerequisites unsatisfiable together: attest before adoption and the
        # attestation is stale, attest after and the attestations are untracked
        # against the revision the approval pins.
        #
        # Byte-level contract drift is not unguarded; it is caught elsewhere, by
        # `test_a_comment_only_contract_edit_is_still_caught`.
        target.write_bytes(
            target.read_bytes().replace(
                b"name: GovernedCustomerOperationsRuntime",
                b"name: GovernedCustomerOperationsRuntimeX",
                1,
            )
        )
    else:
        target.write_bytes(content)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "not_independently_inspected", label
    assert any(
        "not the subject this tree now presents" in problem
        for problem in state["assurance_problems"]
    ), label


def test_a_comment_only_contract_edit_is_still_caught(settled):
    """Byte-level contract drift stays covered, just not by the subject.

    The inspection subject digests what the contracts SAY, and a comment says
    nothing -- so it does not invalidate an inspection of the meaning. It is
    still drift, and the review binding records the exact contract bytes, which
    `--verify` recomputes. Asserted here so the coverage is seen to have moved
    rather than shrunk.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True

    target = work / ".nornyx/contracts/runtime_network.nyx"
    target.write_bytes(target.read_bytes() + b"\n# moved after inspection\n")

    completed = _run(work, reviewers, REFRESH, "--verify")
    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["integrity_state"] == "compromised", (
        "a comment-only contract edit went unreported by integrity verification"
    )


def test_sync_contracts_after_inspection_makes_it_stale(settled):
    """Settling contracts changes the control pack, so it changes the subject."""
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True

    assert _run(work, reviewers, REFRESH, "--as-of", "2026-08-03T00:00:00Z").returncode == 0
    assert _run(work, reviewers, REFRESH, "--sync-contracts").returncode == 0

    assert _inspected(work, reviewers) is False


def test_regenerating_the_digest_alone_leaves_the_inspection_stale(settled):
    """P2-D, restated against signed evidence.

    The tool may recompute what the current subject is. It must never rebind a
    previously produced PASS to that new value — which, now that attestations
    are signed, it could not do even if it tried: the subject is inside the
    signature.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    (work / "src/nornyx_forge/drifted.py").write_bytes(b"X = 1\n")
    assert _inspected(work, reviewers) is False

    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0
    assert _inspected(work, reviewers) is False, (
        "regenerating the binding rebound stale PASS evidence to the new subject"
    )


def test_signing_an_inspection_does_not_move_the_subject_it_inspects(settled):
    """Otherwise no inspection could ever match, and the reason is not obvious.

    The subject includes pre-inspection evidence. If attestations counted as
    that evidence, writing one would change the subject it names — a fixed point
    nothing converges to. It works today because the evidence manifest globs one
    directory level and the attestations live one below it, which is a load-
    bearing property that currently looks like an implementation detail.
    """
    work, reviewers = settled
    before = _current_subject(work)
    _attest(work, reviewers)
    assert _current_subject(work) == before, (
        "writing a signed attestation moved the subject it attests to"
    )


def test_a_fresh_inspection_alone_does_not_restore_assurance(settled):
    """Re-inspecting fixes the inspection, not the evidence it sits on.

    After drift the machine evidence still describes the old content. A new
    signed inspection makes `independent` true again — and assurance stays
    withheld, because assurance requires integrity and the evidence set is
    stale. These are separate facts and must not substitute for each other.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    (work / "src/nornyx_forge/drifted.py").write_bytes(b"X = 1\n")
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["independent"] is True
    assert state["required_inspectors_complete"] is True
    assert state["integrity_state"] == "compromised"
    assert state["assurance_state"] == "not_independently_inspected"


def test_the_full_causal_chain_restores_assurance(settled):
    """Staleness is recoverable by redoing the work, not by asserting again.

    Order is the point: evidence is regenerated, contracts settle, only then is
    the subject stable enough to inspect, and the binding is written last. Run
    out of order it does not converge, which is the honest outcome.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    (work / "src/nornyx_forge/drifted.py").write_bytes(b"X = 1\n")
    assert _inspected(work, reviewers) is False

    _settle(work)
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", state["problems"]
    assert state["integrity_state"] == "intact"


def test_a_stale_attestation_does_not_perturb_the_next_subject(settled):
    """H13. Evidence ABOUT a subject must never become part of it.

    THE CONJUNCTION NEITHER EXISTING TEST COVERED. The fixed-point tests
    regenerate twice with attestations that are never stale, so the
    stale-diagnostic branch never executes. `test_moving_the_subject_makes_the_
    inspection_stale` has a genuinely stale attestation but regenerates once, so
    a subject that moves BETWEEN passes cannot be observed. Only both together
    reach the defect, which is why the historical mutation survived three
    correct-looking attempts.

    The stale diagnostic lands in `verdict_basis`, inside the evidence set the
    subject is computed from. If it names the CURRENT subject, the subject
    becomes a function of itself: every regeneration moves it, and no
    attestation can ever name the one the next run will present.

    Asserted as STATE STABILITY, not as wording. Checking the sentence for a
    digest would be a string-format test wearing a security proof's name, and
    would pass for a system whose subject drifted anyway.

    Reuses the provisioned reviewer trust and real signing from `settled` and
    `_attest`. An earlier version of this proof attached an UNSIGNED
    attestation, which is discarded at authentication -- H14's clause -- before
    control reaches the mismatch branch at all. Branch-body probing reported
    INVALID_TEST_AIM for it, correctly.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True, "the baseline inspection is not complete"

    subject_before = _current_subject(work)

    # Move the subject, so the signed attestation above becomes stale. A
    # DECLARED value, matching what test_moving_the_subject_makes_the_inspection
    # _stale changes, so this exercises the same staleness the suite already
    # recognises rather than inventing a new one.
    contract = work / ".nornyx/contracts/runtime_network.nyx"
    contract.write_bytes(
        contract.read_bytes().replace(
            b"name: GovernedCustomerOperationsRuntime",
            b"name: GovernedCustomerOperationsRuntimeX",
            1,
        )
    )

    _settle(work)
    subject_after = _current_subject(work)
    assert subject_after != subject_before, (
        "the governed subject did not move, so the attestation never became "
        "stale and this test cannot reach the property"
    )

    # The attestation is now stale AND authenticated, so the mismatch branch
    # runs on every pass from here.
    state = _assurance(work, reviewers)
    assert any(
        "not the subject this tree now presents" in problem
        for problem in state["assurance_problems"]
    ), state["assurance_problems"]

    # THE FIXED POINT, with the stale diagnostic being written each time.
    # Nothing governed changes between these two regenerations.
    _settle(work)
    first = _current_subject(work)
    _settle(work)
    second = _current_subject(work)

    assert first == second, (
        "two consecutive regenerations over an unchanged governed tree produced "
        f"different subjects ({first} then {second}) while a stale attestation "
        "was present, so evidence ABOUT the subject has become part of it and "
        "no attestation can name the subject the next run will present"
    )


def test_the_stale_attestation_keeps_naming_the_subject_it_reviewed(settled):
    """Identity preservation, paired with the stability proof above.

    Stability alone could be satisfied by a system that stopped reporting
    staleness at all. This requires the mismatch to stay OBSERVABLE and to be
    described against the subject that was actually reviewed.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    reviewed = _current_subject(work)

    contract = work / ".nornyx/contracts/runtime_network.nyx"
    contract.write_bytes(
        contract.read_bytes().replace(
            b"name: GovernedCustomerOperationsRuntime",
            b"name: GovernedCustomerOperationsRuntimeX",
            1,
        )
    )
    _settle(work)
    current = _current_subject(work)
    assert reviewed != current

    state = _assurance(work, reviewers)
    stale = [p for p in state["assurance_problems"]
             if "not the subject this tree now presents" in p]
    assert stale, state["assurance_problems"]
    assert any(reviewed in problem for problem in stale), (
        "the stale diagnostic no longer names the subject that was reviewed, so "
        "the mismatch has been rewritten as though the attestation belonged to "
        f"the current subject. reviewed={reviewed} current={current}"
    )
    assert not any(current in problem for problem in stale), (
        "the stale diagnostic names the CURRENT subject, which puts the subject "
        "inside the evidence it is derived from"
    )
    assert _inspected(work, reviewers) is False
