"""Build an authenticated independent inspection for a fixture workspace.

A governance contract requires TWO things an autonomous build cannot produce for
itself: an accountable human approval, and an independent inspection signed by
reviewers the operator trusts. Both are named in `required_evidence`.

Fixtures used to supply only the first, and the contracts validated anyway,
because the contract recorded `independent_review_record` with a hand-written
`status: pass` regardless of whether anything had signed it. With the status now
derived from authenticated attestations like every other evidence verdict, a
fixture asserting "the documented commands make this contract validate" has to
produce both prerequisites -- which is what the documented workflow actually
requires.

Ephemeral throughout: keys are generated per call, live only in memory, and the
trust store is written OUTSIDE the governed workspace so no edit to the tree
under test can add a trusted reviewer. Nothing here creates an inspection of
this repository; the attestations cover a temp workspace and are discarded.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

# The reviewer-side tool an actual reviewer runs. Signing another way here would
# prove the fixture works rather than that the tool does.
from issue_inspection_attestation import build_attestation, sign_attestation  # noqa: E402

#: The three roles a complete inspection needs. One reviewer each, distinct, so
#: no single key can cover the set.
REQUIRED_ROLES = ("test-inspector", "architecture-inspector", "security-inspector")
BUILDER = "builder.nornyx_forge"
ATTESTATION_RELATIVE = ".nornyx/contracts/evidence/attestations"


class Reviewers:
    """Three trusted reviewers, one per role, with a store on disk."""

    def __init__(self, store_dir: Path) -> None:
        self.private: dict[str, bytes] = {}
        self.names: dict[str, str] = {}
        self.key_ids: dict[str, str] = {}
        entries = []
        for index, role in enumerate(REQUIRED_ROLES):
            key = Ed25519PrivateKey.generate()
            name = f"reviewer.{role.split('-')[0]}"
            self.private[role] = key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            self.names[role] = name
            self.key_ids[role] = f"rev-{index}"
            entries.append(
                {
                    "key_id": self.key_ids[role],
                    "reviewer": name,
                    "roles": [role],
                    "public_key": key.public_key()
                    .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                    .decode("utf-8"),
                    "status": "active",
                }
            )
        store_dir.mkdir(parents=True, exist_ok=True)
        self.store = store_dir / "reviewer_trust.json"
        self.store.write_text(
            json.dumps(
                {"schema": "nornyx.forge.reviewer_trust_store.v1", "reviewers": entries},
                indent=2,
            ),
            encoding="utf-8",
            newline="",
        )



class OneReviewerForEveryRole(Reviewers):
    """A trust store an operator can plausibly build, and must not be assured.

    `ASSURANCE_BOUNDARY.md` requires each inspector role to be signed by a
    DISTINCT reviewer. Nothing stops an operator authorising one identity for
    all three, so the interesting case is not whether it can be built -- it
    can -- but whether every consumer of the result says the same thing about
    it. One did not: the emitted record applied the coverage clause and not
    the distinctness clause, and displayed `status: pass` over an inspection
    `derive_assurance_state` refused.
    """

    def __init__(self, store_dir: Path) -> None:
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        name = "reviewer.omni"
        self.private = {role: private for role in REQUIRED_ROLES}
        self.names = {role: name for role in REQUIRED_ROLES}
        self.key_ids = {role: "rev-omni" for role in REQUIRED_ROLES}
        store_dir.mkdir(parents=True, exist_ok=True)
        self.store = store_dir / "reviewer_trust.json"
        self.store.write_text(
            json.dumps(
                {
                    "schema": "nornyx.forge.reviewer_trust_store.v1",
                    "reviewers": [
                        {
                            "key_id": "rev-omni",
                            "reviewer": name,
                            "roles": list(REQUIRED_ROLES),
                            "public_key": key.public_key()
                            .public_bytes(
                                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                            )
                            .decode("utf-8"),
                            "status": "active",
                        }
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
            newline="",
        )

def inspection_env(work: Path, reviewers: Reviewers | None) -> dict[str, str]:
    """Environment for a subprocess run against this workspace.

    A `None` reviewer set points at a path that does not exist rather than
    leaving the variable unset, so an operator's real store cannot leak into a
    negative case and make it pass for the wrong reason.
    """
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    env["FORGE_REVIEWER_TRUST_STORE"] = str(
        reviewers.store if reviewers is not None else work / "no-such-store.json"
    )
    env["FORGE_BUILDER_IDENTITY"] = BUILDER
    return env


def current_subject(work: Path) -> str:
    """Ask the tool what an inspection of this workspace would be reviewing."""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0,'scripts');"
            "import refresh_governance_evidence as r;"
            "print(r.current_inspection_subject())",
        ],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=inspection_env(work, None),
        timeout=600,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout.strip()


def authenticate_inspection(
    work: Path, store_dir: Path, *, one_reviewer: bool = False
) -> Reviewers:
    """Sign a passing attestation per role over this workspace's subject.

    Returns the reviewer set so the caller can pass its store to later runs.
    The attestations are written into the workspace's evidence directory, which
    is where the evidence tooling looks for them.
    """
    reviewers = (
        OneReviewerForEveryRole(store_dir) if one_reviewer else Reviewers(store_dir)
    )
    subject = current_subject(work)
    target = work / ATTESTATION_RELATIVE
    target.mkdir(parents=True, exist_ok=True)

    for role in REQUIRED_ROLES:
        signed = sign_attestation(
            build_attestation(
                inspection_subject_digest=subject,
                reviewer=reviewers.names[role],
                reviewer_key_id=reviewers.key_ids[role],
                inspector_role=role,
                verdict="pass",
                findings=[],
                tool="claude-opus",
                tool_version="5",
            ),
            reviewers.private[role],
        )
        (target / f"{role}.json").write_bytes(
            json.dumps(signed, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
    return reviewers
