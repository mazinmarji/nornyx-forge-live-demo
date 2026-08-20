"""Issuer-side tooling: sign an action approval with a human's private key.

Deliberately **not** part of the ``nornyx_forge`` package, and deliberately not
copied into the runtime image. The Dockerfile ships ``src`` and ``.nornyx``; it
does not ship ``scripts``, so the running application contains no signing
implementation at all.

    approval issuer (here)
          │  private key
          ▼
    signed approval artifact
          │
    ══════╪══════ TRUST BOUNDARY ══════
          ▼
    nornyx_forge.approval_trust
          │  public key only
          ▼
    NornyxActionBoundary

The property this arrangement protects is not "one module has no signer". It is
that the verifier *process* cannot mint the artifact it accepts. Keeping the
signer in the package with a comment saying not to call it would leave that
property resting on nobody calling it.

Usage::

    python scripts/issue_action_approval.py \\
        --request-digest sha256:... \\
        --approver human.mazin_marji \\
        --role operations_owner \\
        --key-id mazin-approval-01 \\
        --private-key ~/.nornyx-forge/keys/mazin-approval-01.key \\
        --expires 2026-08-15T00:00:00Z

The private key is read from a path the operator supplies. It is never read from
the repository, never from the runtime configuration, and never written back.
"""

from __future__ import annotations

import argparse
import json
import sys
from base64 import b64decode, b64encode
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nornyx_forge.approval_trust import (  # noqa: E402
    APPROVAL_SCHEMA,
    canonical_grant_payload,
)


def sign_grant(payload: Mapping[str, Any], private_key_bytes: bytes) -> str:
    """Sign the canonical grant payload with an Ed25519 private key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return b64encode(key.sign(canonical_grant_payload(payload))).decode("ascii")


def generate_keypair() -> tuple[str, str]:
    """Create a new Ed25519 keypair, base64-encoded. Operator convenience."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return b64encode(raw).decode("ascii"), b64encode(public).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-keypair", action="store_true")
    parser.add_argument(
        "--request",
        type=Path,
        help="A pending action request artifact emitted by Forge. Preferred: it "
        "carries the exact digest, so the operator signs what the runtime will "
        "verify rather than reconstructing it",
    )
    parser.add_argument(
        "--request-digest",
        help="The digest directly, when the artifact is not to hand",
    )
    parser.add_argument("--approver")
    parser.add_argument("--role")
    parser.add_argument("--key-id")
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--approval-id", default=None)
    parser.add_argument("--expires", help="ISO-8601 UTC, at most seven days out")
    args = parser.parse_args()

    if args.generate_keypair:
        private, public = generate_keypair()
        print(json.dumps({"private_key": private, "public_key": public}, indent=2))
        print(
            "\nStore the private key outside any repository. Put only the public "
            "key in the trust store.",
            file=sys.stderr,
        )
        return 0

    request_digest = args.request_digest
    attempt_id = None
    bound: dict = {}
    if args.request is not None:
        pending = json.loads(args.request.read_text(encoding="utf-8"))
        artifact_digest = pending.get("request_digest")
        if request_digest and request_digest != artifact_digest:
            parser.error(
                f"--request-digest {request_digest} disagrees with the artifact's "
                f"{artifact_digest}. Sign one act, not two."
            )
        request_digest = artifact_digest
        attempt_id = pending.get("attempt_id")
        # THE BINDING FIELDS, lifted from the request this grant is for.
        # Without them the shipped verifier refuses at six clauses in sequence
        # -- producer, request_id, subject_revision, capability, destination,
        # payload_digest -- so the only documented way to obtain an action
        # approval produced an artifact that could not release anything. The
        # runtime writes "Sign this exact request_digest with
        # scripts/issue_action_approval.py" into every pending artifact, and
        # following that instruction terminated in a refusal.
        #
        # It went unnoticed because the one test claiming to prove otherwise
        # supplied these six itself with `signed.update({...})`, then asserted
        # only `signer_authenticated` -- it never called `verify_action_approval`
        # at all. FG32, on the producer side of the boundary.
        binding = pending.get("request") or {}
        for field in ("request_id", "subject_revision", "capability",
                      "payload_digest"):
            if field in binding:
                bound[field] = binding[field]
        # `destination` sits one level down, inside the action, because
        # `ActionRequest.canonical()` nests it there while exposing it as a
        # top-level property. The boundary compares the grant's TOP-LEVEL
        # field, so lifting it is part of producing a usable grant.
        action = binding.get("action")
        if isinstance(action, dict) and "destination" in action:
            bound["destination"] = action["destination"]
        print(
            "Signing this exact request:\n"
            + json.dumps(pending.get("request"), indent=2, sort_keys=True),
            file=sys.stderr,
        )

    required = {"approver": args.approver, "role": args.role, "key_id": args.key_id,
                "private_key": args.private_key, "expires": args.expires,
                "request digest (--request or --request-digest)": request_digest}
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error(f"missing required arguments: {sorted(missing)}")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "schema": APPROVAL_SCHEMA,
        "approval_id": args.approval_id or f"ACT-{now}",
        "request_digest": request_digest,
        "approver": args.approver,
        "approver_role": args.role,
        "signer_key_id": args.key_id,
        "generated_at": now,
        "expires_at": args.expires,
        "granted": True,
    }
    grant = dict(payload)
    grant["signature"] = sign_grant(payload, b64decode(args.private_key.read_text().strip()))
    # OUTSIDE THE SIGNED SET, and that is safe for a reason worth stating
    # rather than assuming. `request_digest` IS signed, and it is the digest of
    # the canonical request these five fields are copied from -- so rewriting
    # any of them makes the grant disagree with the request the boundary is
    # actually evaluating, and it refuses. The signature binds them
    # transitively; restating them here is what lets the verifier say WHICH
    # clause failed instead of only that a digest did not match.
    grant.update(bound)
    # Declared, and cross-checked: `approval_trust` decides humanness from the
    # TRUST STORE's `subject_type` for this key, not from this line. A grant
    # claiming `human` for a machine key is refused as APPROVER_NOT_HUMAN.
    grant.setdefault("approver_type", "human")
    if attempt_id:
        # Provenance for the operator, outside the signed set: the signature
        # already binds the attempt transitively through request_digest.
        grant["attempt_id"] = attempt_id
    print(json.dumps(grant, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
