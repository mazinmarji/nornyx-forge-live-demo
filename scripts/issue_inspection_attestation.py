"""Sign an inspection attestation. Reviewer-side, and deliberately not shipped.

This lives in `scripts/` for the same reason `issue_action_approval.py` does:
the Dockerfile copies `src`, `.nornyx` and `BRD.md`, never `scripts`. The
runtime image therefore holds verification material and no signing capability
at all. A test asserts the Dockerfile still omits it.

The private key never enters the repository. It is read from a path the reviewer
supplies, used once, and not retained.

Separate from action approval on purpose. An approver signs "this effect may be
released"; a reviewer signs "I inspected this content and found these things".
One key satisfying both would let whoever authorizes a payment also certify that
the code releasing it had been independently reviewed.
"""

from __future__ import annotations

import argparse
import json
import sys
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nornyx_forge.reviewer_trust import (  # noqa: E402
    ATTESTATION_SCHEMA,
    canonical_attestation_payload,
    findings_digest,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_attestation(
    *,
    inspection_subject_digest: str,
    reviewer: str,
    reviewer_key_id: str,
    inspector_role: str,
    verdict: str,
    findings: list,
    tool: str,
    tool_version: str,
    produced_at: str | None = None,
) -> dict:
    """The attestation, before signing. Every signed field is present."""
    return {
        "schema": ATTESTATION_SCHEMA,
        "inspection_subject_digest": inspection_subject_digest,
        "reviewer": reviewer,
        "reviewer_key_id": reviewer_key_id,
        "inspector_role": inspector_role,
        "verdict": verdict,
        "findings_digest": findings_digest(findings),
        "produced_at": produced_at or _now(),
        "tool": tool,
        "tool_version": tool_version,
        # Carried alongside the signature rather than inside it: the digest is
        # what is signed, so findings cannot change without invalidating it,
        # while a reader can still see what was found.
        "findings": findings,
    }


def sign_attestation(attestation: dict, private_key_pem: bytes) -> dict:
    """Attach an Ed25519 signature over the canonical payload."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_key_pem, password=None)
    signature = key.sign(canonical_attestation_payload(attestation))  # type: ignore[call-arg]
    return {**attestation, "signature": b64encode(signature).decode("ascii")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject-digest", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--verdict", required=True, choices=["pass", "fail"])
    parser.add_argument("--findings", default="[]", help="JSON array of findings")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    attestation = build_attestation(
        inspection_subject_digest=args.subject_digest,
        reviewer=args.reviewer,
        reviewer_key_id=args.key_id,
        inspector_role=args.role,
        verdict=args.verdict,
        findings=json.loads(args.findings),
        tool=args.tool,
        tool_version=args.tool_version,
    )
    signed = sign_attestation(attestation, args.private_key.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(
        json.dumps(signed, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
