"""Drive the production flow and report what its evidence stream recorded.

Run as a subprocess against a nominated `src` so the pristine and the reverted
module are exercised by BYTE-IDENTICAL driver code -- the only difference
between the two runs is the module under test.

    argv[1]  the src tree to import from
    argv[2]  the risk of the act
    argv[3]  "grant" to supply a real signed approval, "none" otherwise
"""
import json
import sys
import tempfile
from pathlib import Path

SRC, RISK, APPROVE = sys.argv[1], sys.argv[2], sys.argv[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, SRC)

# THE MODULE UNDER TEST IS IMPORTED FIRST, AND THEN CHECKED.
#
# tests/test_governance_failure.py inserts the REAL `src` at `sys.path[0]` when
# it is imported, so anything imported after it resolves to the repository
# rather than to the tree named on the command line. That is how this driver
# came to measure the pristine module while reporting a mutant: `ruff --fix`
# sorted these imports alphabetically, `demo_app` moved below that module, and
# the revert control silently changed what it was about.
#
# Order alone is too fragile to rest a mutation control on -- it is one lint
# pass from being wrong again, and nothing would say so. So the origin is
# ASSERTED below and reported in the result, and the test asserts it too.
# `isort: off` keeps the order; the check is what makes the order unnecessary.
#
# isort: off
from demo_app.agentic import CustomerCaseFlow  # noqa: E402
from nornyx_forge.nornyx_runtime import (  # noqa: E402
    EXTERNAL_TRUST_ZONE,
    ActionDescriptor,
    canonical_action_request,
    exercised_capability,
)
# isort: on

import demo_app.agentic as _under_test  # noqa: E402

_ORIGIN = Path(_under_test.__file__).resolve()
if not _ORIGIN.is_relative_to(Path(SRC).resolve()):
    raise SystemExit(
        "MUTANT ORIGIN WRONG: this driver was asked to exercise "
        + str(Path(SRC).resolve()) + " and imported " + str(_ORIGIN)
        + ". Whatever it measured would be attributed to the wrong tree."
    )

from signing import signed_grant  # noqa: E402
from test_governance_failure import _permissive_boundary  # noqa: E402

NOW = "2026-08-03T00:00:00Z"
root = Path(tempfile.mkdtemp(prefix="capname-"))
case = {
    "id": "CASE-REFUND",
    "customer": "Omar",
    "risk": RISK,
    "summary": "Issue a high-value external refund",
    "requested_action": "issue refund",
}
flow = CustomerCaseFlow(
    dict(case), root=root, worker_mode="deterministic", allow_policy_fallback=True
)
flow.boundary = _permissive_boundary(root, as_of=NOW)

if APPROVE == "grant":
    subject = flow.boundary.runtime_subject
    request = canonical_action_request(
        mission_id=flow.mission_id,
        risk=RISK,
        subject_revision=subject.governed_subject_digest,
        subject_scope_id=subject.scope_id,
        governed_revision_digest=subject.governed_revision_digest,
        descriptor=ActionDescriptor(
            operation="issue refund",
            resource="Omar",
            destination=EXTERNAL_TRUST_ZONE,
            parameters={
                "case_id": "CASE-REFUND",
                "risk": RISK,
                "summary": "Issue a high-value external refund",
            },
        ),
        attempt=1,
    )
    flow.action_approval = signed_grant(request, approval_id="ACT-REFUND")

flow.run_sequential()
recorded = [
    json.loads(line)
    for line in (root / "evidence/runtime/events.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
print(json.dumps({
    "module": str(_ORIGIN),
    "action_status": flow.case["action_status"],
    "effect": flow.case["decision"]["effect"],
    "code": flow.case["decision"]["code"],
    "derivation": exercised_capability(RISK),
    "capabilities": [
        {"event": e["event_type"], "capability": e["capability"]}
        for e in recorded if e["capability"]
    ],
}))
