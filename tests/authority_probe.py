"""Drive BOTH approval authorities and report what actually happened.

Run as a subprocess against a copy of `src/` so a MUTATED build can be measured
without the unmutated package already sitting in `sys.modules`. In-process
monkeypatching cannot do this: it can replace a function, but it cannot answer
"would this change to the source release an effect", which is the only question
a mutation catalogue is asking.

    python tests/authority_probe.py <workdir> <scenario> [--expire] [--rebind]

Prints one JSON object. Every field is an OBSERVED outcome -- the effect, the
callback count, whether the ledger was spent -- because a negative security
result proven by a verdict string alone has been wrong here before.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

#: Governance-only vocabulary, action-only vocabulary, and the overlap.
GOVERNANCE_ROLE = "architecture_reviewer"
ACTION_ROLE = "operations_owner"
SHARED_ROLE = "network_governance_owner"

#: Each scenario is a provisioning plus the role the artifacts claim. They are
#: chosen so that a mutation has somewhere to show: a case whose authentication
#: already fails proves nothing about an authority clause downstream of it.
SCENARIOS = {
    # The key holds GOVERNANCE trust only. Action must refuse it, and the
    # action domain is provisioned with somebody else so the refusal names the
    # key rather than reporting an empty store.
    "governance_only": {
        "governance": (SHARED_ROLE,),
        "action": (),
        "action_extra": (ACTION_ROLE,),
        "claim": SHARED_ROLE,
    },
    # The mirror.
    "action_only": {
        "governance": (),
        "action": (ACTION_ROLE,),
        "governance_extra": (GOVERNANCE_ROLE,),
        "claim": ACTION_ROLE,
    },
    # Trusted in the ACTION domain, but holding a GOVERNANCE-only role. Every
    # clause before authority succeeds, so a refusal can only be the role
    # vocabulary -- which is what a "generic authenticator is enough" mutation
    # removes.
    "action_domain_governance_role": {
        "governance": (),
        "action": (GOVERNANCE_ROLE,),
        "claim": GOVERNANCE_ROLE,
    },
    # The governance mirror: trusted for governance, claiming an action role.
    "governance_domain_action_role": {
        "governance": (ACTION_ROLE,),
        "action": (),
        "claim": ACTION_ROLE,
    },
    # Trusted in the action domain, claiming a role that IS an action role but
    # that this key does not hold. Isolates the second clause -- the domain
    # trusting this key to speak in that role -- from the first.
    "action_domain_unheld_role": {
        "governance": (),
        "action": (ACTION_ROLE,),
        "claim": SHARED_ROLE,
    },
}


def main() -> None:
    work = Path(sys.argv[1])
    scenario = SCENARIOS[sys.argv[2]]
    expire = "--expire" in sys.argv
    rebind = "--rebind" in sys.argv

    from signing import other_signer, signed_grant, write_trust_store

    from nornyx_forge import subject_bootstrap
    from nornyx_forge.approval_trust import verify_governance_approval
    from nornyx_forge.nornyx_runtime import canonical_action_request

    store = write_trust_store(
        work / "trusted_approvers.json",
        governance_roles=scenario["governance"],
        action_roles=scenario["action"],
        governance_extra=(
            (other_signer(scenario["governance_extra"]),)
            if scenario.get("governance_extra")
            else ()
        ),
        action_extra=(
            (other_signer(scenario["action_extra"],),)
            if scenario.get("action_extra")
            else ()
        ),
    )

    # Through the BOOTSTRAP path, so a mutation to the composition root -- one
    # domain assigned from the other -- is inside what this measures.
    import os

    os.environ["FORGE_APPROVER_TRUST_STORE"] = str(store)
    loaded = subject_bootstrap._load_approval_domains(work)

    result: dict[str, object] = {"scenario": sys.argv[2]}

    # ---- GOVERNANCE authority -------------------------------------------
    from governance_artifacts import governance_approval, now_window

    generated, expires, as_of = now_window()
    decision = verify_governance_approval(
        governance_approval(scenario["claim"], generated, expires),
        trust_store=loaded["governance_approval_trust"],
        as_of=as_of,
    )
    result["governance_granted"] = bool(decision.granted)
    result["governance_reason"] = decision.reason

    # ---- ACTION authority, at the real effect boundary -------------------
    from test_governance_failure import TEST_REVISION, _permissive_boundary

    from nornyx_forge.nornyx_runtime import ActionDescriptor

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    boundary = _permissive_boundary(
        work,
        # `signed_grant` fixes its window at 2026-08-02..05. Judging it from
        # outside that window is how the binding-and-time half is made to fail
        # while authentication and roles still succeed.
        as_of="2026-08-10T00:00:00Z" if expire else "2026-08-03T00:00:00Z",
        action_trust=loaded["action_approval_trust"],
    )
    request = canonical_action_request(
        mission_id="CASE-PROBE", risk="high",
        subject_revision=TEST_REVISION, descriptor=descriptor, attempt=1,
    )
    # A grant bound to a DIFFERENT attempt: authentication and roles pass, the
    # request binding does not.
    bound_to = canonical_action_request(
        mission_id="CASE-PROBE", risk="high",
        subject_revision=TEST_REVISION, descriptor=descriptor, attempt=2,
    ) if rebind else request

    calls: list[str] = []
    verdict, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-PROBE",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            bound_to, approval_id="ACT-PROBE", role=scenario["claim"]
        ),
        action_descriptor=descriptor,
        attempt=1,
    )
    result["action_effect"] = verdict.effect
    result["action_reason"] = verdict.reason
    result["calls"] = len(calls)
    result["spent"] = (
        boundary.approval_ledger.lookup(request_digest=request.digest) is not None
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
