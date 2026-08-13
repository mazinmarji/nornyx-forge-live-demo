"""Both approval domains are frozen at bootstrap, and neither leaks the other.

`tests/test_trust_snapshot.py` proved the ACTION snapshot survives a replaced
file. Splitting the domains creates a new way to be wrong that no test there
could see: a context could freeze one domain and rediscover the other, or a
change to one section could travel into the snapshot of its neighbour.

THE PROPERTIES, per domain and across them:

    a bootstrapped context answers from its own snapshot forever
    only an explicit new bootstrap observes a changed document
    changing ONE domain does not move the other, in either direction
    absence, un-migration and malformation stay distinguishable at bootstrap

The last clause matters because all three authorize exactly nothing, so no test
comparing signer sets can tell them apart -- and they call for three different
operator actions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from signing import other_signer, write_trust_store  # noqa: E402

from nornyx_forge.approval_trust import (  # noqa: E402
    ACTION_TRUST_DOMAIN,
    GOVERNANCE_TRUST_DOMAIN,
    ApprovalTrustDomains,
    TrustStoreUnavailable,
)

#: G1/A1 -- the provisioning a context is established with.
G1 = "test-approval-01"
#: G2/A2 -- the provisioning that replaces it on disk afterwards.
G2 = A2 = "test-approval-other"


def _bootstrap(store: Path, monkeypatch) -> ApprovalTrustDomains:
    """Establish a context the way the application does, at a chosen store."""
    from nornyx_forge import subject_bootstrap  # noqa: PLC0415

    monkeypatch.setenv("FORGE_APPROVER_TRUST_STORE", str(store))
    loaded = subject_bootstrap._load_approval_domains(ROOT)
    return ApprovalTrustDomains(
        governance=loaded["governance_approval_trust"],
        action=loaded["action_approval_trust"],
        source=str(store),
    )


def _signers(store) -> list[str]:
    return sorted(store.signers)


def test_replacing_the_document_does_not_move_an_established_context(
    tmp_path: Path, monkeypatch
):
    """The exploit that closed for one domain, re-run against both.

    The file is genuinely replaced between the two observations, so this fails
    if anything downstream reopens it for either authority.
    """
    store = write_trust_store(
        tmp_path / "trust.json",
        governance_roles=("architecture_reviewer",),
        action_roles=("operations_owner",),
    )
    context = _bootstrap(store, monkeypatch)
    assert _signers(context.governance) == [G1]
    assert _signers(context.action) == [G1]

    write_trust_store(
        store,
        governance_extra=(other_signer(("architecture_reviewer",)),),
        action_extra=(other_signer(("operations_owner",)),),
    )

    assert _signers(context.governance) == [G1], "governance trust moved under a context"
    assert _signers(context.action) == [G1], "action trust moved under a context"
    assert G2 not in context.governance.signers
    assert A2 not in context.action.signers


def test_an_explicit_new_bootstrap_observes_both_changes(tmp_path: Path, monkeypatch):
    """A snapshot that could never be refreshed would be its own defect.

    Rotating a key must still work; it must take a deliberate restart rather
    than happening under a running process.
    """
    store = write_trust_store(tmp_path / "trust.json")
    first = _bootstrap(store, monkeypatch)

    write_trust_store(
        store,
        governance_extra=(other_signer(("architecture_reviewer",)),),
        action_extra=(other_signer(("operations_owner",)),),
    )
    second = _bootstrap(store, monkeypatch)

    assert _signers(first.governance) == [G1]
    assert _signers(second.governance) == [G1, G2]
    assert _signers(second.action) == [G1, A2]


def test_changing_one_domain_leaves_the_other_domain_alone(tmp_path: Path, monkeypatch):
    """Independence at the document level, in both directions.

    Two objects read from one file could still share state through a cached
    parse or a common signer map. Each half of this changes exactly one section
    and requires the neighbouring snapshot to be untouched.
    """
    store = tmp_path / "trust.json"
    write_trust_store(store, governance_roles=("architecture_reviewer",),
                      action_roles=("operations_owner",))
    before = _bootstrap(store, monkeypatch)

    # Governance gains a principal. Action must not.
    write_trust_store(
        store,
        governance_roles=("architecture_reviewer",),
        action_roles=("operations_owner",),
        governance_extra=(other_signer(("architecture_reviewer",)),),
    )
    after = _bootstrap(store, monkeypatch)
    assert _signers(after.governance) == [G1, G2]
    assert _signers(after.action) == [G1], "an action grant appeared from a governance edit"
    assert after.governance.digest != before.governance.digest
    assert after.action.digest == before.action.digest, (
        "the action domain's trust identity changed when only governance did"
    )

    # And the reverse.
    write_trust_store(
        store,
        governance_roles=("architecture_reviewer",),
        action_roles=("operations_owner",),
        action_extra=(other_signer(("operations_owner",)),),
    )
    reversed_ = _bootstrap(store, monkeypatch)
    assert _signers(reversed_.action) == [G1, A2]
    assert _signers(reversed_.governance) == [G1], (
        "a governance grant appeared from an action edit"
    )


def test_removing_one_domain_after_bootstrap_leaves_the_context_whole(
    tmp_path: Path, monkeypatch
):
    """Absence after bootstrap must not empty a live snapshot -- either half.

    And a NEW bootstrap over the reduced document must report the removed
    domain as unprovisioned rather than as merely empty, naming the section an
    operator has to restore.
    """
    store = tmp_path / "trust.json"
    write_trust_store(store, governance_roles=("architecture_reviewer",),
                      action_roles=("operations_owner",))
    context = _bootstrap(store, monkeypatch)

    store.write_text(
        json.dumps({"domains": {"action": {"signers": []}}}), encoding="utf-8"
    )

    assert _signers(context.governance) == [G1], "a deleted section emptied a snapshot"
    assert _signers(context.action) == [G1]

    fresh = ApprovalTrustDomains.load(store)
    assert fresh.governance.signers == {}
    assert "declares no 'governance' approval domain" in fresh.governance.source, (
        "a removed domain must say it is unprovisioned, not merely look empty: "
        f"{fresh.governance.source}"
    )
    assert fresh.governance.available is False
    assert fresh.governance.domain == GOVERNANCE_TRUST_DOMAIN


def test_deleting_the_document_leaves_the_context_whole(tmp_path: Path, monkeypatch):
    """Whole-file absence, distinguished from a domain being unprovisioned."""
    store = write_trust_store(tmp_path / "trust.json")
    context = _bootstrap(store, monkeypatch)
    store.unlink()

    assert _signers(context.governance) == [G1]
    assert _signers(context.action) == [G1]

    fresh = ApprovalTrustDomains.load(store)
    assert fresh.governance.signers == {} and fresh.action.signers == {}
    assert fresh.governance.available is False and fresh.action.available is False
    assert str(store) in fresh.governance.source


def test_a_malformed_replacement_refuses_at_the_new_bootstrap_only(
    tmp_path: Path, monkeypatch
):
    """Invalidity is a third state, and it must not reach an established context.

    The exact diagnostic is pinned: a mutation replacing it with an empty string
    survived until a test read it, because "nobody is trusted" and "the trust
    material is damaged" authorize the same amount.
    """
    store = write_trust_store(tmp_path / "trust.json")
    context = _bootstrap(store, monkeypatch)
    store.write_text("{ this is not json", encoding="utf-8")

    assert _signers(context.governance) == [G1]
    assert _signers(context.action) == [G1]

    with pytest.raises(TrustStoreUnavailable, match="is unreadable"):
        ApprovalTrustDomains.load(store)

    # Through the bootstrap path both domains report the damage, and each says
    # which authority it is for -- one half silently reading as "no approvers
    # provisioned" would be the confusion in the domain nobody looked at.
    reloaded = _bootstrap(store, monkeypatch)
    for store_obj, expected in (
        (reloaded.governance, GOVERNANCE_TRUST_DOMAIN),
        (reloaded.action, ACTION_TRUST_DOMAIN),
    ):
        assert store_obj.signers == {}
        assert store_obj.domain == expected
        assert "unreadable" in store_obj.source, store_obj.source


def test_an_undomained_document_refuses_rather_than_granting_both(tmp_path: Path):
    """The migration case, which is where a shortcut would be most tempting.

    A store listing `signers` with no domains cannot answer a per-domain
    question. Reading it as both is the exact grant this split removes, and
    reading it as neither would look like an unprovisioned deployment. It is
    refused, with the shape to fix it.
    """
    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps({"signers": [other_signer(("operations_owner",))]}), encoding="utf-8"
    )

    with pytest.raises(TrustStoreUnavailable) as refusal:
        ApprovalTrustDomains.load(legacy)
    assert "declares no authority domains" in str(refusal.value)
    assert '"governance"' in str(refusal.value), "the refusal does not say how to fix it"


def test_a_misspelled_domain_is_refused_rather_than_ignored(tmp_path: Path):
    """A section nobody reads looks provisioned and grants nothing.

    That failure mode is worse than an outright error: an operator believes a
    key is trusted, no refusal ever mentions it, and the authority is simply
    missing.
    """
    typo = tmp_path / "typo.json"
    typo.write_text(
        json.dumps(
            {
                "domains": {
                    "governance": {"signers": []},
                    "actions": {"signers": [other_signer(("operations_owner",))]},
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(TrustStoreUnavailable, match="unknown authority domains"):
        ApprovalTrustDomains.load(typo)


def test_no_authorization_path_rediscovers_either_domain():
    """Structural: authority discovery is a bootstrap act, consumption is not.

    The behavioural tests above pass while a second, unused load site sits in a
    module waiting to be called. This asserts the shape -- outside the
    constructor and the bootstrap loader, nothing in the runtime reaches for a
    trust document at all.
    """
    import ast  # noqa: PLC0415

    offenders: list[str] = []
    for module, allowed in (
        ("src/nornyx_forge/nornyx_runtime.py", {"__init__"}),
        ("src/nornyx_forge/subject_bootstrap.py", {"_load_approval_domains"}),
    ):
        tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name in allowed:
                continue
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "load"
                    and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id
                    in {"ApprovalTrustStore", "ApprovalTrustDomains"}
                ):
                    offenders.append(f"{module}:{node.name}:{inner.lineno}")
    assert offenders == [], (
        "these functions load approval trust outside bootstrap, so a request "
        f"could rediscover the authority that judges it: {offenders}"
    )
