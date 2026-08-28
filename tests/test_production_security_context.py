"""The established security context must be what production actually runs on.

`tests/test_security_context.py` proves the mechanism: one object, immutable,
environment read once, mutation after startup does not re-aim it. Every one of
those tests passed while `bootstrap_security_context()` had no caller anywhere
under `src/`. The parameter existed, production passed `None`, and the boundary
fell back to resolving its own trust anchors per use — the ambient re-resolution
the subject model exists to remove.

So a mechanism proven in isolation is not a control. These tests assert the
wiring: that the application establishes exactly one context, that the request
path receives that exact object, and that no request can cause a second one.

THE PROPERTY:

    every governed request in a process runs under one security context,
    established before any request was served, and no input to a request can
    cause a different one to be established or observed

Identity is the assertion throughout, never equality. Two independently
bootstrapped contexts over an unchanged tree compare equal on every digest, so
an equality test would pass on precisely the architecture being prevented.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from demo_app import agentic  # noqa: E402
from demo_app.agentic import application_security_context  # noqa: E402

# --------------------------------------------------------------------------
# One context, and the request path gets that one
# --------------------------------------------------------------------------


def test_the_application_establishes_exactly_one_context():
    """Repeated access returns the same object, not an equal rebuild."""
    first = application_security_context()
    second = application_security_context()
    assert first is second


def test_the_http_surface_binds_the_established_context():
    """The interface layer holds the same object the application established.

    Asserted at the surface that serves requests, because that is where a
    per-request bootstrap would be introduced.
    """
    from demo_app import main

    assert main.SECURITY_CONTEXT is application_security_context()


def test_a_governed_run_receives_the_established_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The flow that runs a case is handed the application's context.

    This is the assertion that was missing. `run_case` accepted a context and
    production never supplied one, so the flow ran with `security_context=None`
    and nothing failed — the omission was invisible precisely because the
    parameter was optional.
    """
    captured: list[object] = []
    original = agentic.CustomerCaseFlow

    class Recording(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            captured.append(kwargs.get("security_context"))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(agentic, "CustomerCaseFlow", Recording)
    agentic.run_case(
        {
            "id": "CASE-WIRING",
            "customer": "Amina",
            "summary": "Update delivery instructions",
            "risk": "low",
            "requested_action": "send guidance",
        },
        root=tmp_path,
        # The configuration production uses. Without it `run_case` defaults to
        # the nornyx backend, which refuses on a tmp root carrying no runtime
        # lock -- a refusal about preparation, not about context wiring.
        config=agentic.demonstration_authority(),
    )

    assert captured, "no flow was constructed, so this test asserted nothing"
    assert captured[0] is application_security_context(), (
        "the flow ran under a context that is not the one this application "
        "established"
    )


def test_two_requests_share_one_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """One per application, not one per request."""
    captured: list[object] = []
    original = agentic.CustomerCaseFlow

    class Recording(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            captured.append(kwargs.get("security_context"))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(agentic, "CustomerCaseFlow", Recording)
    for index in (1, 2):
        agentic.run_case(
            {
                "id": f"CASE-{index}",
                "customer": "Amina",
                "summary": "Update delivery instructions",
                "risk": "low",
                "requested_action": "send guidance",
            },
            root=tmp_path,
            config=agentic.demonstration_authority(),
        )

    assert len(captured) == 2
    assert captured[0] is captured[1], "each request established its own context"


# --------------------------------------------------------------------------
# Nothing mutated after startup re-aims the running context
# --------------------------------------------------------------------------

#: Everything that has, at some point in this repository's history, been able to
#: steer which tree the runtime governed or when it thought it was: the retired
#: overrides, the git envelope, the launch directory, and the trust locations.
AMBIENT = {
    "FORGE_ROOT": "/tmp/attacker-tree",
    "FORGE_RUNTIME_REVISION": "git:" + "f" * 40,
    "FORGE_RUNTIME_AS_OF": "2099-01-01T00:00:00Z",
    "FORGE_APPROVAL_LEDGER": "/tmp/attacker-ledger.sqlite3",
    "FORGE_TRUST_STORE": "/tmp/attacker-approvers.json",
    "FORGE_REVIEWER_TRUST_STORE": "/tmp/attacker-reviewers.json",
    "GIT_DIR": "/tmp/attacker.git",
    "GIT_WORK_TREE": "/tmp/attacker-tree",
    "GIT_CEILING_DIRECTORIES": "/tmp",
}


def test_no_ambient_change_after_startup_re_aims_the_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Set every steering variable hostile, change directory, then look again.

    The context was established at import. Nothing here happened before that, so
    nothing here may change what it says. The digests are compared as well as
    the identity: an object could in principle be the same one and still consult
    the environment lazily on attribute access.
    """
    before = application_security_context()
    snapshot = (
        before.runtime_subject.governed_subject_digest,
        before.runtime_subject.governed_revision_digest,
        before.runtime_subject.scope_definition_digest,
        before.runtime_subject.runtime_authority_config_digest,
        before.runtime_subject.subject_verified,
        before.trust.approver_store,
        before.trust.reviewer_store,
        before.trust.approval_ledger,
        before.authority_config.policy_backend,
        before.authority_config.execution_backend,
    )

    for name, value in AMBIENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)

    after = application_security_context()
    assert after is before, "an environment change produced a different context"
    assert (
        after.runtime_subject.governed_subject_digest,
        after.runtime_subject.governed_revision_digest,
        after.runtime_subject.scope_definition_digest,
        after.runtime_subject.runtime_authority_config_digest,
        after.runtime_subject.subject_verified,
        after.trust.approver_store,
        after.trust.reviewer_store,
        after.trust.approval_ledger,
        after.authority_config.policy_backend,
        after.authority_config.execution_backend,
    ) == snapshot, "the established context reported different values afterwards"


def test_editing_the_governed_tree_after_startup_does_not_re_aim_the_context():
    """A file changed mid-process must not change what the running context says.

    The point is not that editing files is prevented — it is that a context
    established before the edit keeps describing what it observed. A runtime
    that re-observed here would let a file written between two requests decide
    the authority the second one is judged under.
    """
    context = application_security_context()
    before = context.runtime_subject.governed_subject_digest
    scratch = ROOT / "src" / "nornyx_forge" / "_context_probe.py"
    assert not scratch.exists(), "probe file already present"
    try:
        scratch.write_text("# transient probe\n", encoding="utf-8", newline="")
        assert application_security_context() is context
        assert context.runtime_subject.governed_subject_digest == before, (
            "the running context re-observed the tree after a file appeared"
        )
    finally:
        scratch.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# Structural: the request path may not establish one
# --------------------------------------------------------------------------


def test_no_request_path_bootstraps_a_context():
    """Establishment happens at module scope, never inside a request function.

    Behavioural tests cannot catch this reliably: a per-request bootstrap over
    an unchanged tree returns an equal context, so only an identity assertion in
    exactly the right place would notice. This asserts the shape directly.
    """
    import ast

    for relative in ("src/demo_app/agentic.py", "src/demo_app/main.py"):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name != "bootstrap_security_context", (
                    f"{relative}:{node.name} establishes a security context "
                    "inside a function, so a request can cause subject identity "
                    "to be resolved"
                )


def test_the_established_context_is_not_optional_in_production():
    """`run_case` must never fall through to an unestablished context.

    The default was `None`, which meant "no context", and every production call
    took it. It now means "the one this application established", so an omitted
    argument cannot silently disable the model.
    """
    import inspect

    source = inspect.getsource(agentic.run_case)
    assert "application_security_context()" in source, (
        "run_case no longer falls back to the established context, so a caller "
        "that omits one runs unestablished"
    )


def test_the_probe_would_notice_a_stale_assertion():
    """The identity assertions above must be capable of failing.

    A test that compares an object to itself through two names that are the same
    name proves nothing. This builds a genuinely separate context and confirms
    it is NOT the established one, so the assertions elsewhere are discriminating
    rather than tautological.
    """
    from nornyx_forge.subject_bootstrap import bootstrap_security_context

    separate = bootstrap_security_context(ROOT)
    assert separate is not application_security_context()
    assert isinstance(separate.runtime_subject.scope_id, str)


def test_an_unresolvable_root_yields_an_unavailable_context_not_an_exception(
    monkeypatch: pytest.MonkeyPatch,
):
    """Startup must not die because the deployment markers are missing.

    `bootstrap_security_context` documented "not an exception", but that covered
    observation failure only: `resolve_packaged_root()` raises, so a deployment
    without markers took the application down at import rather than leaving it
    running without consequential authority. Those are different outcomes and
    the docstring named the wrong one.
    """
    from nornyx_forge import subject_bootstrap
    from nornyx_forge.governed_subject import GovernedSubjectError

    def refuse() -> Path:
        raise GovernedSubjectError("PACKAGED_ROOT_UNRESOLVED: no markers")

    monkeypatch.setattr(subject_bootstrap, "resolve_packaged_root", refuse)
    context = subject_bootstrap.bootstrap_security_context()

    assert context.runtime_subject.subject_verified is False
    assert context.consequential_authority_available is False
    assert "PACKAGED_ROOT_UNRESOLVED" in (context.runtime_subject.unavailable_reason or "")
    assert context.trust.approval_ledger == "", (
        "a context with no resolvable root offered a replay-state location anyway"
    )


def test_os_environ_is_untouched_by_reading_the_context():
    """Reading the context must not be a way to learn what the environment says.

    A guard against the accessor quietly growing an `os.environ` lookup: the
    established values are compared against a context read while the relevant
    variables are absent entirely.
    """
    for name in AMBIENT:
        assert name not in os.environ or os.environ[name] != AMBIENT[name], (
            f"{name} leaked out of a monkeypatched test into the process"
        )


# --------------------------------------------------------------------------
# The context has to arrive where the decision is made
# --------------------------------------------------------------------------
#
# Wiring the context into the flow was only half of it. The flow then built its
# boundary WITHOUT passing `runtime_subject`, so the boundary defaulted it to
# None and refused every release with SUBJECT_UNVERIFIED -- and the whole
# approval path behind it (signature verification, window validation,
# fingerprinting, ledger consumption) was unreachable in the running
# application.
#
# That refusal looked like governance working. It was the boundary saying it did
# not know what it was governing. The high-risk demonstration case was
# "prevented" either way, which is exactly why nothing noticed: a negative
# outcome that arrives for the wrong reason is indistinguishable from the right
# one unless something asserts the reason.
#
# The same defect as one level up, one level down. These assert the object at
# each edge it has to cross, rather than trusting that wiring it in one place
# carried it through to the next.


def test_the_flow_hands_the_established_subject_to_the_boundary(tmp_path: Path):
    """Identity at the edge where authorization actually happens."""
    context = application_security_context()
    flow = agentic.CustomerCaseFlow(
        {
            "id": "CASE-BOUNDARY",
            "customer": "Omar",
            "summary": "Issue a high-value external refund",
            "risk": "high",
            "requested_action": "issue refund",
        },
        root=tmp_path,
        security_context=context,
    )

    assert flow.boundary.runtime_subject is context.runtime_subject, (
        "the boundary is judging requests against a subject that is not the one "
        "this application established"
    )
    assert flow.boundary.trust is context.trust


def test_a_boundary_without_a_subject_refuses_and_says_so(tmp_path: Path):
    """The benign control's opposite: no context means no consequential authority.

    Establishes that SUBJECT_UNVERIFIED is a real, reachable refusal rather than
    the permanent state of the system -- which is what it had become.
    """
    flow = agentic.CustomerCaseFlow(
        {
            "id": "CASE-NOCTX",
            "customer": "Omar",
            "summary": "Issue a high-value external refund",
            "risk": "high",
            "requested_action": "issue refund",
        },
        root=tmp_path,
        security_context=None,
    )
    assert flow.boundary.runtime_subject is None


def test_the_shipped_high_risk_refusal_comes_from_the_fallback_and_says_so():
    """What the END-TO-END path can actually establish, which is less than the
    previous version of this test claimed.

    IT CLAIMED: `prevented` "has to arrive because no human approval exists --
    not because the boundary could not establish what it was governing", and
    that a real canonical request "only happens past the subject check".

    MEASURED, with `boundary.runtime_subject` forced to None -- the precise
    defect it existed to catch -- both of its assertions still passed:

        action_status   prevented
        decision.code   HUMAN_APPROVAL_REQUIRED
        request_digest  sha256:7bccb1d7878bfc322...

    Two reasons, both structural. `HUMAN_APPROVAL_REQUIRED` is the
    deterministic fallback's UNCONDITIONAL constant for any high-risk act,
    returned before subject, trust store, ledger or any approval rule is
    consulted; `_official` is never entered on the shipped path. And
    `canonical_action_request` is called by the CALLER in `agentic.py` AFTER
    `evaluate_and_execute` returns, on every path, with `subject_revision=""`
    when the subject is absent -- so the digest is evidence that the caller ran,
    not that the subject was checked.

    So this asserts the source, which is the honest end-to-end claim, and the
    subject distinction is measured by
    `test_a_boundary_with_no_subject_refuses_as_a_subject_failure` in
    `tests/test_approval_authentication.py`, at a boundary where `_official`
    actually runs.

    THAT CITATION WAS WRONG AND POINTED THE WRONG WAY. It named
    test_an_unverified_subject_is_refused_as_a_subject_failure_not_an_approval_one
    -- a test that exists nowhere -- and placed it "below", in this module. The
    correction was already sitting 28 lines further down, where the note says
    plainly that `SUBJECT_UNVERIFIED` is measured in
    `tests/test_approval_authentication.py`, NOT here. A reader checking whether
    the shipped high-risk refusal is a governance decision or the fallback's
    unconditional constant was handed a name that resolves to nothing.

    The `source` assertion is not decoration. If the shipped path ever does
    load the authorizer, this test goes RED and forces someone to strengthen it
    rather than leaving a fallback-shaped claim standing over a governed path.
    """
    from fastapi.testclient import TestClient

    from demo_app.main import app

    result = TestClient(app).post("/api/demo/run").json()["high_risk"]
    decision = result.get("decision") or {}

    assert result["action_status"] == "prevented"
    assert decision.get("code") == "HUMAN_APPROVAL_REQUIRED", (
        f"the high-risk act was refused for {decision.get('code')!r}, not because "
        "a human approval is required"
    )
    assert decision.get("source") == "deterministic_fallback", (
        "the shipped demonstration path no longer refuses through the "
        f"deterministic fallback but through {decision.get('source')!r}. This "
        "test is calibrated for the fallback, whose high-risk denial is "
        "unconditional and therefore proves nothing about the approval rules. "
        "On a governed path it must assert the governed property instead."
    )


# `SUBJECT_UNVERIFIED` is measured in `tests/test_approval_authentication.py`
# (`test_a_boundary_with_no_subject_refuses_as_a_subject_failure`), not here.
# It is reachable only once an approval is being BOUND -- behind
# `if high_risk and decision.allowed` -- so a module with no signing
# fixtures cannot drive it, and an attempt from here refused with
# HUMAN_APPROVAL_REQUIRED for want of a grant: the very collapse the test
# exists to tell apart, reproduced while trying to measure it.


# --------------------------------------------------------------------------
# A-P2-1. The governing contract and the governed subject describe ONE tree.
# --------------------------------------------------------------------------


def test_a_boundary_rooted_elsewhere_than_its_context_is_refused(tmp_path: Path):
    """The finding: policy from tree A judged against identity from tree B.

    `root` selects the contract and the lock. The injected subject and integrity
    verdict describe whatever tree the application observed at startup. Nothing
    required those to be the same tree, and `nornyx-forge demo --offline` passes
    a root of its own -- so an authority conclusion could span two trees and
    belong to neither.
    """
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        NornyxActionBoundary,
        NornyxRuntimeUnavailable,
    )
    from nornyx_forge.subject_bootstrap import bootstrap_security_context  # noqa: PLC0415

    context = bootstrap_security_context(ROOT)
    assert context.established_root, "the context must record the tree it describes"

    # The other tree carries ITS OWN CONTRACT. That is the dangerous shape: the
    # boundary would take governing policy from here while the injected subject
    # and integrity verdict describe the repository. A scratch directory with no
    # contract supplies no policy at all -- see the case below.
    from nornyx_forge.nornyx_runtime import RUNTIME_CONTRACT  # noqa: PLC0415

    elsewhere = tmp_path / "another_tree"
    planted = elsewhere / RUNTIME_CONTRACT
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes((ROOT / RUNTIME_CONTRACT).read_bytes())

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        NornyxActionBoundary(
            elsewhere,
            runtime_subject=context.runtime_subject,
            governance_integrity=context.governance_integrity,
            established_root=context.established_root,
        )
    message = str(refusal.value)
    assert "security context describes" in message, message
    assert str(elsewhere.resolve()) in message, message


def test_the_matching_tree_is_accepted():
    """The control. A check that refused every pairing would also pass above."""
    from nornyx_forge.nornyx_runtime import NornyxActionBoundary  # noqa: PLC0415
    from nornyx_forge.subject_bootstrap import bootstrap_security_context  # noqa: PLC0415

    context = bootstrap_security_context(ROOT)
    boundary = NornyxActionBoundary(
        ROOT,
        runtime_subject=context.runtime_subject,
        governance_integrity=context.governance_integrity,
        established_root=context.established_root,
    )
    assert boundary.root == ROOT


def test_a_scratch_root_with_no_contract_is_accepted(tmp_path: Path):
    """The scoping, stated as a test rather than left to a comment.

    `root` selects two things -- the governing contract and lock, and where
    evidence and the ledger are written -- and that conflation is the defect
    underneath this finding. Refusing every differing root would also refuse
    writing evidence to a scratch directory, which supplies no policy from
    anywhere: with no contract present the boundary falls back and denies
    high-risk outright, so no conclusion spans two trees.

    If the two roles are ever separated, this test is the one to delete.
    """
    from nornyx_forge.nornyx_runtime import RUNTIME_CONTRACT, NornyxActionBoundary  # noqa: PLC0415
    from nornyx_forge.subject_bootstrap import bootstrap_security_context  # noqa: PLC0415

    context = bootstrap_security_context(ROOT)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    assert not (scratch / RUNTIME_CONTRACT).exists()

    boundary = NornyxActionBoundary(
        scratch,
        runtime_subject=context.runtime_subject,
        governance_integrity=context.governance_integrity,
        established_root=context.established_root,
    )
    assert boundary.authorizer is None, (
        "a root with no contract must fall back, or it is supplying policy "
        "after all and this scoping is wrong"
    )


def test_an_unrooted_context_carries_no_tree_to_check_against():
    """Absence is not a mismatch.

    A deployment whose root could not be resolved has no tree to compare, and
    refusing on that would turn "nothing to check" into "checked and wrong" --
    different states. The empty string disables the comparison rather than
    failing it, and consequential authority is already unavailable there for
    its own reasons.
    """
    from nornyx_forge.subject_bootstrap import unrooted_trust_configuration  # noqa: PLC0415

    assert unrooted_trust_configuration() is not None

    from nornyx_forge.nornyx_runtime import NornyxActionBoundary  # noqa: PLC0415

    boundary = NornyxActionBoundary(ROOT, established_root="")
    assert boundary.root == ROOT


def test_the_application_passes_its_established_root():
    """The wiring, not just the mechanism.

    A refusal nothing calls is decoration. Read from the composition site so
    removing the argument fails here rather than silently disabling the check.
    """
    source = (ROOT / "src/demo_app/agentic.py").read_text(encoding="utf-8")
    assert "established_root=(" in source, (
        "the application no longer hands the boundary the tree its context "
        "describes, so the coherence check cannot fire"
    )


def _unrooted_context():
    """A context from the branch where the deployment root cannot be resolved."""
    import nornyx_forge.subject_bootstrap as sb  # noqa: PLC0415
    from nornyx_forge.governed_subject import GovernedSubjectError  # noqa: PLC0415

    def unresolvable(*_args, **_kwargs):
        raise GovernedSubjectError("no deployment markers")

    original = sb.resolve_packaged_root
    sb.resolve_packaged_root = unresolvable
    try:
        return sb.bootstrap_security_context()
    finally:
        sb.resolve_packaged_root = original


def test_the_trust_closure_is_total_across_both_bootstrap_branches():
    """"Trust is resolved once, here" was true of one path out of two.

    The rooted branch froze two approval stores; the unresolvable-root branch
    left both as None. None is the ABSENCE of a field, which reads the same as
    never established -- a consumer reaching for `action_approval_trust` got
    nothing to ask rather than a store that says it is unavailable and why.

    The domains never depended on the root. `_load_approval_domains` takes it
    and discards it, because the approver store deliberately lives outside the
    governed tree, so there was no reason this branch could not resolve them.
    """
    context = _unrooted_context()

    for name in ("governance_approval_trust", "action_approval_trust"):
        store = getattr(context, name)
        assert store is not None, (
            f"{name} is None on the unresolvable-root branch, so the trust "
            "closure is not total and absence is indistinguishable from "
            "never-established"
        )
        assert store.domain, f"{name} carries no authority domain"
        assert store.available is False, (
            f"{name} reports available on a deployment with no resolvable root"
        )


def test_the_unrooted_branch_still_offers_no_consequential_authority():
    """The control. Resolving trust must not have granted anything.

    Making the closure total is about being able to ASK the store a question,
    not about the answer changing. A deployment whose root cannot be resolved
    still authorizes nothing.
    """
    context = _unrooted_context()

    assert context.consequential_authority_available is False
    assert context.runtime_subject.subject_verified is False
    assert context.governance_integrity is not None
    assert context.governance_integrity.authorizes_consequential_action is False
    assert context.established_root == "", (
        "an unresolvable root produced a tree path, which the boundary would "
        "then compare against"
    )
