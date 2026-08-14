"""Every way the two approval domains could be collapsed back into one.

The separation is worth exactly as much as the evidence that removing it is
visible. These fourteen mutations are the plausible collapses -- the assignment
a refactor would make, the merge a "simplification" would reach for, the
inheritance an implementation would think helpful -- applied to real source and
driven through the real authorities.

A mutation counts as KILLED only when the mutant RUNS TO COMPLETION and the
named authority property changes. A syntax error, an import failure, or a
refusal produced by some unrelated clause earns nothing; those are how a
catalogue reports green while proving nothing.

Two directions of change both count, and they are not the same finding:

    a CROSS GRANT   -- the mutant grants an authority the pristine build refuses
    a LOST AUTHORITY -- the mutant refuses one the pristine build grants

The first is the vulnerability. The second is the collateral damage a collapse
does to the domain it was not aimed at, and it is the reason "just use one
store" is not a simplification.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from mutation import InvalidMutation, Mutation, probe  # noqa: E402

RUNTIME = "src/nornyx_forge/nornyx_runtime.py"
TRUST = "src/nornyx_forge/approval_trust.py"
BOOTSTRAP = "src/nornyx_forge/subject_bootstrap.py"

CATALOGUE = (
    Mutation(
        name="M1 governance trust assigned from action",
        edits=((BOOTSTRAP,
                '"governance_approval_trust": domains.governance,',
                '"governance_approval_trust": domains.action,', 1),),
        scenario="governance_only",
        observable="governance_granted", expected=False,
        why="the composition root hands one domain the other's membership",
    ),
    Mutation(
        name="M2 action trust assigned from governance",
        edits=((BOOTSTRAP,
                '"action_approval_trust": domains.action,',
                '"action_approval_trust": domains.governance,', 1),),
        scenario="action_only",
        observable="action_effect", expected="DENY",
        why="the mirror, and it costs the action domain its authority",
    ),
    Mutation(
        name="M3 both domains wrap one unrestricted principal set",
        edits=((TRUST,
                "            body = domains[name]",
                "            body = {\"signers\": [s for d in domains.values()"
                " for s in d.get(\"signers\", [])]}", 1),),
        scenario="governance_only",
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="the union is cosmetic separation: two objects, one membership",
    ),
    Mutation(
        name="M4 governance verifier consults the action domain",
        edits=((TRUST,
                "        trust_domain=GOVERNANCE_TRUST_DOMAIN,",
                "        trust_domain=ACTION_TRUST_DOMAIN,", 1),),
        scenario="governance_only",
        observable="governance_granted", expected=False,
        why="the store carries its domain, so asking it the wrong question refuses",
    ),
    Mutation(
        name="M5 action verifier consults the governance domain",
        edits=((TRUST,
                "        trust_domain=ACTION_TRUST_DOMAIN,",
                "        trust_domain=GOVERNANCE_TRUST_DOMAIN,", 1),),
        scenario="action_only",
        observable="action_effect", expected="DENY",
        why="the mirror at the action authenticator",
    ),
    Mutation(
        name="M6 action boundary stops at the generic authenticator",
        edits=((RUNTIME,
                '    claimed_role = signer.claimed_role or ""',
                "    return AuthorityDecision(\n"
                "        ACTION_TRUST_DOMAIN, True, signer.reason, evidence\n"
                "    )\n"
                '    claimed_role = signer.claimed_role or ""', 1),),
        scenario="action_domain_governance_role",
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="authentication read as authority releases a governance-only role",
    ),
    Mutation(
        name="M7 governance adoption stops at the generic authenticator",
        edits=((TRUST,
                "    claimed_role = signer.claimed_role\n",
                "    return AuthorityDecision(\n"
                "        GOVERNANCE_TRUST_DOMAIN, True, signer.reason, evidence\n"
                "    )\n"
                "    claimed_role = signer.claimed_role\n", 1),),
        scenario="governance_domain_action_role",
        observable="governance_granted", expected=True,
        why="the same confusion on the governance side",
    ),
    Mutation(
        name="M8 the authenticator's flag becomes the authority",
        edits=((RUNTIME,
                "    if not signer.signer_authenticated:\n"
                "        return refuse(signer.reason)\n",
                "    return AuthorityDecision(\n"
                "        ACTION_TRUST_DOMAIN, signer.signer_authenticated,\n"
                "        signer.reason, evidence,\n"
                "    )\n", 1),),
        scenario="action_domain_governance_role",
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="`granted=signer_authenticated` is the assignment the type exists to stop",
    ),
    Mutation(
        name="M9 a key id trusted in one domain is inherited by the other",
        edits=((TRUST,
                "        return cls(\n"
                "            governance=section(GOVERNANCE_TRUST_DOMAIN),\n"
                "            action=section(ACTION_TRUST_DOMAIN),\n"
                "            source=str(location),\n"
                "        )",
                "        _gov = section(GOVERNANCE_TRUST_DOMAIN)\n"
                "        _act = section(ACTION_TRUST_DOMAIN)\n"
                "        _merged = dict(_act.signers)\n"
                "        for _k, _v in _gov.signers.items():\n"
                "            _merged.setdefault(_k, _v)\n"
                "        return cls(\n"
                "            governance=_gov,\n"
                "            action=replace(_act, signers=_merged, available=True),\n"
                "            source=str(location),\n"
                "        )", 1),),
        scenario="governance_only",
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="the same key id must not bridge a domain it was not granted",
    ),
    Mutation(
        name="M10 a role spelling is accepted without the domain trusting the key in it",
        edits=((RUNTIME,
                "    if claimed_role not in signer.trusted_roles:",
                "    if False and claimed_role not in signer.trusted_roles:", 1),),
        scenario="action_domain_unheld_role",
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="both clauses are required; neither is sufficient alone",
    ),
    Mutation(
        name="M11 a governance role is accepted for action release",
        edits=(
            (RUNTIME,
             "    if claimed_role not in ACTION_APPROVER_ROLES:",
             '    if claimed_role not in (set(ACTION_APPROVER_ROLES) |'
             ' {"architecture_reviewer"}):', 1),
            # The vocabulary is enforced TWICE -- the authority verifier and
            # the binder. Mutating one leaves no observable change, because the
            # other still refuses. That redundancy is a real defence, and the
            # honest way to test it is to remove both.
            (RUNTIME,
             "    if role not in ACTION_APPROVER_ROLES:",
             '    if role not in (set(ACTION_APPROVER_ROLES) |'
             ' {"architecture_reviewer"}):', 1),
        ),
        scenario="action_domain_governance_role",
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="network_governance_owner's twin: a governance role releasing an effect",
    ),
    Mutation(
        name="M12 an action role is accepted for governance approval",
        edits=((TRUST,
                "    if claimed_role not in GOVERNANCE_APPROVER_ROLES:",
                '    if claimed_role not in (set(GOVERNANCE_APPROVER_ROLES) |'
                ' {"operations_owner"}):', 1),),
        scenario="governance_domain_action_role",
        observable="governance_granted", expected=True,
        why="the mirror on the governance vocabulary",
    ),
    Mutation(
        name="M13 the binder runs and its result is discarded",
        edits=((RUNTIME,
                "    released, reason = _bind_action_approval(approval, request, as_of=as_of)",
                "    _discarded, reason = _bind_action_approval(\n"
                "        approval, request, as_of=as_of\n"
                "    )\n"
                "    released = True", 1),),
        scenario="action_only", flags=("--rebind",),
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="one of the two bypasses the old structural guard passed for",
    ),
    Mutation(
        name="M14 the binder runs only on an unreachable branch",
        edits=((RUNTIME,
                "    released, reason = _bind_action_approval(approval, request, as_of=as_of)",
                '    released, reason = True, "released"\n'
                "    if False:\n"
                "        released, reason = _bind_action_approval(\n"
                "            approval, request, as_of=as_of\n"
                "        )", 1),),
        scenario="action_only", flags=("--rebind",),
        observable="action_effect", expected="ALLOW",
        also={"calls": 1},
        why="the other bypass; symbol presence proved composition for neither",
    ),
)


@pytest.fixture(scope="module")
def baselines(tmp_path_factory) -> dict:
    """What the PRISTINE build does, per scenario and flag set.

    Measured, never assumed. A mutant compared against an expectation written
    by hand proves the expectation, and the expectation is the thing most
    likely to be wrong.
    """
    measured: dict[tuple[str, tuple[str, ...]], dict] = {}
    for mutation in CATALOGUE:
        key = (mutation.scenario, mutation.flags)
        if key not in measured:
            where = tmp_path_factory.mktemp("baseline")
            measured[key] = probe(where, mutation.scenario, flags=mutation.flags)
    return measured


def test_the_pristine_build_holds_the_matrix(baselines):
    """The baselines must be the SECURE outcomes, or every kill below is noise.

    A mutant that "changes the behaviour" from one insecure state to another
    proves nothing, so this pins what the unmutated build actually does before
    anything is mutated.
    """
    governance_only = baselines[("governance_only", ())]
    assert governance_only["governance_granted"] is True
    assert governance_only["action_effect"] == "DENY"
    assert governance_only["calls"] == 0 and governance_only["spent"] is False

    action_only = baselines[("action_only", ())]
    assert action_only["governance_granted"] is False
    assert action_only["action_effect"] == "ALLOW"
    assert action_only["calls"] == 1

    cross_role = baselines[("action_domain_governance_role", ())]
    assert cross_role["action_effect"] == "DENY", cross_role["action_reason"]
    assert "may not release a high-risk effect" in cross_role["action_reason"]

    governance_cross = baselines[("governance_domain_action_role", ())]
    assert governance_cross["governance_granted"] is False
    assert "not a governance approver role" in governance_cross["governance_reason"]

    unheld = baselines[("action_domain_unheld_role", ())]
    assert unheld["action_effect"] == "DENY"
    assert "trust domain" in unheld["action_reason"], unheld["action_reason"]

    rebound = baselines[("action_only", ("--rebind",))]
    assert rebound["action_effect"] == "DENY"
    assert "does not match this request" in rebound["action_reason"]


@pytest.mark.parametrize("mutation", CATALOGUE, ids=lambda m: m.name)
def test_the_collapse_is_visible(mutation: Mutation, baselines, tmp_path: Path):
    """Every collapse changes what the system does, or the control is decoration."""
    baseline = baselines[(mutation.scenario, mutation.flags)]
    mutant = probe(
        tmp_path, mutation.scenario, edits=mutation.edits, flags=mutation.flags
    )

    before = baseline[mutation.observable]
    after = mutant[mutation.observable]
    assert before != mutation.expected, (
        f"{mutation.name}: the pristine build already reports "
        f"{mutation.observable}={before!r}, so this mutation could not show "
        "anything. The case does not reach the property it names."
    )
    assert after == mutation.expected, (
        f"{mutation.name} SURVIVED. {mutation.why}.\n"
        f"  {mutation.observable}: {before!r} -> {after!r}, expected "
        f"{mutation.expected!r}\n"
        f"  governance: {mutant['governance_reason'][:160]}\n"
        f"  action    : {mutant['action_reason'][:160]}"
    )
    for extra, value in mutation.also.items():
        assert mutant[extra] == value, (
            f"{mutation.name}: {extra} is {mutant[extra]!r}, expected {value!r}. "
            "The verdict changed but the effect did not, so the observable is "
            "not the one that matters."
        )


def test_a_mutation_that_does_not_apply_is_refused(tmp_path: Path):
    """The harness must not score a no-op as a survivor or as a kill.

    An anchor that stops matching -- a renamed variable, a reflowed line --
    would otherwise turn this whole catalogue into a list of unmutated builds
    reporting the pristine behaviour.
    """
    with pytest.raises(InvalidMutation, match="TARGET NOT FOUND"):
        probe(
            tmp_path,
            "action_only",
            edits=((RUNTIME, "this text is not in the source", "x", 1),),
        )


def test_a_mutation_that_lands_in_a_comment_is_refused(tmp_path: Path):
    """The standing rule, enforced rather than remembered.

    Three false greens in this repository were textual replacements that landed
    in prose: a retired policy token surviving in the comment that explained its
    removal, and a role name whose first occurrence had been a comment for as
    long as the comment existed. Each changed the file, changed no decision, and
    was read as evidence.

    `# ONE authority call.` is a real comment in the action boundary, so this
    mutation genuinely applies and genuinely alters the file -- and is still
    refused, because nothing executable moved.
    """
    with pytest.raises(InvalidMutation, match="TARGET IS INERT"):
        probe(
            tmp_path,
            "action_only",
            edits=((RUNTIME, "# ONE authority call.", "# mutated comment.", 1),),
        )


def test_a_mutation_that_breaks_the_syntax_is_refused(tmp_path: Path):
    """A crash is not a kill.

    Without this, deleting a control could 'pass' by making the module
    unimportable -- the intended test would never execute, and the catalogue
    would count a mutation it never measured.
    """
    with pytest.raises(InvalidMutation, match="DOES NOT PARSE"):
        probe(
            tmp_path,
            "action_only",
            edits=((RUNTIME, "def verify_action_approval(", "def (", 1),),
        )


def test_a_docstring_mutation_is_refused_even_though_the_tree_changes(tmp_path: Path):
    """Docstrings ARE in the parse tree, which is why the tree test is not enough.

    A changed docstring changes `ast.dump`, so a harness proving only "the AST
    differs" would accept it. Nothing consults a docstring to make an authority
    decision, so it is refused explicitly.
    """
    with pytest.raises(InvalidMutation, match="TARGET IS INERT"):
        probe(
            tmp_path,
            "action_only",
            edits=(
                (
                    RUNTIME,
                    "THE ONLY entry point a consequential boundary may use.",
                    "A mutated docstring sentence.",
                    1,
                ),
            ),
        )
