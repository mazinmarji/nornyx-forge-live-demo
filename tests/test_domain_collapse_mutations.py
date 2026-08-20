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

import re
import shutil
import sys
import tempfile
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

    # THE MUTANT MUST HAVE RUN. This module's docstring says "A mutation counts
    # as KILLED only when the mutant RUNS TO COMPLETION and the named authority
    # property changes", and the verdict point asserted only the second half.
    # `healthy_against` was exercised solely by
    # `test_fg23_the_real_collapse_mutants_are_all_healthy`, over its OWN
    # independently built probes -- so the health of the mutant that actually
    # earns each kill here was never checked. A review named the gap.
    #
    # Asked before the observable, so a broken run cannot be read as a moved
    # verdict: reaching the expected value because the mutant crashed is FG23,
    # and this is where that credit would have been given.
    unhealthy = healthy_against(baseline, mutant)
    assert unhealthy == [], (
        f"{mutation.name}: the mutant did not run properly, so any change in "
        f"{mutation.observable} is not attributable to the removed control: "
        f"{unhealthy}"
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


# --------------------------------------------------------------------------
# FG23 -- an unhealthy mutant credited as a kill.
#
# The direct-observable shape has no exact-node/phase attribution, because
# there is no victim test whose failure could be misread. Its analogue is
# this: an observable can reach the value the attack expects because the
# mutant BROKE THE RUN, not because the control was removed. FG10 covers the
# BASELINE already failing; this is the MUTANT failing, and nothing checked it
# until Task 11 measured it by hand.
# --------------------------------------------------------------------------


def healthy_against(base: dict, mutant: dict) -> list[str]:
    """Why this mutant is not a well-formed run, or [] if it is.

    Deliberately NOT "only the target observable moved". A domain collapse is
    supposed to move `calls` and `spent` -- an unauthorised effect actually
    executing IS the consequence being demonstrated, and a check that forbade
    it would be demanding the collapse be inconsequential. That mistake was
    made once and produced a "10 of 14 non-surgical" false alarm.

    What disqualifies a mutant is failing to RUN: observable keys going
    missing, or a decision reason that is a crash rather than a decision.
    """
    problems = []
    missing = sorted(set(base) - set(mutant))
    if missing:
        problems.append(f"observables vanished: {missing}")

    # NOT A TOKEN BLOCKLIST -- and the first attempt at that sentence was one
    # anyway. It replaced five hardcoded names with `[A-Z][A-Za-z]*(?:Error|
    # Exception)`, which is a blocklist of two SUFFIXES: measured against the
    # classes this subject defines, ten of eleven renderings escaped it, so
    # `APPROVAL_NOT_AUTHENTICATED: TrustStoreUnavailable` -- from the catch-all
    # in the very module that raises it in ten places -- read as an ordinary
    # refusal and would have been credited as a kill.
    #
    # So the vocabulary is DERIVED, not authored: the probe reports every
    # exception class its own process can name (`exception_names`), and a name
    # from that set appearing where a decision belongs disqualifies the mutant.
    # Renaming, adding or removing a class needs no edit here.
    vocabulary = mutant.get("exception_names")
    if not isinstance(vocabulary, list) or not vocabulary:
        # Fail closed. An absent vocabulary matches nothing, which would accept
        # every crashed mutant while staying green -- the defect restored, and
        # invisible. Refuse the mutant instead of skipping the check.
        problems.append(
            "the mutant reported no exception vocabulary, so a crash rendered "
            "as a decision cannot be told from a decision"
        )
        vocabulary = []
    names = set(vocabulary)

    # Retained alongside the derived set, for a class the probe's process never
    # imported and so cannot name. Neither is sufficient; the union is what is
    # claimed. A crash whose rendering carries no class name at all -- a bare
    # `str(exc)` -- is outside both, and is a STATED BOUND rather than a gap
    # this pretends to cover.
    exception_shaped = re.compile("[A-Z][A-Za-z]*(?:Error|Exception)")
    for key, value in mutant.items():
        if not key.endswith("_reason"):
            continue
        text = str(value)
        if "Traceback" in text:
            problems.append(f"{key} carries a traceback, not a decision: {text[:60]}")
            continue
        # Identifier tokens, so a class name is matched as a name and not as a
        # substring of some longer word.
        reported = sorted(set(re.findall("[A-Za-z_][A-Za-z0-9_]*", text)) & names)
        if reported or exception_shaped.search(text):
            problems.append(
                f"{key} reports an exception type where a decision belongs, so "
                f"the mutant failed rather than decided: {text[:70]}"
                + (f" (named: {reported})" if reported else "")
            )
    return problems


def test_fg23_a_mutant_that_broke_the_run_is_not_a_kill(tmp_path: Path):
    """The negative specimen: expected value reached for the wrong reason.

    The naive check is `after == expected`. A mutant that cannot complete can
    satisfy it while proving nothing about the control, so the health check has
    to be what distinguishes them.
    """
    base = probe(tmp_path / "base", "action_only")

    # The specimen a review defeated: it fed a string built from the SAME
    # tokens the check listed, so shrinking that list to ("Traceback",) left it
    # passing. This one uses the shape the blocklist could never have caught --
    # an exception swallowed into what reads as an ordinary refusal, which is
    # how a mutant that authenticates nothing in either domain got credited.
    swallowed = dict(base)
    swallowed["governance_reason"] = "APPROVAL_NOT_AUTHENTICATED: ValueError"
    assert healthy_against(base, swallowed), (
        "an exception type reported where a decision belongs was accepted as a "
        "well-formed mutant, so a broken verifier could be credited as a kill"
    )

    broken = dict(base)
    broken["governance_reason"] = "Traceback (most recent call last): ImportError"
    assert healthy_against(base, broken), (
        "a run whose reason is a traceback was accepted as a well-formed "
        "mutant, so a crash could be credited as a kill"
    )

    ordinary = dict(base)
    ordinary["governance_reason"] = "DENY: the role is not trusted in this domain"
    assert healthy_against(base, ordinary) == [], (
        "an ordinary refusal was called unhealthy, so the check refuses "
        "everything and proves nothing"
    )
    lost = {k: v for k, v in base.items() if not k.endswith("_reason")}
    assert healthy_against(base, lost), (
        "a run missing observables was accepted as well-formed"
    )


def test_fg23_a_crash_is_recognised_by_the_builds_own_exception_names(tmp_path: Path):
    """The suffix pattern was a five-name blocklist wearing two suffixes.

    `[A-Z][A-Za-z]*(?:Error|Exception)` recognises a crash only when the class
    happens to be NAMED for one. Measured against the classes this subject
    actually defines, ten of eleven renderings read as ordinary refusals --
    `TrustStoreUnavailable` (raised in ten places in the module whose catch-all
    prints `type(exc).__name__`), `SubjectScopeEscape`, `UnknownRiskLevel`,
    `NornyxRuntimeUnavailable`, and the builtins `StopIteration`,
    `KeyboardInterrupt`, `SystemExit`. Any of them would have been credited as
    a killed mutation.

    So the vocabulary is DERIVED FROM THE BUILD rather than written down: the
    probe reports every exception class its own process can name, and a name
    appearing where a decision belongs is what disqualifies the mutant. A
    class added, renamed or removed tomorrow is covered without editing this.
    """
    base = probe(tmp_path / "base", "action_only")
    vocabulary = set(base["exception_names"])

    # The derivation has to REACH THE SUBJECT. A vocabulary of builtins alone
    # would leave every class above escaping while looking like a fix, and an
    # empty one would accept everything -- so both are refused, here and in
    # `healthy_against` itself.
    assert "TrustStoreUnavailable" in vocabulary, (
        "the probe did not report the subject's own exception classes, so the "
        "check has quietly narrowed to whatever builtins are named"
    )
    assert {"UnknownRiskLevel", "SubjectScopeEscape", "StopIteration"} <= vocabulary

    escaped = []
    for name in sorted(vocabulary):
        crashed = dict(base)
        crashed["governance_reason"] = "APPROVAL_NOT_AUTHENTICATED: " + name
        if healthy_against(base, crashed) == []:
            escaped.append(name)
    assert escaped == [], (
        "these exception classes can be reported where a decision belongs and "
        f"still be credited as a well-formed mutant: {escaped[:12]}"
    )

    # THE CONTROL, WITH MORE THAN ONE SAMPLE. The previous version had exactly
    # one, and it happened to avoid the collision that mattered: the vocabulary
    # was built from MODULE ATTRIBUTE names, so `socket.error is OSError` and
    # `socket.timeout is TimeoutError` put the bare words "error" and "timeout"
    # into it, and any refusal using either as ordinary English was disqualified.
    # A single sample is not a control; it is one measurement that agreed.
    ordinary = [
        "APPROVER_ROLE_UNAUTHORIZED: 'refund-approver' is not a governance role",
        "APPROVAL_REFUSED: a signature error was reported by the verifier",
        "APPROVAL_EXPIRED: the request timeout window has already elapsed",
        "DENY: the role is not trusted in this domain",
        "APPROVAL_NOT_AUTHENTICATED: signature invalid. Any change to the "
        "decision, approver, role, window or bound subject invalidates it.",
    ]
    disqualified = []
    for refusal in ordinary:
        candidate = dict(base)
        candidate["governance_reason"] = refusal
        if healthy_against(base, candidate):
            disqualified.append(refusal)
    assert disqualified == [], (
        "these ordinary refusals were disqualified as crashes, so the "
        f"vocabulary is matching prose rather than exception names: {disqualified}"
    )

    # And the vocabulary itself must not contain bare English words, which is
    # the property rather than a sample of it.
    # THE PROPERTY, NOT A LIST OF FIVE WORDS. This checked membership in
    # {"error", "timeout", "warning", "exception", "failure"} and called itself
    # a property; a review measured 270 kept names including `Clamped`,
    # `Failed`, `Interrupted`, `Rounded`, `Skipped` and `Warning`, none of which
    # that set would have caught.
    #
    # What actually distinguishes a rendered class name from prose is SHAPE: a
    # capital, or an underscore. A name that is entirely lowercase letters is
    # indistinguishable from an English word by any token test, which is why the
    # probe drops those -- so asserting the shape asserts the whole class,
    # including words nobody has thought of.
    word_shaped = sorted(
        name for name in vocabulary
        if name.isalpha() and name.islower()
    )
    assert word_shaped == [], (
        "the exception vocabulary contains names indistinguishable from "
        "ordinary English words, so any refusal using one as prose will be "
        f"read as a crash: {word_shaped[:12]}"
    )


def test_fg23_a_mutant_reporting_no_vocabulary_is_refused(tmp_path: Path):
    """Absence of the vocabulary must fail closed, not skip the check.

    A missing key is the failure mode that would restore the whole defect
    silently: no names to match, so no crash ever recognised, so every broken
    mutant credited -- and nothing red.
    """
    base = probe(tmp_path / "base", "action_only")
    for absent in ({}, {"exception_names": []}):
        blind = dict(base)
        blind.pop("exception_names")
        blind.update(absent)
        problems = healthy_against(base, blind)
        assert any("exception vocabulary" in problem for problem in problems), (
            "a mutant that reported no exception vocabulary was accepted, so "
            f"the crash check silently did nothing: {problems}"
        )


def test_fg23_the_real_collapse_mutants_are_all_healthy(tmp_path: Path):
    """The positive specimen. Without it the check above could refuse everything.

    Measured across the whole collapse catalogue rather than asserted: every
    attack must produce a mutant that RAN, so that its observable change is
    attributable to the control it removed.
    """
    unhealthy = []
    # Indexed, not name-derived: `M1` and `M10` both truncate to the same
    # prefix, and two attacks sharing one workspace is FG05.
    for index, mutation in enumerate(CATALOGUE):
        base = probe(tmp_path / f"b{index}", mutation.scenario,
                     flags=mutation.flags)
        mutant = probe(tmp_path / f"m{index}", mutation.scenario,
                       edits=mutation.edits, flags=mutation.flags)
        problems = healthy_against(base, mutant)
        if problems:
            unhealthy.append(f"{mutation.name}: {problems}")
    assert unhealthy == [], (
        "these attacks are credited on a mutant that did not run properly, so "
        f"the observable change is not attributable to the control: {unhealthy}"
    )


# --------------------------------------------------------------------------
# R3 -- the direct-observable shape enforced NEITHER production scope NOR
# mutant origin. `require_production_mutation_scope` and `require_mutant_origin`
# are called only by the victim-test runner, and `apply_edits` dispatches on
# file extension alone, so an "attack" could mutate a TEST FIXTURE, watch the
# observable move, and be credited -- proving only that the suite reacts to
# itself. A review credited two fabricated kills through exactly these holes.
#
# The catalogue's own claim ("production mutation scope: measured src/ only")
# was an inspection of the data, not a check on the path.
# --------------------------------------------------------------------------


def test_r3_every_collapse_edit_targets_production_scope():
    """Enforced over the live catalogue, in both directions.

    Reading the paths and eyeballing them is what the superseded claim did.
    This puts every edit through the same resolver the victim-test runner uses,
    so `tests/`, `docs/`, `./tests/x` and `src/../tests/x` are all refused by
    canonical resolution rather than by string prefix.
    """
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        require_production_mutation_scope,
    )

    outside = []
    for mutation in CATALOGUE:
        for edit in mutation.edits:
            relative = edit[0]
            try:
                require_production_mutation_scope(relative)
            except AttackNotAdmissible as refusal:
                outside.append(f"{mutation.name}: {relative} -- {refusal}")
    assert outside == [], (
        "these collapse attacks mutate something outside production scope, so "
        f"they measure the suite reacting to itself: {outside}"
    )


def test_r3_a_test_fixture_mutation_is_refused_as_an_attack():
    """The negative specimen: the exact shape that got a fabricated kill.

    An edit aimed at `tests/authority_probe.py` moves the observable -- the
    probe is what produces it -- while `src/` stays byte-identical. Without the
    scope check that is indistinguishable from a real control removal.
    """
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        require_production_mutation_scope,
    )

    for fabricated in ("tests/authority_probe.py", "./tests/authority_probe.py",
                       "src/../tests/authority_probe.py", "docs/ARCHITECTURE.md"):
        with pytest.raises(AttackNotAdmissible):
            require_production_mutation_scope(fabricated)


def test_r3_the_collapse_workspace_loads_the_mutant_not_the_repository():
    """Mutant origin, measured for THIS shape rather than assumed.

    `test_the_delegated_catalogues_prove_mutant_origin_where_they_mutate` writes
    its own spy that hardcodes the same `sys.path` lines as the real probe, so
    it would still pass if the probe lost them -- it measures a copy of the
    mechanism. This asks the workspace itself.
    """
    from mutation_workspace import require_mutant_origin  # noqa: PLC0415

    work = Path(tempfile.mkdtemp(prefix="r3-origin-"))
    try:
        tree = _materialized_tree(work)
        require_mutant_origin(tree, ("nornyx_forge.nornyx_runtime",
                                     "nornyx_forge.approval_trust"))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _materialized_tree(destination: Path) -> Path:
    """The same workspace `probe` builds, without running the scenario."""
    from mutation import _materialize  # noqa: PLC0415

    return _materialize(destination)
