"""Task 9. Can two VALID governed states differ to Nornyx and not to the subject?

THE THEOREM, stated narrowly and truthfully:

    Across every enumerated authored decision-bearing field class below, for a
    pair of states BOTH of which Nornyx accepts as well-formed contracts, a
    measured difference in Nornyx's governance result implies a difference in
    `contract_semantics_digest` AND in the inspection subject.

That is not an unrestricted mathematical claim over the whole contract language.
It is a claim over an enumerated set, and the completeness guard below is what
keeps the enumeration honest as the language grows.

WHY THE REAL TREE. A copied workspace cannot resolve the Nornyx pack: every
contract fails at PACK_PATH_OUTSIDE_ROOT, no mutation changes a verdict, and the
matrix reports "invariant holds" while measuring nothing. This repository has
shipped that false green once, and the first attempt at this module reproduced
it exactly. Contracts are therefore mutated in place and restored BYTE FOR BYTE.

A PARSER REJECTION PROVES NOTHING HERE. Both sides of every pair are checked for
well-formedness first; a mutation that merely breaks the schema has not reached
the property and is excluded by construction.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx/contracts"
RUNTIME = ".nornyx/contracts/runtime_network.nyx"
ARCH = ".nornyx/contracts/architecture_governance.nyx"

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)

#: Codes that mean "this is not a contract", as opposed to "this contract is
#: blocked". The repository's own baseline is blocked -- no human approval
#: exists -- so blocked must not be mistaken for invalid.
MALFORMED = ("PARSE", "SCHEMA", "UNKNOWN_TOP", "MALFORMED", "YAML")


@dataclass(frozen=True)
class FieldClass:
    """One authored semantic field, and a VALID alternative value for it."""

    label: str
    contract: str
    #: Parser block this field lives in, for the completeness guard.
    block: str
    anchor: str
    replacement: str
    #: A  decision-bearing: a valid change alters Nornyx's result
    #: B  semantic but currently decision-invariant
    category: str
    why: str


#: MEASURED against the real tree, never assumed. `category` records what was
#: observed, and the tests below re-measure it every run rather than trusting
#: this table -- a stale category would otherwise silently weaken the theorem.
INVENTORY = (
    FieldClass(
        label="capability risk low->high",
        contract=RUNTIME, block="capabilities",
        anchor="    actions: [execute_low_risk_action]\n    risk: low",
        replacement="    actions: [execute_low_risk_action]\n    risk: high",
        category="A",
        why="raising a declared capability's risk brings a gate requirement with it",
    ),
    FieldClass(
        label="approval required role changed",
        contract=RUNTIME, block="approvals",
        anchor="    required_roles: [network_governance_owner]",
        replacement="    required_roles: [security_reviewer]",
        category="A",
        why="who must approve is the approval's whole content",
    ),
    FieldClass(
        label="architecture approval role changed",
        contract=ARCH, block="approvals",
        anchor="    required_roles: [architecture_reviewer]",
        replacement="    required_roles: [operations_owner]",
        category="A",
        why="the same clause on the architecture side, separately enforced",
    ),
    FieldClass(
        label="runtime policy drops a deny rule",
        contract=RUNTIME, block="policies",
        anchor="      - agent_grants_human_approval\n",
        replacement="",
        category="B",
        why=(
            "Nornyx's own checker does not currently change verdict on this "
            "policy list -- the rule is enforced by this repository's gates -- "
            "so no monotonicity claim is drawn from it. It still moves the "
            "semantic digest, which is the safe direction"
        ),
    ),
    FieldClass(
        label="runtime policy drops a require rule",
        contract=RUNTIME, block="policies",
        anchor="      - human_approval_for_external_high_risk_action\n",
        replacement="",
        category="B",
        why="same as above, on the require list",
    ),
    FieldClass(
        label="architecture policy drops a deny rule",
        contract=ARCH, block="policies",
        anchor="    deny: [undeclared_component_dependency, api_direct_command_execution]",
        replacement="    deny: [api_direct_command_execution]",
        category="B",
        why="tests/test_architecture_vocabulary.py holds these to their own gates",
    ),
)

DECISION_BEARING = tuple(f for f in INVENTORY if f.category == "A")


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------


def _verdict(relative: str) -> str:
    """Nornyx's result as its set of diagnostic codes.

    The codes, not the exit status: a contract blocked before and after a change
    can be blocked for different reasons, and that is a changed decision.
    """
    completed = subprocess.run(  # noqa: S603
        [shutil.which("nornyx") or "nornyx", "check", relative,
         "--as-of", "2026-08-03T00:00:00Z"],
        cwd=ROOT, capture_output=True, text=True,
    )
    codes = sorted(set(re.findall(r'"code":\s*"([A-Z_]+)"', completed.stdout)))
    return f"rc={completed.returncode} {','.join(codes)}"


def _well_formed(verdict: str) -> bool:
    return not any(bad in verdict for bad in MALFORMED)


def _semantics() -> str:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c",
         "import sys; sys.path.insert(0,'src');"
         "from nornyx_forge.subject_observer import observe_contract_semantics_digest;"
         "from pathlib import Path;"
         "print(observe_contract_semantics_digest(Path('.nornyx/contracts')))"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert completed.returncode == 0, completed.stderr[-400:]
    return completed.stdout.strip()


def _subject() -> str:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c",
         "import sys; sys.path.insert(0,'scripts');"
         "import refresh_governance_evidence as r;"
         "print(r.current_inspection_subject())"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stderr[-400:]
    return completed.stdout.strip()


@pytest.fixture
def restored_contracts():
    """Capture every contract as BYTES and put them back exactly.

    Not by regenerating: regeneration is one step of a causal order, and running
    it alone leaves recorded hashes describing artifacts that moved. That
    mistake broke three unrelated tests earlier in this programme.
    """
    before = {p: p.read_bytes() for p in CONTRACTS.rglob("*") if p.is_file()}
    try:
        yield before
    finally:
        for path, data in before.items():
            if path.read_bytes() != data:
                path.write_bytes(data)


def _apply(field: FieldClass) -> None:
    """Apply one field mutation, proving it reached the parsed document."""
    from mutation_validity import check_mutation  # noqa: PLC0415

    target = ROOT / field.contract
    before = target.read_text(encoding="utf-8")
    after = before.replace(field.anchor, field.replacement)
    check_mutation(field.contract, before, after, field.anchor, 1)
    target.write_text(after, encoding="utf-8", newline="")


# --------------------------------------------------------------------------
# 9.3 / 9.6 -- the theorem over the enumerated decision-bearing classes
# --------------------------------------------------------------------------


@needs_nornyx
@pytest.mark.parametrize(
    "field", DECISION_BEARING, ids=[f.label for f in DECISION_BEARING]
)
def test_a_decision_change_moves_the_semantic_identity(
    field: FieldClass, restored_contracts
):
    """The central question, asked per enumerated decision-bearing class.

    "Can I produce two VALID authored governed states that Nornyx treats
    differently while the inspection identity treats them as the same?"

    Every prerequisite is asserted before the conclusion is tested, so a case
    that fails to reach the property is reported as not reaching it rather than
    counted as a pass.
    """
    baseline_verdict = _verdict(field.contract)
    assert _well_formed(baseline_verdict), (
        f"the baseline is not a well-formed contract, so no pair starting here "
        f"can test the theorem: {baseline_verdict}"
    )
    baseline_semantics = _semantics()
    baseline_subject = _subject()

    _apply(field)

    mutated_verdict = _verdict(field.contract)
    assert _well_formed(mutated_verdict), (
        f"{field.label}: the mutation broke the schema, so this is a parser "
        f"rejection and not a decision change: {mutated_verdict}"
    )
    assert mutated_verdict != baseline_verdict, (
        f"{field.label} is classified DECISION-BEARING but Nornyx returned the "
        f"same result: {mutated_verdict}. Either the classification is stale or "
        "the alternative value is not decision-changing, and in both cases this "
        "case proves nothing about monotonicity."
    )

    mutated_semantics = _semantics()
    assert mutated_semantics != baseline_semantics, (
        f"{field.label}: SECURITY FINDING. Nornyx decides differently "
        f"({baseline_verdict} -> {mutated_verdict}) and contract_semantics_digest "
        "is unchanged, so an attestation cannot see the difference."
    )

    mutated_subject = _subject()
    assert mutated_subject != baseline_subject, (
        f"{field.label}: SECURITY FINDING. The semantic digest moved and the "
        "inspection subject did not, so the subject does not incorporate it."
    )


@needs_nornyx
@pytest.mark.parametrize(
    "field",
    tuple(f for f in INVENTORY if f.category == "B"),
    ids=[f.label for f in INVENTORY if f.category == "B"],
)
def test_a_decision_invariant_semantic_still_moves_the_identity(
    field: FieldClass, restored_contracts
):
    """Category B, claimed truthfully and no further.

    These are authored semantics whose tested alternative does NOT change
    Nornyx's current result. No monotonicity conclusion is drawn from them. What
    IS asserted is the safe direction: they still move the semantic identity, so
    an attestation cannot silently span the change.

    If one of these ever starts changing the verdict, the assertion here records
    that it must be reclassified rather than quietly gaining a stronger meaning.
    """
    baseline_verdict = _verdict(field.contract)
    baseline_semantics = _semantics()

    _apply(field)

    assert _well_formed(_verdict(field.contract)), field.label
    assert _semantics() != baseline_semantics, (
        f"{field.label}: an authored semantic change left the semantic identity "
        "unchanged, so an attestation spans it invisibly"
    )
    if _verdict(field.contract) != baseline_verdict:
        pytest.fail(
            f"{field.label} is classified B (decision-invariant) but now changes "
            "the Nornyx result. Reclassify it as A so the full theorem covers it."
        )


# --------------------------------------------------------------------------
# 9.5 -- the semantic projection is the cause, not an incidental file hash
# --------------------------------------------------------------------------


@needs_nornyx
def test_the_projection_is_what_carries_the_change(restored_contracts):
    """Suppress the field from the PROJECTION and the theorem must break.

    Without this, every case above could be passing because some broader hash
    over raw contract bytes moved. Here the raw file changes exactly as before,
    but `risk` is stripped from the projection -- and the semantic digest must
    then fail to notice, which is precisely the finding the theorem forbids.

    Measured with a mutated copy of `governed_subject` on the path, so the real
    module is untouched.
    """
    import json  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    field = DECISION_BEARING[0]
    assert "risk" in field.anchor, "this proof is written against the risk field"

    mutated_src = Path(tempfile.mkdtemp()) / "src"
    shutil.copytree(ROOT / "src", mutated_src,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    module = mutated_src / "nornyx_forge/governed_subject.py"
    text = module.read_text(encoding="utf-8")
    anchor = 'GENERATED_KEYS = frozenset(\n    {\n        "content_hash",'
    assert text.count(anchor) == 1
    module.write_text(
        text.replace(anchor, anchor.replace('"content_hash",', '"content_hash",\n        "risk",')),
        encoding="utf-8", newline="",
    )

    def semantics_under_mutation() -> str:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-c",
             "import sys;"
             f"sys.path.insert(0, {str(mutated_src)!r});"
             "from nornyx_forge.subject_observer import observe_contract_semantics_digest;"
             "from pathlib import Path;"
             "print(observe_contract_semantics_digest(Path('.nornyx/contracts')))"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        assert completed.returncode == 0, completed.stderr[-400:]
        return completed.stdout.strip()

    honest_before = _semantics()
    suppressed_before = semantics_under_mutation()
    _apply(field)
    honest_after = _semantics()
    suppressed_after = semantics_under_mutation()

    # The raw contract really changed, both times.
    assert honest_after != honest_before, "the control mutation stopped working"
    # And with `risk` stripped from the projection, the change becomes invisible
    # -- which is the whole point: the projection is load-bearing, not decoration.
    assert suppressed_after == suppressed_before, (
        "suppressing `risk` from the projection did NOT hide the change, so the "
        "semantic digest is being carried by something other than the projection "
        "and these tests would pass with the projection broken"
    )
    _ = json


# --------------------------------------------------------------------------
# 9.8 -- attack the completeness guard itself
# --------------------------------------------------------------------------


def _parser_authored_blocks() -> set[str]:
    """Top-level authored blocks present across the real contracts."""
    blocks: set[str] = set()
    for contract in sorted(CONTRACTS.glob("*.nyx")):
        document = yaml.safe_load(contract.read_text(encoding="utf-8"))
        blocks.update(document)
    return blocks


#: Blocks deliberately outside the decision-bearing inventory, each with the
#: reason it needs no valid decision-changing pair. Total by construction: a new
#: authored block belongs here or in INVENTORY, and the guard fails otherwise.
UNINVENTORIED = {
    "nornyx": "the language version header",
    "project": "naming and profile metadata",
    "intents": "declared purpose, carried into no Nornyx rule the checker runs",
    "contexts": "content selection for authoring, not a governance rule",
    "agents": "role descriptions bound to policies, which ARE inventoried",
    "goals": "goal records and their validation commands",
    "evidence": "the required-evidence list; its absence is proven elsewhere",
    "governance_evidence": "wholly tool-written; excluded and classified in 9A",
    "architecture_evidence": "tool-written architecture conformance record",
    "changes": "change records, provenance about what was edited",
    "exceptions": "recorded exception reviews",
    "separation_of_duties": "role separation, covered by the approvals cases",
    "architecture": "the component graph, guarded by check_architecture.py",
    "agentic_network": "network declaration; membership covered by identities",
    "agent_identities": "identity records; their roles are inventoried via approvals",
    "capabilities": "inventoried",
    "approvals": "inventoried",
    "policies": "inventoried",
    "budgets": "token budgets, not a governance decision",
    "harnesses": "authoring harness declarations",
    "skills": "authoring skill declarations",
}


def test_every_authored_block_is_either_inventoried_or_excused():
    """The meta-control. A new authored block fails until it is classified.

    Set EQUALITY, not iteration. The historical REQUIRED_MODULES defect was a
    loop that passed over an empty list, so "for item in REQUIRED" proved
    nothing when REQUIRED was empty. Both directions are checked here, and the
    inventory is separately required to be non-empty.
    """
    present = _parser_authored_blocks()
    inventoried = {f.block for f in INVENTORY}
    accounted = inventoried | set(UNINVENTORIED)

    assert present, "no authored blocks were parsed, so this guard proves nothing"
    assert INVENTORY, "the inventory is empty"
    assert DECISION_BEARING, "no decision-bearing class is enumerated"

    unclassified = sorted(present - accounted)
    assert unclassified == [], (
        "these authored contract blocks are neither inventoried as semantic "
        f"field classes nor excused with a reason: {unclassified}"
    )

    stale = sorted(inventoried - present)
    assert stale == [], (
        f"the inventory names blocks no contract carries any more: {stale}"
    )


def test_the_completeness_guard_notices_a_new_authored_block():
    """Load-bearing, proven by simulating the diff it exists to catch."""
    present = _parser_authored_blocks() | {"a_new_authored_block"}
    accounted = {f.block for f in INVENTORY} | set(UNINVENTORIED)
    assert sorted(present - accounted) == ["a_new_authored_block"]


def test_the_completeness_guard_notices_an_emptied_inventory():
    """The REQUIRED_MODULES shape: an empty set must not satisfy the guard."""
    assert len(INVENTORY) >= 4, "the inventory has shrunk below a useful minimum"
    assert len({f.block for f in INVENTORY}) >= 3, (
        "the inventory covers fewer than three distinct parser blocks, so it "
        "cannot be said to enumerate the decision-bearing surface"
    )


def test_every_inventory_entry_states_a_reason_and_a_category():
    for field in INVENTORY:
        assert field.category in {"A", "B"}, field.label
        assert len(field.why) > 25, f"{field.label} is classified without a reason"
        assert field.anchor != field.replacement, f"{field.label} mutates nothing"


# --------------------------------------------------------------------------
# 9.4 -- A -> B -> A reversibility
# --------------------------------------------------------------------------


def _only_intended_change(contract: str, anchor: str, replacement: str) -> None:
    """The working tree differs from HEAD in exactly the intended way.

    Without this, a case could "prove" subject motion while some unrelated edit
    was sitting in the tree doing the work.
    """
    diff = subprocess.run(  # noqa: S603
        ["git", "diff", "--", contract],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).stdout
    changed = [
        line for line in diff.splitlines()
        if (line.startswith("+") or line.startswith("-"))
        and not line.startswith(("+++", "---"))
    ]
    assert changed, "git reports no change, so nothing was mutated"
    removed = "".join(line[1:] for line in changed if line.startswith("-"))
    added = "".join(line[1:] for line in changed if line.startswith("+"))
    assert removed.strip() in anchor.strip() or anchor.strip() in removed.strip(), (
        f"the diff removed something other than the intended anchor: {removed[:200]}"
    )
    if replacement.strip():
        assert added.strip() in replacement.strip() or replacement.strip() in added.strip(), (
            f"the diff added something other than the intended value: {added[:200]}"
        )

    # Scoped to `.nornyx/`, deliberately. What could contaminate THIS
    # measurement is another contract or a generated artifact moving: the
    # inspection subject is contract semantics plus the evidence manifest, and
    # nothing else feeds it. An earlier version of this guard forbade any
    # modified file anywhere and failed on the uncommitted test module itself --
    # correct in spirit, wrong in scope, and a guard that fires on irrelevant
    # state is one people learn to work around.
    others = subprocess.run(  # noqa: S603
        ["git", "status", "--porcelain", "--", ".nornyx"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).stdout.splitlines()
    unexpected = [line for line in others if contract not in line and line.strip()]
    assert unexpected == [], (
        "other governed evidence is modified, so the measurement is "
        f"contaminated: {unexpected[:4]}"
    )


@needs_nornyx
@pytest.mark.parametrize(
    "field", DECISION_BEARING, ids=[f.label for f in DECISION_BEARING]
)
def test_semantic_identity_is_reversible(field: FieldClass, restored_contracts):
    """9.4. A -> B -> A, with NO evidence regeneration in between.

    Regenerating between the observations would be the wrong instrument: it
    rewrites derived state, so a subject that moved could be moving for that
    reason. Restoring the exact original bytes and re-observing is stronger --
    if the identity returns to precisely where it was, subject motion is a pure
    function of the authored semantics rather than residual churn.

    A failure here would mean hidden mutable state contaminates semantic
    identity, which is why the assertion is equality and not "close enough".
    """
    d1, s1 = _semantics(), _subject()

    _apply(field)
    _only_intended_change(field.contract, field.anchor, field.replacement)
    d2, s2 = _semantics(), _subject()

    assert d2 != d1, f"{field.label}: the authored change did not move the digest"
    assert s2 != s1, f"{field.label}: the authored change did not move the subject"

    for path, data in restored_contracts.items():
        if path.read_bytes() != data:
            path.write_bytes(data)

    d3, s3 = _semantics(), _subject()
    assert d3 == d1, (
        f"{field.label}: restoring the exact original bytes did NOT restore the "
        "semantic digest, so something other than the authored semantics is "
        "feeding it"
    )
    assert s3 == s1, (
        f"{field.label}: restoring the exact original bytes did NOT restore the "
        "inspection subject, so hidden mutable state contaminates identity"
    )


# --------------------------------------------------------------------------
# 9C -- attack the production projection itself
# --------------------------------------------------------------------------

_PROJECTION_FILTER = (
    "            if key not in GENERATED_KEYS and key not in GENERATED_BLOCKS\n"
)
_LIST_BRANCH = "        return [semantic_projection(item) for item in node]\n"
_SCALAR_BRANCH = "    return node\n"
_AGGREGATE = (
    '        "contracts": {name: semantic_projection(doc)'
    " for name, doc in sorted(documents.items())},\n"
)
_KEYS_HEAD = 'GENERATED_KEYS = frozenset(\n    {\n        "content_hash",'
_BLOCKS = 'GENERATED_BLOCKS = frozenset({"governance_evidence"})'


@dataclass(frozen=True)
class ProjectionAttack:
    """One way the projection could stop distinguishing two governed states."""

    ident: str
    module: str
    anchor: str
    replacement: str
    #: Which enumerated Category-A pair this attack must be able to hide.
    field_label: str
    why: str


#: Eight attacks. The mechanisms are deliberately different from one another --
#: inclusion, block exclusion, key matching, canonicalisation, structural
#: reclassification, section blanking and aggregation -- because a catalogue
#: that attacked one mechanism eight ways would prove one thing eight times.
PROJECTION_ATTACKS = (
    ProjectionAttack(
        "9C-0 suppress the capability risk field",
        "governed_subject.py", _KEYS_HEAD,
        _KEYS_HEAD.replace('"content_hash",', '"content_hash",\n        "risk",'),
        "capability risk low->high",
        "the original causation proof: inclusion of a decision-bearing key",
    ),
    ProjectionAttack(
        "9C-1 suppress the approval role field",
        "governed_subject.py", _KEYS_HEAD,
        _KEYS_HEAD.replace('"content_hash",', '"content_hash",\n        "required_roles",'),
        "approval required role changed",
        "a second, genuinely distinct decision-bearing class",
    ),
    ProjectionAttack(
        "9C-2 swallow an authored block as generated",
        "governed_subject.py", _BLOCKS,
        'GENERATED_BLOCKS = frozenset({"governance_evidence", "capabilities"})',
        "capability risk low->high",
        "an authored decision-bearing block reclassified out of binding",
    ),
    ProjectionAttack(
        "9C-3 broaden the ignored-key rule by suffix",
        "governed_subject.py", _PROJECTION_FILTER,
        _PROJECTION_FILTER.rstrip("\n")
        + ' and not key.endswith("_roles")\n',
        "approval required role changed",
        "the plausible cleanup: ignore anything matching a shape",
    ),
    ProjectionAttack(
        "9C-4 normalise decision-distinct values together",
        "governed_subject.py", _SCALAR_BRANCH,
        '    return "low" if node in ("low", "high") else node\n',
        "capability risk low->high",
        "collapse inside canonicalisation, which inclusion tests cannot see",
    ),
    ProjectionAttack(
        "9C-5 treat an authored structure as derived",
        "governed_subject.py", _LIST_BRANCH,
        "        return [\n"
        "            semantic_projection(item)\n"
        "            for item in node\n"
        '            if not (isinstance(item, dict) and "revision_binding" in item)\n'
        "        ]\n",
        "approval required role changed",
        "structural reclassification, not a name list",
    ),
    ProjectionAttack(
        "9C-6 blank one authored section",
        "governed_subject.py",
        "            key: semantic_projection(value)\n",
        '            key: ({} if key == "capabilities" else semantic_projection(value))\n',
        "capability risk low->high",
        "a section that still appears but carries nothing",
    ),
    ProjectionAttack(
        "9C-7 omit one contract from the aggregate",
        "governed_subject.py", _AGGREGATE,
        '        "contracts": {\n'
        "            name: semantic_projection(doc)\n"
        "            for name, doc in sorted(documents.items())\n"
        '            if name != "runtime_network.nyx"\n'
        "        },\n",
        "capability risk low->high",
        "the contract is present and Nornyx still reads it; identity does not",
    ),
)

#: The eight projection attacks, BY NAME.
#:
#: This was `frozenset(a.ident for a in PROJECTION_ATTACKS)` -- derived from the
#: very catalogue it checks, so `actual == EXPECTED_9C_IDS` held for any
#: catalogue whatsoever, including one carrying eight different attacks or eight
#: copies of the same one. The count assertions beside it did have force; the
#: identity assertion had none.
#:
#: Written out so that replacing an attack has to be replaced here too, in the
#: diff, where a reviewer can see which invariant stopped being attacked.
EXPECTED_9C_IDS = frozenset(
    {
        "9C-0 suppress the capability risk field",
        "9C-1 suppress the approval role field",
        "9C-2 swallow an authored block as generated",
        "9C-3 broaden the ignored-key rule by suffix",
        "9C-4 normalise decision-distinct values together",
        "9C-5 treat an authored structure as derived",
        "9C-6 blank one authored section",
        "9C-7 omit one contract from the aggregate",
    }
)


def _mutated_src(attack: ProjectionAttack) -> Path:
    """A copy of `src` with one projection attack installed, proven to apply."""
    import tempfile  # noqa: PLC0415

    from mutation_validity import check_python_mutation  # noqa: PLC0415

    destination = Path(tempfile.mkdtemp()) / "src"
    shutil.copytree(ROOT / "src", destination,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    module = destination / "nornyx_forge" / attack.module
    before = module.read_text(encoding="utf-8")
    after = before.replace(attack.anchor, attack.replacement)
    check_python_mutation(
        f"src/nornyx_forge/{attack.module}", before, after, attack.anchor, 1
    )
    module.write_text(after, encoding="utf-8", newline="")
    return destination


def _semantics_under(src: Path) -> str:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c",
         "import sys;"
         f"sys.path.insert(0, {str(src)!r});"
         "from nornyx_forge.subject_observer import observe_contract_semantics_digest;"
         "from pathlib import Path;"
         "print(observe_contract_semantics_digest(Path('.nornyx/contracts')))"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert completed.returncode == 0, (
        "the mutated projection did not run to completion, so nothing was "
        f"measured: {completed.stderr[-400:]}"
    )
    return completed.stdout.strip()


@pytest.mark.parametrize(
    "attack", PROJECTION_ATTACKS, ids=[a.ident for a in PROJECTION_ATTACKS]
)
def test_the_projection_attack_is_killed(attack: ProjectionAttack, restored_contracts):
    """Each attack must be able to hide a real decision difference -- and be caught.

    A mutation is KILLED_VALIDLY here when, with it installed, two governed
    states that Nornyx treats differently become indistinguishable to the
    semantic identity. That is precisely the condition the Task-9 theorem test
    asserts against, so a surviving attack is a hole in the theorem.

    The honest projection is measured on the same pair every time, so an attack
    that "hides" a difference that was never there earns nothing.
    """
    field = next(f for f in INVENTORY if f.label == attack.field_label)
    src = _mutated_src(attack)

    honest_a, attacked_a = _semantics(), _semantics_under(src)
    _apply(field)
    honest_b, attacked_b = _semantics(), _semantics_under(src)

    assert honest_b != honest_a, (
        f"{attack.ident}: the honest projection does not distinguish this pair, "
        "so there is nothing for the attack to hide and this case proves nothing"
    )
    assert attacked_b == attacked_a, (
        f"{attack.ident} SURVIVED. {attack.why}. The mutated projection still "
        "distinguishes the two states, so this attack does not reach the "
        "property -- repair the mutation rather than counting it."
    )


# --------------------------------------------------------------------------
# 9C meta-control
# --------------------------------------------------------------------------


def test_the_attack_catalogue_is_exactly_what_is_expected():
    """Set equality, not iteration.

    `for attack in ATTACKS` passes over an empty list. The expected identifiers
    are asserted independently so removing a case, emptying the catalogue or
    quietly reducing the count all fail.
    """
    actual = frozenset(a.ident for a in PROJECTION_ATTACKS)
    assert actual == EXPECTED_9C_IDS, (
        "the projection attacks no longer match the written inventory. "
        f"missing: {sorted(EXPECTED_9C_IDS - actual)} "
        f"added: {sorted(actual - EXPECTED_9C_IDS)}"
    )
    # The inventory must be WRITTEN, not computed from the catalogue. A derived
    # expectation agrees with its source by construction, which is exactly what
    # this assertion used to do.
    declaration = Path(__file__).read_text(encoding="utf-8")
    declaration = declaration[declaration.index("EXPECTED_9C_IDS = frozenset("):]
    declaration = declaration[: declaration.index(chr(10) + ")" + chr(10))]
    assert "PROJECTION_ATTACKS" not in declaration, (
        "EXPECTED_9C_IDS is derived from the catalogue it checks, so the "
        "equality above is a tautology"
    )
    assert len(PROJECTION_ATTACKS) == 8, (
        f"the projection attack catalogue has {len(PROJECTION_ATTACKS)} cases, "
        "expected 8"
    )
    assert len({a.ident for a in PROJECTION_ATTACKS}) == 8, "duplicate attack ids"


def test_the_attacks_cover_more_than_one_mechanism_and_more_than_one_field():
    """A catalogue attacking one mechanism eight ways proves one thing eight times."""
    anchors = {a.anchor for a in PROJECTION_ATTACKS}
    assert len(anchors) >= 5, (
        f"only {len(anchors)} distinct production anchors are attacked, so the "
        "catalogue does not cover the projection's separate mechanisms"
    )
    fields = {a.field_label for a in PROJECTION_ATTACKS}
    assert len(fields) >= 2, (
        "every attack hides the same field class, so a second decision-bearing "
        "class is untested"
    )
    assert fields <= {f.label for f in DECISION_BEARING}, (
        "an attack names a field class that is not inventoried as decision-bearing"
    )


def test_removing_an_inventory_row_is_visible():
    """The Category-A inventory cannot be quietly reduced."""
    assert len(DECISION_BEARING) >= 3, (
        f"only {len(DECISION_BEARING)} decision-bearing classes are inventoried"
    )
    labels = {f.label for f in DECISION_BEARING}
    assert {a.field_label for a in PROJECTION_ATTACKS} <= labels
