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
