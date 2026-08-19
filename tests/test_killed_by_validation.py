"""A `killed_by` name is not a proof. The body must carry hostile-path evidence.

`delegation_problems` walks the owner module and checks that a `FunctionDef`
with the right NAME exists. It never looks inside. Lens B exhibited it accepting
three private helpers with zero assertions as the thing that kills an attack:

    killed_by='_isolated_env'   -> delegation_problems = []
    killed_by='_plain_copy'     -> delegation_problems = []
    killed_by='tracked_files'   -> GUTTED: no longer defines tracked_files

Five functions carry all 41 kills. Replace their bodies with `pass` and the
counts, the identity set, `41 = 37 + 4` and `GATE: PASS` all survive, because
every one is `@pytest.mark.parametrize`-driven so the collected total does not
move either.

The false-green audit already fixed exactly this -- FOR ITS OWN SELF-ATTACKS
ONLY. `test_every_false_green_class_has_a_self_attack_that_trips_its_guard`
parses each named function and requires an assertion, and its docstring says "A
NAME IS NOT A TEST". That fix was never extended to the five functions carrying
the campaign.

WHAT THIS FILE MAY AND MAY NOT CLAIM. Static body inspection defends the
catalogue against shrinkage and substitution. It does NOT establish that the
right assertion runs on the hostile path -- only execution does, and the runner
owns that. So these tests are deliberately scoped to "the named proof still
contains executable defensive semantics", and the docstrings say so, because
turning `ast.Assert` into the new authority would recreate the defect one level
along.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

#: The five functions every kill in the catalogue delegates to.
KILL_BEARING = {
    "test_removing_the_control_revives_the_defect": "tests/test_historical_reproof.py",
    "test_removing_one_guard_leaves_the_property_protected": "tests/test_historical_reproof.py",
    "test_disabling_the_whole_chain_recreates_the_historical_unsafe_state": (
        "tests/test_historical_reproof.py"
    ),
    "test_the_collapse_is_visible": "tests/test_domain_collapse_mutations.py",
    "test_the_projection_attack_is_killed": "tests/test_semantic_binding_theorem.py",
}

SPECIMENS = [
    ("empty body", "def {name}():\n    ...\n"),
    ("body replaced with pass", "def {name}():\n    pass\n"),
    (
        "comments and a docstring naming the property, executing nothing",
        'def {name}():\n'
        '    """Proves the control is removed and the property revives."""\n'
        "    # asserts that the mutation kills the intended proof\n"
        "    return None\n",
    ),
    (
        "calls an unrelated helper and asserts nothing",
        "def {name}():\n    _isolated_env(None)\n",
    ),
    (
        "asserts a constant, which cannot fail",
        "def {name}():\n    assert True\n",
    ),
]


def _defensive_evidence(source: str, name: str) -> int:
    """Executable checks inside `name`: assertions and expected-refusal blocks.

    Deliberately narrow, and deliberately not the authority. A count above zero
    means the body is not a placeholder; it does not mean the body proves
    anything, which is why the runner still has to execute it.
    """
    tree = ast.parse(source)
    found = [
        fn for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name == name
    ]
    if len(found) != 1:
        return 0
    evidence = 0
    for child in ast.walk(found[0]):
        if isinstance(child, ast.Assert):
            # `assert True` and `assert 1` cannot fail, so they are not evidence.
            if isinstance(child.test, ast.Constant) and child.test.value:
                continue
            evidence += 1
        elif (
            isinstance(child, ast.withitem)
            and isinstance(child.context_expr, ast.Call)
            and "raises" in ast.dump(child.context_expr)
        ):
            evidence += 1
        elif isinstance(child, ast.Raise):
            # An explicit `raise AssertionError(...)` is evidence just as much
            # as `assert`. Counting only the statement form misses proofs that
            # build a message before failing.
            evidence += 1
        elif (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "fail"
        ):
            evidence += 1
        elif isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            # A call into the admission protocol is a refusal that can fire.
            if child.func.id.startswith("require_"):
                evidence += 1
    return evidence


@pytest.mark.parametrize(("label", "template"), SPECIMENS, ids=[s[0] for s in SPECIMENS])
def test_a_named_proof_with_no_executable_evidence_is_refused(label: str, template: str):
    """Correct name, hollow body. Every specimen must be refused.

    These are the shapes a gutted proof actually takes. The last is the subtle
    one: `assert True` satisfies "the body contains an assertion" while being
    incapable of failing, so a check that merely counted `ast.Assert` nodes
    would accept it -- the same substitution one level along.
    """
    source = template.format(name="test_removing_the_control_revives_the_defect")

    assert _defensive_evidence(source, "test_removing_the_control_revives_the_defect") == 0, (
        f"{label}: a body with no executable defensive evidence was accepted"
    )


def test_the_real_kill_bearing_proofs_all_carry_executable_evidence():
    """The control. Without it the refusals above could be 'refuses everything'."""
    hollow: list[str] = []
    for name, relative in KILL_BEARING.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        if _defensive_evidence(source, name) == 0:
            hollow.append(f"{name} in {relative}")
    assert hollow == [], (
        "these functions carry kills in the catalogue but contain no executable "
        f"defensive evidence: {hollow}"
    )


def test_every_catalogue_kill_delegates_to_a_body_bearing_proof():
    """Bind the catalogue to the bodies, not only to the names.

    `delegation_problems` checks a FunctionDef with the right name exists. This
    asserts the same functions also contain something that can fail.
    """
    import test_mutation_catalogue as catalogue  # noqa: PLC0415

    problems: list[str] = []
    for attack in catalogue.CATALOGUE:
        source = (ROOT / attack.owner).read_text(encoding="utf-8")
        if _defensive_evidence(source, attack.killed_by) == 0:
            problems.append(f"{attack.attack_id} -> {attack.killed_by}")
    assert problems == [], (
        f"these attacks delegate to a proof with no executable evidence: {problems}"
    )


def test_static_evidence_is_not_claimed_to_be_execution():
    """The scope limit, asserted so it cannot quietly widen.

    A future reader must not take these checks for proof that the right
    assertion runs on the hostile path. That is the runner's job, and recording
    the boundary here is what stops `ast.Assert` becoming the next name standing
    in for the thing.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    assert "does NOT establish that the right assertion runs" in source, (
        "the scope limit has been edited out of this module's docstring"
    )
    # Structural, not textual. A first attempt asserted that a token was ABSENT
    # from this file, and the assertion contained the token -- so it failed on
    # itself. Checking imports asks whether this module has taken on
    # execution-side work, which is the thing that would actually mean it had
    # widened into the runner's territory.
    imported = {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "mutation_workspace" not in imported, (
        "this module now imports the execution-side harness, so static body "
        "inspection is being wired into the kill verdict rather than kept "
        "alongside it as a catalogue-integrity guard"
    )
