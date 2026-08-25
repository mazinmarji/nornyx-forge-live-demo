"""Root mechanisms, above the individual defects that expressed them.

Fifteen review rounds found real defects in every round, and most of them were
the SAME MECHANISM discovered again one spelling over, because each was
repaired locally. `docs/governance/CLOSURE_PROTOCOL.md` states the rule that
ends that; this module is where the classes live so a new finding can be
classified before it is patched.

A class here is not a description. Each carries an executable probe, so a new
member is caught by the class rather than by the next reviewer.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


@dataclass(frozen=True)
class AttackClass:
    ident: str
    title: str
    #: What actually goes wrong, stated as a mechanism rather than an instance.
    mechanism: str
    #: How the repository decides the question now, instead.
    decided_by: str
    #: Collected test nodes that hold this class down. Checked to exist.
    specimens: tuple[str, ...]
    #: Instances found, kept so a reader can see the class is not theoretical.
    instances: tuple[str, ...] = field(default_factory=tuple)


ATTACK_CLASSES = (
    AttackClass(
        "AC01",
        "a rule that matches a SPELLING rather than deciding the property",
        "A control names the shapes it refuses. Every synonym of those shapes "
        "walks through it, and the control keeps its name. Repairing one "
        "spelling leaves the class open, which is why it kept returning "
        "round after round -- twice by ADDING a spelling to close a "
        "spelling class. The instances below are what has been found, not "
        "a count of what there was.",
        "The rule resolves what the expression DENOTES -- through imports, "
        "aliases, container shapes and type -- and the synonym table below "
        "requires semantically identical inputs to be answered identically.",
        (
            "tests/test_false_green_audit.py::test_a_swallowing_handler_is_found_however_the_class_is_named",
            "tests/test_false_green_audit.py::test_the_screen_is_recognised_however_it_is_named",
            "tests/test_false_green_audit.py::test_a_text_question_about_a_dumped_tree_is_found_however_it_is_written",
            "tests/test_absence_is_not_success.py::test_the_scan_answers_emptiness_and_not_a_list_of_spellings",
            "tests/test_governance_integrity_authority.py::test_a_recorded_pass_is_refused_however_the_artifact_says_otherwise",
        ),
        (
            "SWALLOWING matched three class names; `_Err = AssertionError` escaped",
            "`from contextlib import suppress as quiet` escaped the same rule",
            "the screen filter knew two spellings; `import ... as _screen` escaped",
            "`_empty_return_sites` knew four spellings; `()` and `frozenset()` escaped",
            "the dumped-tree detector knew `in`; `.find`, `.split`, `ast.unparse` escaped",
            "`_status_contradictions` knew `{}`; `[]` and `{'granted': false}` escaped",
            "`_supplies_the_module` counted arity; `f(guard, None)` escaped",
            "`_status_contradictions` again: an ABSENT key, `0`, `false` "
            "and `{'granted': 0}` all escaped the repaired version",
        ),
    ),
    AttackClass(
        "AC02",
        "a fix that nothing fails without",
        "An escape is measured in a throwaway probe, a fix is written, the "
        "probe is discarded. The fix works and no test would notice its "
        "removal, so the next edit -- or the next lint pass -- silently undoes "
        "it. Proven by a reviewer replacing a repaired function's body with "
        "`return True` and watching every control stay green.",
        "Every fix carries a specimen, and the specimen is proven to go RED "
        "when that fix alone is reverted on a copy of the tree.",
        (
            "tests/test_false_green_audit.py::test_a_star_is_not_proof_that_a_module_was_supplied",
            "tests/test_historical_reproof.py::test_removing_the_control_revives_the_defect",
            "tests/test_capability_binding.py::test_reverting_the_derivation_restores_the_mislabelled_record",
        ),
        (
            "`_could_be_a_module` reverted to `return True`: all five wiring controls green",
            "`capability=exercised` reverted: the released high-risk effect filed as low-risk",
            "a signed `findings_digest` that no consumer recomputed: findings scrubbed to [] and a P1 rewritten as `no issues found` both authenticated, while `test_findings_cannot_be_edited_after_review` passed by recomputing the digest ITSELF",
        ),
    ),
    AttackClass(
        "AC03",
        "a claim measured in prose beside a table nobody parses",
        "A count, a rate or a name is typed next to the thing it describes. "
        "The thing changes; the prose does not; nothing reads it. Found in "
        "five separate comments, including one where correcting the headline "
        "left the dependent sentence stale so the block gave two different "
        "answers to its own question.",
        "A derived number is either promoted to a row a guard parses, or "
        "removed. The reasons are kept; the arithmetic is not restated.",
        (
            "tests/test_skip_gate.py::test_the_aggregate_floor_comment_states_the_measured_numbers",
            "tests/test_skip_gate.py::test_the_slack_the_bands_grant_is_the_measured_sum",
            "tests/test_documented_claims.py::test_every_guard_the_repository_cites_by_name_exists",
        ),
        (
            "the census slack: 152, then 163, then 166, then 167 -- five rots",
            "'13 further sites' was 8; 'the seven expecting 1' was eleven",
            "'216 tracked files' was 217, duplicated into two files",
        ),
    ),
    AttackClass(
        "AC04",
        "a widening applied to discovery and not to inspection",
        "A scan finds more things and then looks at them the old way. "
        "`rglob` discovered nested consumers and the basename was still "
        "reported, so a different file was read; attribute-form imports were "
        "discovered and the call filter still required a bare name.",
        "Discovery and inspection share one implementation, and the specimen "
        "constructs the newly discovered shape rather than trusting that "
        "finding it means reading it.",
        (
            "tests/test_false_green_audit.py::test_a_consumer_in_a_subdirectory_keeps_its_path",
            "tests/test_false_green_audit.py::test_no_call_anywhere_asks_the_screen_without_the_module",
        ),
        (
            "`screen_consumers` rglob'd and reported `tests/` + basename",
            "`screen_call_sites` required `ast.Name` after discovery was widened",
        ),
    ),
    AttackClass(
        "AC05",
        "a gate that raises where it is relied on to report",
        "A control's whole value is that it produces a verdict. When it "
        "raises instead, the caller dies and the PREVIOUS verdict is what an "
        "operator reads -- so a damaged state presents as the last good one. "
        "Repaired three times, one exception class at a time, before the "
        "guard was moved to the boundary.",
        "The read boundary catches at the boundary rather than by exception "
        "class, and every derived value a verdict needs is computed where a "
        "failure to compute it becomes a diagnostic.",
        (
            "tests/test_evidence.py::test_a_stream_that_cannot_be_decoded_is_reported",
            "tests/test_evidence.py::test_a_deeply_nested_line_is_reported",
            "tests/test_evidence.py::test_a_torn_line_is_reported_rather_than_raised",
            "tests/test_evidence.py::test_a_sequence_that_is_not_a_number_is_reported_not_raised",
        ),
        (
            "`json.loads` raised out of `_stage` at intake; report.json kept saying pass",
            "`(sequence or expected) + 1` concatenated on a retyped sequence",
            "an invalid UTF-8 byte and 60000 nested arrays both escaped the guard",
        ),
    ),
    AttackClass(
        "AC06",
        "a coarse process exit read as the named subject's verdict",
        "A control runs something in a subprocess and reads `returncode != 0` "
        "as proof that the thing it named failed. A non-zero exit is also a "
        "collection error, a missing fixture, an unrelated import failure, or "
        "a teardown guard -- and when the environment supplies one "
        "unconditionally, every run is a pass. Measured on the AC02 probe "
        "itself: the copied tree was not a git repository, the working-tree "
        "guard raised at teardown on EVERY run, and a semantics-preserving "
        "reformat supplied as a revert made the probe pass.",
        "The workspace is made answerable, the specimen is proven GREEN in "
        "THAT workspace before anything is broken, the edit is proven to "
        "change executable code, and the failure is attributed to the exact "
        "node in the call phase by reading the JUnit report -- never by the "
        "exit code alone.",
        (
            "tests/test_attack_classes.py::test_the_revert_probe_refuses_a_revert_that_changes_nothing",
            "tests/test_false_green_audit.py::test_fg10_a_workspace_whose_baseline_already_fails_is_refused",
            "tests/test_historical_reproof.py::test_removing_the_control_revives_the_defect",
        ),
        (
            "the AC02 probe: rc=1 on every run, from the conftest teardown",
            "FG10: `returncode != 0` credited a kill for a workspace defect, three times",
        ),
    ),
    AttackClass(
        "AC07",
        "a support range declared, and measured at one point in it",
        "The repository declares a range it supports -- `requires-python` is machine-read by pip, and the CI matrix runs every version in it -- and then every local measurement is taken on ONE interpreter. The gates go green, the census goes green, and none of them has asked anything about the other three versions. This is not AC03: the declaration IS parsed. Nothing compares the repository to it.",
        "The floor is DERIVED from `requires-python` rather than typed again, and three axes are measured against it: every module parses at the floor, every specimen source the suite feeds to `ast.parse` parses at the floor, and no module imports a stdlib module newer than the floor without a guarded fallback. The first two are decided by CPython's own parser through `feature_version`, not by a table kept here.",
        (
            "tests/test_attack_classes.py::test_every_module_parses_at_the_declared_floor",
            "tests/test_attack_classes.py::test_every_specimen_source_parses_at_the_declared_floor",
            "tests/test_attack_classes.py::test_no_module_imports_stdlib_newer_than_the_floor",
            "tests/test_attack_classes.py::test_the_floor_is_read_from_the_declaration",
        ),
        (
            "tests/test_xfail_strictness.py imported tomllib (3.11+) at module level: a COLLECTION ERROR on 3.10, losing the module rather than a test",
            "tests/test_false_green_audit.py imported tomllib inside a test",
            "three ROUND_FOUR_SPECIMENS rows are `except*` source, which `ast.parse` rejects on 3.10",
        ),
    ),
)


#: Rules that decide a PROPERTY, with pairs that mean the same thing.
#:
#: THE HELPERS THE AC01 CLASS PROBE DRIVES. The synonym TABLES, and the
#: tests over them, live in `tests/test_attack_classes.py` -- pytest
#: collects nothing from this module, so a table here would be parsed by
#: nothing. The protocol document and the note that stood here both said
#: the tables were "below", and a contributor following that literally
#: would have added a synonym where no parametrize reads it: the local
#: patch the protocol exists to prevent, produced by the protocol's own
#: prose.
#:
#: A new rule of this kind belongs in that module with its synonyms, and
#: so does a new synonym of an existing rule.
def _screen_says(module_source: str, body: str) -> int:
    from guard_evidence import exercised_assertions  # noqa: PLC0415

    lines = ["def guard():", '    """A docstring."""']
    lines += ["    " + line if line.strip() else line for line in body.split(chr(10))]
    source = (
        module_source + (chr(10) if module_source else "")
        + chr(10).join(lines) + chr(10)
    )
    module = ast.parse(source)
    guard = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard"
    )
    return exercised_assertions(guard, module)


def _detector_says(source: str) -> bool:
    from test_false_green_audit import substring_tests_against_a_dumped_tree  # noqa: PLC0415

    return bool(substring_tests_against_a_dumped_tree(ast.parse(source)))


def _contradiction_says(
    payload: dict, location: Path,
    schema: str = "nornyx.forge.independent_review_record.v1",
) -> bool:
    import json  # noqa: PLC0415

    from nornyx_forge.subject_observer import _status_contradictions  # noqa: PLC0415

    # THE SCHEMA IS THE ARTIFACT SAYING WHAT IT IS. A filename is a label
    # someone chose, and reading one to decide an artifact's KIND flagged a
    # machine review that had never claimed an inspection.
    location.write_text(
        json.dumps({"schema": schema, **payload}), encoding="utf-8", newline="",
    )
    return bool(
        _status_contradictions("c.nyx", "a.json", {"status": "pass"}, location)
    )
