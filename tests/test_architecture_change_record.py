"""The architecture change record reports the contract's declared changes.

The claims in `architecture_change_record.json` are derived from the
`changes:` entries of `.nornyx/contracts/architecture_governance.nyx`, and
from the declared approvals those entries name: no git revision, no history
and no clock reach them. It carries two
values, the highest declared architecture impact over every entry and the same
maximum over the entries that are not closed, and it lists every entry as
declared. What it cannot see it says in its own statement.

Five groups:

- the derivation over synthetic contracts: the maximum, which entries count
  for which value, the listing, the statement and its text, the clause naming
  entries whose approval requires the independent review record, and one
  named refusal per malformed shape;
- the vocabulary and the YAML loader, against the installed Nornyx;
- the committed contract and record: the Windows payload entry and its
  separation-of-duties assignment as declared, and the record the evidence
  carries;
- verification: every key, every derived claim and the canonical form;
- the tool end to end in a copy of the repository: the emit site writes the
  derived record, a refusal comes before any write, two revisions over the
  same content give the same claims and inspection subject, and `--verify`
  reports a changed record, and a contract or an evidence file that it cannot
  read or interpret where it reads it, by name and without a traceback.
"""

from __future__ import annotations

import copy
import errno
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import refresh_governance_evidence as tool  # noqa: E402
from mutation_workspace import faithful_copy  # noqa: E402

CONTRACT = ROOT / tool.ARCHITECTURE_CONTRACT
RECORD = tool.EVIDENCE_DIR / tool.CHANGE_RECORD
WINDOWS_PAYLOAD_CHANGE = "architecture.windows_payload_module"
HIGHEST = "highest_declared_architecture_impact"
HIGHEST_OPEN = "highest_open_declared_architecture_impact"

#: Written out rather than read from the tool, so a change to the tool's
#: vocabulary cannot shrink the cases that test it.
STATUSES = ("draft", "proposed", "approved", "in_progress", "completed", "closed",
            "rejected", "rolled_back", "cancelled")
OPEN_STATUSES = tuple(status for status in STATUSES if status != "closed")


def _change(change_id: str, impact: str, status: str = "proposed", **extra) -> dict:
    return {"schema": "nornyx.change.v1", "id": change_id, "type": "architecture_change",
            "status": status, "scope": [f"scope.{change_id}"],
            "impacts": {"security": "none", "architecture": impact, "data": "none",
                        "dependency": "none", "operational": "none"}, **extra}


def _contract(*changes: dict, approvals: list | None = None) -> dict:
    document = {"changes": list(changes), "architecture": {"modules": []}}
    if approvals is not None:
        document["approvals"] = approvals
    return document


def _record(*changes: dict, approvals: list | None = None) -> dict:
    return tool.declared_change_record(_contract(*changes, approvals=approvals))


# ---------------------------------------------------------------------------
# The derivation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("impacts, expected", [
    (["minor"], "minor"),
    (["major", "minor"], "major"),
    (["minor", "major"], "major"),
    (["none", "critical", "minor"], "critical"),
    (["minor", "none"], "minor"),
    (["none", "none"], "none"),
    (["major", "critical"], "critical"),
    (["critical", "major"], "critical"),
    (["minor", "critical", "major"], "critical"),
], ids=["one-minor", "major-first", "major-last", "critical-in-the-middle",
        "minor-then-none", "all-none", "critical-after-major", "critical-before-major",
        "critical-between"])
def test_the_highest_impact_is_the_maximum_on_the_nornyx_scale(impacts, expected):
    """Whatever the order: not the first or last entry, not the least, and not
    the alphabetical largest (which would rank `none` above `critical`)."""
    record = _record(*[_change(f"change.{index}", impact)
                       for index, impact in enumerate(impacts)])
    assert record[HIGHEST] == expected
    assert record[HIGHEST_OPEN] == expected


def test_the_scale_is_pinned_in_order():
    assert tool.ARCHITECTURE_IMPACT_ORDER == ("none", "minor", "major", "critical")


@pytest.mark.parametrize("status", STATUSES)
def test_every_status_counts_in_the_highest_value(status):
    record = _record(_change("change.declared", "major", status), _change("change.other", "minor"))
    assert record[HIGHEST] == "major"


@pytest.mark.parametrize("status", OPEN_STATUSES)
def test_every_status_but_closed_counts_in_the_open_value(status):
    """A rejected, cancelled or rolled-back entry still counts as open until it
    is closed, as the rule says."""
    record = _record(_change("change.declared", "major", status), _change("change.other", "minor"))
    assert record[HIGHEST_OPEN] == "major"


def test_a_closed_entry_counts_in_the_highest_value_and_not_in_the_open_one():
    record = _record(_change("change.done", "critical", "closed"), _change("change.open", "minor"))
    assert record[HIGHEST] == "critical"
    assert record[HIGHEST_OPEN] == "minor"


def test_an_entry_declared_closed_in_the_change_that_introduces_it_still_counts():
    """Nornyx checks a closed entry's own fields only, so an entry can arrive
    already closed. Its declared impact still reaches the highest value."""
    born_closed = _change("change.born_closed", "critical", "closed",
                          transition={"from": "completed", "to": "closed",
                                      "evidence": ["architecture_conformance_report"]},
                          closure_evidence=["architecture_conformance_report"])
    record = _record(born_closed)
    assert record[HIGHEST] == "critical"
    assert record[HIGHEST_OPEN] == "none"


def test_an_entry_of_any_type_counts_in_both_values():
    record = _record(_change("change.security", "major", type="security_change"))
    assert record[HIGHEST] == record[HIGHEST_OPEN] == "major"


def test_an_entry_with_no_scope_counts_and_is_listed_with_an_empty_scope():
    entry = _change("change.a", "major")
    del entry["scope"]
    record = _record(entry)
    assert record[HIGHEST] == record[HIGHEST_OPEN] == "major"
    assert record["declared_changes"][0]["scope"] == []


def test_only_the_architecture_dimension_counts_in_both_values():
    entry = _change("change.a", "none")
    entry["impacts"].update(security="critical", data="major", dependency="major",
                            operational="major")
    record = _record(entry)
    assert record[HIGHEST] == record[HIGHEST_OPEN] == "none"


def test_the_record_lists_every_entry_as_declared_in_declared_order():
    record = _record(_change("z.first", "minor", "approved", scope=["s.1", "s.2", "s.3"]),
                     _change("a.second", "none", "closed"))
    assert record["declared_changes"] == [
        {"id": "z.first", "type": "architecture_change", "status": "approved",
         "architecture_impact": "minor", "scope": ["s.1", "s.2", "s.3"]},
        {"id": "a.second", "type": "architecture_change", "status": "closed",
         "architecture_impact": "none", "scope": ["scope.a.second"]},
    ]
    assert record["impact_rule"] == tool.ARCHITECTURE_IMPACT_RULE


STATEMENTS = {
    "one-open-one-closed-three": (
        [_change("change.zed", "minor"), _change("change.alpha", "major", "in_progress"),
         _change("change.old", "critical", "closed")],
        "The architecture contract declares 3 change entries: change.zed (proposed, "
        "architecture impact minor); change.alpha (in_progress, architecture impact major); "
        "change.old (closed, architecture impact critical). The highest declared "
        "architecture impact is critical. Among the entries that are not closed, it is "
        "major. "),
    "no-entries": (
        [], "The architecture contract declares no change entries, so the highest declared "
            "architecture impact is none. No entry is open, so the highest open declared "
            "architecture impact is none. "),
    "only-closed": (
        [_change("change.done", "major", "closed")],
        "The architecture contract declares 1 change entry: change.done (closed, architecture "
        "impact major). The highest declared architecture impact is major. No entry is open, "
        "so the highest open declared architecture impact is none. "),
    "one-open-declared-none": (
        [_change("change.a", "none")],
        "The architecture contract declares 1 change entry: change.a (proposed, architecture "
        "impact none). The highest declared architecture impact is none. Among the entries "
        "that are not closed, it is none. "),
    "two-declared-none": (
        [_change("change.a", "none"), _change("change.b", "none", "closed")],
        "The architecture contract declares 2 change entries: change.a (proposed, "
        "architecture impact none); change.b (closed, architecture impact none). The highest "
        "declared architecture impact is none. Among the entries that are not closed, it is "
        "none. "),
}


@pytest.mark.parametrize("changes, expected", STATEMENTS.values(), ids=STATEMENTS.keys())
def test_the_statement_is_exact_for_each_shape(changes, expected):
    """Entries are listed in declared order and counted in the right number;
    an entry declared `none` is still listed and still open; the limitation
    always follows, the all-clear case included."""
    assert _record(*changes)["statement"] == expected + tool.CHANGE_RECORD_LIMITATION


def test_the_rule_and_the_limitation_keep_every_clause():
    """Each clause the derivation depends on, word for word, so a rule or a
    limitation that says the opposite cannot pass."""
    rule = tool.ARCHITECTURE_IMPACT_RULE
    for phrase in ("highest_declared_architecture_impact is the highest impacts.architecture "
                   "(none < minor < major < critical) over every changes: entry",
                   "whatever its status, and none when the contract declares no entry",
                   "highest_open_declared_architecture_impact is the same maximum over the "
                   "entries whose status is not terminal",
                   "which is true of closed only",
                   "not the impact of the commit that carries this record",
                   "status and impact are what its author declared",
                   "this record reports them and verifies neither"):
        assert phrase in rule, phrase
    limitation = tool.CHANGE_RECORD_LIMITATION
    for phrase in ("This record reports the changes: entries of the architecture contract "
                   "as declared.",
                   "It does not verify a declared status or impact: an entry may be "
                   "declared closed in the change that introduces it.",
                   "The open value trusts each entry's declared status, including a "
                   "closure and the evidence it cites; this record does not check closure "
                   "evidence.",
                   "It keeps no history: an entry removed from the contract, or one whose "
                   "declared impact is lowered, stops counting, so both values can fall.",
                   "It does not compare the declared architecture between revisions",
                   "cannot detect an architecture change that no entry declares",
                   "a change declared in another contract",
                   "It does not check that the evidence an entry's approval or "
                   "separation-of-duties policy requires has been produced."):
        assert phrase in limitation, phrase
    assert "windows_payload" not in limitation, "the limitation is general; entries are derived"


def test_the_limitation_is_exactly_this_text():
    assert tool.CHANGE_RECORD_LIMITATION == (
        "This record reports the changes: entries of the architecture contract as declared. "
        "It does not verify a declared status or impact: an entry may be declared closed in "
        "the change that introduces it. The open value trusts each entry's declared status, "
        "including a closure and the evidence it cites; this record does not check closure "
        "evidence. It keeps no history: an entry removed from the contract, or one whose "
        "declared impact is lowered, stops counting, so both values can fall. It does not "
        "compare the declared architecture between revisions, so it cannot detect an "
        "architecture change that no entry declares, or a change declared in another "
        "contract. It does not check that the evidence an entry's approval or "
        "separation-of-duties policy requires has been produced.")


def test_the_architecture_block_does_not_reach_the_record():
    """Two in-memory contracts with the same `changes:` and different declared
    architectures give the same record."""
    one = _contract(_change("change.a", "minor"))
    other = copy.deepcopy(one)
    other["architecture"] = {"modules": [{"id": "module.new", "layer": "layer.domain"}]}
    assert tool.declared_change_record(one) == tool.declared_change_record(other)


def _without(key: str) -> dict:
    entry = _change("change.a", "minor")
    del entry[key]
    return entry


def _with_impacts(impacts: object) -> dict:
    entry = _change("change.a", "minor")
    entry["impacts"] = impacts
    return entry


REFUSALS = {
    "not-a-mapping": (["changes"], "the contract is not a mapping"),
    "no-changes-block": ({"architecture": {}}, "there is no changes: block"),
    "changes-a-mapping": ({"changes": {"id": "x"}}, "changes is dict, not a list"),
    "changes-a-string": ({"changes": "none"}, "changes is str, not a list"),
    "entry-not-a-mapping": (_contract("change.a"), "changes[0] is str, not a change entry"),
    "entry-without-id": (_contract(_without("id")), "changes[0] has no id"),
    "blank-id": (_contract(_change(" ", "minor")), "changes[0] has no id"),
    "id-leading-space": (_contract(_change(" change.a", "minor")), "changes[0] has no id"),
    "id-trailing-space": (_contract(_change("change.a ", "minor")), "changes[0] has no id"),
    "id-tab": (_contract(_change("\tchange.a", "minor")), "changes[0] has no id"),
    "id-integer": (_contract(_change(7, "minor")), "changes[0] has no id"),
    "duplicate-id": (_contract(_change("change.a", "minor"), _change("change.a", "none")),
                     "changes[1] repeats the change id 'change.a'"),
    "entry-without-type": (_contract(_without("type")), "changes[0] (change.a) has no type"),
    "blank-type": (_contract(_change("change.a", "minor", type=" ")),
                   "changes[0] (change.a) has no type"),
    "type-leading-space": (_contract(_change("change.a", "minor", type=" architecture_change")),
                           "changes[0] (change.a) has no type"),
    "type-trailing-space": (_contract(_change("change.a", "minor", type="architecture_change ")),
                            "changes[0] (change.a) has no type"),
    "type-tab": (_contract(_change("change.a", "minor", type="\tarchitecture_change")),
                 "changes[0] (change.a) has no type"),
    "type-a-list": (_contract(_change("change.a", "minor", type=["architecture_change"])),
                    "changes[0] (change.a) has no type"),
    "no-status": (_contract(_without("status")),
                  "changes[0] (change.a) declares no status. nornyx.change.v1 does not "
                  "require one, but this record cannot tell whether an entry without one "
                  "is closed"),
    "unknown-status": (_contract(_change("change.a", "minor", "merged")),
                       "has status 'merged', which is not a nornyx.change.v1 status"),
    "status-null": (_contract(_change("change.a", "minor", None)),
                    "has status None, which is not a nornyx.change.v1 status"),
    "status-capitalised": (_contract(_change("change.a", "major", "Closed")),
                           "has status 'Closed', which is not"),
    "status-upper": (_contract(_change("change.a", "major", "CLOSED")),
                     "has status 'CLOSED', which is not"),
    "status-leading-space": (_contract(_change("change.a", "major", " closed")),
                             "has status ' closed', which is not"),
    "status-trailing-space": (_contract(_change("change.a", "major", "closed ")),
                              "has status 'closed ', which is not"),
    "status-a-list": (_contract(_change("change.a", "major", ["closed"])),
                      "has status ['closed'], which is not"),
    "status-a-mapping": (_contract(_change("change.a", "major", {"closed": True})),
                         "has status {'closed': True}, which is not"),
    "status-a-boolean": (_contract(_change("change.a", "major", True)),
                         "has status True, which is not"),
    "no-impacts": (_contract(_without("impacts")),
                   "changes[0] (change.a) declares no impacts.architecture"),
    "impacts-a-list": (_contract(_with_impacts(["minor"])),
                       "changes[0] (change.a) declares no impacts.architecture"),
    "impacts-a-word": (_contract(_with_impacts("architecture")),
                       "changes[0] (change.a) declares no impacts.architecture"),
    "impacts-containing-the-word": (_contract(_with_impacts("xarchitecturex")),
                                    "changes[0] (change.a) declares no impacts.architecture"),
    "impacts-an-integer": (_contract(_with_impacts(5)),
                           "changes[0] (change.a) declares no impacts.architecture"),
    "impacts-a-boolean": (_contract(_with_impacts(True)),
                          "changes[0] (change.a) declares no impacts.architecture"),
    "no-architecture-impact": (_contract(_with_impacts({"security": "minor"})),
                               "changes[0] (change.a) declares no impacts.architecture"),
    "unknown-impact": (_contract(_change("change.a", "huge")),
                       "declares architecture impact 'huge', which is not one of"),
    "impact-capitalised": (_contract(_change("change.a", "Major")),
                           "declares architecture impact 'Major', which is not one of"),
    "impact-upper": (_contract(_change("change.a", "MAJOR")),
                     "declares architecture impact 'MAJOR', which is not one of"),
    "impact-leading-space": (_contract(_change("change.a", " major")),
                             "declares architecture impact ' major', which is not one of"),
    "impact-trailing-space": (_contract(_change("change.a", "major ")),
                              "declares architecture impact 'major ', which is not one of"),
    "impact-tab": (_contract(_change("change.a", "\tmajor")),
                   "declares architecture impact '\\tmajor', which is not one of"),
    "impact-null": (_contract(_change("change.a", None)),
                    "declares architecture impact None, which is not one of"),
    "impact-integer": (_contract(_change("change.a", 1)),
                       "declares architecture impact 1, which is not one of"),
    "impact-a-list": (_contract(_change("change.a", ["major"])),
                      "declares architecture impact ['major'], which is not one of"),
    "scope-not-a-list": (_contract(_change("change.a", "minor", scope="module.a")),
                         "has a scope that is not a list of ids"),
    "scope-null": (_contract(_change("change.a", "minor", scope=None)),
                   "has a scope that is not a list of ids"),
    "scope-holding-null": (_contract(_change("change.a", "minor", scope=[None])),
                           "has a scope that is not a list of ids"),
    "approval-ids-not-a-list": (
        _contract(_change("change.a", "minor", approval_ids="ArchitectureAuthority")),
        "changes[0] (change.a) has approval_ids that are not a list of ids"),
    "required-evidence-holding-null": (
        _contract(_change("change.a", "minor", required_evidence=[None])),
        "changes[0] (change.a) has required_evidence that is not a list of ids"),
    "approvals-a-mapping": (_contract(_change("change.a", "minor"), approvals={"name": "A"}),
                            "approvals is dict, not a list of approvals"),
    "approval-without-name": (_contract(_change("change.a", "minor"),
                                        approvals=[{"required_evidence": []}]),
                              "approvals[0] has no name"),
    "approval-evidence-not-a-list": (
        _contract(_change("change.a", "minor"),
                  approvals=[{"name": "A", "required_evidence": "independent_review_record"}]),
        "approvals[0] (A) has required_evidence that is not a list of ids"),
    "approval-evidence-null": (
        _contract(_change("change.a", "minor"),
                  approvals=[{"name": "A", "required_evidence": None}]),
        "approvals[0] (A) has required_evidence that is not a list of ids"),
}


@pytest.mark.parametrize("document, message", REFUSALS.values(), ids=REFUSALS.keys())
def test_a_malformed_changes_block_is_refused_by_name(document, message):
    """One named refusal per shape. A skipped entry would lower a derived
    impact, so nothing is skipped."""
    with pytest.raises(tool.ChangeRecordRefusal) as refused:
        tool.declared_change_record(document)
    assert message in str(refused.value)
    assert str(refused.value).startswith(tool.ARCHITECTURE_CONTRACT)


def test_closure_evidence_is_not_checked():
    """The limitation says the open value trusts a declared closure and the
    evidence it cites. An entry closed on the change record itself, in either
    place, is derived like any other, and still counts in the highest value."""
    entry = _change("change.a", "critical", "closed",
                    transition={"from": "completed", "to": "closed", "evidence": ["change_record"]},
                    closure_evidence=["change_record"])
    record = _record(entry)
    assert record[HIGHEST] == "critical"
    assert record[HIGHEST_OPEN] == "none"


REVIEW_APPROVALS = [
    {"name": "ReviewedAuthority",
     "required_evidence": ["conformance_report", "independent_review_record"]},
    {"name": "PlainAuthority", "required_evidence": ["conformance_report"]},
]


def test_the_review_clause_names_each_entry_whose_approval_requires_the_record():
    """Derived from the approvals each entry names, in declared order, saying
    whether the entry lists the record itself; an entry whose approvals do not
    require it, or that names none, is not mentioned."""
    record = _record(
        _change("change.lists", "minor", approval_ids=["ReviewedAuthority"],
                required_evidence=["independent_review_record"]),
        _change("change.plain", "minor", approval_ids=["PlainAuthority"]),
        _change("change.omits", "none", approval_ids=["PlainAuthority", "ReviewedAuthority"]),
        _change("change.none", "none"),
        approvals=REVIEW_APPROVALS)
    assert record["statement"].endswith(
        tool.CHANGE_RECORD_LIMITATION + " Entries naming an approval that requires "
        "independent_review_record: change.lists names ReviewedAuthority and lists it among "
        "its own required evidence; change.omits names ReviewedAuthority and does not list it "
        "among its own required evidence. Whether a passing independent_review_record exists "
        "is not shown here.")


SEVERAL_REQUIRING = [
    {"name": "First", "required_evidence": ["independent_review_record"]},
    {"name": "Second", "required_evidence": ["independent_review_record", "x"]},
    {"name": "Plain", "required_evidence": []},
]


def test_every_approval_that_requires_the_record_is_named_in_declared_order():
    """Each requiring approval an entry names, in the order the entry names
    them; an approval that does not require the record is left out."""
    record = _record(
        _change("change.a", "minor", approval_ids=["First", "Plain", "Second"]),
        _change("change.b", "minor", approval_ids=["Second"],
                required_evidence=["independent_review_record"]),
        approvals=SEVERAL_REQUIRING)
    assert record["statement"].endswith(
        " Entries naming an approval that requires independent_review_record: change.a names "
        "First, Second and does not list it among its own required evidence; change.b names "
        "Second and lists it among its own required evidence. Whether a passing "
        "independent_review_record exists is not shown here.")


@pytest.mark.parametrize("name", [" ", "", " A", "A ", 7], ids=["blank", "empty", "leading-space",
                                                              "trailing-space", "integer"])
def test_an_approval_whose_name_is_not_canonical_is_refused_by_name(name):
    with pytest.raises(tool.ChangeRecordRefusal, match=r"approvals\[0\] has no name"):
        _record(_change("change.a", "minor"), approvals=[{"name": name, "required_evidence": []}])


def test_an_approval_with_no_required_evidence_requires_nothing():
    """Not a crash, and not a requirement: an approval that declares no
    required evidence does not require the review record."""
    record = _record(_change("change.a", "minor", approval_ids=["Bare"]),
                     approvals=[{"name": "Bare"}])
    assert record["statement"].endswith(tool.CHANGE_RECORD_LIMITATION)


@pytest.mark.parametrize("approvals", [None, [], REVIEW_APPROVALS[1:]],
                         ids=["no-approvals-block", "no-approvals", "none-requires-the-record"])
def test_no_review_clause_when_no_named_approval_requires_the_record(approvals):
    record = _record(_change("change.a", "minor", approval_ids=["PlainAuthority"]),
                     approvals=approvals)
    assert record["statement"].endswith(tool.CHANGE_RECORD_LIMITATION)


def test_a_refusal_is_a_system_exit():
    """So the tool stops with the message, not a traceback; the end-to-end
    tests below assert the stderr."""
    assert issubclass(tool.ChangeRecordRefusal, SystemExit)


CONTRACT_ENTRY = (b"changes:\n  - id: change.a\n    type: architecture_change\n"
                  b"    status: proposed\n    impacts: {architecture: minor}\n")
UNREADABLE = {
    "missing": (None, "the contract is not present"),
    "a-directory": ("directory", "the contract cannot be read"),
    "yaml-error": (b"changes: [unclosed\n", "the contract is not parseable YAML ("),
    "not-utf8": (b"changes: []\nnote: \xff\xfe\n", "the contract is not parseable YAML ("),
    "two-documents": (b"---\nchanges: []\n---\nchanges: []\n",
                      "the contract is not parseable YAML ("),
    "python-tag": (b"changes: !!python/object/apply:os.getcwd []\n",
                   "the contract is not parseable YAML ("),
    "invalid-date": (CONTRACT_ENTRY + b"x: 2026-13-45\n", "month must be in 1..12"),
    "year-zero": (CONTRACT_ENTRY + b"x: 0000-01-01\n", "the contract is not parseable YAML ("),
    "invalid-time": (CONTRACT_ENTRY + b"x: 2026-01-01 25:61:61\n", "hour must be in 0..23"),
    "invalid-offset": (CONTRACT_ENTRY + b"x: 2026-01-01T00:00:00+99:99\n",
                       "the contract is not parseable YAML ("),
    "escape-out-of-range": (CONTRACT_ENTRY + b'x: "\\UFFFFFFFF"\n',
                            "the contract is not parseable YAML ("),
    "bad-int-tag": (CONTRACT_ENTRY + b"x: !!int abc\n", "the contract is not parseable YAML ("),
    "bad-float-tag": (CONTRACT_ENTRY + b"x: !!float abc\n", "the contract is not parseable YAML ("),
    "bool-maybe": (CONTRACT_ENTRY + b"x: !!bool maybe\n", "the contract is not parseable YAML ("),
    "bool-empty": (CONTRACT_ENTRY + b"x: !!bool\n", "the contract is not parseable YAML ("),
    "int-empty": (CONTRACT_ENTRY + b"x: !!int ''\n", "the contract is not parseable YAML ("),
    "float-empty": (CONTRACT_ENTRY + b"x: !!float\n", "the contract is not parseable YAML ("),
    "timestamp-abc": (CONTRACT_ENTRY + b"x: !!timestamp abc\n",
                      "the contract is not parseable YAML ("),
    "set-of-a-scalar": (CONTRACT_ENTRY + b"x: !!set [a]\n", "the contract is not parseable YAML ("),
    "bool-maybe-key": (CONTRACT_ENTRY + b"? !!bool maybe\n: v\n",
                       "the contract is not parseable YAML ("),
    "duplicate-top-level-key": (CONTRACT_ENTRY + b"changes: []\n",
                                "found duplicate key 'changes'"),
    "duplicate-key-in-an-entry": (CONTRACT_ENTRY + b"    status: closed\n",
                                  "found duplicate key 'status'"),
    "duplicate-key-in-a-flow-mapping": (
        b"changes: [{id: change.a, type: architecture_change, status: closed, status: proposed, "
        b"impacts: {architecture: minor}}]\n", "found duplicate key 'status'"),
    "duplicate-integer-key": (CONTRACT_ENTRY + b"1: a\n1: b\n", "found duplicate key 1"),
    "duplicate-boolean-key": (CONTRACT_ENTRY + b"true: a\ntrue: b\n", "found duplicate key True"),
    "unhashable-key": (CONTRACT_ENTRY + b"? [a, b]\n: v\n", "found unhashable key"),
    "deep-nesting": (b"changes: " + b"[" * 5000 + b"]" * 5000 + b"\n",
                     "the contract nests too deeply to parse"),
}

def _contract_bytes_at(monkeypatch, tmp_path, content) -> None:
    target = tmp_path / tool.ARCHITECTURE_CONTRACT
    if content == "directory":
        target.mkdir(parents=True)
    elif content is not None:
        target.parent.mkdir(parents=True)
        target.write_bytes(content)
    monkeypatch.setattr(tool, "ROOT", tmp_path)


@pytest.mark.parametrize("content, message", UNREADABLE.values(), ids=UNREADABLE.keys())
def test_a_contract_the_tool_cannot_read_is_refused_by_name(monkeypatch, tmp_path,
                                                           content, message):
    _contract_bytes_at(monkeypatch, tmp_path, content)
    with pytest.raises(tool.ChangeRecordRefusal) as refused:
        tool.architecture_change_record()
    assert message in str(refused.value)


@pytest.mark.parametrize("raised", [OverflowError("Python int too large to convert to C int"),
                                    KeyError("maybe"), IndexError("string index out of range"),
                                    AttributeError("'NoneType' object has no attribute 'x'"),
                                    TypeError("cannot unpack non-iterable ScalarNode object")],
                         ids=["overflow", "key", "index", "attribute", "type"])
def test_the_build_loader_names_every_class_construction_raises(monkeypatch, tmp_path, raised):
    """On every Python, whichever class a given input raises there: the loader's
    catch is not narrowed to the classes one interpreter happens to raise."""
    _contract_bytes_at(monkeypatch, tmp_path, CONTRACT_ENTRY)

    def failing(*_args, **_kwargs):
        raise raised
    monkeypatch.setattr(tool.yaml, "load", failing)
    with pytest.raises(tool.ChangeRecordRefusal) as refused:
        tool.architecture_change_record()
    assert "the contract is not parseable YAML (" in str(refused.value)


def test_the_loader_accepts_a_merge_key(monkeypatch, tmp_path):
    _contract_bytes_at(monkeypatch, tmp_path,
                       b"base: &b {status: proposed, impacts: {architecture: major}}\nchanges:\n"
                       b"  - <<: *b\n    id: change.a\n    type: architecture_change\n")
    assert tool.architecture_change_record()[HIGHEST] == "major"


def _failing_read(monkeypatch, name: str) -> None:
    original = Path.read_bytes

    def read_bytes(self):
        if self.name == name:
            raise OSError(errno.EIO, "input/output error")
        return original(self)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)


def test_an_io_error_on_the_contract_is_refused_by_name(monkeypatch, tmp_path):
    """Any OSError, not only the PermissionError a directory gives on Windows."""
    _contract_bytes_at(monkeypatch, tmp_path, CONTRACT_ENTRY)
    _failing_read(monkeypatch, Path(tool.ARCHITECTURE_CONTRACT).name)
    with pytest.raises(tool.ChangeRecordRefusal) as refused:
        tool.architecture_change_record()
    assert "the contract cannot be read (OSError)" in str(refused.value)


# ---------------------------------------------------------------------------
# The vocabulary and the loader, against the installed Nornyx
# ---------------------------------------------------------------------------

def test_the_vocabulary_is_nornyx_s():
    """The tool restates nornyx.change.v1 rather than importing Nornyx; this
    is where a Nornyx upgrade that moves it fails."""
    from importlib.resources import files  # noqa: PLC0415

    from nornyx.governance.structural import (  # noqa: PLC0415
        ARCHITECTURE_IMPACTS,
        CHANGE_TRANSITIONS,
    )

    schema = json.loads(files("nornyx").joinpath("schemas/change_v1.schema.json")
                        .read_text(encoding="utf-8"))
    assert set(schema["$defs"]["status"]["enum"]) == tool.CHANGE_STATUSES == set(STATUSES)
    assert set(CHANGE_TRANSITIONS) == tool.CHANGE_STATUSES
    assert {status for status, after in CHANGE_TRANSITIONS.items() if not after} \
        == tool.TERMINAL_CHANGE_STATUSES == {"closed"}
    assert set(schema["$defs"]["impacts"]["properties"]["architecture"]["enum"]) \
        == set(tool.ARCHITECTURE_IMPACT_ORDER) == ARCHITECTURE_IMPACTS


def test_the_loader_reads_the_whole_committed_contract_as_nornyx_does():
    """The whole document, not only `changes:`. The loaders do differ in one
    respect this contract does not exercise: Nornyx resolves only true and
    false as booleans, and this loader keeps YAML 1.1's yes, no, on and off.
    That only ever makes the record refuse, because it accepts no boolean where
    it reads a string."""
    from nornyx.parser import NornyxSafeLoader  # noqa: PLC0415

    raw = CONTRACT.read_bytes()
    ours = yaml.load(raw, Loader=tool._ContractLoader)  # noqa: S506 - SafeLoader subclasses
    theirs = yaml.load(raw, Loader=NornyxSafeLoader)  # noqa: S506
    assert ours == theirs


@pytest.mark.parametrize("content", [
    UNREADABLE["duplicate-top-level-key"][0], UNREADABLE["duplicate-key-in-an-entry"][0],
    UNREADABLE["duplicate-key-in-a-flow-mapping"][0], UNREADABLE["duplicate-integer-key"][0],
    UNREADABLE["duplicate-boolean-key"][0]],
    ids=["top-level", "in-an-entry", "flow-mapping", "integer-key", "boolean-key"])
def test_the_loader_refuses_a_repeated_key_as_nornyx_does(content):
    from nornyx.parser import NornyxSafeLoader  # noqa: PLC0415

    for loader in (tool._ContractLoader, NornyxSafeLoader):
        with pytest.raises(yaml.constructor.ConstructorError, match="found duplicate key"):
            yaml.load(content, Loader=loader)  # noqa: S506


# ---------------------------------------------------------------------------
# The committed contract and record
# ---------------------------------------------------------------------------

def _document() -> dict:
    return yaml.load(CONTRACT.read_bytes(), Loader=tool._ContractLoader)  # noqa: S506


def _declared_ids(architecture: dict) -> set[str]:
    return {entry["id"] for entries in architecture.values() if isinstance(entries, list)
            for entry in entries if isinstance(entry, dict) and "id" in entry}


def test_the_windows_payload_entry_is_declared_as_committed():
    """The whole entry, field by field, as committed: the change the payload
    module's addition is recorded by. Approving or closing it changes the
    entry on purpose, and this test with it."""
    document = _document()
    [entry] = [item for item in document["changes"] if item["id"] == WINDOWS_PAYLOAD_CHANGE]
    assert entry == {
        "schema": "nornyx.change.v1",
        "id": WINDOWS_PAYLOAD_CHANGE,
        "type": "architecture_change",
        "purpose": "Declare nornyx_forge.windows_payload, the Windows payload manifest and its "
                   "standard-library self-check, as a module of the Windows runtime component.",
        "status": "proposed",
        "transition": {"from": "draft", "to": "proposed",
                       "evidence": ["architecture_conformance_report"]},
        "scope": ["component.windows_runtime", "module.windows_payload"],
        "excluded_scope": [],
        "risk_tier": "medium",
        "blast_radius": "component",
        "reversibility": "reversible",
        "rollback_required": False,
        "rollback_plan_artifact": None,
        "irreversible_authority": None,
        "impacts": {"security": "minor", "architecture": "minor", "data": "none",
                    "dependency": "none", "operational": "none"},
        "required_controls": ["architecture_conformance_policy", "separation_of_duties_policy"],
        "required_evidence": ["architecture_conformance_report", "independent_review_record"],
        "approver_roles": ["architecture_reviewer"],
        "approval_ids": ["ArchitectureAuthority"],
        "separation_of_duties": {"author_role": "repository_maintainer",
                                 "approver_role": "architecture_reviewer", "disjoint": True},
        "exceptions": [],
    }
    assert set(entry["scope"]) <= _declared_ids(document["architecture"])


CANONICAL_TEXT_CHANGE = "architecture.canonical_text_rule"


def test_the_canonical_text_rule_touch_is_declared_as_committed():
    """The boundary touch of `src/nornyx_forge/governed_subject.py` is named by
    a declared change, whole, as committed: the three suffixes it adds, at
    architecture impact none (no module, dependency or layer moves) and
    security impact minor. Approving or closing it changes the entry on
    purpose, and this test with it."""
    document = _document()
    [entry] = [item for item in document["changes"] if item["id"] == CANONICAL_TEXT_CHANGE]
    assert entry == {
        "schema": "nornyx.change.v1",
        "id": CANONICAL_TEXT_CHANGE,
        "type": "architecture_change",
        "purpose": "Name .nsi, .nsh and .ps1 in CANONICAL_TEXT_SUFFIXES of "
                   "nornyx_forge.governed_subject, so the Windows installer's sources are "
                   "governed as LF text.",
        "status": "proposed",
        "transition": {"from": "draft", "to": "proposed",
                       "evidence": ["architecture_conformance_report"]},
        "scope": ["component.governed_subject", "module.governed_subject"],
        "excluded_scope": [],
        "risk_tier": "medium",
        "blast_radius": "component",
        "reversibility": "reversible",
        "rollback_required": False,
        "rollback_plan_artifact": None,
        "irreversible_authority": None,
        "impacts": {"security": "minor", "architecture": "none", "data": "none",
                    "dependency": "none", "operational": "none"},
        "required_controls": ["architecture_conformance_policy", "separation_of_duties_policy"],
        "required_evidence": ["architecture_conformance_report", "independent_review_record"],
        "approver_roles": ["architecture_reviewer"],
        "approval_ids": ["ArchitectureAuthority"],
        "separation_of_duties": {"author_role": "repository_maintainer",
                                 "approver_role": "architecture_reviewer", "disjoint": True},
        "exceptions": [],
    }
    assert set(entry["scope"]) <= _declared_ids(document["architecture"])
    [assignment] = [item for item in document["separation_of_duties"]["assignments"]
                    if item["subject"] == CANONICAL_TEXT_CHANGE]
    assert assignment["evidence_producers"] == ["tool:check_architecture",
                                                "tool:in_session_inspectors"]
    assert assignment["require_evidence_independence"] is True


def test_the_declared_canonical_text_touch_is_what_the_source_changes():
    """The entry names the suffixes the source gains. The source's tuple holds
    exactly those three beyond the base list, and the entry's purpose names the
    same three, so a fourth suffix added later is not covered by it."""
    from nornyx_forge.governed_subject import CANONICAL_TEXT_SUFFIXES  # noqa: PLC0415

    base = {".py", ".pyi", ".md", ".toml", ".yml", ".yaml", ".json", ".cfg", ".ini", ".txt",
            ".sh", ".nyx", ".gitignore", ".gitattributes", ".dockerignore", ".js", ".mjs",
            ".cjs", ".ts", ".html", ".htm", ".css", ".svg", ".xml", ".sql", ".env", ".lock",
            ".rst", ".csv"}
    assert set(CANONICAL_TEXT_SUFFIXES) - base == {".nsi", ".nsh", ".ps1"}
    assert base <= set(CANONICAL_TEXT_SUFFIXES), "no suffix of the base list was dropped"
    [entry] = [item for item in _document()["changes"] if item["id"] == CANONICAL_TEXT_CHANGE]
    assert all(suffix in entry["purpose"] for suffix in (".nsi", ".nsh", ".ps1"))


def test_the_windows_payload_assignment_is_declared_as_committed():
    """The separation-of-duties assignment that names the entry, whole. Its
    producers are those of the entry's evidence, as for the existing
    assignment: the conformance checker and the in-session inspectors."""
    [assignment] = [item for item in _document()["separation_of_duties"]["assignments"]
                    if item["subject"] == WINDOWS_PAYLOAD_CHANGE]
    assert assignment == {
        "subject": WINDOWS_PAYLOAD_CHANGE, "risk_tier": "medium",
        "author": "human:repository_maintainer", "approvers": ["human:architecture_reviewer"],
        "evidence_producers": ["tool:check_architecture", "tool:in_session_inspectors"],
        "require_evidence_independence": True, "release_requester": None,
        "final_release_approver": None, "exception_requester": None,
        "exception_approver": None}


def test_the_windows_payload_entry_names_the_approval_the_contract_requires():
    """`ArchitectureAuthority` is required to merge an architecture change; the
    entry names it and the role it requires."""
    document = _document()
    [entry] = [item for item in document["changes"] if item["id"] == WINDOWS_PAYLOAD_CHANGE]
    [authority] = [item for item in document["approvals"]
                   if item["name"] == "ArchitectureAuthority"]
    assert "merge_architecture_change" in authority["required_for"]
    assert "ArchitectureAuthority" in entry["approval_ids"]
    assert set(authority["required_roles"]) <= set(entry["approver_roles"])


def test_the_committed_entry_and_architecture_agree():
    document = _document()
    architecture = document["architecture"]
    runtime = next(item for item in architecture["components"]
                   if item["id"] == "component.windows_runtime")
    assert "module.windows_payload" in runtime["modules"]
    module = next(item for item in architecture["modules"]
                  if item["id"] == "module.windows_payload")
    assert module["component"] == "component.windows_runtime"
    assert module["name"] == "nornyx_forge.windows_payload"


def test_the_committed_record_is_what_the_contract_derives():
    recorded = json.loads(RECORD.read_text(encoding="utf-8"))
    assert recorded["schema"] == tool.CHANGE_RECORD_SCHEMA
    derived = tool.architecture_change_record()
    assert {key: recorded[key] for key in derived} == derived
    assert tool.change_record_problems() == []
    declared = {entry["id"]: entry["impacts"]["architecture"]
                for entry in _document()["changes"]}
    listed = {entry["id"]: entry["architecture_impact"] for entry in recorded["declared_changes"]}
    assert listed == declared


def test_the_committed_record_states_the_review_record_clause_it_derives():
    """The clause the record derives for the committed contract: all three entries
    name ArchitectureAuthority, which requires the independent review record,
    and all list it among their own required evidence."""
    statement = json.loads(RECORD.read_text(encoding="utf-8"))["statement"]
    assert statement.endswith(
        " Entries naming an approval that requires independent_review_record: "
        "architecture.nornyx_forge_demo names ArchitectureAuthority and lists it among its "
        "own required evidence; architecture.windows_payload_module names "
        "ArchitectureAuthority and lists it among its own required evidence; "
        "architecture.canonical_text_rule names ArchitectureAuthority and lists it among "
        "its own required evidence. Whether "
        "a passing independent_review_record exists is not shown here.")


def test_the_review_clause_does_not_read_the_review_record_s_status():
    """The clause is derived from declarations only. A passing review record
    changes nothing in the record, which is part of the subject an inspection
    is bound to and so must not move with that inspection's outcome."""
    document = _document()
    passing = copy.deepcopy(document)
    for record in passing["governance_evidence"]["records"]:
        if record["id"] == "independent_review_record":
            record["status"] = "pass"
    assert tool.declared_change_record(passing) == tool.declared_change_record(document)


def test_no_passing_independent_review_record_is_recorded_today():
    """The entry comment and the PR text say no passing independent review
    record exists. They are true while this holds; when one is produced this
    fails, and they are updated with it."""
    [record] = [item for item in _document()["governance_evidence"]["records"]
                if item["id"] == "independent_review_record"]
    assert record["status"] != "pass"


def test_no_python_file_outside_the_generator_and_the_tests_names_the_value_keys():
    """The record's three value keys appear in no tracked Python file except the
    generator and the tests. `src/nornyx_forge/subject_observer.py` reads the
    record's file to digest it and to read its schema; it does not name these
    keys. The record's other claims, `impact_rule` and `statement`, share their
    names with other artifacts' fields and are not pinned this way."""
    tracked = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, check=True,  # noqa: S603
                             capture_output=True, text=True, timeout=120).stdout.split()
    keys = re.compile(r"highest_declared_architecture_impact|highest_open_declared_architecture"
                      r"_impact|declared_changes")
    readers = sorted(name for name in tracked if not name.startswith("tests/")
                     and keys.search((ROOT / name).read_text(encoding="utf-8")))
    assert readers == ["scripts/refresh_governance_evidence.py"]


# ---------------------------------------------------------------------------
# Verification: every key, every derived claim and the canonical form
# ---------------------------------------------------------------------------

PROVENANCE = {"subject_revision": "git:" + "0" * 40, "generated_at": "2026-01-01T00:00:00Z",
              "governed_input_digest": "sha256:" + "0" * 64}


def _full_record(contract: dict) -> dict:
    return {"schema": tool.CHANGE_RECORD_SCHEMA, **PROVENANCE,
            **tool.declared_change_record(contract)}


def _tool_at(monkeypatch, tmp_path, contract: dict, record: dict | bytes | str | None) -> None:
    target = tmp_path / tool.ARCHITECTURE_CONTRACT
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump(contract), encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    if isinstance(record, dict):
        (evidence / tool.CHANGE_RECORD).write_bytes(tool._canonical_bytes(record))
    elif isinstance(record, bytes):
        (evidence / tool.CHANGE_RECORD).write_bytes(record)
    elif record == "directory":
        (evidence / tool.CHANGE_RECORD).mkdir()
    monkeypatch.setattr(tool, "ROOT", tmp_path)
    monkeypatch.setattr(tool, "EVIDENCE_DIR", evidence)


CONTRACT_TWO = _contract(_change("change.a", "minor"), _change("change.b", "none"))


def test_verification_accepts_the_record_the_tool_writes(monkeypatch, tmp_path):
    _tool_at(monkeypatch, tmp_path, CONTRACT_TWO, _full_record(CONTRACT_TWO))
    assert tool.change_record_problems() == []


def test_the_canonical_form_is_the_evidence_form():
    """`_write` and verification share `_canonical_bytes`, so only a literal
    pins the form itself: indented by two, keys sorted, a final newline."""
    assert tool._canonical_bytes({"b": 1, "a": [2]}) == b'{\n  "a": [\n    2\n  ],\n  "b": 1\n}\n'


def _edit(key: str, value: object):
    def apply(record: dict) -> None:
        record[key] = value
    return apply


def _drop(key: str):
    def apply(record: dict) -> None:
        del record[key]
    return apply


EDITS = {
    "highest-impact": (_edit(HIGHEST, "none"), f"at: {HIGHEST}"),
    "open-impact": (_edit(HIGHEST_OPEN, "none"), f"at: {HIGHEST_OPEN}"),
    "impact-rule": (_edit("impact_rule", "Whatever the author says."), "at: impact_rule"),
    "statement": (_edit("statement", "Nothing changed."), "at: statement"),
    "schema": (_edit("schema", "nornyx.forge.change_record.v1"), "at: schema"),
    "entries-reordered": (lambda record: record["declared_changes"].reverse(),
                          "at: declared_changes"),
    "entry-edited-in-place": (lambda record: record["declared_changes"][1].update(status="closed"),
                              "at: declared_changes"),
    "entry-dropped": (lambda record: record["declared_changes"].pop(), "at: declared_changes"),
    "extra-key": (_edit("assessed_architecture_impact", "none"),
                  "keys the tool does not write: assessed_architecture_impact"),
    "legacy-v1-key": (_edit("architecture_impact", "none"),
                      "keys the tool does not write: architecture_impact"),
    **{f"missing-{key}": (_drop(key), f"missing keys: {key}")
       for key in ("schema", HIGHEST, HIGHEST_OPEN, "declared_changes", "impact_rule",
                   "statement", "subject_revision", "generated_at", "governed_input_digest")},
}


@pytest.mark.parametrize("edit, message", EDITS.values(), ids=EDITS.keys())
def test_verification_refuses_a_record_the_tool_would_not_write(monkeypatch, tmp_path,
                                                               edit, message):
    record = _full_record(CONTRACT_TWO)
    edit(record)
    _tool_at(monkeypatch, tmp_path, CONTRACT_TWO, record)
    [problem] = tool.change_record_problems()
    assert message in problem


@pytest.mark.parametrize("value", [b'"none"', b'"minor"'], ids=["different-value", "same-value"])
def test_verification_refuses_a_repeated_key_placed_first(monkeypatch, tmp_path, value):
    """A reader keeping the first of two keys would see the first value. The
    record may hold only one, whatever the two values are."""
    honest = tool._canonical_bytes(_full_record(CONTRACT_TWO))
    forged = honest.replace(b"{\n", b'{\n  "highest_declared_architecture_impact": ' + value
                            + b",\n", 1)
    _tool_at(monkeypatch, tmp_path, CONTRACT_TWO, forged)
    [problem] = tool.change_record_problems()
    assert "repeats the key(s) highest_declared_architecture_impact" in problem


FORMS = {
    "compact": lambda raw: json.dumps(json.loads(raw), sort_keys=True).encode("utf-8"),
    "extra-final-newline": lambda raw: raw + b"\n",
    "no-final-newline": lambda raw: raw.rstrip(b"\n"),
    "leading-blank-line": lambda raw: b"\n" + raw,
    "crlf": lambda raw: raw.replace(b"\n", b"\r\n"),
}


@pytest.mark.parametrize("reform", FORMS.values(), ids=FORMS.keys())
def test_verification_refuses_a_record_not_in_the_tool_s_form(monkeypatch, tmp_path, reform):
    raw = reform(tool._canonical_bytes(_full_record(CONTRACT_TWO)))
    _tool_at(monkeypatch, tmp_path, CONTRACT_TWO, raw)
    [problem] = tool.change_record_problems()
    assert "is not in the form the tool writes" in problem


UNCHECKABLE = {
    "missing": (None, _contract(), "architecture_change_record.json is missing"),
    "a-directory": ("directory", _contract(), "architecture_change_record.json cannot be read"),
    "not-json": (b"{not json", _contract(), "architecture_change_record.json is not readable JSON"),
    "not-utf8": (b'{"a": "\xff"}', _contract(), "is not readable JSON"),
    "not-an-object": (b"[]", _contract(), "architecture_change_record.json is not a JSON object"),
    "deep-nesting": (b"[" * 100000 + b"]" * 100000, _contract(),
                     "architecture_change_record.json is nested too deeply to read"),
    "contract-refused": ({}, {"changes": "none"}, "the change record cannot be re-derived"),
    "contract-status-a-list": ({}, _contract(_change("change.a", "major", ["closed"])),
                               "the change record cannot be re-derived"),
}


@pytest.mark.parametrize("record, contract, message", UNCHECKABLE.values(), ids=UNCHECKABLE.keys())
def test_verification_reports_a_record_it_cannot_check(monkeypatch, tmp_path, record,
                                                       contract, message):
    _tool_at(monkeypatch, tmp_path, contract, record)
    [problem] = tool.change_record_problems()
    assert message in problem


def test_an_io_error_on_the_record_is_reported_by_name(monkeypatch, tmp_path):
    """Any OSError, not only the PermissionError a directory gives on Windows."""
    _tool_at(monkeypatch, tmp_path, CONTRACT_TWO, _full_record(CONTRACT_TWO))
    _failing_read(monkeypatch, tool.CHANGE_RECORD)
    [problem] = tool.change_record_problems()
    assert "architecture_change_record.json cannot be read (OSError)" in problem


# ---------------------------------------------------------------------------
# The tool end to end, in a copy of the repository
# ---------------------------------------------------------------------------

AS_OF = "2026-09-01T00:00:00Z"
TOOL = "scripts/refresh_governance_evidence.py"


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, TOOL, *args], cwd=work, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=900,
        env={**os.environ, "PYTHONPATH": str(work / "src")},
    )


def _git(work: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=fixture@example.invalid", "-c", "user.name=fixture", *args],
        cwd=work, check=True, capture_output=True, text=True, timeout=600,
    ).stdout.strip()


def _regenerate(work: Path) -> dict:
    done = _run(work, "--as-of", AS_OF)
    assert done.returncode == 0, done.stdout[-1500:] + done.stderr[-1500:]
    return json.loads((work / ".nornyx/contracts/evidence" / tool.CHANGE_RECORD)
                      .read_text(encoding="utf-8"))


def _subject(work: Path) -> str:
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import sys; sys.path.insert(0, 'scripts');"
         "import refresh_governance_evidence as r; print(r.current_inspection_subject())"],
        cwd=work, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=600, env={**os.environ, "PYTHONPATH": str(work / "src")},
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout.strip()


def _set_windows_payload_impact(work: Path, impact: str) -> None:
    contract = work / tool.ARCHITECTURE_CONTRACT
    text = contract.read_text(encoding="utf-8")
    start = text.index(f"    id: {WINDOWS_PAYLOAD_CHANGE}\n")
    old = "      architecture: minor\n"
    at = text.index(old, start)
    contract.write_text(text[:at] + f"      architecture: {impact}\n" + text[at + len(old):],
                        encoding="utf-8")


def _derived_in(work: Path) -> dict:
    document = yaml.load((work / tool.ARCHITECTURE_CONTRACT).read_bytes(),
                         Loader=tool._ContractLoader)  # noqa: S506
    return {"schema": tool.CHANGE_RECORD_SCHEMA, **tool.declared_change_record(document)}


def _claims(record: dict) -> dict:
    return {key: value for key, value in record.items()
            if key not in {"generated_at", "subject_revision"}}


def test_the_tool_writes_every_key_and_the_derived_claims(tmp_path):
    """The emit site in `build()`: every key is written, every derived claim
    equals the derivation from the copy's contract, and the record follows an
    edit of that contract, so fixed text written there fails."""
    work = faithful_copy(tmp_path)
    record = _regenerate(work)
    assert set(record) == {"schema", "subject_revision", "generated_at", "governed_input_digest",
                           HIGHEST, HIGHEST_OPEN, "declared_changes", "impact_rule", "statement"}
    assert record["generated_at"] == AS_OF
    derived = _derived_in(work)
    assert {key: record[key] for key in derived} == derived
    _set_windows_payload_impact(work, "critical")
    record = _regenerate(work)
    derived = _derived_in(work)
    assert {key: record[key] for key in derived} == derived
    assert record[HIGHEST] == record[HIGHEST_OPEN] == "critical"


BREAKAGES = {
    "duplicate-id": "repeats the change id 'architecture.canonical_text_rule'",
    "yaml-error": "the contract is not parseable YAML",
    "repeated-changes-key": "found duplicate key 'changes'",
    "status-a-list": "which is not a nornyx.change.v1 status",
    "invalid-date": "not parseable YAML (ValueError: month must be in 1..12)",
    "deep-nesting": "the contract nests too deeply to parse",
}


def _break(work: Path, breakage: str) -> None:
    contract = work / tool.ARCHITECTURE_CONTRACT
    raw = contract.read_bytes()
    appended = {"yaml-error": b"\nbroken: [unclosed\n",
                "repeated-changes-key": b"\nchanges: []\n",
                "invalid-date": b"\nx_note: 2026-13-45\n",
                "deep-nesting": b"\nx_deep: " + b"[" * 5000 + b"]" * 5000 + b"\n",
                "syntax-error": b"\nbroken: [unclosed\n",
                "python-name": b"\nx_note: !!python/name:os.getcwd\n",
                "unhashable-key": b"\n? [a, b]\n: v\n",
                "second-document": b"\n---\nx_note: 1\n",
                "bool-maybe": b"\nx_note: !!bool maybe\n",
                "int-empty": b"\nx_note: !!int ''\n",
                "timestamp-abc": b"\nx_note: !!timestamp abc\n",
                "set-of-a-scalar": b"\nx_note: !!set [a]\n",
                "escape-out-of-range": b'\nx_note: "\\UFFFFFFFF"\n'}
    if breakage in appended:
        contract.write_bytes(raw + appended[breakage])
        return
    document = yaml.safe_load(raw)
    if breakage == "duplicate-id":
        document["changes"].append(copy.deepcopy(document["changes"][-1]))
    else:
        document["changes"][-1]["status"] = ["proposed"]
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize("breakage", BREAKAGES, ids=BREAKAGES)
def test_a_refusal_comes_before_any_artifact_is_written(tmp_path, breakage):
    work = faithful_copy(tmp_path)
    _break(work, breakage)
    evidence = work / ".nornyx/contracts/evidence"
    before = {path: path.read_bytes() for path in evidence.rglob("*") if path.is_file()}
    done = _run(work, "--as-of", AS_OF)
    assert done.returncode != 0
    assert BREAKAGES[breakage] in done.stderr
    assert "Traceback" not in done.stderr
    after = {path: path.read_bytes() for path in evidence.rglob("*") if path.is_file()}
    assert after == before, "the tool wrote evidence before refusing"


def test_two_revisions_over_the_same_content_give_the_same_claims_and_subject(tmp_path):
    """Regenerated at a parent whose contract declares neither the payload
    module nor its change entry, and again once the content is committed: the
    HEAD moves and its contract differs, in the architecture and in changes:,
    while the content does not. Neither the record's claims nor the inspection
    subject may move."""
    work = faithful_copy(tmp_path)
    contract = work / tool.ARCHITECTURE_CONTRACT
    real = contract.read_bytes()
    parent = yaml.safe_load(real)
    parent["changes"] = [entry for entry in parent["changes"]
                         if entry["id"] != WINDOWS_PAYLOAD_CHANGE]
    architecture = parent["architecture"]
    architecture["modules"] = [entry for entry in architecture["modules"]
                               if entry["id"] != "module.windows_payload"]
    for component in architecture["components"]:
        if component["id"] == "component.windows_runtime":
            component["modules"] = [module for module in component["modules"]
                                    if module != "module.windows_payload"]
    contract.write_text(yaml.safe_dump(parent, sort_keys=False), encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "a parent without the module or its change entry")

    contract.write_bytes(real)
    _git(work, "add", "-A")
    first = _regenerate(work)
    first_subject = _subject(work)

    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "the content committed")
    second = _regenerate(work)
    second_subject = _subject(work)

    assert first["subject_revision"] != second["subject_revision"]
    assert _claims(first) == _claims(second)
    assert first_subject == second_subject


def _rebind(work: Path) -> None:
    for step in ("--sync-contracts", "--review-binding"):
        assert _run(work, step).returncode == 0
    _git(work, "add", "-A")


def _verify(work: Path) -> dict:
    done = _run(work, "--verify")
    assert "Traceback" not in done.stderr, done.stderr[-600:]
    report = json.loads(done.stdout)
    report["exit"] = done.returncode
    return report


def test_verify_re_derives_the_record_after_every_digest_is_rebound(tmp_path):
    """A contract edit followed by `--sync-contracts` and `--review-binding`
    rebinds every recorded digest. `--verify` must still see that the change
    record no longer says what the contract declares."""
    work = faithful_copy(tmp_path)
    _regenerate(work)
    _rebind(work)
    assert _verify(work)["exit"] == 0

    _set_windows_payload_impact(work, "major")
    _rebind(work)
    report = _verify(work)
    assert report["exit"] == 2
    assert report["verification"]["integrity_state"] == "compromised"
    assert any("architecture_change_record.json differs" in problem
               and HIGHEST in problem for problem in report["problems"])


UNREADABLE_FILES = {
    "contract-status-a-list": ("status-a-list", None,
                               "which is not a nornyx.change.v1 status"),
    "contract-invalid-date": ("invalid-date", None, "month must be in 1..12"),
    "contract-deep-nesting": ("deep-nesting", None, "nests too deeply"),
    "record-deep-nesting": (None, b"[" * 100000 + b"]" * 100000, "nested too deeply to read"),
    **{f"contract-{name}": (name, None, "the contract is not parseable YAML (")
       for name in ("syntax-error", "python-name", "unhashable-key", "second-document",
                    "bool-maybe", "int-empty", "timestamp-abc", "set-of-a-scalar",
                    "escape-out-of-range")},
}


def test_verify_names_an_evidence_file_json_will_not_construct(tmp_path):
    """An integer longer than Python's integer-string limit is a plain
    ValueError from `json`, not a JSONDecodeError: the evidence-file loop
    catches the class, so it is named like any unreadable file."""
    work = faithful_copy(tmp_path)
    _regenerate(work)
    _rebind(work)
    report_file = work / ".nornyx/contracts/evidence/architecture_conformance_report.json"
    report_file.write_bytes(report_file.read_bytes().replace(
        b"{\n", b'{\n  "x_big": ' + b"9" * 5000 + b",\n", 1))
    _git(work, "add", "-A")
    report = _verify(work)
    assert report["exit"] == 2
    assert report["verification"]["integrity_state"] == "compromised"
    assert "architecture_conformance_report.json is not readable JSON" in report["problems"]


@pytest.mark.parametrize("breakage, record, message", UNREADABLE_FILES.values(),
                         ids=UNREADABLE_FILES.keys())
def test_verify_reports_an_unreadable_contract_or_record_by_name(tmp_path, breakage, record,
                                                                 message):
    """Through the real CLI: exit 2, a named problem and integrity compromised,
    and no traceback, at whichever read site meets the file first."""
    work = faithful_copy(tmp_path)
    _regenerate(work)
    _rebind(work)
    if breakage:
        _break(work, breakage)
    if record is not None:
        (work / ".nornyx/contracts/evidence" / tool.CHANGE_RECORD).write_bytes(record)
    _git(work, "add", "-A")
    report = _verify(work)
    assert report["exit"] == 2
    assert report["verification"]["integrity_state"] == "compromised"
    assert any(message in problem for problem in report["problems"]), report["problems"]



SITES = {
    "review-binding": "_review_binding_claim_problems",
    "inspection-subject": "current_inspection_subject",
}
NAMED = {
    "subject-error": tool.GovernedContentError("the observer could not read a contract"),
    "recursion": RecursionError("maximum recursion depth exceeded"),
    "yaml": yaml.YAMLError("unexpected end of stream"),
    "value": ValueError("month must be in 1..12"),
    "type": TypeError("cannot unpack non-iterable ScalarNode object"),
    "overflow": OverflowError("date value out of range"),
    "key": KeyError("maybe"),
    "index": IndexError("string index out of range"),
    "attribute": AttributeError("'NoneType' object has no attribute 'groupdict'"),
}


def _raising(monkeypatch, site: str, raised: BaseException) -> None:
    def failing(*_args, **_kwargs):
        raise raised
    monkeypatch.setattr(tool, SITES[site], failing)


@pytest.mark.parametrize("raised", NAMED.values(), ids=NAMED.keys())
@pytest.mark.parametrize("site", SITES, ids=SITES)
def test_a_read_site_reports_what_it_cannot_read_by_name(monkeypatch, site, raised):
    """At each site that reads the contracts and evidence, the classes YAML and
    JSON parsing and construction raise, and the observer's own error, become a
    named integrity problem that compromises integrity."""
    _raising(monkeypatch, site, raised)
    state = tool.derive_assurance_state()
    assert state["integrity_state"] == "compromised"
    cause = ("nested too deeply to read" if isinstance(raised, RecursionError)
             else f"{type(raised).__name__}: {raised}")
    assert any(problem.startswith("a contract or an evidence file could not be read or "
                                  "interpreted while ")
               and problem.endswith(f"({cause}), so the evidence cannot be shown to describe "
                                    "this tree") for problem in state["problems"]), state["problems"]


KEPT = {
    "decode": UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    "encode": UnicodeEncodeError("ascii", "\xe9", 0, 1, "ordinal not in range(128)"),
    "missing-file": FileNotFoundError(2, "No such file or directory"),
    "os-error": OSError(5, "input/output error"),
    "runtime": RuntimeError("an unrelated defect"),
}


@pytest.mark.parametrize("raised", KEPT.values(), ids=KEPT.keys())
@pytest.mark.parametrize("site", SITES, ids=SITES)
def test_a_parse_site_leaves_every_other_failure_its_traceback(monkeypatch, site, raised):
    """Decoding errors, though ValueErrors, a missing or unreadable file, and
    every class outside the parse set keep their traceback: the repository's
    own named controls for them are proven by the traceback they prevent."""
    _raising(monkeypatch, site, raised)
    with pytest.raises(type(raised)):
        tool.derive_assurance_state()


def test_the_inspection_subject_site_reports_on_its_own(monkeypatch):
    """With the binding recomputation answering, a failure while computing the
    inspection subject is still a named problem of its own."""
    monkeypatch.setattr(tool, "_review_binding_claim_problems", lambda binding: [])
    _raising(monkeypatch, "inspection-subject", KeyError("maybe"))
    state = tool.derive_assurance_state()
    assert state["integrity_state"] == "compromised"
    assert any("while computing the inspection subject (KeyError: 'maybe')" in problem
               for problem in state["problems"]), state["problems"]
    assert state["inspection_subject_digest"] is None
    assert state["assurance_problems"][0] == (
        "the inspection subject could not be computed, so no inspection can be matched to it")


DEEP_JSON = b"[" * 100000 + b"]" * 100000
UNREADABLE_JSON = {
    "not-json": (b"{not json", "(JSONDecodeError: "),
    "deep-nesting": (DEEP_JSON, "(nested too deeply to read)"),
}


@pytest.mark.parametrize("content, cause", UNREADABLE_JSON.values(), ids=UNREADABLE_JSON.keys())
def test_an_unreadable_evidence_index_is_reported_by_name(monkeypatch, tmp_path, content, cause):
    index = tmp_path / "INDEX.json"
    index.write_bytes(content)
    monkeypatch.setattr(tool, "INDEX_PATH", index)
    [problem] = tool.verify()
    assert "could not be read or interpreted while reading the evidence index " + cause in problem


def test_an_evidence_index_that_is_not_an_object_is_reported_by_name(monkeypatch, tmp_path):
    index = tmp_path / "INDEX.json"
    index.write_bytes(b"[]")
    monkeypatch.setattr(tool, "INDEX_PATH", index)
    assert tool.verify() == ["the evidence index is not a JSON object, so no artifact can be "
                             "checked against it"]


@pytest.mark.parametrize("content, problem", [
    (b"{not json", "could not be read or interpreted while reading the review binding "
                   "(JSONDecodeError: "),
    (DEEP_JSON, "could not be read or interpreted while reading the review binding "
                "(nested too deeply to read)"),
    (b"[]", "the review binding is not a JSON object, so no claim can be recomputed"),
], ids=["not-json", "deep-nesting", "not-an-object"])
def test_an_unreadable_review_binding_is_reported_by_name(tmp_path, content, problem):
    path = tmp_path / "review_binding.json"
    path.write_bytes(content)
    state = {"problems": [], "evidence_manifest_match": True, "governed_input_match": True}
    assert tool._read_review_binding(path, state) is None
    assert state["evidence_manifest_match"] is False
    assert state["governed_input_match"] is False
    [recorded] = state["problems"]
    assert problem in recorded
