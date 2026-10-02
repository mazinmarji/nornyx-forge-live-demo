"""Assert the governance contracts fail only for want of an EXTERNAL AUTHORITY.

The invariant this gate protects is narrow and deliberate: a governance contract
may be blocked *only* because an authority outside this repository has not acted.
Any other diagnostic — a schema break, a stale revision, expired or mismatched
evidence — is a defect and fails this check.

TWO AUTHORITIES, NOT ONE, and this docstring said "a human approval" for both.
`EXPECTED_PRE_APPROVAL_DIAGNOSTICS` has five members and they divide:

    AN_APPROVAL_RECORD_MISSING   an accountable human has not approved
    APPROVAL_EVIDENCE_MISSING    an accountable human has not approved
    EVIDENCE_REQUIRED_MISSING    an accountable human has not approved

    CHANGE_EVIDENCE_MISSING        no AUTHENTICATED INDEPENDENT INSPECTION
    SOD_EVIDENCE_PRODUCER_UNKNOWN  no AUTHENTICATED INDEPENDENT INSPECTION

So the both-directions claim that stood here -- "after a real human approval
record is supplied they validate outright" -- was false. A human approval alone
leaves `architecture_governance.nyx` failing, because it also needs an inspection
signed by a reviewer whose key is in a trust store this repository does not have.
A reader who believed the old sentence would conclude that one signature is all
that stands between this repository and validating governance contracts, and that
the independent-inspection control is already satisfied. It is not, and never was.

CLAUDE.md corrected exactly this substitution in ITSELF and recorded doing so.
The correction did not reach this file, the CI step that runs it, or
docs/governance/EVIDENCE_FRESHNESS.md, which is why a fresh lens found it here
three rounds later.

It still holds in both directions, stated correctly: before either authority acts
the contracts fail with those five diagnostics only; once both have acted they
validate outright. Either is acceptable; anything else is not.

The check never creates, infers, or backdates an approval or an inspection.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GOVERNANCE_CONTRACTS = (
    ".nornyx/contracts/runtime_network.nyx",
    ".nornyx/contracts/architecture_governance.nyx",
)

#: Diagnostics that mean "an accountable prerequisite is genuinely absent", and
#: nothing else.
#:
#: The set used to name only the human approval, because a second missing
#: prerequisite was hidden. The architecture contract recorded
#: `independent_review_record` with `status: pass` while the evidence index and
#: the artifact itself both reported it as merely `observed` with
#: `authenticated_inspections: {}`. Nornyx counts only `pass` records as usable
#: evidence, so that one hand-authored word was satisfying change control,
#: required evidence, and the separation-of-duties assignment on the strength of
#: an unsigned self-report the builder wrote about its own work.
#:
#: With the status now synced from the index like every other derived field,
#: the contract states the truth: this branch has neither an accountable human
#: approval NOR an authenticated independent inspection. Both are absent for the
#: same underlying reason -- nobody with standing has attested to this content --
#: and neither can be manufactured from inside the repository.
#:
#: Every diagnostic below is therefore still "a prerequisite requiring an
#: authority outside this build is missing". None of them can be cleared by
#: changing code, and none of them may be cleared by relabelling an artifact.
#:
#: Matched on the structured triple Nornyx documents as its stable vocabulary —
#: code, path, source module — never on message text. The previous version
#: searched for "approval_record" inside the human-readable message while its own
#: comment claimed exact matching, so a reworded message would have broken the
#: gate and an unrelated diagnostic that happened to mention the phrase would
#: have satisfied it.
#:
#: EVIDENCE_REQUIRED_MISSING is qualified deliberately. On its own that code means
#: *some* required evidence record is absent, which is not the same claim as "a
#: human has not approved". Pairing it with its path and source module is what
#: makes it specific.
EXPECTED_PRE_APPROVAL_DIAGNOSTICS = frozenset(
    {
        (
            "AN_APPROVAL_RECORD_MISSING",
            "governance_evidence.records",
            "agentic_network_foundation.v1",
        ),
        (
            "EVIDENCE_REQUIRED_MISSING",
            "governance_evidence.records",
            "evidence_integrity.v1",
        ),
        (
            "APPROVAL_EVIDENCE_MISSING",
            "approvals[0].required_evidence",
            "human_approval.v1",
        ),
        # The two below are the consequences of having no AUTHENTICATED
        # independent inspection. They appeared the moment the contract stopped
        # claiming `pass` for an inspection nothing had signed, so they are not
        # a regression -- they are the state that stamp was concealing.
        #
        # ACCEPTED BY WHAT IS MISSING, NOT BY POSITION. These two read
        # `changes[0]` and `assignments[0]`, which accepted ANY evidence missing
        # at the first change entry -- an absent architecture decision record
        # included -- and NO evidence missing at any later entry, so a second
        # change could only pass by not declaring the review evidence its own
        # approval requires. `[*]` stands for any index, and is reached only
        # through `_acceptance_key`: the diagnostic is accepted when every item
        # missing at that entry, or every producer the assignment declares that
        # its change's evidence does not account for, belongs to a record that
        # change cites and that an external authority alone can make usable
        # (`EXTERNAL_AUTHORITY_EVIDENCE_TYPES`, see `_external_records`).
        # Anything else missing there keeps its own index, matches nothing
        # here, and fails the gate.
        (
            "CHANGE_EVIDENCE_MISSING",
            "changes[*].required_evidence",
            "change_control.v1",
        ),
        (
            "SOD_EVIDENCE_PRODUCER_UNKNOWN",
            "separation_of_duties.assignments[*].evidence_producers",
            "separation_of_duties.v1",
        ),
    }
)


#: The Nornyx evidence types whose records only an authority outside this
#: repository can make pass: a human approval, and an authenticated independent
#: inspection. One constant, the only place these are named;
#: `tests/test_pre_approval_baseline.py` pins it to the governance contract,
#: whose approval requires one record of each.
EXTERNAL_AUTHORITY_EVIDENCE_TYPES = frozenset({"approval_record", "independent_review_record"})

#: The diagnostics accepted at any index, and the path each is reported at.
_INDEXED_PATHS = {
    "CHANGE_EVIDENCE_MISSING": re.compile(r"changes\[(\d+)\]\.required_evidence"),
    "SOD_EVIDENCE_PRODUCER_UNKNOWN": re.compile(
        r"separation_of_duties\.assignments\[(\d+)\]\.evidence_producers"),
}


def _canonical(value: object) -> str | None:
    if isinstance(value, str) and value and value == value.strip():
        return value
    return None


def _strings(value: object) -> list[str]:
    """The canonical strings in a list; anything else contributes nothing."""
    if not isinstance(value, list):
        return []
    return [item for item in value if _canonical(item) is not None]


def _records(document: dict) -> list[dict]:
    block = document.get("governance_evidence")
    records = block.get("records") if isinstance(block, dict) else None
    return [record for record in records or [] if isinstance(record, dict)]


def _usable_records(document: dict) -> list[dict]:
    """The records Nornyx counts as usable evidence: uniquely identified,
    `pass`, with every dependency usable in turn. The same rule as
    `nornyx.governance.structural._usable_evidence_records`, restated because
    the checker is run as a program; `tests/test_pre_approval_baseline.py`
    compares the two."""
    by_id: dict[str, dict] = {}
    duplicates: set[str] = set()
    for record in _records(document):
        identifier = _canonical(record.get("id"))
        if identifier is None:
            continue
        if identifier in by_id:
            duplicates.add(identifier)
        else:
            by_id[identifier] = record
    for identifier in duplicates:
        by_id.pop(identifier, None)
    candidates: dict[str, list[str]] = {}
    for identifier, record in by_id.items():
        dependencies = record.get("dependencies")
        if dependencies is None:
            dependencies = []
        if (record.get("status") != "pass" or not isinstance(dependencies, list)
                or len(_strings(dependencies)) != len(dependencies)
                or any(item not in by_id for item in dependencies)):
            continue
        candidates[identifier] = dependencies
    usable: set[str] = set()
    grew = True
    while grew:
        grew = False
        for identifier, dependencies in candidates.items():
            if identifier not in usable and set(dependencies) <= usable:
                usable.add(identifier)
                grew = True
    return [by_id[identifier] for identifier in sorted(usable)]


def _references(records: list[dict]) -> set[str]:
    """What evidence citations resolve to: each record's id and its type."""
    return {value for record in records
            for value in (_canonical(record.get("id")), _canonical(record.get("type")))
            if value is not None}


def _producer_aliases(record: dict) -> set[str]:
    """The names a record's producer can be declared by, as Nornyx's
    `_producer_actor_aliases` forms them."""
    producer = record.get("producer")
    if not isinstance(producer, dict):
        return set()
    producer_id, kind = _canonical(producer.get("id")), _canonical(producer.get("type"))
    if producer_id is None or kind is None:
        return set()
    kind = kind.casefold()
    aliases = {producer_id, f"{kind}:{producer_id}"}
    if kind == "human":
        human = producer_id.split(".", 1)[1] if producer_id.casefold().startswith("human.") \
            else producer_id
        aliases.add(f"user:{human}")
    tool = record.get("tool")
    if kind == "tool" and isinstance(tool, dict) and _canonical(tool.get("name")) is not None:
        aliases.update({tool["name"], f"tool:{tool['name']}"})
    return aliases


def _external_records(document: dict) -> list[dict]:
    """The records whose absence an external authority alone can close: of an
    external type, uniquely identified, and with every dependency usable
    already or such a record in turn. A record of an external type that fails
    any of these would stay unusable after that authority acted -- a repeated
    id, or a dependency on failing evidence, needs a repository edit -- so
    nothing missing on its account is accepted."""
    usable = {record["id"] for record in _usable_records(document)}
    counts: dict[str, int] = {}
    for record in _records(document):
        identifier = _canonical(record.get("id"))
        if identifier is not None:
            counts[identifier] = counts.get(identifier, 0) + 1
    candidates: dict[str, tuple[dict, list[str]]] = {}
    for record in _records(document):
        identifier = _canonical(record.get("id"))
        dependencies = record.get("dependencies")
        if dependencies is None:
            dependencies = []
        if (identifier is None or counts[identifier] != 1
                or record.get("type") not in EXTERNAL_AUTHORITY_EVIDENCE_TYPES
                or not isinstance(dependencies, list)
                or len(_strings(dependencies)) != len(dependencies)
                or any(item not in counts for item in dependencies)):
            continue
        candidates[identifier] = (record, dependencies)
    resolvable: set[str] = set()
    grew = True
    while grew:
        grew = False
        for identifier, (_record, dependencies) in candidates.items():
            if identifier not in resolvable and set(dependencies) <= usable | resolvable:
                resolvable.add(identifier)
                grew = True
    return [candidates[identifier][0] for identifier in sorted(resolvable)]


def _indexed(document: dict, block: list | None, index: int) -> dict | None:
    if not isinstance(block, list) or index >= len(block):
        return None
    entry = block[index]
    return entry if isinstance(entry, dict) else None


def _missing_change_evidence_is_external(document: dict, index: int) -> bool:
    """Every item `changes[index]` requires that no usable record answers is a
    record only an external authority can make pass, and there is at least one.
    Each missing item is cited by the entry by construction: it is taken from
    the entry's own required evidence."""
    change = _indexed(document, document.get("changes"), index)
    if change is None:
        return False
    missing = set(_strings(change.get("required_evidence"))) - _references(
        _usable_records(document))
    return bool(missing) and missing <= _references(_external_records(document))


def _unlinked_producers_are_external(document: dict, index: int) -> bool:
    """Every producer `assignments[index]` declares that no usable record cited
    by its change, or by the approvals that change names, accounts for, is the
    producer of a record only an external authority can make pass that the
    same citations name; and there is at least one. The producer of an
    external record nothing here cites is refused: authenticating that record
    would leave the producer unlinked until the change is edited to cite it.
    Only directly cited records count, which is stricter than Nornyx's own
    linking, so this refuses rather than accepts at the margin."""
    duties = document.get("separation_of_duties")
    assignment = _indexed(document, duties.get("assignments") if isinstance(duties, dict)
                          else None, index)
    if assignment is None:
        return False
    subject = _canonical(assignment.get("subject"))
    changes = document.get("changes") if isinstance(document.get("changes"), list) else []
    matches = [item for item in changes if isinstance(item, dict) and subject is not None
               and subject in (item.get("id"), f"change:{item.get('id')}")]
    if len(matches) != 1:
        return False
    change = matches[0]
    cited = set(_strings(change.get("required_evidence"))) | set(
        _strings(change.get("closure_evidence")))
    transition = change.get("transition")
    if isinstance(transition, dict):
        cited |= set(_strings(transition.get("evidence")))
    named = set(_strings(change.get("approval_ids")))
    approvals = document.get("approvals") if isinstance(document.get("approvals"), list) else []
    for approval in approvals:
        if isinstance(approval, dict) and (approval.get("name") in named
                                           or approval.get("id") in named):
            cited |= set(_strings(approval.get("required_evidence")))
    linked = {alias for record in _usable_records(document)
              if _references([record]) & cited for alias in _producer_aliases(record)}
    unlinked = set(_strings(assignment.get("evidence_producers"))) - linked
    external = {alias for record in _external_records(document)
                if _references([record]) & cited for alias in _producer_aliases(record)}
    return bool(unlinked) and unlinked <= external


_ACCOUNTED_FOR = {
    "CHANGE_EVIDENCE_MISSING": _missing_change_evidence_is_external,
    "SOD_EVIDENCE_PRODUCER_UNKNOWN": _unlinked_producers_are_external,
}


def _acceptance_key(item: dict, document: dict | None) -> tuple[str, str, str]:
    """The triple a diagnostic is matched against `EXPECTED_PRE_APPROVAL_DIAGNOSTICS`.

    Its own `(code, path, source_id)`, except for the two diagnostics accepted
    at any index: those take the `[*]` path only when the contract shows that
    what they report missing is exactly what an external authority has not yet
    produced. Read from the contract's structure, never from the message."""
    code, path, source = (str(item.get("code")), str(item.get("path")),
                          str(item.get("source_id")))
    pattern = _INDEXED_PATHS.get(code)
    match = pattern.fullmatch(path) if pattern is not None else None
    if match is not None and document is not None and _ACCOUNTED_FOR[code](
            document, int(match.group(1))):
        return code, re.sub(r"\[\d+\]", "[*]", path), source
    return code, path, source


def _contract_document(contract: str) -> dict | None:
    """The contract as a mapping, or None: then nothing is accepted by index."""
    try:
        document = yaml.safe_load((ROOT / contract).read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


class UnstructuredCheckerOutput(RuntimeError):
    """The checker emitted something this gate cannot classify."""


#: Diagnostic levels this gate knows how to classify.
#:
#: Enumerated from the installed Nornyx, which emits `error` and `warning`.
#: `info` is included because it is the obvious next one and ignoring it would
#: be harmless; anything OUTSIDE this set is reported rather than dropped.
KNOWN_DIAGNOSTIC_LEVELS = frozenset({"error", "warning", "info"})


def _diagnostics(output: str) -> list[dict]:
    """Parse the concatenated JSON objects the Nornyx CLI prints.

    Strict. The previous parser advanced one byte at a time past anything it
    could not decode, which meant unexpected output was silently discarded:

        INTERNAL VALIDATOR CRASHED
        {"code": "AN_APPROVAL_RECORD_MISSING", ...}

    would have been classified as a clean approval-only block. For an assurance
    gate, output it cannot account for is a reason to fail, not to skip.
    """

    decoder = json.JSONDecoder()
    found: list[dict] = []
    text = output.strip()
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        try:
            value, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            remainder = text[index : index + 200]
            raise UnstructuredCheckerOutput(
                f"checker emitted output this gate cannot classify at offset "
                f"{index}: {remainder!r}"
            ) from exc
        if isinstance(value, dict):
            found.append(value)
    return found


#: What the checker prints when a contract validates.
#:
#: An exact set, not a substring search. "passed" appearing anywhere in a
#: diagnostic would otherwise read as success, which is the substitution this
#: gate exists to refuse -- one level down.
CHECKER_SUCCESS_LINES = frozenset({"Nornyx check passed"})


def _is_success_output(output: str) -> bool:
    """Is this the checker's plain-text success report, and nothing else?"""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return bool(lines) and all(line in CHECKER_SUCCESS_LINES for line in lines)


def _check(contract: str, executable: str, as_of: str | None = None) -> dict:
    command = [executable, "check", contract]
    if as_of:
        command += ["--as-of", as_of]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        # PINNED, not inherited. Without this the output decodes with the
        # Windows locale codepage while the renderer emits `ensure_ascii=False`,
        # so a diagnostic carrying a non-cp1252 character raises out of the gate
        # instead of being classified. The sibling checker already pins it.
        encoding="utf-8",
        errors="replace",
        timeout=900,
        capture_output=True,
        check=False,
    )
    try:
        diagnostics = _diagnostics(completed.stdout + completed.stderr)
    except UnstructuredCheckerOutput as exc:
        # A CONTRACT THAT PASSES PRINTS PROSE, AND THIS READ THAT AS FAILURE.
        #
        # `nornyx check` on a VALIDATING contract writes the plain line
        # "Nornyx check passed" and exits 0 -- no JSON at all. `_diagnostics`
        # refuses it, correctly by its own strictness rule, and this handler
        # then hardcoded `validates: False`, discarding `returncode` entirely.
        # The normal return path computes `validates` from the return code;
        # only this early exit threw it away.
        #
        # Measured on this checkout, against the one contract that passes:
        #
        #     raw            rc 0, stdout "Nornyx check passed"
        #     _check(...)    validates False, approval_blocked False
        #
        # `healthy = all(validates or approval_blocked)`, so the gate exits 2.
        # WHICH MEANS SUPPLYING THE REAL HUMAN APPROVAL -- the event that makes
        # both governance contracts validate -- WOULD TURN THIS GATE FROM PASS
        # TO FAIL. `--has-approval` could never return 0, so CI took the "no
        # approval" branch permanently and the strict-authorization path was
        # unreachable even after a genuine approval. And
        # `human_approval_present`, which is `all(validates)`, would report
        # false at the exact moment every contract validated.
        #
        # The strictness rule stands for a NON-ZERO exit: output the gate
        # cannot account for is a reason to fail. A ZERO exit is the checker
        # asserting success, and unstructured output there is not evidence of
        # failure. Narrowly: exit 0 plus a RECOGNISED success line validates;
        # anything else is still refused.
        if completed.returncode == 0 and _is_success_output(
            completed.stdout + completed.stderr
        ):
            return {
                "contract": contract,
                "returncode": completed.returncode,
                "validates": True,
                "approval_blocked": False,
                "unexpected_diagnostics": [],
            }
        return {
            "contract": contract,
            "returncode": completed.returncode,
            "validates": False,
            "approval_blocked": False,
            "unexpected_diagnostics": [{"unstructured_output": str(exc)}],
        }

    # A FAILURE THAT SAYS NOTHING IS NOT AN APPROVAL GAP.
    #
    # `_diagnostics("")` returns an empty list without raising, so a checker
    # that exited non-zero having printed NOTHING left `offending` empty, and
    # `not offending` is vacuously true. The gate then reported
    # `approval_blocked: True` and `status: pass` -- under the sentence
    # "Governance contracts must fail only because a human approval record is
    # absent" -- having observed nothing to be absent, or present.
    #
    # Measured with two fake checkers differing by a single echo line:
    #     noisy crash  -> status FAIL, approval_blocked False
    #     SILENT crash -> status PASS, approval_blocked True
    #
    # The docstring on `_diagnostics` already states the rule this violated:
    # output the gate cannot account for is a reason to fail, not to skip. An
    # unexplained non-zero exit is the emptiest such output there is.
    # AN EXIT EXPLAINED ONLY BY WARNINGS IS NOT EXPLAINED.
    #
    # The first repair required at least one PARSED diagnostic. A review then
    # pointed at the neighbouring vacuity: a checker exiting non-zero having
    # emitted only `warning`-level items leaves `offending` empty for the same
    # reason, and `not offending` is true again. Today's `nornyx check` returns
    # non-zero only when it has errors, so this is latent rather than live --
    # and "latent because of what another program happens to do" is the
    # property that stops holding without anyone noticing.
    explained = [item for item in diagnostics if item.get("level") == "error"]
    if completed.returncode != 0 and not explained:
        return {
            "contract": contract,
            "returncode": completed.returncode,
            "validates": False,
            "approval_blocked": False,
            "unexpected_diagnostics": [{
                "unexplained_failure":
                    f"the checker exited {completed.returncode} and emitted no "
                    f"error-level diagnostic ({len(diagnostics)} non-error "
                    "item(s) seen). Nothing was observed to be absent, so "
                    "nothing licenses calling this an approval gap.",
            }],
        }

    # A LEVEL THIS GATE DOES NOT KNOW IS NOT A LEVEL IT MAY IGNORE.
    #
    # The filter read `level == "error"` and dropped everything else on the
    # floor. Today's checker emits only `error` and `warning`, so this is
    # complete now -- and "complete now" is exactly the property that stops
    # holding without anyone noticing. An unknown level is unaccountable
    # output, and lands in `unexpected_diagnostics` where it can be read.
    unknown_levels = [
        item for item in diagnostics
        if str(item.get("level")) not in KNOWN_DIAGNOSTIC_LEVELS
    ]

    document = _contract_document(contract)
    offending = unknown_levels + [
        item
        for item in diagnostics
        if item.get("level") == "error"
        and _acceptance_key(item, document)
        not in EXPECTED_PRE_APPROVAL_DIAGNOSTICS
    ]
    # A ZERO EXIT MUST BE EXPLAINED TOO, and this is the symmetric half of the
    # rule above. A checker that exits 0 having printed NOTHING leaves
    # `_diagnostics("")` empty without raising, and `returncode == 0` alone was
    # then read as "this contract validates" -- absence taken as confirmation,
    # the same class as the unexplained failure this gate already refuses.
    #
    # It is not hypothetical in shape: a checker that silently no-ops on a
    # contract path it cannot read exits 0 and says nothing, and the gate would
    # credit a pass for a check that never ran.
    #
    # Positive evidence means the recognised success line, or at least one
    # parsed diagnostic. Today's checker always supplies one or the other.
    explained_pass = _is_success_output(
        completed.stdout + completed.stderr
    ) or bool(diagnostics)
    if completed.returncode == 0 and not explained_pass:
        return {
            "contract": contract,
            "returncode": completed.returncode,
            "validates": False,
            "approval_blocked": False,
            "unexpected_diagnostics": [{
                "unexplained_pass":
                    "the checker exited 0 and said nothing this gate "
                    "recognises, so nothing observed says the contract was "
                    "checked at all.",
            }],
        }
    return {
        "contract": contract,
        "returncode": completed.returncode,
        "validates": completed.returncode == 0,
        "approval_blocked": completed.returncode != 0 and not offending,
        "unexpected_diagnostics": offending,
    }


def _regenerate(as_of: str | None) -> int:
    """Run the documented review-time refresh: rebuild evidence, then rebind.

    Machine evidence has a real, finite freshness window because Nornyx 1.11.0
    offers no way to express a non-expiring one — see
    docs/governance/EVIDENCE_FRESHNESS.md. Regenerating is the honest way to get
    a healthy baseline at an arbitrary instant, and it is one command.
    """

    refresh = str(ROOT / "scripts" / "refresh_governance_evidence.py")
    for stage in ([refresh] + (["--as-of", as_of] if as_of else []), [refresh, "--sync-contracts"]):
        completed = subprocess.run(
            [sys.executable, *stage], cwd=ROOT, text=True, capture_output=True,
            check=False, timeout=1800
        )
        if completed.returncode:
            print(completed.stdout + completed.stderr)
            return completed.returncode
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--has-approval",
        action="store_true",
        help="Exit 0 only if every governance contract already validates",
    )
    parser.add_argument(
        "--as-of",
        help="Evaluate at an explicit instant. The committed machine evidence "
        "carries a finite window, so a distant instant needs --regenerate too",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Run the documented review-time refresh before checking. Nornyx "
        "has no non-expiring representation for machine evidence, so this is "
        "how the baseline is made healthy at an arbitrary instant",
    )
    args = parser.parse_args()

    executable = shutil.which("nornyx")
    if not executable:
        print(json.dumps({"status": "fail", "error": "nornyx CLI not installed"}, indent=2))
        return 2

    if args.regenerate and _regenerate(args.as_of) != 0:
        print(json.dumps({"status": "fail", "error": "regeneration failed"}, indent=2))
        return 2

    results = [
        _check(contract, executable, args.as_of) for contract in GOVERNANCE_CONTRACTS
    ]

    if args.has_approval:
        # Used by CI to decide whether the strict-authorization path can run.
        return 0 if all(item["validates"] for item in results) else 1

    healthy = all(item["validates"] or item["approval_blocked"] for item in results)
    report = {
        "schema": "nornyx.forge.pre_approval_baseline.v1",
        "status": "pass" if healthy else "fail",
        "statement": (
            "Governance contracts must fail only because a human approval record "
            "is absent, or the consequences of having no AUTHENTICATED "
            "independent inspection. The accepted set is "
            "EXPECTED_PRE_APPROVAL_DIAGNOSTICS; any diagnostic outside it "
            "is a defect. The narrower wording this replaces named only "
            "the approval record, while the accepted set is wider."
        ),
        "evaluated_at": args.as_of or "now",
        "human_approval_present": all(item["validates"] for item in results),
        "contracts": results,
    }
    print(json.dumps(report, indent=2))
    return 0 if healthy else 2


if __name__ == "__main__":
    raise SystemExit(main())
