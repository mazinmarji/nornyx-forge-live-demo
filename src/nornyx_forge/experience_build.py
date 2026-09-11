"""BUILD-stage wiring: translate real development-flow output into evidence.

The Experience Contract consumes typed evidence; the development flow produces
a result dictionary. This module is the one place that mapping lives, and its
whole discipline is REFUSING TO IMPROVE THE NEWS:

  * `flow_run.passed` is exactly the flow's own `accepted` flag;
  * `gate_results.passed` is True only when EVERY gate passed;
  * `governance_validation` is derived from the gates whose command is the
    Nornyx CLI — and when no such gate ran (the CLI was absent), the evidence
    is ABSENT, not passing. An environment that could not ask the governance
    question produces no governance answer.

Behaviour-preserving by construction: this module never imports, calls, or
alters `development_flow`. It reads the plain dictionary the flow already
returns (`DevelopmentFlow.run()` / `run_sequential()`), and the flow's own
tests continue to define the flow. `layer.application`, since it interprets
application results; it starts nothing and decides nothing beyond the mapping
stated here.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .capsule import CapsuleValidationError
from .experience import EvidenceRef

#: How a Nornyx-CLI gate is recognised in a flow result: by its recorded
#: command vector, not by parsing the display name. `gates.run` stores the
#: exact command tuple it executed, so this decides on what ran rather than
#: on how it was spelled.
_NORNYX_EXECUTABLE = "nornyx"

#: `RequirementsModel.source_digest`'s shape -- the flow's own statement of
#: which BRD it parsed. MATCHED rather than trusted: a result carrying
#: anything else under that key contributes nothing to the reference, which
#: is honest absence rather than a digest of something nobody parsed.
_SOURCE_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")


def flow_evidence(data: Mapping[str, Any]) -> tuple[EvidenceRef, ...]:
    """Evidence references for one completed flow run.

    Accepts the dictionary `DevelopmentFlow.run()` returns. Raises
    `CapsuleValidationError` when the dictionary does not carry the keys a
    completed run records — a half-run is not evidence of anything, and
    translating it would manufacture a verdict the flow never gave.
    """
    if not isinstance(data, Mapping):
        raise CapsuleValidationError("a flow result must be a mapping")
    for key in ("accepted", "gates", "execution_backend"):
        if key not in data:
            raise CapsuleValidationError(
                f"the flow result carries no {key!r}; this is not a completed "
                "run, and an incomplete run translates to no evidence"
            )
    if not isinstance(data["accepted"], bool):
        raise CapsuleValidationError("flow 'accepted' must be a bool")
    gates = data["gates"]
    if not isinstance(gates, list) or not all(isinstance(g, Mapping) for g in gates):
        raise CapsuleValidationError("flow 'gates' must be a list of gate records")
    for gate in gates:
        if "name" not in gate or "passed" not in gate:
            raise CapsuleValidationError("each gate record needs 'name' and 'passed'")
        if not isinstance(gate["passed"], bool):
            raise CapsuleValidationError(f"gate {gate.get('name')!r} 'passed' must be a bool")

    backend = data["execution_backend"]
    if not isinstance(backend, str) or not backend:
        raise CapsuleValidationError("flow 'execution_backend' must be a non-empty string")

    # THE REFERENCES CARRY CONTENT WHERE THE FLOW RECORDED IT. They were
    # COUNTS -- `flow/sequential`, `gates/2-run`, `gates/nornyx/1-run` -- and
    # were measured IDENTICAL for two runs with different gate names,
    # different commands and different details, while `EvidenceRef`'s own
    # docstring says a ref "is expected to resolve". A count resolves to
    # nothing and distinguishes nothing. What changes is PROVENANCE and only
    # provenance: every `passed` below is exactly what it was, and none of
    # these digests is re-checked anywhere as a verdict.
    parsed_brd = _parsed_brd_digest(data)
    refs = [
        EvidenceRef(
            kind="flow_run",
            ref=f"flow/{backend}" if parsed_brd is None
            else f"flow/{backend}/brd/{parsed_brd}",
            passed=data["accepted"],
        ),
        EvidenceRef(
            kind="gate_results",
            ref=f"gates/{len(gates)}-run/{_gate_fingerprint(gates)}",
            passed=bool(gates) and all(gate["passed"] for gate in gates),
        ),
    ]

    nornyx_gates = [gate for gate in gates if _is_nornyx_gate(gate)]
    if nornyx_gates:
        refs.append(
            EvidenceRef(
                kind="governance_validation",
                ref=f"gates/nornyx/{len(nornyx_gates)}-run/"
                    f"{_gate_fingerprint(nornyx_gates)}",
                passed=all(gate["passed"] for gate in nornyx_gates),
            )
        )
    # No nornyx gate ran -> NO governance_validation reference. The absence is
    # the honest translation, and the Experience Contract will refuse the
    # stages that need it — which is the correct outcome for an environment
    # that never asked the governance question.

    for ref in refs:
        ref.validate()
    return tuple(refs)


def _gate_fingerprint(gates: Sequence[Mapping[str, Any]]) -> str:
    """Sixteen hex characters over the gate records as the translator was
    handed them.

    A function of the CONTENT, so the same records translate to the same
    reference and two different runs do not share one. `default=str` because
    a gate record is whatever the flow put in it -- `command` arrives as a
    tuple from the real runner and as a list through JSON, and both have to
    render the same way, which they do because `json.dumps` writes an array
    for either. It is a label for telling records apart, never a verdict:
    nothing re-checks it, and `passed` beside it is unchanged.
    """
    return hashlib.sha256(
        json.dumps(list(gates), sort_keys=True, separators=(",", ":"),
                   default=str).encode("utf-8")
    ).hexdigest()[:16]


def _parsed_brd_digest(data: Mapping[str, Any]) -> str | None:
    """The BRD the flow says it parsed, or `None` when it said nothing.

    `DevelopmentFlow.requirements()` records `requirements_model` from
    `parse_brd`, whose `source_digest` is `sha256:<hex>` of the decoded BRD
    text. A run that carries none -- an older result, a double, a half-run --
    yields no digest and the reference stays exactly what it was.
    """
    model = data.get("requirements_model")
    if not isinstance(model, Mapping):
        return None
    found = _SOURCE_DIGEST.match(str(model.get("source_digest", "")))
    return found.group(1) if found else None


def _is_nornyx_gate(gate: Mapping[str, Any]) -> bool:
    """Did this gate execute the Nornyx CLI?

    Decided from the recorded command vector's first element when present —
    the thing that ran — with the display name accepted only as a fallback for
    records that carry no command. A name-only decision would be a spelling
    test; the command vector is what was actually executed.
    """
    command = gate.get("command")
    if isinstance(command, (list, tuple)) and command:
        return str(command[0]) == _NORNYX_EXECUTABLE
    name = gate.get("name")
    return isinstance(name, str) and name.startswith(_NORNYX_EXECUTABLE + " ")
