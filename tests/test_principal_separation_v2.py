"""`separated` is derived from measured artefacts, and forgery fails closed.

WHY THIS FILE EXISTS. `control_plane_authority` requires `denied`, and
`control_plane_authority_outcome` yields `denied` only for a principal the
record says is `separated`. A v1 producer may never record that word, so the
criterion was unsatisfiable by construction -- true, and a criterion nothing
can satisfy is not being tested, it is being hard-coded to fail. This slice
makes the word DERIVABLE FROM MEASUREMENT, which means the rule now has to be
defended against every way a reader would expect it to be talked into a yes.

THE POSITIVE TWIN IS THE POINT OF THE FILE, not a footnote. Without it every
negative here is satisfied by a function returning `unknown` unconditionally,
and the suite would be green over a rule that decides nothing. The twin states
exactly what evidence would legitimately establish separation, so a later
reader can argue with the criterion instead of guessing at it.

WHAT THE REPAIR ROUND ADDED. The first head trusted
`separation_evidence.channels` -- a bare `{name: word}` map with no mechanism,
no detail and no link to anything measured -- so a record could assert six
refusals over an EMPTY artefact list and reach `separated`. The channel map is
derived from artefacts now, the summary is only allowed to agree with them, and
a `refused` counts only when its own detail evidences a denial.

WHAT NONE OF THIS ESTABLISHES. No provider row moves, Codex is not eligible,
and no Windows measurement is taken here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nornyx_forge.provider_contract import (  # noqa: E402
    AMBIGUOUS_REFUSAL_MARKERS,
    CHANNEL_DENIAL_EVIDENCE,
    CHANNEL_REQUIRED_MECHANISM,
    CONFINEMENT_PROPERTIES,
    CONTROL_PLANE_PROBE_SCHEMA,
    CONTROL_PLANE_PROBE_V2_SCHEMA,
    PRINCIPAL_SEPARATION,
    PROVIDER_CONFINEMENT,
    SEPARATION_CHANNEL_OUTCOMES,
    SEPARATION_CLOSURE_CHANNELS,
    SEPARATION_REQUIRED_CHANNELS,
    ProviderError,
    _V1_SEPARATION_VALUES,
    channels_from_artefacts,
    confinement_probe_from_surface_record,
    control_plane_authority_outcome,
    derive_principal_separation,
    governed_build_eligibility,
    qualifying_channel_outcome,
)

V1_PRODUCER = ROOT / "scripts" / "probe_control_plane.py"
C3_MEASUREMENT = ROOT / "docs" / "governance" / "control_plane_authority_measurement.json"

#: Details the shipped producer writes for a REAL denial, per channel.
DENIAL_DETAIL = {
    "process_vm_read": ("OpenProcess denied this principal PROCESS_VM_READ on pid 9 "
                        "(error 5, ERROR_ACCESS_DENIED): the process is there and this "
                        "caller may not open it"),
    "runtime_record": "present but not readable by this principal: PermissionError",
    "runtime_log": "present but not readable by this principal: PermissionError",
    "seal_dir_listing": "present but not listable by this principal: PermissionError",
    "browser_history": ("0 of 2 present history store(s) opened: this principal was "
                        "denied every one"),
    "browser_handler_cmdline": "no refusal path exists for this channel",
}

#: The separated-qualifying shape: closure channels denied, breach-only channels
#: merely not observed.
QUALIFYING = ({name: "refused" for name in SEPARATION_CLOSURE_CHANNELS}
              | {name: "not_applicable" for name in SEPARATION_REQUIRED_CHANNELS
                 if name not in SEPARATION_CLOSURE_CHANNELS})


def artefact(name, outcome, *, detail=None, mechanism=CHANNEL_REQUIRED_MECHANISM):
    if detail is None:
        detail = DENIAL_DETAIL[name] if outcome == "refused" else f"{outcome} detail"
    return {"name": name, "outcome": outcome, "mechanism": mechanism, "detail": detail}


def derive(**kwargs):
    base = {"principal_distinct": True, "channels": dict(QUALIFYING),
            "bearer_acquired": False}
    base.update(kwargs)
    return derive_principal_separation(**base)


def _c3_v1_record():
    """The real 2026-09-08 v1 record, used as the shape for synthetic v2 ones.

    Built FROM A REAL RECORD rather than hand-rolled so a synthetic cannot drift
    into a shape the translation would never see in the field.
    """
    def find(obj):
        if isinstance(obj, dict):
            if str(obj.get("schema", "")).endswith("control_plane_probe.v1"):
                return obj
            for value in obj.values():
                found = find(value)
                if found:
                    return found
        if isinstance(obj, list):
            for value in obj:
                found = find(value)
                if found:
                    return found
        return None

    record = find(json.loads(C3_MEASUREMENT.read_text(encoding="utf-8")))
    assert record is not None, "the C3 measurement no longer embeds a v1 probe record"
    return record


def v2_record(*, outcomes=None, distinct=True, owner_read=True, probe_read=True,
              summary=None, drop=(), mechanism=CHANNEL_REQUIRED_MECHANISM,
              bearer=False, extra=None, duplicate=None):
    record = json.loads(json.dumps(_c3_v1_record()))
    record["schema"] = CONTROL_PLANE_PROBE_V2_SCHEMA
    record.pop("principal_separated", None)
    record.pop("not_confinement_reason", None)
    record["bearer_acquired_through_surface"] = bearer
    outcomes = dict(QUALIFYING if outcomes is None else outcomes)
    artefacts = [artefact(name, outcomes.get(name, "refused"), mechanism=mechanism)
                 for name in SEPARATION_REQUIRED_CHANNELS if name not in drop]
    if duplicate:
        artefacts.append(artefact(duplicate, outcomes.get(duplicate, "refused"),
                                  mechanism=mechanism))
    record["artefacts"] = artefacts
    record["separation_evidence"] = {
        "owner_principal_read": owner_read,
        "probe_principal_read": probe_read,
        "principal_distinct": distinct,
        "owner_principal": {"read": owner_read, "uid": 0},
        "channels": ({a["name"]: a["outcome"] for a in artefacts}
                     if summary is None else summary),
    }
    if extra:
        record.update(extra)
    return record


def e2e(record, provider="codex"):
    """record -> probe -> outcome. The chain a consumer actually walks."""
    probe = confinement_probe_from_surface_record(record, provider=provider)
    probe.validate()
    return probe


# ===========================================================================
# The positive twin, end to end. The ONLY path to `denied`.
# ===========================================================================

def test_the_positive_twin_reaches_denied_end_to_end():
    """A complete, self-consistent, qualifying record -> `denied`.

    Every negative in this file is a mutation of THIS record, so each one
    isolates exactly the property it names.
    """
    probe = e2e(v2_record())
    assert probe.outcome == "denied"
    assert probe.property == "control_plane_authority"
    assert probe.provider == "codex"
    assert probe.attempt_observed is True


def test_the_unit_twin_yields_separated():
    assert derive() == "separated"


def test_only_a_separated_principal_reaches_denied_through_the_mapping():
    for state in ("reachable_unadmitted", "admitted_nuisance"):
        assert control_plane_authority_outcome(state, principal_separated="separated") == "denied"
        for word in ("unknown", "not_separated"):
            assert control_plane_authority_outcome(
                state, principal_separated=word) == "inconclusive"


# ===========================================================================
# P1 -- the channel map is derived from artefacts, never trusted as a summary.
# ===========================================================================

def test_a_record_with_no_artefacts_never_reaches_separated():
    """THE DEFECT THE REPAIR CLOSES, stated as its sharpest case.

    Six asserted refusals in the summary, an EMPTY artefact list. The first
    head returned `denied` here.
    """
    record = v2_record(drop=tuple(SEPARATION_REQUIRED_CHANNELS),
                       summary={n: "refused" for n in SEPARATION_REQUIRED_CHANNELS})
    with pytest.raises(ProviderError, match="disagrees"):
        e2e(record)


def test_an_empty_artefact_list_with_an_honest_summary_is_inconclusive():
    record = v2_record(drop=tuple(SEPARATION_REQUIRED_CHANNELS), summary={})
    assert e2e(record).outcome == "inconclusive"


def test_the_summary_is_only_allowed_to_agree_with_the_artefacts():
    """Artefacts say observed, summary says refused -> refused outright.

    Not silently repaired to the artefact's answer either: two halves that
    disagree mean neither can be trusted.
    """
    record = v2_record(outcomes=dict(QUALIFYING) | {"process_vm_read": "observed"},
                       summary={n: "refused" for n in SEPARATION_REQUIRED_CHANNELS})
    with pytest.raises(ProviderError, match="disagrees with the measured artefacts"):
        e2e(record)


def test_a_record_carrying_no_summary_at_all_still_works():
    """The artefacts are the authority; the summary is optional corroboration."""
    record = v2_record()
    del record["separation_evidence"]["channels"]
    assert e2e(record).outcome == "denied"


@pytest.mark.parametrize("channel", sorted(SEPARATION_REQUIRED_CHANNELS))
def test_a_duplicated_channel_is_refused(channel):
    """Answering one channel twice lets a reader pick the convenient half."""
    with pytest.raises(ProviderError, match="more than once"):
        e2e(v2_record(duplicate=channel))


@pytest.mark.parametrize("channel", sorted(SEPARATION_CLOSURE_CHANNELS))
def test_a_missing_closure_artefact_is_inconclusive(channel):
    assert e2e(v2_record(drop=(channel,))).outcome == "inconclusive"


def test_artefacts_must_be_a_list():
    record = v2_record()
    record["artefacts"] = {"process_vm_read": "refused"}
    with pytest.raises(ProviderError, match="artefacts"):
        e2e(record)


@pytest.mark.parametrize("mechanism", ["observed_surface_record", "", None, "acl"])
def test_an_incompetent_mechanism_is_refused(mechanism):
    with pytest.raises(ProviderError, match="mechanism"):
        e2e(v2_record(mechanism=mechanism))


# ===========================================================================
# P2-c -- a `refused` must mean a facility existed and denied THIS caller.
# ===========================================================================

@pytest.mark.parametrize("detail", [
    "not attempted: the deadline was exceeded before this read",
    "the presence check itself was denied to this principal, so whether the artefact "
    "exists is not determinable from here",
    "OpenProcess could not be attempted: OSError",
    "2 of 3 history store path(s) could not be checked at all",
])
def test_an_ambiguous_refusal_does_not_qualify(detail):
    """Timeout, existence-undetermined, instrumentation failure: not denials."""
    assert qualifying_channel_outcome(
        artefact("process_vm_read", "refused", detail=detail)) == "not_applicable"


def test_an_unexpected_win32_error_does_not_qualify():
    """Only ERROR_ACCESS_DENIED evidences a denial; other codes do not."""
    assert qualifying_channel_outcome(artefact(
        "process_vm_read", "refused",
        detail="OpenProcess refused a PROCESS_VM_READ handle on pid 7 (error 1450)",
    )) == "not_applicable"


def test_a_generic_oserror_refusal_does_not_qualify():
    assert qualifying_channel_outcome(artefact(
        "runtime_record", "refused",
        detail="the read could not be attempted on this host: OSError",
    )) == "not_applicable"


@pytest.mark.parametrize("channel", sorted(SEPARATION_CLOSURE_CHANNELS))
def test_a_real_denial_qualifies(channel):
    assert qualifying_channel_outcome(
        artefact(channel, "refused")) == "refused"


def test_a_non_qualifying_refusal_cannot_reach_separated_end_to_end():
    record = v2_record()
    for row in record["artefacts"]:
        if row["name"] == "runtime_log":
            row["detail"] = "not attempted: the deadline was exceeded before this read"
    record["separation_evidence"]["channels"] = {
        a["name"]: a["outcome"] for a in record["artefacts"]}
    assert e2e(record).outcome == "inconclusive"


def test_the_filter_can_only_weaken_never_strengthen():
    """It may turn `refused` into `not_applicable` and nothing else."""
    for name in SEPARATION_REQUIRED_CHANNELS:
        for outcome in SEPARATION_CHANNEL_OUTCOMES:
            got = qualifying_channel_outcome(artefact(name, outcome))
            if outcome != "refused":
                assert got == outcome
            else:
                assert got in ("refused", "not_applicable")


def test_a_refusal_whose_detail_cannot_be_read_is_refused_by_name():
    row = {"name": "runtime_log", "outcome": "refused",
           "mechanism": CHANNEL_REQUIRED_MECHANISM, "detail": None}
    with pytest.raises(ProviderError, match="detail"):
        qualifying_channel_outcome(row)


def test_browser_channels_can_witness_a_breach_but_never_a_closure():
    """The measured asymmetry, pinned so a later edit must argue with it."""
    for name in ("browser_history", "browser_handler_cmdline"):
        assert CHANNEL_DENIAL_EVIDENCE[name] == ()
        assert qualifying_channel_outcome(artefact(name, "refused")) == "not_applicable"
        assert qualifying_channel_outcome(artefact(name, "observed")) == "observed"
        assert name not in SEPARATION_CLOSURE_CHANNELS
        assert name in SEPARATION_REQUIRED_CHANNELS


# ===========================================================================
# P2-b -- the channel set is pinned to the producer's actual artefacts,
#         derived independently of the criterion's own constant.
# ===========================================================================

def _artefact_names_in_producer_source() -> set[str]:
    """Every artefact name the shipped v1 producer can emit, read from source.

    INDEPENDENT OF THE CRITERION'S CONSTANT ON PURPOSE. A test that compared
    `SEPARATION_REQUIRED_CHANNELS` against something derived from
    `SEPARATION_REQUIRED_CHANNELS` would agree with itself forever. This reads
    the producer's own literals, so adding, removing or renaming a measured
    channel there fails here until the criterion is reconciled with it.
    """
    source = V1_PRODUCER.read_text(encoding="utf-8")
    # TWO SPELLINGS, because the producer has two. Four channels are named as
    # literals at their `_observed`/`_refused`/`_not_applicable` call sites;
    # `runtime_record` and `runtime_log` are named once at the `guarded(...)`
    # assembly and passed down as a variable. Reading only the first spelling
    # found four of six and would have let either of the other two be renamed
    # without this failing.
    direct = re.findall(r'_(?:observed|refused|not_applicable)\(\s*"([a-z_]+)"', source)
    assembled = re.findall(r'guarded\(\s*"([a-z_]+)"', source)
    return set(direct) | set(assembled)


def test_the_required_channels_are_exactly_the_producers_artefacts():
    assert _artefact_names_in_producer_source() == set(SEPARATION_REQUIRED_CHANNELS)


def test_the_required_channels_match_a_real_recorded_measurement():
    """A third, independent witness: the names in the 2026-09-08 record."""
    assert {row["name"] for row in _c3_v1_record()["artefacts"]} == set(
        SEPARATION_REQUIRED_CHANNELS)


def test_every_closure_channel_has_a_refusal_path_in_the_producer():
    """A channel required to prove closure must be able to answer `refused`."""
    source = V1_PRODUCER.read_text(encoding="utf-8")
    for name in SEPARATION_CLOSURE_CHANNELS:
        assert re.search(rf'_refused\(\s*(?:name|"{name}")', source), (
            f"{name} is required to evidence closure but the producer has no refusal "
            "path that can name it")


def test_every_closure_channel_carries_denial_evidence():
    for name in SEPARATION_CLOSURE_CHANNELS:
        assert CHANNEL_DENIAL_EVIDENCE[name], (
            f"{name} must prove closure but no detail can evidence its denial")


def test_closure_is_a_subset_of_required():
    assert set(SEPARATION_CLOSURE_CHANNELS) <= set(SEPARATION_REQUIRED_CHANNELS)


def test_every_denial_marker_still_appears_in_the_producer():
    """A reworded refusal must go stale loudly, not silently admit nothing."""
    source = V1_PRODUCER.read_text(encoding="utf-8")
    for name, markers in CHANNEL_DENIAL_EVIDENCE.items():
        for marker in markers:
            assert marker in source, (
                f"denial marker {marker!r} for {name} no longer appears in the "
                "producer; it can never match, so the channel silently stopped "
                "qualifying")


def test_every_ambiguity_marker_still_appears_in_the_producer():
    source = V1_PRODUCER.read_text(encoding="utf-8")
    for marker in AMBIGUOUS_REFUSAL_MARKERS:
        assert marker in source, (
            f"ambiguity marker {marker!r} no longer appears in the producer")


def test_the_channel_outcome_vocabulary_matches_the_producers():
    from probe_control_plane import ARTEFACT_OUTCOMES  # noqa: PLC0415

    assert tuple(SEPARATION_CHANNEL_OUTCOMES) == tuple(ARTEFACT_OUTCOMES)


def test_the_required_mechanism_is_the_producers_acl_label():
    from probe_control_plane import MECH_ACL  # noqa: PLC0415

    assert CHANNEL_REQUIRED_MECHANISM == MECH_ACL


# ===========================================================================
# P2-e -- fabrication, binding and malformed records, end to end.
# ===========================================================================

def test_a_fabricated_principal_separated_is_refused_not_ignored():
    record = v2_record()
    record["principal_separated"] = "separated"
    with pytest.raises(ProviderError, match="principal_separated"):
        e2e(record)


def test_the_derivation_takes_no_word_from_any_caller():
    import inspect  # noqa: PLC0415

    params = set(inspect.signature(derive_principal_separation).parameters)
    assert params == {"principal_distinct", "channels", "bearer_acquired"}


def test_an_unread_owner_principal_is_inconclusive_end_to_end():
    assert e2e(v2_record(owner_read=False)).outcome == "inconclusive"


def test_the_owner_itself_is_inconclusive_end_to_end():
    assert e2e(v2_record(distinct=False)).outcome == "inconclusive"


def test_a_bearer_through_the_surface_cannot_reach_denied():
    """Refused OUTRIGHT, which is stronger than inconclusive.

    A record claiming `admitted_nuisance` while its own body says a bearer was
    taken through the surface is a label disagreeing with the evidence under
    it, and the translation refuses that before separation is even consulted.
    The derivation's own bearer branch is covered at unit level.
    """
    with pytest.raises(ProviderError, match="bearer acquired through the surface"):
        e2e(v2_record(bearer=True))
    assert derive(bearer_acquired=True) == "not_separated"


@pytest.mark.parametrize("channel", sorted(SEPARATION_REQUIRED_CHANNELS))
def test_an_observed_channel_is_inconclusive_end_to_end(channel):
    outcomes = dict(QUALIFYING) | {channel: "observed"}
    assert e2e(v2_record(outcomes=outcomes)).outcome == "inconclusive"


@pytest.mark.parametrize("provider", ["codex", "claude"])
def test_the_probe_carries_the_provider_it_was_translated_for(provider):
    """Evidence carries its subject and may not travel between providers."""
    probe = e2e(v2_record(), provider=provider)
    assert probe.provider == provider


def test_an_unknown_provider_is_refused():
    with pytest.raises(ProviderError):
        e2e(v2_record(), provider="not-a-provider")


def test_the_probe_carries_the_platform_the_record_names():
    probe = e2e(v2_record())
    assert probe.platform == _c3_v1_record()["subject"]["principal"]["platform"]


@pytest.mark.parametrize("mutation", [
    {"schema": "nornyx.forge.control_plane_probe.v3"},
    {"transport": "test_client"},
    {"bearer_acquired_through_surface": "no"},
])
def test_a_malformed_v2_record_is_refused(mutation):
    with pytest.raises(ProviderError):
        e2e(v2_record(extra=mutation))


def test_separation_evidence_must_be_a_mapping():
    record = v2_record()
    record["separation_evidence"] = []
    with pytest.raises(ProviderError, match="separation_evidence"):
        e2e(record)


@pytest.mark.parametrize("field", ["owner_principal_read", "probe_principal_read"])
def test_a_non_boolean_read_flag_is_refused(field):
    record = v2_record()
    record["separation_evidence"][field] = "yes"
    with pytest.raises(ProviderError, match=field):
        e2e(record)


# ===========================================================================
# Unit-level derivation negatives.
# ===========================================================================

def test_sid_inequality_alone_does_not_yield_separated():
    channels = {name: "not_applicable" for name in SEPARATION_REQUIRED_CHANNELS}
    assert derive(channels=channels) == "unknown"


@pytest.mark.parametrize("channel", sorted(SEPARATION_CLOSURE_CHANNELS))
def test_an_untested_closure_channel_withholds_separated(channel):
    assert derive(channels=dict(QUALIFYING) | {channel: "not_applicable"}) == "unknown"


@pytest.mark.parametrize("channel", sorted(SEPARATION_REQUIRED_CHANNELS))
def test_any_observed_channel_makes_it_not_separated(channel):
    assert derive(channels=dict(QUALIFYING) | {channel: "observed"}) == "not_separated"


@pytest.mark.parametrize("channel", sorted(SEPARATION_REQUIRED_CHANNELS))
def test_a_missing_channel_is_unknown(channel):
    assert derive(channels={k: v for k, v in QUALIFYING.items() if k != channel}) == "unknown"


def test_a_missing_channel_still_loses_to_an_observed_one():
    channels = {k: v for k, v in QUALIFYING.items() if k != "runtime_log"}
    channels["process_vm_read"] = "observed"
    assert derive(channels=channels) == "not_separated"


@pytest.mark.parametrize("word", ["separated", "yes", "true", "SEPARATED", ""])
def test_an_unrecognised_channel_word_raises(word):
    with pytest.raises(ProviderError, match="outside"):
        derive(channels=dict(QUALIFYING) | {"process_vm_read": word})


@pytest.mark.parametrize("value", [1, "yes", None, [], {}])
def test_a_non_boolean_bearer_flag_is_refused(value):
    with pytest.raises(ProviderError, match="bearer_acquired"):
        derive(bearer_acquired=value)


@pytest.mark.parametrize("value", [1, 0, "separated", [], {}])
def test_a_non_boolean_distinctness_is_refused(value):
    with pytest.raises(ProviderError, match="principal_distinct"):
        derive(principal_distinct=value)


def test_the_derivation_only_ever_returns_vocabulary_words():
    for distinct in (True, False, None):
        for outcome in SEPARATION_CHANNEL_OUTCOMES:
            for bearer in (True, False):
                assert derive(
                    principal_distinct=distinct,
                    channels={n: outcome for n in SEPARATION_REQUIRED_CHANNELS},
                    bearer_acquired=bearer,
                ) in PRINCIPAL_SEPARATION


# ===========================================================================
# The slice boundary.
# ===========================================================================

def test_the_criterion_still_demands_denied():
    assert CONFINEMENT_PROPERTIES["control_plane_authority"] == "denied"


def test_v1_still_may_never_record_separated():
    assert _V1_SEPARATION_VALUES == ("not_separated", "unknown")


def test_v2_is_a_second_schema_not_a_replacement():
    assert CONTROL_PLANE_PROBE_SCHEMA.endswith(".v1")
    assert CONTROL_PLANE_PROBE_V2_SCHEMA.endswith(".v2")


def test_there_is_no_dead_v2_vocabulary_constant():
    """It existed, was bound to PRINCIPAL_SEPARATION, and enforced nothing."""
    import nornyx_forge.provider_contract as module  # noqa: PLC0415

    assert not hasattr(module, "_V2_SEPARATION_VALUES")


def test_the_producer_emits_no_unvalidated_required_channels_field():
    import probe_principal_separation as v2mod  # noqa: PLC0415

    evidence = v2mod.separation_evidence(
        {"read": True, "uid": 0}, {"uid": 1},
        [artefact(n, "refused") for n in SEPARATION_REQUIRED_CHANNELS])
    assert "required_channels" not in evidence


def test_the_codex_row_is_untouched():
    assert PROVIDER_CONFINEMENT["codex"]["windows"] == "declared"
    assert PROVIDER_CONFINEMENT["claude"]["windows"] == "none"


def test_no_provider_becomes_eligible():
    for provider in ("codex", "claude"):
        for platform in ("windows", "linux", "darwin"):
            assert governed_build_eligibility(provider, platform).eligible is False


def test_the_v1_producer_is_not_edited_by_this_slice():
    """Its git blob is pinned by the 2026-09-08 measurement.

    SELF-CONTAINED: the blob id is computed in-process from the file's bytes by
    git's own object rule, and compared against the hash the measurement
    RECORDS. No subprocess, no repository history, no network -- so this holds
    in a shallow clone, an exported tarball and a sdist alike, where a
    `git rev-parse` against a historical commit does not.
    """
    data = V1_PRODUCER.read_bytes()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324
    recorded = C3_MEASUREMENT.read_text(encoding="utf-8")
    assert blob in recorded, (
        f"the shipped v1 producer hashes to {blob}, which the C3 measurement does not "
        "record. Its blob is pinned by that measurement and the repair is RE-MEASURING, "
        "not editing the row")


def test_the_v2_producer_validates_its_own_output():
    import probe_principal_separation as v2mod  # noqa: PLC0415

    good = v2_record()
    v2mod.validate_v2_record(good)
    for mutate in (lambda r: r.update({"principal_separated": "separated"}),
                   lambda r: r.update({"separation_evidence": []}),
                   lambda r: r.update({"schema": CONTROL_PLANE_PROBE_SCHEMA})):
        bad = v2_record()
        mutate(bad)
        with pytest.raises((ValueError, ProviderError)):
            v2mod.validate_v2_record(bad)


def test_channels_from_artefacts_is_what_the_translation_uses():
    """No second copy of the channel rule anywhere."""
    record = v2_record()
    assert channels_from_artefacts(record) == QUALIFYING
