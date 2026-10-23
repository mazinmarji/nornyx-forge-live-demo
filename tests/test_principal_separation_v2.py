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

WHAT THE OWNER-PRINCIPAL CYCLE ADDED. On Windows the owner's principal is now
read from its token, and on the hosted Windows runner this module reads a real
same-user process that way: the one Windows measurement taken here, and it can
only show the two principals to be the SAME. A different SID, a denied read and
Forge's own attestation of its principal all leave the derivation at `unknown`.

WHAT NONE OF THIS ESTABLISHES. No provider row moves, Codex is not eligible,
and no cross-user Windows measurement is taken anywhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat as stat_module
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import probe_control_plane as v1mod  # noqa: E402
import probe_principal_separation as v2mod  # noqa: E402

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


# ===========================================================================
# The owner principal on Windows: a same-user read, failing closed.
#
# Every test here runs on both platforms with no skip. The host test reads a
# real child process: through `/proc` on Linux and through the token on the
# hosted Windows runner, where this module runs in the windows-runtime job.
# The rest inject the token reader, so its failures are deterministic.
# ===========================================================================

SID_A = "S-1-5-21-1111111111-2222222222-3333333333-1001"
SID_B = "S-1-5-21-1111111111-2222222222-3333333333-1002"


def _qualifying_artefacts():
    return [artefact(name, QUALIFYING[name]) for name in SEPARATION_REQUIRED_CHANNELS]


def _reader(answer, calls):
    """A token reader that records the pid it was asked for, then answers."""
    def read(pid):
        calls.append(pid)
        if isinstance(answer, BaseException):
            raise answer
        return answer
    return read


def _v1_qualifying(sid=SID_A):
    """The real v1 record, with qualifying artefacts and a Windows probe SID."""
    record = json.loads(json.dumps(_c3_v1_record()))
    record["artefacts"] = _qualifying_artefacts()
    record["subject"]["principal"] = {"platform": "win32", "sid": sid, "uid": None}
    return record


@pytest.fixture
def child():
    """A real process of this same user, so its owner is this caller."""
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    try:
        yield process
    finally:
        process.kill()
        process.wait(timeout=30)


def test_the_same_user_owner_is_read_on_this_host_and_derives_not_separated(child):
    """THE MEASUREMENT this cycle adds, taken on the host the suite runs on.

    On the hosted Windows runner this is the ctypes token read of a real
    process; on Linux it is `/proc`. Either way the owner is this same user,
    so the honest answer is `not_separated` -- where Windows used to answer
    `unknown` because it did not read at all.
    """
    owner = v2mod.owner_principal(child.pid, probe_pid=os.getpid())
    assert owner["read"] is True, owner
    if sys.platform == "win32":
        assert v2mod.SID_SHAPE.fullmatch(owner["sid"]), owner
        assert owner["uid"] is None
    probe = v1mod._principal()
    evidence = v2mod.separation_evidence(owner, probe, _qualifying_artefacts())
    assert evidence["owner_principal_read"] is True
    assert evidence["principal_distinct"] is False
    assert evidence["comparison_withheld"] is None
    assert derive(principal_distinct=evidence["principal_distinct"]) == "not_separated"


def test_the_token_reader_answers_on_windows_and_refuses_everywhere_else():
    if sys.platform == "win32":
        sid = v2mod._windows_owner_sid(os.getpid())
        assert v2mod.SID_SHAPE.fullmatch(sid)
        assert sid == v1mod._principal()["sid"], "the token read and whoami disagree"
    else:
        with pytest.raises(OSError, match="only on Windows"):
            v2mod._windows_owner_sid(os.getpid())


def test_a_same_sid_token_read_is_not_separated(monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(v2mod, "_windows_owner_sid", _reader(SID_A, calls), raising=False)
    owner = v2mod.owner_principal(4242, probe_pid=1, platform_name="win32")
    assert owner["read"] is True and owner["sid"] == SID_A and calls == [4242], owner
    evidence = v2mod.separation_evidence(owner, {"platform": "win32", "sid": SID_A},
                                         _qualifying_artefacts())
    assert evidence["principal_distinct"] is False
    assert derive(principal_distinct=False) == "not_separated"


@pytest.mark.parametrize("answer", [
    PermissionError(5, "OpenProcess denied"),
    OSError(87, "OpenProcess failed"),
    OSError("the token read is available only on Windows"),
    RuntimeError("anything else"),
    None,
    5,
    "",
    "not-a-sid",
    "S-1-5",
    SID_A + "\n",
])
def test_every_failed_token_read_is_an_unread_owner(monkeypatch, answer):
    """Denied, failed, unsupported or malformed: unread, so `unknown`. The
    reader WAS asked, which is what this cycle changes; its failure decides
    nothing but that the owner is unread."""
    calls: list[int] = []
    monkeypatch.setattr(v2mod, "_windows_owner_sid", _reader(answer, calls), raising=False)
    owner = v2mod.owner_principal(4242, probe_pid=1, platform_name="win32")
    assert calls == [4242], "the Windows token read was never attempted"
    assert owner["read"] is False and owner["sid"] is None and owner["uid"] is None, owner
    assert "never `separated`" in owner["detail"], owner
    evidence = v2mod.separation_evidence(owner, {"platform": "win32", "sid": SID_A},
                                         _qualifying_artefacts())
    assert evidence["owner_principal_read"] is False and evidence["principal_distinct"] is None
    assert derive(principal_distinct=None) == "unknown"


def test_a_token_read_naming_a_different_sid_is_withheld_not_separated(monkeypatch):
    """A cross-user read that SUCCEEDS is an ACL fact, not separation.

    Every closure channel refused, the probe's SID read, the owner's SID read
    and different: in this cycle that is still `unknown`, end to end. A
    producer that compared it would derive `separated` from a token read alone.
    """
    calls: list[int] = []
    monkeypatch.setattr(v2mod, "_windows_owner_sid", _reader(SID_B, calls), raising=False)
    v2 = v2mod.to_v2(_v1_qualifying(SID_A), probe_pid=1, platform_name="win32")
    evidence = v2["separation_evidence"]
    assert calls == [_c3_v1_record()["subject"]["surface"]["pid"]]
    assert evidence["owner_principal"]["read"] is True
    assert evidence["owner_principal_read"] is False
    assert evidence["principal_distinct"] is None
    assert "different SID" in evidence["comparison_withheld"]
    assert v2mod.derived_word(v2) == "unknown"
    assert e2e(v2).outcome == "inconclusive"


def test_a_withheld_comparison_cannot_be_reasserted_past_the_validator(monkeypatch):
    monkeypatch.setattr(v2mod, "_windows_owner_sid", _reader(SID_B, []), raising=False)
    v2 = v2mod.to_v2(_v1_qualifying(SID_A), probe_pid=1, platform_name="win32")
    v2["separation_evidence"]["owner_principal_read"] = True
    v2["separation_evidence"]["principal_distinct"] = True
    with pytest.raises(ValueError, match="withheld"):
        v2mod.validate_v2_record(v2)


# ===========================================================================
# The owner attestation: bound to the run, recorded, and never trusted.
# ===========================================================================

def _runtime_record(path, *, instance=None, pid=None, attested=None, schema=None,
                    drop=()):
    surface = _c3_v1_record()["subject"]["surface"]
    record = {
        "schema": schema or "nornyx.forge.windows_runtime.v1",
        "instance": surface["instance"] if instance is None else instance,
        "pid": surface["pid"] if pid is None else pid,
        "status": "ready", "port": surface["port"],
        "attested_principal": ({"platform": "win32", "sid": SID_B, "uid": None,
                                "detail": "read by this process from its own token user"}
                               if attested is None else attested),
    }
    for key in drop:
        record.pop(key)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _unwritable(_path):
    return False


def test_the_runtime_schema_restated_by_the_probe_is_the_runtimes_own():
    from nornyx_forge import windows_runtime  # noqa: PLC0415

    assert v2mod.RUNTIME_RECORD_SCHEMA == windows_runtime.RUNTIME_SCHEMA


def test_a_bound_attestation_with_every_closure_refused_still_derives_unknown(
        tmp_path, monkeypatch):
    """THE PIN THIS CYCLE PROMISED. Forge attests a DIFFERENT principal, the
    attestation is bound to this run's instance, pid and v1 digest from a
    channel this principal was not found able to write, the owner's own token
    was denied, and every closure channel was measured refused. `unknown`."""
    monkeypatch.setattr(v2mod, "_windows_owner_sid",
                        _reader(PermissionError(5, "denied"), []), raising=False)
    v1_record = _v1_qualifying(SID_A)
    attestation = v2mod.owner_attestation(_runtime_record(tmp_path / "r.json"), v1_record,
                                          writable=_unwritable)
    assert attestation["bound"] is True and attestation["trusted"] is False, attestation
    assert attestation["attested_principal"]["sid"] == SID_B
    assert attestation["v1_record_sha256"] == v2mod.record_digest(v1_record)
    assert attestation["runtime_record_sha256"].startswith("sha256:")
    owner = v2mod.owner_principal(v1_record["subject"]["surface"]["pid"], probe_pid=1,
                                  platform_name="win32")
    evidence = v2mod.separation_evidence(owner, v1_record["subject"]["principal"],
                                         v1_record["artefacts"], attestation)
    v2 = dict(v1_record, schema=CONTROL_PLANE_PROBE_V2_SCHEMA, separation_evidence=evidence)
    v2.pop("principal_separated")
    v2.pop("not_confinement_reason")
    v2mod.validate_v2_record(v2)
    assert evidence["owner_principal_read"] is False and evidence["principal_distinct"] is None
    assert v2mod.derived_word(v2) == "unknown"
    assert e2e(v2).outcome == "inconclusive"


def test_the_attestation_feeds_no_field_the_derivation_reads(tmp_path):
    v1_record = _v1_qualifying(SID_A)
    attestation = v2mod.owner_attestation(_runtime_record(tmp_path / "r.json"), v1_record,
                                          writable=_unwritable)
    assert attestation["bound"] is True
    for owner in ({"read": False, "platform": "win32", "sid": None, "uid": None},
                  {"read": True, "platform": "win32", "sid": SID_A, "uid": None}):
        without = v2mod.separation_evidence(owner, v1_record["subject"]["principal"],
                                            v1_record["artefacts"])
        with_it = v2mod.separation_evidence(owner, v1_record["subject"]["principal"],
                                            v1_record["artefacts"], attestation)
        assert with_it.pop("owner_principal_attestation") == attestation
        assert with_it == without


def test_to_v2_records_the_attestation_and_derives_the_same_word(tmp_path, monkeypatch):
    monkeypatch.setattr(v2mod, "_windows_owner_sid",
                        _reader(PermissionError(5, "denied"), []), raising=False)
    path = _runtime_record(tmp_path / "r.json")
    with_it = v2mod.to_v2(_v1_qualifying(SID_A), probe_pid=1, platform_name="win32",
                          runtime_record=path)
    without = v2mod.to_v2(_v1_qualifying(SID_A), probe_pid=1, platform_name="win32")
    attestation = with_it["separation_evidence"]["owner_principal_attestation"]
    # The real writability check: this test wrote the file, so it is refused.
    assert attestation["trusted"] is False and attestation["bound"] is False
    assert "owner_principal_attestation" not in without["separation_evidence"]
    assert v2mod.derived_word(with_it) == v2mod.derived_word(without) == "unknown"


def test_an_attestation_from_a_channel_this_principal_can_write_is_refused(tmp_path):
    """The REAL check, not an injected one: a file this test just wrote is
    writable by this principal, which could have written the attestation."""
    attestation = v2mod.owner_attestation(_runtime_record(tmp_path / "r.json"),
                                          _v1_qualifying())
    assert attestation["bound"] is False
    assert attestation["channel_writable_by_this_principal"] is True
    assert "writable by this principal" in attestation["refusal"]
    assert attestation["attested_principal"] is None


@pytest.mark.parametrize("writable, words", [(True, "writable"), (None, "could not be asked")])
def test_an_unclearable_channel_is_refused(tmp_path, writable, words):
    attestation = v2mod.owner_attestation(_runtime_record(tmp_path / "r.json"),
                                          _v1_qualifying(), writable=lambda _p: writable)
    assert attestation["bound"] is False and words in attestation["refusal"]
    assert attestation["attested_principal"] is None


@pytest.mark.parametrize("make, words", [
    (lambda p: _runtime_record(p, drop=("instance",)), "no instance token"),
    (lambda p: _runtime_record(p, instance=""), "no instance token"),
    (lambda p: _runtime_record(p, instance="0" * 32), "not the measured surface's"),
    (lambda p: _runtime_record(p, pid=1), "pid"),
    (lambda p: _runtime_record(p, pid=True), "pid"),
    (lambda p: _runtime_record(p, drop=("pid",)), "pid"),
    (lambda p: _runtime_record(p, drop=("attested_principal",)), "attested principal"),
    (lambda p: _runtime_record(p, attested={"platform": "win32", "sid": None, "uid": None}),
     "attested principal"),
    (lambda p: _runtime_record(p, attested={"platform": "win32", "sid": SID_B, "uid": 0}),
     "attested principal"),
    (lambda p: _runtime_record(p, attested={"platform": "win32", "sid": "S-1-x", "uid": None}),
     "attested principal"),
    (lambda p: _runtime_record(p, attested={"platform": "linux", "sid": None, "uid": True}),
     "attested principal"),
    (lambda p: _runtime_record(p, attested={"sid": SID_B, "uid": None}), "attested principal"),
    (lambda p: _runtime_record(p, schema="nornyx.forge.windows_runtime.v0"), "not a"),
    (lambda p: (p.write_text("{not json", encoding="utf-8"), p)[1], "not JSON"),
    (lambda p: (p.write_bytes(b"\xff\xfe"), p)[1], "not JSON"),
    (lambda p: (p.write_text("[]", encoding="utf-8"), p)[1], "not a"),
    (lambda p: p / "absent.json", "could not be read"),
])
def test_an_unbindable_attestation_is_refused_by_name(tmp_path, make, words):
    attestation = v2mod.owner_attestation(make(tmp_path / "r.json"), _v1_qualifying(),
                                          writable=_unwritable)
    assert attestation["bound"] is False, attestation
    assert words in attestation["refusal"], attestation
    assert attestation["attested_principal"] is None and attestation["trusted"] is False
    v2mod.validate_attestation(attestation)


def test_a_v1_record_without_an_instance_cannot_bind_one(tmp_path):
    v1_record = _v1_qualifying()
    v1_record["subject"]["surface"]["instance"] = None
    attestation = v2mod.owner_attestation(_runtime_record(tmp_path / "r.json", instance="x"),
                                          v1_record, writable=_unwritable)
    assert attestation["bound"] is False
    assert "no instance token to bind to" in attestation["refusal"]


def test_the_attestation_takes_no_principal_from_its_caller():
    import inspect  # noqa: PLC0415

    params = set(inspect.signature(v2mod.owner_attestation).parameters)
    assert params == {"runtime_record", "v1_record", "writable"}


def _bound(tmp_path):
    return v2mod.owner_attestation(_runtime_record(tmp_path / "r.json"), _v1_qualifying(),
                                   writable=_unwritable)


@pytest.mark.parametrize("mutate, words", [
    (lambda a: a.update(trusted=True), "never trusted"),
    (lambda a: a.update(trusted="false"), "never trusted"),
    (lambda a: a.update(trusted=None), "never trusted"),
    (lambda a: a.update(source="probe_self_report"), "refused"),
    (lambda a: a.update(principal_distinct=True), "carries exactly"),
    (lambda a: a.pop("limit"), "carries exactly"),
    (lambda a: a.update(refusal="but refused"), "bound owner attestation"),
    (lambda a: a.update(channel_writable_by_this_principal=None), "bound owner attestation"),
    (lambda a: a.update(attested_principal=None), "bound owner attestation"),
    (lambda a: a.update(bound=False), "refused owner attestation"),
    (lambda a: a.update(bound="yes"), "bool"),
])
def test_the_producer_refuses_an_attestation_it_would_never_write(tmp_path, mutate, words):
    attestation = _bound(tmp_path)
    v2mod.validate_attestation(attestation)
    mutate(attestation)
    with pytest.raises(ValueError, match=words):
        v2mod.validate_attestation(attestation)
    record = v2_record()
    record["separation_evidence"]["owner_principal_attestation"] = attestation
    with pytest.raises(ValueError):
        v2mod.validate_v2_record(record)


@pytest.mark.parametrize("owner_read, distinct", [(False, True), (False, None), (True, False)])
def test_a_forged_trusted_attestation_cannot_move_the_translation(tmp_path, owner_read,
                                                                   distinct):
    """A hand-written record whose attestation says `trusted: true` and names
    a different principal, beside every closure channel refused: the
    translation never reads it, so the outcome is exactly the outcome of the
    same record without it -- and never `denied`."""
    forged = _bound(tmp_path) | {"trusted": True}
    plain = v2_record(owner_read=owner_read, distinct=distinct)
    carrying = v2_record(owner_read=owner_read, distinct=distinct)
    carrying["separation_evidence"]["owner_principal_attestation"] = forged
    assert e2e(carrying).outcome == e2e(plain).outcome == "inconclusive"


def test_the_cli_records_an_attestation_and_prints_the_same_word(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(v2mod, "owner_principal", lambda pid, **_: {
        "read": False, "platform": "win32", "sid": None, "uid": None, "detail": "test"})
    source = tmp_path / "v1.json"
    source.write_text(json.dumps(_c3_v1_record()), encoding="utf-8")
    out = tmp_path / "v2.json"
    assert v2mod.main(["--from-v1-record", str(source), "--out", str(out)]) == 0
    plain = capsys.readouterr().err
    assert v2mod.main(["--from-v1-record", str(source), "--out", str(out),
                       "--owner-attestation-from-runtime-record",
                       str(_runtime_record(tmp_path / "r.json"))]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    attestation = written["separation_evidence"]["owner_principal_attestation"]
    assert attestation["trusted"] is False and attestation["bound"] is False
    # The real 2026-09-08 record observed a channel, so its word is
    # `not_separated` with or without an attestation.
    assert capsys.readouterr().err == plain == "derived principal_separated: not_separated\n"


def test_a_record_swapped_in_after_its_channel_was_judged_is_refused(tmp_path):
    """The file whose channel was judged must be the file whose bytes are
    bound. Here the judgement itself swaps a different record onto the path,
    as a racing writer would, and the read finds another file there."""
    path = _runtime_record(tmp_path / "r.json")
    replacement = _runtime_record(tmp_path / "other.json", attested={
        "platform": "win32", "sid": SID_A, "uid": None})

    def judge_then_swap(target):
        os.replace(replacement, target)
        return False

    attestation = v2mod.owner_attestation(path, _v1_qualifying(), writable=judge_then_swap)
    assert attestation["bound"] is False, attestation
    assert "changed between its check and its read" in attestation["refusal"]
    assert attestation["attested_principal"] is None


def test_a_descriptor_that_is_not_the_checked_file_is_refused(tmp_path, monkeypatch):
    path = _runtime_record(tmp_path / "r.json")
    real = os.fstat

    def other_file(descriptor):
        values = list(real(descriptor))
        values[1] += 1  # st_ino
        return os.stat_result(values)

    monkeypatch.setattr(v2mod.os, "fstat", other_file)
    attestation = v2mod.owner_attestation(path, _v1_qualifying(), writable=_unwritable)
    assert attestation["bound"] is False
    assert "changed between its check and its read" in attestation["refusal"]


def test_a_link_is_refused_without_being_followed(tmp_path, monkeypatch):
    """Forge writes a regular file. A link could send the read to a file the
    writability check never looked at, so a path that IS a link is refused --
    shown by its `lstat`, so no link needs creating on a host that may not
    allow one."""
    path = _runtime_record(tmp_path / "r.json")
    real = os.lstat

    def as_link(target, *args, **kwargs):
        values = list(real(target, *args, **kwargs))
        values[0] = stat_module.S_IFLNK | 0o777
        return os.stat_result(values)

    monkeypatch.setattr(v2mod.os, "lstat", as_link)
    attestation = v2mod.owner_attestation(path, _v1_qualifying(), writable=_unwritable)
    assert attestation["bound"] is False and "is a link" in attestation["refusal"]


def test_a_directory_and_an_oversized_file_are_refused(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    attestation = v2mod.owner_attestation(folder, _v1_qualifying(), writable=_unwritable)
    assert attestation["bound"] is False and "not a regular file" in attestation["refusal"]
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (v2mod.RUNTIME_RECORD_LIMIT + 1))
    attestation = v2mod.owner_attestation(big, _v1_qualifying(), writable=_unwritable)
    assert attestation["bound"] is False and "larger than" in attestation["refusal"]
