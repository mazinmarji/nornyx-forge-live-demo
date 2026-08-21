"""What each execution mode DOES, not what it requests.

`docs/VALIDATION.md` said the normal bootstrap, the CI demo job and the Docker
path "request strict Nornyx/CrewAI execution and fail closed", and that only an
explicit local smoke path was labelled `deterministic_fallback`. Measured, the
shipped container requests neither:

    demo_app.main:app  ->  AUTHORITY = demonstration_authority()
                       ->  policy_backend    = "deterministic_demo"
                       ->  execution_backend = "sequential"

So the sentence described the strict posture while the thing that ships runs the
permissive one -- the same direction of error as the compose file that claimed a
fail-closed default nothing implemented.

The implementation was not the problem and was not changed. `deterministic_demo`
is a deliberate choice: no human approval exists in this repository, so strict
Nornyx refuses everything, and a demonstration that cannot run is not a
demonstration. What was wrong is that the document claimed otherwise.

These tests pin the OBSERVED matrix, so the document can be checked against
behaviour rather than against intent.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from human_authority import (  # noqa: E402
    APPROVAL_NAMED_DIRECTLY,
    LOCK_ABSENT,
    assert_absent_human_authority,
)

# `forbidden_claim_patterns` is deliberately NOT imported here any more. It is
# the retired four-shape enumeration -- the module that defines it says so --
# and this file used it to judge the operator dashboard while the markdown side
# used `find_overclaims`. One concept, two implementations, and the weaker one
# simply passed.
from test_documented_claims import find_overclaims  # noqa: E402

from nornyx_forge.governed_subject import (  # noqa: E402
    GovernedSubjectError,
    RuntimeAuthorityConfig,
)

CASE = {
    "id": "MODE-TRUTH",
    "customer": "Omar",
    "summary": "Issue a high-value external refund",
    "risk": "high",
    "requested_action": "issue refund",
}


def _run(config: RuntimeAuthorityConfig) -> dict:
    """Run one case, with the orchestrator's console noise contained."""
    from demo_app.agentic import run_case  # noqa: PLC0415

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        return run_case(dict(CASE), root=ROOT, config=config)


def test_the_shipped_application_requests_the_permissive_backend():
    """The container's authority, stated as a fact rather than an aspiration.

    This is the assertion the documentation was contradicting. If a future
    change makes the shipped path strict, this fails and the document has to be
    updated with it -- which is the only arrangement under which the two can
    stay in agreement.
    """
    from demo_app.agentic import demonstration_authority  # noqa: PLC0415
    from demo_app.main import AUTHORITY  # noqa: PLC0415

    assert AUTHORITY == demonstration_authority()
    assert AUTHORITY.policy_backend == "deterministic_demo"
    assert AUTHORITY.execution_backend == "sequential"


def test_the_bare_default_is_strict_and_the_shipped_choice_is_not():
    """Both facts together, because either alone reads as the other.

    `RuntimeAuthorityConfig()` defaults to ("nornyx", "crewai"). A reader who
    knows only that would reasonably conclude the application is strict. It is
    not: it names its mode explicitly, and names the permissive one.
    """
    default = RuntimeAuthorityConfig()
    assert (default.policy_backend, default.execution_backend) == ("nornyx", "crewai")

    from demo_app.main import AUTHORITY  # noqa: PLC0415

    assert (AUTHORITY.policy_backend, AUTHORITY.execution_backend) != (
        default.policy_backend,
        default.execution_backend,
    )


def test_the_strict_backend_actually_fails_closed_in_this_repository():
    """"Fails closed" is claimed, so it is measured.

    Nornyx cannot authorize here -- there is no human approval record, which is
    the honest state of this repository -- and the strict path RAISES rather
    than falling back to a deterministic decision under an unchanged label.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable  # noqa: PLC0415

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        _run(RuntimeAuthorityConfig("nornyx", "sequential"))

    # THE DIAGNOSTIC DEPENDS ON THE ENVIRONMENT; THE PROPERTY DOES NOT.
    # This asserted `"CONTRACT_INVALID" in reason`, which only appears once a
    # runtime lock exists -- so it passed in its author's tree and failed on
    # every clean checkout, taking the CI `test` job with it. Its identical
    # twin in tests/test_approval_reachability.py was repaired and this one,
    # one grep away, was not; an independent review found it and I reproduced
    # it in a fresh clone.
    #
    # The helper refuses anything that is not absent human authority, and when
    # the refusal names only the absent lock it establishes the CAUSE from the
    # tree -- a lock someone deleted while an approval stands is not evidence
    # about human authority, and would fail here.
    depth = assert_absent_human_authority(str(refusal.value), ROOT)
    assert depth in (LOCK_ABSENT, *APPROVAL_NAMED_DIRECTLY), depth


def test_a_malformed_backend_refuses_before_anything_runs():
    """Unreadable configuration is refused at construction, not interpreted.

    A mode that fell back to a default when it could not be parsed would let a
    typo select the permissive backend silently.
    """
    with pytest.raises(GovernedSubjectError, match="unknown policy backend"):
        RuntimeAuthorityConfig("NOT_A_BACKEND", "sequential")
    with pytest.raises(GovernedSubjectError, match="unknown execution backend"):
        RuntimeAuthorityConfig("nornyx", "NOT_A_BACKEND")


def test_crewai_cannot_be_claimed_when_crewai_cannot_run(monkeypatch):
    """"CrewAI execution" must mean CrewAI executed.

    A silent downgrade to the sequential driver under an unchanged label is how
    a whole suite once stayed green with CrewAI absent, so the unavailable case
    refuses instead.
    """
    import demo_app.agentic as agentic  # noqa: PLC0415

    monkeypatch.setattr(agentic, "CREWAI_AVAILABLE", False)
    with pytest.raises(agentic.ExecutionBackendUnavailable, match="Refusing to run"):
        _run(RuntimeAuthorityConfig("deterministic_demo", "crewai"))


def test_the_observed_backend_comes_from_the_driver_not_the_configuration():
    """The field that makes the claim checkable at all.

    Restating the configuration would make every backend test tautological --
    it would assert the config equals itself. `_sequential_driver` is set only
    by `run_sequential`, so this reads the execution path.
    """
    from demo_app.agentic import CustomerCaseFlow  # noqa: PLC0415

    flow = CustomerCaseFlow.__new__(CustomerCaseFlow)
    flow.case = {}

    flow._sequential_driver = True
    flow._record_observed_backend()
    assert flow.case["observed_execution_backend"] == "sequential"

    flow._sequential_driver = False
    flow._record_observed_backend()
    assert flow.case["observed_execution_backend"] == "crewai_flow"


def test_the_sequential_path_reports_the_sequential_driver():
    """End to end, so the field above is shown to be reached by a real run."""
    case = _run(RuntimeAuthorityConfig("deterministic_demo", "sequential"))

    assert case["configured_execution_backend"] == "sequential"
    assert case["observed_execution_backend"] == "sequential"
    assert case["configured_policy_backend"] == "deterministic_demo"
    # The high-risk effect is still prevented on the permissive backend. That
    # is the point of recording the mode rather than hiding it: the fallback
    # is a cooperative control, and it refuses this action.
    assert case["status"] == "prevented"
    assert case["action_status"] == "prevented"


def test_the_validation_record_does_not_claim_a_posture_the_container_lacks():
    """The document is checked against the measured matrix, not against intent.

    Kept as a test rather than a review habit because the false sentence
    survived every review that read it.
    """
    text = (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8")

    assert "deterministic_demo" in text, (
        "the validation record does not name the backend the shipped container "
        "actually runs"
    )
    forbidden = "Docker path request strict Nornyx/CrewAI execution"
    assert forbidden not in text, (
        "the validation record claims the Docker path requests strict "
        "Nornyx/CrewAI execution; demo_app.main runs deterministic_demo and "
        "sequential"
    )


# ---------------------------------------------------------------------------
# Lens C P2-2. `README.md` claimed the documented workflow "requires strict
# Nornyx/CrewAI execution in the installed path, launches the application, and
# prints" three URLs. Both halves were false, and the guard written when the
# same claim was corrected in `docs/VALIDATION.md` read ONLY that file -- so the
# claim survived in the README. These three pin it against the code and against
# an executed run, and are kept separate on purpose: a static inference must
# never be recorded later as something that was observed.
# ---------------------------------------------------------------------------


def test_static_the_bootstrap_launch_is_unreachable_once_the_demo_refuses():
    """STATICALLY PROVEN -- control flow only.

    Establishes three facts about `scripts/bootstrap.py` and stops there:
    `run()` defaults to `check=True`, it raises on a nonzero return, and the
    URL prints come after the demo call. Together they mean a nonzero demo ends
    the process before anything launches. WHETHER the demo is nonzero is a
    different question, answered by execution in the next test.
    """
    tree = ast.parse((ROOT / "scripts/bootstrap.py").read_text(encoding="utf-8"))

    run_fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "run")
    check_default = next(
        (d for a, d in zip(run_fn.args.kwonlyargs, run_fn.args.kw_defaults)
         if a.arg == "check"), None)
    assert isinstance(check_default, ast.Constant) and check_default.value is True, (
        "bootstrap.run no longer defaults to check=True, so a refusing demo "
        "would no longer stop the bootstrap"
    )
    assert any(isinstance(n, ast.Raise) for n in ast.walk(run_fn)), (
        "bootstrap.run no longer raises on a nonzero return"
    )

    main_fn = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "main")
    demo_call = next(n.lineno for n in ast.walk(main_fn)
                     if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "run"
                     and "demo_command" in ast.dump(n))
    url_prints = [n.lineno for n in ast.walk(main_fn)
                  if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "print"
                  and "localhost:8000" in ast.dump(n)]
    assert url_prints, "the URL prints are gone; this test pins nothing"
    assert min(url_prints) > demo_call, (
        "the URL prints no longer follow the demo call, so the unreachability "
        "argument in the README is stale"
    )


def test_executed_the_strict_demo_exit_status_agrees_with_the_readme():
    """EXECUTED -- run it, do not infer it. Bidirectional.

    Measured on this branch: exit 2, `status: blocked`,
    `reason: nornyx_runtime_unavailable`, because no human approval exists.

    Asserted as an equivalence rather than a one-way ban. If strict execution
    legitimately starts succeeding later, this fails and forces the launch
    sentence back INTO the README, instead of fossilising today's refusal as
    permanent prose.
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "nornyx_forge.cli", "demo", "--offline",
         "--strict-nornyx"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        timeout=900,
    )
    launched = completed.returncode == 0
    claims_launch = "launches the application, and prints" in (
        ROOT / "README.md"
    ).read_text(encoding="utf-8")

    assert launched == claims_launch, (
        f"README claims the documented workflow launches the application: "
        f"{claims_launch}; the strict demo it documents exited "
        f"{completed.returncode}. Correct the document to the behaviour. "
        f"Output tail: {completed.stdout[-300:]!r}"
    )



#: Quoted and code-span text, which a document MENTIONS rather than ASSERTS.
_QUOTED = re.compile(r"`[^`]*`|\"[^\"]*\"|'[^']*'")


def _unquoted(line: str) -> str:
    """Strip quoted spans, so use can be told from mention.

    The first version of the check below flagged three lines that were all
    CORRECTIONS: README quoting the retired wording to say it was wrong,
    `RUNTIME_INPUT_AUDIT.md` recording `FORGE_STRICT_CREWAI` as a finding, and
    `VALIDATION.md` quoting the sentence it had already fixed. A document that
    repeats a false claim in order to retract it must not be read as making it.

    Piling up negation keywords ("not", "never", "no longer") would have been
    whack-a-mole against prose. Quoting is a real convention and a structural
    one: if you are repeating a retired claim, quote it. Everything outside
    quotes is what the document asserts in its own voice, and that is what gets
    checked.
    """
    return _QUOTED.sub(" ", line)



def _constructs_without_config(module: Path) -> bool:
    """Does this module build a governed flow without passing a config?

    If so, the dataclass default is what actually runs there, and the default
    is part of what the repository REQUESTS -- however few literals appear.
    """
    tree = ast.parse(module.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, 'id', '') in {'DevelopmentFlow',
                                                     'CustomerCaseFlow'}
                and not any(kw.arg == 'config' for kw in node.keywords)):
            return True
    return False

def test_no_document_claims_crewai_where_the_cli_requests_sequential():
    """STATIC over the CODE, quantified over EVERY shipped document.

    `cli.py` sets `execution_backend` unconditionally; only `policy_backend`
    depends on `--strict-nornyx`. So "strict Nornyx/CrewAI execution" was never
    true on any path.

    Quantified over every `.md` rather than a remembered list, because the
    predecessor guard named `docs/VALIDATION.md` explicitly and the identical
    claim then survived in `README.md` -- a list of documents to check is a list
    an author must remember to extend.
    """
    cli = ast.parse((ROOT / "src/nornyx_forge/cli.py").read_text(encoding="utf-8"))
    requested = {
        kw.value.value
        for node in ast.walk(cli)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "RuntimeAuthorityConfig"
        for kw in node.keywords
        if kw.arg == "execution_backend" and isinstance(kw.value, ast.Constant)
    }
    assert requested, "execution_backend is no longer a literal; re-measure it"

    # THE BARE DEFAULT COUNTS AS REQUESTED. This scanned only explicit
    # `RuntimeAuthorityConfig(execution_backend=...)` literals, so it could not
    # see that `cli.py` builds `DevelopmentFlow` with NO config -- where the
    # dataclass default `crewai` applies and a real Flow kickoff runs
    # (build-summary.json: execution_backend crewai_flow). The guard therefore
    # rested on a false premise and would have FAILED THE SUITE on a truthful
    # sentence about the build path.
    from nornyx_forge.governed_subject import (  # noqa: PLC0415
        RuntimeAuthorityConfig,
    )

    if _constructs_without_config(ROOT / 'src/nornyx_forge/cli.py'):
        requested.add(RuntimeAuthorityConfig().execution_backend)
    if any("crew" in value.lower() for value in requested):
        return  # the claim would be true; nothing to forbid

    offenders = []
    # THE CANONICAL DISCOVERY HELPER, not a hand-built list. This read
    # [README.md, *docs/**] while its docstring claimed it quantified over
    # every .md -- and a review found the retired claim alive in
    # PUBLISH.md, outside the sweep. `governance_docs()` was written for
    # exactly this failure and was not being used here.
    from test_documented_claims import governance_docs  # noqa: PLC0415

    for path in governance_docs():
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            asserted = _unquoted(line).lower()
            # WHOLE WORDS. A substring test matched "strict" inside
            # "non-strict", so a sentence saying the job runs the demo
            # NON-strict was read as claiming strict execution -- the negation
            # flagged as the assertion it denies.
            # Hyphens stay INSIDE tokens, so "non-strict" is one word and not
            # the word "strict". Splitting on every non-letter turned the
            # negation into the term it negates.
            words = set(re.split("[^a-z-]+", asserted))
            if "crewai" in words and "strict" in words:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    assert offenders == [], (
        f"cli.py requests execution_backend={sorted(requested)}, so CrewAI is "
        f"never asked for, but these lines claim strict CrewAI execution: {offenders}"
    )


#: Assertions that must be caught, and corrections that must not. The last
#: three are real lines from this repository that the first version of the
#: check flagged -- all of them documents retracting the claim, not making it.
USE_MENTION_SPECIMENS = [
    ("bare assertion",
     "The workflow requires strict Nornyx/CrewAI execution in the installed path.",
     True),
    ("assertion wrapped in markdown emphasis",
     "It **requires strict Nornyx/CrewAI execution** and fails closed.", True),
    ("README correction quoting the retired claim",
     'the previous wording "strict Nornyx/CrewAI execution" said otherwise.', False),
    ("audit row naming the env var in backticks",
     "`FORGE_USE_CREWAI_KICKOFF` / `FORGE_STRICT_CREWAI` select a degraded backend.",
     False),
    ("VALIDATION quoting the sentence it already fixed",
     'said the Docker path "request strict Nornyx/CrewAI execution and fail closed".',
     False),
]


@pytest.mark.parametrize(
    ("label", "line", "should_flag"),
    USE_MENTION_SPECIMENS,
    ids=[case[0] for case in USE_MENTION_SPECIMENS],
)
def test_a_retracted_claim_is_not_read_as_a_claim(
    label: str, line: str, should_flag: bool
):
    """Both directions. A check that stops firing is not the same as a fix.

    Loosening the CrewAI check until it went quiet would have removed the only
    thing standing between this repository and the claim coming back. These
    pin that an UNQUOTED assertion is still caught while a quoted retraction is
    not.
    """
    asserted = _unquoted(line).lower()
    flagged = "crewai" in asserted and "strict" in asserted
    assert flagged is should_flag, (
        f"{label}: flagged={flagged}, expected={should_flag}"
    )


#: Surfaces an operator actually looks at. A review found
#: "Live CrewAI Flow · Nornyx policy decisions" hardcoded in the dashboard,
#: served at both `/` and `/dashboard`, while every decision measured
#: `deterministic_fallback` and `sequential`. Static markup reads identically
#: whatever ran, so it cannot go false -- and no guard scanned `.html`.
UI_SUFFIXES = (".html", ".htm", ".js", ".css")


def _ui_surfaces() -> list[Path]:
    """Authored UI files, discovered rather than listed."""
    skip = {".venv", "node_modules", ".git", ".nornyx", "evidence", "site-packages"}
    return sorted(
        path
        for suffix in UI_SUFFIXES
        for path in ROOT.rglob(f"*{suffix}")
        if not any(part in skip for part in path.relative_to(ROOT).parts)
    )


def test_the_ui_surface_sweep_finds_the_dashboard():
    """Guard the guard: an empty sweep would pass the check below silently."""
    names = {p.relative_to(ROOT).as_posix() for p in _ui_surfaces()}
    assert "src/demo_app/static/index.html" in names, (
        f"the dashboard is outside the UI sweep: {sorted(names)[:6]}"
    )


def test_no_ui_surface_claims_a_governance_mode_the_run_does_not_use():
    """The operator-facing claim must match what a run reports.

    Measured rather than assumed: the shipped path reports
    `governance_mode: deterministic_fallback` and
    `observed_execution_backend: sequential`, so a surface asserting Nornyx
    governance or a CrewAI Flow is asserting something the run does not do.
    """
    offenders = []
    for path in _ui_surfaces():
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            asserted = _unquoted(line).lower()
            words = set(re.split("[^a-z-]+", asserted))
            claims_crewai_flow = "crewai" in words and "flow" in words
            compatible = "compatible" in words or "sequential" in words
            if claims_crewai_flow and not compatible:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
            if "governance" in words and "nornyx" in words and "fallback" not in words:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    # THE SAME QUESTION, ASKED OF LABEL AND VALUE TOGETHER. The sweep above is
    # per LINE, and `_dashboard_metrics` allows whitespace between the label
    # span and the value strong -- so putting the value on its own line hid it:
    #
    #     <article><span>Governance</span>
    #       <strong>Nornyx runtime authorization</strong></article>
    #
    # measured 47 passed, while the guard's own scraper read
    # {"Governance": "Nornyx runtime authorization"}. The Framework row was
    # caught by the identical split, which is how it is clear the closed metric
    # set works and only the VALUE check was line-bound.
    for label, value in _dashboard_metrics().items():
        asserted = _unquoted(label + " " + value).lower()
        words = set(re.split("[^a-z-]+", asserted))
        if "crewai" in words and "flow" in words and not (
            "compatible" in words or "sequential" in words
        ):
            offenders.append(f"dashboard metric {label!r} = {value!r}")
        if "governance" in words and "nornyx" in words and "fallback" not in words:
            offenders.append(f"dashboard metric {label!r} = {value!r}")

    assert offenders == [], (
        "these operator-facing surfaces claim a governance or execution mode "
        f"the shipped run does not use: {offenders}"
    )


# --------------------------------------------------------------------------
# C3-P2-4 -- the dashboard's ASSURANCE metrics were covered by nothing.
#
# The sweep above checks two keyword pairs -- CrewAI/Flow and Nornyx/governance
# -- and reads no run at all. A review substituted each of the four metric
# values in turn and measured which the module would catch:
#
#     'Live CrewAI Flow'                  -> caught
#     'Nornyx governance active'          -> caught
#     'Nornyx runtime authorization'      -> ADMITTED
#     'Independently inspected'           -> ADMITTED
#     'Production approval granted'       -> ADMITTED
#     'Human review: Performed'           -> ADMITTED
#
# The markdown overclaim guard does not reach here either: it scans `*.md`, and
# its patterns are tuned for prose and JSON, where a separator sits between key
# and value. In markup the two are separated by TAGS, so
# `<span>Human review</span><strong>Performed</strong>` matches nothing.
#
# So this does not add more keywords. All four metrics are STATIC LITERALS that
# `app.js` never touches. TWO of them -- Human review and Production approval --
# restate a value this repository records in an artifact, and the check is that
# they AGREE with it. The other two, Framework and Governance, are value-checked
# by the keyword sweep above, not here; a review measured this comment implying
# all four were bound to artifacts when `ASSURANCE_METRICS` holds two.
# `NON_ASSURANCE_METRICS` names the other two so the set of rows is CLOSED and a
# fifth row cannot arrive unclassified.
# --------------------------------------------------------------------------

#: Dashboard label -> (artifact field, the value that field holds today, the
#: text the dashboard must show while it holds it).
ASSURANCE_METRICS = {
    "Human review": ("human_review", "not_performed", "not performed"),
    "Production approval": ("production_approval", "not_granted", "not granted"),
}

#: Metrics that are NOT assurance state, and are value-checked by the keyword
#: sweep above instead. Listed so the set of dashboard rows is CLOSED.
NON_ASSURANCE_METRICS = frozenset({"Framework", "Governance"})


def _dashboard_metrics() -> dict:
    """Every `<span>LABEL</span><strong>VALUE</strong>` pair, tags stripped."""
    html = (ROOT / "src/demo_app/static/index.html").read_text(encoding="utf-8")
    found = {}
    for label, value in re.findall(
        r"<span>([^<]+)</span>\s*<strong>([^<]+)</strong>", html
    ):
        found[label.strip()] = value.strip()
    return found


def test_the_metric_scrape_finds_the_dashboard_values():
    """Guard the guard. A scrape that returns nothing passes everything below."""
    metrics = _dashboard_metrics()
    missing = sorted(set(ASSURANCE_METRICS) - set(metrics))
    assert missing == [], (
        f"the dashboard no longer presents these metrics in the shape this "
        f"check reads, so it is measuring nothing: {missing} (found "
        f"{sorted(metrics)})"
    )


@pytest.mark.parametrize("label", sorted(ASSURANCE_METRICS))
def test_the_dashboard_assurance_metrics_match_the_recorded_state(label: str):
    """The operator sees what the artifacts say, or this fails.

    Not a keyword list. The approval record is regenerated on every commit and
    is the repository's own statement about whether a human approved anything;
    if the dashboard ever disagrees with it, one of the two is lying to an
    operator and this says which.
    """
    field, expected_value, expected_text = ASSURANCE_METRICS[label]
    record = json.loads(
        (ROOT / ".nornyx/contracts/evidence/architecture_approval_record.json")
        .read_text(encoding="utf-8")
    )
    assert record[field] == expected_value, (
        f"the recorded {field} is now {record[field]!r}. If a human really has "
        "approved, this table and the dashboard both need updating together -- "
        "which is the point of failing here rather than letting them drift."
    )
    shown = _dashboard_metrics()[label].lower()
    assert shown == expected_text, (
        f"the dashboard shows {label!r} as {shown!r} while the repository "
        f"records {field}={record[field]!r}. An operator reading the dashboard "
        "would believe something the evidence does not support."
    )


def test_the_dashboard_claims_no_independent_inspection():
    """The one assurance claim with no metric row, checked directly.

    `independently_inspected` is derived and derives to false here. The markdown
    guard refuses it in documents; nothing refused it in the UI, and a review
    measured `Independently inspected` admitted when substituted in.
    """
    # THE LIVE GUARD. This ran `forbidden_claim_patterns()`, which the module
    # defining it describes as "what the guard used to BE ... admitting 9 of 14
    # assertion spellings". A review put four claim markups through both and
    # measured the dashboard scan admitting every one that `find_overclaims`
    # catches, including the badge text `Independent inspection completed`.
    #
    # Importing the concept guard rather than keeping a second enumeration is
    # the point: two lists of shapes drift, and the drift is invisible because
    # the weaker one simply passes.
    #
    # The manual `not[ _-]+$` lookback is gone too -- `find_overclaims` decides
    # negation by clause scope, which is strictly what that lookback was
    # approximating with one character class.
    html = (ROOT / "src/demo_app/static/index.html").read_text(encoding="utf-8")
    stripped = re.sub(r"<[^>]+>", " ", html)
    offences = [hit.group() for hit in find_overclaims(stripped)]
    assert offences == [], (
        "the operator dashboard asserts assurance this repository does not "
        f"hold: {offences}"
    )


def test_the_dashboard_presents_no_metric_outside_the_closed_set():
    """C4-P2-2: the metric table was open, so a new row was covered by nothing.

    `ASSURANCE_METRICS` binds two labels and the keyword sweep binds two more.
    A review added four fabricated rows -- `Nornyx runtime authorization`,
    `Fully assured, three attestations`, `Independent inspection performed`,
    `Production release authorized` -- and every guard passed. One of them was
    caught only incidentally, because the word *governance* happened to sit in
    that row's label.

    So the set is closed. A row nobody has classified fails here rather than
    defaulting to unchecked, which is the same rule `artifact_authority`
    applies to evidence files: absence of a classification is a refusal, never
    a default.
    """
    shown = set(_dashboard_metrics())
    known = set(ASSURANCE_METRICS) | NON_ASSURANCE_METRICS
    unclassified = sorted(shown - known)
    assert unclassified == [], (
        "the operator dashboard presents metrics that no guard classifies, so "
        "their values are checked by nothing: " + str(unclassified)
    )
    missing = sorted(known - shown)
    assert missing == [], (
        f"a classified metric is no longer on the dashboard: {missing}. The "
        "guard would then be checking a row that does not exist."
    )
