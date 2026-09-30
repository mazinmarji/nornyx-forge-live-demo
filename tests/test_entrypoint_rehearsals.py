"""Three real entrypoints are rehearsed, and three guards are shown load-bearing.

What is held here, in words:

- REHEARSED: `scripts/prepare_runtime.py`, `scripts/check_pre_approval_baseline.py`
  and `python -m nornyx_forge.cli demo --offline` each run, unmodified, in a copy
  of this repository's tracked files, and the run matches its declared contract
  in full: exit code, every file created, modified or deleted under the fixture,
  an empty home and an empty temp directory, and output text. For the demo the
  test also reads its JSON and requires every case, and the number of cases, to
  report its Nornyx evidence as `fallback` naming `RUNTIME_LOCK_MISSING`.
- GUARD-LIVE: the accepted-set filter and the unexplained-failure guard of the
  baseline check, and the absent-CLI guard of runtime preparation, are each shown
  load-bearing for one declared trigger: the run refuses, with the guard alone
  neutralized (one exact snippet, in the copy) the refusal goes and the run
  reaches the declared point past it, and a control run without the trigger does
  not refuse. Every refusal signature names the guard's own message or finding.
- BUILT FROM NOTHING: each child sees only the declared PATH, PYTHONPATH and
  PYTHONDONTWRITEBYTECODE, an empty home and temp directory and no stdin. A static
  test holds every spec to that: no inherited variable, exactly those three names,
  and every absolute path token in any string of the spec is exactly one it may name.

NO NETWORK IS NOT CHECKED HERE. The rehearsals were also run with no network
access on a Linux host (a fresh user and network namespace, with a positive
control); that is NOT ESTABLISHED on CI, where the hosted runner refuses
unprivileged user namespaces ("unshare: write failed /proc/self/uid_map: Operation
not permitted"), so those checks are not part of this suite.

The demo CLI rehearsal declares writes that are not this repository's own
logic: importing CrewAI creates its generated key and state under the child's
HOME. Those paths are declared, so any other write fails the run; the fix is
outside this change (`docs/requirements/ASSUMPTIONS.md`, A-039).

The harness runs on Linux only, so this module is collected everywhere and runs
on Linux. The declared clock input is the wall clock: the baseline check and its
controls pass only inside the committed evidence window, as the CI step that runs
the same check does.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import rehearse_entrypoint as harness  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="the harness runs on Linux only and refuses elsewhere")

#: The interpreter's own directory also holds the `nornyx` CLI of the installed extra.
BIN = Path(sys.executable).parent
SYSTEM_PATH = "/usr/bin:/bin"
#: The one path a spec may name besides the interpreter's directory and the system ones.
ALLOWED_ABSOLUTE = {str(BIN), "/usr/bin", "/bin"}


def _env(path: str = f"{BIN}:{SYSTEM_PATH}") -> dict:
    """The whole environment a child is given, besides HOME and the temp names."""
    return {"PATH": path, "PYTHONPATH": "{fixture}/src", "PYTHONDONTWRITEBYTECODE": "1"}


def _run(argv: list, env: dict | None = None) -> dict:
    return {"fixture": "fixture", "argv": argv, "env": env or _env(), "timeout_seconds": 300}


def _rehearsal(name: str, argv: list, expect: dict, env: dict | None = None) -> dict:
    return {"schema": harness.REHEARSAL_SPEC, "name": name, "run": _run(argv, env),
            "expect": expect}


# -- the contracts -------------------------------------------------------------

_PREPARE = ["{python}", "scripts/prepare_runtime.py"]
_BASELINE = ["{python}", "scripts/check_pre_approval_baseline.py"]
_DEMO = ["{python}", "-m", "nornyx_forge.cli", "demo", "--offline"]

_PREPARE_EXPECT = {
    "exit": [2],
    "files": {"created": ["fixture/.nornyx/runtime/",
                          "fixture/.nornyx/runtime/preparation-report.json"]},
    "stdout": {"must_match": ["AN_APPROVAL_RECORD_MISSING"]},
}
_BASELINE_EXPECT = {"exit": [0], "stdout": {"must_match": ['"status": "pass"']}}
_DEMO_HOME = [
    "home/.config/", "home/.config/crewai/", "home/.local/", "home/.local/share/",
    "home/.local/share/crewai/", "home/.local/share/crewai/credentials/",
    "home/.local/share/crewai/credentials/secret.key", "home/.local/share/fixture/",
    "home/.local/share/fixture/memory/",
]
_DEMO_EXPECT = {
    "exit": [0],
    # The run's own evidence, and the state CrewAI writes when it is imported:
    # declared, so that any other write fails the run (A-039).
    "files": {"created": ["fixture/evidence/", "fixture/evidence/runtime/",
                          "fixture/evidence/runtime/events.jsonl",
                          "fixture/evidence/runtime/events.jsonl.highwater",
                          "fixture/evidence/runtime/report.json", *_DEMO_HOME]},
    "stdout": {
        "must_match": ['"observed_execution_backend": "sequential"',
                       '"framework": "CrewAI Flow-compatible sequential execution"',
                       '"schema": "nornyx.forge.demo_evidence_report.v1"',
                       '"status": "fallback"', "RUNTIME_LOCK_MISSING"],
        "must_not_match": ['"observed_execution_backend": "crewai_flow"', "CrewAI Flow kickoff"],
    },
}

#: name -> (argv, expectation)
REHEARSALS = {
    "prepare-runtime": (_PREPARE, _PREPARE_EXPECT),
    "pre-approval-baseline": (_BASELINE, _BASELINE_EXPECT),
    "demo-offline": (_DEMO, _DEMO_EXPECT),
}

#: Files a guard specimen needs in the fixture: spec name -> path -> (text, mode).
EXTRA: dict = {}

SPECS: dict = {}


def _register_rehearsal(name: str, argv: list, expect: dict) -> None:
    SPECS[name] = lambda: _rehearsal(name, argv, expect)


for _name, (_argv, _expect) in REHEARSALS.items():
    _register_rehearsal(_name, _argv, _expect)


# -- the guards ----------------------------------------------------------------

_FAR = ["--as-of", "2100-01-01T00:00:00Z"]
_SILENT_CRASH = f"{{fixture}}/specimen-bin:{SYSTEM_PATH}"
_SUBJECT_BASELINE = "scripts/check_pre_approval_baseline.py"
_SUBJECT_PREPARATION = "src/nornyx_forge/runtime_preparation.py"
EXTRA["guard-unexplained-failure"] = {"specimen-bin/nornyx": ("#!/bin/sh\nexit 1\n", 0o755)}


def _guard_spec(name: str, subject: str, find: str, replace: str, run: dict, refused: dict,
           bypassed: dict, control: dict, expect: dict) -> dict:
    digest = hashlib.sha256((ROOT / subject).read_bytes()).hexdigest()
    return {"schema": harness.GUARD_SPEC, "name": name, "run": run,
            "subject": {"path": subject, "sha256": digest},
            "neutralize": {"find": find, "replace": replace}, "refused": refused,
            "bypassed": bypassed, "control": {"run": control, "expect": expect}}


SPECS["guard-accepted-set-filter"] = lambda: _guard_spec(
    "guard-accepted-set-filter", _SUBJECT_BASELINE,
    "        not in EXPECTED_PRE_APPROVAL_DIAGNOSTICS\n    ]",
    "        not in EXPECTED_PRE_APPROVAL_DIAGNOSTICS\n        and False\n    ]",
    _run([*_BASELINE, *_FAR]),
    {"exit": [2], "stdout": {"must_match": ['"status": "fail"',
                                            '"code": "AN_AUTHORIZATION_EXPIRED"']}},
    {"exit": [0], "stdout": {"must_match": ['"status": "pass"',
                                            '"evaluated_at": "2100-01-01T00:00:00Z"']}},
    _run(_BASELINE), _BASELINE_EXPECT)
SPECS["guard-unexplained-failure"] = lambda: _guard_spec(
    "guard-unexplained-failure", _SUBJECT_BASELINE,
    "    if completed.returncode != 0 and not explained:\n", "    if False:\n",
    _run(_BASELINE, _env(_SILENT_CRASH)),
    {"exit": [2], "stdout": {"must_match": ['"status": "fail"', '"unexplained_failure"']}},
    {"exit": [0], "stdout": {"must_match": ['"status": "pass"']}},
    _run(_BASELINE), _BASELINE_EXPECT)
SPECS["guard-absent-cli"] = lambda: _guard_spec(
    "guard-absent-cli", _SUBJECT_PREPARATION, "    if not executable:\n", "    if False:\n",
    _run(_PREPARE, _env(SYSTEM_PATH)),
    {"exit": [2], "stdout": {"must_match": ["nornyx CLI not installed"]}},
    {"exit": [1], "files": {"created": ["fixture/.nornyx/runtime/"]},
     "stderr": {"must_match": ["TypeError"]}},
    _run(_PREPARE), _PREPARE_EXPECT)


# -- the fixture ---------------------------------------------------------------


def _write_case(case: Path, spec: dict) -> Path:
    """`case/fixture` (this working tree's tracked files, plus the spec's extras)
    and `case/spec.json`; the work root is the caller's."""
    listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], check=True,
                            capture_output=True).stdout.decode("utf-8")
    for name in filter(None, listed.split("\0")):
        assert not (ROOT / name).is_symlink(), f"a tracked link would be followed: {name}"
        (case / "fixture" / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, case / "fixture" / name)
    for name, (text, mode) in EXTRA.get(spec["name"], {}).items():
        target = case / "fixture" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        target.chmod(mode)
    path = case / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8", newline="\n")
    return path


def _measure(tmp_path: Path, name: str) -> dict:
    case = tmp_path.resolve() / "case"
    case.mkdir()
    spec = SPECS[name]()
    (tmp_path / "work").mkdir()
    path = _write_case(case, spec)
    check = harness.rehearse if spec["schema"] == harness.REHEARSAL_SPEC else harness.check_guard
    return check(path, tmp_path.resolve() / "work")


def _matches(tmp_path: Path, name: str) -> dict:
    record = _measure(tmp_path, name)
    assert record["verdict"] == "MATCH", json.dumps(record, indent=2, sort_keys=True)
    return record


def _every_case_reports_fallback(record: dict) -> None:
    """The demo prints one object per case, each with its own `nornyx_evidence`. A literal
    pattern is satisfied by one occurrence, so the claim 'fallback on every case' is read
    from the JSON the run printed: both cases, and each of them."""
    result = json.loads(record["observation"]["streams"]["stdout"]["text"])
    cases = {key: value for key, value in result.items()
             if isinstance(value, dict) and "nornyx_evidence" in value}
    assert sorted(cases) == ["high_risk", "low_risk"], sorted(cases)
    for key, case in cases.items():
        evidence = case["nornyx_evidence"]
        assert evidence.get("status") == "fallback", (key, evidence)
        assert "RUNTIME_LOCK_MISSING" in str(evidence.get("load_error")), (key, evidence)


# -- the tests -----------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(REHEARSALS))
def test_a_real_entrypoint_matches_its_contract(name, tmp_path):
    """Each entrypoint, unmodified, reaches its declared exit, file changes and output."""
    record = _matches(tmp_path, name)
    if name == "demo-offline":
        _every_case_reports_fallback(record)


@pytest.mark.parametrize("name", ["guard-accepted-set-filter", "guard-unexplained-failure",
                                  "guard-absent-cli"])
def test_a_guard_is_shown_load_bearing(name, tmp_path):
    """The run refuses on the trigger, with the guard alone neutralized the refusal is gone
    and the run reaches the declared point, and the run without the trigger is quiet."""
    record = _measure(tmp_path, name)
    assert record["verdict"] == "LIVE", json.dumps(record, indent=2, sort_keys=True)


#: Where a token of a spec string ends: whitespace, a quote or backtick (code and quoted
#: arguments), `:` (the entries of a PATH-like list), `=` (`--opt=/path`, `NAME=/path`), `,`
#: and `;` (lists and statements), `|` and `&` (shell), and brackets and angle brackets (calls,
#: lists, redirects). Every other character can belong to a path (`%`, `+`, `@`, `~`, `-`, `.`,
#: `_`, `{`, `}`, `\`), so it stays in the token and makes a longer path than an allowed one.
_DELIMITER = re.compile(r"""[\s'"`:=,;|&()\[\]<>]""")
_ENV_NAMES = {"PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE"}


def _strings(value):
    """Every string of a spec, its keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _absolute_tokens(text: str) -> list:
    """The tokens of `text` that start with `/`, each read in full up to the next delimiter.
    `{fixture}/src` starts with a placeholder and `scripts/x.py` with a name: not absolute."""
    return [token for token in _DELIMITER.split(text) if token.startswith("/")]


def _spec_problems(spec: dict) -> list:
    problems = []
    runs = [spec["run"], *([spec["control"]["run"]] if "control" in spec else [])]
    for run in runs:
        if run.get("inherit_env"):
            problems.append(f"inherit_env is not empty: {run['inherit_env']}")
        if set(run.get("env", {})) != _ENV_NAMES:
            problems.append(f"env names are {sorted(run.get('env', {}))}")
    for text in _strings(spec):
        problems += [f"{token!r} in {text[:60]!r}" for token in _absolute_tokens(text)
                     if token not in ALLOWED_ABSOLUTE]
    return problems


def test_no_spec_names_an_absolute_path_of_the_host():
    """Every spec is built from nothing: no inherited variable, exactly the three declared
    names, and every absolute path token in every string of the spec (an argument, a value,
    a pattern), read whole, is exactly the interpreter's directory, `/usr/bin` or `/bin`:
    a longer path, or one with other characters, fails, even when an allowed path is its prefix."""
    assert SPECS
    for name in SPECS:
        assert not _spec_problems(SPECS[name]()), (name, _spec_problems(SPECS[name]()))
    # the scan does see the allowed paths, so it is not vacuous
    seen = {token for name in SPECS for text in _strings(SPECS[name]())
            for token in _absolute_tokens(text)}
    assert seen == ALLOWED_ABSOLUTE, sorted(seen)
