"""Real entrypoints are rehearsed, and guards are shown load-bearing.

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
  The decoding specs below add exactly the three names of one locale, pinned.
- DECODING, on a checkout with its history (the section of this module that holds
  the codec of the evidence tool's git calls, A-036): `scripts/refresh_governance_evidence.py
  --verify` is rehearsed in a full clone of this repository's HEAD, under a work root
  whose path holds U+00E9, in the C locale with UTF-8 mode and locale coercion off, and
  again in the environment with no locale named (UTF-8), and each run matches one
  contract: exit 0, `integrity_state` intact, no traceback, and the one write git itself
  makes, a refresh of the clone's index (declared). Taking back the codec's error
  handler makes that rehearsal fail; taking the whole codec back, as text mode reads it,
  ends in a traceback, which the revert controls of tests/test_subprocess_decoding.py
  hold and this module does not. The codec is also shown load-bearing with the guard-liveness
  check, for the refusal it makes reachable: a governed tree with no repository of its
  own, enclosed by a foreign one, at that path and in that locale, is refused by name;
  with the codec's error handler taken back (one snippet, in the copy) the refusal is
  replaced by the tool's own "cannot be decoded" refusal; and the same locale and path in
  a clone that is its own repository is quiet. The trigger is held not to be vacuous: the
  child's codecs are not UTF-8 in the locale environment and are UTF-8 without it.
  The working trees of the fixtures are the tracked files only, held by a test with a
  control. The clone's `.git` is more than HEAD: it carries the source's tags with their
  objects and a reflog line naming the source path, which the tool's git calls here
  (`rev-parse`, `diff`, `ls-files`) do not consult.

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

import codecs
import hashlib
import json
import os
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
E_ACUTE = chr(0xE9)
#: A locale whose codecs are not UTF-8, by environment: the C locale with UTF-8 mode and
#: locale coercion off. `LC_ALL=C` alone turns UTF-8 mode ON (PEP 540), and then every
#: codec in the child is UTF-8. The three names and their values are pinned by the shape test.
LOCALE_ENV = {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
LOCALE_NAMES = set(LOCALE_ENV)


def _env(path: str = f"{BIN}:{SYSTEM_PATH}", locale: bool = False, tree: str = "") -> dict:
    """The whole environment a child is given, besides HOME and the temp names. `locale`
    adds the pinned locale; `tree` names the directory of the fixture whose `src` is imported."""
    source = "{fixture}/" + (tree + "/" if tree else "") + "src"
    env = {"PATH": path, "PYTHONPATH": source, "PYTHONDONTWRITEBYTECODE": "1"}
    return {**env, **LOCALE_ENV} if locale else env


def _run(argv: list, env: dict | None = None, cwd: str | None = None) -> dict:
    run = {"fixture": "fixture", "argv": argv, "env": env or _env(), "timeout_seconds": 300}
    return {**run, "cwd": cwd} if cwd else run


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
           bypassed: dict, control: dict, expect: dict, member: str | None = None) -> dict:
    """`subject` is the file of this repository whose bytes are hashed; `member` is the
    name the fixture's listing gives it, where that is not the same name."""
    digest = hashlib.sha256((ROOT / subject).read_bytes()).hexdigest()
    return {"schema": harness.GUARD_SPEC, "name": name, "run": run,
            "subject": {"path": member or subject, "sha256": digest},
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


# -- the decoding of git's answers (A-036) -------------------------------------

_REFRESH = "scripts/refresh_governance_evidence.py"
_VERIFY = ["{python}", _REFRESH, "--verify"]
#: The clone's index is the one write the run makes: git refreshes the cached file data of
#: the index for the copy, whose files are new to it. Nothing else is created, modified or
#: deleted, and no output holds a traceback or the tool's own "cannot be decoded" refusal.
_VERIFY_EXPECT = {
    "exit": [0],
    "files": {"modified": ["fixture/.git/index"]},
    "stdout": {"must_match": ['"integrity_state": "intact"']},
    "stderr": {"must_not_match": ["Traceback", "cannot be decoded"]},
}
_VERIFY_IN_CLONE_EXPECT = {**_VERIFY_EXPECT, "files": {"modified": ["fixture/clone/.git/index"]}}
#: The same code line, and the call as it stands without the error handler: the tool then
#: refuses the bytes of the checkout's own path, in its own words.
_CODEC = "        text = raw.decode(GIT_TEXT_ENCODING, GIT_TEXT_ERRORS)\n"
_CODEC_WITHOUT_HANDLER = "        text = raw.decode(GIT_TEXT_ENCODING)\n"
_ENCLOSED_REFUSAL = "is not the root of the git repository that encloses it"
_UNDECODABLE_REFUSAL = "wrote output that cannot be decoded as"

SPECS["refresh-verify-c-locale"] = lambda: _rehearsal(
    "refresh-verify-c-locale", _VERIFY, _VERIFY_EXPECT, _env(locale=True))
SPECS["refresh-verify-utf8"] = lambda: _rehearsal(
    "refresh-verify-utf8", _VERIFY, _VERIFY_EXPECT)
SPECS["guard-git-codec"] = lambda: _guard_spec(
    "guard-git-codec", _REFRESH, _CODEC, _CODEC_WITHOUT_HANDLER,
    _run(["{python}", _REFRESH, "--verify"], _env(locale=True, tree="enclosed"),
         cwd="enclosed"),
    {"exit": [1], "stderr": {"must_match": [_ENCLOSED_REFUSAL]}},
    {"exit": [1], "stderr": {"must_match": [_UNDECODABLE_REFUSAL]}},
    _run(["{python}", _REFRESH, "--verify"], _env(locale=True, tree="clone"), cwd="clone"),
    _VERIFY_IN_CLONE_EXPECT, member="enclosed/" + _REFRESH)

#: The specs that carry the locale, and the fixture each is built on (the others are the
#: tracked files alone): a clone of HEAD with its history; and a foreign repository holding a
#: clone of HEAD, which is its own repository, and a copy of the tracked files, which is not.
LOCALE_SPECS = {"refresh-verify-c-locale", "guard-git-codec"}
CLONE_SPECS = {"refresh-verify-c-locale", "refresh-verify-utf8"}
FOREIGN_SPECS = {"guard-git-codec"}
#: These run at a work root whose path holds U+00E9.
NON_ASCII_SPECS = CLONE_SPECS | FOREIGN_SPECS


# -- the fixture ---------------------------------------------------------------


def _copy_tracked(destination: Path) -> None:
    """This working tree's tracked files, and nothing else, at `destination`."""
    listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], check=True,
                            capture_output=True).stdout.decode("utf-8")
    for name in filter(None, listed.split("\0")):
        assert not (ROOT / name).is_symlink(), f"a tracked link would be followed: {name}"
        (destination / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination / name)


def _git_env(home: Path) -> dict:
    """What the fixture builders' own git calls see: no global or system configuration."""
    return {"PATH": os.environ.get("PATH", SYSTEM_PATH), "HOME": str(home),
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"}


def _git(env: dict, *args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True,
                          timeout=600).stdout.decode("utf-8")


def _clone_head(destination: Path, home: Path) -> None:
    """A full clone of this repository's HEAD at `destination`: its own repository, with
    no remote, no template and no link (its `.git` still carries the source's tags and their
    objects, and a reflog line naming the source). It is the committed tree that is rehearsed, so a
    working tree that differs from HEAD in a tracked file fails here, rather than being
    measured as something it is not."""
    env = _git_env(home)
    changed = _git(env, "-C", str(ROOT), "--no-optional-locks", "status", "--porcelain",
                   "--untracked-files=no")
    assert not changed, ("the clone is of HEAD, and this working tree differs from it: commit "
                         f"or stash first\n{changed}")
    _git(env, "clone", "--quiet", "--no-local", "--template=", "--", str(ROOT), str(destination))
    _git(env, "remote", "remove", "origin", cwd=destination)
    assert not (destination / ".git" / "shallow").exists(), "the clone needs full history"
    assert _git(env, "rev-parse", "HEAD", cwd=destination) == _git(env, "-C", str(ROOT),
                                                                   "rev-parse", "HEAD")


def _foreign_fixture(fixture: Path, home: Path) -> None:
    """`fixture` is a repository of its own that holds nothing else it tracks (a foreign
    one); `clone` in it is a clone of HEAD (a repository of its own), and `enclosed` a copy
    of the tracked files with no repository, which the foreign one then encloses."""
    fixture.mkdir()
    _git(_git_env(home), "init", "--quiet", "--template=", cwd=fixture)
    _clone_head(fixture / "clone", home)
    _copy_tracked(fixture / "enclosed")


def _write_case(case: Path, spec: dict) -> Path:
    """`case/fixture` (this working tree's tracked files, or a clone of HEAD, or a foreign
    repository holding one, as the spec needs, plus the spec's extras) and `case/spec.json`;
    the work root is the caller's."""
    if spec["name"] in CLONE_SPECS:
        _clone_head(case / "fixture", case)
    elif spec["name"] in FOREIGN_SPECS:
        _foreign_fixture(case / "fixture", case)
    else:
        _copy_tracked(case / "fixture")
    for name, (text, mode) in EXTRA.get(spec["name"], {}).items():
        target = case / "fixture" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        target.chmod(mode)
    path = case / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8", newline="\n")
    return path


def _work_root(tmp_path: Path, name: str) -> Path:
    """Where the harness makes its run directory: under a name that holds U+00E9 for the
    decoding specs, since the child's own path then holds it."""
    return tmp_path.resolve() / ("caf" + E_ACUTE if name in NON_ASCII_SPECS else "") / "work"


def _measure(tmp_path: Path, name: str) -> dict:
    case = tmp_path.resolve() / "case"
    case.mkdir()
    spec = SPECS[name]()
    work = _work_root(tmp_path, name)
    work.mkdir(parents=True)
    path = _write_case(case, spec)
    check = harness.rehearse if spec["schema"] == harness.REHEARSAL_SPEC else harness.check_guard
    return check(path, work)


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
                                  "guard-absent-cli", "guard-git-codec"])
def test_a_guard_is_shown_load_bearing(name, tmp_path):
    """The run refuses on the trigger, with the guard alone neutralized the refusal is gone
    and the run reaches the declared point, and the run without the trigger is quiet."""
    record = _measure(tmp_path, name)
    assert record["verdict"] == "LIVE", json.dumps(record, indent=2, sort_keys=True)


def _codecs_of(env: dict) -> set:
    """The locale codec and the filesystem codec a child with `env` gets."""
    probe = subprocess.run(
        [sys.executable, "-c",
         "import locale, sys; print(locale.getpreferredencoding(False)); "
         "print(sys.getfilesystemencoding())"],
        env=env, capture_output=True, timeout=120, check=True)
    return {codecs.lookup(name).name for name in probe.stdout.decode("ascii").split()}


def _env_of_run(spec: dict) -> dict:
    """The declared environment of a spec's run that a probe can use: its names and values,
    with the one placeholder (`PYTHONPATH`) left out, and this interpreter's own `PATH`."""
    declared = {name: value for name, value in spec["run"]["env"].items()
                if name != "PYTHONPATH"}
    return {**declared, "PATH": os.environ.get("PATH", SYSTEM_PATH)}


@pytest.mark.parametrize("name", ["refresh-verify-c-locale", "refresh-verify-utf8"])
def test_the_evidence_tool_verifies_a_non_ascii_checkout_in_both_locales(name, tmp_path):
    """`--verify` in a full clone of HEAD, at a work root whose path holds U+00E9, reaches
    the same declared contract in the C locale with UTF-8 mode off and in UTF-8, from an
    environment built from nothing. The trigger is not vacuous: the child's codecs are not
    UTF-8 in the first and are UTF-8 in the second, so the first could not pass by
    measuring nothing and the second is the control."""
    assert any(ord(character) > 0x7F for character in str(_work_root(tmp_path, name))), (
        "the work root's path must hold a non-ASCII character, or this measures nothing")
    locale_codecs = _codecs_of(_env_of_run(SPECS[name]()))
    assert ("utf-8" not in locale_codecs) == (name in LOCALE_SPECS), (name, locale_codecs)
    record = _matches(tmp_path, name)
    observed = record["observation"]["environment"]
    declared = set(SPECS[name]()["run"]["env"])
    assert set(observed) == {"HOME", "TMPDIR", "TMP", "TEMP"} | declared, sorted(observed)
    assert observed["HOME"] == "{home}" and observed["TMPDIR"] == "{tmp}", observed


def test_the_verify_rehearsal_fails_when_the_codec_is_taken_back(tmp_path):
    """The red control of the rehearsal above: with the codec's error handler taken back in
    the clone (one snippet, exactly once) the same run, at the same path and in the same
    locale, no longer reaches its contract. It fails for the right reason: the tool
    refuses the bytes of its own checkout path, in its own words, and does not reach
    a verdict."""
    case = tmp_path.resolve() / "case"
    case.mkdir()
    spec = SPECS["refresh-verify-c-locale"]()
    path = _write_case(case, spec)
    subject = case / "fixture" / _REFRESH
    text = subject.read_text(encoding="utf-8")
    assert text.count(_CODEC) == 1
    subject.write_text(text.replace(_CODEC, _CODEC_WITHOUT_HANDLER), encoding="utf-8",
                       newline="\n")
    work = _work_root(tmp_path, "refresh-verify-c-locale")
    work.mkdir(parents=True)
    record = harness.rehearse(path, work)
    assert record["verdict"] == "MISMATCH", json.dumps(record, indent=2, sort_keys=True)
    failed = {check["check"] for check in record["checks"] if not check["passed"]}
    assert failed == {"exit", "files", "patterns"}, record["checks"]
    observation = record["observation"]
    assert observation["exit_code"] == 1
    assert _UNDECODABLE_REFUSAL in observation["streams"]["stderr"]["text"]
    assert "integrity_state" not in observation["streams"]["stdout"]["text"]


def _strays(tree: Path, tracked: set) -> list:
    """What is not the tracked tree in `tree` (`.git` apart): a file that is not tracked, a
    tracked file that is missing, any link, and any remote or host path in the repository's
    own configuration."""
    found, problems = set(), []
    for path in sorted(tree.rglob("*")):
        relative = path.relative_to(tree).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            problems.append(f"a link: {relative}")
        elif path.is_file():
            found.add(relative)
    problems += [f"not tracked: {name}" for name in sorted(found - tracked)]
    problems += [f"tracked and missing: {name}" for name in sorted(tracked - found)]
    config = tree / ".git" / "config"
    if config.exists() and "url =" in config.read_text(encoding="utf-8"):
        problems.append("the repository's configuration names a remote")
    return problems


def _tracked_names() -> set:
    listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], check=True,
                            capture_output=True).stdout.decode("utf-8")
    return set(filter(None, listed.split("\0")))


@pytest.mark.parametrize("name", ["refresh-verify-utf8", "guard-git-codec"])
def test_the_working_trees_of_the_decoding_fixtures_are_the_tracked_files_only(name, tmp_path):
    """Built from nothing, in the files too: each working tree of the fixture holds exactly
    this repository's tracked files, so no untracked file of the checkout (a review record,
    a runtime lock, a secret) can be a hidden input, and the clone is of HEAD with its
    history, its own repository and no remote. Its `.git` is not held to HEAD: it also
    carries the source's tags and their objects and a reflog naming the source path."""
    case = tmp_path.resolve() / "case"
    case.mkdir()
    _write_case(case, SPECS[name]())
    trees = [case / "fixture"] if name in CLONE_SPECS else [
        case / "fixture" / "clone", case / "fixture" / "enclosed"]
    tracked = _tracked_names()
    assert len(tracked) > 100
    for tree in trees:
        assert _strays(tree, tracked) == [], (tree.name, _strays(tree, tracked))
    if name in FOREIGN_SPECS:
        assert (case / "fixture" / ".git").is_dir()
        assert not (case / "fixture" / "enclosed" / ".git").exists()
        assert (case / "fixture" / "clone" / ".git").is_dir()


def test_a_stray_file_a_link_or_a_remote_in_a_fixture_is_seen(tmp_path):
    """The control of the test above: a fixture with an untracked review record, a missing
    tracked file, a link and a remote is reported, each in its own words; one without them
    is not."""
    (tmp_path / ".nornyx" / "in-session").mkdir(parents=True)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    assert _strays(tmp_path, {"a.py"}) == []
    (tmp_path / ".nornyx" / "in-session" / "reviews.json").write_text("{}", encoding="utf-8")
    (tmp_path / "link").symlink_to("a.py")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[remote]\n\turl = /somewhere\n", encoding="utf-8")
    assert _strays(tmp_path, {"a.py", "b.py"}) == [
        "a link: link", "not tracked: .nornyx/in-session/reviews.json",
        "tracked and missing: b.py", "the repository's configuration names a remote"]


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


def _env_problems(name: str, run: dict) -> list:
    """The environment of one run: exactly the three names, or those and exactly the three
    names of the pinned locale with their pinned values, and the second only in a spec named
    in `LOCALE_SPECS`."""
    env = run.get("env", {})
    names = set(env)
    if not names & LOCALE_NAMES:
        return [] if names == _ENV_NAMES else [f"env names are {sorted(names)}"]
    problems = []
    if names != _ENV_NAMES | LOCALE_NAMES:
        problems.append(f"env names are {sorted(names)}")
    elif {key: env[key] for key in LOCALE_NAMES} != LOCALE_ENV:
        problems.append(f"the locale is not the pinned one: {sorted(env.items())}")
    if name not in LOCALE_SPECS:
        problems.append(f"{name} may not carry a locale")
    return problems


def _spec_problems(spec: dict) -> list:
    problems = []
    runs = [spec["run"], *([spec["control"]["run"]] if "control" in spec else [])]
    for run in runs:
        if run.get("inherit_env"):
            problems.append(f"inherit_env is not empty: {run['inherit_env']}")
        problems += _env_problems(spec["name"], run)
    for text in _strings(spec):
        problems += [f"{token!r} in {text[:60]!r}" for token in _absolute_tokens(text)
                     if token not in ALLOWED_ABSOLUTE]
    return problems


def test_no_spec_names_an_absolute_path_of_the_host():
    """Every spec is built from nothing: no inherited variable, exactly the three declared
    names (or those and the three of the pinned locale, in a spec named for it), and every
    absolute path token in every string of the spec (an argument, a value, a pattern), read
    whole, is exactly the interpreter's directory, `/usr/bin` or `/bin`: a longer path, or
    one with other characters, fails, even when an allowed path is its prefix."""
    assert SPECS
    for name in SPECS:
        assert not _spec_problems(SPECS[name]()), (name, _spec_problems(SPECS[name]()))
    # the scan does see the allowed paths, so it is not vacuous
    seen = {token for name in SPECS for text in _strings(SPECS[name]())
            for token in _absolute_tokens(text)}
    assert seen == ALLOWED_ABSOLUTE, sorted(seen)


def test_the_locale_is_carried_by_the_decoding_specs_and_only_by_them():
    """The other direction of the rule: a spec named for the locale carries it in the run
    that triggers (so the name cannot be a stale allowance), and no other spec carries any
    name of it."""
    carried = {name for name, build in SPECS.items() if LOCALE_NAMES & set(build()["run"]["env"])}
    assert carried == LOCALE_SPECS, sorted(carried)
    assert LOCALE_SPECS <= set(SPECS) and NON_ASCII_SPECS <= set(SPECS)
    assert LOCALE_ENV == {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}


def test_the_shape_rule_refuses_every_environment_it_does_not_allow():
    """The rule is tested, not only applied: an extra name, a locale that is not the pinned
    one (a missing name, a changed value), the locale in a spec not named for it, and an
    inherited variable are each reported; the allowed forms are not."""
    locale_spec = "refresh-verify-c-locale"
    plain = SPECS["prepare-runtime"]()
    with_locale = SPECS[locale_spec]()
    assert _spec_problems(plain) == [] and _spec_problems(with_locale) == []

    def env_of(spec, **changes):
        mutated = json.loads(json.dumps(spec))
        mutated["run"]["env"].update(changes)
        return mutated

    assert _spec_problems(env_of(plain, LANG="C"))
    assert _spec_problems(env_of(plain, LC_ALL="C"))
    assert _spec_problems(env_of(plain, **LOCALE_ENV)), "a spec not named for the locale"
    assert _spec_problems(env_of(with_locale, LANG="C"))
    assert _spec_problems(env_of(with_locale, PYTHONUTF8="1"))
    assert _spec_problems(env_of(with_locale, LC_ALL="C.UTF-8"))
    partial = json.loads(json.dumps(with_locale))
    del partial["run"]["env"]["PYTHONCOERCECLOCALE"]
    assert _spec_problems(partial)
    inherited = json.loads(json.dumps(with_locale))
    inherited["run"]["inherit_env"] = ["LANG"]
    assert _spec_problems(inherited)
    renamed = json.loads(json.dumps(with_locale))
    renamed["name"] = "prepare-runtime"
    assert _spec_problems(renamed)
    # the control's run is held to the same rule as the run
    guard = SPECS["guard-git-codec"]()
    assert _spec_problems(guard) == []
    for changes in ({"LANG": "C"}, {"PYTHONUTF8": "1"}, {"LC_ALL": "C.UTF-8"}):
        mutated = json.loads(json.dumps(guard))
        mutated["control"]["run"]["env"].update(changes)
        assert _spec_problems(mutated), changes
    lacking = json.loads(json.dumps(guard))
    del lacking["control"]["run"]["env"]["PYTHONCOERCECLOCALE"]
    assert _spec_problems(lacking)
    inherited_control = json.loads(json.dumps(guard))
    inherited_control["control"]["run"]["inherit_env"] = ["LANG"]
    assert _spec_problems(inherited_control)
