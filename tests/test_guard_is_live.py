"""A guard is shown live only when it refuses on its trigger and the refusal goes with it.

What is held here, in words:

- LIVE needs all of: the triggered run refuses; with the guard alone
  neutralized (one exact, hash-bound snippet replaced, in the copy) the refusal
  is gone and the run reaches the declared point past the guard; and, when
  declared, the untriggered run does not refuse.
- A guard that never fires, a guard masked by a second guard, and a guard that
  fires without its trigger are DEAD. A neutralization that breaks the subject
  is INCONCLUSIVE, never LIVE or DEAD.
- Spec and subject errors refuse: weak or vacuous signatures, fields the check
  no longer has, a control run on another fixture, a drifted subject, a snippet
  that is absent or repeated (overlapping occurrences count as a repeat), an
  oversized subject, and a subject that is not a regular file of the fixture
  template spelled exactly as its listing spells it.
- Each run's copy takes its entries, kinds and modes from the listing, every file
  but the subject is read again against its listed digest, and the subject is
  the bytes read: a changed subject or entry mode cannot reach a later run's
  copy, and a changed file's content refuses. Only the listed entries of each
  copy are compared; nothing else is (the harness's LIMITS name it).
- The harness never modifies the real subject or fixture, in content or mode,
  prints its record on stdout and writes nothing but its run directory.
- Each decision check is load-bearing: removed, its specimen gets the wrong verdict.

The subjects are a few lines of Python with an environment-variable guard, or a
policy line in a data file, written by each test into the fixture template. The
harness runs on Linux only, so this module runs on Linux.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rehearse_entrypoint.py"
sys.path.insert(0, str(ROOT / "scripts"))

import rehearse_entrypoint as harness  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="the harness runs on Linux only and refuses elsewhere")

_TRIGGER = 'if os.environ.get("SAMPLE_MODE") == "unsafe":'
_GUARD = _TRIGGER + '\n    print("REFUSE: unsafe mode is not allowed")\n    sys.exit(3)\n'
_ENTRY = ("import os\nimport sys\nfrom pathlib import Path\n\n{guard}"
          'Path("result.txt").write_text("done")\nprint("OK: reached the work")\n')


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _tree(top: Path) -> dict:
    """Every entry under `top`: its bytes (None for a directory) and its mode."""
    return {p.relative_to(top).as_posix(): (p.read_bytes() if p.is_file() else None,
                                            stat.S_IMODE(p.lstat().st_mode))
            for p in sorted(top.rglob("*"))}


def _run(mode: str) -> dict:
    return {"fixture": "fixture", "argv": ["{python}", "entry.py"], "timeout_seconds": 60,
            "env": {"SAMPLE_MODE": mode}}


_REACHED = {"exit": [0], "stdout": {"must_match": ["OK: reached"]},
            "files": {"created": ["fixture/result.txt"]}}


def _case(tmp_path: Path, guard: str = _GUARD, *, find: str = _TRIGGER,
          replace: str = "if False:", control: bool = True, subject: str = "entry.py",
          declared_sha: str = "", files=None, edit=None) -> Path:
    """A fixture template holding `entry.py` (and `files`), and a guard-liveness
    spec whose subject is the template's file `subject`."""
    case = tmp_path / "case"
    _write(case / "fixture" / "entry.py", _ENTRY.format(guard=guard))
    for name, content in (files or {}).items():
        _write(case / "fixture" / name, content)
    target = case / "fixture" / subject
    actual = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else "0" * 64
    spec = {"schema": harness.GUARD_SPEC, "name": "sample guard", "run": _run("unsafe"),
            "subject": {"path": subject, "sha256": declared_sha or actual},
            "neutralize": {"find": find, "replace": replace},
            "refused": {"exit": [3], "stdout": {"must_match": ["REFUSE: "]}},
            "bypassed": _REACHED}
    if control:
        spec["control"] = {"run": _run("safe"), "expect": _REACHED}
    if edit is not None:
        edit(spec)
    return _write(case / "spec.json", json.dumps(spec))


def _check(spec: Path) -> dict:
    work = spec.parent.parent / "work"
    work.mkdir(exist_ok=True)
    return harness.check_guard(spec, work)


def _cli(spec: Path, tmp_path: Path):
    (tmp_path / "work").mkdir(exist_ok=True)
    return subprocess.run([sys.executable, str(SCRIPT), "guard-live", str(spec), "--work-root",
                           str(tmp_path / "work")], capture_output=True, timeout=300)


_MASKED = _GUARD + 'if os.environ.get("SAMPLE_MODE", "").startswith("unsafe"):\n' \
    '    print("REFUSE: still unsafe")\n    sys.exit(3)\n'
_ALWAYS_ON = _GUARD.replace('== "unsafe"', '!= "never"')
_DEAD = _GUARD.replace('== "unsafe"', '== "forbidden"')
_REPEATED = _GUARD + _GUARD
_MARKING = _ALWAYS_ON.replace('    print("REFUSE', '    if os.environ["SAMPLE_MODE"] != "unsafe":\n'
                              '        Path("marker.txt").write_text("x")\n    print("REFUSE')


def test_a_live_guard_is_reported_live(tmp_path):
    """Refuses on its trigger, gets past it once neutralized, and is quiet
    without the trigger: LIVE, with all three runs in the record."""
    record = _check(_case(tmp_path))
    assert record["verdict"] == "LIVE", record
    runs = record["runs"]
    assert (runs["triggered"]["exit_code"], runs["neutralized"]["exit_code"],
            runs["control"]["exit_code"]) == (3, 0, 0)
    assert [(c["check"], c["passed"]) for c in record["checks"]] == [
        ("fires on its trigger", True), ("its refusal is gone once it is neutralized", True),
        ("the neutralized run reaches the bypass point", True),
        ("it is quiet without its trigger", True)]
    assert [sum(s in x for x in record["limits"]) for s in ("{spec_dir}", "ext4")] == [1, 1]


def test_a_guard_that_never_fires_is_dead(tmp_path):
    """A guard its trigger does not trip is DEAD: it did not fire."""
    record = _check(_case(tmp_path, _DEAD, find=_TRIGGER.replace("unsafe", "forbidden")))
    assert (record["verdict"], record["reason"]) == ("DEAD", "the guard did not fire on its trigger")


def test_a_masked_guard_is_dead(tmp_path):
    """With a second guard refusing on the same trigger, neutralizing the first
    leaves the refusal in place: DEAD, because this guard is not what decides."""
    record = _check(_case(tmp_path, _MASKED))
    assert (record["verdict"], record["reason"]) == (
        "DEAD", "the refusal persists without this guard")
    assert [c["passed"] for c in record["checks"]] == [True, False, False, True]


def test_a_masked_guard_that_leaves_the_bypass_marker_is_dead(tmp_path):
    """The second guard writes the file the bypass expectation waits for, then refuses:
    the neutralized run still shows the refusal's exit and output, so DEAD, not LIVE."""
    masked = _MASKED.replace('    print("REFUSE: still', '    Path("bypass.txt").write_text("x")\n'
                             '    print("REFUSE: still')
    files = {"exit": [0, 3], "files": {"created": ["fixture/bypass.txt"]}}
    record = _check(_case(tmp_path, masked, edit=lambda s: s.update(bypassed=files)))
    assert (record["verdict"], record["reason"]) == (
        "DEAD", "the refusal persists without this guard")


_SECOND = ('if os.environ.get("SAMPLE_MODE", "").startswith("unsafe"):\n'
           '    Path("bypass.txt").write_text("x")\n')
_BOTH = {"exit": [0], "files": {"created": ["fixture/bypass.txt", "fixture/result.txt"]}}
_STRAY = _GUARD.replace("    sys.exit(3)", '    Path("stray.txt").write_text("x")\n    sys.exit(3)')


@pytest.mark.parametrize("guard, bypassed, verdict", [
    (_GUARD + _SECOND + '    print("REFUSE: still")\n', _BOTH, "LIVE"),
    (_GUARD + _SECOND + '    print("crashed")\n    sys.exit(3)\n',
     {"exit": [3], "files": {"created": ["fixture/bypass.txt"]}}, "LIVE"),
    (_STRAY, None, "DEAD")])
def test_a_refusal_is_its_exit_code_and_its_output_and_firing_needs_the_full_match(
        guard, bypassed, verdict, tmp_path):
    """Refusal text without the refusal's exit code, or its exit code without its text, is
    not the refusal (LIVE); a triggered run that also leaves an undeclared file is not the
    declared refusal (DEAD)."""
    edit = (lambda s: s.update(bypassed=bypassed)) if bypassed else None
    assert _check(_case(tmp_path, guard, edit=edit))["verdict"] == verdict


@pytest.mark.parametrize("expected", ["the-bypass", "a-failure", "a-marker-file"])
def test_a_guard_that_fires_without_its_trigger_is_dead(expected, tmp_path):
    """A guard that also refuses the untriggered run is DEAD, whether the control
    run was expected to reach the bypass point, merely to fail, or to fail and
    leave a marker file: refusing without the trigger is enough."""
    marker = {"files": {"created": ["fixture/marker.txt"]}} if expected == "a-marker-file" else {}
    edit = None if expected == "the-bypass" else lambda s: s["control"].update(
        expect={"exit": "failure", **marker})
    find = _TRIGGER.replace('== "unsafe"', '!= "never"')
    record = _check(_case(tmp_path, _MARKING if marker else _ALWAYS_ON, find=find, edit=edit))
    assert (record["verdict"], record["reason"]) == ("DEAD", "the guard fires without its trigger")


def test_an_executable_subject_keeps_its_listed_mode(tmp_path):
    """A subject the entrypoint runs directly keeps the mode the listing recorded,
    although each run's copy of it is written from the bytes read: it runs, LIVE."""
    source = "#!" + os.path.realpath(sys.executable) + "\n" + _ENTRY.format(guard=_GUARD)

    def direct(spec):
        for part in (spec, spec["control"]):
            part["run"]["argv"] = ["{fixture}/entry.py"]

    spec = _case(tmp_path, files={"entry.py": source}, edit=direct)
    (spec.parent / "fixture" / "entry.py").chmod(0o755)
    assert _check(spec)["verdict"] == "LIVE"


def test_a_neutralization_that_breaks_the_subject_is_inconclusive(tmp_path):
    """A replacement that breaks the subject neither refuses nor reaches the
    bypass point: INCONCLUSIVE, and the entrypoint exits 2."""
    spec = _case(tmp_path, replace="if (:")
    assert _check(spec)["verdict"] == "INCONCLUSIVE"
    assert _cli(spec, tmp_path).returncode == 2


_INVALID = {
    "unknown-field": lambda s: s.update(colour="blue"),
    "missing-neutralize": lambda s: s.pop("neutralize"),
    "find-not-text": lambda s: s["neutralize"].update(find=3),
    "empty-find": lambda s: s["neutralize"].update(find=""),
    "replace-equals-find": lambda s: s["neutralize"].update(replace=_TRIGGER),
    "removed-field-encoding": lambda s: s["neutralize"].update(encoding="utf-8"),
    "removed-field-subject-root": lambda s: s["subject"].update(root="fixture"),
    "control-on-another-fixture": lambda s: s["control"]["run"].update(fixture="other"),
    "vacuous-bypassed": lambda s: s.update(bypassed={"exit": [0]}),
    "weak-refused-class": lambda s: s.update(refused={"exit": "failure"}),
    "weak-refused-zero": lambda s: s.update(refused={"exit": [0, 3]}),
    "empty-refused-pattern": lambda s: s.update(refused={"exit": "failure", "stdout": {
        "must_match": [""]}}),
    "empty-bypassed-pattern": lambda s: s.update(bypassed={"exit": [0], "stdout": {
        "must_match": [""]}}),
    "empty-control-pattern": lambda s: s["control"].update(
        expect={**_REACHED, "stdout": {"must_not_match": [""]}}),
    "unknown-placeholder": lambda s: s["run"].update(argv=["{python}", "{nowhere}/entry.py"]),
    "wrong-schema": lambda s: s.update(schema=harness.REHEARSAL_SPEC),
}
_INVALID_REASONS = {"empty-refused-pattern": "an empty pattern",
                    "empty-bypassed-pattern": "an empty pattern",
                    "empty-control-pattern": "an empty pattern",
                    "removed-field-encoding": "['encoding']",
                    "removed-field-subject-root": "['root']",
                    "control-on-another-fixture": "one fixture"}


@pytest.mark.parametrize("case", sorted(_INVALID))
def test_invalid_guard_specs_refuse(case, tmp_path):
    """A malformed spec, one too weak to decide anything, one carrying a field the
    check no longer has, or one whose control run names another fixture refuses
    before any run."""
    record = _check(_case(tmp_path, edit=_INVALID[case]))
    assert record["verdict"] == "REFUSED" and record["reason"], record
    assert record["runs"] == {"triggered": None, "neutralized": None, "control": None}
    assert _INVALID_REASONS.get(case, "") in record["reason"], record["reason"]


_SUBJECT_ERRORS = {"missing": "listing", "not-a-regular-file": "listing", "a-symlink": "listing",
                   "not-listed-as-declared": "listing", "digest-mismatch": "drifted",
                   "snippet-absent": "exactly once", "snippet-repeated": "exactly once",
                   "snippet-overlapping": "exactly once",
                   "too-large": "larger than", "snippet-not-utf-8": "UTF-8"}


@pytest.mark.parametrize("case", sorted(_SUBJECT_ERRORS))
def test_subject_errors_refuse(case, tmp_path, monkeypatch):
    """A subject that is absent, a directory, a link, or spelled otherwise than the
    template's listing spells it (here './entry.py'); one that drifted from its
    declared digest, is larger than the bound, or does not hold the snippet
    exactly once (two overlapping occurrences are two); and a snippet that is not
    UTF-8 text refuse before any run."""
    options = {"missing": {"subject": "absent.py"}, "not-a-regular-file": {"subject": "folder"},
               "a-symlink": {"subject": "link.py"}, "not-listed-as-declared": {
                   "subject": "./entry.py", "edit": lambda s: s["subject"].update(
                       sha256=hashlib.sha256(_ENTRY.format(guard=_GUARD).encode()).hexdigest())},
               "digest-mismatch": {"declared_sha": "0" * 64},
               "snippet-absent": {"find": "if never_present:"},
               "snippet-repeated": {"guard": _REPEATED}, "too-large": {},
               "snippet-overlapping": {"guard": _GUARD + "# xxx\n", "find": "xx"},
               "snippet-not-utf-8": {"find": "\ud800"}}[case]
    if case == "too-large":
        monkeypatch.setattr(harness, "MAX_SUBJECT_BYTES", 16)
    fixture = tmp_path / "case" / "fixture"
    _write(fixture / "folder" / "keep.txt", "kept")
    fixture.joinpath("link.py").symlink_to("entry.py")
    record = _check(_case(tmp_path, **options))
    assert record["verdict"] == "REFUSED" and record["runs"]["triggered"] is None, record
    assert _SUBJECT_ERRORS[case] in record["reason"], record["reason"]


def test_a_dotdot_subject_path_writes_nothing_outside(tmp_path):
    """A subject path whose '..' names a real file outside the template, with that
    file's own digest, refuses: it is no file the template's listing holds. The
    file is unchanged and the work root is empty."""
    real = _write(tmp_path / "case" / "escaped.txt", _ENTRY.format(guard=_GUARD))
    before = real.read_bytes()
    spec = _case(tmp_path, edit=lambda s: s["subject"].update(
        path="../escaped.txt", sha256=hashlib.sha256(before).hexdigest()))
    record = _check(spec)
    assert record["verdict"] == "REFUSED" and record["runs"]["triggered"] is None, record
    assert real.read_bytes() == before and list((tmp_path / "work").iterdir()) == []


def _masked(effect: str, mask: str, real: str, files: dict) -> dict:
    """A masked guard: the first guard, when it fires, applies `effect` to the real
    template entry REAL (run A's side effect); a second guard refuses the same
    trigger while `mask` holds in the run's copy."""
    guard = (_TRIGGER + "\n    " + effect + '\n    print("REFUSE: unsafe mode is not allowed")\n'
             '    sys.exit(3)\nif os.environ.get("SAMPLE_MODE") == "unsafe" and ' + mask
             + ':\n    print("REFUSE: masked")\n    sys.exit(3)\n')
    return {"guard": guard, "files": files, "edit": lambda s: s["run"]["env"].update(
        REAL="{spec_dir}/fixture/" + real)}


_REWRITE = 'Path(os.environ["REAL"]).write_text("allow")'
_POLICY = '"deny" in Path("policy.txt").read_text()'
_CHANGES = {
    "a-template-file": _masked(_REWRITE, _POLICY, "policy.txt", {"policy.txt": "deny"}),
    "the-real-subject": _masked(_REWRITE, _POLICY, "entry.py", {"policy.txt": "deny"}),
    "a-template-file-mode": _masked('os.chmod(os.environ["REAL"], 0o755)',
                                    'not os.access("policy.sh", os.X_OK)', "policy.sh",
                                    {"policy.sh": ""}),
    # As root, os.access ignores the mode, so this case cannot tell the routes apart.
    "a-template-directory-mode": _masked('os.chmod(os.environ["REAL"], 0o555)',
                                         'os.access("gate", os.W_OK)', "gate",
                                         {"gate/keep.txt": "kept"}),
}


@pytest.mark.parametrize("changed", sorted(_CHANGES))
def test_every_run_copies_the_listed_fixture_but_the_neutralized_file(changed, tmp_path):
    """The guard is masked, so the right verdict is DEAD. Run A changes a real
    entry of the template. When that is the subject, or the mode of a file or a
    directory, no later run's copy sees it: each copy takes its modes from the listing
    and the subject from the bytes read, and the verdict stays DEAD. When it is
    another template file's content (the policy that masks the guard), run B would
    see another fixture than run A did, and the check refuses instead of deciding."""
    record = _check(_case(tmp_path, **_CHANGES[changed]))
    if changed == "a-template-file":
        assert record["verdict"] == "REFUSED", record
        assert "the fixture differed between runs" in record["reason"], record["reason"]
    else:
        assert (record["verdict"], record["reason"]) == (
            "DEAD", "the refusal persists without this guard"), record


def test_a_copy_whose_mode_is_not_the_listed_one_is_not_the_listed_fixture():
    assert not harness._check_same_fixture({"a": ("file", "d", 0o644)}, {"a": ("file", "d", 0o600)})


@pytest.mark.parametrize("scenario", ["live", "inconclusive", "timeout", "refused"])
def test_the_real_subject_is_never_modified(scenario, tmp_path):
    """The real subject and fixture template are byte-identical after every
    verdict path, including INCONCLUSIVE, a timeout and a refusal."""
    slow = 'if os.environ.get("SAMPLE_MODE") == "slow":\n    import time\n    time.sleep(8)\n'
    options = {"live": {}, "inconclusive": {"replace": "if (:"},
               "timeout": {"guard": slow + _GUARD, "edit": lambda s: s["run"].update(
                   timeout_seconds=1, env={"SAMPLE_MODE": "slow"})},
               "refused": {"declared_sha": "0" * 64}}[scenario]
    spec = _case(tmp_path, **options)
    before = _tree(spec.parent)
    record = _check(spec)
    assert record["verdict"] == {"live": "LIVE", "inconclusive": "INCONCLUSIVE",
                                 "timeout": "REFUSED", "refused": "REFUSED"}[scenario]
    assert scenario != "timeout" or "did not finish" in record["reason"], record
    assert _tree(spec.parent) == before and list((tmp_path / "work").iterdir()) == []


_DECISIONS = {
    "fired": ({"guard": _DEAD, "find": _TRIGGER.replace("unsafe", "forbidden")}, True,
              "DEAD", "LIVE"),
    "gone": ({"guard": _MASKED}, True, "DEAD", "INCONCLUSIVE"),
    "reached": ({"replace": "if (:"}, True, "INCONCLUSIVE", "LIVE"),
    "quiet_without_trigger": ({"guard": _ALWAYS_ON,
                               "find": _TRIGGER.replace('== "unsafe"', '!= "never"')}, True,
                              "DEAD", "LIVE"),
    "snippet_once": ({"guard": _REPEATED}, True, "REFUSED", "DEAD"),
    "subject_digest": ({"declared_sha": "1" * 64}, True, "REFUSED", "LIVE"),
    "spec_strength": ({"replace": "sys.exit(0)\nif False:",
                       "edit": lambda s: s.update(bypassed={"exit": [0]})}, None,
                      "REFUSED", "LIVE"),
    "same_fixture": (_CHANGES["a-template-file"], True, "REFUSED", "LIVE"),
}


@pytest.mark.parametrize("check", sorted(_DECISIONS))
def test_removing_a_decision_check_flips_its_specimen(check, tmp_path, monkeypatch):
    """Each decision check decides its specimen: with it the verdict is right, and
    with it removed the dead, masked, broken, always-on, repeated, drifted, vacuous
    or fixture-changing specimen gets a wrong verdict."""
    options, passes, right, wrong = _DECISIONS[check]
    spec = _case(tmp_path, **options)
    policy = spec.parent / "fixture" / "policy.txt"
    assert _check(spec)["verdict"] == right
    if policy.exists():
        _write(policy, "deny")  # run A rewrote it: restore the template
    monkeypatch.setattr(harness, "_check_" + check, lambda *args: passes)
    assert _check(spec)["verdict"] == wrong


def test_the_guard_record_is_byte_identical_across_runs(tmp_path):
    """Two checks of the same spec give byte-identical records with no temporary path."""
    spec = _case(tmp_path)
    first, second = (json.dumps(_check(spec), sort_keys=True) for _ in range(2))
    assert first == second and '"LIVE"' in first
    for form in (str(tmp_path), str(tmp_path.resolve())):
        assert form not in first and json.dumps(form)[1:-1] not in first


_POLICY_ENTRY = ("import os\nimport sys\nfrom pathlib import Path\n\n"
                 'policy = Path("policy.txt").read_text(encoding="utf-8")\n'
                 'if os.environ.get("SAMPLE_MODE") == "unsafe" and "allow_unsafe = no" in policy:\n'
                 '    print("REFUSE: the policy forbids unsafe mode")\n    sys.exit(3)\n'
                 'Path("result.txt").write_text("done")\nprint("OK: reached the work")\n')


def test_a_guard_in_a_data_file_is_shown_live(tmp_path):
    """A guard held in a data file the entrypoint reads -- a policy line -- is
    shown live by the same mechanism: the snippet is in the data, not the code."""
    policy = "allow_unsafe = no\n"
    spec = _case(tmp_path, subject="policy.txt", files={"policy.txt": policy},
                 find="allow_unsafe = no", replace="allow_unsafe = yes")
    _write(spec.parent / "fixture" / "entry.py", _POLICY_ENTRY)
    record = _check(spec)
    assert record["verdict"] == "LIVE" and record["subject"]["path"] == "policy.txt", record
    assert record["subject"]["sha256"] == hashlib.sha256(policy.encode()).hexdigest()


def test_the_guard_helper_writes_nothing_but_its_run_directory(tmp_path):
    """The real entrypoint prints its record on stdout and leaves nothing behind:
    the work root is empty again and nothing under the test's directory changed."""
    spec = _case(tmp_path)
    (tmp_path / "work").mkdir()
    before = _tree(tmp_path)
    done = _cli(spec, tmp_path)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["verdict"] == "LIVE" and _tree(tmp_path) == before


@pytest.mark.parametrize(("scenario", "code"), [("live", 0), ("dead", 1), ("inconclusive", 2),
                                                 ("refused", 2)])
def test_the_guard_entrypoint_exit_codes(scenario, code, tmp_path):
    """The real entrypoint's exit code names LIVE (0), DEAD (1), and INCONCLUSIVE
    or REFUSED (2), and the record it prints names the same verdict."""
    options = {"live": {}, "dead": {"guard": _MASKED}, "inconclusive": {"replace": "if (:"},
               "refused": {"declared_sha": "0" * 64}}[scenario]
    done = _cli(_case(tmp_path, **options), tmp_path)
    assert done.returncode == code, done.stderr
    assert json.loads(done.stdout)["verdict"] == scenario.upper()
    assert done.stderr.startswith(b"REFUSE: ") == (code == 2) and b"\r" not in done.stdout


def test_a_harness_failure_refuses_with_one_line(tmp_path, monkeypatch, capsys):
    """An unexpected error inside the harness exits 2 with one REFUSE line and
    prints no record: an error decides nothing."""
    monkeypatch.setattr(harness, "check_guard", lambda *args: 1 / 0)
    code = harness.main(["guard-live", str(_case(tmp_path)), "--work-root", str(tmp_path)])
    captured = capsys.readouterr()
    assert (code, captured.out) == (2, "")
    assert captured.err == "REFUSE: the harness failed (ZeroDivisionError)\n"


def test_the_assertion_form_raises_unless_live(tmp_path):
    """`assert_guard_is_live` returns the record for a live guard and raises for
    a dead guard and for a spec it must refuse."""
    work = tmp_path / "work"
    work.mkdir()
    assert harness.assert_guard_is_live(_case(tmp_path / "live"), work)["verdict"] == "LIVE"
    for name, options in (("dead", {"guard": _MASKED}), ("refused", {"declared_sha": "0" * 64})):
        with pytest.raises(AssertionError, match="not shown live"):
            harness.assert_guard_is_live(_case(tmp_path / name, **options), work)
