"""The rehearsal harness runs a real entrypoint in a controlled root and refuses any mismatch.

What is held here, in words:

- A run matches only when its exit code, its exact set of file changes under
  the watched roots (fixture, home, tmp) and its output patterns all agree with
  the spec. Each kind of mismatch is listed; an expectation that names only an
  exit code still refuses any file change; patterns see a CR the child wrote.
- Spec errors (a removed field such as `stdin` among them), a declared path
  that is not plain components or that a link on it resolves elsewhere, a link
  or special file in the fixture, a relative program, a timeout, a spawn
  failure, an undecodable or oversized stream, a stream still held, an existing
  run directory, a work root inside the spec's directory (by identity, a
  simulated alias too), two template names landing on one copy, and any run
  off Linux refuse rather than pass.
- A work root under a non-ASCII directory and declared paths through dot
  directories are accepted.
- The child sees exactly the declared environment and directory, and a
  process it starts is ended with its process group.
- Records of one spec and work root are identical whatever spelling of its paths
  the child prints; the fixture and spec are never modified; cleanup removes a
  read-only file and directory, and a link as itself, never changing an outside
  file; a write outside every watched root is NOT seen, and the limits say so.
- Each comparison is load-bearing: removing it accepts the mismatch it exists for.
- The entrypoint prints its record on stdout and writes nothing but its run
  directory; any command line but the two forms refuses with one REFUSE line.

The harness runs on Linux only, so this module is collected everywhere and runs
on Linux. Every child is a few lines the test writes (Python, or a shell script
that prints one line) or this repository's linter.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rehearse_entrypoint.py"
LINTER = ROOT / "scripts" / "ps51_lint.py"
SPECIMENS = ROOT / "tests" / "specimens" / "ps51"
sys.path.insert(0, str(ROOT / "scripts"))

import rehearse_entrypoint as harness  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="the harness runs on Linux only and refuses elsewhere")

_HARNESS_NAMES = {"HOME", "TMPDIR", "TMP", "TEMP"}

_WRITER = """import os
from pathlib import Path
Path(os.environ.get("TARGET", "."), "out.txt").write_text("done")
print(os.readlink("/proc/self/fd/0"))
print("OK finished", end="\\r\\n" if os.environ.get("CRLF") else "\\n")
raise SystemExit(int(os.environ.get("CODE", "0")))
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _spec(case: Path, script: str, expect: dict, **run) -> Path:
    """A fixture holding `tool.py` and a spec that runs it with `{python}`."""
    _write(case / "fixture" / "tool.py", script)
    body = {"fixture": "fixture", "argv": ["{python}", "tool.py"], "timeout_seconds": 60}
    body.update(run)
    spec = {"schema": harness.REHEARSAL_SPEC, "name": "sample", "run": body, "expect": expect}
    return _write(case / "spec.json", json.dumps(spec))


def _rehearse(spec: Path) -> dict:
    work = spec.parent.parent / "work"
    work.mkdir(exist_ok=True)
    return harness.rehearse(spec, work)


def _failed(record: dict) -> list:
    return [check["check"] for check in record["checks"] if not check["passed"]]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cli(*args, cwd: Path):
    """The real entrypoint in `cwd`, its output in bytes."""
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd, capture_output=True,
                          input=b"held", timeout=300)


def _tree(top: Path) -> dict:
    """Every entry under `top`: its bytes (None for a directory) and its mode."""
    return {p.relative_to(top).as_posix(): (p.read_bytes() if p.is_file() else None,
                                            stat.S_IMODE(p.lstat().st_mode))
            for p in sorted(top.rglob("*"))}


def test_a_matching_run_is_accepted(tmp_path):
    """Exit, the exact created file with its digest and the output patterns all
    agree, so the verdict is MATCH and every check passed."""
    expect = {"exit": [0], "files": {"created": [{"path": "fixture/out.txt", "sha256": _sha("done")}]},
              "stdout": {"must_match": ["OK finished"], "must_not_match": ["Traceback"]}}
    record = _rehearse(_spec(tmp_path / "case", _WRITER, expect))
    assert record["verdict"] == "MATCH" and _failed(record) == [], record


_CREATED = {"exit": [0], "files": {"created": ["fixture/out.txt"]}}
_MISMATCHES = {
    "wrong-exit": ({"CODE": "3"}, _CREATED, "exit"),
    "undeclared-created": ({}, {"exit": [0]}, "files"),
    "undeclared-modified": ({"TARGET": "data"}, {"exit": [0]}, "files"),
    "undeclared-deleted": ({"MODE": "delete"}, _CREATED, "files"),
    "declared-file-absent": ({}, {"exit": [0], "files": {
        "created": ["fixture/out.txt", "fixture/missing.txt"]}}, "files"),
    "wrong-digest": ({}, {"exit": [0], "files": {
        "created": [{"path": "fixture/out.txt", "sha256": _sha("other")}]}}, "files"),
    "must-match-absent": ({}, dict(_CREATED, stdout={"must_match": ["never printed"]}), "patterns"),
    "must-not-match-present": ({}, dict(_CREATED, stdout={"must_not_match": ["OK"]}), "patterns"),
    "carriage-return-kept": ({"CRLF": "1"}, dict(_CREATED, stdout={"must_not_match": ["\r"]}),
                             "patterns"),
}


@pytest.mark.parametrize("case", sorted(_MISMATCHES))
def test_each_mismatch_is_refused(case, tmp_path):
    """Each kind of mismatch gives MISMATCH, and the check that names it failed.
    Patterns see the output as written: a CR the child printed is still there."""
    env, expect, failing = _MISMATCHES[case]
    script = _WRITER
    if env.get("MODE") == "delete":
        script = "from pathlib import Path\nPath('data', 'old.txt').unlink()\n" + _WRITER
    _write(tmp_path / "case" / "fixture" / "data" / "old.txt", "old")
    if env.get("TARGET") == "data":
        script = _WRITER.replace('"out.txt"', '"old.txt"')
    spec = _spec(tmp_path / "case", script, expect,
                 env={k: v for k, v in env.items() if k != "MODE"})
    record = _rehearse(spec)
    assert record["verdict"] == "MISMATCH" and failing in _failed(record), record


def _valid() -> dict:
    return {"schema": harness.REHEARSAL_SPEC, "name": "sample",
            "run": {"fixture": "fixture", "argv": ["{python}", "tool.py"], "timeout_seconds": 60},
            "expect": {"exit": [0], "files": {"created": ["fixture/out.txt"]}}}


_INVALID = {
    "unknown-field": lambda s: s.update(colour="blue"),
    "missing-run": lambda s: s.pop("run"),
    "unknown-run-field": lambda s: s["run"].update(colour="blue"),
    "removed-field-stdin": lambda s: s["run"].update(stdin="x"),
    "removed-field-sentinels": lambda s: s["run"].update(sentinels=[]),
    "removed-field-streams": lambda s: s["run"].update(streams={}),
    "wrong-schema": lambda s: s.update(schema="something.else"),
    "empty-argv": lambda s: s["run"].update(argv=[]),
    "argv-not-a-list": lambda s: s["run"].update(argv="python tool.py"),
    "absolute-cwd": lambda s: s["run"].update(cwd="/absolute"),
    "escaping-cwd": lambda s: s["run"].update(cwd="../.."),
    "cwd-missing": lambda s: s["run"].update(cwd="absent"),
    "cwd-is-a-file": lambda s: s["run"].update(cwd="tool.py"),
    "unknown-placeholder": lambda s: s["run"].update(argv=["{nothing}"]),
    "lone-brace": lambda s: s["run"].update(argv=["{python"]),
    "empty-must-match": lambda s: s["expect"].update(stdout={"must_match": [""]}),
    "empty-must-not-match": lambda s: s["expect"].update(stdout={"must_not_match": ["x", ""]}),
    "empty-stderr-pattern": lambda s: s["expect"].update(stderr={"must_match": [""]}),
    "too-many-patterns": lambda s: s["expect"].update(
        stdout={"must_match": ["x"] * 30, "must_not_match": ["y"] * 35}),
    "timeout-zero": lambda s: s["run"].update(timeout_seconds=0),
    "timeout-too-long": lambda s: s["run"].update(timeout_seconds=3601),
    "timeout-boolean": lambda s: s["run"].update(timeout_seconds=True),
    "fixture-missing": lambda s: s["run"].update(fixture="absent"),
    "fixture-is-a-file": lambda s: s["run"].update(fixture="fixture/tool.py"),
    "fixture-with-an-empty-component": lambda s: s["run"].update(fixture="fixture/"),
    "fixture-with-a-nul": lambda s: s["run"].update(fixture="fix\x00ture"),
    "fixture-not-encodable": lambda s: s["run"].update(fixture="fix\ud800ture"),
    "env-name-with-equals": lambda s: s["run"].update(env={"A=B": "x"}),
    "program-bare-name": lambda s: s["run"].update(argv=["sample-tool"],
                                                   env={"PATH": "{fixture}/bin"}),
    "program-path-not-absolute": lambda s: s["run"].update(argv=["bin/sample-tool"]),
    "program-not-found": lambda s: s["run"].update(argv=["{fixture}/no-such-program"]),
    "missing-exit": lambda s: s["expect"].pop("exit"),
    "empty-exit": lambda s: s["expect"].update(exit=[]),
    "boolean-exit": lambda s: s["expect"].update(exit=[True]),
    "escaping-file-entry": lambda s: s["expect"].update(files={"created": ["fixture/../x"]}),
    "dot-component-in-a-file-entry": lambda s: s["expect"].update(
        files={"created": ["fixture/./out.txt"]}),
    "unknown-file-root": lambda s: s["expect"].update(files={"created": ["elsewhere/x"]}),
    "deleted-with-digest": lambda s: s["expect"].update(files={"deleted": [
        {"path": "fixture/tool.py", "sha256": "0" * 64}]}),
    "inherit-env-not-a-list": lambda s: s["run"].update(inherit_env="PATH"),
    "env-value-not-text": lambda s: s["run"].update(env={"CODE": 3}),
    "run-not-an-object": lambda s: s.update(run=["fixture"]),
    "files-kind-not-a-list": lambda s: s["expect"].update(files={"created": "fixture/out.txt"}),
}


_SPEC_SHAPES = ["duplicate-key", "not-json", "spec-missing", "spec-too-large",
                "fixture-too-many-entries", "fixture-too-many-bytes", "fixture-link",
                "fixture-special-file"]


#: Each bound, set small enough that the sample fixture or spec exceeds it; the
#: refusal must name the bound, not some later failure of the same input.
_BOUNDS = {"spec-too-large": "MAX_SPEC_BYTES", "fixture-too-many-entries": "MAX_ENTRIES",
           "fixture-too-many-bytes": "MAX_TREE_BYTES"}
#: The words each refusal must carry where another check could refuse the same spec.
_REASONS = {"empty-must-match": "an empty pattern", "empty-must-not-match": "an empty pattern",
            "empty-stderr-pattern": "an empty pattern",
            "too-many-patterns": "more than 64 patterns", "duplicate-key": "['name']", "program-bare-name": "absolute",
            "program-path-not-absolute": "absolute", "removed-field-stdin": "['stdin']",
            "removed-field-sentinels": "['sentinels']", "removed-field-streams": "['streams']",
            "cwd-missing": "working directory", "cwd-is-a-file": "working directory",
            "spec-missing": "the spec cannot be read", "run-not-an-object": "must be an object",
            "files-kind-not-a-list": "must be a list",
            "fixture-link": "link or special file", "fixture-special-file": "link or special file"}


@pytest.mark.parametrize("case", sorted(_INVALID) + _SPEC_SHAPES)
def test_invalid_rehearsal_specs_refuse(case, tmp_path, monkeypatch):
    """A spec, fixture or program the harness cannot judge refuses with a
    reason, before the child runs. A bare program name refuses even when a
    program of that name lies on the child's declared PATH: nothing is looked
    up. Fields the harness no longer has (stdin, sentinels, streams) are unknown."""
    case_dir = tmp_path / "case"
    _write(case_dir / "fixture" / "tool.py", _WRITER)
    _write(case_dir / "fixture" / "work" / "keep.txt", "kept")
    _write(case_dir / "fixture" / "bin" / "sample-tool", "#!/bin/sh\necho GOT\n").chmod(0o755)
    spec_path = case_dir / "spec.json"
    if case in _INVALID:
        spec = _valid()
        _INVALID[case](spec)
        _write(spec_path, json.dumps(spec))
    elif case == "duplicate-key":
        _write(spec_path, '{"name": "first", ' + json.dumps(_valid())[1:])
    elif case == "not-json":
        _write(spec_path, "{ this is not json")
    elif case == "spec-missing":
        pass
    else:
        _write(spec_path, json.dumps(_valid()))
        if case == "fixture-link":
            _write(tmp_path / "outside" / "private.txt", "outside")
            (case_dir / "fixture" / "outside").symlink_to(tmp_path / "outside")
        elif case == "fixture-special-file":
            os.mkfifo(case_dir / "fixture" / "pipe")
        else:
            monkeypatch.setattr(harness, _BOUNDS[case], 0 if case.endswith("entries") else 16)
    record = _rehearse(spec_path)
    assert record["verdict"] == "REFUSED" and record["observation"] is None, record
    assert _REASONS.get(case, "") in record["refusal"], record["refusal"]
    assert case not in _BOUNDS or any(w in record["refusal"] for w in ("exceeds", "larger")), record
    assert list((tmp_path / "work").iterdir()) == []


_SLEEPER = "import time\ntime.sleep(30)\n"
_UNDECODABLE = "import sys\nsys.stdout.buffer.write(bytes([255, 254, 253]))\n"
_FLOOD = "print('x' * 5000)\n"
_HOLDER = ("import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; "
           "time.sleep(6)'], start_new_session=True, stderr=subprocess.DEVNULL)\n")
_RUN_FAILURES = {"timeout": "did not finish", "undecodable-stream": "cannot be decoded",
                 "oversized-stream": "exceeded", "run-directory-exists": "already exists",
                 "spawn-failure": "could not be started (FileNotFoundError)",
                 "stream-held": "stayed open", "no-work-root": "not a usable path",
                 "work-root-missing": "the run directory cannot be made",
                 "copy-failure": "the fixture template cannot be copied",
                 "left-behind": "group was ended; and the run directory could not be removed"}


@pytest.mark.parametrize("case", sorted(_RUN_FAILURES))
def test_run_failures_refuse(case, tmp_path, monkeypatch):
    """A run that cannot be judged refuses, for its own reason: no answer is
    never a pass. A run directory that cannot be removed refuses after the first
    cause; so does a work root that is not a path or does not exist, and a listed
    file the copy cannot read. The timeout ends the run within a few seconds of the declared
    one, and a stream a process the child started (outside its group) still
    holds when the drain time is up refuses the run."""
    case_dir, created = tmp_path / "case", _CREATED
    if case == "run-directory-exists":
        spec = _spec(case_dir, _WRITER, created)
        (tmp_path / "work" / "rehearsal").mkdir(parents=True)
    elif case == "spawn-failure":
        spec = _spec(case_dir, _WRITER, {"exit": [0]}, argv=["{fixture}/broken"])
        _write(case_dir / "fixture" / "broken", "#!/nonexistent/interpreter\n").chmod(0o755)
    elif case == "oversized-stream":
        monkeypatch.setattr(harness, "MAX_STREAM_BYTES", 1000)
        spec = _spec(case_dir, _FLOOD, {"exit": [0]})
    elif case in ("no-work-root", "work-root-missing", "copy-failure"):
        spec = _spec(case_dir, _WRITER, created)
    elif case == "stream-held":
        monkeypatch.setattr(harness, "DRAIN_SECONDS", 1)
        spec = _spec(case_dir, _HOLDER, {"exit": [0]})
    else:
        timeout = case in ("timeout", "left-behind")
        spec = _spec(case_dir, _SLEEPER if timeout else _UNDECODABLE, {"exit": [0], "stdout": {
            "must_match": ["x"]}}, timeout_seconds=1 if timeout else 60)
    if case == "left-behind":  # no directory can be removed, so the run directory stays
        monkeypatch.setattr(os, "rmdir", os.mkdir)
    if case == "copy-failure":  # a listed file that is gone when the copy reads it
        real = harness._snapshot
        monkeypatch.setattr(harness, "_snapshot", lambda root, label, **options: dict(
            real(root, label, **options), **{"gone.txt": ("file", "0" * 64, 0o644)}))
    started = time.monotonic()
    work = {"no-work-root": None, "work-root-missing": tmp_path / "absent"}
    record = harness.rehearse(spec, work[case]) if case in work else _rehearse(spec)
    assert record["verdict"] == "REFUSED" and _RUN_FAILURES[case] in record["refusal"], record
    assert case != "timeout" or time.monotonic() - started < 1 + 5, "the timeout did not bound it"


@pytest.mark.parametrize("case", ["the-spec-directory", "a-directory-inside-it",
                                  "inside-the-fixture", "a-simulated-alias"])
def test_the_work_root_must_lie_outside_the_spec_directory(case, tmp_path, monkeypatch):
    """Inputs live under the spec's directory and outputs outside it: a work root
    that is that directory or lies below it refuses before anything runs. It is
    decided by file identity, not by name: a directory elsewhere with the spec
    directory's identity (a simulated alias, as a bind mount gives) refuses too."""
    case_dir = tmp_path / "case"
    spec = _spec(case_dir, _WRITER, _CREATED, env={"TARGET": "{spec_dir}"})
    work = {"the-spec-directory": case_dir, "a-directory-inside-it": case_dir / "work",
            "inside-the-fixture": case_dir / "fixture", "a-simulated-alias": tmp_path / "alias"}[case]
    work.mkdir(exist_ok=True)
    if case == "a-simulated-alias":
        real_stat, wanted, alias = os.stat, os.stat(case_dir), os.path.realpath(work)
        monkeypatch.setattr(os, "stat", lambda path, *args, **kwargs: wanted if os.fspath(
            path) == alias else real_stat(path, *args, **kwargs))
    record = harness.rehearse(spec, work)
    monkeypatch.undo()
    assert record["verdict"] == "REFUSED" and "outside it" in record["refusal"], record
    assert not (case_dir / "out.txt").exists() and not (work / "rehearsal").exists()


_LISTER = "import os\nprint(sorted(os.listdir('.')))\n"


@pytest.mark.parametrize("case", ["fixture-with-dotdot", "fixture-with-dotdot-back-inside",
                                  "fixture-given-absolutely", "fixture-through-a-link",
                                  "fixture-that-is-a-link"])
def test_a_path_that_leaves_the_spec_directory_refuses(case, tmp_path):
    """A fixture path with '..' (even leading back inside), an absolute one, or
    one a link on it resolves elsewhere, refuses before anything runs, so the
    child never sees what lies there."""
    kit = tmp_path / "kit"
    _write(tmp_path / "outside" / "tool.py", _LISTER)
    _write(tmp_path / "outside" / "private.txt", "outside")
    fixture = {"fixture-with-dotdot": "../outside",
               "fixture-with-dotdot-back-inside": "fixture/../fixture",
               "fixture-given-absolutely": (tmp_path / "outside").as_posix(),
               "fixture-through-a-link": "link/outside", "fixture-that-is-a-link": "again"}[case]
    spec = _spec(kit, _LISTER, {"exit": [0]}, fixture=fixture)
    (kit / "link").symlink_to(tmp_path, target_is_directory=True)
    (kit / "again").symlink_to(kit / "fixture", target_is_directory=True)
    record = _rehearse(spec)
    assert record["verdict"] == "REFUSED" and record["observation"] is None, record


_DOTS = """import os
from pathlib import Path
Path("state.txt").write_text("after")
Path("r\\u00e9sum\\u00e9.txt").write_text("new")
print("GOT", os.getcwd())
"""


def test_a_non_ascii_work_root_and_dot_directories_are_accepted(tmp_path):
    """A work root under a directory named with U+00E9, a fixture whose name
    starts with a dot, and a working directory and expected paths through a dot
    directory, with a non-ASCII file name, are plain paths: the run matches."""
    case = tmp_path / "case"
    _write(case / ".kit" / "tool.py", _DOTS)
    _write(case / ".kit" / ".nornyx" / "state.txt", "before")
    spec = _spec(case, "", {"exit": [0], "files": {
        "modified": ["fixture/.nornyx/state.txt"],
        "created": ["fixture/.nornyx/résumé.txt"]},
        "stdout": {"must_match": ["GOT {fixture}/.nornyx"]}},
        fixture=".kit", cwd=".nornyx", argv=["{python}", "../tool.py"])
    (case / "fixture" / "tool.py").unlink()
    work = tmp_path / "café" / "work"
    work.mkdir(parents=True)
    record = harness.rehearse(spec, work)
    assert record["verdict"] == "MATCH", record
    assert list(work.iterdir()) == []


def test_the_child_runs_in_the_declared_directory(tmp_path):
    """The child runs in the declared directory inside the fixture copy, which
    has the template directory's mode, as every entry of the copy does."""
    _write(tmp_path / "case" / "fixture" / "work" / "keep.txt", "kept").parent.chmod(0o555)
    expect = {"exit": [0], "stdout": {"must_match": ["GOT {fixture}/work 0o555"]}}
    script = "import os\nprint('GOT', os.getcwd(), oct(os.stat('.').st_mode & 0o777))\n"
    record = _rehearse(_spec(tmp_path / "case", script, expect, cwd="work",
                             argv=["{python}", "../tool.py"]))
    assert record["verdict"] == "MATCH", record


@pytest.mark.parametrize("alias", ["./tool.py", "./sub/"])
def test_a_copy_that_would_land_on_an_existing_entry_refuses(alias, tmp_path, monkeypatch):
    """Every entry of the copy, a file or a directory, is created exclusively: two
    template names that land on one entry (simulated here by a second, normalizing
    name in the listing) refuse before anything runs, instead of one overwriting
    the other or two directories merging."""
    spec = _spec(tmp_path / "case", _WRITER, _CREATED)
    _write(tmp_path / "case" / "fixture" / "sub" / "keep.txt", "kept")
    real = harness._snapshot

    def listing(root, label, **options):
        found = real(root, label, **options)
        if label == "the fixture template":
            found[alias] = found[alias[2:]]
        return found

    monkeypatch.setattr(harness, "_snapshot", listing)
    record = _rehearse(spec)
    assert record["verdict"] == "REFUSED" and "land on one entry" in record["refusal"], record
    assert list((tmp_path / "work").iterdir()) == []


def test_the_harness_refuses_off_linux(tmp_path, monkeypatch):
    """Off Linux the harness refuses before it reads the fixture or starts
    anything; the same spec on Linux runs and matches."""
    spec = _spec(tmp_path / "case", _WRITER, {"exit": [0]}, env={"TARGET": "{spec_dir}"})
    monkeypatch.setattr(harness.sys, "platform", "win32")
    record = _rehearse(spec)
    monkeypatch.undo()
    assert record["verdict"] == "REFUSED" and "Linux only" in record["refusal"], record
    assert not (tmp_path / "case" / "out.txt").exists()
    assert list((tmp_path / "work").iterdir()) == []
    assert _rehearse(spec)["verdict"] == "MATCH"


_READ_ONLY = """import os, stat, sys
from pathlib import Path
sealed, outside = Path(os.environ["TMP"], "sealed"), os.path.abspath(os.environ["OUTSIDE"])
sealed.mkdir()
if sys.argv[1] == "hard-link":
    os.link(os.path.join(outside, "locked.txt"), sealed / "shared.txt")
else:
    (sealed / "locked.txt").write_text("locked")
    os.chmod(sealed / "locked.txt", stat.S_IREAD)
    os.symlink(outside, sealed / "outside")
os.chmod(sealed, stat.S_IREAD | stat.S_IEXEC)
"""


@pytest.mark.parametrize("case", ["read-only", "hard-link"])
def test_cleanup_never_follows_a_link_or_changes_an_outside_file(case, tmp_path):
    """A read-only file, and a directory without write permission, left under a
    watched root are removed; a link there to an outside directory is recorded
    as one created entry, nothing behind it listed, and removed as itself; a hard
    link to an outside read-only file is removed without its mode, which the
    outside file shares, ever changing. MATCH, no run directory left, and the
    outside files unchanged in content and mode."""
    locked = _write(tmp_path / "outside" / "locked.txt", "outside")
    locked.chmod(stat.S_IREAD)
    before = (locked.stat().st_mode, (tmp_path / "outside").stat().st_mode)
    created = ["tmp/sealed/"] + (["tmp/sealed/shared.txt"] if case == "hard-link" else [
        "tmp/sealed/locked.txt", "tmp/sealed/outside"])
    spec = _spec(tmp_path / "case", _READ_ONLY, {"exit": [0], "files": {"created": created}},
                 argv=["{python}", "tool.py", case], env={"OUTSIDE": "{spec_dir}/../outside"})
    record = _rehearse(spec)
    assert record["verdict"] == "MATCH", record
    assert (locked.stat().st_mode, (tmp_path / "outside").stat().st_mode) == before
    assert list((tmp_path / "work").iterdir()) == []
    assert locked.read_text(encoding="utf-8") == "outside"
    assert sorted(p.name for p in (tmp_path / "outside").iterdir()) == ["locked.txt"]


@pytest.mark.parametrize("arguments", [
    (), ("rehearse",), ("-h",), ("rehearse", "-h"), ("rehearse", "spec.json"),
    ("rehearse", "spec.json", "--work-root"), ("rehearse", "spec.json", "--record", "work"),
    ("rehearse", "spec.json", "--work-root", "work", "extra"), ("frobnicate", "spec.json",
                                                                 "--work-root", "work"),
    ("rehearse", "-spec.json", "--work-root", "work"), ("guard-live", "spec.json", "--work-root",
                                                        "-work")])
def test_any_other_command_line_refuses(arguments, tmp_path):
    """Only `rehearse SPEC --work-root DIR` and `guard-live SPEC --work-root DIR`
    are accepted: anything else, help included, exits 2 with one REFUSE usage
    line, judges nothing and prints no record. Every line ends in LF alone."""
    done = _cli(*arguments, cwd=tmp_path)
    assert (done.returncode, done.stdout) == (2, b""), done.stderr
    assert done.stderr.startswith(b"REFUSE: usage: ") and done.stderr.count(b"\n") == 1
    assert b"\r" not in done.stderr


def test_an_exit_only_expectation_still_checks_files(tmp_path):
    """An expectation naming only the exit code still refuses any file change."""
    record = _rehearse(_spec(tmp_path / "case", _WRITER, {"exit": "success"}))
    assert record["verdict"] == "MISMATCH" and _failed(record) == ["files"]
    assert "undeclared created fixture/out.txt" in record["checks"][1]["detail"]


_ENV_DUMP = "import json, os\nprint(json.dumps(dict(sorted(os.environ.items()))))\n"


def test_the_child_environment_is_exactly_the_declared_one(tmp_path, monkeypatch):
    """The child sees HOME, TMPDIR, TMP and TEMP, the inherited names and the
    declared ones, and nothing else from the harness's environment: exact in
    both directions. A declared name wins over the same name inherited, and a name
    inherited from an environment that lacks it is not recorded as inherited."""
    monkeypatch.setenv("HARNESS_ONLY_CANARY", "must-not-reach")
    monkeypatch.setenv("INHERITED_CANARY", "inherited")
    monkeypatch.setenv("BOTH", "inherited")
    monkeypatch.delenv("HOME", raising=False)
    # A Python child in the C locale adds LC_CTYPE to its OWN environment (locale
    # coercion); switching that off, as a declared name, shows exactly what it received.
    declared = {"DECLARED": "{home}/declared", "PYTHONCOERCECLOCALE": "0", "BOTH": "declared"}
    spec = _spec(tmp_path / "case", _ENV_DUMP, {"exit": [0]},
                 inherit_env=["INHERITED_CANARY", "BOTH", "HOME"], env=declared)
    record = _rehearse(spec)
    seen = json.loads(record["observation"]["streams"]["stdout"]["text"])
    names = _HARNESS_NAMES | {"INHERITED_CANARY"} | set(declared)
    assert record["verdict"] == "MATCH" and set(seen) == names and seen["BOTH"] == "declared"
    environment = record["observation"]["environment"]
    assert environment["INHERITED_CANARY"] == "(inherited)" and environment["BOTH"] == "declared"
    assert environment["DECLARED"] == "{home}/declared" and environment["HOME"] == "{home}"


@pytest.mark.parametrize("root", ["fixture", "home", "tmp"])
def test_writes_are_seen_in_every_watched_root(root, tmp_path):
    """A write into the fixture, home or tmp is seen: declared, the run matches."""
    spec = _spec(tmp_path / "case", _WRITER, {"exit": [0], "files": {"created": [
        f"{root}/out.txt"]}}, env={"TARGET": "{" + root + "}"})
    assert _rehearse(spec)["verdict"] == "MATCH"


def test_a_write_outside_the_watched_roots_is_not_seen(tmp_path):
    """The stated blind spot, pinned: a write outside every watched root passes
    unseen, and the record's limits name exactly that."""
    elsewhere = tmp_path / "case" / "elsewhere"
    elsewhere.mkdir(parents=True)
    spec = _spec(tmp_path / "case", _WRITER, {"exit": [0]}, env={"TARGET": "{spec_dir}/elsewhere"})
    record = _rehearse(spec)
    assert record["verdict"] == "MATCH" and (elsewhere / "out.txt").is_file()
    assert any(limit.startswith("writes outside the watched roots") for limit in record["limits"])


@pytest.mark.parametrize("root", ["fixture", "home", "tmp"])
def test_a_watched_root_replaced_during_the_run_refuses(root, tmp_path):
    """A watched root replaced by a link to a directory (tmp: a new one) is no MATCH."""
    swap = ("import os, shutil, sys\nr, t = sys.argv[1:]\nd = r.endswith('tmp')\n"
            "os.rename(r, r + '.old') if d else shutil.rmtree(r)\nos.mkdir(r) if d else os.symlink(t, r)\n")
    spec = _spec(tmp_path / "case", swap, {"exit": [0], "files": {"created": [f"{root}/tool.py"]}},
                 argv=["{python}", "tool.py", "{" + root + "}", "{spec_dir}/fixture"])
    assert "was replaced" in str(_rehearse(spec)["refusal"])


def test_a_spec_with_many_unique_keys_is_read_in_linear_time(tmp_path):
    """Four times the keys costs well under eight times as much, where a quadratic
    duplicate check costs sixteen; a repeated key among them still refuses."""
    def cost(n):
        path = _write(tmp_path / f"keys{n}.json", json.dumps({f"k{i}": 0 for i in range(n)}))
        started = time.perf_counter()
        harness._load(path)
        return time.perf_counter() - started

    small, large = min(cost(6000) for _ in range(3)), min(cost(24000) for _ in range(3))
    assert large < 8 * small, f"{small:.4f}s, then {large:.4f}s for four times the keys"
    with pytest.raises(harness.Refusal, match="repeats the keys"):
        harness._load(_write(tmp_path / "dup.json", '{"a": 1, "b": 2, "a": 3}'))


def test_a_spec_that_exhausts_the_json_reader_refuses_instead_of_crashing(tmp_path):
    """Nesting deep enough to exhaust the JSON reader is a refusal with a reason, never
    an uncaught error whose exit code reads as a mismatch."""
    spec = _spec(tmp_path / "case", _WRITER, {"exit": [0]})
    _write(spec, "[" * 200000 + "]" * 200000)
    record = _rehearse(spec)
    assert record["verdict"] == "REFUSED" and record["refusal"], record


def _judged(patterns: dict, text: str) -> tuple:
    """`_check_patterns` for one stdout text, without a run."""
    empty = {"must_match": [], "must_not_match": []}
    return harness._check_patterns({"patterns": {"stdout": {**empty, **patterns}, "stderr": empty}},
                                   {"streams": {"stdout": {"full": text}, "stderr": {"full": ""}}})


def test_an_output_pattern_is_literal_text(tmp_path):
    """Regular-expression syntax is not read: `a.c` is not `abc`, `(a+)+$` is those
    characters, a bare `(` is accepted, and a substring decides."""
    assert _judged({"must_match": ["a.c"]}, "abc")[0] is False
    assert _judged({"must_match": ["a.c"]}, "xa.cx")[0] is True
    assert _judged({"must_match": ["(a+)+$"]}, "aaa")[0] is False
    assert _judged({"must_not_match": ["(a+)+$"]}, "aaa")[0] is True
    assert _judged({"must_match": ["("], "must_not_match": ["z"]}, "f(x)")[0] is True
    spec = _spec(tmp_path / "case", _WRITER, {"exit": [0], "stdout": {"must_match": [
        "(", "a.c", *(f"p{i}" for i in range(62))]}})   # the most patterns a stream may hold
    assert _rehearse(spec)["verdict"] != "REFUSED"


def test_matching_the_patterns_costs_time_linear_in_the_output():
    """Four times the output costs well under eight times as much for the shapes that make
    a backtracking engine hang, `(a+)+$` on a near-match among them, and for the most patterns
    a stream may hold, each one a long near-match of the text."""
    shapes = {"nested-quantifier": ["(a+)+$"], "long-near-match": ["a" * 99 + "b"],
              "the-most-patterns": ["a" * 99 + "b"] * 64}
    for name, patterns in shapes.items():
        def cost(n):
            text = "a" * n + "!"
            started = time.perf_counter()
            assert _judged({"must_match": patterns}, text)[0] is False
            return time.perf_counter() - started

        small, large = min(cost(2_000_000) for _ in range(3)), min(cost(8_000_000) for _ in range(3))
        assert large < 8 * small, f"{name}: {small:.4f}s, then {large:.4f}s for four times the text"


_SPELLINGS = """import json, os, sys
here = os.getcwd()
print(here, json.dumps(here), here.upper(), os.environ["HOME"], os.path.realpath(sys.executable),
      sep="\\n")
sys.stderr.buffer.write(bytes([255]) + here.encode())
"""


def test_the_record_is_deterministic_for_one_spec_and_work_root(tmp_path, monkeypatch):
    """Two rehearsals of one spec with one work root give byte-identical records,
    whatever spelling of its paths the child prints: as given or resolved, a path
    is recorded as a placeholder, the interpreter's too when it is reached through
    a link. A stream that cannot be decoded is recorded with no digest, size or
    text, and the record's limits say so."""
    real = os.path.realpath(sys.executable)
    (tmp_path / "linked").mkdir()
    (tmp_path / "linked" / "python").symlink_to(real)
    monkeypatch.setattr(harness.sys, "executable", str(tmp_path / "linked" / "python"))
    spec = _spec(tmp_path / "case", _SPELLINGS, {"exit": [0]})
    first, second = (json.dumps(_rehearse(spec), sort_keys=True) for _ in range(2))
    record = json.loads(first)
    assert first == second and record["verdict"] == "MATCH", (first, second)
    lines = record["observation"]["streams"]["stdout"]["text"].split("\n")
    assert (lines[0], lines[3], lines[4]) == ("{fixture}", "{home}", "{python}"), lines
    assert record["observation"]["streams"]["stderr"] == {"bytes": None, "sha256": None,
                                                          "text": None}
    assert any(limit.startswith("an output stream that cannot be decoded")
               for limit in record["limits"])
    assert str(tmp_path) not in first and real not in first


_ENV_CANARY = "import os\nraise SystemExit(3 if 'HARNESS_ONLY_CANARY' in os.environ else 0)\n"


@pytest.mark.parametrize("step", ["exit", "files", "patterns", "environment"])
def test_removing_a_comparison_accepts_its_mismatch(step, tmp_path, monkeypatch):
    """With one comparison removed, the mismatch it exists for is accepted (or,
    for the environment step, the harness's own variable leaks into the child)."""
    monkeypatch.setenv("HARNESS_ONLY_CANARY", "must-not-reach")
    specs = {
        "exit": (_WRITER, dict(_CREATED, exit=[5])),
        "files": (_WRITER, {"exit": [0]}),
        "patterns": (_WRITER, dict(_CREATED, stdout={"must_match": ["never printed"]})),
        "environment": (_ENV_CANARY, {"exit": [0]}),
    }
    script, expect = specs[step]
    spec = _spec(tmp_path / "case", script, expect)
    with_control = _rehearse(spec)["verdict"]
    if step == "environment":
        monkeypatch.setattr(harness, "_child_environment", lambda run, layout: dict(os.environ))
        assert (with_control, _rehearse(spec)["verdict"]) == ("MATCH", "MISMATCH")
        return
    monkeypatch.setattr(harness, "_check_" + step, lambda expect, observation: (True, "removed"))
    assert (with_control, _rehearse(spec)["verdict"]) == ("MISMATCH", "MATCH")


@pytest.mark.parametrize("scenario", ["match", "mismatch", "timeout"])
def test_the_fixture_and_spec_are_never_modified(scenario, tmp_path):
    """The fixture template, the spec and its directory are byte-identical after
    a run, whether it matched, mismatched or was refused."""
    case = tmp_path / "case"
    script = {"match": _WRITER, "mismatch": "from pathlib import Path\nPath('tool.py').unlink()\n"
              + _WRITER, "timeout": _SLEEPER}[scenario]
    spec = _spec(case, script, {"exit": [0], "files": {"created": ["fixture/out.txt"]}},
                 timeout_seconds=1 if scenario == "timeout" else 60)
    before = _tree(case)
    record = _rehearse(spec)
    assert record["verdict"] == {"match": "MATCH", "mismatch": "MISMATCH",
                                 "timeout": "REFUSED"}[scenario]
    assert _tree(case) == before
    assert list((tmp_path / "work").iterdir()) == []


@pytest.mark.parametrize(("verdict", "code"), [("MATCH", 0), ("MISMATCH", 1), ("REFUSED", 2)])
def test_the_rehearsal_entrypoint_exit_codes(verdict, code, tmp_path):
    """The real entrypoint, given relative paths, exits 0, 1 or 2 and prints a
    record naming the same verdict on stdout; it writes nothing else, so the
    directory it ran in is unchanged; what it prints ends its lines in LF alone.
    The child's stdin is /dev/null although the entrypoint's own stdin is a pipe."""
    expect = {"MATCH": {"exit": [0], "files": {"created": ["fixture/out.txt"]},
                        "stdout": {"must_match": ["/dev/null"]}},
              "MISMATCH": {"exit": [0]}, "REFUSED": {"exit": []}}[verdict]
    _spec(tmp_path / "case", _WRITER, expect)
    (tmp_path / "work").mkdir()
    before = _tree(tmp_path)
    done = _cli("rehearse", "case/spec.json", "--work-root", "work", cwd=tmp_path)
    assert done.returncode == code, done.stderr
    assert json.loads(done.stdout)["verdict"] == verdict and _tree(tmp_path) == before
    assert done.stderr.startswith(b"REFUSE: ") == (code == 2)
    assert b"\r" not in done.stdout + done.stderr


def test_the_linter_entrypoint_rehearses_end_to_end(tmp_path):
    """The harness drives a real entrypoint of this repository: rehearsing the
    PowerShell linter over a specimen fixture gives exit 1 and the expected report."""
    specimen = (SPECIMENS / "fires-exit-code-null-cast.ps1.txt").read_text(encoding="ascii")
    _write(tmp_path / "case" / "fixture" / "sample.ps1", specimen)
    record = _rehearse(_spec(tmp_path / "case", "", {"exit": [1], "stdout": {
        "must_match": ['"verdict": "findings"', '"rule": "exit-code-null-cast"'],
        "must_not_match": ['"status": "refused"']}}, argv=["{python}", str(LINTER), "sample.ps1"],
        timeout_seconds=120))
    assert record["verdict"] == "MATCH", record
    text = record["observation"]["streams"]["stdout"]["text"]
    declared = specimen.count("# expect: exit-code-null-cast ")
    assert declared and text.count('"rule": "exit-code-null-cast"') == declared


_LAUNCHER = """import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", "import sys, time; time.sleep(3); "
                  "open(sys.argv[1], 'w').write('late')", sys.argv[1]])
if sys.argv[2] == "hang":
    time.sleep(60)
"""


@pytest.mark.parametrize("how", ["timeout", "normal-exit"])
def test_a_timeout_ends_the_process_group(how, tmp_path):
    """A grandchild that stays in the child's process group and would write
    later is ended with the group, after a timeout or a normal exit; one that
    leaves the group is a stated limit."""
    marker = tmp_path / "case" / "late.txt"
    spec = _spec(tmp_path / "case", _LAUNCHER, {"exit": [0]},
                 argv=["{python}", "tool.py", "{spec_dir}/late.txt",
                       "hang" if how == "timeout" else "exit"],
                 timeout_seconds=1 if how == "timeout" else 60)
    record = _rehearse(spec)
    assert record["verdict"] == ("REFUSED" if how == "timeout" else "MATCH"), record
    time.sleep(4.5)
    assert not marker.exists(), "a process in the child's group survived the rehearsal"
    assert any("leave its process group" in limit for limit in record["limits"])
