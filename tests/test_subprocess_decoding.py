"""Git's answers and the gates' recorded output are decoded with the codec their child writes.

The assumptions record (docs/requirements/ASSUMPTIONS.md) states the property and its limits
under the same title.

THE C LOCALE WITH UTF-8 MODE OFF is how a Linux runner reproduces a non-UTF-8
locale that is always installed. `LC_ALL=C` alone turns UTF-8 mode ON (PEP 540),
and then every codec in the child is UTF-8. Every specimen that relies on it
first requires that the child's codecs are not UTF-8, so it cannot pass by
measuring nothing.

POSIX only, and skipped elsewhere: the C locale and the executable git and ruff
doubles are POSIX mechanisms. No CI job reproduces the Windows half of the
defect.
"""

from __future__ import annotations

import ast
import codecs
import hashlib
import json
import locale
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from mutation_validity import mutate
from mutation_workspace import faithful_copy, isolated_env

from nornyx_forge import capsule_store, gates, repo_qualifier
from nornyx_forge.capsule import Actor, create_document
from nornyx_forge.capsule_store import CapsuleStore, CapsuleStoreError
from nornyx_forge.experience import start_experience
from nornyx_forge.models import QualificationReport

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="requires the POSIX C locale and executable git and ruff doubles"
)

#: A POSIX locale whose codecs are not UTF-8: the C locale with UTF-8 mode off.
C_LOCALE = {"LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
#: UTF-8 whatever locale the runner has.
UTF8_MODE = {"PYTHONUTF8": "1"}
E_ACUTE = chr(0xE9)
RIGHT_DOUBLE_QUOTE = chr(0x201D)
REPLACEMENT_CHARACTER = chr(0xFFFD)

REFRESH = "scripts/refresh_governance_evidence.py"
AS_OF = "2026-08-11T00:00:00Z"
REGENERATION = (("--as-of", AS_OF), ("--sync-contracts",), ("--review-binding",))
BINDING = ".nornyx/contracts/evidence/review_binding.json"
AT = "2026-09-03T09:00:00Z"

#: The repaired decode at the evidence tool's root question, and the two ways of
#: taking it back. TEXT MODE: the filesystem codec strictly with nothing caught,
#: which on POSIX is exactly what text mode did (the locale codec and the
#: filesystem codec are one codec there). STRICT UTF-8: the plausible repair.
FS_DECODE = (
    "        text = raw.decode(GIT_TEXT_ENCODING, GIT_TEXT_ERRORS)\n"
    "    except UnicodeDecodeError as exc:\n"
)
TEXT_MODE_DECODE = (
    "        text = raw.decode(GIT_TEXT_ENCODING)\n"
    "    except LookupError as exc:\n"
)
UTF8_DECODE = (
    '        text = raw.decode("utf-8")\n'
    "    except UnicodeDecodeError as exc:\n"
)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "backslashreplace")


def _codecs_of(env: dict) -> tuple[str, str]:
    """The locale codec and the filesystem codec a child with `env` gets."""
    probe = subprocess.run(
        [sys.executable, "-c",
         "import locale, sys; print(locale.getpreferredencoding(False)); "
         "print(sys.getfilesystemencoding())"],
        env=env, capture_output=True, timeout=120, check=True,
    )
    locale_codec, filesystem_codec = probe.stdout.decode("ascii").split()
    return codecs.lookup(locale_codec).name, codecs.lookup(filesystem_codec).name


def _require_non_utf8_codecs(env: dict) -> None:
    """Refuse a specimen that cannot tell the repair from the defect."""
    names = _codecs_of(env)
    assert "utf-8" not in names, (
        f"the child's codecs are {names}: with UTF-8 there, text mode and the "
        "repair decode alike, and this specimen would measure nothing"
    )


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=decode@example.invalid", "-c", "user.name=decode", *args],
        cwd=cwd, capture_output=True, timeout=600, check=True,
    )


def _refresh(tree: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, REFRESH, *args],
        cwd=tree, env=env, capture_output=True, timeout=900, check=False,
    )


def _regenerate(tree: Path, env: dict) -> list:
    """The documented order: stage, build, sync, bind, stage."""
    _git(tree, "add", "-A")
    steps = [_refresh(tree, env, *step) for step in REGENERATION]
    _git(tree, "add", "-A")
    return steps


def _evidence(tree: Path) -> dict[str, bytes]:
    base = tree / ".nornyx" / "contracts"
    return {
        path.relative_to(tree).as_posix(): path.read_bytes()
        for path in sorted(base.rglob("*"))
        if path.is_file()
    }


def _failed_steps(steps: list) -> list:
    """Steps that exited non-zero or wrote a traceback anywhere in stderr."""
    return [
        (step.returncode, _text(step.stderr)[-600:]) for step in steps
        if step.returncode != 0 or "Traceback" in _text(step.stderr)
    ]


@pytest.fixture(scope="module")
def settled(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One faithful copy at a checkout path holding U+00E9, its evidence
    regenerated twice from the SAME state: under UTF-8, then, reset, under the
    C locale. It is left in the second state, staged, for `--verify`."""
    tree = faithful_copy(tmp_path_factory.mktemp("caf" + E_ACUTE))
    utf8 = isolated_env(tree)
    c_locale = {**utf8, **C_LOCALE}
    utf8_steps = _regenerate(tree, utf8)
    utf8_evidence = _evidence(tree)
    _git(tree, "reset", "-q", "--hard", "HEAD")
    _git(tree, "clean", "-fdq")
    c_steps = _regenerate(tree, c_locale)
    return SimpleNamespace(
        tree=tree, utf8=utf8, c_locale=c_locale, utf8_steps=utf8_steps,
        c_steps=c_steps, utf8_evidence=utf8_evidence, c_evidence=_evidence(tree),
    )


def _copy(tree: Path, destination: Path) -> Path:
    shutil.copytree(tree, destination, symlinks=True)
    return destination


# ---------------------------------------------------------------------------
# The evidence tool: git answers the root question in the filesystem codec
# ---------------------------------------------------------------------------


def test_verify_is_intact_in_a_non_ascii_checkout_under_the_c_locale(settled):
    """The specimen: `--verify` reaches a verdict, and the verdict is intact.

    Before the repair it ended in a UnicodeDecodeError traceback raised out of
    `subprocess.run` inside `_git`, before any evidence was read.
    """
    assert any(byte > 0x7F for byte in os.fsencode(str(settled.tree)))
    _require_non_utf8_codecs(settled.c_locale)
    done = _refresh(settled.tree, settled.c_locale, "--verify")
    error = _text(done.stderr)
    assert "Traceback" not in error, error[-1500:]
    assert done.returncode == 0, (done.returncode, error[-1500:])
    report = json.loads(_text(done.stdout))
    assert report["status"] == "pass", report
    assert report["problems"] == []
    assert report["verification"]["integrity_state"] == "intact"


def test_evidence_regenerates_the_same_under_the_c_and_utf8_locales(settled):
    """Build, sync and bind complete in a non-ASCII checkout under the C locale
    -- before the repair the build ended in the same traceback, through
    `_revision` -- and from one starting state equal the UTF-8 regeneration
    byte for byte, but for the review binding's `generated_at`, which is the
    wall clock and not `--as-of`."""
    _require_non_utf8_codecs(settled.c_locale)
    assert _failed_steps(settled.c_steps) == []
    assert _failed_steps(settled.utf8_steps) == []
    assert settled.utf8_evidence.keys() == settled.c_evidence.keys()
    differing = sorted(
        name for name, raw in settled.utf8_evidence.items()
        if settled.c_evidence[name] != raw
    )
    assert set(differing) <= {BINDING}, differing
    if differing:
        utf8_binding = json.loads(settled.utf8_evidence[BINDING])
        c_binding = json.loads(settled.c_evidence[BINDING])
        utf8_binding.pop("generated_at")
        c_binding.pop("generated_at")
        assert utf8_binding == c_binding


def test_restoring_text_mode_at_the_root_question_reddens_the_verify_specimen(
    settled, tmp_path
):
    """The revert control: the repaired decode taken back to text mode's, in a
    copy, turns the specimen red with the defect's own exception and frames."""
    mutant = _copy(settled.tree, tmp_path / ("caf" + E_ACUTE) / "tree")
    mutate(mutant, [(REFRESH, FS_DECODE, TEXT_MODE_DECODE, 1)])
    done = _refresh(mutant, {**isolated_env(mutant), **C_LOCALE}, "--verify")
    error = _text(done.stderr)
    assert done.returncode != 0
    assert "UnicodeDecodeError" in error, error[-1500:]
    assert "in _git\n" in error and "in _repository_root\n" in error, error[-1500:]


def test_a_strict_utf8_decode_is_not_the_repair(settled, tmp_path):
    """The codec is load-bearing, not merely naming one. Strict UTF-8 decodes
    git's answer, and the comparison with ROOT -- which Python decoded with the
    filesystem codec -- then fails to encode it back."""
    mutant = _copy(settled.tree, tmp_path / ("caf" + E_ACUTE) / "tree")
    mutate(mutant, [(REFRESH, FS_DECODE, UTF8_DECODE, 1)])
    done = _refresh(mutant, {**isolated_env(mutant), **C_LOCALE}, "--verify")
    error = _text(done.stderr)
    assert done.returncode != 0
    assert "UnicodeEncodeError" in error, error[-1500:]
    assert "in _same_directory\n" in error, error[-1500:]


def test_a_foreign_enclosing_repository_is_still_refused_under_the_c_locale(
    settled, tmp_path
):
    """Fail-closed is preserved: a governed tree with no repository of its own,
    inside a foreign one at a non-ASCII path, is still refused by name."""
    outer = tmp_path / ("caf" + E_ACUTE + "-outer")
    outer.mkdir()
    _git(outer, "init", "-q")
    inner = outer / "forge"
    shutil.copytree(settled.tree, inner, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    env = {**isolated_env(inner), **C_LOCALE}
    _require_non_utf8_codecs(env)
    done = _refresh(inner, env, "--verify")
    error = _text(done.stderr)
    assert "Traceback" not in error, error[-1500:]
    assert done.returncode != 0
    assert "is not the root of the git repository that encloses it" in error, error[-1500:]


def test_undecodable_git_output_is_refused_not_raised(monkeypatch):
    """The Windows shape, injected: Windows decodes file names as UTF-8 with
    `surrogatepass`, which refuses invalid UTF-8. The tool refuses in its own
    words and says nothing was modified; it neither raises a decode error nor
    hands on text git did not write."""
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    monkeypatch.setattr(refresh, "GIT_TEXT_ENCODING", "utf-8")
    monkeypatch.setattr(refresh, "GIT_TEXT_ERRORS", "surrogatepass")
    monkeypatch.setattr(
        refresh.subprocess, "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, b"/caf\xff/x\n", b""),
    )
    with pytest.raises(SystemExit) as refusal:
        refresh._repository_root()
    message = str(refusal.value)
    assert "cannot be decoded" in message and "nothing was modified" in message


@pytest.mark.parametrize("raw", [
    b"",
    b"0123456789abcdef0123456789abcdef01234567\n",
    b"line\r\nwith\rreturns\n",
    b"src/caf\xc3\xa9.py\n",
    b"fatal: not a git repository (or any of the parent directories): .git\n",
])
def test_on_posix_valid_git_output_reads_as_text_mode_read_it(monkeypatch, raw):
    """For every answer text mode could read, the callers see the same text:
    the same decode on this runner and the same newline translation. git is
    replaced by a child writing these bytes, run with `_git`'s own options, so
    text mode, where `_git` asks for it, really decodes them."""
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    real_run = subprocess.run
    writes = f"sys.stdout.buffer.write({raw!r}); sys.stderr.buffer.write({raw!r})"
    child = [sys.executable, "-c", "import sys; " + writes]
    monkeypatch.setattr(refresh.subprocess, "run",
                        lambda _args, **options: real_run(child, **options))
    answer = refresh._git("status")
    text_mode = raw.decode(locale.getpreferredencoding(False))
    text_mode = text_mode.replace("\r\n", "\n").replace("\r", "\n")
    assert answer.stdout == text_mode
    assert answer.stderr == text_mode


@pytest.mark.parametrize("separator", [chr(0x85), chr(0x2028), chr(0x2029)])
def test_git_answers_are_split_into_lines_at_newlines_only(monkeypatch, separator):
    """A name may hold any character but a newline, so git's answers are split
    at newlines alone -- not at the other boundaries `str.splitlines` knows --
    in the store's status, the evidence tool's root check and its listings."""
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    name = "notes" + separator + ".txt"
    assert capsule_store._tree_changes(f"?? {name}\n") == [f"?? {name}"]
    refused = f"fatal: {name}{separator}fatal: not a git repository\n"
    monkeypatch.setattr(refresh, "_git", lambda *args: subprocess.CompletedProcess(
        args, 128 if "rev-parse" in args else 0, name + "\n", refused))
    with pytest.raises(SystemExit):
        refresh._repository_root()
    monkeypatch.setattr(refresh, "_repository_root", lambda: refresh.ROOT)
    assert refresh._git_lines("ls-files") == [name]


# ---------------------------------------------------------------------------
# The capsule store: every git answer in the filesystem codec, strictly
# ---------------------------------------------------------------------------


STORE_DRIVER = """\
import json
import locale
import os
import sys
from pathlib import Path

from nornyx_forge import capsule_store
from nornyx_forge.capsule import Actor, create_document
from nornyx_forge.experience import start_experience

root, mode = Path(sys.argv[1]), sys.argv[2]
if mode == "revert":
    capsule_store._git_text = lambda raw: raw.decode(locale.getpreferredencoding(False))
store = capsule_store.CapsuleStore(root)
actor = Actor("human", "casey")
at = "2026-09-03T09:00:00Z"
document = create_document("proj-1", "Portal", actor, at)
store.initialize(document, experience=start_experience(actor, at))
snapshot = store.snapshot()
worker_file = os.path.join(os.fsencode(str(root)), b"caf\\xc3\\xa9.txt")
with open(worker_file, "wb") as handle:
    handle.write(b"written by a worker")
if mode == "save":
    try:
        store.save(document, "a worker left a file")
    except capsule_store.CapsuleStoreError as refusal:
        print(json.dumps({"refused": str(refusal)}))
else:
    print(json.dumps({"problems": store.seal_problems(snapshot)}))
"""


def _store_driver(tmp_path: Path, locale_env: dict, mode: str,
                  src: Path = ROOT / "src") -> subprocess.CompletedProcess:
    """A store at a path holding U+00E9, in its own process: a worker names a
    file with U+00E9, and the user's own git configuration writes names
    unquoted (`core.quotePath`). The store keeps no seal directory: its git
    answers are what is measured."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = tmp_path / "gitconfig"
    config.write_text("[core]\n\tquotePath = false\n", encoding="ascii", newline="\n")
    driver = tmp_path / "store_driver.py"
    driver.write_text(STORE_DRIVER, encoding="ascii", newline="\n")
    env = {
        **os.environ, "PYTHONPATH": str(src), "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_NOSYSTEM": "1", **locale_env,
    }
    if locale_env is C_LOCALE:
        _require_non_utf8_codecs(env)
    return subprocess.run(
        [sys.executable, str(driver), str(tmp_path / ("caf" + E_ACUTE) / "capsule"), mode],
        cwd=tmp_path, env=env, capture_output=True, timeout=600, check=False,
    )


def _sealed_store(tmp_path: Path) -> CapsuleStore:
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    actor = Actor("human", "casey")
    store.initialize(create_document("proj-1", "Portal", actor, AT),
                     experience=start_experience(actor, AT))
    return store


def _double(directory: Path, name: str, body: str) -> Path:
    """An executable `name` in `directory` running this interpreter over `body`."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!" + sys.executable + "\n" + body, encoding="ascii", newline="\n")
    path.chmod(0o755)
    return path


def _answers(stdout: bytes = b"", stderr: bytes = b"", code: int = 0) -> str:
    """A double's body that writes exactly these bytes and exits with `code`."""
    return (
        "import sys\n"
        f"sys.stdout.buffer.write({stdout!r})\n"
        f"sys.stderr.buffer.write({stderr!r})\n"
        f"sys.exit({code})\n"
    )


def _relaying(noisy: tuple[str, ...]) -> str:
    """A double that runs the real git, and adds an undecodable byte to the
    error output of the commands named in `noisy`."""
    real = shutil.which("git")
    assert real, "git is required"
    return (
        "import subprocess, sys\n"
        "args = sys.argv[1:]\n"
        f"done = subprocess.run([{real!r}, *args], capture_output=True, timeout=600)\n"
        "sys.stdout.buffer.write(done.stdout)\n"
        f"noisy = any(word in args for word in {noisy!r})\n"
        "sys.stderr.buffer.write(done.stderr + (b'\\xff' if noisy else b''))\n"
        "sys.exit(done.returncode)\n"
    )


def _on_path(patch, directory: Path) -> None:
    patch.setenv("PATH", str(directory) + os.pathsep + os.environ.get("PATH", ""))


def _encodes(texts) -> None:
    """No lone surrogate may reach the onboarding surface's UTF-8 encoder."""
    for text in texts:
        text.encode("utf-8")


def test_the_seal_check_reports_an_undecodable_name_as_a_finding(tmp_path):
    """The specimen, in its own process under the C locale: the store's seal
    check reports a finding and does not raise. Before the repair the porcelain
    answer raised UnicodeDecodeError out of `subprocess.run`."""
    done = _store_driver(tmp_path, C_LOCALE, "repaired")
    error = _text(done.stderr)
    assert done.returncode == 0 and "Traceback" not in error, error[-1500:]
    problems = json.loads(_text(done.stdout))["problems"]
    assert any("working tree" in problem and "decoded" in problem for problem in problems), problems
    _encodes(problems)


def test_the_seal_check_names_the_file_under_a_utf8_locale(tmp_path):
    """The over-reach control: where the name CAN be decoded it is reported by
    name, exactly as before."""
    done = _store_driver(tmp_path, UTF8_MODE, "repaired")
    assert done.returncode == 0, _text(done.stderr)[-1500:]
    problems = json.loads(_text(done.stdout))["problems"]
    assert "the working tree is not clean: ?? caf" + E_ACUTE + ".txt" in problems, problems


def test_a_save_refuses_a_status_answer_it_cannot_decode(tmp_path):
    """The same scenario through `save`, under the C locale: the save is a store
    refusal naming the question. Before the repair the status answer raised
    UnicodeDecodeError out of `subprocess.run`."""
    done = _store_driver(tmp_path, C_LOCALE, "save")
    error = _text(done.stderr)
    assert done.returncode == 0 and "Traceback" not in error, error[-1500:]
    refused = json.loads(_text(done.stdout))["refused"]
    assert refused == "git status --porcelain answered in output that could not be decoded"
    _encodes([refused])


#: The store's refusal of an answer it cannot decode, as its revert control removes it.
UNDECODABLE_ANSWER_REFUSAL = (
    "    if stdout is None:\n"
    "        raise CapsuleStoreError(\n"
    "            f\"git {' '.join(args[:2])} answered in output that could not be decoded\"\n"
    "        )\n"
)


def test_removing_the_store_refusal_reddens_the_save_specimen(tmp_path):
    """The revert control: without the refusal, the answer that cannot be
    decoded reaches `save` as None, and the save breaks on it."""
    mutant = tmp_path / "mutant"
    shutil.copytree(ROOT / "src", mutant / "src", ignore=shutil.ignore_patterns("__pycache__"))
    mutate(mutant, [("src/nornyx_forge/capsule_store.py", UNDECODABLE_ANSWER_REFUSAL, "", 1)])
    done = _store_driver(tmp_path / "child", C_LOCALE, "save", src=mutant / "src")
    error = _text(done.stderr)
    assert done.returncode != 0
    assert "AttributeError: 'NoneType' object has no attribute 'strip'" in error, error[-1500:]


def test_a_store_git_failure_with_undecodable_output_is_a_store_error(tmp_path, monkeypatch):
    """A failing git whose message cannot be decoded is a store refusal like any
    other failure: `CapsuleStoreError`, never a decode error, and no text git
    did not write."""
    _on_path(monkeypatch, _double(tmp_path / "bin", "git",
                                  _answers(stderr=b"fatal: \xff\n", code=128)).parent)
    with pytest.raises(CapsuleStoreError) as refusal:
        capsule_store._run_git(tmp_path, "status", "--porcelain")
    message = str(refusal.value)
    assert "could not be decoded" in message, message
    _encodes([message])


def test_the_seal_check_reports_an_unreadable_git_answer(tmp_path, monkeypatch):
    """A seal check reports; it never raises. An answer about HEAD, or about
    the working tree, that cannot be decoded is a finding naming the question."""
    store = _sealed_store(tmp_path)
    snapshot = store.sealed()
    _on_path(monkeypatch, _double(tmp_path / "bin", "git", _answers(stdout=b"\xff\n")).parent)
    problems = store.seal_problems(snapshot)
    assert any("HEAD" in problem and "decoded" in problem for problem in problems), problems
    assert any("working tree" in problem and "decoded" in problem for problem in problems), problems
    _encodes(problems)


def _restorable(tmp_path: Path):
    store = _sealed_store(tmp_path)
    snapshot = store.sealed()
    (tmp_path / "capsule" / "notes.txt").write_text("stray", encoding="utf-8", newline="\n")
    assert store.seal_problems(snapshot), "the specimen store is not out of its seal"
    return store, snapshot


def test_restore_is_not_derailed_by_undecodable_git_messages(tmp_path, monkeypatch):
    """The honest restore route completes when git's reset and clean messages
    cannot be decoded: only their exit status is read, so they are not decoded."""
    store, snapshot = _restorable(tmp_path)
    _on_path(monkeypatch, _double(tmp_path / "bin", "git", _relaying(("reset", "clean"))).parent)
    revision, notes = store.restore(snapshot)
    assert notes == [], notes
    assert revision == snapshot.revision
    assert store.seal_problems(snapshot) == []


def test_restoring_the_locale_codec_in_the_store_reddens_its_specimens(tmp_path, monkeypatch):
    """The revert control: the store's decode taken back to text mode's -- the
    locale codec, strictly, nothing caught -- turns each specimen red with the
    defect's own exception, and the decode is shown to have been reached."""
    reached = []

    def text_mode(raw: bytes) -> str:
        reached.append(raw)
        return raw.decode(locale.getpreferredencoding(False))

    with monkeypatch.context() as patch:
        patch.setattr(capsule_store, "_git_text", text_mode)
        _on_path(patch, _double(tmp_path / "failing", "git",
                                _answers(stderr=b"fatal: \xff\n", code=128)).parent)
        with pytest.raises(UnicodeDecodeError):
            capsule_store._run_git(tmp_path, "status", "--porcelain")
    assert reached
    store = _sealed_store(tmp_path / "unreadable")
    snapshot = store.sealed()
    with monkeypatch.context() as patch:
        patch.setattr(capsule_store, "_git_text", text_mode)
        _on_path(patch, _double(tmp_path / "junk", "git", _answers(stdout=b"\xff\n")).parent)
        with pytest.raises(UnicodeDecodeError):
            store.seal_problems(snapshot)
    done = _store_driver(tmp_path / "child", C_LOCALE, "revert")
    error = _text(done.stderr)
    assert done.returncode != 0
    assert "UnicodeDecodeError" in error and "in seal_problems\n" in error, error[-1500:]


def test_decoding_restore_output_again_reddens_its_specimen(tmp_path, monkeypatch):
    """The revert control for restore: text mode put back at the reset and
    clean calls alone raises out of the honest restore route."""
    store, snapshot = _restorable(tmp_path)
    real_run = subprocess.run

    def text_mode_at_restore(args, **kwargs):
        if "reset" in args or "clean" in args:
            kwargs["text"] = True
        return real_run(args, **kwargs)

    _on_path(monkeypatch, _double(tmp_path / "bin", "git", _relaying(("reset", "clean"))).parent)
    monkeypatch.setattr(capsule_store.subprocess, "run", text_mode_at_restore)
    with pytest.raises(UnicodeDecodeError):
        store.restore(snapshot)


# ---------------------------------------------------------------------------
# The acceptance gates: the codec each child writes; the verdict its exit
# ---------------------------------------------------------------------------


GATES_DRIVER = """\
import json
import locale
import shutil
import sys
from pathlib import Path

from nornyx_forge import gates

root, ruff, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
shutil.which = lambda name, *args, **kwargs: ruff if name == "ruff" else None
if mode == "revert":
    gates._gate_text = lambda raw, stream, encoding: raw.decode(locale.getpreferredencoding(False))
if mode == "undeclared":
    gates.GATE_OUTPUT_ENCODINGS = {}
results = gates.default_gates(root, quick=True)
print(json.dumps([[list(result.command), result.passed, result.detail] for result in results]))
"""

#: What the ruff double writes: a finding carrying U+201D, as ruff writes it.
RUFF_LINE = "app.py:1:1: E999 quoted " + RIGHT_DOUBLE_QUOTE + " text"


def _gates_driver(tmp_path: Path, mode: str) -> subprocess.CompletedProcess:
    """`default_gates` in its own process under the C locale, with ruff a double
    on PATH and every other optional gate absent."""
    ruff = _double(tmp_path / "bin", "ruff",
                   _answers(stdout=(RUFF_LINE + "\n").encode("utf-8"), code=1))
    driver = tmp_path / "gates_driver.py"
    driver.write_text(GATES_DRIVER, encoding="ascii", newline="\n")
    (tmp_path / "project").mkdir()
    env = {
        **os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": str(ruff.parent) + os.pathsep + os.environ.get("PATH", ""), **C_LOCALE,
    }
    _require_non_utf8_codecs(env)
    return subprocess.run(
        [sys.executable, str(driver), str(tmp_path / "project"), str(ruff), mode],
        cwd=tmp_path, env=env, capture_output=True, timeout=600, check=False,
    )


def _ruff_details(done: subprocess.CompletedProcess) -> list[str]:
    results = json.loads(_text(done.stdout))
    return [detail for command, _passed, detail in results if command[0] == "ruff"]


def _emitter(tmp_path: Path, name: str, **answers) -> tuple[str, ...]:
    script = tmp_path / f"{name}.py"
    script.write_text(_answers(**answers), encoding="ascii", newline="\n")
    return (sys.executable, str(script))


@pytest.mark.parametrize("stdout, stderr, code", [
    (b"plain\n", b"", 0),
    (b"line\r\nwith\rreturns\n", b"warning\n", 1),
    (("caf" + E_ACUTE + " " + RIGHT_DOUBLE_QUOTE + "\n").encode("utf-8"), b"x\n", 0),
])
def test_a_python_gate_child_is_recorded_as_before(tmp_path, stdout, stderr, code):
    """A Python child writes the codec text mode reads, so its gate records
    exactly what text mode recorded: the same detail and the same verdict."""
    command = _emitter(tmp_path, "emit", stdout=stdout, stderr=stderr, code=code)
    gate = gates.run(command, cwd=tmp_path)
    text_mode = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True,
                               timeout=120, check=False)
    assert gate.detail == (text_mode.stdout + text_mode.stderr).strip()
    assert gate.passed is (text_mode.returncode == 0)
    assert gate.returncode == text_mode.returncode == code


def test_a_utf8_gate_child_is_recorded_exactly_under_the_c_locale(tmp_path):
    """The specimen: ruff's UTF-8 is recorded exactly under a non-UTF-8 locale.
    Before the repair text mode raised UnicodeDecodeError out of `run`."""
    done = _gates_driver(tmp_path, "repaired")
    error = _text(done.stderr)
    assert done.returncode == 0 and "Traceback" not in error, error[-1500:]
    assert _ruff_details(done) == [RUFF_LINE]


def test_an_undecodable_gate_stream_is_described_not_rendered(tmp_path):
    """A stream that cannot be decoded is Forge's account of it -- which stream,
    why, where, how long, and the SHA-256 of the exact bytes -- never U+FFFD,
    never text in another codec, and never an exception."""
    emitted = b"before \xff after"
    gate = gates.run(_emitter(tmp_path, "junk", stdout=emitted), cwd=tmp_path)
    assert "stdout could not be decoded as" in gate.detail, gate.detail
    assert "at byte 7" in gate.detail
    assert f"{len(emitted)} bytes" in gate.detail
    assert "sha256:" + hashlib.sha256(emitted).hexdigest() in gate.detail
    assert REPLACEMENT_CHARACTER not in gate.detail and "before" not in gate.detail


@pytest.mark.parametrize("code", [0, 3])
def test_the_gate_verdict_still_comes_from_the_exit_status(tmp_path, code):
    """An account decides nothing: the verdict is the exit status, as before."""
    gate = gates.run(_emitter(tmp_path, "junk", stdout=b"\xff", code=code), cwd=tmp_path)
    assert gate.passed is (code == 0)
    assert gate.returncode == code


def test_restoring_the_locale_codec_in_the_gates_reddens_its_specimens(tmp_path, monkeypatch):
    """The revert controls: text mode's decode put back raises out of `run` for
    both specimens; and without ruff's declared codec its UTF-8 is not recorded
    exactly any more, so the declaration is load-bearing."""
    reached = []

    def text_mode(raw: bytes, stream: str, encoding: str) -> str:
        reached.append(stream)
        return raw.decode(locale.getpreferredencoding(False))

    monkeypatch.setattr(gates, "_gate_text", text_mode)
    with pytest.raises(UnicodeDecodeError):
        gates.run(_emitter(tmp_path, "junk", stdout=b"before \xff after"), cwd=tmp_path)
    assert reached
    reverted = _gates_driver(tmp_path / "reverted", "revert")
    assert reverted.returncode != 0
    assert "UnicodeDecodeError" in _text(reverted.stderr), _text(reverted.stderr)[-1500:]
    undeclared = _gates_driver(tmp_path / "undeclared", "undeclared")
    assert undeclared.returncode == 0, _text(undeclared.stderr)[-1500:]
    (detail,) = _ruff_details(undeclared)
    assert "could not be decoded" in detail and RIGHT_DOUBLE_QUOTE not in detail, detail


# ---------------------------------------------------------------------------
# The repository qualifier (BRD-F-007): git's messages never stop a report
# ---------------------------------------------------------------------------


REVISION = "0123456789abcdef0123456789abcdef01234567"


def _remote_report(repository: str, profile=None) -> QualificationReport:
    """The metadata step, replaced in-process: these tests use no network."""
    return QualificationReport(
        repository=repository, revision="git:" + REVISION, verdict="GO",
        overall_score=90.0, dimensions=(),
    )


def test_the_local_revision_ignores_undecodable_git_messages(tmp_path, monkeypatch):
    """BRD-F-007. The revision is read from git's answer alone: a message git
    writes beside it, decodable or not, cannot stop the qualification."""
    bin_dir = tmp_path / "bin"
    _on_path(monkeypatch, bin_dir)
    _double(bin_dir, "git", _answers(stdout=(REVISION + "\n").encode("ascii"),
                                     stderr=b"warning: \xff\n"))
    assert repo_qualifier._local_git_revision(tmp_path) == "git:" + REVISION
    _double(bin_dir, "git", _answers(stderr=b"fatal: \xff\n", code=128))
    assert repo_qualifier._local_git_revision(tmp_path) is None


def test_an_undecodable_clone_failure_is_reported_not_raised(tmp_path, monkeypatch):
    """BRD-F-007. A deep clone that fails with a message that cannot be decoded
    yields INSUFFICIENT_EVIDENCE, its hard stop an account of the bytes."""
    emitted = b"fatal: could not create work tree dir '\xff'\n"
    _on_path(monkeypatch, _double(tmp_path / "bin", "git",
                                  _answers(stderr=emitted, code=128)).parent)
    monkeypatch.setattr(repo_qualifier, "qualify_remote", _remote_report)
    report = repo_qualifier.qualify_deep_remote("octo/demo")
    assert report.verdict == "INSUFFICIENT_EVIDENCE"
    (stop,) = report.hard_stops
    assert stop.startswith("Deep clone failed: "), stop
    assert "sha256:" + hashlib.sha256(emitted).hexdigest() in stop
    assert REPLACEMENT_CHARACTER not in stop
    _encodes([stop])


def test_a_clone_failure_message_is_recorded_as_before(tmp_path, monkeypatch):
    """The over-reach control: a message that can be decoded is recorded as it
    always was."""
    _on_path(monkeypatch, _double(tmp_path / "bin", "git",
                                  _answers(stderr=b"fatal: repository not found\n",
                                           code=128)).parent)
    monkeypatch.setattr(repo_qualifier, "qualify_remote", _remote_report)
    report = repo_qualifier.qualify_deep_remote("octo/demo")
    assert report.verdict == "INSUFFICIENT_EVIDENCE"
    assert report.hard_stops == ("Deep clone failed: fatal: repository not found",)


def test_restoring_the_locale_codec_in_the_qualifier_reddens_its_specimens(
    tmp_path, monkeypatch
):
    """The revert controls: text mode put back at the qualifier's git calls
    raises out of both specimens; and the decode alone taken back to text
    mode's, and shown reached, raises out of the clone specimen."""
    real_run = subprocess.run

    def text_mode_for_git(args, **kwargs):
        if args and args[0] == "git":
            kwargs["text"] = True
        return real_run(args, **kwargs)

    bin_dir = tmp_path / "bin"
    monkeypatch.setattr(repo_qualifier, "qualify_remote", _remote_report)
    with monkeypatch.context() as patch:
        _on_path(patch, bin_dir)
        patch.setattr(repo_qualifier.subprocess, "run", text_mode_for_git)
        _double(bin_dir, "git", _answers(stdout=(REVISION + "\n").encode("ascii"),
                                         stderr=b"warning: \xff\n"))
        with pytest.raises(UnicodeDecodeError):
            repo_qualifier._local_git_revision(tmp_path)
        _double(bin_dir, "git", _answers(stderr=b"fatal: \xff\n", code=128))
        with pytest.raises(UnicodeDecodeError):
            repo_qualifier.qualify_deep_remote("octo/demo")
    reached = []
    with monkeypatch.context() as patch:
        _on_path(patch, bin_dir)
        patch.setattr(repo_qualifier, "_git_text", lambda raw: reached.append(raw) or (
            raw.decode(locale.getpreferredencoding(False))))
        with pytest.raises(UnicodeDecodeError):
            repo_qualifier.qualify_deep_remote("octo/demo")
    assert reached


# ---------------------------------------------------------------------------
# The lint: every call that still decodes with the locale codec is listed
# ---------------------------------------------------------------------------


#: Every subprocess call under src/ and scripts/ that decodes in text mode with
#: no named codec, keyed by file and enclosing function, with why it may.
TEXT_MODE_WITHOUT_A_CODEC = {
    ("scripts/build_windows_bundle.py", "_installer_command"):
        "only the exit status of `pip --version` is read, but text mode also decodes its "
        "standard error (limitation 9)",
    ("scripts/build_windows_bundle.py", "_source_commit"):
        "standard output is a 40-hex commit, ASCII in every codec; standard error is "
        "also decoded (limitation 9); informational, never authority",
    ("scripts/build_windows_bundle.py", "verify_bundle"):
        "the bundle's own Python writes the codec this process reads (a path "
        "outside the ANSI code page makes the child refuse: a stated limitation)",
    ("scripts/check_pre_approval_baseline.py", "_regenerate"):
        "a Python child with this environment: ASCII JSON on stdout, stderr "
        "written with backslashreplace, text printed only on failure",
    ("scripts/refresh_governance_evidence.py", "_architecture_report"):
        "a Python child with this environment printing ASCII JSON",
    ("scripts/smoke_http.py", "main"):
        "nothing is piped: the server writes to a file read with a named codec",
    ("src/nornyx_forge/gates.py", "trusted_greenfield_gates"):
        "a Python child printing ASCII JSON; it writes stderr only when already "
        "failing, and a strict non-UTF-8 parent reading non-ASCII there is a "
        "stated limitation",
    ("src/nornyx_forge/policy.py", "DemoPolicyEngine.validate_contract"):
        "no production caller; the Nornyx CLI's source prints through the default "
        "text stream, so it is read in this process's codec (not measured on Windows)",
}

#: Every call under src/ and scripts/ that passes a keyword named `text` or
#: `universal_newlines`, that the lint therefore reports as a call it cannot judge, and
#: that is listed here with why it needs no judging. An entry is keyed by the file, the
#: qualified name of the enclosing scope and the spelling of the callee
#: (`ast.unparse` of the call's function), never by line.
#:
#: WHAT IS HELD, both ways, like the list above: a call with a text keyword that no
#: entry names (by file, scope and callee spelling) is reported; an entry that does not
#: match exactly one such call is stale; two matches are reported. WHAT IS NOT HELD: that
#: the call starts no child. That is the entry's stated reason, read by a reviewer, and
#: the lint does not check it: a call with the listed callee spelling in the listed scope
#: satisfies the entry, whatever it does.
NOT_A_CHILD_PROCESS = {
    ("scripts/rehearse_entrypoint.py", "observe", "streams[name].update"):
        "a dict update whose keyword is named text; no child process",
}

_STARTERS = frozenset({"run", "Popen", "call", "check_output", "check_call"})
#: Names in `subprocess` that start no process.
_INERT = frozenset({"PIPE", "DEVNULL", "STDOUT", "CompletedProcess", "TimeoutExpired",
                    "CalledProcessError", "SubprocessError", "list2cmdline"})


def _qualified_names(tree: ast.AST) -> dict[ast.AST, str]:
    names: dict[ast.AST, str] = {}

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = (*scope, child.name)
            names[child] = ".".join(inner) or "<module>"
            visit(child, inner)

    visit(tree, ())
    return names


def _text_mode_verdict(call: ast.Call) -> bool | None:
    """Whether a direct call decodes in text mode with no named codec; None
    when its arguments are expanded or its text flag is not a constant."""
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    flags = [keywords[name] for name in ("text", "universal_newlines") if name in keywords]
    if None in keywords or len(call.args) > 1 or any(
            isinstance(arg, ast.Starred) for arg in call.args) or any(
            not isinstance(flag, ast.Constant) for flag in flags):
        return None
    encoding = keywords.get("encoding")
    named = encoding is not None and not (
        isinstance(encoding, ast.Constant) and encoding.value is None)
    text_mode = any(flag.value for flag in flags) or "encoding" in keywords or (
        "errors" in keywords)
    return text_mode and not named


def _decoding_lint(source: str, relative: str) -> tuple[list[tuple[str, str]], list[str]]:
    """`_lint` with the text-keyword reports as sentences: what a caller that does
    not disposition them sees."""
    found, unjudged, flagged = _lint(source, relative)
    return found, unjudged + [message for _site, message in flagged]


def _lint(source: str, relative: str) -> tuple[list, list[str], list[tuple[tuple, str]]]:
    """(file, function) of every call that decodes a child's output with the
    locale codec, every reference this lint cannot judge, and, apart, every `text`
    or `universal_newlines` keyword on a call it did not judge, as
    ((file, qualified scope, callee spelling), sentence).

    A LINT OVER NAMES, not spellings. Every name `subprocess`, and every
    attribute named `subprocess` or `popen`, is judged or reported. Judged: a
    direct call to one of `_STARTERS`, by its arguments; `os.popen`, always text
    mode with the locale codec; a name in `_INERT`. Reported: any other use
    of `subprocess` (an alias, a starter passed as a value, `getoutput`, an
    attribute chain); `subprocess` or `os` imported under another name; any
    import from `subprocess`, and `popen` or `*` from `os`; a direct call whose
    arguments are expanded or whose text flag is not a constant; and a `text` or
    `universal_newlines` keyword on any call not judged, unless an entry of
    `NOT_A_CHILD_PROCESS` names its file, scope and callee spelling. `os.system`, `os.exec*` and `os.spawn*` capture no
    output and pass. A module reached through a string is not seen.
    """
    tree = ast.parse(source)
    names = _qualified_names(tree)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    found: list[tuple[str, str]] = []
    unjudged: list[str] = []
    judged: set[ast.AST] = set()
    for node in ast.walk(tree):
        why = ""
        if isinstance(node, ast.Import) and any(
                alias.name in ("subprocess", "os") and alias.asname not in (None, alias.name)
                for alias in node.names):
            why = "imports subprocess or os under another name"
        elif isinstance(node, ast.ImportFrom) and (node.module == "subprocess" or (
                node.module == "os" and any(alias.name in ("popen", "*") for alias in node.names))):
            why = f"imports names from {node.module}"
        elif isinstance(node, ast.Attribute) and node.attr in ("subprocess", "popen"):
            if node.attr == "popen" and getattr(node.value, "id", None) == "os":
                found.append((relative, names[node]))
            else:
                why = f"reaches {node.attr} through an attribute"
        elif isinstance(node, ast.Name) and node.id == "subprocess":
            attribute = parents[node]
            name = getattr(attribute, "attr", None)
            call = parents.get(attribute)
            if name in _STARTERS and isinstance(call, ast.Call) and call.func is attribute:
                judged.add(call)
                verdict = _text_mode_verdict(call)
                if verdict:
                    found.append((relative, names[call]))
                why = "passes arguments this lint cannot judge" if verdict is None else ""
            elif name not in _INERT:
                why = f"uses subprocess.{name}" if name else "uses subprocess by name"
        if why:
            unjudged.append(f"{relative}:{node.lineno} {why}")
    flagged = [
        ((relative, names[node], ast.unparse(node.func)),
         f"{relative}:{node.lineno} passes a text flag to a call this lint cannot judge")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node not in judged
        and any(keyword.arg in ("text", "universal_newlines") for keyword in node.keywords)
    ]
    return found, unjudged, flagged


def _judge(found: list[tuple[str, str]], listed) -> tuple[list, list, list]:
    """Unlisted calls, listed entries that match no call, and entries matched twice."""
    unlisted = sorted(set(found) - set(listed))
    stale = sorted(set(listed) - set(found))
    repeated = sorted({site for site in found if found.count(site) > 1})
    return unlisted, stale, repeated


def _scan(root: Path, files: list[Path]) -> dict:
    """The lint over `files` (under `root`) against both lists: what is unjudged, and
    what each list holds wrong (unlisted, stale, repeated)."""
    found: list[tuple[str, str]] = []
    unjudged: list[str] = []
    text_keyword: list[tuple[str, str, str]] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        more, cannot, flagged = _lint(path.read_text(encoding="utf-8"), relative)
        found += more
        unjudged += cannot
        text_keyword += [site for site, _message in flagged]
    return {
        "unjudged": unjudged,
        "text_mode": _judge(found, TEXT_MODE_WITHOUT_A_CODEC),
        "not_a_child": _judge(text_keyword, NOT_A_CHILD_PROCESS),
    }


CLEAN = {"unjudged": [], "text_mode": ([], [], []), "not_a_child": ([], [], [])}


def test_every_locale_decoding_subprocess_site_is_dispositioned():
    """Every call under src/ and scripts/ the lint finds decoding with the
    locale codec is listed with its reason, every listed entry is still exactly
    one call, and nothing is left unjudged: a new site the lint can see cannot
    appear, and a listed one cannot leave, silently. The same holds for the calls
    that pass a text keyword and are listed as needing no judging."""
    files = sorted(
        path for directory in ("src", "scripts") for path in (ROOT / directory).rglob("*.py")
    )
    assert len(files) >= 60, f"only {len(files)} files were found; the scope stopped matching"
    assert _scan(ROOT, files) == CLEAN
    assert all(reason for reason in NOT_A_CHILD_PROCESS.values())


def test_the_second_list_is_held_by_file_scope_and_callee_both_ways(tmp_path):
    """The second list, on scratch files. The listed call alone is quiet. Swapping it for
    a child-starting call with a text keyword in the same scope, which is the swap that
    a list keyed by scope alone let through, makes the entry stale and the new call
    unlisted; so does another `update(text=...)` of a different receiver added beside it,
    and a second call of the listed spelling is a repeat. A listed entry whose call is
    gone is stale; an unlisted call in a new file is reported. What is not held is that a
    call of the listed spelling starts no child: that is the entry's reason."""
    listed_file, scope, callee = next(iter(NOT_A_CHILD_PROCESS))
    where = tmp_path / listed_file
    where.parent.mkdir(parents=True, exist_ok=True)
    entry = (listed_file, scope, callee)

    def scan(body: str) -> dict:
        where.write_text(f"def {scope}(streams, name):\n{body}", encoding="utf-8", newline="\n")
        return _scan(tmp_path, [where])

    listed_call = f"    {callee}(x=1, text='x')\n"
    quiet = scan(listed_call)
    assert quiet["unjudged"] == [] and quiet["not_a_child"] == ([], [], [])
    swapped = scan("    _spawn(['/bin/true'], 5, text=True)\n")
    assert swapped["not_a_child"] == ([(listed_file, scope, "_spawn")], [entry], [])
    beside = scan(listed_call + "    other.update(text='x')\n")
    assert beside["not_a_child"] == ([(listed_file, scope, "other.update")], [], [])
    twice = scan(listed_call + f"    {callee}(text='y')\n")
    assert twice["not_a_child"] == ([], [], [entry])
    gone = scan("    streams[name].update(x=1)\n")
    assert gone["not_a_child"] == ([], [entry], [])
    stray = tmp_path / "scripts" / "stray.py"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_text("def f(d):\n    d.update(text='x')\n", encoding="utf-8", newline="\n")
    assert _scan(tmp_path, [stray])["not_a_child"][0] == [("scripts/stray.py", "f", "d.update")]
    # still unjudged where the list is not asked: the sentence a reader sees
    assert _decoding_lint(stray.read_text(encoding="utf-8"), "scripts/stray.py")[1] == [
        "scripts/stray.py:2 passes a text flag to a call this lint cannot judge"]


@pytest.mark.parametrize("source, flagged, unjudged", [
    ("import subprocess\nsubprocess.run(c, text=True)\n", 1, 0),
    ("import subprocess\nsubprocess.run(c, universal_newlines=True)\n", 1, 0),
    ("import subprocess\nsubprocess.run(c, errors='replace')\n", 1, 0),
    ("import subprocess\nsubprocess.run(c, text=True, encoding=None)\n", 1, 0),
    ("import subprocess\nsubprocess.Popen(c, text=True)\n", 1, 0),
    ("import subprocess\ndef f():\n    subprocess.check_output(c, text=True)\n", 1, 0),
    ("import subprocess\nsubprocess.run(c, text=True, encoding='utf-8')\n", 0, 0),
    ("import subprocess\nsubprocess.run(c, encoding=codec)\n", 0, 0),
    ("import subprocess\nsubprocess.run(c, capture_output=True)\n", 0, 0),
    ("import subprocess\nsubprocess.run(c, text=False)\n", 0, 0),
    ("import subprocess\nsubprocess.run(c, **options)\n", 0, 1),
    ("import subprocess\nsubprocess.run(*c)\n", 0, 1),
    ("import subprocess\nsubprocess.run(c, text=flag)\n", 0, 1),
    ("import subprocess as sp\nsp.run(c, text=True)\n", 0, 2),
    ("from subprocess import run\nrun(c, text=True)\n", 0, 2),
    ("import subprocess\nsubprocess.getoutput(c)\n", 0, 1),
    ("import subprocess\nsubprocess.getstatusoutput(c)\n", 0, 1),
    ("import os\nos.popen(c).read()\n", 1, 0),
    ("import subprocess\nrun = subprocess.run\nrun(c, text=True)\n", 0, 2),
    ("import functools, subprocess\nfunctools.partial(subprocess.run, text=True)\n", 0, 2),
    ("x.s.run(c, text=True)\n", 0, 1),
    ("import subprocess\nsp = subprocess\n", 0, 1),
    ("import subprocess\ngetattr(subprocess, 'run')(c)\n", 0, 1),
    ("x.subprocess.run(c)\n", 0, 1),
    ("import os as o\no.popen(c)\n", 0, 2),
    ("from os import popen\npopen(c)\n", 0, 1),
    ("import os\nos.system(c)\nos.execvp(f, a)\nos.spawnv(m, f, a)\n", 0, 0),
    ("import subprocess\nsubprocess.run(c, stdout=subprocess.PIPE)\n", 0, 0),
])
def test_the_decoding_lint_fires_on_each_shape(source, flagged, unjudged):
    """The lint on synthetic sources: each shape flagged, passed or reported as
    one it cannot judge, as declared; and the list is held in both directions."""
    found, cannot = _decoding_lint(source, "specimen.py")
    assert (len(found), len(cannot)) == (flagged, unjudged)
    site = ("specimen.py", "<module>")
    assert _judge([site], {}) == ([site], [], [])
    assert _judge([], {site: "listed"}) == ([], [site], [])
    assert _judge([site, site], {site: "listed"}) == ([], [], [site])
