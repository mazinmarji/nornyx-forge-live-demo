r"""The opt-in provider start through the hash-pinned run-act gate.

What is held here, and how. No provider is started and no gate is run: every
test that reaches the start replaces the runner with a recorder, or -- in the
Windows-only tests -- starts a real `powershell.exe -File` on a STUB written
by this module, which has the gate's parameter names and nothing else of it.
It reads no credential and starts no process; it reports what each parameter
received, as base64 of UTF-8. The Windows-only tests measure TRANSPORT ONLY:
that the vector this module builds reaches a PowerShell 5.1 parameter block as
it was sent. They establish nothing about the gate itself.

Groups:

- the pin and the exact vector, for each worker, against the vector the same
  worker builds on today's path;
- `launch=None` as today, for each worker: the same result, the same
  `subprocess.run` call, `_provider_env()` and the timeout, and the gate code
  never reached;
- the refusals, each before any process: a mismatched or unreadable script,
  no console, no system directory, every malformed field, a `-ProviderArgs`
  value PowerShell would read as a parameter name, a NUL, an over-long line;
- the environment: constructed, the allowlist only, no key name or value, and
  PowerShell named by the system directory, never by PATH or SystemRoot;
- the exit-code mapping through an injected runner, and the script's hold
  released after the run and on every refusal after the read;
- eligibility unchanged in both modes;
- on Windows: the round trip through a real `powershell.exe -File` (quotes,
  newlines, non-ASCII), the refused class shown misbound by PowerShell, the
  held script refusing writers while PowerShell still reads it, the console
  check refusing a NUL device and a pipe, and the system directory read from
  the operating system.
"""

from __future__ import annotations

import ast
import base64
import dataclasses
import hashlib
import inspect
import os
import subprocess
import sys
from pathlib import Path, PureWindowsPath

import pytest

from nornyx_forge import claude_worker, codex_worker, provider_gate
from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.codex_worker import CodexWorker
from nornyx_forge.provider_contract import (
    PROVIDER_CONFINEMENT,
    TIMEOUT_RETURNCODE,
    UNAVAILABLE_RETURNCODE,
    classify_result,
    governed_build_eligibility,
    result_from_worker,
)
from nornyx_forge.provider_gate import (
    GATE_ENVIRONMENT_INHERITED,
    GateLaunch,
    LaunchVia,
    build_gate_argv,
    build_gate_environment,
)

ROOT = Path(__file__).resolve().parents[1]

#: Written out here, not read from the module: the value the reviewed gate
#: script hashes to. A change to the module's constant is a red test.
REVIEWED_RUN_ACT_SHA256 = "8830b243ff911a5c1aaaa026cb30a259d8bfc070ae6e6753a2096f8b1c7441e1"

SYSTEM = "C:\\Windows\\System32"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
#: Absolute by this host's rules, as the script path must be: it is opened here.
GATE = str(Path(ROOT.anchor, "Gate Zone", "gate", "run-act.ps1"))
CLAUDE_EXE = "C:\\Provider Zone\\claude\\claude.exe"
CODEX_EXE = "C:\\Provider Zone\\codex\\codex.exe"

windows_only = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows is the subject: these start a real Windows PowerShell 5.1 on a stub, "
           "hold a file with a Windows share mode, and read the console and system "
           "directory through kernel32; the windows-runtime CI job runs them all",
)


class Recorder:
    """The injected runner: records what would have been started, starts nothing."""

    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls: list[tuple[tuple[str, ...], dict[str, str], str]] = []

    def __call__(self, argv, env, cwd):
        self.calls.append((argv, env, cwd))
        return self.returncode


@pytest.fixture
def script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stand-in script whose digest the pin is patched to, so the hash check
    passes and the start is reached. Tests of the real pin use other bytes."""
    path = tmp_path / "stand-in-gate.ps1"
    path.write_bytes(b"# a stand-in; never executed by these tests\n")
    monkeypatch.setattr(provider_gate, "PINNED_RUN_ACT_SHA256",
                        hashlib.sha256(path.read_bytes()).hexdigest())
    return path


@pytest.fixture
def seams(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """The Windows-only defaults replaced, for a run on any host: a system
    directory, a console, and a recording runner. The script read is the real
    one."""
    recorder = Recorder()
    monkeypatch.setattr(provider_gate, "_system_directory", lambda: SYSTEM)
    monkeypatch.setattr(provider_gate, "_has_console", lambda: True)
    monkeypatch.setattr(provider_gate, "_run_on_console", recorder)
    return recorder


def _launch(gate: str | Path = GATE, exe: str = CLAUDE_EXE, role: str = "claude",
            policy: str = "Bypass") -> GateLaunch:
    return GateLaunch(gate_script=str(gate), provider_exe=exe, role=role,
                      execution_policy=policy)


def _direct_command(monkeypatch: pytest.MonkeyPatch, worker, workspace: Path) -> tuple[str, ...]:
    """The vector the worker hands `subprocess.run` on today's path, captured
    without starting anything."""
    seen: list[tuple[str, ...]] = []

    def fake_run(command, **kwargs):
        seen.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", fake_run)
        worker.run(role="builder", goal='build "it"\nnow', workspace=workspace,
                   allowed_tools=("Read", "Write"), max_turns=7, timeout_seconds=30)
    [command] = seen
    return command


def _run_gate(worker, workspace: Path):
    return worker.run(role="builder", goal='build "it"\nnow', workspace=workspace,
                      allowed_tools=("Read", "Write"), max_turns=7, timeout_seconds=30)


def _no_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any process start anywhere in this test fails it."""
    def refuse(*args, **kwargs):
        raise AssertionError("a process was started")
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)


def _refused(result) -> None:
    assert result.success is False
    assert result.returncode == provider_gate.REFUSED_BEFORE_START_RETURNCODE
    assert "refused before any process started" in result.output


# ---------------------------------------------------------------------------
# The pin and the exact vector
# ---------------------------------------------------------------------------

def test_the_pin_is_the_reviewed_gate_script_digest():
    assert provider_gate.PINNED_RUN_ACT_SHA256 == REVIEWED_RUN_ACT_SHA256
    assert {member.name: member.value for member in LaunchVia} == {
        "DIRECT": "direct", "D3G_GATE": "d3g_gate"}
    assert _launch().via is LaunchVia.D3G_GATE
    assert dataclasses.fields(GateLaunch)[0].name == "gate_script"
    assert [field.name for field in dataclasses.fields(GateLaunch)] == [
        "gate_script", "provider_exe", "role", "execution_policy"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        _launch().role = "codex"  # type: ignore[misc]


@pytest.mark.parametrize("worker_class, exe, role", [
    (ClaudeCodeWorker, CLAUDE_EXE, "claude"),
    (CodexWorker, CODEX_EXE, "codex"),
], ids=["claude", "codex"])
def test_the_gate_vector_is_exact_and_carries_todays_worker_arguments(
        worker_class, exe, role, tmp_path, monkeypatch, script, seams):
    """The whole vector, element by element, for each worker; `-ProviderArgs`
    is list2cmdline of exactly the arguments the same worker builds today."""
    monkeypatch.setattr(worker_class, "available", lambda self: True)
    direct = _direct_command(monkeypatch, worker_class(exe), tmp_path)
    result = _run_gate(worker_class(exe, launch=_launch(script, exe, role)), tmp_path)
    [(argv, env, cwd)] = seams.calls
    assert argv == (
        POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
        "-Action", "Run", "-AuthorizedSha256", provider_gate.PINNED_RUN_ACT_SHA256,
        "-Role", role, "-ProviderExe", exe,
        "-ProviderArgs", subprocess.list2cmdline(direct[1:]),
    )
    assert direct[0] == exe and result.command == argv and cwd == SYSTEM
    assert result.success is False and result.returncode == provider_gate.GATE_RAN_RETURNCODE


def test_build_gate_argv_spells_only_the_run_action():
    """The vector's literals, read from the code: the nine parameter names and
    `Run`. No other action, and no switch, is spelled where the vector is built."""
    tree = ast.parse(inspect.getsource(build_gate_argv).strip())
    literals = [node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    assert [value for value in literals if value.startswith("-") or value == "Run"] == [
        "-NoProfile", "-ExecutionPolicy", "-File", "-Action", "Run", "-AuthorizedSha256",
        "-Role", "-ProviderExe", "-ProviderArgs"]
    argv = build_gate_argv(_launch(), ("-p", "x y"), system_dir=SYSTEM)
    for absent in ("-NoCredential", "RecordStep7", "Release", "CloseNothingReleased",
                   "-Step7Result", "-Confirmation", "-CycleId"):
        assert absent not in argv


# ---------------------------------------------------------------------------
# launch=None is today's path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("worker_class, module", [
    (ClaudeCodeWorker, claude_worker), (CodexWorker, codex_worker)], ids=["claude", "codex"])
def test_launch_none_starts_the_provider_exactly_as_today(worker_class, module, tmp_path,
                                                          monkeypatch):
    """The default and an explicit None make the same `subprocess.run` call --
    the vector, `cwd`, capture, the timeout and `_provider_env()` -- give equal
    results, and never reach the gate code."""
    monkeypatch.setenv("FORGE_SECRET_DECOY", "decoy")
    monkeypatch.setattr(worker_class, "available", lambda self: True)

    def gate_reached(*args, **kwargs):
        raise AssertionError("the gate path was reached with launch=None")
    monkeypatch.setattr(module, "launch_through_gate", gate_reached)
    calls: list[tuple[tuple[str, ...], dict]] = []

    def fake_run(command, **kwargs):
        calls.append((tuple(command), kwargs))
        return subprocess.CompletedProcess(command, 0, b'{"session_id": "s-1"}', b"")
    monkeypatch.setattr(subprocess, "run", fake_run)
    results = [worker.run(role="builder", goal="g", workspace=tmp_path,
                          allowed_tools=("Read",), max_turns=3, timeout_seconds=41)
               for worker in (worker_class("tool"), worker_class("tool", launch=None))]
    assert results[0] == results[1]
    assert calls[0] == calls[1]
    command, kwargs = calls[0]
    assert command[0] == "tool"
    assert kwargs == {"cwd": tmp_path, "capture_output": True, "check": False,
                      "timeout": 41, "env": module._provider_env()}
    assert "FORGE_SECRET_DECOY" not in kwargs["env"]
    assert worker_class("tool").launch is None


# ---------------------------------------------------------------------------
# Refusals, each before any process
# ---------------------------------------------------------------------------

def test_a_script_whose_bytes_are_not_the_pinned_bytes_is_refused_before_any_process(
        tmp_path, monkeypatch, seams):
    """The REAL pin, against a script with other bytes: refused, the digest
    named, and no process started anywhere."""
    gate = tmp_path / "run-act.ps1"
    gate.write_bytes(b"Write-Output 'not the reviewed gate'\r\n")
    monkeypatch.setattr(ClaudeCodeWorker, "available", lambda self: True)
    _no_process(monkeypatch)
    result = _run_gate(ClaudeCodeWorker(CLAUDE_EXE, launch=_launch(gate)), tmp_path)
    _refused(result)
    assert hashlib.sha256(gate.read_bytes()).hexdigest() in result.output
    assert REVIEWED_RUN_ACT_SHA256 in result.output
    assert seams.calls == []


@pytest.mark.parametrize("shape", ["missing", "directory"])
def test_a_script_that_is_not_one_regular_file_is_refused_before_any_process(
        shape, tmp_path, monkeypatch, seams):
    gate = tmp_path / "gate.ps1"
    if shape == "directory":
        gate.mkdir()
    monkeypatch.setattr(ClaudeCodeWorker, "available", lambda self: True)
    _no_process(monkeypatch)
    result = _run_gate(ClaudeCodeWorker(CLAUDE_EXE, launch=_launch(gate)), tmp_path)
    _refused(result)
    assert "could not be read as one regular file" in result.output
    assert seams.calls == []


def test_no_console_is_refused_before_the_script_is_read_or_anything_starts(
        tmp_path, monkeypatch, script, seams):
    monkeypatch.setattr(provider_gate, "_has_console", lambda: False)
    read: list[str] = []
    monkeypatch.setattr(provider_gate, "_read_script", lambda path: read.append(path))
    monkeypatch.setattr(CodexWorker, "available", lambda self: True)
    result = _run_gate(CodexWorker(CODEX_EXE, launch=_launch(script, CODEX_EXE, "codex")),
                       tmp_path)
    _refused(result)
    assert "no console input" in result.output
    assert seams.calls == [] and read == []


def test_a_host_with_no_system_directory_is_refused(tmp_path, monkeypatch, script, seams):
    monkeypatch.setattr(provider_gate, "_system_directory", lambda: None)
    monkeypatch.setattr(ClaudeCodeWorker, "available", lambda self: True)
    result = _run_gate(ClaudeCodeWorker(CLAUDE_EXE, launch=_launch(script)), tmp_path)
    _refused(result)
    assert "only on Windows" in result.output and result.command == ()
    assert seams.calls == []


def test_the_real_defaults_report_a_system_directory_and_a_console_only_on_windows():
    """Off Windows the defaults answer None and False, so the gate path refuses
    there before reading anything."""
    if os.name == "nt":
        assert PureWindowsPath(provider_gate._system_directory()).is_absolute()
    else:
        assert provider_gate._system_directory() is None
        assert provider_gate._has_console() is False


@pytest.mark.parametrize("change, expected", [
    ({"execution_policy": "Bypass -NoCredential"}, "execution policy"),
    ({"execution_policy": "bypass"}, "execution policy"),
    ({"role": "-NoCredential"}, "role"),
    ({"role": ""}, "role"),
    ({"role": "claude codex"}, "role"),
    ({"role": "c" * 65}, "role"),
    ({"gate_script": "gate\\run-act.ps1"}, "gate_script"),
    ({"gate_script": "C:\\gate\\run\"act.ps1"}, "gate_script"),
    ({"gate_script": "C:\\gate\\run\0act.ps1"}, "gate_script"),
    ({"provider_exe": "claude.exe"}, "provider_exe"),
    ({"role": 7}, "role is not a string"),
], ids=["policy-with-switch", "policy-case", "role-dash", "role-empty", "role-space",
        "role-long", "gate-relative", "gate-quote", "gate-nul", "exe-relative", "role-type"])
def test_every_malformed_field_is_refused_before_any_process(change, expected, tmp_path,
                                                             monkeypatch, seams):
    _no_process(monkeypatch)
    fields = {"gate_script": GATE, "provider_exe": CLAUDE_EXE, "role": "claude",
              "execution_policy": "Bypass", **change}
    result = provider_gate.launch_through_gate(
        GateLaunch(**fields), (fields["provider_exe"], "-p", "x y"),
        role="builder", goal="g", worker="Claude Code worker")
    _refused(result)
    assert expected in result.output
    assert seams.calls == []


def test_a_launch_that_is_not_a_gate_launch_and_a_mismatched_executable_are_refused(
        tmp_path, monkeypatch, seams):
    """The worker's executable must be the gate's provider executable, so the
    recorded command and what the gate starts name one file."""
    _no_process(monkeypatch)
    monkeypatch.setattr(ClaudeCodeWorker, "available", lambda self: True)
    result = _run_gate(ClaudeCodeWorker("claude", launch=_launch()), tmp_path)
    _refused(result)
    assert "is not the gate's provider executable" in result.output
    result = _run_gate(ClaudeCodeWorker(CLAUDE_EXE, launch={"gate_script": GATE}), tmp_path)
    _refused(result)
    assert "not a GateLaunch" in result.output
    for command in ((CLAUDE_EXE, 7), CLAUDE_EXE, ()):
        result = provider_gate.launch_through_gate(_launch(), command, role="r", goal="g",
                                                   worker="w")
        _refused(result)
    assert seams.calls == []


@pytest.mark.parametrize("args, refused", [
    (("-NoCredential",), True),
    (("-",), True),
    (("--",), True),
    (("\u2013NoCredential",), True),
    (("\u2014NoCredential",), True),
    (("\u2015NoCredential",), True),
    (('-p"x"',), True),
    (("-NoCredential x",), False),
    (("-p", "x"), False),
    (("exec",), False),
    (("/NoCredential",), False),
], ids=["switch", "dash", "dash-dash", "en-dash", "em-dash", "horizontal-bar",
        "dash-quote", "quoted-switch", "two-args", "plain", "slash"])
def test_provider_args_powershell_would_read_as_a_parameter_name_are_refused(
        args, refused, tmp_path, monkeypatch, script, seams):
    """Measured through a real `powershell.exe -File` (the Windows test below
    repeats it): an UNQUOTED value that begins with a dash PowerShell reads is
    bound as a parameter name. list2cmdline quotes a value only for a space, a
    tab or emptiness."""
    result = provider_gate.launch_through_gate(
        _launch(script), (CLAUDE_EXE, *args), role="builder", goal="g",
        worker="Claude Code worker")
    if refused:
        _refused(result)
        assert "read as a parameter name" in result.output
        assert seams.calls == []
    else:
        assert len(seams.calls) == 1 and result.returncode == provider_gate.GATE_RAN_RETURNCODE


def test_a_nul_an_over_long_line_and_trailing_whitespace_are_refused_before_any_process(
        tmp_path, monkeypatch, script, seams):
    """Trailing whitespace: measured through a real `powershell.exe -File`
    (the Windows test below repeats it), a quoted value loses its last
    character when that is whitespace; inside the value it survives."""
    _no_process(monkeypatch)
    for last in ("\n", "\r", "\x0b", "\x0c", "\x85", "\xa0", "\u2028", "\u2029", "\u3000"):
        for args in (("-p", "x" + last), ("x" + last,)):
            trailing = provider_gate.launch_through_gate(
                _launch(script), (CLAUDE_EXE, *args), role="builder", goal="g",
                worker="Claude Code worker")
            _refused(trailing)
            assert "drops trailing whitespace" in trailing.output, (args, trailing.output)
    inner = build_gate_argv(_launch(script), ("-p", "goal ends\n", "--allowedTools", "Read"),
                            system_dir=SYSTEM)
    assert provider_gate._argv_problem(inner) is None
    nul = provider_gate.launch_through_gate(
        _launch(script), (CLAUDE_EXE, "-p", "a\0b c"), role="builder", goal="g",
        worker="Claude Code worker")
    _refused(nul)
    assert "holds a NUL" in nul.output
    long = provider_gate.launch_through_gate(
        _launch(script), (CLAUDE_EXE, "-p", "x " * 16400), role="builder", goal="g",
        worker="Claude Code worker")
    _refused(long)
    assert "over Windows' 32767" in long.output
    assert seams.calls == []


# ---------------------------------------------------------------------------
# The environment, and PowerShell's own path
# ---------------------------------------------------------------------------

def test_no_key_name_or_value_reaches_the_vector_or_the_environment(tmp_path, monkeypatch,
                                                                    script, seams):
    secrets = {"OPENAI_API_KEY": "sk-openai-sentinel", "ANTHROPIC_API_KEY": "sk-ant-sentinel",
               "CODEX_HOME": "C:\\secret-codex-home", "CLAUDE_CONFIG_DIR": "C:\\secret-claude",
               "FORGE_TOKEN": "forge-bearer-sentinel", "FORGE": "bare-forge-sentinel",
               "forge_lower": "lower-forge-sentinel", "GITHUB_TOKEN": "gh-sentinel"}
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    for worker_class, exe, role in ((ClaudeCodeWorker, CLAUDE_EXE, "claude"),
                                    (CodexWorker, CODEX_EXE, "codex")):
        monkeypatch.setattr(worker_class, "available", lambda self: True)
        _run_gate(worker_class(exe, launch=_launch(script, exe, role)), tmp_path)
    assert len(seams.calls) == 2
    for argv, env, _cwd in seams.calls:
        names = {name.casefold() for name in env}
        text = "\0".join([*argv, *env, *env.values()])
        for name, value in secrets.items():
            assert name.casefold() not in names
            assert value not in text
        assert not any(name.startswith("forge") for name in names)


def test_the_environment_is_constructed_from_the_allowlist_and_the_system_directory():
    environ = {"temp": "C:\\t", "UserProfile": "C:\\u", "PATH": "C:\\evil",
               "SystemRoot": "C:\\evil", "ComSpec": "C:\\evil\\cmd.exe", "OTHER": "x",
               "PSModulePath": "C:\\evil\\modules", "OPENAI_API_KEY": "k"}
    env = build_gate_environment(environ, system_dir=SYSTEM)
    assert env == {
        "TEMP": "C:\\t", "USERPROFILE": "C:\\u",
        "SystemRoot": "C:\\Windows", "windir": "C:\\Windows",
        "ComSpec": "C:\\Windows\\System32\\cmd.exe",
        "PATH": "C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\Wbem;"
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    }
    constructed = {"SystemRoot", "windir", "ComSpec", "PATH"}
    assert set(build_gate_environment(dict(os.environ), system_dir=SYSTEM)) <= (
        set(GATE_ENVIRONMENT_INHERITED) | constructed)
    assert not constructed & set(GATE_ENVIRONMENT_INHERITED)
    assert not any("KEY" in name or "TOKEN" in name or "FORGE" in name.upper()
                   or name.upper().endswith("HOME") for name in GATE_ENVIRONMENT_INHERITED)


def test_powershell_is_named_by_the_system_directory_never_by_path_or_systemroot(
        tmp_path, monkeypatch, script, seams):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    (tmp_path / "powershell.exe").write_bytes(b"")
    result = provider_gate.launch_through_gate(
        _launch(script), (CLAUDE_EXE, "-p", "x y"), role="builder", goal="g",
        worker="Claude Code worker")
    [(argv, env, cwd)] = seams.calls
    assert argv[0] == POWERSHELL == result.command[0] and cwd == SYSTEM
    assert env["SystemRoot"] == "C:\\Windows" and str(tmp_path) not in env["PATH"]


def test_the_public_entry_passes_the_modules_own_defaults(monkeypatch):
    """Nothing a caller passes replaces the console check, the system
    directory, the script read, the runner or the environment."""
    seen: dict = {}
    monkeypatch.setattr(provider_gate, "_launch", lambda *args, **kwargs: seen.update(kwargs))
    provider_gate.launch_through_gate(_launch(), (CLAUDE_EXE,), role="r", goal="g", worker="w")
    assert seen["system_directory"] is provider_gate._system_directory
    assert seen["has_console"] is provider_gate._has_console
    assert seen["read_script"] is provider_gate._read_script
    assert seen["runner"] is provider_gate._run_on_console
    assert seen["environ"] is os.environ
    assert set(inspect.signature(provider_gate.launch_through_gate).parameters) == {
        "launch", "command", "role", "goal", "worker"}


def test_the_gate_runs_on_the_console_with_no_capture_and_no_timeout(monkeypatch):
    """Killing the gate mid-cycle would leave its cycle open, and its prompt
    reads the console: so no stream is redirected and no timeout is set."""
    calls: list[tuple[tuple, dict]] = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 20)
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert provider_gate._run_on_console(("ps",), {"A": "b"}, "C:\\sys") == 20
    assert calls == [((("ps",),), {"env": {"A": "b"}, "cwd": "C:\\sys", "check": False})]


# ---------------------------------------------------------------------------
# The exit-code mapping, and the hold
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, meaning", [
    (0, "holds the cycle"), (10, "refused before opening a cycle"),
    (20, "failed with its cycle open"),
    (TIMEOUT_RETURNCODE, "not one of the gate's exit codes"),
    (UNAVAILABLE_RETURNCODE, "not one of the gate's exit codes"),
    (255, "not one of the gate's exit codes"),
    (-1, "not one of the gate's exit codes"),
], ids=["completed", "refused", "failed", "timeout-sentinel", "unavailable-sentinel",
        "unknown", "negative"])
def test_every_gate_exit_code_is_a_failed_worker_run_classified_error(code, meaning, tmp_path,
                                                                      monkeypatch, script,
                                                                      seams):
    """No provider output reaches the workspace through the gate, so not even
    exit 0 is a successful worker run. The gate's status is named in the
    output and never passed through as the returncode: a status of 124 or 127
    would otherwise read as a timeout or an absent executable. Every one is
    `error`, through the Provider Contract's unchanged mapping."""
    seams.returncode = code
    monkeypatch.setattr(CodexWorker, "available", lambda self: True)
    result = _run_gate(CodexWorker(CODEX_EXE, launch=_launch(script, CODEX_EXE, "codex")),
                       tmp_path)
    assert result.success is False
    assert result.returncode == provider_gate.GATE_RAN_RETURNCODE
    assert meaning in result.output and f"The gate exited {code}:" in result.output
    assert result.session_id is None
    assert classify_result(result.success, result.returncode) == "error"
    assert result_from_worker("codex", result).failure_class == "error"


class _CommandLineTooLong(FileNotFoundError):
    """CPython's spelling of Windows error 206: a FileNotFoundError that is
    not an absent file."""

    winerror = 206


@pytest.mark.parametrize("raised, returncode, words", [
    (FileNotFoundError(2, "No such file"), UNAVAILABLE_RETURNCODE, "reports it not found"),
    (_CommandLineTooLong(2, "The filename or extension is too long"),
     provider_gate.REFUSED_BEFORE_START_RETURNCODE, "refused to start"),
    (PermissionError(13, "Access is denied"), provider_gate.REFUSED_BEFORE_START_RETURNCODE,
     "refused to start"),
], ids=["absent", "winerror-206", "permission"])
def test_a_start_failure_is_unavailable_only_when_powershell_is_not_found(
        raised, returncode, words, tmp_path, script, seams, monkeypatch):
    def cannot(argv, env, cwd):
        raise raised
    monkeypatch.setattr(provider_gate, "_run_on_console", cannot)
    result = provider_gate.launch_through_gate(
        _launch(script), (CLAUDE_EXE, "-p", "x y"), role="builder", goal="g",
        worker="Claude Code worker")
    assert result.returncode == returncode and not result.success
    assert words in result.output and str(raised) in result.output
    expected = "unavailable" if returncode == UNAVAILABLE_RETURNCODE else "error"
    assert classify_result(result.success, result.returncode) == expected
    assert provider_gate.NOT_STARTED_RETURNCODE == UNAVAILABLE_RETURNCODE


def test_the_length_preflight_counts_utf16_code_units(tmp_path, monkeypatch, script, seams):
    """`CreateProcessW` bounds the line at 32767 UTF-16 code units. A
    character outside the Basic Multilingual Plane is two of them, so 16500
    of them pass a count of characters and still exceed the bound."""
    _no_process(monkeypatch)
    emoji = "\U0001F600" * 16500
    args = ("-p", emoji + " x")
    argv = build_gate_argv(_launch(script), args, system_dir=SYSTEM)
    line = subprocess.list2cmdline(argv)
    assert len(line) + 1 <= provider_gate.WINDOWS_COMMAND_LINE_LIMIT
    assert len(line.encode("utf-16-le")) // 2 + 1 > provider_gate.WINDOWS_COMMAND_LINE_LIMIT
    result = provider_gate.launch_through_gate(
        _launch(script), (CLAUDE_EXE, *args), role="builder", goal="g",
        worker="Claude Code worker")
    _refused(result)
    assert "UTF-16 code units" in result.output and seams.calls == []
    within = build_gate_argv(_launch(script), ("-p", "\U0001F600" * 100 + " x"),
                             system_dir=SYSTEM)
    assert provider_gate._argv_problem(within) is None


def test_the_script_hold_lasts_through_the_run_and_is_released_on_every_path(monkeypatch):
    events: list[str] = []
    pinned = hashlib.sha256(b"pinned").hexdigest()
    monkeypatch.setattr(provider_gate, "PINNED_RUN_ACT_SHA256", pinned)

    def reader(data):
        return lambda path: (events.append("read") or data, lambda: events.append("released"))

    def runner(argv, env, cwd):
        events.append("run")
        return 0

    for data, expected in ((b"pinned", ["read", "run", "released"]),
                           (b"other", ["read", "released"])):
        events.clear()
        provider_gate._launch(
            _launch(), (CLAUDE_EXE, "-p", "x y"), role="r", goal="g", worker="w",
            system_directory=lambda: SYSTEM, has_console=lambda: True,
            read_script=reader(data), runner=runner, environ={})
        assert events == expected

    def failing(argv, env, cwd):
        raise OSError("no")
    events.clear()
    provider_gate._launch(
        _launch(), (CLAUDE_EXE, "-p", "x y"), role="r", goal="g", worker="w",
        system_directory=lambda: SYSTEM, has_console=lambda: True,
        read_script=reader(b"pinned"), runner=failing, environ={})
    assert events == ["read", "released"]


def test_the_refusal_and_limit_values_are_the_workers_own():
    assert (provider_gate.REFUSED_BEFORE_START_RETURNCODE
            == claude_worker.MALFORMED_INVOCATION_RETURNCODE
            == codex_worker.MALFORMED_INVOCATION_RETURNCODE)
    assert provider_gate.REFUSED_BEFORE_START_RETURNCODE not in provider_gate.GATE_EXIT_MEANINGS
    assert (provider_gate.WINDOWS_COMMAND_LINE_LIMIT == claude_worker.WINDOWS_COMMAND_LINE_LIMIT
            == codex_worker.WINDOWS_COMMAND_LINE_LIMIT)
    assert sorted(provider_gate.GATE_EXIT_MEANINGS) == [0, 10, 20]


# ---------------------------------------------------------------------------
# Eligibility is unchanged in both modes
# ---------------------------------------------------------------------------

def test_eligibility_is_the_contracts_table_in_both_modes(tmp_path, monkeypatch, script, seams):
    """The decision reads its own table and nothing about how a worker starts
    its provider; this module reads and names none of it."""
    cases = [(provider, platform) for provider, rows in PROVIDER_CONFINEMENT.items()
             for platform in (*rows, "linux")]
    assert len(cases) >= 4

    def decide():
        return [dataclasses.asdict(governed_build_eligibility(p, q)) for p, q in cases]
    before = decide()
    for worker_class, exe, role in ((ClaudeCodeWorker, CLAUDE_EXE, "claude"),
                                    (CodexWorker, CODEX_EXE, "codex")):
        monkeypatch.setattr(worker_class, "available", lambda self: True)
        _run_gate(worker_class(exe, launch=_launch(script, exe, role)), tmp_path)
    assert decide() == before and len(seams.calls) == 2
    assert "launch" not in inspect.signature(governed_build_eligibility).parameters
    tree = ast.parse(Path(provider_gate.__file__).read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    imported = {alias.name for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    assert not any("eligib" in name.lower() or "confinement" in name.lower()
                   for name in names | imported)
    assert "provider_contract" not in imported


# ---------------------------------------------------------------------------
# Windows: the transport through a real powershell.exe -File, and the hold
# ---------------------------------------------------------------------------

#: A stand-in with the gate's parameter NAMES and nothing else of it. It reads
#: no credential and starts nothing; it reports what each parameter received.
STUB = """[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Action,
    [Parameter(Mandatory = $true)][string]$AuthorizedSha256,
    [string]$Role = '',
    [string]$CycleId = '',
    [string]$ProviderExe = '',
    [string]$ProviderArgs = '',
    [switch]$NoCredential,
    [string]$Step7Result = '',
    [string]$Confirmation = ''
)
$ErrorActionPreference = 'Stop'
function B64([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
foreach ($n in 'Action', 'AuthorizedSha256', 'Role', 'CycleId', 'ProviderExe', 'ProviderArgs', 'Step7Result', 'Confirmation') {
    [Console]::Out.WriteLine($n + '=' + (B64 (Get-Variable -Name $n -ValueOnly)))
}
[Console]::Out.WriteLine('NoCredential=' + [string][bool]$NoCredential)
[Console]::Out.WriteLine('Unbound=' + [string]@($args).Count)
exit 0
"""

#: Prompts as Forge composes them, and the characters a command line mangles.
TRANSPORT_CASES = {
    "claude-prompt": ("-p", "You are the builder worker in Nornyx Forge. Execute only this "
                      "bounded goal:\nbuild it\n\nRead CLAUDE.md.", "--output-format", "json",
                      "--max-turns", "30", "--allowedTools", "Read,Write"),
    "quotes": ("-p", 'say "hi" then \\"bye\\" and \\\\ end\\', "--allowedTools", 'Read,"Write"'),
    "trailing-backslash": ("-p", "C:\\path\\", "x"),
    "newlines": ("-p", "a\r\nb\nc\rd"),
    "newline-before-an-inner-quote": ("-p", "goal ends\n", "--allowedTools", "Read"),
    "leading-whitespace": ("\nexec", "x"), "leading-ideographic-space": ("\u3000exec", "x"),
    "non-ascii": ("-p", "caf\u00e9 \u2019q\u201d \u05d0 \U0001F600 \u4e2d \u00fc"),
    "dash-inside-quoted": ("-Action", "Release", "-NoCredential"),
    "empty-argument": ("-p", "", "x"),
    "powershell-syntax": ("-p", "it's 'q' $env:PATH `n $(whoami) ; & | < > @x {a} [b]"),
    "cmd-syntax": ("-p", "%PATH% ^ ! # ,"),
    "tab": ("-p", "a\tb"),
    "codex-shape": ("exec", "--json", "--cd", "C:\\work space\\p", "--skip-git-repo-check",
                    "--sandbox", "workspace-write", "--color", "never", 'You are\n"x"'),
    "long": ("-p", "word " * 5000),
}


def _stub(tmp_path: Path) -> Path:
    path = tmp_path / "stub gate \u00fc" / "stub-gate.ps1"
    path.parent.mkdir()
    path.write_text(STUB, encoding="ascii", newline="\r\n")
    return path


def _received(stdout: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in stdout.decode("ascii").splitlines():
        name, _, value = line.partition("=")
        values[name] = value if name in ("NoCredential", "Unbound") else (
            base64.b64decode(value).decode("utf-8"))
    return values


def _powershell(argv: tuple[str, ...]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, timeout=120, check=False,  # noqa: S603
                          stdin=subprocess.DEVNULL)


@windows_only
def test_the_vector_reaches_a_powershell_file_parameter_block_unchanged(tmp_path):
    """TRANSPORT ONLY: each case's -ProviderArgs, and every other parameter,
    arrive as sent through the real Windows PowerShell 5.1 at the system
    directory's path, with no switch bound and nothing left over."""
    stub = _stub(tmp_path)
    system = provider_gate._system_directory()
    launch = _launch(stub, "C:\\Provider Zone\\claude\\claude.exe", "claude")
    for name, args in TRANSPORT_CASES.items():
        argv = build_gate_argv(launch, args, system_dir=system)
        assert provider_gate._argv_problem(argv) is None, name
        done = _powershell(argv)
        assert done.returncode == 0, (name, done.stderr.decode("utf-8", "replace"))
        got = _received(done.stdout)
        assert got == {
            "Action": "Run", "AuthorizedSha256": REVIEWED_RUN_ACT_SHA256, "Role": "claude",
            "CycleId": "", "ProviderExe": "C:\\Provider Zone\\claude\\claude.exe",
            "ProviderArgs": subprocess.list2cmdline(args), "Step7Result": "",
            "Confirmation": "", "NoCredential": "False", "Unbound": "0"}, name


@windows_only
def test_powershell_alters_each_refused_class(tmp_path):
    """Why the two transport refusals exist, measured: built anyway, an
    unquoted `-NoCredential` as -ProviderArgs is not delivered as the value,
    and a quoted value ending in a newline is delivered without it."""
    stub = _stub(tmp_path)
    system = provider_gate._system_directory()
    for args in (("-NoCredential",), ("-p", "x\n")):
        argv = build_gate_argv(_launch(stub), args, system_dir=system)
        assert argv[-1] == subprocess.list2cmdline(args)
        assert provider_gate._argv_problem(argv) is not None, args
        done = _powershell(argv)
        delivered = done.returncode == 0 and _received(done.stdout)["ProviderArgs"] == argv[-1]
        assert not delivered, f"PowerShell delivered {argv[-1]!r}; the refusal is not needed"


@windows_only
def test_the_held_script_refuses_writers_while_powershell_still_reads_it(tmp_path,
                                                                         monkeypatch):
    stub = _stub(tmp_path)
    data, release = provider_gate._read_script(str(stub))
    try:
        assert data == stub.read_bytes()
        with pytest.raises(PermissionError):
            stub.open("ab")
        with pytest.raises(PermissionError):
            os.replace(stub, stub.with_name("moved.ps1"))
        with pytest.raises(PermissionError):
            stub.unlink()
        monkeypatch.setattr(provider_gate, "PINNED_RUN_ACT_SHA256",
                            hashlib.sha256(data).hexdigest())
        argv = build_gate_argv(_launch(stub), ("-p", "held"),
                               system_dir=provider_gate._system_directory())
        done = _powershell(argv)
        assert done.returncode == 0 and _received(done.stdout)["ProviderArgs"] == '-p held'
    finally:
        release()
    with stub.open("ab") as handle:
        handle.write(b"\r\n")


@windows_only
def test_the_whole_gate_path_runs_the_stub_through_each_worker(tmp_path, monkeypatch):
    """The real system directory, the real held read and the real vector,
    through both workers; only the console check and the runner's streams are
    replaced, because a CI job has no console to give the gate."""
    stub = _stub(tmp_path)
    monkeypatch.setattr(provider_gate, "PINNED_RUN_ACT_SHA256",
                        hashlib.sha256(stub.read_bytes()).hexdigest())
    monkeypatch.setattr(provider_gate, "_has_console", lambda: True)
    received: list[dict[str, str]] = []

    def capture(argv, env, cwd):
        done = subprocess.run(argv, env=env, cwd=cwd, capture_output=True,  # noqa: S603
                              timeout=120, check=False, stdin=subprocess.DEVNULL)
        received.append(_received(done.stdout))
        return done.returncode
    monkeypatch.setattr(provider_gate, "_run_on_console", capture)
    for worker_class, exe, role in ((ClaudeCodeWorker, CLAUDE_EXE, "claude"),
                                    (CodexWorker, CODEX_EXE, "codex")):
        monkeypatch.setattr(worker_class, "available", lambda self: True)
        direct = _direct_command(monkeypatch, worker_class(exe), tmp_path)
        result = _run_gate(worker_class(exe, launch=_launch(stub, exe, role)), tmp_path)
        assert result.returncode == provider_gate.GATE_RAN_RETURNCODE and not result.success
        assert "The gate exited 0:" in result.output
        assert received[-1]["ProviderArgs"] == subprocess.list2cmdline(direct[1:])
        assert received[-1]["Role"] == role and received[-1]["NoCredential"] == "False"


@windows_only
def test_the_console_check_refuses_a_nul_device_and_a_pipe():
    """`GetConsoleMode` on the standard input handle, not `isatty()`: the NUL
    device and a pipe are both refused."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); "
            "from nornyx_forge.provider_gate import _has_console; print(_has_console())")
    for stdin in (subprocess.DEVNULL, subprocess.PIPE):
        done = subprocess.run([sys.executable, "-c", code, str(ROOT / "src")],  # noqa: S603
                              stdin=stdin, capture_output=True, text=True, timeout=120,
                              check=False)
        assert done.returncode == 0 and done.stdout.strip() == "False", done.stderr


@windows_only
def test_the_system_directory_is_the_operating_systems_not_the_environments(monkeypatch,
                                                                            tmp_path):
    before = provider_gate._system_directory()
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setenv("windir", str(tmp_path))
    assert provider_gate._system_directory() == before
    assert Path(before, "WindowsPowerShell", "v1.0", "powershell.exe").is_file()
