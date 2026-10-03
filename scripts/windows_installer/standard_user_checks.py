"""Install, launch, stop and reopen ForgeSetup.exe on Windows, as a standard user.

Run by the `windows-install` CI job, in two modes:

    elevated       as the runner's administrator: the installer must REFUSE
                   (exit 10) and leave nothing;
    standard-user  as a local account the job creates in the Users group only,
                   with no administrator token: every other behaviour.

It reads the artifact the Linux job built (the real installer, and four
installers built from tiny sealed payloads that exercise refusals which all
happen before anything is extracted) and prints one PASS or FAIL line per
observation. It exits non-zero if any observation failed.

WHAT A PASS HERE IS, AND IS NOT. It is a run on a GitHub-hosted Windows image,
non-interactive, by a freshly created local account. It is NOT a run on a clean
accepted machine by a person: nothing here observes a UAC prompt on a default
configuration, SmartScreen or Smart App Control on a downloaded copy, the
Start-menu shortcut being double-clicked, the browser opening, or the absence of
network traffic during install. Those stay with the real-machine acceptance.

The pure parts (parsing, comparing) import and run anywhere; the Windows parts
are reached only by `main`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _path in (ROOT / "src", ROOT / "scripts", ROOT / "scripts" / "windows_installer"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import installer_contract as contract  # noqa: E402

#: Names the installer must never create, before or after it runs: the state
#: classes it does not own (the person's project, Forge's runtime and seals,
#: the trust stores, CrewAI's storage and the provider homes).
STATE_NAMES = frozenset(name.casefold() for name in (
    ".nornyx", ".nornyx-forge", ".config", ".crewai", ".claude", ".codex", "ForgeProject",
    "CrewAI"))
#: Where an installer could leave state, as profile-relative folders, and the
#: only names each may gain from an install. Listing them is non-recursive.
WATCHED = {
    "": set(),
    "AppData/Local": {"Programs", "Microsoft", "Temp", "Packages"},
    "AppData/Local/Programs": {"Nornyx Forge"},
    "AppData/Roaming": {"Microsoft"},
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs": {contract.SHORTCUT_NAME},
}
#: Registry places an installer registers itself in; each must be unchanged.
REGISTRY_WATCH = (
    r"Environment",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"Software\Microsoft\Windows\CurrentVersion\App Paths",
    r"Software\Microsoft\Windows\CurrentVersion\Run",
)

#: Exit codes this driver does not provoke, and why. Each stays a property of
#: the script's text until a real machine shows it.
UNEXERCISED = {
    "EXIT_FAILED": "a failure part-way (the rename, the shortcut, the receipt) needs a fault "
                   "injected into Windows",
    "EXIT_ELEVATION_UNKNOWN": "a process whose token cannot be read cannot be produced here",
    "EXIT_LOCATION": "a location outside the profile, or a UNC spelling, needs the account's "
                     "shell folders redirected",
}

FAILURES: list[str] = []


def expect(ok: bool, what: str) -> bool:
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        FAILURES.append(what)
    return ok


# ---------------------------------------------------------------------------
# Pure parts
# ---------------------------------------------------------------------------

def parse_icacls(output: str, path: str) -> list[tuple[str, str]]:
    """(principal, permission flags) for each ACE `icacls <path>` printed. The
    first line leads with the path; the line "Successfully processed" and blank
    lines are not ACEs."""
    aces = []
    for raw in output.splitlines():
        line = raw.replace(path, "", 1).strip()
        match = re.fullmatch(r"(.+?):(\(.+\))", line)
        if match:
            aces.append((match.group(1).strip(), match.group(2)))
    return aces


def acl_problems(aces: list[tuple[str, str]], *, computer: str, user: str) -> list[str]:
    """Why a folder's ACL shows the installer adding something: a principal
    beyond SYSTEM, Administrators and the user, or an ACE that is not
    inherited from the profile above it."""
    allowed = {"nt authority\\system", "builtin\\administrators",
               f"{computer}\\{user}".casefold()}
    problems = []
    if not aces:
        problems.append("icacls printed no ACE")
    for principal, flags in aces:
        if principal.casefold() not in allowed:
            problems.append(f"{principal} holds {flags}")
        if "(I)" not in flags:
            problems.append(f"{principal}'s ACE {flags} is explicit, not inherited")
    return problems


def listing_problems(before: dict[str, set[str]], after: dict[str, set[str]]) -> list[str]:
    """What an install added to the watched folders beyond what each may gain,
    what it removed, and any state-class name present afterwards."""
    problems = []
    for folder, allowed in WATCHED.items():
        added = {name for name in after[folder] - before[folder]
                 if not name.casefold().startswith("ntuser")} - allowed
        if added:
            problems.append(f"{folder or '<profile>'} gained {sorted(added)}")
        if before[folder] - after[folder]:
            problems.append(f"{folder or '<profile>'} lost {sorted(before[folder] - after[folder])}")
        stateful = {name for name in after[folder] if name.casefold() in STATE_NAMES}
        if stateful:
            problems.append(f"{folder or '<profile>'} holds state-class names {sorted(stateful)}")
    return problems


def tree_state(root: Path) -> dict[str, tuple[int, int]]:
    """Every file under `root` as relative path -> (size, mtime in ns)."""
    state = {}
    for directory, _subdirectories, files in os.walk(root):
        for name in files:
            path = Path(directory) / name
            status = path.lstat()
            state[path.relative_to(root).as_posix()] = (status.st_size, status.st_mtime_ns)
    return state


def path_without(names: tuple[str, ...], path_value: str) -> str:
    """`path_value` without any folder that holds one of `names`."""
    kept = [entry for entry in path_value.split(os.pathsep)
            if entry and not any((Path(entry) / name).exists() for name in names)]
    return os.pathsep.join(kept)


# ---------------------------------------------------------------------------
# Windows parts
# ---------------------------------------------------------------------------

def _powershell(script: str, **variables: str) -> str:
    environment = {**os.environ, **variables}
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, timeout=180, env=environment)
    # Bytes, decoded here: the output is ASCII (JSON, process ids) and a
    # replacement character is a visible difference, never a crash.
    if completed.returncode != 0:
        raise RuntimeError(f"powershell exited {completed.returncode}: "
                           f"{completed.stderr.decode('utf-8', 'replace')[:400]}")
    return completed.stdout.decode("utf-8", "replace").strip()


def read_shortcut(path: Path) -> dict[str, str]:
    script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:FORGE_LNK); "
              "@{TargetPath=$s.TargetPath; Arguments=$s.Arguments; "
              "WorkingDirectory=$s.WorkingDirectory} | ConvertTo-Json -Compress")
    return json.loads(_powershell(script, FORGE_LNK=str(path)))


def processes_under(folder: Path, name: str | None = None) -> list[int]:
    script = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and "
              "$_.ExecutablePath.StartsWith($env:FORGE_DIR, [StringComparison]::OrdinalIgnoreCase) "
              "-and ((-not $env:FORGE_NAME) -or $_.Name -ieq $env:FORGE_NAME) } | "
              "ForEach-Object { $_.ProcessId }")
    out = _powershell(script, FORGE_DIR=str(folder) + "\\", FORGE_NAME=name or "")
    return [int(line) for line in out.split() if line.strip()]


def is_admin() -> bool:
    import ctypes  # noqa: PLC0415 - Windows only

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def registry_state() -> dict[str, object]:
    import winreg  # noqa: PLC0415 - Windows only

    def read(hive, key: str, want_values: bool):
        try:
            with winreg.OpenKey(hive, key) as handle:
                if want_values:
                    values, index = {}, 0
                    while True:
                        try:
                            name, value, _kind = winreg.EnumValue(handle, index)
                        except OSError:
                            return values
                        values[name] = value
                        index += 1
                subkeys, index = [], 0
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(handle, index))
                    except OSError:
                        return sorted(subkeys)
                    index += 1
        except OSError:
            return None

    state: dict[str, object] = {
        "HKLM PATH": (read(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                           True) or {}).get("Path")}
    for key in REGISTRY_WATCH:
        state["HKCU " + key] = read(winreg.HKEY_CURRENT_USER, key, key == "Environment")
    return state


def watched_listing(profile: Path) -> dict[str, set[str]]:
    listing = {}
    for folder in WATCHED:
        path = profile.joinpath(*folder.split("/")) if folder else profile
        listing[folder] = set(os.listdir(path)) if path.is_dir() else set()
    return listing


def run_setup(exe: Path, work: Path, tag: str, *, env: dict[str, str] | None = None,
              timeout: int = 1800) -> tuple[int, str]:
    """Run an installer silently with an opt-in log; (exit code, log text)."""
    log = work / f"{tag}.log"
    log.unlink(missing_ok=True)
    started = time.monotonic()
    completed = subprocess.run([str(exe), "/S", f"/LOG={log}"], env=env, timeout=timeout,
                               cwd=str(work))
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    print(f"  {exe.parent.name}\\{exe.name} /S -> exit {completed.returncode} in "
          f"{time.monotonic() - started:.1f}s; log {text.strip()[:500]!r}", flush=True)
    return completed.returncode, text


def build_record(folder: Path) -> dict:
    return json.loads((folder / "ForgeSetup.build.json").read_text(encoding="utf-8"))


def manifest_of(record: dict) -> dict:
    """The fields of a payload manifest the receipt and the shortcut name,
    from a build record."""
    payload = record["payload"]
    return {"version": payload["version"], "source_commit": payload["source_commit"],
            "payload_sha256": payload["sha256"]}


def verify_installed(folder: Path, sha: str) -> int:
    python = folder / "python" / "python.exe"
    return subprocess.run([str(python), "-B", "-I", "-m", "nornyx_forge.windows_payload",
                           "verify", str(folder), "--expect", sha],
                          capture_output=True, timeout=900).returncode


def install_root() -> Path:
    return Path(os.environ["LOCALAPPDATA"]).joinpath(*contract.INSTALL_ROOT_PARTS)


# ---------------------------------------------------------------------------
# The two modes
# ---------------------------------------------------------------------------

def mode_elevated(artifact: Path, work: Path) -> None:
    codes = contract.exit_codes(contract.nsi_text())
    expect(is_admin(), "the runner's process is elevated (the refusal needs an elevated process "
                       "to be observed at all)")
    root = install_root()
    expect(not root.exists(), "no install folder exists before the elevated run")
    code, log = run_setup(artifact / "forge-setup" / "ForgeSetup.exe", work, "elevated")
    expect(code == codes["EXIT_ELEVATED"], f"an elevated run exits {codes['EXIT_ELEVATED']}"
           f" (got {code})")
    expect("without 'Run as administrator'" in log, "the refusal explains itself in the log")
    expect(not root.exists(), "the elevated run created no install folder")


def mode_standard_user(artifact: Path, work: Path) -> None:
    codes = contract.exit_codes(contract.nsi_text())
    import build_windows_bundle as bundle  # noqa: PLC0415

    profile = Path(os.environ["USERPROFILE"])
    user, computer = os.environ["USERNAME"], os.environ["COMPUTERNAME"]
    real_dir = artifact / "forge-setup"
    real_exe = real_dir / "ForgeSetup.exe"
    real_record = build_record(real_dir)
    manifest = manifest_of(real_record)
    variants = {name: artifact / "variants" / name for name in
                ("small", "other", "same-version", "long")}
    root = install_root()
    programs = root.parent
    folder = root / contract.version_directory(manifest)

    expect(not is_admin(), f"this process is not elevated (user {user})")
    expect(not root.exists(), "no install folder exists before the run")
    before_listing, before_registry = watched_listing(profile), registry_state()

    # --- refusals, each from a tiny sealed payload, each leaving nothing
    code, log = run_setup(variants["long"] / "ForgeSetup.exe", work, "long")
    expect(code == codes["EXIT_TOO_LONG"] and not root.exists(),
           f"a path that would reach 260 characters is refused ({codes['EXIT_TOO_LONG']}), "
           "and nothing is created")

    small = variants["small"]
    small_manifest = manifest_of(build_record(small))
    programs.mkdir(parents=True, exist_ok=True)
    root.mkdir()
    (root / "stranger.txt").write_text("not forge's\n", encoding="utf-8")
    code, _log = run_setup(small / "ForgeSetup.exe", work, "stranger")
    expect(code == codes["EXIT_NOT_FORGE"] and sorted(os.listdir(root)) == ["stranger.txt"],
           f"a non-empty folder without a receipt is not Forge's ({codes['EXIT_NOT_FORGE']}) "
           "and is left alone")
    shutil.rmtree(root)

    target = work / "junction-target"
    target.mkdir()
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(root), str(target)], check=True,
                   capture_output=True, timeout=60)
    code, _log = run_setup(small / "ForgeSetup.exe", work, "junction")
    expect(code == codes["EXIT_LINK"] and os.listdir(target) == [],
           f"a junction at the install folder is refused ({codes['EXIT_LINK']}) and its target "
           "is untouched")
    os.rmdir(root)
    shutil.rmtree(target)

    root.mkdir()
    (root / contract.RECEIPT_NAME).write_text("{}\n", encoding="utf-8")
    (root / (contract.version_directory(small_manifest) + contract.PARTIAL_SUFFIX)).mkdir()
    code, _log = run_setup(small / "ForgeSetup.exe", work, "unfinished")
    expect(code == codes["EXIT_UNFINISHED"],
           f"an unfinished earlier install is refused ({codes['EXIT_UNFINISHED']})")
    shutil.rmtree(root)

    # --- the real install, into an existing EMPTY folder
    root.mkdir()
    code, log = run_setup(real_exe, work, "install")
    if not expect(code == 0, f"the real installer exits 0 (got {code})"):
        return
    expect(folder.is_dir() and (folder / "forge-payload.json").is_file(),
           "the verified payload folder is in place")
    expect(not (root / (folder.name + contract.PARTIAL_SUFFIX)).exists(),
           "no .partial folder remains")
    receipt_path = root / contract.RECEIPT_NAME
    receipt = receipt_path.read_text(encoding="utf-8")
    problems = contract.check_receipt(receipt, manifest)
    expect(not problems, f"the receipt is the installer's and names exactly this payload {problems}")
    parsed = json.loads(receipt)
    expect(parsed["root_created"] is False, "the receipt says the (pre-existing, empty) root "
                                            "folder was not created by the installer")
    expect(parsed["prerequisites"]["git"] == "found", "git on PATH is reported found")
    expect(verify_installed(folder, manifest["payload_sha256"]) == 0,
           "the installed copy verifies, from outside, against the expected identity")
    shortcut_path = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu"
                     / "Programs" / contract.SHORTCUT_NAME)
    expect(shortcut_path.is_file(), "the per-user Start-menu shortcut exists")
    if shortcut_path.is_file():
        found = read_shortcut(shortcut_path)
        wanted = contract.shortcut_expectation(manifest, install_root=str(root),
                                               profile=str(profile))
        expect({k: found[k].casefold() for k in wanted} == {k: v.casefold()
                                                            for k, v in wanted.items()},
               f"the shortcut starts the embedded interpreter in the install root {found}")
    icacls = subprocess.run(["icacls", str(root)], capture_output=True, timeout=60)
    listing = icacls.stdout.decode("utf-8", "replace")
    expect(not (acl := acl_problems(parse_icacls(listing, str(root)), computer=computer,
                                    user=user)), f"the installer added no ACE {acl}")
    after_listing, after_registry = watched_listing(profile), registry_state()
    expect(not (listed := listing_problems(before_listing, after_listing)),
           f"only the install folder and the shortcut were added {listed}")
    expect(after_registry == before_registry,
           "no registry value changed (PATH, Uninstall, App Paths, Run)")

    # --- the existing-install rule
    state, kept_receipt = tree_state(root), receipt_path.read_bytes()
    code, log = run_setup(real_exe, work, "again")
    expect(code == 0 and "already installed" in log, "the same payload again verifies and "
                                                      "exits 0")
    expect(tree_state(root) == state and receipt_path.read_bytes() == kept_receipt,
           "the second run changed no file, size or time")
    code, _log = run_setup(variants["other"] / "ForgeSetup.exe", work, "other")
    expect(code == codes["EXIT_OTHER_VERSION"] and tree_state(root) == state,
           f"another version is refused ({codes['EXIT_OTHER_VERSION']}) and nothing changes")
    code, _log = run_setup(variants["same-version"] / "ForgeSetup.exe", work, "same-version")
    expect(code == codes["EXIT_DOES_NOT_VERIFY"] and tree_state(root) == state,
           f"other bytes under the same version are refused ({codes['EXIT_DOES_NOT_VERIFY']}) "
           "and nothing changes")

    # --- launch, stop, reopen, from the shortcut's own command line
    launch_checks(bundle, work, folder, read_shortcut(shortcut_path), manifest)
    expect(verify_installed(folder, manifest["payload_sha256"]) == 0,
           "the installed copy still verifies after being run (the shortcut starts the "
           "interpreter with bytecode writing off)")

    # --- git absent: a fresh install from a tiny payload, with no git and no Python on PATH
    shutil.rmtree(root)
    shortcut_path.unlink()
    lean = {**os.environ, "PATH": path_without(("git.exe", "python.exe"), os.environ["PATH"])}
    code, _log = run_setup(small / "ForgeSetup.exe", work, "no-git", env=lean)
    expect(code == 0, "an install with no git and no Python on PATH succeeds (git is advisory; "
                      "only the embedded interpreter runs)")
    absent = (root / contract.RECEIPT_NAME).read_text(encoding="utf-8") if code == 0 else "{}"
    expect(not contract.check_receipt(absent, small_manifest)
           and json.loads(absent)["prerequisites"]["git"] == "not found"
           and json.loads(absent)["root_created"] is True,
           "the receipt records git as not found and the root as created")


def launch_checks(bundle, work: Path, folder: Path, shortcut: dict, manifest: dict) -> None:
    """Start the runtime with the shortcut's exact command line (plus the
    scratch arguments the smoke also passes), join it, stop it, and start it
    again."""
    scratch = work / "launch"
    shutil.rmtree(scratch, ignore_errors=True)
    (scratch / "profile").mkdir(parents=True)
    runtime, project, session = scratch / "runtime", scratch / "project", work / "session.json"
    session.unlink(missing_ok=True)
    environment = {**os.environ, "USERPROFILE": str(scratch / "profile"),
                   "HOME": str(scratch / "profile"),
                   "PATH": path_without(("python.exe",), os.environ["PATH"])}
    extra = subprocess.list2cmdline(["--project-dir", str(project), "--runtime-dir", str(runtime),
                                     "--port", "0", "--no-browser", "--session-file",
                                     str(session)])
    command = f'"{shortcut["TargetPath"]}" {shortcut["Arguments"]} {extra}'

    def wait_record(status: str, timeout: float = 180.0) -> dict | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for path in sorted(runtime.glob("*.json")) if runtime.exists() else []:
                record = bundle._read_record(path)
                if isinstance(record, dict) and record.get("status") == status:
                    return record
            time.sleep(0.5)
        return None

    first = subprocess.Popen(command, env=environment, cwd=str(folder.parent),
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    ready = wait_record("ready")
    if not expect(ready is not None, "the shortcut's command line starts the runtime and it "
                                      "reaches ready"):
        first.kill()
        return
    port, instance = ready["port"], ready["instance"]
    status, body, _kind = bundle._get(port, "/api/runtime")
    expect(status == 200 and json.loads(body).get("instance") == instance,
           "the running runtime answers as the recorded instance")
    expect(len(processes_under(folder, "pythonw.exe")) == 1,
           "one pythonw.exe from the install folder is running")

    joined = subprocess.run(command, env=environment, cwd=str(folder.parent), timeout=300,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    again = wait_record("ready", 30)
    expect(joined.returncode == 0 and again is not None and again["instance"] == instance
           and len(processes_under(folder, "pythonw.exe")) == 1,
           "a second launch joins the running instance and starts no second server")

    deadline, token = time.monotonic() + 30, None
    while token is None and time.monotonic() < deadline:
        token = bundle._read_session_token(session)
        time.sleep(0.2)
    stop_status, _body = bundle._post_json(port, "/api/runtime/stop",
                                           {"actor": bundle.SMOKE_ACTOR}, token=token)
    stopped = wait_record("stopped", 60)
    expect(stop_status == 200 and stopped is not None and stopped["instance"] == instance,
           "stop is accepted and the record reaches stopped")
    try:
        first.wait(timeout=60)
    except subprocess.TimeoutExpired:
        first.kill()
    gone = time.monotonic() + 30
    while processes_under(folder, "pythonw.exe") and time.monotonic() < gone:
        time.sleep(0.5)
    expect(not processes_under(folder, "pythonw.exe"),
           "no pythonw.exe from the install folder remains after stop")

    restarted = subprocess.Popen(command, env=environment, cwd=str(folder.parent),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
    time.sleep(2)  # the previous record says stopped; the new owner writes its own
    second = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and second is None:
        for path in sorted(runtime.glob("*.json")):
            record = bundle._read_record(path)
            if isinstance(record, dict) and record.get("status") == "ready" and record.get(
                    "instance") != instance:
                second = record
        time.sleep(0.5)
    expect(second is not None, "a launch after stop starts a new instance")
    if second is not None:
        token = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            token = bundle._read_session_token(session)
            if token:
                break
            time.sleep(0.2)
        bundle._post_json(second["port"], "/api/runtime/stop", {"actor": bundle.SMOKE_ACTOR},
                          token=token)
    try:
        restarted.wait(timeout=60)
    except subprocess.TimeoutExpired:
        restarted.kill()
    gone = time.monotonic() + 30
    while processes_under(folder, "pythonw.exe") and time.monotonic() < gone:
        time.sleep(0.5)
    expect(not processes_under(folder, "pythonw.exe"),
           "the second instance stopped too and no pythonw.exe remains")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=["elevated", "standard-user"])
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    arguments = parser.parse_args(argv)
    arguments.work.mkdir(parents=True, exist_ok=True)
    try:
        {"elevated": mode_elevated, "standard-user": mode_standard_user}[arguments.mode](
            arguments.artifact, arguments.work)
    except Exception as error:  # noqa: BLE001 - a crash is a failed observation, never a pass
        expect(False, f"the run crashed: {type(error).__name__}: {error}")
    print(f"{len(FAILURES)} failed observations" if FAILURES else "all observations passed",
          flush=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
