"""Rehearse a real entrypoint against a local fixture, and show a guard is load-bearing.

Linux only: both commands refuse on any other platform.

REHEARSE (`rehearse SPEC --work-root DIR`) runs one program once, in a copy of one
directory under the spec's directory, and compares what happened with the declared
expectation: the exit code, every file created, modified or deleted under the three
watched roots (the fixture copy, an empty home and an empty temp directory), and
output patterns. A pattern is literal text, tested as a substring of the output: no
regular-expression syntax is read, so a pattern costs time linear in the output, and a
stream holds at most `MAX_PATTERNS` of them, none empty. Every mismatch is listed, and the record is
printed on stdout. The
child runs without a shell in the declared directory of the copy, in its own
session, with stdin on /dev/null and an environment built from nothing (`HOME`,
`TMPDIR`, `TMP` and `TEMP`, then the inherited names, then the declared ones); when
it exits or its timeout passes, its process group is ended.

PATHS. A declared path (the fixture, the working directory, an expected file) is
'/'-separated components, none empty, '.' or '..'; any other character is allowed,
a leading dot and non-ASCII letters included. The fixture must resolve to exactly
itself under the spec's real directory: no link lies on it. The spec path and the
work root may be spelled any way, but the work root must lie outside the spec's
directory, decided by file identity along the work root's own path: inputs live
there, outputs outside it. `argv[0]`, with placeholders expanded, must be absolute
(normally `{python}`): no program is looked up.

WRITES. The harness creates `DIR/rehearsal` exclusively (an existing one refuses)
and in it every entry of the copy, exclusively and with the mode the template's
listing recorded, so two template names never land on one entry; the template may
hold only directories and regular files. It then removes the run directory without
following a link or changing a file's mode: each directory is opened by
descriptor, made owner-writable and emptied through it. Whatever stays behind
refuses the run, and so does a watched root that is no longer the directory the
harness made. It writes nothing else but stdout and stderr, never edits the
entrypoint, spec or template, and decides nothing: a person or a pipeline acts on
the record.

DETERMINISM. Two runs of one spec with one work root give the same record unless
the entrypoint behaves differently: the run directory's name is fixed, and a path
the harness gave the child is recorded as its placeholder, as given or resolved.
Output is decoded as UTF-8 and otherwise kept as written, a CR included; a stream
that cannot be decoded has no digest, size or text, and patterns on it refuse.

GUARD-LIVE (`guard-live SPEC --work-root DIR`) shows one guard is load-bearing. Its
subject is one file of the fixture template, named as the template's listing names
it and read once. The triggered run must refuse (run A); with one exact, hash-bound
snippet of the subject replaced in the copy, the refusal must disappear and the run
must reach a declared point past the guard (run B); an optional untriggered run
must not refuse (run C). Run A must match the refused expectation in full; runs B
and C show the refusal by its exit code and output patterns alone, whatever files
they changed, so a persisting refusal that also leaves a marker file is not missed.
Each run's copy takes its entries, kinds and modes from
one listing of the template; every file but the subject is read again from the
template and must match its listed digest, and the subject is the bytes read once. A
copy that differs from the listing refuses. Only the listed entries of each run's
copy are compared; nothing else is isolated or compared (`LIMITS` names it), so the
verdict assumes the subject changes no state that a later run reads: the subject is
the repository's own code under rehearsal, not an adversary. It shows the guard
decides for the declared trigger, not that it is correct.

What the harness cannot see is `LIMITS`, repeated in every record. Exit codes:
rehearse 0 MATCH, 1 MISMATCH, 2 REFUSED; guard-live 0 LIVE, 1 DEAD, 2 INCONCLUSIVE
or REFUSED; any other command line 2. Every exit 2 prints one REFUSE line.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

REHEARSAL_SPEC = "nornyx.forge.rehearsal_spec.v1"
REHEARSAL_RECORD = "nornyx.forge.rehearsal_record.v1"
GUARD_SPEC = "nornyx.forge.guard_liveness_spec.v1"
GUARD_RECORD = "nornyx.forge.guard_liveness_record.v1"
MAX_SPEC_BYTES = 1024 * 1024
MAX_ENTRIES = 20_000
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_STREAM_BYTES = 16 * 1024 * 1024
MAX_SUBJECT_BYTES = 4 * 1024 * 1024
RECORD_TEXT_CHARS = 64 * 1024
MAX_PATTERNS = 64
DRAIN_SECONDS = 10
RUN_DIRECTORY = "rehearsal"
LIMITS = (
    "the harness runs on Linux only, and refuses on any other platform",
    "writes outside the watched roots (fixture, home, tmp) are not seen",
    "reads of any kind, and network use, are not seen",
    "processes the child starts that leave its process group, and what they do later, "
    "are not seen",
    "metadata changes in the watched roots (timestamps, permissions, extended attributes) are "
    "not compared",
    "the work root is judged by identity along its own path, so a bind mount of a directory "
    "inside the spec's directory, used as the work root, is not detected",
    "rehearse, unlike guard-live, does not compare the copy with the template's listing, so a "
    "work root whose file system drops modes gives the child other modes than the listed ones "
    "(prefer ext4)",
    "between guard-live runs only the listed entries of each run's copy are compared; nothing "
    "else is isolated or compared, among it the copy's own root directory, the spec's "
    "directory (reachable through {spec_dir}) beyond the listed files' content (a file added "
    "or a mode changed there is not seen; a changed listed file's content is caught through "
    "the next copy), the work root's own attributes, ACLs, extended attributes, inode flags, "
    "security labels, the ownership of entries and every other path",
    "behaviour depending on time, randomness, the machine or on noticing a rehearsal is not "
    "controlled",
    "an output stream that cannot be decoded is recorded with no digest, size or text",
)


class Refusal(Exception):
    """A spec, subject or run that cannot be judged. Never read as a pass."""


# -- spec validation ---------------------------------------------------------


def _unique(pairs: list) -> dict:
    seen, repeated = set(), set()
    for key, _value in pairs:
        (repeated if key in seen else seen).add(key)
    if repeated:
        raise Refusal(f"the spec repeats the keys {sorted(repeated)}")
    return dict(pairs)


def _load(path: Path) -> tuple:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SPEC_BYTES + 1)
    except OSError as exc:
        raise Refusal(f"the spec cannot be read ({type(exc).__name__})") from exc
    if len(data) > MAX_SPEC_BYTES:
        raise Refusal(f"the spec is larger than {MAX_SPEC_BYTES} bytes")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique), data
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Refusal(f"the spec is not valid JSON ({type(exc).__name__})") from exc


def _object(value, where: str, required=(), optional=()) -> dict:
    if not isinstance(value, dict):
        raise Refusal(f"{where} must be an object")
    unknown, missing = sorted(set(value) - set(required) - set(optional)), sorted(
        set(required) - set(value))
    if unknown or missing:
        raise Refusal(f"{where}: unknown fields {unknown}, missing fields {missing}")
    return value


def _text(value, where: str) -> str:
    if not isinstance(value, str):
        raise Refusal(f"{where} must be a string")
    return value


def _texts(value, where: str) -> list:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise Refusal(f"{where} must be a list of strings")
    return value


# -- paths: declared components, the spec's directory and the work root ------


def _relative(value, where: str) -> Path:
    """A declared relative path: '/'-separated components, none empty, '.' or '..',
    and none the file system cannot name (holding a NUL, or not encodable)."""
    parts = _text(value, where).split("/")
    try:
        plain = all(part not in ("", ".", "..") and b"\0" not in os.fsencode(part)
                    for part in parts)
    except UnicodeEncodeError:
        plain = False
    if not plain:
        raise Refusal(f"{where} is not a plain relative path: '/'-separated components, "
                      "none empty, '.' or '..'")
    return Path(*parts)


def _operator(value, where: str) -> Path:
    """The spec path or the work root, spelled any way, resolved."""
    try:
        return Path(os.path.realpath(os.fspath(value)))
    except (TypeError, ValueError) as exc:
        raise Refusal(f"{where} is not a usable path ({type(exc).__name__})") from exc


def _within(path, container) -> bool:
    """Whether `path` is `container` or lies below it, decided by file identity
    (device and inode) along `path`'s resolved ancestors, never by name."""
    try:
        wanted = os.stat(container)
    except OSError:
        return False
    current = os.path.realpath(path)
    while True:
        with contextlib.suppress(OSError):
            if os.path.samestat(os.stat(current), wanted):
                return True
        if os.path.dirname(current) == current:
            return False
        current = os.path.dirname(current)


_PLACEHOLDER = re.compile(r"\{\{|\}\}|\{([a-z_]+)\}|[{}]")
_PLACEHOLDERS = ("fixture", "home", "tmp", "spec_dir", "python")


def _expand(text: str, values: dict) -> str:
    """Replace `{name}` placeholders; `{{` and `}}` are literal braces."""

    def replace(match):
        if match.group(0) in ("{{", "}}"):
            return match.group(0)[0]
        if match.group(1) is None:
            raise Refusal(f"a lone brace in {text!r}: write {{{{ or }}}}")
        if match.group(1) not in values:
            raise Refusal(f"unknown placeholder {{{match.group(1)}}} in {text!r}")
        return values[match.group(1)]

    return _PLACEHOLDER.sub(replace, text)


def _parse_run(value, where: str) -> dict:
    run = _object(value, where, ("fixture", "argv", "timeout_seconds"),
                  ("cwd", "env", "inherit_env"))
    argv = _texts(run["argv"], where + ".argv")
    timeout = run["timeout_seconds"]
    if not argv or isinstance(timeout, bool) or not isinstance(timeout, int) \
            or not 1 <= timeout <= 3600:
        raise Refusal(f"{where} needs a non-empty argv and timeout_seconds from 1 to 3600")
    env = run.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(v, str) for v in env.values()):
        raise Refusal(f"{where}.env must map names to strings")
    dummy = {name: "/x" for name in _PLACEHOLDERS}
    for text in [*argv, *env.values()]:
        _expand(text, dummy)
    cwd = run.get("cwd")
    return {"fixture": _relative(run["fixture"], where + ".fixture"), "argv": argv,
            "cwd": None if cwd is None else _relative(cwd, where + ".cwd"), "env": env,
            "inherit_env": _texts(run.get("inherit_env", []), where + ".inherit_env"),
            "timeout": timeout}


_ROOTS = ("fixture", "home", "tmp")


def _parse_expect(value, where: str) -> dict:
    expect = _object(value, where, ("exit",), ("files", "stdout", "stderr"))
    code = expect["exit"]
    if code not in ("success", "failure") and not (
            isinstance(code, list) and code and all(
                isinstance(c, int) and not isinstance(c, bool) for c in code)):
        raise Refusal(f"{where}.exit must be a non-empty list of codes, 'success' or 'failure'")
    files = _object(expect.get("files", {}), where + ".files", (), ("created", "modified", "deleted"))
    declared = {kind: {} for kind in ("created", "modified", "deleted")}
    for kind, entries in files.items():
        if not isinstance(entries, list):
            raise Refusal(f"{where}.files.{kind} must be a list")
        for entry in entries:
            entry = {"path": entry} if isinstance(entry, str) else _object(
                entry, f"{where}.files.{kind}[]", ("path",), ("sha256",))
            path, digest = _text(entry["path"], "a file path"), entry.get("sha256")
            parts = _relative(path[:-1] if path.endswith("/") else path, f"the path {path!r}").parts
            if len(parts) < 2 or parts[0] not in _ROOTS:
                raise Refusal(f"{path!r} is not fixture/, home/ or tmp/ plus a path")
            if digest is not None and (kind == "deleted" or not re.fullmatch(r"[0-9a-f]{64}",
                                                                              str(digest))):
                raise Refusal(f"{path!r} carries a digest that cannot apply")
            declared[kind][path] = digest
    patterns = {}
    for stream in ("stdout", "stderr"):
        spec = _object(expect.get(stream, {}), f"{where}.{stream}", (),
                       ("must_match", "must_not_match"))
        patterns[stream] = {key: _texts(spec.get(key, []), f"{where}.{stream}.{key}")
                            for key in ("must_match", "must_not_match")}
        if sum(map(len, patterns[stream].values())) > MAX_PATTERNS:
            raise Refusal(f"{where}.{stream} holds more than {MAX_PATTERNS} patterns")
        if "" in patterns[stream]["must_match"] + patterns[stream]["must_not_match"]:
            raise Refusal(f"{where}.{stream} holds an empty pattern, which any output contains")
    return {"exit": code, "files": declared, "patterns": patterns}


# -- the fixture: listing, copy and removal ----------------------------------


@contextlib.contextmanager
def _regular(path):
    """A regular file opened for reading, never through a link at its last
    component and never blocking on a FIFO swapped in; anything else refuses."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise Refusal("an entry listed as a regular file is no longer one")
        yield handle, info


def _digest_file(path, size: int) -> str:
    """The digest of the regular file `path`, of at most the `size` bytes checked."""
    digest = hashlib.sha256()
    with _regular(path) as (handle, _info):
        while size > 0 and (chunk := handle.read(min(size, 1 << 20))):
            digest.update(chunk)
            size -= len(chunk)
    return digest.hexdigest()


def _snapshot(root: Path, label: str, made=None, modes: bool = False) -> dict:
    """relative path -> (kind, detail), plus the entry's permission bits when `modes`
    is set (the template's listing, and the copy a run sees); directories end in '/'.
    A link is recorded, never followed, and the count and size bounds hold before a
    file is hashed."""
    entries, total, pending = {}, 0, [(str(root), "")]
    try:
        if made and not (os.path.samestat(os.lstat(root), made) and not os.path.islink(root)):
            raise Refusal(f"the watched root {label} was replaced during the run")
        while pending:
            directory, prefix = pending.pop()
            with os.scandir(directory) as found:
                children = sorted(found, key=lambda entry: entry.name)
            for child in children:
                relative, info = prefix + child.name, os.lstat(child.path)
                total += info.st_size if stat.S_ISREG(info.st_mode) else 0
                if len(entries) >= MAX_ENTRIES or total > MAX_TREE_BYTES:
                    raise Refusal(f"{label} exceeds {MAX_ENTRIES} entries or {MAX_TREE_BYTES} "
                                  "bytes")
                if stat.S_ISLNK(info.st_mode):
                    key, entry = relative, ("link", os.readlink(child.path))
                elif stat.S_ISDIR(info.st_mode):
                    key, entry = relative + "/", ("dir", "")
                    pending.append((child.path, key))
                elif stat.S_ISREG(info.st_mode):
                    key, entry = relative, ("file", _digest_file(child.path, info.st_size))
                else:
                    key, entry = relative, ("special", stat.filemode(info.st_mode)[0])
                entries[key] = entry + ((stat.S_IMODE(info.st_mode),) if modes else ())
    except OSError as exc:
        raise Refusal(f"{label} cannot be read ({type(exc).__name__})") from exc
    return entries


def _template(run: dict, spec_dir: Path) -> tuple:
    """The fixture template and its listing. Joined to the spec's real directory,
    the template must resolve to exactly itself, so no link lies on it. Both
    commands reach this before they touch a file or start a run, and here, only
    here, the harness refuses off Linux."""
    if sys.platform != "linux":
        raise Refusal("the harness runs on Linux only")
    template = spec_dir / run["fixture"]
    if os.path.realpath(template) != str(template):
        raise Refusal("the fixture template does not resolve to exactly the path declared: "
                      "a link lies on it")
    return template, _snapshot(template, "the fixture template", modes=True)


def _create(path: str, mode: int, write) -> None:
    """Create the file `path` exclusively (an existing entry or link refuses), fill
    it, and give it `mode` through its descriptor."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, 0o600), "wb") as out:
        write(out)
        os.fchmod(out.fileno(), mode)


def _copy_tree(listing: dict, template: Path, target: Path, subject=None) -> None:
    """Copy the listed template into the empty directory `target`: every entry is
    created exclusively, with the mode the listing holds (a mode is never read
    again). For a guard run `subject` is (listed name, bytes): that entry is written
    from those bytes, never read again; every other file's content is copied from
    the template."""
    modes = []
    try:
        for relative, (kind, _detail, mode) in sorted(listing.items()):
            source, destination = template / relative, os.path.join(target, relative)
            if kind == "dir":
                os.mkdir(destination)
                modes.append((destination, mode))
            elif kind != "file":
                raise Refusal(f"the fixture template holds a link or special file: {relative}")
            elif subject and relative == subject[0]:
                _create(destination, mode, lambda out: out.write(subject[1]))
            else:
                with _regular(source) as (handle, _info):
                    _create(destination, mode, lambda out: shutil.copyfileobj(handle, out))
        for destination, mode in reversed(modes):
            os.chmod(destination, mode)
    except FileExistsError as exc:
        raise Refusal(f"two template names land on one entry of the copy: {relative}") from exc
    except OSError as exc:
        raise Refusal(f"the fixture template cannot be copied ({type(exc).__name__})") from exc


def _remove(root: Path, cause=None) -> None:
    """Remove the run directory without following a link or changing any file's
    mode: each real directory is opened by descriptor, made owner-writable, listed
    and emptied through that descriptor, and anything else is unlinked. Whatever
    stays behind refuses, after the first cause."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def empty(directory: int) -> None:
        os.fchmod(directory, stat.S_IRWXU)
        for name in os.listdir(directory):
            with contextlib.suppress(OSError):  # what stays keeps its directory, and the root
                if stat.S_ISDIR(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode):
                    inner = os.open(name, flags, dir_fd=directory)
                    try:
                        empty(inner)
                    finally:
                        os.close(inner)
                    os.rmdir(name, dir_fd=directory)
                else:
                    os.unlink(name, dir_fd=directory)

    with contextlib.suppress(OSError, RecursionError):
        top = os.open(root, flags)
        try:
            empty(top)
        finally:
            os.close(top)
        os.rmdir(root)
    if os.path.lexists(root):
        raise Refusal((f"{cause}; and " if isinstance(cause, Refusal) else "")
                      + "the run directory could not be removed and was left behind")


def _prepare(template: Path, listing: dict, spec_dir: Path, work_root: Path,
             subject=None) -> dict:
    """The run directory `<work root>/rehearsal`, created exclusively and holding the
    fixture copy, home/ and tmp/, for a template listed by `_template`."""
    if _within(work_root, spec_dir):
        raise Refusal("the work root lies inside the spec's directory: inputs live there, "
                      "outputs outside it")
    root = work_root / RUN_DIRECTORY
    try:
        os.mkdir(root)
    except FileExistsError as exc:
        raise Refusal("the run directory already exists in the work root: another run is "
                      "using it, or an earlier one left it behind") from exc
    except OSError as exc:
        raise Refusal(f"the run directory cannot be made ({type(exc).__name__})") from exc
    roots = {name: root / name for name in ("fixture", "home", "tmp")}
    try:
        for path in roots.values():
            os.mkdir(path)
        _copy_tree(listing, template, roots["fixture"], subject)
    except BaseException as exc:
        _remove(root, exc)
        if isinstance(exc, OSError):
            raise Refusal(f"the run directory cannot be filled ({type(exc).__name__})") from exc
        raise
    values = {**{name: str(path) for name, path in roots.items()}, "spec_dir": str(spec_dir),
              "python": sys.executable}
    return {"root": root, "roots": roots, "values": values, "paths": {**values, "root": str(root)}}


# -- the child ---------------------------------------------------------------


def _child_environment(run: dict, layout: dict) -> dict:
    """Built from nothing: HOME, TMPDIR, TMP and TEMP, then `inherit_env`, then `env`."""
    values = layout["values"]
    env = {"HOME": values["home"], "TMPDIR": values["tmp"], "TMP": values["tmp"],
           "TEMP": values["tmp"]}
    env.update({name: os.environ[name] for name in run["inherit_env"] if name in os.environ})
    env.update({name: _expand(value, values) for name, value in run["env"].items()})
    return env


class _Reader(threading.Thread):
    def __init__(self, stream, overflow) -> None:
        super().__init__(daemon=True)
        self.stream, self.data, self.overflowed, self.overflow = stream, bytearray(), False, overflow

    def run(self) -> None:
        for chunk in iter(lambda: self.stream.read1(65536), b""):
            if len(self.data) + len(chunk) > MAX_STREAM_BYTES:
                self.overflowed = True
                self.overflow()
            else:
                self.data += chunk
        self.stream.close()


def _end_group(process) -> None:
    with contextlib.suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)


def _finish(process, timeout: int) -> bool:
    """Wait for the child, then end its whole process group while the unreaped
    child still holds the group's id, so nothing in the group writes afterwards."""
    deadline = time.monotonic() + timeout
    while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    _end_group(process)
    process.wait()
    return True


def _spawn(argv: list, cwd: Path, env: dict, timeout: int) -> tuple:
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
    except (OSError, ValueError) as exc:
        raise Refusal(f"the entrypoint could not be started ({type(exc).__name__})") from exc
    readers = [_Reader(stream, lambda: _end_group(process))
               for stream in (process.stdout, process.stderr)]
    for reader in readers:
        reader.start()
    finished = _finish(process, timeout)
    if not finished:
        _end_group(process)
        try:
            process.wait(timeout=DRAIN_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise Refusal("the entrypoint's process could not be ended") from exc
    deadline = time.monotonic() + DRAIN_SECONDS
    for reader in readers:
        reader.join(max(0.0, deadline - time.monotonic()))
    if any(reader.is_alive() for reader in readers):
        raise Refusal("an output stream of the entrypoint stayed open after it ended: a "
                      "process it started still holds one")
    if not finished:
        raise Refusal(f"the entrypoint did not finish within {timeout} seconds; its process "
                      "group was ended")
    if any(reader.overflowed for reader in readers):
        raise Refusal(f"an output stream exceeded {MAX_STREAM_BYTES} bytes")
    return process.returncode, bytes(readers[0].data), bytes(readers[1].data)


def _normalize(text: str, layout: dict) -> str:
    """Each path the harness gave the child, as given or resolved, becomes its
    placeholder; nothing else changes (a CR stays)."""
    pairs = {(variant, "{" + name + "}") for name, path in layout["paths"].items()
             for variant in (path, os.path.realpath(path))}
    for variant, placeholder in sorted(pairs, key=lambda pair: (-len(pair[0]), pair)):
        text = text.replace(variant, placeholder)
    return text


def observe(run: dict, layout: dict) -> dict:
    """Run once in a prepared run directory (`layout`: its roots, placeholder values
    and paths) and describe what happened, with the fixture the child saw. It has no
    platform check of its own: both commands reach `_template`, which refuses off
    Linux, before any layout is built."""
    values, roots = layout["values"], layout["roots"]
    argv = [_expand(item, values) for item in run["argv"]]
    if not os.path.isabs(argv[0]):
        raise Refusal("the program must be named by an absolute path once placeholders are "
                      "expanded (normally {python}): no program is looked up")
    env = _child_environment(run, layout)
    made = {name: os.lstat(path) for name, path in roots.items()}
    before = {name: _snapshot(path, name, modes=True) for name, path in roots.items()}
    if run["cwd"] and before["fixture"].get(run["cwd"].as_posix() + "/", ("",))[0] != "dir":
        raise Refusal("the working directory is not a directory of the fixture copy")
    code, *raw = _spawn(argv, roots["fixture"] / (run["cwd"] or ""), env, run["timeout"])
    delta, digests = {"created": [], "modified": [], "deleted": []}, {}
    for name, path in roots.items():
        later, was = _snapshot(path, name, made[name]), {p: e[:2] for p, e in before[name].items()}
        digests.update({f"{name}/{p}": detail for p, (kind, detail) in later.items()
                        if kind == "file"})
        delta["created"] += [f"{name}/{p}" for p in later.keys() - was.keys()]
        delta["deleted"] += [f"{name}/{p}" for p in was.keys() - later.keys()]
        delta["modified"] += [f"{name}/{p}" for p in later.keys() & was.keys()
                              if later[p] != was[p]]
    streams = {}
    for name, data in zip(("stdout", "stderr"), raw):
        try:
            text = _normalize(data.decode("utf-8"), layout)
        except UnicodeDecodeError:
            text = None
        # An undecodable stream cannot be normalized, so it is described by
        # nothing that a path inside it could change.
        streams[name] = {"bytes": None, "sha256": None, "text": None, "full": text}
        if text is not None:
            body = text.encode("utf-8")
            streams[name].update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                                 text=text[:RECORD_TEXT_CHARS])
    environment = {name: "(inherited)" if name in run["inherit_env"] and name in os.environ
                   and name not in run["env"] else run["env"].get(name, _normalize(value, layout))
                   for name, value in sorted(env.items())}
    return {"exit_code": code, "files": {k: sorted(v) for k, v in delta.items()},
            "digests": digests, "streams": streams, "environment": environment,
            "fixture": before["fixture"]}


def _observe_once(run: dict, template: Path, listing: dict, spec_dir: Path, work_root: Path,
                  subject=None) -> dict:
    layout = _prepare(template, listing, spec_dir, work_root, subject)
    try:
        observation = observe(run, layout)
    except BaseException as exc:
        _remove(layout["root"], exc)
        raise
    _remove(layout["root"])
    return observation


# -- comparison --------------------------------------------------------------


def _check_exit(expect: dict, observation: dict) -> tuple:
    code, wanted = observation["exit_code"], expect["exit"]
    passed = code == 0 if wanted == "success" else code != 0 if wanted == "failure" else code in wanted
    return passed, f"exit {code}, expected {wanted}"


def _check_files(expect: dict, observation: dict) -> tuple:
    problems = []
    for kind in ("created", "modified", "deleted"):
        declared, seen = set(expect["files"][kind]), set(observation["files"][kind])
        problems += [f"undeclared {kind} {p}" for p in sorted(seen - declared)]
        problems += [f"declared {kind} {p} did not happen" for p in sorted(declared - seen)]
        problems += [f"{p} has another digest" for p, digest in expect["files"][kind].items()
                     if digest and observation["digests"].get(p) != digest]
    return not problems, "; ".join(problems) or "the file changes are exactly the declared ones"


def _check_patterns(expect: dict, observation: dict) -> tuple:
    problems = []
    for stream, patterns in expect["patterns"].items():
        text = observation["streams"][stream]["full"]
        if text is None and (patterns["must_match"] or patterns["must_not_match"]):
            raise Refusal(f"{stream} cannot be decoded, so its patterns cannot be judged")
        problems += [f"{stream} lacks {p!r}" for p in patterns["must_match"] if p not in text]
        problems += [f"{stream} holds {p!r}" for p in patterns["must_not_match"] if p in text]
    return not problems, "; ".join(problems) or "every pattern holds"


def _compare(expect: dict, observation: dict) -> list:
    checks = []
    for name, check in (("exit", _check_exit), ("files", _check_files),
                        ("patterns", _check_patterns)):
        passed, detail = check(expect, observation)
        checks.append({"check": name, "passed": passed, "detail": detail})
    return checks


def _matches(expect: dict, observation: dict) -> bool:
    return all(check["passed"] for check in _compare(expect, observation))


def _shows(expect: dict, observation: dict) -> bool:
    """Whether a run shows the refusal `expect` describes: its exit code and output
    patterns, whatever files the run changed."""
    return _check_exit(expect, observation)[0] and _check_patterns(expect, observation)[0]


def _public(observation) -> dict:
    if observation is None:
        return None
    streams = {name: {k: v for k, v in stream.items() if k != "full"}
               for name, stream in observation["streams"].items()}
    return {"exit_code": observation["exit_code"], "files": observation["files"],
            "streams": streams, "environment": observation["environment"]}


def rehearse(spec_path, work_root) -> dict:
    """The rehearsal record for one spec (see the module docstring)."""
    record = {"schema": REHEARSAL_RECORD, "name": None, "spec_sha256": None, "argv": None,
              "fixture_manifest_sha256": None, "observation": None, "checks": [],
              "verdict": "REFUSED", "refusal": None, "limits": list(LIMITS)}
    try:
        spec_path = _operator(spec_path, "the spec path")
        work_root = _operator(work_root, "the work root")
        spec, data = _load(spec_path)
        record["spec_sha256"] = hashlib.sha256(data).hexdigest()
        _object(spec, "the spec", ("schema", "name", "run", "expect"))
        if spec["schema"] != REHEARSAL_SPEC:
            raise Refusal(f"the spec's schema is not {REHEARSAL_SPEC}")
        record["name"] = _text(spec["name"], "name")
        run = _parse_run(spec["run"], "run")
        expect = _parse_expect(spec["expect"], "expect")
        record["argv"] = run["argv"]
        template, listing = _template(run, spec_path.parent)
        observation = _observe_once(run, template, listing, spec_path.parent, work_root)
        # The manifest is of the copy the child saw, taken just before it started.
        record["fixture_manifest_sha256"] = hashlib.sha256(
            json.dumps(observation["fixture"], sort_keys=True).encode("utf-8")).hexdigest()
        record["checks"] = _compare(expect, observation)
        record["observation"] = _public(observation)
        passed = all(check["passed"] for check in record["checks"])
        record["verdict"] = "MATCH" if passed else "MISMATCH"
    except Refusal as exc:
        record["refusal"] = str(exc)
    return record


# -- guard liveness ----------------------------------------------------------


def _check_spec_strength(refused: dict, bypassed: dict):
    """A problem sentence when the refusal or bypass signature decides nothing."""
    specific = isinstance(refused["exit"], list) and 0 not in refused["exit"]
    patterns = any(refused["patterns"][s]["must_match"] for s in ("stdout", "stderr"))
    if not (specific or patterns):
        return "'refused' must name non-zero exit codes or a must-match pattern"
    positive = any(bypassed["patterns"][s]["must_match"] for s in ("stdout", "stderr")) or \
        bypassed["files"]["created"] or bypassed["files"]["modified"]
    if not positive:
        return "'bypassed' must carry a must-match pattern or a created or modified file"
    return None


def _check_subject_digest(data: bytes, declared: str) -> bool:
    return hashlib.sha256(data).hexdigest() == declared


def _check_snippet_once(data: bytes, snippet: bytes) -> bool:
    first = data.find(snippet)
    return first >= 0 and data.find(snippet, first + 1) < 0


def _check_same_fixture(listed: dict, seen: dict) -> bool:
    return listed == seen


def _check_fired(refused: dict, triggered: dict) -> bool:
    return _matches(refused, triggered)


def _check_gone(refused: dict, neutralized: dict) -> bool:
    return not _shows(refused, neutralized)


def _check_reached(bypassed: dict, neutralized: dict) -> bool:
    return _matches(bypassed, neutralized)


def _check_quiet_without_trigger(expect: dict, refused: dict, control: dict) -> bool:
    return _matches(expect, control) and not _shows(refused, control)


def _subject(spec: dict, template: Path, listing: dict) -> tuple:
    """(listed name, bytes read, neutralized bytes): the subject is a regular file of
    the fixture template, named as its listing names it, and read once."""
    subject = _object(spec["subject"], "subject", ("path", "sha256"))
    neutralize = _object(spec["neutralize"], "neutralize", ("find", "replace"))
    find, replace = _text(neutralize["find"], "find"), _text(neutralize["replace"], "replace")
    if not find or find == replace:
        raise Refusal("neutralize needs a non-empty find and a different replacement")
    path = _text(subject["path"], "subject.path")
    if listing.get(path, ("",))[0] != "file":
        raise Refusal("the subject path must name a regular file of the fixture template, "
                      "spelled as the template's listing spells it")
    try:
        encoded = [text.encode("utf-8") for text in (find, replace)]
        with _regular(template / path) as (handle, _info):
            data = handle.read(MAX_SUBJECT_BYTES + 1)
    except (OSError, UnicodeEncodeError) as exc:
        raise Refusal("the subject cannot be read, or a snippet is not UTF-8 text "
                      f"({type(exc).__name__})") from exc
    if len(data) > MAX_SUBJECT_BYTES:
        raise Refusal(f"the subject file is larger than {MAX_SUBJECT_BYTES} bytes")
    if not _check_subject_digest(data, _text(subject["sha256"], "subject.sha256")):
        raise Refusal("the subject's digest differs from the declared one: it drifted")
    if not _check_snippet_once(data, encoded[0]):
        raise Refusal("the snippet to neutralize must occur exactly once in the subject")
    return path, data, data.replace(encoded[0], encoded[1], 1)


def check_guard(spec_path, work_root) -> dict:
    """The guard-liveness record for one spec (see the module docstring)."""
    record = {"schema": GUARD_RECORD, "name": None, "spec_sha256": None, "subject": None,
              "runs": {"triggered": None, "neutralized": None, "control": None}, "checks": [],
              "verdict": "REFUSED", "reason": None, "limits": list(LIMITS)}
    try:
        spec_path = _operator(spec_path, "the spec path")
        work_root = _operator(work_root, "the work root")
        spec, data = _load(spec_path)
        record["spec_sha256"] = hashlib.sha256(data).hexdigest()
        _object(spec, "the spec", ("schema", "name", "run", "subject", "neutralize", "refused",
                                   "bypassed"), ("control",))
        if spec["schema"] != GUARD_SPEC:
            raise Refusal(f"the spec's schema is not {GUARD_SPEC}")
        record["name"] = _text(spec["name"], "name")
        run = _parse_run(spec["run"], "run")
        refused, bypassed = (_parse_expect(spec[key], key) for key in ("refused", "bypassed"))
        control = None
        if "control" in spec:
            part = _object(spec["control"], "control", ("run", "expect"))
            control = (_parse_run(part["run"], "control.run"),
                       _parse_expect(part["expect"], "control.expect"))
            if control[0]["fixture"] != run["fixture"]:
                raise Refusal("control.run.fixture must be run.fixture: the runs share one "
                              "fixture")
        weakness = _check_spec_strength(refused, bypassed)
        if weakness:
            raise Refusal(f"the spec is too weak to decide anything: {weakness}")
        spec_dir = spec_path.parent
        template, listing = _template(run, spec_dir)
        path, original, neutralized = _subject(spec, template, listing)
        record["subject"] = {"path": path, "sha256": hashlib.sha256(original).hexdigest(),
                             "neutralized_sha256": hashlib.sha256(neutralized).hexdigest()}
        runs = [("triggered", run, original), ("neutralized", run, neutralized)]
        runs += [("control", control[0], original)] if control else []
        observed = {}
        for name, which, content in runs:
            observed[name] = _observe_once(which, template, listing, spec_dir, work_root,
                                           (path, content))
            record["runs"][name] = _public(observed[name])
            # Each run must see the template as listed, modes included, and its subject
            # as the bytes given, with the subject's listed mode.
            digest = hashlib.sha256(content).hexdigest()
            listed = dict(listing, **{path: ("file", digest, listing[path][2])})
            if not _check_same_fixture(listed, observed[name]["fixture"]):
                raise Refusal("the fixture differed between runs: the " + name + " run saw "
                              "a template file other than the one listed")
        triggered, changed, quiet = (observed.get(n) for n in ("triggered", "neutralized",
                                                               "control"))
        # Every decision check, with its result, in the order the verdict reads them.
        checks = [("fires on its trigger", _check_fired(refused, triggered), "DEAD",
                   "the guard did not fire on its trigger"),
                  ("its refusal is gone once it is neutralized", _check_gone(refused, changed),
                   "DEAD", "the refusal persists without this guard"),
                  ("the neutralized run reaches the bypass point",
                   _check_reached(bypassed, changed), "INCONCLUSIVE",
                   "the neutralized subject neither refused nor reached the bypass point")]
        if quiet is not None:
            checks.append(("it is quiet without its trigger",
                           _check_quiet_without_trigger(control[1], refused, quiet), "DEAD",
                           "the guard fires without its trigger"))
        record["checks"] = [{"check": name, "passed": passed} for name, passed, _v, _r in checks]
        failed = next(((verdict, reason) for _n, passed, verdict, reason in checks
                       if not passed), None)
        record["verdict"], record["reason"] = failed or ("LIVE", (
            "it refuses on its trigger, and with it neutralized the run gets past it"))
    except Refusal as exc:
        record["reason"] = str(exc)
    return record


def assert_guard_is_live(spec_path, work_root) -> dict:
    """Raise AssertionError unless the guard the spec names is shown LIVE."""
    record = check_guard(spec_path, work_root)
    if record["verdict"] != "LIVE":
        raise AssertionError(f"the guard is not shown live: {record['verdict']}: "
                             f"{record['reason']}")
    return record


# -- command line ------------------------------------------------------------

_USAGE = "usage: rehearse_entrypoint.py (rehearse | guard-live) SPEC --work-root DIR"


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(newline="")
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) != 4 or argv[0] not in ("rehearse", "guard-live") or argv[2] != "--work-root" \
            or argv[1].startswith("-") or argv[3].startswith("-"):
        sys.stderr.write(f"REFUSE: {_USAGE}\n")
        return 2
    try:
        if argv[0] == "rehearse":
            record, codes = rehearse(argv[1], argv[3]), {"MATCH": 0, "MISMATCH": 1}
        else:
            record, codes = check_guard(argv[1], argv[3]), {"LIVE": 0, "DEAD": 1}
    except Exception as exc:  # noqa: BLE001 - an error decides nothing
        sys.stderr.write(f"REFUSE: the harness failed ({type(exc).__name__})\n")
        return 2
    sys.stdout.write(json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    if record["verdict"] not in codes:
        reason = record.get("refusal") or record.get("reason")
        sys.stderr.write(f"REFUSE: {record['verdict']}: {reason}\n")
    return codes.get(record["verdict"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
