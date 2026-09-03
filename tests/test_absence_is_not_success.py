"""Required evidence being absent is not a successful empty verification.

Five defects in this repository have shared one root cause:

    missing contracts directory  -> empty result   -> intact
    empty contracts directory    -> empty result   -> intact
    missing review_binding.json  -> loop skipped   -> intact
    git binary unreachable       -> empty path set -> clean tree
    a foreign repository around  -> that repository's index and HEAD
      a tree with no .git of its own
      (with NO repository around it the old tool's answer depended on the
       git version: refused on 2.43, silently clean on 2.55; see
       `test_a_tree_with_no_repository_is_refused_not_clean`)

Each was fixed where it was found. Five instances of one class is not five
bugs, so this is the class written down as a control:

    PRESENT + VERIFIED        -> intact / authenticated / available
    PRESENT + INVALID         -> compromised / unauthenticated
    REQUIRED BUT ABSENT       -> unavailable / incomplete
    OPTIONAL AND ABSENT       -> explicitly not-applicable

never

    absent -> empty collection -> no problems -> success

The behavioural half asserts each known instance still fails closed. The
structural half is the part that generalises: a scan for the constructs that
produced them, so a FIFTH one has to be classified deliberately instead of
appearing by accident.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from nornyx_forge.governed_subject import INTEGRITY_UNAVAILABLE  # noqa: E402
from nornyx_forge.subject_observer import observe_governance_integrity  # noqa: E402

#: Modules where absence can change an authority answer.
NL = chr(10)

SURFACES = (
    "src/nornyx_forge/approval_trust.py",
    "src/nornyx_forge/reviewer_trust.py",
    "src/nornyx_forge/governed_subject.py",
    "src/nornyx_forge/subject_observer.py",
    "src/nornyx_forge/subject_bootstrap.py",
    "src/nornyx_forge/nornyx_runtime.py",
    "scripts/refresh_governance_evidence.py",
    "scripts/governed_content.py",
)

#: Handlers that may return an empty collection, each with the reason absence
#: cannot increase authority there. Classifying one is a decision someone makes
#: in writing; the scan below fails on anything not listed.
#:
#: Keyed by "<relative>:<function>" so moving a construct into a new function is
#: a new decision rather than an inherited exemption.
CLASSIFIED_EMPTY_RETURNS: dict[str, str] = {
    # Empty, and that is the current truth rather than an oversight: after the
    # dirty-tree fix there is no handler in these modules that turns a failure
    # into an empty collection. Two entries were written here from memory and
    # named functions that do not exist, which
    # `test_every_classification_still_names_a_real_site` caught -- an
    # exemption for a site that is not there is cover for whatever later takes
    # the name.
    #
    # An entry belongs here only with a reason beginning OPTIONAL. or
    # CONDITIONAL. that says why absence at that site cannot increase authority.
}


#: Zero-argument builtin constructors that produce an empty value.
#:
#: `frozenset` and `bytearray` were absent from the four this used to list, and
#: `str`/`bytes` were never considered. They are here for completeness rather
#: than because anything returns them: the point is that the rule no longer
#: depends on which of them a handler happens to spell.
EMPTY_CONSTRUCTORS = frozenset({
    "bytearray", "bytes", "dict", "frozenset", "list", "set", "str", "tuple",
})


def _is_empty_value(value: ast.expr, empty_names: set) -> bool:
    """Is this expression an empty collection or string?

    STRUCTURE, NOT SPELLING. The rule this replaced tested for `ast.List` with
    no elements, `ast.Dict` with no keys, and a call to one of four names.
    Measured against it, every one of these was invisible:

        return ()                a tuple displays as neither List nor Dict
        return frozenset()       a fifth constructor
        return ''                emptiness is not only about containers
        return b''
        except ...:              the scan read only the handler's top level
            if partial:
                return []
        except ...:              and only the returned expression itself
            rows = []
            return rows

    In a module whose whole subject is that a rule naming four spellings is a
    rule about the spellings. `literal_eval` decides the class and executes
    nothing.

    `return None` IS NOT COVERED, deliberately and after measuring it: adding it
    finds 8 further sites across these eight surfaces, and it is a different
    construct. An empty collection reads to a caller as "I looked and there was
    nothing"; `None` reads as "no answer", and callers branch on it. Widening
    this rule to cover it would put 8 sites in front of a classification table
    whose entries must each state why absence cannot increase authority --
    which is worth doing on its own evidence, not as a side effect of a fix to
    the spelling problem. Recorded in the ledger as its own exposure.
    """
    if isinstance(value, ast.Name):
        return value.id in empty_names
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return (
            value.func.id in EMPTY_CONSTRUCTORS
            and not value.args
            and not value.keywords
        )
    try:
        literal = ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        # Anything computed is not an empty literal, and `literal_eval` says so
        # by refusing rather than by returning a value.
        return False
    return literal is not None and hasattr(literal, "__len__") and len(literal) == 0


def _empty_return_sites(relative: str) -> list[tuple[str, int]]:
    """Every `except ...: return <empty>` in a module, with its function."""
    source = (ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative)
    found: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.ExceptHandler):
                continue
            # Names the handler itself binds to something empty, so
            # `rows = []` followed by `return rows` is the same site as
            # `return []` -- one rename apart, and the rename hid it.
            empty_names: set = set()
            for statement in ast.walk(inner):
                if isinstance(statement, ast.Assign) and _is_empty_value(
                    statement.value, empty_names
                ):
                    empty_names |= {
                        target.id for target in statement.targets
                        if isinstance(target, ast.Name)
                    }
            # ANYWHERE IN THE HANDLER, not only its top level: a return under
            # an `if` inside the handler is the same swallowed failure.
            for statement in ast.walk(inner):
                if (
                    isinstance(statement, ast.Return)
                    and statement.value is not None
                    and _is_empty_value(statement.value, empty_names)
                ):
                    found.append((node.name, statement.lineno))
    return found


#: (label, handler body, is it a swallowed failure).
#:
#: NO COUNTS ARE STATED HERE, and that is the repair rather than a better
#: count. This block said "five and four" against a seven/five table; the
#: correction updated the headline and left the dependent sentence at the
#: old value, so the comment gave two different answers to its own
#: question -- and a third review found that. Three rounds, three stale
#: numbers, in the module next to the one whose census comment documents
#: exactly this at length. A count typed beside a table nobody parses is a
#: liability; the table is immediately below, and pytest prints its ids.
#:
#: The rows expecting True were invisible to the rule that named four
#: spellings -- all but one, which is the spelling it did catch, kept so
#: the repair reads as a widening rather than a replacement. The rows
#: expecting False are the over-reach control: a handler that returns
#: something, or re-raises, is not a swallowed failure, and a screen that
#: flagged those would put real code in front of a classification table
#: for no reason.
EMPTY_RETURN_SPECIMENS = [
    ("an empty tuple display", "    return ()", True),
    ("a fifth constructor", "    return frozenset()", True),
    ("an empty string", "    return ''", True),
    ("empty bytes", "    return b''", True),
    ("returned from inside the handler",
     "    if partial:" + NL + "        return []", True),
    ("bound to a name first",
     "    rows = []" + NL + "    return rows", True),
    ("the spelling the old rule did catch", "    return []", True),

    # --- and the other direction, which must stay unflagged -------------
    ("a non-empty literal", "    return [1]", False),
    ("a computed value", "    return _recover()", False),
    ("a constructor with an argument", "    return list(rows)", False),
    ("a name bound to something real",
     "    rows = _recover()" + NL + "    return rows", False),
    ("a re-raise", "    raise", False),
]


@pytest.mark.parametrize(
    ("label", "handler", "swallowed"), EMPTY_RETURN_SPECIMENS,
    ids=[case[0] for case in EMPTY_RETURN_SPECIMENS],
)
def test_the_scan_answers_emptiness_and_not_a_list_of_spellings(
    label: str, handler: str, swallowed: bool, tmp_path: Path, monkeypatch,
):
    """Every synonym of "I looked and there was nothing" is the same site.

    Driven through `_empty_return_sites` itself rather than a copy of its rule,
    so this cannot pass against a second implementation that agrees with the
    specimens and not with the scan the gate runs.
    """
    module = tmp_path / "surface.py"
    module.write_text(
        "def probe():" + NL
        + "    try:" + NL
        + "        return _work()" + NL
        + "    except Exception:" + NL
        + NL.join("    " + line for line in handler.split(NL)) + NL,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "test_absence_is_not_success.ROOT", tmp_path, raising=True,
    )
    found = _empty_return_sites("surface.py")
    assert bool(found) is swallowed, (
        label + ": the scan " + ("missed" if swallowed else "flagged")
        + " this handler:" + NL + handler
    )
    if swallowed:
        assert found[0][0] == "probe", found


def test_every_empty_return_from_a_handler_is_classified():
    """A swallowed failure must be a decision, not a default.

    `except Exception: return []` is how the dirty-tree gate came to report a
    clean tree when git could not be run at all. The construct is not banned --
    some absences genuinely are optional -- but each one has to say which, and
    an unclassified one fails here rather than being read as harmless.
    """
    unclassified: list[str] = []
    for relative in SURFACES:
        for function, lineno in _empty_return_sites(relative):
            key = f"{relative}:{function}"
            if key not in CLASSIFIED_EMPTY_RETURNS:
                unclassified.append(f"{key} (line {lineno})")

    assert unclassified == [], (
        "these handlers turn a failure into an empty result with no stated "
        "reason why absence cannot increase authority. Classify each in "
        "CLASSIFIED_EMPTY_RETURNS or make it fail closed: " + str(unclassified)
    )


def test_every_classification_still_names_a_real_site():
    """A stale exemption is a hole nobody is watching.

    Moving or deleting one of these would otherwise leave its entry standing as
    cover for whatever later takes the name.
    """
    live = {
        f"{relative}:{function}"
        for relative in SURFACES
        for function, _ in _empty_return_sites(relative)
    }
    stale = sorted(set(CLASSIFIED_EMPTY_RETURNS) - live)
    assert stale == [], f"these classifications name sites that no longer exist: {stale}"


def test_each_classification_states_a_reason():
    """An allowlist without reasons becomes a place to hide things.

    `len(reason) > 80` was the whole of it, and eighty-one characters of
    anything satisfies that -- an assertion about LENGTH reported as one
    about explanation, in the module whose subject is exactly that
    substitution. The analogous check in the false-green audit is
    backstopped by parsing the function it names; this one had no
    backstop at all.

    A reason now has to NAME the site it exempts and say what happens
    instead, which is a claim a reader can check against the code rather
    than a quantity of prose.
    """
    for key, reason in CLASSIFIED_EMPTY_RETURNS.items():
        assert reason.startswith(("OPTIONAL.", "CONDITIONAL.")), key
        relative, _, function = key.partition(":")
        assert function and function in reason, (
            key + " is exempted by a reason that never names the function "
            "it exempts, so nobody can tell which site it was written for"
        )
        assert Path(relative).name in reason or relative in reason, (
            key + " is exempted by a reason that never names its module"
        )
        # NO CLAUSE HERE PRETENDS TO CHECK THAT THE REASON EXPLAINS.
        #
        # There was one: `any(phrase in reason for phrase in ("caller",
        # "refus", "denie", "closed", "authority"))`, under a failure
        # message reading "is exempted without saying what the caller does
        # with the empty result". A reason containing the word `caller` and
        # nothing about the caller satisfied it -- a five-stem substring
        # scan reported as a semantic check, which is the substitution this
        # module is about, committed inside the module.
        #
        # What CAN be checked mechanically is checked above: the reason
        # declares its class, names its module, and names its function, so
        # it cannot be a reason written for somewhere else. Whether it
        # explains anything is a judgement, and the honest place for it is
        # a person at review time -- said here rather than simulated with a
        # word list.
        assert len(reason) > 80, f"{key} is exempted without a real explanation"


# --------------------------------------------------------------------------
# The four known instances, each still failing closed
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "location"),
    [
        ("a missing contracts directory", "no/such/directory"),
        ("a contracts directory holding none", "tests"),
    ],
)
def test_an_unobservable_governance_surface_is_unavailable(label: str, location: str):
    state = observe_governance_integrity(ROOT / location)
    assert state.status == INTEGRITY_UNAVAILABLE, label
    assert state.authorizes_consequential_action is False, label


def test_an_unrunnable_git_is_not_a_clean_tree(monkeypatch: pytest.MonkeyPatch):
    """The fourth instance, reproduced exactly.

    `_git_lines` raises SystemExit on a non-zero exit and SystemExit is not an
    Exception, so that path was already fail-closed. What the handler caught was
    git being unreachable -- and it answered "no unstaged paths", which reads as
    a clean governed tree and lets an approval be honoured over content nobody
    could prove was unchanged.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    real = subprocess.run

    def unreachable(args, **kwargs):
        if args and args[0] == "git":
            raise FileNotFoundError(2, "not found", "git")
        return real(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", unreachable)
    with pytest.raises(SystemExit) as refusal:
        refresh._unstaged_governed_paths()
    assert "clean governed tree cannot be proven" in str(refusal.value)


# --------------------------------------------------------------------------
# The fifth instance: a repository that is not this tree's.
#
# Every git question in the evidence tool ran with the governed tree as its
# working directory and trusted whatever repository git discovered walking
# upward from there. Two outcomes, one construct:
#
#     a foreign repository above it  -> that repository's index  -> its answer
#     no repository above the tree   -> whatever `git diff` does outside a
#                                       repository on the reader's git version
#
# Measured on an archive of this repository extracted, byte for byte, into a
# temp directory inside a foreign repository (intact, borrowed) and inside a
# foreign repository whose index differed at one governed path (compromised,
# naming a file whose bytes were exactly the archive's). Outside any
# repository the same archive verified intact on git 2.55.0.windows.5 and was
# REFUSED on git 2.43.0: the first was recorded here as if it were the only
# behaviour, and an independent review measured the second. The refusal is
# git's usage error for a `diff` with more than two paths outside a
# repository; git 2.51 taught `diff --no-index` to take the first two paths
# as directories and the rest as limits, which made the same command exit 0
# printing nothing. The anchored-measurement harness in
# tests/test_recorded_measurements.py ran `--verify` in exactly such an
# extraction, so its verdict was a property of where the reader keeps temp
# files and of which git they run. The tool now establishes the repository
# before asking anything of it, on every git.
# --------------------------------------------------------------------------

#: A governed path, as the covered roots name it.
GOVERNED = "src/nornyx_forge/util.py"


def _repository(root: Path, files: dict[str, str]) -> None:
    """A repository at `root` holding `files`, committed.

    LF ON EVERY PLATFORM. `write_text` emits CRLF on Windows, and the commit
    below runs under the reader's git, whose `core.autocrlf=true` (Git for
    Windows' system default) stores LF. The tool then reads the tree under
    policy-neutral configuration, where nothing normalises, and truthfully
    reports a working copy whose bytes differ from what git holds. Measured
    when the tool stopped inheriting the reader's configuration: this
    fixture's governed file came back "modified" from a commit seconds old.
    The tool is right and the fixture was leaning on the reader's autocrlf,
    which is the dependency the tool exists to refuse.
    """
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline=NL)
    for command in (
        ["init", "-q"],
        ["add", "-A"],
        ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture"],
    ):
        subprocess.run(["git", *command], cwd=root, check=True,  # noqa: S603, S607
                       capture_output=True, timeout=600)


def _diverge_index(root: Path, relative: str) -> None:
    """Change `relative` in the index only; the file on disk keeps its bytes."""
    path = root / relative
    original = path.read_bytes()
    path.write_bytes(original + ("# index only" + NL).encode("utf-8"))
    subprocess.run(["git", "add", relative], cwd=root, check=True,  # noqa: S603, S607
                   capture_output=True, timeout=600)
    path.write_bytes(original)


def test_the_real_checkout_answers_for_itself():
    """The root check must not refuse the repository it lives in.

    Driven here because this checkout may be a worktree, whose `.git` is a
    file pointing elsewhere, and CI's is a plain clone: both must resolve to
    the tree itself, under whatever spelling git prints the path in.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    assert refresh._repository_root() == refresh.ROOT


def test_a_tree_inside_a_foreign_repository_is_refused_not_measured_against_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Measured before this check existed: `_unstaged_governed_paths` returned
    the governed path as divergent, because a repository that is not this
    tree's held a different blob for it in its index. The bytes on disk were
    exactly what they should have been.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    enclosing = tmp_path / "enclosing"
    tree = enclosing / "tree"
    _repository(enclosing, {"tree/" + GOVERNED: "print('governed')" + NL})
    _diverge_index(enclosing, "tree/" + GOVERNED)
    monkeypatch.setattr(refresh, "ROOT", tree)

    with pytest.raises(SystemExit) as refusal:
        refresh._unstaged_governed_paths()
    message = str(refusal.value)
    assert "is not the root of the git repository that encloses it" in message
    # THE REPOSITORY GIT FOUND, compared as a path. `enclosing.name in message`
    # stood here and could not fail: the message also prints ROOT, which is
    # `.../enclosing/tree`, so the name was always present.
    resolved = re.search(r"git resolves (.+?)\. Its index", message)
    assert resolved, "the refusal does not say which repository git resolved"
    assert os.path.normcase(os.path.realpath(resolved.group(1))) == os.path.normcase(
        os.path.realpath(enclosing)
    ), f"the refusal names {resolved.group(1)!r}, not the enclosing repository"
    assert "nothing was modified" in message

    # The other two questions, from the same tree. Before the root check both
    # ANSWERED, with the enclosing repository's HEAD as this tree's bound
    # revision and as its provenance. Asserted here and not in the
    # no-repository case, where a failing `git rev-parse` already produced
    # the same refusal and the same `git:unbound` before this change.
    for question in (refresh._revision, refresh._head_commit):
        with pytest.raises(SystemExit) as borrowed:
            question()
        assert "is not the root of the git repository that encloses it" in str(
            borrowed.value
        ), f"{question.__name__} answered from the enclosing repository"


def test_a_tree_with_no_repository_is_refused_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Outside any repository the tool refuses, whatever git would have said.

    What git says there depends on its version. Measured at b999537 with the
    tool as archived at f114074, in an extraction no repository encloses:

        git 2.55.0.windows.5   `git diff --name-only -- <13 roots>` exits 0
                               printing nothing; --verify reports intact
        git 2.43.0 (Linux)     the same command is a usage error, exit 129;
                               --verify refuses (measured here in WSL Ubuntu;
                               the independent review of the previous change
                               measured the same refusal)

    The first is git 2.51's pathspec limiting for `diff --no-index`: outside
    a repository, three or more paths make git compare the first two as
    directories in no-index mode and read the rest as limits, so the answer
    is empty and `_unstaged_governed_paths` returned `[]`, which every caller
    reads as a clean tree. This docstring once stated that behaviour as the
    only one; an independent review measured the second. Establishing the
    repository first makes the version irrelevant.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    placed = subprocess.run(  # noqa: S603, S607
        ["git", "rev-parse", "--show-toplevel"], cwd=tree, capture_output=True,
        text=True, timeout=600,
    )
    assert placed.returncode != 0, (
        "this test needs a temp directory outside any repository, and "
        f"{tmp_path} sits inside {placed.stdout.strip()}; point TMPDIR elsewhere"
    )
    monkeypatch.setattr(refresh, "ROOT", tree)

    with pytest.raises(SystemExit) as refusal:
        refresh._unstaged_governed_paths()
    assert "could not name the repository enclosing" in str(refusal.value)
    assert "cannot be proven" in str(refusal.value)
    # The other two vocabularies for the same absence, from the same tree: a
    # bound revision is refused, and provenance is recorded as unbound rather
    # than invented.
    with pytest.raises(SystemExit) as unbound:
        refresh._revision()
    assert "a bound revision is required" in str(unbound.value)
    assert refresh._head_commit() == "git:unbound"


#: Steering variables aimed at the foreign repository, each by the path git
#: expects for it. Two of them defeat the root check on their own: with
#: `GIT_DIR` set and no `GIT_WORK_TREE`, git takes the working directory as
#: the work tree, so `--show-toplevel` names this tree while the index and
#: HEAD are the foreign repository's; with `GIT_INDEX_FILE`, discovery finds
#: this tree's repository and compares its files against another index
#: entirely (measured under review, git 2.55: the top level still names this
#: tree). `GIT_WORK_TREE` moves the top level, which the root check refuses,
#: so it proves the drop from the other side. The remaining members of
#: `GIT_STEERING_VARIABLES` yield a refusal rather than a foreign answer.
STEERED_AT_FOREIGN = {
    "GIT_DIR": lambda foreign: foreign / ".git",
    "GIT_INDEX_FILE": lambda foreign: foreign / ".git" / "index",
    "GIT_WORK_TREE": lambda foreign: foreign,
}


@pytest.mark.parametrize("variable", sorted(STEERED_AT_FOREIGN))
def test_a_steering_variable_cannot_re_aim_the_governed_tree(
    variable: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The variables are dropped from every git call, so the answer comes
    from this tree's own repository whatever the environment says.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    _repository(tree, {GOVERNED: "print('governed')" + NL})
    foreign = tmp_path / "foreign"
    _repository(foreign, {GOVERNED: "print('foreign')" + NL})
    _diverge_index(foreign, GOVERNED)
    monkeypatch.setattr(refresh, "ROOT", tree)
    honest_paths = refresh._unstaged_governed_paths()
    honest_head = refresh._head_commit()
    assert honest_paths == []
    assert honest_head.startswith("git:") and honest_head != "git:unbound"

    monkeypatch.setenv(variable, str(STEERED_AT_FOREIGN[variable](foreign)))

    assert refresh._unstaged_governed_paths() == honest_paths, (
        f"{variable} re-aimed the dirty-tree question at another repository"
    )
    assert refresh._head_commit() == honest_head, (
        f"{variable} re-aimed provenance at another repository's HEAD"
    )


# --------------------------------------------------------------------------
# Reader configuration. Root equality is not enough.
#
# The root check above establishes WHICH repository answers. An independent
# review of that change measured what it does not establish: the
# configuration git answers UNDER. At b999537, in a fresh clone holding a
# governed, untracked `src/untracked.py`, nine reader-controlled routes --
# `GIT_CONFIG_COUNT`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`,
# `GIT_CONFIG_SYSTEM`, an `XDG_CONFIG_HOME` config and its ignore file, a
# `HOME` gitconfig and its ignore file, an include -- each left
# `git rev-parse --show-toplevel` naming the governed tree while
# `git ls-files --others --exclude-standard -- src` named nothing, and the
# dirty-tree gate reported the tree clean. A reader attributes file naming a
# clean filter did the same to a MODIFIED governed file. None of these touch
# the repository. The tool now runs every git question through one runner,
# `_git`, under a policy-neutral environment: the configuration variables
# dropped by prefix, the system and global files switched off, the default
# ignore and attributes files pinned to nothing. The repository's own
# `.git/config`, `.gitattributes` and `.gitignore` still apply, deliberately.
# --------------------------------------------------------------------------

#: A governed path with no tracked counterpart, as the covered roots name it.
UNTRACKED = "src/nornyx_forge/untracked.py"


def _file(path: Path, body: str) -> Path:
    """`body` at `path`, LF on every platform (see `_repository`)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8", newline=NL)
    return path


def _home(root: Path) -> dict[str, str]:
    """Point git's home at `root` on every platform git for Windows supports."""
    return {"HOME": str(root), "USERPROFILE": str(root)}


#: A route entry whose value is None UNSETS the variable. The HOME default
#: files (`~/.config/git/ignore`, `~/.config/git/attributes`) are consulted
#: only while `XDG_CONFIG_HOME` is unset; the GitHub ubuntu runner exports
#: it, and both HOME routes were measured there to hide nothing for a plain
#: git until the variable was cleared, so those routes clear it.
UNSET = None


def _apply(monkeypatch: pytest.MonkeyPatch, delta: dict[str, str | None]) -> None:
    for name, value in delta.items():
        if value is UNSET:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


#: label -> (tmp_path, ignore file) -> environment. Every route hands git a
#: `core.excludesFile` naming the reader's ignore file, or the default ignore
#: file that stands in for one. All were measured live at b999537 on git
#: 2.55.0.windows.5; the positive control in the test re-measures each on the
#: machine running it, so a route git has since stopped honouring fails there
#: rather than passing for nothing.
READER_CONFIGURATION_ROUTES = {
    "GIT_CONFIG_COUNT": lambda tmp, ignore: {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.excludesFile",
        "GIT_CONFIG_VALUE_0": ignore.as_posix(),
    },
    # The family is numbered, so a fixed list of names would miss any slot
    # it did not think of. Third slot, harmless first two.
    "GIT_CONFIG_COUNT third slot": lambda tmp, ignore: {
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "color.ui", "GIT_CONFIG_VALUE_0": "never",
        "GIT_CONFIG_KEY_1": "diff.noprefix", "GIT_CONFIG_VALUE_1": "true",
        "GIT_CONFIG_KEY_2": "core.excludesFile", "GIT_CONFIG_VALUE_2": ignore.as_posix(),
    },
    "GIT_CONFIG_PARAMETERS": lambda tmp, ignore: {
        "GIT_CONFIG_PARAMETERS": f"'core.excludesFile'='{ignore.as_posix()}'",
    },
    "GIT_CONFIG_GLOBAL": lambda tmp, ignore: {
        "GIT_CONFIG_GLOBAL": str(_file(
            tmp / "reader-global", f"[core]{NL}\texcludesFile = {ignore.as_posix()}{NL}",
        )),
    },
    "GIT_CONFIG_GLOBAL include.path": lambda tmp, ignore: {
        "GIT_CONFIG_GLOBAL": str(_file(
            tmp / "reader-outer",
            f"[include]{NL}\tpath = "
            + _file(tmp / "reader-inner", f"[core]{NL}\texcludesFile = {ignore.as_posix()}{NL}").as_posix()
            + NL,
        )),
    },
    "GIT_CONFIG_SYSTEM": lambda tmp, ignore: {
        "GIT_CONFIG_SYSTEM": str(_file(
            tmp / "reader-system", f"[core]{NL}\texcludesFile = {ignore.as_posix()}{NL}",
        )),
    },
    "XDG_CONFIG_HOME config": lambda tmp, ignore: {
        "XDG_CONFIG_HOME": str(_file(
            tmp / "xdg-config" / "git" / "config",
            f"[core]{NL}\texcludesFile = {ignore.as_posix()}{NL}",
        ).parents[1]),
    },
    "XDG_CONFIG_HOME ignore": lambda tmp, ignore: {
        "XDG_CONFIG_HOME": str(_file(tmp / "xdg-ignore" / "git" / "ignore", "untracked.py" + NL).parents[1]),
    },
    "HOME gitconfig": lambda tmp, ignore: {
        **_home(_file(
            tmp / "home-config" / ".gitconfig",
            f"[core]{NL}\texcludesFile = {ignore.as_posix()}{NL}",
        ).parent),
        "XDG_CONFIG_HOME": UNSET,
    },
    "HOME ignore": lambda tmp, ignore: {
        **_home(_file(
            tmp / "home-ignore" / ".config" / "git" / "ignore", "untracked.py" + NL,
        ).parents[2]),
        "XDG_CONFIG_HOME": UNSET,
    },
}


def _plain_git(
    *args: str, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """git as a reader would run it: the process environment, nothing scrubbed."""
    return subprocess.run(  # noqa: S603, S607
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=600, env=env,
    )


@pytest.mark.parametrize("route", sorted(READER_CONFIGURATION_ROUTES))
def test_reader_configuration_cannot_hide_a_governed_untracked_file(
    route: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """G1, G2 and their kin: the untracked answer is the tree's, not the reader's.

    Root resolution stays correct under every route -- that is what made
    the gap invisible to the root check -- so it is asserted alongside the
    answer rather than instead of it.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    _repository(tree, {GOVERNED: "print('governed')" + NL})
    _file(tree / UNTRACKED, "print('untracked')" + NL)
    monkeypatch.setattr(refresh, "ROOT", tree)
    honest = refresh._dirty_governed_inputs()
    assert honest == ([], [UNTRACKED])

    ignore = _file(tmp_path / "reader-ignore", "untracked.py" + NL)
    delta = READER_CONFIGURATION_ROUTES[route](tmp_path, ignore)
    _apply(monkeypatch, delta)

    # POSITIVE CONTROL. The route must be live for a plain git on this
    # machine, or the assertion after it shows nothing about isolation. The
    # control's HOME is an empty directory unless the route IS a HOME route:
    # a reader whose own `~/.gitconfig` names an excludes file would outrank
    # the system and XDG routes and fail the control for a reason that has
    # nothing to do with the route (measured under review).
    control = dict(os.environ)
    if "HOME" not in delta:
        empty_home = tmp_path / "empty-home"
        empty_home.mkdir(exist_ok=True)
        control.update(_home(empty_home))
    plain = _plain_git(
        "ls-files", "--others", "--exclude-standard", "--", "src", cwd=tree, env=control,
    )
    assert plain.returncode == 0 and plain.stdout.strip() == "", (
        f"{route} did not hide {UNTRACKED} from a plain git here, so this test "
        f"cannot show the tool is isolated from it: {plain.stdout!r} {plain.stderr!r}"
    )
    placed = _plain_git("rev-parse", "--show-toplevel", cwd=tree, env=control)
    assert placed.returncode == 0, f"{route} broke root resolution: {placed.stderr!r}"

    assert refresh._repository_root() == tree, f"{route} moved the root"
    assert refresh._dirty_governed_inputs() == honest, (
        f"{route} changed the dirty-tree answer: the governed untracked file is hidden"
    )


#: Two ways a reader attributes file hides a real change. The clean filter
#: needs its command from configuration, so that route is refused twice over;
#: `ident` needs no configuration at all, which is what makes the
#: `core.attributesFile` pin load-bearing on its own (measured: with the pin
#: removed the tool answered clean under the second route).
ATTRIBUTE_ROUTES = {
    "clean filter via GIT_CONFIG_COUNT": (
        "print('governed')" + NL,
        "print('governed')" + NL + "# appended" + NL,
    ),
    "ident via the HOME default attributes file": (
        "# $Id$" + NL + "print('governed')" + NL,
        "# $Id: tampered$" + NL + "print('governed')" + NL,
    ),
}


def _reader_attributes(route: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the route's attributes in the reader's hands."""
    if route == "clean filter via GIT_CONFIG_COUNT":
        strip = _file(
            tmp_path / "strip.py",
            "import sys" + NL
            + "data = sys.stdin.buffer.read()" + NL
            + "sys.stdout.buffer.write(data.replace(b'# appended\\n', b''))" + NL,
        )
        attributes = _file(tmp_path / "reader-attributes", "*.py filter=strip" + NL)
        monkeypatch.setenv("GIT_CONFIG_COUNT", "3")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.attributesFile")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", attributes.as_posix())
        monkeypatch.setenv("GIT_CONFIG_KEY_1", "filter.strip.clean")
        monkeypatch.setenv(
            "GIT_CONFIG_VALUE_1", f'"{Path(sys.executable).as_posix()}" "{strip.as_posix()}"'
        )
        monkeypatch.setenv("GIT_CONFIG_KEY_2", "filter.strip.required")
        monkeypatch.setenv("GIT_CONFIG_VALUE_2", "false")
        return
    home = _file(tmp_path / "home-attributes" / ".config" / "git" / "attributes", "*.py ident" + NL)
    _apply(monkeypatch, {**_home(home.parents[2]), "XDG_CONFIG_HOME": UNSET})


@pytest.mark.parametrize("route", sorted(ATTRIBUTE_ROUTES))
def test_a_reader_attributes_file_cannot_hide_a_governed_modification(
    route: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The modified answer is the tree's too, and it is decided by attributes.

    Measured at b999537: an attributes file assigning `filter=strip` to
    `*.py`, reached through `core.attributesFile` with the filter's clean
    command supplied by `GIT_CONFIG_COUNT`, made `git diff --name-only -- src`
    print nothing for a governed file with a line appended; a clean filter
    rewrites the working copy before git compares it. And with no
    configuration anywhere, `~/.config/git/attributes` reading `*.py ident`
    made a change inside a `$Id$` span vanish the same way, since `ident`
    collapses the span before the comparison. Either way the reader decides
    what "unchanged" means.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    before, after = ATTRIBUTE_ROUTES[route]
    tree = tmp_path / "tree"
    _repository(tree, {GOVERNED: before})
    _file(tree / GOVERNED, after)
    monkeypatch.setattr(refresh, "ROOT", tree)
    assert refresh._unstaged_governed_paths() == [GOVERNED]

    _reader_attributes(route, tmp_path, monkeypatch)

    plain = _plain_git("diff", "--name-only", "--", "src", cwd=tree)
    assert plain.returncode == 0 and plain.stdout.strip() == "", (
        f"{route} did not hide the change from a plain git here, so this test "
        f"cannot show the tool is isolated from it: {plain.stdout!r} {plain.stderr!r}"
    )

    assert refresh._unstaged_governed_paths() == [GOVERNED], (
        f"{route}: a reader attributes file hid a modified governed file from the tool"
    )


def _commit(root: Path, message: str) -> None:
    for command in (
        ["add", "-A"],
        ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", message],
    ):
        subprocess.run(["git", *command], cwd=root, check=True,  # noqa: S603, S607
                       capture_output=True, timeout=600)


def test_an_attributes_source_variable_cannot_hide_a_governed_modification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """`GIT_ATTR_SOURCE` reads attributes from a commit instead of the tree.

    Found by two inspectors of the configuration repair. Measured: a fixture
    whose first commit carried `*.py ident` and whose HEAD carries no
    attributes at all; with `GIT_ATTR_SOURCE=HEAD~1` a change inside a `$Id$`
    span vanished from plain `git diff --name-only`, from a plain git with
    `core.attributesFile` pinned, and from the tool. Its configuration form,
    `attr.tree`, was already refused with the rest of the reader's
    configuration. The variable is now dropped with the steering variables,
    which is what it is: it re-aims where an answer comes from.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    body = "# $Id$" + NL + "print('governed')" + NL
    _repository(tree, {".gitattributes": "*.py ident" + NL, GOVERNED: body})
    (tree / ".gitattributes").unlink()
    _commit(tree, "attribute removed")
    _file(tree / GOVERNED, "# $Id: tampered$" + NL + "print('governed')" + NL)
    monkeypatch.setattr(refresh, "ROOT", tree)
    assert refresh._unstaged_governed_paths() == [GOVERNED]

    monkeypatch.setenv("GIT_ATTR_SOURCE", "HEAD~1")
    plain = _plain_git("diff", "--name-only", "--", "src", cwd=tree)
    assert plain.returncode == 0 and plain.stdout.strip() == "", (
        "GIT_ATTR_SOURCE did not hide the change from a plain git here, so this "
        f"test cannot show the tool is isolated from it: {plain.stdout!r} {plain.stderr!r}"
    )

    assert refresh._unstaged_governed_paths() == [GOVERNED], (
        "GIT_ATTR_SOURCE hid a modified governed file from the tool"
    )


def _beyond_max_path(path: Path) -> Path:
    """`path`, spelled so that Python can create it past MAX_PATH on Windows."""
    text = str(path)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        return Path("\\\\?\\" + text)
    return path


def test_a_governed_path_beyond_max_path_is_still_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Severing the reader's global file severed `core.longpaths` with it.

    Found by two inspectors of the configuration repair. On Windows, git
    without `core.longpaths` answers for a governed path beyond MAX_PATH with
    NOTHING: `ls-files --others` and `diff --name-only` exit 0, print no
    path, and put a warning on stderr the tool does not read. The reader's
    global `core.longpaths=true` was the only thing making such a path
    visible, and the neutral environment dropped it. Measured at 342
    characters: reported under the reader's global, silent under the neutral
    environment, reported again with the key pinned on. Every other
    platform's git ignores the key, so on those this proves only that a deep
    governed path is seen, which is still the property.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    _repository(tree, {GOVERNED: "print('governed')" + NL})
    deep = "src/nornyx_forge/" + "/".join(
        f"directory-with-a-long-name-{index}" for index in range(9)
    ) + "/deep.py"
    assert len(str(tree / deep)) > 260, "the fixture path does not exceed MAX_PATH"
    target = _beyond_max_path(tree / deep)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("print('deep')" + NL, encoding="utf-8", newline=NL)
    monkeypatch.setattr(refresh, "ROOT", tree)

    if os.name == "nt":
        # POSITIVE CONTROL, where the key means something: the neutral
        # environment WITHOUT the pin is blind to the path, exit 0.
        blind = subprocess.run(  # noqa: S603, S607
            ["git", "-c", "core.longpaths=false", "ls-files", "--others",
             "--exclude-standard", "--", "src"],
            cwd=tree, capture_output=True, text=True, timeout=600,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
        )
        assert blind.returncode == 0 and blind.stdout.strip() == "", (
            "git with core.longpaths off still saw the long path here, so this "
            f"test cannot show the pin matters: {blind.stdout!r} {blind.stderr!r}"
        )

    assert refresh._dirty_governed_inputs() == ([], [deep]), (
        "an untracked governed path beyond MAX_PATH was not reported"
    )

    for command in (
        ["-c", "core.longpaths=true", "add", "-A"],
        ["-c", "core.longpaths=true", "-c", "user.name=fixture",
         "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
         "commit", "-q", "-m", "deep"],
    ):
        subprocess.run(["git", *command], cwd=tree, check=True,  # noqa: S603, S607
                       capture_output=True, timeout=600)
    target.write_text("print('deep edited')" + NL, encoding="utf-8", newline=NL)
    assert refresh._unstaged_governed_paths() == [deep], (
        "an edited governed path beyond MAX_PATH was not reported"
    )


def test_a_repository_git_refuses_is_a_refusal_not_an_unbound_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """G6. Git exits 128 for "no repository" and for "a repository I will not
    answer for": one owned by another user, whose `safe.directory` allowance
    lived in the reader configuration this tool no longer reads. Reading the
    second as the first told the operator git could not NAME the repository
    and sent provenance out as `git:unbound` for a bound tree. Found by an
    inspector of the configuration repair; measured with git's own
    `GIT_TEST_ASSUME_DIFFERENT_OWNER`, which makes every repository look
    foreign-owned. The tool must refuse in git's words, not misdescribe.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    _repository(tree, {GOVERNED: "print('governed')" + NL})
    # Built now, before every repository here starts looking foreign-owned.
    named = tmp_path / "not a git repository" / "tree"
    _repository(named, {GOVERNED: "print('governed')" + NL})
    monkeypatch.setattr(refresh, "ROOT", tree)
    assert refresh._repository_root() == tree

    monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
    # POSITIVE CONTROL under the tool's own file settings, not the reader's:
    # the question is whether THIS git honours the knob, and a reader whose
    # configuration already allows the directory would answer a different
    # question. Measured on the GitHub ubuntu runner: a plain git under the
    # runner's configuration resolved the repository despite the knob, with
    # no ownership message at all, so the control failed there for an
    # allowance the tool never sees.
    plain = _plain_git(
        "rev-parse", "--show-toplevel", cwd=tree,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )
    assert plain.returncode != 0 and "dubious ownership" in plain.stderr, (
        "this git does not refuse a foreign-owned repository under "
        f"GIT_TEST_ASSUME_DIFFERENT_OWNER, so the refusal cannot be exercised: "
        f"{plain.stdout!r} {plain.stderr!r}"
    )

    for question in (
        refresh._repository_root, refresh._head_commit,
        refresh._revision, refresh._unstaged_governed_paths,
    ):
        with pytest.raises(SystemExit) as refused:
            question()
        message = str(refused.value)
        assert "will not answer for it" in message and "dubious ownership" in message, (
            f"{question.__name__} did not report git's refusal: {message}"
        )
        assert "could not name the repository" not in message, (
            f"{question.__name__} described a refusal as an absence: {message}"
        )

    # The refusal embeds the checkout's path. Measured under review: a
    # checkout under a directory literally named "not a git repository" was
    # read as absent when git's message was matched anywhere in stderr, so
    # the match is anchored to the start of a line, and this pins it.
    monkeypatch.setattr(refresh, "ROOT", named)
    with pytest.raises(SystemExit) as refused:
        refresh._repository_root()
    assert "will not answer for it" in str(refused.value), (
        f"a path containing git's absence phrase read as absence: {refused.value}"
    )


def test_the_real_checkout_answers_under_the_neutral_environment():
    """G3. Isolation must not stop the tool answering for the repository it
    lives in -- a worktree here, a plain clone in CI -- and for a question
    configuration cannot bend, HEAD, it must agree with a plain git.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    assert refresh._repository_root() == refresh.ROOT
    plain = _plain_git("rev-parse", "HEAD", cwd=ROOT)
    assert plain.returncode == 0
    assert refresh._head_commit() == "git:" + plain.stdout.strip()
    assert refresh._revision() == "git:" + plain.stdout.strip()
    # Runs to an answer rather than a refusal; what it lists depends on the
    # checkout's state and is not the point.
    assert isinstance(refresh._unstaged_governed_paths(), list)


def test_a_genuine_change_to_the_governed_tree_is_still_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """G4. Every isolation proof above is satisfied by a tool that answers
    "clean" to everything. This is the other half: change the tree and the
    tool must say so, at each of the three questions it asks.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    body = "print('governed')" + NL
    _repository(tree, {GOVERNED: body})
    monkeypatch.setattr(refresh, "ROOT", tree)
    assert refresh._unstaged_governed_paths() == []
    assert refresh._dirty_governed_inputs() == ([], [])

    _file(tree / GOVERNED, body + "# edited" + NL)
    assert refresh._unstaged_governed_paths() == [GOVERNED]
    assert refresh._dirty_governed_inputs() == ([GOVERNED], [])

    # Staged: the working tree agrees with the index, so the unstaged
    # question is answered clean and the HEAD question is not.
    subprocess.run(["git", "add", GOVERNED], cwd=tree, check=True,  # noqa: S603, S607
                   capture_output=True, timeout=600)
    assert refresh._unstaged_governed_paths() == []
    assert refresh._dirty_governed_inputs() == ([GOVERNED], [])

    _file(tree / UNTRACKED, "print('untracked')" + NL)
    assert refresh._dirty_governed_inputs() == ([GOVERNED], [UNTRACKED])


def test_a_git_failure_under_the_neutral_environment_is_still_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """G5. A repository with no commit: the root resolves, and every question
    about HEAD fails. The runner returns the failure and each caller keeps
    its own vocabulary for it; none of them reads it as an empty answer.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=tree, check=True,  # noqa: S603, S607
                   capture_output=True, timeout=600)
    monkeypatch.setattr(refresh, "ROOT", tree)
    assert refresh._repository_root() == tree

    with pytest.raises(SystemExit) as refusal:
        refresh._dirty_governed_inputs()
    assert "failed" in str(refusal.value)
    assert "cannot be proven" in str(refusal.value)
    with pytest.raises(SystemExit) as unbound:
        refresh._revision()
    assert "a bound revision is required" in str(unbound.value)
    assert refresh._head_commit() == "git:unbound"


def test_every_git_question_in_the_tool_goes_through_the_one_runner():
    """One policy, one place. A second git start in the tool is a git question
    the policy does not reach, whatever environment its author remembered to
    pass.

    What this sees, stated so the net is not mistaken for the sea: a call to
    `subprocess.run`, `Popen`, `check_output`, `check_call` or `call` whose
    first argument is a literal list beginning with "git", anywhere in the
    module, inside a function or at module level. Not seen: a list bound to
    a name first, a tuple literal, or `subprocess.run` imported under another
    name. None of those is how this module has ever started git; the
    runner's docstring is the claim, and this is the check that reaches the
    shapes the module uses.
    """
    source = (ROOT / "scripts/refresh_governance_evidence.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(module):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node: ast.AST) -> str:
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
        return "<module>"

    starters: dict[str, list[int]] = {}
    for node in ast.walk(module):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        callee = node.func
        starts_process = (
            isinstance(callee, ast.Attribute)
            and callee.attr in {"run", "Popen", "check_output", "check_call", "call"}
            and isinstance(callee.value, ast.Name) and callee.value.id == "subprocess"
        )
        first = node.args[0]
        starts_git = (
            isinstance(first, ast.List) and first.elts
            and isinstance(first.elts[0], ast.Constant) and first.elts[0].value == "git"
        )
        if starts_process and starts_git:
            starters.setdefault(enclosing(node), []).append(node.lineno)
    assert list(starters) == ["_git"] and len(starters["_git"]) == 1, (
        f"git is started outside the one runner: {starters}"
    )


def test_a_missing_review_binding_is_not_a_passing_verification(tmp_path: Path):
    """The third instance, at the tool's own boundary.

    Deleting the artifact that carries the claims verification recomputes must
    not be the way to pass verification.
    """
    work = tmp_path / "repo"
    work.mkdir()
    archive = tmp_path / "tree.tar"
    subprocess.run(["git", "-C", str(ROOT), "archive", "-o", str(archive), "HEAD"], check=True)
    shutil.unpack_archive(str(archive), str(work), format="tar")
    for command in (["init", "-q"], ["config", "user.email", "a@b.invalid"],
                    ["config", "user.name", "a"], ["add", "-A"],
                    ["commit", "-qm", "fixture"]):
        subprocess.run(["git", "-C", str(work), *command], capture_output=True, check=True)

    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        assert subprocess.run(
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=work, capture_output=True, env=env,
        ).returncode == 0

    (work / ".nornyx/contracts/evidence/review_binding.json").unlink()
    completed = subprocess.run(
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=work, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env,
    )
    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["integrity_state"] != "intact"
    assert any("review binding is absent" in problem for problem in report["problems"])


# --------------------------------------------------------------------------
# A governed MODULE the tool imports, removed. Distinct from a governed file or
# contract, which is a different absence handled on a different path.
# --------------------------------------------------------------------------


def _settled_copy(tmp_path: Path) -> Path:
    """A faithful workspace with its evidence set generated in causal order."""
    from mutation_workspace import faithful_copy, isolated_env  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    env = isolated_env(tree)
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=900,
        )
        assert completed.returncode == 0, completed.stderr[-400:]
    return tree


def _verify(tree: Path):
    from mutation_workspace import isolated_env  # noqa: PLC0415

    return subprocess.run(  # noqa: S603
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=900,
    )


def test_a_deleted_governed_module_is_refused_not_crashed(tmp_path: Path):
    """THE CONTROL THAT HAD NO PROOF.

    `_refuse_missing_governed_module` translates a ModuleNotFoundError for
    governed source into a governance finding. Nothing exercised it: the test
    named for this class deletes a governed FILE or CONTRACT, and neither raises
    ModuleNotFoundError, so the helper never ran in any test in this suite.

    Traced backward from the observable rather than assumed. Deleting
    `src/nornyx_forge/reviewer_trust.py` and running `--verify` produces exit 2
    and a structured refusal naming the absent module -- and that message is
    built in exactly one place, which is the helper.

    The distinction under test is SEMANTIC, not the exit code. A traceback also
    exits non-zero. What separates a refusal from a crash is that the refusal is
    machine-readable, names the missing content, and reports integrity as
    UNAVAILABLE rather than claiming anything about soundness.
    """
    tree = _settled_copy(tmp_path)
    (tree / "src/nornyx_forge/reviewer_trust.py").unlink()

    completed = _verify(tree)
    combined = completed.stdout + completed.stderr

    # A CRASH would put a traceback on stderr and no JSON on stdout.
    assert "Traceback (most recent call last)" not in combined, (
        f"a missing governed module produced an uncontrolled traceback:\n"
        f"{combined[-600:]}"
    )
    assert completed.stdout.strip().startswith("{"), (
        f"the refusal is not machine-readable:\n{combined[-400:]}"
    )

    report = json.loads(completed.stdout[completed.stdout.find("{"):])
    assert report["status"] == "fail"
    verification = report["verification"]
    assert verification["integrity_state"] == "unavailable", verification
    assert verification["governed_input_match"] is False
    assert any(
        "nornyx_forge.reviewer_trust" in problem
        for problem in verification["problems"]
    ), verification["problems"]


def test_the_refusal_names_the_module_rather_than_the_python_error(tmp_path: Path):
    """An operator must learn that governed content is absent.

    Not that Python could not import something -- which is what a traceback
    says, and it sends the reader to reinstall the tool instead of restoring the
    file.
    """
    tree = _settled_copy(tmp_path)
    (tree / "src/nornyx_forge/reviewer_trust.py").unlink()

    report = json.loads(_verify(tree).stdout[_verify(tree).stdout.find("{"):])
    problem = report["verification"]["problems"][0]

    assert "governed content is missing" in problem, problem
    assert "not present in the tree" in problem, problem
    assert "ModuleNotFoundError" not in problem, (
        "the refusal leaks the Python exception name, which describes the "
        "interpreter's difficulty rather than the governed state"
    )


@pytest.mark.false_green("FG37")
def test_a_non_governed_import_failure_keeps_its_traceback(tmp_path: Path):
    """The control, and the reason the translation is narrow.
    FG37: a structural control that a COMMENT satisfied.

    Only modules under the governed source packages are translated. Anything
    else is a real environment fault, and dressing it up as a governance finding
    would hide a broken installation behind a sentence about governed content.
    """
    # AST, NOT SUBSTRING. R5: a scan must structurally distinguish USE from
    # MENTION. Measured on the previous version of this guard: the real
    # `raise exc` was deleted and replaced with the comment
    #
    #     # a non-governed failure would raise exc here
    #
    # and this control PASSED. `"raise exc" in source` cannot tell a statement
    # from a sentence about one, and a guard that a comment satisfies is not a
    # check on the code.
    #
    # (Three behavioural tests in this module did catch that deletion, which is
    # why it was not a live false green. But relying on a sibling test to cover
    # what this one claims is a helper standing in for a measured semantic --
    # the substitution the invariant names.)
    import ast  # noqa: PLC0415

    tree = ast.parse(
        (ROOT / "scripts/refresh_governance_evidence.py").read_text(encoding="utf-8")
    )
    handler = next(
        (node for node in ast.walk(tree)
         if isinstance(node, ast.FunctionDef)
         and node.name == "_refuse_missing_governed_module"),
        None,
    )
    assert handler is not None, (
        "the refusal function is gone or renamed, so this control is aimed "
        "at nothing"
    )

    guarded = [
        node for node in ast.walk(handler)
        if isinstance(node, ast.Set)
        and {getattr(e, "value", None) for e in node.elts}
        == {"governed_content", "nornyx_forge"}
    ]
    assert guarded, (
        "the translation is no longer restricted to the governed packages by a "
        "literal set of their names, so an unrelated ImportError could be "
        "reported as missing governed content"
    )

    reraises = [node for node in ast.walk(handler) if isinstance(node, ast.Raise)]
    assert reraises, (
        "the function contains no `raise` STATEMENT, so a non-governed "
        "ModuleNotFoundError is no longer re-raised -- whatever the comments say"
    )


def test_a_string_statement_anywhere_is_prose(tmp_path: Path):
    """`inert_spans` treated only a FIRST statement string as a docstring.

    A bare string one statement further down -- a PEP-224 attribute docstring,
    a free-standing note -- was in neither `inert_spans` nor
    `executable_projection`. An anchor inside one cleared TARGET IS INERT,
    cleared TARGET UNCHANGED (a string constant is an AST node) and cleared
    PROSE-ONLY MUTATION, so a prose-only edit would have been credited as a
    real change to executable Python -- the class that module exists to refuse,
    one statement position away.
    """
    from mutation_validity import InvalidMutation, check_python_mutation  # noqa: PLC0415

    before = (
        "VALUE = 1" + chr(10)
        + '"a note that is not the module docstring, mentioning TARGET"' + chr(10)
        + "def go():" + chr(10)
        + "    return VALUE" + chr(10)
    )
    after = before.replace("TARGET", "OTHER")
    try:
        check_python_mutation("probe.py", before, after, "TARGET", 1)
    except InvalidMutation as exc:
        assert "INERT" in str(exc).upper(), str(exc)
    else:
        raise AssertionError(
            "a prose-only edit to a non-leading string statement was accepted "
            "as a real change to executable Python"
        )
