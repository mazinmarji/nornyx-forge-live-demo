"""The hostile-probe CI job, held to the release contract that names it.

The closure gate in `docs/governance/RELEASE_CONTRACT_V1.md` lists the remote
CI results v1 closes on. One of them named a job no workflow in this repository
had ever defined, and every test stayed green: the gate's list was prose beside
a workflow nothing parsed, which is AC03. This module parses it, in four parts.

- Every result the gate's remote-CI line names is a job, or an interpreter of a
  job's matrix, in `.github/workflows/ci.yml`. The names are read from the
  contract, not listed again here.
- The `hostile-probe` job, and the workflow keys that reach it, have exactly
  the shape written down here and no other: an allowed set of keys for the
  workflow, the job and each step, with the values the job relies on pinned.
  The workflow's `name` and `concurrency` values are not pinned, because
  neither changes what the job runs. Anything outside that set is refused,
  whatever it is called, and each clause of the reader has an edit that must
  turn it red, as does each of its fallbacks for a value that is absent or of
  another type, except four type-coercion fallbacks that have none: a job that
  is not a mapping, the string coercion of a step's `run` and of the checkout's
  `uses`, and the empty-`run` half of the heredoc guard. Removing one of those
  four makes the reader raise; it does not make it pass.
- The step itself. Its Python is taken out of the workflow and executed against
  small synthetic repositories that carry the census's own reader. Each refusal
  it makes has a case that must fail, at the granularity of the reasons it
  names: where one refusal tests several conditions, each has its own case.
  The first case is the one shared passing control: each failing case changes
  only what its own refusal needs. A job text nothing executes would be a
  claim, not a control.
- The step against this tree. It is run here with its pytest launch
  intercepted, so the set of test modules it locates is the one the step
  itself derives, and that set is pinned exactly.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CONTRACT = ROOT / "docs" / "governance" / "RELEASE_CONTRACT_V1.md"
ASSUMPTIONS = ROOT / "docs" / "requirements" / "ASSUMPTIONS.md"
CENSUS = ROOT / "scripts" / "check_test_coverage.py"

#: The job this module holds. Checked against the contract below, so this name
#: cannot drift from the one the gate uses.
JOB = "hostile-probe"
#: The assumption that states what the job runs, cited by its title: its number
#: appears only in its own heading.
TITLE = (
    "The hostile-probe job runs every owner and specimen the registries name, "
    "and every test in the modules the closure protocol names"
)
HEREDOC = "python - <<'PY'"
PASS = "HOSTILE-PROBE: PASS"
FAIL = "HOSTILE-PROBE: FAIL - "

#: The test modules the closure protocol's corpus table locates, exactly as the
#: step derives them from this tree (see the pin test). The registry,
#: `tests/attack_classes.py`, is not a located module, and the further nodes
#: the registries name are held by the registries' own freeze tests, so neither
#: is here. Compared for equality: a change that adds or removes a corpus
#: module changes what the job runs, so it must edit this set as well.
LOCATED_MODULES = frozenset({
    "tests/test_attack_classes.py",
    "tests/test_evidence.py",
    "tests/test_false_green_audit.py",
    "tests/test_historical_reproof.py",
    "tests/test_mutation_catalogue.py",
})


def _section(text: str, heading: str) -> str:
    """The text under `heading`, up to the next heading of level one or two."""
    parts = text.split("\n" + heading + "\n")
    assert len(parts) == 2, f"{heading!r} is not exactly one section"
    return re.split(r"^#{1,2}(?:[ \t]|$)", parts[1], maxsplit=1, flags=re.M)[0]


def _load(text: str) -> dict:
    return yaml.safe_load(text)


def remote_ci_results(contract: str) -> tuple[list[str], list[str]]:
    """(interpreters, jobs) that the closure gate's remote-CI line names."""
    gate = _section(contract, "## The closure gate")
    named = re.findall(r"Remote CI \(([^)]*)\)", gate)
    assert len(named) == 1, f"the closure gate names its remote results {len(named)} times"
    interpreters: list[str] = []
    jobs: list[str] = []
    for item in (part.strip() for part in named[0].split(",")):
        versions = [version.strip() for version in item.split("/")]
        if all(re.fullmatch(r"\d+\.\d+", version) for version in versions):
            interpreters += versions
        else:
            jobs.append(item)
    return interpreters, jobs


def _matrix_holders(jobs: dict, interpreters: list[str]) -> list[str]:
    """The jobs whose python-version matrix carries every named interpreter."""
    holders = []
    for name, job in jobs.items():
        matrix = ((job.get("strategy") or {}).get("matrix") or {}).get("python-version") or []
        if interpreters and set(interpreters) <= {str(value) for value in matrix}:
            holders.append(name)
    return holders


def missing_remote_results(contract: str, workflow_text: str) -> list[str]:
    """Every remote result the gate names that the workflow does not define."""
    interpreters, names = remote_ci_results(contract)
    jobs = _load(workflow_text).get("jobs") or {}
    missing = [f"job {name}" for name in names if name not in jobs]
    if not _matrix_holders(jobs, interpreters):
        missing.append("a matrix over " + " / ".join(interpreters))
    return missing


def _without_job(text: str, name: str) -> str:
    """The workflow with one job's key and body removed and its comment kept."""
    lines = text.splitlines(keepends=True)
    start = lines.index(f"  {name}:\n")
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith("    ")):
        end += 1
    return "".join(lines[:start] + lines[end:])


def _once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, f"{old!r} occurs {text.count(old)} times"
    return text.replace(old, new)


def test_every_remote_result_the_closure_gate_names_is_defined_by_the_workflow():
    """AC03 for the gate's remote-CI line, which nothing parsed.

    The job this module exists for was missing from the workflow for as long
    as the contract had named it. The negatives are the shapes that let that
    happen: the job absent, and only its comment left behind.
    """
    contract = CONTRACT.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    interpreters, names = remote_ci_results(contract)
    assert interpreters and names and JOB in names, (interpreters, names)
    assert missing_remote_results(contract, workflow) == []

    # NEGATIVE: the job gone with its comment still standing above where it was.
    orphaned = _without_job(workflow, JOB)
    assert f"  {JOB}:\n" not in orphaned and JOB in orphaned
    assert missing_remote_results(contract, orphaned) == [f"job {JOB}"]
    # NEGATIVE: the names come from the contract. One more name there is one
    # more result the workflow must define.
    widened = _once(contract, f"strict-authorization, {JOB})", f"strict-authorization, {JOB}, "
                    "a-job-nobody-defined)")
    assert missing_remote_results(widened, workflow) == ["job a-job-nobody-defined"]
    extended = _once(contract, "3.10 / 3.11 / 3.12 / 3.13,", "3.10 / 3.11 / 3.12 / 3.13 / 3.99,")
    assert missing_remote_results(extended, workflow) == [
        "a matrix over 3.10 / 3.11 / 3.12 / 3.13 / 3.99"]


# --------------------------------------------------------------------------
# The job's shape, as an allowed set
# --------------------------------------------------------------------------

#: The workflow's own keys. `permissions` and `defaults` reach this job, so
#: their values are pinned; `env` is not among them, so no workflow-level
#: environment reaches the step.
WORKFLOW_KEYS = frozenset({"name", "on", "concurrency", "permissions", "defaults", "jobs"})
WORKFLOW_VALUES = {"permissions": {"contents": "read"}, "defaults": {"run": {"shell": "bash"}}}
#: The push trigger is filtered to main. A head that is not on main gets its
#: run by dispatch; a pull-request run tests a merge commit, not the head.
TRIGGERS = {"push": {"branches": ["main"]}, "pull_request": None, "workflow_dispatch": None}
JOB_KEYS = frozenset({"runs-on", "timeout-minutes", "steps"})
#: The job's steps, in order, and the keys each may carry: checkout,
#: setup-python, the install, and the step that runs the corpus.
STEP_KEYS = (
    frozenset({"uses", "with"}),
    frozenset({"uses", "with"}),
    frozenset({"run"}),
    frozenset({"name", "run"}),
)
CHECKOUT = {"fetch-depth": 0, "persist-credentials": False}
INSTALL = "python -m pip install -e '.[demo,dev]'"


def _same(left: object, right: object) -> bool:
    """Equal as JSON, so that 0 and False, or 1 and True, are different values."""
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _keys(where: str, found: object, allowed: frozenset) -> list[str]:
    """One problem for each key outside the allowed set, and each allowed key absent."""
    present = {"on" if key is True else key for key in found} if isinstance(found, dict) else set()
    return [f"{where} {'carries' if key in present else 'lacks'} {key!r}"
            for key in sorted(present ^ allowed, key=str)]


def job_shape_problems(workflow: dict, interpreters: list[str]) -> list[str]:
    """Every way the job, or a workflow key that reaches it, differs from its allowed shape."""
    jobs = workflow.get("jobs") or {}
    job = jobs.get(JOB)
    if not isinstance(job, dict):
        return [f"there is no {JOB} job"]
    problems = _keys("the workflow", workflow, WORKFLOW_KEYS)
    for key, value in WORKFLOW_VALUES.items():
        if key in workflow and not _same(workflow[key], value):
            problems.append(f"the workflow's {key} is not exactly {value}")
    # PyYAML reads the bare key `on` as the boolean True.
    if not _same(workflow.get("on", workflow.get(True)), TRIGGERS):
        problems.append("the workflow's triggers are not exactly push to main, "
                        "pull_request and workflow_dispatch")
    problems += _keys("the job", job, JOB_KEYS)
    platforms = {jobs[name].get("runs-on") for name in _matrix_holders(jobs, interpreters)}
    if job.get("runs-on") not in platforms:
        problems.append("the job runs on a platform the interpreter matrix does not")
    minutes = job.get("timeout-minutes")
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes <= 0:
        problems.append("the job has no timeout")
        minutes = 0
    steps = job.get("steps") or []
    if len(steps) != len(STEP_KEYS):
        problems.append(f"the job has {len(steps)} steps, not checkout, setup-python, "
                        "the install and the corpus")
    for number, (step, allowed) in enumerate(zip(steps, STEP_KEYS), 1):
        problems += _keys(f"step {number}", step, allowed)
    checkout, setup, install, last = [
        step if isinstance(step, dict) else {} for step in (list(steps) + [{}] * 4)[:4]]
    if not str(checkout.get("uses", "")).startswith("actions/checkout@"):
        problems.append("the first step is not actions/checkout")
    if not _same(checkout.get("with"), CHECKOUT):
        problems.append("the checkout's options are not exactly full history and no kept token")
    if not str(setup.get("uses", "")).startswith("actions/setup-python@"):
        problems.append("the second step is not actions/setup-python")
    options = setup.get("with") if isinstance(setup.get("with"), dict) else {}
    if set(options) != {"python-version"}:
        problems.append("the interpreter setup carries options other than python-version")
    if str(options.get("python-version")) not in interpreters:
        problems.append("the job runs on an interpreter the gate does not name")
    if install.get("run") != INSTALL:
        problems.append("the third step is not exactly the install of the demo extra")
    lines = str(last.get("run", "")).splitlines()
    if not lines or lines[0] != HEREDOC:
        problems.append("the corpus step does not open a Python heredoc")
    if not lines or lines[-1] != "PY":
        problems.append("the corpus step does not end with its heredoc")
    if "PY" in lines[1:-1]:
        problems.append("the corpus step closes its heredoc early")
    limits = re.findall(r"^LIMIT = (\d+)\b", "\n".join(lines), re.M)
    if len(limits) != 1:
        problems.append("the corpus step does not set its limit on pytest exactly once")
    elif int(limits[0]) >= minutes * 60:
        problems.append("the step's own limit on pytest does not sit below the job's")
    return problems


def _step(jobs: dict, number: int) -> dict:
    return jobs[JOB]["steps"][number - 1]


def _run(jobs: dict, text: str) -> None:
    _step(jobs, 4)["run"] = text


def _corpus(jobs: dict) -> str:
    return _step(jobs, 4)["run"]


#: (what the edit is, the edit, the problem the reader must report). Each
#: clause of `job_shape_problems` has at least one, and so has each of its
#: fallbacks for a value that is absent or of another type, except four
#: type-coercion fallbacks that have none (a job that is not a mapping, the
#: string coercion of a step's `run` and of the checkout's `uses`, and the
#: empty-`run` half of the heredoc guard): removing one of those makes the
#: reader raise; it does not make it pass. Job and step keys named in the
#: edits are examples of the allowed set's complement, not a list the reader
#: checks.
JOB_EDITS = [
    ("the job removed", lambda wf: wf["jobs"].pop(JOB), f"there is no {JOB} job"),
    ("a workflow-level env", lambda wf: wf.update({"env": {"PYTEST_ADDOPTS": "-k nothing"}}),
     "the workflow carries 'env'"),
    ("the workflow's defaults removed", lambda wf: wf.pop("defaults"),
     "the workflow lacks 'defaults'"),
    ("a working directory in the workflow's defaults",
     lambda wf: wf["defaults"]["run"].update({"working-directory": "tests"}),
     "the workflow's defaults is not exactly"),
    ("the workflow's permissions widened", lambda wf: wf.update({"permissions": "write-all"}),
     "the workflow's permissions is not exactly"),
    ("no push trigger", lambda wf: wf[True].pop("push"), "the workflow's triggers are not exactly"),
    ("no pull_request trigger", lambda wf: wf[True].pop("pull_request"),
     "the workflow's triggers are not exactly"),
    ("no workflow_dispatch trigger", lambda wf: wf[True].pop("workflow_dispatch"),
     "the workflow's triggers are not exactly"),
    ("push on every branch", lambda wf: wf[True]["push"].update({"branches": ["**"]}),
     "the workflow's triggers are not exactly"),
    ("a scheduled trigger", lambda wf: wf[True].update({"schedule": [{"cron": "0 0 * * *"}]}),
     "the workflow's triggers are not exactly"),
    ("a job-level env", lambda wf: wf["jobs"][JOB].update({"env": {"PYTEST_ADDOPTS": "-k x"}}),
     "the job carries 'env'"),
    ("a job-level defaults", lambda wf: wf["jobs"][JOB].update(
        {"defaults": {"run": {"working-directory": "tests"}}}), "the job carries 'defaults'"),
    ("a job-level working directory", lambda wf: wf["jobs"][JOB].update(
        {"working-directory": "tests"}), "the job carries 'working-directory'"),
    ("job-level permissions", lambda wf: wf["jobs"][JOB].update({"permissions": "write-all"}),
     "the job carries 'permissions'"),
    ("failure tolerated", lambda wf: wf["jobs"][JOB].update({"continue-on-error": True}),
     "the job carries 'continue-on-error'"),
    ("a condition on the job", lambda wf: wf["jobs"][JOB].update({"if": "false"}),
     "the job carries 'if'"),
    ("a dependency on another job", lambda wf: wf["jobs"][JOB].update({"needs": ["test"]}),
     "the job carries 'needs'"),
    ("a matrix, which renames the check", lambda wf: wf["jobs"][JOB].update(
        {"strategy": {"matrix": {"python-version": ["3.13"]}}}), "the job carries 'strategy'"),
    ("a name, which renames the check", lambda wf: wf["jobs"][JOB].update({"name": "other"}),
     "the job carries 'name'"),
    ("a container", lambda wf: wf["jobs"][JOB].update({"container": "python:3.13"}),
     "the job carries 'container'"),
    ("another platform", lambda wf: wf["jobs"][JOB].update({"runs-on": "windows-latest"}),
     "the job runs on a platform the interpreter matrix does not"),
    ("no timeout", lambda wf: wf["jobs"][JOB].pop("timeout-minutes"), "the job has no timeout"),
    ("a timeout of zero", lambda wf: wf["jobs"][JOB].update({"timeout-minutes": 0}),
     "the job has no timeout"),
    ("a timeout that is a boolean", lambda wf: wf["jobs"][JOB].update({"timeout-minutes": True}),
     "the job has no timeout"),
    ("a step that writes the environment of the next", lambda wf: wf["jobs"][JOB]["steps"].insert(
        3, {"run": 'echo "PYTEST_ADDOPTS=-k nothing" >> "$GITHUB_ENV"'}),
     "the job has 5 steps"),
    ("an env on the corpus step", lambda wf: _step(wf["jobs"], 4).update(
        {"env": {"PYTEST_ADDOPTS": "-k nothing"}}), "step 4 carries 'env'"),
    ("failure tolerated on the corpus step", lambda wf: _step(wf["jobs"], 4).update(
        {"continue-on-error": True}), "step 4 carries 'continue-on-error'"),
    ("another shell for the corpus step", lambda wf: _step(wf["jobs"], 4).update({"shell": "sh"}),
     "step 4 carries 'shell'"),
    ("a condition on the corpus step", lambda wf: _step(wf["jobs"], 4).update({"if": "false"}),
     "step 4 carries 'if'"),
    ("a working directory for the corpus step", lambda wf: _step(wf["jobs"], 4).update(
        {"working-directory": "tests"}), "step 4 carries 'working-directory'"),
    ("the corpus step unnamed", lambda wf: _step(wf["jobs"], 4).pop("name"),
     "step 4 lacks 'name'"),
    ("an env on the install", lambda wf: _step(wf["jobs"], 3).update(
        {"env": {"PIP_NO_DEPS": "1"}}), "step 3 carries 'env'"),
    ("a condition on the checkout", lambda wf: _step(wf["jobs"], 1).update({"if": "false"}),
     "step 1 carries 'if'"),
    ("an env on the interpreter setup", lambda wf: _step(wf["jobs"], 2).update(
        {"env": {"PYTHONPATH": "tests"}}), "step 2 carries 'env'"),
    ("another action in place of the checkout", lambda wf: _step(wf["jobs"], 1).update(
        {"uses": "someone/checkout@v1"}), "the first step is not actions/checkout"),
    ("a shallow clone", lambda wf: _step(wf["jobs"], 1)["with"].update({"fetch-depth": 1}),
     "the checkout's options are not exactly"),
    ("the token kept in the checkout", lambda wf: _step(wf["jobs"], 1)["with"].update(
        {"persist-credentials": True}), "the checkout's options are not exactly"),
    ("the depth written as a boolean", lambda wf: _step(wf["jobs"], 1)["with"].update(
        {"fetch-depth": False}), "the checkout's options are not exactly"),
    ("another ref checked out", lambda wf: _step(wf["jobs"], 1)["with"].update({"ref": "main"}),
     "the checkout's options are not exactly"),
    ("another action in place of setup-python", lambda wf: _step(wf["jobs"], 2).update(
        {"uses": "someone/setup-python@v1"}), "the second step is not actions/setup-python"),
    ("an option beside the interpreter", lambda wf: _step(wf["jobs"], 2)["with"].update(
        {"cache": "pip"}), "the interpreter setup carries options other than python-version"),
    ("an interpreter the gate does not name", lambda wf: _step(wf["jobs"], 2)["with"].update(
        {"python-version": "3.9"}), "the job runs on an interpreter the gate does not name"),
    ("the install without the demo extra", lambda wf: _step(wf["jobs"], 3).update(
        {"run": "python -m pip install -e '.[dev]'"}), "the third step is not exactly the install"),
    ("another opening for the corpus step", lambda wf: _run(
        wf["jobs"], _corpus(wf["jobs"]).replace(HEREDOC, "python3 - <<'PY'", 1)),
     "the corpus step does not open a Python heredoc"),
    ("a command after the heredoc", lambda wf: _run(wf["jobs"], _corpus(wf["jobs"]) + "echo done\n"),
     "the corpus step does not end with its heredoc"),
    ("the heredoc closed early", lambda wf: _run(
        wf["jobs"], _corpus(wf["jobs"]).replace(HEREDOC + "\n", HEREDOC + "\nPY\n", 1)),
     "the corpus step closes its heredoc early"),
    ("the step's limit set twice", lambda wf: _run(wf["jobs"], re.sub(
        r"(?m)^(LIMIT = \d+.*)$", r"\1\nLIMIT = 99999", _corpus(wf["jobs"]))),
     "does not set its limit on pytest exactly once"),
    ("the step's limit above the job's", lambda wf: _run(wf["jobs"], re.sub(
        r"(?m)^LIMIT = \d+", "LIMIT = 999999", _corpus(wf["jobs"]))),
     "the step's own limit on pytest does not sit below the job's"),
    # The reader's fallbacks for a value that is absent or of another type. Each
    # edit below is one the reader must report rather than raise on.
    ("the workflow's jobs removed", lambda wf: wf.pop("jobs"), f"there is no {JOB} job"),
    ("the job's steps removed", lambda wf: wf["jobs"][JOB].pop("steps"),
     "the job lacks 'steps'"),
    ("the install step removed", lambda wf: wf["jobs"][JOB]["steps"].pop(2),
     "the job has 3 steps"),
    ("the corpus step a string", lambda wf: wf["jobs"][JOB]["steps"].__setitem__(
        3, "python -m pytest"), "step 4 lacks 'run'"),
    ("the corpus step a list of its keys", lambda wf: wf["jobs"][JOB]["steps"].__setitem__(
        3, ["name", "run"]), "step 4 lacks 'run'"),
    ("the interpreter setup's options a string", lambda wf: _step(wf["jobs"], 2).update(
        {"with": "3.13"}), "the interpreter setup carries options other than python-version"),
    ("the corpus step's run empty", lambda wf: _run(wf["jobs"], ""),
     "the corpus step does not open a Python heredoc"),
]


def test_the_job_and_the_workflow_keys_that_reach_it_have_exactly_the_allowed_shape():
    """The job must be able to answer for the exact head the gate asks about.

    Nothing may skip it, tolerate its failure, rename the job, leave it
    unbounded, or change the environment or the directory its step runs in.
    The reader does not list those forms: it accepts an allowed set of keys at
    each level and refuses the rest, so an `env` carrying `PYTEST_ADDOPTS` is
    refused for being an `env`, not for what it holds. The interpreter and the
    platform are read from what the gate names and from the matrix that runs
    them. The workflow's `name` and `concurrency` are allowed keys whose values
    are unpinned, because neither changes what the job runs.
    """
    workflow = _load(WORKFLOW.read_text(encoding="utf-8"))
    interpreters, _names = remote_ci_results(CONTRACT.read_text(encoding="utf-8"))
    assert job_shape_problems(workflow, interpreters) == []
    unreported = []
    for label, edit, problem in JOB_EDITS:
        specimen = copy.deepcopy(workflow)
        edit(specimen)
        # repr, not ==: 0 == False, and one edit changes exactly that.
        assert repr(specimen) != repr(workflow), f"{label}: the edit changed nothing"
        found = job_shape_problems(specimen, interpreters)
        if not any(problem in line for line in found):
            unreported.append(f"{label}: expected {problem!r}, got {found}")
    assert unreported == [], "\n".join(unreported)


def test_the_workflow_points_at_the_one_statement_of_what_the_job_runs():
    """The job's scope is stated once, and the workflow's comment points there."""
    headings = re.findall(r"^## A-\d+ (.+)$", ASSUMPTIONS.read_text(encoding="utf-8"), re.M)
    assert headings.count(TITLE) == 1, "the assumption the workflow points at is not one entry"
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    key = lines.index(f"  {JOB}:")
    comment = []
    while key > 0 and lines[key - 1].startswith("  #"):
        key -= 1
        comment.insert(0, lines[key][3:].strip())
    assert TITLE in " ".join(comment), "the job's comment does not name the assumption"


# --------------------------------------------------------------------------
# The step, executed
# --------------------------------------------------------------------------


def step_source() -> str:
    """The Python the job's last step runs, exactly as the workflow holds it."""
    run = _load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][JOB]["steps"][-1]["run"]
    lines = run.splitlines()
    assert lines[0] == HEREDOC and lines[-1] == "PY", "the step is not one Python heredoc"
    return "\n".join(lines[1:-1]) + "\n"


GATE = "(2 FG + 1 AC)"
OWNERS = (
    ("FG01", "tests/test_false_green_audit.py::test_owner_one"),
    ("FG02", "tests/test_named.py::test_owner_two"),
)
SPECIMENS = (("AC01", ("tests/test_named.py::test_specimen",)),)
TABLE = (
    "| Corpus | Where |", "|---|---|",
    "| Registry | `tests/attack_classes.py` |",
    "| Audit | `tests/test_false_green_audit.py` (`INVENTORY`) |",
    "| Probes | `tests/test_attack_classes.py` |",
)
#: Every test body, failing: under a mode that runs no test body, the run must
#: still be refused.
FAILING = {name: "assert False" for name in (
    "test_owner_one", "test_probe", "test_second_probe", "test_owner_two", "test_specimen")}
SETUP_ONLY_CONFTEST = "def pytest_configure(config):\n    config.option.setuponly = True\n"
DESELECT = (
    "def pytest_collection_modifyitems(config, items):\n"
    "    items[:] = [item for item in items if item.name != {name!r}]\n"
)
#: A row naming a module whose one test fails if it runs: a row the step drops
#: without refusing would turn such a repository green.
EXTRA_ROW = "| Extra | `tests/test_extra.py` |"
EXTRA = {"tests/test_extra.py": "\n\ndef test_extra():\n    assert False\n"}
#: A second statement of the corpus, after a block inside which a line starting
#: `# ` is not a heading. Read as a heading, that line would end the section
#: before the second statement.
HIDDEN_COUNT = "    Permanent hostile corpus (9 FG + 1 AC)\n"
GATE_REFUSED = "in its '## The closure gate' section"
PROTOCOL_REFUSED = "in its '## Where the corpus lives' section"


def _hidden(opening: str, closing: str) -> str:
    """A block that holds a line starting `# `, then the extra row."""
    return f"\n{opening}\n# not a heading here\n{closing}\n\n{EXTRA_ROW}\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def _tests(bodies: dict, *names: str) -> str:
    return "".join(f"\n\ndef {name}():\n    {bodies.get(name, 'assert True')}\n" for name in names)


def synthetic(tmp_path: Path, *, gate: str = GATE, gate_elsewhere: bool = False,
              gate_heading: str = "## The closure gate", gate_extra: str = "",
              rows: tuple = (), table: tuple | None = None, after_table: str = "",
              heading: str = "## Where the corpus lives", prose_first: bool = False,
              protocol_extra: str = "", owners: tuple = OWNERS, specimens: tuple = SPECIMENS,
              bodies: dict | None = None, conftest: str | None = None, ini: str = "",
              files: dict | None = None) -> Path:
    """A repository with the shape the step reads, and the census's own reader."""
    bodies = bodies or {}
    repo = tmp_path / "repo"
    _write(repo / "pytest.ini", "[pytest]\n" + ini)
    (repo / "scripts").mkdir(parents=True)
    shutil.copyfile(CENSUS, repo / "scripts" / "check_test_coverage.py")
    line = f"    Permanent hostile corpus {gate}     PASS\n"
    _write(repo / "docs/governance/RELEASE_CONTRACT_V1.md",
           f"# Contract\n\n{gate_heading}\n\n" + ("" if gate_elsewhere else line) + gate_extra
           + "\n## After the gate\n\n" + (line if gate_elsewhere else ""))
    lines = (*TABLE, *rows) if table is None else table
    # `tests/test_elsewhere.py` fails if it runs. It is cited in prose inside
    # the corpus section, and in prose and a table of a later section. None of
    # them may bring it into the run.
    _write(repo / "docs/governance/CLOSURE_PROTOCOL.md",
           f"# Protocol\n\n{heading}\n\n" + ("Prose before the table.\n\n" if prose_first else "")
           + "\n".join(lines) + "\n" + after_table
           + "\nThis cites `tests/test_elsewhere.py`, outside the table.\n"
           "\n## A later section\n\nSo does this: `tests/test_elsewhere.py`.\n"
           "\n| Elsewhere | Where |\n|---|---|\n| Other | `tests/test_elsewhere.py` |\n"
           + protocol_extra)
    _write(repo / "tests/attack_classes.py",
           "from collections import namedtuple\n\nAttackClass = namedtuple('AttackClass', "
           "'ident specimens')\nATTACK_CLASSES = tuple(AttackClass(*row) for row in "
           f"{specimens!r})\n")
    _write(repo / "tests/test_false_green_audit.py",
           "from collections import namedtuple\n\nFalseGreen = namedtuple('FalseGreen', "
           f"'ident owner')\nINVENTORY = tuple(FalseGreen(*row) for row in {owners!r})\n"
           + _tests(bodies, "test_owner_one"))
    _write(repo / "tests/test_attack_classes.py", _tests(bodies, "test_probe", "test_second_probe"))
    _write(repo / "tests/test_named.py",
           _tests(bodies, "test_owner_two", "test_specimen") + _tests({}, "test_not_named")
           .replace("assert True", "assert False"))
    _write(repo / "tests/test_elsewhere.py", _tests({}, "test_elsewhere")
           .replace("assert True", "assert False"))
    if conftest is not None:
        _write(repo / "tests/conftest.py", conftest)
    for relative, text in (files or {}).items():
        _write(repo / relative, text)
    return repo


def run_step(repo: Path, tmp_path: Path, *, env: dict | None = None, unset: tuple = (),
             source: str | None = None) -> tuple[int, str, str]:
    """(exit code, last line, whole output) of the step run in `repo`."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"}}
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(parents=True, exist_ok=True)
    environment.update({"RUNNER_TEMP": str(runner_temp), "PYTHONDONTWRITEBYTECODE": "1"})
    environment.update(env or {})
    for key in unset:
        environment.pop(key, None)
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-"], input=source or step_source(), cwd=repo, env=environment,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    output = completed.stdout + completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    return completed.returncode, (lines[-1] if lines else ""), output


#: (label, how the repository or the run differs from the first row, and the
#: reason the verdict must give -- None for a pass).
CASES = [
    ("the corpus runs", {}, None),
    ("the gate counts differently from the registries", {"gate": "(3 FG + 1 AC)"},
     "the closure gate counts 3 FG + 1 AC and the registries hold 2 FG + 1 AC"),
    ("the gate states the corpus twice", {"gate": GATE + "\n    Permanent hostile corpus (9 FG + 1 AC)"},
     "does not state the corpus exactly once"),
    ("the gate states the corpus once, in another shape", {"gate": "(two FG + one AC)"},
     "does not state the corpus exactly once"),
    ("the gate mentions the corpus a second time in another shape",
     {"gate_extra": "    Permanent hostile corpus: see the protocol\n"},
     "does not state the corpus exactly once"),
    ("the count sits outside the closure gate", {"gate_elsewhere": True},
     "does not state the corpus exactly once"),
    ("the contract's closure-gate section is renamed", {"gate_heading": "## The closing gate"},
     "does not hold exactly one '## The closure gate' section"),
    ("the protocol's section is renamed", {"heading": "## Where the corpus is kept"},
     "does not hold exactly one '## Where the corpus lives' section"),
    ("the protocol's section appears twice",
     {"protocol_extra": "\n## Where the corpus lives\n\n| Corpus | Where |\n|---|---|\n"},
     "does not hold exactly one '## Where the corpus lives' section"),
    ("the protocol's section does not open with its table", {"prose_first": True},
     "does not open with a table"),
    ("the protocol's table has no separator row",
     {"table": (TABLE[0], *TABLE[2:])}, "does not open with a table"),
    ("a row inside the table is indented", {"rows": ("  " + EXTRA_ROW,), "files": EXTRA},
     "a line of the corpus table does not start with |"),
    ("a row inside the table has no leading pipe",
     {"rows": (EXTRA_ROW.lstrip("| "),), "files": EXTRA},
     "a line of the corpus table does not start with |"),
    ("a row follows a blank line", {"after_table": "\n" + EXTRA_ROW + "\n", "files": EXTRA},
     "a line after the corpus table holds |"),
    ("an indented row follows a blank line",
     {"after_table": "\n   " + EXTRA_ROW + "\n", "files": EXTRA},
     "a line after the corpus table holds |"),
    ("a row follows a sub-heading inside the section",
     {"after_table": "\n### Also\n\n" + EXTRA_ROW + "\n", "files": EXTRA},
     "a line after the corpus table holds |"),
    ("a row written as a block quote follows the table",
     {"after_table": "\n> " + EXTRA_ROW + "\n", "files": EXTRA},
     "a line after the corpus table holds |"),
    ("a row written as a list item follows the table",
     {"after_table": "\n- " + EXTRA_ROW + "\n", "files": EXTRA},
     "a line after the corpus table holds |"),
    ("a backtick fence in the closure gate hides a second statement",
     {"gate_extra": "```\n# not a heading here\n```\n" + HIDDEN_COUNT}, GATE_REFUSED),
    ("an HTML block in the closure gate hides a second statement",
     {"gate_extra": "<!--\n# not a heading here\n-->\n" + HIDDEN_COUNT}, GATE_REFUSED),
    ("a backtick fence in the corpus section hides a row",
     {"after_table": _hidden("```", "```"), "files": EXTRA}, PROTOCOL_REFUSED),
    ("a tilde fence in the corpus section hides a row",
     {"after_table": _hidden("~~~", "~~~"), "files": EXTRA}, PROTOCOL_REFUSED),
    ("a fence indented by three spaces hides a row",
     {"after_table": _hidden("   ````", "   ````"), "files": EXTRA}, PROTOCOL_REFUSED),
    ("an HTML block in the corpus section hides a row",
     {"after_table": _hidden("<div>", "</div>"), "files": EXTRA}, PROTOCOL_REFUSED),
    ("a table row names no module", {"rows": ("| Stray | tests/test_elsewhere.py |",)},
     "a corpus table row names no module"),
    ("a table row names a second module bare",
     {"rows": ("| Extra | `tests/test_attack_classes.py`, tests/test_extra.py |",), "files": EXTRA},
     "a corpus table row names a module in a form the step does not read"),
    ("a table row names a second module with a ./ prefix",
     {"rows": ("| Extra | `tests/test_attack_classes.py`, `./tests/test_extra.py` |",),
      "files": EXTRA},
     "a corpus table row names a module in a form the step does not read"),
    ("a table row names a module that does not exist", {"rows": ("| Stray | `tests/test_gone.py` |",)},
     "cites tests/test_gone.py, which is not a module in this tree"),
    ("a table row names a node, not a module",
     {"rows": ("| Stray | `tests/test_named.py::test_specimen` |",)},
     "which is not a module in this tree"),
    ("a table row names a file that is not Python",
     {"rows": ("| Data | `tests/test_data.json` |",), "files": {"tests/test_data.json": "{}\n"}},
     "cites tests/test_data.json, which is not a module in this tree"),
    ("a table row names a helper that is not a test module",
     {"rows": ("| Stray | `tests/helper.py` |",), "files": {"tests/helper.py": "VALUE = 1\n"}},
     "neither a test module nor the registry"),
    ("the table locates only the registry", {"table": TABLE[:3]},
     "the corpus table locates no test module"),
    ("the registries are empty", {"owners": (), "specimens": (), "gate": "(0 FG + 0 AC)"},
     "the registries name no owner and no specimen"),
    ("a test skips", {"bodies": {"test_second_probe": "import pytest; pytest.skip('specimen')"}},
     "1 skipped testcases"),
    ("a test fails", {"bodies": {"test_specimen": "assert False"}}, "pytest exited 1"),
    ("an owed test is taken out of the run", {"conftest": DESELECT.format(name="test_owner_two")},
     "1 owed identities not executed"),
    ("a located module executes nothing",
     {"rows": (EXTRA_ROW,), "conftest": DESELECT.format(name="test_extra"),
      "files": {"tests/test_extra.py": "\n\ndef test_extra():\n    assert True\n"}},
     "1 located modules executed nothing"),
    ("setup-only asked for by the environment",
     {"bodies": FAILING, "env": {"PYTEST_ADDOPTS": "--setup-only"}}, "wrote no report"),
    ("setup-plan asked for by the environment",
     {"bodies": FAILING, "env": {"PYTEST_ADDOPTS": "--setup-plan"}}, "wrote no report"),
    ("setup-only asked for by the repository's own addopts",
     {"bodies": FAILING, "ini": "addopts = --setup-only\n"}, "pytest exited 1"),
    ("setup-only switched on by a conftest", {"bodies": FAILING, "conftest": SETUP_ONLY_CONFTEST},
     "records 0 outcomes"),
    ("pytest cannot start", {"env": {"PYTEST_ADDOPTS": "--no-such-option"}}, "wrote no report"),
    ("RUNNER_TEMP is not set", {"unset": ("RUNNER_TEMP",)}, "RUNNER_TEMP is not set"),
]
RUN_KEYS = {"env", "unset"}


@pytest.mark.parametrize(("label", "change", "reason"), CASES, ids=[case[0] for case in CASES])
def test_the_step_decides_each_case_as_stated(label: str, change: dict, reason: str | None,
                                              tmp_path: Path):
    """Each refusal the step makes, driven by the smallest repository that needs it."""
    repo = synthetic(tmp_path, **{key: value for key, value in change.items()
                                  if key not in RUN_KEYS})
    code, last, output = run_step(repo, tmp_path, **{key: value for key, value in change.items()
                                                     if key in RUN_KEYS})
    if reason is None:
        assert (code, last) == (0, PASS), f"{label}: {output[-2000:]}"
    else:
        assert code != 0 and last.startswith(FAIL) and reason in last, (
            f"{label}: expected a refusal naming {reason!r}, got {code}: {output[-2000:]}")


def test_the_step_runs_exactly_the_located_modules_and_the_owed_nodes(tmp_path: Path):
    """The scope the assumption states, measured on the report the step reads.

    A test in a named-only module that no registry names, and a module cited
    only in prose or in a later section's table, all fail if they run; none may
    run.
    """
    import xml.etree.ElementTree as ET  # noqa: PLC0415

    code, last, output = run_step(synthetic(tmp_path), tmp_path)
    assert (code, last) == (0, PASS), output[-2000:]
    report = ET.parse(tmp_path / "runner-temp" / "hostile.xml").getroot()
    ran = {(case.get("classname"), case.get("name")) for case in report.iter("testcase")}
    assert ran == {
        ("tests.test_false_green_audit", "test_owner_one"),
        ("tests.test_attack_classes", "test_probe"),
        ("tests.test_attack_classes", "test_second_probe"),
        ("tests.test_named", "test_owner_two"),
        ("tests.test_named", "test_specimen"),
    }


def test_a_report_left_by_an_earlier_run_is_not_read_as_this_one(tmp_path: Path):
    """A run that ends before writing its report must not inherit the last one's.

    The earlier report is a genuine pass. The second run's pytest exits 0
    before it writes anything, which is what the step would otherwise read.
    """
    repo = synthetic(tmp_path)
    code, last, output = run_step(repo, tmp_path)
    assert (code, last) == (0, PASS), output[-2000:]
    assert (tmp_path / "runner-temp" / "hostile.xml").is_file()
    _write(repo / "tests" / "conftest.py",
           "import os\n\n\ndef pytest_collection_finish(session):\n    os._exit(0)\n")
    code, last, output = run_step(repo, tmp_path)
    assert code != 0 and last == FAIL + "pytest exited 0 and wrote no report", output[-2000:]


def test_a_run_that_does_not_finish_is_refused_by_the_step_itself(tmp_path: Path):
    """The step's own limit, lowered here only so that this case ends quickly."""
    source = step_source()
    limits = re.findall(r"^LIMIT = \d+", source, re.M)
    assert len(limits) == 1, limits
    repo = synthetic(tmp_path, bodies={"test_probe": "import time; time.sleep(30)"})
    code, last, output = run_step(repo, tmp_path, source=source.replace(limits[0], "LIMIT = 3"))
    assert code != 0 and last == FAIL + "pytest did not finish within 3 s", output[-2000:]


# --------------------------------------------------------------------------
# The step against this tree, with pytest intercepted
# --------------------------------------------------------------------------

LAUNCH = "PYTEST LAUNCH "
#: Put ahead of the step's own source. The step's pytest launch prints its
#: argument list and ends the process there, so nothing of the corpus runs.
INTERCEPT = (
    "import json as _json, os as _os, subprocess as _subprocess\n\n\n"
    "def _launch(argv, *args, **kwargs):\n"
    f"    print({LAUNCH!r} + _json.dumps([str(part) for part in argv]), flush=True)\n"
    "    _os._exit(0)\n\n\n"
    "_subprocess.run = _launch\n"
)


def launched(repo: Path, tmp_path: Path) -> tuple[frozenset, frozenset]:
    """(modules, nodes) the step hands to pytest in `repo`; pytest is never started.

    The step's own code decides both. This only splits the argument list it
    launches with: what follows the report option is the located modules, then
    the further named nodes, which alone carry `::`.
    """
    code, last, output = run_step(repo, tmp_path, source=INTERCEPT + step_source())
    assert code == 0 and last.startswith(LAUNCH), f"the step did not reach its launch: {output[-2000:]}"
    argv = json.loads(last[len(LAUNCH):])
    report = [number for number, part in enumerate(argv) if part.startswith("--junitxml=")]
    assert argv[1:3] == ["-m", "pytest"] and len(report) == 1, argv
    targets = argv[report[0] + 1:]
    return (frozenset(part for part in targets if "::" not in part),
            frozenset(part for part in targets if "::" in part))


def pin_problems(modules: frozenset) -> list[str]:
    """How a located set differs from the pin, in both directions."""
    return ([f"located and not pinned: {name}" for name in sorted(modules - LOCATED_MODULES)]
            + [f"pinned and not located: {name}" for name in sorted(LOCATED_MODULES - modules)])


def test_the_step_locates_exactly_the_pinned_modules_in_this_tree(tmp_path: Path):
    """The located set, as the step derives it from this tree, is pinned exactly.

    No second parser of the protocol's table is written here: that would be a
    second implementation free to disagree with the step's. The step's own
    source runs against this tree -- the real registries, the real closure
    gate and the real table -- with its pytest launch intercepted, which takes
    seconds, and the modules it would have run are compared for equality with
    `LOCATED_MODULES`. The pin sits in the commit it guards, so it is an alarm
    against drift, not evidence against tampering.
    """
    # CONTROL: the interception reports what the step derives, and follows the
    # table. A row added in a synthetic repository appears in what it reports.
    plain = synthetic(tmp_path / "plain")
    modules, nodes = launched(plain, tmp_path / "plain")
    assert modules == {"tests/test_false_green_audit.py", "tests/test_attack_classes.py"}
    assert nodes == {"tests/test_named.py::test_owner_two", "tests/test_named.py::test_specimen"}
    extended = synthetic(tmp_path / "extended", rows=(EXTRA_ROW,), files=EXTRA)
    assert launched(extended, tmp_path / "extended")[0] == modules | {"tests/test_extra.py"}
    # CONTROL: the comparison is equality. One module more, or one fewer, is a
    # difference.
    assert pin_problems(LOCATED_MODULES | {"tests/test_extra.py"}) == [
        "located and not pinned: tests/test_extra.py"]
    assert pin_problems(LOCATED_MODULES - {"tests/test_evidence.py"}) == [
        "pinned and not located: tests/test_evidence.py"]

    # THE PIN: the real tree reaches its launch, which it does only when the
    # closure gate's counts agree with the registries and every line of the
    # table is read, and it hands pytest exactly the pinned modules.
    modules, nodes = launched(ROOT, tmp_path / "this-tree")
    assert pin_problems(modules) == [], (
        "Adding or removing a corpus module changes what the job runs, so the same "
        "change edits LOCATED_MODULES.")
    assert nodes, "the registries name no node outside the located modules"
