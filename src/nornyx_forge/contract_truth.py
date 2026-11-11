"""Whether a greenfield build's generated contract describes its workspace.

THE DEFECT THIS CLOSES (A-063). `nornyx check` (A-049) validates a contract's
STRUCTURE. Nothing checked that the contract described the workspace it
governs, so a contract scoping a directory that held none of the code, naming
a validation script that did not exist, and giving an authority pattern that
matched nothing passed -- and a recorded greenfield build did exactly that.

WHAT THIS CHECKS, against the contract Forge rendered (never bytes read back
from the workspace) and the workspace's files:

  * every goal declares a scope and validation commands, and the repository
    context declares include and authority patterns;
  * the declared source scope -- each directory a goal scopes, other than the
    tests directory -- holds application source;
  * no application source lies outside that scope and outside the tests
    directory;
  * every script a validation command names exists in the workspace;
  * every include and every authority pattern matches at least one file.

Application source is `produced_app_manifest.application_source_files`, the
one definition of it. Each failure is a finding with its reason; no finding
means the contract describes the workspace's LAYOUT. It says nothing about
whether the code is correct, safe or confined.

`contract_truth_findings` is pure: text and a path list in, findings out.
`trusted_contract_truth_check` is the gate Forge's trusted parent runs: it
lists the workspace by the trusted verifier's collection rule and records the
findings as one gate result. `layer.application`: it reads the workspace's
file names and starts no process.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Collection
from pathlib import Path
from typing import Any

import yaml

from .models import GateResult
from .produced_app_handoff import read_subject
from .produced_app_manifest import (
    APPLICATION_PACKAGE,
    ENTRY_POINT,
    GENERATED_CONTRACT_PATH,
    TESTS_DIRECTORY,
    application_source_files,
)

#: The gate this check is recorded as, beside the other greenfield gates.
CONTRACT_TRUTH_GATE = "greenfield:contract-truth"

#: The context whose include and authority patterns describe the workspace.
REPOSITORY_CONTEXT = "GeneratedRepoContext"

#: Suffixes by which a validation-command argument names a script.
SCRIPT_SUFFIXES = (".py", ".sh", ".ps1", ".bat", ".cmd")

#: How many offending paths a finding quotes before it summarizes the rest.
_QUOTED = 10

_TESTS_SCOPE = TESTS_DIRECTORY + "/"


def _quoted(paths: list[str]) -> str:
    shown = ", ".join(paths[:_QUOTED])
    rest = len(paths) - _QUOTED
    return shown + (f" and {rest} more" if rest > 0 else "")


def pattern_regex(pattern: str) -> re.Pattern[str]:
    """A contract path pattern as an anchored regular expression.

    `**/` matches any number of whole directories, including none; `**`
    elsewhere matches anything; `*` matches within one path segment; `?`
    matches one character within a segment. Everything else is literal.
    """
    out: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out) + r"\Z")


def _string_list(value: Any) -> list[str] | None:
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return value
    return None


def _script_arguments(command: str) -> list[str] | None:
    """The workspace scripts a validation command names, or None if unparsable.

    The first word is the program. An argument is a script when it is not an
    option, is not the module after `-m`, and contains a path separator or
    ends in one of `SCRIPT_SUFFIXES`.
    """
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if not words:
        return None
    scripts: list[str] = []
    after_module_flag = False
    for word in words[1:]:
        if after_module_flag:
            after_module_flag = False
            continue
        if word == "-m":
            after_module_flag = True
            continue
        if word.startswith("-"):
            continue
        if "/" in word or word.endswith(SCRIPT_SUFFIXES):
            scripts.append(word)
    return scripts


def contract_truth_findings(contract_text: Any, files: Collection[str]) -> list[str]:
    """Why the contract does not describe the workspace; empty when it does.

    `files` is every file in the workspace as a relative POSIX path, listed by
    the trusted verifier's collection rule, plus any file Forge itself wrote
    that the contract names. Fails closed: a contract that cannot be read, or
    lacks a field this check needs, is a finding, never a pass.
    """
    if not isinstance(contract_text, str):
        return ["the generated contract is not text"]
    try:
        contract = yaml.safe_load(contract_text)
    except yaml.YAMLError as error:
        return [f"the generated contract cannot be parsed: {error}"]
    if not isinstance(contract, dict):
        return ["the generated contract cannot be parsed: it is not a mapping"]

    findings: list[str] = []
    goals = contract.get("goals")
    if not isinstance(goals, list) or not goals or not all(isinstance(g, dict) for g in goals):
        return ["the generated contract has no goals"]
    contexts = contract.get("contexts")
    context = next(
        (item for item in contexts if isinstance(item, dict) and item.get("name") == REPOSITORY_CONTEXT),
        None,
    ) if isinstance(contexts, list) else None
    if context is None:
        return [f"the generated contract has no {REPOSITORY_CONTEXT} context"]

    scopes: list[str] = []
    commands: list[str] = []
    for goal in goals:
        scope = _string_list(goal.get("scope"))
        validation = _string_list(goal.get("validation"))
        if scope is None:
            findings.append(f"goal {goal.get('id')!r} has no scope")
        else:
            scopes.extend(entry for entry in scope if entry not in scopes)
        if validation is None:
            findings.append(f"goal {goal.get('id')!r} has no validation commands")
        else:
            commands.extend(entry for entry in validation if entry not in commands)
    patterns: dict[str, list[str]] = {}
    for field in ("include", "authority"):
        listed = _string_list(context.get(field))
        if listed is None:
            findings.append(f"the {REPOSITORY_CONTEXT} context has no {field} patterns")
        else:
            patterns[field] = listed
    if findings:
        return findings

    present = sorted(set(files))
    source_scopes = [entry for entry in scopes if entry.endswith("/") and entry != _TESTS_SCOPE]
    if not source_scopes:
        findings.append("the generated contract declares no source scope")
    else:
        sources = application_source_files(present, None)
        inside = [path for path in sources if any(path.startswith(s) for s in source_scopes)]
        outside = [path for path in sources
                   if not any(path.startswith(s) for s in source_scopes)
                   and not path.startswith(_TESTS_SCOPE)]
        named = ", ".join(source_scopes)
        if not inside:
            findings.append(f"the declared source scope {named} holds no application source")
        if outside:
            findings.append(
                f"application source lies outside the declared source scope {named} "
                f"and outside {_TESTS_SCOPE}: {_quoted(outside)}"
            )

    for command in commands:
        scripts = _script_arguments(command)
        if scripts is None:
            findings.append(f"the validation command {command!r} cannot be parsed")
            continue
        missing = [script for script in scripts if script not in present]
        if missing:
            findings.append(
                f"the validation command {command!r} names a script the workspace does "
                f"not contain: {_quoted(missing)}"
            )

    for field, listed in patterns.items():
        for pattern in listed:
            regex = pattern_regex(pattern)
            if not any(regex.match(path) for path in present):
                findings.append(f"the {field} pattern {pattern!r} matches no file in the workspace")
    return findings


def trusted_contract_truth_check(root: Path, contract_text: str | None) -> GateResult:
    """Whether the contract Forge rendered describes the workspace (A-063).

    Run by Forge, never by a provider. The contract is the text the
    digest-bound renderer call produced, never bytes read back from the
    workspace. The workspace is listed by the trusted verifier's collection
    rule (`read_subject`), which excludes `.nornyx/`; the generated contract
    Forge wrote there is added when it is present, because the greenfield
    contract names it as its authority. Fails closed: no rendered text, a
    workspace that cannot be listed, or any finding fails the gate.
    """
    if contract_text is None:
        return GateResult(CONTRACT_TRUTH_GATE, False,
                          "no rendered contract was recorded for this build")
    try:
        subject, problems = read_subject(root)
    except OSError as error:
        return GateResult(CONTRACT_TRUTH_GATE, False,
                          f"the workspace cannot be listed: {error}")
    files = set(subject)
    generated = root / GENERATED_CONTRACT_PATH
    if generated.is_file() and not generated.is_symlink():
        files.add(GENERATED_CONTRACT_PATH)
    findings = [f"the workspace cannot be listed: {problem}" for problem in problems]
    findings += contract_truth_findings(contract_text, files)
    if findings:
        return GateResult(CONTRACT_TRUTH_GATE, False, "; ".join(findings))
    return GateResult(
        CONTRACT_TRUTH_GATE,
        True,
        "the generated contract describes the workspace's layout: its source scope "
        "holds the application source, every validation script exists, and every "
        "include and authority pattern matches a file",
    )


#: What a greenfield architect and builder are told about the layout the
#: generated contract declares, from the produced-application conventions.
GREENFIELD_LAYOUT_GOAL = (
    f" Put the application's code in {APPLICATION_PACKAGE}/ (its entry point is "
    f"{ENTRY_POINT}) and its tests in {TESTS_DIRECTORY}/: the generated contract "
    "declares that scope, and acceptance checks that the workspace matches it."
)
