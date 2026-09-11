"""Claude confinement on native Windows: measured, and NOT ESTABLISHED.

THE FINDING, stated first so nothing below has to be read to reach it. No
operating-system confinement mechanism is reachable for a Claude Code worker on
native Windows at the measured version. The CLI exposes no `sandbox`
subcommand and no `--sandbox` flag, the bundled Windows sandbox runtime's
broker binary was not found within a bounded search of the named roots and is
not on PATH, the dedicated sandbox account it requires is
not provisioned, and Forge's own adapter asks the operating system for nothing:
its command line carries `--allowedTools`, which is Claude Code's own
permission allowlist over the MODEL's tool calls, and a working directory,
which is a directory and not a boundary. So `PROVIDER_CONFINEMENT["claude"]
["windows"]` stays `none`, and this module exists to hold it there in BOTH
directions -- the row cannot be promoted by an edit, and it cannot be quietly
demoted from a measured state back to an untested default either.

WHAT IS DIFFERENT FROM THE CODEX MODULE BESIDE IT, and it is not the verdict.
PA-01 could drive every Codex probe from `codex sandbox windows` -- the
provider's OWN entry point -- so no model decided whether the forbidden
operation was attempted. Claude has no equivalent on this platform: every Bash,
Write and Edit tool call a `claude -p` run makes is a model decision. So the
five write probes in the shipped record carry `attempt_observed: false`, which
is an honest ABSENCE rather than a refusal, and the sixth carries the same for
a different reason: `control_plane_authority: denied` is not merely unobserved
for Claude here, it is UNREACHABLE, because every state the shipped v1
producers can derive maps to `inconclusive` or `allowed` and this platform has
no separated Claude principal to take a record from at all.

THE CRITERION IS BEING APPLIED, NOT RESTATED. A module that asserted "the
record does not establish confinement" over a record built to fail would be
measuring its own fixture. So the honest record is put through the REAL
verifier and refused, and a POSITIVE TWIN -- the same record with six
qualifying probes substituted -- is put through the same verifier and accepted.
The criterion discriminates; the verdict is the criterion's, not this module's.

AND THE CONTROL IS NOT A PROBE. The harness records what a stand-in process
launched under the adapter's own working directory and environment rule can
reach: the workspace, a sibling, a seal surrogate, Forge material, a home-config
surrogate, and a target through a live junction. That is evidence about FORGE'S
LAUNCH CONSTRUCTION, and a stand-in process is not the provider. Recording it
as `observed_process_result` probes against `provider: "claude"` would be a
header re-subjecting the observations under it, which the contract already
refuses one layer down. It lives in a labelled non-voting section, and a test
below proves that section's rows cannot be loaded as probes.
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from nornyx_forge import claude_worker
from nornyx_forge.provider_contract import (
    CONFINEMENT_PROPERTIES,
    PROBE_OUTCOMES,
    PROPERTY_EVIDENCE_MECHANISMS,
    PROVIDER_CONFINEMENT,
    RETIRED_PROPERTIES,
    ConfinementMeasurement,
    ConfinementProbe,
    ProviderError,
    assess_confinement,
    governed_build_eligibility,
)

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs" / "governance" / "claude_confinement_measurement.json"
CODEX_RECORD = ROOT / "docs" / "governance" / "codex_confinement_measurement.json"
DOCUMENT = ROOT / "docs" / "governance" / "CLAUDE_CONFINEMENT_MEASUREMENT.md"
ASSUMPTIONS = ROOT / "docs" / "requirements" / "ASSUMPTIONS.md"
HARNESS = ROOT / "scripts" / "probe_claude_confinement.py"
CHANGELOG = ROOT / "CHANGELOG.md"

sys.path.insert(0, str(ROOT / "scripts"))

PROVIDER = "claude"
#: The AUTHORED word, matching the table's key and the record's own header.
PLATFORM = "windows"

#: The isolation flags Forge's adapter does not pass, spelled here rather than
#: imported from the harness: a pin that reads its subject's own list of what
#: to check is a pin the subject can switch off.
ISOLATION_FLAGS = (
    "--permission-mode", "--add-dir", "--settings", "--setting-sources",
    "--strict-mcp-config", "--safe-mode", "--bare", "--disallowedTools",
    "--tools", "--mcp-config", "--disable-slash-commands", "--agents",
    "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions",
)

#: Every option string the harness is allowed to put in an argv. Declared HERE
#: and held equal to the harness's own constant, so widening that constant is a
#: red test in this file rather than a silent licence to spend quota.
PERMITTED_ARGV_FLAGS = ("--version", "--help")

#: EVERY argv the harness may start, as COMPLETE tuples -- declared HERE and
#: held equal to the harness's own table, for the same reason the flags above
#: are: a pin that read its subject's own table would pass whatever the subject
#: put in it. The option allow-list is not enough on its own, because it can
#: only see tokens that begin with `-`: a review added the FLAGLESS shape
#: `("<executable>", "<argument>")` -- which would start `claude <prompt>` on
#: the CLI's own documented positional -- and every gate passed.
SPAWN_SHAPES = {
    "claude_version": ("<executable>", "--version"),
    "claude_help": ("<executable>", "--help"),
    "host_accounts": ("net", "user"),
    "head_revision": ("git", "rev-parse", "HEAD"),
    "make_junction": ("cmd", "/c", "mklink", "/J", "<path>", "<path>"),
    "standin_attempt": ("<executable>", "<path>", "<argument>"),
}

#: The ONE function in the harness that may start a process.
SPAWN_SEAM = "_run_cli"

#: The spellings measured to walk past the rule below, in in-session
#: adversarial sweeps -- past `ruff check .`, `scripts/check_security.py` and
#: `scripts/check_architecture.py` as well. The rule was deliberately NOT widened to
#: catch them -- that is a separate slice with its own review -- so what a
#: later reader has is the DISCLOSURE, and a disclosure nothing reads is a
#: disclosure that rots. Held against A-033 by the pin at the end of this
#: module, in the register's own words.
#:
#: A SAMPLE, NOT A BOUND. This is what two sweeps happened to try; the second
#: added the last three to a list the first had presented as the whole of it.
#: The last one is different in kind: it names no process module at all, and no
#: rule phrased over process-module names can reach it.
DISCLOSED_UNREFUSED_SPELLINGS = (
    "a spawner fetched by name through `getattr`",
    "a process module reached through `sys.modules` rather than imported",
    "a module-level alias the enumeration does not spell",
    "a `ctypes` handle bound to a local before it is called",
    "a spawn shape carrying no option string at all",
    "an extra attribute hop through `subprocess.run.__call__`",
    "a subclass of `subprocess.Popen`",
    "a call into Forge's own already-imported `claude_worker` adapter",
)

#: The universal claim these three governed texts used to make, and the
#: distinction that the correction of it introduced. BOTH WERE FALSE, and the
#: second was written while removing the first -- so this register holds the
#: retired spellings rather than trusting the next editor to remember them.
#: `test_the_three_governed_texts_state_the_measured_bound` below asserts their
#: ABSENCE; a review restored each one and watched nothing go red.
RETIRED_UNIVERSAL_CLAIMS = (
    "refuses any other spawn call",
    "refuses any spawn call",
    "refuses any process-creation call",
    "refuses: any process-creation call",
    "refuse any process-creation call",
    "the one-expression form being refused",
)

#: The bound each of the three must state instead, in the register the
#: repository already uses for its standing-obligations lint.
MEASURED_BOUND = "it holds the shapes it names and no others"

#: CALL SPELLINGS, AND WHETHER THE RULE BELOW REFUSES THEM. Every row was
#: measured by driving this module's own `_dotted` and `_starts_a_process` over
#: the parsed source, and each was also appended ALONE to the harness and run
#: against this whole module, `ruff check .`, `scripts/check_security.py` and
#: `scripts/check_architecture.py`.
#:
#: THE TWO `ctypes` ROWS ARE THE REASON THIS TABLE EXISTS. They are both a
#: single expression, they both reach `ctypes`, and they differ only in the
#: spelling of the final attribute -- which is what the rule decides on. Three
#: governed texts once said the discriminator was the one-expression form
#: versus the two-step form. It is not, and a table that would redden if that
#: ever changed is the difference between a claim and a sentence about one.
RULE_SPECIMENS = (
    # (source, the dotted names the rule derives, whether the rule refuses it)
    ("os.system(cmd)", ("os.system",), True),
    ("subprocess.run(argv)", ("subprocess.run",), True),
    ('sys.modules["subprocess"].check_output(argv)', ("check_output",), True),
    ('sys.modules["ctypes"].CDLL("msvcrt").system(cmd)',
     ("system", "CDLL"), True),
    ('sys.modules["ctypes"].windll.kernel32.WinExec(cmd, 1)',
     ("windll.kernel32.WinExec",), False),
    ('getattr(subprocess, "run")(argv)', ("", "getattr"), False),
    ("subprocess.run.__call__(argv)", ("subprocess.run.__call__",), False),
    ("_adapter.run(role=r, goal=g, workspace=w, allowed_tools=t)",
     ("_adapter.run",), False),
)

#: The only function allowed to read the environment, and what it reads it for:
#: `adapter_construction` compares `os.environ` against the adapter's own
#: filtered environment to report which variables Forge drops. The result is a
#: list of NAMES in the record, and a test below proves it reaches no argv.
ENVIRONMENT_READERS = frozenset({"adapter_construction"})

#: EVERY SPELLING BY WHICH A PROCESS CAN BE STARTED, enumerated HERE rather than
#: imported from the harness: a pin that read its subject's own list of what to
#: refuse is a pin the subject can switch off. The previous version of this pin
#: watched three call NAMES (`run`, `Popen`, `_run`), and an independent review
#: walked past it with `os.system`, `subprocess.check_output([exe, "--print",
#: prompt])` and a concatenated `"-" + "p"` -- each of which also passed `ruff`,
#: `scripts/check_security.py` and `scripts/check_architecture.py`.
SUBPROCESS_SPAWNERS = frozenset({
    "run", "Popen", "call", "check_call", "check_output",
    "getoutput", "getstatusoutput",
})
OS_SPAWNERS = frozenset({
    "system", "popen", "startfile", "fork", "forkpty",
    "posix_spawn", "posix_spawnp",
})
#: `os.exec*` and `os.spawn*` are families, so they are matched by prefix.
OS_SPAWN_PREFIXES = ("exec", "spawn", "posix_spawn")
#: Modules whose callables create processes or load code. None may be imported,
#: and `subprocess` only in its plain module form -- `from subprocess import
#: check_output` would put a spawner behind a bare name.
PROCESS_MODULES = frozenset({
    "subprocess", "multiprocessing", "pty", "runpy", "ctypes", "asyncio",
    "importlib",
})
PERMITTED_PROCESS_IMPORT = "subprocess"
#: String-building method names. A built string is a string a reader cannot
#: check against the allow-list.
STRING_BUILDING_METHODS = frozenset({"format", "join"})
#: Environment-read spellings.
ENVIRONMENT_READS = frozenset({"os.environ", "os.getenv", "os.environb",
                               "os.putenv", "os.unsetenv"})


def _dotted(node: ast.AST) -> str:
    """`subprocess.run` for an Attribute chain, `run` for a bare Name."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _starts_a_process(dotted: str) -> bool:
    """Whether a call by this dotted name can create a process."""
    module, _, attr = dotted.rpartition(".")
    root = module.split(".")[0]
    if module == "subprocess":
        return attr in SUBPROCESS_SPAWNERS
    if module == "os":
        return attr in OS_SPAWNERS or attr.startswith(OS_SPAWN_PREFIXES)
    if module == "asyncio":
        return attr.startswith("create_subprocess")
    if root in {"pty", "runpy", "multiprocessing", "ctypes"}:
        return True
    if not module:
        # WHAT THIS ARM HOLDS, and it is narrower than the reason that used to
        # be written here. It refuses a bare name SPELLED like one of the
        # enumerated spawners, however that name came to exist: a direct import
        # (which the import rule already refuses, so this is the second line)
        # or an alias. WHAT IT DOES NOT HOLD: an alias spelled anything else.
        # `run = subprocess.run` is caught because `run` is enumerated;
        # `_launch = subprocess.run`, then `_launch(...)`, is a bare spawner
        # name under the plain `import subprocess` the rule allows, and it is
        # NOT caught -- measured by a review, past this pin and all three
        # deterministic gates. `__import__` is enumerated for the same spelling
        # reason, not for a stronger one.
        return attr in SUBPROCESS_SPAWNERS | OS_SPAWNERS | {"__import__"}
    return False


def _builds_a_string(node: ast.AST) -> bool:
    """An f-string, a `+`/`%` expression, or a `.format()`/`.join()` call."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in STRING_BUILDING_METHODS
    )


def _harness_tree() -> ast.Module:
    return ast.parse(HARNESS.read_text(encoding="utf-8"), filename=str(HARNESS))


def _harness_functions(tree: ast.Module) -> dict[str, ast.AST]:
    return {node.name: node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _owner_of(tree: ast.Module) -> dict[int, str]:
    """Which function each node sits inside, keyed by object id. Module-level
    nodes are absent from the mapping, which is itself a refusal: a spawn at
    module level belongs to no function and so is not the seam."""
    owner: dict[int, str] = {}
    for name, function in _harness_functions(tree).items():
        for node in ast.walk(function):
            owner[id(node)] = name
    return owner


def _record() -> dict:
    return json.loads(RECORD.read_text(encoding="utf-8"))


def _probes_of(data: dict) -> tuple[ConfinementProbe, ...]:
    return tuple(
        ConfinementProbe(
            provider=p["provider"], property=p["property"], platform=p["platform"],
            attempt_observed=p["attempt_observed"], outcome=p["outcome"],
            mechanism=p["mechanism"],
        )
        for p in data["probes"]
    )


def _measurement(**overrides) -> ConfinementMeasurement:
    """The SHIPPED record, as the object the verifier consumes."""
    data = _record()
    fields = {
        "provider": data["provider"],
        "platform": data["platform"],
        "measured_at_commit": data["measured_at_commit"],
        "probes": _probes_of(data),
    }
    fields.update(overrides)
    return ConfinementMeasurement(**fields)


def _probe(prop: str, **overrides) -> ConfinementProbe:
    """One QUALIFYING observation of `prop` -- the shape a record would need."""
    fields = {
        "provider": PROVIDER, "property": prop, "platform": PLATFORM,
        "attempt_observed": True, "outcome": CONFINEMENT_PROPERTIES[prop],
        "mechanism": PROPERTY_EVIDENCE_MECHANISMS[prop][0],
    }
    fields.update(overrides)
    return ConfinementProbe(**fields)


def _closed() -> ConfinementMeasurement:
    """THE POSITIVE TWIN, and it is a HYPOTHETICAL, labelled as one.

    The shipped record's six probes are replaced by six that would qualify.
    Nothing else moves, so a test that goes red against this is telling us
    about the criterion rather than about the fixture. No such measurement
    exists, and on this platform none can: five of the six outcomes it carries
    cannot be produced here, because there is no mechanism that could produce
    them.
    """
    return replace(_measurement(), probes=tuple(_probe(p) for p in CONFINEMENT_PROPERTIES))


# ---------------------------------------------------------------------------
# H1  the shipped record, through the real verifier
# ---------------------------------------------------------------------------

def test_the_shipped_record_establishes_nothing_and_names_every_gap():
    """PIN (i). The honest record is REFUSED, and the refusal names each row.

    Every property is unmet for the same structural reason -- no competent
    observation -- because no attempt by a Claude principal was observed for
    any of them. That is what an absence looks like when it is written down
    instead of rounded to a verdict.
    """
    assessment = assess_confinement(PROVIDER, PLATFORM, _measurement())
    assert assessment.establishes is False
    assert assessment.unmet == tuple(CONFINEMENT_PROPERTIES)
    assert assessment.provider == PROVIDER and assessment.platform == PLATFORM
    for prop in CONFINEMENT_PROPERTIES:
        assert f"{prop}: no competent observation" in assessment.reason


def test_the_positive_twin_shows_the_criterion_discriminates():
    """PIN (ii). A record that genuinely closed every property IS accepted.

    Without this, the test above would be satisfied by a verifier that always
    says no -- which is a verdict hard-coded, not a criterion applied.
    """
    assessment = assess_confinement(PROVIDER, PLATFORM, _closed())
    assert assessment.establishes is True
    assert assessment.unmet == ()


@pytest.mark.parametrize("prop", sorted(CONFINEMENT_PROPERTIES))
def test_no_probe_claims_an_attempt_or_a_denial(prop: str):
    """PIN (iii). Two things a hand-edit toward admission would have to write,
    and neither is in the file.

    `attempt_observed: true` would claim a Claude principal was observed
    attempting something; nothing was, because no model-free entry point exists
    to make it attempt anything and no model was invoked. `outcome: denied`
    would claim an operating system refused it; none did, because there is no
    mechanism on this platform that could. Both are red here.
    """
    matching = [p for p in _record()["probes"] if p["property"] == prop]
    assert len(matching) == 1, f"expected exactly one probe for {prop}: {len(matching)}"
    probe = matching[0]
    assert probe["attempt_observed"] is False
    assert probe["outcome"] == "inconclusive"
    assert probe["mechanism"] == PROPERTY_EVIDENCE_MECHANISMS[prop][0]
    assert probe["not_attempted_because"].strip(), (
        "a probe that was not attempted must say why; an unexplained absence is "
        "indistinguishable from a backlog item"
    )


def test_the_record_carries_no_denial_anywhere():
    """The same guard, over the WHOLE file rather than per row, because a probe
    added under a name this module does not enumerate would slip past the
    parametrised test above."""
    outcomes = {p["outcome"] for p in _record()["probes"]}
    assert "denied" not in outcomes, (
        "a probe in the Claude record reports a denial. No operating-system "
        "mechanism is reachable for this provider on this platform, so nothing "
        "here could have refused anything: this is a claim with no mechanism "
        "under it"
    )
    assert outcomes <= set(PROBE_OUTCOMES)


def test_the_claude_row_stays_none_while_the_assessment_fails():
    """PIN (iv), as an IMPLICATION and not as a literal.

    Stated the way the Codex guard is stated: while the shipped record fails to
    establish confinement, the row it would license must not say `established`.
    An edit that promotes the row without producing a measurement that passes
    the verifier turns this red.
    """
    assessment = assess_confinement(PROVIDER, PLATFORM, _measurement())
    if not assessment.establishes:
        assert PROVIDER_CONFINEMENT[PROVIDER][PLATFORM] == "none", (
            "the table says Claude's confinement on this platform is "
            f"{PROVIDER_CONFINEMENT[PROVIDER][PLATFORM]!r} while the recorded "
            "measurement establishes nothing at all"
        )
        assert governed_build_eligibility(PROVIDER, PLATFORM).eligible is False


# ---------------------------------------------------------------------------
# H2  the harness cannot spend quota
# ---------------------------------------------------------------------------

def test_the_harness_has_one_process_spawning_seam():
    """PIN (v), first arm. A STRUCTURAL RULE OVER THE SHAPES IT NAMES, and not
    a proof that no model can be invoked.

    A harness that could send a prompt to a provider is a harness that can
    spend the founder's quota, and quota is an external act. What this measures
    is that the module contains exactly one function able to start a process,
    and that no import puts another spelling within reach. What it does NOT
    measure is that the property holds under every possible evasion: an earlier
    version of this pin watched three call names, and three specimens walked
    past it. The rule below names the spellings it refuses; a spelling it does
    not name is not refused, and that is the honest bound of it.
    """
    tree = _harness_tree()
    owner = _owner_of(tree)
    functions = _harness_functions(tree)
    assert SPAWN_SEAM in functions, (
        f"the harness has no {SPAWN_SEAM!r}; this pin is reading the wrong file "
        "or the seam has been renamed without renaming the rule"
    )

    # The blanket check first: the prompt flag must not appear as a string
    # anywhere in the module, in an argv or out of one.
    constants = {node.value for node in ast.walk(tree)
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    assert "-p" not in constants, (
        "the measurement harness carries the prompt flag as a literal; a "
        "measurement that can start a provider session is not model-free"
    )

    # No import may put a second spawning spelling within reach.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in PROCESS_MODULES or (
                    alias.name == PERMITTED_PROCESS_IMPORT and alias.asname is None
                ), (
                    f"the harness imports {alias.name!r}, which can start a "
                    f"process; only a plain `import {PERMITTED_PROCESS_IMPORT}` "
                    "is allowed, and only because the seam needs it"
                )
        if isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in PROCESS_MODULES, (
                f"the harness imports names out of {node.module!r}; a spawner "
                "behind a bare name is a spawner this pin would have to guess at"
            )

    # Every process-creating call sits inside the seam, and nowhere else.
    spawns: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        if not _starts_a_process(dotted):
            continue
        spawns.setdefault(owner.get(id(node), "<module level>"), []).append(dotted)
    assert set(spawns) == {SPAWN_SEAM}, (
        f"process-creating calls were found outside {SPAWN_SEAM!r}: "
        f"{ {name: sorted(calls) for name, calls in sorted(spawns.items()) if name != SPAWN_SEAM} }"
    )
    assert len(spawns[SPAWN_SEAM]) == 1, (
        f"{SPAWN_SEAM!r} starts more than one process ({sorted(spawns[SPAWN_SEAM])}); "
        "one seam means one call, so there is one argv to read"
    )


def test_the_seam_starts_only_an_allow_listed_argv_and_builds_no_string():
    """PIN (v), second arm: the seam's argv comes from the constant.

    The spawn's first positional argument is the local `argv`, `argv` is bound
    from `SPAWN_SHAPES`, and the seam performs no string formatting,
    concatenation or joining ANYWHERE -- so there is no expression in it
    through which a built argument could reach an argv. That last rule is why
    the seam delegates its refusal and failure messages to helpers: a message
    is a built string, and the function that starts processes builds none.
    """
    tree = _harness_tree()
    seam = _harness_functions(tree)[SPAWN_SEAM]

    spawn = next(node for node in ast.walk(seam)
                 if isinstance(node, ast.Call) and _starts_a_process(_dotted(node.func)))
    assert spawn.args and isinstance(spawn.args[0], ast.Name), (
        "the seam's argv is not a plain local name, so this pin cannot say "
        "where it came from -- and an argv that cannot be read cannot be checked"
    )
    argv_name = spawn.args[0].id

    bindings = [node for node in ast.walk(seam)
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == argv_name
                        for target in node.targets)]
    assert len(bindings) == 1, (
        f"{argv_name!r} is bound {len(bindings)} times in the seam; one binding "
        "means one place to read the argv's origin"
    )
    # TWO LINKS, BOTH READ: `argv` is bound from a local, and that local is bound
    # from a subscript of the shape constant. A pin that only checked the local's
    # NAME appeared here would pass on any local spelled the same way.
    locals_used = {node.id for node in ast.walk(bindings[0].value)
                   if isinstance(node, ast.Name)}
    origins = {
        _dotted(node.value.value)
        for node in ast.walk(seam)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Subscript)
        and any(isinstance(target, ast.Name) and target.id in locals_used
                for target in node.targets)
    }
    assert origins == {"SPAWN_SHAPES"}, (
        f"{argv_name!r} is not built from the shape constant ({sorted(origins)}); "
        "the seam may start only an argv the allow-list names"
    )
    # And every token written into it afterwards is a plain local, not an
    # expression: `argv[index] = token`, never `argv[index] = something + flag`.
    for store in [node for node in ast.walk(seam) if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Subscript)
                          and _dotted(target.value) == argv_name
                          for target in node.targets)]:
        assert isinstance(store.value, ast.Name), (
            "a token is written into the seam's argv from an expression rather "
            f"than a checked local: {ast.dump(store.value)}"
        )

    built = [ast.dump(node) for node in ast.walk(seam) if _builds_a_string(node)]
    assert built == [], (
        f"{SPAWN_SEAM!r} builds strings, so an argument could be assembled "
        f"inside the one function that starts processes: {built}"
    )


def test_no_call_site_hands_the_seam_a_built_argument():
    """PIN (v), third arm: every caller names a shape and passes no built string.

    `_run_cli("claude_version", located)` is checkable by reading. `_run_cli(
    "claude_version", exe + flag)` is not, and neither is a shape name computed
    at runtime. Both are refused here.
    """
    tree = _harness_tree()

    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and _dotted(node.func) == SPAWN_SEAM]
    assert len(calls) >= 5, (
        f"only {len(calls)} call sites of {SPAWN_SEAM!r} were found, so this pin "
        "is probably reading the wrong file"
    )
    for call in calls:
        assert call.args, f"{SPAWN_SEAM} was called with no shape name"
        shape = call.args[0]
        assert isinstance(shape, ast.Constant) and isinstance(shape.value, str), (
            "a shape name computed at runtime is a shape no reader can check "
            "against the allow-list"
        )
        assert shape.value in SPAWN_SHAPES, (
            f"{shape.value!r} is not a shape the harness declares"
        )
        for argument in call.args[1:] + [keyword.value for keyword in call.keywords]:
            built = [ast.dump(node) for node in ast.walk(argument)
                     if _builds_a_string(node)]
            assert built == [], (
                f"a call to {SPAWN_SEAM} with shape {shape.value!r} passes an "
                f"argument built by formatting, concatenation or joining: {built}"
            )


def test_the_harness_reads_no_environment_into_an_argv():
    """PIN (v), fourth arm: the environment cannot become a flag.

    An environment-derived option string is the evasion that leaves no literal
    to find. Exactly one function here may read the environment, it reads it to
    report which variables Forge's adapter DROPS, and it starts no process.
    """
    tree = _harness_tree()
    owner = _owner_of(tree)

    readers: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        dotted = _dotted(node) if isinstance(node, (ast.Name, ast.Attribute)) else ""
        if dotted in ENVIRONMENT_READS:
            readers.setdefault(owner.get(id(node), "<module level>"), []).append(dotted)
    unexpected = sorted(name for name in readers if name not in ENVIRONMENT_READERS)
    assert unexpected == [], (
        "the harness reads the environment outside the functions allowed to: "
        f"{unexpected}"
    )
    functions = _harness_functions(tree)
    for reader in sorted(set(readers)):
        seam_calls = [node for node in ast.walk(functions[reader])
                      if isinstance(node, ast.Call) and _dotted(node.func) == SPAWN_SEAM]
        assert seam_calls == [], (
            f"{reader!r} both reads the environment and starts a process, so a "
            "value from the environment has a route into an argv"
        )


def test_the_harnesss_permitted_flags_are_the_ones_this_module_allows():
    """The allowlist is declared in TWO places on purpose. A pin that read the
    harness's own constant would pass whatever the harness put in it.

    The second assertion is what makes the first load-bearing now that argvs
    are selected rather than written: every option string across EVERY declared
    shape must be one of these, so a new shape cannot smuggle a flag in.
    """
    from probe_claude_confinement import (  # noqa: PLC0415
        PERMITTED_ARGV_FLAGS as declared,
    )
    from probe_claude_confinement import (  # noqa: PLC0415
        SPAWN_SHAPES as declared_shapes,
    )

    assert tuple(declared) == PERMITTED_ARGV_FLAGS, (
        "the harness widened the set of option flags it may construct; every "
        "addition is a step toward a provider session and belongs in a diff "
        "that says so"
    )
    # THE TABLE, not only its flags. The assertion below can see nothing in a
    # shape whose tokens all lack a leading `-`, so the shapes themselves are
    # held to this module's own literal.
    assert {name: tuple(shape) for name, shape in declared_shapes.items()} \
        == SPAWN_SHAPES, (
        "the harness's declared spawn shapes are not the ones this pin names; "
        "adding or editing a shape belongs in a diff that says so"
    )
    options = {token for shape in declared_shapes.values() for token in shape
               if token.startswith("-")}
    assert options == set(PERMITTED_ARGV_FLAGS), (
        "a declared spawn shape carries an option string outside the allow-list: "
        f"{sorted(options - set(PERMITTED_ARGV_FLAGS))}"
    )


def test_the_harness_reads_the_repositorys_revision_not_the_callers():
    """`measured_at_commit` is the subject revision A-024's version-is-a-subject
    rule turns on, and a record carrying `null` there looks complete.

    Measured before the repair: `_head_revision()` ran `git rev-parse HEAD` in
    the CURRENT WORKING DIRECTORY, so a harness run from anywhere outside the
    checkout produced a complete-looking record with a `null` subject, silently.

    This drives the harness's own function from a foreign working directory in
    a bounded subprocess. It does NOT run `--print`: that would re-run the
    bounded directory walk, which took over an hour on this host, and a test
    that takes an hour is a test nobody runs.
    """
    foreign = Path(tempfile.mkdtemp(prefix="forgeH_foreign_cwd_"))
    try:
        control = subprocess.run(
            [sys.executable, "-c", "import subprocess,sys;"
             "sys.exit(subprocess.run(['git','rev-parse','HEAD'],"
             "capture_output=True).returncode)"],
            cwd=foreign, capture_output=True, timeout=120, check=False,
        )
        assert control.returncode != 0, (
            f"{foreign} is inside a git repository, so this test would pass "
            "even with the defect: it is measuring nothing"
        )
        measured = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]);"
             "import probe_claude_confinement as p; print(p._head_revision())",
             str(ROOT / "scripts")],
            cwd=foreign, capture_output=True, text=True, timeout=300, check=False,
        )
        assert measured.returncode == 0, measured.stderr
        revision = measured.stdout.strip()
    finally:
        shutil.rmtree(foreign, ignore_errors=True)
    assert len(revision) == 40 and set(revision) <= set("0123456789abcdef"), (
        "the harness read no revision from a foreign working directory, so a "
        f"record taken from there would carry a null subject: {revision!r}"
    )


# ---------------------------------------------------------------------------
# H3  coverage, and the retirement
# ---------------------------------------------------------------------------

def test_the_record_probes_exactly_the_required_properties():
    """Read through the retirement, as the Codex module does. Claude has no
    historical evidence to keep loadable, so a retired name here would be a
    probe about a criterion nobody ever measured for this provider."""
    named = [p["property"] for p in _record()["probes"]]
    assert len(named) == len(set(named)), f"a property is probed twice: {named}"
    assert set(named) == set(CONFINEMENT_PROPERTIES)
    retired = [name for name in named if name in RETIRED_PROPERTIES]
    assert retired == [], (
        f"the Claude record carries a retired criterion: {retired}. Nothing was "
        "ever measured for Claude under a retired name, so this can only be a "
        "probe copied from somewhere it did not come from"
    )


def test_every_probe_names_claude_and_this_platform():
    """The binding is PER OBSERVATION, not only on the header -- which is the
    whole reason `ConfinementProbe` carries a provider of its own."""
    for probe in _record()["probes"]:
        assert probe["provider"] == PROVIDER
        assert probe["platform"] == PLATFORM
    data = _record()
    assert data["provider"] == PROVIDER and data["platform"] == PLATFORM
    assert data["schema"] == "nornyx.forge.provider_confinement_measurement.v1"
    _measurement().validate()


# ---------------------------------------------------------------------------
# H4  subject binding, both directions
# ---------------------------------------------------------------------------

def test_the_claude_record_cannot_establish_codex():
    even_closed = replace(_closed(), provider=PROVIDER)
    assessment = assess_confinement("codex", PLATFORM, even_closed)
    assert assessment.establishes is False
    assert assessment.unmet == tuple(CONFINEMENT_PROPERTIES)
    assert "establishes nothing about 'codex'" in assessment.reason


def test_the_codex_record_cannot_establish_claude():
    """Asserted HERE as well as in the Codex module, deliberately. That module's
    version would survive deleting this one, and a binding that is only checked
    from the side that happens to still exist is not checked."""
    codex = json.loads(CODEX_RECORD.read_text(encoding="utf-8"))
    measurement = ConfinementMeasurement(
        provider=codex["provider"], platform=codex["platform"],
        measured_at_commit=codex["measured_at_commit"], probes=_probes_of(codex),
    )
    assessment = assess_confinement(PROVIDER, PLATFORM, measurement)
    assert assessment.establishes is False
    assert assessment.unmet == tuple(CONFINEMENT_PROPERTIES)
    assert f"establishes nothing about {PROVIDER!r}" in assessment.reason


def test_a_header_cannot_re_subject_the_claude_probes_beneath_it():
    with pytest.raises(ProviderError):
        replace(_measurement(), provider="codex").validate()


# ---------------------------------------------------------------------------
# H5  platform binding -- the half item 1 added
# ---------------------------------------------------------------------------

def test_a_linux_relabelling_of_this_record_answers_for_nothing_on_windows():
    """Relabelling the header is not re-measuring, and the relabelled record
    does not reach the shipped platform's decision either."""
    relabelled = replace(
        _closed(), platform="linux",
        probes=tuple(replace(p, platform="linux") for p in _closed().probes),
    )
    assert assess_confinement(PROVIDER, "linux", relabelled).establishes is True
    asked_here = assess_confinement(PROVIDER, PLATFORM, relabelled)
    assert asked_here.establishes is False
    assert "does not transfer" in asked_here.reason
    # And the half that did not exist before Tranche H: the served decision for
    # THIS platform is unmoved by a green taken on another one.
    assert governed_build_eligibility(PROVIDER, PLATFORM).eligible is False
    assert PROVIDER_CONFINEMENT[PROVIDER] == {PLATFORM: "none"}, (
        "a linux row appeared in the Claude table. Evidence does not travel "
        "between platforms, and a row that was not measured on the platform it "
        "names is a claim with nothing under it"
    )


# ---------------------------------------------------------------------------
# H6  what the refusal a person reads is allowed to say
# ---------------------------------------------------------------------------

def test_the_claude_refusal_names_the_measurement_and_claims_no_more():
    """The reason must now NAME its measurement -- a refusal that said nothing
    about what was found left a reader with the pre-tranche implication that
    nobody had looked -- and it must claim nothing beyond it."""
    from test_actor_declaration_boundary import FORBIDDEN_CLAIMS  # noqa: PLC0415

    reason = governed_build_eligibility(PROVIDER, PLATFORM).reason
    assert "CLAUDE_CONFINEMENT_MEASUREMENT" in reason
    assert PLATFORM in reason
    assert "no filesystem confinement" in reason
    assert "established" not in reason, (
        "the refusal for a provider nothing could be established about uses the "
        "word that means the opposite"
    )
    assert "confined" not in reason, (
        "the refusal claims the provider is confined; the measured finding is "
        "that nothing confines it here"
    )
    offending = [phrase for phrase in FORBIDDEN_CLAIMS if phrase in reason]
    assert offending == [], f"the refusal claims a person acted: {offending}"


# ---------------------------------------------------------------------------
# H7  the vocabulary limit, and where impossibility is allowed to live
# ---------------------------------------------------------------------------

def test_not_applicable_is_refused_as_a_probe_outcome():
    """A platform on which the mechanism CANNOT EXIST has only
    `attempt_observed: false` plus `inconclusive` to say so in the probe
    vocabulary -- which reads identically to "nobody got around to it". This
    pins that the vocabulary really does refuse the honest word, which is why
    the record carries a separate, non-voting field for it."""
    with pytest.raises(ProviderError) as refused:
        ConfinementProbe(
            provider=PROVIDER, property="external_seal_write", platform=PLATFORM,
            attempt_observed=True, outcome="not_applicable",
            mechanism="observed_process_result",
        ).validate()
    assert "not_applicable" in str(refused.value)
    assert "not_applicable" not in PROBE_OUTCOMES


def test_the_platform_mechanism_field_says_it_and_carries_no_vote():
    """The one place impossibility is stated, and it is stated OUTSIDE the
    probe list so no assessment can read it."""
    field = _record()["platform_mechanism"]
    assert field["state"] == "absent"
    assert field["carries_a_vote"] is False
    assert "reachable" in field["finding"]
    # The over-reading this field is most likely to invite, refused in the
    # record itself: a Windows sandbox implementation DOES exist in the
    # bundled runtime library. It is unreachable here; it is not absent
    # everywhere.
    assert "not 'no mechanism exists'" in field["what_is_not_being_claimed"]
    with pytest.raises((TypeError, KeyError)):
        ConfinementProbe(**field)


def test_the_platform_mechanisms_finding_does_not_contradict_its_own_bound():
    """The field a reader is most likely to quote must not assert the sentence
    the record beside it records as NOT being claimed.

    It did. `platform_mechanism.finding` said the vendor broker binary was "not
    on disk" while `host.srt_win_search_bound.establishes` says "NOT 'absent
    from this disk'" and the measurement document lists that same sentence
    under "What is explicitly NOT claimed". The walk is BOUNDED -- depth-limited
    below five named roots, plus PATH -- and a bounded walk that finds nothing
    establishes "not found within that bound".
    """
    record = _record()
    finding = record["platform_mechanism"]["finding"]
    bound = record["host"]["srt_win_search_bound"]
    for overstated in ("not on disk", "absent from this disk", "anywhere on this disk"):
        assert overstated not in finding, (
            f"the recorded finding claims {overstated!r}, which the search bound "
            "beside it and the measurement document both say is not claimed"
        )
    assert "not found within" in finding, (
        "the finding does not say what the bounded search established"
    )
    assert str(bound["entries_visited"]) in finding, (
        "the finding names no bound, so a reader cannot tell how wide the "
        "search that found nothing actually was"
    )
    assert str(bound["max_depth_below_each_root"]) in finding
    assert bound["search_completed_within_bound"] is True, (
        "the walk hit its own limit, so even 'not found within the bound' is "
        "weaker than this finding says"
    )


def test_the_platform_mechanisms_three_sentences_move_together():
    """`state`, `finding` and `what_is_not_being_claimed` are all DERIVED from
    the same four signals, so a host on which a mechanism became reachable
    cannot ship a record whose state says one thing and whose sentences beside
    it were written for the other.

    Driven rather than read: the harness's own deriving function is called with
    a surface that reports a sandbox subcommand, and every one of the three
    fields has to change.
    """
    from probe_claude_confinement import _platform_mechanism  # noqa: PLC0415

    record = _record()
    absent = _platform_mechanism(record["cli_surface"], record["host"])
    assert absent["state"] == "absent"
    assert absent == {key: record["platform_mechanism"][key] for key in absent}, (
        "the shipped record's platform_mechanism is not what the harness's own "
        "deriving function produces from the record's own inputs"
    )

    reachable = _platform_mechanism(
        {**record["cli_surface"], "sandbox_subcommand": True}, record["host"])
    assert reachable["state"] == "present"
    assert reachable["carries_a_vote"] is False, (
        "a reachable mechanism is still not a probe; nothing about this field "
        "votes on any confinement property"
    )
    for key in ("finding", "what_is_not_being_claimed"):
        assert reachable[key] != absent[key], (
            f"{key} did not move with the state, so a future host would ship a "
            "record contradicting itself"
        )
    assert "IS reachable" in reachable["finding"]
    assert "a sandbox subcommand" in reachable["finding"]


def test_the_ambient_control_cannot_be_loaded_as_probes():
    """THE CONTROL IS NOT A PROBE, pinned structurally rather than promised in
    prose. A stand-in process is not the provider, so nothing in this section
    may have the shape a probe list is read from."""
    control = _record()["ambient_capability_control"]
    assert "a stand-in process is not the provider" in control["is_not_a_probe_because"]
    assert control["real_seal_directory"]["written"] is False

    probe_fields = {"provider", "property", "platform", "attempt_observed",
                    "outcome", "mechanism"}
    rows = [value for value in control.values() if isinstance(value, dict)]
    rows.append(control)
    for row in rows:
        assert not probe_fields <= set(row), (
            "a row in the ambient-capability control has the full shape of a "
            "ConfinementProbe, so a later edit could move it into the probe "
            "list and give a stand-in process a vote on Claude's confinement"
        )


# ---------------------------------------------------------------------------
# H8  the steering surface, recorded and NOT closed here (item 5)
# ---------------------------------------------------------------------------

def test_the_adapter_asks_the_operating_system_for_nothing():
    """GREEN TODAY BY CONSTRUCTION, and that is its job.

    This does not repair anything. It makes any future addition of `--settings`,
    `--strict-mcp-config` or `--permission-mode` a visible, deliberate diff
    rather than a silent change in what "the adapter confines" means -- and it
    records, in a place that runs, that none of them is an enforcement
    mechanism, so none of them may move the row.
    """
    module_source = Path(claude_worker.__file__).read_text(encoding="utf-8")
    present = sorted(flag for flag in ISOLATION_FLAGS if flag in module_source)
    assert present == [], (
        f"the Claude adapter now passes {present}. None of these is an "
        "operating-system boundary -- they steer Claude Code's own harness -- so "
        "whatever else this change does, the confinement row must not move and "
        "the measurement document must say what changed"
    )
    assert "sandbox" not in module_source

    import inspect  # noqa: PLC0415
    source = inspect.getsource(claude_worker.ClaudeCodeWorker.run)
    dedented = "\n".join(line[4:] if line.startswith("    ") else line
                         for line in source.splitlines())
    literals = [node.value for node in ast.walk(ast.parse(dedented))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
                and (node.value.startswith("-") or node.value == "json")]
    assert literals == ["-p", "--output-format", "json", "--max-turns",
                        "--allowedTools"], (
        f"the adapter's command construction moved: {literals}. The tuple is "
        "pinned so that what Forge hands the provider is read from the code "
        "rather than remembered from a document"
    )


def test_the_record_states_the_steering_surface_it_did_not_close():
    """The inherited configuration is a FINDING, recorded rather than repaired,
    in PA-01's "also observed, not fixed here" form."""
    adapter = _record()["adapter_construction"]
    assert adapter["argv_literals_in_run"] == [
        "-p", "--output-format", "json", "--max-turns", "--allowedTools"]
    assert all(adapter["isolation_flags_absent"][flag] for flag in ISOLATION_FLAGS)
    assert adapter["sandbox_string_in_module"] is False
    assert adapter["environment_rule"] == "os.environ minus FORGE and FORGE_*"
    assert adapter["environment_variables_passed_through"] > 0


# ---------------------------------------------------------------------------
# H9  the document, held to the record under it
# ---------------------------------------------------------------------------

def test_the_measurement_document_states_the_recorded_verdict():
    """A document read by nothing is a document that goes quietly false. This
    holds its load-bearing sentences to values derived from the record and from
    running the code."""
    text = DOCUMENT.read_text(encoding="utf-8")
    # NORMALISED, and the two concessions are named rather than left implicit.
    # Whitespace: a load-bearing sentence that happens to wrap across a line is
    # the same sentence, and a pin that failed on the author's line width would
    # be measuring the margin. Case: a phrase opening a sentence carries a
    # capital, and "No model was invoked" is not a different claim from "no
    # model was invoked". Neither concession lets a phrase be ABSENT.
    flattened = " ".join(text.split()).lower()
    assessment = assess_confinement(PROVIDER, PLATFORM, _measurement())
    required = (
        "**Result: NOT ESTABLISHED.**",
        f'`PROVIDER_CONFINEMENT["claude"]["{PLATFORM}"]` stays '
        f'`{PROVIDER_CONFINEMENT[PROVIDER][PLATFORM]}`',
        "no model was invoked",
        "a stand-in process is not the provider",
        "EA-1", "EA-2", "EA-3", "EA-4",
    )
    missing = [phrase for phrase in required
               if " ".join(phrase.split()).lower() not in flattened]
    assert missing == [], f"the measurement document no longer says: {missing}"
    assert str(assessment.establishes) == "False"
    for prop in CONFINEMENT_PROPERTIES:
        assert prop in text, f"the results table does not mention {prop}"

    # THE ONE NUMBER IN THE DOCUMENT THAT CAN ROT, tied to the record it came
    # from. The search bound's entry count changes with the disk, so a figure
    # typed into prose and read by nothing would be stale on the next run --
    # which is how the census comment in this repository went stale twice.
    bound = _record()["host"]["srt_win_search_bound"]
    assert f"{bound['entries_visited']:,}" in text, (
        "the document states an entry count the record does not: it says the "
        "walk visited a number that this record did not measure"
    )
    assert bound["search_completed_within_bound"] is True, (
        "the recorded walk hit its own bound, so 'not found' is weaker than the "
        "document's table says; re-run the harness or weaken the sentence"
    )


# ---------------------------------------------------------------------------
# H10  the affirmative limit pin (A-029's pattern)
# ---------------------------------------------------------------------------

def test_the_claude_confinement_limit_is_the_disclosed_boundary():
    """THE LIMIT, PINNED IN THE AFFIRMATIVE.

    The behaviour above is the disclosed limit, so a slice that closes the case
    -- or one that quietly deletes the admission and leaves the mechanism -- has
    to rewrite the disclosure in the same commit. The three limit behaviours are
    asserted in the SAME test as the register text, because a later slice could
    otherwise close one without touching the other.

    Falsified before it was kept: with A-033's section removed this reddens.
    """
    from test_actor_declaration_boundary import FORBIDDEN_CLAIMS  # noqa: PLC0415

    disclosed = ASSUMPTIONS.read_text(encoding="utf-8")
    assert "## A-033" in disclosed, "A-033 is gone; the limit is disclosed nowhere"
    # WHITESPACE ONLY, and case is deliberately NOT normalised. A load-bearing
    # sentence that wraps across a line is the same sentence, so failing on the
    # author's line width would be measuring the margin. But the first phrase
    # below is SHOUTED on purpose -- it is the finding -- and a register that
    # softened it to ordinary prose would be saying something quieter than what
    # the code relies on it saying, so the case is part of the claim.
    flattened = " ".join(disclosed.split())
    required = (
        "NO OPERATING-SYSTEM CONFINEMENT MECHANISM IS REACHABLE FOR CLAUDE ON "
        "NATIVE WINDOWS",
        "a stand-in process is not the provider",
        "no model was invoked",
        "`denied` cannot be observed on this platform",
        "evidence does not travel between platforms",
        "the row stays `none`",
    )
    missing = [phrase for phrase in required
               if " ".join(phrase.split()) not in flattened]
    assert missing == [], (
        "A-033 no longer says what the code relies on it saying. A slice that "
        f"closed this case must rewrite the disclosure, not drop it: {missing}")
    assert "A-033" in disclosed.split("## A-024")[1].split("## A-025")[0], (
        "A-024 closed by saying Claude was not measured and keeps the row it "
        "had; that sentence must point at the measurement that has since been "
        "taken, or the register disagrees with itself")

    # (i) the shipped record still establishes nothing.
    assessment = assess_confinement(PROVIDER, PLATFORM, _measurement())
    assert assessment.establishes is False
    assert assessment.unmet == tuple(CONFINEMENT_PROPERTIES)
    # (ii) the decision still refuses, and claims nothing while refusing.
    verdict = governed_build_eligibility(PROVIDER, PLATFORM)
    assert verdict.eligible is False and verdict.confinement == "none"
    assert [phrase for phrase in FORBIDDEN_CLAIMS if phrase in verdict.reason] == []
    # (iii) the probe vocabulary still refuses the word that would make the
    # impossibility look like a closed gap.
    with pytest.raises(ProviderError):
        ConfinementProbe(
            provider=PROVIDER, property="link_escape_write", platform=PLATFORM,
            attempt_observed=True, outcome="not_applicable",
            mechanism="observed_process_result",
        ).validate()


def test_the_a033_disclosure_names_every_spelling_the_rule_does_not_refuse():
    """PIN: the register's limit sentence and the structural rule agree.

    The rule refuses the process-creation shapes it names and no others. Three
    governed texts used to say it refused "any other spawn call"; they now
    state the measured bound and name what got past it. This holds the A-033
    half, because the register is the text a person quotes -- and a sentence
    that names four of five is the substitution this repository keeps finding.

    SCOPED TO THE A-033 SECTION ON PURPOSE. A phrase matched anywhere in a
    4,600-line register would let the disclosure drift into some other entry
    and still pass here, which would make this pin a spell-checker rather than
    a measurement of where the limit is written.

    Falsified before it was kept: with one named spelling deleted from A-033
    this reddens and names the missing one.
    """
    disclosed = ASSUMPTIONS.read_text(encoding="utf-8")
    assert "## A-033" in disclosed, "A-033 is gone; the limit is disclosed nowhere"
    section = disclosed.split("## A-033", 1)[1].split("\n## ", 1)[0]
    # POSITIVE CONTROL ON THE SPLIT. A boundary that matched the wrong thing
    # would hand an empty string to the loop below, every phrase would be
    # "missing", and the failure would look like a disclosure defect rather
    # than a broken reader. A short section is the louder, truer message.
    assert len(section) > 2000, (
        f"the A-033 section read back as {len(section)} characters, which is "
        "too short to be the register entry; the section split found the wrong "
        "boundary and nothing below is measuring the disclosure"
    )
    # WHITESPACE ONLY, for the reason the pin above gives: a load-bearing
    # sentence that wraps across a line is the same sentence.
    flattened = " ".join(section.split())
    missing = [phrase for phrase in DISCLOSED_UNREFUSED_SPELLINGS
               if " ".join(phrase.split()) not in flattened]
    assert missing == [], (
        "A-033 no longer names every spelling the structural rule does NOT "
        "refuse, so the register states a bound wider than the one measured. "
        f"Name them or close them, but do not drop them: {missing}"
    )


def test_the_rule_is_decided_by_the_spelling_not_by_the_expression_shape():
    """PIN: the named specimens, and what the rule above ACTUALLY does to them.

    THE DEFECT THIS EXISTS TO STOP RECURRING. Three governed texts said the
    rule refused "any" process-creation call; that was corrected, and the
    correction asserted instead that a `ctypes` handle was refused in its
    one-expression form and not in its two-step form. The second sentence was
    false for the same reason as the first: it generalised one specimen. The
    round-2 specimen reddened because its final attribute happened to be spelled
    `system`, not because it was one expression -- and the row below carrying
    `windll.kernel32.WinExec` is one expression, reaches `ctypes`, and is NOT
    refused.

    So the discriminator is asserted here as a measurement rather than
    described in prose: the same expression shape appears twice, once refused
    and once not, and what separates them is the spelling of the final
    attribute together with the exact dotted prefix.

    THE ADAPTER ROW IS DIFFERENT IN KIND. `_adapter.run(...)` names no process
    module at all; `_dotted` returns `_adapter.run`, whose module part is not
    enumerated and cannot be, because the spawn is in another module. Nothing
    here closes it, and no rule phrased over process-module names would.

    NOT AN EXECUTION. Every source below is PARSED and never run.
    """
    for source, expected_dotted, expected_refused in RULE_SPECIMENS:
        dotted = tuple(_dotted(node.func)
                       for node in ast.walk(ast.parse(source))
                       if isinstance(node, ast.Call))
        assert dotted == expected_dotted, (
            f"the rule derives {dotted} from {source!r}, not "
            f"{expected_dotted}; `_dotted` has changed and this table is now "
            "describing a rule that no longer exists"
        )
        refused = any(_starts_a_process(name) for name in dotted)
        assert refused is expected_refused, (
            f"the rule {'refuses' if refused else 'does NOT refuse'} "
            f"{source!r}, and this table says the opposite. Either the rule "
            "moved, in which case the three governed texts that describe it "
            "have to move with it, or the table states a refusal that is not "
            "performed"
        )
    # THE TABLE MUST CONTAIN BOTH ANSWERS, or it measures nothing. A row set
    # that drifted to all-refused would pass every assertion above while
    # proving the rule catches everything, which is the claim this whole
    # round exists to retire.
    verdicts = {row[2] for row in RULE_SPECIMENS}
    assert verdicts == {True, False}, (
        "the specimen table no longer carries both a refused and an unrefused "
        f"spelling ({verdicts}), so it cannot show where the rule's edge is"
    )


def test_the_three_governed_texts_state_the_measured_bound():
    """PIN: the CLAIM the three texts make, not the vocabulary beside it.

    The pin above holds A-033 to NAMING the spellings. A review then restored
    the retired universal claim AROUND those names -- in A-033, in the CHANGELOG
    entry and in the harness docstring, one text at a time -- and all three runs
    stayed green, because naming a spelling and stating a bound are different
    assertions and only the first was held anywhere.

    WHAT THIS HOLDS: that none of the three carries one of the retired
    spellings, and that each states the measured bound.

    WHAT IT DOES NOT HOLD, said plainly because the failure mode here is
    believing otherwise: it is a text pin over named strings. A paraphrase it
    does not enumerate can still claim too much, and no string test can decide
    that question. What ties the claim to a measurement is the specimen table
    above; this holds the three texts to the words that measurement produced.
    Both are needed, and neither is a substitute for the other.
    """
    disclosed = ASSUMPTIONS.read_text(encoding="utf-8")
    assert "## A-033" in disclosed, "A-033 is gone; the limit is disclosed nowhere"
    section = disclosed.split("## A-033", 1)[1].split("\n## ", 1)[0]
    # THE SAME POSITIVE CONTROL ON THE SPLIT the sibling pin carries: a boundary
    # that matched the wrong thing would hand a short string to the loop and
    # every absence would pass for the wrong reason.
    assert len(section) > 2000, (
        f"the A-033 section read back as {len(section)} characters, which is "
        "too short to be the register entry; nothing below is measuring it"
    )
    texts = {
        "docs/requirements/ASSUMPTIONS.md (## A-033)": section,
        "CHANGELOG.md": CHANGELOG.read_text(encoding="utf-8"),
        "scripts/probe_claude_confinement.py (module docstring)":
            ast.get_docstring(_harness_tree()) or "",
    }
    for label, text in texts.items():
        flattened = " ".join(text.split()).lower()
        restored = [claim for claim in RETIRED_UNIVERSAL_CLAIMS
                    if claim in flattened]
        assert restored == [], (
            f"{label} states a bound wider than the one measured: {restored}. "
            "The rule refuses the shapes it names and no others, and at least "
            "eight spellings have been measured getting past it. Correct the "
            "claim; do not correct this register"
        )
        assert MEASURED_BOUND in flattened, (
            f"{label} no longer states the measured bound "
            f"({MEASURED_BOUND!r}), so a reader has the disclosure without the "
            "sentence that says what the rule is worth"
        )
