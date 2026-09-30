"""The PowerShell 5.1 linter reports what its tokens show and refuses the rest.

What is held here, in words:

- FAIL-CLOSED INPUT. Missing, unreadable, linked, special, oversized and
  wrongly-suffixed inputs refuse, each for its own stated reason, and so does a
  directory; so do bytes whose decoding no byte-order mark fixes, every control
  or format character but TAB, LF and CR (in code, a string, a comment, after a
  backtick, a key or a braced name, refused by `tokenize` itself), malformed
  source, no path, too many paths, and an exception inside a rule. One refused
  file refuses the run. A refusal is never "clean".
- EXACTLY THE NAMED FILES. Each distinct argument gets exactly one entry, even
  when two arguments name one file; nothing is walked, dropped or merged.
- BOUNDED COST. Four times the input costs well under eight times as much for
  the shapes that once cost quadratic time.
- EXACT SPECIMENS. Every specimen under `tests/specimens/ps51/` declares its
  findings in its own header, and the linter must produce exactly those, no
  more and no fewer. Every rule has a firing specimen, and removing a rule
  fails exactly the specimens that declare it.
- NOT CODE, NOT FOUND. Each firing specimen, wrapped whole in a comment, a
  single-quoted string or here-string, stop-parsing arguments or (for rules not
  keyed on expandable text) an expandable string or here-string, yields nothing.
- THE LEXER'S BASIS. The token shapes Windows PowerShell 5.1's own tokenizer
  produced for synthetic snippets are reproduced case by case.
- NO AUTHORITY. The linter writes nothing, starts nothing, and imports no
  process or network module; its report is byte-identical across runs and
  ends its lines in LF alone. No option exists: any argument starting with '-'
  refuses as a usage error and nothing is judged.

The specimens are `.ps1.txt`, never `.ps1`: `.txt` is declared canonical text,
so they stay under the repository's LF rule. Byte-level inputs (marks, UTF-16,
control characters, typographic quotes) are built in memory, never committed.
"""

from __future__ import annotations

import ast
import gc
import io
import json
import os
import re
import stat
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ps51_lint.py"
SPECIMENS = ROOT / "tests" / "specimens" / "ps51"
sys.path.insert(0, str(ROOT / "scripts"))

import ps51_lint  # noqa: E402

_POSIX = os.name == "posix"
_UNPRIVILEGED = _POSIX and os.geteuid() != 0
_EXPECT = re.compile(r"^# expect: (?:none|([a-z0-9-]+) ([0-9]+):([0-9]+))$")
LSQ, RSQ, LDQ, RDQ = chr(0x2018), chr(0x2019), chr(0x201C), chr(0x201D)
EN_DASH, EM_DASH, NBSP = chr(0x2013), chr(0x2014), chr(0xA0)


def _specimens() -> list:
    return sorted(SPECIMENS.glob("*.ps1.txt"))


def _declared(path: Path):
    """The (rule, line, column) findings a specimen's header declares, or None
    when it declares nothing at all (not even `none`)."""
    lines = path.read_text(encoding="ascii").splitlines()
    matches = [_EXPECT.match(line) for line in lines]
    header = matches[:next((i for i, m in enumerate(matches) if m is None), len(matches))]
    if not header:
        return None
    return sorted((m.group(1), int(m.group(2)), int(m.group(3))) for m in header if m.group(1))


def _found(text: str) -> list:
    return sorted((f.rule, f.line, f.column) for f in ps51_lint.lint_text(text))


def _body(path: Path) -> list:
    """A specimen's lines after its header: the expectations and one description line."""
    lines = path.read_text(encoding="ascii").splitlines()
    skip = next(i for i, line in enumerate(lines) if not line.startswith("# expect:")) + 1
    return lines[skip:]


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _run(*args, cwd: Path):
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd, capture_output=True,
                          timeout=120)


def _verdict(paths) -> str:
    return ps51_lint.lint_paths([str(p) for p in paths]).verdict


# -- exact specimens -----------------------------------------------------------


@pytest.mark.parametrize("specimen", _specimens(), ids=lambda p: p.name[:-len(".ps1.txt")])
def test_each_specimen_yields_exactly_its_declared_findings(specimen):
    """A specimen's findings equal its declared (rule, line, column) set exactly."""
    declared = _declared(specimen)
    assert declared is not None, f"{specimen.name} declares no expectation"
    assert _found(specimen.read_text(encoding="ascii")) == declared


def test_every_specimen_declares_and_every_rule_has_a_firing_specimen():
    """Every specimen declares, and the rules named by specimens are exactly the
    rules the linter runs: a dropped rule or specimen cannot shrink the proof."""
    specimens = _specimens()
    assert len(specimens) >= len(ps51_lint.RULES)
    assert [p.name for p in specimens if _declared(p) is None] == []
    firing = {rule for p in specimens for rule, _line, _column in _declared(p)}
    assert firing == {rule for rule, _check in ps51_lint.RULES}


@pytest.mark.parametrize("rule", [rule for rule, _check in ps51_lint.RULES])
def test_removing_a_rule_fails_exactly_its_specimens(rule, monkeypatch):
    """With one rule removed from the registry, exactly the specimens declaring
    that rule stop matching their declarations, so every rule is load-bearing."""
    monkeypatch.setattr(ps51_lint, "RULES", tuple(p for p in ps51_lint.RULES if p[0] != rule))
    failing = [p.name for p in _specimens()
               if _found(p.read_text(encoding="ascii")) != _declared(p)]
    declaring = [p.name for p in _specimens() if any(r == rule for r, _l, _c in _declared(p))]
    assert declaring and failing == declaring


# -- non-code contexts ---------------------------------------------------------

_EXPANDABLE_KEYED = {"variable-case-variants", "string-colon-variable"}


def _contexts(rules: set, lines: list) -> dict:
    """The generator: a firing specimen's whole body wrapped in each non-code
    context. Stop-parsing wraps line by line and needs lines without '|'; its
    `x ;` would end the statement if `--%` were not recognized, putting the
    trigger in command position. The expandable contexts are left out for
    rules keyed on expandable text."""
    body = "\n".join(lines)
    contexts = {
        "line-comment": "\n".join("# " + line for line in lines),
        "block-comment": "<#\n" + body + "\n#>",
        "single-quoted": "Write-Output '" + body.replace("'", "''") + "'",
        "single-here-string": "Write-Output @'\n" + body + "\n'@",
    }
    if not any("|" in line for line in lines):
        contexts["stop-parsing"] = "\n".join("cmd /c echo --% x ; " + line for line in lines)
    if not rules & _EXPANDABLE_KEYED:
        contexts["expandable"] = 'Write-Output "' + body.replace("`", "``").replace('"', '""') + '"'
        contexts["expandable-here-string"] = 'Write-Output @"\n' + body + '\n"@'
    return contexts


def _wrapped_cases() -> list:
    cases = []
    for path in _specimens():
        rules = {rule for rule, _line, _column in _declared(path) or []}
        if rules:
            cases += [pytest.param(path, name, text, id=path.name[:-8] + "-" + name)
                      for name, text in _contexts(rules, _body(path)).items()]
    return cases


@pytest.mark.parametrize(("specimen", "context", "wrapped"), _wrapped_cases())
def test_a_trigger_in_a_non_code_context_does_not_fire(specimen, context, wrapped):
    """The same trigger text that fires as code yields no finding (and no
    refusal) once it is inside a comment, a string or stop-parsing arguments."""
    assert _found(specimen.read_text(encoding="ascii")), "the unwrapped specimen must fire"
    assert _found(wrapped + "\n") == [], context


# -- the lexer's measured basis ------------------------------------------------

#: Token shapes measured with Windows PowerShell 5.1's own tokenizer on synthetic
#: snippets, written as kind:text joined by " ~ ", or REFUSED where the engine
#: reported a parse error. Line continuations are not tokens here. Two rows depart
#: from the engine on purpose: it split tokens at a form feed and a vertical tab,
#: and it kept U+0085 inside a comment; the linter refuses all three, as it
#: refuses every other control character.
MEASURED = [
    ("hash-inside-an-argument", "Write-Output a#b # tail comment",
     "bareword:Write-Output ~ bareword:a#b ~ comment:# tail comment"),
    ("typographic-single-quotes", "Write-Output " + LSQ + "y z" + RSQ + " ; $after = 1",
     "bareword:Write-Output ~ string:" + LSQ + "y z" + RSQ
     + " ~ punct:; ~ variable:$after ~ operator:= ~ number:1"),
    ("typographic-double-quotes", "Write-Output " + LDQ + "y $v z" + RDQ + " ; $after = 1",
     "bareword:Write-Output ~ string:" + LDQ + "y $v z" + RDQ
     + " refs=$v ~ punct:; ~ variable:$after ~ operator:= ~ number:1"),
    ("en-dash-parameter", "Get-ChildItem " + EN_DASH + "Recurse",
     "bareword:Get-ChildItem ~ dash:" + EN_DASH + "Recurse"),
    ("here-string-header-with-trailing-spaces", '@"   \nbody\n"@', 'string:@"   \nbody\n"@'),
    ("here-string-terminator-not-at-column-0", "@'\nbody\n '@\n'@\n$after = 1",
     "string:@'\nbody\n '@\n'@ ~ newline:\n ~ variable:$after ~ operator:= ~ number:1"),
    ("qualified-name-inside-expandable-string", '"$user:home"', 'string:"$user:home" refs=$user:home'),
    ("colon-then-space-inside-expandable-string", '"$user: home"', "REFUSED"),
    ("stop-parsing-token", "cmd.exe /c echo --% a | b # c",
     "bareword:cmd.exe ~ bareword:/c ~ bareword:echo ~ stopparse:--% ~ raw:a  ~ punct:| "
     "~ bareword:b ~ comment:# c"),
    ("stderr-merge-redirection", "git status 2>&1", "bareword:git ~ bareword:status ~ redirect:2>&1"),
    ("hash-right-after-a-variable", "$x#y", "variable:$x ~ comment:#y"),
    ("hash-right-after-a-number", "$x = 5#c", "variable:$x ~ operator:= ~ number:5 ~ comment:#c"),
    ("line-continuation", "Get-Item `\n -Path x", "bareword:Get-Item ~ dash:-Path ~ bareword:x"),
    ("quote-inside-a-subexpression-inside-a-string", '"a $("b") c" ; $after = 1',
     'string:"a $("b") c" ~ punct:; ~ variable:$after ~ operator:= ~ number:1'),
    ("block-comment-then-code", "<# a #> $x = 1", "comment:<# a #> ~ variable:$x ~ operator:= ~ number:1"),
    ("block-comment-opener-inside-single-quotes", "'<#' ; $y = 1", "string:'<#' ~ punct:; ~ variable:$y ~ operator:= ~ number:1"),
    ("braced-variable", "${a b} = 1", "variable:${a b} ~ operator:= ~ number:1"),
    ("scope-and-drive-qualified", "$script:x; $env:PATH; $variable:x; $global:X",
     "variable:$script:x ~ punct:; ~ variable:$env:PATH ~ punct:; ~ variable:$variable:x "
     "~ punct:; ~ variable:$global:X"),
    ("terminator-shaped-line-inside-a-subexpression-of-a-here-string", '@"\n$(\n"@\n)\n"@\n$after = 1', "REFUSED"),
    ("unterminated-single-quoted-string", "'abc", "REFUSED"),
    ("here-string-header-followed-by-text", "@'abc\n'@", "REFUSED"),
    ("member-access-and-index", "$r = Get-Thing; $r[0]; $r.Count",
     "variable:$r ~ operator:= ~ bareword:Get-Thing ~ punct:; ~ variable:$r ~ punct:[ "
     "~ number:0 ~ punct:] ~ punct:; ~ variable:$r ~ punct:. ~ member:Count"),
    ("doubled-quote-escapes", "'it''s' ; \"say \"\"hi\"\"\"", "string:'it''s' ~ punct:; ~ string:\"say \"\"hi\"\"\""),
    ("hash-inside-a-double-quoted-string", '"a # b" # real', 'string:"a # b" ~ comment:# real'),
    ("backtick-escape-of-a-quote-inside-a-string", '"a `" b" ; $after = 1',
     'string:"a `" b" ~ punct:; ~ variable:$after ~ operator:= ~ number:1'),
    ("mixed-typographic-and-ascii-single-quotes", "Write-Output " + LSQ + "q' ; $after = 1",
     "bareword:Write-Output ~ string:" + LSQ + "q' ~ punct:; ~ variable:$after ~ operator:= "
     "~ number:1"),
    ("comment-opener-glued-to-an-argument", "Write-Output ab<#c#>d", "bareword:Write-Output ~ bareword:ab<#c#>d"),
    ("hash-after-stop-parsing", "cmd.exe /c echo --% a # b",
     "bareword:cmd.exe ~ bareword:/c ~ bareword:echo ~ stopparse:--% ~ raw:a # b"),
    ("semicolon-after-stop-parsing", "cmd.exe /c echo --% a ; b",
     "bareword:cmd.exe ~ bareword:/c ~ bareword:echo ~ stopparse:--% ~ raw:a ; b"),
    ("block-comment-inside-an-expression", "$x = 1 <# c #> + 2",
     "variable:$x ~ operator:= ~ number:1 ~ comment:<# c #> ~ operator:+ ~ number:2"),
    ("here-string-with-crlf", "@'\r\nbody\r\n'@\r\n$after = 1",
     "string:@'\r\nbody\r\n'@ ~ newline:\r\n ~ variable:$after ~ operator:= ~ number:1"),
    ("lone-cr-separates-statements", "$a = 1\r$b = 2",
     "variable:$a ~ operator:= ~ number:1 ~ newline:\r ~ variable:$b ~ operator:= ~ number:2"),
    ("parameter-with-colon-value", "Get-Item x -ErrorAction:SilentlyContinue -ea 0",
     "bareword:Get-Item ~ bareword:x ~ dash:-ErrorAction: ~ bareword:SilentlyContinue "
     "~ dash:-ea ~ number:0"),
    ("no-break-space-between-tokens", "Write-Output" + NBSP + "x", "bareword:Write-Output ~ bareword:x"),
    ("redirection-to-null", "Get-Item x 2>$null",
     "bareword:Get-Item ~ bareword:x ~ redirect:2> ~ variable:$null"),
    ("doubled-typographic-double-quotes", LDQ + "a" + RDQ + RDQ + "b" + RDQ + " ; $after = 1",
     "string:" + LDQ + "a" + RDQ + RDQ + "b" + RDQ
     + " ~ punct:; ~ variable:$after ~ operator:= ~ number:1"),
    ("unterminated-subexpression-inside-a-string", '"a $(b"', "REFUSED"),
    ("form-feed-and-vertical-tab-between-tokens", "Write-Output\x0cx\x0by", "REFUSED"),
    ("line-separator-inside-a-comment", "# a" + chr(0x2028) + "$x = 1", "comment:# a" + chr(0x2028) + "$x = 1"),
    ("next-line-inside-a-comment", "# a" + chr(0x85) + "$x = 1", "REFUSED"),
    ("em-dash-operator", "$a " + EM_DASH + "join ','", "variable:$a ~ dash:" + EM_DASH + "join ~ string:','"),
    ("splat", "Get-Item @params", "bareword:Get-Item ~ splat:@params"),
    ("number-forms", "$a = 1kb + 0x1F + 1.5e3 + 1..3",
     "variable:$a ~ operator:= ~ number:1kb ~ operator:+ ~ number:0x1F ~ operator:+ "
     "~ number:1.5e3 ~ operator:+ ~ number:1 ~ operator:.. ~ number:3"),
    ("dollar-alone-and-dollar-hash", "Write-Output $ $#", "bareword:Write-Output ~ bareword:$ ~ bareword:$#"),
    ("variable-followed-by-double-colon", "$t::Now", "variable:$t ~ operator::: ~ member:Now"),
    ("at-sign-alone", "Write-Output a@b @", "REFUSED"),
    ("gt-inside-an-argument", "Write-Output a>b", "bareword:Write-Output ~ bareword:a>b"),
    ("lt-inside-an-argument", "Write-Output a<b", "bareword:Write-Output ~ bareword:a<b"),
    ("hash-gt-inside-an-argument", "Write-Output a#>b", "bareword:Write-Output ~ bareword:a#>b"),
    ("single-quotes-inside-an-argument", "Write-Output a'b c'd", "bareword:Write-Output ~ bareword:a'b c'd"),
    ("double-quotes-inside-an-argument", 'Write-Output a"b c"d', 'bareword:Write-Output ~ bareword:a"b c"d'),
    ("dollar-inside-an-argument", "Write-Output a$b", "bareword:Write-Output ~ bareword:a$b"),
    ("question-mark-in-a-variable-name", "$a?b = 1; $c? = 2",
     "variable:$a?b ~ operator:= ~ number:1 ~ punct:; ~ variable:$c? ~ operator:= ~ number:2"),
    ("colon-then-space-after-a-variable-in-a-command", "Write-Output $user: home", "REFUSED"),
    ("colon-then-space-after-a-variable-in-an-expression", "$x = $user: + 1", "REFUSED"),
    ("hash-after-a-number-in-a-command", "Write-Output 5#c", "bareword:Write-Output ~ bareword:5#c"),
    ("digits-then-letters", "Write-Output 1abc 2x", "bareword:Write-Output ~ bareword:1abc ~ bareword:2x"),
    ("equals-inside-an-argument", "Write-Output a=b", "bareword:Write-Output ~ bareword:a=b"),
    ("hash-after-a-quoted-argument", "Write-Output 'a'#b", "bareword:Write-Output ~ string:'a' ~ comment:#b"),
    ("hash-after-a-quoted-value", "$x = 'a'#b", "variable:$x ~ operator:= ~ string:'a' ~ comment:#b"),
    ("redirection-glued-to-an-argument", "Write-Output a2>&1", "REFUSED"),
    ("backtick-in-a-braced-variable", "Write-Output ${a`}b}", "bareword:Write-Output ~ variable:${a`}b}"),
    ("dot-and-colon-inside-an-argument", "Write-Output a.b:c", "bareword:Write-Output ~ bareword:a.b:c"),
    ("dash-inside-a-parameter", "Get-Thing -Name:x -a-b",
     "bareword:Get-Thing ~ dash:-Name: ~ bareword:x ~ dash:-a-b"),
    ("nested-generic-type-literal", "[System.Collections.Generic.List[object]]$x = $null",
     "punct:[ ~ bareword:System.Collections.Generic.List ~ punct:[ ~ bareword:object ~ punct:] "
     "~ punct:] ~ variable:$x ~ operator:= ~ variable:$null"),
    ("member-assignment-without-spaces", "$p.Arguments=$a -join ' '",
     "variable:$p ~ punct:. ~ member:Arguments ~ operator:= ~ variable:$a ~ dash:-join "
     "~ string:' '"),
    ("hash-after-a-parenthesis", "Write-Output (1)#c",
     "bareword:Write-Output ~ punct:( ~ number:1 ~ punct:) ~ comment:#c"),
    ("brackets-then-hash-in-an-argument", "Write-Output a[1]#c", "bareword:Write-Output ~ bareword:a[1]#c"),
    ("comma-and-semicolon-split", "Write-Output a,b;c",
     "bareword:Write-Output ~ bareword:a ~ punct:, ~ bareword:b ~ punct:; ~ bareword:c"),
    ("double-dash-argument", "git --version 2>&1 | Out-Null",
     "bareword:git ~ bareword:--version ~ redirect:2>&1 ~ punct:| ~ bareword:Out-Null"),
    ("call-operator-and-merge-all", "& 'x.exe' *>&1", "punct:& ~ string:'x.exe' ~ redirect:*>&1"),
    ("escaped-hash-inside-an-argument", "Write-Output a`#b", "bareword:Write-Output ~ bareword:a`#b"),
    ("hashtable-literal", "$h = @{ a = 1; 'b' = 2 }",
     "variable:$h ~ operator:= ~ punct:@{ ~ bareword:a ~ operator:= ~ number:1 ~ punct:; "
     "~ string:'b' ~ operator:= ~ number:2 ~ punct:}"),
    ("scoped-function-name", "function global:Foo { }",
     "bareword:function ~ bareword:global:Foo ~ punct:{ ~ punct:}"),
    ("colon-parameter-with-a-variable", "Write-Output -a:$b", "bareword:Write-Output ~ dash:-a: ~ variable:$b"),
    ("member-then-hash", "Write-Output $a.b#c",
     "bareword:Write-Output ~ variable:$a ~ punct:. ~ member:b ~ comment:#c"),
    ("double-quoted-then-letters", 'Write-Output "a"b', 'bareword:Write-Output ~ string:"a" ~ bareword:b'),
    ("here-string-end-then-hash", '$h = @"\nx\n"@#c', 'variable:$h ~ operator:= ~ string:@"\nx\n"@ ~ comment:#c'),
    ("two-colons-after-a-variable", "Write-Output $x:y:z", "bareword:Write-Output ~ variable:$x:y:z"),
    ("double-colon-inside-a-string", '"$a::b"', 'string:"$a::b" refs=$a'),
    ("braced-and-qualified-inside-a-string", '"${a}:b $script:c $env:d"',
     'string:"${a}:b $script:c $env:d" refs=${a},$script:c,$env:d'),
    ("relative-script-path", ".\\run.ps1 -Arg 1", "bareword:.\\run.ps1 ~ dash:-Arg ~ number:1"),
    ("dot-source", ". .\\lib.ps1", "punct:. ~ bareword:.\\lib.ps1"),
    ("member-count-then-hash", "$a.Count#c", "variable:$a ~ punct:. ~ member:Count ~ comment:#c"),
    ("not-operators", "if (-not $x) { !$y }",
     "bareword:if ~ punct:( ~ dash:-not ~ variable:$x ~ punct:) ~ punct:{ ~ operator:! "
     "~ variable:$y ~ punct:}"),
    ("backslash-then-hash", "Write-Output a\\#b", "bareword:Write-Output ~ bareword:a\\#b"),
    ("cast-before-a-variable", "$c = [int]$LASTEXITCODE; $d = [int] $p.ExitCode",
     "variable:$c ~ operator:= ~ punct:[ ~ bareword:int ~ punct:] ~ variable:$LASTEXITCODE "
     "~ punct:; ~ variable:$d ~ operator:= ~ punct:[ ~ bareword:int ~ punct:] ~ variable:$p "
     "~ punct:. ~ member:ExitCode"),
    ("index-after-a-variable", "$r = Get-Thing; $r[0]; $r[-1]; $r.Count",
     "variable:$r ~ operator:= ~ bareword:Get-Thing ~ punct:; ~ variable:$r ~ punct:[ "
     "~ number:0 ~ punct:] ~ punct:; ~ variable:$r ~ punct:[ ~ number:-1 ~ punct:] ~ punct:; "
     "~ variable:$r ~ punct:. ~ member:Count"),
    ("type-literal-static-call", "[string]::Join(' ', $a)",
     "punct:[ ~ bareword:string ~ punct:] ~ operator::: ~ member:Join ~ punct:( ~ string:' ' "
     "~ punct:, ~ variable:$a ~ punct:)"),
    ("lone-lt-in-an-expression", "$a = 1 < 2", "REFUSED"),
    ("at-paren-and-at-brace", "$a = @(1); $b = @{}",
     "variable:$a ~ operator:= ~ punct:@( ~ number:1 ~ punct:) ~ punct:; ~ variable:$b "
     "~ operator:= ~ punct:@{ ~ punct:}"),
    ("dollar-paren-in-a-command", "Write-Output $(1)x",
     "bareword:Write-Output ~ punct:$( ~ number:1 ~ punct:) ~ bareword:x"),
    ("stop-parsing-at-line-start-then-pipe", 'cmd /c --% a "b" | Out-Null',
     'bareword:cmd ~ bareword:/c ~ stopparse:--% ~ raw:a "b"  ~ punct:| ~ bareword:Out-Null'),
    ("variable-then-dot-then-digit", "$a.1", "variable:$a ~ punct:. ~ member:1"),
    ("splat-then-hash", "Get-Thing @p#c", "bareword:Get-Thing ~ bareword:@p#c"),
    ("unicode-spaces-and-separators-split-tokens", "Get-Item x" + chr(0x2003) + "-ErrorAction"
     + chr(0x2028) + "SilentlyContinue" + chr(0x3000) + "y",
     "bareword:Get-Item ~ bareword:x ~ dash:-ErrorAction ~ bareword:SilentlyContinue ~ bareword:y"),
]


def _shape(text: str) -> str:
    try:
        tokens = ps51_lint.tokenize(text)
    except ps51_lint.LintRefusal:
        return "REFUSED"
    return " ~ ".join(
        f"{t.kind}:{t.text}" + (" refs=" + ",".join(r.text for r in t.refs) if t.refs else "")
        for t in tokens)


@pytest.mark.parametrize(("case", "text", "expected"), MEASURED, ids=[c[0] for c in MEASURED])
def test_the_lexer_matches_the_measured_forms(case, text, expected):
    """Each measured snippet tokenizes to the shape the engine's tokenizer gave."""
    assert _shape(text) == expected, case


def test_the_lexer_whitespace_is_every_unicode_space_and_separator():
    """Measured: every space, line separator and paragraph separator (Unicode
    categories Zs, Zl, Zp) splits tokens as ' ' does and ends no line. The lexer's
    set is exactly that, in this Python's Unicode database, plus TAB: VT and FF
    are control characters, refused before lexing."""
    spaces = {chr(c) for c in range(0x110000) if unicodedata.category(chr(c)) in ("Zs", "Zl", "Zp")}
    assert set(ps51_lint._SPACES) == spaces | {"\t"}


#: Every control or format character the scan must refuse, and the places the
#: lexer reads differently: each character is refused in each of them.
_CONTROLS = [chr(c) for c in range(0x110000) if unicodedata.category(chr(c)) in ("Cc", "Cf")
             and chr(c) not in "\t\n\r"]
_CONTROL_CONTEXTS = {
    "code": "Write-Output a{}b\n", "single-quoted-string": "Write-Output 'a{}b'\n",
    "comment": "# a{}b\nWrite-Output 1\n", "after-a-backtick": "Write-Output a`{}b\n",
    "hashtable-key": "$h = @{{ a{}b = 1 }}\n", "attribute-key": "[CmdletBinding(a{}b = 1)]\n",
    "braced-name": "${{a{}b}} = 1\n", "after-stop-parsing": "cmd /c echo --% a{}b\n",
}


@pytest.mark.parametrize("context", sorted(_CONTROL_CONTEXTS))
def test_every_control_and_format_character_refuses_before_lexing(context, monkeypatch):
    """Every Unicode Cc or Cf character but TAB, LF and CR refuses, through
    `tokenize` itself and through `lint_text`, for the scan's own reason, in
    every place the lexer reads differently. Without the scan, the lexer
    accepts one held in a comment: the scan, not the lexer, refuses it."""
    for char in _CONTROLS:
        text = _CONTROL_CONTEXTS[context].format(char)
        for entry in (ps51_lint.tokenize, ps51_lint.lint_text):
            with pytest.raises(ps51_lint.LintRefusal, match="control or format character"):
                entry(text)
    if context == "comment":
        monkeypatch.setattr(ps51_lint, "_refuse_controls", lambda text: None)
        held = _CONTROL_CONTEXTS[context].format(chr(0x200B))
        assert ps51_lint.tokenize(held) and ps51_lint.lint_text(held) == []


@pytest.mark.parametrize("first, second, top, inside", [
    ("$item", "$ITEM", 1, 1), ("$item", "${ITEM}", 1, 1), ("$item", "$variable:ITEM", 1, 1),
    ("$item", "$local:ITEM", 1, 1), ("$item", "$private:ITEM", 1, 1), ("$local:item", "$ITEM", 1, 1),
    ("$item", "$script:ITEM", 1, 0), ("$script:item", "$ITEM", 1, 0),
    ("${script:item}", "$ITEM", 1, 0), ("${Global:item}", "$global:ITEM", 1, 1),
    ("$item", "$global:ITEM", 0, 0), ("$global:item", "$ITEM", 0, 0), ("$item", "$using:ITEM", 0, 0),
    ("$item", "$env:ITEM", 0, 0), ("$env:Path", "$env:PATH", 1, 1),
    ("${env:Path}", "$env:PATH", 1, 1), ("$env:item", "$x:env:ITEM", 0, 0)])
def test_variable_spellings_join_only_within_one_scope(first, second, top, inside):
    """One scope-aware key serves the case rule and the flow rules: the unit's own scope
    joins, `script:` only at the script level, and `global:` and `$env:` never join."""
    for rule, body, joined, at in (
            ("variable-case-variants", f"{first} = 1\nWrite-Output {second}\n", 1, (2, 14)),
            ("unwrapped-result-indexed", f"{first} = gci\n{second}[0]\n", 1, (2, 1)),
            ("json-null-unchecked", f"{first} = ConvertFrom-Json 1\nif ({second}) {{1}}\n", 1, (2, 1)),
            ("exit-code-null-cast", f"{first} = Start-Process -PassThru\n{second}.ExitCode\n", 1, (2, 1)),
            ("unwrapped-result-indexed", f"{first} = gci\n{second} = 1\n{first}[0]\n", 0, (3, 1))):
        for text, ok, shift in ((body, top, 0), ("function Get-It {\n" + body + "}\n", inside, 1)):
            hits = [(line - shift, col) for name, line, col in _found(text) if name == rule]
            assert hits == ([at] if ok == joined else [])


@pytest.mark.parametrize("text, rule, found", [
    ("$env:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 0),
    ("$other:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 0),
    ("${env:ErrorActionPreference} = 'SilentlyContinue'", "silenced-query", 0),
    ("$ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 1),
    ("$global:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 1),
    ("$script:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 1),
    ("$local:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 1),
    ("$private:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 1),
    ("$variable:ErrorActionPreference = 'SilentlyContinue'", "silenced-query", 1),
    ("[int]$env:LASTEXITCODE", "exit-code-null-cast", 0),
    ("[int]$other:LASTEXITCODE", "exit-code-null-cast", 0),
    ("[int]$script:LASTEXITCODE", "exit-code-null-cast", 1),
    ("[int]$LASTEXITCODE", "exit-code-null-cast", 1),
    ("$j = ConvertFrom-Json 1\nif ($env:null -ne $j) {1}", "json-null-unchecked", 0),
    ("$j = ConvertFrom-Json 1\nif ('null' -ne $j) {1}", "json-null-unchecked", 0),
    ("$j = ConvertFrom-Json 1\nif ($global:null -ne $j) {1}", "json-null-unchecked", 1),
    ("$j = ConvertFrom-Json 1\nif ($null -ne $j) {1}", "json-null-unchecked", 1)])
def test_an_automatic_or_preference_variable_needs_a_qualifier_that_can_address_it(
        text, rule, found):
    """`$env:ErrorActionPreference` and a drive `$other:LASTEXITCODE` or `$other:null` are not
    the automatic or preference variable; none, `local:`, `private:`, `script:`, `global:`
    and `variable:` can be."""
    assert sum(name == rule for name, _line, _col in _found(text)) == found


@pytest.mark.parametrize("text, rule, found", [
    ("Start-Process notepad.exe -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("Start-Process -FilePath notepad -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("Start-Process $exe -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("Start-Process $pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("notepad -Command child.ps1", "command-runs-script", 0),
    ("Start-Process powershell.exe -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -FilePath pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -File PWSH.EXE -ArgumentList '-c child.ps1'", "command-runs-script", 1),
    (r"Start-Process C:\Tools\pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Wait pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Verb RunAs powershell -ArgumentList '-Command a.ps1'", "command-runs-script", 1),
    (r". .\child.ps1 2>&1", "native-stderr-merged", 0),
    (". $path 2>&1", "native-stderr-merged", 0),
    (r"& .\child.ps1 2>&1", "native-stderr-merged", 0),
    (r".\child.ps1 2>&1", "native-stderr-merged", 0),
    ("& $exe 2>&1", "native-stderr-merged", 1),
    ("& (Get-Command git) x 2>&1", "native-stderr-merged", 1),
    ("& 'git' status 2>&1", "native-stderr-merged", 1),
    ("& git status 2>&1", "native-stderr-merged", 1),
    (r"& 'C:\Tools\git.exe' status 2>&1", "native-stderr-merged", 1),
    ("& 'Get-Item' x 2>&1", "native-stderr-merged", 0),
    ("& Get-Item x 2>&1", "native-stderr-merged", 0),
    ("& gci 2>&1", "native-stderr-merged", 0),
    ("function Foo-Bar {}\n& 'Foo-Bar' 2>&1", "native-stderr-merged", 0),
    ("function build {}\n& 'build' 2>&1", "native-stderr-merged", 0),
    ("git status 2>&1", "native-stderr-merged", 1),
    ("Start-Process -ArgumentList '-Command child.ps1', 'extra' -FilePath pwsh", "command-runs-script", 1),
    ("Start-Process -ArgumentList '-Command child.ps1', 'extra' -FilePath notepad", "command-runs-script", 0),
    ("Start-Process -ArgumentList '-Command child.ps1', 'extra' pwsh", "command-runs-script", 1),
    ("Start-Process -ArgumentList '-Command child.ps1', 'extra' notepad", "command-runs-script", 0),
    ("Start-Process -ArgumentList '-Command child.ps1' -FilePath $exe pwsh", "command-runs-script", 0),
    ("Start-Process -Verbose pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Debug pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Deb pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -vb pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -nnw pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Verbose:$false pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Wait:$false pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -FilePath:pwsh -Wait:$true -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -ErrorAction Stop pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -ea Stop notepad -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("Start-Process -V RunAs pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -V pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("Start-Process -W pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 0),
    ("Start-Process -PSPath pwsh -ArgumentList '-Command child.ps1'", "command-runs-script", 1),
    ("Start-Process -Args '-Command child.ps1', 'e' -PSPath notepad", "command-runs-script", 0),
    ("Start-Process notepad -V RunAs", "elevated-child-output", 1),
    ("Start-Process notepad -Verbose RunAs", "elevated-child-output", 0),
    ("$p = Start-Process x -Pa\n$p.ExitCode", "exit-code-null-cast", 1)])
def test_a_command_is_classified_by_what_it_runs(text, rule, found):
    """`Start-Process` carries a `-Command` line for a script only when its target is
    `powershell` or `pwsh`; a dot-sourced or `.ps1` script is PowerShell, not a native
    command, and a statically named `&` target is judged like a bareword command, while
    a native command still merges its stderr lines into error records."""
    assert sum(name == rule for name, _line, _col in _found(text)) == found


@pytest.mark.parametrize("text, rule, found", [
    ("$x = Get-Item .\n& { $x = @() }\n$x[0]", "unwrapped-result-indexed", 1),
    ("& { $x = Get-Item . }\n$x[0]", "unwrapped-result-indexed", 0),
    ("1 | & { $x = Get-Item . }\n$x[0]", "unwrapped-result-indexed", 0),
    ("& { $x = Get-Item .\n$x[0] }", "unwrapped-result-indexed", 1),
    ("$x = Get-Item .\n. { $x = @() }\n$x[0]", "unwrapped-result-indexed", 0),
    (". { $x = Get-Item . }\n$x[0]", "unwrapped-result-indexed", 1),
    ("$x = Get-Item .\n1 | ForEach-Object { $x = @() }\n$x[0]", "unwrapped-result-indexed", 0),
    ("1 | ForEach-Object { $x = Get-Item . }\n$x[0]", "unwrapped-result-indexed", 1),
    ("$j = ConvertFrom-Json 1\n& { $j = 2 }\nif ($j) {1}", "json-null-unchecked", 1),
    ("& { $j = ConvertFrom-Json 1 }\nif ($j) {1}", "json-null-unchecked", 0),
    (". { $j = ConvertFrom-Json 1 }\nif ($j) {1}", "json-null-unchecked", 1),
    ("$p = Start-Process x -PassThru\n& { $p = 1 }\n$p.ExitCode", "exit-code-null-cast", 1),
    ("& { $p = Start-Process x -PassThru }\n$p.ExitCode", "exit-code-null-cast", 0),
    (". { $p = Start-Process x -PassThru }\n$p.ExitCode", "exit-code-null-cast", 1),
    ("$item = 1\n& { $ITEM = 2 }", "variable-case-variants", 0),
    ("& { $item = 1\n$ITEM = 2 }", "variable-case-variants", 1),
    ("$item = 1\n. { $ITEM = 2 }", "variable-case-variants", 1),
    ("$item = 1\n1 | ForEach-Object { $ITEM = 2 }", "variable-case-variants", 1),
    ("$script:item = 1\n$ITEM = 2", "variable-case-variants", 1),
    ("& { $script:item = 1\n$ITEM = 2 }", "variable-case-variants", 0),
    ("function f { & { $MyInvocation.MyCommand } }", "myinvocation-in-function", 1),
    ("& { $MyInvocation.MyCommand }", "myinvocation-in-function", 0)])
def test_a_block_run_by_the_call_operator_is_a_child_scope(text, rule, found):
    """`& { }` runs in a child scope, so its assignments neither taint nor clear the
    caller's variables and `script:` is not the script level inside it; a `. { }` block and
    the block of `ForEach-Object` run in the current scope; a block inside a function
    still counts as inside a function."""
    assert sum(name == rule for name, _line, _col in _found(text)) == found


@pytest.mark.parametrize("text, rule, found", [
    ("function Outer { function build {} }\nbuild 2>&1", "native-stderr-merged", 1),
    ("function Outer { function build {} }\nfunction Other { build 2>&1 }", "native-stderr-merged", 1),
    ("function Outer { function build {} }\n& { build 2>&1 }", "native-stderr-merged", 1),
    ("function Outer { function build {} }\n& 'build' 2>&1", "native-stderr-merged", 1),
    ("function Outer { function local:build {} }\nbuild 2>&1", "native-stderr-merged", 1),
    ("& { function build {} }\nbuild 2>&1", "native-stderr-merged", 1),
    ("build 2>&1\nfunction build {}", "native-stderr-merged", 1),
    ("function Outer { build 2>&1\nfunction build {} }", "native-stderr-merged", 1),
    ("& { build 2>&1 }\nfunction build {}", "native-stderr-merged", 1),
    ("function Outer { function build {}\n& { build 2>&1 } }", "native-stderr-merged", 0),
    ("function build {}\nbuild 2>&1\nfunction build {}", "native-stderr-merged", 0),
    ("function build {}\nbuild 2>&1", "native-stderr-merged", 0),
    ("function build {}\n& 'build' 2>&1", "native-stderr-merged", 0),
    ("function Outer { function build {}\nbuild 2>&1 }", "native-stderr-merged", 0),
    ("function Outer { function build {}\nfunction Inner { build 2>&1 } }", "native-stderr-merged", 0),
    ("function A { build 2>&1 }\nfunction build {}", "native-stderr-merged", 0),
    (". { function build {} }\nbuild 2>&1", "native-stderr-merged", 0),
    ("1 | ForEach-Object { function build {} }\nbuild 2>&1", "native-stderr-merged", 0),
    ("function Outer { function global:build {} }\nbuild 2>&1", "native-stderr-merged", 0),
    ("function Outer { function script:build {} }\nbuild 2>&1", "native-stderr-merged", 0),
    ("function Outer { function ls {} }", "function-named-like-alias", 1),
    ("function ls {}", "function-named-like-alias", 1)])
def test_a_function_is_visible_where_it_is_defined(text, rule, found):
    """A function is visible in the unit that defines it, after its definition, and in
    the units nested inside; not in its parent, a sibling or after a `& { }` block; a
    `global:` or `script:` name is visible everywhere; a definition, wherever it is, still
    loses to a default alias."""
    assert sum(name == rule for name, _line, _col in _found(text)) == found


# -- fail-closed inputs --------------------------------------------------------

_UNREADABLE = ["missing", "read-error"] + (["no-permission", "unreadable-directory"]
                                           if _UNPRIVILEGED else [])


@pytest.mark.parametrize("case", _UNREADABLE)
def test_missing_or_unreadable_input_refuses(case, tmp_path, monkeypatch):
    """A path that is absent or cannot be read refuses the run; it is never clean."""
    target = _write(tmp_path / "in" / "sample.ps1", b"Write-Output 'fine'\n")
    argument = target
    if case == "missing":
        argument = tmp_path / "absent.ps1"
    elif case == "read-error":
        real_open = Path.open

        def failing_open(self, *args, **kwargs):
            if self == target:
                raise PermissionError("denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", failing_open)
    elif case == "no-permission":
        target.chmod(0)
    else:  # a file in a directory that cannot be searched cannot be examined
        target.parent.chmod(0)
    try:
        report = ps51_lint.lint_paths([str(argument)])
    finally:
        target.parent.chmod(stat.S_IRWXU)
        target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert report.verdict == "refused"
    assert all(entry["status"] == "refused" for entry in report.files) and report.files
    assert case != "missing" or report.files[0]["refusal"] == "the path does not exist"


#: Each input with the words of the refusal its own check gives: a UTF-32 file
#: must be refused as UTF-32, not later for the NUL its bytes also hold.
_UNDECODABLE = {
    "unmarked-high-byte": (b"Write-Output 'caf\xe9'\n", "above 0x7F"),
    "utf8-mark-invalid-bytes": (b"\xef\xbb\xbfWrite-Output '\xff'\n", "marked utf-8"),
    "utf16le-odd-length": (b"\xff\xfe" + "Write-Output 1\n".encode("utf-16-le") + b"\x41",
                           "marked utf-16-le"),
    "utf16le-unpaired-surrogate": (b"\xff\xfe" + b"\x00\xd8" + "x\n".encode("utf-16-le"),
                                   "marked utf-16-le"),
    "utf16be-unpaired-surrogate": (b"\xfe\xff" + b"\xdc\x00" + "x\n".encode("utf-16-be"),
                                   "marked utf-16-be"),
    "utf32le-mark": (b"\xff\xfe\x00\x00" + "x\n".encode("utf-32-le"), "UTF-32"),
    "utf32be-mark": (b"\x00\x00\xfe\xff" + "x\n".encode("utf-32-be"), "UTF-32"),
    "nul-in-ascii": (b"Write-Output 1\x00\n", "NUL"),
    "nul-in-utf16": (b"\xff\xfe" + "Write-Output 1\x00\n".encode("utf-16-le"), "NUL"),
}


@pytest.mark.parametrize("case", sorted(_UNDECODABLE))
def test_undecodable_input_refuses(case, tmp_path):
    """Bytes whose decoding no byte-order mark fixes, or that decode to a NUL,
    refuse for their own stated reason: the decoder and the file-level report
    both say so."""
    data, reason = _UNDECODABLE[case]
    with pytest.raises(ps51_lint.LintRefusal, match=re.escape(reason)):
        ps51_lint.decode_source(data)
    report = ps51_lint.lint_paths([str(_write(tmp_path / "sample.ps1", data))])
    assert report.verdict == "refused" and reason in report.files[0]["refusal"]


def test_a_lenient_decoder_would_accept_what_is_refused(tmp_path, monkeypatch):
    """The strict decoder is what refuses those inputs: replaced by a lenient one,
    every one of them is accepted instead."""
    paths = [_write(tmp_path / f"{name}.ps1", data)
             for name, (data, _reason) in sorted(_UNDECODABLE.items())]
    assert [_verdict([p]) for p in paths] == ["refused"] * len(paths)

    def lenient(data: bytes):
        return data.decode("latin-1").replace("\x00", ""), "lenient"

    monkeypatch.setattr(ps51_lint, "decode_source", lenient)
    assert "refused" not in [_verdict([p]) for p in paths]


_MALFORMED = {
    "unterminated-single-quote": "Write-Output 'abc\n",
    "unterminated-double-quote": 'Write-Output "abc\n',
    "unterminated-here-string": "$a = @'\nbody\n",
    "text-after-here-string-header": "$a = @'x\nbody\n'@\n",
    "unterminated-block-comment": "<# never closed\n$a = 1\n",
    "unterminated-subexpression": 'Write-Output "a $(b"\n',
    "unterminated-braced-variable": "Write-Output ${abc\n",
    "extra-closing-parenthesis": "Write-Output (1))\n",
    "unclosed-brace": "if ($a) {\n",
    "mismatched-bracket": "$a = @(1]\n",
    "lone-at-sign": "Write-Output a @\n",
    "colon-then-space-in-code": "Write-Output $user: home\n",
    "colon-then-space-in-a-string": 'Write-Output "$user: home"\n',
    "deep-subexpressions-in-strings": '"$(' * 400 + ')"' * 400 + "\n",
    "deep-parentheses": "$a = " + "(" * 600 + "1" + ")" * 600 + "\n",
    "double-ampersand": "Get-Sample && Get-Other\n",
    "double-pipe": "Get-Sample || Get-Other\n",
    "reserved-less-than": "$a = 1 < 2\n",
    "ampersand-inside-a-command": "Write-Output a2>&1\n",
    "backtick-at-the-end": "Write-Output a`",
}


@pytest.mark.parametrize("case", sorted(_MALFORMED))
def test_malformed_source_refuses(case, tmp_path):
    """Source the lexer cannot tokenize refuses, directly and as a file."""
    text = _MALFORMED[case]
    with pytest.raises(ps51_lint.LintRefusal):
        ps51_lint.lint_text(text)
    data = text.encode("ascii") if text.isascii() else b"\xef\xbb\xbf" + text.encode("utf-8")
    assert _verdict([_write(tmp_path / "sample.ps1", data)]) == "refused"


@pytest.mark.parametrize("case", ["no-path", "a-directory-beside-a-script"])
def test_an_empty_input_set_refuses(case, tmp_path):
    """No path refuses: an empty set is never a clean result. A named directory,
    which yields no script, refuses beside one that does, so the run refuses."""
    script = _write(tmp_path / "ok" / "sample.ps1", b"Write-Output 'fine'\n")
    empty = tmp_path / "empty"
    empty.mkdir()
    arguments = {"no-path": [], "a-directory-beside-a-script": [empty, script]}[case]
    assert _verdict(arguments) == "refused"
    if case == "no-path":
        assert _run(cwd=tmp_path).returncode == 2


def test_without_the_empty_set_check_an_empty_invocation_passes(monkeypatch):
    """The empty-set check is load-bearing: removed, naming nothing reads as clean."""
    assert _verdict([]) == "refused"
    monkeypatch.setattr(ps51_lint, "paths_given", lambda paths: True)
    assert _verdict([]) == "clean"


_INPUT_SHAPES = ["other-suffix", "psd1-data-file", "oversize", "grows-after-examination",
                 "too-many-files", "a-directory"] + (
    ["link-argument", "special-file-argument"] if _POSIX else [])


_SHAPE_REASONS = {"other-suffix": "not a .ps1", "psd1-data-file": "not a .ps1",
                  "oversize": "larger than", "grows-after-examination": "larger than",
                  "too-many-files": "more than 2 files", "a-directory": "a directory is not linted",
                  "link-argument": "is a link", "special-file-argument": "special file"}


@pytest.mark.parametrize("case", _INPUT_SHAPES)
def test_links_special_files_other_suffixes_and_oversize_refuse(case, tmp_path, monkeypatch):
    """A link (never followed), a special file, another suffix, an oversized file
    (one that grows after it is examined too), a directory and too many names
    refuse, each for its own stated reason: no named input is skipped silently,
    and the count is refused before any file is examined."""
    folder = tmp_path / "in"
    script = _write(folder / "sample.ps1", b"Write-Output 'fine'\n")
    arguments = [script]
    if case == "other-suffix":
        arguments = [_write(tmp_path / "sample.txt", b"Write-Output 'fine'\n")]
    elif case == "psd1-data-file":
        arguments = [_write(tmp_path / "sample.psd1", b"@{ Name = 'fine' }\n")]
    elif case == "oversize":
        monkeypatch.setattr(ps51_lint, "MAX_FILE_BYTES", 8)
    elif case == "grows-after-examination":
        # Small when examined, larger when read: only the check after reading sees it.
        monkeypatch.setattr(ps51_lint, "MAX_FILE_BYTES", 64)
        real_open = Path.open
        monkeypatch.setattr(Path, "open", lambda self, *args, **kwargs: io.BytesIO(b"#" * 100)
                            if self == script else real_open(self, *args, **kwargs))
    elif case == "too-many-files":
        arguments += [_write(folder / name, b"Write-Output 'fine'\n")
                      for name in ("second.ps1", "third.ps1")]
        monkeypatch.setattr(ps51_lint, "MAX_FILES", 2)
        monkeypatch.setattr(ps51_lint, "_collect", lambda argument: 1 / 0)
    elif case == "a-directory":
        arguments = [folder]
    elif case == "link-argument":
        arguments = [tmp_path / "link.ps1"]
        arguments[0].symlink_to(script)
    else:
        arguments = [folder / "pipe.ps1"]
        os.mkfifo(arguments[0])
    report = ps51_lint.lint_paths([str(argument) for argument in arguments])
    reasons = [report.refusal] + [entry["refusal"] for entry in report.files]
    assert report.verdict == "refused" and any(_SHAPE_REASONS[case] in str(r) for r in reasons), (
        reasons)


@pytest.mark.parametrize("case", ["a-hard-link-pair", "two-spellings-of-one-file",
                                  "a-refused-argument-beside-a-linted-one"])
def test_every_named_file_has_exactly_one_entry(case, tmp_path):
    """Each distinct argument gets exactly one entry under the name it was given:
    none dropped, none merged and none implied. Two names of one file (a hard
    link) and two spellings of one path are two arguments, each linted; a
    refused argument beside a linted one keeps both entries."""
    first = _write(tmp_path / "in" / "k.ps1", b"$code = [int]$LASTEXITCODE\n")
    second = {"a-hard-link-pair": str(tmp_path / "in" / "second.ps1"),
              "two-spellings-of-one-file": str(tmp_path / "in") + "/./k.ps1",
              "a-refused-argument-beside-a-linted-one": str(tmp_path / "absent.ps1")}[case]
    if case == "a-hard-link-pair":
        os.link(first, second)
    report = ps51_lint.lint_paths([str(first), second])
    assert sorted(entry["path"] for entry in report.files) == sorted([str(first), second])
    linted = [entry["status"] for entry in report.files].count("linted")
    assert (linted, len(report.findings)) == ((1, 1) if "refused" in case else (2, 2)), (
        report.as_dict())


def test_one_refused_file_refuses_the_run(tmp_path):
    """A single refused file makes the run refused (exit 2) whatever the others
    hold, and the findings of the other files are still reported."""
    names = ["in/a-clean.ps1", "in/b-finding.ps1", "in/c-refused.ps1"]
    for name, data in zip(names, (b"Write-Output 'fine'\n", b"$code = [int]$LASTEXITCODE\n",
                                  b"Write-Output 'caf\xe9'\n")):
        _write(tmp_path / name, data)
    report = ps51_lint.lint_paths([str(tmp_path / name) for name in names])
    assert report.verdict == "refused"
    assert [f["rule"] for f in report.findings] == ["exit-code-null-cast"]
    assert _run(*names, cwd=tmp_path).returncode == 2


def test_an_exception_inside_a_rule_refuses_the_file(tmp_path, monkeypatch):
    """A rule that raises refuses its file; it is never read as zero findings."""
    path = _write(tmp_path / "sample.ps1", b"Write-Output 'fine'\n")
    assert _verdict([path]) == "clean"

    def broken(analysis):
        raise KeyError("a rule defect")

    monkeypatch.setattr(ps51_lint, "RULES", ps51_lint.RULES + (("broken-rule", broken),))
    with pytest.raises(ps51_lint.LintRefusal, match="broken-rule"):
        ps51_lint.lint_text("Write-Output 'fine'\n")
    assert _verdict([path]) == "refused"


# -- bounded cost -------------------------------------------------------------------


def _cost(text: str) -> float:
    """The best of three timings of one lint, with the garbage collector paused."""
    gc.collect()
    gc.disable()
    try:
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            ps51_lint.lint_text(text)
            best = min(best, time.perf_counter() - start)
        return best
    finally:
        gc.enable()


#: Shapes that once cost quadratic time: a pattern that backtracked over every
#: `-c`, a copy of the rest of the element for every `-a`, a clause chain copied
#: again at every join, strings and here-strings nested in subexpressions each
#: copied at every level, and nested assignments whose right sides were each
#: scanned to the bottom. Each `n` makes the small lint cost tens of milliseconds,
#: well above timer and scheduler noise, while the quadratic cost already dominated.
_SCALING = {
    "argument-list-of-dash-c": (60000, lambda n: "Start-Process pwsh -ArgumentList '"
                                + "-c " * n + "'\n"),
    "dash-a-run": (8000, lambda n: "Start-Process x " + "-a " * n + "\n"),
    "elseif-chain": (4000, lambda n: "if ($a) {}\n" + "elseif ($b) {}\n" * n),
    "nested-strings": (30000, lambda n: '"$(' * (n // 1000) + '"' + "x" * (4 * n) + '"'
                       + ')"' * (n // 1000) + "\n"),
    "nested-here-strings": (30000, lambda n: '@"\n$(\n' * (n // 1000) + '@"\n' + "x" * (4 * n)
                            + '\n"@\n' + ')\n"@\n' * (n // 1000)),
    "nested-assignments": (2500, lambda n: "$v = @(" * (n // 50) + "x " * (4 * n)
                           + ")" * (n // 50) + "\n"),
    "nested-argument-assignments": (2500, lambda n: "$p.Arguments = @(" * (n // 50)
                                    + "x " * (4 * n) + ")" * (n // 50) + "\n"),
}


@pytest.mark.parametrize("shape", sorted(_SCALING))
def test_the_cost_grows_linearly_with_the_input(shape):
    """Four times the input costs well under eight times as much, where a
    quadratic cost would be sixteen times: a file within the size bound is
    answered in bounded time, never effectively hung."""
    n, build = _SCALING[shape]
    small, large = _cost(build(n)), _cost(build(4 * n))
    assert large < 8 * small, f"{shape}: {small:.4f}s, then {large:.4f}s for four times the input"


# -- the entrypoint, determinism and no authority ---------------------------------


@pytest.mark.parametrize(("case", "code", "verdict"), [("clean", 0, "clean"),
                                                        ("findings", 1, "findings"),
                                                        ("refused", 2, "refused")])
def test_the_entrypoint_exit_codes_name_the_verdict(case, code, verdict, tmp_path):
    """The real entrypoint exits 0, 1 or 2, its JSON report names the same
    verdict, and what it prints ends its lines in LF alone on every platform."""
    data = {"clean": b"Write-Output 'fine'\n", "findings": b"$code = [int]$LASTEXITCODE\n",
            "refused": b"Write-Output 'caf\xe9'\n"}[case]
    _write(tmp_path / "sample.ps1", data)
    done = _run("sample.ps1", cwd=tmp_path)
    report = json.loads(done.stdout.decode("ascii"))
    assert (done.returncode, report["verdict"]) == (code, verdict)
    assert done.stderr.decode("ascii").startswith("REFUSE: ") == (code == 2)
    assert b"\r" not in done.stdout + done.stderr


@pytest.mark.parametrize("arguments", [(), ("--list-rules",), ("-h",), ("--help",),
                                       ("--format", "text", "sample.ps1"),
                                       ("sample.ps1", "--he"), ("-",), ("-x.ps1",)])
def test_an_option_is_refused_and_nothing_is_judged(arguments, tmp_path):
    """No option exists: no argument, or any argument starting with '-', exits 2
    with one REFUSE usage line and judges nothing, so exit 0 comes only from a
    judged clean report. A file whose name starts with '-' is named as ./-x.ps1."""
    for name in ("sample.ps1", "-x.ps1"):
        _write(tmp_path / name, b"Write-Output 'fine'\n")
    done = _run(*arguments, cwd=tmp_path)
    assert (done.returncode, done.stdout) == (2, b""), done.stderr
    assert done.stderr.startswith(b"REFUSE: usage: ") and done.stderr.count(b"\n") == 1
    judged = _run("./-x.ps1", cwd=tmp_path)
    assert judged.returncode == 0 and json.loads(judged.stdout)["verdict"] == "clean"


def test_the_report_is_byte_identical_across_runs_and_orders(tmp_path):
    """Two runs, with the path arguments in different orders, print the same bytes."""
    names = ["copies/" + path.name.replace(".ps1.txt", ".ps1") for path in _specimens()[:6]]
    for name, path in zip(names, _specimens()):
        _write(tmp_path / name, path.read_bytes())
    _write(tmp_path / "loose.ps1", b"Write-Output $x\n")
    first = _run(*names, "loose.ps1", cwd=tmp_path)
    second = _run("loose.ps1", *reversed(names), cwd=tmp_path)
    assert first.returncode == 1 and first.stdout == second.stdout
    assert b"copies/" in first.stdout and str(tmp_path).encode() not in first.stdout


def test_the_linter_writes_nothing(tmp_path):
    """A run over every specimen leaves each file, and the directory it runs in,
    byte-identical, and creates nothing."""
    names = ["copies/" + path.name.replace(".ps1.txt", ".ps1") for path in _specimens()]
    for name, path in zip(names, _specimens()):
        _write(tmp_path / name, path.read_bytes())

    def snapshot():
        return {p.relative_to(tmp_path).as_posix(): p.read_bytes() if p.is_file() else None
                for p in sorted(tmp_path.rglob("*"))}

    before = snapshot()
    assert _run(*names, cwd=tmp_path).returncode == 1
    assert snapshot() == before


#: Every module the linter may import. An allow-list, so a module that could
#: start a process, open a connection or write a file (`tempfile`, `io`,
#: `logging`, `os` and the rest) cannot be imported unseen.
_ALLOWED_IMPORTS = {"__future__", "bisect", "dataclasses", "hashlib", "json",
                    "pathlib", "re", "stat", "sys", "unicodedata"}


#: Calls that write, move, link or remove a file. `replace` is not listed:
#: `str.replace` is the linter's own text operation and a name cannot tell them apart.
_WRITING_CALLS = {"write_text", "write_bytes", "mkdir", "unlink", "touch", "rename", "rmdir",
                  "symlink_to", "hardlink_to", "chmod"}


def _opens_for_writing(node: ast.Call) -> bool:
    """A builtin `open` or an `.open` whose mode is not a literal read-only mode."""
    if isinstance(node.func, ast.Name) and node.func.id == "open":
        mode = node.args[1] if len(node.args) > 1 else None
    elif isinstance(node.func, ast.Attribute) and node.func.attr == "open":
        mode = node.args[0] if node.args else None
    else:
        return False
    mode = next((keyword.value for keyword in node.keywords if keyword.arg == "mode"), mode)
    return mode is not None and not (isinstance(mode, ast.Constant) and isinstance(
        mode.value, str) and not set(mode.value) & set("wax+"))


def test_the_linter_imports_no_process_or_network_module():
    """A lint over the linter's own syntax tree: it imports only the allowed
    modules, none of which starts a process, opens a connection or writes a
    file by itself; it makes no call that writes, moves, links or removes a file
    (`replace` aside, see `_WRITING_CALLS`); and it opens nothing for writing."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    roots = {alias.name.split(".")[0] for node in ast.walk(tree)
             if isinstance(node, ast.Import) for alias in node.names}
    roots |= {node.module.split(".")[0] for node in ast.walk(tree)
              if isinstance(node, ast.ImportFrom) and node.module}
    assert roots and roots <= _ALLOWED_IMPORTS, roots - _ALLOWED_IMPORTS
    writers = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr in _WRITING_CALLS)
        or _opens_for_writing(node))]
    assert writers == []


def test_the_alias_table_is_sorted_unique_and_lower_case():
    """The embedded default-alias table has the measured shape: 153 names,
    sorted, unique and lower-case (its contents are a measurement, not a test)."""
    names = ps51_lint.DEFAULT_ALIAS_NAMES
    assert len(names) == 153 and list(names) == sorted(set(names))
    assert all(name == name.lower() for name in names)
    assert ps51_lint.DEFAULT_ALIASES == frozenset(names)
