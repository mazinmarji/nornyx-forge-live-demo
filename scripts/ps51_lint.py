"""Report token patterns that carry known Windows PowerShell 5.1 defect classes.

WHAT IT DOES. Each `.ps1` or `.psm1` file named on the command line is decoded,
tokenized by a hand-written lexer and checked by sixteen rules (`RULES`) for token
patterns that are known carriers of scripting defects: one variable spelled in two
letter cases, an exit code cast to `[int]`, a query whose errors are silenced, and
so on. A finding is a pattern, not a verdict that the code is wrong in context. No
rule claims completeness; each rule's docstring states what it misses.

WHAT IT JUDGES: exactly the files it is named, each distinct argument once, in
sorted order. Nothing is walked and nothing is merged: two spellings or two
hard-linked names of one file give two entries. How the operating system resolves
a named path, links above it included, is the operating system's affair. A name is
examined, then opened by path: if another process swaps it between the two, the
linter reads what the name then leads to, through a link, or waits on a FIFO.

FAIL-CLOSED. These are REFUSED, never reported as clean: no path, or more than
`MAX_FILES` names; a missing, unexaminable, unreadable, special or oversized input, a
directory, a link (not followed when examined) or another suffix; bytes whose decoding no
byte-order mark fixes (Windows PowerShell 5.1 reads an unmarked script in the ANSI
code page, which this linter cannot know); a control or format character anywhere
but TAB, LF and CR, which `tokenize` refuses before it lexes; malformed source; an
exception inside a rule. One refused file makes the run `refused`, and the report
still lists the other files' findings. No pass copies the rest of a sequence
inside a loop, and no string is sliced or unescaped once per level it is nested in;
the cost test measures linear growth for the shapes it names, and no other is claimed.

THE LEXER follows forms measured against the engine's own tokenizer on Windows
PowerShell 5.1 with synthetic snippets: comments, the quote kinds, here-string
headers and terminators, stop-parsing, variables and qualifiers, dashes, numbers,
redirections, whitespace, and where a command argument ends. Other forms may
tokenize differently. Where the engine reads a control character (it splits tokens
at a form feed or vertical tab, and keeps U+0085 inside a comment), the linter
refuses it. Code inside a `$( )` subexpression of an expandable string is scanned
only to find where the string ends; no rule checks it.

WHAT IT DOES NOT DO. It never runs PowerShell; resolves types, data flow,
dot-sourced files, modules or the ambient session; walks a directory or follows,
when it examines it, a link it is named; reads a configuration, rule selection,
suppression or baseline; writes a file; starts a process; uses the network; lints
`.psd1` data; or fixes code. It holds no authority: a person or a pipeline decides
what a finding means.

USAGE: `ps51_lint.py FILE [FILE ...]`, with no option: no argument, or any argument
starting with `-`, is a usage error (name `-x.ps1` as `./-x.ps1`). The output is a
JSON report (schema `nornyx.forge.ps51_lint_report.v1`) in LF lines on every
platform. Exit codes: 0 clean, 1 findings, 2 refused, usage errors included; a
refusal prints one `REFUSE:` line.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "nornyx.forge.ps51_lint_report.v1"
MAX_FILES = 10_000
MAX_FILE_BYTES = 4 * 1024 * 1024
SUFFIXES = (".ps1", ".psm1")

#: The alias names of a default Windows PowerShell 5.1 session, measured with
#: `Get-Alias` in a `-NoProfile` session: sorted, unique and lower-case. Other
#: builds, profiles and modules can add or remove aliases.
DEFAULT_ALIAS_NAMES = (
    "%", "?", "ac", "asnp", "cat", "cd", "cfs", "chdir", "clc", "clear", "clhy", "cli", "clp",
    "cls", "clv", "cnsn", "compare", "copy", "cp", "cpi", "cpp", "curl", "cvpa", "dbp", "del",
    "diff", "dir", "dnsn", "ebp", "echo", "epal", "epcsv", "epsn", "erase", "etsn", "exsn", "fc",
    "fhx", "fl", "foreach", "ft", "fw", "gal", "gbp", "gc", "gci", "gcm", "gcs", "gdr", "ghy", "gi",
    "gjb", "gl", "gm", "gmo", "gp", "gps", "gpv", "group", "gsn", "gsnp", "gsv", "gu", "gv", "gwmi",
    "h", "history", "icm", "iex", "ihy", "ii", "ipal", "ipcsv", "ipmo", "ipsn", "irm", "ise",
    "iwmi", "iwr", "kill", "lp", "ls", "man", "md", "measure", "mi", "mount", "move", "mp", "mv",
    "nal", "ndr", "ni", "nmo", "npssc", "nsn", "nv", "ogv", "oh", "popd", "ps", "pushd", "pwd", "r",
    "rbp", "rcjb", "rcsn", "rd", "rdr", "ren", "ri", "rjb", "rm", "rmdir", "rmo", "rni", "rnp",
    "rp", "rsn", "rsnp", "rujb", "rv", "rvpa", "rwmi", "sajb", "sal", "saps", "sasv", "sbp", "sc",
    "select", "set", "shcm", "si", "sl", "sleep", "sls", "sort", "sp", "spjb", "spps", "spsv",
    "start", "sujb", "sv", "swmi", "tee", "trcm", "type", "wget", "where", "wjb", "write",
)
DEFAULT_ALIASES = frozenset(DEFAULT_ALIAS_NAMES)


class LintRefusal(Exception):
    """An input the linter cannot judge. It is never read as "nothing found"."""


# -- decoding ----------------------------------------------------------------


def decode_source(data: bytes) -> tuple:
    """(text, encoding) of script bytes, refusing every input whose decoding is not fixed.

    UTF-32 marks are tested first because they share a prefix with UTF-16's.
    Without a mark only ASCII is accepted: PowerShell 5.1 would read any other
    byte in the machine's ANSI code page, so the text it runs is unknowable here.
    """
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        raise LintRefusal("the file starts with a UTF-32 byte-order mark, which is not accepted")
    marks = ((b"\xef\xbb\xbf", "utf-8", "utf-8-bom"), (b"\xff\xfe", "utf-16-le", "utf-16-le-bom"),
             (b"\xfe\xff", "utf-16-be", "utf-16-be-bom"))
    for mark, codec, encoding in marks:
        if data.startswith(mark):
            try:
                text = data[len(mark):].decode(codec)
            except UnicodeDecodeError as exc:
                raise LintRefusal(f"the file is marked {codec} but its bytes are not valid "
                                  f"{codec} ({exc.reason})") from exc
            break
    else:
        if not data.isascii():
            raise LintRefusal("the file has no byte-order mark and holds a byte above 0x7F; "
                              "Windows PowerShell 5.1 would decode it in the ANSI code page, "
                              "so its tokens cannot be determined")
        text, encoding = data.decode("ascii"), "ascii"
    if "\x00" in text:
        raise LintRefusal("the decoded source holds a NUL character")
    return text, encoding


# -- lexer -------------------------------------------------------------------

_SINGLE_QUOTES = "'" + "".join(map(chr, (0x2018, 0x2019, 0x201A, 0x201B)))
_DOUBLE_QUOTES = '"' + "".join(map(chr, (0x201C, 0x201D, 0x201E)))
_DASHES = "-" + "".join(map(chr, (0x2013, 0x2014, 0x2015)))
#: Whitespace in code; measured: every space and line or paragraph separator splits like ' '.
_SPACES = " \t" + "".join(map(chr, (0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028,
                                      0x2029, 0x202F, 0x205F, 0x3000)))
_LINE_ENDS = "\r\n"
_ENDS_ARGUMENT = _SPACES + _LINE_ENDS + "{}();,|&"
_END = "\x00"  # never in decoded text: NUL is refused before lexing
_ESCAPES = dict(zip("0abfnrtv", "\x00\x07\x08\x0c\n\r\t\x0b"))
_NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F]+|(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)"
                     r"[dDlL]?(?:[kKmMgGtTpP][bB])?")
_VARIABLE = re.compile(r"[\w?]+(?::[\w?]+)*")
_BRACED = re.compile(r"([\w?]+):(?!:)(.*)", re.S)
_LINE_END = re.compile(r"[\r\n]")
_KEYWORDS = frozenset((
    "begin", "break", "catch", "class", "configuration", "continue", "data", "define",
    "do", "dynamicparam", "else", "elseif", "end", "enum", "exit", "filter", "finally",
    "for", "foreach", "from", "function", "hidden", "if", "in", "inlinescript",
    "parallel", "param", "process", "return", "sequence", "static", "switch",
    "throw", "trap", "try", "until", "using", "var", "while", "workflow",
))


@dataclass(frozen=True)
class Token:
    """One token; `line` and `column` are 1-based and columns count code points.

    A string token carries the variable references of its expandable text in
    `refs` (tokens with `in_string` set); a subexpression's contents are not kept.
    `command` marks where the lexer saw a command start: its name, or `&` or a
    dot-sourcing `.` -- the one notion of command position the rules read.
    """

    kind: str
    text: str
    start: int
    end: int
    line: int
    column: int
    value: str = ""
    qualifier: str = ""
    braced: bool = False
    in_string: bool = False
    refs: tuple = ()
    command: bool = False


def _is_name_char(char: str) -> bool:
    return char.isalnum() or char in "_?"


def _unescape(body: str, quotes: str, backtick: bool) -> str:
    out, index = [], 0
    while index < len(body):
        char = body[index]
        if backtick and char == "`" and index + 1 < len(body):
            out.append(_ESCAPES.get(body[index + 1], body[index + 1]))
            index += 2
            continue
        out.append(char)
        doubled = char in quotes and index + 1 < len(body) and body[index + 1] in quotes
        index += 2 if doubled else 1
    return "".join(out)


class _Frame:
    """One bracket level: where a pipeline element starts, whether the tokens
    read are a command's arguments, and whether a hashtable or attribute key
    is expected."""

    __slots__ = ("kind", "start", "command", "key")

    def __init__(self, kind: str) -> None:
        self.kind, self.start, self.command = kind, kind != "bracket", False
        self.key = kind in ("hash", "attr")

    def reset(self) -> None:
        self.start, self.command, self.key = True, False, self.kind in ("hash", "attr")

    def value(self) -> None:
        self.start, self.command, self.key = True, False, False

    def operand(self) -> None:
        if self.start:
            self.start = self.command = False


class _Lexer:
    def __init__(self, text: str) -> None:
        self.text, self.n, self.tokens = text, len(text), []
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\r\n|\r|\n", text)]

    def _c(self, index: int) -> str:
        return self.text[index] if index < self.n else _END

    def _make(self, kind: str, start: int, end: int, **fields) -> Token:
        """A token whose value is its text unless given; only emitted tokens are sliced.
        A braced name splits its scope off like `$scope:name`: `${scope:name}`."""
        line, text = bisect.bisect_right(self.line_starts, start), self.text[start:end]
        if fields.get("braced") and (found := _BRACED.fullmatch(fields["value"])):
            fields.update(qualifier=found[1].lower(), value=found[2])
        return Token(kind, text, start, end, line, start - self.line_starts[line - 1] + 1,
                     **{"value": text, **fields})

    def _emit(self, emit: bool, kind: str, start: int, end: int, **fields) -> None:
        if emit:
            self.tokens.append(self._make(kind, start, end, **fields))

    def run(self) -> list:
        frames = [_Frame("script")]
        self._scan(0, frames, True)
        if len(frames) != 1:
            raise LintRefusal("a bracket is opened and never closed")
        return self.tokens

    def _scan(self, pos: int, frames: list, emit: bool) -> int:
        """Scan code until the text ends or the outermost frame is closed."""
        operand_ends_at = -1
        while pos < self.n and frames:
            char = self.text[pos]
            if char in _SPACES:
                pos += 1
            elif char in _LINE_ENDS:
                end = pos + 2 if self.text.startswith("\r\n", pos) else pos + 1
                self._emit(emit, "newline", pos, end)
                frames[-1].reset()
                pos = end
            else:
                end, operand = self._token(pos, frames, emit, operand_ends_at == pos)
                operand_ends_at, pos = (end if operand else -1), end
        return pos

    def _token(self, pos: int, frames: list, emit: bool, after_operand: bool):
        text, frame = self.text, frames[-1]
        char, nxt = text[pos], self._c(pos + 1)
        if char == "#":
            found = _LINE_END.search(text, pos)
            end = found.start() if found else self.n
            self._emit(emit, "comment", pos, end)
            return end, False
        if char == "<":
            close = text.find("#>", pos + 2) if nxt == "#" else -2
            if close == -2:
                raise LintRefusal("a '<' starting a token is reserved in Windows PowerShell 5.1")
            if close < 0:
                raise LintRefusal("a block comment is never closed")
            self._emit(emit, "comment", pos, close + 2)
            return close + 2, False
        if char == "`" and nxt in _LINE_ENDS:
            return pos + (3 if text.startswith("\r\n", pos + 1) else 2), False
        if char in _SINGLE_QUOTES or char in _DOUBLE_QUOTES:
            double = char in _DOUBLE_QUOTES
            refs: list = []
            end = self._double_end(pos, refs) if double else self._single_end(pos)
            if emit:
                self._emit(emit, "string", pos, end, refs=tuple(refs), value=_unescape(
                    text[pos + 1:end - 1], _DOUBLE_QUOTES if double else _SINGLE_QUOTES, double))
            frame.operand()
            return end, True
        if char == "@":
            return self._at(pos, frames, emit)
        if char == "$":
            return self._dollar(pos, frames, emit)
        if char in _DASHES:
            return self._dash(pos, frame, emit, after_operand)
        if (char in "123456*" and nxt == ">") or char == ">":
            end = pos + (0 if char == ">" else 1) + 1
            if self._c(end) == ">":
                end += 1
            elif self._c(end) == "&" and self._c(end + 1) in "12":
                end += 2
            self._emit(emit, "redirect", pos, end)
            frame.start = False
            return end, False
        if "0" <= char <= "9":
            return self._number(pos, pos, frame, emit)
        if char == ".":
            return self._dot(pos, frames, emit, after_operand)
        if char == ":" and nxt == ":" and after_operand:
            self._emit(emit, "operator", pos, pos + 2)
            return self._member(pos + 2, emit)
        if char in "({[":
            if char == "[" and frame.command and not frame.start and not after_operand:
                return self._word(pos, frames, emit), False
            self._emit(emit, "punct", pos, pos + 1)
            frame.operand()
            inside = "attr" if frame.kind == "bracket" else "paren"
            frames.append(_Frame({"(": inside, "{": "block"}.get(char, "bracket")))
            return pos + 1, False
        if char in ")}]":
            allowed = {")": ("paren", "subexpr", "array", "attr"), "}": ("block", "hash")}
            if frame.kind not in allowed.get(char, ("bracket",)):
                raise LintRefusal(f"a closing '{char}' does not match an open bracket")
            frames.pop()
            self._emit(emit, "punct", pos, pos + 1)
            return pos + 1, char != "}"
        if char in ";,|&":
            if char in "|&" and nxt == char:
                raise LintRefusal(f"'{char}{char}' is not a statement separator in "
                                  "Windows PowerShell 5.1")
            if char == "&" and not frame.start:
                raise LintRefusal("an ampersand appears where no command starts")
            self._emit(emit, "punct", pos, pos + 1, command=char == "&")
            if char == ";" or (char == "," and frame.kind == "attr"):
                frame.reset()
            elif char == ",":
                frame.start = False
            else:
                frame.start, frame.command = char == "|", char == "&"
            return pos + 1, False
        if frame.command and not frame.start or char not in "=+*/%!":
            return self._word(pos, frames, emit), False
        if char == "=" or (nxt == "=" and char in "+*/%"):
            end = pos + (1 if char == "=" else 2)
            self._emit(emit, "operator", pos, end)
            frame.value()
            return end, False
        end = pos + (2 if char == "+" and nxt == "+" else 1)
        self._emit(emit, "operator", pos, end)
        frame.operand()
        return end, False

    def _word(self, pos: int, frames: list, emit: bool) -> int:
        text, frame = self.text, frames[-1]
        if frame.kind == "bracket":
            end = pos
            while end < self.n and (text[end].isalnum() or text[end] in "_.`+"):
                end += 1
            self._emit(emit, "bareword" if end > pos else "operator", pos, max(end, pos + 1))
            return max(end, pos + 1)
        if frame.kind in ("hash", "attr") and frame.start and frame.key:
            end = pos
            while end < self.n and text[end] not in _ENDS_ARGUMENT + "=[]$#" + _SINGLE_QUOTES \
                    + _DOUBLE_QUOTES:
                end += 1
            end = max(end, pos + 1)
            self._emit(emit, "bareword", pos, end)
            frame.start = False
            return end
        end, starts = self._argument_end(pos), frame.start
        if frame.start:
            word = text[pos:end].lower()
            frame.start = frame.command = False
            if word in ("return", "throw", "exit"):
                frame.start = True
            elif word == "foreach":
                probe = end
                while probe < self.n and text[probe] in _SPACES:
                    probe += 1
                frame.command = self._c(probe) != "("
            elif word not in _KEYWORDS:
                frame.command = True
        self._emit(emit, "bareword", pos, end, command=starts and frame.command)
        return end

    def _argument_end(self, pos: int) -> int:
        """Where a command argument starting at `pos` ends. Measured: it runs on
        through '#', '<', '>', '=', '.', ':', '[', ']', '@', embedded quoted
        sections and variables, and ends at whitespace, a line end or { } ( ) ; , | &."""
        text, index = self.text, pos
        while index < self.n and text[index] not in _ENDS_ARGUMENT:
            char, nxt = text[index], self._c(index + 1)
            if char == "`":
                if nxt == _END:
                    raise LintRefusal("a backtick at the end of the source escapes nothing")
                if nxt in _LINE_ENDS:
                    break
                index += 2
            elif char in _SINGLE_QUOTES:
                index = self._single_end(index)
            elif char in _DOUBLE_QUOTES:
                index = self._double_end(index, None)
            elif char == "$" and nxt == "(":
                index = self._subexpression_end(index + 2)
            elif char == "$" and nxt == "{":
                index = self._braced_end(index + 1)
            else:
                index += 1
        return max(index, pos + 1)

    def _single_end(self, pos: int) -> int:
        index = pos + 1
        while index < self.n:
            if self.text[index] in _SINGLE_QUOTES:
                if self._c(index + 1) not in _SINGLE_QUOTES:
                    return index + 1
                index += 1
            index += 1
        raise LintRefusal("a single-quoted string is never closed")

    def _double_end(self, pos: int, refs) -> int:
        index = pos + 1
        while index < self.n:
            char = self.text[index]
            if char == "`":
                if index + 1 >= self.n:
                    break
                index += 3 if self.text.startswith("\r\n", index + 1) else 2
            elif char in _DOUBLE_QUOTES:
                if self._c(index + 1) not in _DOUBLE_QUOTES:
                    return index + 1
                index += 2
            elif char == "$":
                index = self._text_dollar(index, refs)
            else:
                index += 1
        raise LintRefusal("an expandable string is never closed")

    def _here_end(self, pos: int, double: bool, refs) -> tuple:
        text, index = self.text, pos + 2
        while index < self.n and text[index] in " \t":
            index += 1
        if index >= self.n or text[index] not in _LINE_ENDS:
            raise LintRefusal("a here-string header must be followed by a line end")
        index += 2 if text.startswith("\r\n", index) else 1
        body_start = break_at = index
        quotes, line_start = (_DOUBLE_QUOTES if double else _SINGLE_QUOTES), True
        while index < self.n:
            char = text[index]
            if line_start and char in quotes and self._c(index + 1) == "@":
                return index + 2, (body_start, max(body_start, break_at))
            line_start = char in _LINE_ENDS
            if line_start:
                break_at = index
                index += 2 if text.startswith("\r\n", index) else 1
            elif double and char == "`":
                index += 1 if self._c(index + 1) in _LINE_ENDS else 2
            elif double and char == "$":
                index = self._text_dollar(index, refs)
            else:
                index += 1
        raise LintRefusal("a here-string is never closed")

    def _text_dollar(self, pos: int, refs) -> int:
        """A '$' inside expandable text: a subexpression, a variable or a literal."""
        nxt = self._c(pos + 1)
        if nxt == "(":
            return self._subexpression_end(pos + 2)
        if nxt == "{":
            end, qualifier = self._braced_end(pos + 1), ""
            name = _unescape(self.text[pos + 2:end - 1], "", True)
        elif _is_name_char(nxt):
            end, qualifier, name = self._variable_end(pos)
        elif nxt in "$^":
            end, qualifier, name = pos + 2, "", nxt
        else:
            return pos + 1
        if refs is not None:
            refs.append(self._make("variable", pos, end, value=name, qualifier=qualifier,
                                   braced=nxt == "{", in_string=True))
        return end

    def _subexpression_end(self, pos: int) -> int:
        frames = [_Frame("subexpr")]
        end = self._scan(pos, frames, False)
        if frames:
            raise LintRefusal("a $( ) subexpression is never closed")
        return end

    def _braced_end(self, pos: int) -> int:
        """`pos` is at the '{' of '${...}'; returns the index after its '}'."""
        index = pos + 1
        while index < self.n:
            if self.text[index] == "}":
                return index + 1
            index += 2 if self.text[index] == "`" else 1
        raise LintRefusal("a braced variable name is never closed")

    def _variable_end(self, pos: int) -> tuple:
        """`$name`, `$scope:name` or `$drive:name`; '::' after a name is an operator."""
        end = _VARIABLE.match(self.text, pos + 1).end()
        if self._c(end) == ":" and self._c(end + 1) != ":":
            raise LintRefusal("a variable reference ends in ':' before a character that cannot "
                              "start a name; Windows PowerShell 5.1 rejects it")
        body = self.text[pos + 1:end]
        qualifier, colon, rest = body.partition(":")
        return (end, qualifier.lower(), rest) if colon else (end, "", body)

    def _at(self, pos: int, frames: list, emit: bool):
        text, frame, nxt = self.text, frames[-1], self._c(pos + 1)
        if nxt in _SINGLE_QUOTES or nxt in _DOUBLE_QUOTES:
            double, refs = nxt in _DOUBLE_QUOTES, []
            end, (first, last) = self._here_end(pos, double, refs)
            if emit:  # sliced and unescaped only when emitted, never once per nesting level
                self._emit(emit, "string", pos, end, refs=tuple(refs), value=_unescape(
                    text[first:last], "", True) if double else text[first:last])
            frame.operand()
            return end, True
        if nxt in "({":
            self._emit(emit, "punct", pos, pos + 2)
            frame.operand()
            frames.append(_Frame("array" if nxt == "(" else "hash"))
            return pos + 2, False
        if not _is_name_char(nxt):
            raise LintRefusal("a lone '@' is not a Windows PowerShell 5.1 token")
        end = pos + 1
        while end < self.n and _is_name_char(text[end]):
            end += 1
        if frame.command and not frame.start and self._c(end) not in _ENDS_ARGUMENT + _END:
            end = self._argument_end(pos)
            self._emit(emit, "bareword", pos, end)
        else:
            self._emit(emit, "splat", pos, end, value=text[pos + 1:end])
        return end, False

    def _dollar(self, pos: int, frames: list, emit: bool):
        frame, nxt = frames[-1], self._c(pos + 1)
        frame.operand()
        if nxt == "(":
            self._emit(emit, "punct", pos, pos + 2)
            frames.append(_Frame("subexpr"))
            return pos + 2, False
        if nxt == "{":
            end = self._braced_end(pos + 1)
            name = _unescape(self.text[pos + 2:end - 1], "", True)
            self._emit(emit, "variable", pos, end, value=name, braced=True)
        elif _is_name_char(nxt):
            end, qualifier, name = self._variable_end(pos)
            self._emit(emit, "variable", pos, end, value=name, qualifier=qualifier)
        elif nxt in "$^":
            end = pos + 2
            self._emit(emit, "variable", pos, end, value=nxt)
        else:
            end = self._argument_end(pos)
            self._emit(emit, "bareword", pos, end)
            return end, False
        return end, True

    def _dash(self, pos: int, frame: _Frame, emit: bool, after_operand: bool):
        text, nxt = self.text, self._c(pos + 1)
        in_command = frame.command and not frame.start
        if text.startswith("--%", pos) and self._c(pos + 3) in _SPACES + _LINE_ENDS + _END:
            self._emit(emit, "stopparse", pos, pos + 3)
            start = pos + 3
            while start < self.n and text[start] in _SPACES:
                start += 1
            end = start
            while end < self.n and text[end] not in "|" + _LINE_ENDS:
                end += 1
            if end > start:
                self._emit(emit, "raw", start, end)
            frame.start = False
            return end, False
        if nxt in _DASHES:
            if in_command and _is_name_char(self._c(pos + 2)):
                end = self._argument_end(pos)
                self._emit(emit, "bareword", pos, end)
                return end, False
            self._emit(emit, "operator", pos, pos + 2)
            return pos + 2, False
        if nxt == "=":
            self._emit(emit, "operator", pos, pos + 2)
            frame.value()
            return pos + 2, False
        if nxt.isalpha() or nxt in "_?":
            end = pos + 1
            while end < self.n and (_is_name_char(text[end]) or text[end] in _DASHES):
                end += 1
            name = "".join("-" if c in _DASHES else c for c in text[pos + 1:end]).lower()
            colon = self._c(end) == ":" and self._c(end + 1) != ":"
            self._emit(emit, "dash", pos, end + colon, value=name)
            frame.operand()
            return end + colon, False
        if (in_command or not after_operand) and _NUMBER.match(text, pos + 1):
            return self._number(pos, pos + 1, frame, emit)
        self._emit(emit, "operator", pos, pos + 1)
        frame.operand()
        return pos + 1, False

    def _number(self, pos: int, digits: int, frame: _Frame, emit: bool):
        index = _NUMBER.match(self.text, digits).end()
        following = self._c(index)
        in_command, starts = frame.command and not frame.start, frame.start
        frame.operand()
        if (following not in _ENDS_ARGUMENT + _END) if in_command else \
                (following.isalnum() or following == "_"):
            # A name such as `7z.exe` where a command starts is that command's name.
            end = self._argument_end(pos)
            self._emit(emit, "bareword", pos, end, command=starts)
            return end, False
        self._emit(emit, "number", pos, index)
        return index, True

    def _dot(self, pos: int, frames: list, emit: bool, after_operand: bool):
        frame, nxt = frames[-1], self._c(pos + 1)
        if after_operand and nxt != ".":
            self._emit(emit, "punct", pos, pos + 1)
            return self._member(pos + 1, emit)
        if frame.start and nxt in _SPACES + _LINE_ENDS + _END:
            self._emit(emit, "punct", pos, pos + 1, command=True)
            frame.start, frame.command = False, True
            return pos + 1, False
        if not after_operand and (frame.start or frame.command):
            return self._word(pos, frames, emit), False
        if "0" <= nxt <= "9" and not after_operand:
            return self._number(pos, pos, frame, emit)
        end = pos + (2 if nxt == "." else 1)
        self._emit(emit, "operator" if nxt == "." else "punct", pos, end)
        return end, False

    def _member(self, pos: int, emit: bool):
        end = pos
        while end < self.n and (self.text[end].isalnum() or self.text[end] == "_"):
            end += 1
        if end > pos:
            self._emit(emit, "member", pos, end)
        return end, end > pos


def tokenize(text: str) -> list:
    """Every token of `text`, comments included. Raises `LintRefusal` for
    malformed source, so an unreadable script is never mistaken for an empty one,
    and first for any control or format character but TAB, LF and CR, so no
    public entry lexes one."""
    _refuse_controls(text)
    try:
        return _Lexer(text).run()
    except RecursionError as exc:
        raise LintRefusal("the source nests deeper than the linter can follow") from exc


# -- structure ---------------------------------------------------------------

_OPENING, _CLOSING = ("(", "$(", "@(", "{", "@{", "["), (")", "}", "]")
_ASSIGNMENT = ("=", "+=", "-=", "*=", "/=", "%=")
_CONTINUING = _ASSIGNMENT + ("+", "-", "*", "/", "%", "..")
_BINARY = frozenset(
    prefix + name for prefix in ("", "i", "c")
    for name in ("eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch",
                 "contains", "notcontains", "in", "notin", "replace", "split")
) | {"and", "or", "xor", "band", "bor", "bxor", "join", "is", "isnot", "as", "f", "shl", "shr"}
_BLOCK_KEYWORDS = frozenset(("if", "elseif", "else", "foreach", "for", "while", "switch", "try",
                             "catch", "finally", "function", "filter", "do", "begin", "process",
                             "end", "trap", "until", "dynamicparam"))


@dataclass
class _Group:
    opener: Token
    items: list = field(default_factory=list)
    closer: Token | None = None


@dataclass
class _Unit:
    """One scope: the script level, a function or filter body with its parameters, or
    a script block run by `&`, which runs in a child scope (measured on Windows
    PowerShell 5.1: its assignments do not reach the caller). Not modeled: a block given
    to `Invoke-Command`, `icm` or `Start-Job` (also a child scope or another runspace)
    stays in the surrounding unit; so does a block held in a variable or a group
    (`& $block`, `& ({ })`); a child unit sees nothing of its parent's state; and
    `script:` is not the script level inside a child unit. Blocks dot-sourced with `.`,
    run by `ForEach-Object` or `Where-Object`, and the bodies of `if`, loops and `try`
    run in the current scope, and stay in its unit. A function is visible in the unit that
    declares it, from its declaration on, and in the units nested inside that unit, from
    their start when a function body lies between (its code runs when called); not in the
    parent or a sibling. `function global:` and `function script:` declare in the script
    unit. Not modeled: a callee sees its caller's functions (dynamic scope), and whether
    the declaring function was ever called."""

    kind: str
    statements: list = field(default_factory=list)
    tokens: list = field(default_factory=list)
    param_lists: list = field(default_factory=list)
    nested: bool = False  # in a function body, or a block run inside one
    parent: "_Unit | None" = None
    functions: dict = field(default_factory=dict)  # name -> where it is declared


def _is(item, kind: str, *texts: str) -> bool:
    return isinstance(item, Token) and item.kind == kind and (not texts or item.text in texts)


def _is_group(item, *openers: str) -> bool:
    return isinstance(item, _Group) and (not openers or item.opener.text in openers)


def _word_of(item) -> str:
    return item.value.lower() if _is(item, "bareword") else ""


def _head(statement: list) -> str:
    return _word_of(statement[0]) if statement else ""


def _span(item) -> tuple:
    if isinstance(item, _Group):
        return item.opener.start, item.closer.end
    return item.start, item.end


def _inner(group: _Group) -> list:
    return [item for item in group.items if not _is(item, "newline")]


def _tree(code: list) -> list:
    root: list = []
    stack, groups = [root], []
    for token in code:
        if token.kind == "punct" and token.text in _OPENING:
            groups.append(_Group(token))
            stack[-1].append(groups[-1])
            stack.append(groups[-1].items)
        elif token.kind == "punct" and token.text in _CLOSING:
            stack.pop()
            groups.pop().closer = token
        else:
            stack[-1].append(token)
    return root


def _statements(items: list) -> list:
    """Split at ';' and at line ends, except after '|', ',', an assignment or a
    binary operator; then join if/else, try/catch and do/while clauses and a
    block keyword's body on the next line, in place: a clause chain is linear."""
    statements, current = [], []
    for item in items:
        ends = _is(item, "punct", ";") or (_is(item, "newline") and current and not (
            _is(current[-1], "punct", "|", ",") or _is(current[-1], "operator", *_CONTINUING)
            or (_is(current[-1], "dash") and current[-1].value in _BINARY)))
        if ends and current:
            statements.append(current)
            current = []
        elif not (_is(item, "newline") or _is(item, "punct", ";")):
            current.append(item)
    statements += [current] if current else []
    joined: list = []
    for statement in statements:
        head, previous = _head(statement), (joined[-1] if joined else [])
        if previous and ((head in ("elseif", "else") and _head(previous) == "if")
                         or (head in ("catch", "finally") and _head(previous) == "try")
                         or (head in ("while", "until") and _head(previous) == "do")
                         or (len(statement) == 1 and _is_group(statement[0], "{")
                             and _head(previous) in _BLOCK_KEYWORDS
                             and not _is_group(previous[-1], "{"))):
            previous.extend(statement)
        else:
            joined.append(statement)
    return joined


def _function(statement: list):
    """(name token, parameter group or None, body group) for a function or filter."""
    if len(statement) < 3 or _head(statement) not in ("function", "filter") \
            or not _is(statement[1], "bareword"):
        return None
    rest = statement[2:]
    params = rest.pop(0) if _is_group(rest[0], "(") else None
    return (statement[1], params, rest[0]) if len(rest) == 1 and _is_group(rest[0], "{") else None


def _parameters(group: _Group) -> list:
    """(variable, [bracket groups before it]) for each parameter of a list."""
    found, chunk = [], []
    for item in _inner(group) + [None]:
        if item is None or _is(item, "punct", ","):
            variable = next((i for i in chunk if _is(i, "variable")), None)
            if variable is not None:
                found.append((variable, [g for g in chunk[:chunk.index(variable)]
                                         if _is_group(g, "[")]))
            chunk = []
        else:
            chunk.append(item)
    return found


def _assignment(statement: list) -> tuple:
    """(target items, operator, right side) at the first top-level assignment."""
    for index, item in enumerate(statement):
        if _is(item, "operator", *_ASSIGNMENT):
            return statement[:index], item, statement[index + 1:]
    return None, None, None


def _target_variable(target) -> tuple:
    """`$v` or `[T]$v` as an assignment target: (the variable, its type groups)."""
    if target and _is(target[-1], "variable") and all(_is_group(i, "[") for i in target[:-1]):
        return target[-1], target[:-1]
    return None, []


def _target_member(target) -> tuple:
    """`$x.a.b` as an assignment target: (the variable, the last member, lower-case)."""
    if target and len(target) >= 3 and len(target) % 2 and _is(target[0], "variable") and all(
            _is(target[k], "punct", ".") and _is(target[k + 1], "member")
            for k in range(1, len(target), 2)):
        return target[0], target[-1].value.lower()
    return None, ""


def _is_array_type(group) -> bool:
    inner = _inner(group) if _is_group(group, "[") else []
    return (len(inner) == 1 and _word_of(inner[0]) in ("array", "system.array")) or (
        len(inner) == 2 and _is(inner[0], "bareword") and _is_group(inner[1], "[")
        and not _inner(inner[1]))


def _elements(items: list) -> list:
    """The pipeline elements of a command side that the lexer saw start a command."""
    if items and _head(items) in ("return", "throw", "exit"):
        items = items[1:]
    elements: list = [[]]
    for item in items:
        if _is(item, "punct", "|"):
            elements.append([])
        else:
            elements[-1].append(item)
    return [element for element in elements if element and getattr(element[0], "command", False)]


class _Analysis:
    """Tokens, tree, statements with their assignments, commands and units of a file."""

    def __init__(self, tokens: list) -> None:
        self.code = [t for t in tokens if t.kind != "comment"]
        self.position = {t.start: i for i, t in enumerate(self.code)}
        self.tree = _tree(self.code)
        self.units, self.functions = [_Unit("script")], []
        self._walk(self.tree, self.units[0])
        self.top = {t.start for token in self.units[0].tokens for t in (token, *token.refs)}
        self.unit_of = {t.start: unit for unit in self.units for t in unit.tokens}
        self.statements = [s for unit in self.units for s in unit.statements]
        self.assigned = {id(s): _assignment(s) for s in self.statements}
        self.commands = []
        for statement in self.statements:
            target, _operator, right = self.assigned[id(statement)]
            for element in _elements(right if target is not None else statement):
                called = element[0].kind == "punct"
                command = (element[1:2] or [None])[0] if called else element[0]
                named = _is(command, "bareword") or _is(command, "string")
                self.commands.append((command.value.lower() if named else "", command, called,
                                      element))
        self.params = [pair for unit in self.units for group in unit.param_lists
                       for pair in _parameters(group)]
        self.param_starts = {variable.start for variable, _types in self.params}

    def _walk(self, items: list, unit: _Unit) -> None:
        for statement in _statements(items):
            definition = _function(statement)
            if definition is not None:
                name, params, body = definition
                self.functions.append(definition)
                declared = name.value.lower()
                owner = self.units[0] if declared.startswith(("global:", "script:")) else unit
                owner.functions.setdefault(declared.split(":", 1)[-1], name.start)
                inner = _Unit("function", param_lists=[params] if params else [], nested=True,
                              parent=unit)
                self.units.append(inner)
                unit.tokens.extend(statement[:2])
                for group in ([params] if params else []) + [body]:
                    self._walk_group(group, inner)
                continue
            unit.statements.append(statement)
            if _head(statement) == "param" and len(statement) > 1 and _is_group(statement[1], "("):
                unit.param_lists.append(statement[1])
            for index, item in enumerate(statement):
                if not isinstance(item, _Group):
                    unit.tokens.append(item)
                elif _is_group(item, "{") and index and _is(statement[index - 1], "punct", "&"):
                    self.units.append(_Unit("block", nested=unit.nested, parent=unit))
                    self._walk_group(item, self.units[-1])
                else:
                    self._walk_group(item, unit)

    def defined(self, name: str, token: Token) -> bool:
        """Whether a function `name` exists where `token` runs (see `_Unit`)."""
        unit, deferred = self.unit_of.get(token.start), False
        while unit is not None:
            start = unit.functions.get(name)
            if start is not None and (deferred or start < token.start):
                return True
            deferred, unit = deferred or unit.kind == "function", unit.parent
        return False

    def _walk_group(self, group: _Group, unit: _Unit) -> None:
        unit.tokens.append(group.opener)
        self._walk(group.items, unit)
        unit.tokens.append(group.closer)

    def after(self, token: Token, step: int = 1):
        index = self.position[token.start] + step
        return self.code[index] if 0 <= index < len(self.code) else None

    def member_after(self, token: Token) -> str:
        """The member read directly after `token` (`$x.Name`), lower-case, or ''."""
        dot, member = self.after(token), self.after(token, 2)
        if _is(dot, "punct", ".") and dot.start == token.end and _is(member, "member"):
            return member.value.lower()
        return ""

    def key(self, token: Token) -> tuple:
        """The variable a token names, for every rule: its lower-case name and its scope. The
        unit's own scope is one: no qualifier, `local:`, `private:` and `variable:`, and
        `script:` at the script level; any other qualifier, `using:` included, names another
        variable. Misses `script:` or `global:` beside an unqualified name, even where a read
        resolves to it, and `$using:x` beside the caller's own `$x`, which names the same value."""
        own = ("", "local", "private", "variable") + (
            ("script",) if token.start in self.top else ())
        return ("" if token.qualifier in own else token.qualifier, token.value.lower())

    def written(self, token: Token) -> bool:
        """Assigned, incremented, a parameter, or a `foreach` loop variable."""
        if token.in_string:
            return False
        if token.start in self.param_starts:
            return True
        nxt, prev, before = self.after(token), self.after(token, -1), self.after(token, -2)
        return (_is(nxt, "operator", *_ASSIGNMENT, "++", "--") or _is(prev, "operator", "++", "--")
                or (_is(prev, "punct", "(") and _word_of(before) == "foreach"
                    and _word_of(nxt) == "in"))

    def events(self, unit: _Unit, reader) -> list:
        """A unit's variable assignments (at their statement's end) and the reads
        `reader` names, in source order."""
        events = []
        for statement in unit.statements:
            target, operator, right = self.assigned[id(statement)]
            variable, types = _target_variable(target)
            if variable is not None:
                end = _span(statement[-1])[1]
                events.append((end, 0, "assign", variable, types, operator, right))
        events += [(t.start, 1, reader(t), t, None, None, None) for t in unit.tokens
                   if t.kind == "variable" and reader(t)]
        return sorted(events, key=lambda event: event[:2])


# -- rules -------------------------------------------------------------------

#: The qualifiers that can address an automatic or preference variable: never a drive.
_ADDRESSING = ("", "local", "private", "script", "global", "variable")


def _named(token, name: str) -> bool:
    """A variable token that can be the automatic or preference variable `name`:
    `$env:ErrorActionPreference` is an environment variable, not the preference."""
    return _is(token, "variable") and token.value.lower() == name \
        and token.qualifier in _ADDRESSING


def _variable_case_variants(analysis: _Analysis) -> list:
    """One base name in two or more letter cases in one scope unit, at least one
    spelling written; reported at the first use of each later spelling. Misses
    `Set-Variable -Name`, splats and uses across units or dot-sourced files."""
    found = []
    for unit in analysis.units:
        refs = [r for t in unit.tokens if t.kind == "string" for r in t.refs]
        uses: dict = {}
        for token in sorted([t for t in unit.tokens if t.kind == "variable"] + refs,
                            key=lambda t: t.start):
            uses.setdefault(analysis.key(token), []).append(token)
        for tokens in uses.values():
            if len({t.value for t in tokens}) > 1 and any(analysis.written(t) for t in tokens):
                seen = {tokens[0].value}
                for token in tokens:
                    if token.value not in seen:
                        seen.add(token.value)
                        found.append((token, f"'${token.value}' and '${tokens[0].value}' are one "
                                             "variable: variable names ignore letter case"))
    return found


def _myinvocation_in_function(analysis: _Analysis) -> list:
    """`$MyInvocation.MyCommand` (unqualified or `local:`) inside a function or
    filter describes the call, not the script. Remedy: `$script:MyInvocation`.
    Misses aliases of the variable and string subexpressions."""
    return [(token, "$MyInvocation inside a function describes the call, not the script; "
                    "read $script:MyInvocation")
            for unit in analysis.units if unit.nested for token in unit.tokens
            if token.kind == "variable" and token.value.lower() == "myinvocation"
            and token.qualifier in ("", "local") and analysis.member_after(token) == "mycommand"]


def _unrolls(items: list) -> bool:
    """A right side that is a command or pipeline whose output unrolls. `@( )`
    and a leading unary comma are not: neither starts a command or holds a pipe."""
    if not items:
        return False
    if any(_is(item, "punct", "|") for item in items) or getattr(items[0], "command", False):
        return True
    grouped = len(items) == 1 and _is_group(items[0], "(", "$(")
    inner = _statements(items[0].items) if grouped else []
    return len(inner) == 1 and _unrolls(inner[0])


def _unwrapped_result_indexed(analysis: _Analysis) -> list:
    """`$v =` a command or pipeline not wrapped in `@( )`, then `$v[<integer>]` or
    `$v.Count` before `$v` is assigned again. Remedies: `@( )`, an array type on
    `$v`, a leading comma. Misses `.Length`, variable indices and uses across
    units or merging control flow."""

    def reader(token: Token) -> str:
        bracket, index, close = (analysis.after(token, k) for k in (1, 2, 3))
        if _is(bracket, "punct", "[") and bracket.start == token.end and _is(index, "number") \
                and re.fullmatch(r"-?[0-9]+", index.value) and _is(close, "punct", "]"):
            return "use"
        return "use" if analysis.member_after(token) == "count" else ""

    found = []
    for unit in analysis.units:
        tainted: set = set()
        for _at, _order, kind, token, types, operator, right in analysis.events(unit, reader):
            key = analysis.key(token)
            if kind == "assign":
                unwrapped = operator.text == "=" and _unrolls(right) and not any(
                    _is_array_type(group) for group in types)
                (tainted.add if unwrapped else tainted.discard)(key)
            elif key in tainted:
                found.append((token, "a command's output is indexed or counted without @( ): "
                                     "one result arrives as a scalar and none as $null"))
    return found


def _function_named_like_alias(analysis: _Analysis) -> list:
    """A function or filter named like a default alias (scope prefix stripped) or
    with at most two characters: the alias wins. Misses aliases created at run
    time or by modules."""
    found = []
    for name, _params, _body in analysis.functions:
        base = re.sub(r"(?i)^(?:global|script|local|private):", "", name.value)
        if base.lower() in DEFAULT_ALIASES or len(base) <= 2:
            found.append((name, "a function named like a default alias (or of at most two "
                                "characters) loses to the alias"))
    return found


def _null_test(condition: list, key):
    """The variable an `if` condition tests for non-null, or None."""
    def plain(item):
        return _is(item, "variable") and not null(item)

    def null(item):
        return _named(item, "null")

    if len(condition) == 1 and plain(condition[0]):
        return key(condition[0])
    if len(condition) == 3 and _is(condition[1], "dash") and condition[1].value == "ne":
        for tested, other in ((condition[2], condition[0]), (condition[0], condition[2])):
            if plain(tested) and null(other):
                return key(tested)
    return None


def _within(starts: list, items: list) -> bool:
    """Whether a sorted start offset lies inside the span of `items`: a range
    test, so nested statements are not each scanned to the bottom."""
    first = bisect.bisect_left(starts, _span(items[0])[0])
    return first < len(starts) and starts[first] < _span(items[-1])[1]


def _json_null_unchecked(analysis: _Analysis) -> list:
    """`$v` assigned in a statement holding `ConvertFrom-Json`, later tested by an
    `if` whose whole condition is `$v`, `$null -ne $v` or `$v -ne $null`, with no
    `else`: an empty document is $null and the branch silently does nothing.
    Misses compound conditions, results never tested, and whether `ConvertFrom-Json` is in
    command position: `$v = Write-Output ConvertFrom-Json` counts as a parse."""
    found, converts = [], [t.start for t in analysis.code if _word_of(t) == "convertfrom-json"]
    for unit in analysis.units:
        json_keys: set = set()
        for statement in sorted(unit.statements, key=lambda s: _span(s[0])[0]):
            variable, _types = _target_variable(analysis.assigned[id(statement)][0])
            if variable is not None:
                keep = _within(converts, statement)
                (json_keys.add if keep else json_keys.discard)(analysis.key(variable))
            elif _head(statement) == "if" and len(statement) > 1 and _is_group(statement[1], "(") \
                    and _null_test(_inner(statement[1]), analysis.key) in json_keys \
                    and not any(_word_of(item) == "else" for item in statement):
                found.append((statement[0], "a ConvertFrom-Json result is only tested for being "
                                            "non-null, with no else: an empty document is $null"))
    return found


_INT_TYPES = ("int", "int32", "int64", "long", "system.int32", "system.int64")


def _exit_code_null_cast(analysis: _Analysis) -> list:
    """An `[int]` cast of `$LASTEXITCODE` or of a member chain ending `.ExitCode`
    turns a missing code into 0; `.ExitCode` read after `Start-Process -PassThru`
    with no `.Handle` read in between can be $null. Misses `-as [int]` and codes
    copied to other variables."""
    found, code = [], analysis.code
    for index, token in enumerate(code[:-3]):
        if not (_is(token, "punct", "[") and _word_of(code[index + 1]) in _INT_TYPES
                and _is(code[index + 2], "punct", "]")):
            continue
        subject = code[index + 4] if _is(code[index + 3], "punct", "(") and index + 4 < len(code) \
            else code[index + 3]
        chain, cursor = "", subject
        while subject.kind == "variable" and analysis.member_after(cursor):
            chain, cursor = analysis.member_after(cursor), analysis.after(cursor, 2)
        if subject.kind == "variable" and (chain == "exitcode" or (
                not chain and _named(subject, "lastexitcode"))):
            found.append((token, "[int] turns a missing exit code into 0, which reads as success"))

    def reader(token: Token) -> str:
        member = analysis.member_after(token)
        return member if member in ("handle", "exitcode") else ""

    for unit in analysis.units:
        armed: dict = {}
        for _at, _order, kind, token, _types, _operator, right in analysis.events(unit, reader):
            key = analysis.key(token)
            if kind == "assign":
                armed[key] = bool(right) and _word_of(right[0]) == "start-process" and any(
                    _is_parameter(i, "passthru") for i in right)
            elif kind == "handle":
                armed[key] = False
            elif armed.get(key):
                found.append((token, "ExitCode read from Start-Process -PassThru without first "
                                     "reading .Handle can be $null"))
    return found


_SILENT_ENUM = re.compile(r"\[[a-z0-9_.]*actionpreference\]::(?:silentlycontinue|ignore)")


def _silences(items: list) -> bool:
    first = items[0] if items else None
    if isinstance(first, Token) and first.kind in ("bareword", "string", "number"):
        value = first.value.lower()
        return value in ("silentlycontinue", "ignore", "0", "4") \
            or bool(_SILENT_ENUM.fullmatch(value))
    if _is_group(first, "("):
        return _silences(_inner(first))
    inner = _inner(first) if _is_group(first, "[") else []
    return len(items) >= 3 and len(inner) == 1 and _word_of(inner[0]).endswith("actionpreference") \
        and _is(items[1], "operator", "::") and _is(items[2], "member") \
        and items[2].value.lower() in ("silentlycontinue", "ignore")


def _silenced_query(analysis: _Analysis) -> list:
    """A `Get-*`, `Resolve-Path` or `Select-String` command with `-ErrorAction`
    (unique prefix from `-ErrorA`, alias `-ea`, colon form) set to
    SilentlyContinue, Ignore, 0 or 4, or those values assigned to
    `$ErrorActionPreference`. Misses alias spellings of the commands, splatting,
    ambient defaults, `2>$null` and catch blocks that swallow."""
    message = "a query's errors are silenced: an error and an absent result look alike"
    found = []
    for name, _command, _called, element in analysis.commands:
        if (name.startswith("get-") and len(name) > 4) or name in ("resolve-path", "select-string"):
            found += [(item, message) for index, item in enumerate(element)
                      if _is(item, "dash") and (item.value == "ea" or (
                          len(item.value) >= 6 and "erroraction".startswith(item.value)))
                      and _silences(element[index + 1:index + 4])]
    for statement in analysis.statements:
        target, _operator, right = analysis.assigned[id(statement)]
        variable, _types = _target_variable(target)
        if variable is not None and _named(variable, "erroractionpreference") \
                and _silences(right):
            found.append((variable, message))
    return found


def _event_log_read(analysis: _Analysis) -> list:
    """Every `Get-WinEvent` or `Get-EventLog` read (the -List forms excepted): an
    unreadable log and an empty one answer alike. Misses `wevtutil` and .NET
    event-log classes."""
    return [(command, "an event-log read: an unreadable log and an empty one answer alike")
            for name, command, _called, element in analysis.commands
            if name in ("get-winevent", "get-eventlog")
            and not any(_is(i, "dash") and i.value.startswith("list") for i in element)]


def _native_stderr_merged(analysis: _Analysis) -> list:
    """`2>&1` or `*>&1` on a native command: invoked with `&` (not dot-sourced), or a
    bareword. A statically named target, a bareword or a string, is judged alike either
    way: a `.ps1` script, a Verb-Noun name, a default alias or a function defined where
    the call runs is PowerShell. A target held in a variable, expression or block is unknown, and native
    when called with `&`. Misses native commands with Verb-Noun names."""
    found = []
    for name, command, called, element in analysis.commands:
        leaf = name.replace("/", "\\").rsplit("\\", 1)[-1]
        powershell = (leaf.endswith(".ps1") or re.fullmatch(r"[a-z]+-[a-z0-9]+", leaf)
                      or name in DEFAULT_ALIASES or (name and analysis.defined(name, command)))
        native = not powershell and (
            (called and element[0].text == "&"
             and not _is_group(element[1] if len(element) > 1 else None, "{"))
            or (not called and _is(command, "bareword")))
        found += [(item, "2>&1 on a native command turns its stderr lines into error records "
                         "in Windows PowerShell 5.1")
                  for item in element if native and _is(item, "redirect", "2>&1", "*>&1")]
    return found


def _window_title_match(analysis: _Analysis) -> list:
    """`.MainWindowTitle`, or `MainWindowTitle` as a bareword or string argument:
    the console window may belong to a host that also serves the caller. Misses
    computed property names."""
    return [(token, "a window-title check can match the caller's own console window")
            for token in analysis.code
            if token.kind in ("member", "bareword", "string")
            and token.value.lower() == "mainwindowtitle"]


def _elevated_child_output(analysis: _Analysis) -> list:
    """`Start-Process` with `-Verb RunAs` (exact name, colon form, any case), or
    `runas` assigned to a `.Verb` member: the elevated child's output never
    reaches the caller. Misses other elevation routes."""
    message = "an elevated child's console output never reaches the caller"
    found = [(item, message) for name, _command, _called, element in analysis.commands
             if name == "start-process" for index, item in enumerate(element[:-1])
             if _is_parameter(item, "verb")
             and _word_of(element[index + 1]) + _string_of(element[index + 1]) == "runas"]
    for statement in analysis.statements:
        target, _operator, right = analysis.assigned[id(statement)]
        variable, member = _target_member(target)
        if member == "verb" and right and _word_of(right[0]) + _string_of(right[0]) == "runas":
            found.append((variable, message))
    return found


def _string_of(item) -> str:
    return item.value.lower() if _is(item, "string") else ""


def _file_array_parameter(analysis: _Analysis) -> list:
    """An array type (`[T[]]`, `[array]`) on a parameter of the script-level
    `param( )`: `powershell.exe -File` cannot pass an array. Function
    parameters are not flagged. Misses `ValueFromRemainingArguments`."""
    for statement in _statements(analysis.tree):
        if _head(statement) == "param" and len(statement) > 1 and _is_group(statement[1], "("):
            return [(group.opener, "an array parameter of the script cannot be passed through "
                                   "powershell.exe -File")
                    for _variable, groups in _parameters(statement[1]) for group in groups
                    if _is_array_type(group)]
    return []


def _runs_ps1(text: str) -> bool:
    """`-c` ... `-command` as a word, then `.ps1` later on the same line: one pass
    over each line's words, where a pattern would backtrack over every `-c`."""
    for words in (line.split() for line in text.lower().split("\n")):
        first = next((i for i, w in enumerate(words) if len(w) > 1 and w[0] == "-"
                      and "command".startswith(w[1:])), len(words))
        if ".ps1" in " ".join(words[first + 1:]):
            return True
    return False


_SHELLS = ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
# `Start-Process`'s parameters, read on Windows PowerShell 5.1 from `(Get-Command
# Start-Process).Parameters`: name -> (takes a value, alias). A parameter is a switch when
# its type is `SwitchParameter`. Its own parameters come first, the common ones after.
_START_PROCESS = {
    "filepath": (True, "pspath"), "argumentlist": (True, "args"), "credential": (True, "runas"),
    "workingdirectory": (True, ""), "redirectstandarderror": (True, "rse"),
    "redirectstandardinput": (True, "rsi"), "redirectstandardoutput": (True, "rso"),
    "verb": (True, ""), "windowstyle": (True, ""), "loaduserprofile": (False, "lup"),
    "nonewwindow": (False, "nnw"), "passthru": (False, ""), "wait": (False, ""),
    "usenewenvironment": (False, "")}
_COMMON = {
    "verbose": (False, "vb"), "debug": (False, "db"), "erroraction": (True, "ea"),
    "warningaction": (True, "wa"), "informationaction": (True, "infa"),
    "errorvariable": (True, "ev"), "warningvariable": (True, "wv"),
    "informationvariable": (True, "iv"), "outvariable": (True, "ov"),
    "outbuffer": (True, "ob"), "pipelinevariable": (True, "pv")}


def _start_process_parameter(name: str):
    """(name, takes a value) of the `Start-Process` parameter that `name` writes: an exact
    name or alias, else a unique prefix among its own parameters, else among the common
    ones (measured: `-V` is `-Verb`, `-Deb` is `-Debug`); None when unknown or ambiguous."""
    for table in (_START_PROCESS, _COMMON):
        for known, (valued, alias) in table.items():
            if name in (known, alias):
                return known, valued
    for table in (_START_PROCESS, _COMMON):
        hits = [known for known in table if known.startswith(name)]
        if hits:
            return (hits[0], table[hits[0]][0]) if len(hits) == 1 else None
    return None


def _is_parameter(item, name: str) -> bool:
    """Whether a dash names the `Start-Process` parameter `name`."""
    return _is(item, "dash") and (_start_process_parameter(item.value) or ("",))[0] == name


def _leaf(item) -> str:
    """The lower-case last component of a word, '' when the item is not a word."""
    if _is(item, "bareword") or _is(item, "string"):
        return item.value.lower().replace("/", "\\").rsplit("\\", 1)[-1]
    return ""


def _process_target(element: list) -> str:
    """The lower-case leaf of a `Start-Process` target: an explicit `-FilePath` value, else
    the first positional item, after the whole value of each parameter that takes one (a
    comma list included); '' when the target is not a word. A switch takes no value unless
    it is written with a colon (`-Wait:$false`), which keeps its value as the next item."""
    items, index = element[1:], 0
    for at, item in enumerate(items):
        if _is_parameter(item, "filepath"):
            return _leaf(items[at + 1]) if at + 1 < len(items) else ""
    while index < len(items) and _is(items[index], "dash"):
        parameter = _start_process_parameter(items[index].value)
        valued = parameter is None or parameter[1]
        taken = valued or items[index].text.endswith(":")
        index += 2 if taken else 1
        while valued and index < len(items) and _is(items[index], "punct", ","):
            index += 2
    return _leaf(items[index]) if index < len(items) else ""


def _command_runs_script(analysis: _Analysis) -> list:
    """`powershell`/`pwsh` run with `-Command`/`-c` whose next argument holds
    `.ps1`, or such a command line given to `Start-Process -ArgumentList` when its
    target is `powershell` or `pwsh` (`.exe`, a path and case do not matter): the
    script's exit code is lost. Remedy: `-File`. Misses `-EncodedCommand`, command
    lines built in variables and targets held in variables."""
    message = "-Command running a .ps1 loses the script's exit code; use -File"
    found = []
    for name, _command, _called, element in analysis.commands:
        leaf = name.replace("/", "\\").rsplit("\\", 1)[-1]
        target = _process_target(element) if leaf == "start-process" else ""
        for index, item in enumerate(element):
            if not _is(item, "dash") or not item.value:
                continue
            following = element[index + 1] if index + 1 < len(element) else None
            if leaf in _SHELLS \
                    and "command".startswith(item.value) and isinstance(following, Token) \
                    and ".ps1" in (following.value or following.text).lower():
                found.append((item, message))
            if target in _SHELLS and _is_parameter(item, "argumentlist"):
                texts, later = [], index + 1  # read in place: no copy of the rest per dash
                while later < len(element) and not _is(element[later], "dash"):
                    if _is(element[later], "string") or _is(element[later], "bareword"):
                        texts.append(element[later].value)
                    later += 1
                if _runs_ps1(" ".join(texts)):
                    found.append((item, message))
    return found


def _space_joins(items: list, found: list) -> list:
    """Where each `-join ' '` or `[string]::Join(' ', ...)` starts, at any depth."""
    for index, item in enumerate(items):
        following = items[index + 1:index + 4]
        if (_is(item, "dash") and item.value == "join" and following
                and _is(following[0], "string") and following[0].value == " ") or (
                _is_group(item, "[") and len(following) == 3 and _is(following[0], "operator", "::")
                and _word_of(_inner(item)[0] if len(_inner(item)) == 1 else None) in (
                    "string", "system.string")
                and _is(following[1], "member") and following[1].value.lower() == "join"
                and _is_group(following[2], "(") and len(_inner(following[2])) >= 2
                and _string_of(_inner(following[2])[0]) == " "
                and _is(_inner(following[2])[1], "punct", ",")):
            found.append(_span(item)[0])
        if _is_group(item):
            _space_joins(item.items, found)
    return found


def _argument_join(analysis: _Analysis) -> list:
    """An assignment to a `.Arguments` member whose right side joins with a single
    space (`-join ' '`, `[string]::Join(' ', ...)`): the argument vector loses
    its quoting. Misses interpolation and `-f` formatting."""
    found, joins = [], sorted(_space_joins(analysis.tree, []))
    for statement in analysis.statements:
        target, _operator, right = analysis.assigned[id(statement)]
        variable, member = _target_member(target)
        if member == "arguments" and right and _within(joins, right):
            found.append((variable, "an argument vector joined with spaces loses its quoting"))
    return found


def _args_parameter(analysis: _Analysis) -> list:
    """A parameter named `$Args` (any case) in any parameter list: the automatic
    `$args` shadows it, so it never binds."""
    return [(variable, "a parameter named $Args never binds: the automatic $args shadows it")
            for variable, _types in analysis.params if variable.value.lower() == "args"]


_STRING_QUALIFIERS = ("global", "local", "script", "private", "using", "workflow", "env",
                      "variable", "function", "alias")


def _string_colon_variable(analysis: _Analysis) -> list:
    """Inside an expandable string or here-string (not in `$( )`), `$name:rest`
    whose `name` is not a scope or variable drive reads a drive-qualified
    variable. Remedy: `${name}:`."""
    return [(ref, f"'${ref.qualifier}:' inside an expandable string reads a drive-qualified "
                  "variable; write '${name}:' for a literal colon")
            for token in analysis.code if token.kind == "string" for ref in token.refs
            if ref.qualifier and not ref.braced and ref.qualifier not in _STRING_QUALIFIERS]


#: The rules in report order: (identifier, check). A check returns
#: (token, message) pairs for one analysed file.
RULES = (
    ("variable-case-variants", _variable_case_variants),
    ("myinvocation-in-function", _myinvocation_in_function),
    ("unwrapped-result-indexed", _unwrapped_result_indexed),
    ("function-named-like-alias", _function_named_like_alias),
    ("json-null-unchecked", _json_null_unchecked),
    ("exit-code-null-cast", _exit_code_null_cast),
    ("silenced-query", _silenced_query),
    ("event-log-read", _event_log_read),
    ("native-stderr-merged", _native_stderr_merged),
    ("window-title-match", _window_title_match),
    ("elevated-child-output", _elevated_child_output),
    ("file-array-parameter", _file_array_parameter),
    ("command-runs-script", _command_runs_script),
    ("argument-join", _argument_join),
    ("args-parameter", _args_parameter),
    ("string-colon-variable", _string_colon_variable),
)


@dataclass(frozen=True, order=True)
class Finding:
    line: int
    column: int
    rule: str
    message: str


def _refuse_controls(text: str) -> None:
    """Before lexing, a control or format character anywhere but TAB, LF and CR
    refuses the file: one scan of the whole text, so no path of the lexer, no
    string and no comment lets one through."""
    odd = [c for c in set(text) - set("\t\n\r") if unicodedata.category(c) in ("Cc", "Cf")]
    if odd:
        first = min(text.index(c) for c in odd)
        line = len(re.findall(r"\r\n|\r|\n", text[:first])) + 1
        raise LintRefusal(f"the control or format character U+{ord(text[first]):04X} on line "
                          f"{line}: its meaning to Windows PowerShell 5.1 was not measured")


def lint_text(text: str) -> list:
    """Findings for decoded source, sorted by (line, column, rule). Raises
    `LintRefusal` for malformed source and for any exception in the analysis or
    a rule: an error is never read as "no findings"."""
    tokens = tokenize(text)
    try:
        analysis = _Analysis(tokens)
    except RecursionError as exc:
        raise LintRefusal("the source nests deeper than the linter can follow") from exc
    findings = set()
    for rule, check in RULES:
        try:
            produced = check(analysis)
        except Exception as exc:  # noqa: BLE001 - a failing rule refuses the file
            raise LintRefusal(f"rule {rule} raised {type(exc).__name__}, so the file cannot "
                              "be judged") from exc
        findings.update(Finding(t.line, t.column, rule, message) for t, message in produced)
    return sorted(findings)


# -- files and the report ----------------------------------------------------


@dataclass
class Report:
    files: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    refusal: str | None = None

    @property
    def verdict(self) -> str:
        if self.refusal or any(entry["status"] == "refused" for entry in self.files):
            return "refused"
        return "findings" if self.findings else "clean"

    def as_dict(self) -> dict:
        return {"schema": SCHEMA, "verdict": self.verdict, "refusal": self.refusal,
                "files": sorted(self.files, key=lambda entry: entry["path"]),
                "findings": sorted(self.findings, key=lambda f: (f["path"], f["line"],
                                                                 f["column"], f["rule"])),
                "rules": [rule for rule, _check in RULES]}

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _refused(path: str, reason: str) -> dict:
    return {"path": path, "sha256": None, "encoding": None, "status": "refused", "refusal": reason}


def _collect(argument: str) -> tuple:
    """(Path or None, refusal or None) for one named file. Nothing is walked or
    followed: a link, a directory, a special file or another suffix refuses."""
    path = Path(argument)
    try:
        info = path.lstat()
    except OSError as exc:
        return None, ("the path does not exist" if isinstance(exc, FileNotFoundError)
                      else f"the path cannot be examined ({type(exc).__name__})")
    if stat.S_ISLNK(info.st_mode):
        return None, "the path is a link; links are not followed"
    if stat.S_ISDIR(info.st_mode):
        return None, "a directory is not linted: name its files"
    if not stat.S_ISREG(info.st_mode):
        return None, "the path is a special file"
    if not argument.lower().endswith(SUFFIXES):
        return None, "the file is not a .ps1 or .psm1 file"
    return path, None


def paths_given(paths: list) -> bool:
    """The empty-set check: a run must name at least one path."""
    return bool(paths)


def _lint_file(shown: str, path: Path) -> tuple:
    try:
        if path.lstat().st_size > MAX_FILE_BYTES:
            return _refused(shown, f"the file is larger than {MAX_FILE_BYTES} bytes"), []
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        return _refused(shown, f"the file cannot be read ({type(exc).__name__})"), []
    if len(data) > MAX_FILE_BYTES:
        return _refused(shown, f"the file is larger than {MAX_FILE_BYTES} bytes"), []
    entry = {"path": shown, "sha256": hashlib.sha256(data).hexdigest(), "encoding": None,
             "status": "linted", "refusal": None}
    try:
        text, entry["encoding"] = decode_source(data)
        findings = lint_text(text)
    except LintRefusal as exc:
        entry.update(status="refused", refusal=str(exc))
        return entry, []
    return entry, [{"path": shown, "line": f.line, "column": f.column, "rule": f.rule,
                    "message": f.message} for f in findings]


def lint_paths(paths) -> Report:
    """Judge each distinct path string once, in sorted order: linted, or refused
    for its own reason. A repeated string is one argument; nothing else is merged,
    and the count is bounded before any file is examined."""
    report, names = Report(), sorted(set(paths))
    if not paths_given(names):
        report.refusal = "no path was given"
    elif len(names) > MAX_FILES:
        report.refusal = f"more than {MAX_FILES} files were named"
    else:
        for name in names:
            path, refusal = _collect(name)
            entry, findings = _lint_file(name, path) if refusal is None else (
                _refused(name, refusal), [])
            report.files.append(entry)
            report.findings += findings
    return report


_USAGE = ("usage: ps51_lint.py FILE [FILE ...]; no option exists, so name a file that starts "
          "with '-' as ./-x.ps1")


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):  # LF lines on every platform
        getattr(stream, "reconfigure", lambda **_: None)(newline="")
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or any(argument.startswith("-") for argument in argv):
        sys.stderr.write(f"REFUSE: {_USAGE}\n")
        return 2
    try:
        report = lint_paths(argv)
        sys.stdout.write(report.to_json())
        if report.verdict != "refused":
            return 1 if report.verdict == "findings" else 0
        reason = report.refusal or next(e["refusal"] for e in report.as_dict()["files"]
                                        if e["status"] == "refused")
        sys.stderr.write(f"REFUSE: {reason}\n")
    except Exception as exc:  # noqa: BLE001 - an unexpected error is a refusal
        sys.stderr.write(f"REFUSE: the linter failed ({type(exc).__name__}); nothing was judged\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
