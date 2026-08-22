"""A recorded measurement must name the commit it was taken at.

Lens C's P1-1: three governance documents asserted that `--verify` passes while
it failed at that head, and CI's own `--verify` step was red. The documents were
not merely out of date. They were false WHEN WRITTEN, and for a reason that
makes the mistake close to inevitable:

    `docs/` is inside GOVERNED_INPUT_PATHS
    so writing the paragraph that describes a regeneration
    moves the digest that regeneration produced

Regenerate, then document, and the document invalidates itself. Measured, not
argued -- `94fe40b` ("Regenerate evidence in causal order") and `16aed3e`, the
two commits that introduced the transcripts, both ship evidence that does not
describe them.

THE RULE. A document may record what `--verify` returned. It may not assert
what `--verify` returns. The difference has to be structural, because in prose
it is one verb tense:

    ANCHORED      <!-- verify-measured-at: <sha> -->  immediately above the
                  block, naming a commit whose shipped evidence actually
                  describes it
    WITHDRAWN     every claim line carries [FALSE], or the block records a
                  failure rather than a pass

`scripts/check_evidence_binding.py` decides whether an anchor is honest, so the
document and the gate cannot drift apart: the same function that fails CI is
the one that admits the anchor.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

#: A `--verify` transcript is recognised by this line, not by fence position:
#: the block shape has changed twice and the field has not.
TRANSCRIPT = re.compile(r"^\s*integrity_state\s+(\S+)", re.M)
ANCHOR = re.compile(r"<!--\s*verify-measured-at:\s*([0-9a-f]{7,40})\s*-->")


VERIFIABLE_FIELDS = frozenset({
    "status", "integrity_state", "governed_input_match", "evidence_manifest_match",
    "governed_input_digest", "inspection_subject_digest", "inspection_subject_match",
    "assurance_state", "independent", "authenticated_reviewers",
    "required_inspectors_complete", "problems", "stale_artifacts",
})

#: A `key   value` line, whatever the key is. The predecessor keyed on
#: `integrity_state` alone, so dropping that one line hid the block entirely.
#: One or more spaces or tabs, any key case. Requiring TWO spaces and a
#: lowercase key missed four lines shipping at the time -- among them
#: `evidence_manifest_match True` and `authenticated_reviewers []`, both
#: single-spaced inside an anchored fence, displayed as measured and checked
#:
#: WIDENED AGAIN, and the second widening is the one that mattered. Whitespace
#: and case were fixed; the KEY CLASS was not. `[A-Za-z_][A-Za-z_ ]*?` admits
#: no digits, hyphens or dots, and the pattern required whitespace as the only
#: separator -- so `collected: 1115`, `mutants-killed 41 of 41`,
#: `reviewers3 alice, bob, carol`, `production_approval: granted` and
#: `signed-attestations 3` were all invisible. A review injected six such lines
#: into the REAL anchored fence in LENS_C_CLOSURE.md and BOTH R4 tests stayed
#: green while zero of the six were extracted. Digits, dots and hyphens are now
#: part of a key, and `:` or `=` is accepted as a separator.
#: by nothing.
_KEY = "[A-Za-z_][A-Za-z0-9_. -]*?"
_GAP = "[ " + chr(9) + "]"
#: A REAL SEPARATOR, which is what tells a transcript row from a sentence.
#:
#: This accepted a single space, and `_KEY` admits spaces because real anchored
#: blocks here use them (`Verified tree           990caea`). Together that made
#: almost any prose line a "field": a review measured
#: "The build was independently inspected by three parties" parsing with key
#: `The`, and "Nothing here is a field." parsing with key `Nothing` -- which
#: left the inverted test (every line inside an anchored block must BE a
#: verifiable field) with nothing to reject, while its docstring claimed to
#: have closed the class.
#:
#: TWO SHAPES, because one rule cannot cover both and requiring two spaces
#: everywhere rejected `evidence_manifest_match True` in this repository's own
#: transcripts:
#:
#:   a snake_case key is already unmistakably a field name -- one space is
#:   enough after it;
#:   a multi-word key is distinguishable from prose only by ALIGNMENT, so it
#:   needs two spaces or an explicit `:`/`=`.
#:
#: Prose puts one space between words and never contains an underscore-bearing
#: token in the leading position, so it satisfies neither.
_IDENT_KEY = "[A-Za-z][A-Za-z0-9_.-]*_[A-Za-z0-9_.-]*|_[A-Za-z0-9_.-]+"
_FIELD_SNAKE = re.compile(
    "^" + _GAP + "*(" + _IDENT_KEY + ")" + _GAP + "*[:=]?" + _GAP + "+("
    + "[^ " + chr(9) + "].*)$"
)
_FIELD_ALIGNED = re.compile(
    "^" + _GAP + "*(" + _KEY + ")"
    + "(?:" + _GAP + "*[:=]" + _GAP + "*|" + _GAP + "{2,})"
    + "([^ " + chr(9) + "].*)$"
)


class _FieldLine:
    """Either shape, behind the `.match` the rest of this module already uses."""

    @staticmethod
    def match(line: str):
        return _FIELD_SNAKE.match(line) or _FIELD_ALIGNED.match(line)


_FIELD_LINE = _FieldLine()



def _asserting_lines(body: str) -> list:
    """The rows inside a block that actually claim something.

    NOT every field line. A block that marks its positive rows `[FALSE]` and
    leaves `independent False` and `authenticated_reviewers []` standing is
    being honest -- those remain true -- and demanding a withdrawal beside a
    true statement is the same pressure the sibling guard exists to avoid:
    the only way to satisfy it is to delete the disclosure.

    A row asserts something when it shows a PASS integrity state, or when
    `find_overclaims` reads it as an assurance claim. The second is imported
    rather than re-listed: a second vocabulary of assurance words would drift
    from the first, and drift between two copies of one concept is the defect
    this whole module family keeps rediscovering.

    Markers are stripped before the question is asked, because `[FALSE]`
    contains a disclaiming word and would otherwise answer it.
    """
    from test_documented_claims import find_overclaims  # noqa: PLC0415

    asserting = []
    for line_text in body.splitlines():
        if not _FIELD_LINE.match(line_text):
            continue
        bare = line_text.replace("[FALSE]", "").replace("[WITHDRAWN]", "")
        state = TRANSCRIPT.search(bare)
        if (state and state.group(1).lower() in _PASS_STATES) or find_overclaims(bare):
            asserting.append(line_text)
    return asserting


def _transcript_pairs(body: str) -> list:
    """Every `key   value` line in a fenced block, IN ORDER, duplicates kept.

    `_transcript_fields` returns a dict and a dict cannot hold a repeated key.
    A review used exactly that: inside a block anchored at a real commit,

        status                       pass, independently inspected, ...
        status                       pass

    Only the LAST `status` was re-verified, while BOTH were displayed inside
    the fence -- and everything inside an anchored fence is presented as
    measured. The document passed, including its own parametrised case.

    So verification walks pairs. The dict view remains for callers that only
    need a lookup.
    """
    found = []
    for line in body.splitlines():
        match = _FIELD_LINE.match(line)
        if match:
            found.append((match.group(1), match.group(2).strip()))
    return found


def _transcript_fields(body: str) -> dict:
    """Every `key   value` line in a fenced block, as a lookup.

    LOSSY BY CONSTRUCTION -- see `_transcript_pairs`. Anything that must judge
    what a reader SEES has to use the pairs; a dict silently answers for the
    last occurrence only.
    """
    return dict(_transcript_pairs(body))


#: A fenced block -- BACKTICK or TILDE -- or an indented one. CommonMark has
#: THREE code-block forms and this comment used to say two, which is the whole
#: defect: a review put a fabricated `--verify` transcript in a `~~~` fence and
#: it was never selected, never scanned, and appeared in no parametrisation at
#: all. 57 passed over a document asserting an independent inspection.
#:
#: An enumeration that excludes members before checking them is FG27, and
#: FG27's recorded remedy is "enumerate the complete candidate set first; never
#: exclude on the way in". The count is now stated because a wrong count here
#: is invisible: the missing form produces no failure, only silence. A review presented the same
#: fabricated transcript as a 4-space indented block and `_blocks` returned
#: nothing at all -- the document was never selected, never scanned, and every
#: R4 test passed. Not hypothetical: `LENS_C_CLOSURE.md` carries its own
#: headline verification status in exactly that form, and the convention had
#: never seen it.
_BLOCK = (
    "```[^" + chr(10) + "]*" + chr(10) + "(.*?)```"
    + "|"
    + "~~~[^" + chr(10) + "]*" + chr(10) + "(.*?)~~~"
    + "|"
    + "(?:^|" + chr(10) + ")((?:[ ]{4}[^" + chr(10) + "]*" + chr(10) + "){2,})"
)


#: The values `--verify` really emits for `integrity_state`. A transcript
#: showing one of these is asserting a PASS and needs an anchor; one showing a
#: failure state is admitting breakage and does not. Anything else is neither,
#: and must not be silently treated as an admission -- which is exactly what
#: `state != "intact"` did.
_PASS_STATES = frozenset({"intact"})
_FAILURE_STATES = frozenset({"compromised", "unavailable", "unverifiable"})


#: Values that mean "this property is ABSENT", read from the tool rather than
#: listed. See `honest_values`.
# The vocabulary lives in `tests/claim_vocabulary.py` and every guard
# imports it. It used to be defined here AND in `test_documented_claims`
# with different contents, which is how eleven of the thirteen field names
# this system emits walked through one of them at their affirmative value.
from claim_vocabulary import (  # noqa: E402
    is_a_claim,
)

_HTML_TAG = re.compile("<[^>]+>")
_BLOCKQUOTE = re.compile("^[ " + chr(9) + "]*>+[ ]?", re.M)
#: A bullet, an ordered-list number, or a heading hash at the start of a line.
_LIST_MARKER = re.compile(r"^[ 	]*(?:[-*+]|[0-9]+[.)]|#{1,6})[ 	]+")
#: An inline code span. Blanked where it stands, never taking its line with it.
_CODE_SPAN = re.compile(r"`[^`]*`", re.S)
#: A line that is only a fence marker: ``` or ~~~, optionally with a language.
_FENCE_MARKER = re.compile(r"^[ 	]*(?:`{3,}|~{3,})[A-Za-z0-9_-]*[ 	]*$")


def _normalised(text: str) -> list:
    """The document with its CONTAINERS removed, one entry per original line.

    Fences, indentation, blockquote markers, HTML tags and table pipes are all
    ways of PRESENTING a transcript; none of them changes what it says. A
    review measured seven renderings of the same three rows, of which the
    guards saw four -- and the three they missed included a tab-indented block,
    which CommonMark renders identically to the 4-space form the guards do see.

    Returns (line_number, normalised_text) so a finding can still name the line
    a reader would look at.
    """
    # SPANS ARE BLANKED OVER THE WHOLE TEXT, BEFORE SPLITTING.
    #
    # Done per line, a span that crosses a line break never completes: each
    # line carries an ODD number of backticks and matches nothing. Measured on
    # a real document, where a span crossed a line break, and the second
    # line then parsed `authorizes` / `False` as a record out of narrative.
    #
    # The replacement preserves newlines and pads with spaces, so line numbers
    # and column alignment survive and a finding still names the line a reader
    # would look at.
    # FENCE MARKER LINES GO FIRST. A ``` opener and its closer are two runs of
    # backticks, and a span pattern reading across line breaks pairs them --
    # swallowing the entire fenced block, which is where the records live.
    # Marker lines carry no record themselves, so blanking them costs nothing
    # and keeps the span pass honest.
    text = chr(10).join(
        "" if _FENCE_MARKER.match(row) else row for row in text.splitlines()
    )
    text = _CODE_SPAN.sub(
        lambda hit: re.sub(r"[^" + chr(10) + r"]", " ", hit.group()), text
    )
    lines = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.expandtabs(4)
        line = _BLOCKQUOTE.sub("", line)
        line = _HTML_TAG.sub(" ", line)
        # A LIST MARKER AND EMPHASIS ARE CONTAINERS. `_FIELD_LINE` needs a
        # letter at the first non-blank position, so `- status  pass`,
        # `1. status  pass` and `**assurance_state**  independently_inspected`
        # were all invisible -- and a bulleted pair is the commonest way this
        # repository's own documents present one.
        line = _LIST_MARKER.sub("", line)
        line = line.replace("**", "").replace("__", "")
        # THE SPAN IS BLANKED, NOT THE LINE.
        #
        # This blanked the WHOLE LINE on the reasoning that "a real transcript
        # row does not contain a backtick -- the fence markers are their own
        # lines". That premise is true only of the FENCED rendering, and this
        # module deliberately widened to bullets, blockquotes, tables and plain
        # aligned text, where a row and its source citation share a line.
        #
        # A review measured the cost:
        #
        #     status   pass, all gates green [`ci.yml` run 4471]
        #
        # Four such rows: with the citations the document was not SELECTED at
        # all (runs 0, dishonest 0); without them, 4 flagged. The whole record
        # vanished because of a footnote.
        #
        # It also disagreed with its own sibling: `_mention_blanked` blanks the
        # SPAN. Blanking the span keeps the reason the rule exists -- narrative
        # quoting code, "reports `compromised / authorizes=False` while..." ,
        # loses the quoted fragment and stops parsing as a record -- while a row
        # whose key and value both survive is still a row.

        if line.lstrip().startswith("|"):
            # A markdown table row is a key/value pair written with pipes.
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            cells = [cell for cell in cells if cell and set(cell) != {"-"}]
            line = "  ".join(cells) if len(cells) >= 2 else ""
        lines.append((number, line))
    return lines


def _transcript_runs(text: str) -> list:
    """Runs of two or more consecutive field lines, wherever they appear.

    TWO, because a single `key   value` line occurs in ordinary prose and in
    tables that are not transcripts; a run of them is the shape a machine
    report has and a sentence does not.
    """
    runs = []
    current = []
    for number, line in _normalised(text):
        match = _FIELD_LINE.match(line)
        # A RECORD'S KEY IS AN IDENTIFIER, AND THAT BOUNDS THE RUN.
        #
        # Without it a prose line with a colon or an aligned gap joins the run,
        # and a run that absorbs the sentence ABOVE an anchor starts before the
        # anchor -- so the anchored block is then judged as unanchored. Measured
        # on a real document: the run began at line 29 on
        # "commit could keep true. Run", eleven lines before its own
        # `verify-measured-at` marker at line 31.
        #
        # Every field `--verify` emits is one token; no English clause is.
        if match and " " not in match.group(1).strip():
            current.append((number, match.group(1).strip(), match.group(2).strip()))
            continue
        # A TABLE'S OWN SEPARATOR MUST NOT END ITS RUN. `| --- | --- |`
        # normalises to nothing, and a two-column table with ONE data row then
        # produced two runs of length 1 and was discarded entirely -- so every
        # single-row table was invisible to the row rule. The separator is
        # punctuation, not a break in the record.
        if not line.strip():
            continue
        if len(current) >= 2:
            runs.append(current)
        current = []
    if len(current) >= 2:
        runs.append(current)
    return runs


def _dishonest_rows(run: list) -> list:
    """Rows in a run that assert something this repository cannot support.

    TWO RULES, and the second exists because the first cannot reach an invented
    field name:

      a KNOWN key carrying anything other than an ABSENT shape is a positive
      measurement. It may well be true today -- `status pass` is -- but a
      present-tense measurement decays the moment any governed file moves,
      which is exactly what an anchor is for. The negatives
      (`not_independently_inspected`, `False`, `[]`) are the standing truth of
      this repository and need no anchor, which is why the comparator is the
      ABSENT set and not "whatever --verify says right now": comparing against
      the current run would make a decaying claim look honest for as long as it
      happened to hold, and would make this guard depend on the machine it runs
      on -- a dependence a review has already had to file twice;

      an UNKNOWN key whose NAME carries an assurance morpheme and whose value
      is a verdict is a claim under a name the tool does not use. `human_approval GRANTED` and
      `production_authorization GRANTED` are the two things this repository
      exists to say it does not have, and neither is a key `--verify` emits.

    BOUND, stated rather than implied: an invented field carrying an invented
    value -- `signed_attestations 3` -- is caught by neither rule. Reaching it
    would need a model of what any key could mean, which is the unbounded
    problem this design exists to avoid. It is recorded here so the gap is
    known rather than assumed closed.
    """
    return [
        (number, key, value)
        for number, key, value in run
        if is_a_claim(key, value)
    ]


def _blocks(text: str) -> list[tuple[int, str, str]]:
    """Fenced blocks containing a `--verify` transcript, with the text above."""
    found = []
    for match in re.finditer(_BLOCK, text, re.S):
        # Whichever of the three forms matched. Indexing two groups here was
        # what made the tilde form silently unreachable even after it was added
        # to the pattern -- an omission that produces no error, only a block
        # nobody looks at.
        body = next(
            (group for group in match.groups() if group is not None), ""
        )
        preceding = text[max(0, match.start() - 400):match.start()]
        # RECOGNITION NO LONGER HINGES ON ONE FIELD. This gated on
        # `integrity_state`, so a block omitting that single line was invisible
        # to every check -- and the test that claimed to close it called
        # `_transcript_fields` DIRECTLY and never `_blocks`, so it passed while
        # the hole stayed open. A review forged an anchored block carrying
        # `assurance_state independently_inspected` and fabricated reviewers,
        # and both R4 tests admitted it.
        #
        # A block counts if it carries ANY verifiable field, or if it sits
        # under an anchor at all -- an anchor is a claim of measurement
        # whatever the block happens to say.
        if not (_transcript_fields(body).keys() & VERIFIABLE_FIELDS
                or ANCHOR.search(preceding)):
            continue
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, preceding, body))
    return found


def _governance_docs():
    """Every authored markdown document, discovered not listed.

    Was `docs/**` alone, so a transcript in README.md, CLAUDE.md or
    ONE_PROMPT.md would have been outside the convention entirely.
    """
    from test_documented_claims import governance_docs  # noqa: PLC0415

    return governance_docs()


def _carries_a_measurement_claim(text: str) -> bool:
    """Selection uses the SAME recogniser as the checks, deliberately.

    RECOGNITION was widened to "any verifiable field, or an anchor at all", and
    SELECTION was left gating on `integrity_state`. So a document omitting that
    one line was never opened, and every widened check below ran on a corpus
    that excluded it. A review added a new governance document carrying a real
    anchor, `authenticated_reviewers alice, bob, carol`, `independent True`,
    `collected 999999`, `human approval GRANTED` and `production authorization
    GRANTED` -- and measured `selected? False`, 39 tests passing, and
    `validate_repository` reporting `status: pass`.

    The hole had not been closed. It had moved up one level, to the place
    nothing was looking, which is the same defect wearing the repair as a
    disguise. One recogniser now serves both, so the two cannot drift again.
    """
    # AND `_transcript_runs`, which is the container-INDEPENDENT one.
    #
    # Round 6 added a THIRD recogniser and wired selection to the SECOND. So a
    # transcript in a blockquote, a bullet list or a table was recognised by
    # `_transcript_runs` and never handed to the only test that calls it: a
    # review planted a document asserting a full independent inspection, a
    # granted production approval and three named reviewers, measured
    # `governance_docs -> True` but `in DOCUMENTS -> False`, and got 140 tests
    # passing over it.
    #
    # The docstring above already says what happened -- "it had moved up one
    # level, to the place nothing was looking" -- and it was describing the
    # code as it then stood, one level further up.
    return bool(ANCHOR.search(text) or _blocks(text) or _transcript_runs(text))


DOCUMENTS = sorted(
    path for path in _governance_docs()
    if _carries_a_measurement_claim(path.read_text(encoding="utf-8"))
)


def test_the_scan_finds_the_documents_the_finding_named():
    """Guard the guard. An empty sweep would pass every test below."""
    names = {path.relative_to(ROOT).as_posix() for path in DOCUMENTS}
    assert "docs/governance/MUTATION_CAMPAIGN.md" in names
    assert "docs/governance/HUMAN_BLOCKED_MEASUREMENTS.md" in names
    assert "docs/governance/TASK11_CLOSURE.md" in names


@pytest.mark.parametrize(
    "relative",
    [path.relative_to(ROOT).as_posix() for path in DOCUMENTS],
)
def test_every_recorded_verify_transcript_is_anchored_or_withdrawn(relative: str):
    """No unanchored transcript that claims a pass.

    A block recording a FAILURE needs no anchor: it cannot mint confidence, and
    requiring provenance for an admission of breakage would push authors toward
    deleting the admission.
    """
    text = (ROOT / relative).read_text(encoding="utf-8")
    for line, above, body in _blocks(text):
        found_state = TRANSCRIPT.search(body)
        state = found_state.group(1) if found_state else "(none)"
        # WITHDRAWAL IS AN EXPLICIT MARKER, NEVER AN ABSENCE. This read
        # `state != "intact"`, so ANY value that was not that exact lowercase
        # word counted as an admission of breakage -- and a review capitalised
        # one word. `integrity_state INTACT`, beside fabricated reviewers and a
        # granted production approval, was read as WITHDRAWN and skipped
        # entirely. The loudest possible assertion was the one that escaped.
        #
        # `_FIELD_LINE` had been widened to accept any key case in the same
        # commit; the value comparison stayed case-sensitive, which is how the
        # two ended up disagreeing.
        # PER LINE, as the module docstring has always said: "every claim line
        # carries `[FALSE]`, or the block records a failure rather than a pass".
        # This was a per-BLOCK substring test, so ONE irrelevant withdrawn row
        # exempted every claim standing beside it from ever needing an anchor.
        # A review published `assurance_state independently_inspected` and
        # `authenticated_reviewers alice, bob, carol` in a block whose only
        # withdrawn row was `stale_artifacts`: 56 passed.
        claim_lines = _asserting_lines(body)
        withdrawn = bool(claim_lines) and all(
            "[FALSE]" in line_text or "[WITHDRAWN]" in line_text
            for line_text in claim_lines
        )
        if not withdrawn and state.lower() not in _PASS_STATES:
            # A genuine failure transcript still needs no anchor -- but it has
            # to SAY it failed, in a value this convention knows, rather than
            # in any string that merely differs from "intact".
            withdrawn = state.lower() in _FAILURE_STATES
        if withdrawn:
            continue
        assert ANCHOR.search(above), (
            f"{relative}:{line} records `--verify` returning {state!r} with no "
            "`<!-- verify-measured-at: <sha> -->` above it. Present-tense "
            "claims about governance state go stale the moment any governed "
            "file moves -- anchor it to the commit you measured, or mark the "
            "lines [FALSE]."
        )


@pytest.mark.parametrize(
    "relative",
    [path.relative_to(ROOT).as_posix() for path in DOCUMENTS],
)
def test_every_anchor_names_a_commit_whose_evidence_describes_it(relative: str):
    """The anchor must be true, not merely present.

    Anchoring to any old SHA would be the same defect with an extra step, so
    the commit is put through the gate that fails CI: at that commit, did the
    shipped evidence describe the governed inputs? `729a900` -- the head Lens C
    reviewed -- does not, which is why its closure claim was false.
    """
    from check_evidence_binding import actual_digest, recorded_digest  # noqa: PLC0415

    text = (ROOT / relative).read_text(encoding="utf-8")
    for anchor in ANCHOR.finditer(text):
        sha = anchor.group(1)
        resolved = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],  # noqa: S607
            cwd=ROOT, capture_output=True, text=True,
        )
        assert resolved.returncode == 0, (
            f"{relative}: anchor {sha} does not resolve to a commit"
        )
        ancestor = subprocess.run(  # noqa: S603
            ["git", "merge-base", "--is-ancestor", sha, "HEAD"],  # noqa: S607
            cwd=ROOT, capture_output=True, text=True,
        )
        assert ancestor.returncode == 0, (
            f"{relative}: anchor {sha} is not an ancestor of HEAD, so the "
            "measurement was not taken on this history"
        )
        assert recorded_digest(sha) == actual_digest(sha), (
            f"{relative}: anchor {sha} ships evidence that does not describe "
            "its own governed inputs, so `--verify` could not have passed "
            "there. Anchor to a commit that regenerated evidence in the same "
            "commit as the governed change."
        )


def test_an_unanchored_pass_is_refused_by_this_check():
    """The negative specimen, so the sweep above cannot pass by finding nothing.

    Built as text rather than a file: the checks operate on document content,
    and writing a fixture into `docs/` would move the governed input digest --
    the exact defect this module exists to prevent.
    """
    forged = (
        "The evidence set is regenerated and `--verify` reports:\n\n"
        "```\nstatus                 pass\nintegrity_state        intact\n```\n"
    )
    blocks = _blocks(forged)
    assert len(blocks) == 1, "the specimen no longer parses as a transcript"
    _line, above, body = blocks[0]
    assert "[FALSE]" not in body
    assert TRANSCRIPT.search(body).group(1) == "intact"
    assert not ANCHOR.search(above), (
        "the unanchored specimen is being read as anchored, so the check that "
        "refuses it proves nothing"
    )


# --------------------------------------------------------------------------
# R4 -- the anchor verified ONE field and displayed sixteen.
#
# A review built an anchored block at a real, self-consistent commit carrying
# `collected 999999`, `independently reviewed YES, three signed attestations`
# and `authenticated_reviewers ["alice","bob","carol"]` alongside
# `integrity_state intact`, and BOTH enforcement tests admitted it. Only the
# governed_input_digest was ever checked; the rest was unverified prose inside
# a fence the convention made look verified.
#
# The same block was invisible if the `integrity_state` line was simply
# omitted, because that regex was the only thing making a fence a transcript.
#
# Two changes close it: recognition no longer hinges on one field name, and an
# anchored block may carry ONLY fields `--verify` actually emits. Anything a
# machine cannot recompute belongs outside the fence, where it reads as prose.
# --------------------------------------------------------------------------

#: Exactly what `--verify` emits, top level plus `verification`.
#: A real anchor, a real commit, fabricated payload.
_SPECIMEN_FORGED = (
    "<!-- verify-measured-at: 990caea -->" + chr(10) * 2
    + "```" + chr(10)
    + "status                       pass" + chr(10)
    + "integrity_state              intact" + chr(10)
    + "collected                    999999" + chr(10)
    + "authenticated_reviewers      alice, bob, carol" + chr(10)
    + "```" + chr(10)
)
_SPECIMEN_EVASIVE = (
    "```" + chr(10)
    + "status                       pass" + chr(10)
    + "governed_input_match         True" + chr(10)
    + "assurance_state              independently_inspected" + chr(10)
    + "```" + chr(10)
)


@pytest.mark.parametrize(
    "relative",
    [path.relative_to(ROOT).as_posix() for path in DOCUMENTS],
)
def test_r4_an_anchored_block_has_no_line_that_is_not_a_verifiable_field(
    relative: str,
):
    """INVERTED, because enumerating shapes has failed three rounds running.

    The sibling below extracts lines that parse as `key value` and checks the
    keys. That is a blacklist: a line the parser cannot read is simply absent
    from the result, so every unreadable spelling is admitted. Reviews walked
    six new spellings past it in one round -- leading `-`, `*`, `>`, `[`, a
    digit, and `key:value` with no space -- after the previous round had
    already widened it twice.

    So this asks the opposite question. Inside an anchored fence, every
    non-blank line must BE a verifiable field. Anything the parser cannot read
    is a defect by construction, whatever spelling it uses, including spellings
    nobody has thought of yet. That is what closing a class means, as opposed
    to adding shapes to an enumeration.
    """
    text = (ROOT / relative).read_text(encoding="utf-8")
    for line, above, body in _blocks(text):
        if not ANCHOR.search(above):
            continue
        parsed = _transcript_fields(body)
        unreadable = [
            raw.strip() for raw in body.splitlines()
            if raw.strip() and _FIELD_LINE.match(raw) is None
        ]
        assert unreadable == [], (
            f"{relative}:{line} is under a `verify-measured-at` anchor and "
            "carries lines that are not verifiable fields. Inside an anchored "
            "block every line is presented as measured, so a line a machine "
            f"cannot even parse cannot be one: {unreadable[:6]}"
        )
        assert parsed, (
            f"{relative}:{line} is anchored but carries no readable field at "
            "all, so the anchor vouches for nothing"
        )


@pytest.mark.parametrize(
    "relative",
    [path.relative_to(ROOT).as_posix() for path in DOCUMENTS],
)
def test_r4_an_anchored_block_carries_only_verifiable_fields(relative: str):
    """No field may sit inside a verified fence unless a machine can recheck it.

    `collected 999999` or a list of reviewer names cannot be recomputed from
    the anchor, so presenting them inside the block presents them as verified
    when nothing verifies them.
    """
    text = (ROOT / relative).read_text(encoding="utf-8")
    for line, above, body in _blocks(text):
        if not ANCHOR.search(above):
            continue
        unverifiable = sorted(
            key for key in _transcript_fields(body) if key not in VERIFIABLE_FIELDS
        )
        assert unverifiable == [], (
            f"{relative}:{line} presents {unverifiable} inside an anchored "
            "block, but `--verify` does not emit them, so nothing can check "
            "them at the anchored commit. Move them outside the fence."
        )


def test_r4_a_fabricated_field_inside_an_anchored_block_is_refused():
    """FG30. The counterexample a review used, pinned."""
    forged = _SPECIMEN_FORGED
    blocks = _blocks(forged)
    assert len(blocks) == 1, "the specimen no longer parses as a transcript"
    _line, _above, body = blocks[0]
    unverifiable = sorted(
        key for key in _transcript_fields(body) if key not in VERIFIABLE_FIELDS
    )
    assert "collected" in unverifiable, (
        "a fabricated census count inside an anchored block was accepted as a "
        "verified field"
    )


def test_r4_recognition_does_not_hinge_on_one_field_name():
    """Omitting `integrity_state` must not hide a transcript from the checks."""
    fields = _transcript_fields(_SPECIMEN_EVASIVE)
    assert {"status", "governed_input_match", "assurance_state"} <= set(fields), (
        "a block with no integrity_state line is invisible to field "
        "extraction, so dropping one line evades the convention entirely"
    )


def _verify_at(sha: str) -> dict:
    """Re-run `--verify` on an archived copy of the anchored commit.

    The anchor's whole point is that the numbers were true THERE. Checking the
    governed_input_digest alone left every other displayed field unverified, so
    this recomputes them at the commit rather than trusting the document.

    WHAT THIS RE-EXECUTION IS, precisely, because a review measured the gap
    between the description and the mechanism: the DATA is the commit's, and
    the ALGORITHM is the working tree's, because the editable install resolves
    `nornyx_forge` to the repository rather than to the extraction. So this
    detects a fabricated VALUE, which is what it exists for, and would not
    detect a change to the code that computes it. Recorded rather than implied.
    """
    import json  # noqa: PLC0415
    import shutil  # noqa: PLC0415
    import tarfile  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    work = Path(tempfile.mkdtemp(prefix=f"anchor-{sha}-"))
    try:
        bundle = work / "tree.tar"
        with bundle.open("wb") as handle:
            archived = subprocess.run(  # noqa: S603
                ["git", "archive", sha], cwd=ROOT,  # noqa: S607
                stdout=handle, stderr=subprocess.PIPE,
            )
        assert archived.returncode == 0, f"git archive {sha}: {archived.stderr[-200:]}"
        tree = work / "tree"
        tree.mkdir()
        with tarfile.open(bundle) as tar:
            tar.extractall(tree)  # noqa: S202

        # AN EXPLICIT ENVIRONMENT. With none, the child inherited
        # `FORGE_REVIEWER_TRUST_STORE` and `HOME`, and the assurance fields this
        # function re-verifies -- `assurance_state`, `independent`,
        # `authenticated_reviewers`, `required_inspectors_complete` -- are
        # derived from the reviewer store those name. A review changed one
        # variable and changed `--verify`'s assurance output in an unchanged
        # tree.
        #
        # `ASSURANCE_BOUNDARY.md` removed `FORGE_RUNTIME_AS_OF` on the ground
        # that an environment variable is ambient authority. This was the same
        # authority, still deciding, inside the function whose entire purpose is
        # to recompute a value instead of trusting one.
        #
        # The variables are dropped rather than pinned to a fixture: a store
        # supplied here would be this machine's answer too, just a tidier one.
        # Absent, the answer is the one the commit's own content produces.
        # AND THE HOME DIRECTORY, which is the half that was left in.
        #
        # Dropping `FORGE_*` and stopping there was measured to leave the
        # verdict a property of the reader's machine: `reviewer_store_path()`
        # falls back to `Path.home()/".nornyx"/...`, so a review signed three
        # attestations with its own keys, put the trust store in a home
        # directory it controlled, and got a document displaying
        # `independent True` and three named reviewers to pass -- while the
        # same document, same commit, failed for any other reader.
        #
        # A home-directory default is STRICTLY MORE AMBIENT than a variable:
        # at least a variable is visible in the process environment. The
        # comment here claimed that with `FORGE_*` gone "the answer is the one
        # the commit's own content produces". That is only true once every
        # ambient store resolution is severed, not one of them.
        # REDIRECTED, NOT REMOVED. Deleting `HOME`/`USERPROFILE` outright makes
        # `Path.home()` raise `RuntimeError: Could not determine home
        # directory`, so `--verify` produced no report at all and the anchored
        # checks failed for want of output rather than for want of truth.
        # Pointing them at an EMPTY directory severs the same authority and
        # leaves the tool able to run: both stores resolve, both find nothing,
        # and nothing about the answer depends on whose machine it is.
        empty_home = work / "no-home"
        empty_home.mkdir(exist_ok=True)
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("FORGE_")
        }
        environment.update({
            "HOME": str(empty_home),
            "USERPROFILE": str(empty_home),
            "HOMEDRIVE": empty_home.drive or "",
            "HOMEPATH": str(empty_home)[len(empty_home.drive):] or "\\",
            "PYTHONIOENCODING": "utf-8",
        })
        done = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=1800, env=environment,
        )
        start = done.stdout.find("{")
        assert start >= 0, (
            f"--verify produced no report at {sha}: {done.stdout[-300:]}"
            f"{done.stderr[-300:]}"
        )
        report = json.loads(done.stdout[start:])
        merged = dict(report.get("verification", {}))
        merged["status"] = report.get("status")
        return merged
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _anchored_blocks() -> list[tuple[str, int, str, str]]:
    """(document, line, sha, body) for every anchored transcript in docs/."""
    # CONTAINER-INDEPENDENT, like selection already is.
    #
    # This used `_blocks`, which knows backtick, four-backtick, tilde and
    # 4-space-indent. Measured: an anchored transcript claiming
    # `assurance_state independently_inspected` and `independent True` -- both
    # false at the anchored commit -- was NEVER FIELD-CHECKED when rendered as
    # tab-indented, blockquoted or bulleted. Only the fenced form was.
    #
    # `_transcript_runs` recognises all four, including the fenced one, so the
    # narrower recogniser is not needed here at all. This is the same defect as
    # the selection gate one level along: recognition was widened in one place
    # and the anchored path kept the old recogniser.
    found = []
    for path in DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for run in _transcript_runs(text):
            first = run[0][0]
            above = chr(10).join(lines[max(0, first - 12):first])
            anchor = ANCHOR.search(above)
            if not anchor:
                continue
            # A RECORD'S KEY IS AN IDENTIFIER, NOT A PHRASE.
            #
            # Without the fence to bound it, a run absorbs the prose that
            # follows: "...so nothing can recheck them at the anchored commit:
            # human approval ABSENT" parses as a key/value pair on the colon,
            # and was then compared against `--verify` output that of course
            # does not emit it. Two real documents failed that way.
            #
            # Requiring a single-token key restores the boundary WITHOUT
            # reintroducing a whitelist of known field names -- the shape that
            # let an invented key pass unseen elsewhere in this module. Every
            # field `--verify` emits is one token; no English clause is.
            records = [
                (key, value) for _n, key, value in run if not key.strip().count(" ")
            ]
            if len(records) < 2:
                continue
            body = chr(10).join(f"{key}  {value}" for key, value in records)
            found.append(
                (path.relative_to(ROOT).as_posix(), first, anchor.group(1), body)
            )
    return found


@pytest.mark.parametrize(
    ("relative", "line", "sha"),
    [(doc, line, sha) for doc, line, sha, _body in _anchored_blocks()],
    ids=[f"{doc.split('/')[-1]}:{line}@{sha}"
         for doc, line, sha, _b in _anchored_blocks()],
)
def test_r4_every_displayed_field_is_true_at_the_anchored_commit(
    relative: str, line: int, sha: str
):
    """Re-execute, do not trust. This is the half that makes the fence honest.

    Every field inside an anchored block is recomputed by running `--verify` on
    an archive of that commit and compared. A fabricated value cannot survive,
    because nothing here reads the document for its answer.
    """
    body = next(b for doc, ln, s, b in _anchored_blocks()
                if (doc, ln, s) == (relative, line, sha))
    # PAIRS, not the dict. Everything inside the fence is presented as
    # measured, so everything inside it is verified -- including a key that
    # appears twice, where the dict would answer for the last one only.
    displayed = _transcript_pairs(body)
    assert displayed, f"{relative}:{line} anchored block carries no fields"

    measured = _verify_at(sha)
    wrong = []
    for key, shown in displayed:
        actual = measured.get(key)
        text = shown.strip()
        if isinstance(actual, (list, tuple)):
            # A collection may be shown as itself or as its size: `problems 0`
            # and `problems []` are the same claim, and both are checkable.
            matches = text in {str(list(actual)), str(len(actual))}
        elif isinstance(actual, bool):
            matches = text.lower() == str(actual).lower()
        else:
            matches = text == str(actual)
        if not matches:
            wrong.append(
                f"{key}: document says {shown!r}, {sha} measures {actual!r}")
    assert wrong == [], (
        f"{relative}:{line} displays fields that are not true at {sha}: {wrong}"
    )


# --------------------------------------------------------------------------
# THE FORGERIES, KEPT.
#
# Each of these is a document a review actually built against this convention
# and got a green suite from. They are pinned for the same reason as the
# corpus in `test_documented_claims.py`: for five rounds the evidence that a
# hole was closed lived in a review report, and the next repair reopened it.
#
# Each test asserts the MECHANISM the forgery exploited, not the forged
# document as a whole -- driving a whole document would need it written into
# the tree, and a guard that only fires on files it can see is the shape being
# refused here.
# --------------------------------------------------------------------------

_TILDE = "~" * 3


def test_a_tilde_fence_is_not_invisible():
    """CommonMark has three code-block forms; this convention saw two.

    A review put a fabricated `--verify` transcript in a `~~~` fence. The
    document was never selected, never scanned, and appeared in no
    parametrisation: 57 passed while it asserted an independent inspection.
    """
    document = (
        "Running --verify on this tree today reports:" + chr(10) * 2
        + _TILDE + chr(10)
        + "status                       pass" + chr(10)
        + "integrity_state              intact" + chr(10)
        + "assurance_state              independently_inspected" + chr(10)
        + _TILDE + chr(10)
    )
    found = _blocks(document)
    assert found, (
        "a tilde-fenced transcript is invisible to `_blocks`, so every test in "
        "this module skips it silently -- no failure, just a document nobody "
        "looks at"
    )
    assert "integrity_state" in found[0][2]


def test_a_repeated_key_is_not_collapsed_to_its_last_value():
    """Everything inside an anchored fence is presented as measured.

    A review anchored a block at a real commit and wrote `status` twice: once
    with a fabricated sentence, once with the true value. `_transcript_fields`
    returns a dict, so only the second was re-verified while both were
    displayed, and the document passed -- including its own parametrised case.
    """
    body = (
        "status                       pass, independently inspected, granted"
        + chr(10) + "status                       pass" + chr(10)
    )
    pairs = _transcript_pairs(body)
    assert len(pairs) == 2, (
        f"the repeated key collapsed to {pairs}, so the occurrence a reader "
        "sees first is never compared against the re-executed value"
    )
    assert dict(pairs) != dict.fromkeys(["status"]), "sanity"
    assert [value for _key, value in pairs] == [
        "pass, independently inspected, granted", "pass"
    ]


def test_one_withdrawn_row_does_not_withdraw_the_claims_beside_it():
    """Documented per-line, implemented as a per-block substring test.

    A review marked `stale_artifacts` withdrawn and left
    `assurance_state independently_inspected` and
    `authenticated_reviewers alice, bob, carol` standing beside it. 56 passed.
    """
    forged = (
        "status                       pass" + chr(10)
        + "integrity_state              intact" + chr(10)
        + "stale_artifacts              [WITHDRAWN]" + chr(10)
        + "assurance_state              independently_inspected" + chr(10)
        + "authenticated_reviewers      alice, bob, carol" + chr(10)
    )
    asserting = _asserting_lines(forged)
    assert asserting, "no row was read as asserting anything; this measures nothing"
    withdrawn = all(
        "[FALSE]" in row or "[WITHDRAWN]" in row for row in asserting
    )
    assert not withdrawn, (
        "a block whose only withdrawn row is `stale_artifacts` counts as "
        "withdrawn, so the assurance claims beside it never need an anchor: "
        + repr([row.split()[0] for row in asserting])
    )


def test_a_block_that_withdraws_its_positive_rows_is_still_withdrawn():
    """The control, and the reason the rule is scoped rather than total.

    `TASK11_CLOSURE.md` marks its positive rows `[FALSE]` and leaves
    `independent False` and `authenticated_reviewers []` standing, because
    those remain TRUE. A rule demanding a marker on every field line would
    demand that a document withdraw a true statement -- and the only way to
    satisfy that is to delete the disclosure.
    """
    honest = (
        "status                    pass   [FALSE]" + chr(10)
        + "integrity_state           intact   [FALSE]" + chr(10)
        + "assurance_state           not_independently_inspected" + chr(10)
        + "independent               False" + chr(10)
        + "authenticated_reviewers   []" + chr(10)
    )
    asserting = _asserting_lines(honest)
    assert all(
        "[FALSE]" in row or "[WITHDRAWN]" in row for row in asserting
    ), (
        "an honest withdrawal is no longer recognised, so a document that "
        "correctly retracted its positive claims is now required to anchor "
        f"them: {[row.split()[0] for row in asserting]}"
    )


def test_prose_inside_an_anchored_block_is_not_a_verifiable_field():
    """The key pattern admits spaces, so the inversion needed a real separator.

    A review measured "The build was independently inspected by three parties"
    parsing as a field with key `The`, which left the inverted test -- every
    line inside an anchored block must BE a verifiable field -- with nothing to
    reject, while its docstring claimed to have closed the class.
    """
    rejected = (
        "The build was independently inspected by three parties",
        "This block was measured at the anchored commit and is true",
        "Nothing here is a field.",
    )
    for line in rejected:
        assert _FIELD_LINE.match(line) is None, (
            f"prose parses as a verifiable field: {line!r}"
        )
    accepted = (
        "evidence_manifest_match True",
        "authenticated_reviewers []",
        "Verified tree           990caea",
        "problems               []",
        "production_approval: granted",
    )
    for line in accepted:
        assert _FIELD_LINE.match(line) is not None, (
            f"a real transcript row no longer parses: {line!r}"
        )


@pytest.mark.parametrize(
    "relative",
    [path.relative_to(ROOT).as_posix() for path in DOCUMENTS],
)
def test_no_transcript_row_asserts_a_measurement_without_an_anchor(relative: str):
    """The rule, applied to every rendering and every field.

    The convention this module enforces is one sentence: a document may RECORD
    what `--verify` returned; it may not ASSERT what `--verify` returns. Until
    now that was enforced fence-by-fence over two of the thirteen fields, and a
    review built a document that satisfied every guard while publishing a
    fabricated PASS block, a human approval and three named reviewers.

    So the question is asked of CONTENT rather than of containers, and answered
    by INVERSION rather than by a vocabulary of ways to say yes. A row showing a
    field at anything other than an absent shape is a positive measurement, and
    it needs one of three things: an anchor naming the commit where it was
    measured, a withdrawal marker on that line, or a value that is the standing
    truth here.
    """
    text = (ROOT / relative).read_text(encoding="utf-8")
    offences = []
    for run in _transcript_runs(text):
        dishonest = _dishonest_rows(run)
        if not dishonest:
            continue
        first = run[0][0]
        above = chr(10).join(text.splitlines()[max(0, first - 12):first])
        if ANCHOR.search(above):
            continue
        for number, key, value in dishonest:
            line = text.splitlines()[number - 1]
            if "[FALSE]" in line or "[WITHDRAWN]" in line:
                continue
            offences.append(f"{relative}:{number} {key} = {value!r}")

    assert offences == [], (
        "these rows assert a measurement with no anchor above them and no "
        "withdrawal marker on them. Anchor the block to the commit you "
        "measured, mark the line [FALSE], or state the standing value: "
        + repr(offences[:8])
    )


def test_the_anchored_re_execution_does_not_depend_on_the_readers_machine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """The property C6-C6 is about, driven rather than argued.

    `reviewer_store_path()` falls back to `Path.home()/".nornyx"/...`, so a
    review signed three attestations with keys it generated, put the store in a
    home directory it controlled, and made a document displaying
    `independent True` and three named reviewers PASS on its machine and FAIL
    for every other reader. The repair severs both routes; this is what shows
    it worked.

    A HOME that carries a store is planted, and the re-execution must return
    the same fields it returns without one. If it does not, the anchored
    verdict is a property of whoever runs it.
    """
    import subprocess as _sp
    sha = _sp.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                  capture_output=True, text=True, timeout=600,
                  check=True).stdout.strip()
    baseline = _verify_at(sha)

    planted = tmp_path / "planted-home"
    (planted / ".nornyx").mkdir(parents=True)
    (planted / ".nornyx" / "forge_reviewer_trust.json").write_text(
        json.dumps({
            "schema": "nornyx.forge.reviewer_trust_store.v1",
            "reviewers": [{
                "key_id": "planted", "reviewer": "planted reviewer",
                "roles": ["security"], "public_key": "not a key", "status": "active",
            }],
        }),
        encoding="utf-8",
    )
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(planted))
    monkeypatch.setenv("FORGE_REVIEWER_TRUST_STORE",
                       str(planted / ".nornyx" / "forge_reviewer_trust.json"))

    planted_result = _verify_at(sha)

    # THE FIELDS THE EXPLOIT MOVED, compared exactly. `assurance_problems` is
    # deliberately not among them: its text embeds the resolved store path,
    # which is a fresh temp directory on every call, so comparing it would fail
    # for a reason that has nothing to do with authority. What matters is that
    # a planted store cannot make an inspection authenticate.
    decided_by_the_store = (
        "assurance_state", "independent", "authenticated_reviewers",
        "required_inspectors_complete",
    )
    for field in decided_by_the_store:
        assert planted_result.get(field) == baseline.get(field), (
            f"{field} changed from {baseline.get(field)!r} to "
            f"{planted_result.get(field)!r} when a reviewer trust store was "
            "planted in the environment and the home directory. An anchored "
            "document's verdict is then a property of the machine reading it "
            "rather than of the commit it names."
        )
    assert len(planted_result.get("assurance_problems", [])) == len(
        baseline.get("assurance_problems", [])
    ), "the planted store changed how many assurance problems were reported"


@pytest.mark.parametrize(
    ("rendering", "prefix"),
    [("fenced", None), ("tab-indented", chr(9)), ("blockquoted", "> "),
     ("bulleted", "- ")],
    ids=lambda v: v if isinstance(v, str) else "fence",
)
def test_r4_an_anchor_is_recognised_in_every_rendering(rendering, prefix):
    """R4: an anchored claim must be field-checked whatever encloses it.
    FG36: a verified anchor when only one rendering was ever read.

    MEASURED before this was fixed: `_anchored_blocks` used `_blocks`, which
    knows backtick, four-backtick, tilde and 4-space indent. An anchored
    transcript claiming `assurance_state independently_inspected` and
    `independent True` -- both FALSE at the anchored commit -- was never
    field-checked at all when rendered tab-indented, blockquoted or bulleted.
    Only the fenced form was.

    That is the selection defect one level along: recognition was widened in one
    place and the anchored path kept the narrow recogniser. The document a
    reader trusts most is the one carrying a commit SHA, and three of its four
    renderings were unchecked.
    """
    rows = [
        "status                 pass",
        "integrity_state        intact",
        "assurance_state        independently_inspected",
        "independent            True",
    ]
    if prefix is None:
        block = "```" + chr(10) + chr(10).join(rows) + chr(10) + "```"
    else:
        block = chr(10).join(prefix + row for row in rows)
    text = ("<!-- verify-measured-at: 341e177 -->" + chr(10) + chr(10) + block)

    runs = [run for run in _transcript_runs(text)
            if len([1 for _n, key, _v in run if not key.strip().count(" ")]) >= 2]
    assert runs, (
        f"{rendering}: an anchored transcript in this rendering produces no "
        "recognised run, so nothing about it is ever checked against the "
        "commit it names"
    )
    keys = {key for run in runs for _n, key, _v in run}
    assert "assurance_state" in keys and "independent" in keys, (
        f"{rendering}: the run was recognised but the claim rows were not "
        f"extracted from it: {sorted(keys)}"
    )
