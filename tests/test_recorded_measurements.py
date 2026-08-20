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
_FIELD_LINE = re.compile(
    "^" + _GAP + "*(" + _KEY + ")" + _GAP + "*[:=]?" + _GAP + "+("
    + "[^ " + chr(9) + "].*)$"
)


def _transcript_fields(body: str) -> dict:
    """Every `key   value` line in a fenced block."""
    found = {}
    for line in body.splitlines():
        match = _FIELD_LINE.match(line)
        if match:
            found[match.group(1)] = match.group(2).strip()
    return found


#: A fenced block, OR an indented one. Markdown has two code-block forms and
#: this convention only ever saw the first. A review presented the same
#: fabricated transcript as a 4-space indented block and `_blocks` returned
#: nothing at all -- the document was never selected, never scanned, and every
#: R4 test passed. Not hypothetical: `LENS_C_CLOSURE.md` carries its own
#: headline verification status in exactly that form, and the convention had
#: never seen it.
_BLOCK = (
    "```[^" + chr(10) + "]*" + chr(10) + "(.*?)```"
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


def _blocks(text: str) -> list[tuple[int, str, str]]:
    """Fenced blocks containing a `--verify` transcript, with the text above."""
    found = []
    for match in re.finditer(_BLOCK, text, re.S):
        body = match.group(1) if match.group(1) is not None else match.group(2)
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
    return bool(ANCHOR.search(text) or _blocks(text))


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
        withdrawn = "[FALSE]" in body or "[WITHDRAWN]" in body
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
    """The counterexample a review used, pinned."""
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

        done = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=1800,
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
    found = []
    for path in DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        for line, above, body in _blocks(text):
            anchor = ANCHOR.search(above)
            if anchor:
                found.append(
                    (path.relative_to(ROOT).as_posix(), line, anchor.group(1), body)
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
    displayed = _transcript_fields(body)
    assert displayed, f"{relative}:{line} anchored block carries no fields"

    measured = _verify_at(sha)
    wrong = []
    for key, shown in displayed.items():
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
