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


def _blocks(text: str) -> list[tuple[int, str, str]]:
    """Fenced blocks containing a `--verify` transcript, with the text above."""
    found = []
    for match in re.finditer(r"```[^\n]*\n(.*?)```", text, re.S):
        body = match.group(1)
        if not TRANSCRIPT.search(body):
            continue
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, text[max(0, match.start() - 400):match.start()], body))
    return found


DOCUMENTS = sorted(
    path for path in (ROOT / "docs").rglob("*.md")
    if TRANSCRIPT.search(path.read_text(encoding="utf-8"))
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
        state = TRANSCRIPT.search(body).group(1)
        withdrawn = "[FALSE]" in body or state != "intact"
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
