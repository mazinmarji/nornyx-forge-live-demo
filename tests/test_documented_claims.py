"""What the documentation asserts must be what the system does.

Two claims had gone stale without failing anything.

`ASSUMPTIONS.md` opened with `Run subject revision: git:8a8fea6a...` — a commit
hash pinned in a document, superseded by the next commit and by R1's removal of
commit identity as authority. A small instance of exactly why A-011 was
superseded: a document cannot name the revision it is part of.

`README.md` said the session "writes independent review evidence". After R2 that
is not what happens: an independent inspection requires an attestation signed by
a reviewer who is not the builder. What the session records is a self-reported
observation.

Prose is where a system's claims outlive its behaviour, because nothing executes
prose. These are the claims specific enough to check.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Documents making claims about authority or assurance.
GOVERNANCE_DOCS = (
    "README.md",
    "docs/ASSURANCE_BOUNDARY.md",
    "docs/ARCHITECTURE.md",
    "docs/requirements/ASSUMPTIONS.md",
    "docs/governance/RUNTIME_INPUT_AUDIT.md",
)

#: A 40-hex git object id, the shape that goes stale silently.
COMMIT_LITERAL = re.compile(r"git:[0-9a-f]{40}")


def test_no_governance_document_pins_a_commit_as_the_subject():
    """Identity is content. A commit named in prose is a claim that decays.

    Fixture and example hashes elsewhere are fine — this is about a document
    asserting which revision the repository *is*.
    """
    offenders: list[str] = []
    for name in GOVERNANCE_DOCS:
        for number, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
            if not COMMIT_LITERAL.search(line):
                continue
            lowered = line.lower()
            # A document may *discuss* a commit — A-002 records a placeholder
            # revision that was corrected, and deleting that history to satisfy
            # a regex would lose the reasoning. What it must not do is pin one
            # as the revision this repository currently is.
            if any(
                word in lowered
                for word in (
                    "fixture",
                    "example",
                    "superseded",
                    "tag",
                    "does not correspond",
                    "was bound to",
                    "stale",
                )
            ):
                continue
            offenders.append(f"{name}:{number}")

    assert offenders == [], (
        "a document names a commit as the subject; identity is the governed "
        "content digest, and a hash in prose is stale on the next commit: "
        + ", ".join(offenders)
    )


def test_no_document_claims_an_independent_inspection_this_repository_lacks():
    """`independently_inspected` is derived, and derives to false here.

    A document asserting otherwise would be the same defect as an artifact
    asserting it — a claim about assurance from something that cannot establish
    it — just written in English.
    """
    forbidden = ("writes independent review evidence", "independently inspected by")
    offenders: list[str] = []
    for name in GOVERNANCE_DOCS:
        text = (ROOT / name).read_text(encoding="utf-8").lower()
        for phrase in forbidden:
            if phrase in text:
                offenders.append(f"{name}: {phrase!r}")

    assert offenders == [], (
        "documentation claims an independent inspection that no authenticated "
        "attestation supports: " + ", ".join(offenders)
    )


def test_the_assurance_boundary_still_states_what_is_not_established():
    """The disclaimers are load-bearing; a tidy-up must not quietly drop them."""
    text = (ROOT / "docs/ASSURANCE_BOUNDARY.md").read_text(encoding="utf-8").lower()
    for required in (
        "not_independently_inspected",
        "human review",
        "reviewer keys are not approver keys",
    ):
        assert required in text, f"the assurance boundary no longer states {required!r}"
