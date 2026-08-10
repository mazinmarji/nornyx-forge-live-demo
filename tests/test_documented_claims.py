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

def governance_docs() -> list[Path]:
    """Every markdown document in the repository, discovered rather than listed.

    This was a hardcoded five-tuple. An independent review added a new file
    under `docs/` containing a pinned commit and both forbidden phrases, and all
    three tests passed: a document that did not exist when the list was written
    escaped the module entirely. A list of documents to check is a list of
    documents an author must remember to extend, and the ones that get forgotten
    are the new ones.

    Discovery instead. Vendored and generated trees are excluded because nobody
    authored their claims here.
    """
    root = Path(__file__).resolve().parents[1]
    skip = {".venv", "node_modules", ".git", ".nornyx", "evidence", "site-packages"}
    return sorted(
        path
        for path in root.rglob("*.md")
        if not any(part in skip for part in path.relative_to(root).parts)
    )


#: Retained for the required-module registration and for tests that want the
#: historically-scanned core; every scan below uses `governance_docs()`.
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
    for document in governance_docs():
        name = document.relative_to(ROOT).as_posix()
        for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
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
    # Patterns, not exact strings. The review defeated the previous list by
    # dropping a trailing word: "independently inspected by" was forbidden,
    # "independently inspected and fully assured" was not.
    forbidden = (
        re.compile(r"writes\s+independent\s+review\s+evidence"),
        re.compile(r"(?<!not )independently\s+inspected"),
        re.compile(r"human\s+review\s*[:=]\s*performed"),
    )
    offenders: list[str] = []
    for document in governance_docs():
        name = document.relative_to(ROOT).as_posix()
        text = document.read_text(encoding="utf-8").lower()
        for pattern in forbidden:
            for match in pattern.finditer(text):
                line = text[: match.start()].count(chr(10)) + 1
                offenders.append(f"{name}:{line} {match.group(0)!r}")

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


# --------------------------------------------------------------------------
# The documents a reviewer reads must be inside what a reviewer signs
# --------------------------------------------------------------------------


def test_there_is_one_definition_of_governed_input():
    """Two lists that must agree cannot be allowed to disagree.

    `refresh_governance_evidence` carried its own GOVERNED_INPUT_PATHS naming
    `docs`, `.nornyx/contracts` and `CLAUDE.md`, documented as "paths whose
    content a human approval actually covers". Every digest read the *other*
    list, in `governed_subject`, which named none of them. The list that looked
    like the tool's own definition bound nothing, and the one that bound
    everything did not look authoritative.

    Identity, not equality: equal copies would satisfy a value comparison the
    moment someone edited one of them back.
    """
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_governance_evidence as evidence_tool  # noqa: PLC0415

    from nornyx_forge.governed_subject import GOVERNED_INPUT_PATHS

    # NOT equality. These are two concepts, and merging them is a regression:
    # the dirty-tree gate must see `.nornyx/contracts` so that editing a contract
    # under a pinned approval refuses, while the input digest must NOT, because
    # settled contracts are output and folding them in would make the input
    # depend on something derived from it.
    #
    # I merged them once, on the strength of the shared name, and silently
    # removed contract coverage from the dirty-tree gate. What this asserts is
    # that the wider list is built FROM the narrower one, so they cannot drift
    # apart, and that the one thing that distinguishes them is still there.
    assert set(GOVERNED_INPUT_PATHS) <= set(evidence_tool.APPROVAL_COVERED_PATHS), (
        "the dirty-tree gate no longer covers everything the input digest does"
    )
    assert ".nornyx/contracts" in evidence_tool.APPROVAL_COVERED_PATHS, (
        "editing a settled contract under a pinned approval would not be refused"
    )
    assert ".nornyx/contracts" not in GOVERNED_INPUT_PATHS, (
        "settled contracts are output; folding them into the input digest makes "
        "the input depend on something derived from it"
    )


def test_the_claims_documents_are_inside_the_governed_input():
    """A reviewer signs a subject digest; it must cover what they read.

    `--verify` reported `intact` while documentation, `.dockerignore`, and
    `CLAUDE.md` were edited freely, so a signed `inspection_subject_digest` did
    not cover the documents making the claims being inspected. The pointed case
    was commit 13844c7 -- "Stop the documentation asserting things the system
    stopped doing" -- which changed README.md and ASSUMPTIONS.md, and was
    structurally unbindable by the evidence chain that exists to bind what was
    reviewed.

    `.dockerignore` is here for a different reason: it decides what enters the
    runtime image, so it is authority-relevant in the most direct sense.
    """
    from nornyx_forge.governed_subject import GOVERNED_INPUT_PATHS

    for required in ("docs", "CLAUDE.md", ".dockerignore"):
        assert required in GOVERNED_INPUT_PATHS, (
            f"{required} is outside the governed input digest, so an inspection "
            "does not cover it"
        )


def test_editing_a_claims_document_moves_the_governed_input_digest():
    """Behaviour, not membership. A list entry that changes no digest is decor."""
    import shutil
    import tempfile

    from nornyx_forge.governed_subject import REPOSITORY_SCOPE
    from nornyx_forge.subject_observer import observe_input_manifest

    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(
        ROOT,
        work,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", "*.pyc", "*.egg-info", "evidence"
        ),
    )
    before = observe_input_manifest(work, REPOSITORY_SCOPE)

    target = work / "docs/ASSURANCE_BOUNDARY.md"
    marker = (chr(10) + '<!-- probe -->' + chr(10)).encode('utf-8')
    target.write_bytes(target.read_bytes() + marker)
    after = observe_input_manifest(work, REPOSITORY_SCOPE)

    assert after != before, (
        "editing a claims document left the governed input unchanged, so an "
        "inspection signed over it covers nothing it says"
    )
