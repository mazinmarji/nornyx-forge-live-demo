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

import pytest

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



#: Backticked code spans and quoted text, which a document MENTIONS rather
#: than ASSERTS. Blanked rather than removed so reported line numbers stay
#: true -- a guard that misreports where it found something teaches people to
#: distrust it.
#: INLINE spans only -- nothing spanning a newline. This paired the three
#: backticks of a ``` fence with the next fence's and blanked the ENTIRE BODY
#: of every fenced block. Transcripts live in fences, so the guard could not
#: see the claims that matter most: `assurance_state: independently_inspected`
#: inside a fence was invisible while the identical line outside one was
#: flagged. A review demonstrated it.
#: BACKTICK SPANS ONLY. The double-quote arm blanked every quoted string in
#: every document -- which is precisely the form this system EMITS:
#: {"assurance_state": "independently_inspected"} and "human_review":
#: "performed" are the spellings in all five evidence artifacts, and both
#: walked straight past the guard. A review put ten forged documents through
#: the real test and measured seven admitted, including those two, a
#: bold-emphasised claim, a YAML value and an ordinary quoted sentence.
#:
#: The arm was also NOT LOAD-BEARING: scanning every authored document with it
#: and without it both yield `offenders == []`. It was costing the guard its
#: reach and protecting nothing, so it is gone rather than narrowed.
_NEWLINE = chr(10)
_MENTION = re.compile("[`][^`" + _NEWLINE + "]*[`]")

#: THE SEPARATOR CROSSES A LINE BREAK. Every document here is hard-wrapped at
#: about 78 columns, so a claim landing on a wrap boundary was not matched by
#: a separator class of `[ _-]+` -- a review measured a wrapped prose claim
#: ADMITTED while the identical sentence on one line was caught. Wrapping is a
#: typesetting accident and must not decide whether a claim is visible.
_SEP = "[ _" + _NEWLINE + "-]+"

#: THE NEGATION IS NOT A LOOKBEHIND. Python lookbehinds are FIXED WIDTH, so
#: `(?<!not[ _-])` can see exactly one separator character. That was adequate
#: while a separator was one space; once the class crosses line breaks, a claim
#: hard-wrapped as "not" + newline + four spaces of indent puts FIVE characters
#: between the negation and the claim, the lookbehind sees only the indent, and
#: the HONEST sentence is reported as an overclaim.
#:
#: My own specimen caught this: adding the wrapped negation to the table turned
#: it red immediately. It is the same mistake the docstring below already
#: records -- widening the separator without widening the negation -- committed
#: a second time in a form the fixed-width construct cannot express at all.
#:
#: So the negation is a variable-width scan done in Python, over the text
#: immediately preceding a candidate. Same question, asked where the answer can
#: actually be computed.
_NEGATED_BEFORE = re.compile("not[ _" + _NEWLINE + "-]+$")


def find_overclaims(text: str) -> list:
    """Every claim in `text` that is not negated. ONE implementation.

    Both the live sweep and the specimen table call this. The specimen test
    used to re-declare the patterns in its own body -- a test that
    re-implements the thing it tests measures its own copy, which can stay
    correct while the live guard rots, green either way. That is the defect an
    independent review found in the false-green audit's own owners, so it is
    removed here rather than left to be found again.
    """
    scanned = _mention_blanked(text.lower())
    return [
        match
        for pattern in forbidden_claim_patterns()
        for match in pattern.finditer(scanned)
        if not _NEGATED_BEFORE.search(scanned[: match.start()])
    ]


def forbidden_claim_patterns() -> tuple:
    """The claim shapes themselves. Negation is applied by `find_overclaims`."""
    return (
        re.compile("writes" + _SEP + "independent" + _SEP + "review" + _SEP
                   + "evidence"),
        re.compile("independently" + _SEP + "inspected"),
        # THE SEPARATOR TOLERATES QUOTE CHARACTERS. In the form this system
        # actually emits -- {"human_review": "performed"} -- the key and value
        # are separated by quote, colon, space, quote. A class of `[ ]*[:=][ ]*`
        # matches none of that, so the exact JSON spelling in all five evidence
        # artifacts walked past while the prose form was caught.
        # CLAIMING TO PERFORM IT, which the three patterns above did not
        # cover. A document read "Claude Code performs requirements,
        # architecture, implementation, repair, and independent inspection" --
        # inside governance_docs(), matched by nothing. The verb is what makes
        # this a claim rather than a definition: ASSURANCE_BOUNDARY.md says
        # what independent inspection REQUIRES, which must stay sayable.
        re.compile("(?:performs|provides|carries" + _SEP + "out|delivers)"
                   + _SEP + "(?:[a-z,]+" + _SEP + "){0,8}independent"
                   + _SEP + "inspection"),
        re.compile("human" + _SEP + "review"
                   + "[ " + chr(34) + chr(39) + "]*[:=][ " + chr(34) + chr(39) + "]*"
                   + "performed"),
    )


def _mention_blanked(text: str) -> str:
    return _MENTION.sub(lambda m: " " * len(m.group(0)), text)

def test_no_document_claims_an_independent_inspection_this_repository_lacks():
    """`independently_inspected` is derived, and derives to false here.

    A document asserting otherwise would be the same defect as an artifact
    asserting it — a claim about assurance from something that cannot establish
    it — just written in English.
    """
    # Patterns, not exact strings. The review defeated the previous list by
    # dropping a trailing word: "independently inspected by" was forbidden,
    # "independently inspected and fully assured" was not.
    # SEPARATORS, not just whitespace. These used `\s`, which does not match
    # `_` -- so `independently_inspected` and `human_review: performed`, the
    # exact spellings this system EMITS in every transcript and report block,
    # walked past a guard whose docstring claimed it had generalised beyond
    # exact strings. It had generalised to prose and not to the machine form.
    offenders: list[str] = []
    for document in governance_docs():
        name = document.relative_to(ROOT).as_posix()
        # USE, NOT MENTION. Code spans and quotations are blanked (length
        # preserved, so line numbers stay true). ASSURANCE_BOUNDARY.md has a
        # section DEFINING what `assurance_state: independently_inspected`
        # requires -- that is the term being explained, not the repository
        # claiming to hold it, and the same structural rule already separates
        # a retracted CrewAI claim from a live one.
        raw = document.read_text(encoding="utf-8")
        for match in find_overclaims(raw):
            line = raw[: match.start()].lower().count(chr(10)) + 1
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


def test_the_request_digest_covers_exactly_what_the_comment_says():
    """A comment claiming coverage it does not have is worse than no comment.

    `ActionRequest` documented `subject_scope_id` and `governed_revision_digest`
    as "both covered by the request digest, so a grant cannot be re-aimed at a
    different scope or a different assurance state". An independent review
    measured it: neither field is in `canonical()`, and two requests differing
    only in those two produce identical digests.

    The property does hold, by `subject_revision` -- which IS signed, IS
    compared, and is the `governed_subject_digest` embedding the scope id and
    scope definition digest. Measured here rather than described, because the
    previous description was written by someone who believed it.
    """
    from nornyx_forge.nornyx_runtime import ActionDescriptor, canonical_action_request

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:probe",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    base = canonical_action_request(
        mission_id="CASE-PROBE",
        risk="high",
        subject_revision="sha256:" + "a" * 64,
        descriptor=descriptor,
    )
    relabelled = canonical_action_request(
        mission_id="CASE-PROBE",
        risk="high",
        subject_revision="sha256:" + "a" * 64,
        descriptor=descriptor,
    )
    object.__setattr__(relabelled, "subject_scope_id", "scope.WIDE_OPEN")
    object.__setattr__(relabelled, "governed_revision_digest", "sha256:unassured")

    assert relabelled.digest == base.digest, (
        "these fields are now covered by the digest -- update the ActionRequest "
        "comment, which says they are not"
    )

    moved = canonical_action_request(
        mission_id="CASE-PROBE",
        risk="high",
        subject_revision="sha256:" + "b" * 64,
        descriptor=descriptor,
    )
    assert moved.digest != base.digest, (
        "subject_revision is what actually binds a grant to a subject, and it "
        "no longer moves the digest"
    )


def test_ci_shell_propagates_pipeline_failure():
    """A piped assurance command must not be able to report a false green.

    GitHub's IMPLICIT shell for `run:` is `bash -e`, which does NOT set
    pipefail. `pytest ... | tail -3` therefore reports `tail`'s status, and a
    failing suite leaves the step green.

    Measured in this repository, not imagined: a commit was made over a red
    suite because `pytest ... | tail -3 && git commit` saw success. The
    displayed output looked correct; the displayed output was never the measured
    exit state -- which is the whole Task-14 finding, in a shell.

    Declaring `shell: bash` explicitly is what enables `-eo pipefail`.
    """
    import yaml  # noqa: PLC0415

    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    shell = (workflow.get("defaults") or {}).get("run", {}).get("shell")
    assert shell == "bash", (
        "CI does not declare `defaults.run.shell: bash`, so steps run under "
        "`bash -e` without pipefail and a piped assurance command can mask the "
        f"failure of the command that matters (found shell={shell!r})"
    )


#: Every way a Python process can start another process. `os.system` and the
#: `spawn` family are included even though nothing uses them today: the claim
#: this pins is "these are ALL the places", so the detector has to look for
#: routes the code does not currently take.
PROCESS_STARTERS = (
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "os.system", "os.popen", "os.exec", "os.spawn", "os.posix_spawn",
)


def test_the_process_start_sites_match_the_documented_list():
    """`docs/ARCHITECTURE.md` stakes a security claim on an enumeration.

    "the list of places this system can start a process short enough to read"
    is only worth reading if it is complete. It was not: it named five modules
    and the code had seven, omitting `nornyx_cli_adapter` (which invokes the
    governance authority) and `subject_observer` (which invokes `git`, behind
    revision binding). A reader auditing process execution would have checked
    five call sites and missed the two nearest the trust boundary.

    Asserted in BOTH directions. A list that is merely a superset can be padded
    with modules that start nothing, which reads as thoroughness while making
    the claim weaker.
    """
    measured = {
        path.stem
        for path in (ROOT / "src").rglob("*.py")
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
        and any(starter in line for starter in PROCESS_STARTERS)
    }

    text = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
    sentence = re.search(
        r"the list\s*\n?of places this system can start a process[^:]*:(.*?)\.\s*\n",
        text, re.S,
    )
    assert sentence, (
        "the sentence enumerating process-start sites is gone from "
        "docs/ARCHITECTURE.md -- if the claim was withdrawn, delete this test "
        "deliberately rather than letting it pass by finding nothing"
    )
    documented = set(re.findall(r"`([a-z_]+)`", sentence.group(1)))

    assert documented == measured, (
        "docs/ARCHITECTURE.md and the code disagree about where a process can "
        f"start.\n  documented but starts nothing: {sorted(documented - measured)}"
        f"\n  starts a process, undocumented: {sorted(measured - documented)}"
    )


#: (label, text, must be flagged). The machine spellings are the ones that
#: matter: this system emits `independently_inspected`, never the prose form,
#: and the guard used `\s` which does not match `_`.
OVERCLAIM_SPECIMENS = [
    ("machine spelling, bare claim", "assurance_state: independently_inspected", True),
    ("prose spelling, bare claim", "this build was independently inspected", True),
    ("machine spelling, honest negative", "not_independently_inspected", False),
    ("prose spelling, honest negative", "not independently inspected", False),
    ("definitional, inside a code span",
     "`assurance_state: independently_inspected` is derived, never read", False),
    ("human review, machine spelling", "human_review: performed", True),
    ("human review, honest", "human_review: not_performed", False),
    # THE FORMS A REVIEW GOT PAST THIS GUARD. Each was measured admitted by the
    # real test, decided by exit code rather than by reading the pattern. The
    # first two are the spelling every evidence artifact in this repository
    # uses, and the third is how every document here is typeset.
    ("json object, the form all five evidence files use",
     '{"assurance_state": "independently_inspected"}', True),
    ("json human_review: quote, colon, space, quote",
     '{"human_review": "performed"}', True),
    ("hard-wrapped across a line break, as every document here is",
     "the build is independently" + chr(10) + "    inspected by three parties", True),
    ("bold emphasis around the claim", "**independently inspected**", True),
    ("an ordinary quoted sentence, which used to be blanked wholesale",
     'the report says "this build is independently inspected" today', True),
    # And the negations in the same widened forms, so extending the reach did
    # not cost the guard its honesty about the values this system really emits.
    ("hard-wrapped honest negative",
     "the state is not" + chr(10) + "    independently inspected", False),
    ("json honest negative", '{"human_review": "not_performed"}', False),
]


@pytest.mark.parametrize(
    ("label", "text", "flagged"),
    OVERCLAIM_SPECIMENS,
    ids=[case[0] for case in OVERCLAIM_SPECIMENS],
)
def test_the_overclaim_guard_reads_machine_spellings_and_respects_mention(
    label: str, text: str, flagged: bool
):
    """Both directions, including the two the guard used to miss entirely.

    Widening the separator alone flagged ten TRUTHFUL lines, because the
    negative lookbehind still expected a space -- so `not_independently_inspected`,
    the honest value, read as a claim. Widening the negation without widening
    the separator would have left the original hole. Both are pinned here.
    """
    # THE REAL IMPLEMENTATION, not a copy of it. This re-declared its own pair
    # of patterns, so it could have gone on passing while the live sweep used
    # something else entirely -- a specimen that measures itself.
    hit = bool(find_overclaims(text))
    assert hit is flagged, f"{label}: flagged={hit}, expected {flagged}"


def test_the_success_criteria_name_exactly_the_accepted_diagnostics():
    """C3-P3-6: CLAUDE.md restates a set the gate owns, and nothing bound them.

    The criterion in CLAUDE.md lists the diagnostics an autonomous run may
    leave outstanding. That list is a COPY of
    `check_pre_approval_baseline.EXPECTED_PRE_APPROVAL_DIAGNOSTICS`, and a copy
    with no test is a copy that drifts -- which has already happened once here,
    when the document listed three codes against a gate that accepts five and
    the criterion was, read literally, false at every head.

    The document says the script is authoritative. This makes that true rather
    than merely asserted: the codes the gate accepts and the codes the document
    names must be the same set, in both directions. A code added to the gate
    and not to the document silently widens what a run may leave behind; a code
    in the document and not in the gate promises tolerance the gate will not
    give.

    Codes only. The gate matches `(code, path, source_id)` triples, and the
    document deliberately names just the code -- a reader is being told which
    absences are expected, not where each one surfaces. That narrowing is the
    document's business; drifting apart is not.
    """
    import sys  # noqa: PLC0415

    sys.path.insert(0, str(ROOT / "scripts"))
    from check_pre_approval_baseline import (  # noqa: PLC0415
        EXPECTED_PRE_APPROVAL_DIAGNOSTICS,
    )

    accepted = {code for code, _path, _source in EXPECTED_PRE_APPROVAL_DIAGNOSTICS}
    text = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")

    # BOTH DIRECTIONS READ THE ENUMERATION, not the document. Scanning the
    # whole file made the first direction unfalsifiable: every one of these
    # codes is also DISCUSSED in the prose below the list, so deleting one from
    # the list left the prose mention behind and the check still passed. I
    # measured exactly that -- struck a code from the enumeration and the
    # comparison reported nothing missing. A mention is not an entry.
    marker = "`scripts/check_pre_approval_baseline.py` accepts:"
    assert marker in text, (
        "the success criteria no longer enumerate the accepted diagnostics "
        "under the sentence this test locates them by"
    )
    after = text[text.index(marker) + len(marker):]
    enumeration = after[: after.index(chr(10) * 2, after.index("A"))]
    listed = set(re.findall("[A-Z][A-Z_]{6,}", enumeration))

    missing = sorted(accepted - listed)
    assert missing == [], (
        "the success criteria do not name these diagnostics the gate accepts, "
        f"so a run could leave one behind and still read as compliant: {missing}"
    )

    # The other direction, scoped to THE ENUMERATION rather than to the whole
    # document. My first attempt scanned every uppercase token in CLAUDE.md and
    # flagged RUNTIME_LOCK_MISSING -- which the document mentions in a
    # different criterion, describing the `load_error` a clean checkout shows,
    # and does not offer as an accepted outstanding diagnostic at all. A guard
    # that reads a mention as a claim is the defect two modules here already
    # exist to prevent; it does not get a pass for being mine.
    overpromised = sorted(listed - accepted)
    assert overpromised == [], (
        "the success criteria name diagnostics the pre-approval gate does NOT "
        f"accept, so the criterion promises tolerance that does not exist: "
        f"{overpromised}"
    )
