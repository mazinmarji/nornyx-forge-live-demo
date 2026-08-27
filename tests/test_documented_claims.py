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

def _discovered_docs() -> list[Path]:
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
    # EXCLUDED BY LOCATION, NOT BY A NAME THAT MAY APPEAR ANYWHERE. This
    # skipped any path with a COMPONENT called `evidence`, so a review created
    # `docs/evidence/REPORT.md` -- asserting "This build has been independently
    # inspected", `human_review: performed`, `production_approval: granted` --
    # and measured it discovered: False, find_overclaims: 3 hits, 52 passed.
    # An author making a `docs/evidence/` directory is doing nothing unusual.
    #
    # FG27 again, and shared: the transcript module imports this helper, so the
    # hole was in both sweeps at once.
    #
    # Vendored trees keep component matching because they genuinely nest
    # (`node_modules` inside a package).
    #
    # `.nornyx/` IS EXCLUDED FOR TWO DIFFERENT REASONS, and this comment used
    # to give one. `.nornyx/contracts/evidence/*.json` is GENERATED, so nobody
    # authored its claims here. `.nornyx/contracts/*.nyx` is HAND-AUTHORED and
    # is the governance source of truth -- a different case entirely, and one
    # this sentence silently covered.
    #
    # It stays excluded, and the reason is measured rather than asserted: the
    # contracts are a STRUCTURED surface defended by content-hash binding, not
    # by wording. Running the prose sweep over them produces eleven hits and
    # every one is a field VALUE -- `status: authorized` six times,
    # `require_evidence_independence: true` -- not a claim anyone made in
    # prose. A sweep that reports a contract field as an overclaim is matching
    # text and calling it meaning, which is the substitution this module
    # exists to refuse.
    #
    # `test_the_excluded_contracts_are_covered_by_hash_binding` checks that the
    # defence actually applies, so the exclusion rests on a measured fact.
    vendored = {".venv", "node_modules", ".git", "site-packages", "__pycache__"}
    generated = (".nornyx/",)
    found = []
    # CASE-INSENSITIVE, AND DELIBERATELY SO. `rglob("*.md")` is
    # case-insensitive on Windows and case-sensitive on the Linux runner, so a
    # document named `REPORT.MD` is scanned on the author's machine and
    # invisible in CI -- the corpus would differ between the place a claim is
    # written and the place it is checked. Zero such files exist today, which
    # makes this a latent scope gap rather than a live one; it is closed here
    # because "no such file exists right now" is not a property.
    for path in root.rglob("*"):
        if path.suffix.lower() not in {".md", ".markdown", ".mdown"}:
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in vendored for part in path.relative_to(root).parts):
            continue
        if relative.startswith(generated):
            continue
        found.append(path)
    return sorted(found)


#: A document that declares the single commit it assessed.
#:
#: `**Target commit:** <sha>` is the header the G2 sponsor self-assessments
#: carry. A document that names the commit it looked at is EVIDENCE ABOUT
#: THAT COMMIT, not a statement of what this repository currently claims --
#: which is the whole subject of the guards below.
_ASSESSED_COMMIT = re.compile(
    r"^\s*\*{0,2}Target commit:?\*{0,2}\s*:?\s*[`\"]?([0-9a-f]{7,40})",
    re.MULTILINE | re.IGNORECASE,
)

#: A document that declares itself a method rather than a measurement.
_METHODOLOGY_ONLY = re.compile(
    r"^\s*\*{0,2}Implementation status:?\*{0,2}\s*:?\s*Methodology only\b",
    re.MULTILINE | re.IGNORECASE,
)


def classify_document(text: str) -> str:
    """`current_claim`, `historical_assessment`, or `methodology`.

    DECIDED FROM THE DOCUMENT'S OWN DECLARATION, never from its path or its
    name. A file called `docs/assessments/ANYTHING.md` that does not declare
    a target commit is a CURRENT claim surface and is scanned like any other;
    a file anywhere that does declare one is evidence about that commit. This
    is the same rule the runtime observer uses for artifacts -- keying on the
    filename was AC01, and it was committed once already while repairing AC01.

    The word `assessment` decides nothing. Neither does the directory. Only
    the declaration does, and
    `test_assessment_language_alone_does_not_leave_the_claim_surface` proves
    it: a document full of assessment vocabulary, under an assessments path,
    is still classified `current_claim` without the header.
    """
    if _ASSESSED_COMMIT.search(text):
        return "historical_assessment"
    if _METHODOLOGY_ONLY.search(text):
        return "methodology"
    return "current_claim"


def governance_docs() -> list[Path]:
    """The CURRENT Forge governance-claim surface.

    Every guard reached through this helper asks the same kind of question:
    what does this repository claim about itself NOW -- which revision it
    is, whether it has been independently inspected, what its runtime does,
    what its measurements say. A document that declares the commit it
    assessed, or declares itself a methodology rather than a measurement,
    is not answering that question and cannot be read as though it were.

    NOT A DOCUMENTATION EXEMPTION. The classification is `classify_document`,
    which reads the declaration and nothing else, so an ordinary governance
    document cannot leave this surface by being moved, renamed, or written
    in assessment vocabulary. The claim rules themselves are unchanged: what
    narrows is WHICH DOCUMENTS ARE ASKED, not what counts as a violation.

    Introduced when the hardened baseline was integrated with main, which
    brought in SHA-bound G2 sponsor self-assessments and an assessment
    methodology. Three attempts to make those documents satisfy the
    current-claim guards each failed against a stricter adjacent rule; the
    collision is structural, because `_normalised` deliberately strips
    presentation and a dated assessment is written in the same shapes a
    live report uses.
    """
    return [
        path for path in _discovered_docs()
        if classify_document(path.read_text(encoding="utf-8")) == "current_claim"
    ]


def authored_docs() -> list[Path]:
    """Every authored markdown document, whatever it declares."""
    return _discovered_docs()


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
#:
#: THE PREFIX IS OPTIONAL, because the prefix was never the concept. This read
#: `git:[0-9a-f]{40}`, and a review wrote the identical pinning line without
#: those four characters -- "Run subject revision: bb5db12f...22c0" -- and
#: measured 24 passed, where the same line WITH `git:` gives 1 failed. The
#: historical incident this guard cites (`ASSUMPTIONS.md` opening with a pinned
#: revision) recurs verbatim minus the prefix.
#:
#: NOT SPELLED WITH A WORD-BOUNDARY ESCAPE, AND THAT IS THE WHOLE POINT.
#:
#: In the author's intent this line read `[word-boundary](?:git:)?[0-9a-f]{40}
#: [word-boundary]`. In the FILE it held two literal U+0008 BACKSPACE bytes,
#: written by a tool that turned the escape into the character it names. It is
#: a raw string, so nothing put the boundary back. No document contains a
#: backspace, so the pattern MATCHED NOTHING, EVER, and
#: `test_no_governance_document_pins_a_commit_as_the_subject` passed over all
#: 40 documents by finding zero of everything -- including the two real 40-hex
#: ids sitting in ASSUMPTIONS.md.
#:
#: An inert pattern is a guard that cannot fail, and it reads exactly like one
#: that works. Two things changed. The bound is written with LOOKAROUNDS, which
#: contain no backslash escape for a tool to eat. And
#: `test_the_commit_pin_rule_fires_and_stops_where_it_says` now requires this pattern to fire on
#: a specimen, so an inert successor is red rather than reassuring.
#:
#: The bound still does what the old comment claimed: a 64-hex sha256 is not
#: matched on its first 40 characters, because the character after them is hex.
COMMIT_LITERAL = re.compile(r"(?<![0-9a-f])(?:git:)?[0-9a-f]{40}(?![0-9a-f])")


#: Where one sentence ends and the next begins, for exemption scoping.
_SENTENCE_EDGES = (". ", "." + chr(10), "! ", "? ", chr(10) * 2,
                   chr(10) + "- ", chr(10) + "#")


def _sentence_around(text: str, index: int) -> str:
    """The sentence containing `index`, spanning line breaks.

    Markdown wraps prose at whatever column the author left it at, so the
    physical line is not the unit the exemption is about. This walks out to
    the nearest sentence edge in each direction instead.
    """
    before = max(text.rfind(edge, 0, index) for edge in _SENTENCE_EDGES)
    after = [position for position in
             (text.find(edge, index) for edge in _SENTENCE_EDGES)
             if position != -1]
    return text[(before + 1) if before != -1 else 0:
                (min(after) + 1) if after else len(text)]


def _cited_guards() -> dict:
    """Every backticked `test_...` in tracked text, by name -> where."""
    import subprocess  # noqa: PLC0415

    listing = subprocess.run(  # noqa: S603
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
        check=True, encoding="utf-8", errors="replace",
    )
    cited: dict = {}
    # SPLIT ON NEWLINES, not whitespace: a tracked path containing a
    # space was fragmented into two names that resolve to nothing, so
    # the scan silently skipped the file it was meant to read.
    for name in listing.stdout.splitlines():
        path = ROOT / name
        if path.suffix not in {".py", ".md", ".nyx", ".json", ".toml",
                               ".yml", ".yaml", ".cfg", ".ini", ".txt"}:
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        # ACROSS A LINE BREAK, and case-sensitively complete. The pattern was
        # `` `(test_[a-z0-9_]+)` `` on one line: three real citations are
        # wrapped by markdown and were invisible to it, and six defined tests
        # carry uppercase letters (`test_A_an_action_only_principal...`) so a
        # document citing one would be neither resolved nor flagged. All nine
        # resolve today, which is exactly why they were latent.
        for match in re.finditer(
            # `\s` already matches a newline, so one class covers the
            # wrap. Written without an explicit escape for the newline
            # itself: a tool along the way turns that escape into the
            # character it names, which is how a pattern in this very
            # module came to match nothing at all.
            r"`(test_[A-Za-z0-9_]+(?:\s+[A-Za-z0-9_]+)?)`", text
        ):
            line = text.count(chr(10), 0, match.start()) + 1
            wrapped = "".join(match.group(1).split())
            cited.setdefault(wrapped, []).append(f"{name}:{line}")
    return cited


def _defined_guards() -> set:
    """Every test function the suite actually defines."""
    found: set = set()
    for module in sorted((ROOT / "tests").glob("test_*.py")):
        found.update(re.findall(
            r"^def (test_[A-Za-z0-9_]+)\(", module.read_text(encoding="utf-8"),
            re.MULTILINE,
        ))
    return found


def test_every_guard_the_repository_cites_by_name_exists():
    """A citation nobody can resolve reads as assurance and carries none.

    THIS CHECK ALREADY EXISTED AND READ ONE FILE. It was written for the census
    script, scoped to `scripts/check_test_coverage.py`, and correct there. Run
    across the repository it found thirteen names that resolve to nothing --
    including a comment in PRODUCTION source (`approval_trust.py`) whose whole
    argument for admitting the one hole in subject binding was "this hole is
    NAMED and TESTED by two guards", where the second name existed nowhere; a
    test docstring deferring a security property to a guard that was never
    written, contradicted by a correct note 28 lines below it in the same file;
    and a citation this very module had written twenty minutes earlier under a
    name that was changed before the test was committed.

    That last one is the argument for the check. The names are not wrong because
    anyone was careless with them -- they are wrong because a name in prose has
    nothing holding it to the thing it names, and only a machine reading every
    one of them can keep the two together.

    Seven of the thirteen were MODULES cited by their bare stem. Those are now
    written as paths, which is unambiguous and cannot collide with a function.

    THERE IS NO EXCEPTION LIST, on purpose. The first draft had one, for names
    the repository deliberately records as DEAD -- and an exception list is a
    way to make this guard green by growing it rather than by fixing anything.
    The convention does the same work with nothing to abuse: backticks around a
    `test_...` name mean IT RESOLVES. A name being recorded as dead is written
    plainly, without them, which is also how it reads: as history, not as a
    guard someone can go and look at.
    """
    defined = _defined_guards()
    unresolved = {
        name: where for name, where in _cited_guards().items()
        if name not in defined
    }
    assert unresolved == {}, (
        "these guard names are cited in tracked content and defined nowhere "
        "in tests/. If a MODULE was meant, cite it as a path. If the guard was "
        "renamed, cite the new name. If the name is DEAD and you are recording "
        "that it died, write it WITHOUT backticks -- in this repository "
        "backticks around a `test_...` name mean it resolves, and that is the "
        f"whole convention this guard enforces: {unresolved}"
    )


def commit_pins(text: str) -> list:
    """Line numbers where `text` pins a commit as the subject.

    EXTRACTED so the specimen tables below exercise THIS rule rather than a
    copy of it. A specimen table that tests a reimplementation proves the
    reimplementation.
    """
    found = []
    for match in COMMIT_LITERAL.finditer(text):
        number = text.count(chr(10), 0, match.start()) + 1
        # SCOPED TO THE SENTENCE, NOT THE LINE.
        #
        # A line break in markdown is a wrapping artifact, not a unit of
        # meaning, and the exemption is about what the prose SAYS. Measured
        # when this was line-scoped: ASSUMPTIONS.md wrote "which does not
        # correspond to any commit in this repository (`HEAD` is <sha>)"
        # across two lines, so the qualifying clause sat on line 26 and the
        # id on line 27 -- a sentence saying explicitly that the id is NOT
        # this repository, reported as pinning it. Re-wrapping the paragraph
        # would have silenced it, which is the tell that the line was never
        # the right unit.
        #
        # A document may *discuss* a commit: A-002 records a placeholder
        # revision that was corrected, and deleting that history to satisfy
        # a regex would lose the reasoning. What it must not do is pin one
        # as the revision this repository currently is.
        # WHITESPACE COLLAPSED, for the same reason the window spans lines:
        # `does not correspond` is a phrase, and markdown will wrap it
        # between any two of its words. A phrase that stops matching
        # because the paragraph was re-flowed is not a rule about prose.
        lowered = " ".join(_sentence_around(text, match.start()).lower().split())
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
                # A document saying a commit FAILED makes the opposite
                # claim to the one this guard refuses. Kept as a PHRASE:
                # single words like "tag" are cheap to sprinkle by
                # accident, a phrase has to be meant.
                "failed pre-candidate",
            )
        ):
            continue
        found.append(number)


    return found


#: (document text, the line numbers `commit_pins` must report).
#:
#: THE GUARD THIS TABLE DEFENDS WAS INERT FOR ITS ENTIRE LIFE. `COMMIT_LITERAL`
#: held two literal U+0008 BACKSPACE bytes where a word-boundary escape was
#: meant, so it matched nothing in any document and the guard passed over all
#: 40 of them by finding zero of everything. Nothing noticed, because a guard
#: that never fires is indistinguishable from a guard with nothing to report.
COMMIT_PIN_SPECIMENS = [
    # CAUGHT: the historical incident, with and without the prefix.
    ("Run subject revision: git:" + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + ".", [1]),
    ("Run subject revision: " + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + ".", [1]),
    ("This repository is `" + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + "`.", [1]),

    # NOT A COMMIT ID: a 64-hex digest must not match on its first 40.
    ("The governed input digests to sha256:" + 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' + ".", []),
    ("No identifier of any kind appears in this sentence.", []),

    # EXEMPT, and each for a reason stated in the exemption vocabulary.
    ("The contracts were bound to `git:" + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + "`, which does not" + chr(10)
     + "correspond to any commit here (`HEAD` is `" + 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' + "`).", []),
    ("`" + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + "` is a failed pre-candidate head, not a candidate.", []),

    # THE CONTROL THAT KEEPS SENTENCE SCOPING FROM BECOMING PARAGRAPH SCOPING.
    # An exemption word in a NEIGHBOURING sentence must not exempt this one.
    ("The subject revision is `" + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + "`. Stale hashes are discussed" + chr(10)
     + "in the appendix.", [1]),
    ("Fixtures are listed below. The repository is `" + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + "`.", [2 - 1]),
]


@pytest.mark.parametrize(("document", "expected"), COMMIT_PIN_SPECIMENS)
def test_the_commit_pin_rule_fires_and_stops_where_it_says(document, expected):
    """A pattern that matches nothing reads exactly like one with nothing to say.

    Both directions are here on purpose. The catches prove the pattern is not
    inert; the exemptions prove it has not been widened into silence; and the
    two neighbouring-sentence cases prove the scoping fix did not turn the
    exemption into "any paragraph mentioning a stale hash is fine".
    """
    assert commit_pins(document) == expected, (
        "the commit-pin rule reported " + repr(commit_pins(document))
        + " for this specimen, expected " + repr(expected) + ": " + repr(document)
    )


#: Characters that are invisible in an editor and change what code means.
#:
#: THE RULE USED TO BE "byte < 32", and that is one range out of several. The
#: historical defect was U+0008 inside a regex, and every character below does
#: the same thing to a raw string -- the pattern silently stops matching, the
#: file looks identical, and the guard reports nothing forever.
#:
#: Measured against the rule as written, with planted specimens:
#:
#:     U+0008 BACKSPACE   caught      the one that actually happened
#:     U+007F DELETE      MISSED
#:     U+0085 NEL         MISSED      a C1 control
#:     U+200B ZWSP        MISSED
#:     U+00A0 NBSP        MISSED
#:     U+202E RTL OVERRIDE MISSED
#:
#: NBSP and ZWSP are the likeliest of all of them: they are what survives a
#: copy-paste through a rendered document, which is exactly how an invisible
#: character reaches a source file in practice.
#:
#: TAB and LF are absent because they are legitimate. CR is present because the
#: governed-content digest is canonical-LF and a stray CR changes it.
INVISIBLE_CHARACTERS = {
    chr(0x00): "NUL", chr(0x07): "BEL", chr(0x08): "BACKSPACE",
    chr(0x0B): "VERTICAL TAB", chr(0x0C): "FORM FEED", chr(0x0D): "CARRIAGE RETURN",
    chr(0x1B): "ESCAPE", chr(0x7F): "DELETE",
    chr(0x85): "NEXT LINE (C1)", chr(0x8D): "REVERSE LINE FEED (C1)",
    chr(0xA0): "NO-BREAK SPACE", chr(0xAD): "SOFT HYPHEN",
    chr(0x200B): "ZERO WIDTH SPACE", chr(0x200C): "ZERO WIDTH NON-JOINER",
    chr(0x200D): "ZERO WIDTH JOINER", chr(0x2028): "LINE SEPARATOR",
    chr(0x2029): "PARAGRAPH SEPARATOR",
    chr(0x202A): "LEFT-TO-RIGHT EMBEDDING",
    chr(0x202B): "RIGHT-TO-LEFT EMBEDDING",
    chr(0x202D): "LEFT-TO-RIGHT OVERRIDE",
    chr(0x202E): "RIGHT-TO-LEFT OVERRIDE",
    chr(0xFEFF): "ZERO WIDTH NO-BREAK SPACE",
}


@pytest.mark.parametrize(
    ("label", "character"),
    sorted((why, char) for char, why in INVISIBLE_CHARACTERS.items()),
)
def test_every_invisible_character_in_the_table_is_actually_detected(
    label: str, character: str, tmp_path: Path,
):
    """The rule and its table cannot drift apart.

    A table naming twenty-two characters and a scan checking one byte range is
    how the previous version read: complete in prose, one range in code.
    """
    # NO NEWLINE TRANSLATION IN EITHER DIRECTION. `write_text` on Windows
    # turns LF into CRLF and `read_text` turns it back, which plants extra
    # carriage returns and then hides them -- so the CR specimen measured the
    # platform rather than the rule. The production scan reads BYTES and
    # decodes, so this has to as well.
    planted = tmp_path / "specimen.md"
    planted.write_bytes(("before" + character + "after" + chr(10)).encode("utf-8"))
    text = planted.read_bytes().decode("utf-8")
    found = [
        ord(inner) for inner in text if inner in INVISIBLE_CHARACTERS
    ]
    assert found == [ord(character)], (
        label + " is in the table and the scan does not find it"
    )


def test_the_characters_a_source_file_needs_are_not_refused():
    """TAB, LF and ordinary text must never be flagged.

    Over-strictness here fails every file in the repository, which is the one
    way this guard could be worse than absent.
    """
    for legitimate in (chr(9), chr(10), " ", "a", "-", chr(0x2014), chr(0x00E9)):
        assert legitimate not in INVISIBLE_CHARACTERS, repr(legitimate)


def test_no_tracked_text_file_carries_an_injected_control_character():
    """U+0008 in a regex is how the guard above came to match nothing.

    The escape was written correctly and a tool along the way turned it into the
    character it names. In a raw string nothing puts it back, and the result is
    syntactically valid, visually identical in most editors, and semantically
    dead. That is the worst possible failure mode for a guard.

    So no tracked text file may carry one. TAB and LF are the only control
    characters with a legitimate place in this repository's sources; CR is
    excluded too, because the governed-content digest is canonical-LF and a
    stray CR changes it.
    """
    import subprocess  # noqa: PLC0415

    listing = subprocess.run(  # noqa: S603
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
        check=True, encoding="utf-8", errors="replace",
    )
    offenders = []
    # SPLIT ON NEWLINES, not whitespace: a tracked path containing a
    # space was fragmented into two names that resolve to nothing, so
    # the scan silently skipped the file it was meant to read.
    for name in listing.stdout.splitlines():
        path = ROOT / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue  # genuinely binary; not a text file this rule is about
        for index, character in enumerate(text):
            if character not in INVISIBLE_CHARACTERS:
                continue
            line = text.count(chr(10), 0, index) + 1
            offenders.append(
                f"{name}:{line} U+{ord(character):04X} "
                f"({INVISIBLE_CHARACTERS[character]})"
            )
    assert offenders == [], (
        "a tracked text file carries a control character that no editor shows "
        "and no reviewer sees. In a regex this makes the pattern inert; in "
        f"governed content it changes the digest: {offenders}"
    )


def test_no_governance_document_pins_a_commit_as_the_subject():
    """Identity is content. A commit named in prose is a claim that decays.

    Fixture and example hashes elsewhere are fine — this is about a document
    asserting which revision the repository *is*.
    """
    offenders: list[str] = []
    for document in governance_docs():
        name = document.relative_to(ROOT).as_posix()
        text = document.read_text(encoding="utf-8")
        offenders += [f"{name}:{number}" for number in commit_pins(text)]

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


#: A quoted TERM is a mention. A quoted SENTENCE is not.
#:
#: Blanking every double-quoted span is exactly the arm removed above, after a
#: review measured an ordinary quoted sentence carrying a forgery past the
#: guard. The distinction that survives is length: naming a concept takes a few
#: words, asserting one takes a sentence. Three words, so
#: `"independent inspection"` in a section heading is a mention and
#: `"This repository has been independently inspected"` is not.
_QUOTED_TERM = re.compile('"[^"' + _NEWLINE + ']{1,40}"')


def _mention_blanked(text: str) -> str:
    def blank(match):
        # THE WORDS GO, THE SENTENCE STRUCTURE STAYS.
        #
        # Blanking replaced every character with a space, including the `;`
        # that ends a record. Measured on `FAILED_REVIEW_45f858c.md:68`, where
        # two records share a line:
        #
        #     `rows in consumed_approvals = 0`; `ledger.available=True`
        #
        # With the semicolon blanked, `consumed_approvals`' value ran on into
        # the NEXT record and picked up its `True` -- so an honest disclosure
        # of ZERO rows was read as a claim. `_BOUNDARY` already treats `;` as
        # a clause break; the blanker was destroying the evidence it needs.
        #
        # Only `;` is preserved. A `.` would be wrong to keep blindly --
        # `ledger.available` carries one mid-token -- and `_BOUNDARY` only
        # honours a period followed by whitespace anyway.
        return "".join(
            character if character == ";" else " "
            for character in match.group(0)
        )

    def term(match):
        inner = match.group(0).strip(chr(34)).split()
        # A SINGLE quoted word is a JSON token, not a mention. Blanking those
        # erased `"human_review"` and `"performed"` and stopped the guard
        # reading the JSON form that all five evidence files use -- measured
        # immediately, by two cases already in the table below.
        #
        # And a multi-word span carrying an affirmative is a quoted CLAIM, not
        # a term: `"production approval granted"` names nothing, it asserts.
        if not 2 <= len(inner) <= 3:
            return match.group(0)
        if any(word.lower() in _AFFIRMATIVE for word in inner):
            return match.group(0)
        if any(part in word.lower() for word in inner for part in _PARTICIPLES):
            return match.group(0)
        return blank(match)

    def span(match):
        """A backtick span is bounded exactly as a quoted one is.

        `_QUOTED_TERM` was deliberately bounded after a review measured a
        quoted SENTENCE carrying a forgery through -- "A quoted TERM is a
        mention. A quoted SENTENCE is not." The backtick arm never got that
        bound, so ANY length of text between two backticks was a mention.

        Measured on the surfaces that matter:

            `.claude-plugin/plugin.json` description, the text a marketplace
            listing shows a reader, carrying "This release has been
            independently inspected; production approval granted and human
            review performed."   -> backticked: PASSED. Unbackticked, the same
            sentence: FAILED with 4 offenders.

            The same sentence as a <p> above the dashboard metric tiles:
            3 operator-surface guards, all PASSED.

        Backticks render as literal characters in JSON metadata and as inline
        code in HTML and markdown. The claim reaches the reader intact. This is
        the class already repaired here for `I` escapes, reached by a
        different mechanism.
        """
        inner = match.group(0).strip(chr(96)).split()
        # A bare identifier is a token, not an assertion: `human_review`,
        # `assurance_state`, `--no-baseline`. Blanking those is what lets the
        # definitional sections of ASSURANCE_BOUNDARY.md name a field without
        # being read as claiming it.
        if len(inner) == 1:
            return blank(match)
        if len(inner) > 3:
            return match.group(0)
        # AN IDENTIFIER IS NOT AN ENGLISH WORD. `independently_inspected` is
        # the VALUE this system emits, and the definitional sections of
        # ASSURANCE_BOUNDARY.md name it to explain what it would require.
        # Reading its embedded `inspected` as an English participle flagged the
        # definition -- measured, `assurance_state: independently_inspected`
        # went from admitted to flagged on the first version of this rule.
        # Underscored words are excluded from the English tests for that
        # reason; a claim spelled without underscores is still prose.
        english = [word for word in inner if "_" not in word]
        if any(word.lower() in _AFFIRMATIVE for word in english):
            return match.group(0)
        if any(part in word.lower() for word in english for part in _PARTICIPLES):
            return match.group(0)
        return blank(match)

    text = _MENTION.sub(span, text)
    return _QUOTED_TERM.sub(term, text)


def forbidden_claim_patterns() -> tuple:
    """Retained for the specimen table; the live decision is `find_overclaims`.

    These four shapes are what the guard used to BE. A review measured them
    admitting 9 of 14 assertion spellings -- passive voice, past tense, other
    verbs, the noun-plus-colon form, and the space-aligned `human_review
    performed` layout that every `--verify` fence in this repository emits.
    """
    return (
        re.compile("writes" + _SEP + "independent" + _SEP + "review" + _SEP
                   + "evidence"),
        re.compile("independently" + _SEP + "inspected"),
        re.compile("(?:performs|provides|carries" + _SEP + "out|delivers)"
                   + _SEP + "(?:[a-z,]+" + _SEP + "){0,8}independent"
                   + _SEP + "inspection"),
        re.compile("human" + _SEP + "review"
                   + "[ " + chr(34) + chr(39) + "]*[:=][ " + chr(34) + chr(39) + "]*"
                   + "performed"),
    )


#: The MACHINE fields whose affirmative value is an assurance claim on its own.
from claim_vocabulary import (  # noqa: E402
    ABSENT_SHAPES as _ABSENT_SHAPES,
)
from claim_vocabulary import (  # noqa: E402
    ASSURANCE_FIELDS,
    is_a_claim,
)
from claim_vocabulary import (  # noqa: E402
    ASSURANCE_ROOTS as _ASSURANCE_ROOTS,
)
from claim_vocabulary import (  # noqa: E402
    VERDICT_VALUES as _VERDICT_VALUES,
)


def _clause_text(lowered: str, tokens: list, clauses: list, index: int) -> str:
    """The raw text of the clause a token sits in, for punctuation questions."""
    same = [position for position, clause in enumerate(clauses)
            if clause == clauses[index]]
    if not same:
        return ""
    start = tokens[same[0]][1]
    last = tokens[same[-1]]
    return lowered[start: last[1] + len(last[0]) + 2]

#: THE SUBJECT VOCABULARY IS DERIVED. It used to be the four literals below and
#: nothing else, and a review measured ELEVEN of the thirteen field names this
#: system actually emits walking through at their affirmative value --
#: including `production_approval: approved`, the field's own root, admitted
#: because `approved` was in the participle list while the participle test was
#: applied to the SUBJECT token and never to the VALUE.
#:
#: `CLAIM_FIELDS` is NOT folded in here, and that is deliberate. It is consumed
#: by the MACHINE-ROW branch in `find_overclaims`, which requires an identifier
#: or a recognisable value after the field name. Adding the bare field names to
#: this set instead made ordinary prose a claim -- "The status of the review is
#: recorded elsewhere" was flagged, because `status` became a subject and `is`
#: an affirmative. A field name in a sentence is a word; a field name in a row
#: is a measurement.
#: THE SUBJECT VOCABULARY IS DERIVED NOW; THIS SET IS THE REMAINDER.
#:
#: `_names_an_assurance_concept` derives the subject from `ASSURANCE_ROOTS` by
#: HEAD NOUN. These four stay because their head noun carries no root at all.
#:
#: WHAT THIS CLOSED, measured on eleven ordinary English approval sentences
#: whose verdicts were already in the affirmative vocabulary and were never
#: ASKED for want of a subject:
#:
#:     claims caught      2 / 11  ->  10 / 11
#:     honest misflagged  0 / 15  ->   0 / 15
#:     shipped corpus     green   ->  green
#:
#: Eight mechanisms, each derived rather than enumerated: the subject from the
#: roots by head noun; `audit` and `certif` completing that root set; the
#: participle from the roots including the two-word `signed off` form; a
#: COPULA separated from a verdict (a copula asserts EXISTENCE, a claim
#: asserts COMPLETION) and possession separated from both; ATTRIBUTIVE
#: participles excluded by the closed class of English function words;
#: an assurance noun that ACTED read as an actor by adjacency; the prose guard
#: no longer judging FENCED machine transcripts, which this module already
#: said was the transcript rule's domain; and each string literal in a
#: structured file made its own CLAUSE, which closed a real leak where a
#: verdict in one JSON value completed a claim whose subject sat in another.
#:
#: TWO GRAMMATICAL BOUNDS, both measured on stored commit subjects in
#: `EVIDENCE_BINDING_BASELINE.json`, which are imperative by convention: a
#: clause that OPENS with its verb has no subject, so the assurance noun after
#: it is an OBJECT; and `being <participle>` is a passive gerund naming a
#: CAPACITY, not a completed act.
#:
#: THE ONE REMAINING GAP, stated rather than closed: "cleared for production
#: deployment by the CAB" is still ADMITTED. It contains no assurance
#: vocabulary at all -- `cleared`, `production`, `deployment`, `CAB` -- so the
#: verdict has no subject to attach to. Closing it means deciding which nouns
#: denote governance authorities, which is the unbounded enumeration this
#: whole repair exists to escape. 10 of 11, and the eleventh is named.

_SUBJECT_FIELDS = frozenset({
    "human_review", "production_approval", "assurance_state",
    # `attested` was named in the docstring below as a subject word and was
    # NOT in this set. It was caught only incidentally, by the loose
    # self-affirmation rule that also flagged "Independent inspection ... has
    # never been performed"; tightening that rule dropped "Attested by three
    # independent inspectors" -- a claim the operator dashboard was publishing.
    # A vocabulary the docstring describes and the set omits is the same
    # substitution of prose for a measured criterion this module exists to
    # refuse.
    "attested",
})


def _stem(word: str) -> str:
    """The stem of a regular past participle."""
    if word.endswith("ied"):
        return word[:-3] + "y"
    return word[:-2] if word.endswith("ed") else word


def _names_an_assurance_concept(word: str, after: str = "") -> bool:
    """Is this word ABOUT assurance -- derived from the roots, not listed.

    THE ENUMERATION HAD MOVED FROM THE PREDICATES TO THE SUBJECTS. The value
    vocabulary was derived by inversion and this set stayed four literals, so
    a review measured NINE of eleven ordinary English approval sentences
    admitted -- not because their verdicts were unknown, but because the
    verdict is never ASKED for want of a subject. `approved`, `signed off`,
    `certified` and `established` were already in the affirmative vocabulary.

    THE HEAD NOUN, which is the question the sibling rule asks. Matching the
    root anywhere in the identifier reintroduces a defect already recorded and
    closed here: `assurance_moved` and `trusted_approvers_loaded` become
    subjects, and both are MECHANISM -- they are named by `moved` and `loaded`.

    The two-word form is reached through `after`: English attaches the
    particle to the stem, so `signed off` is one concept spelled as two
    tokens, and `sign_off` is how this repository spells the root.
    """
    if word in _SUBJECT_FIELDS:
        return True
    head_noun = word.rsplit("_", 1)[-1]
    if any(root in head_noun for root in _ASSURANCE_ROOTS):
        return True
    return bool(after) and (_stem(word) + "_" + after) in _ASSURANCE_ROOTS

#: "INDEPENDENT REVIEW" IS NOT THE CLAIM; "INDEPENDENT INSPECTION" IS.
#:
#: My first concept-matching version treated any `independent*` as a subject
#: and flagged six real documents. One was a genuine finding; five were
#: sentences like "an independent review found two defects in the criteria" --
#: narrative about a REVIEWER, which is true, must stay sayable, and is not a
#: claim about this repository's assurance state.
#:
#: The formal term `docs/ASSURANCE_BOUNDARY.md` defines is independent
#: INSPECTION, and the derived field is `independently_inspected`. So the claim
#: is `independent*` qualified by `inspect*` -- which still catches "has been
#: independently reviewed and inspected", and still admits "an independent
#: review measured X".
#:
#: Widening a guard until it flags truthful sentences is not a stronger guard.
#: It is the same defect pointing the other way, and the pressure it creates on
#: an author is to delete the disclosure.
_QUALIFIER = ("inspect",)

#: PEOPLE, not states. `independent inspectors` describes who someone is;
#: `independent inspection` describes something that happened. A real document
#: saying "read-only AI inspectors that are independent of the builder" was
#: flagged as an assurance claim because `inspectors` satisfied the nearby
#: inspection test. The dashboard claim "Attested by three independent
#: inspectors" is still caught -- through `attested`, which is both a subject
#: word and a completed participle -- so excluding agents costs no reach.
_AGENTS = frozenset({"inspector", "inspectors", "reviewer", "reviewers",
                     "auditor", "auditors"})

#: Words that make a nearby assurance word a CLAIM rather than a description.
_AFFIRMATIVE = frozenset({
    "performed", "completed", "complete", "granted", "authorized", "authorised",
    "done", "passed", "satisfied", "obtained", "achieved", "true", "yes",
    "conducted", "conducts", "conduct", "carried", "provided", "delivered",
    "established", "assured",
    "hold",
})

#: A COPULA IS NOT A VERDICT. With the subject derived, these turned every
#: mechanism sentence about assurance into a claim: "Human review is
#: required before any production deployment", "The audit trail is written
#: to the evidence directory". A copula asserts that something EXISTS or is
#: DISCUSSED; an assurance claim asserts an act was COMPLETED.
_COPULA = frozenset({"is", "was", "were", "are"})

#: POSSESSION IS DIFFERENT FROM PREDICATION. "We hold a valid production
#: approval" asserts that this repository HAS one, which is a claim; "the
#: review is recorded elsewhere" is not.
_POSSESSION = frozenset({"holds", "hold", "have", "has"})

#: Values a table cell or an adjective carries, not prose verdicts.
_CELL_VALUES = frozenset({"true", "yes"})

_AFFIRMATIVE = _AFFIRMATIVE | _COPULA | _POSSESSION

#: Words that make it NOT a claim: a negation, an unmet condition, or a
#: definition of what the thing WOULD require.
_DISCLAIMING = frozenset({
    "no", "not", "never", "without", "cannot", "lacks", "lacking", "absent",
    "absence", "missing", "unavailable", "would", "requires", "require",
    "required", "needs", "need", "means", "if", "unless", "until", "yet",
    "false", "none", "nothing", "neither", "nor", "non", "pending", "blocked",
    "outstanding", "must", "should", "before", "not_performed", "not_granted",
    "not_independently_inspected", "unverified", "claims", "claim", "claimed",
    "forbids", "refuses", "refused", "retracted", "withdrawn", "cannot",
    # CONDITIONAL, TEMPORAL AND FUTURE FRAMES. A review measured eight of nine
    # truthful or harmless sentences refused for want of these -- "Once
    # production_approval is granted, the dashboard row changes", "A
    # human_review will be performed before any production release". An author
    # documenting the bar had one narrow permitted vocabulary, which this
    # module's own docstring calls worse than a missed claim.
    "when", "once", "after", "where", "will", "whether", "becomes", "become",
    "shall", "may", "might", "could", "upon",
    # `scheduled` IS THE SAME FRAME IN THE VALUE SLOT. "Human review:
    # scheduled" says the review has NOT happened, and it was refused
    # while "A human_review WILL be performed" -- the identical claim
    # about the identical future -- was admitted, because one spelling
    # was here and the other was not.
    "scheduled",
    # RETRACTION AND PAST NARRATIVE, completing classes already open here.
    # `retracted` and `withdrawn` were members and `removed` was not, so a
    # document describing a defect it had DELETED still read as asserting
    # it: "described has been **removed**: a review proved it could revive
    # an expired ...". `means` was a member and `meant` was not, so a
    # narrative about a PAST defect -- "which meant the builder certified
    # their own independence in a file" -- read as a certification.
    #
    # A tense is not a different kind of statement, and neither is a
    # synonym its own class. `says` is deliberately NOT here: this module
    # has a RECORDED decision that quoting a claim publishes it.
    "removed", "meant",
})

#: Past participles that carry a COMPLETED state in themselves, so
#: `independently <participle>` needs no separate verb. A noun -- `inspection`,
#: `review` -- does not, and treating it as though it did is what flagged an
#: honest disclosure.
_PARTICIPLES = ("inspected", "reviewed", "audited", "attested", "verified",
                "approved", "certified")


#: THE CLOSED CLASS OF ENGLISH FUNCTION WORDS, used to tell a PREDICATIVE
#: participle from an ATTRIBUTIVE one. `approved` in "reported as approved
#: content" modifies `content` and asserts nothing about this release;
#: `approved` in "approved by the Change Advisory Board" IS the assertion.
#: English marks the difference by what FOLLOWS: a bare noun means modifier, a
#: function word or the end of the clause means predicate. Measured, without
#: this the derived rule flagged honest lines across the tree -- "reported as
#: approved content", "from the approved requirements", "the bundled certified
#: foundation" -- every one a noun phrase naming a mechanism this repository
#: does have. A closed class in the language, not a list of spellings.
_FUNCTION_WORDS = frozenset({
    "the", "a", "an", "this", "that", "these", "those", "its", "their",
    "his", "her", "our", "your", "my", "no", "any", "all", "both", "each",
    "by", "for", "in", "on", "at", "to", "of", "with", "from", "under",
    "over", "after", "before", "as", "into", "per", "via", "within",
    "without", "against", "between", "during", "since", "until", "upon",
    "and", "or", "but", "nor", "so", "yet", "if", "unless", "when",
    "while", "because", "though", "although", "whether",
    "is", "was", "were", "are", "be", "been", "being", "has", "have",
    "had", "will", "would", "can", "could", "may", "might", "must",
    "shall", "should", "do", "does", "did", "not", "never",
    "off", "out", "up", "down", "here", "there", "then", "now",
})


def _completed_act(word: str, after: str) -> bool:
    """A completed assurance act: an assurance root carrying a participle.

    DERIVED FROM THE ROOTS, not listed beside them. The seven literals above
    are the participles of seven roots, and the list drifted from the set it
    shadows: `assured` and `authorised` are completed acts by the same reading
    and were absent, while `signed off` -- whose root `sign_off` IS in the set
    -- had no participle at all, so "signed off by three inspectors outside the
    build team" was admitted with a subject present and a verdict present.
    """
    if not word.endswith("ed"):
        return False
    joined = bool(after) and (_stem(word) + "_" + after) in _ASSURANCE_ROOTS
    if not (any(root in word for root in _ASSURANCE_ROOTS) or joined):
        return False
    # PREDICATIVE, NOT ATTRIBUTIVE. The two-word form is predicative by
    # construction: its particle IS the following token.
    return joined or not after or after in _FUNCTION_WORDS

#: How far apart the two halves of a claim may sit and still be one claim.
_WINDOW = 10


#: Where one claim stops and the next begins. A disclaimer on the far side of
#: one of these does not modify what precedes it.
#:
#: `.` is a boundary ONLY at end of sentence -- followed by whitespace or the
#: end of the text -- because a bare `.` also sits inside `nornyx.forge`, and
#: splitting there would let a disclaimer in an unrelated earlier sentence stop
#: suppressing a claim it genuinely modifies.
#:
#: `|` is deliberately NOT a boundary. Markdown table cells are how this
#: repository writes its honest disclosures ("| Human review | not performed
#: |"), and splitting on the pipe would separate every subject from its own
#: negation and flag the disclosure table wholesale -- the exact false positive
#: this change exists to remove.
#: A SINGLE newline is NOT a boundary, and treating it as one was measured
#: wrong immediately: hard-wrapped prose puts "has not been" at the end of
#: one line and "performed" at the start of the next, so every wrapped
#: honest disclosure lost its own negation and 13 real documents were
#: flagged. A BLANK line is a paragraph break and does separate claims.
_BOUNDARY = re.compile(r"[;!?#()]|--|\.(?=\s|$)|\n[ \t]*\n")


def _words(text: str) -> list:
    return [(m.group(0), m.start()) for m in re.finditer("[a-z_]+", text)]


#: A machine-layout record: a bare key followed by two-or-more spaces and a
#: value, or `key: value`. Each such line is its own claim, so the newline that
#: ends it separates it from its neighbours -- unlike the newline inside a
#: wrapped sentence, which separates nothing.
_FIELD_LINE = re.compile("^[ " + chr(9) + "]*[a-z_][a-z0-9_.]*(:| {2,})", re.I)


#: A markdown table row. Each one is a separate claim, for the same reason a
#: machine-record line is.
_TABLE_ROW = re.compile("^[ " + chr(9) + "]*[|]")


def _field_newlines(text: str) -> list:
    """Offsets of newlines that separate RECORDS rather than wrap prose.

    TABLE ROWS ARE RECORDS. `|` is deliberately not a boundary WITHIN a row --
    that is what keeps `| Human review | not performed |` pairing a subject
    with its own negation, and it is why the exception was written. But no
    boundary BETWEEN rows meant an entire table body was one clause, and
    English negation scopes leftward, so an honest row shielded every claim
    below it.

    Measured on this repository's own `BRD.md`: appending a forged assurance
    row to the real BRD-F-005 table produced no overclaim at all, while the
    identical row standing alone was flagged. Twelve real tables here were
    already working as shields -- including the findings-closed table in a
    governance closure record.

    Cutting between rows keeps the within-row pairing and removes the shield.
    """
    cuts = []
    offset = 0
    lines = text.split(chr(10))
    for index, line in enumerate(lines[:-1]):
        offset += len(line)
        nxt = lines[index + 1]
        if (
            _FIELD_LINE.match(line) or _FIELD_LINE.match(nxt)
            or _TABLE_ROW.match(line) or _TABLE_ROW.match(nxt)
        ):
            cuts.append(offset)
        offset += 1
    return cuts


def _clause_of(text: str, tokens: list) -> list:
    """Which clause each token belongs to, by counting boundaries before it."""
    cuts = sorted(
        [m.start() for m in _BOUNDARY.finditer(text)] + _field_newlines(text)
    )
    clauses = []
    for _word, offset in tokens:
        index = 0
        for cut in cuts:
            if cut < offset:
                index += 1
            else:
                break
        clauses.append(index)
    return clauses


class _Overclaim:
    """The shape callers already expect from `re.Match`: `.start()`, `.group()`.

    A plain namespace with an int attribute looked right and broke the live
    sweep with `'int' object is not callable`, because the caller does
    `raw[: match.start()]`.
    """

    __slots__ = ("_offset", "_word")

    def __init__(self, offset: int, word: str):
        self._offset = offset
        self._word = word

    def start(self) -> int:
        return self._offset

    def group(self, _index: int = 0) -> str:
        return self._word


def find_overclaims(text: str) -> list:
    """Every assurance CLAIM in `text`, matched by concept rather than spelling.

    THE ENUMERATION WAS THE DEFECT. Three consecutive review rounds walked new
    spellings past four hand-written patterns, and each round the repair added
    another shape. A reviewer named it exactly: "these guards are enumerations
    of the shapes an earlier reviewer used, and each round adds shapes rather
    than closing the class."

    So this asks a question instead of matching a list. An assurance word --
    `independent*`, `inspection`, `attested`, `human_review`,
    `production_approval` -- is a CLAIM when an affirmative word sits within a
    short window and no disclaiming word does. Passive voice, past tense, any
    verb, the noun-plus-colon form and the space-aligned machine layout are all
    caught without being enumerated, because none of them changes the concept.

    BOUNDED WINDOW, NOT ADJACENCY. The previous negation test looked only at
    the characters immediately before a match, so `**not** independently
    inspected` -- two asterisks in the way -- read as a claim. A review measured
    10 of 12 honest sentences flagged, which is worse than a missed claim: the
    only escape it left an author was to delete the disclosure, and the sibling
    docstring says that pressure must be avoided.

    Definitions stay sayable because `requires`, `would`, `means`, `if` and
    `until` are disclaiming: "an independent inspection REQUIRES three
    attestations" describes the bar rather than clearing it.
    """
    lowered = _mention_blanked(text.lower())
    tokens = _words(lowered)
    words = [word for word, _offset in tokens]
    clauses = _clause_of(lowered, tokens)
    hits = []
    for index, (word, offset) in enumerate(tokens):
        independent = word.startswith("independent")
        # A FIELD NAME, OR AN INVENTED NAME CARRYING AN ASSURANCE MORPHEME.
        # `independent` is itself a field, so the narrative check below -- which
        # exists to keep "an independent review found two defects" sayable --
        # must not run first and bail on `independent: True`.
        # IS THIS A MACHINE ROW, or prose that happens to contain a field name?
        #
        # `independent: True` is a row; "an independent review found two
        # defects" is narrative about a reviewer, which must stay sayable --
        # this module already carries a finding about flagging five such
        # sentences. The distinction that separates them without a word list:
        # an UNDERSCORED token is a machine identifier and never ordinary
        # English, and a bare field name is a row only when what follows it is
        # a recognisable VALUE rather than a noun.
        # AN ADJACENT PAIR WHOSE JOINED FORM IS A FIELD IS THAT FIELD.
        #
        # `machine_name = "_" in word` made `human_review` a subject and
        # `human review` not one, so the ENGLISH spelling of this guard's own
        # subjects was not a claim:
        #
        #     production approval   GRANTED by the Change Advisory Board  -> no
        #     production_approval   GRANTED by the Change Advisory Board  -> yes
        #
        # Joining the pair recovers the subject. The clause machinery still
        # keeps `| Human review | not performed |` sayable, because `not`
        # precedes the point the claim completes.
        joined = ""
        if index + 1 < len(words):
            candidate = word + "_" + words[index + 1]
            if candidate in ASSURANCE_FIELDS:
                joined = candidate
        if joined:
            word = joined
        machine_name = "_" in word or bool(joined)
        after = words[index + 1] if index + 1 < len(words) else ""
        # THE HEAD NOUN CARRIES THE CONCEPT. An English compound is named by
        # its LAST element: `human_approval` is an approval, `independent_ai_review`
        # is a review. `assurance_moved` and `trusted_approvers_loaded` are not
        # -- they are mechanism, named by `moved` and `loaded`, and matching the
        # root anywhere in the identifier flagged both of them in this
        # repository's own value-flow document.
        #
        # A machine row whose head noun is not an assurance concept is still
        # reached by the TRANSCRIPT rule, which judges aligned runs; this guard
        # is about what a document says in prose.
        head_noun = word.rsplit("_", 1)[-1]
        names_a_field = word in ASSURANCE_FIELDS or (
            machine_name and any(root in head_noun for root in _ASSURANCE_ROOTS)
        )
        field_like = names_a_field and (
            machine_name or after in _VERDICT_VALUES or after in _ABSENT_SHAPES
        )
        derived_subject_is_a_field = (
            field_like or word in _SUBJECT_FIELDS or independent
        )
        if not (independent or field_like
                or _names_an_assurance_concept(word, after)):
            continue
        if independent and not field_like:
            near = words[max(0, index - 3): index + 4]
            if not any(
                (token.startswith(_QUALIFIER) or "inspect" in token)
                and token not in _AGENTS
                for token in near
            ):
                # "an independent review found ..." -- a reviewer, not a state.
                continue
        # `window` used to be materialised here and scanned as an unordered
        # bag. Both lookups are index ranges now, because WHERE a word sits
        # relative to the claim is the whole question -- a bag cannot answer
        # it, which is why eleven evasions walked through.
        low = max(0, index - _WINDOW)
        # SELF-AFFIRMATIVE. `independently inspected` and
        # `independently_inspected` carry the completed state in the participle
        # itself -- there is no separate verb to find nearby, so requiring one
        # missed the machine spelling this system emits and the bold-emphasised
        # prose form alike. The disclaiming window above still applies, which is
        # why `not_independently_inspected` and "never independently inspected"
        # are unaffected.
        # THE PARTICIPLE, NOT THE NOUN PHRASE. This accepted any following token
        # starting with `inspect`, so `independent inspection` -- an adjective
        # and a noun, which asserts nothing on its own -- was read as a
        # completed state. A review measured the consequence: "Independent
        # inspection of the artifacts ... has never been performed" was FLAGGED
        # as an overclaim, and the only way for an author to write that
        # disclosure honestly was to delete it.
        following = words[index: index + 3]
        # A PARTICIPLE IS SELF-AFFIRMING WHEREVER IT SITS, not only after
        # `independently`. `attested` is both a subject word and a completed
        # state, so "Attested by three independent inspectors" asserts one
        # without any separate verb -- and narrowing this to the
        # `independently <participle>` pair alone dropped exactly that claim,
        # which the dashboard was already publishing.
        # `being <participle>` IS A PASSIVE GERUND, not a completed act. "a
        # subject that survives BEING INSPECTED" describes a CAPACITY; it does
        # not say an inspection happened. Measured on a stored commit subject,
        # where it credited a claim.
        before = words[index - 1] if index > 0 else ""
        self_affirming = (
            (before != "being" and _completed_act(word, after))
            or (independent and len(following) > 1
                and following[1].startswith(_PARTICIPLES))
        )
        # A question is not an assertion. "Has an independent inspection been
        # performed here?" was refused, which leaves an author no way to ask.
        if "?" in _clause_text(lowered, tokens, clauses, index):
            continue
        if field_like:
            # THE VALUE DECIDES, NOT A LIST OF WAYS TO SAY YES.
            #
            # For a field this system emits, the honest values are enumerable
            # and the affirmative ones are not. So the question is inverted:
            # does the value that follows mean the property is ABSENT? Anything
            # else is a claim -- including spellings nobody wrote down.
            # `approved`, `accepted`, `cleared`, `signed_off` and
            # `fully_assured` were all admitted by the affirmative list.
            # THE VALUE IS READ FROM THE TEXT, NOT FROM THE TOKEN STREAM.
            # `_words` matches `[a-z_]+`, so `[]`, `0` and `3` produce NO
            # token at all -- and `authenticated_reviewers      []` then took
            # its "value" from the next line. Measured: four real documents
            # flagged, three of them for rows whose actual value was `[]`.
            # THE WHOLE VALUE, NOT THE FIRST RECOGNISABLE TOKEN.
            #
            # This scanned for the first token in either vocabulary and handed
            # `is_a_claim` that ONE token -- which reintroduced, here, exactly
            # the head-only judgement `claim_vocabulary` was rewritten to
            # remove. Measured:
            #
            #   production_approval  not_granted (granted by the Change
            #                                     Advisory Board)
            #
            # first recognisable token `not_granted` -> absent -> not a claim,
            # while the transcript rule beside it flagged the same row. Two
            # guards over one shared vocabulary, disagreeing because one of
            # them pre-chewed the input.
            #
            # BOUNDED TO THE CLAUSE, NOT THE LINE.
            #
            # "so the next record cannot leak in" was the intent, and a line is
            # the wrong unit for it: two records share a line whenever they are
            # separated by a semicolon. Measured on
            # `FAILED_REVIEW_45f858c.md:68`, where a builder's notes read
            #
            #     rows in consumed_approvals = 0 ; ledger.available=True
            #
            # `consumed_approvals`' value ran past the `;` and picked up the
            # NEXT record's `True`, so an honest disclosure of ZERO rows was
            # read as a claim. `_BOUNDARY` already knows where a clause ends;
            # this is the same boundary the disclaimer scope rule uses, and
            # using a different one here is what let the leak happen.
            # THE RECORD SEPARATOR IS `;`, NOT EVERY CLAUSE BREAK. Using the
            # whole of `_BOUNDARY` here was measured wrong in the other
            # direction: it contains `(` and `--`, so the value stopped before
            # the parenthetical, and the three forgery specimens --
            # `not_granted (granted by the CAB)` and its colon and dashed
            # forms -- went from FLAGGED to admitted. A verdict ANYWHERE in
            # the value is what those need; what must not leak in is the NEXT
            # RECORD, and on a shared line that is exactly a semicolon away.
            line_end = lowered.find(chr(10), offset)
            stop = line_end if line_end != -1 else len(lowered)
            after_key = offset + len(word)
            separator = lowered.find(";", after_key, stop)
            tail = lowered[after_key: separator if separator != -1 else stop]
            # TWO DIFFERENT QUESTIONS, TWO DIFFERENT INPUTS.
            #
            # `is_a_claim` judges the WHOLE value, because a claim can sit
            # anywhere in it. `completes_at` needs the position of the VALUE
            # TOKEN, because a disclaimer counts only when it precedes the point
            # the claim completes -- and "a human_review WILL be performed"
            # depends on `will` sitting before `performed`. Setting the anchor
            # from the first word of the tail put it on `will` itself, so the
            # frame could not scope its own clause.
            # BOUNDED TO THE VALUE, NOT THE LINE. A line carries prose after the
            # value -- "State autonomous_demo, human_review not_performed, and
            # production_approval not_granted." -- and judging the whole line
            # makes "every token is an absent shape" false for every sentence,
            # so honest prose reads as a claim. Two real documents were flagged
            # that way. A verdict ANYWHERE in the value still counts, which is
            # what the parenthetical forgery needs.
            recognised = re.findall(r"n/a|[a-z_]+|\[\]|\{\}|[0-9]+", tail)
            has_verdict = any(tok in _VERDICT_VALUES for tok in recognised)
            has_absent = any(tok in _ABSENT_SHAPES for tok in recognised)
            # A DISCLAIMING WORD THAT IS THE VALUE DISCLAIMS THE ROW IT IS
            # THE VALUE OF.
            #
            # `pending` and `blocked` are in `_DISCLAIMING`, and the scope rule
            # requires a disclaimer to PRECEDE the point a claim completes -- so
            # a word standing in the value slot, which is always after the key,
            # could never disclaim the row it was the honest answer for.
            # Measured, every one of these REFUSED while the pipe-table form of
            # the same fact was admitted:
            #
            #     Production approval: pending    Human review: scheduled
            #     Production approval: blocked    Human review: TBD
            #     Production approval: N/A        assurance_state: unknown
            #     | Production approval | pending |   <- ok
            #
            # That is the mirror of the bug the adjacent-absent-shape exception
            # was added to fix, and it left an author no way to disclose a
            # pending approval in the commonest notation there is.
            #
            # GATED ON THERE BEING NO VERDICT, which is what keeps the
            # parenthetical forgery closed: `production_approval  not_granted
            # (granted by the CAB)` carries `granted`, so it is still judged.
            has_disclaimer = any(tok in _DISCLAIMING for tok in recognised)
            decided = tail if has_verdict else ("" if has_absent else "")
            # THE CLAIM COMPLETES AT THE AFFIRMATIVE, so only a VERDICT value
            # anchors it. Anchoring on any recognisable token put the anchor on
            # the disclaimer itself when the disclaimer is also an absent shape
            # -- `absent`, `false`, `no`, `none`, `unavailable` -- and a
            # disclaimer cannot scope a claim it is standing on. Measured: five
            # such words failed the generated placement sweep in the
            # between-subject-and-verb column.
            value_token = ""
            for candidate in re.findall(r"n/a|[a-z_]+|\[\]|\{\}|[0-9]+", tail):
                if candidate in _VERDICT_VALUES:
                    value_token = candidate
                    break
            if decided:
                if not is_a_claim(word, decided, fields=ASSURANCE_FIELDS):
                    continue
                decided = value_token or (decided.split() or [""])[0]
            elif has_absent:
                # Only absent shapes in the value: the honest form.
                continue
            else:
                # NO RECOGNISABLE VALUE. `authenticated_reviewers: alice, bob,
                # carol` names three people, and a name is in no value
                # vocabulary -- but the honest value for that field is EMPTY,
                # so a non-empty one is a claim however it is spelled.
                #
                # Only when this is a MACHINE ROW, though: the key must be
                # followed by a colon or by aligned spacing. "with human_review
                # set to ..." is a sentence about a field, and a sentence is
                # not a row. That separator is the same one `_FIELD_LINE` uses.
                separator = lowered[offset + len(word): offset + len(word) + 3]
                if not (separator.startswith(":") or separator.startswith("=")
                        or separator.startswith("   ")
                        or separator.startswith("  ")):
                    continue
                if word not in ASSURANCE_FIELDS:
                    continue
                if has_disclaimer:
                    # See `has_disclaimer`: the value says the property is not
                    # established, which is the disclosure, not a claim.
                    continue
                decided = "(unrecognised)"
            # THE CLAIM COMPLETES AT THE VALUE TOKEN, wherever that is.
            #
            # A fixed offset was measured wrong on 51 of 336 generated
            # placements, all in one column: a disclaimer sitting BETWEEN the
            # field and its value -- "human_review was NOT performed" -- landed
            # exactly on the offset and `position < settled` excluded it. The
            # value's real position is what the disclaimer has to precede.
            completes_at = index
            for offset_index in range(index + 1, min(len(words), index + 12)):
                if words[offset_index] == decided:
                    completes_at = offset_index
                    break
            else:
                completes_at = min(index + 1, len(words) - 1)
        elif self_affirming:
            # The claim is complete at the subject itself; nothing after it is
            # part of the assertion.
            completes_at = index
        else:
            # SAME CLAUSE, like the disclaimer below. An affirmative in a
            # neighbouring record is not this record's verb -- measured on a
            # real transcript where `true` on the preceding line supplied the
            # affirmative for `assurance_state`, and the
            # `not_independently_inspected` written beside it could not
            # withdraw a claim that had been completed one line earlier.
            # AN ASSURANCE NOUN THAT DID SOMETHING IS AN ACTOR.
            #
            # "A review established that no production call site supplied
            # action_approval" is a finding BY a review, not a state OF this
            # repository -- and this module already draws that line for
            # `independent` subjects through `_AGENTS`. With the subject
            # derived, it has to hold for every subject. English marks it by
            # ADJACENCY: an affirmative immediately after the noun is that
            # noun's own verb. "assurance HAS BEEN established" puts a copula
            # between them; "a review ESTABLISHED" does not.
            # AN IMPERATIVE ASSERTS NOTHING ABOUT STATE. A clause that OPENS
            # with its verb has no subject -- the addressee is implied -- so
            # the assurance noun after it is the verb's OBJECT, not something
            # being predicated. Measured on stored commit subjects, which are
            # imperative by convention: "Hold the inspection subject still"
            # read `hold` as POSSESSION and credited a claim.
            first_in_clause = not any(
                clauses[earlier] == clauses[index] for earlier in range(index)
            )
            if first_in_clause is False and index > 0:
                opener = next(
                    (p for p in range(index) if clauses[p] == clauses[index]),
                    None,
                )
                if (opener is not None
                        and words[opener] in _POSSESSION
                        and not derived_subject_is_a_field):
                    continue
            actor = (
                index + 1 < len(words)
                and words[index + 1] in _AFFIRMATIVE
                and words[index + 1] not in _COPULA
                and words[index + 1] not in _POSSESSION
            )
            if actor and not derived_subject_is_a_field:
                continue
            affirmative = [
                position for position in range(low, min(len(words), index + _WINDOW + 1))
                if (words[position] in _AFFIRMATIVE
                    and words[position] not in _COPULA
                    or (words[position - 1] != "being" if position else True)
                    and _completed_act(
                        words[position],
                        words[position + 1] if position + 1 < len(words) else "",
                    ))
                and clauses[position] == clauses[index]
                # `true` AND `yes` ARE CELL VALUES, NOT PROSE VERDICTS. For a
                # field this system emits the value decides, and that is the
                # `field_like` branch above. In running prose they attach to
                # whatever noun is nearest: measured, "CI asserts the TRUE
                # pre-approval state" and two freshness-table rows reading
                # "| Yes, finite window |" each completed a claim about an
                # adjacent assurance noun.
                and not (not derived_subject_is_a_field
                         and words[position] in _CELL_VALUES)
            ]
            if not affirmative:
                continue
            completes_at = max(affirmative)

        # SCOPE, NOT PROXIMITY. A disclaimer counts only when it modifies THIS
        # claim: same clause, and at or before the point where the claim
        # completes. English negation precedes what it negates -- "has NOT been
        # performed", "NO independent inspection" -- while a modal arriving
        # after a completed claim is a new obligation, not a retraction.
        #
        # Measured: 11 of 11 deliberate evasions were admitted by the previous
        # unordered-bag test, including `independently_inspected  # operators
        # must not edit` and `granted -- deployers must record the date`.
        # The claim is complete at the LATER of the subject and its verb, and a
        # disclaimer anywhere earlier in the clause modifies it. `<= completes_at`
        # alone missed post-copular negation -- "Those findings ARE a
        # self-reported observation, NOT an independent inspection" -- where the
        # verb precedes the negation and the negation precedes the subject.
        settled = max(index, completes_at)
        if any(
            words[position] in _DISCLAIMING
            and clauses[position] == clauses[index]
            and position < settled
            # IN A RECORD, AN ABSENT SHAPE AFTER THE KEY IS THE VALUE, NOT A
            # MODIFIER. This is the semantic core of the parenthetical forgery:
            #
            #     production_approval  not_granted (granted by the CAB)
            #
            # `not_granted` is in `_DISCLAIMING`, so the honest head suppressed
            # the claim appended behind it -- an author writes the true value
            # first and the false one second, and the scope rule reads the
            # second as disclaimed by the first. For prose that rule is right;
            # for a row it inverts the meaning, because a row states ONE value
            # and a second one contradicts rather than qualifies it.
            #
            # IMMEDIATELY after the key, and only there. Applied to any later
            # position it reached into prose -- "human_review was ABSENT
            # performed today" -- where an absent-shape word genuinely IS the
            # disclaimer, and five such words failed the generated placement
            # sweep. Adjacency is what distinguishes a value from a modifier.
            and not (field_like and position == index + 1
                     and words[position] in _ABSENT_SHAPES)
            for position in range(len(words))
        ):
            continue
        hits.append(_Overclaim(offset, word))
    return hits


#: A fenced block opener or closer.
_FENCE = re.compile(r"^[ \t]*(?:```|~~~)", re.M)


def _prose_only(text: str) -> str:
    """Blank fenced blocks, preserving length and line numbers.

    THIS GUARD IS ABOUT WHAT A DOCUMENT SAYS IN PROSE, and it says so itself:
    the head-noun rule beside `find_overclaims` records that "a machine row
    whose head noun is not an assurance concept is still reached by the
    TRANSCRIPT rule, which judges aligned runs; this guard is about what a
    document says in prose." The code did not honour that boundary -- it
    handed `find_overclaims` the whole file, fenced transcripts included.

    Measured: `TASK11_CLOSURE.md:132` reads `D2  zone crossing authorized at
    every risk level, behaviourally` inside a fenced results block. That is a
    measurement about ZONE CROSSING in a machine transcript, and the prose
    rule read it as a governance authorization.

    A stated control the code does not implement is the FG37 shape, and this
    is the second instance found in this module. Line numbers survive because
    the content is replaced space-for-space, so a finding still names the line
    a reader would look at.
    """
    rows = text.split(chr(10))
    inside = False
    for index, row in enumerate(rows):
        if _FENCE.match(row):
            inside = not inside
            rows[index] = " " * len(row)
            continue
        # ONLY THE RECORDS, NOT THE WHOLE BLOCK.
        #
        # This blanked every line inside a fence, and the docstring above
        # justified that with a compensating control that DOES NOT EXIST for
        # prose: the transcript rule judges `key value` runs, so an English
        # sentence in a fence is reached by NOTHING. Measured:
        #
        #     "The external audit is complete ... production approval has been
        #      granted by the Change Advisory Board."
        #        inside a fence   ADMITTED, 0 offenders, document not selected
        #        the same text unfenced   8 offenders
        #
        # A guard whose name certifies that no document claims an independent
        # inspection, admitting that sentence because of the characters around
        # it, is the FG37 shape -- introduced here while closing an
        # FG37-shaped finding.
        #
        # It also made ONE STRAY FENCE MARKER a corpus-deletion primitive: odd
        # parity blanks every line after it. That is the defect `_CODE_SPAN`
        # was repaired for one module over, reintroduced at block level.
        #
        # What the fence rule is FOR is machine rows -- `D2  zone crossing
        # authorized at every risk level` is a measurement about zone crossing
        # in a transcript, not a governance claim, and the transcript rule
        # genuinely does judge those. So a record inside a fence is still
        # blanked and prose is not.
        if inside and _FIELD_LINE.match(row):
            rows[index] = " " * len(row)
    return chr(10).join(rows)


def test_no_document_claims_an_independent_inspection_this_repository_lacks():
    """LINT OVER PROSE. Defence in depth, NOT a certification of English.

    `independently_inspected` is derived, and derives to false here. A
    document asserting otherwise is the same defect as an artifact asserting
    it -- a claim about assurance from something that cannot establish it --
    just written in English, and this sweep catches a great many of them.

    WHAT THIS TEST DOES NOT CLAIM, stated because the name reads stronger
    than the property. It does not certify that repository prose is free of
    false governance claims. It cannot: the grammar is bounded and English is
    not. The measured limit is recorded in `test_claim_surface_boundary.py`
    with its specimen -- "cleared for production deployment by the CAB" is
    admitted here and always will be, because closing it means enumerating
    governance-authority nouns forever.

    The property this repository DOES mechanically claim is the one that
    module states and measures: assurance is verified over a CLOSED,
    explicitly declared claim surface, and prose is not part of it -- a
    sentence this sweep misses cannot create, upgrade, or satisfy any
    assurance, inspection, approval or production-readiness state.

    Prose remains subject to HUMAN EDITORIAL REVIEW. That is not a gap this
    sweep is failing to fill; it is the correct authority for free text, and
    saying so here is what keeps this control's claim equal to what it
    measures.
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
        raw = _prose_only(document.read_text(encoding="utf-8"))
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


@pytest.mark.false_green("FG20")
def test_ci_shell_propagates_pipeline_failure():
    """FG20. A piped assurance command must not be able to report a false green.

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
    # ------------------------------------------------------------------
    # FRESH TASK 14, LENS C. Each of these was ADMITTED at 67d85f9.
    # ------------------------------------------------------------------
    # C P1-2: `_MENTION` had no length bound, so a whole sentence in backticks
    # was a mention -- on the package description a marketplace shows.
    ("a whole sentence inside one backtick pair",
     "`This release has been independently inspected; production approval "
     "granted.`", True),
    # ... and the three shapes that must stay admitted, because the bound is
    # what makes the rule usable rather than merely strict.
    ("a definitional identifier span",
     "`assurance_state: independently_inspected` is derived, never read",
     False),
    ("a bare identifier is a token, not an assertion",
     "the field `assurance_state` is derived", False),
    # C, found while fixing P2-1: two records sharing a line, separated by a
    # semicolon. The value ran past the `;` into the NEXT record's `True`, so
    # an honest disclosure of ZERO rows read as a claim.
    ("two records on one line, the first honest",
     "rows in consumed_approvals = 0 ; ledger.available=True", False),
    # THE TWO FORMS REMOVED FROM GOVERNANCE DOCUMENTS BY THE C9-P1-7 REPAIR.
    # They are pinned HERE so that correcting the published prose did not also
    # retire the guard's obligation to catch them. Both quoted an assurance
    # claim, and this module's recorded rule is that quoting publishes -- so
    # both were TRUE positives, and must stay caught forever.
    ("retired doc form, quoted first-person inspection",
     'A reviewer signs "I inspected this content"; an approver signs "this', True),
    ("retired doc form, quoted assurance cycle",
     "It says that the tree at `990caea` passed an assurance cycle WITH ONE ROW",
     True),
    # ------------------------------------------------------------------
    # C9-P1-7 -- THE SUBJECT VOCABULARY, DERIVED. Nine of these eleven were
    # ADMITTED while the subject set was four literals: their verdicts were
    # already in the affirmative vocabulary and were never ASKED, because no
    # subject was present. Baseline 2/11; these are the hostile regressions.
    # ------------------------------------------------------------------
    ("english, reviewed and approved by a board",
     "reviewed and approved by the Change Advisory Board on 2026-08-19", True),
    ("english, signed off by inspectors",
     "signed off by three inspectors outside the build team", True),
    ("english, approval was granted",
     "Approval for production deployment was granted on 2026-08-19", True),
    ("english, external audit complete",
     "The external audit is complete and all findings are closed", True),
    ("english, assurance established",
     "Full assurance has been established for this release", True),
    ("english, certified by an auditor", "certified by an external auditor", True),
    ("english, we hold an approval",
     "We hold a valid production approval for this release", True),
    ("english, auditor has certified",
     "An external auditor has certified the governance posture of this release",
     True),
    # ... AND THE HONEST PROSE THAT MUST SURVIVE THE WIDENING. Each of these
    # was measured MISFLAGGED by an intermediate version of the rule.
    ("honest, a copula is not a verdict",
     "Human review is required before any production deployment.", False),
    ("honest, mechanism not assurance",
     "The audit trail is written to the evidence directory.", False),
    ("honest, an assurance noun that ACTED",
     "an independent review found three defects in the runtime", False),
    ("honest, attributive participle",
     "reported as approved content, bound into evidence", False),
    ("honest, out of scope",
     "Obtaining an approval is out of scope for an autonomous run.", False),
    ("honest, certification disclaimed",
     "certification is not claimed anywhere in this tree", False),
    # IMPERATIVE MOOD ASSERTS NOTHING. Stored commit subjects are imperative
    # by convention, and a governance baseline records them verbatim.
    ("honest, imperative commit subject",
     "Hold the inspection subject still, and follow tamper to the effect", False),
    ("honest, passive gerund",
     "Let an inspection bind to a subject that survives being inspected", False),
    # C9-P2-2 -- A DISCLAIMING WORD IN THE VALUE SLOT DISCLAIMS ITS OWN ROW.
    # Every one of these was REFUSED while the pipe-table form of the same
    # fact was admitted, which left an author no way to disclose a pending
    # approval in the commonest notation there is.
    ("colon form, pending", "Production approval: pending", False),
    ("colon form, blocked", "Production approval: blocked", False),
    ("colon form, not applicable", "Production approval: N/A", False),
    ("colon form, scheduled", "Human review: scheduled", False),
    ("colon form, to be determined", "Human review: TBD", False),
    ("colon form, unknown", "assurance_state: unknown", False),
    ("pipe form, the control that always worked",
     "| Production approval | pending |", False),
    # ... AND THE FORGERIES THAT MUST STILL BE CAUGHT, because the rule above
    # is gated on there being no verdict anywhere in the value. Without that
    # gate an author writes the honest value first and the false one second.
    ("disclaimer then claim, parenthetical",
     "production_approval  not_granted (granted by the Change Advisory Board)",
     True),
    ("disclaimer then claim, colon form",
     "assurance_state: unknown (independently_inspected)", True),
    ("disclaimer then claim, dashed",
     "Human review: TBD -- performed by K. Osei", True),
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


# --------------------------------------------------------------------------
# THE ADVERSARIAL CORPUS.
#
# Every one of these is a sentence a REVIEW put through this guard and
# measured. They are kept because the alternative is what happened for five
# rounds: a reviewer demonstrates an evasion, the guard is repaired, the
# demonstration lives only in a report, and the next repair reopens it.
#
# `_EVASIONS` were ADMITTED when they were measured, and must now be caught.
# `_TRUTHFUL` must stay sayable: a guard that flags honest disclosure leaves an
# author no escape but to delete it, and this module's own docstring says that
# is worse than a missed claim.
#
# Adding a case is cheap and removing one should be hard. If a case here ever
# becomes wrong, the right change is to say why in the diff, not to delete the
# line.
# --------------------------------------------------------------------------

_Q = chr(34)

#: Round 5, Lens C: eleven deliberate evasions, ELEVEN ADMITTED. Every one
#: worked the same way -- an ordinary English word from `_DISCLAIMING` placed
#: within ten tokens of a completed claim, suppressing it regardless of what
#: the word modified.
_EVASIONS = (
    ("disclaimer in a later clause",
     "This repository has been independently inspected and every finding "
     "closed; downstream consumers must retain a copy of the attestation."),
    ("modal after the claim", "This build has been independently inspected "
     "and must be retained."),
    ("negation of something else", "This build has been independently "
     "inspected and no exceptions were noted."),
    ("temporal word after the claim",
     "This build has been independently inspected before shipping."),
    ("advice after the claim", "This build has been independently inspected; "
     "you should keep the record."),
    ("condition on something else", "This build has been independently "
     "inspected if you need the record."),
    ("obligation after the claim", "This build has been independently "
     "inspected and requires archiving."),
    ("concessive after the claim", "This build has been independently "
     "inspected yet nobody objected."),
    ("machine field with a trailing comment",
     "assurance_state: independently_inspected  # operators must not edit"),
    ("machine field with a parenthetical",
     "human_review: performed (auditors must keep the record)"),
    ("machine field with a dashed note",
     "production_approval: granted -- deployers must record the date"),
    # Round 5, Lens C, the operator dashboard: four markups the UI published
    # that the DOCUMENT guard caught and the UI guard did not.
    ("dashboard badge", "Independent inspection completed"),
    ("dashboard badge, colon form", "Independent inspection: passed"),
    ("dashboard body, agent form", "Attested by three independent inspectors"),
    ("dashboard body, verb form",
     "This build has undergone an independent inspection"),
    # A quoted CLAIM is not a mention. The mention rule blanks a quoted TERM;
    # blanking a quoted sentence is an arm this module already removed once,
    # after a review measured a forgery riding through it.
    # Task 14, Lens C: AN HONEST HEAD WITH THE CLAIM IN A PARENTHETICAL.
    # `tokens_of` deleted parentheticals, on the reasoning that
    # `status fail (claimed: pass)` is a retraction. The two are structurally
    # identical -- honest head, opposing parenthetical -- and six rows in this
    # shape returned `is_a_claim False` while a reader takes away exactly the
    # parenthetical. A retraction is MARKED now, not inferred from brackets.
    ("the claim in a parenthetical",
     "production_approval          not_granted (granted by the Change Advisory Board)"),
    ("and again, with a name",
     "human_review                 not_performed (performed by K. Osei, 2026-08-19)"),
    # And the disclaimer inversion underneath it: `not_granted` is itself in
    # `_DISCLAIMING`, so the honest head suppressed the claim appended behind
    # it. In a RECORD an absent shape adjacent to the key is the VALUE, and a
    # second value contradicts rather than qualifies.
    ("an honest value followed by a contradicting one",
     "assurance_state              not_independently_inspected (inspection closed)"),
    # Round 6, Lens C: ELEVEN of the thirteen field names this system emits,
    # at their affirmative value, all ADMITTED by the affirmative word list.
    # `approved` is the root of the field's own name.
    ("the field's own root as its value", "production_approval: approved"),
    ("another way to say performed", "human_review: accepted"),
    ("and another", "human_review: cleared"),
    ("and another still", "human_review: signed_off"),
    ("an invented assurance state", "assurance_state: fully_assured"),
    ("an invented field name, verdict value",
     "independent_ai_review: established"),
    ("a boolean field at True", "required_inspectors_complete: True"),
    ("the independence field itself", "independent: True"),
    ("named reviewers", "authenticated_reviewers: alice, bob, carol"),
    ("an invented approval field", "human_approval: adopted"),
    ("the JSON spelling", '{"production_approval": "approved"}'),
    ("a whole claim inside quotation marks",
     _Q + "This repository has been independently inspected and every finding "
     "closed" + _Q),
)

#: Sentences that must remain sayable. The first three were FLAGGED by a repair
#: to the above -- widening a guard until it refuses honest disclosure is the
#: same defect pointing the other way.
_TRUTHFUL = (
    ("negation far from the subject",
     "Independent inspection of the artifacts, the contracts, the evidence "
     "manifest, the runtime lock and the approval ledger has never been "
     "performed."),
    ("agents, not a state", "read-only AI inspectors that are independent of "
     "the builder and cannot modify the implementation"),
    ("post-copular negation", "Those findings are a self-reported "
     "observation, not an independent inspection: independence requires an "
     "attestation signed by a reviewer who is not the builder."),
    ("a quoted term in a heading",
     "## What an " + _Q + "independent inspection" + _Q + " is allowed to mean"),
    ("plain negation", "This repository has not been independently inspected."),
    ("machine field, negative", "human_review: not_performed"),
    ("machine field, negative approval", "production_approval: not_granted"),
    ("machine field, negative assurance",
     "assurance_state: not_independently_inspected"),
    ("a definition of the bar",
     "An independent inspection requires three signed attestations."),
    ("a hypothetical bar", "An independent inspection would require an "
     "authenticated attestation."),
    ("leading negation", "No independent inspection has been performed."),
    ("a disclosure table row", "| Human review | not performed |"),
    ("never", "This build has never been independently inspected."),
    ("narrative about a reviewer",
     "an independent review found two defects in the criteria"),
    ("negated participle", "This repository is not attested."),
    ("negated noun", "No attestation has been performed."),
    # Round 6, Lens C: EIGHT of nine truthful or harmless sentences REFUSED,
    # for want of a conditional, temporal or interrogative frame. An author
    # documenting the bar had one narrow permitted vocabulary and no way to ask
    # a question -- the direction this module's docstring calls worse than a
    # missed claim.
    ("a conditional frame",
     "Once production_approval is granted, the dashboard row changes."),
    ("a temporal frame",
     "After an independent inspection has been completed, the state changes."),
    ("a locative frame",
     "Where human_review is performed, the operator records the date."),
    ("a future frame",
     "A human_review will be performed before any production release."),
    ("a question", "Has an independent inspection been performed here?"),
    ("a field name in ordinary prose",
     "The status of the review is recorded elsewhere."),
    # Round 6: mechanism identifiers that merely CONTAIN an assurance morpheme.
    ("mechanism, not assurance", "ASSURANCE_MOVED   true"),
    ("a store that loaded", "trusted_approvers_loaded=true"),
    ("an empty reviewer list", "authenticated_reviewers      []"),
    # Round 5, Lens C: the transcript block this repository actually publishes.
    # The `true` on the preceding line supplied an affirmative for the line
    # below it, and the honest value beside it could not withdraw the claim.
    ("adjacent machine fields",
     "problems               []" + _NEWLINE
     + "governed_input_match   true" + _NEWLINE
     + "assurance_state        not_independently_inspected"),
)


@pytest.mark.parametrize(("label", "text"), _EVASIONS, ids=lambda v: v)
def test_every_recorded_evasion_is_still_caught(label: str, text: str):
    """What a review has walked past this guard once, it must not walk past again."""
    assert find_overclaims(text), (
        f"{label}: this evasion was measured being ADMITTED by an earlier "
        "version of this guard and is admitted again. The class it belongs to "
        "was reported closed: " + repr(text[:90])
    )


@pytest.mark.parametrize(("label", "text"), _TRUTHFUL, ids=lambda v: v)
def test_every_recorded_truthful_disclosure_is_still_admitted(label: str, text: str):
    """A guard that refuses honest disclosure leaves an author only deletion."""
    hits = find_overclaims(text)
    assert not hits, (
        f"{label}: this sentence is TRUE of this repository and the guard "
        f"refuses it, so the only way to satisfy the suite is to delete the "
        f"disclosure. Flagged on {[h.group() for h in hits]}: "
        + repr(text[:90])
    )


# --------------------------------------------------------------------------
# THE PLACEMENT SWEEP.
#
# The corpus above proves that seventeen sentences are caught. A reviewer's
# closing sentence on the round that produced it: "'33 nodes pinning every
# forgery' is a COUNT, not a closure." That is correct, and this is the answer
# to it for the one part of the guard where the space CAN be enumerated.
#
# The rule `find_overclaims` implements is stateable in a sentence:
#
#     a subject word is a CLAIM when an affirmative completes it in the same
#     clause, and no disclaiming word appears in that clause before the point
#     where it completes.
#
# So the space of single-disclaimer placements is generated -- every word in
# `_DISCLAIMING`, at every position that matters, in both sentence shapes --
# and the expected verdict is DERIVED FROM THE RULE rather than written down
# beside each case. Nobody chooses the cases, so a reviewer inventing a new
# placement is inventing one this already covers.
#
# Every one of round 5's eleven evasions was a disclaimer placed AFTER the
# claim completed or in a LATER clause. Those are two whole columns here.
#
# WHAT THIS DOES NOT CLOSE, stated rather than implied: it closes single
# disclaimer placements over two sentence shapes. It does not close English,
# it says nothing about two disclaimers interacting, and a guard cannot be
# made complete over prose. Claiming otherwise would be the substitution this
# repository exists to refuse.
# --------------------------------------------------------------------------


def _placement_cases():
    """Generate (label, sentence, expected) from the rule, not from a list."""
    disclaimers = sorted(
        word for word in _DISCLAIMING
        if word.isalpha() and word not in _AFFIRMATIVE
    )
    assert len(disclaimers) > 15, (
        f"only {len(disclaimers)} usable disclaimers; the sweep would be "
        "measuring almost nothing"
    )

    for word in disclaimers:
        # SEPARATE VERB: the claim completes at `performed`, which follows the
        # subject. Four positions, and the rule decides each.
        head = ["the", "record", "states", "that"]
        tail = ["today"]
        yield (
            f"{word}: before the subject",
            " ".join(head + [word, "human_review", "was", "performed"] + tail),
            False,
        )
        yield (
            f"{word}: between subject and verb",
            " ".join(head + ["human_review", "was", word, "performed"] + tail),
            False,
        )
        yield (
            f"{word}: after the claim completes",
            " ".join(head + ["human_review", "was", "performed", word] + tail),
            True,
        )
        yield (
            f"{word}: in a later clause",
            " ".join(head + ["human_review", "was", "performed"] + tail)
            + "; " + " ".join([word, "the", "operator", "should", "check"]),
            True,
        )

        # SELF-AFFIRMING PARTICIPLE: the claim completes at the subject itself,
        # so there is no "between" position and anything after it is later.
        yield (
            f"{word}: before a participle claim",
            " ".join(["this", "build", "has", word, "been", "independently",
                      "inspected"] + tail),
            False,
        )
        yield (
            f"{word}: after a participle claim",
            " ".join(["this", "build", "has", "been", "independently",
                      "inspected", word] + tail),
            True,
        )


def test_a_disclaimer_decides_by_scope_at_every_generated_placement():
    """Generated, so the cases are not the ones anybody thought of."""
    wrong = []
    total = 0
    for label, sentence, expected in _placement_cases():
        total += 1
        if bool(find_overclaims(sentence)) != expected:
            verdict = "ADMITTED" if expected else "FLAGGED"
            wrong.append(f"{label} -> {verdict}: {sentence!r}")

    assert total > 100, (
        f"the generator produced only {total} cases; it has stopped generating "
        "and this test would pass over nothing"
    )
    assert wrong == [], (
        f"{len(wrong)} of {total} generated placements disagree with the rule "
        "this guard states. A disclaimer that suppresses a claim it does not "
        "scope is how eleven evasions walked past it; one that suppresses "
        "nothing refuses honest disclosure. First few: " + repr(wrong[:6])
    )


@pytest.mark.parametrize(
    ("label", "body", "flagged"),
    [
        ("prose inside a fence", "```" + chr(10)
         + "The external audit is complete and production approval has been "
         "granted." + chr(10) + "```", True),
        ("one unclosed fence, then the claim", "```" + chr(10) * 2
         + "production approval has been granted.", True),
        ("a machine row inside a fence belongs to the transcript rule",
         "```" + chr(10) + "  D2  zone crossing authorized at every risk level"
         + chr(10) + "```", False),
        ("a machine row outside a fence is still prose here",
         "  production_approval  granted", True),
    ],
)
def test_the_fence_rule_hides_records_and_not_prose(label, body, flagged):
    """Fresh Task 14, Lens C P1-1 and P2-1. Both introduced by this function.

    `_prose_only` blanked every line inside a fence, and its docstring
    justified that with a compensating control that DOES NOT EXIST for prose:
    the transcript rule judges `key value` runs, so an English sentence in a
    fence was reached by nothing. Measured at 67d85f9: the fenced form gave 0
    offenders and the document was not selected; the identical text unfenced
    gave 8.

    It also made ONE STRAY FENCE MARKER a corpus-deletion primitive, by odd
    parity -- the defect `_CODE_SPAN` was repaired for one module over,
    reintroduced here at block level.

    What the fence rule is FOR is machine rows: `D2 zone crossing authorized`
    is a measurement about zone crossing, and the transcript rule genuinely
    does judge those. So records inside a fence are still hidden from this
    guard and prose is not, and both halves are pinned here.
    """
    document = "# Report" + chr(10) * 2 + body + chr(10)
    hits = [match.group() for match in find_overclaims(_prose_only(document))]
    assert bool(hits) is flagged, f"{label}: {hits}"


#: The authoritative terminal classification for each measurement that has one.
#:
#: ONE PLACE. Four documents carried a classification for the D1/D2 question and
#: three of them agreed; the fourth said the opposite, in a live remediation
#: section, with no supersession marker, and its very next sentence cited the
#: document that corrects it. Each previous round closed this by hand-editing
#: the document a reviewer happened to be reading, and each following round
#: found another copy -- three rounds, three hand edits, three recurrences.
#:
#: The distinction is not bookkeeping. `INVALID_BASELINE` means an attack
#: entered the protocol and its harness broke: an engineering problem, closable
#: by machine work, and a reader goes looking for the fix. `HUMAN_BLOCKED`
#: means the precondition is a human approval this repository must never
#: manufacture -- the one category no autonomous run can close. Labelling it as
#: the closable one points a reader at work that does not exist.
AUTHORITATIVE_CLASSIFICATIONS = {
    "D1": "HUMAN_BLOCKED",
    "D2": "HUMAN_BLOCKED",
}

#: The outcome vocabulary. A term outside this set is not a classification.
OUTCOME_TERMS = frozenset({
    "HUMAN_BLOCKED", "INVALID_BASELINE", "SURVIVED", "KILLED",
    "ADMITTED_ATTACK_INVALID_BASELINE", "OBSOLETE_HISTORICAL_ATTACK",
})

#: A document declares a classification with a marker, not with a sentence.
#:
#:     <!-- classification: D1 = HUMAN_BLOCKED -->
#:
#: PROSE SCANNING CANNOT DO THIS, and two attempts measured why. Scoped to the
#: sentence, the guard reached ONE line -- inside a fenced block in a document
#: whose header says nothing in it is a current claim -- because neither the
#: wrong statement ("Three attempts ... all produced INVALID_BASELINE") nor the
#: right one ("were all HUMAN_BLOCKED") names D1 or D2 in the same sentence as
#: the term. Widened to the section, it flagged the vocabulary DEFINITIONS: a
#: section that discusses D1 and also explains what KILLED and SURVIVED mean
#: read as asserting all three.
#:
#: This repository has already spent a review cycle learning that a regex
#: cannot be taught what a sentence asserts, and the answer there is the answer
#: here: a closed, declared surface. A marker is unambiguous, cheap to write,
#: and impossible to produce by accident -- and what it does NOT cover is
#: stated rather than implied.
_CLASSIFICATION_MARKER = re.compile(
    r"<!--\s*classification:\s*([A-Za-z0-9_-]+)\s*=\s*([A-Z_]+)\s*-->"
)

#: Documents that are superseded in their own header. A marker there records
#: history and is not a current claim.
_WITHDRAWN = ("TASK11_CLOSURE",)


def _declared_classifications() -> dict:
    """subject -> {term: [where]}, from declared markers in tracked documents."""
    import subprocess  # noqa: PLC0415

    listing = subprocess.run(  # noqa: S603
        ["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True,
        check=True, encoding="utf-8", errors="replace",
    )
    found: dict = {}
    for name in listing.stdout.splitlines():
        path = ROOT / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in _CLASSIFICATION_MARKER.finditer(text):
            subject, term = match.group(1), match.group(2)
            line = text.count(chr(10), 0, match.start()) + 1
            found.setdefault(subject, {}).setdefault(term, []).append(
                f"{name}:{line}"
            )
    return found


def test_the_inspection_record_does_not_assert_an_inspection_that_did_not_happen():
    """The statement was a fixed string on every path.

    Emitted unconditionally -- not on `reviews.json` existing, not on any
    inspector having run, not on `authenticated_inspections` being non-empty.
    A reader of the governed evidence set saw three passing inspectors and a
    sentence saying the inspection happened and was independent, while
    `authenticated_inspections` in the same object was `{}`.

    "did not author this record's verdict on their own behalf" is exactly the
    self-certification `ASSURANCE_BOUNDARY.md` records retiring
    `builder_self_approval` for -- the builder certifying their own
    independence in a file anyone could write. As an unconditional string it
    was that, restored.

    The `reviewers` rows come from `.nornyx/in-session/reviews.json`, which
    `.gitignore` excludes, so on a clean clone their source is not in the
    repository at all.

    This is the ONE surface where a false independence claim would be worst,
    because it is inside the governed evidence set rather than in prose beside
    it -- and `governance_docs()` deliberately does not read `.nornyx/`, so no
    prose sweep covers it.
    """
    import json as _json  # noqa: PLC0415

    record = _json.loads(
        (ROOT / ".nornyx/contracts/evidence/architecture_independent_review.json")
        .read_text(encoding="utf-8")
    )
    authenticated = record.get("authenticated_inspections") or {}
    statement = record.get("statement", "")
    assert statement, "the record carries no statement at all"
    if authenticated:
        assert "independent machine review" in statement, (
            "an authenticated inspection exists and the record does not say so"
        )
        return
    for asserted in (
        "was inspected by read-only inspectors",
        "did not author this record's verdict on their own behalf",
        "This is an independent machine review",
    ):
        assert asserted not in statement, (
            "no authenticated inspection exists and the record asserts one: "
            + repr(asserted) + " appears in the statement"
        )
    assert "NO AUTHENTICATED INSPECTION" in statement, (
        "the record neither asserts an inspection nor states its absence, so a "
        "reader cannot tell which: " + statement[:120]
    )


def test_the_excluded_contracts_are_covered_by_hash_binding():
    """`.nornyx/` is skipped by the prose sweep. Something must still cover it.

    The exclusion is correct -- the contracts are a structured surface, and
    running a prose sweep over them reports field values like
    `status: authorized` as overclaims. But "correct because it is structured"
    is an argument, and the argument only holds while the structured defence
    genuinely applies.

    MY FIRST VERSION OF THIS GUARD NAMED THE WRONG MECHANISM. It asserted the
    contracts were inside `GOVERNED_INPUT_PATHS`, and they are not -- that
    tuple covers `src`, `scripts`, `tests`, `docs`, `.github` and a handful of
    root files. Running it said so immediately, which is the only reason the
    error did not ship: the contracts are bound by their OWN digests in
    `review_binding.json`, a different mechanism entirely.

    So this measures the mechanism that actually applies: every contract's
    bytes hash to the digest the binding records for it. If a contract were
    edited without regenerating, this is red -- and `--verify` reports
    `EVIDENCE_ARTIFACT_HASH_MISMATCH` on the same fact.
    """
    import hashlib  # noqa: PLC0415
    import json as _json  # noqa: PLC0415

    binding = _json.loads(
        (ROOT / ".nornyx/contracts/evidence/review_binding.json")
        .read_text(encoding="utf-8")
    )
    digests = binding.get("digests") or {}
    bound_to = {
        "architecture_governance.nyx": "architecture_contract",
        "forge_control.nyx": "forge_control_contract",
        "runtime_network.nyx": "runtime_contract",
    }
    contracts = sorted(
        path.name for path in (ROOT / ".nornyx/contracts").glob("*.nyx")
    )
    assert contracts, "no contracts exist, so this guard measured nothing"
    undeclared = sorted(name for name in contracts if name not in bound_to)
    assert undeclared == [], (
        "these contracts are excluded from the prose sweep and this guard does "
        "not know which digest binds them, so nothing here covers them: "
        + repr(undeclared)
    )
    unbound = []
    for name in contracts:
        raw = (ROOT / ".nornyx/contracts" / name).read_bytes()
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digests.get(bound_to[name]) != actual:
            unbound.append(
                name + " hashes to " + actual[:23] + "... and the binding "
                "records " + str(digests.get(bound_to[name]))[:23] + "..."
            )
    assert unbound == [], (
        "these contracts are excluded from the prose sweep AND their recorded "
        "digest does not match their content, so the structured defence the "
        "exclusion relies on is not applying: " + repr(unbound)
    )


def test_no_two_documents_classify_the_same_measurement_differently():
    """Four documents carried a classification for D1/D2 and one disagreed.

    Three rounds closed that by hand -- each time correcting the file a
    reviewer happened to be reading -- and each following round found another
    copy. The fourth was in a LIVE remediation section, with no supersession
    marker, and its very next sentence cited the document that corrects it.

    WHAT THIS MEASURES: every declared `<!-- classification: ... -->` marker in
    a tracked document agrees with `AUTHORITATIVE_CLASSIFICATIONS`, and at
    least one LIVE document declares each subject.

    WHAT IT DOES NOT MEASURE, said plainly: unmarked prose. Neither the wrong
    statement nor the right one named the subject in the same sentence as the
    term, so no sentence-scoped rule can find them, and a section-scoped one
    flags the vocabulary definitions instead. The marker is the surface; prose
    beside it is not checked, and a document that classifies in prose without a
    marker is invisible here.
    """
    declared = _declared_classifications()
    missing = sorted(set(AUTHORITATIVE_CLASSIFICATIONS) - set(declared))
    assert missing == [], (
        "no document declares a classification marker for these subjects, so "
        f"nothing here is being checked about them: {missing}"
    )
    for subject in AUTHORITATIVE_CLASSIFICATIONS:
        live = [
            where
            for term in declared.get(subject, {})
            for where in declared[subject][term]
            if not any(mark in where for mark in _WITHDRAWN)
        ]
        assert live, (
            f"only withdrawn documents declare {subject}, so this guard is "
            "satisfied by text that says of itself that nothing in it is a "
            "current claim"
        )
    wrong = []
    for subject, expected in AUTHORITATIVE_CLASSIFICATIONS.items():
        for term, where in sorted(declared.get(subject, {}).items()):
            if term != expected:
                wrong.append(f"{subject} is {expected}; {where} declare {term}")
    assert wrong == [], (
        "documents disagree about how a measurement was classified. One of "
        "these terms means an engineering problem someone can fix and the "
        "other means a human approval no autonomous run may manufacture, so a "
        "reader is sent to work that does not exist: " + repr(wrong)
    )


def test_assessment_language_alone_does_not_leave_the_claim_surface():
    """The evasion control: neither the path nor the vocabulary decides.

    The narrowing exists so a DATED assessment of one commit is not read as a
    statement about the current head. It must not become a way for an ordinary
    governance document to stop being scanned -- by living under
    `docs/assessments/`, by being renamed, or by talking like an assessment.

    `classify_document` reads only the declaration, so this is provable rather
    than hoped for.
    """
    sounds_like_one = _NEWLINE.join([
        "# Governance Evidence Assessment — Something",
        "",
        "**Status:** G2 sponsor self-assessment",
        "**Assessor:** project-sponsor self-assessment",
        "**Assessment date:** 2026-08-21",
        "**Observation surfaces:** O1 repository content",
        "",
        "This assessment concludes the build has been independently inspected.",
    ])
    assert classify_document(sounds_like_one) == "current_claim", (
        "a document with no declared target commit left the current-claim "
        "surface on assessment vocabulary alone, so any document could"
    )
    assert find_overclaims(sounds_like_one), (
        "and the claim rule itself must still refuse its content -- the "
        "narrowing changes WHICH documents are asked, not what is a violation"
    )

    declares_its_commit = _NEWLINE.join([
        "# Governance Evidence Assessment — Something",
        "",
        "**Target commit:** `db5089e8d8373ebaae1c3ff8ca0864fe92c328dc`",
        "",
        "This assessed the state at that commit.",
    ])
    assert classify_document(declares_its_commit) == "historical_assessment"

    methodology = _NEWLINE.join([
        "# Governance Evidence Assessment",
        "",
        "**Implementation status:** Methodology only; no engine is provided",
    ])
    assert classify_document(methodology) == "methodology"


def test_the_live_governance_documents_are_still_on_the_claim_surface():
    """The other direction: the narrowing must not empty the corpus.

    An exclusion that quietly removed the documents that matter would satisfy
    every guard above by scanning nothing. These four are the repository's live
    claim surface and must remain on it.
    """
    scanned = {path.relative_to(ROOT).as_posix() for path in governance_docs()}
    for required in (
        "README.md",
        "docs/ASSURANCE_BOUNDARY.md",
        "docs/governance/RELEASE_CONTRACT_V1.md",
        "docs/governance/MODULE_ACQUISITION.md",
    ):
        assert required in scanned, (
            required + " left the current-claim surface; the narrowing was "
            "meant to exclude dated assessments, not live governance documents"
        )
    assert len(scanned) >= 20, (
        "the claim surface collapsed to " + str(len(scanned)) + " documents, so "
        "the guards below prove much less than they read as proving"
    )
