"""The packaging guard must see every way of shipping a directory.

Each case below is a real spelling an independent review used to slip
`scripts/` — which holds `issue_action_approval.py` and
`issue_inspection_attestation.py` — past the old guard while it asserted the
opposite.

The parser is tested against synthetic Dockerfiles rather than the repository's
own, because the repository's is correct: a guard verified only against the
passing case is exactly the facade being replaced.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from dockerfile_surface import assert_image_excludes, copy_sources, ships

ROOT = Path(__file__).resolve().parents[1]

#: Every one of these ships scripts/ and every one passed the previous guard.
EVASIONS = [
    ("second source argument", "COPY pyproject.toml scripts /app/"),
    ("relative prefix", "COPY ./scripts /app/scripts"),
    ("file beneath the directory", "COPY scripts/issue_action_approval.py /app/sign.py"),
    ("trailing slash", "COPY scripts/ /app/scripts/"),
    ("ADD instead of COPY", "ADD scripts /app/scripts"),
    ("lowercase instruction", "copy scripts /app/scripts"),
    ("flag mistaken for source", "COPY --chown=1:1 . /app"),
    ("whole build context", "COPY . /app"),
    ("line continuation", "COPY pyproject.toml \\\n    scripts \\\n    /app/"),
    ("json array form", 'COPY ["scripts", "/app/scripts"]'),
]


@pytest.mark.parametrize(
    ("label", "instruction"), EVASIONS, ids=[case[0] for case in EVASIONS]
)
def test_every_way_of_shipping_the_directory_is_detected(label: str, instruction: str):
    dockerfile = "FROM python:3.12-slim\nWORKDIR /app\n" + instruction + "\n"
    assert ships(dockerfile, "scripts"), f"{label}: not detected"


HONEST = [
    ("unrelated directory", "COPY src /app/src"),
    ("similarly named prefix", "COPY scripts_docs /app/scripts_docs"),
    ("destination happens to be named scripts", "COPY src /app/scripts"),
]


@pytest.mark.parametrize(("label", "instruction"), HONEST, ids=[case[0] for case in HONEST])
def test_an_honest_dockerfile_is_not_flagged(label: str, instruction: str):
    """A guard that cries wolf gets deleted, so the false-positive side matters.

    `COPY src /app/scripts` is the pointed case: the destination is named
    `scripts` and nothing from `scripts/` is shipped. Matching on the
    destination would fail the real Dockerfile the moment someone renamed a
    directory inside the image.
    """
    dockerfile = "FROM python:3.12-slim\nWORKDIR /app\n" + instruction + "\n"
    assert not ships(dockerfile, "scripts"), f"{label}: falsely flagged"


def test_the_parser_reads_sources_not_destinations():
    dockerfile = "COPY pyproject.toml README.md /app/\n"
    assert copy_sources(dockerfile) == ["pyproject.toml", "README.md"]


def test_the_committed_dockerfile_excludes_the_signing_utilities():
    """The property this exists for, against the real file."""
    assert_image_excludes("scripts", root=ROOT)


def test_no_signing_primitive_reaches_the_runtime_package():
    """Packaging is one route in; importing is another.

    `scripts/` staying out of the image is worth nothing if a module under
    `src/` re-exports the signing capability, so the verification modules are
    checked for private-key handling directly.
    """
    for name in ("approval_trust.py", "reviewer_trust.py"):
        source = (ROOT / "src/nornyx_forge" / name).read_text(encoding="utf-8")
        for primitive in (
            "load_pem_private_key",
            "Ed25519PrivateKey",
            "from_private_bytes",
            ".sign(",
        ):
            assert primitive not in source, (
                f"{name} contains {primitive!r}: the runtime image must carry "
                "verification material only"
            )
