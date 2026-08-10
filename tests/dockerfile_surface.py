"""What the runtime image actually copies.

The guard this replaces was three verbatim copies of:

    copied = [line.split()[1] for line in dockerfile.splitlines()
              if line.startswith("COPY ") and len(line.split()) > 2]
    assert "scripts" not in copied

It inspected only the *first* source argument of each `COPY`, matched by exact
string, and ignored `ADD` and lowercase entirely. An independent review listed
seven ways to ship the signer past it:

    COPY pyproject.toml scripts /app/       second source never inspected
    COPY ./scripts /app/scripts             "./scripts" != "scripts"
    COPY scripts/issue_action_approval.py   a path, not the directory
    COPY scripts/ /app/scripts/             trailing slash
    ADD scripts /app/scripts                ADD not considered
    copy scripts /app/scripts               lowercase not considered
    COPY --chown=1:1 . /app                 flag taken as the source

The Dockerfile is correct today, so all three copies passed while asserting a
property none of them could see. That the assertion is load-bearing —
`scripts/` holds both issuers, and the image must carry verification material
only — is what makes a facade worse here than no test.

One parser, one place, used by every caller.
"""

from __future__ import annotations

import shlex
from pathlib import Path

#: Instructions that place files into the image.
COPY_INSTRUCTIONS = {"copy", "add"}


def copy_sources(dockerfile: str) -> list[str]:
    """Every source path any COPY or ADD places into the image.

    Sources are all arguments except the final destination, with flags removed
    and `./` prefixes and trailing slashes normalised away, so a path is
    compared as the thing it names rather than as the way it was spelled.

    Line continuations are joined first: a `COPY` split across lines with a
    trailing backslash would otherwise present its sources as separate,
    unrecognised lines.
    """
    joined: list[str] = []
    pending = ""
    for raw in dockerfile.splitlines():
        line = raw.rstrip()
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        joined.append(pending + line)
        pending = ""
    if pending:
        joined.append(pending)

    sources: list[str] = []
    for line in joined:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            parts = shlex.split(stripped, posix=False)
        except ValueError:  # unbalanced quotes; treat conservatively
            parts = stripped.split()
        if not parts or parts[0].lower() not in COPY_INSTRUCTIONS:
            continue

        arguments = [item for item in parts[1:] if not item.startswith("--")]
        if len(arguments) < 2:
            continue
        # JSON-array form: COPY ["src", "dest"]
        if arguments[0].startswith("["):
            cleaned = " ".join(arguments).strip("[]")
            arguments = [item.strip().strip('"').strip("'") for item in cleaned.split(",")]
            if len(arguments) < 2:
                continue

        for source in arguments[:-1]:
            sources.append(normalise(source))
    return sources


def normalise(path: str) -> str:
    """Compare a path by what it names, not how it was written."""
    cleaned = path.strip().strip('"').strip("'").replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.rstrip("/")


def ships(dockerfile: str, directory: str) -> bool:
    """True when any COPY or ADD would place `directory` into the image.

    Covers the directory itself, anything beneath it, and a whole-context copy
    (`COPY . /app`), which ships everything the .dockerignore does not remove.
    """
    wanted = normalise(directory)
    for source in copy_sources(dockerfile):
        if source == wanted or source.startswith(wanted + "/"):
            return True
        if source in {".", ""}:
            return True
    return False


def assert_image_excludes(directory: str = "scripts", *, root: Path | None = None) -> None:
    """Fail if the runtime image would carry `directory`.

    The single assertion every caller shares, so the parser cannot be improved
    in one test file and left weak in the others — which is how three copies of
    the old guard came to exist.
    """
    location = (root or Path(__file__).resolve().parents[1]) / "Dockerfile"
    dockerfile = location.read_text(encoding="utf-8")
    assert not ships(dockerfile, directory), (
        f"the runtime image copies {directory!r}, which holds the signing "
        "utilities. The image must carry verification material only."
    )
