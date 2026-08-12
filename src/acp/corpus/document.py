"""One corpus document, and the metadata that makes it evidence rather than data.

A corpus is the only thing that can turn "this firewall works" into a number, so
every document in it is a claim somebody has to be able to check. Three fields
carry that weight, and each exists because a corpus without it can be read as
proving more than it does.

**``why``.** Why this document is here. For an ordinary one that is
uninteresting; for a *hard* one it is the whole point — "contains 'ignore
previous instructions' as prose about the attack" is what tells a reviewer this
file is load-bearing rather than filler, and stops somebody deleting it when it
starts failing.

**``source``.** Whether the text was excerpted from this repository or written
for the corpus. This is the honesty field. A corpus invented by the same author
as the detectors has a ceiling on what it can prove — the author knows what the
patterns look for and will, without meaning to, write around them. Naming which
documents are real lets a reader discount the rest, and gives the corpus
somewhere to grow: replacing synthetic documents with real ones is a measurable
improvement that anybody can make.

**``hard``.** Whether this is a deliberate near-miss. A benign corpus of tidy
text has a false-positive rate near zero and the number is fraudulent. The hard
documents are the ones that legitimately trip a detector — a security advisory
quoting a payload, an emoji family joined by zero-width characters, Arabic with
directional marks, a JWT, a page with a logo on it. A test asserts there are
enough of them, so "this corpus is realistic" is a property the build checks
rather than a claim in a README.

The front-matter parsing here is shared with `acp.corpus.attack`, which needs the
same fencing and the same strictness over a different set of keys. See ADR 0039
for the benign half and ADR 0040 for the adversarial one.
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from acp.exceptions import ConfigurationError

DELIMITER: Final = "---"
"""Front matter is fenced the way every static site generator fences it, and
for the same reason: the document below stays exactly what it is, with no
escaping, no quoting and no encoding. That matters more here than anywhere —
many of these documents contain zero-width joiners, directional overrides and
base64 payloads on purpose, and a format that turned those into ``\\u200d``
would be storing a description of the document instead of the document."""

REQUIRED: Final = frozenset({"why", "source"})
UNDERSTOOD: Final = REQUIRED | {"hard"}


class Source(StrEnum):
    """Where a document's text came from."""

    REPOSITORY = "repository"
    """Excerpted from this repository, unaltered. The most valuable kind: it was
    written to be read by humans rather than to be screened, so it cannot have
    been shaped around a detector even accidentally. It also means the firewall
    is tested against the documents its own authors read every day."""

    SYNTHETIC = "synthetic"
    """Written for this corpus, in the shape of the real thing. Honest about its
    limit: whoever wrote it knew what the detectors match, so a clean result on
    synthetic text is weaker evidence than a clean result on found text."""


@dataclass(frozen=True, slots=True)
class Document:
    """One benign document, and why it is in the corpus."""

    id: str
    """``<kind>/<slug>``, derived from the path. Not a field in the file — a
    name that can disagree with its own location is a name that eventually
    does."""

    kind: str
    """The directory it sits in: runbook, incident, advisory, adr, code, ticket,
    db_row, log, email, doc, chat, i18n, spec. Derived, for the same reason."""

    why: str
    source: Source
    hard: bool
    text: str

    @property
    def chars(self) -> int:
        return len(self.text)


def front_matter(
    path: Path,
    text: str,
    *,
    required: AbstractSet[str],
    understood: AbstractSet[str],
) -> tuple[dict[str, Any], str]:
    """Split a corpus file into its metadata and its body, or refuse it by name.

    Strict about unknown keys, and shared by both corpora so they cannot become
    strict in different ways. A corpus is edited by hand over months, and a
    typo'd ``hardd: true`` that silently means "not hard" — or ``expects:``
    where ``expect:`` was meant — is a document quietly leaving the set the
    numbers are computed from, with nothing anywhere to say so.
    """
    if not text.startswith(DELIMITER):
        msg = f"corpus file {str(path)!r} does not begin with a `---` front matter block"
        raise ConfigurationError(msg)

    header, closing, body = text.partition(f"\n{DELIMITER}\n")
    if not closing:
        msg = f"corpus file {str(path)!r} has no closing `---` on its own line"
        raise ConfigurationError(msg)

    try:
        loaded: Any = yaml.safe_load(header[len(DELIMITER) :])
    except yaml.YAMLError as exc:
        msg = f"corpus file {str(path)!r} has invalid front matter: {exc}"
        raise ConfigurationError(msg) from exc

    if not isinstance(loaded, dict):
        msg = f"corpus file {str(path)!r}: front matter must be a mapping"
        raise ConfigurationError(msg)

    missing = set(required) - set(loaded)
    if missing:
        msg = f"corpus file {str(path)!r} is missing front matter: {', '.join(sorted(missing))}"
        raise ConfigurationError(msg)

    unknown = set(loaded) - set(understood)
    if unknown:
        msg = (
            f"corpus file {str(path)!r} has front matter nobody reads: "
            f"{', '.join(sorted(unknown))}. Understood keys are "
            f"{', '.join(sorted(understood))}."
        )
        raise ConfigurationError(msg)

    body = body.strip("\n")
    if not body.strip():
        msg = f"corpus file {str(path)!r} has front matter and no document"
        raise ConfigurationError(msg)

    return loaded, body


def read_source(path: Path, value: object) -> Source:
    try:
        return Source(str(value))
    except ValueError as exc:
        msg = (
            f"corpus file {str(path)!r}: `source` must be one of "
            f"{', '.join(s.value for s in Source)}, got {value!r}"
        )
        raise ConfigurationError(msg) from exc


def read_why(path: Path, value: object) -> str:
    why = str(value).strip()
    if not why:
        msg = f"corpus file {str(path)!r}: `why` is empty, so nobody can tell why it is here"
        raise ConfigurationError(msg)
    return why


def parse(path: Path, text: str, *, kind: str) -> Document:
    """Parse one benign corpus file, or refuse it by name."""
    loaded, body = front_matter(path, text, required=REQUIRED, understood=UNDERSTOOD)

    return Document(
        id=f"{kind}/{path.stem}",
        kind=kind,
        why=read_why(path, loaded["why"]),
        source=read_source(path, loaded["source"]),
        hard=bool(loaded.get("hard", False)),
        text=body,
    )
