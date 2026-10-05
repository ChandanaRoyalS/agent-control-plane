"""One benign corpus document and the front matter that makes it checkable evidence.

``why`` says why it is here, ``source`` whether it is real repository text or
synthetic (weaker evidence), and ``hard`` marks deliberate near-misses, whose
minimum count a test asserts. Front-matter parsing is shared with
`acp.corpus.attack`. See ADR 0039 and ADR 0040.
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
"""Front-matter fence, so the body is stored verbatim (invisible characters included)."""

REQUIRED: Final = frozenset({"why", "source"})
UNDERSTOOD: Final = REQUIRED | {"hard"}


class Source(StrEnum):
    """Where a document's text came from."""

    REPOSITORY = "repository"
    """Excerpted unaltered from this repository, so not shaped around a detector."""

    SYNTHETIC = "synthetic"
    """Written for this corpus; weaker evidence, since its author knew the detectors."""


@dataclass(frozen=True, slots=True)
class Document:
    """One benign document, and why it is in the corpus."""

    id: str
    """``<kind>/<slug>``, derived from the path."""

    kind: str
    """The containing directory (runbook, incident, advisory, adr, code, ticket,
    db_row, log, email, doc, chat, i18n, spec)."""

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
    """Split a corpus file into metadata and body.

    Raises:
        ConfigurationError: on a missing fence, invalid YAML, a missing required
            key, an unknown key (so typos cannot silently change meaning), or an
            empty body.
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
