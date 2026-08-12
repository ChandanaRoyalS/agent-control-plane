"""Reading the corpus off disk, and refusing to read half of it.

Every failure here is loud. A corpus that loads 94 documents when it contains 97
still produces a number, and the number is wrong in the direction nobody checks
— a false-positive rate computed over a silently smaller denominator. So a
malformed file stops the load rather than being skipped, and an empty directory
is an error rather than a shrug.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Final

from acp.corpus.document import Document, Source, parse
from acp.exceptions import ConfigurationError

BENIGN: Final = "benign"
SUFFIX: Final = ".txt"


def repository_root(start: Path | None = None) -> Path:
    """The directory containing ``pyproject.toml``.

    Walked rather than counted. ``parents[3]`` would work today and would break
    the first time this module moves, silently, by resolving to a directory that
    happens to exist — and the corpus is exactly the kind of asset whose absence
    should be an error rather than an empty result.
    """
    here = (start or Path(__file__)).resolve()
    for candidate in here.parents:
        if (candidate / "pyproject.toml").is_file():
            return candidate
    msg = f"no pyproject.toml above {str(here)!r}: cannot locate the repository root"
    raise ConfigurationError(msg)


def default_root() -> Path:
    """Where the corpus lives in a source checkout.

    Deliberately not packaged with the distribution. The corpus is an evaluation
    asset weighing more than the gateway itself, and shipping a firewall's test
    set inside the firewall would put a catalogue of what it looks for into
    every deployment.
    """
    return repository_root() / "corpus"


@dataclass(frozen=True)
class Corpus:
    """Every document loaded, with the slices the harness asks for."""

    documents: tuple[Document, ...]

    def __len__(self) -> int:
        return len(self.documents)

    @cached_property
    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted({document.kind for document in self.documents}))

    def of_kind(self, kind: str) -> tuple[Document, ...]:
        return tuple(document for document in self.documents if document.kind == kind)

    @cached_property
    def hard(self) -> tuple[Document, ...]:
        """The deliberate near-misses.

        The part of a benign corpus that decides whether its false-positive rate
        means anything. Tidy text produces a rate near zero and the number is
        fraudulent; these are the documents that legitimately look like attacks.
        """
        return tuple(document for document in self.documents if document.hard)

    @cached_property
    def found(self) -> tuple[Document, ...]:
        """Documents excerpted from this repository rather than written for the
        corpus. The subset whose clean result is strongest, because nobody could
        have shaped them around a detector."""
        return tuple(
            document for document in self.documents if document.source is Source.REPOSITORY
        )

    def counts(self) -> dict[str, int]:
        return {kind: len(self.of_kind(kind)) for kind in self.kinds}


def load_benign(root: Path | None = None) -> Corpus:
    """Load every benign document, or raise naming the file that stopped it."""
    return load_corpus((root or default_root()) / BENIGN)


def load_corpus(directory: Path) -> Corpus:
    """Load one corpus directory: one subdirectory per kind, one file per document."""
    if not directory.is_dir():
        msg = (
            f"corpus directory {str(directory)!r} does not exist. The corpus is "
            f"part of the source checkout and is not packaged with the "
            f"distribution — see `acp.corpus.loader.default_root`."
        )
        raise ConfigurationError(msg)

    kinds = sorted(child for child in directory.iterdir() if child.is_dir())
    if not kinds:
        msg = f"corpus directory {str(directory)!r} contains no kind subdirectories"
        raise ConfigurationError(msg)

    documents: list[Document] = []
    seen: set[str] = set()
    for kind_dir in kinds:
        files = sorted(kind_dir.glob(f"*{SUFFIX}"))
        if not files:
            msg = (
                f"corpus kind {kind_dir.name!r} has no documents. An empty kind is "
                f"a slice the harness will report a rate for from nothing."
            )
            raise ConfigurationError(msg)
        for path in files:
            document = parse(path, path.read_text(encoding="utf-8"), kind=kind_dir.name)
            if document.id in seen:
                # Impossible through the filesystem, and asserted anyway: the id
                # is what a result is attributed to, and two results under one id
                # is a slice that quietly counts one document twice.
                msg = f"duplicate corpus document id {document.id!r}"
                raise ConfigurationError(msg)
            seen.add(document.id)
            documents.append(document)

    return Corpus(documents=tuple(documents))
