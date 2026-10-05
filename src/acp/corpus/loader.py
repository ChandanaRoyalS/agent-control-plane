"""Loading the corpus from disk; every malformed file or empty directory is an error.

A silently skipped file would shrink the denominator of every reported rate.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Final

from acp.corpus.attack import Attack, AttackFamily, Expectation, parse_attack
from acp.corpus.document import Document, Source, parse
from acp.exceptions import ConfigurationError

BENIGN: Final = "benign"
ATTACK: Final = "attack"
SUFFIX: Final = ".txt"


def repository_root(start: Path | None = None) -> Path:
    """The nearest ancestor directory containing ``pyproject.toml``.

    Raises:
        ConfigurationError: if there is none.
    """
    here = (start or Path(__file__)).resolve()
    for candidate in here.parents:
        if (candidate / "pyproject.toml").is_file():
            return candidate
    msg = f"no pyproject.toml above {str(here)!r}: cannot locate the repository root"
    raise ConfigurationError(msg)


def default_root() -> Path:
    """The corpus directory in a source checkout; deliberately not packaged."""
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
        """The deliberate near-misses that make the false-positive rate meaningful."""
        return tuple(document for document in self.documents if document.hard)

    @cached_property
    def found(self) -> tuple[Document, ...]:
        """Documents excerpted from this repository (the strongest evidence)."""
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
                # Impossible via the filesystem; asserted so no result is double-counted.
                msg = f"duplicate corpus document id {document.id!r}"
                raise ConfigurationError(msg)
            seen.add(document.id)
            documents.append(document)

    return Corpus(documents=tuple(documents))


@dataclass(frozen=True)
class AttackCorpus:
    """Every attack loaded, with the slices the harness asks for.

    A separate type from `Corpus` so benign and attack documents cannot be mixed.
    """

    attacks: tuple[Attack, ...]

    def __len__(self) -> int:
        return len(self.attacks)

    @cached_property
    def families(self) -> tuple[AttackFamily, ...]:
        return tuple(sorted({attack.family for attack in self.attacks}))

    def of_family(self, family: AttackFamily) -> tuple[Attack, ...]:
        return tuple(attack for attack in self.attacks if attack.family is family)

    def expecting(self, expect: Expectation) -> tuple[Attack, ...]:
        return tuple(attack for attack in self.attacks if attack.expect is expect)

    @cached_property
    def undetectable(self) -> tuple[Attack, ...]:
        """The attacks expected to be undetected."""
        return self.expecting(Expectation.UNDETECTED)

    def counts(self) -> dict[str, int]:
        return {str(family): len(self.of_family(family)) for family in self.families}


def load_attacks(root: Path | None = None) -> AttackCorpus:
    """Load every adversarial document, or raise naming the file that stopped it."""
    directory = (root or default_root()) / ATTACK
    if not directory.is_dir():
        msg = (
            f"attack corpus {str(directory)!r} does not exist. The corpus is part "
            f"of the source checkout and is not packaged with the distribution — "
            f"see `acp.corpus.loader.default_root`."
        )
        raise ConfigurationError(msg)

    families = sorted(child for child in directory.iterdir() if child.is_dir())
    if not families:
        msg = f"attack corpus {str(directory)!r} contains no family subdirectories"
        raise ConfigurationError(msg)

    attacks: list[Attack] = []
    seen: set[str] = set()
    for family_dir in families:
        files = sorted(family_dir.glob(f"*{SUFFIX}"))
        if not files:
            msg = (
                f"attack family {family_dir.name!r} has no documents. An empty family "
                f"is a slice the harness will report a rate for from nothing."
            )
            raise ConfigurationError(msg)
        for path in files:
            attack = parse_attack(path, path.read_text(encoding="utf-8"), family=family_dir.name)
            if attack.id in seen:
                msg = f"duplicate attack id {attack.id!r}"
                raise ConfigurationError(msg)
            seen.add(attack.id)
            attacks.append(attack)

    return AttackCorpus(attacks=tuple(attacks))
