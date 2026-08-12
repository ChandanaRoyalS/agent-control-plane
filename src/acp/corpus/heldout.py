"""The held-out split: the attacks the firewall is not allowed to be built against.

A detection rate over the corpus the firewall was tuned on measures fit, not
generalisation — it answers "does the firewall catch the attacks it was shaped
by", which it must, because it was shaped by them. The held-out split is the
answer to a different and harder question: does it catch attacks it has never
seen. That number only means anything if the split is sealed — if nothing in it
influenced a detector — so the split is a committed, versioned manifest rather
than a random draw, and the loader that serves the development corpus excludes it
by construction.

This module is deliberately incurious about what the held-out documents *say*.
It partitions by id and never inspects a body; the whole discipline is that those
documents stay unread until there is a number to report against them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from acp.corpus.attack import Attack
from acp.corpus.loader import AttackCorpus, default_root, load_attacks
from acp.exceptions import ConfigurationError

_VERSION_PREFIX = "version:"


@dataclass(frozen=True, slots=True)
class HeldoutManifest:
    """The sealed set of attack ids, and the version that names this split."""

    version: int
    ids: frozenset[str]

    def __len__(self) -> int:
        return len(self.ids)


def load_heldout_manifest(path: Path) -> HeldoutManifest:
    """Parse the held-out manifest, or raise naming what stopped it.

    The format is intentionally plain — a ``version:`` line and one attack id per
    line, ``#`` comments and blanks ignored — because a split that a human cannot
    read and check in a diff is a split they cannot trust is sealed.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read held-out manifest {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    version: int | None = None
    ids: set[str] = set()
    for lineno, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(_VERSION_PREFIX):
            value = stripped[len(_VERSION_PREFIX) :].strip()
            try:
                version = int(value)
            except ValueError as exc:
                msg = (
                    f"held-out manifest {str(path)!r} line {lineno}: "
                    f"version must be an integer, got {value!r}"
                )
                raise ConfigurationError(msg) from exc
            continue
        # Anything else is an attack id. It must look like <family>/<slug> — a
        # bare word here is a typo that would silently hold nothing out.
        if "/" not in stripped:
            msg = (
                f"held-out manifest {str(path)!r} line {lineno}: "
                f"{stripped!r} is not an attack id (<family>/<slug>)"
            )
            raise ConfigurationError(msg)
        if stripped in ids:
            msg = f"held-out manifest {str(path)!r} line {lineno}: duplicate id {stripped!r}"
            raise ConfigurationError(msg)
        ids.add(stripped)

    if version is None:
        msg = f"held-out manifest {str(path)!r} has no `version:` line"
        raise ConfigurationError(msg)
    if not ids:
        msg = (
            f"held-out manifest {str(path)!r} holds nothing out. An empty split "
            f"is a measurement against nothing — remove the file or add ids."
        )
        raise ConfigurationError(msg)

    return HeldoutManifest(version=version, ids=frozenset(ids))


@dataclass(frozen=True, slots=True)
class Split:
    """A corpus divided into what may be tuned against and what may not."""

    development: AttackCorpus
    heldout: AttackCorpus
    version: int


def split_attacks(corpus: AttackCorpus, manifest: HeldoutManifest) -> Split:
    """Partition ``corpus`` into development and held-out on the manifest's ids.

    Raises if the manifest names an id the corpus does not contain: a held-out
    entry pointing at nothing is a seal on an empty box, and usually a rename the
    manifest did not follow.
    """
    by_id = {attack.id: attack for attack in corpus.attacks}
    missing = sorted(manifest.ids - by_id.keys())
    if missing:
        msg = (
            f"held-out manifest names {len(missing)} id(s) not in the corpus: "
            f"{', '.join(missing)}. A held-out id that matches no document seals "
            f"nothing — check for a renamed or deleted attack."
        )
        raise ConfigurationError(msg)

    development: list[Attack] = []
    heldout: list[Attack] = []
    for attack in corpus.attacks:
        (heldout if attack.id in manifest.ids else development).append(attack)

    return Split(
        development=AttackCorpus(attacks=tuple(development)),
        heldout=AttackCorpus(attacks=tuple(heldout)),
        version=manifest.version,
    )


def default_heldout_path(root: Path | None = None) -> Path:
    """Where the held-out manifest lives in a source checkout."""
    return (root or default_root()) / "heldout.txt"


def load_split(root: Path | None = None) -> Split:
    """Load the full attack corpus and partition it on the committed manifest."""
    corpus = load_attacks(root)
    manifest = load_heldout_manifest(default_heldout_path(root))
    return split_attacks(corpus, manifest)


def load_development_attacks(root: Path | None = None) -> AttackCorpus:
    """The attacks a detector may be built and tuned against — the held-out split
    removed. This is the loader task 51's tuning should call instead of
    ``load_attacks``, so a detector cannot be shaped by a sealed document without
    someone deliberately reaching past this function to do it.
    """
    return load_split(root).development
