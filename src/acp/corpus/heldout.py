"""The held-out split: attacks no detector may be tuned against (ADR 0041).

A committed, versioned manifest of attack IDs; the development loader excludes
them by construction. A split is scored once, after which its manifest records
``unsealed:``. This module partitions by ID and never reads a held-out body.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from acp.corpus.attack import Attack
from acp.corpus.loader import AttackCorpus, default_root, load_attacks
from acp.exceptions import ConfigurationError

_VERSION_PREFIX = "version:"
_UNSEALED_PREFIX = "unsealed:"


@dataclass(frozen=True, slots=True)
class HeldoutManifest:
    """The sealed set of attack ids, and the version that names this split."""

    version: int
    ids: frozenset[str]
    unsealed: str | None = None
    """When and where this version was scored (e.g. ``2026-10-04, ADR 0060``), else None.

    Once scored, a split is no longer unseen, and later runs must say so.
    """

    def __len__(self) -> int:
        return len(self.ids)


def load_heldout_manifest(path: Path) -> HeldoutManifest:
    """Parse the manifest: a ``version:`` line, optional ``unsealed:``, one ID per line.

    ``#`` comments and blank lines are ignored.

    Raises:
        ConfigurationError: if the file is unreadable, malformed, or holds no IDs.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read held-out manifest {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    version: int | None = None
    unsealed: str | None = None
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
        if stripped.startswith(_UNSEALED_PREFIX):
            unsealed = stripped[len(_UNSEALED_PREFIX) :].strip()
            if not unsealed:
                msg = (
                    f"held-out manifest {str(path)!r} line {lineno}: `unsealed:` needs "
                    f"a date and a reference, e.g. `unsealed: 2026-10-04, ADR 0060`"
                )
                raise ConfigurationError(msg)
            continue
        # An attack ID must be <family>/<slug>; a bare word is a typo.
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

    return HeldoutManifest(version=version, ids=frozenset(ids), unsealed=unsealed)


@dataclass(frozen=True, slots=True)
class Split:
    """A corpus divided into what may be tuned against and what may not."""

    development: AttackCorpus
    heldout: AttackCorpus
    version: int
    unsealed: str | None = None


def split_attacks(corpus: AttackCorpus, manifest: HeldoutManifest) -> Split:
    """Partition ``corpus`` into development and held-out on the manifest's IDs.

    Raises:
        ConfigurationError: if the manifest names an ID not in the corpus.
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
        unsealed=manifest.unsealed,
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
    """The attacks without the held-out split; detector tuning calls this, not ``load_attacks``."""
    return load_split(root).development
