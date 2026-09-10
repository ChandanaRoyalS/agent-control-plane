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

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from acp.corpus.attack import Attack
from acp.corpus.loader import AttackCorpus, default_root, load_attacks
from acp.exceptions import ConfigurationError

_VERSION_PREFIX = "version:"


@dataclass(frozen=True, slots=True)
class HeldoutManifest:
    """The sealed set of attack ids, and the version that names this split."""

    version: int
    ids: frozenset[str]

    digests: Mapping[str, str] = field(default_factory=dict)
    """``id -> sha256`` of the document's bytes, for the ids that carry one.

    **What turns a list into a seal.** Without it, "held out" is a promise that
    the files were not read while tuning — a promise nothing checks and which an
    edit to one of those files quietly breaks. With it, a held-out document that
    changed since the split was drawn fails the load, and a measurement citing
    "held-out v1" names a set whose contents can be shown to be the same set.

    Optional per id so a split can be committed before its documents settle, and
    absent digests are reported by `verify_seal` rather than assumed to match —
    an unsealed entry is a weaker claim, not an equivalent one.
    """

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
    digests: dict[str, str] = {}
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
        # Anything else is an attack id, optionally followed by the sha256 of
        # the document it names: `<family>/<slug>  sha256:<hex>`. The digest is
        # what makes this a *seal* rather than a list — see `verify_seal`.
        stripped, _, digest = (part.strip() for part in stripped.partition("sha256:"))
        stripped = stripped.rstrip()
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
        if digest:
            digests[stripped] = digest

    if version is None:
        msg = f"held-out manifest {str(path)!r} has no `version:` line"
        raise ConfigurationError(msg)
    if not ids:
        msg = (
            f"held-out manifest {str(path)!r} holds nothing out. An empty split "
            f"is a measurement against nothing — remove the file or add ids."
        )
        raise ConfigurationError(msg)

    return HeldoutManifest(version=version, ids=frozenset(ids), digests=digests)


@dataclass(frozen=True, slots=True)
class Split:
    """A corpus divided into what may be tuned against and what may not."""

    development: AttackCorpus
    heldout: AttackCorpus
    version: int

    manifest: HeldoutManifest | None = None
    """The manifest this split came from, carried so a caller can check the
    seal without loading it a second time and risking a different file."""


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
        manifest=manifest,
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


def digest_of(attack: Attack) -> str:
    """The seal for one held-out attack.

    Over the payload **and its expectation**, not the payload alone. Editing
    `expect: detected` to `expect: undetected` after a disappointing run is the
    tampering worth detecting, and a digest that covered only the text would not
    notice it. Whitespace-only formatting of the front matter is not covered,
    which is the deliberate trade: a reformat should not break a seal, and a
    changed claim should.
    """
    material = json.dumps(
        [SEAL_VERSION, attack.id, str(attack.expect), str(attack.source), attack.text],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


SEAL_VERSION: Final = "acp-heldout-seal-v1"
"""Domain separation, so a digest computed under a future scheme cannot be
mistaken for one computed under this one."""


def verify_seal(corpus: AttackCorpus, manifest: HeldoutManifest | None) -> tuple[str, ...]:
    """Ids whose document no longer matches the digest the manifest recorded.

    Returns them rather than raising, because the caller decides what a broken
    seal means: the evaluation harness refuses to report a held-out number, and
    a test asserts the tuple is empty. Ids with no recorded digest are not
    reported here — `unsealed_ids` answers that question separately, so
    "changed" and "never sealed" cannot be confused.
    """
    if manifest is None:
        return ()
    broken: list[str] = []
    for attack in corpus.attacks:
        expected = manifest.digests.get(attack.id)
        if expected is not None and digest_of(attack) != expected:
            broken.append(attack.id)
    return tuple(sorted(broken))


def unsealed_ids(manifest: HeldoutManifest | None) -> tuple[str, ...]:
    """Held-out ids carrying no digest. A weaker claim, named rather than hidden."""
    if manifest is None:
        return ()
    return tuple(sorted(manifest.ids - set(manifest.digests)))
