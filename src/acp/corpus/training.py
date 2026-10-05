"""The learned classifier's data: what it trains on, tunes on, and is scored on (ADR 0074).

- **train**: InjecAgent development groups (poisoned responses and the same responses
  with the instruction removed), BIPIA's train split (planted and clean contexts), and
  CPython standard-library docstrings as benign technical prose.
- **validation**: one fifth of those groups by salted hash, for choosing a threshold.
- **report-only**: the internal benign corpus and the internal development attacks,
  never trained on, so the false-positive yardstick stays independent.
- **sealed**: BIPIA's test split and the evasion corpus built from it, scored once.

Splits are by group (one attacker instruction, or one context), so the same
sentence never sits on both sides; `check_disjoint` enforces it.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from acp.corpus.bipia import ATTACK, BipiaDocument, default_bipia_dir, load_bipia
from acp.corpus.external import load_external_split
from acp.corpus.heldout import load_development_attacks
from acp.corpus.loader import default_root, load_benign
from acp.firewall.learned import normalise, windows

VALIDATION_SALT: Final = "acp-classifier-validation-v1"
VALIDATION_SHARE: Final = 5
"""One group in five goes to validation."""
TRANSFORMER_DESIGN: Final[dict[str, Any]] = {
    "base": "distilbert/distilroberta-base",
    "epochs": 3,
    "batch_size": 16,
    "learning_rate": 2e-5,
    "weight_decay": 0.01,
    "warmup_share": 0.06,
    "max_tokens": 512,
    "seed": 0,
    "limit": None,
}
"""The transformer run fixed in ADR 0077 before any training; only it may see sealed sets."""
FILLER_CHARS: Final = (40, 160)
"""Length bounds for a benign sentence standing in for a removed instruction."""


@dataclass(frozen=True, slots=True)
class Example:
    id: str
    text: str
    label: int
    """1 for an attack, 0 for benign."""
    group: str
    source: str
    planted: str = ""
    """The planted instruction, when the source records it; empty otherwise."""


@dataclass(frozen=True, slots=True)
class Datasets:
    train: tuple[Example, ...]
    validation: tuple[Example, ...]
    report: dict[str, tuple[Example, ...]] = field(default_factory=dict)
    sealed: dict[str, tuple[Example, ...]] = field(default_factory=dict)


def in_validation(group: str) -> bool:
    digest = hashlib.sha256(f"{VALIDATION_SALT}:{group}".encode()).hexdigest()
    return int(digest, 16) % VALIDATION_SHARE == 0


def _text_group(text: str) -> str:
    return "text/" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def _dedupe(examples: Iterable[Example]) -> list[Example]:
    seen: set[str] = set()
    kept: list[Example] = []
    for example in examples:
        if example.text not in seen:
            seen.add(example.text)
            kept.append(example)
    return kept


def _bipia(docs: Iterable[BipiaDocument], source: str) -> list[Example]:
    return [Example(d.id, d.text, int(d.label == ATTACK), d.group, source, d.planted) for d in docs]


def fillers(docs: Iterable[BipiaDocument]) -> list[str]:
    """Benign sentences from BIPIA's train emails, to stand where an instruction was."""
    found: set[str] = set()
    for d in docs:
        if d.split == "train" and d.task == "email" and d.label != ATTACK:
            for raw in d.text.replace("\n", " ").split(". "):
                sentence = " ".join(raw.split())
                if FILLER_CHARS[0] <= len(sentence) <= FILLER_CHARS[1] and "|" not in sentence:
                    found.add(sentence.rstrip(".") + ".")
    return sorted(found)


def control_text(text: str, planted: str, pool: Sequence[str]) -> str:
    """The template with its instruction replaced by a benign sentence.

    Removing the instruction outright leaves an empty field (``''``) that real text
    rarely has, and a model learns that instead of the instruction (ADR 0075).
    """
    choice = int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16) % len(pool)
    return text.replace(planted, pool[choice], 1)


def development_pool(root: Path | None = None) -> list[Example]:
    """Everything the classifier may learn from, before the validation cut."""
    root = root or default_root()
    injecagent = load_external_split(root / "external" / "injecagent").development
    bipia = load_bipia(default_bipia_dir(root))
    pool_sentences = fillers(bipia)
    pool = [Example(d.id, d.text, 1, d.group, "injecagent", d.planted) for d in injecagent]
    for d in injecagent:
        # Many groups share a template, so a control's group is its text, which
        # keeps it on one side of the validation cut.
        pool.append(
            Example(
                f"{d.id}/control",
                control_text(d.text, d.planted, pool_sentences),
                0,
                _text_group(d.control),
                "injecagent",
            )
        )
    pool += _bipia((d for d in bipia if d.split == "train"), "bipia")
    pool += [
        Example(row["id"], row["text"], 0, row["group"], "stdlib")
        for row in _jsonl(root / "external" / "stdlib" / "documents.jsonl")
    ]
    return _dedupe(pool)


def _jsonl(path: Path) -> list[dict[str, str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def assemble(root: Path | None = None, *, unseal: bool = False) -> Datasets:
    """The splits; the sealed sets are empty unless ``unseal`` is set."""
    root = root or default_root()
    pool = development_pool(root)
    benign = load_benign(root)
    attacks = load_development_attacks(root)
    report = {
        "internal_benign": tuple(
            Example(f"benign/{d.id}", d.text, 0, f"benign/{d.id}", "internal")
            for d in benign.documents
        ),
        "internal_attacks": tuple(
            Example(f"attack/{a.id}", a.text, 1, f"attack/{a.id}", "internal")
            for a in attacks.attacks
        ),
    }
    sealed: dict[str, tuple[Example, ...]] = {}
    if unseal:
        bipia = load_bipia(default_bipia_dir(root))
        sealed["bipia_test"] = tuple(_bipia((d for d in bipia if d.split == "test"), "bipia"))
        sealed["evasion_v1"] = tuple(_bipia(load_bipia(root / "external" / "evasion"), "evasion"))
    return Datasets(
        train=tuple(e for e in pool if not in_validation(e.group)),
        validation=tuple(e for e in pool if in_validation(e.group)),
        report=report,
        sealed=sealed,
    )


def check_disjoint(sets: dict[str, Sequence[Example]]) -> None:
    """Raise if any group or exact text appears in two of ``sets``."""
    owner_of_group: dict[str, str] = {}
    owner_of_text: dict[str, str] = {}
    for name, examples in sets.items():
        for e in examples:
            for key, owners in ((e.group, owner_of_group), (e.text, owner_of_text)):
                other = owners.setdefault(key, name)
                if other != name:
                    what = "group" if owners is owner_of_group else "text"
                    msg = f"{e.id}: its {what} is in both {other} and {name}"
                    raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LabelledWindows:
    """Training windows of normalised text, for any model trained on these splits."""

    texts: list[str]
    labels: list[int]
    skipped: Counter[str]


def labelled_windows(examples: Iterable[Example]) -> LabelledWindows:
    """Windows of each example, labelled by how much of the planted instruction they hold.

    A window of an attack document is a positive if it holds at least half of the
    instruction, a negative if it holds none of it (that text is benign context),
    and is skipped otherwise, as is an attack whose instruction cannot be located.
    """
    texts: list[str] = []
    labels: list[int] = []
    skipped: Counter[str] = Counter()
    for e in examples:
        text = normalise(e.text)
        span: tuple[int, int] | None = None
        if e.label == 1:
            planted = normalise(e.planted)
            start = text.find(planted) if planted else -1
            if start < 0:
                skipped["attack without a locatable instruction"] += 1
                continue
            span = (start, start + len(planted))
        for start, window in windows(text):
            if span is None:
                label = 0
            else:
                overlap = max(0, min(span[1], start + len(window)) - max(span[0], start))
                if overlap >= (span[1] - span[0]) / 2:
                    label = 1
                elif overlap == 0:
                    label = 0
                else:
                    skipped["window with part of an instruction"] += 1
                    continue
            texts.append(window)
            labels.append(label)
    return LabelledWindows(texts, labels, skipped)


def data_digest(examples: Iterable[Example]) -> str:
    """A hash of ids, labels and texts: two models with equal digests saw the same data."""
    h = hashlib.sha256()
    for e in sorted(examples, key=lambda e: e.id):
        h.update(f"{e.id}\0{e.label}\0{e.text}\0".encode())
    return h.hexdigest()
