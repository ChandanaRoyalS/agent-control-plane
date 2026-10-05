"""BIPIA as a corpus: benign contexts and the same contexts with an instruction planted.

BIPIA (Yi et al., 2023, MIT; Microsoft) pairs everyday contexts (emails, tables,
Stack Overflow answers) with attacker instructions, split by its authors into train
and test with no instruction shared. Text attacks go into emails and tables, code
attacks into code answers, at the start, middle or end, as BIPIA does. Which
contexts and positions each instruction gets is a fixed rule over indices, so the
import is byte-identical on every run. The test half is sealed (ADR 0074).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from acp.corpus.loader import default_root

SOURCE: Final = "bipia"
SPLITS: Final = ("train", "test")
POSITIONS: Final = ("start", "middle", "end")
TEXT_TASKS: Final = ("email", "table")
CODE_TASK: Final = "code"
CONTEXTS_PER_ATTACK: Final = 4
TABLE_CONTEXTS: Final = 100
"""Tables that receive attacks, per split. The test split has 100; the train split's
other 800 are added as clean documents only, as benign training data."""

ATTACK: Final = "attack"
CLEAN: Final = "clean"


@dataclass(frozen=True, slots=True)
class Context:
    task: str
    index: int
    text: str


@dataclass(frozen=True, slots=True)
class Instruction:
    kind: str
    """``text`` or ``code``: which contexts it is planted in."""
    category: str
    text: str


@dataclass(frozen=True, slots=True)
class BipiaDocument:
    id: str
    group: str
    """The instruction for an attack, the context for a clean document."""
    split: str
    task: str
    label: str
    position: str
    category: str
    text: str
    planted: str


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def plant(context: str, instruction: str, position: str) -> str:
    """Insert ``instruction`` on its own line; ``middle`` is before the middle line."""
    if position == "start":
        return f"{instruction}\n{context}"
    if position == "end":
        return f"{context}\n{instruction}"
    lines = context.split("\n")
    cut = len(lines) // 2
    return "\n".join([*lines[:cut], instruction, *lines[cut:]])


def placements(attack_index: int, contexts: int) -> list[tuple[int, str]]:
    """The contexts and positions one instruction is planted in: spread, deterministic."""
    chosen: list[tuple[int, str]] = []
    for k in range(CONTEXTS_PER_ATTACK):
        context = (attack_index * 37 + k * 53) % contexts
        chosen.append((context, POSITIONS[(attack_index + k) % len(POSITIONS)]))
    return chosen


def build(
    split: str,
    contexts: Mapping[str, Sequence[Context]],
    instructions: Sequence[Instruction],
    clean_only: Sequence[Context] = (),
) -> list[BipiaDocument]:
    """Every clean context once, then each instruction in its placements.

    ``clean_only`` contexts appear as clean documents and never receive an attack.
    """
    docs: list[BipiaDocument] = []
    for task in (*TEXT_TASKS, CODE_TASK):
        for ctx in [*contexts[task], *(c for c in clean_only if c.task == task)]:
            docs.append(
                BipiaDocument(
                    id=f"bipia/{split}-{task}-clean-{ctx.index:04d}",
                    group=f"bipia/{split}/ctx-{task}-{ctx.index:04d}",
                    split=split,
                    task=task,
                    label=CLEAN,
                    position="none",
                    category="",
                    text=ctx.text,
                    planted="",
                )
            )
    text_pool = [c for task in TEXT_TASKS for c in contexts[task]]
    code_pool = list(contexts[CODE_TASK])
    for number, instruction in enumerate(instructions):
        pool = text_pool if instruction.kind == "text" else code_pool
        for slot, (where, position) in enumerate(placements(number, len(pool))):
            ctx = pool[where]
            docs.append(
                BipiaDocument(
                    id=f"bipia/{split}-{ctx.task}-attack-{number:03d}-{slot}",
                    group=f"bipia/{split}/{digest(instruction.text)}",
                    split=split,
                    task=ctx.task,
                    label=ATTACK,
                    position=position,
                    category=instruction.category,
                    text=plant(ctx.text, instruction.text, position),
                    planted=instruction.text,
                )
            )
    return docs


def instructions_from(kind: str, raw: Mapping[str, Sequence[str]]) -> list[Instruction]:
    """BIPIA's ``{category: [instruction, ...]}`` in file order."""
    return [Instruction(kind, category, text) for category, texts in raw.items() for text in texts]


def default_bipia_dir(root: Path | None = None) -> Path:
    return (root or default_root()) / "external" / SOURCE


def load_bipia(directory: Path | None = None) -> tuple[BipiaDocument, ...]:
    path = (directory or default_bipia_dir()) / "documents.jsonl"
    return tuple(_parse(path.read_text(encoding="utf-8").splitlines()))


def _parse(lines: Iterable[str]) -> Iterable[BipiaDocument]:
    for line in lines:
        if line.strip():
            row = json.loads(line)
            yield BipiaDocument(**{f: row[f] for f in BipiaDocument.__slots__})


def dump(docs: Iterable[BipiaDocument]) -> str:
    return "".join(
        json.dumps(
            {f: getattr(d, f) for f in BipiaDocument.__slots__}, ensure_ascii=False, sort_keys=True
        )
        + "\n"
        for d in docs
    )
