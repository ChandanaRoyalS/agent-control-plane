"""Scoring any yes/no injection detector (e.g. DeBERTa, Prompt Guard) before wiring it (ADR 0039).

Scored on the benign documents (false positives, by name), the internal
development attacks by family, and InjecAgent's development half (ADR 0061),
where an attack counts as caught only if the template without it is not flagged;
intervals resample attacker instructions. Held-out splits are not touched.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from acp.corpus.attack import Attack, AttackFamily
from acp.corpus.classifier_eval import Latency, percentile, prepare
from acp.corpus.document import Document
from acp.corpus.external import SUBSETS, VARIANTS, ExternalDocument
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion, measure, measure_clustered

Detect = Callable[[str], bool]
"""Text in, "is this an injection" out; the seam a backend fills."""

Progress = Callable[[int, int], None]


@dataclass(frozen=True, slots=True)
class FamilyRow:
    family: AttackFamily
    detected: Proportion


@dataclass(frozen=True, slots=True)
class SliceRow:
    label: str
    groups: int
    caught: Proportion
    """Yes on the attack, no on its control."""
    flagged: Proportion
    """Yes on the attack, whatever the control got."""


@dataclass(frozen=True, slots=True)
class DetectorReport:
    benign_flagged: Proportion
    benign_flagged_ids: tuple[str, ...]
    internal: tuple[FamilyRow, ...]
    external: tuple[SliceRow, ...]
    controls_flagged: int
    """Attack-free templates the detector still flagged (false positives)."""
    latency: Latency


def evaluate_detector(
    detect: Detect,
    *,
    benign: Sequence[Document],
    attacks: Sequence[Attack],
    external: Sequence[ExternalDocument],
    seed: int = 0,
    resamples: int = DEFAULT_RESAMPLES,
    clock: Callable[[], float] = time.perf_counter,
    progress: Progress | None = None,
) -> DetectorReport:
    """Ask the detector about every document and its control; score the answers."""
    jobs: list[tuple[str, str]] = [(f"benign:{d.id}", d.text) for d in benign]
    jobs.extend((f"attack:{a.id}", a.text) for a in attacks)
    for e in external:
        jobs.append((f"external:{e.id}", e.text))
        jobs.append((f"control:{e.id}", e.control))

    said: dict[str, bool] = {}
    seconds: list[float] = []
    for index, (key, text) in enumerate(jobs, start=1):
        started = clock()
        said[key] = detect(prepare(text))
        seconds.append(clock() - started)
        if progress is not None:
            progress(index, len(jobs))

    rng = random.Random(seed)  # noqa: S311 — reproducibility, not cryptography
    benign_flags = [said[f"benign:{d.id}"] for d in benign]

    by_family: dict[AttackFamily, list[bool]] = {}
    for a in attacks:
        by_family.setdefault(a.family, []).append(said[f"attack:{a.id}"])

    def caught(e: ExternalDocument) -> bool:
        return said[f"external:{e.id}"] and not said[f"control:{e.id}"]

    slices: list[SliceRow] = []
    for subset in SUBSETS:
        for variant in VARIANTS:
            members = [e for e in external if e.subset == subset and e.variant == variant]
            if not members:
                continue
            groups: dict[str, list[ExternalDocument]] = {}
            for e in members:
                groups.setdefault(e.group, []).append(e)
            grouped = list(groups.values())
            slices.append(
                SliceRow(
                    label=f"{subset} {variant}",
                    groups=len(grouped),
                    caught=measure_clustered(
                        [[caught(e) for e in g] for g in grouped], rng=rng, resamples=resamples
                    ),
                    flagged=measure_clustered(
                        [[said[f"external:{e.id}"] for e in g] for g in grouped],
                        rng=rng,
                        resamples=resamples,
                    ),
                )
            )

    return DetectorReport(
        benign_flagged=measure(benign_flags, rng=rng, resamples=resamples),
        benign_flagged_ids=tuple(d.id for d in benign if said[f"benign:{d.id}"]),
        internal=tuple(
            FamilyRow(family=f, detected=measure(by_family[f], rng=rng, resamples=resamples))
            for f in sorted(by_family, key=lambda f: f.value)
        ),
        external=tuple(slices),
        controls_flagged=sum(1 for e in external if said[f"control:{e.id}"]),
        latency=Latency(
            calls=len(seconds),
            median=percentile(seconds, 0.5),
            p95=percentile(seconds, 0.95),
            worst=max(seconds, default=0.0),
        ),
    )
