"""The model classifier, scored on its own.

`acp.corpus.harness` scores the *firewall*, and with the classifier attached the
firewall's numbers cannot say what the model contributed: a benign document the
patterns already flagged is flagged either way, so the model's own false
positives hide behind the patterns' ones. This module asks the model directly,
document by document, and keeps everything the firewall throws away.

**Five outcomes, not two.** The firewall reduces a model call to "finding" or
"nothing", which is right on the request path and useless for measuring the
model, because "nothing" covers four different events:

- `CLEAN` — the model said "not an attack";
- `DISCARDED` — the model said "attack" but named no family, or one the
  firewall cannot report. Until ADR 0062 the prompt itself offered two such
  families; now it offers exactly `Family`, so this counts the model inventing
  one (it once answered `prompt-injection`). Right or wrong, the firewall never
  heard it;
- `MALFORMED` — the answer was not the JSON asked for;
- `FAILED` — the call raised: timeout, connection refused.

Only `FLAGGED` becomes a `Finding`, and `judge` decides it with
`parse_verdict` itself, so the count here and the count in the firewall cannot
disagree about what a finding is.

**The text is prepared the way the screener prepares it** — bounded, then
stripped of invisible characters, then bounded again to what the classifier
sends — so the model is scored on what it would actually see in production.

**Repeats measure agreement.** A model's answer to the same document can change
between calls. Every rate below is computed from the *first* run, so it is
comparable with a single-run firewall evaluation; the later runs only answer
"would the same document get the same answer again?".

Nothing here is a CI gate. The model is not installed in CI, and gating on its
output would make a build fail for reasons nobody could reproduce (ADR 0047).
"""

from __future__ import annotations

import json
import math
import random
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from acp.corpus.attack import Attack, AttackFamily
from acp.corpus.document import Document
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion, measure
from acp.firewall import Family
from acp.firewall.classifier import MAX_CLASSIFIED_CHARS, ClassifyFn, parse_verdict
from acp.firewall.detectors import strip_invisible
from acp.firewall.screen import MAX_SCREENED_CHARS

SMALL_SAMPLE: Final = 10
"""Same threshold, same reason, as `acp.corpus.harness.SMALL_SAMPLE`."""


class Outcome(StrEnum):
    """What one model call amounted to. See the module docstring."""

    FLAGGED = "flagged"
    DISCARDED = "discarded"
    CLEAN = "clean"
    MALFORMED = "malformed"
    FAILED = "failed"

    @property
    def said_attack(self) -> bool:
        """The model's opinion, whether or not the firewall could use it."""
        return self in (Outcome.FLAGGED, Outcome.DISCARDED)


@dataclass(frozen=True, slots=True)
class Call:
    """One model call: what it amounted to, the family it named, how long it took."""

    outcome: Outcome
    family: str | None
    """The family string the model named, verbatim — kept for `DISCARDED`, where
    it is the reason the firewall dropped the answer."""
    seconds: float


def prepare(text: str) -> str:
    """The text the classifier would be sent for ``text`` inside the firewall."""
    return strip_invisible(text[:MAX_SCREENED_CHARS])[:MAX_CLASSIFIED_CHARS]


def judge(raw: str) -> tuple[Outcome, str | None]:
    """Sort a raw model response into an outcome, and the family it named."""
    verdict = parse_verdict(raw)
    if verdict.is_attack and verdict.family is not None:
        return Outcome.FLAGGED, verdict.family.value

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return Outcome.MALFORMED, None
    if not isinstance(data, dict) or not isinstance(data.get("attack"), bool):
        return Outcome.MALFORMED, None
    if not data["attack"]:
        return Outcome.CLEAN, None
    named = data.get("family")
    return Outcome.DISCARDED, named if isinstance(named, str) else None


def classify_once(
    classify_fn: ClassifyFn, text: str, *, clock: Callable[[], float] = time.perf_counter
) -> Call:
    """Ask the model about one document, timing the call whatever it returns."""
    started = clock()
    try:
        raw = classify_fn(prepare(text))
    except Exception:
        # Exactly what OllamaClassifier does with it — no finding — but counted,
        # because "the model was down for a third of the corpus" changes what
        # every rate below means.
        return Call(outcome=Outcome.FAILED, family=None, seconds=clock() - started)
    elapsed = clock() - started
    outcome, family = judge(raw)
    return Call(outcome=outcome, family=family, seconds=elapsed)


@dataclass(frozen=True, slots=True)
class Latency:
    """Wall-clock per call, over every call including failures — a timeout is
    the slowest answer there is, and leaving it out would flatter the model."""

    calls: int
    median: float
    p95: float
    worst: float


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile. No interpolation: with a few hundred calls, the
    reported number should be one that actually happened."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


@dataclass(frozen=True, slots=True)
class ClassifierRecallRow:
    family: AttackFamily
    flagged: Proportion
    """What the firewall would have received: a finding."""
    said_attack: Proportion
    """What the model thought, including answers the firewall discarded."""


@dataclass(frozen=True, slots=True)
class ClassifierReport:
    benign_flagged: Proportion
    benign_said_attack: Proportion
    recall: tuple[ClassifierRecallRow, ...]
    outcomes: dict[Outcome, int]
    """Every call, every run."""
    discarded_families: dict[str, int]
    """What the model named when the firewall dropped its answer."""
    latency: Latency
    repeats: int
    agreement: Proportion | None
    """Documents whose outcome was identical in every run; ``None`` for one run."""
    benign_flagged_ids: tuple[str, ...]
    attack_discarded_ids: tuple[str, ...]
    disagreeing_ids: tuple[str, ...]
    warnings: tuple[str, ...]


Progress = Callable[[int, int], None]


def evaluate_classifier(
    classify_fn: ClassifyFn,
    *,
    benign: Sequence[Document],
    attacks: Sequence[Attack],
    repeats: int = 2,
    seed: int = 0,
    resamples: int = DEFAULT_RESAMPLES,
    clock: Callable[[], float] = time.perf_counter,
    progress: Progress | None = None,
) -> ClassifierReport:
    """Run the model over every document ``repeats`` times and score the first run."""
    if repeats < 1:
        msg = "repeats must be at least 1"
        raise ValueError(msg)

    items: list[tuple[str, str]] = [(d.id, d.text) for d in benign]
    items.extend((a.id, a.text) for a in attacks)
    runs: dict[str, list[Call]] = {doc_id: [] for doc_id, _ in items}
    total = len(items) * repeats
    done = 0
    for _ in range(repeats):
        for doc_id, text in items:
            runs[doc_id].append(classify_once(classify_fn, text, clock=clock))
            done += 1
            if progress is not None:
                progress(done, total)

    rng = random.Random(seed)  # noqa: S311 — reproducibility, not cryptography
    first = {doc_id: calls[0] for doc_id, calls in runs.items()}

    benign_first = [first[d.id] for d in benign]
    benign_flagged = measure(
        [c.outcome is Outcome.FLAGGED for c in benign_first], rng=rng, resamples=resamples
    )
    benign_said = measure(
        [c.outcome.said_attack for c in benign_first], rng=rng, resamples=resamples
    )
    recall = _recall_rows(attacks, first, rng=rng, resamples=resamples)

    every_call = [call for calls in runs.values() for call in calls]
    outcomes = Counter(call.outcome for call in every_call)
    discarded = Counter(
        call.family or "(none named)" for call in every_call if call.outcome is Outcome.DISCARDED
    )
    seconds = [call.seconds for call in every_call]
    latency = Latency(
        calls=len(seconds),
        median=percentile(seconds, 0.5),
        p95=percentile(seconds, 0.95),
        worst=max(seconds, default=0.0),
    )

    disagreeing = tuple(
        doc_id for doc_id, calls in runs.items() if len({c.outcome for c in calls}) > 1
    )
    agreement = (
        measure(
            [len({c.outcome for c in calls}) == 1 for calls in runs.values()],
            rng=rng,
            resamples=resamples,
        )
        if repeats > 1
        else None
    )

    return ClassifierReport(
        benign_flagged=benign_flagged,
        benign_said_attack=benign_said,
        recall=recall,
        outcomes={outcome: outcomes[outcome] for outcome in Outcome},
        discarded_families=dict(sorted(discarded.items())),
        latency=latency,
        repeats=repeats,
        agreement=agreement,
        benign_flagged_ids=tuple(d.id for d in benign if first[d.id].outcome is Outcome.FLAGGED),
        attack_discarded_ids=tuple(
            a.id for a in attacks if first[a.id].outcome is Outcome.DISCARDED
        ),
        disagreeing_ids=disagreeing,
        warnings=_warnings(recall, outcomes),
    )


def _recall_rows(
    attacks: Sequence[Attack],
    first: dict[str, Call],
    *,
    rng: random.Random,
    resamples: int,
) -> tuple[ClassifierRecallRow, ...]:
    by_family: dict[AttackFamily, list[Call]] = {}
    for attack in attacks:
        by_family.setdefault(attack.family, []).append(first[attack.id])
    return tuple(
        ClassifierRecallRow(
            family=family,
            flagged=measure(
                [c.outcome is Outcome.FLAGGED for c in by_family[family]],
                rng=rng,
                resamples=resamples,
            ),
            said_attack=measure(
                [c.outcome.said_attack for c in by_family[family]], rng=rng, resamples=resamples
            ),
        )
        for family in sorted(by_family, key=lambda f: f.value)
    )


REPORTABLE: Final = frozenset(family.value for family in Family)
"""The families a model answer can carry into a finding."""


def _warnings(recall: Sequence[ClassifierRecallRow], outcomes: Counter[Outcome]) -> tuple[str, ...]:
    warnings: list[str] = []
    thin = [row.family.value for row in recall if row.flagged.total < SMALL_SAMPLE]
    if thin:
        warnings.append(
            f"fewer than {SMALL_SAMPLE} attacks in "
            + ", ".join(thin)
            + " — read the interval, not the percentage"
        )
    unreachable = [row.family.value for row in recall if row.family.value not in REPORTABLE]
    if unreachable:
        warnings.append(
            "the firewall cannot report "
            + ", ".join(unreachable)
            + ", so 'flagged' there counts the model naming some OTHER family"
        )
    if outcomes[Outcome.FAILED]:
        warnings.append(
            f"{outcomes[Outcome.FAILED]} call(s) failed (timeout or refused) and count "
            "as no finding, as they would in the firewall — every rate is a floor"
        )
    if outcomes[Outcome.MALFORMED]:
        warnings.append(
            f"{outcomes[Outcome.MALFORMED]} answer(s) were not the JSON asked for "
            "and count as no finding"
        )
    return tuple(warnings)
