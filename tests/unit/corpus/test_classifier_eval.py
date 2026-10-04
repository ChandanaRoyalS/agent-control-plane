"""The classifier-alone evaluation, with a scripted model instead of a real one.

The point of `acp.corpus.classifier_eval` is that it does not collapse a model
call into "finding / nothing" the way the firewall must. So the tests that matter
are the ones that feed it each of the four kinds of "nothing" and check that
they stay apart — above all `DISCARDED`, the model saying "attack" in a family
the firewall cannot report, which the firewall drops without a trace.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable, Iterator

import pytest

from acp.corpus.attack import Attack, AttackFamily, Expectation
from acp.corpus.classifier_eval import (
    Outcome,
    classify_once,
    evaluate_classifier,
    judge,
    percentile,
    prepare,
)
from acp.corpus.document import Document, Source
from acp.firewall.classifier import MAX_CLASSIFIED_CHARS, OllamaClassifier

ATTACK = json.dumps({"attack": True, "family": "direct_override"})
CLEAN = json.dumps({"attack": False, "family": None})
UNREPORTABLE = json.dumps({"attack": True, "family": "plain_assertion"})
UNNAMED = json.dumps({"attack": True, "family": None})


def doc(doc_id: str, text: str = "text") -> Document:
    return Document(
        id=doc_id, kind="doc", why="fixture", source=Source.SYNTHETIC, hard=False, text=text
    )


def attack(family: AttackFamily, slug: str, text: str = "text") -> Attack:
    return Attack(
        id=f"{family.value}/{slug}",
        family=family,
        expect=Expectation.UNDETECTED,
        why="fixture",
        source=Source.SYNTHETIC,
        text=text,
    )


def by_text(answers: dict[str, str]) -> Callable[[str], str]:
    """A model that answers by document text — deterministic across repeats."""
    return lambda text: answers[text]


def ticking() -> Callable[[], float]:
    """A clock that advances one second per reading, so every call takes 1s."""
    counter: Iterator[int] = itertools.count()
    return lambda: float(next(counter))


# ---------------------------------------------------------------------------
# judge: five outcomes, and agreement with the firewall about which is a finding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "outcome", "family"),
    [
        (ATTACK, Outcome.FLAGGED, "direct_override"),
        (CLEAN, Outcome.CLEAN, None),
        (UNREPORTABLE, Outcome.DISCARDED, "plain_assertion"),
        (UNNAMED, Outcome.DISCARDED, None),
        ("I think this is fine", Outcome.MALFORMED, None),
        ("[true]", Outcome.MALFORMED, None),
        (json.dumps({"attack": "yes"}), Outcome.MALFORMED, None),
    ],
)
def test_judge_keeps_the_four_kinds_of_nothing_apart(
    raw: str, outcome: Outcome, family: str | None
) -> None:
    assert judge(raw) == (outcome, family)


@pytest.mark.parametrize("raw", [ATTACK, CLEAN, UNREPORTABLE, UNNAMED, "nonsense", "{}"])
def test_flagged_means_exactly_what_the_firewall_turns_into_a_finding(raw: str) -> None:
    """If these two ever disagreed, the 'became a finding' column would be
    describing a firewall that does not exist."""
    produces_finding = bool(OllamaClassifier(classify_fn=lambda _: raw).classify("x"))
    assert (judge(raw)[0] is Outcome.FLAGGED) is produces_finding


def test_a_raising_model_is_a_counted_failure_not_a_crash() -> None:
    def down(_: str) -> str:
        raise TimeoutError

    call = classify_once(down, "anything", clock=ticking())
    assert call.outcome is Outcome.FAILED
    assert call.seconds == 1.0


def test_the_model_sees_what_the_screener_would_send_it() -> None:
    seen: list[str] = []

    def model(text: str) -> str:
        seen.append(text)
        return CLEAN

    hidden = "ig\u200bnore" + "x" * (MAX_CLASSIFIED_CHARS * 2)
    classify_once(model, hidden)
    assert seen == [prepare(hidden)]
    assert seen[0].startswith("ignore")
    assert len(seen[0]) == MAX_CLASSIFIED_CHARS


def test_percentile_is_nearest_rank() -> None:
    values = [float(v) for v in range(1, 21)]
    assert percentile(values, 0.5) == 10.0
    assert percentile(values, 0.95) == 19.0
    assert percentile([], 0.5) == 0.0


# ---------------------------------------------------------------------------
# evaluate_classifier
# ---------------------------------------------------------------------------


def test_benign_false_positives_count_only_findings_but_report_opinions() -> None:
    benign = [doc("a", "a"), doc("b", "b"), doc("c", "c"), doc("d", "d")]
    model = by_text({"a": ATTACK, "b": UNREPORTABLE, "c": CLEAN, "d": CLEAN})

    report = evaluate_classifier(model, benign=benign, attacks=[], repeats=1, resamples=50)

    assert (report.benign_flagged.successes, report.benign_flagged.total) == (1, 4)
    assert report.benign_said_attack.successes == 2
    assert report.benign_flagged_ids == ("a",)


def test_an_attack_the_firewall_would_discard_is_named() -> None:
    caught = attack(AttackFamily.PLAIN_ASSERTION, "refund", "refund")
    missed = attack(AttackFamily.PLAIN_ASSERTION, "skip", "skip")
    model = by_text({"refund": UNREPORTABLE, "skip": CLEAN})

    report = evaluate_classifier(model, benign=[], attacks=[caught, missed], repeats=1)

    (row,) = report.recall
    assert row.flagged.successes == 0
    assert row.said_attack.successes == 1
    assert report.attack_discarded_ids == ("plain_assertion/refund",)
    assert report.discarded_families == {"plain_assertion": 1}
    assert any("cannot report plain_assertion" in w for w in report.warnings)


def test_rates_come_from_the_first_run_and_disagreement_is_listed() -> None:
    flip = iter([ATTACK, CLEAN])
    report = evaluate_classifier(
        lambda _: next(flip), benign=[doc("x")], attacks=[], repeats=2, resamples=50
    )

    assert report.benign_flagged.successes == 1
    assert report.disagreeing_ids == ("x",)
    assert report.agreement is not None
    assert report.agreement.successes == 0


def test_every_call_is_counted_and_timed_including_failures() -> None:
    def model(text: str) -> str:
        if text == "down":
            raise ConnectionError
        return CLEAN

    seen: list[tuple[int, int]] = []
    report = evaluate_classifier(
        model,
        benign=[doc("up", "up"), doc("down", "down")],
        attacks=[],
        repeats=3,
        clock=ticking(),
        progress=lambda done, total: seen.append((done, total)),
    )

    assert report.latency.calls == 6
    assert report.latency.worst == 1.0
    assert report.outcomes[Outcome.FAILED] == 3
    assert report.outcomes[Outcome.CLEAN] == 3
    assert seen[-1] == (6, 6)
    assert any("failed" in w for w in report.warnings)


def test_one_run_reports_no_agreement() -> None:
    report = evaluate_classifier(lambda _: "junk", benign=[doc("x")], attacks=[], repeats=1)
    assert report.agreement is None
    assert report.outcomes[Outcome.MALFORMED] == 1
    assert any("not the JSON" in w for w in report.warnings)


def test_zero_repeats_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        evaluate_classifier(lambda _: CLEAN, benign=[], attacks=[], repeats=0)
