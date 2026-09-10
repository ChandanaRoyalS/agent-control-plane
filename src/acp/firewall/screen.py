"""Running every detector over one piece of text, within bounds.

Two responsibilities, and neither is deciding anything. The screener orders the
detectors so that obfuscation is recorded *before* it is undone, and it bounds
the work so that a hostile document cannot turn screening into the outage it was
meant to prevent.

**Ordering.** Invisible and bidirectional characters are detected first, then
stripped, then everything else runs over the cleaned text. Strip first and the
evidence of obfuscation is gone; match first without stripping and
``ig\u200bnore previous instructions`` defeats every pattern while a model reads
it as the sentence it plainly is. Doing both, in that order, is what turns one
evasion into two findings.

**Bounds.** The text comes from an upstream that may be compromised — that is
the premise of the whole phase — so it is an attacker-controlled input to this
code. Long documents are truncated before any pattern runs, and the truncation
is itself reported, because a screener that silently examined the first 64KB of
a 10MB document would be a control with a documented bypass: put the payload at
the end.

Screening never raises and never blocks. It returns findings. What to do about
them is task 47, and keeping the two apart is what makes the false-positive rate
measurable at all — a detector that also refuses can only be evaluated by
counting refusals, and by then a legitimate caller has already been told no.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from itertools import islice
from typing import Final

from acp.firewall import detectors
from acp.firewall.classifier import DETECTOR_NAME as CLASSIFIER_NAME
from acp.firewall.classifier import OllamaClassifier
from acp.firewall.findings import DETECTOR_NAMES, Confidence, Family, Finding

logger = logging.getLogger(__name__)

MAX_FINDINGS_PER_DETECTOR: Final = 64
"""How many findings one detector may report about one result.

**Capping costs enforcement nothing.** `triggers_for` withholds on the presence
of a single HIGH finding from an enforceable detector; the sixty-fifth
zero-width character does not make the result more withheld than the first. What
the cap removes is allocation whose size the upstream chooses: a result of
256KB of U+200B produced 262,140 `Finding` objects, each with an evidence string
and a metrics increment, on the request loop.

Every detector is a generator, so the cap is applied with `islice` and the
findings past it are never constructed. That a detector was cut is reported —
see `Screening.capped` — because a count that silently stops counting is a
number a reader would believe.
"""

MAX_SCREENED_CHARS: Final = 256 * 1024
"""How much of a document is examined.

Generous — a quarter of a megabyte of text is a long document — and finite,
because every detector is linear in this number and it is chosen by whoever
wrote the document. The cap is reported rather than applied silently: see
``Screening.truncated``.
"""


@dataclass(frozen=True, slots=True)
class Screening:
    """Everything one pass observed."""

    findings: tuple[Finding, ...] = ()
    truncated: bool = False
    """Whether the document was longer than ``MAX_SCREENED_CHARS``.

    Load-bearing, not an implementation detail. An unscreened tail is a bypass
    with a known address, so a caller that treats "no findings" and "no findings
    in the part I looked at" as the same thing has a control it does not have.
    Task 47 should treat a truncated screening as suspicious in its own right.
    """

    scanned_chars: int = 0

    capped: frozenset[str] = frozenset()
    """Detectors that had more to say than `MAX_FINDINGS_PER_DETECTOR` allows.

    Not the same claim as `truncated`. Truncated means text was never examined;
    capped means it was examined and the *listing* stopped. Enforcement is
    unaffected — one finding is enough to withhold — so a capped screening is
    still a complete decision, and stays cacheable.
    """

    @property
    def clean(self) -> bool:
        """No findings *and* nothing left unexamined."""
        return not self.findings and not self.truncated

    def by_family(self) -> dict[Family, int]:
        counts: dict[Family, int] = {}
        for finding in self.findings:
            counts[finding.family] = counts.get(finding.family, 0) + 1
        return counts

    def highest(self) -> Confidence | None:
        """The strongest claim made, or ``None``. What a decision layer reads
        first, and the reason `Confidence` is ordered by construction rather
        than by name."""
        order = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)
        present = [f.confidence for f in self.findings]
        return max(present, key=order.index) if present else None


@dataclass(frozen=True)
class ScreenPolicy:
    """What this deployment considers ordinary.

    Both fields default to empty, and both defaults are deliberately the
    *noisy* choice rather than the quiet one: with no allowed hosts every URL is
    reported, and with no catalogue the tool-name detector never fires. A
    deployment that has configured neither gets a screener that over-reports
    links and under-reports tool mentions, which is visible in the numbers —
    where the opposite defaults would look clean and detect less.
    """

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    tools: frozenset[str] = field(default_factory=frozenset)
    max_chars: int = MAX_SCREENED_CHARS


class Screener:
    """Runs every detector, in the one order that makes obfuscation visible."""

    def __init__(
        self,
        policy: ScreenPolicy | None = None,
        *,
        classifier: OllamaClassifier | None = None,
    ) -> None:
        self._policy = policy or ScreenPolicy()
        # Optional model-based detector. Absent by default; when present it
        # adds findings after the patterns, never replaces them, and its own
        # absence or failure yields no findings (see acp.firewall.classifier).
        self._classifier = classifier

    @property
    def detector_names(self) -> tuple[str, ...]:
        """Which detectors this screener actually runs.

        Compared against `DETECTOR_NAMES` by a test, so a detector written and
        not registered — or registered and not named — fails the build. The
        same alarm task 31 put on the `Upstream` protocol: a security layer's
        coverage should not be able to shrink without somebody noticing.
        """
        if self._classifier is None:
            return DETECTOR_NAMES
        return (*DETECTOR_NAMES, CLASSIFIER_NAME)

    def screen(self, text: str) -> Screening:
        """Every finding in ``text``, and whether all of it was examined."""
        return self._screen(text, self._policy.max_chars)

    def _screen(self, text: str, budget: int) -> Screening:
        """``screen``, against a caller-supplied character budget.

        Private because the budget is the *result's*, not the text's: a caller
        screening several blocks spends one allowance across all of them, so
        that splitting a payload into more blocks buys an attacker nothing.
        """
        if not text or budget <= 0:
            return Screening(truncated=bool(text))

        truncated = len(text) > budget
        window = text[:budget]

        found: list[Finding] = []
        capped: set[str] = set()

        def take(name: str, produced: Iterator[Finding]) -> None:
            """Up to the cap, and record whether there was more."""
            batch = list(islice(produced, MAX_FINDINGS_PER_DETECTOR))
            found.extend(batch)
            if len(batch) == MAX_FINDINGS_PER_DETECTOR and next(produced, None) is not None:
                capped.add(name)

        # Obfuscation first, over the *raw* window, because these detectors are
        # the only ones whose evidence the next step destroys.
        take("invisible_characters", detectors.invisible_characters(window))
        take("bidirectional_override", detectors.bidirectional_override(window))

        # Then the same text with the hiding removed, so a payload that used it
        # is matched by everything below as if it had never been disguised.
        cleaned = detectors.strip_invisible(window)

        take("instruction_override", detectors.instruction_override(cleaned))
        take("external_image", detectors.external_image(cleaned, self._policy.allowed_hosts))
        take("disallowed_url", detectors.disallowed_url(cleaned, self._policy.allowed_hosts))
        take("encoded_payload", detectors.encoded_payload(cleaned))
        take("tool_name_mention", detectors.tool_name_mention(cleaned, self._policy.tools))

        # The model-based detector runs last, over the same de-obfuscated
        # text, and only when one is attached. It emits findings like any
        # other detector; a model that is absent, down, or slow adds nothing.
        if self._classifier is not None:
            take(CLASSIFIER_NAME, iter(self._classifier.classify(cleaned)))

        if found or truncated:
            # One line per screening, not per finding: a document with two
            # hundred zero-width characters is one event, and a logger that
            # emitted two hundred lines for it would be an amplification the
            # attacker controls.
            logger.warning(
                "firewall.findings",
                extra={
                    "count": len(found),
                    "families": {str(k): v for k, v in _counts(found).items()},
                    "truncated": truncated,
                    "scanned_chars": len(window),
                },
            )

        return Screening(
            findings=tuple(found),
            truncated=truncated,
            scanned_chars=len(window),
            capped=frozenset(capped),
        )

    def screen_all(self, texts: Sequence[str], *, complete: bool = True) -> Screening:
        """One screening over several strings — everything a tool result carries.

        Merged rather than returned per block, because a decision is made about
        a *result*, and a payload split across two content blocks is one attack.
        Offsets become per-block and therefore only comparable within a block,
        which is the honest cost of merging and is why they are not renumbered
        to look global.

        **The character budget is the result's, not each string's.** It used to
        be per block, which meant a result with eight blocks bought eight times
        the allowance and the cost of screening was a number the upstream chose.
        One budget, spent in order, and a result that exhausts it is reported as
        truncated.

        ``complete`` is ``False`` when the caller's own extraction hit a bound
        before it reached the end of the result — see
        ``acp.firewall.content.screenable_strings``. It is carried into
        ``truncated`` for the same reason the character budget is: the caller
        must not be able to tell "clean" from "clean as far as I looked".
        """
        findings: list[Finding] = []
        truncated = not complete
        capped: set[str] = set()
        scanned = 0
        for text in texts:
            remaining = self._policy.max_chars - scanned
            if remaining <= 0:
                # The allowance is spent and there is more result behind it.
                # Reported, never silent: an unexamined remainder is a bypass
                # with a known address.
                truncated = True
                break
            screening = self._screen(text, remaining)
            findings.extend(screening.findings)
            truncated = truncated or screening.truncated
            capped |= screening.capped
            scanned += screening.scanned_chars
        return Screening(
            findings=tuple(findings),
            truncated=truncated,
            scanned_chars=scanned,
            capped=frozenset(capped),
        )


def _counts(findings: Sequence[Finding]) -> dict[Family, int]:
    counts: dict[Family, int] = {}
    for finding in findings:
        counts[finding.family] = counts.get(finding.family, 0) + 1
    return counts


def screen_policy_for(
    *, allowed_hosts: AbstractSet[str] = frozenset(), tools: AbstractSet[str] = frozenset()
) -> ScreenPolicy:
    return ScreenPolicy(allowed_hosts=frozenset(allowed_hosts), tools=frozenset(tools))
