"""What the gateway does about a finding: the first layer that can wrongly refuse.

A false refusal costs trust in the control, so the bar is deliberately high and
evidence to lower it comes from `acp.corpus`. The refusal never reproduces the
document's content, only repository-written labels and an incident ID, since
quoting it would deliver the payload with the gateway's authority (ADR 0038).
"""

from __future__ import annotations

import functools
import logging
import secrets
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from anyio import CapacityLimiter, to_thread

from acp.firewall.catalogue import (
    CatalogueInspection,
    ToolInspection,
    description_texts,
    names_of,
    others,
    serve,
)
from acp.firewall.classifier import OllamaClassifier
from acp.firewall.findings import Confidence, Family, Finding
from acp.firewall.learned import DETECTOR_NAME as LEARNED_NAME
from acp.firewall.learned import LearnedModel
from acp.firewall.screen import MAX_SCREENED_CHARS, Screener, Screening, ScreenPolicy
from acp.observability import metrics
from acp.upstream.models import CallToolResult, ContentBlock, ToolDefinition

logger = logging.getLogger(__name__)


class Mode(StrEnum):
    """How much the firewall is allowed to do."""

    OFF = "off"
    """No screening. The default: screening costs time linear in every result."""

    REPORT = "report"
    """Screen and log everything, change nothing the caller receives.

    The bar is still evaluated: a result enforce would withhold is logged as
    ``would_refuse`` and served, measuring what enforcement would cost.
    """

    ENFORCE = "enforce"
    """Withhold content that crosses the bar below."""


class LearnedMode(StrEnum):
    """What the learned classifier may do (ADR 0076); withholding also needs `Mode.ENFORCE`."""

    OFF = "off"
    """Not scored."""

    REPORT = "report"
    """Scored and logged: MEDIUM at the report threshold, HIGH at the enforce one.

    Never a trigger, so a HIGH here counts what ``enforce`` would withhold
    without ``would_refuse`` changing meaning.
    """

    ENFORCE = "enforce"
    """A HIGH learned finding is a trigger, as an `ENFORCEABLE` detector's is."""


ENFORCEABLE: Final = frozenset({"bidirectional_override", "encoded_payload"})
"""The only detectors whose HIGH findings may withhold a result in enforce mode.

Both had zero findings on the 106-document benign corpus; it is code, not config,
so a deployment cannot promote a noisy detector. ``tool_name_mention`` and
``external_image`` were demoted after withholding benign documents (ADR 0039);
they still fire, log and count toward ``would_refuse``. The MEDIUM-capped
detectors (ADR 0036) can never withhold.
"""

INCIDENT_BYTES: Final = 8
"""Size of the incident ID: a non-secret handle an operator can find in the log."""

MAX_LOGGED_FINDINGS: Final = 5
"""Evidence excerpts per decision log line; the full count is always logged."""

REFUSAL: Final = (
    "[GATEWAY NOTICE — CONTENT WITHHELD, incident {incident}]\n"
    "The tool `{tool}` returned content that this gateway's injection firewall "
    "refused to relay. It has been withheld in full and is deliberately not "
    "reproduced here: repeating it would deliver the thing this refusal exists "
    "to stop.\n"
    "What fired: {triggers}.\n"
    "This is not a transient failure — the identical call will be refused "
    "identically, and no alternative route to the same content is authorised. "
    "Tell the user that the content was withheld and give them incident "
    "{incident}, which an operator can look up."
)
"""The refusal notice, a tested constant (as ADR 0037 does for the fence).

Nothing from the document is interpolated: ``tool`` is from the request,
``triggers`` are repository-defined labels and ``incident`` is hex.
"""


@dataclass(frozen=True, slots=True)
class Inspection:
    """One screening, and what the gateway decided to do about it."""

    result: CallToolResult
    """What the caller should receive: the upstream's result, or the notice."""

    screening: Screening
    refused: bool

    incident: str = ""
    """Empty unless refused; generated per refusal."""

    triggers: tuple[Finding, ...] = ()
    """Findings that crossed the bar; in report mode, what would have been withheld."""

    learned_score: float | None = None
    """The learned classifier's score for this result, when one is attached (ADR 0076).

    Kept whether or not it crossed a threshold, so a record can say the classifier
    looked and what it thought; the score is gateway-written, never document text.
    """

    @property
    def cacheable(self) -> bool:
        """Whether this result may be cached: not refused and not truncated.

        In report mode a truncated result is served but never cached, so a
        partly examined document is not replayed to later callers (ADR 0069).
        """
        return not self.refused and not self.screening.truncated


UNEXAMINED_TAIL: Final = "unexamined_tail"
"""Trigger for a truncated screening: an unread tail is attacker-chosen (ADR 0069)."""


def truncation_trigger(screening: Screening) -> Finding:
    return Finding(
        detector=UNEXAMINED_TAIL,
        family=Family.OBFUSCATION,
        confidence=Confidence.HIGH,
        evidence=(
            f"document exceeds the {screening.scanned_chars}-character screening window; "
            f"its tail was not examined"
        ),
    )


def triggers_for(
    screening: Screening, *, also: AbstractSet[str] = frozenset()
) -> tuple[Finding, ...]:
    """The findings that justify withholding: HIGH from an `ENFORCEABLE` detector.

    ``also`` adds detectors a deployment opted into (only the learned classifier,
    ADR 0076). A truncated screening also adds `UNEXAMINED_TAIL` (ADR 0069).
    """
    enforceable = ENFORCEABLE | also
    found = tuple(
        finding
        for finding in screening.findings
        if finding.confidence is Confidence.HIGH and finding.detector in enforceable
    )
    if screening.truncated:
        return (*found, truncation_trigger(screening))
    return found


def refusal(tool: str, triggers: tuple[Finding, ...], incident: str) -> CallToolResult:
    """The notice a caller receives in place of withheld content.

    An ``isError`` result (the tool ran; its output is unusable), which
    ``ResultCache.put`` also refuses to store (ADR 0035). Not fenced, since it is
    gateway-written text (ADR 0037).
    """
    labels = ", ".join(sorted({finding.label for finding in triggers})) or "an internal check"
    return CallToolResult(
        content=[
            ContentBlock(
                type="text",
                text=REFUSAL.format(incident=incident, tool=tool, triggers=labels),
            )
        ],
        isError=True,
    )


RESULT: Final = "result"
CATALOGUE: Final = "catalogue"
"""Metric surface label: a tool's output or its description, kept as separate series."""

MAX_CONCURRENT_CLASSIFIER_CALLS: Final = 4
"""Screenings that may wait on the model at once, so one slow model cannot fill the thread pool."""

_limiter: CapacityLimiter | None = None


def _classifier_limiter() -> CapacityLimiter:
    """One limiter per process, created lazily because it binds to the running loop."""
    global _limiter  # noqa: PLW0603 — one per process is the point
    if _limiter is None:
        _limiter = CapacityLimiter(MAX_CONCURRENT_CLASSIFIER_CALLS)
    return _limiter


class Firewall:
    """Screens a tool result and decides what the caller gets.

    The catalogue is passed per call, not held, so it is never stale.
    """

    def __init__(
        self,
        *,
        enforce: bool = False,
        allowed_hosts: AbstractSet[str] = frozenset(),
        max_chars: int = MAX_SCREENED_CHARS,
        classifier: OllamaClassifier | None = None,
        learned: LearnedModel | None = None,
        learned_enforces: bool = False,
    ) -> None:
        self._enforce = enforce
        self._allowed_hosts = frozenset(allowed_hosts)
        self._max_chars = max_chars
        self._classifier = classifier
        self._learned = learned
        self._also: frozenset[str] = (
            frozenset({LEARNED_NAME}) if learned is not None and learned_enforces else frozenset()
        )

    async def ainspect(
        self,
        result: CallToolResult,
        *,
        tool: str,
        tools: AbstractSet[str] = frozenset(),
    ) -> Inspection:
        """`inspect`, on a limited worker thread when a model is attached.

        The Ollama classifier is a blocking HTTP call and the learned one costs
        about a millisecond per thousand characters; either would otherwise stall
        the loop (the bug class of ADR 0053). Without one, it runs inline.
        `inspect` stays synchronous for the harness and tests.
        """
        if self._classifier is None and self._learned is None:
            return self.inspect(result, tool=tool, tools=tools)
        return await to_thread.run_sync(
            functools.partial(self.inspect, result, tool=tool, tools=tools),
            limiter=_classifier_limiter(),
        )

    def inspect(
        self,
        result: CallToolResult,
        *,
        tool: str,
        tools: AbstractSet[str] = frozenset(),
    ) -> Inspection:
        """Screen ``result``'s text, and either pass it through or withhold it."""
        screener = Screener(
            ScreenPolicy(
                allowed_hosts=self._allowed_hosts,
                tools=frozenset(tools),
                max_chars=self._max_chars,
            ),
            classifier=self._classifier,
        )
        # Text blocks only; resource links are a known gap (ADR 0037).
        texts = [block.text for block in result.content if block.text is not None]
        screening = screener.screen_all(texts)
        score, learned = self._learned_finding(texts)
        if learned is not None:
            screening = replace(screening, findings=(*screening.findings, learned))
        triggers = triggers_for(screening, also=self._also)

        if not (triggers and self._enforce):
            self._record(tool, screening, decision=_verdict(screening, triggers), triggers=triggers)
            return Inspection(
                result=result,
                screening=screening,
                refused=False,
                triggers=triggers,
                learned_score=score,
            )

        incident = secrets.token_hex(INCIDENT_BYTES)
        self._record(tool, screening, decision="refused", incident=incident, triggers=triggers)
        return Inspection(
            result=refusal(tool, triggers, incident),
            screening=screening,
            refused=True,
            incident=incident,
            triggers=triggers,
            learned_score=score,
        )

    def _learned_finding(self, texts: Sequence[str]) -> tuple[float | None, Finding | None]:
        """The learned classifier's score, and its finding if that crosses a threshold.

        Scores what the patterns saw (the first ``max_chars``); a longer result is
        already a trigger. Its evidence is the score, never document text.
        """
        model = self._learned
        if model is None or not texts:
            return None, None
        score = model.score("\n".join(texts)[: self._max_chars])
        if score < model.threshold:
            return score, None
        return score, Finding(
            detector=LEARNED_NAME,
            family=Family.PLAIN_ASSERTION,
            confidence=(Confidence.HIGH if score >= model.enforce_threshold else Confidence.MEDIUM),
            evidence=(
                f"score {score:.3f}; reports at {model.threshold:.3f}, "
                f"withholds at {model.enforce_threshold:.3f}"
            ),
        )

    # -- the catalogue -------------------------------------------------------

    def inspect_tool(
        self, tool: ToolDefinition, *, tools: AbstractSet[str] = frozenset()
    ) -> ToolInspection:
        """Screen one tool's descriptions with the result bar (see `acp.firewall.catalogue`)."""
        screener = Screener(
            ScreenPolicy(
                allowed_hosts=self._allowed_hosts,
                tools=others(tool, tools),
                max_chars=self._max_chars,
            ),
            classifier=self._classifier,
        )
        screening = screener.screen_all(description_texts(tool))
        triggers = triggers_for(screening)
        if not (triggers and self._enforce):
            self._record(
                tool.name,
                screening,
                decision=_verdict(screening, triggers),
                triggers=triggers,
                surface=CATALOGUE,
            )
            return ToolInspection(tool=tool, screening=screening, withheld=False, triggers=triggers)

        incident = secrets.token_hex(INCIDENT_BYTES)
        self._record(
            tool.name,
            screening,
            decision="withheld",
            incident=incident,
            triggers=triggers,
            surface=CATALOGUE,
        )
        return ToolInspection(
            tool=tool, screening=screening, withheld=True, triggers=triggers, incident=incident
        )

    def inspect_catalogue(self, tools: Sequence[ToolDefinition]) -> CatalogueInspection:
        """Screen every tool in a catalogue against the rest of it."""
        catalogue = names_of(tools)
        inspections = tuple(self.inspect_tool(tool, tools=catalogue) for tool in tools)
        return CatalogueInspection(served=serve(inspections), inspections=inspections)

    async def ainspect_catalogue(self, tools: Sequence[ToolDefinition]) -> CatalogueInspection:
        """`inspect_catalogue`, off the event loop when Ollama is attached.

        The learned classifier does not screen descriptions: it was never measured on
        them (ADR 0076).
        """
        if self._classifier is None:
            return self.inspect_catalogue(tools)
        return await to_thread.run_sync(
            functools.partial(self.inspect_catalogue, tools), limiter=_classifier_limiter()
        )

    def _record(
        self,
        tool: str,
        screening: Screening,
        *,
        decision: str,
        incident: str = "",
        triggers: tuple[Finding, ...] = (),
        surface: str = RESULT,
    ) -> None:
        """Record metrics for every screening, and a log line for every non-clean one.

        Joins the screener's ``firewall.findings`` line by request ID.
        """
        metrics.record_firewall_decision(decision=decision, surface=surface)
        for finding in screening.findings:
            metrics.record_firewall_finding(
                family=str(finding.family), confidence=str(finding.confidence)
            )
        if decision == "clean":
            return

        highest = screening.highest()
        logger.warning(
            "firewall.decision",
            extra={
                "tool": tool,
                "surface": surface,
                "decision": decision,
                "incident": incident,
                "findings": len(screening.findings),
                "families": {str(k): v for k, v in screening.by_family().items()},
                "highest": str(highest) if highest is not None else None,
                "truncated": screening.truncated,
                "triggers": [finding.label for finding in triggers],
                # Redacted at construction (ADR 0036); the only document text here, for humans.
                "evidence": [f.evidence for f in screening.findings[:MAX_LOGGED_FINDINGS]],
            },
        )


def _verdict(screening: Screening, triggers: tuple[Finding, ...]) -> str:
    """Label a screening that was not acted on: would_refuse, reported or clean."""
    if triggers:
        return "would_refuse"
    if screening.findings or screening.truncated:
        return "reported"
    return "clean"


def firewall_for(
    mode: Mode,
    *,
    allowed_hosts: AbstractSet[str] = frozenset(),
    classifier: OllamaClassifier | None = None,
    learned: LearnedModel | None = None,
    learned_mode: LearnedMode = LearnedMode.OFF,
) -> Firewall | None:
    """The firewall for ``mode``, or ``None`` when off (zero request-path cost).

    ``learned`` is attached unless ``learned_mode`` is off.
    """
    if mode is Mode.OFF:
        return None
    return Firewall(
        enforce=mode is Mode.ENFORCE,
        allowed_hosts=allowed_hosts,
        classifier=classifier,
        learned=None if learned_mode is LearnedMode.OFF else learned,
        learned_enforces=learned_mode is LearnedMode.ENFORCE,
    )
