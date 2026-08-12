"""What the gateway does about a finding — the first place the firewall can be wrong.

Task 45 detects and decides nothing. Task 46 frames and judges nothing. This is
the first module that changes what a caller receives because of what a detector
thought, and therefore the first that can be wrong about a real request.

The asymmetry is the design. A missed attack costs whatever the attack was
worth; a false refusal costs the deployment's trust in the control, and the
observed response to a firewall that refuses honest traffic is not a tuning
ticket, it is ``ACP_FIREWALL_MODE=off``. So the bar is set deliberately high and
the numbers that would justify lowering it are tasks 48 to 52.

**The refusal never reproduces the content.** Not the payload, not the matched
span, not a paraphrase. Explaining a refusal by quoting what was in the document
delivers that text to the model, in the model's context, wearing the gateway's
authority and outside any fence — a better delivery mechanism than the original
attack had. The notice carries labels, which this repository writes and which
cannot carry an instruction, plus an incident identifier a human can look up.

See ADR 0038.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from acp.firewall.findings import Confidence, Finding
from acp.firewall.screen import MAX_SCREENED_CHARS, Screener, Screening, ScreenPolicy
from acp.observability import metrics
from acp.upstream.models import CallToolResult, ContentBlock

logger = logging.getLogger(__name__)


class Mode(StrEnum):
    """How much the firewall is allowed to do."""

    OFF = "off"
    """No screening at all. The default, because screening is linear in the size
    of every result and a control that turns itself on is a control nobody
    chose."""

    REPORT = "report"
    """Screen everything, log everything, change nothing the caller receives.

    Where a deployment starts, and it answers the question that actually decides
    whether enforcement is safe here: not "how many findings does my traffic
    produce" but "how many of them would have been *refused*". So the bar is
    evaluated in this mode too, and a result that would have been withheld is
    logged as ``would_refuse`` and served anyway.
    """

    ENFORCE = "enforce"
    """Withhold content that crosses the bar below."""


ENFORCEABLE: Final = frozenset({"bidirectional_override", "encoded_payload"})
"""The only detectors whose findings may withhold a result.

Two, and the list is short because it was **measured** rather than reasoned
about. Both of these produced zero findings across the 106 documents of the
benign corpus (task 48). Everything else produced some, and a detector that
fires on real documents cannot be allowed to withhold them.

In code rather than in configuration, deliberately. A deployment can say what it
knows about its own environment — its hosts, its mode — but it cannot promote a
noisy detector into a blocking one, because what is encoded here is what *this
project has measured* about its own detectors' error rates.

Absent, and each for a reason the corpus either predicted or produced:

``instruction_override`` — capped at MEDIUM by ADR 0036, so it could never
withhold anything. Fired on 10 benign documents, exactly as expected: security
advisories, an incident report, this repository's own ADRs.

``invisible_characters`` — MEDIUM, same reasoning. Fired on 10: emoji built from
zero-width joiners, Persian requiring the zero-width non-joiner as spelling,
French non-breaking spaces.

``disallowed_url`` — MEDIUM. Fired on 10 benign documents that link to things,
because benign documents link to things.

``tool_name_mention`` — **demoted by the corpus** (ADR 0039). It was on this
list, described as having a false-positive rate near zero because a *qualified*
name is unusual in prose. That was a guess and it was wrong in a predictable
class: it withheld the gateway's own audit log, a policy-decision record and its
own firewall log lines. A document that is a record of tool calls names tools.
An observability tool returning that record would have been refused by the
gateway that wrote it.

``external_image`` — **demoted by the corpus** (ADR 0039). It withheld a
marketing newsletter carrying a tracking pixel and a security advisory
demonstrating the exfiltration pattern. Both are benign, both are exactly the
shape, and no allow-list a real deployment would write covers a third party's
newsletter.

Both demoted detectors still fire, are still logged, and still count toward
`would_refuse` in report mode. What changed is that they no longer withhold
anything on their own. Tasks 51 and 52 can promote them again by combining them
with a second signal — which is what the corpus says they need.
"""

INCIDENT_BYTES: Final = 8
"""64 bits of reference. Not a secret — a handle, so that a user given a refusal
can quote something an operator can find in a log, and the payload never has to
travel in order to explain itself."""

MAX_LOGGED_FINDINGS: Final = 5
"""How many findings' evidence reaches the decision log line.

The full count is always reported; the excerpts are capped. A document with two
hundred zero-width characters is one event, and a log line reproducing all two
hundred is an amplification whose size the attacker chose.
"""

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
"""What the caller is told. It is a security control written in English, so it
is a constant in one module with tests over its contents rather than a string
built at the call site — the same rule ADR 0037 applied to the fence.

Note what is *not* interpolated: nothing from the document. ``tool`` comes from
the request, ``triggers`` are detector and family names this repository defines,
and ``incident`` is hex.
"""


@dataclass(frozen=True, slots=True)
class Inspection:
    """One screening, and what the gateway decided to do about it."""

    result: CallToolResult
    """What the caller should receive: the upstream's result, or the notice."""

    screening: Screening
    refused: bool

    incident: str = ""
    """Empty unless refused. A reference, generated per refusal."""

    triggers: tuple[Finding, ...] = ()
    """The findings that crossed the bar — populated in report mode too, where
    they mean "this would have been withheld". That number, rather than the
    finding count, is what tells a deployment whether enforcement is safe for
    its own traffic."""

    @property
    def cacheable(self) -> bool:
        """Whether this result may be stored.

        Not refused, and not truncated. The second half is ADR 0036's open
        question answered: refusing a document for being long would be a false
        positive with an obvious trigger, but storing one whose tail was never
        examined turns a single unexamined document into every subsequent
        caller's answer for the length of its TTL. Served once, examined in
        part, never repeated.
        """
        return not self.refused and not self.screening.truncated


def triggers_for(screening: Screening) -> tuple[Finding, ...]:
    """The findings that justify withholding a result.

    Two conditions, both necessary: HIGH confidence, and a detector on the
    enforceable list. HIGH alone is not enough because confidence is a claim a
    detector makes about itself; the list is what decides which detectors are
    trusted to make it.

    There used to be a third condition — that a host-dependent detector could
    only withhold once the deployment had configured its allowed hosts. It went
    when `external_image` left the enforceable list, because a condition on a
    detector that can no longer withhold anything is a guard that cannot fire,
    and a guard that cannot fire is worse than none: a reader trusts it.
    """
    return tuple(
        finding
        for finding in screening.findings
        if finding.confidence is Confidence.HIGH and finding.detector in ENFORCEABLE
    )


def refusal(tool: str, triggers: tuple[Finding, ...], incident: str) -> CallToolResult:
    """The notice a caller receives in place of withheld content.

    ``isError`` rather than a JSON-RPC error, because the transport worked, the
    request was well-formed and the tool ran — what failed is that its output is
    not usable, which is exactly the line MCP draws. It also means
    ``ResultCache.put`` refuses it for free (ADR 0035), so a refusal cannot be
    cached even by a call site that forgets.

    Not framed, either. Provenance framing marks text the gateway did not write;
    fencing text the gateway *did* write would be a lie about its origin, and
    would teach a model that fenced text is sometimes authoritative — the one
    belief ADR 0037 exists to prevent.
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


class Firewall:
    """Screens a tool result and decides what the caller gets.

    Holds the deployment's mode and host list. The *catalogue* is passed per
    call rather than held, because it grows as upstreams are listed and a
    firewall holding a stale copy would under-report exactly the detector only a
    gateway can write.
    """

    def __init__(
        self,
        *,
        enforce: bool = False,
        allowed_hosts: AbstractSet[str] = frozenset(),
        max_chars: int = MAX_SCREENED_CHARS,
    ) -> None:
        self._enforce = enforce
        self._allowed_hosts = frozenset(allowed_hosts)
        self._max_chars = max_chars

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
            )
        )
        # Text blocks only. An image is bytes and this layer has no opinion
        # about bytes; a resource link is a URI the *client* may fetch, which is
        # a real exfiltration channel and a gap named in ADR 0037 rather than
        # closed here by guessing at a field name that varies by content type.
        screening = screener.screen_all(
            [block.text for block in result.content if block.text is not None]
        )
        triggers = triggers_for(screening)

        if not (triggers and self._enforce):
            self._record(tool, screening, decision=_verdict(screening, triggers), triggers=triggers)
            return Inspection(result=result, screening=screening, refused=False, triggers=triggers)

        incident = secrets.token_hex(INCIDENT_BYTES)
        self._record(tool, screening, decision="refused", incident=incident, triggers=triggers)
        return Inspection(
            result=refusal(tool, triggers, incident),
            screening=screening,
            refused=True,
            incident=incident,
            triggers=triggers,
        )

    def _record(
        self,
        tool: str,
        screening: Screening,
        *,
        decision: str,
        incident: str = "",
        triggers: tuple[Finding, ...] = (),
    ) -> None:
        """The decision record: which tool, what the gateway did, and why.

        Separate from the screener's own ``firewall.findings`` line, and the
        split follows the layering rather than fighting it — a screener does not
        know what a tool is, and a decision layer should not have to re-derive
        what a detector found. Both carry the request ID, which is what makes
        them one event to anybody reading them.

        Metrics are recorded for every screening including the clean ones,
        because a detection count without its denominator is not a rate. The
        *log line* is not: a line per successful call saying "nothing happened"
        is how a security log becomes unreadable.
        """
        metrics.record_firewall_decision(decision=decision)
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
                "decision": decision,
                "incident": incident,
                "findings": len(screening.findings),
                "families": {str(k): v for k, v in screening.by_family().items()},
                "highest": str(highest) if highest is not None else None,
                "truncated": screening.truncated,
                "triggers": [finding.label for finding in triggers],
                # Redacted at construction (ADR 0036), capped here. This is the
                # only place the document's own text appears anywhere in this
                # module, and its reader is a human with a grep rather than a
                # model with tools.
                "evidence": [f.evidence for f in screening.findings[:MAX_LOGGED_FINDINGS]],
            },
        )


def _verdict(screening: Screening, triggers: tuple[Finding, ...]) -> str:
    """What to call a screening that was not acted on.

    ``would_refuse`` is the whole value of report mode: it separates "my traffic
    produces findings", which is interesting, from "enforcement would have
    withheld this result", which is the number a deployment needs before it
    turns enforcement on.
    """
    if triggers:
        return "would_refuse"
    if screening.findings or screening.truncated:
        return "reported"
    return "clean"


def firewall_for(mode: Mode, *, allowed_hosts: AbstractSet[str] = frozenset()) -> Firewall | None:
    """The firewall this mode asks for, or ``None`` for no screening at all.

    ``None`` rather than a ``Firewall`` in an inert mode, so that "off" costs
    nothing on the request path and cannot become a branch inside the hot loop
    that somebody later gets wrong.
    """
    if mode is Mode.OFF:
        return None
    return Firewall(enforce=mode is Mode.ENFORCE, allowed_hosts=allowed_hosts)
