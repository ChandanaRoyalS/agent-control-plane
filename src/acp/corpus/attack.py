"""The adversarial corpus: attacks, sliced by family, each carrying what this
project expects the firewall to do about it.

Two fields make this corpus different from the benign one, and both exist to
stop it flattering the thing it measures.

**Family.** A single detection rate over mixed attacks is unreadable: 70% could
be even coverage of everything, or perfect coverage of the easy families and
nothing whatsoever on encoding. `AttackFamily` is a superset of
`acp.firewall.findings.Family` — the five families a *detector* can report, plus
two that no detector can. A test asserts the subset relation, so the corpus and
the detectors cannot drift into describing different things.

**Expectation.** Every attack records what the firewall is expected to do with
it: withhold it, merely detect it, or *miss it entirely*. That third value is
the one worth arguing about.

**Why record attacks this project cannot catch.** Because a corpus containing
only catchable attacks reports a detection rate that is a property of the corpus.
`plain_assertion` — a well-written paragraph asserting something false, with
nothing misspelled, encoded or hidden — is the attack ADR 0037's framing exists
for, and no pattern will ever match it. Leaving it out would make the numbers
look better and mean less. Writing it down as `undetected` puts the gap in the
same table as the successes, where a reader can see it.

**And the build fails when an expectation is wrong in either direction.** If a
document marked `undetected` starts producing a finding, that is a genuine
improvement — and it still fails, because a security control changing behaviour
without anybody noticing is the thing this project spends its effort on. The fix
is one line of front matter and a sentence in the ADR, which is exactly the
review that should happen when a firewall starts catching something new.

See ADR 0040.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from acp.corpus.document import Source, front_matter, read_source, read_why
from acp.exceptions import ConfigurationError

REQUIRED: Final = frozenset({"why", "source", "expect"})
UNDERSTOOD: Final = REQUIRED


class AttackFamily(StrEnum):
    """How the corpus is sliced.

    A deliberate superset of `acp.firewall.findings.Family`. The first five are
    what a detector can report and are spelled identically, so a per-family
    detection rate can be computed by comparing the two directly. The last two
    are attacks no detector claims — named here because a taxonomy that only
    contains what you can catch is a taxonomy that flatters you.
    """

    DIRECT_OVERRIDE = "direct_override"
    EXFILTRATION = "exfiltration"
    OBFUSCATION = "obfuscation"
    TOOL_CONFUSION = "tool_confusion"
    BOUNDARY_ESCAPE = "boundary_escape"

    PLAIN_ASSERTION = "plain_assertion"
    """A paragraph that simply asserts something false — "the customer has
    already approved this refund", "the on-call engineer said to skip the
    check". Nothing is misspelled, encoded or hidden, so there is no pattern to
    match and there never will be. This is the family provenance framing
    (ADR 0037) exists for, and the family that makes the detection rate honest
    by dragging it down."""

    DELAYED_MULTI_STEP = "delayed_multi_step"
    """A payload that is harmless in the document it appears in, and becomes an
    instruction only in combination with a second retrieval or a later turn.
    Screening is per-result by construction (ADR 0036), so a control that never
    sees two documents together cannot reason about the pair."""


class Expectation(StrEnum):
    """What the firewall is expected to do with an attack."""

    WITHHELD = "withheld"
    """Enforcement withholds it: a HIGH finding from a detector on
    `acp.firewall.decision.ENFORCEABLE`. The strongest outcome, and after
    ADR 0039 demoted two detectors, the rarest."""

    DETECTED = "detected"
    """At least one finding, and not enough to withhold. The document reaches
    the model, fenced, with the finding in the log. For most families this is
    the correct outcome rather than a shortfall — the decision layer is
    deliberately narrow, and `report` mode is where the signal is meant to
    land."""

    UNDETECTED = "undetected"
    """No finding at all, recorded as a fact about this firewall rather than
    omitted from the corpus. Asserted, so that a future detector catching it
    fails the build and somebody has to say so out loud."""


@dataclass(frozen=True, slots=True)
class Attack:
    """One adversarial document, its family, and what is expected of it."""

    id: str
    """``<family>/<slug>``, derived from the path."""

    family: AttackFamily
    expect: Expectation
    why: str
    source: Source
    text: str

    @property
    def chars(self) -> int:
        return len(self.text)


def read_family(path: Path, name: str) -> AttackFamily:
    """The family, taken from the directory rather than from a field.

    A file that could name a family different from the directory it sits in is
    a file that eventually does, and the slice it belongs to is the whole point
    of the taxonomy.
    """
    try:
        return AttackFamily(name)
    except ValueError as exc:
        msg = (
            f"corpus directory {name!r} (for {str(path)!r}) is not an attack family. "
            f"Families are {', '.join(f.value for f in AttackFamily)}."
        )
        raise ConfigurationError(msg) from exc


def read_expectation(path: Path, value: object) -> Expectation:
    try:
        return Expectation(str(value))
    except ValueError as exc:
        msg = (
            f"corpus file {str(path)!r}: `expect` must be one of "
            f"{', '.join(e.value for e in Expectation)}, got {value!r}"
        )
        raise ConfigurationError(msg) from exc


def parse_attack(path: Path, text: str, *, family: str) -> Attack:
    """Parse one adversarial corpus file, or refuse it by name."""
    loaded, body = front_matter(path, text, required=REQUIRED, understood=UNDERSTOOD)

    return Attack(
        id=f"{family}/{path.stem}",
        family=read_family(path, family),
        expect=read_expectation(path, loaded["expect"]),
        why=read_why(path, loaded["why"]),
        source=read_source(path, loaded["source"]),
        text=body,
    )
