"""The adversarial corpus: attacks sliced by family, each with an expected outcome (ADR 0040).

Families include ones no pattern can catch, so the gaps sit in the same table as
the successes. The build fails when an expectation is wrong in either direction,
so a newly caught attack must be acknowledged in front matter and the ADR.
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
    """How the corpus is sliced: a superset of `acp.firewall.findings.Family` (test-enforced).

    No detector can claim `delayed_multi_step`; only the classifier claims
    `plain_assertion` (ADR 0062).
    """

    DIRECT_OVERRIDE = "direct_override"
    EXFILTRATION = "exfiltration"
    OBFUSCATION = "obfuscation"
    TOOL_CONFUSION = "tool_confusion"
    BOUNDARY_ESCAPE = "boundary_escape"

    PLAIN_ASSERTION = "plain_assertion"
    """A fluent false claim with no pattern to match; what framing targets (ADR 0037)."""

    DELAYED_MULTI_STEP = "delayed_multi_step"
    """Harmful only combined with a later retrieval; screening is per result (ADR 0036)."""


class Expectation(StrEnum):
    """What the firewall is expected to do with an attack."""

    WITHHELD = "withheld"
    """A HIGH finding from an `acp.firewall.decision.ENFORCEABLE` detector withholds it.

    The rarest outcome since ADR 0039 demoted two detectors.
    """

    DETECTED = "detected"
    """At least one finding but not enough to withhold; often the intended outcome."""

    UNDETECTED = "undetected"
    """No finding; asserted, so a detector newly catching it fails the build."""


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
    """The family from the directory name, so a file cannot contradict its location."""
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
