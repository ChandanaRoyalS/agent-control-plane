"""Which tools may have their results cached, and for how long.

**Opt-in, never inferred.** A tool is cacheable because somebody with a
deployment in front of them said so in a file that shows up in a diff — not
because its name begins with ``get_``, not because the method looked like a
read, and emphatically not because the upstream said so about itself.

The reasons, in order of how expensive the mistake is:

**A name is not a contract.** A tool called ``search`` may write an audit row.
One called ``get_report`` may bill per call. Caching either is a correctness bug
that shows up as a missing record or a lost charge, and neither will look like a
cache problem when somebody eventually investigates.

**An upstream that can declare its own results cacheable can make this gateway
serve stale data on request.** That is ADR 0013's argument about tool
descriptions, arriving through a new field: a compromised or merely
badly-configured upstream should never be able to change how long the gateway
repeats what it said. So there is no ``cacheable`` hint read off the catalogue,
by design.

**Absent means off.** No file, or a tool not listed, means the call goes to the
upstream exactly as it did before. Turning result caching on with an empty table
changes nothing — the same shape ADR 0033 chose for costs, so no existing
deployment behaves differently until it opts in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

MAX_TTL_SECONDS: Final = 300.0
"""Ceiling on how long any result may be held, whatever the file asks for.

A result cache is for the same caller repeating themselves inside a few seconds
— a retry, a re-render, an agent that asked twice in one turn. It is not for
holding yesterday's answer.

The ceiling is a *security* limit before it is a freshness one. Entitlements
change upstream in ways this gateway cannot observe: a record alice could read
this morning may be restricted by lunchtime, and the gateway will not be told.
Policy still refuses her if she loses the *tool*, because authorization runs
before the cache is consulted — but data-level changes inside a tool she still
holds are invisible here. The TTL is the entire duration of that exposure, so it
is bounded in code rather than left to whatever somebody typed.
"""


@dataclass(frozen=True)
class CacheableTools:
    """The tools whose results may be cached, each with its own lifetime.

    ``ttls`` maps a qualified tool name (``upstream__tool``, ADR 0003) to how
    many seconds its result may be held. A tool absent from the map is not
    cacheable, which is the default for everything.
    """

    ttls: dict[str, float] = field(default_factory=dict)

    def ttl_for(self, tool: str) -> float | None:
        """How long ``tool``'s result may be held, or ``None`` for never.

        ``None`` rather than ``0.0`` for the not-cacheable case, deliberately.
        Zero is a legitimate value somebody might write meaning "cache it but
        expire immediately", and a function that returns the same thing for
        "never cache this" and "cache this for no time" is one where a falsy
        check eventually treats a configured tool as an unconfigured one.
        """
        return self.ttls.get(tool)

    @property
    def names(self) -> tuple[str, ...]:
        """Every cacheable tool, sorted. For the startup log line — an operator
        should be able to see which tools are being cached without reading the
        file, because "why is this stale" starts with "what is cached"."""
        return tuple(sorted(self.ttls))
