"""The live trace console — task 63.

`events` is the wire shape, `hub` the fan-out, `app` the routes. The design
argument lives in `events`: **the console is a view of the audit chain, not a
second telemetry path.**
"""

from acp.console.events import Source, TraceEvent, from_entry, from_record, observed
from acp.console.hub import Subscription, TraceHub

__all__ = [
    "Source",
    "Subscription",
    "TraceEvent",
    "TraceHub",
    "from_entry",
    "from_record",
    "observed",
]
