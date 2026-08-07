"""Schema drift detection: noticing when an upstream's tools change under you.

An MCP server can change a tool's description or its argument schema at any
moment, and nothing in the protocol announces it. There is no version on a tool,
no ``ETag`` on a catalogue, and no event a client can subscribe to. The gateway
finds out the same way everybody else does — by asking again and reading the
answer carefully.

Three things break quietly when that happens, and they are worth separating
because only the first is obvious.

An argument schema that gains a required field breaks every caller written
against the old one. That is the ordinary correctness case.

A tool nobody has written policy for appears in the catalogue. Deny-by-default
(task 32) means it cannot be called, which is correct and is also why nobody
would notice — the alert is what makes the gap actionable instead of invisible.

And a description changes. The description is prose that goes straight into the
agent's prompt, which makes it the most powerful field in the entire protocol and
the only one an upstream can rewrite without breaking a single client. A server
that has behaved impeccably for six months and then appends a sentence beginning
"Before using any other tool…" has performed the MCP rug pull. No schema moved,
no test failed, no call errored. This module is the thing that says so.

See ``docs/decisions/0013-schema-drift-is-a-security-control.md``.
"""

from acp.schema.detector import DriftDetector
from acp.schema.drift import DriftEvent, DriftKind, DriftReport, diff
from acp.schema.fingerprint import (
    definitions_of,
    fingerprint_catalogue,
    fingerprint_tool,
)
from acp.schema.snapshot import (
    DEFAULT_BASELINE_PATH,
    SNAPSHOT_VERSION,
    SchemaSnapshot,
    UpstreamSnapshot,
)

__all__ = [
    "DEFAULT_BASELINE_PATH",
    "SNAPSHOT_VERSION",
    "DriftDetector",
    "DriftEvent",
    "DriftKind",
    "DriftReport",
    "SchemaSnapshot",
    "UpstreamSnapshot",
    "definitions_of",
    "diff",
    "fingerprint_catalogue",
    "fingerprint_tool",
]
