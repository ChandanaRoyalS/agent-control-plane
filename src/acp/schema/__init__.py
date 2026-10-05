"""Schema drift detection: noticing when an upstream's tools change (ADR 0013).

MCP announces no catalogue changes, so the gateway re-fetches and compares against a
committed baseline. It flags schema changes that break callers, new tools without policy,
and description changes (the "rug pull", since descriptions go straight into the prompt).
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
