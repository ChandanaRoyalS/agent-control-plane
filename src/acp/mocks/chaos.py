"""Repeatable failure modes for the mock upstreams, to exercise resilience features.

The mode comes from the ``X-ACP-Chaos-Mode`` header, else the ``CHAOS_MODE`` env var.
``X-ACP-Chaos-Param`` (or ``CHAOS_PARAM``) sets its knob: seconds to hang or bytes to inflate.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import StrEnum

import anyio

DEFAULT_HANG_SECONDS = 5.0
DEFAULT_OVERSIZED_BYTES = 5_000_000

CHAOS_SIMULATED_ERROR = -32050
"""JSON-RPC code for an induced failure, in the implementation-defined range."""

CHAOS_MODE_HEADER = "x-acp-chaos-mode"
CHAOS_PARAM_HEADER = "x-acp-chaos-param"


class ChaosMode(StrEnum):
    """The failure modes an upstream can be made to exhibit."""

    NONE = "none"
    HANG = "hang"
    """Sleep past any sane client timeout, to exercise timeout handling."""
    MALFORMED = "malformed"
    """Return HTTP 200 with a body that is not valid JSON-RPC."""
    ERROR = "error"
    """Return a well-formed JSON-RPC error for every request."""
    OVERSIZED = "oversized"
    """Return a result inflated far past any reasonable size limit."""
    DISCONNECT = "disconnect"
    """Start a response, then drop the connection mid-stream."""


class Disconnected(Exception):  # noqa: N818 — a transport stand-in, not an error
    """Raised to simulate a mid-response connection drop.

    uvicorn closes the socket; the in-process test transport surfaces this exception instead.
    """


def resolve_mode(header_value: str | None) -> ChaosMode:
    """Resolve the effective chaos mode: header wins, then env, then NONE."""
    raw = header_value or os.environ.get("CHAOS_MODE") or ChaosMode.NONE.value
    try:
        return ChaosMode(raw.lower())
    except ValueError:
        # Fail loudly so a mistyped mode does not look like normal behaviour.
        msg = f"unknown chaos mode: {raw!r}"
        raise ValueError(msg) from None


def resolve_param(header_value: str | None, *, default: float) -> float:
    """Resolve the numeric chaos parameter: header wins, then env, then default."""
    raw = header_value or os.environ.get("CHAOS_PARAM")
    if raw is None:
        return default
    return float(raw)


@asynccontextmanager
async def maybe_hang(mode: ChaosMode, seconds: float) -> AsyncIterator[None]:
    """Sleep before yielding, if ``mode`` is ``HANG``. No-op otherwise."""
    if mode is ChaosMode.HANG:
        await anyio.sleep(seconds)
    yield


def oversized_text(byte_count: int) -> str:
    """A deterministic string of ``byte_count`` characters."""
    unit = "chaos-oversized-payload-filler "
    repeats = (byte_count // len(unit)) + 1
    return (unit * repeats)[:byte_count]
