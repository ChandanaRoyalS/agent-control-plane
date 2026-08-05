"""Controllable misbehavior for the mock upstream servers.

Every resilience feature the gateway builds — timeouts, retries with jitter,
circuit breakers, health-driven catalog withdrawal — needs an upstream that can
be provoked into failing in a specific, repeatable way. That is what this module
is for. It is deliberately simple: one enum of modes, one function that applies
a mode to an in-flight request.

Two ways to select a mode, checked in this order:

1. Per-request, via the ``X-ACP-Chaos-Mode`` header — lets a test flip one
   upstream between modes without restarting the process.
2. Process-wide, via the ``CHAOS_MODE`` environment variable — lets
   docker-compose or a manual run make a whole mock chaotic by default.

``X-ACP-Chaos-Param`` (or the ``CHAOS_PARAM`` env var) carries the one numeric
knob each mode needs: seconds to hang, or bytes to inflate a payload to.
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
"""JSON-RPC code for a deliberately induced failure.

Sits in the implementation-defined range (-32000 to -32099) so it can never be
confused with a real protocol error the gateway must handle differently.
"""

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


class Disconnected(Exception):  # noqa: N818 — deliberately not an *Error; see below
    """Raised to simulate a mid-response connection drop.

    Not named ``DisconnectedError`` on purpose: this is not really an
    application error, it is a stand-in for the transport vanishing. Real ASGI
    servers (uvicorn) close the socket when a handler raises after starting a
    response; the in-process ASGI test transport surfaces this same exception
    to the caller, which is the closest an in-process test can get to a genuine
    dropped TCP connection. Full socket-level disconnect behaviour is exercised
    later, in Phase 1's integration tests against a real running server.
    """


def resolve_mode(header_value: str | None) -> ChaosMode:
    """Resolve the effective chaos mode: header wins, then env, then NONE."""
    raw = header_value or os.environ.get("CHAOS_MODE") or ChaosMode.NONE.value
    try:
        return ChaosMode(raw.lower())
    except ValueError:
        # An unrecognized mode fails loud rather than silently acting normal —
        # a mistyped header should not masquerade as "everything is fine".
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
    """A deterministic string of approximately ``byte_count`` bytes.

    Deterministic (not random) so a test can assert on its exact length and,
    if useful later, its exact content.
    """
    unit = "chaos-oversized-payload-filler "
    repeats = (byte_count // len(unit)) + 1
    return (unit * repeats)[:byte_count]
