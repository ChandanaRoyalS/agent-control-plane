"""Unit tests for the request envelope, and for how trace context rides in it.

The trace-context rules are the interesting part. They are a deliberate
*exception* to the namespacing convention the rest of this module enforces, so
they are the rules most likely to be "corrected" by someone tidying up later.
"""

from __future__ import annotations

from acp.upstream import envelope
from acp.upstream.models import PROTOCOL_VERSION

TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"


def meta(trace_context: dict[str, str] | None = None) -> dict[str, object]:
    params = envelope.with_envelope(None, "acp-tests", "0", trace_context)
    assert isinstance(params["_meta"], dict)
    return params["_meta"]


# ---------------------------------------------------------------------------
# The envelope itself
# ---------------------------------------------------------------------------


def test_the_envelope_carries_the_two_required_keys() -> None:
    envelope_meta = meta()

    for key in envelope.REQUIRED_META_KEYS:
        assert key in envelope_meta


def test_capabilities_are_declared_empty_rather_than_omitted() -> None:
    """Omitting the key is a protocol error. Sending an empty object is an
    honest statement that a broker advertises nothing it cannot honour."""
    assert meta()[envelope.CLIENT_CAPABILITIES_META_KEY] == {}


def test_params_exist_even_for_a_method_that_takes_none() -> None:
    """`tools/list` has no arguments, but the envelope lives inside params, so
    a request without them is rejected before the method is dispatched."""
    assert "_meta" in envelope.with_envelope(None, "acp-tests", "0")


def test_the_callers_params_survive_alongside_the_envelope() -> None:
    params = envelope.with_envelope({"name": "search"}, "acp-tests", "0")

    assert params["name"] == "search"
    assert params["_meta"][envelope.PROTOCOL_VERSION_META_KEY] == PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# Trace context — the documented exception
# ---------------------------------------------------------------------------


def test_traceparent_is_carried_unprefixed() -> None:
    """SEP-414 states this explicitly. An implementation that namespaced it as
    `io.modelcontextprotocol/traceparent` would break traces and log
    correlation against every implementation that did not — which is why the
    exception exists at all."""
    assert meta({"traceparent": TRACEPARENT})["traceparent"] == TRACEPARENT


def test_tracestate_and_baggage_ride_along_too() -> None:
    carrier = {"traceparent": TRACEPARENT, "tracestate": "vendor=x", "baggage": "k=v"}

    assert dict(meta(carrier), **carrier) == meta(carrier)


def test_no_trace_context_means_no_extra_keys() -> None:
    """An untraced gateway must send exactly the request it sent before tracing
    existed — so an absent trace cannot be inferred from the wire."""
    assert set(meta()) == set(meta({}))


def test_keys_the_spec_does_not_reserve_are_dropped() -> None:
    """`_meta` is a shared namespace. A propagator configured to emit something
    extra would be planting an unexpected bare key in it, and an unexpected
    bare key in someone else's namespace is a bug they get to discover."""
    carrier = {"traceparent": TRACEPARENT, "x-vendor-trace": "leaked"}

    assert "x-vendor-trace" not in meta(carrier)
    assert meta(carrier)["traceparent"] == TRACEPARENT


def test_trace_context_cannot_overwrite_the_protocol_envelope() -> None:
    """A propagator cannot be tricked into forging the protocol version: only
    the three reserved keys are merged, so the envelope keys are unreachable."""
    hostile = {
        "traceparent": TRACEPARENT,
        envelope.PROTOCOL_VERSION_META_KEY: "1999-01-01",
    }

    assert meta(hostile)[envelope.PROTOCOL_VERSION_META_KEY] == PROTOCOL_VERSION
