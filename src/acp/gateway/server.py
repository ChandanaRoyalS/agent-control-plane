"""The gateway's inbound half: the MCP server that agents connect to.

Built on the SDK's low-level ``Server`` rather than the high-level
``MCPServer`` — see ADR 0005. The distinction matters more than it looks.
``MCPServer`` registers tools statically with decorators, which models a tool
*provider*. A gateway is a tool *broker*: its catalogue is computed on every
request, merged from live upstreams and (from task 35) filtered by what the
calling principal is entitled to see. ``Server`` takes ``on_list_tools`` and
``on_call_tool`` as per-request async handlers, which is exactly that shape.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette

from acp import __version__
from acp.approvals import DEFAULT_TTL_SECONDS, ApprovalStore, Outcome, gate
from acp.budget import (
    CostTable,
    QuotaCounter,
    RateLimiter,
    enforce_quota,
    enforce_rate_limit,
)
from acp.exceptions import ACPError, PolicyDeniedError
from acp.firewall import Firewall, frame
from acp.gateway.converters import to_input_required, to_mcp_call_tool_result, to_mcp_tool
from acp.gateway.naming import upstream_of
from acp.gateway.registry import UpstreamRegistry
from acp.identity import (
    AuthenticationMiddleware,
    ProtectedResource,
    TokenValidator,
    metadata_route,
)
from acp.identity.principal import Principal, current_principal
from acp.observability import RequestContextMiddleware, metrics
from acp.policy import Policy, enforce_call, visible_tools
from acp.policy.predispatch import PreDispatchAuthorizationMiddleware
from acp.results import CacheableTools, ResultCache, ResultKey, key_for
from acp.upstream.models import CallToolResult

logger = logging.getLogger(__name__)

APPROVAL_EVENT = "approval.gate"
"""One record per approval decision on the request path — started, still
waiting, proceeded or refused. The operator side (task 55) writes the human's
answer; this writes what the gateway did with it."""

SERVER_NAME = "agent-control-plane"

DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")
"""Hosts accepted when nothing else is configured.

The SDK enables DNS-rebinding protection by default and its allow-list has *no*
default value, so an unconfigured server rejects every request. That is the
right default for a security control — deny until told otherwise — but it means
the allow-list is a required decision rather than an optional one.
"""


def to_mcp_error(exc: ACPError) -> MCPError:
    """Render a gateway error as an MCP protocol error.

    The taxonomy already knows how to describe itself as a JSON-RPC error
    object, including the ``recoverable`` hint the agent reasons over, so this
    reuses that rather than inventing a second representation. One error shape,
    one place to change it.
    """
    rendered = exc.to_jsonrpc_error()
    # MCPError takes the JSON-RPC error fields directly rather than an
    # ErrorData object. Verified against mcp 2.0.0's signature, not assumed.
    return MCPError(rendered["code"], rendered["message"], rendered["data"])


def _result_key(
    *,
    principal: Principal | None,
    tool: str,
    arguments: Mapping[str, Any],
    ttl: float | None,
    results: ResultCache | None,
) -> ResultKey | None:
    """The cache key for this call, or ``None`` when it must not be cached.

    ``None`` for four separate reasons, and each is a deliberate refusal rather
    than a missing feature: the tool is not declared cacheable, no cache is
    configured, there is no principal to key on, or the arguments will not
    encode. The third is the one worth naming — an unauthenticated deployment
    gets no result caching at all, because a shared entry is exactly the bug, and
    the control that would make it safe is the one that is absent.
    """
    if ttl is None or results is None or principal is None:
        return None
    return key_for(
        subject=principal.subject,
        actor=principal.actor.subject if principal.actor else None,
        upstream=upstream_of(tool),
        tool=tool,
        arguments=arguments,
    )


def _framed(result: CallToolResult, tool: str, provenance: bool) -> CallToolResult:
    """The result the caller receives: fenced when provenance framing is on.

    Applied at the point of return and nowhere else, so both the cache-hit and
    cache-miss paths get their own fresh delimiter, and the cache never holds
    one. See ADR 0037.
    """
    return frame(result, tool=tool) if provenance else result


def _charge(
    *,
    subject: str | None,
    tool: str,
    limiter: RateLimiter | None,
    costs: CostTable | None,
    quota: QuotaCounter | None,
) -> None:
    """Draw this call against both budgets, or raise the refusal it earns.

    Both key on the principal's subject; with no principal (auth off) there is
    no per-caller budget to charge, so both are skipped. The cost is resolved
    once and shared, because a tool that costs ten should cost ten to each
    budget rather than ten to one and one to the other.

    Extracted from ``on_call_tool`` for a reason worth stating: it is the *only*
    thing between authorization and the cache, so a reader following the
    security argument in that function should be able to see the whole ordering
    on one screen.
    """
    if subject is None or (limiter is None and quota is None):
        return
    cost = costs.cost_of(tool) if costs is not None else 1.0
    try:
        if limiter is not None:
            # A monotonic clock for the rate: a wall-clock jump must not hand
            # out or withhold burst allowance.
            enforce_rate_limit(limiter, subject, time.monotonic(), cost)
        if quota is not None:
            # Wall-clock time for the window: a daily quota aligns to real
            # calendar time, not to how long the process has been running.
            enforce_quota(quota, subject, time.time(), cost)
    except ACPError as exc:
        raise to_mcp_error(exc) from exc


def _served_from_cache(results: ResultCache, key: ResultKey, tool: str) -> CallToolResult | None:
    """A held result for this key, with the hit or miss recorded either way."""
    held = results.get(key)
    results.record(hit=held is not None)
    metrics.record_result_cache(outcome="hit" if held is not None else "miss")
    if held is not None:
        logger.debug("gateway.result_cache_hit", extra={"tool": tool, "key": key.short})
    return held


def _await_approval(
    store: ApprovalStore | None,
    principal: Principal,
    params: types.CallToolRequestParams,
    rule: str | None,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> types.InputRequiredResult | None:
    """Start or resolve an approval; ``None`` means the call may now proceed.

    **`params.input_responses` is read by nobody, and that is the point.** MRTR
    lets a client answer the questions a server asked, and an approval answered
    by the caller is not an approval — the caller is the agent, and an agent
    talked into a destructive call by a poisoned document is exactly the one
    that will answer "yes" on its own behalf. Only `request_state` is read, and
    only as a handle to a decision made somewhere the agent cannot reach.

    A loaded policy that holds a call with no store configured is the same
    fail-closed misconfiguration as a policy with no principal: refused, not
    permitted. The alternative is a deployment where `require_approval` silently
    means `allow`, which is the worst possible reading of that word.
    """
    if store is None:
        logger.error(
            "approval.no_store",
            extra={"tool": params.name, "rule": rule},
        )
        raise to_mcp_error(PolicyDeniedError("this call was not permitted"))

    outcome = gate(
        store,
        token=params.request_state,
        subject=principal.subject,
        actor=principal.actor.subject if principal.actor else None,
        tool=params.name,
        arguments=params.arguments or {},
        rule=rule,
        now=time.time(),
        ttl=ttl,
    )
    logger.info(
        APPROVAL_EVENT,
        extra={
            "subject": principal.subject,
            "tool": params.name,
            "rule": rule,
            "outcome": outcome.outcome.value,
            "reason": outcome.reason,
        },
    )
    if outcome.outcome is Outcome.PROCEED:
        return None
    if outcome.outcome is Outcome.WAIT and outcome.token is not None:
        return to_input_required(
            token=outcome.token,
            expires_in=(outcome.expires_at or 0.0) - time.time(),
        )
    raise to_mcp_error(PolicyDeniedError("this call was not permitted"))


def build_server(
    registry: UpstreamRegistry,
    *,
    policy: Policy | None = None,
    limiter: RateLimiter | None = None,
    costs: CostTable | None = None,
    quota: QuotaCounter | None = None,
    cacheable: CacheableTools | None = None,
    results: ResultCache | None = None,
    provenance: bool = False,
    firewall: Firewall | None = None,
    approvals: ApprovalStore | None = None,
    approval_ttl: float = DEFAULT_TTL_SECONDS,
) -> Server[None]:
    """Build an MCP server that brokers for the registry's upstreams.

    The handlers are closures over ``registry`` rather than methods on a class
    because the SDK wants plain callables, and because there is no per-server
    mutable state to hold — every request is answered from the upstreams as they
    are *now*, which is the property that makes health-driven catalogue
    withdrawal (task 18) possible later.
    """

    # `_ctx` and `_params` are positional in the SDK's handler contract, so
    # they cannot be dropped. Underscore-prefixed until they are used:
    # `_ctx` carries the HTTP request (headers, auth) and becomes load-bearing
    # in tasks 22 and 35; `_params.cursor` matters once catalogues paginate.
    async def on_list_tools(
        _ctx: ServerRequestContext[None, Any],
        _params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        catalogue = await registry.list_tools()

        if policy is not None:
            # Show only what this principal may call. Fail-closed, like
            # on_call_tool: a loaded policy with no principal sees an
            # empty catalogue, not the full one.
            principal = current_principal()
            visible = (
                visible_tools(policy, principal, catalogue.tools) if principal is not None else []
            )
            catalogue = replace(catalogue, tools=visible)

        if catalogue.is_total_failure:
            # Nothing answered. Returning an empty catalogue would tell the
            # agent it has no tools, which is indistinguishable from a correctly
            # configured gateway with nothing attached — and would send it off
            # to attempt the task without them. An error says "ask again later".
            first = next(iter(catalogue.failures.values()))
            raise to_mcp_error(first)

        # Withdrawals are deliberately not logged here. They were logged once,
        # by the health monitor, when the upstream changed state — logging them
        # again on every request would produce a warning per request for as long
        # as the outage lasts.
        for name, exc in catalogue.failures.items():
            # Partial failure is served, not raised — see UpstreamRegistry.
            logger.warning(
                "gateway.upstream_degraded",
                extra={
                    "upstream": name,
                    "operation": "tools/list",
                    "error": type(exc).__name__,
                    "reason": exc.message,
                    "served_tools": len(catalogue.tools),
                    "withdrawn": sorted(catalogue.withdrawn),
                },
            )

        # The gateway's own freshness hint, composed from the upstreams that
        # contributed. An agent's prompt contains this list, so a catalogue that
        # changes every turn misses the model provider's prompt cache and the
        # whole prompt is billed again — stability here is a cost decision, not
        # only a latency one.
        return types.ListToolsResult(
            tools=[to_mcp_tool(tool) for tool in catalogue.tools],
            ttl_ms=catalogue.ttl_ms,
            cache_scope="public" if catalogue.cache_scope == "public" else "private",
        )

    async def on_call_tool(
        _ctx: ServerRequestContext[None, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult | types.InputRequiredResult:
        principal = current_principal()
        if policy is not None:
            # Fail-closed: a loaded policy means authorization is
            # expected. A missing principal here is a misconfiguration
            # (policy set, auth not), and must deny rather than permit.
            if principal is None:
                raise to_mcp_error(PolicyDeniedError("this call was not permitted"))
            try:
                decision = enforce_call(policy, principal, params.name, params.arguments or {})
            except ACPError as exc:
                raise to_mcp_error(exc) from exc

            if decision.requires_approval:
                # Held for a person (ADR 0048). Returns before budget is
                # charged, before the cache is consulted and before anything
                # reaches an upstream — a call that has not happened must not
                # spend, must not be answered from memory, and must not run.
                awaiting = _await_approval(
                    approvals, principal, params, decision.rule, approval_ttl
                )
                if awaiting is not None:
                    return awaiting

        # After authorization: a denied call must not spend budget, and charging
        # a call we would refuse anyway is wasted work.
        _charge(
            subject=principal.subject if principal is not None else None,
            tool=params.name,
            limiter=limiter,
            costs=costs,
            quota=quota,
        )
        # The result cache, and its position in this function is the whole
        # security argument (ADR 0035). Everywhere else in this codebase caching
        # is outermost, because a hit should cost nothing — ADR 0006 argues it
        # explicitly. Here that instinct is a vulnerability: a result cache
        # consulted before authorization serves a caller the policy would have
        # refused, and the denial never runs at all.
        #
        # So it sits *after* policy and *after* budget. After policy, because a
        # denied call must never be answered from memory. After budget, because
        # a caller repeating themselves is still making a call — otherwise the
        # cheapest way to stay under a quota is to ask the same question twice,
        # and ADR 0033's cost table quietly stops meaning anything.
        arguments = params.arguments or {}
        ttl = cacheable.ttl_for(params.name) if cacheable is not None else None
        cache_key = _result_key(
            principal=principal,
            tool=params.name,
            arguments=arguments,
            ttl=ttl,
            results=results,
        )
        if cache_key is not None and results is not None:
            held = _served_from_cache(results, cache_key, params.name)
            if held is not None:
                # Framed here rather than before storing: a cached fence is a
                # fence the attacker has already seen, and a per-result nonce
                # replayed from a cache entry is a per-entry one (ADR 0037).
                return to_mcp_call_tool_result(_framed(held, params.name, provenance))

        try:
            result = await registry.call_tool(params.name, arguments)
        except ACPError as exc:
            raise to_mcp_error(exc) from exc

        # Screened on the miss path only. A cache hit was screened before it was
        # stored, so what is held is by construction what the firewall allowed —
        # and re-screening every hit would erase the reason the cache exists.
        # The honest cost, and its two bounds, are in ADR 0038.
        if firewall is not None:
            inspection = firewall.inspect(result, tool=params.name, tools=registry.known_tools)
            if inspection.refused:
                # Returned unframed, and that is deliberate: the fence marks
                # text the gateway did *not* write, so fencing the gateway's own
                # notice would be a lie about its origin. With framing on, an
                # unfenced block is by construction the gateway speaking.
                return to_mcp_call_tool_result(inspection.result)
            if not inspection.cacheable:
                # Truncated screening: served once, examined in part, never
                # repeated. Storing a document whose tail was never examined
                # turns one unexamined document into every later caller's answer
                # for the length of its ttl.
                cache_key = None

        if cache_key is not None and results is not None and ttl is not None:
            # `put` refuses an `is_error` result itself, so a failed tool call
            # cannot be cached even from here.
            results.put(cache_key, result, ttl=ttl)
        return to_mcp_call_tool_result(_framed(result, params.name, provenance))

    return Server(
        SERVER_NAME,
        version=__version__,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_app(
    registry: UpstreamRegistry,
    *,
    allowed_hosts: Sequence[str] = DEFAULT_ALLOWED_HOSTS,
    allowed_origins: Sequence[str] = (),
    validator: TokenValidator | None = None,
    resource: ProtectedResource | None = None,
    policy: Policy | None = None,
    limiter: RateLimiter | None = None,
    costs: CostTable | None = None,
    quota: QuotaCounter | None = None,
    cacheable: CacheableTools | None = None,
    results: ResultCache | None = None,
    provenance: bool = False,
    firewall: Firewall | None = None,
    approvals: ApprovalStore | None = None,
    approval_ttl: float = DEFAULT_TTL_SECONDS,
) -> Starlette:
    """Build the ASGI application agents connect to.

    ``stateless_http=True`` matches ADR 0001: the 2026-07-28 revision removed
    the initialize handshake and the session header, so there is no session to
    keep and any instance can serve any request.

    ``json_response=True`` returns a plain JSON body rather than an SSE stream
    for unary responses. Simpler to proxy, simpler to test, and nothing in the
    gateway's current surface streams.

    ``allowed_hosts`` and ``allowed_origins`` drive the SDK's DNS-rebinding
    protection: it rejects any ``Host`` it was not told to expect, which defends
    a locally-bound server against a malicious web page resolving a hostname to
    a loopback address. Defaults cover local development; deployment behind a
    real hostname must pass its own list, and that becomes config in task 11.

    ``resource``, when given, adds the RFC 9728 metadata route *and* is what the
    authentication middleware exempts. One object doing both is the point: the
    only unauthenticated path in the gateway is derived from the document being
    served there rather than from a list of paths kept in step by hand.
    """
    security = TransportSecuritySettings(
        allowed_hosts=list(allowed_hosts),
        allowed_origins=list(allowed_origins),
    )
    app = build_server(
        registry,
        policy=policy,
        limiter=limiter,
        costs=costs,
        quota=quota,
        cacheable=cacheable,
        results=results,
        provenance=provenance,
        firewall=firewall,
        approvals=approvals,
        approval_ttl=approval_ttl,
    ).streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
    if resource is not None:
        # Inserted at the front rather than appended, because the SDK is free to
        # mount its transport at the root — and a route added after a catch-all
        # mount is a route that never matches. This is one line of defence
        # against a silent 404 on the one endpoint whose entire job is to be
        # findable by a client that knows nothing else about this gateway.
        #
        # The middleware receives the same object, which is what makes this
        # route reachable without a token: the exemption is `metadata_path`
        # taken from `resource`, so serving it and exempting it cannot come
        # apart. See `acp.identity.resource`.
        app.router.routes.insert(0, metadata_route(resource))
    # Added to Starlette's own stack rather than by wrapping the app, so the
    # returned object is still a Starlette instance — `app.router` and the
    # lifespan context are part of this function's contract and the tests use
    # them. Safe to call here because Starlette builds its middleware stack
    # lazily, on the first request rather than at construction.
    #
    # Order matters, and Starlette's is the reverse of the reading order:
    # `add_middleware` inserts at the front, so the *last* one added runs
    # outermost and the *first* one added runs innermost. Read the three calls
    # below bottom-up and you have the order a request actually meets them:
    # request context, then authentication, then pre-dispatch authorization.
    #
    # Authentication runs *inside* the request-context middleware, which is what
    # makes a rejected request still carry a request ID in its log line. A 401
    # nobody can correlate is a 401 nobody can investigate.
    #
    # Pre-dispatch authorization runs innermost of the three, inside
    # authentication, which is what lets it read a principal that has already
    # been resolved. It refuses a call the policy could never permit before the
    # body is parsed (ADR 0043), and it can only ever subtract: anything it does
    # not refuse still reaches `enforce_call`, which reads the body and remains
    # authoritative.
    app.add_middleware(PreDispatchAuthorizationMiddleware, policy=policy)
    app.add_middleware(AuthenticationMiddleware, validator=validator, resource=resource)
    app.add_middleware(RequestContextMiddleware)
    return app
