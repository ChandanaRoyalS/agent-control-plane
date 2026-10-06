"""The MCP server agents connect to, brokering calls to the upstreams.

Built on the SDK's low-level ``Server`` (ADR 0005), whose per-request ``on_list_tools`` and
``on_call_tool`` handlers suit a broker whose catalogue is merged from live upstreams and
filtered per principal.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any, Final

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette

from acp import __version__
from acp.approvals import DEFAULT_TTL_SECONDS, ApprovalStore, Outcome, gate
from acp.audit import AuditLog
from acp.audit import Category as AuditCategory
from acp.audit import Outcome as AuditOutcome
from acp.budget import CostTable, QuotaCounter, RateLimiter, account
from acp.budget.charge import Budgets, LocalBudgets
from acp.exceptions import ACPError, ApprovalUnsupportedError, PolicyDeniedError
from acp.firewall import Firewall, Inspection, frame
from acp.firewall.catalogue import CatalogueInspection
from acp.firewall.learned import DETECTOR_NAME as LEARNED_DETECTOR
from acp.gateway.converters import to_input_required, to_mcp_call_tool_result, to_mcp_tool
from acp.gateway.naming import upstream_of
from acp.gateway.registry import Catalogue, UpstreamRegistry
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
from acp.policy.tenancy import PolicySet
from acp.results import CacheableTools, ResultCache, ResultKey, key_for
from acp.upstream.models import CallToolResult

logger = logging.getLogger(__name__)

APPROVAL_EVENT = "approval.gate"
"""Log event for each request-path approval outcome (started, waiting, proceeded, refused)."""

SERVER_NAME = "agent-control-plane"

DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")
"""Hosts accepted by default; the SDK's DNS-rebinding allow-list rejects all when empty."""


def to_mcp_error(exc: ACPError) -> MCPError:
    """Render a gateway error as an MCP protocol error via ``to_jsonrpc_error``."""
    rendered = exc.to_jsonrpc_error()
    # MCPError takes the fields directly (verified against mcp 2.0.0).
    return MCPError(rendered["code"], rendered["message"], rendered["data"])


def _result_key(
    *,
    principal: Principal | None,
    tool: str,
    arguments: Mapping[str, Any],
    ttl: float | None,
    results: ResultCache | None,
) -> ResultKey | None:
    """Return the cache key for this call, or ``None`` when it must not be cached.

    ``None`` when the tool is not cacheable, no cache is configured, the arguments will
    not encode, or there is no principal: unauthenticated deployments get no result
    caching, since a shared entry would leak across callers.
    """
    if ttl is None or results is None or principal is None:
        return None
    return key_for(
        tenant=principal.tenant,
        subject=principal.subject,
        actor=principal.actor.subject if principal.actor else None,
        upstream=upstream_of(tool),
        tool=tool,
        arguments=arguments,
    )


def _framed(result: CallToolResult, tool: str, provenance: bool) -> CallToolResult:
    """Return the result fenced when provenance framing is on.

    Applied only at return, so each hit or miss gets a fresh delimiter and the cache
    never holds one (ADR 0037).
    """
    return frame(result, tool=tool) if provenance else result


def _keeper(
    budgets: Budgets | None, limiter: RateLimiter | None, quota: QuotaCounter | None
) -> Budgets | None:
    """Return ``budgets``, else ``LocalBudgets`` over the given limiter/quota, else ``None``."""
    if budgets is not None:
        return budgets
    if limiter is None and quota is None:
        return None
    return LocalBudgets(limiter, quota)


async def _charge(
    *,
    payer: str | None,
    tool: str,
    budgets: Budgets | None,
    costs: CostTable | None,
    charged: Callable[[str, str, float], None] | None = None,
) -> None:
    """Charge this call against both budgets, or raise the refusal as an MCP error.

    ``payer`` is the tenant-qualified account (`acp.budget.account`); ``None`` (auth off)
    skips charging. One resolved cost is applied to both budgets. Check-both-then-debit-both
    (ADR 0044 §3) is the keeper's guarantee (`RedisBudgets`: ADR 0067).
    """
    if payer is None or budgets is None:
        return
    cost = costs.cost_of(tool) if costs is not None else 1.0
    # Monotonic for the rate (immune to clock jumps); wall clock for calendar quotas.
    mono, wall = time.monotonic(), time.time()
    try:
        await budgets.charge(payer, cost, mono=mono, wall=wall)
    except ACPError as exc:
        raise to_mcp_error(exc) from exc

    if charged is not None:
        # Reported only after both draws succeed, so a refused call is not spend. A
        # callback keeps this module unaware of the console (cf. `AuditLog.published`).
        charged(payer, tool, cost)


def _served_from_cache(results: ResultCache, key: ResultKey, tool: str) -> CallToolResult | None:
    """Return a cached result for this key, recording the hit or miss."""
    held = results.get(key)
    results.record(hit=held is not None)
    metrics.record_result_cache(outcome="hit" if held is not None else "miss")
    if held is not None:
        logger.debug("gateway.result_cache_hit", extra={"tool": tool, "key": key.short})
    return held


FIREWALL_EVENT = "firewall.screened"
CATALOGUE_EVENT = "firewall.catalogue"
AUTHORIZATION_EVENT = "policy.decision"
TOOL_CALL_EVENT = "tool.called"


async def _chain(audit: AuditLog, *args: Any, **fields: Any) -> None:
    """Write one audit record, converting a fail-closed refusal into an MCP error.

    Otherwise `AuditUnavailableError` would reach the caller as a generic -32603 and lose
    its ``recoverable`` hint.
    """
    try:
        # `arecord` keeps the fsync off the event loop (ADR 0053); awaited, so the
        # request waits until its entry is durable.
        await audit.arecord(*args, **fields)
    except ACPError as exc:
        raise to_mcp_error(exc) from exc


def _actor_of(principal: Principal | None) -> str | None:
    return principal.actor.subject if principal is not None and principal.actor else None


async def _audit_decision(
    audit: AuditLog | None,
    principal: Principal,
    params: types.CallToolRequestParams,
    *,
    allowed: bool,
    rule: str | None,
    held: bool = False,
) -> None:
    """Chain one authorization decision: allowed, denied or held.

    Records argument names, never values (ADR 0045).
    """
    if audit is None:
        return
    outcome = (
        AuditOutcome.HELD if held else (AuditOutcome.ALLOWED if allowed else AuditOutcome.DENIED)
    )
    await _chain(
        audit,
        AuditCategory.AUTHORIZATION,
        AUTHORIZATION_EVENT,
        subject=principal.subject,
        actor=_actor_of(principal),
        tenant=principal.tenant,
        tool=params.name,
        rule=rule,
        outcome=outcome,
        detail={"argument_names": sorted(params.arguments or {})},
    )


async def _audit_screening(
    audit: AuditLog | None,
    principal: Principal | None,
    tool: str,
    inspection: Inspection,
) -> None:
    """Chain a screening finding, if any; clean results are counted by metrics only.

    Records families, confidences and detector names, never the matched text
    (ADR 0038). The learned classifier's evidence is its score and thresholds,
    gateway-written text, so it is recorded too (ADR 0076).
    """
    findings = inspection.screening.findings
    if audit is None or not findings:
        return
    learned = [f.evidence for f in findings if f.detector == LEARNED_DETECTOR]
    await _chain(
        audit,
        AuditCategory.FIREWALL,
        FIREWALL_EVENT,
        subject=principal.subject if principal is not None else None,
        actor=_actor_of(principal),
        tenant=principal.tenant if principal is not None else None,
        tool=tool,
        outcome=AuditOutcome.DENIED if inspection.refused else AuditOutcome.ALLOWED,
        detail={
            "families": sorted({str(f.family) for f in findings}),
            "confidences": sorted({str(f.confidence) for f in findings}),
            "finding_count": len(findings),
            # 0 for a flagged-but-served document, the common case (ADR 0039).
            "trigger_count": len(inspection.triggers),
            "detectors": sorted({f.detector for f in findings}),
            **({"learned": learned[0]} if learned else {}),
        },
    )


async def _screen_catalogue(
    firewall: Firewall | None, audit: AuditLog | None, catalogue: Catalogue
) -> Catalogue:
    """Return the catalogue with tool descriptions screened (ADR 0065).

    In enforce mode a description crossing the bar is withheld. Runs after policy
    filtering, so hidden tools are neither screened nor recorded.
    """
    if firewall is None or not catalogue.tools:
        return catalogue
    inspection = await firewall.ainspect_catalogue(catalogue.tools)
    await _audit_catalogue(audit, current_principal(), inspection)
    return replace(catalogue, tools=inspection.served)


async def _audit_catalogue(
    audit: AuditLog | None,
    principal: Principal | None,
    inspection: CatalogueInspection,
) -> None:
    """Chain one record per flagged tool, never the description text."""
    if audit is None:
        return
    for screened in inspection.flagged:
        findings = screened.screening.findings
        await _chain(
            audit,
            AuditCategory.FIREWALL,
            CATALOGUE_EVENT,
            subject=principal.subject if principal is not None else None,
            actor=_actor_of(principal),
            tenant=principal.tenant if principal is not None else None,
            tool=screened.tool.name,
            outcome=AuditOutcome.DENIED if screened.withheld else AuditOutcome.ALLOWED,
            detail={
                "families": sorted({str(f.family) for f in findings}),
                "confidences": sorted({str(f.confidence) for f in findings}),
                "finding_count": len(findings),
                "trigger_count": len(screened.triggers),
            },
        )


async def _audit_call(
    audit: AuditLog | None,
    principal: Principal | None,
    tool: str,
    outcome: AuditOutcome,
    *,
    reason: str | None = None,
) -> None:
    """Chain whether a call reached an upstream."""
    if audit is None:
        return
    await _chain(
        audit,
        AuditCategory.TOOL_CALL,
        TOOL_CALL_EVENT,
        subject=principal.subject if principal is not None else None,
        actor=_actor_of(principal),
        tenant=principal.tenant if principal is not None else None,
        tool=tool,
        outcome=outcome,
        reason=reason,
    )


MRTR_VERSION: Final = "2026-07-28"
"""First protocol revision with `input_required`; revisions are dates and order as strings."""


def can_wait(protocol_version: str | None) -> bool:
    """Return whether a client on this revision can be held for approval (ADR 0072).

    An unknown version cannot, since nobody could resume its approval.
    """
    return protocol_version is not None and protocol_version >= MRTR_VERSION


async def _await_approval(
    store: ApprovalStore | None,
    principal: Principal,
    params: types.CallToolRequestParams,
    rule: str | None,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> types.InputRequiredResult | None:
    """Start or resolve an approval; ``None`` means the call may now proceed.

    Only `request_state` is read, as a handle; ``input_responses`` is ignored because the
    caller (the agent) must not approve its own call. With no store configured a held call
    is refused (fail closed), never allowed.
    """
    if store is None:
        logger.error(
            "approval.no_store",
            extra={"tool": params.name, "rule": rule},
        )
        raise to_mcp_error(PolicyDeniedError("this call was not permitted"))

    try:
        outcome = await gate(
            store,
            token=params.request_state,
            tenant=principal.tenant,
            subject=principal.subject,
            actor=principal.actor.subject if principal.actor else None,
            tool=params.name,
            arguments=params.arguments or {},
            rule=rule,
            now=time.time(),
            ttl=ttl,
        )
    except ACPError as exc:
        # Unreachable shared store (ADR 0070): refuse legibly.
        raise to_mcp_error(exc) from exc
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


async def _authorize(
    policies: PolicySet,
    principal: Principal | None,
    params: types.CallToolRequestParams,
    *,
    protocol_version: str | None,
    audit: AuditLog | None,
    approvals: ApprovalStore | None,
    approval_ttl: float,
) -> types.InputRequiredResult | None:
    """Decide a call under a loaded policy: raise, hold, or ``None`` to proceed.

    Runs before budget, cache and upstream: decision, its audit record, then any approval.
    """
    # Fail closed: a loaded policy with no principal is a misconfiguration.
    if principal is None:
        raise to_mcp_error(PolicyDeniedError("this call was not permitted"))
    try:
        decision = enforce_call(
            policies.policy_for(principal.tenant),
            principal,
            params.name,
            params.arguments or {},
        )
    except ACPError as exc:
        # Audit the denial before raising, so refusals reach the chain.
        await _audit_decision(audit, principal, params, allowed=False, rule=None)
        raise to_mcp_error(exc) from exc

    # Unwaitable held call: refused and recorded as refused, not held (ADR 0072).
    unwaitable = decision.requires_approval and not can_wait(protocol_version)
    await _audit_decision(
        audit,
        principal,
        params,
        allowed=decision.allowed and not unwaitable,
        rule=decision.rule,
        held=decision.requires_approval and not unwaitable,
    )
    if unwaitable:
        raise to_mcp_error(
            ApprovalUnsupportedError(
                "this call needs a person's approval; connect with "
                f"MCP {MRTR_VERSION} or later to wait for it"
            )
        )

    if decision.requires_approval:
        # Held (ADR 0048): return before budget, cache or upstream.
        return await _await_approval(approvals, principal, params, decision.rule, approval_ttl)
    return None


def build_server(
    registry: UpstreamRegistry,
    *,
    policy: Policy | PolicySet | None = None,
    limiter: RateLimiter | None = None,
    costs: CostTable | None = None,
    quota: QuotaCounter | None = None,
    budgets: Budgets | None = None,
    cacheable: CacheableTools | None = None,
    results: ResultCache | None = None,
    provenance: bool = False,
    firewall: Firewall | None = None,
    approvals: ApprovalStore | None = None,
    approval_ttl: float = DEFAULT_TTL_SECONDS,
    audit: AuditLog | None = None,
    charged: Callable[[str, str, float], None] | None = None,
) -> Server[None]:
    """Build an MCP server that brokers for the registry's upstreams.

    Handlers are stateless closures; every request is answered from the upstreams as
    they are now.
    """

    # A bare `Policy` becomes a set's default, so a tenanted principal fails closed to
    # DENY_ALL rather than getting the single-tenant rules.
    policies = policy if isinstance(policy, PolicySet) or policy is None else PolicySet(policy)

    # In-memory keeper around limiter/quota, or a shared one (`RedisBudgets`, ADR 0067).
    keeper = _keeper(budgets, limiter, quota)

    # `_ctx` and `_params` are positional in the SDK contract; unused for now.
    async def on_list_tools(
        _ctx: ServerRequestContext[None, Any],
        _params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        catalogue = await registry.list_tools()

        if policies is not None:
            # Only what this principal's tenant policy permits; no principal sees nothing.
            principal = current_principal()
            visible = (
                visible_tools(policies.policy_for(principal.tenant), principal, catalogue.tools)
                if principal is not None
                else []
            )
            catalogue = replace(catalogue, tools=visible)

        catalogue = await _screen_catalogue(firewall, audit, catalogue)

        if catalogue.is_total_failure:
            # Raise rather than return an empty list the agent would take as "no tools".
            first = next(iter(catalogue.failures.values()))
            raise to_mcp_error(first)

        # Withdrawals are not logged here; the health monitor logged the state change.
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

        # Stable hints keep the agent's prompt cache warm, which is a cost decision.
        return types.ListToolsResult(
            tools=[to_mcp_tool(tool) for tool in catalogue.tools],
            ttl_ms=catalogue.ttl_ms,
            cache_scope="public" if catalogue.cache_scope == "public" else "private",
        )

    async def on_call_tool(
        ctx: ServerRequestContext[None, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult | types.InputRequiredResult:
        principal = current_principal()
        if policies is not None:
            awaiting = await _authorize(
                policies,
                principal,
                params,
                protocol_version=ctx.protocol_version,
                audit=audit,
                approvals=approvals,
                approval_ttl=approval_ttl,
            )
            if awaiting is not None:
                return awaiting

        # Budget after authorization: a denied call must not spend.
        await _charge(
            payer=account(principal.tenant, principal.subject) if principal is not None else None,
            tool=params.name,
            budgets=keeper,
            costs=costs,
            charged=charged,
        )
        # Cache after policy and budget (ADR 0035): a denied call is never served from
        # memory, and a repeat still spends (ADR 0033), unlike outermost caching (ADR 0006).
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
                # Framed on return, never stored framed, so the nonce stays fresh (ADR 0037).
                return to_mcp_call_tool_result(_framed(held, params.name, provenance))

        try:
            result = await registry.call_tool(params.name, arguments)
        except ACPError as exc:
            await _audit_call(
                audit, principal, params.name, AuditOutcome.FAILED, reason=type(exc).__name__
            )
            raise to_mcp_error(exc) from exc

        # Separate from the authorization record: allowed is not the same as ran.
        await _audit_call(audit, principal, params.name, AuditOutcome.COMPLETED)

        # Screen on the miss path only; cached results were screened before storing
        # (ADR 0038).
        if firewall is not None:
            inspection = await firewall.ainspect(
                result, tool=params.name, tools=registry.known_tools
            )
            await _audit_screening(audit, principal, params.name, inspection)
            if inspection.refused:
                # Unframed: the fence marks upstream text, and this notice is the gateway's.
                return to_mcp_call_tool_result(inspection.result)
            if not inspection.cacheable:
                # Partially screened: serve once, never cache.
                cache_key = None

        if cache_key is not None and results is not None and ttl is not None:
            # `put` itself refuses `is_error` results.
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
    policy: Policy | PolicySet | None = None,
    limiter: RateLimiter | None = None,
    costs: CostTable | None = None,
    quota: QuotaCounter | None = None,
    budgets: Budgets | None = None,
    cacheable: CacheableTools | None = None,
    results: ResultCache | None = None,
    provenance: bool = False,
    firewall: Firewall | None = None,
    approvals: ApprovalStore | None = None,
    approval_ttl: float = DEFAULT_TTL_SECONDS,
    audit: AuditLog | None = None,
    charged: Callable[[str, str, float], None] | None = None,
) -> Starlette:
    """Build the ASGI application agents connect to.

    ``stateless_http=True`` per ADR 0001 (no session in the 2026-07-28 revision);
    ``json_response=True`` since nothing streams. ``allowed_hosts``/``allowed_origins``
    drive the SDK's DNS-rebinding protection; deployments must pass their own hostnames.
    ``resource`` adds the RFC 9728 route and is also the middleware's only exemption.
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
        budgets=budgets,
        cacheable=cacheable,
        results=results,
        provenance=provenance,
        firewall=firewall,
        approvals=approvals,
        approval_ttl=approval_ttl,
        audit=audit,
        charged=charged,
    ).streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
    if resource is not None:
        # Insert first: a route after the SDK's catch-all mount would never match. The
        # middleware exempts the same `metadata_path` (see `acp.identity.resource`).
        app.router.routes.insert(0, metadata_route(resource))
    # Added via Starlette's stack so the app stays a Starlette instance (tests use it).
    # The last added runs outermost, so requests meet: request context (so 401s carry a
    # request ID), then authentication, then pre-dispatch authorization (ADR 0043),
    # which can only subtract; `enforce_call` remains authoritative.
    app.add_middleware(PreDispatchAuthorizationMiddleware, policy=policy, audit=audit)
    app.add_middleware(AuthenticationMiddleware, validator=validator, resource=resource)
    app.add_middleware(RequestContextMiddleware)
    return app
