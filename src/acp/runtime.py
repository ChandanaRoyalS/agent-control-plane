"""Process lifecycle: building the gateway from config and taking it down cleanly.

Upstream pools are closed by a context manager wrapped around the server, not the
ASGI lifespan: uvicorn drains in-flight requests on ``SIGTERM`` and returns from
``serve()``, and only then does ``aclose`` run.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Final

from starlette.applications import Starlette

from acp.approvals import DEFAULT_TTL_SECONDS, ApprovalStore, InMemoryApprovalStore
from acp.approvals.redis_store import RedisApprovalStore
from acp.audit import AuditLog, FileAuditSink
from acp.audit.chain import Entry
from acp.audit.signing import load_signer
from acp.budget import CostTable, QuotaCounter, RateLimiter, load_costs
from acp.budget.account import parties
from acp.budget.charge import Budgets
from acp.budget.redis_store import RedisBudgets
from acp.config import GatewaySettings, allowed_hosts_for, load_issuers, load_upstreams
from acp.console.events import from_entry, observed
from acp.console.hub import TraceHub
from acp.exceptions import ConfigurationError
from acp.firewall import Firewall, OllamaClassifier, firewall_for, ollama_classify
from acp.firewall.decision import ENFORCEABLE, LearnedMode
from acp.firewall.decision import Mode as FirewallMode
from acp.firewall.learned import load_model
from acp.gateway import UpstreamRegistry, build_app
from acp.health import DEFAULT_INTERVAL, HealthMonitor, HealthRecord, UpstreamHealth
from acp.identity import (
    ExchangedCredentials,
    IssuerRegistry,
    ProtectedResource,
    TokenExchanger,
    TokenValidator,
    discover,
    protected_resource,
    require_token_endpoints,
)
from acp.identity.cache import CredentialCache
from acp.identity.issuers import registry_from_documents, tenant_labels
from acp.policy import Effect, Policy, PolicySet
from acp.policy.tenancy import load_policy_set
from acp.results import CacheableTools, ResultCache, load_cacheable
from acp.schema import DEFAULT_BASELINE_PATH, DriftDetector, SchemaSnapshot
from acp.secrets import EmptyStore, EncryptedFileStore, SecretStore, read_key
from acp.upstream import Upstream, UpstreamConfig, connect_upstream

logger = logging.getLogger(__name__)


def build_drift_detector(baseline_file: Path, known: Sequence[str]) -> DriftDetector:
    """Load the committed baseline, tolerating its absence and its corruption.

    Unlike config errors this is not fatal, since a monitor must not stop the
    gateway: a corrupt baseline is logged at ERROR and treated as absent.
    """
    try:
        baseline = SchemaSnapshot.load(baseline_file)
    except ConfigurationError as exc:
        logger.error(  # noqa: TRY400 — the traceback adds nothing
            "schema.baseline_unreadable",
            extra={"path": str(baseline_file), "error": exc.message},
        )
        baseline = None

    if baseline is None:
        logger.warning(
            "schema.baseline_missing",
            extra={"path": str(baseline_file), "hint": "run `acp schemas capture`"},
        )
    return DriftDetector(baseline, known=known)


@asynccontextmanager
async def gateway_from_configs(
    upstreams: Sequence[UpstreamConfig],
    *,
    allowed_hosts: Sequence[str] = (),
    allowed_origins: Sequence[str] = (),
    probe_health: bool = False,
    probe_interval: float = DEFAULT_INTERVAL,
    detect_drift: bool = False,
    baseline_file: Path | None = None,
    validator: TokenValidator | None = None,
    resource: ProtectedResource | None = None,
    credentials: ExchangedCredentials | None = None,
    secrets: Mapping[str, str] | None = None,
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
    console: TraceHub | None = None,
    operator_validator: TokenValidator | None = None,
) -> AsyncIterator[Starlette]:
    """Build the ASGI app, and close every upstream pool on the way out.

    Clients are opened one at a time and closed in reverse, so a failure part-way
    through startup leaks no pool.
    """
    clients: list[Upstream] = []
    try:
        for config in upstreams:
            # Secrets are resolved at startup; `None` for upstreams that exchange.
            clients.append(
                await connect_upstream(config, credentials, (secrets or {}).get(config.name))
            )
        logger.info(
            "gateway.ready",
            extra={
                "upstream_count": len(clients),
                "upstreams": [c.config.name for c in clients],
            },
        )

        # Drift detection uses the health prober's fetch, so warn if probing is off.
        detector: DriftDetector | None = None
        if detect_drift and probe_health:
            detector = build_drift_detector(
                baseline_file or DEFAULT_BASELINE_PATH,
                [c.config.name for c in clients],
            )
        elif detect_drift:
            logger.warning("schema.drift_detection_inert", extra={"reason": "probing disabled"})

        def _watch_spend(payer: str, tool: str, cost: float) -> None:
            """Publish a budget draw to the console as `observed`, since the chain holds no totals.

            `payer` is decoded with `acp.budget.parties`, never split by hand.
            """
            if console is None:
                return
            tenant, subject = parties(payer)
            console.publish(
                observed(
                    "budget",
                    "budget.charged",
                    time.time(),
                    subject=subject,
                    tenant=tenant,
                    detail={"tool": tool, "cost": cost},
                )
            )

        def _watch_health(record: HealthRecord, previous: UpstreamHealth) -> None:
            """Publish a health change to the console as `observed`, not audited (ADR 0056)."""
            if console is None:
                return
            console.publish(
                observed(
                    "upstream",
                    "health.changed",
                    # Not `record.checked_at`, which is monotonic, not wall-clock.
                    time.time(),
                    upstream=record.upstream,
                    detail={
                        "state": str(record.state),
                        "previous": str(previous),
                        "tools": record.tool_count,
                        "error": record.error,
                    },
                )
            )

        monitor = (
            HealthMonitor(
                clients,
                interval=probe_interval,
                on_catalogue=detector.observe if detector else None,
                on_health=_watch_health,
            )
            if probe_health
            else None
        )
        if validator is None:
            # Each request then logs `principal: anonymous` (`acp.identity.asgi`).
            logger.warning(
                "auth.disabled",
                extra={"reason": "no identity provider configured", "principal": "anonymous"},
            )

        app = build_app(
            UpstreamRegistry(clients, monitor),
            allowed_hosts=allowed_hosts or ("127.0.0.1", "localhost"),
            allowed_origins=allowed_origins,
            validator=validator,
            resource=resource,
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
            charged=_watch_spend,
        )
        # Read by `acp serve` for the admin app. The probe loop is started there,
        # not here: a task started inside an async generator gets a cancel scope
        # in the wrong task.
        app.state.health = monitor
        app.state.schema_drift = detector
        app.state.approvals = approvals
        app.state.audit = audit
        # Operator-audience validator (ADR 0059); shares key caches with
        # `validator`, so it is never closed on its own.
        app.state.operator_validator = operator_validator
        # Built by the caller because `AuditLog` publishes to it; admin-side only.
        app.state.console = console
        yield app
    finally:
        # Reverse order; every close is attempted even if one raises.
        for client in reversed(clients):
            try:
                await client.aclose()
            except Exception:
                logger.exception(
                    "gateway.upstream_close_failed", extra={"upstream": client.config.name}
                )
        logger.info("gateway.stopped", extra={"upstream_count": len(clients)})


SAFETY_CONTROLS: Final = ("authentication", "audit", "firewall")
"""Controls whose absence the startup banner names at WARNING (ADR 0071)."""


def control_states(settings: GatewaySettings) -> dict[str, str]:
    """Every control and its state, from settings alone so it prints before building."""
    operator = (
        "jwt"
        if settings.approval_operator_audience
        else "shared-token"
        if settings.approval_operator_token
        else "off"
    )
    return {
        "authentication": "on" if settings.authentication_configured else "off",
        "audit": "on" if settings.audit_file is not None else "off",
        "audit_signing": (
            "on"
            if settings.audit_file is not None and settings.audit_signing_key_file is not None
            else "off"
        ),
        "firewall": settings.firewall_mode.value,
        "firewall_learned": (
            settings.firewall_learned.value
            if settings.firewall_mode is not FirewallMode.OFF
            else "off"
        ),
        "provenance_framing": "on" if settings.provenance_framing_enabled else "off",
        "rate_limit": "on" if settings.rate_limit_enabled else "off",
        "quota": "on" if settings.quota_enabled else "off",
        "cost_table": "on" if settings.cost_file is not None else "off",
        "result_cache": "on" if settings.cache_file is not None else "off",
        "approval_operator": operator,
        "approval_store": "redis" if settings.approval_store_shared else "memory",
        "budget_store": "redis" if settings.budget_store_shared else "memory",
    }


def report_controls(settings: GatewaySettings) -> dict[str, str]:
    """Log the control table at INFO, and any off safety control at WARNING (ADR 0071)."""
    states = control_states(settings)
    logger.info("gateway.controls", extra={"controls": states})
    off = [name for name in SAFETY_CONTROLS if states[name] == "off"]
    if off:
        logger.warning(
            "gateway.safety_controls_off",
            extra={
                "off": off,
                "consequence": "this gateway is running without " + ", ".join(off),
            },
        )
    return states


def build_audit_log(settings: GatewaySettings, console: TraceHub | None = None) -> AuditLog | None:
    """Open the audit chain, or return ``None`` when none is configured and not required.

    Running without a chain, or with one not required, logs a WARNING every start.

    Raises:
        ConfigurationError: If no file is set while required (ADR 0071).
    """
    if settings.audit_file is None:
        if settings.audit_required:
            # Fatal before a port is bound, like ACP_AUTH_REQUIRED (ADR 0071).
            msg = (
                "ACP_AUDIT_REQUIRED is set and ACP_AUDIT_FILE is not, so this "
                "gateway would serve every call without recording it. Set "
                "ACP_AUDIT_FILE to a path on a persistent volume. To run without "
                "an audit record on purpose, set ACP_AUDIT_REQUIRED=false."
            )
            raise ConfigurationError(msg)
        logger.warning(
            "audit.disabled",
            extra={
                "reason": "ACP_AUDIT_FILE is not set and ACP_AUDIT_REQUIRED is false",
                "consequence": "no record of authorization decisions is kept",
            },
        )
        return None

    signer = (
        load_signer(settings.audit_signing_key_file)
        if settings.audit_signing_key_file is not None
        else None
    )
    sink = FileAuditSink(settings.audit_file, fsync=settings.audit_fsync, signer=signer)

    if not settings.audit_required:
        logger.warning(
            "audit.not_required",
            extra={
                "reason": "ACP_AUDIT_REQUIRED is false",
                "consequence": (
                    "a call this gateway cannot record will proceed anyway, so the "
                    "chain may contain gaps that nothing in it can reveal — watch "
                    'acp_audit_writes_total{outcome="failed"}'
                ),
            },
        )

    logger.info(
        "audit.enabled",
        extra={
            "path": str(settings.audit_file),
            "entries": sink.length,
            "head": sink.head[:16],
            "required": settings.audit_required,
            "fsync": settings.audit_fsync,
            "signing_key": signer.kid if signer is not None else None,
        },
    )
    published = None
    if console is not None:
        # A closure so the audit module never imports the console. Publishes
        # `entry.record`, the redacted mapping, never the unredacted AuditRecord.
        def published(entry: Entry) -> None:
            console.publish(from_entry(entry.seq, entry.record))

    return AuditLog(sink, required=settings.audit_required, published=published)


def _gated_rule_names(policy: Policy | PolicySet) -> set[str]:
    """Names of rules in any tenant's policy that can hold a call; for logging only."""
    if isinstance(policy, Policy):
        return {r.name for r in policy.rules if r.effect is Effect.REQUIRE_APPROVAL}
    names = {r.name for r in policy.default.rules if r.effect is Effect.REQUIRE_APPROVAL}
    for tenant_policy in policy.tenants.values():
        names |= {r.name for r in tenant_policy.rules if r.effect is Effect.REQUIRE_APPROVAL}
    return names


def build_approval_store(
    settings: GatewaySettings, policy: Policy | PolicySet | None
) -> ApprovalStore | None:
    """An approval store when the policy can hold a call, else ``None``.

    Warns, without refusing, when no operator channel is configured, since another
    replica may answer via a shared store (ADR 0066). Redis when
    `ACP_APPROVAL_STORE_URL` is set, otherwise memory; the Redis store is returned
    unpinged and `gateway_from_settings` pings it.
    """
    if policy is None or not policy.gates_calls:
        return None

    if not (settings.approval_operator_token or settings.approval_operator_audience):
        logger.warning(
            "approval.no_operator_channel",
            extra={
                "reason": (
                    "neither ACP_APPROVAL_OPERATOR_AUDIENCE nor ACP_APPROVAL_OPERATOR_TOKEN is set"
                ),
                "consequence": (
                    "the policy holds calls for a human, and nothing on this gateway "
                    "can answer one: every gated call waits out its TTL and is then "
                    "refused"
                ),
            },
        )

    logger.info(
        "approval.enabled",
        extra={
            "gated_rules": sorted(_gated_rule_names(policy)),
            "ttl_seconds": settings.approval_ttl_seconds,
            "max_pending": None
            if settings.approval_store_shared
            else settings.approval_max_pending,
            "store": "redis" if settings.approval_store_shared else "memory",
            "operator_channel": bool(
                settings.approval_operator_token or settings.approval_operator_audience
            ),
            "operator_jwt": bool(settings.approval_operator_audience),
            "shared_token": bool(settings.approval_operator_token),
        },
    )
    if settings.approval_operator_token and not settings.approval_operator_audience:
        # A shared token is audited as operator `shared-token`, naming nobody.
        logger.warning(
            "approval.shared_token_only",
            extra={
                "consequence": (
                    "the audit row cannot name who approved; set "
                    "ACP_APPROVAL_OPERATOR_AUDIENCE so operators present a JWT"
                ),
            },
        )
    if settings.approval_store_shared:
        return RedisApprovalStore.from_url(settings.approval_store_url)
    return InMemoryApprovalStore(max_pending=settings.approval_max_pending)


def build_budgets(settings: GatewaySettings) -> RedisBudgets | None:
    """The shared Redis budget store, or ``None`` (ADR 0067).

    ``None`` when `ACP_BUDGET_STORE_URL` is empty (in-memory budgets are used) or
    when no budget is enabled. Returned unpinged; `gateway_from_settings` pings it.
    """
    if not settings.budget_store_shared:
        return None
    if not (settings.rate_limit_enabled or settings.quota_enabled):
        logger.warning(
            "budget.store_unused",
            extra={
                "reason": "ACP_BUDGET_STORE_URL is set and neither budget is enabled",
                "consequence": "nothing is charged; the store is not opened",
            },
        )
        return None
    logger.info(
        "budget.shared",
        extra={
            "rate_limit": settings.rate_limit_enabled,
            "quota": settings.quota_enabled,
        },
    )
    return RedisBudgets.from_url(
        settings.budget_store_url,
        capacity=settings.rate_limit_capacity if settings.rate_limit_enabled else None,
        refill_per_second=settings.rate_limit_refill_per_second,
        limit=settings.quota_limit if settings.quota_enabled else None,
        window_seconds=settings.quota_window_seconds,
    )


def build_firewall(settings: GatewaySettings) -> Firewall | None:
    """Assemble the injection firewall, or ``None`` when it is off.

    Warns when enforcing without provenance framing, since a document can then
    impersonate the unfenced refusal notice (ADR 0038), and when no allowed hosts
    are set, since every link and image is then reported (ADR 0039).
    """
    if settings.firewall_mode is FirewallMode.OFF:
        return None

    if settings.firewall_mode is FirewallMode.ENFORCE and not settings.provenance_framing_enabled:
        logger.warning(
            "firewall.enforcing_without_framing",
            extra={
                "reason": "ACP_PROVENANCE_FRAMING_ENABLED is not set",
                "consequence": (
                    "refused content is still withheld, but the refusal notice is "
                    "indistinguishable from upstream content, so a document can "
                    "impersonate one"
                ),
            },
        )
    if not settings.firewall_allowed_hosts:
        logger.warning(
            "firewall.every_link_reported",
            extra={
                "reason": "ACP_FIREWALL_ALLOWED_HOSTS is empty",
                "consequence": (
                    "every link and every image in every result is reported, because "
                    "with no hosts configured the detectors cannot tell an "
                    "exfiltration URL from a logo"
                ),
            },
        )

    classifier = _build_classifier(settings)
    # Loaded here, so a missing or corrupt model fails at startup, not on a call.
    learned = None if settings.firewall_learned is LearnedMode.OFF else load_model()
    enforceable = sorted(ENFORCEABLE)
    if settings.firewall_learned is LearnedMode.ENFORCE:
        enforceable.append("learned_classifier")

    logger.info(
        "firewall.enabled",
        extra={
            "mode": str(settings.firewall_mode),
            "allowed_hosts": list(settings.firewall_allowed_hosts),
            "enforceable_detectors": enforceable,
            "classifier": settings.firewall_classifier_enabled,
            "learned": str(settings.firewall_learned),
            "learned_thresholds": (
                {"report": learned.threshold, "enforce": learned.enforce_threshold}
                if learned is not None
                else None
            ),
        },
    )
    return firewall_for(
        settings.firewall_mode,
        allowed_hosts=frozenset(settings.firewall_allowed_hosts),
        classifier=classifier,
        learned=learned,
        learned_mode=settings.firewall_learned,
    )


def _build_classifier(settings: GatewaySettings) -> OllamaClassifier | None:
    """The model-based detector bound to the configured model and endpoint, else ``None``."""
    if not settings.firewall_classifier_enabled:
        return None

    def classify(document: str) -> str:
        return ollama_classify(
            document,
            model=settings.firewall_classifier_model,
            endpoint=settings.firewall_classifier_endpoint,
            timeout_seconds=settings.firewall_classifier_timeout_seconds,
        )

    return OllamaClassifier(classify_fn=classify)


async def build_token_validator(settings: GatewaySettings) -> TokenValidator | None:
    """Assemble token validation, or ``None`` when no provider is configured.

    Async because missing ``jwks_url`` values are discovered at startup, which
    checks the issuer-key binding (RFC 8414 §3.3). Symmetric algorithms are
    refused here too, before a port is bound.

    Raises:
        ConfigurationError: If ``auth_required`` and no provider is configured.
    """
    if not settings.authentication_configured:
        if settings.auth_required:
            # Enforced here, not in settings, so local commands like
            # `acp schemas capture` still run.
            msg = (
                "ACP_AUTH_REQUIRED is set and no identity provider is configured, "
                "so this gateway would serve every request as `anonymous`. Set "
                "ACP_AUTH_ISSUER and ACP_AUTH_AUDIENCE, or ACP_AUTH_ISSUERS_FILE "
                "for several servers. To run unauthenticated on purpose — a real "
                "mode, and a loud one — set ACP_AUTH_REQUIRED=false."
            )
            raise ConfigurationError(msg)
        return None

    for host in settings.auth_insecure_issuer_hosts:
        # Warned per host on every start so the escape hatch is never quiet (ADR 0018).
        logger.warning(
            "auth.plaintext_issuer_permitted",
            extra={
                "host": host,
                "reason": "named in ACP_AUTH_INSECURE_ISSUER_HOSTS",
                "consequence": (
                    "metadata and signing keys for this host are fetched over plain "
                    "HTTP and can be replaced in transit"
                ),
            },
        )

    documents = _issuer_documents(settings)
    resolved = [await _with_keys(document, settings) for document in documents]
    registrations = registry_from_documents(
        resolved,
        default_algorithms=settings.auth_algorithms,
        leeway=settings.auth_leeway,
        cache_ttl=settings.auth_jwks_cache_ttl,
        min_refresh_interval=settings.auth_jwks_min_refresh_interval,
        insecure_hosts=settings.auth_insecure_issuer_hosts,
    )
    registry = IssuerRegistry(registrations)

    logger.info(
        "auth.enabled",
        extra={
            "issuers": registry.issuers,
            "count": len(registry),
            "algorithms": list(settings.auth_algorithms),
        },
    )
    return TokenValidator(issuers=registry)


def build_operator_validator(
    settings: GatewaySettings, validator: TokenValidator | None
) -> TokenValidator | None:
    """The validator for operator JWTs, or ``None`` without an operator audience.

    Derived from the request validator with only the audience changed
    (`IssuerRegistry.for_audience`), so agent and operator tokens are not
    interchangeable and there is one set of trusted issuers.
    """
    audience = settings.approval_operator_audience
    if not audience or validator is None:
        return None
    logger.info(
        "approval.operator_jwt_enabled",
        extra={"audience": audience, "issuers": validator.issuers.issuers},
    )
    return TokenValidator(issuers=validator.issuers.for_audience(audience))


def build_protected_resource(
    settings: GatewaySettings, validator: TokenValidator | None
) -> ProtectedResource | None:
    """Assemble the RFC 9728 document from the registry's issuers, or ``None``.

    Never fatal, but warns when ``ACP_AUTH_RESOURCE`` is unset or is not one of
    the configured audiences.
    """
    if validator is None:
        # Unauthenticated; `auth.disabled` was already logged.
        return None

    if not settings.auth_resource:
        logger.warning(
            "auth.resource_metadata_disabled",
            extra={
                "reason": "ACP_AUTH_RESOURCE is not set",
                "consequence": (
                    "clients cannot discover this gateway's authorization servers "
                    "and must be configured with them by hand"
                ),
            },
        )
        return None

    resource = protected_resource(
        settings.auth_resource,
        authorization_servers=validator.issuers.issuers,
    )

    audiences = {registration.audience for registration in validator.issuers}
    if settings.auth_resource not in audiences:
        # Discovered tokens would be rejected for their `aud`. Only a warning, as
        # some servers name resources by opaque client ID.
        logger.warning(
            "auth.resource_audience_mismatch",
            extra={
                "resource": settings.auth_resource,
                "audiences": sorted(audiences),
                "consequence": (
                    "a client following the published metadata will request this "
                    "resource as its audience and receive a token this gateway rejects"
                ),
            },
        )

    logger.info(
        "auth.resource_metadata",
        extra={
            "resource": resource.resource,
            "metadata_url": resource.metadata_url,
            "authorization_servers": list(resource.authorization_servers),
        },
    )
    return resource


def build_token_exchanger(
    settings: GatewaySettings,
    validator: TokenValidator | None,
    upstreams: Sequence[UpstreamConfig] = (),
    audit: AuditLog | None = None,
) -> TokenExchanger | None:
    """Assemble RFC 8693 token exchange, or ``None`` without client credentials.

    Checks every issuer has a token endpoint at startup, not on first use.
    """
    if not settings.exchange_configured:
        return None
    if validator is None:  # pragma: no cover — config refuses this combination
        return None

    require_token_endpoints(validator.issuers, settings.auth_insecure_issuer_hosts)
    logger.info(
        "auth.exchange_enabled",
        extra={
            "client_id": settings.auth_client_id,
            "issuers": validator.issuers.issuers,
        },
    )
    return TokenExchanger(
        validator.issuers,
        client_id=settings.auth_client_id,
        client_secret=settings.auth_client_secret,
        # Every upstream audience, so a minted credential can be checked
        # against opening another upstream.
        peer_audiences=[u.audience for u in upstreams if u.audience],
        # Always cached (ADR 0022).
        cache=CredentialCache(max_entries=settings.auth_credential_cache_max_entries),
        # Minted credentials are audited beside the call that needed them.
        audit=audit,
    )


def build_secret_store(settings: GatewaySettings) -> SecretStore:
    """Open the encrypted store, or an ``EmptyStore`` so "no store" has its own error."""
    if not settings.secret_store_configured:
        return EmptyStore()

    # Narrowed for mypy; the property already proved both are set.
    secrets_file = settings.secrets_file
    key_file = settings.secret_key_file
    if secrets_file is None or key_file is None:  # pragma: no cover — see above
        return EmptyStore()

    return EncryptedFileStore.open(secrets_file, read_key(key_file))


async def resolve_upstream_secrets(
    upstreams: Sequence[UpstreamConfig], store: SecretStore
) -> dict[str, str]:
    """Resolve every referenced secret at startup, keyed by upstream name.

    A missing secret fails startup, and the request path never touches the store.
    """
    resolved: dict[str, str] = {}
    for config in upstreams:
        if config.credential_ref:
            resolved[config.name] = await store.get(config.credential_ref)
    if resolved:
        logger.info(
            "secrets.resolved",
            extra={"upstreams": sorted(resolved), "count": len(resolved)},
        )
    return resolved


def check_upstream_audiences(upstreams: Sequence[UpstreamConfig], *, exchanging: bool) -> None:
    """Refuse to start when exchange is on and an upstream has no credential route.

    Fatal, so no upstream is silently reached without a credential.
    """
    if not exchanging:
        return
    # Each upstream needs `audience` or `credential_ref`; config refuses both.
    missing = [u.name for u in upstreams if not u.audience and not u.credential_ref]
    if not missing:
        return
    msg = (
        f"token exchange is configured, but these upstreams are credentialed by "
        f"neither route: {', '.join(sorted(missing))}. Give each an `audience` to "
        f"mint a short-lived credential per call, or a `credential_ref` naming a "
        f"secret in the store for an upstream that cannot exchange."
    )
    raise ConfigurationError(msg)


def _issuer_documents(settings: GatewaySettings) -> list[dict[str, Any]]:
    """The configured authorization servers, from whichever source was used."""
    if settings.auth_issuers_file is not None:
        return load_issuers(settings.auth_issuers_file)
    return [
        {
            "issuer": settings.auth_issuer,
            "audience": settings.auth_audience,
            # Absent, not empty, when unset, so `_with_keys` discovers it.
            **({"jwks_url": settings.auth_jwks_url} if settings.auth_jwks_url else {}),
            **(
                {"token_endpoint": settings.auth_token_endpoint}
                if settings.auth_token_endpoint
                else {}
            ),
        }
    ]


async def _with_keys(document: dict[str, Any], settings: GatewaySettings) -> dict[str, Any]:
    """Fill in ``jwks_url`` by discovery when it was not configured by hand.

    An explicit URL skips the RFC 8414 §3.3 check, since some servers publish no
    metadata; that is logged as a warning.
    """
    if document.get("jwks_url"):
        logger.warning(
            "auth.jwks_url_unverified",
            extra={
                "issuer": document.get("issuer"),
                "reason": "explicit jwks_url skips the RFC 8414 issuer binding check",
            },
        )
        return document

    issuer = str(document.get("issuer") or "")
    metadata = await discover(
        issuer,
        request_timeout=settings.auth_discovery_timeout,
        insecure_hosts=settings.auth_insecure_issuer_hosts,
    )
    # The verified token endpoint too, unless one was configured explicitly.
    discovered = {"jwks_url": metadata.jwks_uri}
    if metadata.token_endpoint and not document.get("token_endpoint"):
        discovered["token_endpoint"] = metadata.token_endpoint
    return {**document, **discovered}


def check_costs_are_payable(costs: CostTable | None, settings: GatewaySettings) -> None:
    """Refuse a tool cost above the rate-limit capacity or quota limit.

    Such a tool could never be called, yet its refusal would report a finite
    `retry_after`.

    Raises:
        ConfigurationError: Naming the unaffordable tools.
    """
    if costs is None:
        return
    priced = {**costs.costs, "(default)": costs.default}
    if settings.rate_limit_enabled:
        over = sorted(t for t, c in priced.items() if c > settings.rate_limit_capacity)
        if over:
            msg = (
                f"cost table: {', '.join(over)} cost more than ACP_RATE_LIMIT_CAPACITY "
                f"({settings.rate_limit_capacity:g}), so no caller could ever afford them. "
                f"Raise the capacity or lower the cost."
            )
            raise ConfigurationError(msg)
    if settings.quota_enabled:
        over = sorted(t for t, c in priced.items() if c > settings.quota_limit)
        if over:
            msg = (
                f"cost table: {', '.join(over)} cost more than ACP_QUOTA_LIMIT "
                f"({settings.quota_limit:g}), so no caller could ever afford them in a "
                f"window. Raise the limit or lower the cost."
            )
            raise ConfigurationError(msg)


@asynccontextmanager
async def gateway_from_settings(settings: GatewaySettings) -> AsyncIterator[Starlette]:
    """Build the gateway described by ``settings``; all config is validated before connecting."""
    report_controls(settings)
    upstreams = load_upstreams(settings.upstreams_file)
    # Default policy plus one per declared tenant, all validated at startup.
    tenants = (
        tenant_labels(_issuer_documents(settings))
        if settings.authentication_configured
        else frozenset()
    )
    policy = load_policy_set(
        settings.policy_file,
        tenant_policy_dir=settings.tenant_policy_dir,
        tenants=tenants,
    )
    # With a shared store, no in-memory limiter or quota is built.
    budgets = build_budgets(settings)
    limiter = (
        RateLimiter(
            capacity=settings.rate_limit_capacity,
            refill_per_second=settings.rate_limit_refill_per_second,
        )
        if settings.rate_limit_enabled and budgets is None
        else None
    )
    costs = load_costs(settings.cost_file) if settings.cost_file is not None else None
    check_costs_are_payable(costs, settings)
    cacheable = load_cacheable(settings.cache_file) if settings.cache_file is not None else None
    # No cache unless some tool is cacheable; an empty table equals no table.
    results = ResultCache(max_entries=settings.result_cache_max_entries) if cacheable else None
    if cacheable is not None:
        logger.info(
            "gateway.result_cache_configured",
            extra={
                "tools": list(cacheable.names),
                "max_entries": settings.result_cache_max_entries,
            },
        )
    quota = (
        QuotaCounter(
            limit=settings.quota_limit,
            window_seconds=settings.quota_window_seconds,
        )
        if settings.quota_enabled and budgets is None
        else None
    )
    firewall = build_firewall(settings)
    approvals = build_approval_store(settings, policy)
    if isinstance(approvals, RedisApprovalStore):
        # Fail at startup rather than on the first gated call.
        await approvals.ping()
    if budgets is not None:
        await budgets.ping()
    # Always built (cheap when unwatched); `console_routes` decides reachability.
    console = TraceHub()
    # Before the exchanger, which is handed it.
    audit = build_audit_log(settings, console)
    validator = await build_token_validator(settings)
    exchanger = build_token_exchanger(settings, validator, upstreams, audit)
    check_upstream_audiences(upstreams, exchanging=exchanger is not None)

    store = build_secret_store(settings)
    secrets = await resolve_upstream_secrets(upstreams, store)
    try:
        async with gateway_from_configs(
            upstreams,
            probe_health=settings.health_probing_enabled,
            probe_interval=settings.health_probe_interval,
            detect_drift=settings.schema_drift_detection_enabled,
            baseline_file=settings.schema_baseline_file,
            # Adds `host:port`, as sent in Host on a non-default port.
            allowed_hosts=allowed_hosts_for(settings.allowed_hosts, settings.port),
            allowed_origins=settings.allowed_origins,
            validator=validator,
            resource=build_protected_resource(settings, validator),
            credentials=ExchangedCredentials(exchanger) if exchanger else None,
            secrets=secrets,
            policy=policy,
            limiter=limiter,
            costs=costs,
            quota=quota,
            budgets=budgets,
            cacheable=cacheable,
            results=results,
            provenance=settings.provenance_framing_enabled,
            firewall=firewall,
            approvals=approvals,
            approval_ttl=settings.approval_ttl_seconds,
            audit=audit,
            console=console,
            operator_validator=build_operator_validator(settings, validator),
        ) as app:
            yield app
    finally:
        # The secret store is closed with everything else this function opened.
        await store.aclose()
        if isinstance(approvals, RedisApprovalStore):
            await approvals.aclose()
        if budgets is not None:
            await budgets.aclose()
        if exchanger is not None:
            await exchanger.aclose()
        if validator is not None:
            await validator.issuers.aclose()
        if audit is not None:
            # Last, so anything the teardown above wanted to record still can.
            audit.close()
