"""Process lifecycle: building the gateway from config and taking it down cleanly.

Upstream clients own connection pools, and a pool that is never closed leaks
sockets until the process dies. So their lifetime is bound to a context manager
rather than left to garbage collection.

**On draining.** ``aclose`` closes idle connections and waits for in-flight
requests on that pool to finish. It does not stop *new* requests arriving —
that is the server's job, and uvicorn already does it: on ``SIGTERM`` it stops
accepting, lets in-flight requests complete, then returns from ``serve()``, at
which point this context manager's ``finally`` runs. The ordering matters and
is the reason the clients are managed *around* the server rather than inside
the ASGI app's own lifespan.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from starlette.applications import Starlette

from acp.approvals import DEFAULT_TTL_SECONDS, ApprovalStore, InMemoryApprovalStore
from acp.audit import AuditLog, FileAuditSink
from acp.budget import CostTable, QuotaCounter, RateLimiter, load_costs
from acp.config import GatewaySettings, allowed_hosts_for, load_issuers, load_upstreams
from acp.exceptions import ConfigurationError
from acp.firewall import Firewall, OllamaClassifier, firewall_for, ollama_classify
from acp.firewall.decision import ENFORCEABLE
from acp.firewall.decision import Mode as FirewallMode
from acp.gateway import UpstreamRegistry, build_app
from acp.health import DEFAULT_INTERVAL, HealthMonitor
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

    The only place in this project where a bad file on disk does *not* stop the
    process. Configuration failures are fatal by design — a gateway that starts
    with a broken policy has already failed open. A schema baseline is the other
    kind of thing: it is a monitor, and a monitor that can prevent the gateway
    from serving is a bigger risk than the one it exists to reduce. So a
    corrupt baseline is logged at ERROR and treated as no baseline, which
    reports every upstream as unbaselined — noisy, obvious, and not an outage.
    """
    try:
        baseline = SchemaSnapshot.load(baseline_file)
    except ConfigurationError as exc:
        logger.error(  # noqa: TRY400 — the traceback adds nothing; the message is the point
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
    cacheable: CacheableTools | None = None,
    results: ResultCache | None = None,
    provenance: bool = False,
    firewall: Firewall | None = None,
    approvals: ApprovalStore | None = None,
    approval_ttl: float = DEFAULT_TTL_SECONDS,
    audit: AuditLog | None = None,
) -> AsyncIterator[Starlette]:
    """Build the ASGI app, and close every upstream pool on the way out.

    Clients are created one at a time and torn down in reverse on failure, so a
    bad upstream part-way through startup does not leak the pools already
    opened before it.
    """
    clients: list[Upstream] = []
    try:
        for config in upstreams:
            # Resolved before this point, so a missing secret is a startup
            # failure rather than a request that reaches an upstream with no
            # credential. `None` for every upstream that exchanges instead.
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

        # Drift detection rides on the health prober's fetch (see
        # `acp.schema.detector`), so it needs one to ride on. Asking for it
        # without probing is a configuration that cannot do what it says, and
        # saying so beats silently detecting nothing.
        detector: DriftDetector | None = None
        if detect_drift and probe_health:
            detector = build_drift_detector(
                baseline_file or DEFAULT_BASELINE_PATH,
                [c.config.name for c in clients],
            )
        elif detect_drift:
            logger.warning("schema.drift_detection_inert", extra={"reason": "probing disabled"})

        monitor = (
            HealthMonitor(
                clients,
                interval=probe_interval,
                on_catalogue=detector.observe if detector else None,
            )
            if probe_health
            else None
        )
        if validator is None:
            # Said once, at startup, at WARNING. The other half of making this
            # impossible to miss is that every request then logs
            # `principal: anonymous` — see `acp.identity.asgi`.
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
            cacheable=cacheable,
            results=results,
            provenance=provenance,
            firewall=firewall,
            approvals=approvals,
            approval_ttl=approval_ttl,
            audit=audit,
        )
        # Attached rather than yielded, so the signature every existing caller
        # and test depends on is unchanged. The probe loop itself is started by
        # whoever owns a task group — deliberately not here: starting a
        # long-lived task inside an async generator puts its cancel scope in a
        # different task from the one that exits the generator, which is the
        # classic way to get a cancellation that fires in the wrong place.
        app.state.health = monitor
        app.state.schema_drift = detector
        # Read by `acp serve` to mount the operator channel on the admin
        # listener. Attached rather than returned for the same reason the other
        # two are: the signature every existing caller depends on is unchanged.
        app.state.approvals = approvals
        app.state.audit = audit
        yield app
    finally:
        # Reverse order, and every close attempted even if one raises — a
        # failure closing one pool must not strand the others open.
        for client in reversed(clients):
            try:
                await client.aclose()
            except Exception:
                logger.exception(
                    "gateway.upstream_close_failed", extra={"upstream": client.config.name}
                )
        logger.info("gateway.stopped", extra={"upstream_count": len(clients)})


def build_audit_log(settings: GatewaySettings) -> AuditLog | None:
    """Open the audit chain, or return ``None`` when none is configured.

    Presence-based on the path, like the secret store: a boolean would let a
    deployment believe it had an audit log because a flag said `true` while the
    path it needed was never set. There is deliberately no default path — an
    evidentiary artifact appearing in somebody's working directory the first time
    they run the gateway is one that gets gitignored, then forgotten.

    **The two states are both logged, and differently.** Running without a chain
    is a legitimate choice; running with one that is not required is a *third*
    state, and the one worth naming loudly, because it means the gateway will
    keep serving calls it cannot record. `ACP_AUDIT_REQUIRED=false` gets the same
    treatment `ACP_AUTH_REQUIRED=false` gets: a warning that says what the
    deployment has traded away, every single start.

    A failure to open is fatal. Every other configuration failure in this module
    is (a gateway that starts with a broken policy has already failed open), and
    an unopenable audit sink is the same class: the alternative is a process that
    serves without the record it was configured to keep.
    """
    if settings.audit_file is None:
        logger.info(
            "audit.disabled",
            extra={
                "reason": "ACP_AUDIT_FILE is not set",
                "consequence": "no tamper-evident record of authorization decisions is kept",
            },
        )
        return None

    sink = FileAuditSink(settings.audit_file, fsync=settings.audit_fsync)

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
        },
    )
    return AuditLog(sink, required=settings.audit_required)


def _gated_rule_names(policy: Policy | PolicySet) -> set[str]:
    """Every rule, in any tenant's policy, that can hold a call for a person.

    Duplicate names across tenants collapse in the set, which is correct for a
    startup log line and would be wrong for enforcement — enforcement never
    reads this; it selects one tenant's policy and reads that (task 58).
    """
    if isinstance(policy, Policy):
        return {r.name for r in policy.rules if r.effect is Effect.REQUIRE_APPROVAL}
    names = {r.name for r in policy.default.rules if r.effect is Effect.REQUIRE_APPROVAL}
    for tenant_policy in policy.tenants.values():
        names |= {r.name for r in tenant_policy.rules if r.effect is Effect.REQUIRE_APPROVAL}
    return names


def build_approval_store(
    settings: GatewaySettings, policy: Policy | PolicySet | None
) -> ApprovalStore | None:
    """A store when the policy can hold a call, and nothing when it cannot.

    Presence-based on the *policy* rather than on a flag, because the rule that
    holds a call is already the statement of intent — a second switch beside it
    could only ever be forgotten, and forgetting it means `require_approval`
    silently fails closed on every gated call at request time rather than at
    startup where somebody would see it.

    **The loud case is a policy that gates calls with no operator channel.** The
    gateway is then perfectly correct and completely useless: every gated call is
    held, nothing can ever answer it, and each caller waits out the TTL and is
    refused. That is a warning rather than a refusal to start, because a
    replicated deployment may legitimately answer approvals from a different
    process against a shared store — a real configuration this project's
    in-memory store cannot yet serve, and one that should not be pre-emptively
    banned. What it must not be is quiet.
    """
    if policy is None or not policy.gates_calls:
        return None

    if not settings.approval_operator_token:
        logger.warning(
            "approval.no_operator_channel",
            extra={
                "reason": "ACP_APPROVAL_OPERATOR_TOKEN is not set",
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
            "max_pending": settings.approval_max_pending,
            "operator_channel": bool(settings.approval_operator_token),
        },
    )
    return InMemoryApprovalStore(max_pending=settings.approval_max_pending)


def build_firewall(settings: GatewaySettings) -> Firewall | None:
    """Assemble the injection firewall, or ``None`` when it is switched off.

    Two things are said out loud here, because both are configurations that look
    like they are doing more than they are.

    **Enforcing without framing.** ADR 0038's interlock: the refusal notice is
    the gateway speaking, so it is deliberately *not* fenced — which means that
    with framing on, an unfenced block is by construction the gateway, and with
    framing off a hostile document can impersonate a refusal notice. The content
    is still withheld either way, so this is a warning rather than a refusal to
    start; a deployment can reasonably adopt the two controls in either order,
    but it should know which half it has.

    **Screening with no allowed hosts.** The URL and image detectors then report
    *every* link and every image in every document. Nothing is withheld either
    way — neither detector may withhold anything since the benign corpus demoted
    them (ADR 0039) — but the finding count becomes noise, and a finding count
    that is mostly noise is how a log stops being read.
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

    logger.info(
        "firewall.enabled",
        extra={
            "mode": str(settings.firewall_mode),
            "allowed_hosts": list(settings.firewall_allowed_hosts),
            "enforceable_detectors": sorted(ENFORCEABLE),
            "classifier": settings.firewall_classifier_enabled,
        },
    )
    return firewall_for(
        settings.firewall_mode,
        allowed_hosts=frozenset(settings.firewall_allowed_hosts),
        classifier=classifier,
    )


def _build_classifier(settings: GatewaySettings) -> OllamaClassifier | None:
    """The model-based detector when it is switched on, else ``None``.

    Off returns ``None`` rather than an inert classifier, so the screener's
    detector set does not grow a name for a detector that never runs. When on,
    the transport is bound to the configured model and endpoint; a failure to
    reach it at screening time is already handled as no-finding, so nothing is
    verified here beyond that the settings are wired to the call.
    """
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

    Note what is *not* here: a flag. Authentication is on when an identity
    provider is configured and off when one is not — see ``acp.config`` for why
    a boolean is the wrong control. Incoherent combinations are already a
    startup failure by this point, so reaching here with a half-configured
    provider is impossible.

    Async because a registration without an explicit ``jwks_url`` has to ask the
    authorization server for one, and that request is also where the binding
    between issuer and key set is checked (RFC 8414 §3.3). Doing it at startup
    rather than lazily is deliberate: an issuer whose metadata contradicts its
    own identity should stop a deployment, not surprise the first request.

    ``TokenPolicy`` refuses a symmetric algorithm in its constructor, so a
    configuration that would accept forged tokens fails here, before a port is
    bound.
    """
    if not settings.authentication_configured:
        if settings.auth_required:
            # Fatal, before a port is bound and before an upstream pool is
            # opened. Deliberately here rather than in the settings validator:
            # the claim is that this gateway must not *serve* unauthenticated,
            # and enforcing it at construction made `acp schemas capture` — a
            # local command with no connection to authentication — refuse to run.
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
        # One line per host, at WARNING, on every start. The whole justification
        # for having an escape hatch at all is that it cannot be used quietly —
        # see ADR 0018 for the two worse hatches this exists instead of.
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


def build_protected_resource(
    settings: GatewaySettings, validator: TokenValidator | None
) -> ProtectedResource | None:
    """Assemble the RFC 9728 document, or ``None`` when there is nothing to say.

    The authorization servers are not configured separately — they are the
    registry's issuers. Two lists that had to be kept in step would eventually
    not be, and the failure mode is a client sent to an authorization server
    this gateway does not actually trust, which looks from the client's side
    like its own token being inexplicably rejected.

    Nothing here is fatal on its own; a gateway with no metadata document
    authenticates exactly as strictly. What it must not do is be *silent* about
    either degraded case, because both produce a client that cannot log in for
    reasons visible only from here.
    """
    if validator is None:
        # Config already refuses a resource identifier with no issuer, so this
        # is the plain unauthenticated case. `auth.disabled` has been said.
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
        # Every step of discovery works and the last one fails: the client reads
        # this document, asks the authorization server for `resource=<this>`,
        # receives a token whose `aud` is `<this>`, and the gateway rejects it
        # for carrying the wrong audience. A warning rather than a refusal
        # because plenty of authorization servers identify a resource by an
        # opaque client ID rather than by its URL, and that is a legitimate
        # deployment — it simply requires the client to be told, which is the
        # thing this document was meant to stop being necessary.
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
    """Assemble RFC 8693 token exchange, or ``None`` when it is not configured.

    Presence-based like everything else in this module: client credentials are
    the switch, because a credential is not a thing you can forget to supply and
    still have the feature appear to work.

    ``require_token_endpoints`` runs here rather than on the first request, so
    an issuer that cannot be exchanged against stops a deployment instead of
    surprising whichever tenant happens to use it.
    """
    if not settings.exchange_configured:
        return None
    if validator is None:  # pragma: no cover — config refuses this combination
        return None

    require_token_endpoints(validator.issuers)
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
        # The whole estate, so a credential minted for one upstream can be
        # checked for opening another's door (task 28). Passed here rather than
        # discovered, because "which audiences are mine" is a fact about this
        # deployment's configuration and not about any token.
        peer_audiences=[u.audience for u in upstreams if u.audience],
        # Every deployment gets one. Task 27 minted per call and cached nothing,
        # which was correct while the key had not been argued over; ADR 0022 is
        # that argument.
        cache=CredentialCache(max_entries=settings.auth_credential_cache_max_entries),
        # So a minted credential appears in the chain beside the call that
        # needed it. Four categories, four emit points, one artifact.
        audit=audit,
    )


def build_secret_store(settings: GatewaySettings) -> SecretStore:
    """Open the encrypted store, or return one that is honestly empty.

    ``EmptyStore`` rather than ``None``, because "no store is configured" and "a
    store is configured and does not contain that" are different mistakes with
    different fixes, and a ``None`` here would collapse them into one branch that
    could only say "missing".
    """
    if not settings.secret_store_configured:
        return EmptyStore()

    # Narrowed for mypy: `secret_store_configured` already proved both are set,
    # but a property cannot tell the type checker that.
    secrets_file = settings.secrets_file
    key_file = settings.secret_key_file
    if secrets_file is None or key_file is None:  # pragma: no cover — see above
        return EmptyStore()

    return EncryptedFileStore.open(secrets_file, read_key(key_file))


async def resolve_upstream_secrets(
    upstreams: Sequence[UpstreamConfig], store: SecretStore
) -> dict[str, str]:
    """Look up every referenced secret now, so none is looked up later.

    At startup, before a port is bound, for the reason every other configuration
    check in this module runs there: an upstream whose credential is missing is
    one the gateway would otherwise reach with no credential at all, and it would
    discover that on somebody's first real request.

    It also means the request path holds a string rather than a store, which is
    what keeps a secrets backend from becoming a dependency of every tool call.
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
    """Refuse to start when exchange is on and an upstream has no audience.

    Fatal rather than a warning, and it is the one place in this file where that
    is worth arguing. The alternative is a gateway which mints scoped
    credentials for four upstreams and reaches the fifth with none — while every
    log line, every ADR and every README says the estate is credentialed. A
    control with a silent hole in it is worse than no control, because the hole
    is the only part nobody is watching.
    """
    if not exchanging:
        return
    # Two ways to be credentialed since task 29, and an upstream needs one of
    # them: it exchanges (`audience`) or it presents something stored
    # (`credential_ref`). The config model already refuses both at once.
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
            # Absent rather than empty when undiscovered, so `_with_keys` can
            # tell "not configured" from "configured as an empty string".
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

    An explicit URL is honoured and *not* checked against the issuer's metadata,
    which is a real gap and a deliberate one: some authorization servers publish
    no metadata at all, and refusing to talk to them would be a purity the
    deployment cannot act on. It is logged, because skipping the RFC 8414 §3.3
    check is a thing somebody should have decided rather than inherited.
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
    # The token endpoint comes along for free and carries the same proof: this
    # document has already been shown to belong to this issuer. An explicitly
    # configured one on the document wins, because somebody typed it on purpose.
    discovered = {"jwks_url": metadata.jwks_uri}
    if metadata.token_endpoint and not document.get("token_endpoint"):
        discovered["token_endpoint"] = metadata.token_endpoint
    return {**document, **discovered}


@asynccontextmanager
async def gateway_from_settings(settings: GatewaySettings) -> AsyncIterator[Starlette]:
    """Build the gateway described by ``settings``.

    Upstreams are read and validated *before* any connection is opened, so a
    malformed config fails without side effects.
    """
    upstreams = load_upstreams(settings.upstreams_file)
    # The whole set, not one file: the default policy plus one per declared
    # tenant, each validated at startup so a malformed or missing tenant policy
    # is a boot failure naming the tenant rather than a surprise on that
    # tenant's first request (task 58). With no tenant labels this collapses to
    # exactly the old single-policy behaviour.
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
    limiter = (
        RateLimiter(
            capacity=settings.rate_limit_capacity,
            refill_per_second=settings.rate_limit_refill_per_second,
        )
        if settings.rate_limit_enabled
        else None
    )
    costs = load_costs(settings.cost_file) if settings.cost_file is not None else None
    cacheable = load_cacheable(settings.cache_file) if settings.cache_file is not None else None
    # The cache is built only when something is actually cacheable. A table that
    # names no tools produces no cache at all, so "configured but empty" and
    # "not configured" are the same runtime shape rather than two paths that
    # have to stay in step.
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
        if settings.quota_enabled
        else None
    )
    firewall = build_firewall(settings)
    approvals = build_approval_store(settings, policy)
    # Before the exchanger, which is handed it.
    audit = build_audit_log(settings)
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
            # Expanded to include `host:port`, because that is what a client
            # actually sends in the Host header on a non-default port.
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
            cacheable=cacheable,
            results=results,
            provenance=settings.provenance_framing_enabled,
            firewall=firewall,
            approvals=approvals,
            approval_ttl=settings.approval_ttl_seconds,
            audit=audit,
        ) as app:
            yield app
    finally:
        # The key cache owns an HTTP connection pool, for the same reason the
        # upstream clients do and with the same consequence for leaking it.
        await store.aclose()
        if exchanger is not None:
            await exchanger.aclose()
        if validator is not None:
            await validator.issuers.aclose()
        if audit is not None:
            # Last, so anything the teardown above wanted to record still can.
            audit.close()
