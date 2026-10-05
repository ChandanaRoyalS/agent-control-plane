"""Configuration, loaded once at startup and never mutated.

Precedence: ``ACP_`` environment variables, then ``.env``, then defaults here;
upstreams and issuers come from YAML files. Every problem raises
``ConfigurationError`` before a port is bound, so the gateway never starts open.
Secrets are read from a mounted secrets directory, not YAML.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from acp.approvals.operator import MIN_OPERATOR_TOKEN_LENGTH
from acp.approvals.record import DEFAULT_TTL_SECONDS
from acp.approvals.store import DEFAULT_MAX_PENDING
from acp.exceptions import ConfigurationError
from acp.firewall.decision import LearnedMode
from acp.firewall.decision import Mode as FirewallMode
from acp.redis_url import check_redis_url
from acp.upstream import UpstreamConfig

DEFAULT_SECRETS_DIR = "/run/secrets"
"""Where container runtimes mount secrets as files; the environment is readable via ``/proc``."""


def _secrets_dir() -> str | None:
    """The secrets directory, or None when it does not exist.

    None avoids pydantic-settings' missing-directory warning on development
    machines without silencing it globally.
    """
    path = Path(os.environ.get("ACP_SECRETS_DIR", DEFAULT_SECRETS_DIR))
    return str(path) if path.is_dir() else None


class GatewaySettings(BaseSettings):
    """Process-level settings for the gateway."""

    model_config = SettingsConfigDict(
        env_prefix="ACP_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=_secrets_dir(),
        extra="forbid",
        frozen=True,
    )

    host: str = "127.0.0.1"
    """Interface to bind; loopback so exposure is a deliberate choice."""

    port: int = Field(default=8080, gt=0, le=65535)

    log_level: str = "INFO"

    log_format: str = "auto"
    """``json``, ``console``, or ``auto`` (console when stderr is a terminal, else JSON)."""

    admin_host: str = "127.0.0.1"
    """Interface for the admin listener; loopback, since metrics aid reconnaissance."""

    admin_port: int = Field(default=9090, gt=0, le=65535)

    admin_enabled: bool = True

    audit_file: Path | None = None
    """Where the hash-chained audit log is written.

    Unset refuses to start while `audit_required` is true (ADR 0071). No default
    path, so writing an audit log is always a deliberate choice.
    """

    audit_required: bool = True
    """Refuse a call this gateway cannot record, and refuse to start with no audit file.

    On by default (ADR 0071), since a silent gap in the log implies nothing
    happened. `false` serves without a record and is logged at every start.
    """

    audit_fsync: bool = True
    """`fsync` each entry before the call proceeds, so a crash loses no record; costs throughput."""

    audit_signing_key_file: Path | None = None
    """An Ed25519 private key that signs every audit entry (ADR 0078).

    Mount it as a secret, never under `config/` or in the image. Unset writes an
    unsigned chain, as before. One key signs one file: the gateway refuses to
    continue a file whose last entry was signed by another key, or not signed at
    all, so turning signing on or rotating the key starts a new `audit_file`.
    """

    approval_operator_token: str = ""
    """Shared-secret credential for the approval channel on the admin listener.

    Empty means the channel does not exist. Compared with `compare_digest`; if the
    admin port leaves loopback, keep it in the secret store.
    """

    approval_operator_audience: str = ""
    """Audience of an operator's JWT on the approval channel (ADR 0059).

    Verified like an agent token but for a distinct audience, so tool tokens cannot
    approve. The subject is audited and the tenant scopes what the operator may
    answer. Requires authentication; empty leaves only the shared token.
    """

    approval_ttl_seconds: float = Field(default=DEFAULT_TTL_SECONDS, gt=0)
    """Seconds a held call waits before expiry denies it (ADR 0048); a security window."""

    approval_max_pending: int = Field(default=DEFAULT_MAX_PENDING, gt=0)
    """Held requests kept before the oldest is evicted; bounds memory a caller can fill."""

    approval_store_url: str = ""
    """Redis for held approvals, shared by every replica (ADR 0066).

    Empty keeps them in process memory, correct only for a single gateway.
    Startup fails if the Redis is unreachable. The URL may hold a password, so use
    the secret store. With Redis, a per-record TTL replaces ``approval_max_pending``.
    """

    health_probing_enabled: bool = True
    """Background upstream probing; off, open breakers recover only via live traffic."""

    health_probe_interval: float = Field(default=15.0, gt=0)
    """Seconds between probe rounds, before jitter."""

    schema_drift_detection_enabled: bool = True
    """Compare each probed catalogue against the baseline; needs health probing on."""

    schema_baseline_file: Path = Path("config/schema-baseline.json")
    """The acknowledged state of every upstream's catalogue.

    Missing means not yet baselined. Unparseable is logged and treated as absent,
    unlike other config errors, because a monitor must not block startup.
    """

    upstreams_file: Path = Path("config/upstreams.yaml")
    """Upstream definitions, relative to the working directory."""

    policy_file: Path = Path("config/policy.yaml")
    """Policy rulebook (relative to cwd); missing or malformed is fatal (ADR 0025)."""

    tenant_policy_dir: Path | None = None
    """Directory of per-tenant policies, ``<dir>/<tenant>.yaml``.

    Required once any issuer declares a ``tenant``; a missing tenant file fails
    startup by name rather than silently denying everything.
    """

    rate_limit_enabled: bool = False
    """Enforce per-principal rate limiting; opt-in, so unconfigured behaviour is unchanged."""

    rate_limit_capacity: float = Field(default=60.0, gt=0)
    """Burst ceiling: back-to-back calls allowed, and the level the bucket refills to."""

    rate_limit_refill_per_second: float = Field(default=1.0, gt=0)
    """Sustained rate, in calls per second, at which a principal's bucket refills."""

    cost_file: Path | None = None
    """Per-tool cost table (``config/costs.yaml``) weighting budget draws; unset, each call is 1."""

    cache_file: Path | None = None
    """Cacheable-tools table (``config/cache.yaml``); unset caches nothing.

    Named tools' results are served to the same principal for their ttl. The file
    is the only switch, with no ``cache_enabled`` boolean (ADR 0035).
    """

    result_cache_max_entries: int = Field(default=512, gt=0)
    """Cache size bound; callers choose the keys, so unbounded would be a memory target."""

    provenance_framing_enabled: bool = False
    """Fence every tool result as retrieved data before the model reads it (ADR 0037).

    Off by default because it adds two content blocks to the wire.
    """

    firewall_mode: FirewallMode = FirewallMode.REPORT
    """How much the injection firewall may do (ADR 0038).

    ``off`` screens nothing; ``report`` screens and logs, logging what enforcement
    would withhold as ``would_refuse``, but changes nothing; ``enforce`` withholds.
    ``report`` is the default so the control runs and is measured (ADR 0071,
    ADR 0055).
    """

    firewall_allowed_hosts: list[str] = Field(default_factory=list)
    """Hosts a tool result may link to or embed images from.

    Empty is deliberately noisy: every link and image is reported, and
    ``external_image`` cannot withhold until this is set (ADR 0036).
    """

    firewall_learned: LearnedMode = LearnedMode.REPORT
    """What the learned injection classifier may do (ADR 0075, ADR 0076).

    ``report`` (the default) scores every result and logs a finding, HIGH where
    ``enforce`` would withhold. ``enforce`` lets that HIGH finding withhold, and
    only when ``firewall_mode`` is also ``enforce``: it withheld 2% of clean
    BIPIA test documents, so it is never on by default. ``off`` skips the cost
    (about a millisecond per thousand characters).
    """

    firewall_classifier_enabled: bool = False
    """Run the optional Ollama-based detector (ADR 0042).

    Off by default since it needs a local model. Adds MEDIUM findings; when the
    model is absent or slow it adds nothing, so screening never goes offline.
    """

    firewall_classifier_model: str = "llama3.2"
    """The Ollama model the classifier asks, when enabled."""

    firewall_classifier_endpoint: str = "http://127.0.0.1:11434/api/generate"
    """Where the local Ollama listens, when the classifier is enabled."""

    firewall_classifier_timeout_seconds: float = Field(default=5.0, gt=0)
    """Wait before treating the model as absent; tight so a slow model never slows results."""

    quota_enabled: bool = False
    """Enforce per-principal quotas; opt-in, so unconfigured behaviour is unchanged."""

    quota_limit: float = Field(default=10000.0, gt=0)
    """Most a principal may spend per window, in rate-limit cost units."""

    quota_window_seconds: float = Field(default=86400.0, gt=0)
    """Quota window in seconds; the tally resets at each boundary. Defaults to a day."""

    budget_store_url: str = ""
    """Redis for rate-limit buckets and quota tallies, shared by every replica (ADR 0067).

    Empty keeps them per process, so N replicas allow N times the budget. With
    Redis both budgets are checked and debited atomically; startup fails if it is
    unreachable. Independent of `approval_store_url`, though both may share a Redis.
    """

    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    """``Host`` values accepted, for DNS-rebinding protection.

    Defaults cover local development only; set it behind a real hostname, since
    the SDK rejects any unlisted ``Host``.
    """

    allowed_origins: list[str] = Field(default_factory=list)
    """Browser origins accepted. Empty is correct for non-browser clients."""

    # -- identity ----------------------------------------------------------
    # No `ACP_AUTH_ENABLED`: authentication is on exactly when a provider is
    # configured, so it cannot be forgotten open. Partial configuration fails startup.

    auth_issuer: str = ""
    """The authorization server's issuer URL. Must match the token's ``iss``."""

    auth_audience: str = ""
    """This gateway's identifier, checked against ``aud`` so other services' tokens fail."""

    auth_jwks_url: str = ""
    """Signing-key URL; better left empty.

    When empty it is discovered from issuer metadata, which verifies the
    issuer-key binding (RFC 8414 §3.3); setting it by hand skips that check.
    """

    auth_issuers_file: Path | None = None
    """YAML file of several authorization servers; exclusive with the single-issuer settings."""

    auth_resource: str = ""
    """This gateway's public resource identifier (RFC 9728), e.g. ``https://gw.corp/mcp``.

    Set, it serves ``/.well-known/oauth-protected-resource`` and adds
    ``resource_metadata`` to every 401 so clients can discover the issuer. Optional:
    validation does not depend on it, but startup reports its absence. It should
    equal the audience (RFC 8707); ``runtime`` warns on a mismatch.
    """

    auth_client_id: str = ""
    """The gateway's own OAuth client ID, used only for token exchange.

    Distinct from ``auth_audience``, which identifies the gateway as a resource
    server. Setting this and the secret is what enables exchange.
    """

    auth_client_secret: str = ""
    """The gateway's client secret; supply it via the secrets directory, not the environment."""

    auth_token_endpoint: str = ""
    """Token-exchange endpoint; normally empty and taken from verified issuer metadata.

    Only for a single issuer whose ``ACP_AUTH_JWKS_URL`` was set by hand. With an
    issuers file, set ``token_endpoint`` on the entry instead.
    """

    secrets_file: Path | None = None
    """Encrypted store for upstreams that cannot use token exchange (RFC 8693).

    Absent means no store; an upstream referencing a secret without one fails startup.
    """

    secret_key_file: Path | None = None
    """The key that opens ``secrets_file``, as a file from the runtime's secret mount.

    Refused at startup if readable beyond its owner, so set the mount mode
    (`defaultMode: 0400` / `mode: 0400`); Kubernetes and Docker default to readable.
    """

    auth_credential_cache_max_entries: int = Field(default=1024, gt=0)
    """Ceiling on cached exchanged credentials.

    Bounds memory a caller could fill with distinct tokens. No boolean disables
    the cache; set a tiny value for effectively per-request caching.
    """

    auth_required: bool = True
    """Refuse to serve without an identity provider (fails closed).

    An assertion that a provider is configured, not a switch that enables auth.
    ``ACP_AUTH_REQUIRED=false`` allows unauthenticated development. Enforced in
    ``build_token_validator``, not here, so local commands like ``acp schemas
    capture`` still load settings.
    """

    auth_insecure_issuer_hosts: list[str] = Field(default_factory=list)
    """Non-loopback hosts whose metadata and keys may use plain HTTP (ADR 0018).

    For a development provider such as ``http://keycloak:8080``; each entry is
    logged as a warning at every start. Loopback is already exempt.
    """

    auth_algorithms: list[str] = Field(
        default_factory=lambda: ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]
    )
    """Accepted signature algorithms, overridable per issuer.

    Asymmetric only; symmetric ones are refused at startup because JWKS keys are public.
    """

    auth_leeway: float = Field(default=60.0, ge=0)
    """Clock skew tolerated on ``exp``, ``nbf`` and ``iat``, in seconds."""

    auth_discovery_timeout: float = Field(default=5.0, gt=0)
    """Seconds to wait for issuer metadata at startup; short so a deploy never hangs."""

    auth_jwks_cache_ttl: float = Field(default=600.0, gt=0)

    auth_jwks_min_refresh_interval: float = Field(default=30.0, ge=0)
    """Floor between refetches on an unknown ``kid``, so tokens cannot amplify load on the IdP."""

    @property
    def authentication_configured(self) -> bool:
        return bool(self.auth_issuers_file or (self.auth_issuer and self.auth_audience))

    @property
    def budget_store_shared(self) -> bool:
        """Whether budgets are charged against a store every replica can reach."""
        return bool(self.budget_store_url)

    @property
    def approval_store_shared(self) -> bool:
        """Whether held approvals live in a store every replica can reach."""
        return bool(self.approval_store_url)

    @field_validator("approval_store_url")
    @classmethod
    def _approval_store_url_is_redis(cls, value: str) -> str:
        return check_redis_url("ACP_APPROVAL_STORE_URL", value)

    @field_validator("budget_store_url")
    @classmethod
    def _budget_store_url_is_redis(cls, value: str) -> str:
        return check_redis_url("ACP_BUDGET_STORE_URL", value)

    @property
    def secret_store_configured(self) -> bool:
        return self.secrets_file is not None and self.secret_key_file is not None

    @property
    def exchange_configured(self) -> bool:
        """Whether the gateway will mint per-upstream credentials."""
        return bool(self.auth_client_id and self.auth_client_secret)

    @model_validator(mode="after")
    def _operator_channel_is_coherent(self) -> GatewaySettings:
        """Check the operator credentials.

        An operator audience needs issuers and must differ from the gateway's audience;
        a set shared token must meet `MIN_OPERATOR_TOKEN_LENGTH`, to catch `changeme`.
        Both empty means no channel.
        """
        if self.approval_operator_audience and not (self.auth_issuer or self.auth_issuers_file):
            msg = (
                "ACP_APPROVAL_OPERATOR_AUDIENCE names an audience for operator tokens, but no "
                "authorization server is configured to verify them (ACP_AUTH_ISSUER or "
                "ACP_AUTH_ISSUERS_FILE). An audience nothing can check is not a credential."
            )
            raise ValueError(msg)
        if (
            self.approval_operator_audience
            and self.approval_operator_audience == self.auth_audience
        ):
            msg = (
                "ACP_APPROVAL_OPERATOR_AUDIENCE must differ from ACP_AUTH_AUDIENCE: with one "
                "audience, every agent token is also an operator token."
            )
            raise ValueError(msg)
        token = self.approval_operator_token
        if token and len(token) < MIN_OPERATOR_TOKEN_LENGTH:
            msg = (
                f"ACP_APPROVAL_OPERATOR_TOKEN is {len(token)} characters; a value this "
                f"short is guessable, and the floor is {MIN_OPERATOR_TOKEN_LENGTH}. "
                "Generate one with `python -c 'import secrets; print(secrets.token_urlsafe(32))'`."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _identity_settings_are_coherent(self) -> GatewaySettings:
        """Refuse identity settings that would authenticate differently than they read."""
        single = {
            "ACP_AUTH_ISSUER": self.auth_issuer,
            "ACP_AUTH_AUDIENCE": self.auth_audience,
        }
        if self.auth_issuers_file and any(single.values()):
            msg = (
                "ACP_AUTH_ISSUERS_FILE and the single-issuer settings are mutually "
                f"exclusive; also set {', '.join(sorted(n for n, v in single.items() if v))}. "
                "Two sources disagreeing about which authorization servers are trusted "
                "is not a merge to be resolved."
            )
            raise ValueError(msg)

        if self.auth_issuers_file and self.auth_jwks_url:
            msg = (
                "ACP_AUTH_JWKS_URL applies to the single-issuer settings only; "
                "per-issuer key sets belong in ACP_AUTH_ISSUERS_FILE."
            )
            raise ValueError(msg)

        missing = [name for name, value in single.items() if not value]
        if missing and len(missing) != len(single):
            msg = (
                "ACP_AUTH_ISSUER and ACP_AUTH_AUDIENCE are all-or-nothing; "
                f"missing {', '.join(sorted(missing))}. Set both to authenticate "
                "against one server, ACP_AUTH_ISSUERS_FILE for several, or none "
                "to run unauthenticated."
            )
            raise ValueError(msg)

        if self.auth_jwks_url and not self.auth_issuer:
            msg = "ACP_AUTH_JWKS_URL was set without ACP_AUTH_ISSUER, so it names keys for nobody"
            raise ValueError(msg)

        pair = {
            "ACP_AUTH_CLIENT_ID": self.auth_client_id,
            "ACP_AUTH_CLIENT_SECRET": self.auth_client_secret,
        }
        absent = [name for name, value in pair.items() if not value]
        if absent and len(absent) != len(pair):
            # Half a client credential would silently disable exchange.
            msg = (
                "ACP_AUTH_CLIENT_ID and ACP_AUTH_CLIENT_SECRET are all-or-nothing; "
                f"missing {', '.join(sorted(absent))}. Both together enable RFC 8693 "
                "token exchange; neither leaves upstream calls uncredentialed."
            )
            raise ValueError(msg)

        if self.exchange_configured and not self.authentication_configured:
            msg = (
                "token exchange is configured but no identity provider is. There is "
                "no inbound token to exchange, so every call would reach its upstream "
                "with no credential. Set ACP_AUTH_ISSUER and ACP_AUTH_AUDIENCE, or "
                "ACP_AUTH_ISSUERS_FILE."
            )
            raise ValueError(msg)

        if self.auth_token_endpoint and not self.auth_issuer:
            msg = (
                "ACP_AUTH_TOKEN_ENDPOINT applies to the single-issuer settings only; "
                "per-issuer endpoints belong in ACP_AUTH_ISSUERS_FILE."
            )
            raise ValueError(msg)

        store = {
            "ACP_SECRETS_FILE": self.secrets_file,
            "ACP_SECRET_KEY_FILE": self.secret_key_file,
        }
        half = [name for name, value in store.items() if value is None]
        if half and len(half) != len(store):
            msg = (
                "ACP_SECRETS_FILE and ACP_SECRET_KEY_FILE are all-or-nothing; "
                f"missing {', '.join(sorted(half))}. An encrypted store with no key "
                "cannot be opened, and a key with no store opens nothing."
            )
            raise ValueError(msg)

        if self.auth_resource and not self.authentication_configured:
            # With no authorization servers, the metadata would be a dead end.
            msg = (
                "ACP_AUTH_RESOURCE names a resource no client can obtain a token for, "
                "because no authorization server is configured. Set ACP_AUTH_ISSUER "
                "and ACP_AUTH_AUDIENCE, or ACP_AUTH_ISSUERS_FILE."
            )
            raise ValueError(msg)
        return self


def allowed_hosts_for(hosts: list[str], port: int) -> list[str]:
    """Add ``host:port`` for each bare host, since ``Host`` carries non-default ports.

    Without it the SDK answers 421. Entries that already have a port are kept as is.
    """
    expanded: list[str] = []

    def add(value: str) -> None:
        # Order-preserving dedup, so applying this twice is a no-op.
        if value not in expanded:
            expanded.append(value)

    for host in hosts:
        add(host)
        if ":" not in host:
            add(f"{host}:{port}")
    return expanded


def load_upstreams(path: Path) -> list[UpstreamConfig]:
    """Read and validate the upstream definitions.

    Raises:
        ConfigurationError: Naming the file and, where possible, the entry.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read upstreams file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"upstreams file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc

    if document is None:
        msg = f"upstreams file {str(path)!r} is empty"
        raise ConfigurationError(msg)
    if not isinstance(document, dict) or "upstreams" not in document:
        msg = f"upstreams file {str(path)!r} must be a mapping with an `upstreams` key"
        raise ConfigurationError(msg)

    entries = document["upstreams"]
    if not isinstance(entries, list):
        msg = f"`upstreams` in {str(path)!r} must be a list"
        raise ConfigurationError(msg)

    configs: list[UpstreamConfig] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            msg = (
                f"upstream #{index} in {str(path)!r} must be a mapping, got {type(entry).__name__}"
            )
            raise ConfigurationError(msg)
        try:
            configs.append(UpstreamConfig.model_validate(entry))
        except ValidationError as exc:
            label = entry.get("name", f"#{index}")
            msg = f"upstream {label!r} in {str(path)!r} is invalid: {exc}"
            raise ConfigurationError(msg) from exc

    _reject_duplicate_names(configs, path)
    return configs


def _reject_duplicate_names(configs: list[UpstreamConfig], path: Path) -> None:
    """Reject duplicate upstream names, which make qualified tool names ambiguous (ADR 0003)."""
    seen: set[str] = set()
    for config in configs:
        if config.name in seen:
            msg = (
                f"upstream name {config.name!r} appears more than once in {str(path)!r}; "
                f"names must be unique because tool qualification depends on them"
            )
            raise ConfigurationError(msg)
        seen.add(config.name)


def load_issuers(path: Path) -> list[dict[str, Any]]:
    """Read the authorization servers this gateway will accept tokens from.

    Returns plain documents, since `jwks_url` discovery is async and happens later.

    Raises:
        ConfigurationError: Naming the file and, where possible, the entry.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read issuers file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"issuers file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc

    if not isinstance(document, dict) or "issuers" not in document:
        msg = f"issuers file {str(path)!r} must be a mapping with an `issuers` key"
        raise ConfigurationError(msg)

    entries = document["issuers"]
    if not isinstance(entries, list) or not entries:
        msg = f"`issuers` in {str(path)!r} must be a non-empty list"
        raise ConfigurationError(msg)

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            msg = f"issuer #{index} in {str(path)!r} must be a mapping, got {type(entry).__name__}"
            raise ConfigurationError(msg)

    documents: list[dict[str, Any]] = list(entries)
    return documents


def load_settings(**overrides: Any) -> GatewaySettings:
    """Build settings from the environment, failing loudly on bad values."""
    try:
        return GatewaySettings(**overrides)
    except ValidationError as exc:
        msg = f"invalid gateway configuration: {exc}"
        raise ConfigurationError(msg) from exc
