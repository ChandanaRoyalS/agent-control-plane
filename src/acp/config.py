"""Configuration, loaded once at startup and never mutated.

Three sources, in decreasing precedence: environment variables prefixed
``ACP_``, a ``.env`` file for local development, and defaults declared here.
Upstreams come from a separate YAML file because a list of servers with
per-server timeouts does not fit comfortably in flat environment variables.

**Everything here fails fast.** A malformed config, an unreadable upstreams
file, two upstreams sharing a name — all of it raises ``ConfigurationError``
before the server binds a port. That is deliberate: a gateway that starts with
a broken policy or a missing credential and discovers it on the first request
has already failed open, which for a security control is the worst possible
outcome. Refusing to start is the safe direction.

**No secrets in the YAML.** Secret-shaped values are read from a directory of
files, the convention container runtimes actually use — Docker and Kubernetes
both mount secrets as files rather than environment variables, because the
environment of a process is readable by anything that can see ``/proc``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from acp.exceptions import ConfigurationError
from acp.firewall.decision import Mode as FirewallMode
from acp.upstream import UpstreamConfig

DEFAULT_SECRETS_DIR = "/run/secrets"
"""Where container runtimes mount secrets.

Docker and Kubernetes both mount secrets as files rather than environment
variables, because a process's environment is readable by anything that can see
``/proc``.
"""


def _secrets_dir() -> str | None:
    """The secrets directory, or None when it does not exist.

    Returning None rather than a missing path is deliberate: pydantic-settings
    emits a ``UserWarning`` for a non-existent secrets directory, and this
    project runs tests with warnings escalated to errors. A development machine
    legitimately has no ``/run/secrets``, so warning about it is noise — but
    silencing the warning globally would also hide a *misconfigured* secrets
    path in production, which is exactly the case worth hearing about.
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
    """Interface to bind. Defaults to loopback: a gateway that binds every
    interface by accident is exposed before anyone decides it should be."""

    port: int = Field(default=8080, gt=0, le=65535)

    log_level: str = "INFO"

    log_format: str = "auto"
    """``json``, ``console``, or ``auto`` to pick by whether stderr is a
    terminal. Production gets JSON without anyone having to remember to ask for
    it, and a developer at a terminal gets something readable."""

    admin_host: str = "127.0.0.1"
    """Interface for the metrics and health listener.

    Loopback by default, and deliberately a *separate* listener from the
    gateway. A scrape endpoint publishes every upstream name, every tool name
    and which dependencies are currently failing — a reconnaissance report for
    anyone choosing what to attack. Exposing it beyond the host should be a
    deliberate act, not the default.
    """

    admin_port: int = Field(default=9090, gt=0, le=65535)

    admin_enabled: bool = True

    health_probing_enabled: bool = True
    """Background probing of upstream health.

    Off means the gateway behaves exactly as it did before task 18: every
    upstream is attempted on every request, and a breaker recovers only when
    some agent's request happens to become its trial call.
    """

    health_probe_interval: float = Field(default=15.0, gt=0)
    """Seconds between probe rounds, before jitter."""

    schema_drift_detection_enabled: bool = True
    """Compare each probed catalogue against the committed baseline (task 20).

    Detection rides on the health prober, so this does nothing when
    ``health_probing_enabled`` is off — see ``acp.schema.detector`` for why that
    is the right place for it rather than the request path.
    """

    schema_baseline_file: Path = Path("config/schema-baseline.json")
    """The acknowledged state of every upstream's catalogue.

    A missing file is not an error: it means nothing has been baselined yet, and
    the gateway says so once per upstream rather than refusing to start. A file
    that exists and cannot be parsed is logged loudly and treated as absent —
    deliberately unlike every other configuration failure in this module, which
    are fatal. A drift detector is a monitor, and a monitor that can stop the
    gateway from starting is a larger risk than the one it was added to reduce.
    """

    upstreams_file: Path = Path("config/upstreams.yaml")
    """Path to the upstream definitions, resolved relative to the process's
    working directory."""

    policy_file: Path = Path("config/policy.yaml")

    rate_limit_enabled: bool = False
    """Whether per-principal rate limiting is enforced. Off by default, opt-in
    like policy: a gateway with no budget configured behaves exactly as before."""

    rate_limit_capacity: float = Field(default=60.0, gt=0)
    """The burst ceiling: the most calls a principal may make back-to-back before
    the sustained rate applies. Also the value the bucket refills toward."""

    rate_limit_refill_per_second: float = Field(default=1.0, gt=0)
    """The sustained rate, in calls per second, at which a principal's budget
    refills once the burst is spent."""

    cost_file: Path | None = None
    """Optional path to a per-tool cost table (``config/costs.yaml``). When set,
    a call's budget draw is weighted by the tool's cost; unset, every call costs
    one, exactly as rate limiting alone behaves."""

    cache_file: Path | None = None
    """Optional path to the cacheable-tools table (``config/cache.yaml``).

    When set, results of the tools it names may be served from memory to the
    *same principal* for the ttl it gives. Unset, nothing is cached and every
    call reaches its upstream, exactly as before.

    There is deliberately no ``cache_enabled`` boolean. Caching is on for the
    tools the file names and off for everything else, so the file *is* the
    switch — a boolean would be a second place for the answer to live, and the
    failure mode of forgetting one is a tool cached that nobody meant to cache
    (ADR 0035).
    """

    result_cache_max_entries: int = Field(default=512, gt=0)
    """How many results to hold. A security limit before a memory one: an
    authenticated caller chooses the keys, so an unbounded cache is a memory
    target rather than a cache."""

    provenance_framing_enabled: bool = False
    """Whether every tool result is fenced as retrieved data before the model
    reads it (task 46, ADR 0037).

    Off by default because it is a visible change to the wire — a caller
    receives two more content blocks than the upstream sent — and a deployment
    should turn that on deliberately rather than discover it.

    It is the half of the firewall with no false-positive rate: framing judges
    nothing, so it cannot be wrong about a document. What it costs is two blocks
    and a little of the model's context; what it buys is that a retrieved
    paragraph no longer arrives looking like something the user said.
    """

    firewall_mode: FirewallMode = FirewallMode.OFF
    """How much the injection firewall is allowed to do (task 47, ADR 0038).

    ``off`` screens nothing. ``report`` screens every tool result, logs every
    finding, and changes nothing the caller receives. ``enforce`` withholds
    content that crosses the bar.

    **Start at ``report``.** It is not a timid setting, it is the measuring
    instrument: it evaluates the same bar enforcement would and logs a result it
    *would* have withheld as ``would_refuse``, so a deployment learns what
    enforcement would cost its own traffic before paying it. A firewall that
    refuses honest documents does not get tuned, it gets set back to ``off``.

    ``off`` is the default because screening is linear in the size of every
    result and a control that turns itself on is a control nobody chose.
    """

    firewall_allowed_hosts: list[str] = Field(default_factory=list)
    """Hosts a tool result may legitimately link to or embed an image from.

    Empty is the *noisy* default on purpose (ADR 0036): with no hosts
    configured every markdown image and every link is reported. That is visible
    in the numbers, where the opposite default would look clean while detecting
    less — and it is why ``external_image`` cannot withhold anything until this
    list is set. Enforcing on the empty default would refuse a wiki page for
    having a logo in it.
    """

    firewall_classifier_enabled: bool = False
    """Whether the optional model-based detector runs (task 51, ADR 0042).

    Off by default: it needs a local Ollama, it is slower than every pattern, and
    a firewall that silently depends on a model service is one that breaks in a
    way nobody configured. When on, it adds findings at MEDIUM alongside the
    patterns; when the model is absent or slow it adds nothing, so enabling it
    cannot take screening offline — only make it quieter than intended."""

    firewall_classifier_model: str = "llama3.2"
    """The Ollama model the classifier asks. Only consulted when the classifier
    is enabled."""

    firewall_classifier_endpoint: str = "http://127.0.0.1:11434/api/generate"
    """Where the local Ollama listens. Only consulted when the classifier is
    enabled."""

    firewall_classifier_timeout_seconds: float = Field(default=5.0, gt=0)
    """How long to wait for the model before treating it as absent. Tight on
    purpose: a slow model must degrade to no-finding the same way a down one
    does, rather than slowing every screened result."""

    quota_enabled: bool = False
    """Whether per-principal quotas are enforced. Off by default, opt-in like
    rate limiting: a gateway with no quota configured behaves exactly as before."""

    quota_limit: float = Field(default=10000.0, gt=0)
    """The most a principal may spend within one window, in the same cost units
    as rate limiting (one per call unless a cost table weights it)."""

    quota_window_seconds: float = Field(default=86400.0, gt=0)
    """The window length in seconds over which ``quota_limit`` applies; the tally
    resets at each window boundary. Defaults to a day."""
    """Path to the policy rulebook (task 32), resolved relative to the
    process's working directory.

    Loaded and validated at startup in task 33; task 32 only defines the
    setting and the schema it points at. A missing or malformed policy is a
    boot failure, unlike the schema-baseline file above — policy is the
    control, not a monitor of one, so its absence is fatal rather than
    tolerated. See ADR 0025."""

    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    """Hosts the inbound server will accept, for DNS-rebinding protection.

    Deployment behind a real hostname must set this — the defaults only cover
    local development, and the SDK rejects any ``Host`` not listed. Discovered
    the hard way in task 9: the SDK's own allow-list has no default at all, so
    an unconfigured server rejects every request including from localhost.
    """

    allowed_origins: list[str] = Field(default_factory=list)
    """Browser origins accepted. Empty is correct for non-browser clients."""

    # -- identity (Phase 2) ------------------------------------------------
    #
    # There is deliberately no `ACP_AUTH_ENABLED`. Authentication is on when an
    # identity provider is configured and off when one is not, because a boolean
    # is a thing somebody forgets to set — and the failure mode of forgetting is
    # a gateway that accepts every request while its configuration says it
    # authenticates them. Presence of configuration cannot be forgotten in that
    # direction: you cannot validate tokens without an issuer.
    #
    # Setting *some* of these and not the others is a startup failure. Half
    # configured authentication that silently does nothing is the worst of the
    # three possible states.

    auth_issuer: str = ""
    """The authorization server's issuer URL. Must match the token's ``iss``."""

    auth_audience: str = ""
    """This gateway's identifier, checked against the token's ``aud``.

    Not optional when authentication is on. A token minted for another service
    in the estate is correctly signed and unexpired, and accepting it would let
    anything that can obtain *any* token act through this gateway.
    """

    auth_jwks_url: str = ""
    """Where the authorization server publishes its signing keys.

    **Optional, and better left empty.** When absent it is discovered from the
    issuer's metadata, and discovery is where the binding between an issuer and
    its keys is *verified* rather than asserted: RFC 8414 §3.3 requires the
    metadata to name the same issuer the document was fetched for. Setting this
    by hand skips that check, which is exactly how a key set belonging to one
    authorization server ends up trusted for another — a mix-up achieved by
    copy-paste rather than by an attacker.
    """

    auth_issuers_file: Path | None = None
    """Path to a YAML file registering several authorization servers.

    A file rather than more environment variables, for the same reason the
    upstreams are one: a list of servers each with its own audience, key set and
    algorithms does not fit flat `KEY=value` pairs without inventing an indexing
    convention nobody can read.

    Mutually exclusive with the single-issuer settings above. Two sources
    disagreeing about which servers are trusted is not a merge to be resolved.
    """

    auth_resource: str = ""
    """This gateway's public resource identifier, published under RFC 9728.

    The URL an agent actually reaches this gateway on — ``https://gw.corp/mcp``,
    not the interface it binds — because it is a public identifier and the two
    are only the same on a laptop. Setting it makes the gateway serve
    ``/.well-known/oauth-protected-resource`` and add ``resource_metadata`` to
    every 401, which together let a client that has never been configured for
    this deployment find its way to a token.

    **Optional, and its absence is a missing convenience rather than a missing
    control.** Nothing about *validating* a token depends on this; a gateway
    without it authenticates exactly as strictly, and clients simply have to be
    told the authorization server by hand. So it is not part of the
    all-or-nothing rule below — but startup does say when it is missing, because
    "clients cannot discover us" should be a state somebody chose.

    It should equal the audience tokens for this gateway carry: a client passes
    this string as RFC 8707's ``resource`` parameter, the authorization server
    copies it into ``aud``, and task 22 checks it. ``runtime`` warns when the
    configured audiences do not include it, because that mismatch produces a
    discovery chain where every step works and the last one fails.
    """

    auth_client_id: str = ""
    """The gateway's own client at the authorization server (task 27).

    Two identities are in play once exchange exists and they are easy to
    conflate. ``auth_audience`` is what the gateway is *called* by tokens
    arriving at it — it is a resource server there. This is who the gateway
    *is* when it asks for a credential, as an OAuth client. Nothing before task
    27 needed the second, because a resource server never speaks to a token
    endpoint.

    Setting this and its secret is what turns exchange on. As everywhere else in
    this module there is no boolean: presence of credentials is the switch,
    because a credential is a thing you cannot forget to supply and still have
    the feature appear to work.
    """

    auth_client_secret: str = ""
    """The gateway's client secret.

    Read from the secrets *directory* in any real deployment — a file at
    ``/run/secrets/auth_client_secret`` — rather than the environment, for the
    reason stated at the top of this module: a process's environment is readable
    by anything that can see ``/proc``, and this is the one value here that is
    genuinely a credential.
    """

    auth_token_endpoint: str = ""
    """Where to exchange tokens, when it cannot be discovered.

    **Normally empty.** It comes from the issuer's metadata, which has already
    been proved to belong to that issuer (RFC 8414 §3.3), so an endpoint read
    from it inherits that proof. This exists only for the single-issuer case
    where ``ACP_AUTH_JWKS_URL`` was set by hand and discovery therefore never
    ran. With an issuers file, put ``token_endpoint`` on the entry that needs it.
    """

    secrets_file: Path | None = None
    """The encrypted secret store (task 29).

    Holds credentials for upstreams that cannot take part in token exchange —
    an API key issued out of band, an appliance that will never speak RFC 8693.
    Everything that *can* exchange should, because a credential minted per call
    and thrown away is not a secret anybody has to store.

    Absent means no store, which is the right state for a deployment where every
    upstream exchanges. An upstream referencing a secret with no store
    configured is a startup failure.
    """

    secret_key_file: Path | None = None
    """The one key that opens ``secrets_file``.

    Its own file, referenced by path, so it can come from wherever a runtime
    puts secrets — a Kubernetes secret mount, a Docker secret, a tmpfs populated
    at boot — rather than from somewhere a person edits. The store's honest
    claim is that it turned many secrets into one; this is the one.

    Refused at startup if readable beyond its owner.
    """

    auth_credential_cache_max_entries: int = Field(default=1024, gt=0)
    """Ceiling on cached exchanged credentials (task 30).

    A security limit before it is a memory one. Unbounded, this grows with every
    distinct (token, upstream) pair the gateway has seen — which an
    authenticated caller with a token mint can drive in a loop. A bound turns
    that into eviction of somebody else's entry, costing an exchange rather than
    the process.

    Set to a very small number to make caching effectively per-request; there is
    deliberately no boolean to turn it off, because a cache that can be disabled
    by configuration is one where "is it on?" becomes a question during an
    incident.
    """

    auth_required: bool = True
    """Refuse to start without an identity provider.

    Read the polarity carefully, because this is the boolean the identity
    settings were designed to avoid and it is the opposite one.

    ``ACP_AUTH_ENABLED=false`` would fail **open** when somebody forgot it: a
    gateway serving every request while its configuration claimed it
    authenticated them. This fails **closed**. It is not a switch that turns
    authentication on — nothing here can do that, only configuring a provider
    can. It is an *assertion* that one is configured, and the failure mode of
    forgetting to set it is a gateway that refuses to start.

    Default ``True``, which is a behaviour change: every task before 26 ran
    unauthenticated with a warning, because there was no identity provider to
    run against and refusing would have meant the gateway could not run at all.
    Task 26 put Keycloak in Compose, so that excuse expired. Development still
    gets the old behaviour by saying so out loud with
    ``ACP_AUTH_REQUIRED=false``, which is a sentence somebody has to write.

    **Enforced where the gateway starts serving, not here.** The first version
    of this checked in the settings validator, which made it impossible to
    construct a ``GatewaySettings`` at all without an identity provider — and
    that broke ``acp schemas capture``, a local command that reads upstream
    catalogues and has nothing whatever to do with authentication. The claim
    being made is "this gateway must not *serve* unauthenticated", so it belongs
    in ``build_token_validator``, where serving is about to happen. A rule
    enforced further out than its own scope stops being a security property and
    starts being an obstacle, which is how fail-closed controls get switched off.
    """

    auth_insecure_issuer_hosts: list[str] = Field(default_factory=list)
    """Hosts whose metadata and key sets may be fetched over plain HTTP.

    Empty by default. Loopback is already exempt without this — traffic that
    never leaves the machine has no in-flight to be rewritten in — so this
    exists for exactly one case: a development identity provider reachable from
    another container by service name, where the URL is ``http://keycloak:8080``
    and neither TLS nor loopback applies.

    The escape hatch is here so that nobody builds a worse one. The alternatives
    when Keycloak arrived were to add ``keycloak`` to the loopback set, which is
    a lie that would ship to every deployment, or to disable certificate
    verification, which is broader, quieter, and invisible in a config file.
    This is narrow, it is a hostname somebody typed, and every start logs a
    warning naming each entry. See ADR 0018.
    """

    auth_algorithms: list[str] = Field(
        default_factory=lambda: ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]
    )
    """Signature algorithms accepted, unless an entry in the issuers file
    overrides them for one server. Asymmetric only — a symmetric algorithm here
    is refused at startup, because a JWKS publishes *public* keys and an
    attacker can sign HS256 with one."""

    auth_leeway: float = Field(default=60.0, ge=0)
    """Clock skew tolerated on ``exp``, ``nbf`` and ``iat``, in seconds."""

    auth_discovery_timeout: float = Field(default=5.0, gt=0)
    """Seconds to wait for an authorization server's metadata at startup.

    Short. This runs before the port is bound, so a hung identity provider
    delays a deployment rather than a request — but a deploy that hangs
    indefinitely on a DNS black hole is its own kind of outage.
    """

    auth_jwks_cache_ttl: float = Field(default=600.0, gt=0)

    auth_jwks_min_refresh_interval: float = Field(default=30.0, ge=0)
    """Floor between key-set fetches triggered by an unknown ``kid``.

    A rate limit on attacker-triggered work: the ``kid`` comes from the token,
    so refetching on every miss makes the gateway an amplifier pointed at its
    own identity provider.
    """

    @property
    def authentication_configured(self) -> bool:
        return bool(self.auth_issuers_file or (self.auth_issuer and self.auth_audience))

    @property
    def secret_store_configured(self) -> bool:
        return self.secrets_file is not None and self.secret_key_file is not None

    @property
    def exchange_configured(self) -> bool:
        """Whether the gateway will mint per-upstream credentials (task 27)."""
        return bool(self.auth_client_id and self.auth_client_secret)

    @model_validator(mode="after")
    def _identity_settings_are_coherent(self) -> GatewaySettings:
        """Refuse anything that would authenticate differently than it reads.

        Three separate ways to be wrong, and all of them fail *open* if allowed
        through — the gateway would serve while its configuration described
        something else. Configuration errors in this project are fatal for
        exactly this reason.
        """
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
            # Half of a client credential is not a weaker credential, it is a
            # gateway that believes it mints per-upstream tokens and does not.
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
            # The document's only useful field would be `authorization_servers`,
            # and there are none. Publishing it anyway would advertise a
            # discovery path that dead-ends, which is a worse answer to "how do
            # I authenticate here" than publishing nothing at all.
            msg = (
                "ACP_AUTH_RESOURCE names a resource no client can obtain a token for, "
                "because no authorization server is configured. Set ACP_AUTH_ISSUER "
                "and ACP_AUTH_AUDIENCE, or ACP_AUTH_ISSUERS_FILE."
            )
            raise ValueError(msg)
        return self


def allowed_hosts_for(hosts: list[str], port: int) -> list[str]:
    """Expand an allow-list to cover the port-qualified form of each host.

    The HTTP ``Host`` header carries the port for any non-default port, so a
    client reaching ``http://127.0.0.1:8080/mcp`` sends ``Host: 127.0.0.1:8080``
    — which does not match a bare ``127.0.0.1`` in the allow-list, and the SDK
    answers 421 Misdirected Request.

    This was missed by the entire test suite because those tests connect on the
    default port, where the Host header has no port suffix at all. It surfaced
    the first time a real MCP client connected on :8080. Entries that already
    specify a port are left alone, so an explicit ``gateway.internal:443`` is
    not mangled.
    """
    expanded: list[str] = []

    def add(value: str) -> None:
        # Order-preserving dedup, so applying this twice is a no-op. Duplicates
        # in an allow-list are harmless but make a config dump confusing to read.
        if value not in expanded:
            expanded.append(value)

    for host in hosts:
        add(host)
        if ":" not in host:
            add(f"{host}:{port}")
    return expanded


def load_upstreams(path: Path) -> list[UpstreamConfig]:
    """Read and validate the upstream definitions.

    Every failure mode here is a startup failure with a message naming the file
    and, where possible, the offending entry. Configuration errors are read by
    a human at 3am; "validation error for UpstreamConfig" without a filename is
    not good enough.
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
    """Two upstreams sharing a name would make qualified tool names ambiguous.

    ``mock-a__search`` must identify exactly one server, or routing silently
    sends calls to whichever happened to be registered last (ADR 0003).
    """
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

    Returns plain documents rather than built registrations, because a
    registration may still need its `jwks_url` discovered — and discovery is
    async, network-touching, and has no business inside a config parser.

    Same failure discipline as `load_upstreams`: every problem is a startup
    failure naming the file and, where possible, the offending entry. This one
    is read by whoever is trying to work out why nothing can authenticate.
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
