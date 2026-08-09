"""Does the secret store actually get consulted at startup?

`test_store.py` proves the encryption works and `test_cli.py` proves an operator
can populate it. Neither says anything about whether the *gateway* reads it —
and "the credential exists but is never resolved" is a real and quiet way to
fail, the same gap that left `build_token_validator` untested behind a 93%
coverage number in task 22.

Written because the coverage report said so. After task 29 `runtime.py` reported
67% with `build_secret_store` and `resolve_upstream_secrets` among the missing
lines, which is precisely the case where reading the percentage rather than the
line numbers would have let a startup path ship untested.
"""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest

from acp.config import GatewaySettings
from acp.exceptions import ConfigurationError
from acp.runtime import (
    build_secret_store,
    check_upstream_audiences,
    resolve_upstream_secrets,
)
from acp.secrets import EmptyStore, SecretNotFoundError
from acp.secrets.cli import initialise, put
from acp.upstream import UpstreamConfig

pytestmark = pytest.mark.integration


def settings(**overrides: object) -> GatewaySettings:
    """Explicit keyword arguments, never a `**dict` splat — mypy cannot check
    one against a model whose fields are variously `Path`, `bool` and `str`."""
    return GatewaySettings(  # type: ignore[call-arg]
        _env_file=None,
        auth_required=False,
        secrets_file=overrides.get("secrets_file"),  # type: ignore[arg-type]
        secret_key_file=overrides.get("secret_key_file"),  # type: ignore[arg-type]
    )


def a_store(tmp_path: Path, name: str = "legacy-crm-key", value: str = "s3cret") -> GatewaySettings:
    key, secrets = tmp_path / "secret.key", tmp_path / "secrets.enc"
    initialise(key, secrets)
    put(key, secrets, name, value)
    return settings(secrets_file=secrets, secret_key_file=key)


def upstream(name: str = "legacy-crm", **fields: str) -> UpstreamConfig:
    return UpstreamConfig(name=name, url=f"https://{name}.internal/mcp", **fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The store is opened
# ---------------------------------------------------------------------------


def test_no_configuration_means_a_store_that_says_so() -> None:
    """`EmptyStore` rather than `None`. "No store is configured" and "a store is
    configured and lacks that secret" are different mistakes with different
    fixes, and a `None` would collapse them into one message."""
    store = build_secret_store(settings())

    assert isinstance(store, EmptyStore)
    with pytest.raises(SecretNotFoundError, match="no secret store configured"):
        anyio.run(store.get, "anything")


def test_a_configured_store_is_opened_and_readable(tmp_path: Path) -> None:
    store = build_secret_store(a_store(tmp_path))

    assert store.names() == ["legacy-crm-key"]
    assert anyio.run(store.get, "legacy-crm-key") == "s3cret"


def test_a_bad_key_stops_the_gateway(tmp_path: Path) -> None:
    """Fatal at startup, before a port is bound — like every other
    configuration failure in this project."""
    config = a_store(tmp_path)
    assert config.secret_key_file is not None
    config.secret_key_file.write_text("not-a-fernet-key", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="Fernet key is 44"):
        build_secret_store(config)


# ---------------------------------------------------------------------------
# References are resolved, once, up front
# ---------------------------------------------------------------------------


def test_a_referenced_secret_is_resolved_before_serving(tmp_path: Path) -> None:
    store = build_secret_store(a_store(tmp_path))

    resolved = anyio.run(
        resolve_upstream_secrets, [upstream(credential_ref="legacy-crm-key")], store
    )

    assert resolved == {"legacy-crm": "s3cret"}


def test_upstreams_that_exchange_resolve_nothing(tmp_path: Path) -> None:
    """A gateway where everything speaks RFC 8693 has no secrets to hold, which
    is the whole point of task 27 and the reason this store is optional."""
    store = build_secret_store(a_store(tmp_path))

    resolved = anyio.run(
        resolve_upstream_secrets, [upstream(audience="acp-upstream-legacy-crm")], store
    )

    assert resolved == {}


def test_a_missing_secret_is_fatal_at_startup(tmp_path: Path) -> None:
    """The property the whole resolve-early design exists for. Left until the
    first request, this would be an upstream reached with no credential at all
    — discovered by whoever was using the gateway rather than by whoever
    deployed it."""
    store = build_secret_store(a_store(tmp_path))

    with pytest.raises(SecretNotFoundError, match="no secret named 'typo'"):
        anyio.run(resolve_upstream_secrets, [upstream(credential_ref="typo")], store)


def test_a_reference_with_no_store_configured_is_fatal() -> None:
    """And says which of the two mistakes it is, rather than reporting a missing
    secret when the real problem is a missing store."""
    with pytest.raises(SecretNotFoundError, match="no secret store configured"):
        anyio.run(
            resolve_upstream_secrets,
            [upstream(credential_ref="anything")],
            build_secret_store(settings()),
        )


# ---------------------------------------------------------------------------
# Two ways to be credentialed, and an upstream needs one
# ---------------------------------------------------------------------------


def test_a_stored_credential_satisfies_the_exchange_era_rule() -> None:
    """Task 27 made `audience` mandatory once exchange is on, which was correct
    for anything that can exchange and a wall for anything that cannot. Task 29
    is the other door, and this is the check that now accepts it."""
    check_upstream_audiences([upstream(credential_ref="legacy-crm-key")], exchanging=True)


def test_an_upstream_credentialed_by_neither_route_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="credentialed by neither route"):
        check_upstream_audiences([upstream()], exchanging=True)


def test_without_exchange_nothing_is_required() -> None:
    """Phase 1's behaviour, which has to keep working: a gateway with no identity
    provider brokers for uncredentialed upstreams exactly as it always did."""
    check_upstream_audiences([upstream()], exchanging=False)
