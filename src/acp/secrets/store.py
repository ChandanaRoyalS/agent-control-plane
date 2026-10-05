"""Secret store interface for upstreams that cannot use token exchange.

A store reduces many secrets to one key small enough to hand to a runtime. It defends
against stray copies (config directories, backups, support bundles, ``/proc`` environ),
not against root or the running process. The Protocol leaves room for a Vault-style
backend as a one-class swap.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from acp.exceptions import ACPError


class SecretNotFoundError(ACPError):
    """The store has no secret by this name; fatal at startup and not retryable."""

    code = -32034


@runtime_checkable
class SecretStore(Protocol):
    """Somewhere secrets come from, by name.

    ``get`` is async for future leased backends; the file store answers from memory.
    """

    async def get(self, name: str) -> str:
        """Return the secret's value; raises ``SecretNotFoundError``, never returns ``None``."""
        ...

    def names(self) -> list[str]:
        """Return every secret name (not secret themselves), never values."""
        ...

    async def aclose(self) -> None:
        """Release anything held."""
        ...


class EmptyStore:
    """A store with nothing in it, distinct from no store so startup errors stay precise."""

    async def get(self, name: str) -> str:
        msg = (
            f"no secret named {name!r}: this gateway has no secret store configured. "
            f"Set ACP_SECRETS_FILE and ACP_SECRET_KEY_FILE, or remove the reference."
        )
        raise SecretNotFoundError(msg)

    def names(self) -> list[str]:
        return []

    async def aclose(self) -> None:
        return
