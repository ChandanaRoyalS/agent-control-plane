"""Where the gateway keeps the secrets it genuinely has to hold.

Task 27 removed most of them. The gateway holds no long-lived upstream
credential, because it mints one per call and throws it away. That is the right
answer wherever it is available, and it is not always available: an upstream may
speak an API key issued out of band, or belong to a team with no OAuth
integration, or be a piece of vendor software that will never learn RFC 8693.

Before this, such an upstream simply could not be configured. Task 27 made
`audience` mandatory once exchange is on, which is correct for anything that can
exchange and a wall for anything that cannot. This is the other door.

**What a store is for, stated honestly.** It does not make secrets safe. It
reduces *many* secrets to *one* — the key — and makes that one small enough to
hand to a runtime rather than to a person. Everything the encrypted backend
defends against follows from that and nothing else: a stray copy of a config
directory, a backup, a file in a support bundle, a value that would otherwise
sit in the process environment where anything reading ``/proc`` can see it. It
does not defend against root on the box, or against the running process, and
saying otherwise would be the kind of reassurance this project keeps refusing to
give.

**Why an interface at all, for one backend.** Because the *good* answer to the
remaining key is to not have one — a workload identity that Vault or a cloud
secrets manager exchanges for a lease, with nothing durable on disk. That is a
deployment this project cannot build or test here, and shipping a half-working
adapter for it would be worse than none. What can be done is put the seam in the
right place, so the swap is one class rather than a refactor.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from acp.exceptions import ACPError


class SecretNotFoundError(ACPError):
    """A secret was asked for by name and the store does not have it.

    A configuration error at heart, and fatal at startup for that reason: an
    upstream whose credential is missing is one the gateway would otherwise
    reach with no credential at all. Not recoverable — no amount of retrying
    puts a value in a store.
    """

    code = -32034


@runtime_checkable
class SecretStore(Protocol):
    """Somewhere secrets come from, by name.

    Async on purpose, for the one backend that does not exist yet. The encrypted
    file store reads and decrypts once at startup and answers from memory, so
    every ``await`` here returns immediately — but a Vault-backed store would
    fetch, lease and renew, and a synchronous interface would force that work
    onto a thread or into the constructor. Retrofitting async into an interface
    is a change to every caller; starting with it costs nothing.
    """

    async def get(self, name: str) -> str:
        """The secret's value, or raise ``SecretNotFoundError``.

        Raises rather than returning ``None``, because every caller of this
        wants the value and has nothing sensible to do without it. A ``None``
        would be checked in some places and not others, and the places it was
        not checked would send the string ``"None"`` somewhere.
        """
        ...

    def names(self) -> list[str]:
        """Every secret this store holds, by name. Never values.

        Synchronous because it is a listing, used by the CLI and by startup
        validation rather than on a request path. Names are not secret — an
        operator has to be able to see what is configured, and a store nobody
        can inventory is a store that quietly stops matching the config.
        """
        ...

    async def aclose(self) -> None:
        """Release anything held. A file store holds nothing; a leased one does."""
        ...


class EmptyStore:
    """A store with nothing in it, for the deployments that need no secrets.

    Distinct from having no store at all, and the difference matters at startup:
    "no store is configured" and "a store is configured and does not contain the
    secret you named" are different mistakes with different fixes, and a `None`
    in place of a store would collapse them into one.
    """

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
