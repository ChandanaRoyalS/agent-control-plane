"""Secrets the gateway holds because it has to — task 29.

Task 27 removed most of them: the gateway mints an upstream credential per call
and keeps none. This is for the upstreams that cannot take part in that — an API
key issued out of band, a vendor appliance that will never speak RFC 8693 — and
which before task 29 could not be configured at all.

The store's honest claim is that it reduces many secrets to one key, and makes
that key small enough to hand to a runtime rather than to a person. See
`store.SecretStore` for what that does and does not defend against, and ADR 0021
for why there is an interface when there is only one backend.
"""

from acp.secrets.encrypted import EncryptedFileStore, generate_key, read_key
from acp.secrets.store import EmptyStore, SecretNotFoundError, SecretStore

__all__ = [
    "EmptyStore",
    "EncryptedFileStore",
    "SecretNotFoundError",
    "SecretStore",
    "generate_key",
    "read_key",
]
