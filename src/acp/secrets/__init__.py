"""Secrets for upstreams that cannot use token exchange (out-of-band API keys, vendor apps).

The store reduces many secrets to one key. See `store.SecretStore` for its threat model
and ADR 0021 for why there is an interface with one backend.
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
