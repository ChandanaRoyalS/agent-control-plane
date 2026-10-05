"""An encrypted file of secrets and the one key that opens it (ADR 0021).

Fernet (authenticated: AES-128-CBC plus HMAC-SHA256), so tampering fails decryption.
The whole document is one ciphertext so the file does not leak secret names. The key
lives in its own file, for a runtime mount rather than a person to edit.
"""

from __future__ import annotations

import json
import logging
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from acp.exceptions import ConfigurationError
from acp.secrets.store import SecretNotFoundError

logger = logging.getLogger(__name__)

KEY_LENGTH = 44
"""Length of a urlsafe-base64 Fernet key; checked for a clear error on truncation."""

WORLD_ACCESSIBLE = stat.S_IRWXG | stat.S_IRWXO
"""Permission bits outside the owner's; any of them set rejects the key file."""


def generate_key() -> str:
    """Return a new Fernet key as text (used by the CLI)."""
    return Fernet.generate_key().decode()


def read_key(path: Path, *, require_private: bool = True) -> str:
    """Load and check the key file.

    Permissions are checked, not silently fixed, so the operator learns what created
    the file wrongly.

    Raises:
        ConfigurationError: Unreadable, wrong length, or (with ``require_private``)
            accessible beyond its owner.
    """
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        msg = f"cannot read the secret key file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    if len(raw) != KEY_LENGTH:
        msg = (
            f"the secret key in {str(path)!r} is {len(raw)} characters; a Fernet key is "
            f"{KEY_LENGTH}. Generate one with `acp secrets init`."
        )
        raise ConfigurationError(msg)

    mode = path.stat().st_mode
    if require_private and mode & WORLD_ACCESSIBLE:
        msg = (
            f"the secret key file {str(path)!r} is readable beyond its owner "
            f"(mode {stat.filemode(mode)}). This one file opens every secret the "
            f"gateway holds. `chmod 600 {path}`."
        )
        raise ConfigurationError(msg)

    return raw


class EncryptedFileStore:
    """Secrets held as one encrypted document on disk.

    Decrypted once at construction and served from memory, so the set cannot change
    under a running gateway.
    """

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    @classmethod
    def open(cls, path: Path, key: str) -> EncryptedFileStore:
        """Read and decrypt the store; raises ``ConfigurationError`` on failure."""
        try:
            payload = path.read_bytes()
        except OSError as exc:
            msg = f"cannot read the secrets file {str(path)!r}: {exc}"
            raise ConfigurationError(msg) from exc

        secrets = cls._decrypt(payload, key, path)
        # Count at INFO, names only at DEBUG: names are the inventory worth hiding.
        logger.info("secrets.loaded", extra={"path": str(path), "count": len(secrets)})
        logger.debug("secrets.inventory", extra={"names": sorted(secrets)})
        return cls(secrets)

    @staticmethod
    def _decrypt(payload: bytes, key: str, path: Path) -> dict[str, str]:
        try:
            plaintext = Fernet(key.encode()).decrypt(payload)
        except InvalidToken as exc:
            # Wrong key and tampering are indistinguishable to Fernet by design.
            msg = (
                f"could not decrypt {str(path)!r}. Either the key does not match this "
                f"file, or the file has been modified since it was written."
            )
            raise ConfigurationError(msg) from exc
        except (ValueError, TypeError) as exc:
            msg = f"the secret key is not a valid Fernet key: {exc}"
            raise ConfigurationError(msg) from exc

        document = json.loads(plaintext)
        if not isinstance(document, dict):
            msg = f"the secrets file {str(path)!r} does not contain an object"
            raise ConfigurationError(msg)
        return {str(name): str(value) for name, value in document.items()}

    @staticmethod
    def write(path: Path, key: str, secrets: dict[str, str]) -> None:
        """Encrypt and replace the store, atomically and privately.

        Temp file plus rename so a crash cannot leave half a document; created 0600
        before any secret is written.
        """
        temporary = path.with_name(f"{path.name}.tmp")
        payload = Fernet(key.encode()).encrypt(json.dumps(secrets, sort_keys=True).encode())

        temporary.touch(mode=0o600, exist_ok=True)
        temporary.chmod(0o600)
        temporary.write_bytes(payload)
        temporary.replace(path)
        path.chmod(0o600)

    async def get(self, name: str) -> str:
        try:
            return self._secrets[name]
        except KeyError as exc:
            # Count only, never the inventory: this message reaches the log.
            msg = (
                f"no secret named {name!r} in the store, which holds "
                f"{len(self._secrets)} secret(s). `acp secrets list` names them."
            )
            raise SecretNotFoundError(msg) from exc

    def names(self) -> list[str]:
        return sorted(self._secrets)

    async def aclose(self) -> None:
        """Release nothing; decrypted values stay in memory (and core dumps) for life."""
        return
