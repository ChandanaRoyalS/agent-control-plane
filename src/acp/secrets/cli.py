"""Operator commands for the secret store: create it, add secrets, list names.

Kept out of ``acp.cli`` (which imports the MCP SDK) so it stays testable and
type-checkable; ``acp.cli`` holds only argparse wiring. Nothing here prints a secret.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

import anyio

from acp.exceptions import ConfigurationError
from acp.secrets.encrypted import EncryptedFileStore, generate_key, read_key


def initialise(key_path: Path, secrets_path: Path, *, force: bool = False) -> str:
    """Create a key and an empty store, returning the key.

    Raises:
        ConfigurationError: The key exists and ``force`` is false; overwriting it makes
            every existing secret permanently unreadable.
    """
    if key_path.exists() and not force:
        msg = (
            f"{str(key_path)!r} already exists. Overwriting it would make every secret "
            f"in the current store permanently unreadable. Pass --force if that is "
            f"genuinely what you want."
        )
        raise ConfigurationError(msg)

    key = generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.touch(mode=0o600, exist_ok=True)
    key_path.chmod(0o600)
    key_path.write_text(key, encoding="utf-8")

    EncryptedFileStore.write(secrets_path, key, {})
    return key


def put(key_path: Path, secrets_path: Path, name: str, value: str) -> list[str]:
    """Add or replace one secret, returning the store's names afterwards.

    Rewrites the whole document, which is one ciphertext (see ``encrypted``).
    """
    if not name:
        msg = "a secret needs a name"
        raise ConfigurationError(msg)

    key = read_key(key_path)
    secrets: dict[str, str] = {}
    if secrets_path.exists():
        # Use the store's accessor so this survives a backend change.
        existing = EncryptedFileStore.open(secrets_path, key)
        secrets = {n: _value_of(existing, n) for n in existing.names()}

    secrets[name] = value
    EncryptedFileStore.write(secrets_path, key, secrets)
    return sorted(secrets)


def _value_of(store: EncryptedFileStore, name: str) -> str:
    """Read one secret synchronously via ``anyio.run``, for the loop-less CLI."""
    return str(anyio.run(store.get, name))


def read_value(stdin_is_tty: bool | None = None) -> str:
    """Read the secret from a prompt or stdin, never argv (shell history, process table).

    Raises:
        ConfigurationError: The value is empty.
    """
    interactive = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
    value = getpass.getpass("secret: ") if interactive else sys.stdin.read()
    value = value.strip()
    if not value:
        msg = "no value was given; nothing was written"
        raise ConfigurationError(msg)
    return value


def names(key_path: Path, secrets_path: Path) -> list[str]:
    """Return every name the store holds, never a value."""
    return EncryptedFileStore.open(secrets_path, read_key(key_path)).names()
