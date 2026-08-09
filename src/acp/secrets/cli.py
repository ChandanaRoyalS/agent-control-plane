"""The operator's side of the secret store: create it, put things in it, list it.

Deliberately here rather than in ``acp.cli``. That module imports the MCP SDK,
which the environment these are written in cannot install, so anything living
there is untestable *and* untype-checkable until it reaches Chandana's machine —
which is how three bugs have shipped so far. What is in ``acp.cli`` for secrets
is argparse wiring; every decision is here, where a test can reach it.

Nothing in this file prints a secret. `set` reads from a prompt or stdin and
echoes nothing back; `list` shows names only. A tool that will happily print a
credential to a terminal is a tool that will eventually print one into a
screen-share, a scrollback buffer, or a support ticket.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

import anyio

from acp.exceptions import ConfigurationError
from acp.secrets.encrypted import EncryptedFileStore, generate_key, read_key


def initialise(key_path: Path, secrets_path: Path, *, force: bool = False) -> str:
    """Create a key and an empty store, refusing to overwrite either.

    ``force`` exists and is not the default, because overwriting the key makes
    every secret in the existing store permanently unreadable — there is no
    recovery, no undo, and the failure appears at the *next* deployment rather
    than now. A flag somebody has to type is the least this deserves.
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

    Read-modify-write of the whole document, because the whole document is one
    ciphertext (see ``encrypted``). That is not a performance concern at this
    size and it is the reason the file leaks no inventory.
    """
    if not name:
        msg = "a secret needs a name"
        raise ConfigurationError(msg)

    key = read_key(key_path)
    secrets: dict[str, str] = {}
    if secrets_path.exists():
        # Read through the store's own accessor rather than reaching into it, so
        # this stays correct if the backend ever changes shape.
        existing = EncryptedFileStore.open(secrets_path, key)
        secrets = {n: _value_of(existing, n) for n in existing.names()}

    secrets[name] = value
    EncryptedFileStore.write(secrets_path, key, secrets)
    return sorted(secrets)


def _value_of(store: EncryptedFileStore, name: str) -> str:
    """Synchronous read of an async accessor, for a CLI that has no loop.

    ``SecretStore.get`` is async for the backend that does not exist yet (see
    ``store``). The file store's implementation is a dictionary lookup, so this
    costs a loop per secret in a one-shot command that writes a handful — which
    is the correct place to pay for an interface that will matter later.
    """
    return str(anyio.run(store.get, name))


def read_value(stdin_is_tty: bool | None = None) -> str:
    """The secret itself, from a prompt or a pipe, never from argv.

    A value passed as an argument is a value in the shell history of whoever ran
    it, in the process table for the duration, and in any audit log that records
    command lines. `getpass` when there is a terminal, stdin when there is not —
    the second is what makes this usable from a deployment script.
    """
    interactive = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
    value = getpass.getpass("secret: ") if interactive else sys.stdin.read()
    value = value.strip()
    if not value:
        msg = "no value was given; nothing was written"
        raise ConfigurationError(msg)
    return value


def names(key_path: Path, secrets_path: Path) -> list[str]:
    """Every name the store holds. Never a value."""
    return EncryptedFileStore.open(secrets_path, read_key(key_path)).names()
