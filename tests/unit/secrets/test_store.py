"""The encrypted store: what it protects, and what it admits it does not."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import anyio
import pytest
from cryptography.fernet import Fernet

from acp.exceptions import ConfigurationError
from acp.secrets import (
    EmptyStore,
    EncryptedFileStore,
    SecretNotFoundError,
    generate_key,
    read_key,
)

SECRET = "an-api-key-issued-out-of-band"


def store_at(tmp_path: Path, secrets: dict[str, str] | None = None) -> tuple[Path, Path, str]:
    key = generate_key()
    key_path = tmp_path / "key"
    key_path.write_text(key, encoding="utf-8")
    key_path.chmod(0o600)
    secrets_path = tmp_path / "secrets.enc"
    EncryptedFileStore.write(secrets_path, key, secrets or {"mock-c": SECRET})
    return key_path, secrets_path, key


# ---------------------------------------------------------------------------
# What it holds
# ---------------------------------------------------------------------------


def test_a_secret_survives_a_round_trip(tmp_path: Path) -> None:
    key_path, secrets_path, _ = store_at(tmp_path)

    store = EncryptedFileStore.open(secrets_path, read_key(key_path))

    assert anyio.run(store.get, "mock-c") == SECRET


def test_the_file_contains_no_plaintext(tmp_path: Path) -> None:
    """The obvious property, worth asserting because the obvious mistake —
    writing JSON and encrypting it later, or not at all — produces a file that
    passes every other test in this module."""
    _, secrets_path, _ = store_at(tmp_path)

    raw = secrets_path.read_bytes()

    assert SECRET.encode() not in raw


def test_the_file_leaks_no_inventory(tmp_path: Path) -> None:
    """Names are the useful half of a reconnaissance find: `stripe-live-key`
    tells you where to look next, and the value is unreadable anyway. One
    ciphertext for the whole document rather than one per entry is what buys
    this, at the cost of rewriting a small file to change one secret."""
    _, secrets_path, _ = store_at(tmp_path, {"stripe-live-key": "x", "hr-database": "y"})

    raw = secrets_path.read_bytes()

    assert b"stripe-live-key" not in raw
    assert b"hr-database" not in raw


def test_a_missing_secret_names_what_is_there(tmp_path: Path) -> None:
    """Safe to print and the only thing that makes the message useful — a typo
    found in one reading rather than one bisection."""
    key_path, secrets_path, _ = store_at(tmp_path, {"mock-a-key": "x", "mock-b-key": "y"})
    store = EncryptedFileStore.open(secrets_path, read_key(key_path))

    with pytest.raises(SecretNotFoundError, match="mock-a-key, mock-b-key"):
        anyio.run(store.get, "mock-c-key")


def test_names_are_listable_and_values_are_not(tmp_path: Path) -> None:
    """An operator has to be able to inventory the store — one nobody can list
    is one that quietly stops matching the config it is referenced from."""
    key_path, secrets_path, _ = store_at(tmp_path, {"a": "1", "b": "2"})

    names = EncryptedFileStore.open(secrets_path, read_key(key_path)).names()

    assert names == ["a", "b"]


# ---------------------------------------------------------------------------
# What it refuses
# ---------------------------------------------------------------------------


def test_a_tampered_file_is_refused_rather_than_partly_read(tmp_path: Path) -> None:
    """Authenticated encryption, and the reason for it. A file an attacker can
    modify but not read is still one they can attack — flip bytes in a
    credential and watch what the upstream does. The HMAC turns that into a
    decryption failure instead of a corrupted secret being sent somewhere."""
    key_path, secrets_path, _ = store_at(tmp_path)
    raw = bytearray(secrets_path.read_bytes())
    raw[-5] ^= 0x01
    secrets_path.write_bytes(bytes(raw))

    with pytest.raises(ConfigurationError, match="could not decrypt"):
        EncryptedFileStore.open(secrets_path, read_key(key_path))


def test_the_wrong_key_and_a_tampered_file_are_one_message(tmp_path: Path) -> None:
    """Indistinguishable to Fernet by design, so guessing between them in an
    error message would invent a distinction the cryptography does not make."""
    _, secrets_path, _ = store_at(tmp_path)

    with pytest.raises(ConfigurationError, match="or the file has been modified"):
        EncryptedFileStore.open(secrets_path, generate_key())


def test_a_world_readable_key_stops_the_gateway(tmp_path: Path) -> None:
    """This one file opens every secret the gateway holds. A key readable by the
    group is a key readable by whatever else runs as that group."""
    key_path, _, _ = store_at(tmp_path)
    key_path.chmod(0o644)

    with pytest.raises(ConfigurationError, match="readable beyond its owner"):
        read_key(key_path)


def test_permissions_are_reported_not_silently_fixed(tmp_path: Path) -> None:
    """Tightening a file the operator created is a change to their system made
    by a program run for another reason — and it hides that whatever created it
    was wrong, which is the part that will happen again next deploy."""
    key_path, _, _ = store_at(tmp_path)
    key_path.chmod(0o644)

    with pytest.raises(ConfigurationError):
        read_key(key_path)

    assert key_path.stat().st_mode & stat.S_IROTH, "the file was modified"


def test_a_truncated_key_says_so_by_name(tmp_path: Path) -> None:
    """Otherwise the failure is an exception from inside `cryptography` naming
    neither the file nor what is wrong with it."""
    key_path = tmp_path / "key"
    key_path.write_text("too-short", encoding="utf-8")
    key_path.chmod(0o600)

    with pytest.raises(ConfigurationError, match="a Fernet key is 44"):
        read_key(key_path)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def test_the_store_is_private_from_the_moment_it_exists(tmp_path: Path) -> None:
    """Created 0600 before anything is written to it. A file that is briefly
    world-readable while it contains secrets is a file that was
    world-readable."""
    _, secrets_path, _ = store_at(tmp_path)

    assert stat.S_IMODE(secrets_path.stat().st_mode) == 0o600


def test_a_write_leaves_no_temporary_behind(tmp_path: Path) -> None:
    """Written and renamed, so a process killed mid-write cannot leave a store
    that decrypts to half a document."""
    store_at(tmp_path)

    assert not (tmp_path / "secrets.enc.tmp").exists()


def test_a_store_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    key = generate_key()
    secrets_path = tmp_path / "secrets.enc"
    secrets_path.write_bytes(Fernet(key.encode()).encrypt(json.dumps(["a", "b"]).encode()))

    with pytest.raises(ConfigurationError, match="does not contain an object"):
        EncryptedFileStore.open(secrets_path, key)


# ---------------------------------------------------------------------------
# No store at all
# ---------------------------------------------------------------------------


def test_an_empty_store_says_no_store_is_configured() -> None:
    """Distinct from a configured store that lacks the secret. Different
    mistakes, different fixes, and a `None` in place of a store would have
    collapsed them into one message that could only say "missing"."""
    with pytest.raises(SecretNotFoundError, match="no secret store configured"):
        anyio.run(EmptyStore().get, "anything")


def test_an_empty_store_lists_nothing_rather_than_failing() -> None:
    assert EmptyStore().names() == []
