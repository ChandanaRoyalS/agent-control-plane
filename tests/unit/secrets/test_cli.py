"""The operator's commands. Every decision here; only argparse lives in `acp.cli`."""

from __future__ import annotations

import io
from pathlib import Path

import anyio
import pytest

from acp.exceptions import ConfigurationError
from acp.secrets import EncryptedFileStore, read_key
from acp.secrets.cli import initialise, names, put, read_value


def test_init_creates_a_key_and_an_empty_store(tmp_path: Path) -> None:
    initialise(tmp_path / "key", tmp_path / "secrets.enc")

    assert names(tmp_path / "key", tmp_path / "secrets.enc") == []


def test_init_refuses_to_overwrite_a_key(tmp_path: Path) -> None:
    """Overwriting it makes every secret in the existing store permanently
    unreadable, with no recovery — and the failure appears at the *next*
    deployment rather than now."""
    initialise(tmp_path / "key", tmp_path / "secrets.enc")

    with pytest.raises(ConfigurationError, match="permanently unreadable"):
        initialise(tmp_path / "key", tmp_path / "secrets.enc")


def test_force_is_available_for_when_that_is_the_point(tmp_path: Path) -> None:
    initialise(tmp_path / "key", tmp_path / "secrets.enc")
    first = (tmp_path / "key").read_text(encoding="utf-8")

    initialise(tmp_path / "key", tmp_path / "secrets.enc", force=True)

    assert (tmp_path / "key").read_text(encoding="utf-8") != first


def test_setting_a_secret_leaves_the_others_alone(tmp_path: Path) -> None:
    """Read-modify-write of one ciphertext, so the mistake worth checking is a
    write that drops everything it did not touch."""
    key_path, secrets_path = tmp_path / "key", tmp_path / "secrets.enc"
    initialise(key_path, secrets_path)
    put(key_path, secrets_path, "mock-c", "first")
    put(key_path, secrets_path, "other", "second")

    put(key_path, secrets_path, "mock-c", "rotated")

    store = EncryptedFileStore.open(secrets_path, read_key(key_path))
    assert anyio.run(store.get, "mock-c") == "rotated"
    assert anyio.run(store.get, "other") == "second"


def test_a_secret_needs_a_name(tmp_path: Path) -> None:
    initialise(tmp_path / "key", tmp_path / "secrets.enc")

    with pytest.raises(ConfigurationError, match="needs a name"):
        put(tmp_path / "key", tmp_path / "secrets.enc", "", "value")


def test_a_value_is_read_from_stdin_when_there_is_no_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What makes this usable from a deployment script. The alternative — a
    value on the command line — puts it in shell history, in the process table
    for the duration, and in any audit log that records command lines."""
    monkeypatch.setattr("sys.stdin", io.StringIO("piped-in-secret\n"))

    assert read_value(stdin_is_tty=False) == "piped-in-secret"


def test_an_empty_value_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stray newline would otherwise store the empty string, and an upstream
    would then be sent `Bearer ` — which fails somewhere far away with a message
    about a malformed header."""
    monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))

    with pytest.raises(ConfigurationError, match="nothing was written"):
        read_value(stdin_is_tty=False)


def test_listing_shows_names_only(tmp_path: Path) -> None:
    key_path, secrets_path = tmp_path / "key", tmp_path / "secrets.enc"
    initialise(key_path, secrets_path)
    put(key_path, secrets_path, "mock-c", "a-real-looking-credential")

    listed = names(key_path, secrets_path)

    assert listed == ["mock-c"]
    assert "a-real-looking-credential" not in str(listed)
