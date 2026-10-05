"""Ed25519 signatures on audit entries (ADR 0078).

The hash chain proves the file is self-consistent; anyone who can write the file can
also rewrite it consistently. A signature on each entry's hash moves that from "who can
write the file" to "who holds the key". One key signs one chain file for its whole life,
so a verifier can require a single key id per file and a retired key cannot be spliced in.

What it does not do: stop whoever holds the key (including a compromised gateway, which
must hold it), or reveal a truncated tail. A checkpoint stored elsewhere still covers that.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from acp.exceptions import ConfigurationError

DOMAIN: Final = b"acp-audit-entry-v1\x00"
"""Prefix on every signed message, so an audit signature cannot be replayed as anything else."""

KID_HEX: Final = 16
"""Key id length: the first 16 hex characters of the SHA-256 of the raw public key."""

PRIVATE_MODE: Final = 0o600


def key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:KID_HEX]


def _message(entry_hash: str) -> bytes:
    return DOMAIN + entry_hash.encode("ascii")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Signer:
    """Signs entry hashes with one private key."""

    private: Ed25519PrivateKey

    @property
    def kid(self) -> str:
        return key_id(self.private.public_key())

    def sign(self, entry_hash: str) -> str:
        return _b64(self.private.sign(_message(entry_hash)))


@dataclass(frozen=True)
class Verifier:
    """The public keys a verifier accepts, by key id."""

    keys: Mapping[str, Ed25519PublicKey]

    def problem(self, entry_hash: str, sig: str | None, kid: str | None) -> str | None:
        """Why this entry's signature does not verify, or ``None`` if it does."""
        if sig is None or kid is None:
            return "entry is not signed"
        key = self.keys.get(kid)
        if key is None:
            return f"signed by key {kid}, which is not one of the keys given"
        try:
            key.verify(_unb64(sig), _message(entry_hash))
        except (InvalidSignature, ValueError):
            return f"signature does not verify under key {kid}"
        return None


def load_signer(path: Path) -> Signer:
    """The private key at ``path``.

    Raises:
        ConfigurationError: Missing, unreadable, encrypted, or not Ed25519.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        msg = f"cannot read the audit signing key at {path}: {exc.strerror or exc}"
        raise ConfigurationError(msg) from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        msg = f"{path} is not an unencrypted PEM private key"
        raise ConfigurationError(msg) from exc
    if not isinstance(key, Ed25519PrivateKey):
        msg = f"{path} is not an Ed25519 key; `acp audit keygen` makes one"
        raise ConfigurationError(msg)
    return Signer(key)


def load_verifier(paths: Iterable[Path]) -> Verifier:
    """Public keys from PEM files.

    Raises:
        ConfigurationError: A file is missing, unreadable or not an Ed25519 public key.
    """
    keys: dict[str, Ed25519PublicKey] = {}
    for path in paths:
        try:
            key = serialization.load_pem_public_key(path.read_bytes())
        except OSError as exc:
            msg = f"cannot read the public key at {path}: {exc.strerror or exc}"
            raise ConfigurationError(msg) from exc
        except (ValueError, TypeError) as exc:
            msg = f"{path} is not a PEM public key"
            raise ConfigurationError(msg) from exc
        if not isinstance(key, Ed25519PublicKey):
            msg = f"{path} is not an Ed25519 public key"
            raise ConfigurationError(msg)
        keys[key_id(key)] = key
    return Verifier(keys)


def generate(private_path: Path, public_path: Path) -> str:
    """Write a new key pair, private at mode 0600; refuse to overwrite either file.

    Returns:
        The new key id.

    Raises:
        ConfigurationError: Either file already exists.
    """
    for path in (private_path, public_path):
        if path.exists():
            msg = f"{path} already exists; a signing key is never overwritten in place"
            raise ConfigurationError(msg)
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_pem)
    public_path.write_bytes(public_pem)
    return key_id(key.public_key())
