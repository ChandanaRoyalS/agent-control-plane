"""An encrypted file of secrets, and the one key that opens it.

Fernet, from `cryptography` — which is already a dependency, because PyJWT
brings it for signature verification. That matters more than it looks: the
alternative to using a vetted authenticated-encryption primitive is composing
one, and the failure mode of composing one is a file that decrypts happily after
somebody has edited it.

**Authenticated, not merely encrypted.** Fernet is AES-128-CBC with an
HMAC-SHA256 over the ciphertext. A file an attacker can *modify* but not read is
still a file they can attack: flip bytes in a credential and see what the
upstream does with the result. The HMAC turns that into a decryption failure
rather than a corrupted secret being sent somewhere.

**The whole document is one ciphertext, not one per entry.** Per-entry would
allow rotating a single secret without rewriting the file, and would leak the
*names* of every secret to anyone holding the file. Names are the useful half
of a reconnaissance find — `stripe-live-key` tells you where to look next, and
the value is useless without the key anyway. Rewriting a small file is cheap;
publishing an inventory is not.

**The key is the remaining problem, and it is deliberately the only one.** It
lives in its own file, referenced by path, so that it can come from a Kubernetes
secret mount, a Docker secret, or a tmpfs the operator populates at boot —
somewhere a runtime puts things, rather than somewhere a person edits them. The
store's honest claim is that it turned N secrets into 1, not that it removed
the last one. See ADR 0021.
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
"""A urlsafe-base64 Fernet key is exactly 44 characters. Checked, because the
failure mode of a truncated key is an exception from deep inside `cryptography`
that names neither the file nor what is wrong with it."""

WORLD_ACCESSIBLE = stat.S_IRWXG | stat.S_IRWXO
"""Any permission bit outside the owner's. A key file readable by the group is a
key file readable by whatever else runs as that group."""


def generate_key() -> str:
    """A new Fernet key, as text. The CLI writes it; nothing else calls it."""
    return Fernet.generate_key().decode()


def read_key(path: Path, *, require_private: bool = True) -> str:
    """Load the key, with the checks whose absence is always regretted.

    Permissions are checked rather than fixed. Silently tightening a file the
    operator created is a change to their system made by a program they ran for
    another reason, and it hides the fact that whatever created it was wrong —
    which is the thing worth knowing, since it will do it again next deploy.
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

    Loaded and decrypted once, at construction, and answered from memory
    thereafter. Two reasons, and the second is the one that matters: a store
    that re-read the file per request would put a disk read and a decryption on
    every upstream call, and — worse — would let the set of secrets change under
    a running gateway without anybody deciding it should. Configuration is read
    at startup here, like everything else.
    """

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    @classmethod
    def open(cls, path: Path, key: str) -> EncryptedFileStore:
        """Read and decrypt the store, or fail with something an operator can act on."""
        try:
            payload = path.read_bytes()
        except OSError as exc:
            msg = f"cannot read the secrets file {str(path)!r}: {exc}"
            raise ConfigurationError(msg) from exc

        secrets = cls._decrypt(payload, key, path)
        logger.info(
            "secrets.loaded",
            extra={
                "path": str(path),
                "count": len(secrets),
                # Names, never values. An operator needs to see that the store
                # holds what the config references; nobody needs the contents in
                # a log, and a log is exactly where a secret survives longest.
                "names": sorted(secrets),
            },
        )
        return cls(secrets)

    @staticmethod
    def _decrypt(payload: bytes, key: str, path: Path) -> dict[str, str]:
        try:
            plaintext = Fernet(key.encode()).decrypt(payload)
        except InvalidToken as exc:
            # One message for two causes, and deliberately so: the wrong key and
            # a tampered file are indistinguishable to Fernet by design, and
            # guessing between them in an error message would be inventing a
            # distinction the cryptography does not make.
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

        Written to a temporary file and renamed, for the reason the schema
        snapshot is: a process killed mid-write must not leave a store that
        decrypts to half a document. Created 0600 *before* anything is written
        to it, because a file that is briefly world-readable while it contains
        secrets is a file that was world-readable.
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
            # Names the store's contents, which is safe and is the only thing
            # that makes this message useful: "no secret named `mock-c-key`;
            # this store has mock-a-key, mock-b-key" is a typo found in one
            # reading.
            msg = (
                f"no secret named {name!r} in the store. It holds: "
                f"{', '.join(sorted(self._secrets)) or '(nothing)'}"
            )
            raise SecretNotFoundError(msg) from exc

    def names(self) -> list[str]:
        return sorted(self._secrets)

    async def aclose(self) -> None:
        """Nothing to release. The decrypted values live for the process's life.

        Worth being explicit rather than leaving the method empty and unexplained:
        they are in memory, they are not wiped, and a core dump contains them.
        Python offers no way to reliably zero a `str`, so pretending otherwise
        with a `del` would be theatre. The mitigation is a runtime that does not
        dump core, which is not something this file can arrange.
        """
        return
