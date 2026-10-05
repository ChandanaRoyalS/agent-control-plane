"""Signed audit entries (ADR 0078): what a key-less writer to the file can no longer do.

The chain alone lets anyone who can write the file rewrite it consistently. Each test
below is one such rewrite, and the assertion is that a verifier holding the public key
names it.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acp.audit.chain import Chain, link, verify
from acp.audit.cli import BROKEN, OK, keygen_command, verify_command
from acp.audit.record import AuditRecord, Category, Outcome
from acp.audit.signing import Signer, Verifier, generate, load_signer, load_verifier
from acp.audit.sink import FileAuditSink, MemoryAuditSink
from acp.exceptions import ConfigurationError


def record(index: int) -> AuditRecord:
    return AuditRecord(
        category=Category.TOOL_CALL,
        event="tool.called",
        at=1786600000.0 + index,
        subject="alice",
        tenant="acme",
        tool="mock-a__search",
        outcome=Outcome.COMPLETED,
    )


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Signer, Verifier, Path]:
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    generate(private, public)
    return load_signer(private), load_verifier([public]), public


def signed_lines(signer: Signer, count: int = 3) -> list[str]:
    sink = MemoryAuditSink(signer=signer)
    for i in range(count):
        sink.append(record(i))
    return sink.lines()


def reasons(lines: list[str], verifier: Verifier) -> list[str]:
    return [b.reason for b in verify(lines, verifier=verifier).breaks]


# -- what a writer without the key cannot do ---------------------------------


def test_a_signed_chain_verifies(keys: tuple[Signer, Verifier, Path]) -> None:
    signer, verifier, _ = keys
    result = verify(signed_lines(signer), verifier=verifier)

    assert result.intact
    assert result.signed == 3
    assert "all 3 signatures valid" in result.describe()


def test_a_consistent_rewrite_without_the_key_is_caught(
    keys: tuple[Signer, Verifier, Path],
) -> None:
    """The attack the chain alone cannot see: change a record and recompute every
    hash from there on. Without the key, the signatures cannot follow."""
    signer, verifier, _ = keys
    entries = [json.loads(line) for line in signed_lines(signer)]
    entries[1]["record"]["subject"] = "mallory"
    head = entries[0]["hash"]
    for entry in entries[1:]:
        entry["prev"] = head
        entry["hash"] = link(prev=head, seq=entry["seq"], payload=entry["record"])
        head = entry["hash"]
    lines = [json.dumps(e) for e in entries]

    assert verify(lines).intact, "the hash chain alone accepts this rewrite"
    assert reasons(lines, verifier) == [
        "signature does not verify under key " + signer.kid,
        "signature does not verify under key " + signer.kid,
    ]


def test_stripping_signatures_is_caught(keys: tuple[Signer, Verifier, Path]) -> None:
    signer, verifier, _ = keys
    entries = [json.loads(line) for line in signed_lines(signer)]
    del entries[2]["sig"], entries[2]["kid"]

    assert reasons([json.dumps(e) for e in entries], verifier) == ["entry is not signed"]


def test_an_unsigned_chain_fails_when_signatures_are_required(
    keys: tuple[Signer, Verifier, Path],
) -> None:
    _, verifier, _ = keys
    sink = MemoryAuditSink()
    sink.append(record(0))

    assert reasons(sink.lines(), verifier) == ["entry is not signed"]


def test_another_key_is_not_accepted(tmp_path: Path, keys: tuple[Signer, Verifier, Path]) -> None:
    _, verifier, _ = keys
    generate(tmp_path / "other.pem", tmp_path / "other.pub")
    other = load_signer(tmp_path / "other.pem")

    [reason] = reasons(signed_lines(other, 1), verifier)
    assert "not one of the keys given" in reason


def test_one_file_one_key(tmp_path: Path, keys: tuple[Signer, Verifier, Path]) -> None:
    """With both public keys given, an entry signed by a second key still breaks the
    file: a retired or leaked key cannot be spliced into a later chain."""
    signer, _, public = keys
    generate(tmp_path / "other.pem", tmp_path / "other.pub")
    other = load_signer(tmp_path / "other.pem")
    both = load_verifier([public, tmp_path / "other.pub"])
    chain = Chain(signer=signer)
    first = chain.append(record(0))
    second = Chain(head=first.hash, seq=first.seq, signer=other).append(record(1))
    lines = [json.dumps(first.as_dict()), json.dumps(second.as_dict())]

    [reason] = reasons(lines, both)
    assert f"this file's entries use {signer.kid}" in reason


def test_without_a_key_signatures_are_counted_not_checked(
    keys: tuple[Signer, Verifier, Path],
) -> None:
    signer, _, _ = keys
    result = verify(signed_lines(signer))

    assert result.intact
    assert "3 signed (not checked: no public key given)" in result.describe()


def test_an_unsigned_entry_is_written_exactly_as_before() -> None:
    entry = Chain().append(record(0))

    assert set(entry.as_dict()) == {"seq", "prev", "hash", "record"}


def test_half_a_signature_is_not_an_entry(keys: tuple[Signer, Verifier, Path]) -> None:
    signer, _, _ = keys
    entry = json.loads(signed_lines(signer, 1)[0])
    del entry["kid"]

    assert verify([json.dumps(entry)]).unreadable == 1


# -- keys --------------------------------------------------------------------


def test_the_private_key_is_written_owner_only(tmp_path: Path) -> None:
    private = tmp_path / "key.pem"
    generate(private, tmp_path / "key.pub")

    assert stat.S_IMODE(private.stat().st_mode) == 0o600


def test_a_key_is_never_overwritten(tmp_path: Path) -> None:
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    generate(private, public)
    before = private.read_bytes()

    with pytest.raises(ConfigurationError, match="never overwritten"):
        generate(private, tmp_path / "elsewhere.pub")
    assert private.read_bytes() == before


def test_a_key_of_another_type_is_refused(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "ec.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = tmp_path / "ec.pub"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    with pytest.raises(ConfigurationError, match="not an Ed25519 key"):
        load_signer(path)
    with pytest.raises(ConfigurationError, match="not an Ed25519 public key"):
        load_verifier([public])


@pytest.mark.parametrize("content", [b"", b"not a key"])
def test_garbage_is_not_a_key(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.pem"
    path.write_bytes(content)

    with pytest.raises(ConfigurationError, match="not an unencrypted PEM private key"):
        load_signer(path)
    with pytest.raises(ConfigurationError, match="not a PEM public key"):
        load_verifier([path])


def test_a_missing_key_file_names_its_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"nothing\.pem"):
        load_signer(tmp_path / "nothing.pem")
    with pytest.raises(ConfigurationError, match=r"nothing\.pub"):
        load_verifier([tmp_path / "nothing.pub"])


# -- the file: one key per file ----------------------------------------------


def test_a_signed_file_resumes_under_its_key(
    tmp_path: Path, keys: tuple[Signer, Verifier, Path]
) -> None:
    signer, verifier, _ = keys
    path = tmp_path / "audit.jsonl"
    for i in range(2):
        sink = FileAuditSink(path, fsync=False, signer=signer)
        sink.append(record(i))
        sink.close()

    assert verify(path.read_text().splitlines(), verifier=verifier).intact


def test_signing_does_not_start_midway_through_a_file(
    tmp_path: Path, keys: tuple[Signer, Verifier, Path]
) -> None:
    signer, _, _ = keys
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path, fsync=False)
    sink.append(record(0))
    sink.close()

    with pytest.raises(ConfigurationError, match="holds unsigned entries"):
        FileAuditSink(path, fsync=False, signer=signer)


def test_a_missing_key_is_not_a_silent_downgrade(
    tmp_path: Path, keys: tuple[Signer, Verifier, Path]
) -> None:
    signer, _, _ = keys
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path, fsync=False, signer=signer)
    sink.append(record(0))
    sink.close()

    with pytest.raises(ConfigurationError, match="no signing key"):
        FileAuditSink(path, fsync=False)


def test_a_new_key_starts_a_new_file(tmp_path: Path, keys: tuple[Signer, Verifier, Path]) -> None:
    signer, _, _ = keys
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path, fsync=False, signer=signer)
    sink.append(record(0))
    sink.close()
    generate(tmp_path / "new.pem", tmp_path / "new.pub")

    with pytest.raises(ConfigurationError, match="Rotating a key starts a new file"):
        FileAuditSink(path, fsync=False, signer=load_signer(tmp_path / "new.pem"))


# -- the commands --------------------------------------------------------------


def test_keygen_then_verify(tmp_path: Path) -> None:
    out: list[str] = []
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    assert keygen_command(private_path=private, public_path=public, out=out.append) == OK
    assert "mounted secret" in " ".join(out)

    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path, fsync=False, signer=load_signer(private))
    sink.append(record(0))
    sink.close()
    shown: list[str] = []

    assert verify_command(path, public_keys=[public], out=shown.append) == OK
    assert any(line.startswith("keys:") for line in shown)


def test_verify_fails_an_unsigned_log_when_given_a_key(
    tmp_path: Path, keys: tuple[Signer, Verifier, Path]
) -> None:
    _, _, public = keys
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path, fsync=False)
    sink.append(record(0))
    sink.close()

    assert verify_command(path, public_keys=[public], out=lambda _: None) == BROKEN
