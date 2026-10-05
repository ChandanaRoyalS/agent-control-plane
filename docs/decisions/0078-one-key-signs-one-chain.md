# ADR 0078 — One key signs one chain

**Status:** accepted
**Date:** 2026-10-05

## Context

The audit chain (ADR 0050) proves a file is self-consistent. Anyone who can
write the file can change a record and recompute every hash after it, and
`acp audit verify` accepts the result. A checkpoint (also ADR 0050) catches that
up to the last anchored entry, and only if someone took one.

Signing was deferred because it is a key-management decision before it is code:
where the key lives, who holds it, how it changes, and what a verifier is told to
trust. This ADR makes those decisions.

## Decision

**Algorithm.** Ed25519 over each entry's hash, with a fixed domain prefix
(`acp-audit-entry-v1\0`) so an audit signature cannot be reused as anything else.
The hash already commits to the record, its position and the previous entry, so
signing it signs all of that. The entry gains two fields, `sig` (base64url) and
`kid` (the first 16 hex characters of the SHA-256 of the raw public key). They
are outside the hash; an unsigned entry is written exactly as before.

**Where the private key lives.** In a file the gateway reads once at startup,
named by `ACP_AUDIT_SIGNING_KEY_FILE`, mounted as a secret. Never under
`config/` (which is committed and baked into the image) and never in an
environment variable. `acp audit keygen` writes it at mode 0600 and refuses to
overwrite an existing key. A missing, unreadable, encrypted or non-Ed25519 key
stops the gateway at startup.

**Where the public key lives.** Committed, by default as
`config/audit-signing.pub`, beside the checkpoint. When that file exists,
`acp audit verify` uses it and requires a valid signature on every entry;
`--public-key` names others. Publishing it costs nothing, and committing it is
what turns "signatures exist" into "signatures are required".

**One key signs one file, from its first entry.**

- The gateway refuses to continue a chain file whose last entry was signed by
  another key, or not signed at all. Turning signing on, or rotating the key,
  therefore starts a new `ACP_AUDIT_FILE`; the old file is checkpointed and
  archived with the public key that verifies it.
- The gateway also refuses to continue a signed file without a key. A
  forgotten setting would otherwise be a silent downgrade to unsigned entries.
- `verify` requires every entry in a file to carry the same key id. A retired
  or leaked key cannot be spliced into a later file even if its public key is
  still on the verifier's list.

## What this does and does not protect

| an attacker who can | without signatures | with signatures |
|---|---|---|
| edit the file (backup, shared volume, log shipper) but not read the key | rewrite any entry consistently | cannot change or add an entry; any edit breaks verification |
| strip signatures to pass as an unsigned chain | n/a | caught: every entry must be signed |
| delete the tail | undetected without a checkpoint | **still undetected** without a checkpoint |
| read the key (or control the running gateway, which holds it) | rewrite anything | **rewrite anything** in files signed by that key |

A signature moves the question from "who can write the file" to "who holds the
key". It does not answer it: the gateway must hold the key to sign, so a
compromised gateway can sign whatever it likes. Truncation still needs a
checkpoint stored where the gateway cannot reach. The two controls cover
different things and are meant to be used together.

**Cost.** About 47 µs per entry on top of the hash (55 µs against 8 µs,
measured in-process). With `fsync` on, the disk dominates either way.

## Consequences

- New setting `ACP_AUDIT_SIGNING_KEY_FILE`, new command `acp audit keygen`, and
  `acp audit verify --public-key`: a minor version under ADR 0058. Entries gain
  two optional fields; existing unsigned files verify as before.
- The startup line `audit.enabled` names the key id; the control banner gains
  `audit_signing`.
- The compose stack stays unsigned: committing a private key, even a
  development one, would teach the wrong thing.
- `cryptography` becomes a declared dependency; it was already installed
  through `pyjwt[crypto]`.

## Alternatives considered

- **Sign periodic checkpoints instead of entries.** Cheaper, but entries
  between checkpoints stay rewritable, which is the gap this closes.
- **HMAC with a shared secret.** A verifier would need the secret, and anyone
  who can verify could forge.
- **Allow several keys in one file for rotation.** A key change would then be
  something an attacker with an old key could imitate. A new file per key is
  simpler to reason about and costs one archived file per rotation.
- **A KMS or HSM.** The right answer for a real deployment, and a different
  `Signer` behind the same interface; out of scope for a file-based reference
  implementation.

## References

- ADR 0050 — the audit record, the chain and checkpoints
- ADR 0058 — the versioned surface
- `src/acp/audit/signing.py`, `src/acp/audit/sink.py`, `src/acp/audit/chain.py`
