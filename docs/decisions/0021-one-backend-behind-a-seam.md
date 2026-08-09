# ADR 0021 — One backend, behind a seam, and an honest claim about what it buys

**Status:** accepted
**Date:** 2026-08-09

## Context

Task 27 removed nearly every secret this gateway had. It mints an upstream
credential per call and keeps none, so there is no long-lived credential to
store, rotate, leak or audit. That is the right answer wherever it is available.

It is not always available. An upstream may authenticate with an API key issued
out of band, belong to a team with no OAuth integration, or be vendor software
that will never learn RFC 8693. Before this task such an upstream could not be
configured *at all*: task 27 made `audience` mandatory once exchange is on,
which is correct for anything that can exchange and a wall for anything that
cannot.

The brief says: encrypted local backend behind an interface that would accept
Vault or Secrets Manager later; ship one backend well rather than three badly.

## What a secret store actually buys

Worth stating plainly, because the honest version is narrower than the phrase
suggests and this project does not get to hand-wave about security controls.

**It reduces many secrets to one.** N credentials become one key. That is the
whole mechanism. Everything else follows from it.

**What that defends against:** a stray copy of a config directory; a backup; a
support bundle; a repository somebody cloned; a value that would otherwise sit
in the process environment where anything that can read `/proc` can see it.
These are the ways secrets actually leak, and they leak in bulk.

**What it does not defend against:** root on the box. The running process. A
core dump. Anyone who can read the key file. The decrypted values live in
memory for the process's lifetime, and Python offers no way to reliably zero a
`str` — a `del` would be theatre, so `aclose()` says so in a comment rather than
performing one.

The claim is "fewer places for a credential to be lying around", not "safe".

## Decision

**Fernet, from `cryptography`.** Already a dependency, because PyJWT brings it
for signature verification. AES-128-CBC with an HMAC — *authenticated*, which
matters: a file an attacker can modify but not read is still one they can
attack. Flip bytes inside a credential and watch what the upstream does with the
result. The HMAC turns that into a decryption failure instead.

**One ciphertext for the whole document, not one per entry.** Per-entry would
allow rotating a single secret without rewriting the file, and would publish an
inventory of *names* to anyone holding it. Names are the useful half of a
reconnaissance find — `stripe-live-key` tells you where to look next, and the
value is unreadable anyway. Rewriting a small file is cheap; publishing an
index is not.

**The key lives in its own file, referenced by path.** So it can come from
wherever a runtime puts secrets — a Kubernetes secret mount, a Docker secret, a
tmpfs populated at boot — rather than from somewhere a person edits. Startup
refuses a key readable beyond its owner, and *reports* rather than fixes the
permissions: silently tightening a file the operator created is a change to
their system made by a program run for another reason, and it hides that
whatever created it was wrong, which is the part that recurs next deploy.

**References in config, never values.** `credential_ref` names a secret; the
value is in the store. A credential in `upstreams.yaml` is a credential in git,
in every backup of it, and in the diff of whoever added it.

**`audience` and `credential_ref` are mutually exclusive**, refused by the
config model. Both set is not a richer configuration but an ambiguous one: two
mechanisms each wanting to own the same header, resolved by whichever branch
runs first — a coin toss decided in code rather than by the person deploying.

**Secrets are resolved at startup**, before a port is bound. The request path
holds a string, not a store. A missing secret is a configuration error that
stops a deployment, not a request that reaches an upstream with nothing.

## Why an interface for one backend

Because the *good* answer is to not have a key at all: a workload identity that
Vault or a cloud secrets manager exchanges for a short lease, with nothing
durable on disk. That eliminates the residual problem this ADR just admitted to
having.

It is also a deployment this project cannot build or test here, and a
half-working adapter for it would be worse than none — it would look like
support. So the seam goes in the right place and the swap is one class:
`SecretStore` is a `Protocol` with `get`, `names` and `aclose`, and it is
**async** despite the file backend having nothing to await. A Vault store
fetches, leases and renews; a synchronous interface would force that onto a
thread or into a constructor, and retrofitting async into an interface is a
change to every caller.

## Alternatives considered

**Put the values in `upstreams.yaml` and rely on file permissions.** The
simplest thing, and it puts credentials in git the first time somebody commits
their config. The reference indirection exists for that one reason.

**Use the existing secrets *directory* (`/run/secrets`) for these too.** It
already works and pydantic-settings already reads it — it is how the gateway's
own OAuth client secret arrives, and that has not changed. It stops being enough
when the number of secrets is per-upstream rather than fixed: a directory is a
delivery mechanism, not a thing an operator can inventory, rotate or hand to a
colleague with one command. Both exist, for the two different shapes of problem.

**Encrypt per entry so one secret can be rotated in place.** Publishes the
inventory, as above. Rotation rewrites a file measured in kilobytes.

**Roll a simple XOR or an unauthenticated AES mode.** The reason not to is the
tamper test in this task's suite: unauthenticated encryption gives a file that
decrypts happily after being edited, and a corrupted credential sent to an
upstream is a strictly worse outcome than a refusal.

**A `get` command in the CLI.** Deliberately absent. A command that prints a
credential to a terminal is one that eventually prints it into a screen-share, a
scrollback buffer or a support ticket. The store exists so the value has exactly
one destination, and adding a second for convenience would undo it.

**Take the value as a command-line argument.** It would then live in shell
history, in the process table for the duration, and in any audit log that
records command lines. `acp secrets set` reads from a prompt when there is a
terminal and from stdin when there is not — the second is what makes it usable
from a deployment script.

**Put the CLI logic in `acp.cli`.** That module imports the MCP SDK, which the
environment this is authored in cannot install, so anything there is untestable
*and* untype-checkable until it reaches Chandana's machine — the cause of three
shipped bugs so far. `acp.secrets.cli` holds every decision and has tests;
`acp.cli` holds argparse wiring.

## Consequences

**An upstream that cannot exchange can finally be configured**, which is the
practical point of the task. `credential_header` and `credential_scheme` are
configurable because `Authorization: Bearer` is right for anything OAuth-shaped
and wrong for a great many real APIs — and a gateway that only brokers for
servers which agreed on a convention has missed its own premise.

**The `Credentials` protocol is untouched.** A static credential is resolved at
startup and handed to the client as a string; it never goes through the exchange
path, which keeps token exchange free of a branch for "except when there isn't
one".

**`.gitignore` grew three lines.** The store is ciphertext, so committing it
would not expose a value directly — it would put every credential the gateway
holds into every clone, every fork and every backup, waiting for the key to leak
once.

**The residual key is documented, not hidden.** SECURITY.md lists it. An ADR
that claimed this made secrets safe would be the kind of reassurance that gets
believed and then relied on.
