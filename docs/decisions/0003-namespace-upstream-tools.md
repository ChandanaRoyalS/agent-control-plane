# ADR 0003 — Namespace upstream tools with a double underscore

**Status:** amended 2026-08-05
**Date:** 2026-08-10

> **Amendment (2026-08-05):** the truncation rule below is kept, with two
> corrections learned from implementing it.
>
> **Truncate the tool half, never the upstream half.** The original text said
> "truncate the upstream segment", which would make routing impossible — the
> upstream name is the one part that must survive intact. Combined with the
> config rule forbidding underscores in upstream names, splitting on the first
> `__` now recovers the upstream exactly, always, even from a truncated name.
>
> **Cap upstream names at 24 characters** (`MAX_UPSTREAM_NAME_LENGTH`). This
> leaves 38 for the tool half within the 64-character budget, making truncation
> rare rather than routine. Without it, a long upstream name would force a
> catalogue lookup on every single call.
>
> **Truncation cannot be detected from the name — only ruled out.** Truncated
> names are always exactly 64 characters by construction, so anything shorter is
> certainly intact and resolves with no lookup at all. Names at exactly the limit
> are genuinely ambiguous (a tool may legitimately be named that long) and are
> resolved through the upstream's catalogue rather than guessed at, because a
> wrong guess invokes a different tool than the caller asked for.
>
> An earlier attempt detected truncation by re-qualifying the suffix and
> comparing. That is always false — a truncated name is itself under the limit,
> so re-qualifying it is a no-op. A randomised check over 200,000 name pairs
> caught it; the idea is recorded here because it is superficially convincing.

## Context

The gateway merges tool catalogs from several upstream MCP servers into one
catalog presented to the agent. Two upstreams can legitimately expose a tool
with the same name, so names must be qualified by their source.

Two constraints apply. Tool names have a restricted character set, and `.`, `/`
and `:` are not reliably legal across MCP clients. Separately, several clients
impose a length cap on tool names in the region of 64 characters, so a long
upstream name concatenated with a long tool name can silently exceed the limit
and break in ways that are hard to trace back.

## Decision

Qualify every upstream tool as `<upstream>__<tool>`, using a double underscore.

When the qualified name would exceed 64 characters, truncate the upstream
segment and append a short deterministic hash of the full qualified name, so the
result is stable across restarts and still unique.

## Alternatives considered

**`.` or `/` as the separator.** Rejected — not reliably accepted by all clients,
and the failure mode is a client-side validation error that surfaces far from
the cause.

**Only qualify names that actually collide.** Rejected. Tool names would then
change when an unrelated upstream is added, which silently breaks any agent
prompt or policy rule referring to the old name. Uniform qualification is
predictable; conditional qualification is a trap.

**Hash every name unconditionally.** Rejected — opaque names make traces, logs
and policy files unreadable by humans, which costs more than it saves.

## Consequences

Tool names are stable, human-readable, and independent of which other upstreams
happen to be configured.

Names are longer, and the truncation rule is a piece of behaviour that must be
tested directly rather than assumed.

Policy rules and audit records reference qualified names, so the upstream a call
targeted is legible without a join.
