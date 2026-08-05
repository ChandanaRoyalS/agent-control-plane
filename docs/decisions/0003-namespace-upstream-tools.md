# ADR 0003 — Namespace upstream tools with a double underscore

**Status:** accepted
**Date:** 2026-08-10

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
