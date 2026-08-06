# ADR 0007 — Structured logging on the standard library

**Status:** accepted
**Date:** 2026-08-06

## Context

Everything built so far logs in sentences: `upstream mock-a failed during
tools/list: connection refused`. That is readable and unqueryable. Nobody can
count failures per upstream without a regular expression, and the regular
expression breaks the first time someone rewords the message.

A gateway makes this worse than it is for an ordinary service. One inbound
`tools/call` fans out to a catalogue lookup, one or more upstream requests, a
retry, and a breaker decision — potentially across several concurrent tasks. Log
lines that cannot be joined back to a single request are close to useless once
more than one agent is connected, and "more than one agent is connected" is the
entire point of the thing.

There is also a security dimension. From task 22 the gateway holds upstream
credentials and forwards agent identity. Anything that reaches a log reaches a
log aggregator, which is typically readable by more people than the secret store
is, and cannot be un-written.

## Decision

Structured logging built directly on `logging`, in `acp.observability`:

- **Events, not sentences.** The message is a stable identifier —
  `upstream.call`, `breaker.opened`, `http.request` — and everything variable
  goes in `extra=`.
- **Request-scoped context via `contextvars`**, merged onto every record by a
  `logging.Filter` on the handler.
- **A redaction pass inside both formatters**, matching secret-shaped keys as
  substrings of a normalised key name, at every depth of a nested structure.
- **JSON when stderr is not a terminal, human-readable when it is.**

## Alternatives considered

**structlog.** The standard answer, and a good library. Rejected for three
reasons. Every other library in the stack — httpx, uvicorn, the MCP SDK — logs
through `logging`, so a bridge from the standard library is needed regardless;
structlog would add a second pipeline rather than replace one. It is a
dependency in a project that is deliberately thin on them. And the ~150 lines it
saves are the lines that demonstrate the thing actually worth demonstrating:
that records, filters, handlers and formatters are understood rather than
configured. Revisit if the processor chain grows past what a single formatter
can express cleanly.

**Threading a request ID through every function signature.** Explicit, and
honest about the data flow. Rejected because it puts a logging concern into the
signature of every function it passes through, including `UpstreamClient`, whose
whole virtue is that it does one small thing. It also cannot survive a fan-out
without being re-threaded through the task group.

**A module-level global for the current request.** Works in a synchronous
single-threaded program and silently corrupts under concurrency, which here
means as soon as two agents connect. `contextvars` is the version of this idea
that is actually correct: values are copied into a task when it is *created*, so
a fan-out inherits the request ID while anything a child binds stays in the
child.

**Starlette's `BaseHTTPMiddleware`.** Fewer lines than raw ASGI. It runs the
downstream app in a separate task and pumps the response through a memory
stream, which breaks streaming responses — and MCP's streamable HTTP transport
is a streaming transport. Raw ASGI middleware is about thirty lines and has none
of those problems.

**Redacting by exact key match against a list.** Predictable and quietly
useless: `x-api-key`, `apiKey`, `refresh_token` and `clientSecret` are all the
same secret wearing different clothes, and the list is only ever updated after
something has already leaked. Substring matching on a normalised key
over-redacts instead, which is the correct direction to fail — a false positive
costs one confusing debugging session, a false negative cannot be taken back.

**Redacting at the call site.** Puts the guarantee in the hands of whoever
writes the next `logger.info`. Doing it in the formatter makes it a property of
the pipeline rather than a convention.

## Consequences

Every log line can be filtered by `upstream`, `tool`, `outcome`, `duration_ms`
and `request_id`, and every line produced while serving one request shares that
ID — including lines from tasks the request fanned out into. Tasks 16 and 17
inherit the context module rather than inventing their own: a trace ID becomes
another bound field, and the metric names fall out of the event names already
chosen here.

`httpx` and `httpcore` are turned down to WARNING, because the gateway now logs
its own upstream calls with more context than the library can. Anyone debugging
transport-level behaviour has to turn them back up deliberately.

The cost is ownership: `_RESERVED` is a hand-maintained list of the attributes
the `logging` module puts on a record, and a future Python that adds one would
leak it into the payload until the list is updated. That is a real maintenance
edge, accepted because the standard library adds record attributes roughly once
a decade and the failure is cosmetic.

One behaviour is worth recording because a test initially got it wrong. The
context filter must be attached to the *handler*, and it reads contextvars in
the task that logged the line. Applying it to a captured record later reads an
empty context, because the task that had the request scope has long since
finished.
