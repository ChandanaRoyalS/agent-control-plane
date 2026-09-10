# ADR 0070 — A refusal is not a symptom

**Status:** accepted
**Date:** 2026-09-10

## Context

Three defects around the circuit breaker, found by a second review. The first is
another instance of this release's recurring pattern: the reasoning was written
down correctly and the code disagreed with it.

**`counts_as_failure` already says 4xx should not count.** Its docstring:

> *Errors the upstream returned deliberately* — a malformed response, a JSON-RPC
> rejection, an unknown tool. These prove the upstream is alive and answering.
> Opening the circuit on them means an agent sending bad arguments can take a
> perfectly healthy upstream offline for everybody, which is a denial of service
> the gateway inflicts on itself.

And `UpstreamClient._parse` mapped **every** 4xx and 5xx to
`UpstreamUnavailableError`, which is `recoverable` — so a client error was
retried three times, counted three times, and opened the breaker in two calls.
The consequences are all reachable by somebody who is not authorised to do
anything:

- a 413 from oversized arguments,
- a WAF's 403,
- a 429, retried into the server that just asked for less,
- and a **401 from the health prober**, which is deliberately uncredentialed
  (ADR 0028). Against a real OAuth-protected upstream the prober is *supposed*
  to be refused, and that refusal withdrew the upstream from every tenant's
  catalogue — for authenticated callers who would have succeeded.

**And a cancelled probe wedged the breaker permanently.** `guard` released with
`await self._leave(exc)` inside `except BaseException`. `_leave` takes the
breaker's lock, and taking an `anyio.Lock` is a checkpoint: under cancellation
it re-raises *before* acquiring, so `_leave` never ran and `_probes_in_flight`
stayed incremented. Every later caller was refused until the process restarted —
the exact failure the context manager exists to prevent, described in its own
docstring two paragraphs above the bug.

Cancellation is not exotic here. A client disconnects, a deadline fires, a task
group unwinds.

## Decision

**Split the mapping by what the status says.** `5xx` remains
`UpstreamUnavailableError`: the upstream is struggling and the breaker should
hear about it. `4xx` becomes `UpstreamRejectedError`, which is not `recoverable`
and does not count as a failure — the upstream received the request and said no,
which is it working.

This closes the prober problem without giving the prober a credential. An
uncredentialed probe against a protected upstream gets a 401, which now means
"alive and refusing me" rather than "down".

**Shield the release.** `with CancelScope(shield=True): await self._leave(exc)`,
on both the exception and the success path. The bookkeeping completes even when
the surrounding task is being torn down.

## Alternatives considered

**Give the health prober a service credential.** Fixes the 401 case and none of
the others, and reintroduces the thing ADR 0028 removed: a credential held by
the gateway for its own use. A probe that authenticates is also a probe that
stops testing the unauthenticated path.

**Exclude only 401, 403, 413 and 429 by status code.** A list of the statuses
somebody thought of, which is how this arrived. `4xx` versus `5xx` is the
distinction HTTP already draws and the one `counts_as_failure` is reasoning
about.

**Do the release bookkeeping synchronously, without the lock.** Removes the
checkpoint and races every other state transition. The lock is not incidental.

**`finally` instead of a shield.** `finally` runs, and the `await` inside it is
still a checkpoint under an active cancellation, so it does not help. The shield
is what makes the await complete.

## Consequences

A tool that reliably returns 4xx no longer opens its upstream's circuit, so a
genuinely misconfigured upstream — wrong URL answering 404 to everything — now
fails every call individually instead of being withdrawn after two. That is the
correct trade for a control whose false positive is "withdraw a healthy upstream
from everybody", but it is a real change: the breaker no longer protects against
an upstream that is up and useless.

Callers see a different error class for 4xx. `UpstreamRejectedError` maps to a
different MCP code than `UpstreamUnavailableError`, and it carries the HTTP
status as `upstream_code` — which is more information than the old flattening
gave, not less.

Both fixes are asserted by tests that fail against the previous implementation:
the cancellation test with `UpstreamCircuitOpenError` on a breaker that should
have reset, and the classification test across six 4xx statuses.

What would make us revisit: an upstream whose 4xx storm is genuinely a health
signal. The answer then is a separate rate-of-rejection alarm, not the breaker —
they are different questions and one control cannot answer both.
