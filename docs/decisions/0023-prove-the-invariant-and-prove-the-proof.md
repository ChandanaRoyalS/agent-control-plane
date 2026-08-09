# ADR 0023 — Prove the invariant, then prove the proof

**Status:** accepted
**Date:** 2026-08-09

## Context

Everything this gateway claims reduces to one sentence: **the inbound token
never reaches an upstream.** Policy, budgets, the injection firewall, the audit
log — all of it assumes the upstream is holding a credential the gateway minted
rather than the one the caller presented. If that assumption fails, a
compromised or merely curious upstream can act as the caller everywhere the
caller has access, and this project has not reduced an agent's blast radius; it
has added a hop to it.

Task 27 asserted the property once, on one path: a `tools/list` through a plain
client. That is the route somebody would think to check, and checking it proved
the mechanism works. It says nothing about the retry path, the cached path, the
path where the exchange fails, the path where an upstream authenticates with a
static API key instead, or the path where nobody authenticated at all. Task 30
then added a cache the property now has to hold *across*.

The brief for this task is one line: a test asserting the inbound token never,
under any path, reaches an upstream.

## Decision

**Sweep every path, and scan the whole request.** A matrix of every wrapper
composition, every method on the `Upstream` protocol, and every credential
configuration, driven to a recorder that keeps requests verbatim. Each recorded
request is searched entirely — URL, every header name, every header value, body
— rather than having one header inspected. A token copied into
`X-Forwarded-Authorization`, folded into a query string, or tucked into
`params._meta` beside the trace context would pass a check that reads
`Authorization` and stops.

**Hunt three forms of the token, not one.** The whole string, the payload
segment, and the signature segment. The signature is the unforgeable half, so a
change that forwarded only that is still a leak; the payload is what a
well-meaning "pass the caller's claims through so the upstream can audit them"
change would send. The *header* segment is deliberately excluded: it is
`{"alg","kid"}`, identical for every token this issuer mints, and asserting on
it would report a leak where none exists — a false positive in a security test
is how the test gets disabled.

**Drive it through the real middleware, over HTTP, with a real signed JWT.**
Nothing in the suite calls `bind_subject_token`. A test that binds the inbound
token its own way is exercising a code path that does not exist in production,
and would keep passing after the real one broke. The token enters the way every
token enters: an `Authorization` header on an HTTP request into
`AuthenticationMiddleware`.

**Assert the positive half in the same sweep.** A gateway that sent *no*
credential would pass a pure no-leak test and would have stopped doing its job.
So the sweep also asserts that upstreams received the minted credential, that
the inbound token *did* reach the authorization server as RFC 8693's
`subject_token`, and that at least a floor number of requests actually left the
process — the guard against the most embarrassing possible green suite, which is
one asserting over an empty list.

**Two static alarms, which is the part that outlives this week.** Everything
above proves no *current* path leaks; these make the next path fail the build.

The first: every member of the `Upstream` protocol must be classified as either
swept or incapable of making a request. Add `read_resource` in Phase 3 and the
test fails until somebody says which it is. Without it the sweep silently covers
a smaller fraction of the surface each time the surface grows, which is how a
security test decays into a formality.

The second, and the strongest guarantee in the file: **the set of source files
that call `current_subject_token` must be exactly one.** That function is the
only way to obtain the inbound token, so the set of modules that call it bounds
the set of code that could ever leak it. One file is in the set. A second means
somebody is holding the token somewhere new, which is a design decision that
deserves a conversation rather than a merge. Its mirror asserts one *writer*,
`identity/asgi.py`, so there is no second way for a token to enter the context
without having been validated.

**And prove the proof.** `scripts/mutate_no_passthrough.py` breaks the invariant
three ways — a second header, a log line, the request envelope — and fails the
build unless the suite notices *and the assertion meant to catch it is the one
that fires*. It runs in CI on every pull request.

## Why the mutation harness exists

Because this project has already shipped the alternative. At task 15 it had 297
passing tests and 95% coverage, certifying an MCP client that no real server
would have accepted a single request from. A test that has never been observed
to fail is a claim about the person who wrote it, not a measurement of the
system — and a *security* test that has never been observed to fail is the worst
version of that, because everything downstream is built on believing it.

"Caught by the right assertion" rather than "something went red" is the part
worth the extra code. A mutation caught by an unrelated test is a mutation
caught by accident, and the accident may not recur the next time somebody
rearranges the code.

The harness edits source files in place and restores them in a `finally`, which
is not sufficient on its own — so it refuses to start unless the working tree is
clean, making `git checkout .` a complete recovery if it ever dies badly.

It also neutralises `addopts`, which carries `--cov-fail-under=80`. Running one
file under that threshold fails the run for reasons unrelated to the mutation,
and *every* mutation would then look caught. That is precisely the failure mode
this script exists to detect in somebody else's test, and it would have been
embarrassing to ship it inside the detector.

## Alternatives considered

**Assert on the `Authorization` header only.** Shorter, and it passes against a
gateway that forwards the token in a second header — which is the most likely
way this bug would actually be written, since it arrives as a compatibility
request from an upstream team rather than as a mistake.

**Property-based testing with Hypothesis over request shapes.** Attractive, and
the wrong tool: the interesting variation is in the *gateway's* configuration
and code path, not in the input. Generating random tool arguments explores a
space where no leak lives.

**Static analysis only — no runtime sweep.** The one-reader test is static and
is the strongest single check here, but it bounds who can *obtain* the token,
not what the one permitted reader does with it. Exchange could send the subject
token to the wrong endpoint and the static check would be satisfied.

**Runtime sweep only — no static alarms.** Then every new method, wrapper and
code path is uncovered until somebody remembers, and the suite's coverage of the
property quietly shrinks with every feature.

**Run the mutation harness manually, not in CI.** A step nobody runs is a step
that stops being true. The counter-argument — that it edits source in the
build — is answered by CI checkouts being disposable and by the clean-tree
refusal.

**Ban the leak with a lint rule instead.** A custom ruff rule forbidding imports
of `current_subject_token` outside one module would be enforcement rather than a
test. It is a reasonable future addition; it is not a substitute, because the
sweep catches leaks that involve no new import at all — an exchanged credential
minted for the wrong upstream, for instance, is a leak with a perfectly innocent
import graph.

## Consequences

**The property is now a suite rather than an assertion**, and it names the
scenario and the exact location on failure. "The no-passthrough test failed"
starts an afternoon; "scenario 'a retried call' → header
x-forwarded-authorization" ends one.

**Adding a method to the `Upstream` protocol now requires a decision.** That is
friction, and it is the intended kind: the decision is "can this reach an
upstream", which is exactly what somebody adding an outbound method should have
in mind.

**A second reader of the inbound token is now a build failure.** If a future
task genuinely needs one — a signed request-forwarding mode, say — the fix is to
change the assertion in the same commit, with the reason in the message. That is
the conversation the test exists to force.

**The sweep is driven once per module and shared.** Re-driving the matrix for
each assertion was five times the work for identical traffic, and a slow
security test gets moved out of the fast suite and then out of the habit.

**The unauthenticated case turned out to be two cases.** A caller with no token
where one is required never reaches the handler at all — the middleware refuses
it, so no upstream is contacted. A gateway deliberately configured without a
validator does reach the handler with no principal, which is the state the
background health prober lives in permanently. Both are asserted, separately,
because conflating them would have left the second untested behind a green test.
