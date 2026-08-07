# ADR 0012 — Honour upstream cache hints, within limits we set

**Status:** accepted
**Date:** 2026-08-07

## Context

The 2026-07-28 revision puts two fields at the top level of every cacheable
result: `ttlMs`, how long the response may be held, and `cacheScope`, either
`public` or `private`. Both default to the conservative answer — zero, and
private — so caching is something an upstream opts into rather than something a
client assumes.

The obvious reason to implement this is the small one: a `tools/list` served
from memory rather than a round trip.

The reason that matters is one layer further out. An agent's prompt *contains*
its tool list. A catalogue that changes between turns misses the model
provider's prompt cache, and the entire prompt is re-processed and re-billed. A
catalogue stable for five minutes is not a latency improvement; it is the
difference between paying for those tokens once and paying for them every turn.
Stability here is a cost decision wearing performance clothes.

`cacheScope` is a third thing again, and not a performance concern at all. The
SDK's own client cache says it outright: only `public` entries may be shared
across authorization contexts. A `private` catalogue is one the upstream
computed *for a particular caller*.

## Decision

A `CachingUpstreamClient` wraps each upstream, outermost in the stack. It holds
a `tools/list` result for the TTL the upstream advertised, clamped to a
configured maximum, and **only** when the response is `public`.

`Upstream` gains `invalidate()`. The gateway composes its own hint for the
merged catalogue: the minimum TTL of the contributors, `public` only if all of
them were, and zero whenever anything failed or was withdrawn.

## Alternatives considered

**Cache the merged catalogue instead of each upstream.** One entry rather than
several, and it breaks the interaction with task 18. Merging is cheap and
fetching is not, so caching per-upstream keeps the expensive part cached while
withdrawal still applies fresh at merge time. A merged cache would have to be
invalidated on every health transition, which is a subscription this layer
should not need.

**Cache `private` responses too, since there is only one caller today.** True
today and a trap. There is no principal yet — identity is task 22 — so a private
entry in a shared cache is currently harmless and would become a cross-principal
leak the moment identity lands, silently, in a module nobody was editing at the
time. Caching `public` only is correct now *and* correct later; when identity
arrives, the key gains the principal and `private` becomes cacheable
per-principal rather than not at all. This is the same failure task 44 exists to
prevent, arriving early and quietly.

**Trust the upstream's TTL unclamped.** It is a hint from a system the gateway
does not control. An upstream advertising twenty-four hours, by bug or by
design, would freeze its catalogue for twenty-four hours and the gateway would
keep offering tools that had stopped existing. The ceiling matches the SDK's own
`MAX_TTL_MS` and is pinned to it by test.

**Treat an explicit `ttlMs: 0` as "no hint" and apply a configured default.**
What the first implementation did, and wrong. The SDK draws the distinction
explicitly — "an explicit `ttlMs: 0` stays 0" — and conflating them means
caching a catalogue whose owner said, in as many words, not to. Pydantic's
`model_fields_set` is what tells an explicit zero from a field nobody sent.

**Serve a stale entry when the upstream is failing.** Superficially attractive:
the agent keeps its tools during a blip. It directly contradicts task 18, which
withdraws an unhealthy upstream precisely so the agent stops calling tools that
cannot work. A cache entry is a claim about freshness, not a consolation prize.

**Cache tool *results* as well.** That is task 43, and it needs the
per-principal key this layer deliberately does not have. Caching an action is
also a different kind of mistake from caching a lookup: a stale `search` is
merely wrong, a cached `create_ticket` is a ticket that never got filed.

**Advertise a fixed TTL on our own catalogue.** Simpler than composing one, and
it would promise durability the gateway cannot deliver. A merge is only as
durable as its shortest-lived component, so the composed TTL is the minimum; and
one `private` contributor makes the whole merge private, because scope is a
boundary and boundaries do not average.

## Consequences

A degraded catalogue advertises `ttlMs: 0`. That is deliberate and worth
stating: the upstream most likely to change in the next minute is the one that
is currently broken, and freezing a reduced tool list into an agent's prompt is
how a recovered upstream stays invisible long after it came back.

`Upstream.list_tools()` now returns a `ListToolsResult` rather than a list. That
rippled through the registry, the health monitor, both resilience wrappers and
several tests — a real cost, accepted because the alternative was stashing the
hints on the client as mutable state and reading them back out, which is a race
waiting to be written.

`invalidate()` on the protocol is what lets the health monitor force a real
request without knowing which wrappers are present. A probe answered from cache
would report on a conversation that happened minutes ago. It has a pleasant side
effect: the prober repopulates the cache, so the background loop keeps it warm.

The mocks now advertise a sixty-second TTL, which makes the behaviour observable
in a demo. A real upstream picks that number from how often its catalogue
actually changes.
