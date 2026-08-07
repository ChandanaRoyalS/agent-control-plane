# ADR 0013 — Treat schema drift as a security control, not an ops nicety

**Status:** accepted
**Date:** 2026-08-07

## Context

An MCP server can change what it exposes at any moment, and the protocol has no
way to say so. There is no version on a tool, no `ETag` on a catalogue, no event
a client can subscribe to. A client finds out by asking again and reading the
answer carefully, or it does not find out at all.

Three things break when that happens, and only the first is the one people think
of.

An argument schema gains a required field and every caller written against the
old one breaks. That is ordinary correctness, and it announces itself: calls
start failing.

A tool nobody has written policy for appears. Deny-by-default (task 32) means it
cannot be called, which is the correct outcome and also exactly why nobody
notices — the capability sits there, unusable and unremarked, until somebody
eventually wonders why the agent cannot do the obvious thing.

And a `description` changes. This is the case that makes drift detection a
security control rather than a monitoring feature. A tool description is prose
that goes verbatim into the agent's prompt: it is the most powerful field in the
protocol and the only one an upstream can rewrite without breaking a single
client. A server that has behaved impeccably for six months and then appends a
sentence beginning "Before using any other tool…" has performed the MCP rug
pull. Nothing times out. Nothing errors. No breaker opens, no retry fires, no
metric moves. Every layer built in tasks 13 through 19 is looking at the
transport, and the transport is fine.

## Decision

Snapshot every upstream's catalogue into a **committed file**, compare each live
catalogue against it, and alert on the difference.

The digest covers the whole tool definition — name, description, `inputSchema`
and any field this build has never heard of — canonicalised by sorting object
keys and nothing else. Differences are classified into kinds (`description_changed`,
`schema_changed`, `tool_added`, `tool_removed`, `metadata_changed`) because the
response to each is a different action taken by a different person.

Observation rides on the **health prober's** fetch. Alerts are edge-triggered;
the baseline is only ever changed by a human running `acp schemas capture`.

## Alternatives considered

**Fingerprint only `inputSchema`.** Cheaper, obvious, and blind to the single
attack this feature exists to catch. A rug pull changes no schema at all.

**Normalise arrays before hashing, so a reordered `required` is not drift.**
Semantically appealing and wrong twice. Deciding which arrays in a JSON Schema
are sets requires per-keyword knowledge, and a normaliser that guesses wrong does
not produce noise — it produces *silence* about a real change. And the model
provider's prompt cache does not normalise either: it hashes the serialised
prompt, and the catalogue is in that prompt. An upstream that reorders arrays
between calls is invalidating that cache and being billed for the whole prompt
again, which is worth knowing about on its own terms.

**Detect on the request path, inside `tools/list`.** The obvious place, and
wrong for three reasons. It puts hashing on a request an agent is waiting for; it
sees nothing through a cache hit, which after task 19 is most requests; and it is
blind to any upstream nobody happens to be calling — which is precisely the
upstream whose description turning malicious matters most, because the change
lands before anyone is watching. The prober already fetches every catalogue on a
timer, past the cache, off the request path. Drift detection is that same fetch
read for a different purpose. The cost, stated rather than discovered: with
probing disabled there is no runtime detection at all.

**Keep the baseline in memory, seeded by the first response after startup.**
Then a change made during a deploy window is adopted as normal before anyone
could see it — the detector certifies whatever it happened to start against. It
also cannot survive a restart, which means the one thing it can never tell you is
that something changed while you were not looking. That is the entire question.

**Keep the baseline in a database.** Works, and costs a dependency, a migration
and a backup story for a document measured in kilobytes. A file in git gets
review, history, blame and rollback for free, and makes acknowledgement an
explicit act with a name attached to it.

**Auto-update the baseline after alerting once.** The tempting fix for repeated
alerts, and it dissolves the feature: a baseline that updates itself is not a
baseline, it is a log of the most recent state. Repeated alerts are instead
solved by edge-triggering *the alert* while leaving the file alone, which is
strictly better — outstanding drift stays visible in `/schemas` and in a gauge
until somebody acknowledges it, so "drifted and nobody has looked for an hour"
becomes something you can page on.

**Store each tool's digest in the file alongside its definition.** Two sources of
truth that can disagree, and the disagreement is silent. Digests are derived on
read; the file holds definitions, which also makes `git diff` on it show exactly
what changed in the upstream's own words.

**Block or withdraw a tool whose description changed.** Overreach at this layer,
and it would make an upstream's routine documentation edit an outage. Screening
what a description *says* is task 45's job and belongs in the injection firewall
with the rest of the content analysis. This layer's obligation is to be unable to
miss the change.

## Consequences

`acp schemas check` exits non-zero on drift, which makes it a CI gate. Run
against the mock fleet on every build, a change to what those servers expose
cannot merge without the baseline being re-captured in the same commit — the
review step this design is arranged around, exercised on every push.

`capture` refuses by default when any upstream is unreachable. Capturing during
an outage records that server as having no tools, turning a transient failure
into a permanent, quietly committed deletion — and when it comes back, every tool
it ever had is reported as newly added by an upstream nobody was suspicious of.

A corrupt baseline file is logged at ERROR and treated as absent rather than
being fatal. This is the only place in the project where a bad file on disk does
not stop the process, and the exception is deliberate: configuration failures are
fatal because a gateway that starts with a broken policy has already failed open,
whereas a schema baseline is a *monitor*, and a monitor that can prevent the
gateway from serving is a larger risk than the one it was added to reduce. It is
the same reasoning that makes an unprobed upstream count as healthy in ADR 0011.

The mocks gained a `MOCK_SCHEMA_DRIFT` switch, kept separate from the chaos modes
because it is a different kind of fault entirely. Chaos breaks the transport;
this leaves the transport perfect and changes only what the response *says*. That
separation is the point of the whole task in one environment variable.

`config/schema-baseline.json` is now a reviewed artifact. Anyone changing a mock
tool has to re-capture it, which is mildly annoying and exactly the friction the
feature is selling.
