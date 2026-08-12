# Security

## Status

**This project has not been security reviewed. Do not run it in front of
anything real.**

That is not boilerplate. The Agent Control Plane is a security control by
design — it sits between AI agents and the systems they are allowed to touch —
and a security control that has not been reviewed is a single point of failure
wearing a reassuring name. It is built in the open, phase by phase, as a study
in doing this properly; it is not a product and has no operational track record.

## Reporting a vulnerability

Open a [security advisory](https://github.com/chandanaroyal719-bot/agent-control-plane/security/advisories/new)
rather than a public issue, and please allow time for a fix before disclosing.

If you would rather not use GitHub advisories, open a normal issue containing
*no detail* — just "I have a security report" — and I will follow up privately.

There is no bounty. There is a commitment to reply, to say plainly whether
something is in scope, and to credit you unless you would rather not be.

## What is in scope

Anything that lets a caller do something the gateway is supposed to prevent:

- Authenticating as a principal you are not, or as no principal at all.
- Crossing credentials between authorization servers — a token issued by one
  server being judged by another's rules ([ADR 0016](docs/decisions/0016-bind-every-credential-to-its-issuer.md)).
- Reaching an upstream, tool or resource the resolved principal is not entitled
  to (from Phase 3 onward, when there is a policy engine to bypass).
- Causing the gateway to forward an inbound token upstream. This invariant is
  asserted by a suite rather than claimed by a comment — every wrapper
  composition, every protocol method and every credential shape, with each
  request searched whole rather than one header inspected
  ([ADR 0023](docs/decisions/0023-prove-the-invariant-and-prove-the-proof.md)).
  A mutation harness breaks it three ways on every pull request and fails the
  build if the suite does not notice. Breaking it is still the most serious
  finding this project could receive, and a report that defeats *both* the sweep
  and the static one-reader check is the most interesting one it could receive.
- Injected instructions surviving result screening (from Phase 5, when there is
  screening to defeat).
- Executing a call a human approved *differently from how they approved it* —
  the same token retried with other arguments, an approval spent twice, an
  approval honoured after it expired, or a caller spending an approval granted
  to somebody else (from Phase 6). The approval is bound to a fingerprint of the
  call, consumed on use, and re-checked before anything runs.
- Reaching the approval channel from the MCP listener, or answering an approval
  without the operator credential. The channel is on the admin listener and the
  routes are not mounted at all when no credential is configured.
- Unauthenticated denial of service that costs the attacker meaningfully less
  than it costs the gateway — for example turning a request into an amplified
  load on the identity provider.

## What is deliberately not defended against

Stated here so that "we did not think of it" and "we decided against it" are
distinguishable. The full reasoning is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

- **A compromised identity provider.** If the authorization server can be made
  to mint arbitrary tokens, everything downstream follows. The gateway binds
  each issuer to its own keys and audience so a *second* server cannot speak for
  the first, but it cannot detect a server lying about its own users.
- **An identity provider reached over plain HTTP, when an operator has asked for
  that by name.** `ACP_AUTH_INSECURE_ISSUER_HOSTS` is empty by default and
  widens the plain-HTTP exemption to hosts listed in it. Anything on the path to
  such a host can replace the key set and mint tokens the gateway will accept.
  It exists because the alternatives people reach for — widening the loopback
  set, or disabling certificate verification — are broader and quieter, and
  every entry is logged at every start ([ADR 0018](docs/decisions/0018-one-issuer-string-from-every-vantage-point.md)).

- **An exchanged credential the gateway cannot read.** Every credential minted
  for an upstream is checked to be scoped to that upstream and no other
  ([ADR 0020](docs/decisions/0020-check-the-scope-you-were-granted.md)). That
  check reads the token's `aud`, so an authorization server issuing *opaque*
  reference tokens defeats it — the gateway logs `auth.scope_unverifiable` and
  proceeds, because refusing would rule out a whole class of provider for a
  property it cannot observe either way.

- **Anything that can read the secret key file, or the running process.** The
  encrypted store ([ADR 0021](docs/decisions/0021-one-backend-behind-a-seam.md))
  reduces many secrets to one key; it does not remove that key. Root on the box,
  a core dump, or read access to the key file gets everything. The decrypted
  values live in memory for the process's lifetime and are not wiped, because
  Python offers no way to reliably zero a `str` and a `del` would be theatre.
  The claim is "fewer places for a credential to be lying around", not "safe".

- **Exchanged credentials living in gateway memory for their lifetime.** Since
  [ADR 0022](docs/decisions/0022-a-cache-key-that-cannot-be-wrong.md) the
  gateway holds each minted credential until shortly before it expires, so a
  core dump or a debugger attached to the process yields live upstream
  credentials for whoever was recently active. Task 27's stronger claim — that
  the process holds nothing reusable — now holds only across the credential's
  few minutes of lifetime. The cache is bounded, per process, never written to
  disk and never shared over a network, and background refresh was rejected
  precisely so the gateway does not hold credentials for callers who have gone
  away.

- **A cached result outliving an upstream entitlement change.** Since
  [ADR 0035](docs/decisions/0035-a-result-cache-key-that-cannot-serve-the-wrong-person.md)
  a tool result may be held for up to its configured ttl, capped at 300 seconds.
  If a principal loses access to the *tool*, policy refuses them before the cache
  is consulted and nothing stale is served. But if they keep the tool and lose
  access to some records *inside* it, the gateway cannot see that change, and a
  held result may be served for the remainder of its ttl. The ttl ceiling is that
  exposure window, which is why it is bounded in code rather than in
  configuration. Cache hits also do not reach the upstream, so an upstream's own
  record of who read what becomes incomplete for any tool opted in — which is a
  reason not to opt one in.

- **An injection this gateway does not catch.** The firewall
  ([ADR 0036](docs/decisions/0036-detect-before-deciding-and-count-the-false-positives.md),
  [ADR 0037](docs/decisions/0037-tell-the-model-where-the-text-came-from.md),
  [ADR 0038](docs/decisions/0038-refuse-loudly-and-never-quote-the-payload.md))
  has three layers and each has a stated limit. The detectors are patterns, so
  they catch what has a shape and miss a well-written paragraph that simply
  asserts something false. Provenance framing removes the *free* version of the
  attack — the one that works because nothing ever told the model the text was
  retrieved — but it is an instruction to a system that follows instructions
  probabilistically, and a sufficiently persuasive document may still win. It
  also does not protect a client that flattens the content blocks and loses
  their order. Structured refusal withholds content on a deliberately narrow
  bar: HIGH confidence from one of *two* detectors — a bidirectional override,
  or base64 that decodes to an instruction. `instruction_override` can never
  withhold anything at all, and neither can the tool-mention or image detectors:
  the benign corpus
  ([ADR 0039](docs/decisions/0039-the-benign-corpus-and-the-two-detectors-it-demoted.md))
  found that they withheld the gateway's own audit log and a marketing
  newsletter, so both were demoted to report-only. **No detection or
  false-positive rate is claimed anywhere in this repository.** The corpus
  produces a withheld rate of zero over 106 benign documents, and the
  adversarial corpus
  ([ADR 0040](docs/decisions/0040-the-adversarial-corpus-and-the-attacks-nothing-catches.md))
  scores the firewall per attack family — including two families,
  `plain_assertion` and `delayed_multi_step`, that no detector catches at all,
  recorded rather than omitted. Both numbers are floors fitted to corpora used
  while developing, not measurements; the honest ones need the held-out split of
  task 50 and the confidence intervals of task 52.

- **A hostile tool description.** Tool *descriptions* reach the model's context
  through `tools/list` and are attacker-controlled in exactly the way tool
  results are, but nothing screens or frames them. Schema drift detection
  ([ADR 0013](docs/decisions/0013-schema-drift-is-a-security-control.md)) catches
  a description that *changes*; a catalogue that was hostile from the first fetch
  passes. Named here rather than left to be assumed closed.

- **A malicious operator.** Anyone who can change the configuration, the schema
  baseline or the policy files can change what the gateway permits. The controls
  here are arranged so that doing so leaves a reviewable trail — the schema
  baseline is a committed file, the container mounts `config/` read-only — not so
  that it is impossible.
- **The model's judgement.** The gateway constrains what an agent *can* do. It
  does not make the agent's decisions good ones.
- **An operator who approves without reading.** The approval channel shows the
  subject, the tool, the rule and the exact arguments the fingerprint binds, so
  a person *can* decide. Whether they do is outside what this can enforce, and a
  gateway that could tell the difference would not need the human.
- **A console that renders approval arguments as instructions.** Those arguments
  were chosen by an agent that may have read a hostile document, and the reader
  is now a person with the authority to say yes — the last place an injection
  can land. The API returns them as JSON data and carries an explicit notice
  saying so; a client is free to interpolate them into markdown anyway, and
  nothing here can stop it.
- **Anything holding the operator credential.** It is a shared secret with one
  power, and that power is approving calls. Treat it as a production credential
  if the admin listener is ever exposed beyond loopback.
- **A replicated deployment on the in-memory approval store.** A call held on
  one instance and retried against another cannot be resolved, and the caller is
  refused a call a person approved. Stated in [ADR 0049](docs/decisions/0049-the-operator-channel-is-not-the-agents-channel.md)
  rather than left to be discovered; the seam for a shared store is four
  operations wide.
- **Traffic the gateway never sees.** An agent holding a direct credential for
  an upstream bypasses this entirely. That is a deployment property, not
  something code here can enforce.

## Design notes relevant to security

The decisions with security consequences are written up as ADRs, with the
alternatives that were rejected and why:

- [0008](docs/decisions/0008-validate-requests-against-the-spec.md) — validate against the specification, not against our own mocks
- [0010](docs/decisions/0010-metrics-on-a-separate-listener.md) — the metrics endpoint is a reconnaissance report, so it gets its own loopback listener
- [0013](docs/decisions/0013-schema-drift-is-a-security-control.md) — a changed tool description is an attack, not an ops event
- [0014](docs/decisions/0014-ship-one-image-and-compose-the-rest.md) — the mock upstreams are stripped from the production image; `config/` is mounted read-only so a compromised gateway cannot silence its own drift alarm
- [0015](docs/decisions/0015-two-identities-not-one.md) — asymmetric algorithms only, because a JWKS publishes public keys and an attacker can sign HS256 with one
- [0016](docs/decisions/0016-bind-every-credential-to-its-issuer.md) — issuer, audience and key set are one indivisible registration
- [0017](docs/decisions/0017-let-the-gateway-tell-clients-where-to-authenticate.md) — the one unauthenticated path is derived from the document served there, not from an allow-list; and why publishing the authorization servers is a reconnaissance cost worth paying where publishing the upstreams is not
- [0018](docs/decisions/0018-one-issuer-string-from-every-vantage-point.md) — an issuer is an identity and not an address; and why the plain-HTTP escape hatch is narrow, named and logged rather than absent
- [0019](docs/decisions/0019-mint-a-credential-per-call-and-hold-none.md) — the gateway holds no upstream credential; the inbound token reaches exactly one module, whose only destination is the issuer that minted it
- [0020](docs/decisions/0020-check-the-scope-you-were-granted.md) — RFC 8707's parameter is a request, not a guarantee; the control is checking the credential that came back names one upstream and no other
- [0021](docs/decisions/0021-one-backend-behind-a-seam.md) — an encrypted store turns many secrets into one key and says so; references live in config, values never do
- [0022](docs/decisions/0022-a-cache-key-that-cannot-be-wrong.md) — a credential cache keyed on the request rather than on claims, because keying it on the upstream serves one caller's credential to the next and passes every functional test
- [0023](docs/decisions/0023-prove-the-invariant-and-prove-the-proof.md) — the no-passthrough invariant swept across every path, two static alarms that fail when a new path appears, and a mutation harness in CI that breaks the invariant on purpose to prove the test can fail
- [0035](docs/decisions/0035-a-result-cache-key-that-cannot-serve-the-wrong-person.md) — a result cache key that cannot serve the wrong person, and why this one cache sits *inside* the policy check rather than outside it
- [0038](docs/decisions/0038-refuse-loudly-and-never-quote-the-payload.md) — a refusal never quotes what it refused, and the refusal notice is deliberately *not* fenced so a document cannot impersonate one
- [0043](docs/decisions/0043-authorize-on-the-routing-headers.md) — authorize on the routing headers, and why a header that disagrees with the body is its own error code
- [0045](docs/decisions/0045-replay-the-log-and-report-what-changes.md) — argument *names* in the decision log and never values, because a `doc_id` is as likely to be a patient record as a public page
- [0047](docs/decisions/0047-a-baseline-not-a-threshold.md) — a committed baseline rather than a threshold, so a firewall regression fails the build on the exact family that got worse
- [0048](docs/decisions/0048-an-approval-is-for-a-call-not-a-token.md) — an approval is granted to a call and not to a token; single use; expiry is the default-deny and is enforced at resolution rather than by a sweeper
- [0049](docs/decisions/0049-the-operator-channel-is-not-the-agents-channel.md) — the agent cannot approve its own call because it cannot address the thing that approves calls; what the operator reads is what the fingerprint binds

## Supported versions

None yet. There has been no release, so there is nothing to backport to. Once
there is, this section will say which versions receive fixes.
