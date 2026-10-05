# Threat model

**Status:** complete as of v1.0.0. Superseded stub kept in git history.
**Last measured:** 2026-08-13, at `main` after PR #64.

## How to read this document

Most security write-ups describe what a system defends. The useful half is the
other one, so this document is organised around a single asymmetry:

> **"We did not think of it" and "we decided against it" must be
> distinguishable from the outside.**

Every gap below is one of the second kind. Where a number appears, it was
measured by `make eval` against a committed corpus and can be reproduced; where
no number appears, that absence is itself stated rather than filled with a
confident adjective. Several sections say *this defence has never been
measured* — those are the most important sentences here.

Nothing in this document is a claim that the Agent Control Plane is safe. It
has not been security reviewed (see `SECURITY.md`), and a control that has not
been attacked by anyone but its author is a hypothesis.

---

## 1. What the system is

A gateway that sits between AI agents and the MCP tool servers they call. An
agent authenticates to it; it resolves *which human the work is for* and *which
agent is doing it*, authorizes the call against a policy, mints a credential
scoped to one upstream, charges the call against a budget, screens what comes
back for injected instructions, and writes the whole story into a hash-chained
audit log.

It exists because the default architecture is worse: an agent holding one
service credential per system, carrying the union of every permission any user
might need, with no principal anywhere in the picture.

---

## 2. Assets, in the order an attacker would want them

| # | Asset | Why it is worth taking |
|---|---|---|
| 1 | **Upstream credentials** | Bearer access to real systems, reusable outside the gateway entirely. |
| 2 | **Data reachable through upstream tools** | The point of the whole system. Often the reason the agent exists. |
| 3 | **The agent's decision-making** | Corruptible through content. An agent talked into a destructive call does the attacker's work with the *user's* authority — no credential theft required. |
| 4 | **The audit log's integrity** | Not valuable to steal; valuable to *edit*. It is the only artifact that says what happened. |
| 5 | **The secret-store key** | One file that decrypts every static credential. |
| 6 | **The operator approval channel** | Whoever can answer approvals can authorise the calls policy refused to decide alone — which is why the answer is recorded against a verified subject (ADR 0059), not a shared secret. |

---

## 3. Trust boundaries

1. **Agent → gateway.** The agent is *authenticated but not trusted*. Its
   context may already be poisoned, so every request it makes may be
   attacker-influenced. This is the boundary most designs get wrong by
   conflating "I know who this is" with "I believe what they are asking for".
2. **Gateway → upstream.** Upstreams are trusted to *hold* data, not trusted to
   *return safe content*.
3. **Upstream content → agent.** The critical one. Everything crossing it is
   untrusted input, never instruction.
4. **Agent → operator channel.** A separate listener on a separate port,
   loopback-bound by default and credentialed. Where a deployment widens the
   bind (the compose stack does, to publish the port), the port and the
   credential are the boundary, not an unreachable address (ADR 0049).
5. **Gateway → its own audit log.** The gateway writes it, so the gateway
   cannot be the thing that proves it did not rewrite it.

---

## 4. Adversaries

| Adversary | Capability assumed | Cannot |
|---|---|---|
| **Injected-content author** | Writes into any source a tool returns — a document, ticket, code comment, DB row, tool *description* | Authenticate; reach the gateway directly |
| **Curious insider** | A legitimate principal with valid credentials | Forge another principal's token |
| **Compromised upstream** | Returns arbitrary content, arbitrary catalogues, arbitrary errors | Read another upstream's credential |
| **Compromised agent** | Makes any request the principal's token permits, at any rate | Escape the principal's entitlement, by design |
| **Network attacker** | Sees and modifies plaintext traffic | Break TLS |
| **Host-level attacker** | Root on the gateway box | — (out of scope, §8) |

Note the fourth row. **A compromised agent is an expected state, not a
contingency**, and it is the case most of this system's controls are shaped by.

---

## 5. What is defended, with the evidence

Claims here are backed by a named test, a mutation harness, or a measured
number. A control with none of those is listed in §6 instead.

### 5.1 Identity and credentials

- **The caller's token is never forwarded upstream.** Asserted across every
  wrapper composition, protocol method and credential shape, with each outbound
  request searched *whole* rather than one header inspected (ADR 0023).
  `make prove-passthrough` breaks the invariant 3 ways on every PR and fails the
  build if the suite does not notice.
- **Each credential is bound to its issuer.** A registration is indivisible:
  issuer, audience, key set, algorithms and token endpoint are configured and
  used together, so a token signed by one authorization server cannot be judged
  by another's rules (ADR 0016). This is the resource-server form of the
  authorization-server mix-up attack, and the defence is *ordering*: the
  registration is selected by the unverified `iss`, then the signature must
  verify against that registration's keys and `iss` must equal its issuer.
- **Credentials are scoped per upstream and checked** (ADR 0020), cached on a
  digest of the subject token (ADR 0022) — a key no two principals and no two
  tenants can share.
- **Delegation is explicit.** `sub` and `act` are separate fields, so "which of
  the four agents acting for alice did this" is answerable (ADR 0015).

### 5.2 Authorization

- **Deny by default, structurally** (ADR 0025): no rule matching is a denial,
  and `rules: []` is a valid policy meaning "deny everything".
- **Argument-level rules** (ADR 0031), first-match-wins (ADR 0026), one pure
  evaluator shared by the request path, `acp policy explain` and the simulator
  (ADR 0030) — so the three answers cannot diverge.
- **A refuse-only pre-dispatch fast path** (ADR 0043) that may refuse and may
  never authorize. `make prove-predispatch`: **655,448 argument-mapping
  re-checks over 30,000 sampled policies, 0 false refusals**, plus a search
  demonstrated to catch 3 broken readings and 2 header bugs.
- **The catalogue is filtered by policy** (ADR 0029), so a caller is not told
  about tools they may not call.
- **Denials never explain themselves to the caller** (ADR 0027) — every
  distinction is an oracle an agent can map one request at a time.

### 5.3 Tenancy *(ADR 0051)*

- **The tenant comes from the issuer registration, never a claim.** It is
  stamped after verification, by the registration whose keys checked the
  signature. A token *claiming* a tenant is ignored — asserted with real RSA
  signatures. **The tenant boundary therefore inherits the mix-up defence
  rather than trusting an IdP's claim hygiene.**
- **One policy file per tenant.** Isolation holds by *file boundary*: no rule
  in one tenant's file can match another's traffic, because that file is never
  opened for them.
- **An unknown tenant gets deny-all, never the default policy** — the default
  is some other tenant's rule set.
- **Every key is tenant-qualified:** result cache (`acp-result-v2`), budget
  accounts, approval fingerprints, audit records. `make prove-cache` removes
  each key field in turn — including the tenant — and requires the assertion
  written for it to be the one that fails.

### 5.4 Budgets

Token-bucket rate limiting (ADR 0032), per-tool cost weighting (ADR 0033) and
fixed-window quotas (ADR 0034), charged **after** authorization so a denied
call cannot spend, and **before** the result cache so repetition is not free.

### 5.5 Injection defence

Three layers, each with a stated limit (§6.1 has the limits):

1. **Deterministic detectors** — seven patterns, no model, no network
   (ADR 0036), over every tool result and, since ADR 0065, every tool
   description in the catalogue.
2. **Provenance framing** — every result fenced in a per-result nonce boundary
   the document cannot forge (ADR 0037).
3. **Structured refusal** — withholds on a deliberately narrow bar, and
   **never quotes what was withheld** (ADR 0038), because a refusal that
   explains itself by quoting the payload delivers that payload with the
   gateway's authority attached, outside any fence.

`make prove-refusal` breaks this 6 ways, including lowering the bar and fencing
the gateway's own refusal as though it were upstream content.

**The result cache sits after policy and after budget** (ADR 0035) — the
opposite of the usual "caching outermost" instinct, because a cache consulted
before authorization serves a caller the policy would have refused, and the
denial never runs.

### 5.6 Human-in-the-loop

- **An approval is granted to a *call*, not a token** (ADR 0048) — a
  fingerprint over the canonical arguments, so an approval cannot be spent on a
  different call wearing its token.
- **The operator channel is on its own listener and port, behind its own
  credential** (ADR 0049). On the default loopback bind an agent cannot reach
  it at all; on a wider bind it would need the operator's credential. The
  approval view and the audit row carry the acting agent and the tenant, so
  the person deciding sees both identities (ADR 0015) and the record says who
  asked — the `request_state` token is not written to the chain, because the
  chain is durable and widely readable and the token is a live handle.
- **Who approved is a verified subject** (ADR 0059). With
  `ACP_APPROVAL_OPERATOR_AUDIENCE` set, an operator presents a JWT from an
  issuer the gateway already trusts, minted for the operator audience; the
  same validator checks it, the tenant is stamped from the registration, and
  the row records the verified `sub`. An agent's token is refused on the
  channel because its audience is the gateway's; an operator decides only
  within their tenant. The shared token remains for development and records
  itself as `shared-token` — the row never asserts a name nothing checked. MRTR's `input_responses` is read by nobody: the
  client **is** the agent, so asking it to confirm would be theatre.
- **What the operator reads is what was fingerprinted**, byte for byte, from
  one encoder. Arguments over 8 KiB are **withheld, not truncated** — a
  truncated display is a different call.
- **Default-deny on expiry**, checked before state, so a late yes counts for
  nothing.

### 5.7 Audit

A hash chain over every authorization decision, credential exchange, tool call,
firewall finding and human approval (ADR 0050). **Fail-closed by default**: a
call this gateway cannot record does not happen. Redaction runs *before*
hashing, so the digest covers exactly the bytes on disk. `acp audit verify`
detects modification, splicing and reordering; a restart continues the chain
rather than starting a second one; an unreadable tail **refuses to start**
rather than truncating, because truncating an audit log to make it parse is
automatic evidence destruction.

---

## 6. What is **not** defended

The register. Each entry: what an attacker gets, why it is open, and what would
close it.

### 6.1 An injection this gateway does not catch — **the largest gap**

Measured, deterministic layer, enforce mode, 37 development attacks, 106 benign
documents, 2,000 bootstrap resamples (seed 20260812):

| attack family | detected | **withheld** |
|---|---|---|
| exfiltration | 5/5 | 0 |
| obfuscation | 7/8 | **5** |
| direct_override | 5/6 | 0 |
| tool_confusion | 3/4 | 0 |
| boundary_escape | 1/4 | 0 |
| **delayed_multi_step** | **0/4** | 0 |
| **plain_assertion** | **0/6** | 0 |

**Two named attack families are caught at a rate of zero.** Not "rarely" —
zero, out of ten documents written specifically to represent them.
`plain_assertion` is a well-written paragraph that simply asserts something
false; it has no shape for a pattern to match. `delayed_multi_step` splits the
attack across calls so no single result is hostile.

Precision, on the flagged set:

| firewall family | precision | interval |
|---|---|---|
| obfuscation | 70% (7/10) | [40%, 100%] |
| direct_override | 53% (8/15) | [27%, 80%] |
| exfiltration | 42% (5/12) | [17%, 67%] |
| tool_confusion | 38% (3/8) | **[0%, 75%]** |

**Under half of what this firewall flags is an attack**, and `tool_confusion`'s
lower bound is *zero*. That is survivable only because of the row that matters
most — **0 of 106 benign documents withheld** — so the bar between "found
something" and "acted on it" is carrying the entire deployment. Any proposal to
lower that bar now has a number to argue against.

Only two detectors can withhold anything at all: bidirectional overrides, and
base64 that decodes to an instruction. `instruction_override` and the
tool-mention and image detectors were **demoted to report-only** after the
benign corpus caught them withholding the gateway's own audit log and a
marketing newsletter (ADR 0039).

**The generalisation claim rests on seven documents.** Held-out v1 (7 attacks,
one per family) was scored once, on 2026-10-04 (ADR 0060): patterns only, 3 of 7
produced a finding, **none was withheld**, and every outcome matched what the
corpus recorded before the seal. That supports "the author's expectations held on
unseen attacks"; it does not support a rate. v1 is now spent, and v2 has to come
from attacks nobody on this project wrote. Every other number above is fitted to
corpora that were consulted while writing the detectors.

**On attacks nobody here wrote, the plain form is not caught at all.** InjecAgent
(ADR 0061), development half, patterns only: of 27 attacker instructions planted
in real-looking tool responses, the polite base form produced **0** findings
attributable to the attack, across 459 documents; the form prefixed "IMPORTANT!!!
Ignore all previous instructions…" was caught every time — one regex, one fixed
sentence. **Nothing was withheld in either form**, because `instruction_override`
is report-only (ADR 0039). **Held-out v2, scored once (ADR 0064), says the
same:** 0 of 595 polite documents caught, 595 of 595 announced ones, 35 unseen
instructions, nothing withheld.

The optional model classifier, measured alone (ADR 0060), flags 1 of 106 benign
documents and 3 of 36 development attacks, at about 1.4 s a call, and added no
held-out recall. It is off by default and is not counted as a defence here.

**No text control tested separates the polite injection from a polite request**
(ADR 0063). On InjecAgent's base form, llama3.2 with `plain_assertion` reportable
caught at most 7 of 459; ProtectAI's purpose-built DeBERTa detector caught 56 of
459 — while calling 65% of the same tool responses *without* the attack an
injection, and 23 of 106 benign documents. Neither is integrated.

**What stops it is the policy, at the tool call.** Every one of the 27
development attacks needs a tool the users' tasks do not: under a least-privilege
policy all 27 chains are denied, and under a broad reads-allowed, writes-held
policy all 27 are held for a person — with none of the users' own 17 task tools
affected (ADR 0063). That is conditional on the deployment's policy being scoped
that way, on a person refusing the held call, and on the attack needing a write:
a chain that only reads (a URL that carries data out) would pass the broad
policy. **On held-out v2 (35 unseen instructions, ADR 0064) the result held:**
35 of 35 chains blocked under least privilege, 35 of 35 held under the broad
policy, no task tool affected — a policy failure rate below about 9% at 95%
confidence by the rule of three, for this attack distribution.

Provenance framing removes the *free* version of the attack — the one that works
because nothing ever told the model the text was retrieved — but it is an
instruction to a system that follows instructions probabilistically, and a
sufficiently persuasive document may still win. It also does not protect a
client that flattens the content blocks and loses their order.

> **What would close it:** least-privilege policy as the default deployment
> posture rather than an option — the measured control for the polite form — and
> for text, a detector whose yes rate on clean tool output is low enough that
> "caught" and "said yes" converge, measured against a fresh held-out source (v1 and v2 are spent), not tuned on it.

### 6.2 A hostile tool *description* — **screened, not fenced; the polite one passes**

Tool descriptions reach the model's context through `tools/list` and are
attacker-controlled in exactly the way tool results are. Since ADR 0065 every
description, and every `description` inside the input schema, is screened with
the same detectors and the same bar as a result; in enforce mode a tool that
crosses it is withheld from the catalogue. Measured on 1,102 descriptions
nobody here wrote: zero findings, zero withheld. On eight poisoned descriptions
written here, the two enforceable detectors withhold, five more are detected
and served, and the polite false claim passes.

What remains: a description **cannot be fenced** — its purpose is to be
followed, so there is no honest frame — and a polite poisoned description reads
like a legitimate one. The control for what it talks the model into is the
tool-call policy (§5.2, ADR 0063).

### 6.3 The static secrets store is shared across tenants

Exchanged credentials — the primary path — are per-principal and tenant-safe.
The static fallback (ADR 0021) is configured **per upstream** and presented for
any tenant's call to it. It predates tenancy and is now **the weakest
credential boundary in the system**. A tenant with any permitted tool on an
upstream that uses a static secret is acting with a credential shared by every
other tenant on it.

### 6.4 The audit chain cannot detect two things, and one is unanchored

- **Truncation of the tail.** Delete the last thousand entries and what remains
  is a *perfectly valid chain*. Asserted as a **passing test**
  (`test_truncating_the_tail_leaves_a_valid_chain`).
- **A wholesale rewrite** by somebody who owns the storage and knows the scheme
  (`test_a_chain_rebuilt_from_genesis_verifies`).

Both are answered by `acp audit checkpoint` — and **no checkpoint is committed
in this repository**, deliberately (ADR 0051 5a: an anchor names a position in
one chain, so a committed one is a guaranteed false break in every other
environment). So today the truncation defence is exercised by tests and by hand,
**not by CI**. A real deployment must anchor somewhere the gateway cannot reach;
this repository cannot do that on its behalf.

Signatures are opt-in (ADR 0078). With `ACP_AUDIT_SIGNING_KEY_FILE` set, every
entry is signed with Ed25519, and someone who can write the file but does not
hold the key can no longer rewrite it consistently. Without it, the chain proves
internal consistency, not authorship: anyone who can write the file can write a
chain. Either way the key holder, which includes the running gateway, can
rewrite anything it signed, and truncation still needs a checkpoint.

And: **clean screenings are not chained**, only findings. The chain is a record
of findings, not of screenings.

### 6.5 In-memory state: two different severities

- **The approval store is per process by default.** Unlike the rate limiter's
  identical cut, this one affects **correctness**: a replicated deployment
  where the retry lands on a different process cannot resolve the approval,
  and a restart drops every pending one. Setting `ACP_APPROVAL_STORE_URL`
  closes it (ADR 0066): every replica holds, decides and spends the same
  record in Redis, an approved token is spent exactly once however many
  retries carry it, and the gateway refuses to start if the store is
  unreachable. What remains is the default — a deployment that scales out
  without setting it has the bug this item always described — and the Redis
  itself, which is now part of the trust base: whoever can write to it can
  write an `APPROVED` record.
- **The audit chain is one file per process.** A replicated fleet writes
  several independent chains with no global ordering between them. Two
  processes on one file are refused at startup (an exclusive advisory lock,
  ADR 0070) rather than allowed to interleave two chains that nothing could
  repair; the chain is SHA-256 over canonical JSON with no key, so whoever
  can write the file can rewrite it consistently, and the checkpoint
  (ADR 0050) is the only thing outside the file that says what it held.
- **The shared stores are in the trust base and on the request path.** A
  Redis that is slow or down refuses every budgeted or held call (bounded
  by a one-second command timeout, two to connect, ADR 0070) — fail closed,
  as a typed refusal the agent can retry — and a Redis an attacker can write
  to can refill a bucket or write an `APPROVED` record.

### 6.6 Budget gaps

- **No per-tool rate limit.** Cost weighting (ADR 0033) makes an expensive tool
  drain a budget faster, but that is *weighting, not isolation* — it cannot
  express "anything at 100/s, but this destructive tool at 1/s". ADR 0044 §3
  calls this the one of its four cuts worth building.
- **No per-tenant limits.** Multi-tenancy (ADR 0051) supplied the tenant ADR 0044 §4
  said was missing, so budgets are now *isolated* per tenant — but every tenant still
  draws from the same capacity and refill numbers. Isolation, not
  differentiation.
- **Rate-limit and quota state are in memory by default**, so a replicated
  fleet multiplies every limit by the number of processes. Setting
  `ACP_BUDGET_STORE_URL` closes it (ADR 0067): one bucket and one tally per
  payer in Redis, charged in one server-side step that checks both budgets
  before debiting either, and the gateway refuses to start if the store is
  unreachable. What remains is the default, a Redis round trip on every
  charged call, and the Redis itself as trust base — whoever can write to it
  can refill a bucket.

### 6.7 A cached result outliving an entitlement change

A result may be held up to its configured TTL, capped at **300 seconds**. If a
principal loses access to the *tool*, policy refuses them before the cache is
consulted. If they keep the tool and lose access to some records *inside* it,
the gateway cannot see that change, and a held result may be served for the
remainder of its TTL. **The TTL ceiling is that exposure window**, which is why
it is bounded in code rather than in configuration.

Cache hits also do not reach the upstream, so **the upstream's own record of who
read what becomes incomplete** for any tool opted in — which is a reason not to
opt one in.

### 6.8 Credentials in process memory

Exchanged credentials live in gateway memory until shortly before they expire
(ADR 0022), so a core dump or an attached debugger yields live upstream
credentials for whoever was recently active. The decrypted secret store lives
there for the process's lifetime and is **not wiped** — Python offers no way to
reliably zero a `str`, and a `del` would be theatre. The claim is "fewer places
for a credential to be lying around", not "safe".

### 6.9 An opaque exchanged credential cannot be scope-checked

The scope check (ADR 0020) reads the token's `aud`, so an authorization server
issuing *opaque* reference tokens defeats it. The gateway logs
`auth.scope_unverifiable` and proceeds, because refusing would rule out a whole
class of provider for a property it cannot observe either way.

### 6.10 A caller whose protocol version cannot carry `input_required`

Deferred. The SDK already fails closed, but the operator sees
`-32603 Handler returned an invalid result` rather than "this caller cannot
answer an approval".

### 6.11 Plaintext issuers, when an operator asks by name

`ACP_AUTH_INSECURE_ISSUER_HOSTS` is empty by default and widens the plain-HTTP
exemption to hosts listed in it. Anything on the path can replace the key set
and mint acceptable tokens. It exists because the alternatives people reach for
— widening the loopback set, disabling certificate verification — are broader
and quieter. Every entry is logged at every start.

### 6.12 Audit rotation is unsolved

A chain spanning rotated files needs the head carried across the boundary.
Today the file grows without bound. `fsync` per entry also bounds write
throughput to the disk's sync rate — a declared cost (ADR 0050 §8), measured by
the perf harness (ADR 0053).

---

## 7. If I were attacking this system

Ranked by expected success against a current deployment. This section exists
because a list of gaps is not a threat model until somebody says which ones
they would actually use.

1. **Write a persuasive false document into any source the agent reads.** No
   pattern matches it (`plain_assertion`: 0/6), nothing withholds it, and the
   only defence is provenance framing — an instruction to a probabilistic
   system. **Cost: writing a paragraph.** This is the attack I would try first
   and the one I would expect to work.
2. **Poison a tool description** on an upstream I control or can influence
   (§6.2), in plain English rather than with anything a detector matches. It
   lands in the model's context on every `tools/list`, and nothing fences it;
   what I make the model call is still the policy's to refuse.
3. **Split the attack across calls** (`delayed_multi_step`: 0/4). No single
   result is hostile; the firewall screens results, not conversations.
4. **Get any permitted tool on an upstream that uses a static secret** and act
   with a credential shared across every tenant (§6.3).
5. **If I already have the host:** read the key file or dump the process for
   live credentials, then truncate the audit tail — which the chain cannot
   detect and, with no committed anchor, nothing else will either (§6.4, §6.8).
6. **Wait out an entitlement change** inside a cached result's TTL, up to 300
   seconds, leaving no trace in the upstream's own access log (§6.7).
7. **Hammer one destructive tool** at the full per-principal rate, since no
   per-tool limit exists (§6.6).

**And the one I would not bother with:** stealing the caller's token from an
upstream request. That invariant is asserted whole-request, mutation-tested
three ways on every pull request, and defeating both the sweep and the static
one-reader check would be the most interesting finding this project could
receive.

---

## 8. Explicitly out of scope

Not oversights. These are the boundaries the design accepts.

- **A compromised identity provider.** If the authorization server can be made
  to mint arbitrary tokens, everything downstream follows. The gateway stops a
  *second* server speaking for the first; it cannot detect a server lying about
  its own users.
- **Host-level compromise of the gateway.** Root on the box, a core dump, or
  read access to the key file gets everything (§6.8).
- **Model-level jailbreaks of the agent itself.** This gateway constrains what
  an agent *may do*, not what it may be persuaded to *want*. That is the correct
  division: the whole design assumes the agent is already corrupted.
- **The agent's own prompt and system message.** Outside the gateway entirely.
- **Denial of service by a legitimate principal within their budget.** That is
  what the budget is for; a principal who is a problem is an authorization
  question.
- **Transport security.** TLS termination is the deployment's job.
- **Malicious operators.** Whoever holds the approval credential can authorise
  anything policy holds. The control is the *separation* of that channel from
  the agent, not the trustworthiness of the human on it.

---

## 9. How to check these claims yourself

Every number in §6.1 comes from a committed baseline and is reproducible:

```bash
make eval          # false positives first, then recall and precision per family
make eval-check    # fails if any measured count got worse
make prove-cache ; make prove-predispatch ; make prove-passthrough ; make prove-refusal
```

The four harnesses are the honest part: each *breaks a control on purpose* and
requires the specific assertion written for it to be the one that fails. A
security test that has never been seen to fail is a claim about whoever wrote
it. Eighteen deliberate breakages are checked on every pull request.

To see the audit chain's stated limits behave as documented: run the approval
demo, `make audit-checkpoint`, edit any line of `audit/audit.jsonl` and verify
(a break at exactly that entry), then restore and delete the last line instead
— **the chain reports intact, and only the anchor catches it.**

---

## 10. Change log

| Date | Change |
|---|---|
| 2026-10-05 | Tool descriptions screened and, in enforce mode, withheld (ADR 0065); §6.2 narrowed. |
| 2026-10-04 | Held-out v2 scored once: firewall and both policies generalised exactly (ADR 0064). |
| 2026-10-04 | Text detectors and tool-call policy measured on InjecAgent (ADR 0063). |
| 2026-10-04 | Held-out v1 scored (ADR 0060); external InjecAgent corpus added and held-out v2 sealed (ADR 0061). |
| 2026-08-13 | Completed. Register consolidated from ADRs 0013–0051, measured numbers from `corpus/eval-baseline.json`. |
| At the start | Stub created, so that what is *not* defended was visible from the beginning rather than implied. |
