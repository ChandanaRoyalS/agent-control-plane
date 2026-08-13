# ADR 0050 — An audit record is not a log line

**Status:** accepted
**Date:** 2026-08-13

## Context

Phase 7 opens with "a hash-chained audit log covering every authorization
decision, credential exchange, tool call and firewall finding, with a
verification command that detects tampering."

The chaining is the easy half. Everything interesting is in what a record
contains, where it is written, what happens when it cannot be, and — the part
most implementations skip — **an honest account of what a chain proves.**

## Decision

### 1. A separate sink, not a logging handler

The tempting design is a `logging.Handler` that filters on the event names the
code already emits and chains whatever passes. One integration point, no
call-site changes, and the vocabulary exists.

Rejected, for three reasons that are all the same reason:

- **The operational log is level-filtered, sampled and rotated.** A chain over it
  breaks when somebody raises the log level, when logrotate runs, when a queue
  handler drops under pressure. Every one of those is a break that means nothing,
  **and a verifier that cries wolf is a verifier nobody runs.**
- **`logging` swallows its own errors by design.** A handler that cannot write
  calls `handleError` and the program continues — correct for logs, fatal here,
  because the whole fail-closed guarantee is that an unrecordable call does not
  happen.
- **It is interleaved with everybody else's lines.** httpx, uvicorn and the SDK
  log through the same root logger.

**A compliance story that depends on your log level is not one.**

### 2. A closed schema, built at the emit point

`AuditRecord` has named fields and one `detail` mapping, rather than taking
whatever `extra=` a call site felt like passing. An auditor's questions — *what
did this agent do, who was it acting for, what stopped it* — can only be answered
by a record whose shape is identical on every path. A record whose keys depend on
the outcome is one no query can group by.

`None` fields are **written, not omitted**. A dropped field and a genuinely
unknown one are the same bytes to a verifier and very different facts to a
reader.

### 3. Argument names, never values — and why that is not inconsistent

The same rule as the decision log (ADR 0045), and the **opposite** of the
approval record (ADR 0049). That looks like a contradiction and is not one: the
axis is exposure, not data.

| | approval record | audit chain |
|---|---|---|
| lifetime | five minutes, in memory | durable, archived, evidentiary |
| readers | the one person deciding | everyone with log access, for years |
| answer | show the values | names only |

Stated here because a future session will find the two and try to "fix" one.

### 4. Redaction runs *before* the entry is chained

The digest must cover exactly the bytes that reach the file. Hashing first and
redacting after produces a chain that cannot be verified against the artifact it
describes — a verifier reporting tampering on a log nobody touched, which is the
worst possible false positive from a tool whose only job is finding real ones.

### 5. What the chain proves, exactly

**Detects:** modification, splicing, reordering. Any edit invalidates that
entry's hash, and repairing it invalidates the next entry's `prev`.

**Does not detect:**

- **Truncation of the tail.** Delete the last thousand entries and what remains
  is a *perfectly valid chain*. Nothing in the file can say otherwise, because
  the file no longer contains the evidence.
- **A wholesale rewrite** by somebody who owns the storage and knows the scheme.

These are asserted as **passing tests**, not omitted. A chain that appeared to
detect everything would be one whose claims nobody had checked.

Both are answered by `acp audit checkpoint`: a `{seq, head}` anchor small enough
to paste into a chat channel, committed to `config/` — which ADR 0014 mounts
read-only, so the running gateway cannot rewrite the anchor that proves it has
not rewritten its own log.

> **A chain plus an external anchor is tamper-evident. A chain alone is
> tamper-evident to anybody who already knows where it should end.**

Where the anchor lives is the entire security property, and it is a deployment
property no code here can enforce — so the command says so every time it writes
one.

**The anchor is checked against the *entry*, not the final head.** A chain can be
rewritten from any point, so "the head is what I expected" only means anything
for an anchor taken at the very end. Anchoring on the entry means a checkpoint
from last Tuesday still detects a rewrite that happened on Wednesday.

### 6. Fail-closed, configurably, and loud either way

`ACP_AUDIT_REQUIRED` defaults to true: a call this gateway cannot record does not
happen. **An audit log that stops recording while the gateway keeps serving is
worse than none, because the record then asserts by omission that nothing
happened during the window somebody will eventually ask about.**

`false` is a real mode — a gateway in front of nothing sensitive may reasonably
prefer to serve — and it warns at every start, the treatment
`ACP_AUTH_REQUIRED=false` already gets.

The failure is reported to the *operational* log at ERROR and to
`acp_audit_writes_total{outcome="failed"}`. It has to be somewhere else: the sink
that would normally record it is the thing that just failed. **That metric is the
only alarm available for a gap the audit log cannot describe.**

The wire message names nothing. A caller told "the audit log is down" has learned
which subsystem to attack in order to stop being recorded — more valuable to them
than the refusal itself.

### 7. A restart continues the chain; an unreadable tail stops the process

`FileAuditSink` recovers its head on open. A sink starting at genesis every
restart would write a file containing several valid chains end to end, and the
verifier would report a break at every restart — training everybody to ignore
breaks.

A half-written final line (an ordinary crash) leaves a tail that is not an entry.
Two options: truncate it, or refuse to start. **Truncating an audit log to make it
parse is automatic evidence destruction, in exactly the circumstances where
somebody later asks what happened.** So it refuses, names the line, and says to
archive rather than repair.

`acp audit checkpoint` refuses to anchor a broken chain for the same reason:
anchoring damage makes it the baseline every later check compares against, and
the break would have been blessed by the tool built to find it.

### 8. `fsync` per entry

A record buffered in the kernel when the machine loses power describes a call
that really happened, and that is precisely the crash-adjacent window an
investigation cares about. The cost is real — it bounds write throughput to the
disk's sync rate — and is declared rather than hidden. Phase 8 measures it.

### 9. The tenant field exists before multi-tenancy does

Task 58 is next. Adding the field afterwards would leave every record written
before the change ambiguous rather than merely tenant-less, and an archived chain
**cannot be migrated** — rewriting it is exactly what the chain exists to detect.
So it is written now, mostly `null`.

## The honest cuts

**Clean firewall screenings are not chained.** Only findings are.
`firewall_decisions_total` already counts every screening including the clean
ones, and a chained, fsynced entry per clean call would multiply the log by every
request for a fact the metric already carries. **So the chain is a record of
findings, not of screenings** — said here rather than discovered.

**One process, one file.** A replicated fleet writes several independent chains.
Each is internally verifiable and there is no global ordering between them. The
`AuditSink` protocol is three operations wide precisely so a shared-sequence
backend is a class rather than a redesign.

**No signature.** The chain proves internal consistency, not authorship — anyone
who can write the file can write a chain. Signing each head with a key the
gateway holds would not help, because an attacker with the file has the key;
signing with a key it does *not* hold means an external service, which is the
same anchor problem the checkpoint already states honestly.

**Rotation is unsolved.** A chain spanning rotated files needs the head carried
across the boundary. Today the file grows. Naming it beats discovering it.

## Alternatives considered

**A logging handler.** Rejected — decision 1.
**A database.** Rejected: the artifact should be readable by `grep`, `jq`, a log
shipper and a court without this project's code being present. A format that
needs its own reader is evidence that expires when the reader stops building.
**Merkle tree instead of a linear chain.** Rejected for now: it buys efficient
inclusion proofs for a third party, which matters when somebody else must verify
a single entry without the whole log. Nobody is asking yet, and a linear chain is
auditable by hand.
**Fail open.** Rejected as the default — decision 6 — and available as a setting.

## Consequences

- New `acp.audit`: `record`, `chain`, `sink`, `writer`, `checkpoint`, `cli`.
- `acp audit verify` / `acp audit checkpoint`; exit 1 on a break, 2 on a missing
  log, so it composes with CI and cron.
- `AuditUnavailableError` (-32060); `acp_audit_writes_total{outcome}`.
- `ACP_AUDIT_FILE` (presence enables), `ACP_AUDIT_REQUIRED`, `ACP_AUDIT_FSYNC`.
- Five emit points: pre-dispatch refusal, policy decision, credential exchange,
  tool call, firewall finding — plus the operator's approval decision, which is
  the one record made by a *person* and the row an investigation actually wants.
- The operator's free-text `reason` **is** recorded, unlike every other
  caller-supplied string: it is written by a trusted, authenticated human who
  knows it is being kept.

## References

- ADR 0007 — events, not sentences (the vocabulary this shares)
- ADR 0013 — a committed baseline as a drift anchor (the pattern `checkpoint` reuses)
- ADR 0014 — `config/` is mounted read-only (why the anchor lives there)
- ADR 0038 — a refusal never quotes the payload (why findings carry families, not text)
- ADR 0045 — argument names, never values, in the decision log
- ADR 0049 — the approval record's opposite answer, and why the axis is exposure
