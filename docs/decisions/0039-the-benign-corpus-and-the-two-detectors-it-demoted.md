# ADR 0039 — The benign corpus, and the two detectors it demoted

**Status:** accepted
**Date:** 2026-08-12

## Context

Everything in `acp.firewall` is a mechanism. ADRs 0036, 0037 and 0038 describe
what it tries to do and argue carefully about where a threshold belongs, and not
one of them contains a number, because none existed. Until something measures
it, "injection firewall" is a statement of intent.

Task 48 is the benign half of the measurement, and it comes before the
adversarial half deliberately. Detection rate is a number anybody can reach by
refusing everything. The number that decides whether a security control survives
contact with a real deployment is the other one: how often it is wrong about a
document somebody legitimately needed. ADR 0036 said a false positive is how a
security control gets switched off; this is the ADR that stops saying it and
starts counting.

## Decision

### The corpus is realistic or it is worthless

**A benign corpus of tidy text is worse than no corpus**, because it produces a
false-positive rate near zero and that rate is a property of the corpus rather
than of the firewall. It reads as evidence and is not.

So the corpus is 106 documents across 13 kinds — runbooks, incident reports,
security advisories, this repository's own ADRs, source code, tickets, database
rows, log lines, email, product docs, chat threads, non-Latin text, and
specification prose — and **48 of them are deliberate near-misses**: an advisory
quoting a complete injection payload, an emoji family built from zero-width
joiners, Persian requiring the zero-width non-joiner as spelling, Arabic and
Hebrew carrying directional marks, a JWT in a session row, a base64 blob that
decodes to an image, a wiki page with a logo on it, a legal hold notice written
entirely in imperatives.

**This is enforced rather than claimed.** One test asserts that no benign
document is withheld. A second asserts that at least a tenth of them *do*
produce a finding — because without it, the first test can be made to pass by
deleting whichever documents are inconvenient, and the corpus would rot into
exactly the tidy filler that makes a fraudulent rate.

### `source` is an honesty field, not metadata

Every document records whether it was excerpted from this repository or written
for the corpus.

A corpus invented by the same author as the detectors has a ceiling on what it
can prove. That author knows what the patterns look for and will, without
intending to, write around them. Thirteen documents are genuine excerpts —
sections of ADRs 0036, 0037 and 0038, module docstrings from `screen.py`,
`findings.py`, `table.py` and `exceptions.py`, and a committed config file. Those
were written to be read by humans, so they cannot have been shaped around a
detector, and a clean result on them is stronger evidence than a clean result on
anything synthetic.

Naming which is which also gives the corpus somewhere to grow: replacing a
synthetic document with a found one is an improvement anybody can make and
anybody can verify.

### Front matter, and the body kept byte for byte

One file per document, a YAML front-matter block, and the document below it
unescaped and unencoded.

That last part is not a formatting preference. Several of these documents
contain zero-width joiners and directional marks *on purpose*. A format that
turned those into `‍` would be storing a description of the document
instead of the document, and the corpus would stop testing the thing it exists
for. It also means a reviewer can read a corpus entry, which matters because a
corpus is evidence and evidence that cannot be reviewed is an assertion.

The parser is strict about unknown keys. A typo'd `hardd: true` silently means
"not hard", which is a near-miss quietly leaving the slice the numbers are drawn
from, and nothing anywhere would say so.

### The measurement, and what it changed

Run against a realistic deployment — the organisation's own hosts allow-listed
and nothing else, and a catalogue whose tool names appear in its own audit logs,
which is what a catalogue *is*:

| | |
|---|---|
| Documents | 106 across 13 kinds |
| Deliberate near-misses | 48 |
| Excerpted from this repository | 13 |
| Produced at least one finding | 20 (19%) |
| **Withheld under the ADR 0038 bar** | **6 (5.7%)** |

Six is not a tuning problem. It is the control being wrong about documents an
organisation cannot do without, and each one falls into a class rather than
being a one-off:

**`tool_name_mention` withheld four.** The gateway's own audit log, a
policy-decision record, an audit trail, and the firewall's own log lines. Every
one of them names qualified tools — *that is what a record of tool calls is*.
An observability tool returning the gateway's audit log would have been refused
by the gateway that wrote it. ADR 0036 described this detector as having a
false-positive rate near zero because a qualified name is unusual in prose; that
was a guess, and it is wrong for every document that describes the estate,
which includes tickets, incident reports and documentation.

**`external_image` withheld two.** A marketing newsletter carrying a tracking
pixel, and the security advisory *demonstrating* the exfiltration pattern. Both
are benign, both are exactly the shape, and no allow-list a real deployment
would write covers a third party's newsletter.

**So both are demoted.** `ENFORCEABLE` is now `bidirectional_override` and
`encoded_payload` — the only two detectors that produced zero findings across
all 106 documents. The withheld count is 0.

Both demoted detectors still fire, are still logged, and still count toward
`would_refuse` in report mode. What they can no longer do is withhold a document
on their own. Tasks 51 and 52 can promote them again by combining them with a
second signal, which is what this measurement says they need.

### A guard that could no longer fire was deleted

`external_image` leaving the enforceable list made the host-dependency check
unreachable: a condition gating a detector that can no longer withhold anything.
`HOST_DEPENDENT` and the `hosts_configured` parameter are gone. This is lesson
14 applied a second time — a guard that cannot fire is worse than no guard,
because a reader trusts it.

The host list still matters. It decides what is *reported*, and the startup
warning was reworded to say that rather than to claim enforcement it no longer
performs.

### The corpus is what guards the bar

`scripts/mutate_refusal.py` gained a mutation that puts `tool_name_mention` back
on the enforceable list, and requires `test_no_benign_document_is_withheld` to
be the test that fails.

That is the point of building the corpus before the numbers. The bar is no
longer defended by an argument in an ADR that a confident engineer can disagree
with — it is defended by 106 real documents in CI, and re-promoting a detector
means explaining to the build why the gateway should refuse its own audit log.

## What this does not do

**It does not produce a false-positive rate.** It produces a *withheld* rate of
zero over this corpus, which is a floor rather than a measurement: the corpus
was used while developing, so the number is fitted to it by construction. The
honest number needs the held-out split of task 50, and the confidence intervals
of task 52. Nothing in the README may claim a rate until then.

**It says nothing about detection.** No attack has been screened. The
adversarial corpus is task 49, and a firewall evaluated only on benign traffic
has a false-positive rate of zero available to it by doing nothing at all.

**It is 76KB of mostly synthetic text.** Real traffic is larger, weirder and
contains things nobody thought to write. Thirteen found documents is a start and
not a sample.

**It is not packaged with the distribution.** The corpus is a source-checkout
asset. Shipping a firewall's test set inside the firewall would put a catalogue
of what it looks for into every deployment.

## Alternatives considered

**Collect the adversarial corpus first.** The natural order, and it produces the
flattering number first. Building the benign half first meant the very first
measurement this project produced was one that made it weaker, which is the
correct direction for a measurement to be able to point.

**Store the corpus as JSONL.** One file, easy to load, and unreadable in review —
100 long lines of escaped text. It would also have escaped the zero-width and
directional characters that half the hard documents exist to carry.

**Allow-list every host the corpus mentions.** Would have made the URL and image
detectors silent, the corpus clean, and the `external_image` false positive
invisible. The allow-list is what a real organisation writes: its own hosts.

**Use a catalogue disjoint from the corpus.** Same failure, and worse, because
`tool_name_mention` could then never fire and the four-document false positive
would never have been found. A real gateway's audit log names its real tools.

**Delete the six failing documents.** The version that keeps the ADR 0038 bar
and makes the corpus a record of what the firewall already handles. It is the
temptation the second test exists to make impossible.

**Add a per-tool exemption** so an observability tool's results skip the
tool-mention detector. Plausible, and it puts a security control's blind spot in
a config file where an attacker only needs to find one exempted tool. Rejected
for now; if it returns it should be a deliberate ADR of its own.

## Consequences

**The firewall withholds less than it did yesterday**, and says so. Two of four
enforceable detectors are gone, and the remaining two catch obfuscation only.
Framing (ADR 0037) is unchanged and is still applied to everything, which is the
control with no error rate.

**Report mode became more useful.** Both demoted detectors still count toward
`would_refuse`, so a deployment running in report mode can measure on its own
traffic exactly what this ADR measured on the corpus.

**The corpus is now a build dependency of the firewall.** `make check` loads and
screens 106 documents, and `make prove-refusal` mutates the bar against them.
That is a deliberate coupling: it is what stops the bar being widened without
evidence.

**Every future threshold change has a place to be argued.** Tasks 49 to 53 add
attacks, a held-out split, a classifier and a regression gate. The question
"should this detector be allowed to withhold a document" now has an answer shape
— run it against the corpus — rather than a debate.

## References

- ADR 0013 — an upstream's self-description is not trusted input
- ADR 0036 — detect before deciding, and make the false positives countable
- ADR 0037 — provenance framing, the half of the firewall with no error rate
- ADR 0038 — refuse loudly, refuse rarely, and never quote the payload
- OWASP GenAI Top Ten 2026, entry 1: prompt injection
