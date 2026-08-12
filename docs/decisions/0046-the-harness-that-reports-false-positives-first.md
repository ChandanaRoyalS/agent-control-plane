# ADR 0046 — The harness: false positives first, two slicings, and no aggregate

**Status:** accepted
**Date:** 2026-08-12

## Context

Tasks 45 to 51 built a firewall, two corpora, a sealed split and an optional
classifier. None of them says how well any of it works. Until something does,
"injection firewall" describes an intention.

Task 52 is that something. The plan asks for precision, recall and false-positive
rate per family with bootstrap confidence intervals — and the interesting
decisions are all about what *not* to report, because the wrong summary of a
security control is worse than none. A number nobody can reproduce, or that
averages over categories chosen by the person quoting it, gets repeated in a
README and believed.

## Decision

### 1. The false-positive rate goes first, and it is two numbers

**First in the report, not a footnote after the flattering figures.** A firewall
that withholds legitimate documents gets switched off, and a switched-off
firewall's recall is zero (ADR 0036, ADR 0039). Ordering the report this way is
the same claim those ADRs make, made where somebody will actually read it.

Two rates, not one: **flagged** (any finding at all) and **withheld** (actually
stopped). They are different events with different costs — one spends an
analyst's afternoon, the other loses a document somebody needed — and folding
them into one number hides which happened.

### 2. Recall and precision are sliced by *different things*

This is the decision most likely to be got wrong by a harness that looks
correct, because the two slicings share names:

- **Recall is indexed by what an attack *is*** — `AttackFamily`, assigned by the
  corpus author. *"Of the six `direct_override` attacks I wrote, how many did
  the firewall notice?"*
- **Precision is indexed by what the firewall *said*** — `Family`, reported by a
  detector. *"Of everything the firewall called `direct_override`, how much was
  actually an attack?"*

They are different denominators over different populations. A `boundary_escape`
attack caught by the instruction-override pattern is a hit for `boundary_escape`
recall and for `direct_override` precision, and a single per-family table
carrying both would silently invite a reader to divide one by the other. So:
two tables, each naming its slicing in its own header. The types differ too —
`AttackFamily` is a superset of `Family` — so a row type that could hold either
would let them be conflated without a type error.

### 3. Precision's denominator spans both corpora — so both are screened under
**one** deployment

Precision computed over attacks alone is structurally 100% and measures nothing;
the denominator has to include the benign documents the firewall flagged.

Which forces something easy to miss. The benign corpus was written for an
organisation whose hosts are `wiki.internal` and whose catalogue contains
`crm__search`; the attack corpus was written against `docs.corp` and
`mock-a__search`. The existing corpus tests screen each under its own settings,
correctly, because each measures its own corpus. **A precision figure cannot.**
Its denominator would be assembled from two differently-configured firewalls —
a ratio between numbers that were never comparable.

So the harness defines one `Deployment`, the union of both, and reports which
one with every set of numbers. `disallowed_url` and `tool_name_mention` are
*entirely* a function of the allow-list and the catalogue, so a rate quoted
without its deployment cannot be reproduced or disputed.

The union is also the honest direction. Adding the benign organisation's hosts
to the allow-list cannot help an attack exfiltrating to a host in neither corpus,
and adding the attack corpus's tool names to the catalogue can only make
`tool_name_mention` fire *more*, on both sides. Neither change flatters the
firewall. It also fixed three apparent mismatches that were an artefact of
screening tool-confusion attacks against a catalogue they could not refer to.

### 4. Percentile bootstrap, and the case where it has nothing to say

Not a normal approximation. The Wald interval is the standard choice and is wrong
in exactly the cases this corpus is made of — small n, rates near 0 or 1 — where
it produces intervals running below zero or above one. A false-positive rate of
−3% is not reportable. Resampling makes no distributional assumption, and a few
thousand resamples of a list of booleans is free at this size.

**And the bootstrap's real limitation is surfaced rather than smoothed over.**
When every observation agrees — 0 of 6 `plain_assertion` caught — every resample
also agrees, so the percentile interval collapses to a point. That point is not
certainty; it is the estimator running out of things to say. Those intervals are
marked `degenerate` and render as `[uninformative]`. **A harness whose weakest
rows look like its most confident ones is worse than no harness.**

The generator is injected and the seed fixed, for the same reason the rate
limiter takes `now`: an interval that moves when nothing moved is one a reader
learns to ignore.

### 5. Still no aggregate detection rate

ADR 0036 argued it; this keeps it structural. An average over families that
include `plain_assertion` (which nothing catches, by construction) and
`obfuscation` (which is mostly withheld) is a number whose value is set by how
many of each somebody chose to write. It measures the corpus. Two integration
tests assert no such attribute exists.

Relatedly, attacks the corpus expects nobody to catch **stay in the denominator**
(ADR 0040). Recall over only the catchable attacks is a statement about the
corpus author's choices.

### 6. The report says what it cannot support

Every family here is under ten documents. The harness says so in its own output
rather than leaving a reader to check seven denominators, names the degenerate
intervals, and **lists the benign documents that tripped a detector by id** — a
rate says how often, and only the list says what. Task 48's entire result came
from reading the six documents, not from the 5.7%.

### 7. The held-out split is named on every run and scored on none

`scripts/evaluate.py` reports the **development** split. The held-out split's
identity and size are printed with every report — so the seal is visible in the
artifact rather than asserted in a document nobody opens — and scoring it
requires `--unseal`, which prints a banner saying what reading it costs.

The reasoning is ADR 0041's, taken seriously. The split's entire value is that
nothing in it has influenced a detector. A harness that printed the held-out
number on every run would be read on every run, and by the third iteration of
"that moved, let me try something" the split has become a second development set
wearing a label — **not through dishonesty, through the ordinary tuning loop.**
The seal is not a file permission; it is a habit, and the flag exists to make
breaking it a decision somebody made rather than a default they inherited. An
integration test asserts the default stayed the default, because otherwise the
guarantee is a habit and a habit is not something a repository can hold anyone
to.

## What the first run said

Deterministic patterns only, enforce mode, development split (36 attacks), 106
benign documents:

| | rate | interval |
|---|---|---|
| benign flagged | 19.8% (21/106) | [13%, 27%] |
| benign **withheld** | **0.0%** (0/106) | uninformative |

| recall (corpus's family) | any finding | withheld |
|---|---|---|
| `exfiltration` | 100% (5/5) | 0% |
| `obfuscation` | 86% (6/7) | 57% |
| `direct_override` | 83% (5/6) | 0% |
| `tool_confusion` | 75% (3/4) | 0% |
| `boundary_escape` | 25% (1/4) | 0% |
| `delayed_multi_step` | 0% (0/4) | 0% |
| `plain_assertion` | 0% (0/6) | 0% |

| precision (firewall's family) | real | split |
|---|---|---|
| `obfuscation` | 67% (6/9) | 6 attack / 3 benign |
| `direct_override` | 53% (8/15) | 8 attack / 7 benign |
| `exfiltration` | 42% (5/12) | 5 attack / 7 benign |
| `tool_confusion` | 38% (3/8) | 3 attack / 5 benign |

**The new information is precision, and it is not flattering: under half of what
this firewall flags is an attack.** Every earlier measurement was a false-positive
*rate* — how often a benign document trips something — which task 48 already put
at ~19%. Nobody had asked the complementary question, and the answer is that a
finding from this firewall is close to a coin flip.

That is survivable only because of the row above it: **0 of 106 benign documents
were withheld.** The bar between "found something" and "acted on it" (ADR 0038,
as amended by 0039) is carrying the entire deployment. Precision at the *finding*
level being ~50% while precision at the *refusal* level is untested-but-clean is
precisely the shape ADR 0036's detect-before-deciding split was built to allow —
and it means any future proposal to lower the enforcement bar has a number to
argue against now, which it did not before.

`plain_assertion` and `delayed_multi_step` at 0% are not failures. They are ADR
0040's prediction confirmed, in the same table as the successes, which is where
a reader should see them.

**Reproduce with `make eval`** — 2,000 resamples at seed 20260812, the shipped
defaults. The seed is fixed precisely so a figure quoted here can be checked
against a run, and so a number that moves means the firewall moved.

**These figures are from a corpus of 36 development attacks. Every family is
under ten documents; the intervals, not the percentages, are the honest part.**

## Alternatives considered

**One per-family table with both metrics.** Rejected — see decision 2. It invites
an F1 nobody can compute correctly from those columns.

**Report an F1 or a single headline number.** Rejected for the same reason as the
aggregate detection rate: it needs precision and recall over a common population,
and here they are over different ones. A single number would also be exactly the
thing that gets quoted without its interval.

**Wilson or Wald intervals.** Wilson would be defensible and behaves well near
the boundaries. Rejected in favour of the bootstrap because it generalises to the
statistics this harness will grow (per-detector rates, ratios), and because
resampling makes the estimator legible to a reader who does not want to check a
closed form.

**Score the held-out split by default.** Rejected — decision 7. This is the whole
point of having one.

**Assert specific rates in the test suite.** Rejected. A test asserting "false
positives are 19.8%" fails the day somebody improves a detector, which is the
wrong incentive entirely. Behaviour changes are already caught by the corpus's
recorded expectations, which fail in *both* directions; the tests here assert the
harness's contract, not its output.

## Consequences

- New `acp.corpus.metrics` (`Interval`, `Proportion`, `bootstrap`, `measure`) and
  `acp.corpus.harness` (`Deployment`, `Report`, `RecallRow`, `PrecisionRow`,
  `evaluate_firewall`). Both pure but for the firewall itself.
- New `scripts/evaluate.py` and `make eval`. Exit 1 on an expectation mismatch,
  so it is usable as the gate task 53 formalises.
- `ACP_FIREWALL_CLASSIFIER_ENABLED=1 make eval` is the first measurement of task
  51's classifier, and the report names which detectors produced its numbers so a
  run with the model on cannot be mistaken for one without it.
- `acp.corpus.evaluate`'s `Scoreboard` stays as it is. It is what the corpus
  *tests* assert against — pass/fail on recorded expectations — and this harness
  is what a human reads. Merging them would put confidence intervals in a test
  assertion, which is not what a test assertion is for.

## References

- ADR 0036 — detect before deciding, and count the false positives
- ADR 0038 — refuse loudly, refuse rarely, never quote the payload
- ADR 0039 — the benign corpus, and the two detectors it demoted
- ADR 0040 — the adversarial corpus, and the attacks nothing catches
- ADR 0041 — the held-out split (the seal this harness declines to break)
- ADR 0042 — the optional model classifier (measured here for the first time)
