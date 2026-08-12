# ADR 0047 — A baseline, not a threshold

**Status:** accepted
**Date:** 2026-08-12

## Context

Task 52 turned the firewall into numbers. Task 53's job is to keep them from
quietly getting worse: *"fail the build when detection drops or false positives
rise beyond threshold. This is what turns the firewall from a claim into a
maintained property."*

The word to argue with is **threshold**.

A threshold is a number somebody picked once, written in a config file, and it
can be raised by whoever the build is annoying that week. "False positives must
stay under 25%" survives exactly until a change pushes it to 26%, at which point
the cheapest fix is to edit the 25. Nothing about that reads as a decision —
it reads as a one-character diff that no reviewer interprets as *"we have
accepted more false positives"*. The gate ends up measuring the team's patience
rather than the firewall.

There is also a subtler problem with thresholds here: they are stated as rates,
and the rates move when the *corpus* changes. Adding one benign document shifts
every percentage in the report without anything about the firewall changing at
all.

## Decision

**A committed baseline, compared by counts, with three outcomes.**

### 1. A baseline, not a threshold

`corpus/eval-baseline.json` records what the firewall did the last time somebody
decided it was acceptable. The gate diffs against it. This is the same shape as
`config/schema-baseline.json` and for the same reason (ADR 0013): the artefact is
committed, so **every change to the numbers is a line in a pull request with a
person's name on it.**

Accepting a regression stays entirely possible — `--capture` and commit — and
stops being invisible. That is the whole design. A gate nobody can override gets
disabled; a gate whose override is a reviewable diff gets used.

`--capture` is a separate verb rather than a `--fix` flag on `--check`,
deliberately. Accepting a change to a security control's measured behaviour is a
decision, and a decision that happens as a side effect of running the check is
one nobody made.

### 2. Counts, not rates

The baseline stores `21 of 106 flagged`, not `19.8%`.

A rate hides its own denominator: 19.8% and 20.7% look like drift and are one
document. Counts make the corpus size *part of the comparison*, which is what
turns "the corpus grew" from an invisible shift in every percentage into an
explicit finding.

### 3. Three outcomes, and the third is the one a simpler design gets wrong

- **Regression** → exit 1. Some count got worse.
- **Improvement** → exit 0, and the report says the baseline now understates the
  firewall. A gate that failed on *any* change is a gate people disable the first
  time they improve something. But it is worth saying out loud, because a
  baseline nobody refreshes drifts into recording a state the firewall left
  months ago — and a gate against a stale baseline would not notice a regression
  back to it.
- **Structural** → exit 2. The corpus grew, a family appeared or vanished, the
  deployment moved, a detector was added. **The two runs are not comparable.**

That third case matters. Reporting it as a regression sends somebody hunting a
bug in the firewall that is really a document they wrote. Reporting it as a pass
lets a corpus change smuggle one through. So it is its own outcome, with its own
exit code, and it suppresses the count diff entirely — a list of "regressions"
derived from incomparable numbers is worse than no list.

The exit codes are distinct for the same reason `simulate` distinguishes its
codes from `USAGE_ERROR`: a CI job that could not tell "find what broke" from
"re-capture, the ruler changed" sends people to the wrong place.

### 4. Every count has a direction

Detection falling is a regression; rising is not. False positives rising is a
regression; falling is not. `withheld` is tracked **separately from** `flagged`
on the benign side, because a flagged benign document costs an analyst an
afternoon and a withheld one is a document somebody needed and did not get —
different events, different costs, and only one of them is how a security
control ends up switched off.

Per-*reported*-family counts are tracked too, not just the totals. A detector can
start firing on benign documents while another stops, leaving the overall flagged
count unmoved; and a detector that goes silent entirely is a regression even when
no family total moved.

### 5. The gate runs the deterministic layer only

No classifier. Gating on a model's output would make the build flaky in a way
nobody could distinguish from a real regression — a red build that goes green on
re-run teaches people to re-run, which is the end of the gate's usefulness. The
classifier is optional and off by default (ADR 0042), and enabling it registers
as a **structural** change here rather than as a set of improvements, because
comparing across it would credit the model with the patterns' work.

### 6. `prove-predispatch` joins the quality job

Not part of task 53, but the same class of thing and the same file. Three of the
four mutation harnesses ran in CI; the fourth has been passing only on demand
since task 35. A harness that runs when somebody remembers is a harness that
stops running.

## Alternatives considered

**A percentage threshold in `pyproject.toml`.** Rejected — the whole argument
above. It is editable without ceremony and it moves when the corpus moves.

**A tolerance band ("fail if FPR rises more than 2 points").** Rejected. Every
input to this gate is deterministic — the detectors are patterns, the corpus is
committed, the bootstrap is seeded — so there is no noise for a band to absorb.
A tolerance here would only ever absorb *real* regressions, one document at a
time, which is exactly how a control degrades without anybody deciding to
degrade it.

**Fail on any change, including improvements.** Rejected — see decision 3. It
makes the gate an obstacle to the thing it is protecting.

**Store the confidence intervals in the baseline and compare those.** Rejected.
The intervals are a property of the sample size, so they move whenever the corpus
does, and comparing them would fire on every corpus change while adding nothing a
count comparison does not already catch. The intervals are for a human reading
the report; the counts are for the gate.

**Gate on the held-out split.** Rejected, firmly. It would read the sealed split
on every pull request, which is precisely the failure ADR 0041 exists to prevent
— and it would make the seal a thing CI breaks automatically, which is worse than
a person breaking it deliberately.

## Consequences

- New `acp.corpus.baseline` (`Baseline`, `Comparison`, `baseline_from`,
  `load_baseline`, `compare`) — pure, and it consumes the same `Report` the human
  report is rendered from, so the gate and the numbers somebody quotes cannot
  disagree.
- `scripts/evaluate.py` gains `--check` and `--capture`; exit 1 on regression or
  an expectation mismatch, 2 on a structural change.
- `corpus/eval-baseline.json` is committed, beside the corpus it describes rather
  than in `config/` — it is a property of the documents and the detectors
  together and is meaningless without them.
- New `make eval-check`, and a CI step running it on every pull request.
- `prove-predispatch` added to the CI quality job.
- The baseline carries a `version`, and an older one is refused rather than
  silently upgraded: a mismatched baseline compared field-by-field skips whatever
  the two versions do not share, which is a gate that passes because it stopped
  looking.

## References

- ADR 0013 — schema drift is a security control (the baseline pattern this copies)
- ADR 0036 — detect before deciding, and count the false positives
- ADR 0041 — the held-out split (why the gate does not touch it)
- ADR 0042 — the optional model classifier (why the gate does not run it)
- ADR 0046 — the harness whose report this gate reads
