# ADR 0041 — The held-out split: the attacks the firewall may not be built against

**Status:** accepted
**Date:** 2026-08-12

## Context

Task 49 gave the firewall an adversarial corpus and task 52 will report a
detection rate over it. But a rate over the corpus the firewall was *tuned on*
answers the wrong question. It measures fit: does the firewall catch the attacks
it was shaped by — which it must, because they are what shaped it. Every detector
added between now and task 52 will be written by a person who has read these
attacks, and a detector written against an attack catches that attack by
construction. The number that means something is the one over attacks the
firewall has never seen. That requires setting some aside, sealed, before the
tuning starts.

## Decision

**A committed, versioned manifest of attack ids held out of the development
corpus, and a development loader that excludes them by construction.**

- **A manifest, not a random draw.** `corpus/heldout.txt` lists the held-out ids
  by hand, versioned. A random split fails the three things that matter: it
  changes every run, it cannot be shown sealed in a diff, and nothing stops
  re-rolling it until the numbers flatter. A committed list is a fact in git a
  reviewer can check and a test can enforce.

- **One attack per family, chosen by id alphabetically.** A rule a machine
  applies, not a judgement made while looking at the documents — because looking
  at them to choose is the first crack in the seal. Every family is represented,
  so the split measures generalisation *per family*, which is the only way it can
  be read given that two families are uncatchable by design (ADR 0040). Seven of
  forty-three held out; thirty-six remain to tune against.

- **The development loader excludes the split; the held-out set is never scored
  during development.** `load_development_attacks()` is what task 51's tuning
  calls — it returns the corpus with the manifest removed, so a detector cannot
  be shaped by a sealed document without someone deliberately reaching past this
  function. `make corpus` *describes* the split (version, sizes, families) but
  does not run the firewall against it: scoring the held-out set on every change
  would leak its results into tuning decisions, which is the contamination the
  split exists to prevent. The held-out number belongs to task 52's harness, run
  deliberately.

- **Versioned, so a measurement can name what it was measured against.**
  "Measured against held-out v1" is reproducible; "measured against the held-out
  set" is not, once the set has moved. When the split changes, the version
  changes with it.

## The seal is tested, and the test cannot be satisfied by emptying the split

The property — nothing tuned against is held out — is asserted directly:
`load_development_attacks()` is disjoint from the manifest. But a seal test alone
has the failure mode lesson 21 names: it passes if the split holds nothing out.
So three anti-filler assertions guard it — the held-out set is non-empty, every
family is represented, and development plus held-out lose no document between
them. Emptying the manifest, or dropping a family from it, turns one of these
red. A test whose failure can be fixed by deleting the awkward data is not a
test; these are the tests that fail *when* the data is deleted.

## Alternatives considered

**A hash-based partition** (held out iff `hash(id) % k == 0`). Deterministic and
needs no manifest, but the split is invisible without running code and reshuffles
silently if the hash changes. A split nobody can read in a diff is a split nobody
can trust is sealed.

**Authoring fresh held-out attacks later** rather than holding out existing ones.
Keeps the development corpus whole, but the held-out set is empty until task 51,
so the seal has nothing to bite on now and the anti-filler tests cannot run.
Holding out existing attacks makes the split real today.

**Holding out a fixed fraction regardless of family.** Rejected — a 20% draw
could miss a family entirely, and a held-out set missing a family cannot report
generalisation for it. Per-family coverage is what makes the number readable.

## Consequences

- New `acp.corpus.heldout`: `HeldoutManifest`, `load_heldout_manifest`,
  `split_attacks`, `load_split`, and `load_development_attacks` — the loader task
  51 should tune against. `corpus/heldout.txt` ships as version 1, seven ids.
- `make corpus` gains a held-out description. It is deliberately not scored there.
- Task 51 (a local classifier) tunes against `load_development_attacks()`; task
  52's harness is the first thing permitted to score the held-out split, and
  reports it separately from the development number with the version named.

## References

- ADR 0039 — the benign corpus (measure before defending a threshold)
- ADR 0040 — the adversarial corpus, sliced by family (no aggregate rate)
- Lesson 21 — a corpus needs an anti-filler assertion or it rots into proof of
  its own tidiness
