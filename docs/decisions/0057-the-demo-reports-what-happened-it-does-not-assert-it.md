# ADR 0057 — The demo reports what happened; it does not assert it

**Status:** accepted
**Date:** 2026-08-14

## Context

Task 64: *"Same agent twice: direct, it reads a poisoned document and
exfiltrates; through the gateway, it is stripped, denied and logged. The single
most valuable artifact in the project — everything else is why it works."*

The plan is right that it is the most valuable artifact, which is exactly why it
is the easiest one to make worthless. A demo of a security control is a
performance whose author chose the script, the actor and the ending. Three
temptations, all of them ordinary, each fatal:

1. **Put the payload in the corpus**, so the demo's attack is one the measured
   evaluation has scored.
2. **Tune the payload until the firewall catches it**, so act three has a
   satisfying ending.
3. **Assert the outcome** — "the gateway blocks it" — and let the script fail
   loudly if it does not.

Every one produces a better-looking demo and a worse project.

## Decision

### 1. The payload is not in the corpus, and the demo says so

`corpus/` produces the recall and precision numbers in ADR 0047 and
`docs/THREAT_MODEL.md`. A hand-written attack, designed by the same person who
wrote the detectors, added to that corpus, would raise those numbers **by
construction.**

That is precisely the failure the held-out split (ADR 0041) exists to prevent,
arriving through a door nobody was watching: not by testing on the training set,
but by *writing* the test set to match.

So the two documents live in `acp.mocks.mock_a`, and the demo states in its own
output that its payload is not corpus material and that the published detection
rates are 75% recall and 38% precision on this family. **The demo illustrates;
the corpus measures.** Confusing the two would let a project claim its most
flattering anecdote as evidence.

### 2. The payload is written for realism, not for detectability

It is a plausible incident runbook with an instruction block in the middle: a
named workflow, real tool names, and a claim that approval has already been
given. That is the shape the corpus's `tool_confusion` family takes, because it
is the shape that works on a model reading retrieved text.

It was not adjusted after seeing what the firewall did with it. If a later
change to the detectors means this document is no longer flagged, that is a
finding about the detectors and the demo will report it.

### 3. The script reports; it does not assert

There is no expected outcome anywhere in `scripts/attack_demo.py`. It prints
what each call returned — served, held, refused, withheld — and ends by asking
the reader which layer stopped it.

**Defence in depth is only a claim worth making if you can show which layer
caught it.** A demo that asserts "blocked" tells you nothing about whether the
firewall, the policy or the approval gate did the work, and a project with three
controls and no idea which one is load-bearing has one control and two
decorations.

This also means the demo cannot rot into a lie. A regression makes it *print
something different*, not fail — and a reader sees the new truth rather than a
red cross whose cause they have to go and find.

### 4. Two runs, because the default posture is the interesting one

`make attack-demo` runs against the composed stack, where the firewall is in
`report` (ADR 0038's starting posture): screening logs everything and withholds
nothing, the poisoned document reaches the agent, and the **approval gate** is
what stands between a runbook and a salary table in a ticket title.

`make attack-demo-enforce` restarts the gateway with `ACP_FIREWALL_MODE=enforce`
and runs the same script. If the document crosses the enforcement bar the agent
is never shown the instruction.

The pair is the argument. A single run showing the firewall winning would hide
that most deployments will start in `report`, and that the layer which actually
saves them there is a human being asked a question.

> **Measured: the two runs are identical**, for a reason worth more than the
> contrast would have been. See below.

### 5. The agent is a parser, and the substitution is defended rather than hidden

`acp.demo.agent` finds instructions in retrieved text and calls the tools they
name. It is not a language model: a model costs an API key, a network round trip
and reproducibility — three runs would produce three transcripts, and a reviewer
could not tell a fixed gateway from a model in a better mood.

**The gateway never sees an agent's reasoning. It sees tool calls.** Whether
those came from a model that was persuaded, a parser that was literal-minded, or
a compromised process typing them by hand is information the gateway does not
have and does not use — so the thing under test is unchanged by the
substitution.

What the demo does *not* claim is that the model half is realistic. It claims
that **an agent which acts on retrieved instructions is the failure mode**,
which is documented and is the reason indirect prompt injection is a category.

Two things the parser got wrong first, both kept as tests:

- **It fired on a tool name merely mentioned**, turning an incident timeline
  reading *"alerts fire on p99 for mock-a__search"* into a tool call. Requiring
  an imperative makes the agent **less** credulous, which makes the demo harder
  on the gateway rather than easier. An agent that fires on prose makes the
  gateway look necessary for the wrong reason.
- **It scoped instructions by line**, and prose wraps: *"call read_document with
  path hr/compensation-2026.md"* split across two lines and the path went to the
  next call. The demo would have failed for a reason with nothing to do with the
  attack.

### 6. The exfiltration needs two innocuous calls, and the agent must be able to chain them

Reading a document is not a leak. Filing a ticket is not a leak. Filing a ticket
*containing* the document is.

So the parser recognises "the full contents of that document" and the driver
substitutes the previous result. An agent that could not carry a result forward
would be a fixture chosen to make the attack impossible — which is temptation 2
wearing a different hat.

## Measured — and the demo earned its design on the first run

Both runs, `report` and `enforce`, produced **identical output**. The poisoned
document reached the agent either way, and the exfiltration was stopped by the
approval gate.

Refusing to assert an outcome is what made that a finding instead of a failure.

### The firewall detected it and was not permitted to act

From the chain, for the read of the poisoned runbook:

```json
{"category":"firewall","event":"firewall.screened","tool":"mock-a__read_document",
 "outcome":"allowed",
 "detail":{"families":["tool_confusion"],"confidences":["high"],
           "finding_count":3,"trigger_count":0}}
```

**Three findings. High confidence. Zero triggers.**

`ENFORCEABLE` is `{bidirectional_override, encoded_payload}` — two detectors,
and the list is short because it was *measured*: those two produced zero
findings across the 106 documents of the benign corpus (ADR 0039). Everything
else produced some, and **a detector that fires on real documents cannot be
allowed to withhold them.**

So the detector that caught this was certain, and demoted, and the mode made no
difference because there was nothing enforceable to enforce.

### Why that is the best available outcome rather than a gap

It would have been easy to read this as a failure and fix it by promoting the
detector. That change would withhold this attack and, on the measured error
rate, withhold roughly one benign document in five — which is how a security
control gets switched off entirely (lesson 15), and then catches nothing at all.

**The demo now shows this rather than concealing it.** It prints the mode, the
enforceable list and the screening record, and it names the distinction that
matters: `findings` is what the detectors noticed; `triggers` is how many came
from a detector permitted to act. High findings with zero triggers means *the
firewall saw it and was not allowed to stop it* — a measurement decision, not a
bug.

### And the fence travelled with the payload

The ticket the agent tried to file through the gateway had a title beginning
`[BEGIN RETRIEVED DATA c6e889ed…] The following content (1 block: 1 text) was…`.

That is provenance framing (ADR 0037) doing exactly what it promises and nothing
more: the agent carried the *fenced* text forward, so what it attempted to
exfiltrate was the wrapped version. **The fence did not stop the leak; it
travelled with it.** Framing tells a model where text came from; it does not
prevent a model that has already been convinced from moving that text.

Worth stating plainly, because a fence in a transcript looks like a defence.

### So the honest one-line summary of this demo

*Three controls looked at this attack. The screening detector saw it and was
measured into silence. Provenance framing labelled it and was carried along with
it. A person, asked a direct question on a listener the agent cannot reach,
stopped it.*

That is a better argument for defence in depth than a run where the first layer
wins, and it is only available to a demo that was willing to report a result its
author did not choose.

## What the direct act is really for

The obvious reading is "unprotected". The more useful one is **unexplainable**:
the direct path leaves no record at all. Nobody could reconstruct afterwards
which document was read, by whom, or what left the building.

That is the half of the argument a security demo usually skips, because a
missing audit trail is invisible in a screenshot. The script says it out loud at
the end.

## The honest cuts

**One agent, one attack, one upstream.** This demonstrates a class; it does not
survey it. `delayed_multi_step` and `plain_assertion` are at 0% recall
(ADR 0047) and a payload from either would produce a run where the firewall does
nothing at all — which is *true* and is in the threat model, and is a different
demo.

**The mock is not a real SaaS.** The document store is a dictionary. What that
costs is realism about how a poisoned document gets *in*; what it buys is a demo
that runs offline, identically, on a laptop with no accounts.

**No video, no timing.** Task 69 is the recording. This is the thing being
recorded.

## References

- ADR 0038 — refuse loudly, and where a deployment starts
- ADR 0041 — the held-out split, and why writing the test set is the same sin
- ADR 0047 — a baseline, not a threshold; the measured 75% / 38%
- ADR 0049 — the operator channel the human answers on
- `acp/demo/agent.py` — why a parser is a fair stand-in for a model
