# ADR 0065 — The catalogue is screened too

**Status:** accepted
**Date:** 2026-10-05

## Context

Every tool *result* passed through the firewall. No tool *description* did.
A description is prose an upstream writes and the model reads before it does
anything, on every turn, in the most trusted position the context has; an
upstream that wants to address the model does not need to poison a document.
The threat model named this the cheapest high-severity gap in the system
(section 6.2), schema drift (ADR 0013) notices only when a description
*changes*, and an outside review of the repository put it first among the
gaps. The machinery to close it already existed and was pointed at the wrong
input.

Two questions had to be answered before it could be pointed at this one. Does a
screen built for documents flag ordinary tool descriptions, which are short,
imperative and full of instructions by design? And what should happen to a tool
whose description crosses the bar, given that a description cannot be fenced —
provenance framing (ADR 0037) says "treat this as data", and a description's
whole purpose is to be followed?

## Measured first

The pattern detectors were run over **1,102 benign tool descriptions**: all 38
toolkit descriptions, 330 tool summaries and 728 parameter descriptions in
InjecAgent's catalogue (`corpus/external/injecagent/descriptions.jsonl`, written
by other researchers with no attack in them), plus this project's six mock
tools, each screened as a tool with the full catalogue as "others".

| kind | texts | flagged | would be withheld |
|---|---|---|---|
| toolkit | 38 | 0 | 0 |
| tool | 330 | 0 | 0 |
| parameter | 728 | 0 | 0 |
| mock | 6 | 0 | 0 |

Zero findings. That is a floor, not a ceiling: these descriptions carry no
URLs, and a real catalogue that links to its documentation would produce
`disallowed_url` findings — report-only, so served, but counted. The result
says the two enforceable detectors (bidirectional override, base64 that decodes
to an instruction) cost nothing on this population, which is what let them
enforce.

On the attack side, `corpus/descriptions/poisoned.jsonl` holds eight poisoned
descriptions written by the detector's author — so a behaviour check with
recorded expectations, not a generalisation estimate:

| description | expected | got |
|---|---|---|
| override phrase in the summary | detected, served | ✓ |
| another upstream's tool named in a parameter description | detected, served | ✓ |
| right-to-left override in the summary | **withheld** | ✓ |
| base64 override in the summary | **withheld** | ✓ |
| zero-width characters splitting the phrase | detected, served | ✓ |
| markdown image to an outside host | detected, served | ✓ |
| fake system turn | detected, served | ✓ |
| a polite false claim ("deletions are pre-approved") | **undetected** | ✓ |

The last row is the same gap as ADR 0061's polite injection, and on this surface
there is no provenance frame to fall back on. The tool-call policy still applies
to whatever the description talks the model into calling.

## Decision

**Every tool's description, and every `description` string in its input schema,
is screened with the same detectors and the same bar as a result. In enforce
mode a tool that crosses the bar is withheld from the catalogue. Nothing is
fenced.**

- `Firewall.inspect_tool` screens one tool; `inspect_catalogue` screens a
  catalogue against itself, each tool told the catalogue *minus its own name*,
  so a tool is never flagged for naming itself while a tool naming another
  upstream's tool is exactly the tool-confusion signal it was.
- Schema descriptions are read at any depth, bounded at 32 levels, because the
  schema is upstream-supplied.
- `on_list_tools` screens after policy filtering, so a tool the caller may not
  see is neither screened nor recorded against them. A withheld tool is absent
  from the response; the alternative — serving it with a blanked description —
  would invent a tool the upstream did not describe.
- Report mode serves and logs, so a deployment can measure what enforcement
  would withhold from its own upstreams first, exactly as for results.
- Every flagged tool is chained to the audit log (`firewall.catalogue`, denied
  when withheld, allowed when served), with families and confidences and never
  the text. `firewall_decisions_total` gains a `surface` label (`result` |
  `catalogue`) so the two populations are not mixed.
- No new setting: the catalogue screen rides on the firewall's mode. The public
  surface is unchanged.

## Alternatives considered

- **Fence descriptions.** There is no honest frame for text that is meant to
  be followed; a fenced description would teach the model that fenced text is
  sometimes an instruction, the one belief ADR 0037 exists to prevent.
- **Serve the tool with its description removed.** Invents a catalogue entry
  the upstream never wrote, and a tool with no description is one the model
  will misuse.
- **Withhold on any finding.** `instruction_override` fires on a legitimate
  description that says "ignore case" or "do not retry"; the benign corpus
  demoted it for less (ADR 0039). The bar stays where it is.
- **A separate, stricter bar for the catalogue.** Tempting — a description is
  short and should be clean — but a second bar is a second thing to measure
  and the first has no false positives on 1,102 texts yet. Revisit with data.

## Consequences

- Section 6.2 of the threat model closes as written and reopens narrower: the
  polite poisoned description is not caught, and a description that only
  carries a URL is reported, not withheld.
- `tools/list` now does the pattern pass per tool. Microseconds per tool with
  no model; with the classifier attached it moves off the event loop like a
  result does, and costs a model call per tool per list — a reason to keep the
  classifier off on this surface until it earns its place (ADR 0060).
- A deployment whose upstream legitimately uses bidirectional text in a
  description would lose that tool in enforce mode. Report mode shows it first.

## References

- ADR 0013 — schema drift: a changed description is an attack
- ADR 0036, 0037, 0038 — detect, frame, refuse
- ADR 0039 — the detectors the benign corpus demoted, and why the bar is narrow
- `scripts/evaluate_descriptions.py` — the measurement
