# ADR 0080 — More attacks did not move the ones that matter

**Status:** accepted
**Date:** 2026-10-05

## Context

ADR 0079 imported AgentDojo as data version 2 and fixed, before training, the rule a
model trained on it ("v2") must meet to replace the gateway's model ("v1"): at each
model's enforce threshold, catch more of the 37 internal attacks than v1's 3, withhold
no more of the 106 internal benign documents than v1's 1, and withhold no more of
BIPIA's 200 clean test contexts than v1's 4.

## Decision

**v2 was trained once**, by ADR 0075's procedure on data version 2
(`scripts/train_classifier.py --data-version 2`): 3,950 windows, `C = 8`, 244 weights,
report threshold 0.612, enforce threshold 0.706. Its file is committed as
`corpus/learned/v2-candidate.json` and it is deterministic like v1.

**Both models were scored once** by `scripts/compare_learned.py`, recorded in
`corpus/learned/v2-comparison.json`.

**The rule, at enforce:**

| | v1 | v2 | rule |
|---|---|---|---|
| internal attacks caught (37) | 3 | 3 | more: **failed** |
| internal benign withheld (106) | 1 | 5 | no more: **failed** |
| BIPIA test clean withheld (200) | 4 | 4 | no more: met |

**v2 does not replace v1.** The gateway's model is unchanged.

## Results

**AgentDojo's sealed half, a first look for both models**, at enforce:

| | v1 | v2 |
|---|---|---|
| attacks caught (500, 11 goals) | 76.2% [64–88] | 96.4% [92–99] |
| clean tool outputs withheld (30) | **23.3% [10–40]** | 6.7% [0–17] |
| by template: `important_instructions` (never trained on) | 98% | 100% |
| `injecagent` | 94% | 100% |
| `ignore_previous` | 77% | 99% |
| `direct` (`TODO: <goal>`) | 57% | 91% |
| `system_message` | 55% | 92% |

v2 is in distribution here and v1 is not, which is why this set did not decide.

**v2 on BIPIA test and evasion v1, a third look:** 62.6% of attacks at enforce (v1:
64.2%), 2.0% of clean contexts (v1: 2.0%); evasion v1 29.4% (v1: 28.8%), with the same
near-zero results on homoglyphs, spacing, leetspeak and base64.

## What this shows

- **Adding AgentDojo did not change what either model catches of this project's own
  attacks.** Both catch the same 3 of 37. Those attacks are mostly exfiltration links,
  boundary escapes and tool confusion, not instructions; a classifier of instruction
  text does not see them, and the pattern detectors remain the better control there.
- **It made v2 withhold more of this project's benign documents** (5 against 1): an
  ADR quoting a prompt-injection example, a CVE advisory, an API reference listing
  errors, an FAQ about agents and a customer complaint.
- **v1 withholds 7 of 30 clean AgentDojo tool outputs (23%).** They are ordinary emails
  and a landlord's notice that ask the reader to do something ("Please make sure to
  update your records"). This is the highest false-positive rate measured for v1, and it
  is on the kind of text this gateway screens. The 2% on BIPIA's clean contexts
  understated it. ADR 0076 and the README now say so beside the setting.
- AgentDojo's templates are easy for both models; its plain `TODO:` and
  `###(system_message)` wrappers are where v1 is weakest.

## Consequences

- `learned_model.json` stays v1; `ACP_FIREWALL_LEARNED=enforce` remains opt-in, and its
  documented false-positive range now includes the 23% on AgentDojo's tool outputs.
- `scripts/train_classifier.py` takes `--data-version` and `--out`; `--check` refits
  with the committed model's data version, so a future swap stays checked in CI.
- AgentDojo's sealed half is spent for this model family.
- The next lever is not more attack text but benign text shaped like tool outputs:
  polite requests in emails and notices are what the classifier mistakes for attacks.

## References

- ADR 0075, ADR 0076 — v1 and its place on the request path
- ADR 0079 — the data and the rule
- `corpus/learned/v2-comparison.json`, `corpus/learned/v2-candidate.json`,
  `scripts/compare_learned.py`
