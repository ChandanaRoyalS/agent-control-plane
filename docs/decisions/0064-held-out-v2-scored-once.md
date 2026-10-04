# ADR 0064 — Held-out v2, scored once

**Status:** accepted
**Date:** 2026-10-04

## Context

ADR 0061 sealed 35 of InjecAgent's 62 attacker instructions (1,190 documents)
as held-out v2, chosen by a hash rule a test re-derives. ADRs 0061–0063 then
measured, on the development half only, three things: the pattern firewall
(0 of 459 polite attacks caught, 459 of 459 "ignore previous instructions"
attacks caught, nothing withheld), two text detectors (neither integrated), and
two policies against the tool calls the attacks need (27 of 27 blocked or held).
Nothing about the firewall or the policies changed after those numbers were
read. This is the one scoring of v2.

## Results — held-out v2, 35 instructions, scored 2026-10-04

**Pattern firewall** (`evaluate_external.py --unseal`):

| slice | instructions | caught | withheld |
|---|---|---|---|
| dh base | 15 | **0 / 255** | 0 |
| dh enhanced | 15 | **255 / 255** | 0 |
| ds base | 20 | **0 / 340** | 0 |
| ds enhanced | 20 | **340 / 340** | 0 |

Every catch was `direct_override`. All 70 controls from the one template with a
non-allow-listed URL were flagged on their own, as on development.

**Policy engine** (`evaluate_actions.py --unseal`):

| policy | subset | blocked | held | executes |
|---|---|---|---|---|
| least privilege | dh | 15 | 0 | **0** |
| | ds | 20 | 0 | **0** |
| reads allowed, writes held | dh | 0 | 15 | **0** |
| | ds | 0 | 20 | **0** |

The users' 17 task tools: allowed under both policies.

## What it says

- **Development generalised exactly.** Every held-out row matches its
  development counterpart in shape: the firewall catches the announced
  injection and none of the polite ones; the policies stop every attack's tool
  chain. No held-out attack needed only reads.
- **The intervals are uninformative because the outcomes are unanimous**, and
  the harness says so. The honest bound for a unanimous result is the rule of
  three: no policy failure in 35 independent instructions puts the failure rate
  below about 3/35 ≈ **9%** at 95% confidence — for this attack distribution,
  under these two policies. The same bound applies to the firewall's polite-form
  recall from the other side: at most about 9%.
- **The ADR 0063 disclosure does not touch this result.** The two held-out tool
  names seen while building the importer (`DisableTwoFactorAuthentication`,
  `GoToRoom`) are writes under `READ_VERBS`, which was written before they were
  seen and never changed. They are held under the broad policy and blocked under
  least privilege, like every other held-out chain.

## Decision

1. **Held-out v2 is spent.** `heldout.txt` carries `unsealed: 2026-10-04, ADR
   0064`, emitted by the importer so a re-import cannot re-seal it; both scripts
   say so on every later `--unseal`, and a test pins the line.
2. **These are the numbers to quote**, held-out v2, InjecAgent, 35
   instructions:
   - pattern firewall: polite form **0/595**, announced form **595/595**, **0
     withheld**;
   - least-privilege policy: **35/35** attack chains blocked;
   - reads-allowed, writes-held policy: **35/35** held for a person;
   - cost to the users' own task tools: **none**.
3. **The next held-out split needs a new source.** All 62 InjecAgent
   instructions have now been read. A v3 comes from a corpus nobody here has
   scored — the same rule as v2.

## Consequences

- The project's injection-defence claim has an external, held-out, pre-registered
  number for each layer, and the layers' roles are measured rather than asserted:
  text screening for the loud injection, policy for the quiet one's action.
- The caveats of ADR 0063 carry over unchanged: this is what the gateway does if
  an agent is fooled, not how often; a hold is only as good as the person
  reading it; InjecAgent's user tasks are all reads, so the zero burden flatters.

## References

- ADR 0041 — the held-out discipline
- ADR 0060 — held-out v1, scored once
- ADR 0061 — InjecAgent and the split
- ADR 0063 — the policy result on development, and the disclosure
