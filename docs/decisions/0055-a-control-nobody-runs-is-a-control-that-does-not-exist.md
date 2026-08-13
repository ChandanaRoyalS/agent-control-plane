# ADR 0055 — A control nobody runs is a control that does not exist

**Status:** accepted
**Date:** 2026-08-13

## Context

Task 62's overhead measurement reads the running gateway's configuration and
prints it before it prints a number. On its first execution it printed this:

```
[on ] cost-weighted budget   a per-tool weight on the budget draw instead of a flat 1.0
[OFF] rate limit             a token-bucket draw per call
[OFF] quota                  a windowed counter per principal
```

`ACP_COST_FILE` is set in `docker-compose.yml`. `ACP_RATE_LIMIT_ENABLED` and
`ACP_QUOTA_ENABLED` are not, and both default to `False`. And
`gateway/server.py:_charge` opens with:

```python
if payer is None or (limiter is None and quota is None):
    return
```

**`config/costs.yaml` was parsed at every start to feed a decision nothing
made.** Tasks 39, 41 and 42 — rate limiting, cost weighting, quotas — built,
tested, merged, and inert in the only deployment anybody runs.

This is the sixth instance of one failure. `scripts/patch_compose_firewall.py`
exists because four features were inert at once: the cost table, the result
cache, provenance framing and the injection firewall. The config directory was
mounted the whole time; nothing pointed at it.

None of these produce an error. The gateway starts, serves traffic, passes its
smoke test, and is quietly a smaller system than the repository describes.

## Decision

### 1. Wire the budget controls, with numbers chosen for this deployment

Not the shipped defaults. `GatewaySettings` gives a burst of 60 and a sustained
1 call per second, which are reasonable for a real deployment and would make
`make load` report roughly ninety percent `THROTTLED` — a load test measuring
the limiter rather than the gateway.

The reverse — raising them for the perf run and leaving the demo at the defaults
— is the same mistake wearing a different hat: a published number measured under
a configuration nobody deploys, which is precisely what ADR 0054 exists to
prevent.

So the composed stack gets numbers that **bind for an abusive caller and not for
the load mix**:

| | value | why |
|---|---|---|
| burst | 500 | one principal in `make load` offers ~28 calls/s; an agent in a loop fires this immediately |
| sustained | 200/s | above the harness, far below a runaway |
| quota | 500,000/day | the mix averages ~2.8 cost units per call, so a 30 s run spends ~2,400 per principal |

All interpolated, so a demo can make either bind for one run:

```
ACP_RATE_LIMIT_CAPACITY=5 ACP_RATE_LIMIT_REFILL_PER_SECOND=1 \
    docker compose up -d --wait gateway
```

**This changes ADR 0054's numbers, and that is the register working.** Those
figures were measured with both switched off and the run said so on its face.
A later `make overhead` will print `[on]` for both and a slightly larger number.

### 2. The real fix is a test derived from the settings model

Wiring two variables fixes this instance. It has now been fixed by hand six
times, so the fix that matters is the one that makes a seventh impossible.

`tests/integration/test_compose_config.py` now enumerates **every setting in
`GatewaySettings` whose default leaves a control off** — `False`, `None`, or an
enum whose value spells `off` — and asserts each is either set in the gateway's
compose environment or named in `DELIBERATELY_OFF` **with a reason**.

Derived rather than listed, and that is the whole design. A hand-written list is
a list somebody has to remember to extend, and the failure being guarded against
*is somebody not remembering*. A feature added tomorrow with an off default fails
this test until a person decides which of the two it is.

**The escape hatch is deliberately awkward.** A reason under 40 characters fails,
and a name that no longer exists in `GatewaySettings` fails — because an excuse
that silently stops matching a setting is an excuse that stops excusing anything
while the real setting goes unchecked.

Five entries today, each naming why the demo does not run it: no second realm to
give tenancy a policy directory, no Ollama for the classifier, single-issuer
settings rather than an issuers file, and no static credential for the secrets
store because both upstreams take an exchanged token.

### 3. Parsed from the file, not from `docker compose config`

`docker compose config` **resolves interpolation**, so
`${ACP_QUOTA_ENABLED:-true}` renders as `true` and a variable that is merely
defaulted becomes indistinguishable from one that is pinned.

That is not a hypothetical: the verify line first shipped with
`patch_compose_ablate.py` used exactly that command, and it could not have
failed. A check the subject can satisfy is not a check — ADR 0050's decision 10,
in a smaller key.

## Consequences

- The composed stack enforces rate limits and quotas, so `THROTTLED` becomes a
  reachable outcome in `perf/scenarios.py`'s classifier for the first time.
- ADR 0054's overhead figures describe a gateway with budgets off. They are not
  restated, because the run that produced them printed the configuration that
  produced them.
- Any future optional control must be wired or excused before `make check`
  passes.

## What this does not fix

**The same failure can still happen one layer out.** This test checks the
gateway's environment in `docker-compose.yml`. It says nothing about a
Kubernetes manifest, a Helm chart or a systemd unit, none of which exist here.
The general form of the bug — *a control configured nowhere is a control that
does not run* — is a property of every deployment artefact, and this repository
has one.

**And it checks that a name is mentioned, not that a value is sensible.**
`ACP_RATE_LIMIT_CAPACITY: 999999999` would pass. Choosing numbers is decision 1's
job, and no test can hold it: the right burst for a demo and the right burst for
production differ, and both are judgement.

## References

- ADR 0044 — what the rate limiter deliberately does not do
- ADR 0050 §10 — a control the party under suspicion can satisfy is not a control
- ADR 0054 — the register that found this, and why a number needs its switches
- `scripts/patch_compose_firewall.py` — instances one through four
