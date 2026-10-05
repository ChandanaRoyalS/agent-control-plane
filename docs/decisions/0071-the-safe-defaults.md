# ADR 0071 — The safe defaults

**Status:** accepted
**Date:** 2026-10-05

## Context

ADR 0055 is titled "a control nobody runs is a control that does not exist".
The external review of v1.3.0 (W10) pointed out that the project's own
defaults were that control. A bare `acp serve` required authentication and
nothing else: no audit chain (`ACP_AUDIT_FILE` unset meant no record, logged
at INFO), and no firewall (`ACP_FIREWALL_MODE` defaulted to `off`). Only the
compose stack turned them on, so the demo looked safe and a real deployment
copied from the variable reference did not.

Each default had a reason when it was set. `audit_file` had no default path
because an evidentiary artifact appearing in someone's working directory gets
gitignored and forgotten. `firewall_mode` was `off` because screening is linear
in the size of every result and "a control that turns itself on is a control
nobody chose". Both reasons are still true. Neither one justified *silence*.

## Decision

- **No audit file means no start, unless the deployment says otherwise.**
  `ACP_AUDIT_REQUIRED` already meant "refuse a call this gateway cannot
  record". With no file configured, the gateway cannot record any call, so the
  same setting now refuses to start. This is the treatment `ACP_AUTH_REQUIRED`
  already gives a missing identity provider, with the same message shape:
  what is missing, what to set, and the explicit escape hatch
  (`ACP_AUDIT_REQUIRED=false`). Using the hatch is logged at WARNING on every
  start. There is still no default path. The deployment chooses where the
  record lives, and now it has to choose.
- **The firewall defaults to `report`.** Report mode screens every result and
  changes nothing the caller receives. The cost is screening time, which is
  linear and measured in the overhead record. What it buys is the
  `would_refuse` count a deployment needs before turning enforcement on.
  `enforce` stays opt-in because it is the one firewall mode that changes
  the wire. `off` stays a real mode.
- **Every start prints what is running.** `gateway.controls` is one INFO line
  with the state of every control: authentication, audit, firewall mode,
  provenance framing, rate limit, quota, cost table, result cache, operator
  channel, approval store and budget store. `gateway.safety_controls_off` is
  one WARNING line naming whichever of the three safety controls is off:
  authentication, audit and the firewall. Those three are the difference
  between a gateway and a proxy. The rest are configuration choices and are
  reported, not warned about.

## Alternatives considered

- **Default the audit file to a path** (`/var/lib/acp/audit.jsonl`). This
  works in the container and surprises everyone else. A laptop run would
  either fail on a missing directory or write a chain into a directory nobody
  watches. Refusing with a message that names the setting is more honest
  than guessing.
- **A single `ACP_PROFILE=production` switch.** One variable that turns a
  bundle of others on is a second way to read every setting. The reviewer
  offered it as an alternative; required settings plus a banner say the same
  thing without the indirection.
- **Default the firewall to `enforce`.** Enforcement withholds very little
  (ADR 0069 lists exactly what), but it is still the mode that changes the
  wire, and ADR 0038's argument that a deployment measures first still holds.

## Consequences

- **A major version under ADR 0058.** `ACP_FIREWALL_MODE`'s default changed,
  which the surface snapshot records, and a bare start that used to succeed
  now refuses. A deployment upgrading must either set `ACP_AUDIT_FILE` or set
  `ACP_AUDIT_REQUIRED=false`, and should expect firewall log lines it did not
  have before.
- The compose stack, the overhead harness and the demo already set an audit
  file and a firewall mode, so they are unchanged. Two wiring tests that
  built a gateway without a chain now say so with `audit_required=False`.
- `.env.example` gains the audit section it never had, and its firewall
  section now describes the enforcement bar ADR 0069 left (three triggers,
  not the four detectors it used to list).

## References

- ADR 0038 — firewall modes, and why `report` comes first
- ADR 0050 — the audit chain
- ADR 0055 — the control nobody runs
- ADR 0058 — a changed default is a major version
