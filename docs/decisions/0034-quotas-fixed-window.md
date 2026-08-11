# ADR 0034 — Quotas: a fixed-window total per principal

**Status:** accepted
**Date:** 2026-08-10

## Context

Rate limiting (task 38) bounds how *fast* a principal may call. It does nothing
about the *total*. A caller can sit just under the rate limit forever and still
run up unbounded spend across a day — a slow drain the burst control never sees.
A quota is the complementary bound: a ceiling on how much a principal may spend
within a window, independent of how evenly they spread it.

## Decision

**A fixed, clock-aligned window per principal, counting spend against a limit.**

- **Fixed window, not rolling.** The window containing ``now`` is
  ``floor(now / window_seconds)``; when it elapses the count resets whole. "1000
  a day" means a calendar day — the same absolute boundary for everyone — not
  "1000 in any trailing 24 hours", which needs a rolling log of timestamps and
  answers "when does it reset" only vaguely. A fixed window is one integer of
  state per principal and a clean reset time, and it is what a deployer means by
  a daily quota.

- **Clock-aligned, so it does not depend on first use.** Anchoring the window to
  each principal's first call would give everyone a personal midnight and make
  the reset time un-answerable without remembering when they started. Aligning to
  the absolute clock means every principal's daily window turns over together,
  and ``resets_at`` is just arithmetic on ``now``.

- **Wall-clock time, unlike the rate limiter's monotonic clock.** The rate limit
  uses ``time.monotonic()`` because a wall-clock jump must not hand out or
  withhold burst allowance. The quota is the opposite: it is *defined* against
  wall-clock calendar time — a daily quota should reset at the real day boundary
  — so it takes ``time.time()``. The two controls want different clocks for the
  same reason, that each should track the thing it is actually bounding.

- **Shares the cost weighting.** A call's draw against the quota is the same cost
  the rate limiter uses (task 39): an expensive tool spends more of the daily
  allowance, a free one spends none. One cost, charged against both budgets.

- **Enforced after authorization, beside the rate limit.** In ``on_call_tool``,
  after policy and after the rate-limit check. A denied call spends neither
  budget; a rate-limited call never reaches the quota. Both are keyed on the
  principal's subject and skipped when there is no principal.

- **Recoverable, with the window's reset as the hint.** ``QuotaExceededError``
  (code ``-32051``) is ``recoverable`` like the rate-limit error, but the wait is
  the window, not a breath — the identical call succeeds once the window rolls
  over. ``retry_after`` carries the seconds until reset.

- **Configured by three scalars, not a file.** ``quota_enabled``,
  ``quota_limit``, ``quota_window_seconds`` — a quota is one limit and one window,
  not a per-tool map, so it lives in settings like the rate limit rather than in
  its own file like costs. Off by default; a gateway with no quota configured
  behaves exactly as before.

## Alternatives considered

**A rolling window** (limit over any trailing 24h). Rejected for the first quota:
it needs a timestamped log per principal and gives a fuzzier reset answer, for a
precision most quotas do not need. A fixed window is the common meaning of "N per
day" and far cheaper; a rolling one can be added later if a use case wants it.

**A slow token bucket** (capacity = daily limit, refill = limit/day). Rejected —
it drips continuously and can never say "you have used 400 of 1000 today, resets
at midnight". A quota's value is the clean window and the answerable reset; the
bucket, right for rates, blurs both.

**Reuse the rate limiter's monotonic clock.** Rejected — a quota anchored to
process uptime is not a daily quota; it would reset relative to the last restart.
Wall-clock is what makes "resets at the day boundary" true.

## Consequences

- New ``acp.budget.quota.QuotaCounter`` (pure, time-injected, clock-aligned) and
  ``acp.budget.quota_enforce.enforce_quota``. ``QuotaExceededError`` joins the
  taxonomy at ``-32051``.
- ``build_server``, ``build_app``, ``gateway_from_configs`` gain an optional
  ``quota``, threaded like ``limiter``; ``gateway_from_settings`` builds one from
  the three settings. ``on_call_tool`` enforces it after the rate limit. An
  integration test on the real path exhausts a window and sees the next call
  refused.
- Result caching is the last Phase 4 piece. A rolling window, and a shared store
  for multi-replica deployments, remain later refinements.

## References

- ADR 0032 — rate limiting (the burst control this complements)
- ADR 0033 — cost accounting (the weighting both budgets share)
- docs/THREAT_MODEL.md — "Runaway spend", now bounded in total as well as rate
