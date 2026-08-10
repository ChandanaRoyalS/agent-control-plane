"""Policy: the rulebook that decides what an authenticated caller may do.

Phase 2 answers *who is asking*. This package answers *what they may do* — and
task 32 is only its first half: the rulebook is loaded and validated at startup,
deny-by-default, but nothing evaluates it yet. The engine that turns a policy
plus a request into an allow/deny decision is `evaluate` (task 33). Wiring
that decision into the request path so a denied call is refused is task 34.

Keeping load/validate separate from evaluate mirrors how identity was built
(a config that fails fast, and an enforcement path that trusts it), and it means
a malformed policy is a boot failure with a filename rather than a surprise on
the first request.
"""

from acp.policy.enforce import enforce_call
from acp.policy.evaluate import Decision, evaluate
from acp.policy.filtering import visible_tools
from acp.policy.schema import Effect, Policy, Rule

__all__ = [
    "Decision",
    "Effect",
    "Policy",
    "Rule",
    "enforce_call",
    "evaluate",
    "visible_tools",
]
