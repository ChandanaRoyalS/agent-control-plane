"""Human-in-the-loop approvals: a call that stops and waits for a person.

Phase 6. Everything before this decides automatically — policy allows or denies,
budgets charge, the firewall screens. This is the case where the right answer is
that no rule should decide: a destructive call, a production dataset, a refund
above a threshold. The policy says `require_approval` (ADR 0048) and the call
stops mid-flight.

The 2026-07-28 revision gives that a shape with no session machinery at all
(ADR 0001): the gateway answers `resultType: "input_required"` with an opaque
`request_state`, and the client retries with it once the approval lands. Nothing
is held open, no connection is pinned, and any instance can take the retry — as
long as the store is shared, which is the honest cut in `store.py`.

**The idea the whole package turns on: an approval is granted to a *call*, not
to a token.** A human reads "delete the test dataset" and says yes; the retry
must not be "delete production" carrying the same token. Every request records a
fingerprint of exactly what was asked, and the retry is re-fingerprinted and
compared. See `record.py`.
"""

from acp.approvals.flow import Gate, Outcome, Resolution, gate, resolve
from acp.approvals.operator import (
    APPROVAL_PATH,
    APPROVALS_PATH,
    UNTRUSTED_NOTICE,
    ApprovalReader,
    operator_routes,
)
from acp.approvals.record import (
    DEFAULT_TTL_SECONDS,
    MAX_DISPLAYED_ARGUMENT_BYTES,
    ApprovalRequest,
    State,
    canonical,
    fingerprint,
    new_token,
    request_for,
)
from acp.approvals.store import ApprovalStore, InMemoryApprovalStore

__all__ = [
    "APPROVALS_PATH",
    "APPROVAL_PATH",
    "DEFAULT_TTL_SECONDS",
    "MAX_DISPLAYED_ARGUMENT_BYTES",
    "UNTRUSTED_NOTICE",
    "ApprovalReader",
    "ApprovalRequest",
    "ApprovalStore",
    "Gate",
    "InMemoryApprovalStore",
    "Outcome",
    "Resolution",
    "State",
    "canonical",
    "fingerprint",
    "gate",
    "new_token",
    "operator_routes",
    "request_for",
    "resolve",
]
