# Threat model

**Status:** stub. Completed in Phase 7. Kept in the repository from Phase 1 so
that what is *not* yet defended is visible rather than implied.

Honest documentation of a system's limits is worth more than a claim of
completeness. This file is expected to grow a "what we do not defend against"
section that stays permanently.

## Assets

- Upstream credentials held by the gateway.
- Data reachable through upstream tools.
- The audit log's integrity.
- The agent's decision-making, which is corruptible via injected content.

## Trust boundaries

1. **Agent → gateway.** The agent is authenticated but not trusted: its context
   may already be poisoned, so any request it makes may be attacker-influenced.
2. **Gateway → upstream.** Upstreams are trusted to hold data, not trusted to
   return safe content.
3. **Upstream content → agent.** The critical boundary. Everything crossing it
   is untrusted input, never instruction.

## Adversaries

- **Injected content author.** Can write into any source an upstream tool
  returns — a document, a ticket, a code comment, a database row.
- **Curious insider.** A legitimate user attempting to reach data through the
  agent that they could not reach directly.
- **Compromised upstream.** A tool server returning hostile responses.

## Currently defended (as of Phase 1)

Nothing. Phase 1 is a passthrough with reliability and observability only.

## Not yet defended

| Threat | Addressed in |
|---|---|
| Over-privileged shared credentials | Phase 2 |
| Agent acting beyond the user's entitlement | Phase 3 |
| Runaway spend | Phase 4 |
| Prompt injection via tool results | Phase 5 |
| Unauthorized destructive actions | Phase 6 |
| Undetectable log tampering | Phase 7 |

## Explicitly out of scope

To be completed in Phase 7. Expected entries include model-level jailbreaks of
the agent itself, compromise of the identity provider, and physical or host-level
compromise of the gateway.
