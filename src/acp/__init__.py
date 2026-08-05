"""Agent Control Plane — a policy-enforcing MCP gateway.

The gateway sits between AI agents and the MCP servers they call tools on. It
authenticates the principal an agent is acting for, mints narrowly scoped
upstream credentials, enforces policy before dispatch, screens tool results for
injected instructions, meters spend, and records an audit trail.

Targets the 2026-07-28 MCP specification (stateless request/response) only.
See docs/decisions/0001-target-2026-07-28-spec-only.md.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
