"""Agent Control Plane — a policy-enforcing MCP gateway.

Sits between AI agents and MCP servers: authenticates principals, mints scoped
upstream credentials, enforces policy, screens results for injection, meters spend,
and audits. Targets the 2026-07-28 MCP spec only
(docs/decisions/0001-target-2026-07-28-spec-only.md).
"""

__version__ = "2.2.0"
"""The version; a test checks `pyproject.toml` matches. ADR 0058 says what it promises."""

__all__ = ["__version__"]
