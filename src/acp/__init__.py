"""Agent Control Plane — a policy-enforcing MCP gateway.

The gateway sits between AI agents and the MCP servers they call tools on. It
authenticates the principal an agent is acting for, mints narrowly scoped
upstream credentials, enforces policy before dispatch, screens tool results for
injected instructions, meters spend, and records an audit trail.

Targets the 2026-07-28 MCP specification (stateless request/response) only.
See docs/decisions/0001-target-2026-07-28-spec-only.md.
"""

__version__ = "1.0.0"
"""The one place a human edits the version.

`pyproject.toml` carries the same string because packaging needs it there, and
a test asserts the two agree — two sources of truth for one fact is a
disagreement waiting for a release. See ADR 0058 for what this number is a
promise **about**, which is not the Python API.
"""

__all__ = ["__version__"]
