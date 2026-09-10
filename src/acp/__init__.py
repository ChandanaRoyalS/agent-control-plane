"""Agent Control Plane — a policy-enforcing MCP gateway.

The gateway sits between AI agents and the MCP servers they call tools on. It
authenticates the principal an agent is acting for, mints narrowly scoped
upstream credentials, enforces policy before dispatch, screens tool results for
injected instructions, meters spend, and records an audit trail.

Targets the 2026-07-28 MCP specification (stateless request/response) only.
See docs/decisions/0001-target-2026-07-28-spec-only.md.
"""

__version__ = "2.0.0"
"""The one place the version exists.

`pyproject.toml` declares `dynamic = ["version"]` and reads it from here at
build time, so there is nothing to keep in agreement. It used to be written in
both files with a test asserting they matched — which catches the disagreement
only after somebody has made it, and is a worse answer than not being able to.

See ADR 0058 for what this number is a promise **about**, which is not the
Python API.
"""

__all__ = ["__version__"]
