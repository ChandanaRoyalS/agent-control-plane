"""Mock upstream MCP servers used as test fixtures for the gateway.

Development-only infrastructure — nothing in the gateway's runtime path imports
this package. It lives under ``src/`` so the mocks can also be run standalone
(docker-compose, manual probing with the MCP Inspector).

See ``docs/decisions/0004-hand-roll-mock-protocol-layer.md`` for why these do
not build on the MCP SDK's server class.
"""
