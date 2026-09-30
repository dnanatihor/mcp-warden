# 0001 — Implementation base

- Status: accepted
- Date: 2026-09-30

## Context

Phase 1 has to choose the MCP library before the gateway is built. SPEC.md §3.2 asks whether the installed FastMCP can: proxy several upstream servers under name prefixes, read the incoming HTTP `Authorization` header per request inside middleware, filter `tools/list` per request, and replace `tools/call` results. If any of those is missing, the gateway must be built on the low-level `mcp` `Server` and streamable HTTP.

The installed version is FastMCP 2.14.7 (`fastmcp>=2.14,<3` in `pyproject.toml`).

## Options considered

1. FastMCP 2.x — mounting and `FastMCPProxy` already proxy tools, middleware can filter lists and wrap calls, and `TokenVerifier` rejects a bearer token with HTTP 401.
2. Low-level `mcp` `Server` with streamable HTTP — full control over the protocol, and more code to own for sessions, tool listing, and transport.

## Decision

Build on FastMCP 2.14.7. The spike in `tests/test_fastmcp_spike.py` confirmed all four capabilities against that version:

- Mounting a server with prefix `catalog_` exposes `catalog__echo`, because FastMCP joins the prefix and the tool key with one underscore. The gateway passes `{server}_` so the public name is `{server}__{tool}`.
- `get_http_headers(include_all=True)` inside `on_list_tools` returns the request `Authorization` header. Authentication itself sits in front of the MCP session: `TokenVerifier.verify_token` returning `None` produces HTTP 401 `invalid_token`.
- `on_list_tools` can drop tools before they reach the client.
- `on_call_tool` can return a different `ToolResult`. `Client.call_tool_mcp` sees that replacement. `Client.call_tool` also validates the replacement against the tool's advertised output schema, so a replacement that does not match the schema is rejected by the client.

## Consequences

- Upstream proxying, HTTP sessions, and bearer authentication stay in FastMCP. Decision and obligation code stays in `src/mcp_warden/core/` and is not coupled to FastMCP.
- Tool names depend on FastMCP's single-underscore prefix join. A future FastMCP that changes that join must be treated as a breaking change for `{server}__{tool}`.
- Phase 3 obligations that change a response away from the upstream output schema need the advertised schema relaxed or removed; otherwise conforming clients reject the transformed result. Pass-through in this phase leaves schemas unchanged.
- Failed bearer checks are logged by our verifier as `authentication failed` and by FastMCP as `invalid_token`. Neither record stores the key. The verifier puts the key's SHA-256 in `AccessToken.token`, not the key itself.
