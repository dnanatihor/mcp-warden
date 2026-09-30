"""Spike of FastMCP 2.14 against SPEC.md §3.2.

The four assertions are the evidence for docs/adr/0001-implementation-base.md.
"""

from __future__ import annotations

import mcp.types as mt
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult
from tests.http_harness import serve_http


class _EchoAuth(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        if token != "good-key":
            return None
        return AccessToken(token="digest-not-the-key", client_id="analyst", scopes=[])


class _Probe(Middleware):
    def __init__(self) -> None:
        self.authorization = ""

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: object,
    ) -> list[object]:
        headers = get_http_headers(include_all=True)
        self.authorization = headers.get("authorization", "")
        tools = await call_next(context)  # type: ignore[operator]
        return [tool for tool in tools if "hidden" not in tool.name]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: object,
    ) -> ToolResult:
        await call_next(context)  # type: ignore[operator]
        return ToolResult(
            content=[mt.TextContent(type="text", text="replaced")],
            structured_content={"result": "replaced"},
        )


async def test_installed_fastmcp_supports_the_gateway_capabilities() -> None:
    import httpx

    sub = FastMCP("sub")

    @sub.tool
    def echo(text: str) -> str:
        """Return the text."""
        return text

    @sub.tool
    def hidden_echo(text: str) -> str:
        """A tool the spike middleware hides."""
        return text

    probe = _Probe()
    parent = FastMCP("parent", auth=_EchoAuth())
    parent.mount(sub, prefix="catalog_")
    parent.add_middleware(probe)
    app = parent.http_app(path="/mcp", transport="streamable-http")

    async with serve_http(app) as url:
        async with httpx.AsyncClient() as http:
            denied = await http.post(
                url,
                headers={
                    "Authorization": "Bearer wrong-key",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "spike", "version": "0"},
                    },
                },
            )
        assert denied.status_code == 401
        assert "wrong-key" not in denied.text

        async with Client(url, auth="good-key") as client:
            names = [tool.name for tool in await client.list_tools()]
            replaced = await client.call_tool_mcp("catalog__echo", {"text": "hello"})

    assert names == ["catalog__echo"]
    assert probe.authorization == "Bearer good-key"
    assert replaced.isError is False
    assert replaced.structuredContent == {"result": "replaced"}
