"""Pass-through MCP gateway.

Upstream tools are mounted as ``{server}__{tool}``. Until the policy engine
exists, tools are visible and callable only when ``allow_all`` is set. That
flag is for tests; the default is deny.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import mcp.types as mt
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.dependencies import get_access_token, get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.proxy import FastMCPProxy
from fastmcp.tools.tool import Tool, ToolResult

from mcp_warden.auth import PrincipalTokenVerifier
from mcp_warden.config import (
    HttpListen,
    StdioUpstream,
    StreamableHttpUpstream,
    UpstreamConfig,
    WardenConfig,
)
from mcp_warden.principals import PrincipalDirectory

logger = logging.getLogger("mcp_warden.gateway")


class AllowAllGate(Middleware):
    """Authenticate the principal, then allow every tool or deny every tool."""

    def __init__(self, directory: PrincipalDirectory, *, allow_all: bool) -> None:
        self._directory = directory
        self._allow_all = allow_all

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        if not self._allowed():
            return []
        return await call_next(context)

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        if not self._allowed():
            raise ToolError("The gateway denied this tool call.")
        return await call_next(context)

    async def on_list_resources(
        self,
        context: MiddlewareContext[mt.ListResourcesRequest],
        call_next: CallNext[mt.ListResourcesRequest, Sequence[Any]],
    ) -> Sequence[Any]:
        return []

    async def on_list_resource_templates(
        self,
        context: MiddlewareContext[mt.ListResourceTemplatesRequest],
        call_next: CallNext[mt.ListResourceTemplatesRequest, Sequence[Any]],
    ) -> Sequence[Any]:
        return []

    async def on_list_prompts(
        self,
        context: MiddlewareContext[mt.ListPromptsRequest],
        call_next: CallNext[mt.ListPromptsRequest, Sequence[Any]],
    ) -> Sequence[Any]:
        return []

    async def on_read_resource(
        self,
        context: MiddlewareContext[mt.ReadResourceRequestParams],
        call_next: CallNext[mt.ReadResourceRequestParams, Sequence[Any]],
    ) -> Sequence[Any]:
        raise NotFoundError("MCP Warden exposes tools only.")

    async def on_get_prompt(
        self,
        context: MiddlewareContext[mt.GetPromptRequestParams],
        call_next: CallNext[mt.GetPromptRequestParams, mt.GetPromptResult],
    ) -> mt.GetPromptResult:
        raise NotFoundError("MCP Warden exposes tools only.")

    def _allowed(self) -> bool:
        return self._allow_all and self._principal_id() is not None

    def _principal_id(self) -> str | None:
        try:
            get_http_request()
        except RuntimeError:
            return _stdio_principal_id(self._directory)
        token = get_access_token()
        if token is None:
            return None
        principal = self._directory.by_id(token.client_id)
        if principal is None:
            return None
        return principal.id


def build_gateway(
    config: WardenConfig,
    directory: PrincipalDirectory,
    *,
    allow_all: bool = False,
) -> FastMCP:
    auth = PrincipalTokenVerifier(directory) if isinstance(config.listen, HttpListen) else None
    gateway = FastMCP("MCP Warden", auth=auth)
    for name, upstream in config.upstreams.items():
        proxy = FastMCPProxy(client_factory=_client_factory(upstream, config), name=name)
        # FastMCP joins "{prefix}_{tool}". A trailing underscore yields "{server}__{tool}".
        gateway.mount(proxy, prefix=f"{name}_")
    gateway.add_middleware(AllowAllGate(directory, allow_all=allow_all))
    return gateway


def _client_factory(upstream: UpstreamConfig, config: WardenConfig) -> Any:
    timeout = config.upstream_timeout_s

    def factory() -> Client[Any]:
        if isinstance(upstream, StdioUpstream):
            transport: StdioTransport | StreamableHttpTransport = StdioTransport(
                command=upstream.command,
                args=list(upstream.args),
                env=dict(os.environ),
                cwd=str(Path.cwd()),
                keep_alive=False,
            )
        elif isinstance(upstream, StreamableHttpUpstream):
            transport = StreamableHttpTransport(url=upstream.url, headers=dict(upstream.headers))
        else:
            logger.error("unsupported upstream transport")
            raise ToolError("The gateway denied this tool call.")
        return Client(transport, timeout=timeout)

    return factory


def _stdio_principal_id(directory: PrincipalDirectory) -> str | None:
    principal_id = os.environ.get("WARDEN_PRINCIPAL", "")
    if not principal_id:
        logger.warning("authentication failed")
        return None
    principal = directory.by_id(principal_id)
    if principal is None:
        logger.warning("authentication failed")
        return None
    return principal.id
