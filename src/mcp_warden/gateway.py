"""MCP gateway.

Upstream tools are mounted as ``{server}__{tool}``. ``allow_all`` skips policy
and is for tests. Otherwise the native policy engine filters ``tools/list``
and denies ``tools/call``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
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
    ConfigError,
    HttpListen,
    OpaPolicyConfig,
    StdioUpstream,
    StreamableHttpUpstream,
    UpstreamConfig,
    WardenConfig,
)
from mcp_warden.core.models import Decision, DecisionRequest
from mcp_warden.core.native import NativePolicyEngine, load_native_policy
from mcp_warden.principals import Principal, PrincipalDirectory

logger = logging.getLogger("mcp_warden.gateway")


class AllowAllGate(Middleware):
    """Authenticate the principal, then apply policy or the test-only allow-all flag."""

    def __init__(
        self,
        directory: PrincipalDirectory,
        *,
        allow_all: bool,
        engine: NativePolicyEngine | None = None,
    ) -> None:
        self._directory = directory
        self._allow_all = allow_all
        self._engine = engine

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        principal = self._principal()
        if principal is None:
            return []
        # Mounted-server middleware applies the policy to unprefixed names.
        return await call_next(context)

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        principal = self._principal()
        if principal is None:
            raise ToolError("The gateway denied this tool call.")
        if self._allow_all:
            return await call_next(context)
        parsed = _split_tool_name(context.message.name)
        if parsed is None or self._engine is None:
            raise ToolError("unknown tool")
        server, name = parsed
        arguments = dict(context.message.arguments or {})
        decision = await self._engine.decide(
            DecisionRequest(
                action="call",
                principal=principal,
                server=server,
                tool=name,
                annotations=await _call_annotations(context),
                arguments=arguments,
            )
        )
        if decision.effect != "ALLOW":
            raise ToolError(_deny_message(decision))
        await _validate_arguments(context, arguments)
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

    def _principal(self) -> Principal | None:
        return _current_principal(self._directory)


class UpstreamPolicyGate(Middleware):
    """Filter one upstream's tools. List hooks see the upstream tool name, not the prefix."""

    def __init__(
        self,
        server: str,
        directory: PrincipalDirectory,
        *,
        allow_all: bool,
        engine: NativePolicyEngine | None,
    ) -> None:
        self._server = server
        self._directory = directory
        self._allow_all = allow_all
        self._engine = engine

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        principal = _current_principal(self._directory)
        tools = await call_next(context)
        if principal is None or self._allow_all:
            return [] if principal is None else tools
        if self._engine is None:
            return []
        visible: list[Tool] = []
        for tool in tools:
            decision = await self._engine.decide(
                DecisionRequest(
                    action="list",
                    principal=principal,
                    server=self._server,
                    tool=tool.name,
                    annotations=_annotation_map(tool.annotations),
                )
            )
            if decision.effect == "ALLOW":
                visible.append(tool)
        return visible


def build_gateway(
    config: WardenConfig,
    directory: PrincipalDirectory,
    *,
    allow_all: bool = False,
) -> FastMCP:
    auth = PrincipalTokenVerifier(directory) if isinstance(config.listen, HttpListen) else None
    gateway = FastMCP("MCP Warden", auth=auth)
    engine = load_policy_engine(config)
    for name, upstream in config.upstreams.items():
        proxy = FastMCPProxy(client_factory=_client_factory(upstream, config), name=name)
        proxy.add_middleware(
            UpstreamPolicyGate(name, directory, allow_all=allow_all, engine=engine)
        )
        # FastMCP joins "{prefix}_{tool}". A trailing underscore yields "{server}__{tool}".
        gateway.mount(proxy, prefix=f"{name}_")
    gateway.add_middleware(AllowAllGate(directory, allow_all=allow_all, engine=engine))
    return gateway


def load_policy_engine(config: WardenConfig) -> NativePolicyEngine:
    if isinstance(config.policy, OpaPolicyConfig):
        raise ConfigError("OPA policy engine is not available")
    return NativePolicyEngine(load_native_policy(config.policy.file))


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


def _current_principal(directory: PrincipalDirectory) -> Principal | None:
    try:
        get_http_request()
    except RuntimeError:
        return _stdio_principal(directory)
    token = get_access_token()
    if token is None:
        return None
    return directory.by_id(token.client_id)


def _stdio_principal(directory: PrincipalDirectory) -> Principal | None:
    principal_id = os.environ.get("WARDEN_PRINCIPAL", "")
    if not principal_id:
        logger.warning("authentication failed")
        return None
    principal = directory.by_id(principal_id)
    if principal is None:
        logger.warning("authentication failed")
        return None
    return principal


@dataclass(frozen=True)
class UpstreamTool:
    server: str
    name: str
    annotations: dict[str, Any]


async def list_upstream_tools(config: WardenConfig) -> tuple[UpstreamTool, ...]:
    found: list[UpstreamTool] = []
    for server, upstream in config.upstreams.items():
        client = _client_factory(upstream, config)()
        async with client:
            for tool in await client.list_tools():
                found.append(
                    UpstreamTool(
                        server=server,
                        name=tool.name,
                        annotations=_annotation_map(tool.annotations),
                    )
                )
    return tuple(found)


def _split_tool_name(namespaced: str) -> tuple[str, str] | None:
    server, separator, tool = namespaced.partition("__")
    if separator == "" or server == "" or tool == "":
        return None
    return server, tool


def _annotation_map(annotations: Any) -> dict[str, Any]:
    if annotations is None:
        return {}
    dumped = annotations.model_dump(exclude_none=True)
    dumped.pop("title", None)
    return {str(key): value for key, value in dumped.items()}


async def _call_annotations(context: MiddlewareContext[mt.CallToolRequestParams]) -> dict[str, Any]:
    fastmcp_context = context.fastmcp_context
    if fastmcp_context is None:
        return {}
    tool = await fastmcp_context.fastmcp.get_tool(context.message.name)
    return _annotation_map(tool.annotations)


async def _validate_arguments(
    context: MiddlewareContext[mt.CallToolRequestParams],
    arguments: dict[str, Any],
) -> None:
    fastmcp_context = context.fastmcp_context
    if fastmcp_context is None:
        raise ToolError("invalid arguments")
    tool = await fastmcp_context.fastmcp.get_tool(context.message.name)
    schema = tool.parameters
    if not isinstance(schema, dict):
        raise ToolError("invalid arguments")
    try:
        jsonschema.validate(instance=arguments, schema=schema)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path)
        detail = f": {location}" if location else ""
        raise ToolError(f"invalid arguments{detail}") from None


def _deny_message(decision: Decision) -> str:
    if not decision.rule_ids:
        return decision.reason
    return f"{decision.reason} ({', '.join(decision.rule_ids)})"
