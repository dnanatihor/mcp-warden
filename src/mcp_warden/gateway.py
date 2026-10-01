"""MCP gateway.

Upstream tools are mounted as ``{server}__{tool}``. ``allow_all`` skips policy
and is for tests. Otherwise the native policy engine filters ``tools/list``
and denies ``tools/call``.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import os
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
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

from mcp_warden.auditlog import AuditWriter, StdoutAnchorSink
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
from mcp_warden.core.audit import canonical_json, utc_timestamp
from mcp_warden.core.models import Decision, DecisionRequest, Obligation
from mcp_warden.core.native import NativePolicyEngine, load_native_policy
from mcp_warden.core.obligations import ObligationResult, apply_obligations, render_json_text
from mcp_warden.principals import Principal, PrincipalDirectory

logger = logging.getLogger("mcp_warden.gateway")


class _ListTally:
    def __init__(self) -> None:
        self.visible = 0
        self.hidden = 0


_LIST_TALLY: contextvars.ContextVar[_ListTally | None] = contextvars.ContextVar(
    "mcp_warden_list_tally",
    default=None,
)


class AllowAllGate(Middleware):
    """Authenticate the principal, then apply policy or the test-only allow-all flag."""

    def __init__(
        self,
        directory: PrincipalDirectory,
        *,
        allow_all: bool,
        engine: NativePolicyEngine | None = None,
        audit: AuditWriter,
    ) -> None:
        self._directory = directory
        self._allow_all = allow_all
        self._engine = engine
        self._audit = audit

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        principal = self._principal()
        if principal is None:
            return []
        started = time.perf_counter()
        tally = _ListTally()
        token = _LIST_TALLY.set(tally)
        status = "error"
        try:
            tools = await call_next(context)
            status = "ok"
        except Exception:
            logger.warning("tool list failed")
            tools = []
        finally:
            _LIST_TALLY.reset(token)
        await self._audit.append(
            {
                "ts": utc_timestamp(),
                "principal": principal.id,
                "action": "list",
                "visible_tools": tally.visible,
                "hidden_tools": tally.hidden,
                "effect": "ALLOW" if status == "ok" else "DENY",
                "upstream_status": status,
                "latency_ms": _latency_ms(started),
            }
        )
        if status != "ok":
            raise ToolError("The gateway denied this tool call.")
        return tools

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        principal = self._principal()
        if principal is None:
            raise ToolError("The gateway denied this tool call.")
        started = time.perf_counter()
        arguments = dict(context.message.arguments or {})
        parsed = _split_tool_name(context.message.name)
        server, tool = parsed if parsed else ("", context.message.name)
        decision = Decision(effect="DENY", rule_ids=(), reason="unknown tool", obligations=())
        result: ToolResult | None = None
        applied: tuple[str, ...] = ()
        skipped: tuple[str, ...] = ()
        status = "denied"
        error: Exception | None = None
        try:
            if self._allow_all:
                decision = Decision(effect="ALLOW", rule_ids=(), reason="", obligations=())
                result = await call_next(context)
            elif parsed is None or self._engine is None:
                raise ToolError("unknown tool")
            else:
                decision = await self._engine.decide(
                    DecisionRequest(
                        action="call",
                        principal=principal,
                        server=server,
                        tool=tool,
                        annotations=await _call_annotations(context),
                        arguments=arguments,
                    )
                )
                if decision.effect != "ALLOW":
                    raise ToolError(_deny_message(decision))
                await _validate_arguments(context, arguments)
                result = await call_next(context)
                result, outcome = _apply_result_obligations(result, decision.obligations)
                applied = outcome.applied
                skipped = outcome.not_applicable
            status = "ok"
        except ToolError as exc:
            error = exc
            status = "denied" if decision.effect != "ALLOW" else "error"
        except Exception:
            logger.warning("tool call failed")
            error = ToolError("The gateway denied this tool call.")
            status = "error"
        await self._audit.append(
            _call_record(
                principal_id=principal.id,
                server=server,
                tool=tool,
                arguments=arguments,
                decision=decision,
                status=status,
                latency_ms=_latency_ms(started),
                result=result,
                error=error,
                applied=applied,
                skipped=skipped,
                store_masked_arguments=self._audit.store_masked_arguments,
            )
        )
        if error is not None:
            raise error
        if result is None:
            raise ToolError("The gateway denied this tool call.")
        return result

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
        tally = _LIST_TALLY.get()
        if principal is None:
            return []
        if self._allow_all:
            if tally is not None:
                tally.visible += len(tools)
            return tools
        if self._engine is None:
            if tally is not None:
                tally.hidden += len(tools)
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
                visible.append(_with_governance_note(tool, decision.obligations))
        if tally is not None:
            tally.visible += len(visible)
            tally.hidden += len(tools) - len(visible)
        return visible


def build_gateway(
    config: WardenConfig,
    directory: PrincipalDirectory,
    *,
    allow_all: bool = False,
) -> FastMCP:
    auth = PrincipalTokenVerifier(directory) if isinstance(config.listen, HttpListen) else None
    audit = AuditWriter(
        config.audit.file,
        anchor_every=config.audit.anchor_every,
        sink=StdoutAnchorSink(),
        store_masked_arguments=config.audit.store_masked_arguments,
    )

    @asynccontextmanager
    async def _lifespan(_server: FastMCP[Any]) -> AsyncIterator[dict[str, Any]]:
        yield {}
        await audit.aclose()

    gateway: FastMCP[Any] = FastMCP("MCP Warden", auth=auth, lifespan=_lifespan)
    engine = load_policy_engine(config)
    for name, upstream in config.upstreams.items():
        proxy = FastMCPProxy(client_factory=_client_factory(upstream, config), name=name)
        proxy.add_middleware(
            UpstreamPolicyGate(name, directory, allow_all=allow_all, engine=engine)
        )
        # FastMCP joins "{prefix}_{tool}". A trailing underscore yields "{server}__{tool}".
        gateway.mount(proxy, prefix=f"{name}_")
    gateway.add_middleware(AllowAllGate(directory, allow_all=allow_all, engine=engine, audit=audit))
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


_GOVERNANCE_NOTE = "Governance: AI inferences may be withheld."


def _apply_result_obligations(
    result: ToolResult, obligations: tuple[Obligation, ...]
) -> tuple[ToolResult, ObligationResult]:
    if not obligations:
        return result, ObligationResult(
            value=result.structured_content, applied=(), not_applicable=()
        )
    structured = result.structured_content
    transformed = apply_obligations(structured, obligations) if structured is not None else None
    content: list[Any] = []
    for block in result.content or []:
        text = getattr(block, "text", None)
        if not isinstance(text, str):
            content.append(block)
            continue
        parsed = _json_block(text)
        if parsed is not None:
            rendered = apply_obligations(parsed, obligations).value
            content.append(mt.TextContent(type="text", text=render_json_text(rendered)))
            continue
        masked = apply_obligations(text, obligations).value
        content.append(
            mt.TextContent(type="text", text=masked if isinstance(masked, str) else text)
        )
    new_structured = transformed.value if transformed is not None else structured
    outcome = transformed or ObligationResult(value=new_structured, applied=(), not_applicable=())
    if isinstance(new_structured, dict) or new_structured is None:
        updated = ToolResult(content=content, structured_content=new_structured, meta=result.meta)
    else:
        updated = ToolResult(
            content=content, structured_content={"result": new_structured}, meta=result.meta
        )
    return updated, outcome


def _latency_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _call_record(
    *,
    principal_id: str,
    server: str,
    tool: str,
    arguments: dict[str, Any],
    decision: Decision,
    status: str,
    latency_ms: int,
    result: ToolResult | None,
    error: Exception | None,
    applied: tuple[str, ...],
    skipped: tuple[str, ...],
    store_masked_arguments: bool,
) -> dict[str, Any]:
    if result is not None and isinstance(result.structured_content, dict):
        response: Any = result.structured_content
    elif error is not None:
        response = {"error": str(error)}
    else:
        response = {"error": "tool call failed"}
    record: dict[str, Any] = {
        "ts": utc_timestamp(),
        "principal": principal_id,
        "action": "call",
        "server": server,
        "tool": tool,
        "arguments_sha256": _sha256(canonical_json(arguments)),
        "effect": decision.effect,
        "rule_ids": list(decision.rule_ids),
        "obligations_applied": list(applied),
        "obligations_not_applicable": list(skipped),
        "upstream_status": status,
        "latency_ms": latency_ms,
        "response_sha256": _sha256(canonical_json(response)),
    }
    if store_masked_arguments:
        record["masked_arguments"] = apply_obligations(
            arguments, (Obligation(type="mask_pii"),)
        ).value
    return record


def _json_block(text: str) -> Any:
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict | list):
        return parsed
    return None


def _with_governance_note(tool: Tool, obligations: tuple[Obligation, ...]) -> Tool:
    if not any(item.type == "strip_inferences" for item in obligations):
        return tool
    description = tool.description or ""
    if _GOVERNANCE_NOTE in description:
        return tool
    updated = f"{description}\n{_GOVERNANCE_NOTE}".strip()
    return tool.model_copy(update={"description": updated})


def _deny_message(decision: Decision) -> str:
    if not decision.rule_ids:
        return decision.reason
    return f"{decision.reason} ({', '.join(decision.rule_ids)})"
