"""Decision matrix for ``mcp-warden check-policy``."""

from __future__ import annotations

from typing import Literal

from mcp_warden.config import WardenConfig
from mcp_warden.core.models import DecisionRequest
from mcp_warden.core.native import NativePolicyEngine
from mcp_warden.gateway import UpstreamTool, list_upstream_tools, load_policy_engine
from mcp_warden.principals import Principal, PrincipalDirectory


async def render_decision_matrix(config: WardenConfig, directory: PrincipalDirectory) -> str:
    engine = load_policy_engine(config)
    tools = await list_upstream_tools(config)
    lines = ["principal | tool | action | effect | rule_ids | reason"]
    for principal in directory.principals:
        for tool in tools:
            for action in ("list", "call"):
                lines.append(await _row(engine, principal, tool, action))
    return "\n".join(lines) + "\n"


async def _row(
    engine: NativePolicyEngine,
    principal: Principal,
    tool: UpstreamTool,
    action: Literal["list", "call"],
) -> str:
    decision = await engine.decide(
        DecisionRequest(
            action=action,
            principal=principal,
            server=tool.server,
            tool=tool.name,
            annotations=tool.annotations,
        )
    )
    rule_ids = ",".join(decision.rule_ids) if decision.rule_ids else "-"
    return (
        f"{principal.id} | {tool.server}__{tool.name} | {action} | "
        f"{decision.effect} | {rule_ids} | {decision.reason}"
    )
