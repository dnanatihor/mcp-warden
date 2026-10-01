"""Run the fixture upstreams through Warden and print the demo outcome.

From the repository root:

    uv run python -m examples.quickstart
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import uvicorn
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_warden.config import load_config
from mcp_warden.gateway import build_gateway
from mcp_warden.principals import load_principals

_ANALYST_KEY = "analyst-secret"
_STEWARD_KEY = "steward-secret"
_CONFIG = Path(__file__).with_name("warden.yaml")


async def _run(url: str) -> None:
    async with Client(url, auth=_ANALYST_KEY) as analyst:
        names = sorted(tool.name for tool in await analyst.list_tools())
        profile = await analyst.call_tool("catalog__get_column_profile", {"column_id": "col_email"})
        denied = False
        try:
            await analyst.call_tool("admin__delete_asset", {"asset_id": "asset-1"})
        except ToolError as exc:
            denied = "Destructive tools are blocked" in str(exc)
        analyst_value = profile.data["profiling_observations"][0]["value"]
        analyst_inferences = len(profile.data["ai_inferences"])
    async with Client(url, auth=_STEWARD_KEY) as steward:
        steward_profile = await steward.call_tool(
            "catalog__get_column_profile", {"column_id": "col_email"}
        )
        steward_inferences = len(steward_profile.data["ai_inferences"])
    print("tools:", ", ".join(names))
    print("analyst profile value:", analyst_value)
    print("analyst inferences:", analyst_inferences)
    print("steward inferences:", steward_inferences)
    print("delete_asset denied:", str(denied).lower())
    if names != ["catalog__get_column_profile", "catalog__search_assets"]:
        raise RuntimeError("unexpected tool list")
    if analyst_value != "«email»" or analyst_inferences != 0 or steward_inferences != 1:
        raise RuntimeError("unexpected profile obligations")
    if not denied:
        raise RuntimeError("delete_asset was not denied")


def main() -> int:
    config = load_config(_CONFIG)
    gateway = build_gateway(config, load_principals(config.principals_file))
    app = gateway.http_app(path="/mcp", transport="streamable-http")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))

    async def _serve() -> None:
        task = asyncio.create_task(server.serve())
        try:
            for _ in range(100):
                if server.started and server.servers:
                    break
                await asyncio.sleep(0.05)
            sockets = next(iter(server.servers)).sockets
            if not sockets:
                raise RuntimeError("quickstart server did not bind")
            port = sockets[0].getsockname()[1]
            await _run(f"http://127.0.0.1:{port}/mcp")
        finally:
            server.should_exit = True
            await task

    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
