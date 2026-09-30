"""Admin fixture: one destructive tool and one unannotated tool."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from examples._call_log import record_call

mcp = FastMCP("admin")


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def delete_asset(asset_id: str) -> dict[str, str]:
    """Permanently delete a catalog asset."""
    record_call("delete_asset", {"asset_id": asset_id})
    return {"deleted": asset_id}


@mcp.tool
def list_jobs() -> dict[str, Any]:
    """List background jobs. This tool carries no annotations."""
    record_call("list_jobs", {})
    return {"jobs": []}


if __name__ == "__main__":
    mcp.run(transport="stdio", show_banner=False)
