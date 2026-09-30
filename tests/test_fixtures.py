"""Fixture upstreams start over stdio and record each call."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from examples.catalog_server import PROFILE_EMAIL, column_profile
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

_ROOT = Path(__file__).resolve().parents[1]


def _transport(module: str, call_log: Path) -> StdioTransport:
    env = os.environ.copy()
    env["FIXTURE_CALL_LOG"] = str(call_log)
    env["FASTMCP_SHOW_SERVER_BANNER"] = "false"
    return StdioTransport(
        command=sys.executable,
        args=["-m", module],
        env=env,
        cwd=str(_ROOT),
        keep_alive=False,
    )


def _annotation(tool: object, name: str) -> object:
    annotations = getattr(tool, "annotations", None)
    if annotations is None:
        return None
    return getattr(annotations, name, None)


@pytest.mark.asyncio
async def test_catalog_fixture_starts_over_stdio(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.jsonl"
    transport = _transport("examples.catalog_server", call_log)

    async with Client(transport) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        profile = await client.call_tool("get_column_profile", {"column_id": "col_email"})
        search = await client.call_tool("search_assets", {"query": "customer"})

    assert set(tools) == {"get_column_profile", "search_assets"}
    assert _annotation(tools["get_column_profile"], "readOnlyHint") is True
    assert _annotation(tools["search_assets"], "readOnlyHint") is True
    assert profile.data == column_profile("col_email")
    assert PROFILE_EMAIL in json.dumps(profile.data)
    assert len(profile.data["ai_inferences"]) == 1
    assert profile.data["inference_permitted"] is True
    assert len(search.data["results"]) == 120

    lines = call_log.read_text(encoding="utf-8").splitlines()
    recorded = [json.loads(line)["tool"] for line in lines]
    assert recorded == ["get_column_profile", "search_assets"]


@pytest.mark.asyncio
async def test_admin_fixture_starts_over_stdio(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.jsonl"
    transport = _transport("examples.admin_server", call_log)

    async with Client(transport) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        await client.call_tool("delete_asset", {"asset_id": "asset-1"})
        await client.call_tool("list_jobs", {})

    assert set(tools) == {"delete_asset", "list_jobs"}
    assert _annotation(tools["delete_asset"], "destructiveHint") is True
    jobs = tools["list_jobs"]
    assert _annotation(jobs, "readOnlyHint") is not True
    assert _annotation(jobs, "destructiveHint") is not True
    assert _annotation(jobs, "idempotentHint") is None
    assert _annotation(jobs, "openWorldHint") is None

    lines = call_log.read_text(encoding="utf-8").splitlines()
    recorded = [json.loads(line) for line in lines]
    assert recorded[0]["tool"] == "delete_asset"
    assert recorded[0]["arguments"] == {"asset_id": "asset-1"}
    assert recorded[1]["tool"] == "list_jobs"
