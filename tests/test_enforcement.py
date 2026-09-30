"""DENY and visibility rows from SPEC.md §9.2, and check-policy."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from tests.http_harness import serve_http

from mcp_warden.config import load_config
from mcp_warden.gateway import build_gateway
from mcp_warden.matrix import render_decision_matrix
from mcp_warden.principals import load_principals

_ANALYST_KEY = "analyst-secret"
_STEWARD_KEY = "steward-secret"
_ROGUE_KEY = "rogue-secret"

_POLICY = """
default: deny
rules:
  - id: no-destructive
    effect: deny
    actions: [call]
    tools: {annotations: {destructiveHint: true}}
    reason: Destructive tools are blocked through the gateway.
  - id: analysts-read-catalog
    effect: allow
    actions: [list, call]
    principals: {roles: [analyst]}
    tools: {servers: [catalog], annotations: {readOnlyHint: true}}
    obligations:
      - {type: mask_pii}
      - {type: strip_inferences}
      - {type: max_items, n: 50}
  - id: stewards-read-catalog
    effect: allow
    actions: [list, call]
    principals: {roles: [steward]}
    tools: {servers: [catalog], annotations: {readOnlyHint: true}}
    obligations:
      - {type: mask_pii}
"""


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _write_config(tmp_path: Path) -> Path:
    (tmp_path / "principals.yaml").write_text(
        f"""
principals:
  - id: analyst-agent
    key_sha256: "{_sha(_ANALYST_KEY)}"
    attributes: {{roles: [analyst], team: finance, clearance: internal}}
  - id: steward-agent
    key_sha256: "{_sha(_STEWARD_KEY)}"
    attributes: {{roles: [steward], team: governance, clearance: confidential}}
  - id: rogue-agent
    key_sha256: "{_sha(_ROGUE_KEY)}"
    attributes: {{}}
""",
        encoding="utf-8",
    )
    (tmp_path / "policy.yaml").write_text(_POLICY, encoding="utf-8")
    path = tmp_path / "warden.yaml"
    path.write_text(
        f"""
listen: {{transport: streamable_http, host: 127.0.0.1, port: 8900, path: /mcp}}
principals_file: ./principals.yaml
policy: {{engine: native, file: ./policy.yaml}}
upstreams:
  catalog:
    transport: stdio
    command: "{sys.executable}"
    args: ["-m", "examples.catalog_server"]
  admin:
    transport: stdio
    command: "{sys.executable}"
    args: ["-m", "examples.admin_server"]
audit: {{file: ./audit/warden.jsonl}}
""",
        encoding="utf-8",
    )
    return path


@pytest.mark.asyncio
async def test_deny_and_visibility_rows(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.jsonl"
    config = load_config(_write_config(tmp_path))
    gateway = build_gateway(config, load_principals(config.principals_file))
    app = gateway.http_app(path="/mcp", transport="streamable-http")

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("FIXTURE_CALL_LOG", str(call_log))
        async with serve_http(app) as url:
            async with Client(url, auth=_ANALYST_KEY) as analyst:
                analyst_tools = sorted(tool.name for tool in await analyst.list_tools())
                profile = await analyst.call_tool(
                    "catalog__get_column_profile",
                    {"column_id": "col_email"},
                )
                search = await analyst.call_tool("catalog__search_assets", {"query": "customer"})
                with pytest.raises(ToolError, match="invalid arguments"):
                    await analyst.call_tool("catalog__get_column_profile", {})
                with pytest.raises(ToolError, match="no-destructive") as denied_delete:
                    await analyst.call_tool("admin__delete_asset", {"asset_id": "asset-1"})
                with pytest.raises(ToolError, match="default deny"):
                    await analyst.call_tool("admin__list_jobs", {})
            async with Client(url, auth=_STEWARD_KEY) as steward:
                steward_tools = sorted(tool.name for tool in await steward.list_tools())
                steward_profile = await steward.call_tool(
                    "catalog__get_column_profile",
                    {"column_id": "col_email"},
                )
                with pytest.raises(ToolError, match="no-destructive") as steward_delete:
                    await steward.call_tool("admin__delete_asset", {"asset_id": "asset-1"})
            async with Client(url, auth=_ROGUE_KEY) as rogue:
                rogue_tools = await rogue.list_tools()
                with pytest.raises(ToolError, match="default deny"):
                    await rogue.call_tool("catalog__get_column_profile", {"column_id": "col_email"})

    catalog_tools = ["catalog__get_column_profile", "catalog__search_assets"]
    assert analyst_tools == catalog_tools
    assert profile.data["profiling_observations"][0]["value"] == "«email»"
    assert profile.data["ai_inferences"] == []
    assert profile.data["inference_permitted"] is False
    assert len(search.data["results"]) == 50
    assert search.data["_warden_truncated"] is True
    assert steward_profile.data["profiling_observations"][0]["value"] == "«email»"
    assert len(steward_profile.data["ai_inferences"]) == 1
    assert steward_profile.data["inference_permitted"] is True
    assert steward_tools == catalog_tools
    assert rogue_tools == []
    assert "Destructive tools are blocked through the gateway." in str(denied_delete.value)
    assert "Destructive tools are blocked through the gateway." in str(steward_delete.value)
    assert not call_log.exists() or "delete_asset" not in call_log.read_text(encoding="utf-8")
    assert not call_log.exists() or "list_jobs" not in call_log.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_check_policy_prints_the_matrix(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    config = load_config(config_path)
    matrix = await render_decision_matrix(config, load_principals(config.principals_file))

    assert "analyst-agent | admin__delete_asset | call | DENY | no-destructive |" in matrix
    assert "Destructive tools are blocked through the gateway." in matrix
    assert "analyst-agent | admin__list_jobs | list | DENY | - | default deny" in matrix
    assert "analyst-agent | admin__delete_asset | list | DENY | - | default deny" in matrix
    assert "steward-agent | admin__delete_asset | call | DENY | no-destructive |" in matrix
    assert "rogue-agent | catalog__get_column_profile | list | DENY | - | default deny" in matrix
    assert (
        "analyst-agent | catalog__get_column_profile | call | ALLOW | analysts-read-catalog |"
        in matrix
    )

    completed = __import__("subprocess").run(
        [sys.executable, "-m", "mcp_warden", "check-policy", "-c", str(config_path)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stdout == matrix
    assert "no-destructive" in completed.stdout
