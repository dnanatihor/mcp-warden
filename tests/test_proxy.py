"""Authenticated, namespaced pass-through of the fixture upstreams."""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path

import httpx
import pytest
from examples.catalog_server import PROFILE_EMAIL
from fastmcp import Client
from fastmcp.exceptions import ToolError
from tests.http_harness import serve_http

from mcp_warden.config import StdioListen, load_config
from mcp_warden.gateway import build_gateway
from mcp_warden.principals import load_principals

_ANALYST_KEY = "analyst-secret"
_BAD_KEY = "do-not-log-this-key"


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _write_config(tmp_path: Path) -> Path:
    (tmp_path / "principals.yaml").write_text(
        f"""
principals:
  - id: analyst-agent
    key_sha256: "{_sha(_ANALYST_KEY)}"
    attributes: {{roles: [analyst]}}
""",
        encoding="utf-8",
    )
    (tmp_path / "policy.yaml").write_text("default: deny\nrules: []\n", encoding="utf-8")
    config_path = tmp_path / "warden.yaml"
    config_path.write_text(
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
    return config_path


@pytest.mark.asyncio
async def test_client_lists_and_calls_namespaced_fixture_tools(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.jsonl"
    monkey_env = {"FIXTURE_CALL_LOG": str(call_log)}
    config_path = _write_config(tmp_path)
    config = load_config(config_path)
    directory = load_principals(config.principals_file)
    gateway = build_gateway(config, directory, allow_all=True)
    app = gateway.http_app(path="/mcp", transport="streamable-http")

    with pytest.MonkeyPatch.context() as patch:
        for key, value in monkey_env.items():
            patch.setenv(key, value)
        async with serve_http(app) as url, Client(url, auth=_ANALYST_KEY) as client:
            names = sorted(tool.name for tool in await client.list_tools())
            profile = await client.call_tool(
                "catalog__get_column_profile",
                {"column_id": "col_email"},
            )

    assert names == [
        "admin__delete_asset",
        "admin__list_jobs",
        "catalog__get_column_profile",
        "catalog__search_assets",
    ]
    assert PROFILE_EMAIL in json.dumps(profile.data)
    recorded = [
        json.loads(line)["tool"] for line in call_log.read_text(encoding="utf-8").splitlines()
    ]
    assert recorded == ["get_column_profile"]


@pytest.mark.asyncio
async def test_invalid_key_is_http_401_and_is_not_logged(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = load_config(_write_config(tmp_path))
    gateway = build_gateway(config, load_principals(config.principals_file), allow_all=True)
    app = gateway.http_app(path="/mcp", transport="streamable-http")

    caplog.set_level(logging.WARNING)
    async with serve_http(app) as url, httpx.AsyncClient() as http:
        response = await http.post(
            url,
            headers={
                "Authorization": f"Bearer {_BAD_KEY}",
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
                    "clientInfo": {"name": "test", "version": "0"},
                },
            },
        )

    assert response.status_code == 401
    assert _BAD_KEY not in response.text
    assert _BAD_KEY not in caplog.text
    assert "authentication failed" in caplog.text


@pytest.mark.asyncio
async def test_without_allow_all_nothing_is_visible_or_forwarded(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.jsonl"
    config = load_config(_write_config(tmp_path))
    gateway = build_gateway(config, load_principals(config.principals_file), allow_all=False)
    app = gateway.http_app(path="/mcp", transport="streamable-http")

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("FIXTURE_CALL_LOG", str(call_log))
        async with serve_http(app) as url, Client(url, auth=_ANALYST_KEY) as client:
            tools = await client.list_tools()
            with pytest.raises(ToolError):
                await client.call_tool("catalog__get_column_profile", {"column_id": "col_email"})

    assert tools == []
    assert not call_log.exists()


@pytest.mark.asyncio
async def test_stdio_mode_uses_warden_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FIXTURE_CALL_LOG", str(call_log))
    monkeypatch.setenv("WARDEN_PRINCIPAL", "analyst-agent")
    config = load_config(_write_config(tmp_path)).model_copy(
        update={"listen": StdioListen(transport="stdio")}
    )
    gateway = build_gateway(config, load_principals(config.principals_file), allow_all=True)

    async with Client(gateway) as client:
        names = sorted(tool.name for tool in await client.list_tools())

    assert "catalog__get_column_profile" in names

    monkeypatch.setenv("WARDEN_PRINCIPAL", "missing-agent")
    denied = build_gateway(config, load_principals(config.principals_file), allow_all=True)
    async with Client(denied) as client:
        assert await client.list_tools() == []
