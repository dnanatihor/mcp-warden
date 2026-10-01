"""Audit chain, verify-log, and one record per tools/list and tools/call."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
from pathlib import Path

import httpx
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from tests.http_harness import serve_http

from mcp_warden.auditlog import AuditWriter
from mcp_warden.cli import main
from mcp_warden.config import load_config
from mcp_warden.core.audit import GENESIS_HASH, canonical_json, record_hash, verify_log
from mcp_warden.gateway import build_gateway
from mcp_warden.principals import load_principals

_ANALYST_KEY = "analyst-secret"
_BAD_KEY = "do-not-log-this-key"
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
"""


class _MemorySink:
    def __init__(self) -> None:
        self.hashes: list[str] = []

    def emit(self, record_hash: str) -> None:
        self.hashes.append(record_hash)


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def test_canonical_json_is_stable() -> None:
    body = {"b": 1, "a": "x", "nested": {"z": True, "m": None}}
    assert canonical_json(body) == '{"a":"x","b":1,"nested":{"m":null,"z":true}}'
    digest = record_hash({"seq": 1, "prev_hash": GENESIS_HASH, "action": "list"})
    assert (
        digest
        == hashlib.sha256(
            canonical_json({"action": "list", "prev_hash": GENESIS_HASH, "seq": 1}).encode("utf-8")
        ).hexdigest()
    )
    assert len(GENESIS_HASH) == 64


def test_verify_log_reports_the_first_broken_seq(tmp_path: Path) -> None:
    first = {"seq": 1, "action": "list", "prev_hash": GENESIS_HASH}
    first["hash"] = record_hash(first)
    second = {"seq": 2, "action": "call", "prev_hash": first["hash"]}
    second["hash"] = record_hash(second)
    text = canonical_json(first) + "\n" + canonical_json(second) + "\n"
    assert verify_log(text) is None

    broken = json.loads(canonical_json(second))
    broken["action"] = "list"
    tampered = canonical_json(first) + "\n" + canonical_json(broken) + "\n"
    assert verify_log(tampered) == 2

    flipped = text.encode("utf-8")
    flipped = flipped[:1] + bytes([(flipped[0] ^ 0x01)]) + flipped[2:]
    assert verify_log(flipped.decode("utf-8")) == 1


def test_verify_log_cli_ok_and_broken(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    record = {"seq": 1, "action": "list", "prev_hash": GENESIS_HASH}
    record["hash"] = record_hash(record)
    path = tmp_path / "warden.jsonl"
    path.write_text(canonical_json(record) + "\n", encoding="utf-8")
    assert main(["verify-log", str(path)]) == 0
    assert capsys.readouterr().out == "OK\n"

    raw = bytearray(path.read_bytes())
    raw[-4] = raw[-4] ^ 0x01
    path.write_bytes(raw)
    assert main(["verify-log", str(path)]) == 1
    assert capsys.readouterr().out == "seq 1\n"


@pytest.mark.asyncio
async def test_parallel_appends_keep_a_contiguous_chain(tmp_path: Path) -> None:
    sink = _MemorySink()
    path = tmp_path / "audit" / "warden.jsonl"
    writer = AuditWriter(path, anchor_every=100, sink=sink, store_masked_arguments=False)

    async def one(index: int) -> None:
        await writer.append(
            {
                "action": "call",
                "tool": "ping",
                "n": index,
                "ts": "2026-09-30T10:15:02.123Z",
            }
        )

    await asyncio.gather(*(one(index) for index in range(100)))
    await writer.aclose()

    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert [record["seq"] for record in records] == list(range(1, 101))
    assert records[0]["prev_hash"] == GENESIS_HASH
    assert verify_log(path.read_text(encoding="utf-8")) is None
    assert sink.hashes == [records[99]["hash"]]


def _write_gateway_config(
    tmp_path: Path,
    *,
    store_masked: bool = False,
    upstreams: str | None = None,
    policy: str = _POLICY,
) -> Path:
    (tmp_path / "principals.yaml").write_text(
        f"""
principals:
  - id: analyst-agent
    key_sha256: "{_sha(_ANALYST_KEY)}"
    attributes: {{roles: [analyst], team: finance, clearance: internal}}
""",
        encoding="utf-8",
    )
    (tmp_path / "policy.yaml").write_text(policy, encoding="utf-8")
    if upstreams is None:
        upstreams = f"""
  catalog:
    transport: stdio
    command: "{sys.executable}"
    args: ["-m", "examples.catalog_server"]
  admin:
    transport: stdio
    command: "{sys.executable}"
    args: ["-m", "examples.admin_server"]
"""
    path = tmp_path / "warden.yaml"
    path.write_text(
        f"""
listen: {{transport: streamable_http, host: 127.0.0.1, port: 8900, path: /mcp}}
principals_file: ./principals.yaml
policy: {{engine: native, file: ./policy.yaml}}
upstreams:
{upstreams}
audit:
  file: ./audit/warden.jsonl
  anchor_every: 100
  store_masked_arguments: {str(store_masked).lower()}
""",
        encoding="utf-8",
    )
    return path


@pytest.mark.asyncio
async def test_each_list_and_call_writes_one_audit_record(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.jsonl"
    config = load_config(_write_gateway_config(tmp_path))
    gateway = build_gateway(config, load_principals(config.principals_file))
    app = gateway.http_app(path="/mcp", transport="streamable-http")

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("FIXTURE_CALL_LOG", str(call_log))
        async with serve_http(app) as url, Client(url, auth=_ANALYST_KEY) as client:
            tools = await client.list_tools()
            await client.call_tool("catalog__get_column_profile", {"column_id": "col_email"})
            with pytest.raises(ToolError, match="no-destructive"):
                await client.call_tool("admin__delete_asset", {"asset_id": "a1"})

    names = sorted(tool.name for tool in tools)
    assert "admin__delete_asset" not in names
    assert "admin__list_jobs" not in names
    recorded = [
        json.loads(line)["tool"] for line in call_log.read_text(encoding="utf-8").splitlines()
    ]
    assert "delete_asset" not in recorded
    assert "list_jobs" not in recorded

    audit_path = config.audit.file
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    lists = [row for row in rows if row["action"] == "list"]
    calls = [row for row in rows if row["action"] == "call"]
    # The MCP client issues tools/list again before the first tools/call.
    assert lists
    assert all(row["visible_tools"] == 2 and row["hidden_tools"] == 2 for row in lists)
    assert len(calls) == 2
    assert lists[0]["visible_tools"] == 2
    assert lists[0]["hidden_tools"] == 2
    assert "tool" not in lists[0]
    assert "arguments_sha256" not in lists[0]
    profile = next(row for row in calls if row["tool"] == "get_column_profile")
    denied = next(row for row in calls if row["tool"] == "delete_asset")
    assert profile["effect"] == "ALLOW"
    assert profile["server"] == "catalog"
    assert profile["principal"] == "analyst-agent"
    assert profile["rule_ids"] == ["analysts-read-catalog"]
    assert "mask_pii" in profile["obligations_applied"]
    assert "strip_inferences" in profile["obligations_applied"]
    assert profile["upstream_status"] == "ok"
    assert profile["prev_hash"] != ""
    assert len(profile["hash"]) == 64
    assert "ada@finance.example" not in audit_path.read_text(encoding="utf-8")
    assert denied["effect"] == "DENY"
    assert denied["rule_ids"] == ["no-destructive"]
    assert denied["upstream_status"] == "denied"
    assert main(["verify-log", str(audit_path)]) == 0

    raw = bytearray(audit_path.read_bytes())
    # Flip one byte inside the second record so JSON still parses.
    second = audit_path.read_text(encoding="utf-8").splitlines()[1]
    start = raw.find(second.encode("utf-8"))
    raw[start + 10] = raw[start + 10] ^ 0x01
    audit_path.write_bytes(raw)
    assert main(["verify-log", str(audit_path)]) == 1


@pytest.mark.asyncio
async def test_invalid_key_writes_no_audit_record(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = load_config(_write_gateway_config(tmp_path))
    gateway = build_gateway(config, load_principals(config.principals_file))
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
    assert not config.audit.file.exists() or config.audit.file.read_text(encoding="utf-8") == ""


@pytest.mark.asyncio
async def test_parallel_tool_calls_keep_a_contiguous_chain(tmp_path: Path) -> None:
    echo = FastMCP("echo")

    @echo.tool
    def ping(n: int) -> dict[str, int]:
        return {"n": n}

    echo_app = echo.http_app(path="/mcp", transport="streamable-http")
    policy = """
default: deny
rules:
  - id: allow-ping
    effect: allow
    actions: [list, call]
    principals: {roles: [analyst]}
    tools: {names: [ping]}
"""
    async with serve_http(echo_app) as echo_url:
        upstreams = f"""
  box:
    transport: streamable_http
    url: "{echo_url}"
"""
        config = load_config(_write_gateway_config(tmp_path, upstreams=upstreams, policy=policy))
        gateway = build_gateway(config, load_principals(config.principals_file))
        app = gateway.http_app(path="/mcp", transport="streamable-http")
        async with serve_http(app) as url:

            async def one(index: int) -> None:
                async with Client(url, auth=_ANALYST_KEY) as client:
                    await client.call_tool("box__ping", {"n": index})

            await asyncio.gather(*(one(index) for index in range(100)))

    rows = [json.loads(line) for line in config.audit.file.read_text(encoding="utf-8").splitlines()]
    calls = [row for row in rows if row["action"] == "call"]
    assert len(calls) == 100
    assert [row["seq"] for row in rows] == list(range(1, len(rows) + 1))
    assert verify_log(config.audit.file.read_text(encoding="utf-8")) is None


@pytest.mark.asyncio
async def test_store_masked_arguments(tmp_path: Path) -> None:
    echo = FastMCP("echo")

    @echo.tool
    def ping(message: str) -> dict[str, str]:
        return {"message": message}

    echo_app = echo.http_app(path="/mcp", transport="streamable-http")
    policy = """
default: deny
rules:
  - id: allow-ping
    effect: allow
    actions: [list, call]
    principals: {roles: [analyst]}
    tools: {names: [ping]}
"""
    async with serve_http(echo_app) as echo_url:
        upstreams = f"""
  box:
    transport: streamable_http
    url: "{echo_url}"
"""
        config = load_config(
            _write_gateway_config(
                tmp_path,
                store_masked=True,
                upstreams=upstreams,
                policy=policy,
            )
        )
        gateway = build_gateway(config, load_principals(config.principals_file))
        app = gateway.http_app(path="/mcp", transport="streamable-http")
        async with serve_http(app) as url, Client(url, auth=_ANALYST_KEY) as client:
            await client.call_tool("box__ping", {"message": "ada@finance.example"})

    text = config.audit.file.read_text(encoding="utf-8")
    assert "ada@finance.example" not in text
    calls = [json.loads(line) for line in text.splitlines() if '"action":"call"' in line]
    assert calls[-1]["masked_arguments"]["message"] == "«email»"
