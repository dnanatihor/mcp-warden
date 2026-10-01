"""OPA engine against a mocked HTTP server, including fail-closed cases."""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from tests.http_harness import serve_http

from mcp_warden.config import load_config
from mcp_warden.core.models import DecisionRequest
from mcp_warden.core.opa import OpaPolicyEngine, document_url, parse_decision
from mcp_warden.gateway import build_gateway
from mcp_warden.principals import Principal, load_principals

_ANALYST_KEY = "analyst-secret"
_STEWARD_KEY = "steward-secret"
_ROGUE_KEY = "rogue-secret"
_HASH = "0" * 64


def example_result(document: dict[str, Any]) -> dict[str, Any]:
    """Python twin of policies/example.rego for the mocked OPA server."""
    action = document.get("action")
    annotations = document.get("annotations") or {}
    attributes = (document.get("principal") or {}).get("attributes") or {}
    roles = attributes.get("roles") or []
    server = document.get("server")
    destructive = action == "call" and annotations.get("destructiveHint") is True
    read_only = (
        action in {"list", "call"}
        and server == "catalog"
        and annotations.get("readOnlyHint") is True
    )
    analyst = read_only and "analyst" in roles
    steward = read_only and "steward" in roles
    if destructive:
        return {
            "allow": False,
            "rule_ids": ["no-destructive"],
            "reason": "Destructive tools are blocked through the gateway.",
            "obligations": [],
        }
    obligations: list[dict[str, Any]] = []
    rule_ids: list[str] = []
    if analyst:
        rule_ids.append("analysts-read-catalog")
        obligations.extend(
            [
                {"type": "mask_pii"},
                {"type": "strip_inferences"},
                {"type": "max_items", "n": 50},
            ]
        )
    if steward:
        rule_ids.append("stewards-read-catalog")
        if not any(item["type"] == "mask_pii" for item in obligations):
            obligations.append({"type": "mask_pii"})
    if rule_ids:
        return {
            "allow": True,
            "rule_ids": rule_ids,
            "reason": "allow",
            "obligations": obligations,
        }
    return {"allow": False, "rule_ids": [], "reason": "default deny", "obligations": []}


def _principal(identifier: str, roles: list[str]) -> Principal:
    attributes: dict[str, list[str]] = {"roles": roles} if roles else {}
    return Principal(id=identifier, key_sha256=_HASH, attributes=attributes)


def _request(
    principal: Principal,
    *,
    action: str = "call",
    server: str = "catalog",
    tool: str = "get_column_profile",
    annotations: dict[str, Any] | None = None,
) -> DecisionRequest:
    return DecisionRequest(
        action=action,  # type: ignore[arg-type]
        principal=principal,
        server=server,
        tool=tool,
        annotations={} if annotations is None else annotations,
        arguments={"column_id": "do-not-log"},
    )


def _engine(handler: Any) -> OpaPolicyEngine:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return OpaPolicyEngine("http://opa:8181", "mcpwarden/decision", timeout=1, client=client)


def test_document_url_uses_the_data_api() -> None:
    assert document_url("http://opa:8181/", "mcpwarden/decision") == (
        "http://opa:8181/v1/data/mcpwarden/decision"
    )
    assert document_url("http://opa:8181", "mcpwarden.decision") == (
        "http://opa:8181/v1/data/mcpwarden/decision"
    )


def test_example_rego_covers_the_yaml_rules() -> None:
    text = Path("policies/example.rego").read_text(encoding="utf-8")
    assert "package mcpwarden.decision" in text
    for rule_id in ("no-destructive", "analysts-read-catalog", "stewards-read-catalog"):
        assert rule_id in text
    assert "strip_inferences" in text
    assert "max_items" in text
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert "policies/example.rego" in compose
    assert "openpolicyagent/opa:" in compose


@pytest.mark.asyncio
async def test_matrix_rows_against_mocked_opa() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        seen.append(json.dumps(body))
        return httpx.Response(200, json={"result": example_result(body["input"])})

    engine = _engine(handler)
    analyst = _principal("analyst-agent", ["analyst"])
    steward = _principal("steward-agent", ["steward"])
    rogue = _principal("rogue-agent", [])
    read_only = {"readOnlyHint": True}
    destructive = {"destructiveHint": True}

    profile = await engine.decide(
        _request(analyst, annotations=read_only, tool="get_column_profile")
    )
    assert profile.effect == "ALLOW"
    assert profile.rule_ids == ("analysts-read-catalog",)
    assert [item.type for item in profile.obligations] == [
        "strip_inferences",
        "mask_pii",
        "max_items",
    ]
    assert profile.obligations[2].n == 50

    steward_profile = await engine.decide(_request(steward, annotations=read_only))
    assert steward_profile.effect == "ALLOW"
    assert steward_profile.rule_ids == ("stewards-read-catalog",)
    assert [item.type for item in steward_profile.obligations] == ["mask_pii"]

    search = await engine.decide(_request(analyst, annotations=read_only, tool="search_assets"))
    assert search.effect == "ALLOW"
    assert search.obligations[2].n == 50

    delete = await engine.decide(
        _request(analyst, server="admin", tool="delete_asset", annotations=destructive)
    )
    assert delete.effect == "DENY"
    assert delete.rule_ids == ("no-destructive",)
    assert delete.obligations == ()

    listed_delete = await engine.decide(
        _request(
            analyst,
            action="list",
            server="admin",
            tool="delete_asset",
            annotations=destructive,
        )
    )
    assert listed_delete.effect == "DENY"
    assert listed_delete.reason == "default deny"

    jobs = await engine.decide(_request(analyst, server="admin", tool="list_jobs", annotations={}))
    assert jobs.effect == "DENY"
    assert jobs.reason == "default deny"

    rogue_call = await engine.decide(_request(rogue, annotations=read_only))
    assert rogue_call.effect == "DENY"
    assert rogue_call.reason == "default deny"
    assert "do-not-log" in "".join(seen)


@pytest.mark.asyncio
async def test_opa_failures_are_closed(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)

    def connect(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    def timeout(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    def crash(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    def missing(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": None})

    def bad_allow(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": {"allow": "yes"}})

    def bad_obligation(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"result": {"allow": True, "obligations": [{"type": "max_items"}]}},
        )

    analyst = _principal("analyst-agent", ["analyst"])
    request = _request(analyst, annotations={"readOnlyHint": True})
    for handler in (connect, timeout, crash, missing, bad_allow, bad_obligation):
        decision = await _engine(handler).decide(request)
        assert decision.effect == "DENY"
        assert decision.reason == "policy_engine_error"
        assert decision.obligations == ()
    assert "do-not-log" not in caplog.text
    with pytest.raises(ValueError, match="missing result"):
        parse_decision({"allow": True})


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_gateway_matrix_with_opa_engine(tmp_path: Path) -> None:
    async def decision(request: Request) -> JSONResponse:
        body = await request.json()
        return JSONResponse({"result": example_result(body["input"])})

    opa = Starlette(routes=[Route("/v1/data/mcpwarden/decision", decision, methods=["POST"])])
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
    async with serve_http(opa) as opa_url:
        opa_base = opa_url.removesuffix("/mcp")
        config_path = tmp_path / "warden.yaml"
        config_path.write_text(
            f"""
listen: {{transport: streamable_http, host: 127.0.0.1, port: 8900, path: /mcp}}
principals_file: ./principals.yaml
policy: {{engine: opa, url: "{opa_base}", package: mcpwarden/decision}}
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
        call_log = tmp_path / "calls.jsonl"
        config = load_config(config_path)
        gateway = build_gateway(config, load_principals(config.principals_file))
        app = gateway.http_app(path="/mcp", transport="streamable-http")
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("FIXTURE_CALL_LOG", str(call_log))
            async with serve_http(app) as url:
                async with Client(url, auth=_ANALYST_KEY) as analyst:
                    names = sorted(tool.name for tool in await analyst.list_tools())
                    profile = await analyst.call_tool(
                        "catalog__get_column_profile", {"column_id": "col_email"}
                    )
                    search = await analyst.call_tool(
                        "catalog__search_assets", {"query": "customer"}
                    )
                    with pytest.raises(ToolError, match="no-destructive"):
                        await analyst.call_tool("admin__delete_asset", {"asset_id": "a1"})
                    with pytest.raises(ToolError, match="default deny"):
                        await analyst.call_tool("admin__list_jobs", {})
                async with Client(url, auth=_STEWARD_KEY) as steward:
                    steward_profile = await steward.call_tool(
                        "catalog__get_column_profile", {"column_id": "col_email"}
                    )
                async with Client(url, auth=_ROGUE_KEY) as rogue:
                    rogue_tools = await rogue.list_tools()

    assert names == ["catalog__get_column_profile", "catalog__search_assets"]
    assert profile.data["profiling_observations"][0]["value"] == "«email»"
    assert profile.data["ai_inferences"] == []
    assert profile.data["inference_permitted"] is False
    assert len(search.data["results"]) == 50
    assert search.data["_warden_truncated"] is True
    assert steward_profile.data["profiling_observations"][0]["value"] == "«email»"
    assert len(steward_profile.data["ai_inferences"]) == 1
    assert rogue_tools == []
    recorded = call_log.read_text(encoding="utf-8") if call_log.exists() else ""
    assert "delete_asset" not in recorded
    assert "list_jobs" not in recorded
