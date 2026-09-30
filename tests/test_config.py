"""warden.yaml models, including ${VAR} interpolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_warden.config import (
    ConfigError,
    HttpListen,
    NativePolicyConfig,
    OpaPolicyConfig,
    StdioUpstream,
    StreamableHttpUpstream,
    load_config,
)

_SPEC_EXAMPLE = """
listen: {transport: streamable_http, host: 127.0.0.1, port: 8900, path: /mcp}
principals_file: ./principals.yaml
policy: {engine: native, file: ./policy.yaml}
upstreams:
  catalog: {transport: stdio, command: python, args: ["-m", "examples.catalog_server"]}
  admin:
    transport: streamable_http
    url: http://localhost:9001/mcp
    headers: {Authorization: "Bearer ${ADMIN_TOKEN}"}
tools_cache_ttl_s: 60
upstream_timeout_s: 30
audit: {file: ./audit/warden.jsonl, anchor_every: 100, store_masked_arguments: false}
telemetry: {otel: false}
"""


def test_spec_example_loads_and_resolves_paths(tmp_path: Path) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(_SPEC_EXAMPLE, encoding="utf-8")

    config = load_config(path, environ={"ADMIN_TOKEN": "token-value"})

    assert isinstance(config.listen, HttpListen)
    assert config.listen.host == "127.0.0.1"
    assert config.listen.port == 8900
    assert config.listen.path == "/mcp"
    assert config.principals_file == (tmp_path / "principals.yaml").resolve()
    assert isinstance(config.policy, NativePolicyConfig)
    assert config.policy.file == (tmp_path / "policy.yaml").resolve()
    catalog = config.upstreams["catalog"]
    assert isinstance(catalog, StdioUpstream)
    assert catalog.command == "python"
    assert catalog.args == ["-m", "examples.catalog_server"]
    admin = config.upstreams["admin"]
    assert isinstance(admin, StreamableHttpUpstream)
    assert admin.url == "http://localhost:9001/mcp"
    assert admin.headers == {"Authorization": "Bearer token-value"}
    assert config.tools_cache_ttl_s == 60
    assert config.upstream_timeout_s == 30
    assert config.audit.file == (tmp_path / "audit" / "warden.jsonl").resolve()
    assert config.audit.anchor_every == 100
    assert config.audit.store_masked_arguments is False
    assert config.telemetry.otel is False


def test_defaults_match_the_spec_example(tmp_path: Path) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(
        """
listen: {transport: streamable_http}
principals_file: principals.yaml
policy: {engine: native, file: policy.yaml}
upstreams: {}
audit: {file: audit/warden.jsonl}
""",
        encoding="utf-8",
    )

    config = load_config(path, environ={})

    assert isinstance(config.listen, HttpListen)
    assert config.listen.host == "127.0.0.1"
    assert config.listen.port == 8900
    assert config.listen.path == "/mcp"
    assert config.tools_cache_ttl_s == 60
    assert config.upstream_timeout_s == 30
    assert config.audit.anchor_every == 100
    assert config.audit.store_masked_arguments is False
    assert config.telemetry.otel is False


def test_opa_policy_config(tmp_path: Path) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(
        """
listen: {transport: streamable_http}
principals_file: principals.yaml
policy: {engine: opa, url: http://opa:8181, package: mcpwarden/decision}
upstreams: {}
audit: {file: audit/warden.jsonl}
""",
        encoding="utf-8",
    )

    config = load_config(path, environ={})

    assert isinstance(config.policy, OpaPolicyConfig)
    assert config.policy.url == "http://opa:8181"
    assert config.policy.package == "mcpwarden/decision"


def test_absolute_paths_are_unchanged(tmp_path: Path) -> None:
    principals = tmp_path / "abs-principals.yaml"
    path = tmp_path / "nested" / "warden.yaml"
    path.parent.mkdir()
    path.write_text(
        f"""
listen: {{transport: streamable_http}}
principals_file: {principals}
policy: {{engine: native, file: policy.yaml}}
upstreams: {{}}
audit: {{file: audit/warden.jsonl}}
""",
        encoding="utf-8",
    )

    config = load_config(path, environ={})

    assert config.principals_file == principals.resolve()
    assert isinstance(config.policy, NativePolicyConfig)
    assert config.policy.file == (path.parent / "policy.yaml").resolve()


def test_unset_environment_variable_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(_SPEC_EXAMPLE, encoding="utf-8")

    with pytest.raises(ConfigError, match="ADMIN_TOKEN") as raised:
        load_config(path, environ={})

    assert "token-value" not in str(raised.value)


def test_invalid_engine_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(
        """
listen: {transport: streamable_http}
principals_file: principals.yaml
policy: {engine: other, file: policy.yaml}
upstreams: {}
audit: {file: audit/warden.jsonl}
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError):
        load_config(path, environ={})
