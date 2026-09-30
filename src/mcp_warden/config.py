"""Configuration models for ``warden.yaml``.

Relative paths are resolved against the directory that contains the config
file. ``${VAR}`` is replaced from the process environment before validation.
A variable that is not set is a configuration error; the error names the
variable and does not include a value.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """A warden config file cannot be loaded."""


class HttpListen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["streamable_http"]
    host: str = "127.0.0.1"
    port: int = Field(default=8900, ge=1, le=65535)
    path: str = "/mcp"


class StdioListen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["stdio"]


ListenConfig = Annotated[HttpListen | StdioListen, Field(discriminator="transport")]


class NativePolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    engine: Literal["native"]
    file: Path


class OpaPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    engine: Literal["opa"]
    url: str
    package: str


PolicyConfig = Annotated[NativePolicyConfig | OpaPolicyConfig, Field(discriminator="engine")]


class StdioUpstream(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["stdio"]
    command: str
    args: list[str] = Field(default_factory=list)


class StreamableHttpUpstream(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: Literal["streamable_http"]
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


UpstreamConfig = Annotated[
    StdioUpstream | StreamableHttpUpstream,
    Field(discriminator="transport"),
]


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    file: Path
    anchor_every: int = Field(default=100, ge=1)
    store_masked_arguments: bool = False


class TelemetryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    otel: bool = False


class WardenConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    listen: ListenConfig
    principals_file: Path
    policy: PolicyConfig
    upstreams: dict[str, UpstreamConfig]
    tools_cache_ttl_s: int = Field(default=60, ge=0)
    upstream_timeout_s: float = Field(default=30, gt=0)
    audit: AuditConfig
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)

    def with_resolved_paths(self, base: Path) -> WardenConfig:
        policy = self.policy
        if isinstance(policy, NativePolicyConfig):
            policy = policy.model_copy(update={"file": _resolve(base, policy.file)})
        return self.model_copy(
            update={
                "principals_file": _resolve(base, self.principals_file),
                "policy": policy,
                "audit": self.audit.model_copy(update={"file": _resolve(base, self.audit.file)}),
            }
        )


def load_config(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> WardenConfig:
    env: Mapping[str, str] = os.environ if environ is None else environ
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ConfigError("warden config must be a mapping")
    interpolated = _interpolate(loaded, env)
    try:
        config = WardenConfig.model_validate(interpolated)
    except ValidationError as exc:
        locations = [".".join(str(item) for item in error["loc"]) for error in exc.errors()]
        raise ConfigError("invalid config: " + ", ".join(locations)) from None
    return config.with_resolved_paths(path.parent.resolve())


def _resolve(base: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return (base / path).resolve()


def _interpolate(value: Any, environ: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda match: _lookup_env(match.group(1), environ), value)
    if isinstance(value, dict):
        return {key: _interpolate(item, environ) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, environ) for item in value]
    return value


def _lookup_env(name: str, environ: Mapping[str, str]) -> str:
    try:
        return environ[name]
    except KeyError:
        raise ConfigError(f"environment variable {name} is not set") from None
