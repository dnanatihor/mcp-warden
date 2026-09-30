"""Decision types from SPEC.md §5.1."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_warden.principals import AttributeValue, Principal

ObligationType = Literal["redact_fields", "strip_inferences", "mask_pii", "max_items"]
OBLIGATION_ORDER: tuple[ObligationType, ...] = (
    "redact_fields",
    "strip_inferences",
    "mask_pii",
    "max_items",
)


class Obligation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: ObligationType
    paths: tuple[str, ...] = ()
    n: int | None = None
    detectors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_parameters(self) -> Obligation:
        if self.type == "max_items" and (self.n is None or self.n < 0):
            raise ValueError("max_items requires n >= 0")
        if self.type == "redact_fields" and not self.paths:
            raise ValueError("redact_fields requires paths")
        if self.type != "max_items" and self.n is not None:
            raise ValueError(f"{self.type} does not take n")
        if self.type != "redact_fields" and self.paths:
            raise ValueError(f"{self.type} does not take paths")
        if self.type != "mask_pii" and self.detectors:
            raise ValueError(f"{self.type} does not take detectors")
        return self


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal["list", "call"]
    principal: Principal
    server: str
    tool: str
    annotations: dict[str, Any] = Field(default_factory=dict)
    arguments: dict[str, Any] | None = None


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    effect: Literal["ALLOW", "DENY"]
    rule_ids: tuple[str, ...]
    reason: str
    obligations: tuple[Obligation, ...]


class ToolSelector(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    servers: tuple[str, ...] | None = None
    names: tuple[str, ...] | None = None
    annotations: dict[str, Any] | None = None


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    effect: Literal["allow", "deny"]
    actions: tuple[Literal["list", "call"], ...] = Field(min_length=1)
    principals: dict[str, AttributeValue] | None = None
    tools: ToolSelector | None = None
    obligations: tuple[Obligation, ...] = ()
    reason: str = ""


class NativePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    default: Literal["allow", "deny"] = "deny"
    rules: tuple[Rule, ...] = ()
