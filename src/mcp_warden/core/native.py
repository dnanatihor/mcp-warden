"""Load and evaluate a native YAML policy."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Protocol

import yaml
from pydantic import ValidationError

from mcp_warden.core.models import Decision, DecisionRequest, NativePolicy
from mcp_warden.core.policy import decide

logger = logging.getLogger("mcp_warden.policy")


class PolicyError(Exception):
    """A policy file cannot be loaded."""


class PolicyEngine(Protocol):
    async def decide(self, request: DecisionRequest) -> Decision: ...


class NativePolicyEngine:
    def __init__(self, policy: NativePolicy) -> None:
        self.policy = policy

    async def decide(self, request: DecisionRequest) -> Decision:
        try:
            return decide(self.policy, request)
        except Exception:
            logger.warning("policy evaluation failed")
            return Decision(
                effect="DENY",
                rule_ids=(),
                reason="policy_engine_error",
                obligations=(),
            )


def load_native_policy(path: Path) -> NativePolicy:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise PolicyError("policy file must be a mapping")
    try:
        return NativePolicy.model_validate(loaded)
    except ValidationError as exc:
        locations = [".".join(str(item) for item in error["loc"]) for error in exc.errors()]
        raise PolicyError("invalid policy: " + ", ".join(locations)) from None
