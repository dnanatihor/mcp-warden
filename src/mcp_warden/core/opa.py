"""OPA decision client.

OPA's Data API wraps the package document in ``{"result": ...}``. A missing
document, a malformed document, an HTTP error, or a connection failure is a
DENY with reason ``policy_engine_error``.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_warden.core.models import Decision, DecisionRequest, Obligation
from mcp_warden.core.policy import merge_obligations

logger = logging.getLogger("mcp_warden.policy")


def document_url(base_url: str, package: str) -> str:
    path = package.strip().strip("/").replace(".", "/")
    if path == "":
        raise ValueError("OPA package path is empty")
    return base_url.rstrip("/") + "/v1/data/" + path


def parse_decision(body: Any) -> Decision:
    if not isinstance(body, dict) or "result" not in body:
        raise ValueError("OPA response is missing result")
    result = body["result"]
    if not isinstance(result, dict):
        raise ValueError("OPA result is not an object")
    allow = result.get("allow")
    if not isinstance(allow, bool):
        raise ValueError("OPA result allow is not a boolean")
    rule_ids = result.get("rule_ids", [])
    if not isinstance(rule_ids, list) or any(not isinstance(item, str) for item in rule_ids):
        raise ValueError("OPA result rule_ids is not a list of strings")
    reason = result.get("reason", "")
    if not isinstance(reason, str):
        raise ValueError("OPA result reason is not a string")
    if not allow:
        return Decision(
            effect="DENY",
            rule_ids=tuple(rule_ids),
            reason=reason or "deny",
            obligations=(),
        )
    raw_obligations = result.get("obligations", [])
    if not isinstance(raw_obligations, list):
        raise ValueError("OPA result obligations is not a list")
    parsed = tuple(Obligation.model_validate(item) for item in raw_obligations)
    return Decision(
        effect="ALLOW",
        rule_ids=tuple(rule_ids),
        reason=reason or "allow",
        obligations=merge_obligations((parsed,)),
    )


class OpaPolicyEngine:
    def __init__(
        self,
        url: str,
        package: str,
        *,
        timeout: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._endpoint = document_url(url, package)
        self._timeout = timeout
        self._client = client

    async def decide(self, request: DecisionRequest) -> Decision:
        try:
            return await self._decide(request)
        except Exception:
            logger.warning("policy evaluation failed")
            return Decision(
                effect="DENY",
                rule_ids=(),
                reason="policy_engine_error",
                obligations=(),
            )

    async def _decide(self, request: DecisionRequest) -> Decision:
        payload = {"input": request.model_dump(mode="json")}
        if self._client is None:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(self._endpoint, json=payload)
        else:
            response = await self._client.post(self._endpoint, json=payload, timeout=self._timeout)
        response.raise_for_status()
        return parse_decision(response.json())
