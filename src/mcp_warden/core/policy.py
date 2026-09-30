"""Native YAML policy matching. Deny overrides allow."""

from __future__ import annotations

import fnmatch
from typing import Any

from mcp_warden.core.models import (
    OBLIGATION_ORDER,
    Decision,
    DecisionRequest,
    NativePolicy,
    Obligation,
    Rule,
)
from mcp_warden.principals import AttributeValue, Principal


def decide(policy: NativePolicy, request: DecisionRequest) -> Decision:
    denies = [rule for rule in policy.rules if rule.effect == "deny" and _matches(rule, request)]
    if denies:
        return Decision(
            effect="DENY",
            rule_ids=tuple(rule.id for rule in denies),
            reason=next((rule.reason for rule in denies if rule.reason), "deny"),
            obligations=(),
        )
    allows = [rule for rule in policy.rules if rule.effect == "allow" and _matches(rule, request)]
    if allows:
        return Decision(
            effect="ALLOW",
            rule_ids=tuple(rule.id for rule in allows),
            reason=next((rule.reason for rule in allows if rule.reason), "allow"),
            obligations=merge_obligations(rule.obligations for rule in allows),
        )
    if policy.default == "allow":
        return Decision(effect="ALLOW", rule_ids=(), reason="default allow", obligations=())
    return Decision(effect="DENY", rule_ids=(), reason="default deny", obligations=())


def merge_obligations(groups: Any) -> tuple[Obligation, ...]:
    """Union by type. ``max_items`` keeps the smallest ``n``. Other types keep the first."""
    chosen: dict[str, Obligation] = {}
    for group in groups:
        for obligation in group:
            current = chosen.get(obligation.type)
            if current is None:
                chosen[obligation.type] = obligation
                continue
            if (
                obligation.type == "max_items"
                and obligation.n is not None
                and current.n is not None
                and obligation.n < current.n
            ):
                chosen[obligation.type] = obligation
    return tuple(chosen[name] for name in OBLIGATION_ORDER if name in chosen)


def _matches(rule: Rule, request: DecisionRequest) -> bool:
    if request.action not in rule.actions:
        return False
    if rule.principals is not None and not _principals_match(rule.principals, request.principal):
        return False
    return rule.tools is None or _tools_match(rule, request)


def _principals_match(expected: dict[str, AttributeValue], principal: Principal) -> bool:
    for name, required in expected.items():
        actual = principal.attributes.get(name)
        if actual is None or not _values_match(required, actual):
            return False
    return True


def _values_match(required: AttributeValue, actual: AttributeValue) -> bool:
    if isinstance(required, list) and isinstance(actual, list):
        return any(item in actual for item in required)
    if isinstance(required, list) or isinstance(actual, list):
        return False
    return required == actual


def _tools_match(rule: Rule, request: DecisionRequest) -> bool:
    selector = rule.tools
    if selector is None:
        return True
    if selector.servers is not None and not _any_glob(selector.servers, request.server):
        return False
    if selector.names is not None and not _any_glob(selector.names, request.tool):
        return False
    if selector.annotations is not None:
        if not request.annotations:
            return False
        for key, expected in selector.annotations.items():
            if request.annotations.get(key) != expected:
                return False
    return True


def _any_glob(patterns: tuple[str, ...], value: str) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)
