"""Rule matching, deny-overrides, and obligation merging."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_warden.core.models import DecisionRequest, NativePolicy, Obligation, Rule, ToolSelector
from mcp_warden.core.policy import decide, merge_obligations
from mcp_warden.principals import Principal

_POLICY = NativePolicy.model_validate(
    {
        "default": "deny",
        "rules": [
            {
                "id": "no-destructive",
                "effect": "deny",
                "actions": ["call"],
                "tools": {"annotations": {"destructiveHint": True}},
                "reason": "Destructive tools are blocked through the gateway.",
            },
            {
                "id": "analysts-read-catalog",
                "effect": "allow",
                "actions": ["list", "call"],
                "principals": {"roles": ["analyst"]},
                "tools": {"servers": ["catalog"], "annotations": {"readOnlyHint": True}},
                "obligations": [
                    {"type": "mask_pii"},
                    {"type": "strip_inferences"},
                    {"type": "max_items", "n": 50},
                ],
            },
            {
                "id": "stewards-read-catalog",
                "effect": "allow",
                "actions": ["list", "call"],
                "principals": {"roles": ["steward"]},
                "tools": {"servers": ["catalog"], "annotations": {"readOnlyHint": True}},
                "obligations": [{"type": "mask_pii"}],
            },
            {
                "id": "named-jobs",
                "effect": "allow",
                "actions": ["list", "call"],
                "tools": {"names": ["list_jobs"]},
            },
        ],
    }
)


def _principal(roles: list[str] | None, team: str = "finance") -> Principal:
    attributes: dict[str, object] = {"team": team}
    if roles is not None:
        attributes["roles"] = roles
    return Principal(id="p", key_sha256="ab" * 32, attributes=attributes)  # type: ignore[arg-type]


def _request(
    principal: Principal,
    *,
    action: str = "call",
    server: str = "catalog",
    tool: str = "get_column_profile",
    annotations: dict[str, object] | None = None,
) -> DecisionRequest:
    return DecisionRequest(
        action=action,  # type: ignore[arg-type]
        principal=principal,
        server=server,
        tool=tool,
        annotations={} if annotations is None else annotations,
    )


def test_role_list_intersects_and_scalar_team_equals() -> None:
    analyst = _principal(["analyst"])
    decision = decide(_POLICY, _request(analyst, annotations={"readOnlyHint": True}))
    assert decision.effect == "ALLOW"
    assert decision.rule_ids == ("analysts-read-catalog",)


def test_scalar_mismatch_and_missing_attribute_do_not_match() -> None:
    policy = NativePolicy(
        rules=(
            Rule(
                id="finance-analysts",
                effect="allow",
                actions=("call",),
                principals={"roles": ["analyst"], "team": "finance"},
            ),
        )
    )
    other_team = _principal(["analyst"], team="risk")
    no_roles = Principal(id="p", key_sha256="ab" * 32, attributes={"team": "finance"})
    assert decide(policy, _request(other_team)).effect == "DENY"
    assert decide(policy, _request(no_roles)).effect == "DENY"
    assert decide(policy, _request(_principal(["analyst"]))).effect == "ALLOW"


def test_server_and_name_globs() -> None:
    policy = NativePolicy(
        rules=(
            Rule(
                id="glob",
                effect="allow",
                actions=("call",),
                tools=ToolSelector(servers=("cat*",), names=("get_*",)),
            ),
        )
    )
    principal = _principal(["analyst"])
    assert decide(policy, _request(principal)).effect == "ALLOW"
    assert decide(policy, _request(principal, server="admin")).effect == "DENY"
    assert decide(policy, _request(principal, tool="search_assets")).effect == "DENY"


def test_unannotated_tool_does_not_match_an_annotation_condition() -> None:
    analyst = _principal(["analyst"])
    decision = decide(_POLICY, _request(analyst, tool="list_jobs", server="admin", annotations={}))
    assert decision.rule_ids == ("named-jobs",)
    annotated = decide(
        _POLICY,
        _request(analyst, annotations={"readOnlyHint": False}),
    )
    assert annotated.effect == "DENY"
    assert annotated.reason == "default deny"


def test_destructive_call_is_denied_by_rule_id() -> None:
    steward = _principal(["steward"])
    decision = decide(
        _POLICY,
        _request(
            steward, server="admin", tool="delete_asset", annotations={"destructiveHint": True}
        ),
    )
    assert decision.effect == "DENY"
    assert decision.rule_ids == ("no-destructive",)
    assert decision.reason == "Destructive tools are blocked through the gateway."
    listed = decide(
        _POLICY,
        _request(
            steward,
            action="list",
            server="admin",
            tool="delete_asset",
            annotations={"destructiveHint": True},
        ),
    )
    assert listed.effect == "DENY"
    assert listed.reason == "default deny"


def test_deny_overrides_a_matching_allow() -> None:
    policy = NativePolicy(
        rules=(
            Rule(
                id="allow-all-calls",
                effect="allow",
                actions=("call",),
            ),
            Rule(
                id="no-destructive",
                effect="deny",
                actions=("call",),
                tools=ToolSelector(annotations={"destructiveHint": True}),
                reason="blocked",
            ),
        )
    )
    decision = decide(
        policy,
        _request(_principal(["analyst"]), annotations={"destructiveHint": True}),
    )
    assert decision.effect == "DENY"
    assert decision.rule_ids == ("no-destructive",)
    assert decision.obligations == ()


def test_obligation_merge_dedupes_and_keeps_smallest_max_items() -> None:
    merged = merge_obligations(
        [
            (
                Obligation(type="mask_pii"),
                Obligation(type="max_items", n=50),
                Obligation(type="strip_inferences"),
            ),
            (
                Obligation(type="mask_pii", detectors=("email",)),
                Obligation(type="max_items", n=10),
                Obligation(type="redact_fields", paths=("$.secret",)),
            ),
        ]
    )
    assert [item.type for item in merged] == [
        "redact_fields",
        "strip_inferences",
        "mask_pii",
        "max_items",
    ]
    assert merged[2].detectors == ()
    assert merged[3].n == 10


def test_multiple_allows_union_their_rule_ids_and_obligations() -> None:
    policy = NativePolicy(
        default="deny",
        rules=(
            Rule(
                id="a",
                effect="allow",
                actions=("call",),
                obligations=(Obligation(type="max_items", n=50),),
            ),
            Rule(
                id="b",
                effect="allow",
                actions=("call",),
                obligations=(Obligation(type="mask_pii"), Obligation(type="max_items", n=20)),
            ),
        ),
    )
    decision = decide(policy, _request(_principal(["analyst"])))
    assert decision.effect == "ALLOW"
    assert decision.rule_ids == ("a", "b")
    assert decision.obligations == (
        Obligation(type="mask_pii"),
        Obligation(type="max_items", n=20),
    )


def test_invalid_obligation_parameters_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Obligation(type="max_items")
    with pytest.raises(ValidationError):
        Obligation(type="strip_inferences", n=1)
