"""Each obligation on a crafted payload."""

from __future__ import annotations

from mcp_warden.core.models import Obligation
from mcp_warden.core.obligations import DefaultPiiDetector, apply_obligations

_ENVELOPE = {
    "envelope_version": "0.1",
    "inference_permitted": True,
    "governance_notice": "present",
    "profiling_observations": [{"value": "ada@finance.example"}],
    "ai_inferences": [{"id": "ai-1", "statement": "guess"}],
}


def test_redact_fields_replaces_jsonpath_matches() -> None:
    result = apply_obligations(
        {"user": {"email": "ada@finance.example"}, "items": [{"secret": "x"}, {"secret": "y"}]},
        (Obligation(type="redact_fields", paths=("$.user.email", "$.items[*].secret")),),
    )
    assert result.value["user"]["email"] == "«redacted»"
    assert result.value["items"] == [{"secret": "«redacted»"}, {"secret": "«redacted»"}]
    assert result.applied == ("redact_fields",)


def test_strip_inferences_withholds_level2_and_removes_level1() -> None:
    level2 = apply_obligations(_ENVELOPE, (Obligation(type="strip_inferences"),))
    assert level2.value["ai_inferences"] == []
    assert level2.value["inference_permitted"] is False
    assert level2.not_applicable == ()

    level1 = apply_obligations(
        {
            "inference_permitted": True,
            "rows": [
                {"epistemic_layer": "observed", "value": 1},
                {"epistemic_layer": "inferred", "value": 2},
            ],
        },
        (Obligation(type="strip_inferences"),),
    )
    assert level1.value["rows"] == [{"epistemic_layer": "observed", "value": 1}]

    skipped = apply_obligations({"results": [1]}, (Obligation(type="strip_inferences"),))
    assert skipped.not_applicable == ("strip_inferences",)


def test_mask_pii_replaces_email_phone_and_card() -> None:
    text = "ada@finance.example called +1 415 555 0132 card 4111111111111111"
    masked = DefaultPiiDetector().find(text)
    kinds = {item.type for item in masked}
    assert {"email", "phone", "card"} <= kinds
    result = apply_obligations(text, (Obligation(type="mask_pii"),))
    assert result.value == "«email» called «phone» card «card»"


def test_max_items_truncates_top_level_arrays() -> None:
    result = apply_obligations(
        {"results": list(range(120)), "note": "keep"},
        (Obligation(type="max_items", n=50),),
    )
    assert result.value["results"] == list(range(50))
    assert result.value["_warden_truncated"] is True
    assert result.value["note"] == "keep"


def test_obligations_run_in_fixed_order() -> None:
    result = apply_obligations(
        _ENVELOPE,
        (
            Obligation(type="max_items", n=50),
            Obligation(type="mask_pii"),
            Obligation(type="strip_inferences"),
        ),
    )
    assert result.applied == ("strip_inferences", "mask_pii", "max_items")
    assert result.value["profiling_observations"][0]["value"] == "«email»"
    assert result.value["ai_inferences"] == []
