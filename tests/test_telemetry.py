"""Optional OpenTelemetry spans record decisions and not payloads."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from mcp_warden.core.models import Decision
from mcp_warden.telemetry import record_decision

_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))
trace.set_tracer_provider(_PROVIDER)


def test_span_records_the_decision_and_not_arguments() -> None:
    _EXPORTER.clear()
    decision = Decision(
        effect="DENY",
        rule_ids=("no-destructive",),
        reason="blocked",
        obligations=(),
    )
    record_decision(
        True,
        action="call",
        server="admin",
        tool="delete_asset",
        decision=decision,
    )
    record_decision(
        False,
        action="call",
        server="admin",
        tool="delete_asset",
        decision=decision,
    )
    spans = _EXPORTER.get_finished_spans()
    assert len(spans) == 1
    attributes = dict(spans[0].attributes or {})
    assert attributes["mcp_warden.effect"] == "DENY"
    assert attributes["mcp_warden.rule_ids"] == "no-destructive"
    assert attributes["mcp_warden.tool"] == "delete_asset"
    assert "argument" not in "".join(attributes)
