"""Optional decision spans.

Enabled with ``telemetry.otel: true``. Attributes are the decision outcome
only: action, server, tool, effect, and rule ids. Arguments and responses are
not span attributes.
"""

from __future__ import annotations

from opentelemetry import trace

from mcp_warden.core.models import Decision

_TRACER = trace.get_tracer("mcp_warden")


def record_decision(
    enabled: bool,
    *,
    action: str,
    server: str,
    tool: str,
    decision: Decision,
) -> None:
    if not enabled:
        return
    with _TRACER.start_as_current_span("mcp_warden.decision") as span:
        span.set_attribute("mcp_warden.action", action)
        span.set_attribute("mcp_warden.server", server)
        span.set_attribute("mcp_warden.tool", tool)
        span.set_attribute("mcp_warden.effect", decision.effect)
        span.set_attribute("mcp_warden.rule_ids", ",".join(decision.rule_ids))
