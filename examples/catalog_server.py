"""Catalog fixture: read-only profiling and search tools."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from examples._call_log import record_call

PROFILE_EMAIL = "ada@finance.example"

mcp = FastMCP("catalog")


def column_profile(column_id: str) -> dict[str, Any]:
    """Level 2 epistemic envelope with one profiled email and one AI inference."""
    return {
        "envelope_version": "0.1",
        "subject": {"type": "column", "id": column_id, "name": "email"},
        "attributes": {"data_type": "varchar", "table": "customers"},
        "inference_permitted": True,
        "governance_notice": "AI-generated content is unverified and not certified.",
        "certified_findings": [
            {
                "id": "cf-1",
                "statement": "Email format rule passed",
                "rule_id": "DQ-17",
                "result": "pass",
                "value": 0.998,
                "certified_by": "steward_a",
                "certified_at": "2026-09-20T00:00:00Z",
                "evidence_uri": None,
            }
        ],
        "profiling_observations": [
            {
                "id": "po-1",
                "metric": "sample_value",
                "value": PROFILE_EMAIL,
                "unit": "string",
                "observed_at": "2026-09-20T00:00:00Z",
                "profile_run_id": "pr_9",
            }
        ],
        "ai_inferences": [
            {
                "id": "ai-1",
                "kind": "classification",
                "statement": "Likely contains personal email addresses",
                "reported_confidence": 0.9,
                "model": "provider/model-id",
                "generated_at": "2026-09-20T00:00:00Z",
                "basis": ["po-1"],
                "review_status": "unreviewed",
            }
        ],
        "curated_metadata": [],
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_column_profile(column_id: str) -> dict[str, Any]:
    """Return a Level 2 profile envelope for a catalog column."""
    record_call("get_column_profile", {"column_id": column_id})
    return column_profile(column_id)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def search_assets(query: str) -> dict[str, Any]:
    """Return 120 catalog assets matching the query."""
    record_call("search_assets", {"query": query})
    return {"results": [{"id": f"asset-{index}", "name": f"asset-{index}"} for index in range(120)]}


if __name__ == "__main__":
    mcp.run(transport="stdio", show_banner=False)
