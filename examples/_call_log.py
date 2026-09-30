"""Append fixture tool calls to the file named by FIXTURE_CALL_LOG."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any


def record_call(tool: str, arguments: Mapping[str, Any]) -> None:
    path = os.environ.get("FIXTURE_CALL_LOG")
    if not path:
        return
    line = json.dumps(
        {"arguments": dict(arguments), "tool": tool}, sort_keys=True, separators=(",", ":")
    )
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
