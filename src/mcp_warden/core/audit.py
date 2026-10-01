"""Tamper-evident audit chain.

Hash is SHA-256 of the canonical JSON of the record with the ``hash`` field
removed. Canonical JSON uses sorted keys, ``(",", ":")`` separators, and UTF-8.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

GENESIS_HASH = "0" * 64


def utc_timestamp() -> str:
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def verify_log(text: str) -> int | None:
    """Return the first broken sequence number, or None when the chain is valid."""
    previous = GENESIS_HASH
    expected = 1
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
        except json.JSONDecodeError:
            return expected
        if not isinstance(loaded, dict):
            return expected
        seq = loaded.get("seq")
        reported = seq if isinstance(seq, int) else expected
        if seq != expected or loaded.get("prev_hash") != previous:
            return reported
        if loaded.get("hash") != record_hash(loaded):
            return reported
        digest = loaded.get("hash")
        if not isinstance(digest, str):
            return reported
        previous = digest
        expected += 1
    return None
