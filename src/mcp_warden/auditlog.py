"""Single-writer audit log.

One task assigns ``seq`` and ``prev_hash`` so concurrent requests cannot fork
the chain. Every ``anchor_every`` records, the latest hash is emitted to a sink
(stdout in v0.1).
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from mcp_warden.core.audit import GENESIS_HASH, canonical_json, record_hash

_Item = tuple[dict[str, Any], asyncio.Future[None]]


class AnchorSink(Protocol):
    def emit(self, record_hash: str) -> None: ...


class StdoutAnchorSink:
    def emit(self, record_hash: str) -> None:
        sys.stdout.write(f"{record_hash}\n")
        sys.stdout.flush()


class AuditError(Exception):
    """The audit log cannot be read or extended."""


class AuditWriter:
    def __init__(
        self,
        path: Path,
        *,
        anchor_every: int,
        sink: AnchorSink,
        store_masked_arguments: bool,
    ) -> None:
        if anchor_every < 1:
            raise AuditError("anchor_every must be at least 1")
        self.path = path
        self.anchor_every = anchor_every
        self.sink = sink
        self.store_masked_arguments = store_masked_arguments
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = _resume(self.path)
        self._queue: asyncio.Queue[_Item | None] | None = None
        self._task: asyncio.Task[None] | None = None
        self._closed = False

    async def append(self, fields: Mapping[str, Any]) -> None:
        if self._closed:
            raise AuditError("audit writer is closed")
        queue = self._ensure_started()
        loop = asyncio.get_running_loop()
        done: asyncio.Future[None] = loop.create_future()
        await queue.put((dict(fields), done))
        await done

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._queue is None or self._task is None:
            return
        await self._queue.put(None)
        await self._task

    def _ensure_started(self) -> asyncio.Queue[_Item | None]:
        if self._queue is None or self._task is None:
            self._queue = asyncio.Queue()
            self._task = asyncio.create_task(self._run(self._queue))
        return self._queue

    async def _run(self, queue: asyncio.Queue[_Item | None]) -> None:
        while True:
            item = await queue.get()
            if item is None:
                return
            fields, done = item
            try:
                self._seq += 1
                record = dict(fields)
                record["seq"] = self._seq
                record["prev_hash"] = self._prev
                record["hash"] = record_hash(record)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(canonical_json(record) + "\n")
                    handle.flush()
                self._prev = str(record["hash"])
                if self._seq % self.anchor_every == 0:
                    self.sink.emit(self._prev)
            except Exception as exc:
                if not done.done():
                    done.set_exception(exc)
                continue
            if not done.done():
                done.set_result(None)


def _resume(path: Path) -> tuple[int, str]:
    if not path.exists() or path.stat().st_size == 0:
        return 0, GENESIS_HASH
    last = ""
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                last = line
    try:
        loaded = json.loads(last)
    except json.JSONDecodeError as exc:
        raise AuditError("audit log is not valid JSON Lines") from exc
    if not isinstance(loaded, dict):
        raise AuditError("audit log is not valid JSON Lines")
    seq = loaded.get("seq")
    digest = loaded.get("hash")
    if not isinstance(seq, int) or not isinstance(digest, str):
        raise AuditError("audit log is missing seq or hash")
    return seq, digest
