# 0002 — Single-task audit writer

- Status: accepted
- Date: 2026-10-01

## Context

Every `tools/list` and `tools/call` must append exactly one hash-chained record. Concurrent requests have to share one `seq` and `prev_hash` without forking the chain.

## Options considered

1. A lock around a synchronous append — simple, but the spec asks for one async writer task.
2. One asyncio task that owns the file and assigns `seq` — matches the spec and keeps hashing off the request tasks.

## Decision

`AuditWriter` is the only writer. Request handlers enqueue a record and wait until that record is on disk. The task sets `seq`, `prev_hash`, and `hash`, appends canonical JSON, and emits the latest hash to an `AnchorSink` every `anchor_every` records. The default sink writes the hash to stdout. When `store_masked_arguments` is true, the call record includes `masked_arguments` (PII-masked) in addition to `arguments_sha256`. A strip that does not apply is recorded as `obligations_not_applicable`. The first record uses 64 zero hex digits as `prev_hash`. `verify-log` prints `OK` or `seq N`.

## Consequences

Restart continues from the last complete line. The chain is tamper-evident only: a writer who rewrites the file can rebuild it, which is why hashes are anchored. List records store `visible_tools` and `hidden_tools` counts and omit tool, argument, and response fields.
