# MCP Warden — Policy-enforcing gateway between AI agents and MCP servers

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/ci.yml)

> **Status:** under construction. The design and build plan are in [SPEC.md](SPEC.md).

## Why

Enterprises adopting MCP need the same controls they already have for APIs: least privilege per agent, data-classification-aware responses, and an audit trail. Putting those controls in each MCP server duplicates effort and the rules drift. MCP Warden is the gateway that centralises authentication, policy, obligations, and audit for the teams operating those agents.

## Audit

The JSONL log is tamper-evident, not tamper-proof. Anyone who can rewrite the file can rebuild the hash chain. Every `audit.anchor_every` records (default 100), Warden prints the latest hash to stdout so another system can keep a copy.

## Quickstart

Planned for Phase 6: one command that starts Warden with the included fixture upstreams on a fresh machine.

The audit log is tamper-evident, not tamper-proof. Anyone who can rewrite the file can rebuild the hash chain. Every `audit.anchor_every` records (default 100), Warden writes the latest hash to stdout so an external system can notice a rewritten chain.

## Licence

Apache-2.0
