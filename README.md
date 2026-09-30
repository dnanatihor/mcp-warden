# MCP Warden — Policy-enforcing gateway between AI agents and MCP servers

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/ci.yml)

> **Status:** under construction. The design and build plan are in [SPEC.md](SPEC.md).

## Why

Enterprises adopting MCP need the same controls they already have for APIs: least privilege per agent, data-classification-aware responses, and an audit trail. Putting those controls in each MCP server duplicates effort and the rules drift. MCP Warden is the gateway that centralises authentication, policy, obligations, and audit for the teams operating those agents.

## Quickstart

Planned for Phase 6: one command that starts Warden with the included fixture upstreams on a fresh machine.

## Licence

Apache-2.0
