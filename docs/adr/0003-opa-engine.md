# 0003 — OPA decision API

- Status: accepted
- Date: 2026-10-01

## Context

The optional engine has to POST a `DecisionRequest` and turn the reply into a `Decision`. OPA's Data API does not return the Rego document by itself; it wraps it.

## Options considered

1. Treat any JSON object with `allow` as a decision.
2. Require the Data API envelope `{"result": {"allow", "rule_ids", "reason", "obligations"}}` at `{url}/v1/data/{package}`.

## Decision

Use the Data API envelope. Package names may use slashes or dots; dots become slashes. Missing, malformed, or unreachable replies are DENY `policy_engine_error`, and the request arguments are not logged. Obligations are parsed and then merged with the same type order as the native engine. Tests mock the HTTP server, which is what SPEC.md §9.3 requires. `policies/example.rego` is the Rego form of the YAML example and is loaded by the OPA sidecar in `docker-compose.yml`.

## Consequences

A Rego document that does not define those four names will fail closed. The example policy is not executed inside the unit tests.
