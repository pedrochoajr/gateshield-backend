# GateShield MVP Scope

## Product Definition
GateShield is a reverse-proxy API security gateway that protects REST endpoints by inspecting incoming requests, validating them against expected schemas and policy rules, assigning a risk score, and deciding whether to allow, flag, or block the request.

## MVP Goals
- Protect a demo REST API through a gateway
- Inspect requests before forwarding
- Apply simple rule-based threat detection
- Assign a risk score
- Allow, flag, or block traffic
- Log security events

## In Scope
- Reverse proxy request handling
- Request inspection
- Rule-based detection
- Event logging

## Out of Scope
- ML anomaly detection
- Enterprise IAM integrations
- Distributed scaling