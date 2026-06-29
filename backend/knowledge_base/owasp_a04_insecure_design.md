# A04:2021 — Insecure Design

OWASP ID: A04:2021
Related CWE: CWE-209, CWE-256, CWE-501, CWE-522

## Description
A new 2021 category about missing or ineffective security controls at the design level. You cannot fix a flawed design with a perfect implementation — threat modeling and secure design patterns must exist before coding.

## How it appears in code
- No rate limiting / lockout on auth or expensive endpoints.
- Business logic that trusts the client to enforce limits (e.g., price).
- Missing segregation of tenants or critical flows.

## Exploit scenario
A checkout flow trusts a client-supplied total, so an attacker buys items for $0.01 by editing the request.

## Fix
Threat-model early; establish secure design patterns and reference architectures; validate business rules server-side; limit resource consumption per user/role.
