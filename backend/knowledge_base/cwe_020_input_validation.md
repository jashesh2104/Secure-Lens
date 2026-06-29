# CWE-20 — Improper Input Validation

CWE ID: CWE-20
OWASP: A03:2021 Injection

## Description
The product does not validate, or incorrectly validates, input that affects control flow or data, enabling many downstream vulnerabilities.

## How it appears in code
Trusting length, type, range, or format of input; missing server-side validation; relying on client checks only.

## Exploit scenario
A negative quantity or oversized value bypasses business rules or triggers a buffer/logic flaw.

## Fix
Validate all input server-side against an allowlist (type, range, length, format); reject invalid early; canonicalize before checks.
