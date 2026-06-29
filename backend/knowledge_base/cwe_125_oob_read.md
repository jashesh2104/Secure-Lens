# CWE-125 — Out-of-bounds Read

CWE ID: CWE-125
OWASP: A04:2021 Insecure Design

## Description
The product reads memory before/after the bounds of a buffer, leaking data or crashing.

## How it appears in code
Indexing past array length; reading a length field from input without validating it.

## Exploit scenario
A crafted length causes the server to return adjacent memory, leaking keys/sessions (e.g., Heartbleed-style).

## Fix
Validate indices/lengths against actual sizes; use safe APIs; reject malformed input.
