# CWE-476 — NULL Pointer Dereference

CWE ID: CWE-476
OWASP: A04:2021 Insecure Design

## Description
The product dereferences a pointer it expects to be valid but is NULL, typically causing a crash (DoS).

## How it appears in code
Using a return value without checking for null; assuming a lookup always succeeds.

## Exploit scenario
An input that forces a null result crashes the service repeatedly, denying availability.

## Fix
Check returns for null before use; fail safely; use options/optionals; add defensive guards at boundaries.
