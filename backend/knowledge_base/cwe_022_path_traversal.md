# CWE-22 — Path Traversal

CWE ID: CWE-22
OWASP: A01:2021 Broken Access Control

## Description
User input used to build a file path without neutralization, letting attackers reach files outside the intended directory via `../` sequences.

## How it appears in code
`open(base + request.filename)` where filename can contain `../`.

## Exploit scenario
`filename = "../../etc/passwd"` lets the attacker read arbitrary server files.

## Fix
Canonicalize and validate paths; reject `..`; confine to a base dir and verify the resolved path stays within it; use safe file APIs.
