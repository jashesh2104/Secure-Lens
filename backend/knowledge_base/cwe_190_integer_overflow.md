# CWE-190 — Integer Overflow or Wraparound

CWE ID: CWE-190
OWASP: A04:2021 Insecure Design

## Description
An arithmetic operation produces a value that exceeds the type's range and wraps, leading to undersized allocations, bypassed checks, or memory corruption.

## How it appears in code
`size = a * b` used for allocation; length checks performed after an overflowing add.

## Exploit scenario
A length that overflows allocates a tiny buffer; the subsequent write overflows it, enabling corruption or RCE.

## Fix
Use checked/wide arithmetic; validate ranges before math; rely on safe allocation APIs; reject implausible sizes.
