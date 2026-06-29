# CWE-787 — Out-of-bounds Write

CWE ID: CWE-787
OWASP: A04:2021 Insecure Design

## Description
The product writes past the end (or before the start) of a buffer, corrupting memory. Consistently #1 on the CWE Top 25.

## How it appears in code
`memcpy`/array writes without bounds checks; off-by-one loops; unchecked indices in C/C++.

## Exploit scenario
A crafted oversized input overflows a stack buffer, overwrites a return address, and executes attacker code.

## Fix
Bounds-check all writes; use safe string/memory APIs; enable compiler/OS mitigations; prefer memory-safe languages where possible.
