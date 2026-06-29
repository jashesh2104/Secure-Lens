# CWE-416 — Use After Free

CWE ID: CWE-416
OWASP: A04:2021 Insecure Design

## Description
The product uses memory after it has been freed, causing crashes, data corruption, or code execution.

## How it appears in code
Dereferencing a pointer after `free`; keeping references to released objects in C/C++.

## Exploit scenario
An attacker reclaims the freed region with controlled data; the dangling use redirects control flow to attacker code.

## Fix
Null pointers after free; use smart pointers/RAII; enable sanitizers; prefer memory-safe languages where feasible.
