# CWE-77 — Command Injection

CWE ID: CWE-77
OWASP: A03:2021 Injection

## Description
User input alters which commands are executed in an interpreter (broader than OS command injection; includes app/DSL commands).

## How it appears in code
Concatenating input into any command string later parsed by an interpreter.

## Exploit scenario
A separator character injects an extra command the developer never intended to expose.

## Fix
Use structured APIs; separate data from commands; validate against an allowlist; avoid dynamic command construction.
