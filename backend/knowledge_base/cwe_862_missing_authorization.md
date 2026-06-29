# CWE-862 — Missing Authorization

CWE ID: CWE-862
OWASP: A01:2021 Broken Access Control

## Description
The product does not perform an authorization check when a user attempts a restricted action, so anyone authenticated (or not) can perform it.

## How it appears in code
An endpoint that authenticates but never checks role/ownership before acting.

## Exploit scenario
A regular user calls `/admin/deleteUser` and it succeeds because only login, not role, was checked.

## Fix
Enforce authorization on every restricted action; deny by default; centralize role/ownership checks; test for missing checks.
