# A01:2021 — Broken Access Control

OWASP ID: A01:2021
Related CWE: CWE-200, CWE-201, CWE-352

## Description
Access control enforces that users cannot act outside their intended permissions. Failures let attackers access other users' accounts, view sensitive files, modify data, or change access rights. It moved to #1 in the 2021 OWASP Top 10.

## How it appears in code
- Missing authorization checks on an API route or controller.
- Using object IDs from the request without verifying ownership (IDOR).
- Trusting client-side enforcement (hidden fields, disabled buttons).
- Permissive CORS allowing untrusted origins.

## Exploit scenario
An attacker changes `/account?id=123` to `id=124` and reads another user's data because the server never checks that the record belongs to the caller.

## Fix
Deny by default; enforce ownership/role checks server-side on every request; centralize access control; reject unless explicitly allowed.
