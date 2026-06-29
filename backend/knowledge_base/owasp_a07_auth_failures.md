# A07:2021 — Identification and Authentication Failures

OWASP ID: A07:2021
Related CWE: CWE-287, CWE-384, CWE-307

## Description
Weaknesses in confirming user identity, authentication, and session management. Allows credential stuffing, brute force, and session hijacking.

## How it appears in code
- No rate limiting on login; weak password policy.
- Session IDs in URLs; not rotated after login; no timeout.
- Storing passwords with weak hashing; no MFA option.

## Exploit scenario
With no lockout, an attacker runs credential stuffing against the login endpoint using leaked password lists and takes over accounts.

## Fix
Enforce MFA where possible; rate-limit and lock out repeated failures; rotate and invalidate sessions; store passwords with bcrypt/argon2; avoid session IDs in URLs.
