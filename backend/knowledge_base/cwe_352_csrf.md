# CWE-352 — Cross-Site Request Forgery (CSRF)

CWE ID: CWE-352
OWASP: A01:2021 Broken Access Control

## Description
The app cannot verify a request was intentionally sent by the user, so an attacker site can force authenticated state-changing requests.

## How it appears in code
State-changing endpoints relying only on cookies, with no anti-CSRF token or SameSite enforcement.

## Exploit scenario
A logged-in user visits a malicious page that auto-submits a form to `/transfer`, moving funds using the user's session.

## Fix
Use anti-CSRF tokens; set cookies `SameSite=Lax/Strict`; require re-auth for sensitive actions; verify Origin/Referer.
