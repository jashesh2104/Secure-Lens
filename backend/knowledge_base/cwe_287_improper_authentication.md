# CWE-287 — Improper Authentication

CWE ID: CWE-287
OWASP: A07:2021 Identification and Authentication Failures

## Description
The product does not, or incorrectly, proves that a claimed identity is correct, allowing attackers to authenticate as others.

## How it appears in code
Comparing passwords with `==` (timing), trusting client-set role flags, skipping verification on a branch, broken token validation.

## Exploit scenario
A JWT is accepted without signature verification; an attacker forges a token claiming admin and gains full access.

## Fix
Verify tokens/signatures; constant-time secret comparison; enforce auth on every protected path; use vetted auth libraries; add MFA.
