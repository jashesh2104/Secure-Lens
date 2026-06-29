# CWE-798 — Use of Hard-coded Credentials

CWE ID: CWE-798
OWASP: A07:2021 Identification and Authentication Failures

## Description
Credentials (passwords, API keys, tokens) embedded in source or config. Anyone with the code gets access; secrets cannot be rotated without a release.

## How it appears in code
`PASSWORD = "p@ss"`, `AWS_SECRET = "AKIA..."`, tokens committed to git history. This is exactly what Gitleaks detects.

## Exploit scenario
A public repo leaks an AWS key; attackers spin up resources and pivot into the account within minutes.

## Fix
Remove secrets from code; load from environment/secrets manager; rotate any exposed secret immediately; add secret scanning to CI; purge from git history.
