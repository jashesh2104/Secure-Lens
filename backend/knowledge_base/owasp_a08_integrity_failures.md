# A08:2021 — Software and Data Integrity Failures

OWASP ID: A08:2021
Related CWE: CWE-502, CWE-345, CWE-494

## Description
Code and infrastructure that fail to protect against integrity violations: insecure deserialization, unsigned updates, and untrusted CI/CD pipelines. New in 2021.

## How it appears in code
- Deserializing attacker-controlled objects (pickle, Java serialization).
- Pulling dependencies/updates without signature or integrity checks.
- CI/CD that runs untrusted code or lacks artifact verification.

## Exploit scenario
An app deserializes a user-supplied object; the attacker crafts a payload that executes code during deserialization, achieving RCE.

## Fix
Never deserialize untrusted data; use signed updates and integrity checks; verify dependencies; secure the CI/CD pipeline and review changes.
