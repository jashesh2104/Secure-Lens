# A02:2021 — Cryptographic Failures

OWASP ID: A02:2021
Related CWE: CWE-259, CWE-327, CWE-331

## Description
Previously "Sensitive Data Exposure." Failures to protect data in transit and at rest: missing encryption, weak/old algorithms, bad key management, or weak randomness.

## How it appears in code
- Hardcoded keys or passwords in source.
- Using MD5/SHA1 for passwords instead of bcrypt/argon2.
- Disabling TLS verification or using HTTP for sensitive data.
- Predictable IVs, ECB mode, or `random` instead of a CSPRNG.

## Exploit scenario
Passwords stored as unsalted MD5 are dumped from a breached DB and cracked offline in minutes, exposing every account.

## Fix
Encrypt data in transit (TLS) and at rest; use strong, current algorithms; salt+hash passwords with bcrypt/argon2; manage keys in a vault; use a CSPRNG.
