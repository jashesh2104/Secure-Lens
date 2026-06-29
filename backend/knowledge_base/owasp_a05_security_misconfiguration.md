# A05:2021 — Security Misconfiguration

OWASP ID: A05:2021
Related CWE: CWE-16, CWE-611

## Description
Insecure defaults, incomplete configs, open cloud storage, verbose errors, or unnecessary features left enabled. Now includes XML External Entities (XXE).

## How it appears in code
- Debug mode on in production; stack traces returned to clients.
- Default admin credentials unchanged.
- Permissive S3 buckets / security groups.
- XML parsers with external entity resolution enabled.

## Exploit scenario
A verbose error page leaks DB connection strings; an attacker uses them to connect directly. An XXE payload reads `/etc/passwd` via an unhardened XML parser.

## Fix
Harden defaults; disable debug in prod; remove unused features; automate config checks; disable external entities in XML parsers; review cloud permissions.
