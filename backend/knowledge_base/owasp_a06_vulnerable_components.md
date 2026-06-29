# A06:2021 — Vulnerable and Outdated Components

OWASP ID: A06:2021
Related CWE: CWE-1104

## Description
Using components (libraries, frameworks, runtimes) with known vulnerabilities, or that are unsupported/out of date. You inherit every flaw of the dependencies you ship.

## How it appears in code
- Pinned dependencies with known CVEs, never updated.
- No inventory (SBOM) of what is in use.
- Transitive dependencies not tracked.

## Exploit scenario
An app ships a logging library with a known remote-code-execution CVE; an attacker triggers it with a crafted input and runs code on the server.

## Fix
Maintain an inventory/SBOM; remove unused deps; track CVEs and update promptly; only obtain components from trusted sources; monitor advisories.
