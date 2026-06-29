# A10:2021 — Server-Side Request Forgery (SSRF)

OWASP ID: A10:2021
Related CWE: CWE-918

## Description
SSRF occurs when an app fetches a remote resource using a user-supplied URL without validating it, letting attackers force the server to make requests to unintended destinations — including internal services.

## How it appears in code
- `requests.get(user_supplied_url)` with no allowlist.
- Image/PDF fetchers, webhooks, or URL previews using raw input.

## Exploit scenario
An attacker submits `http://169.254.169.254/latest/meta-data/` so the server returns cloud instance metadata and credentials.

## Fix
Allowlist destination hosts/schemes; block private/link-local ranges; disable redirects to internal addresses; segment networks; deny by default.
