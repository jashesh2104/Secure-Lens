# CWE-918 — Server-Side Request Forgery (SSRF)

CWE ID: CWE-918
OWASP: A10:2021 SSRF

## Description
The server fetches a URL supplied or influenced by the user without validation, enabling requests to internal or unintended systems.

## How it appears in code
`requests.get(url)` where url comes from the request and is not allowlisted.

## Exploit scenario
Attacker targets cloud metadata `http://169.254.169.254/` to steal instance credentials.

## Fix
Allowlist schemes/hosts; block private/link-local IP ranges; disable internal redirects; isolate egress; deny by default.
