# A09:2021 — Security Logging and Monitoring Failures

OWASP ID: A09:2021
Related CWE: CWE-778, CWE-117, CWE-223

## Description
Insufficient logging, monitoring, and alerting lets breaches go undetected. Without records you cannot detect, respond to, or investigate attacks.

## How it appears in code
- Auth events, failures, and high-value actions not logged.
- Logs without integrity, or stored only locally.
- No alerting thresholds; logging sensitive data in cleartext.

## Exploit scenario
An attacker brute-forces accounts over days; nothing alerts because failures aren't logged, so the breach is found only after data leaks publicly.

## Fix
Log auth and access-control events with context; centralize and protect logs; alert on suspicious patterns; ensure logs are tamper-evident; avoid logging secrets.
