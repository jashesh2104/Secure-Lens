# CWE-306 — Missing Authentication for Critical Function

CWE ID: CWE-306
OWASP: A07:2021 Identification and Authentication Failures

## Description
A critical function does not require authentication, exposing it to anyone who can reach it.

## How it appears in code
Admin/debug/management endpoints registered without an auth guard; internal APIs exposed publicly.

## Exploit scenario
An unauthenticated `/actuator/shutdown` or debug console lets anyone disrupt or control the service.

## Fix
Require authentication on all sensitive functions; remove debug endpoints in prod; segment internal services; deny by default.
