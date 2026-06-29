# A03:2021 — Injection

OWASP ID: A03:2021
Related CWE: CWE-79, CWE-89, CWE-78

## Description
Untrusted data is sent to an interpreter as part of a command or query. Includes SQL, NoSQL, OS command, and LDAP injection, plus Cross-Site Scripting (XSS).

## How it appears in code
- String-concatenated SQL: `"SELECT * FROM users WHERE id=" + req.id`.
- `os.system(f"ping {host}")` with user input.
- Rendering raw user input into HTML without encoding.

## Exploit scenario
A login form field `' OR '1'='1` turns the query into one that always matches, bypassing authentication and dumping the users table.

## Fix
Use parameterized queries / prepared statements; validate and allowlist input; escape output for the target context; avoid shelling out — use safe APIs with argument lists, never a shell string.
