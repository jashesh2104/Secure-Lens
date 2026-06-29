# CWE-434 — Unrestricted Upload of File with Dangerous Type

CWE ID: CWE-434
OWASP: A04:2021 Insecure Design

## Description
The product lets users upload files of dangerous types without validation, which can be executed or served maliciously.

## How it appears in code
Accepting any extension/content-type; storing uploads in a web-executable directory.

## Exploit scenario
An attacker uploads `shell.php`; the server executes it, yielding remote code execution.

## Fix
Allowlist types; verify content (magic bytes); store outside web root; randomize names; disable execution in upload dirs; scan files.
