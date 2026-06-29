# CWE-78 — OS Command Injection

CWE ID: CWE-78
OWASP: A03:2021 Injection

## Description
The product builds an OS command from user input without neutralization, allowing arbitrary command execution.

## How it appears in code
`os.system(f"ping {host}")`, `subprocess.run(cmd, shell=True)` with user input in the string.

## Exploit scenario
`host = "8.8.8.8; rm -rf /"` runs the injected command with the server's privileges.

## Fix
Avoid shells; call programs with an argument list (no `shell=True`); allowlist inputs; never pass raw input to a shell.
