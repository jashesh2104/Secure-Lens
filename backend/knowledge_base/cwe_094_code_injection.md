# CWE-94 — Code Injection

CWE ID: CWE-94
OWASP: A03:2021 Injection

## Description
The product constructs code from user input and evaluates it, letting attackers run arbitrary code in the app's context.

## How it appears in code
`eval(user_input)`, `exec(...)`, dynamic `import`, or template engines that evaluate expressions.

## Exploit scenario
A calculator passes input to `eval`; an attacker sends `__import__('os').system('...')` for RCE.

## Fix
Never eval/exec untrusted input; use safe parsers (e.g., `ast.literal_eval`); sandbox or remove dynamic evaluation entirely.
