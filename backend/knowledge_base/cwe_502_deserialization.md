# CWE-502 — Deserialization of Untrusted Data

CWE ID: CWE-502
OWASP: A08:2021 Software and Data Integrity Failures

## Description
Deserializing data from an untrusted source without validation can instantiate dangerous objects or trigger code execution.

## How it appears in code
`pickle.loads(request.body)`, Java `ObjectInputStream`, YAML `load` without SafeLoader.

## Exploit scenario
A crafted serialized object runs code during deserialization, giving the attacker RCE.

## Fix
Avoid native deserialization of untrusted input; use data-only formats (JSON) with schema validation; if unavoidable, sign and verify, restrict allowed types.
