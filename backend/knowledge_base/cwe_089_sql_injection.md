# CWE-89 — SQL Injection

CWE ID: CWE-89
OWASP: A03:2021 Injection

## Description
The product builds SQL from user input without neutralization, letting attackers alter the query. A perennial CWE Top 25 entry.

## How it appears in code
`cursor.execute("SELECT * FROM u WHERE name='" + name + "'")` — input becomes code.

## Exploit scenario
`name = "'; DROP TABLE u;--"` deletes the table; `' OR '1'='1` bypasses filters and dumps data.

## Fix
Use parameterized queries / prepared statements or an ORM; never concatenate input into SQL; apply least-privilege DB accounts.
