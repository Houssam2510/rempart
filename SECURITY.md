# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Rempart privately through GitHub's **Report a vulnerability** button (Security tab), not in a public issue. You will get an acknowledgement within 72 hours.

## What Rempart does with your data

- It reads files in the directory you scan. Detected secret values are redacted before they are stored or printed.
- With network access, it sends **package names and versions** to OSV.dev and **CVE identifiers** to FIRST EPSS, and downloads the CISA KEV catalog. No source code, file paths or secrets are sent.
- `rempart web` sends ordinary GET requests to the site you name: the page, its `http://` variant and `/.well-known/security.txt`. It sends no payloads. Only audit sites you own or are authorised to test.
- Scan history and triage verdicts stay in a local SQLite file (`REMPART_HOME`, default `~/.local/share/rempart`).
