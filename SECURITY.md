# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Rempart privately through GitHub's **Report a vulnerability** button (Security tab), not in a public issue. You will get an acknowledgement within 72 hours.

## What Rempart sends over the network, and when

| Command | Destination | What is sent |
|---|---|---|
| `scan` (default) | OSV.dev, FIRST EPSS, CISA KEV | package names and versions; CVE identifiers. No code, paths or secrets. |
| `scan --verify-secrets` | each credential's own provider (GitHub, Stripe, AWS STS…) | one read-only identity request authenticated **with the found credential**. Only use it on repositories you own. |
| `image` | the image's registry | standard pull requests (manifest, config, layers). |
| `cloud aws` | AWS APIs of your account | read-only Describe/Get/List calls with your credentials. |
| `k8s` | your cluster, through kubectl | read-only `get` of workloads, services and RBAC. Secrets are never requested. |
| `web` | the site you name | ordinary GET requests (page, `http://` variant, `/.well-known/security.txt`). No payloads. Only audit sites you own or are authorised to test. |
| `agent` | Anthropic API | **excerpts of your repository** (finding details, files and line ranges the agent chooses to read, search results), under your Anthropic account and its data-retention terms. Do not run it on code you are not allowed to share with that provider. |
| `--offline` | nothing | — |

Scan history and triage verdicts stay in a local SQLite file (`REMPART_HOME`, default `~/.local/share/rempart`). Detected secret values are redacted before they are stored or printed.
