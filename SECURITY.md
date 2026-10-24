# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Rempart privately through GitHub's **Report a vulnerability** button (Security tab), not in a public issue. You will get an acknowledgement within 72 hours.

## What Rempart sends over the network, and when

| Command | Destination | What is sent |
|---|---|---|
| `scan` (default) | OSV.dev, FIRST EPSS, CISA KEV | package names and versions; CVE identifiers. No code, paths or secrets. |
| `scan --verify-secrets` | each credential's own provider (GitHub, Stripe, AWS STS…) | one read-only identity request authenticated **with the found credential**. Opt-in only, never from MCP; a warning is printed each time. **Only use it on repositories you own or are authorised to test**: using someone else's credential can be an offence. AWS keys are checked with `sts:GetCallerIdentity`, which is logged in the key owner's CloudTrail and trips **canarytokens** and **GuardDuty** alerts (that is their purpose). The credential travels in a header or a signed body, except where the provider accepts it nowhere else: `SEC-TELEGRAM-BOT` (token in the URL path of the Bot API) and `SEC-MAPBOX-SECRET` (`access_token` query parameter); for those two it may appear in access logs on the provider's side. |
| `image` | the image's registry | standard pull requests (manifest, config, layers). |
| `cloud aws` | AWS APIs of your account | read-only Describe/Get/List calls with your credentials. |
| `cloud gcp` / `cloud azure` | Google Cloud / Azure APIs, through your own `gcloud` / `az` | read-only list/describe/get-iam-policy commands with the identity the CLI is logged in as. |
| `scan --git-history` | nothing (local `git log`) | — ; with `--verify-secrets`, historical credentials are checked like current ones. |
| `scan --baseline REF` | nothing (local `git worktree`) | — ; the temporary worktree is removed after the scan. |
| `agent-eval` | Anthropic API | the bundled synthetic test repositories only, none of your code. |
| `k8s` | your cluster, through kubectl | read-only `get` of workloads, services and RBAC. Secrets are never requested. |
| MCP `rempart_web_audit` | the site the assistant names, **public addresses only** | as `web`, after resolving the host once, refusing any private, loopback, link-local, metadata or reserved address, and connecting to the checked address (DNS rebinding cannot redirect it); each redirect is checked again. MCP scans are confined to the `rempart mcp --root` directories. |
| `web` | the site you name | ordinary GET requests (page, `http://` variant, `/.well-known/security.txt`). No payloads. Only audit sites you own or are authorised to test. |
| `agent` | Anthropic API | **excerpts of your repository** (finding details, files and line ranges the agent chooses to read, search results), under your Anthropic account and its data-retention terms. Before anything is sent, secrets are **masked** with the secrets scanner's own detectors (every provider format, private-key blocks, JWTs, and any value assigned to a secret-looking name, quoted or not). Files that hold credentials by convention are never read nor searched, even when committed: `.env` and `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`, `*.ovpn`, `*.tfstate`, `*.tfvars`, `id_rsa`-style keys, `*credentials*`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.htpasswd`, `secrets.*`, `service-account*.json`. Do not run it on code you are not allowed to share with that provider. Proof tests it writes are saved locally and never executed. |
| `--offline` | nothing | — |

## Pull-request scans read their configuration from the target branch

With `--baseline REF` (and in the GitHub Action, input `trust-config: base` by default), `.rempart.toml` and `.rempart/knowledge.toml` are read from `REF` with `git show`, never from the change under review: a pull request cannot disable the rule that catches it or declare its own function a sanitiser. Any change to these files in the pull request is reported as `REMPART-CONFIG-CHANGED` (HIGH) for a person to review. `--trust-config head` trusts the scanned tree on purpose. Inline `rempart:ignore` comments added by a pull request still apply, as `nosemgrep` does for Semgrep: review them in the diff.

Scan history and triage verdicts stay in a local SQLite file (`REMPART_HOME`, default `~/.local/share/rempart`). Detected secret values are redacted before they are stored or printed.
