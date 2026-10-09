# Rempart

**A security scanner that thinks in attack paths. One tool covers your code, dependencies, container images, live AWS account and Kubernetes cluster, data stores, CI/CD pipelines and AI agents. It verifies what it finds, an AI agent reads the code to confirm or reject each finding, and it learns from your triage.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-77%20passing-brightgreen)](tests)
[![Rules](https://img.shields.io/badge/rules-268-7c5cff)](docs/RULES.md)
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-2025-black)](docs/THREAT_CATALOG.md)
[![MCP](https://img.shields.io/badge/MCP-server-orange)](#use-it-from-any-ai-coding-assistant-mcp)

*Rempart* is French for *rampart*: the wall you build before anyone attacks.

---

## Why

A modern app is not one attack surface but eight. There is the code and its hundreds of npm packages, the container image it ships in, the Terraform and the live AWS account it runs on, and the Kubernetes cluster. There is also the GitHub workflow that deploys it, the Supabase or MongoDB that holds its users, and now the MCP servers and LLM calls wired into it. Each has its own scanner, report format and flood of "HIGH" findings, so solo developers and small teams run none of them.

Real incidents are also **chains**, not single findings. An SSRF is "high" and IMDSv1 is "high". SSRF *plus* IMDSv1 on the same deployment is how the 2019 Capital One breach reached 100 million records.

Rempart answers four questions in one pass:

1. **What is exploitable, and how?** Findings from every source are correlated into **attack paths** (9 chain patterns), each naming every link and the cheapest one to break.
2. **Is it real?** Every finding states *how* it was established: pattern match, data flow, imported dependency, live observation, live-verified secret, or AI review of the code.
3. **What matters first?** Dependency and OS-package CVEs come from OSV.dev and are ranked by exploitation evidence. CISA KEV marks confirmed in-the-wild use and FIRST EPSS gives the predicted probability.
4. **Is it getting better?** Scans are recorded locally, and triage verdicts recalibrate every rule.

## Quick start

```bash
pipx install "rempart[all] @ git+https://github.com/Houssam2510/rempart"   # [aws] boto3, [ai] Anthropic SDK

rempart scan .                                   # code, secrets, deps, IaC, CI/CD, data, AI configs
rempart scan . --aws --image myorg/api:latest    # + live AWS account + container image, correlated together
rempart image python:3.9-slim                    # any registry image or docker-save tar, no Docker needed
rempart cloud aws --profile prod                 # live read-only AWS audit (SecurityAudit policy is enough)
rempart k8s --context prod                       # live cluster audit through kubectl (never reads Secrets)
rempart web https://your-site.example            # passive audit of a site you own
rempart agent .                                  # an AI agent verifies each high-risk finding by reading the code
rempart scan examples/vulnerable-app --offline   # see every domain fire on the demo app
```

The core needs only Python 3.11 and PyYAML. boto3 and the Anthropic SDK are optional extras.

## What a scan looks like

```
$ rempart scan examples/vulnerable-app --offline --limit 4
  Posture score 1/100  grade F
  17 critical  15 high  17 medium  10 low  1 info

■ attack-path (5)
   CRIT  Code execution would escape the container to the host  api/app.py:14
         Links → code execution: CODE-CMD-INJECTION at api/app.py:14 (+1 more)
               | container isolation disabled: K8S-PRIVILEGED at k8s/deployment.yaml:13 (+2 more)
   CRIT  SSRF can reach instance metadata credentials  api/app.py:31
         Links → request forgery: CODE-SSRF at api/app.py:31 | metadata v1 reachable: TF-EC2-IMDSV1 at infra/main.tf:26
   CRIT  Internet-reachable data store with weak protection  infra/main.tf:5
         Links → reachable from the internet: TF-NET-DATA-PORT-OPEN at infra/main.tf:5 (+2 more)
               | weak authentication or encryption: DATA-MONGODB-EXPOSED at docker-compose.yml:4 (+1 more)
```

Dependency and image findings carry exploitation evidence and reachability (real output):

```
CRITICAL  react-server-dom-webpack@19.0.0: CVE-2025-55182 — React Server Components are Vulnerable to RCE
          — fixed in 19.0.1, 19.1.2, 19.2.1 — exploited in the wild (CISA KEV) — transitive, not imported directly
HIGH      lodash@4.17.15: CVE-2021-23337 — Command Injection in lodash — fixed in 4.17.21 — EPSS 21% — imported by your code
HIGH      python 3.9.25 reached end-of-life on 2025-10-31.          (rempart image python:3.9-slim)
```

## How it is intelligent

| Capability | What it does |
|---|---|
| **Attack-path correlation** | Nine chain patterns join findings across domains: SSRF → IMDSv1 credentials, exposed data store × weak auth, PR-controlled CI × publish credentials (TanStack 2026), RCE × privileged container, missing RLS × public client key, debug server × public bind, XSS × script-readable tokens, admin IAM × credential leak, install-time code × publish token (Shai-Hulud). Live AWS findings take part too. |
| **Data flow** | Python is analysed on its AST with per-function taint: values from `request.*` or FastAPI route parameters, and strings built by interpolation, are followed through assignments to SQL, shell, HTTP, file, redirect and regex sinks. JS/TS tracks variables from `req.*`, `request.json()`, `searchParams`, and destructuring. |
| **Reachability** | Each vulnerable dependency is classified *imported by your code*, *declared but not imported*, or *transitive and not imported*, and confidence follows. |
| **Live verification** | `--verify-secrets` asks each provider's read-only identity endpoint (GitHub `/user`, Stripe `/v1/account`, AWS STS `GetCallerIdentity` signed with a stdlib SigV4 implementation tested against botocore…) whether a leaked key still works. Live means CRITICAL. Revoked means LOW, purge the history. |
| **AI verification agent** | `rempart agent` gives an LLM read-only tools over the repository. It confirms or rejects each finding with file:line evidence and proposes minimal fixes as a patch. |
| **Learning loop** | Your verdicts update a Beta-Bernoulli precision per rule, shared across projects. AI verdicts count half and can never close a finding. Only a human can. |

Every finding carries its **verification level**: `static` · `reachable` · `declared` · `not-imported` · `observed` (live AWS / cluster / image / site) · `live-secret` · `revoked-secret` · `correlated` · `ai-confirmed` · `ai-rejected` · `ai-uncertain`.

## What it covers

| Domain | Examples | Frameworks |
|---|---|---|
| **Code (SAST)** | Injection (SQL, NoSQL, OS command, code, template), XSS sinks, SSRF, path traversal, open redirect, deserialization, JWT `none`, weak crypto, mass assignment, CORS with credentials, uploads, ReDoS, Trojan Source, IDOR review queue. Python AST + JS/TS/Svelte/Vue, Go, Java/Kotlin, PHP, Ruby, C#, C/C++ | OWASP A01–A10:2025, CWE Top 25 2025 |
| **Secrets** | 25 provider token formats, private keys, entropy-filtered generic secrets, committed `.env`/key files. Optional live verification for 13 providers | CWE-798 |
| **Dependencies & supply chain** | 12 lockfile formats → OSV + KEV + EPSS, malicious releases, install scripts, typosquats, dependency confusion, unpinned/HTTP sources | A03:2025, CICD-SEC-3 |
| **Container images** | Registry pull without Docker (Docker Hub, GHCR, OCI), whiteout-aware layer merge, dpkg (incl. distroless) and apk packages via OSV Debian/Ubuntu/Alpine, Python and npm packages inside the image, EOL OS and runtimes, secrets in files/ENV/history, root user, age | A03/A06:2025 |
| **Live AWS** | 28 read-only checks: root MFA/keys, password policy, credential report (MFA, key age, unused), `*:*` policies, admin users, S3 public access and TLS enforcement, open security groups (IPv4/IPv6), IMDSv1, EBS default encryption, public snapshots/AMIs, flow logs, RDS exposure/encryption/backups, CloudTrail, GuardDuty, Config, KMS rotation, Lambda URLs and runtimes, EKS endpoints, Access Analyzer | CIS AWS Foundations |
| **Kubernetes** | Manifests and live clusters: privileged pods, host namespaces, hostPath, capabilities, RBAC wildcards and escalation verbs, cluster-admin bindings, exposed data services | OWASP K8s Top 10 (2025), Pod Security Standards |
| **IaC** | Terraform for AWS, GCP and Azure (incl. `jsonencode()` policies): public storage, open ports, wildcard IAM, IMDSv1, encryption, public DBs, TLS, audit trails, state committed | CIS, A02/A04:2025 |
| **CI/CD** | Pwn requests, script injection, unpinned actions, cache poisoning, OIDC on untrusted triggers, secrets echoed, long-lived publish tokens | OWASP CICD-SEC-1…10 |
| **Data** | Credentials in connection strings, DB without TLS, exposed MongoDB/Redis/Postgres/MySQL/Elasticsearch, Supabase RLS, Firebase rules, Atlas 0.0.0.0/0, SQL grants, PII and cards committed, sensitive logging | Québec Law 25, PIPEDA, GDPR, PCI DSS |
| **AI & agents** | Unpinned MCP servers, secrets in MCP configs, broad shell/filesystem servers, invisible Unicode in `AGENTS.md`/rules files, LLM output to `eval`/HTML/SQL, shell-executing agent tools, prompts built from user input | OWASP LLM 2025, Agentic 2026 |
| **Quality & performance** | Fail-open authorization, swallowed exceptions, N+1 queries, missing timeouts, unbounded queries, blocking I/O, complexity | A10:2025, CWE-400/770 |
| **Web (passive)** | HTTPS, HSTS, CSP, framing, cookies, CORS, banners, legacy TLS, certificate expiry, `security.txt`, warm/cold TTFB | A02/A04/A07:2025 |

The research behind every rule, with the 2025-2026 incidents that motivated it and an honest list of what static analysis cannot see, is in **[docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md)**. All rules: [docs/RULES.md](docs/RULES.md).

## The AI verification agent

```bash
export ANTHROPIC_API_KEY=...            # or an `ant auth login` profile
rempart agent . --max-findings 15       # report: rempart-agent-report.md, fixes: rempart-fixes.patch
rempart agent . --apply                 # also write the proposed fixes (review with git diff)
```

Static rules cannot read intent. Is that `eval` fed by a constant table? Is that IDOR candidate guarded by middleware three files away? The agent answers those questions the way a reviewer would. It uses the newest Opus-tier model available to your Anthropic API key, or the one you set with `--model` / `REMPART_MODEL`. Its tools are `list_findings`, `get_finding`, `read_file`, `search_code`, `record_verdict` and `propose_fix`. Each verdict cites file:line evidence. Each fix is an exact search-and-replace rendered as a unified diff.

Safety by construction:

- It can only read files the scan discovered. Path escapes are refused, and there is no tool to execute code, reach the network or write.
- Repository content is treated as untrusted data, a defence against prompt injection planted in comments or READMEs.
- The loop is bounded (turns, findings). Server-side refusal fallback keeps one declined request from aborting the run.
- AI verdicts lower or raise confidence but never delete a finding. They count half in the learning loop and never override a human verdict.

The agent is tested against the real Anthropic Python SDK with a mocked HTTP transport. The tests assert the exact request bodies: model, strict tool schemas, fallback header, append-only history, and a tool result for every tool call.

## Use it from any AI coding assistant (MCP)

Rempart is also a Model Context Protocol server, so a coding agent can scan, inspect and triage while it writes code:

```json
{ "mcpServers": { "rempart": { "command": "rempart", "args": ["mcp"] } } }
```

The tools are `rempart_scan`, `rempart_finding`, `rempart_triage`, `rempart_web_audit`, `rempart_image_scan` and `rempart_rules`.

## Ranking and score

```
risk = severity_weight × (0.5 + confidence / 2)
if EPSS is known:      risk = max(risk, 0.6 × risk + 40 × EPSS)
if CVE is in CISA KEV: risk = max(risk, 95)
posture score = 100 × exp(−penalty / 120)   (repeats of one rule weigh 1, ½, ⅓…)
```

Distribution CVEs with no fix in your release that are over three years old are kept but ranked LOW, unless KEV-listed. That pattern marks issues the distribution judged disputed or minor.

## Learning loop

```bash
rempart triage 7d9771c7fb --fp --note "bounded regex"   # human verdicts close findings in this project
rempart learn                                           # learned precision per rule, across projects
rempart history                                         # score trend, new vs fixed, mean time to remediate
```

`precision = (TP + a) / (TP + FP + a + b)`, with the rule's declared confidence as the prior. Rules with ≥ 5 false positives and < 25 % precision drop one severity level. State lives in a local SQLite file (`REMPART_HOME`, default `~/.local/share/rempart`).

## In CI

SARIF 2.1.0 output lands in GitHub's Security tab:

```yaml
- uses: Houssam2510/rempart@<commit-sha>
  with: { fail-on: high }
- uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
  with: { sarif_file: rempart.sarif }
```

Other formats are `json`, `md` and `html` (a self-contained, filterable report). Configuration goes in `.rempart.toml` (exclude, disable, severity overrides, `fail_on`) or inline with `rempart:ignore[RULE-ID]`.

## Measured precision

Every false positive found by scanning real repositories became a regression test.

| Target | Result |
|---|---|
| A production SvelteKit SaaS (350 files, 426 npm packages) | All findings reviewed. Dogfooding removed false positives on a language cookie, escaped JSON-LD, bounded regexes and `RegExp.exec()`. It surfaced real advisories in transitive framework dependencies. |
| [cspm-lite](https://github.com/Houssam2510/cspm-lite) vulnerable AWS lab | 9 of 9 planted misconfigurations, plus 2 attack paths (admin IAM × IMDSv1, exposed data store). |
| `python:3.9-slim` (live pull, 6 s) | Debian 13, 64 packages, EOL Python runtime detected, OS CVEs ranked with fixed ones first. |
| AWS checks | All 28 validated against the official AWS service models with botocore's Stubber. Wrong operation or parameter names fail the build. |
| Rempart itself | Grade A. CI fails on any high finding. Self-scan found an f-string SQL query in the history module, rewritten with bound parameters. |

## Limits, stated plainly

- **Data flow is intra-procedural.** A value laundered across functions or files is missed. CodeQL and Semgrep Pro go deeper. Rempart trades depth for breadth and zero setup, and the agent covers part of the gap.
- **Attack paths come from co-occurrence, not a resource graph.** Links are findings that coexist in the same repository or account, so two links may concern different resources. Each chain names its links so you can check them. A resource-level graph is on the roadmap.
- **Logic flaws** (IDOR, business-flow abuse) are a review queue for humans or the agent, not verdicts.
- **Images**: RPM databases, Go binaries and JARs are not parsed yet. zstd layers need Python 3.14.
- **Live cloud** is AWS only. GCP and Azure are covered in Terraform, not live.
- **The web mode is passive.** It sends no payloads and is not a penetration test.

## Related

[cspm-lite](https://github.com/Houssam2510/cspm-lite) and [triage](https://github.com/Houssam2510/triage) were the first steps. Rempart now includes their live AWS audit and their KEV + EPSS prioritisation and goes further, so it stands on its own. Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md) · Security policy: [SECURITY.md](SECURITY.md) · MIT license.
