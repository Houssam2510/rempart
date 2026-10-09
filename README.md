# Rempart

**One security scanner for everything you ship: code, dependencies, cloud infrastructure, data stores, CI/CD pipelines and AI agents. It ranks findings by real-world exploitation and learns from your triage.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-54%20passing-brightgreen)](tests)
[![Rules](https://img.shields.io/badge/rules-216-7c5cff)](docs/RULES.md)
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-2025-black)](docs/THREAT_CATALOG.md)

*Rempart* is French for *rampart*: the wall you build before anyone attacks.

---

## Why

A modern side project or startup app is not one attack surface but six. There is the code, its 400 transitive npm packages, the Terraform that creates its bucket and database, the GitHub workflow that deploys it, the Supabase or MongoDB that holds its users, and now the MCP servers and LLM calls wired into it. Each has its own scanner, its own report format and its own flood of "HIGH" findings, so solo developers and small teams run none of them.

Rempart runs one pass over a repository and answers three questions:

1. **What is actually exploitable?** Dependency CVEs are checked against [OSV.dev](https://osv.dev), then ranked by exploitation evidence: CISA KEV membership (confirmed in the wild) and FIRST EPSS (predicted probability). React2Shell outranks a theoretical bug with the same CVSS.
2. **What is misconfigured?** 216 rules across 13 domains, mapped to OWASP Top 10:2025, CWE Top 25 (2025), OWASP Kubernetes Top 10 (2025), OWASP CI/CD Top 10, OWASP LLM Top 10 (2025) and OWASP Agentic Top 10 (2026).
3. **Is it getting better?** Every scan is recorded locally. Rempart diffs against the last scan, tracks mean time to remediate, and adjusts each rule's confidence from your true-positive / false-positive verdicts.

It is a static, defensive tool: it reads your files, and its web mode only sends the requests a browser would.

## Quick start

```bash
pipx install git+https://github.com/Houssam2510/rempart     # or: pip install -e .
rempart scan .                                             # scan the current repository
rempart scan examples/vulnerable-app --offline             # see every domain fire on the demo app
rempart web https://your-site.example                      # passive audit of a site you own
```

Only dependency is PyYAML. No account, no API key, no telemetry.

## What it finds

```
$ rempart scan examples/vulnerable-app --offline --limit 8
Rempart — examples/vulnerable-app
11 files · 10 scanners · 0.02s

  Posture score 3/100  grade F
  12 critical  15 high  17 medium  10 low  1 info

■ iac (7)
   CRIT  S3 bucket readable or writable by everyone  infra/main.tf:1
         aws_s3_bucket_acl.uploads: ACL public-read.
   CRIT  Database or cache port open to the internet  infra/main.tf:5
         aws_security_group.db: 5432/PostgreSQL reachable from anywhere.
   CRIT  IAM policy allows every action on every resource  infra/main.tf:20
         aws_iam_policy.ci: Action "*" on Resource "*".
   HIGH  EC2 instance metadata v1 allowed  infra/main.tf:26
         aws_instance.worker: metadata_options.http_tokens is not "required".
...
```

With network access, dependency findings are enriched and ordered by exploitation evidence:

```
   CRIT  Dependency with a known vulnerability  package-lock.json
         react-server-dom-webpack@19.0.0: GHSA-fv66-9v8q-g76r / CVE-2025-55182 — React Server
         Components are Vulnerable to RCE — fixed in 19.0.1, 19.1.2, 19.2.1 — exploited in the wild (CISA KEV)
   CRIT  Dependency with a known vulnerability  package-lock.json
         next@15.0.0: GHSA-f82v-jwr5-mffw / CVE-2025-29927 — Authorization Bypass in Next.js
         Middleware — fixed in 13.5.9, 14.2.25, 15.2.3 — EPSS 99%
```

| Domain | Examples of what is checked | Frameworks |
|---|---|---|
| **Secrets** | 25 provider token formats (AWS, GitHub, Stripe, OpenAI, Anthropic, Supabase…), private keys, entropy-filtered generic secrets, committed `.env` and key files. Values are always redacted. | CWE-798 |
| **Code (SAST)** | Python on its AST; JS/TS/Svelte/Vue, Go, Java/Kotlin, PHP, Ruby, C#, C/C++ by sink + untrusted-source rules: SQL/NoSQL/command/code injection, XSS sinks, SSRF, path traversal, open redirect, unsafe deserialization, JWT `none`, weak crypto, mass assignment, CORS with credentials, ReDoS, Trojan Source, IDOR review queue | OWASP A01–A10:2025, CWE Top 25 |
| **Dependencies** | 12 lockfile formats (npm, pnpm, yarn, pip, Poetry, uv, Pipenv, Go, Cargo, Bundler, Composer, Gradle) → OSV.dev, CISA KEV, FIRST EPSS; known-malicious releases | A03:2025 |
| **Supply chain** | Install scripts that download code, typosquats, dependency confusion (`--extra-index-url`), unpinned and HTTP sources, missing lockfiles | A03:2025, CICD-SEC-3 |
| **Infrastructure as code** | Terraform for AWS, GCP, Azure: public buckets, open admin/database ports (IPv4 and IPv6), wildcard IAM and privilege escalation, IMDSv1, unencrypted data stores, public DBs, weak TLS, audit trails, state files committed | CIS AWS, A02/A04:2025 |
| **Containers** | Dockerfile and Compose: root user, unpinned bases, `curl \| sh`, secrets in layers, Docker socket mounts, DB ports published on 0.0.0.0 | K01:2025 |
| **Kubernetes** | Privileged pods, host namespaces, hostPath, capabilities, RBAC wildcards and escalation verbs, cluster-admin bindings, committed Secrets | OWASP K8s Top 10 (2025), Pod Security Standards |
| **CI/CD** | `pull_request_target` pwn requests, script injection from issue/PR text, unpinned actions, cache poisoning in privileged jobs, OIDC on untrusted triggers, secrets echoed, long-lived publish tokens | OWASP CICD-SEC-1…10 |
| **Data** | Credentials in connection strings, TLS disabled to the database, exposed MongoDB/Redis/Postgres/MySQL/Elasticsearch configs, Supabase tables without RLS, open Firebase rules, MongoDB Atlas 0.0.0.0/0, excessive SQL grants, PII and card numbers in committed files, sensitive data in logs | Québec Law 25, PIPEDA, GDPR, PCI DSS |
| **AI and agents** | MCP servers from unpinned packages (rug pulls), secrets in MCP configs, broad filesystem/shell servers, invisible-Unicode instructions in `AGENTS.md`/`.cursorrules`, LLM output reaching `eval`/HTML/SQL, shell-executing agent tools, prompts built from user input | OWASP LLM Top 10 (2025), Agentic Top 10 (2026) |
| **Quality** | Authorization that fails open on exceptions, swallowed exceptions, security `assert`s, complexity, security TODOs, async `forEach` | A10:2025 |
| **Performance** | N+1 queries and sequential awaits in loops, HTTP calls without timeouts, unbounded queries, blocking I/O in request paths, missing resource limits, image bloat | CWE-400/770 |
| **Web (passive)** | HTTPS redirect, HSTS, CSP quality, framing, cookies, CORS, version banners, legacy TLS, certificate expiry, `security.txt`, warm/cold TTFB, compression | A02/A04/A07:2025 |

The full research behind these rules, including the 2025-2026 incidents that motivated each one and what static analysis cannot see, is in **[docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md)**. Every rule is listed in [docs/RULES.md](docs/RULES.md).

## How it decides what matters

Each finding carries a severity, a confidence and a 0-100 **risk**:

```
risk = severity_weight × (0.5 + confidence / 2)
if EPSS is known:      risk = max(risk, 0.6 × risk + 40 × EPSS)
if CVE is in CISA KEV: risk = max(risk, 95)        # confirmed exploitation is a floor, not a bonus
```

The repository's **posture score** is `100 × exp(−penalty / 120)`. Repeats of the same rule have diminishing weight (1, ½, ⅓…), so one noisy rule cannot sink a grade, while many distinct problems do.

## It learns from you

```bash
rempart scan .                          # each finding has a short id
rempart triage 7d9771c7fb --fp --note "bounded regex, not ReDoS"
rempart triage 697ff3c2a7 --tp
rempart learn                           # what the feedback loop has learned
rempart history                         # score trend, new vs fixed, mean time to remediate
```

Verdicts feed a per-rule Beta-Bernoulli estimate of precision, shared across all your projects:

```
precision = (TP + a) / (TP + FP + a + b)     with a, b set from the rule's prior confidence
```

New findings inherit the learned confidence. A rule that keeps being wrong (≥ 5 false positives, < 25 % precision) is automatically downgraded one severity level. Findings you marked false positive or accepted risk stay suppressed in that project. Everything lives in a local SQLite file (`~/.local/share/rempart`, override with `REMPART_HOME`).

## In CI

Rempart writes SARIF 2.1.0, so findings appear in GitHub's Security tab and as PR annotations:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: Houssam2510/rempart@<commit-sha>
    with:
      fail-on: high
  - uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
    with:
      sarif_file: rempart.sarif
```

Other outputs: `--format json | md | html` (self-contained, filterable report). `--fail-on <severity>` sets the exit code.

## Configuration

`.rempart.toml` at the scan root:

```toml
exclude = ["fixtures/**"]
disable = ["DOCKER-NO-HEALTHCHECK"]
fail_on = "high"

[severity]
"QUAL-COMPLEXITY" = "low"
```

Inline: `// rempart:ignore` or `# rempart:ignore[CODE-SQL-INJECTION]` on the line or the line above.

## Measured precision

The heuristics were tuned by scanning real repositories, and every false positive found that way became a regression test.

| Target | Result |
|---|---|
| A production SvelteKit SaaS (350 files, 426 npm packages) | Grade A. First pass raised 19 findings; review showed that the cookie, `{@html}` and regex alerts were safe, which led to session-context, JSON-LD-escaping and separator-aware ReDoS logic. |
| [cspm-lite](https://github.com/Houssam2510/cspm-lite) intentionally vulnerable AWS lab | 9 of 9 planted misconfigurations, including SSH open on IPv6 and `jsonencode()` IAM/S3 policies (the latter was a miss, now fixed and tested). |
| [triage](https://github.com/Houssam2510/triage) | Grade A, one finding: a paginated NVD fetch inside a loop. |
| Rempart itself | Grade A (CI fails the build on any high finding). |

## Architecture

```
            rempart scan PATH                        rempart web URL
                   │                                       │
       engine.discover()  ← honours .gitignore             web.audit()  passive GET, TLS, security.txt
                   │
   ┌───────┬───────┼────────┬──────────┬─────────┬─────────┬──────┬────┬─────────┐
 secrets  code   deps     terraform containers kubernetes  cicd  data  ai  quality
           │       │
   Python AST   lockfiles → OSV.dev ─┬─ CISA KEV
   + line rules                      └─ FIRST EPSS          (cached on disk, offline mode)
                   │
         findings (rule + location + fingerprint)
                   │
   suppressions (.rempart.toml, inline)  →  history.apply_knowledge()  ← verdicts (SQLite)
                   │
       score / diff / MTTR  →  console · JSON · SARIF · Markdown · HTML
```

Rules are data (`registry.rule(...)`) and scanners are small classes with one `scan(ctx)` method. Adding a check means one rule definition, one detection block and one test. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Limits, stated plainly

- **No inter-procedural taint tracking.** Non-Python rules need the dangerous sink and the untrusted source on the same line (or a small window). A value laundered through three functions is missed. CodeQL and Semgrep Pro go further. Rempart trades depth for breadth, speed and zero setup.
- **Logic flaws need context.** Broken access control, IDOR and business-logic abuse are mostly invisible to static rules. `CODE-IDOR-CANDIDATE` is a low-confidence review queue, not a verdict.
- **Memory safety** (CWE-787/416/125) is limited to banned C functions.
- **The web mode is passive.** It does not crawl, fuzz or send payloads, so it is safe on production and is not a penetration test.

## Related

Rempart is the code-and-config layer of a three-part toolkit:
[cspm-lite](https://github.com/Houssam2510/cspm-lite) audits the *running* AWS account against CIS, and [triage](https://github.com/Houssam2510/triage) prioritises container-image CVEs with the same KEV + EPSS model.

Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md). Security policy: [SECURITY.md](SECURITY.md). License: MIT.
