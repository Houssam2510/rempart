# Threat catalog

This document is the research behind Rempart. It inventories the attack classes that matter for a web, data and cloud application in 2026. For each one it states whether Rempart detects it, partly detects it, or cannot see it from source and configuration alone.

It is organised by domain and anchored to the current editions of the reference lists:
OWASP Top 10:2025, CWE Top 25 (2025), OWASP API Security Top 10 (2023), OWASP Top 10 CI/CD Security Risks, OWASP Kubernetes Top 10 (2025), OWASP Top 10 for LLM Applications (2025) and OWASP Top 10 for Agentic Applications (2026).

**Legend**

| Mark | Meaning |
|---|---|
| ✅ | Detected. Rule IDs are given. |
| 🟡 | Partly detected: a heuristic, a single framework, or a review queue. |
| 🔭 | Not visible statically. Needs runtime testing, cloud API access or human review. |

Descriptions stay at the level of *what the weakness is and how to recognise it*. Exploitation techniques are out of scope.

---

## 1. What changed in 2025-2026

- **OWASP Top 10:2025** promoted **Software Supply Chain Failures** to A03 and added **A10 Mishandling of Exceptional Conditions** (failing open, swallowed errors). SSRF was folded into A01 Broken Access Control. Security Misconfiguration rose to A02.
- **CWE Top 25 (2025)**, built from 39,080 CVE records, still has XSS (CWE-79) and SQL injection (CWE-89) at #1 and #2. Missing Authorization (CWE-862) climbed to #4, and Unrestricted Resource Allocation (CWE-770) entered at #25.
- **Supply-chain worms became the dominant npm threat.** Shai-Hulud (Sep 2025, 500+ packages) and Shai-Hulud 2.0 (Nov 2025, ~800 packages, pre-install execution) stole tokens and republished every package the victim maintained. In 2026 came the Axios compromise (Mar 2026, stolen maintainer token, no OIDC binding) and TanStack (May 2026: `pull_request_target`, then GitHub Actions cache poisoning, then OIDC token extraction from runner memory). Mini Shai-Hulud then shipped with **valid SLSA Build Level 3 attestations**: provenance alone no longer proves a package is safe.
- **Mutable CI references.** The tj-actions/changed-files compromise (Mar 2025) repointed a version tag to a commit that dumped runner secrets into public logs.
- **React2Shell (CVE-2025-55182, CVSS 10).** Unauthenticated RCE in React Server Components was exploited within hours of disclosure (Dec 2025) and added to CISA KEV. It was followed by a run of RSC/Next.js DoS, cache-poisoning and middleware-bypass CVEs through May 2026.
- **Exposed databases are still ransomed automatically.** Flare (Feb 2026) counted ~3,100 internet-exposed MongoDB servers without authentication. About 1,400 of them had already been wiped and left with a ransom note.
- **Cloud: identity beats network.** Intruder's 2026 Cloud Security Index (about 3,000 organisations) found weak IAM in 87-97 % of accounts depending on provider. The most common AWS issue was S3 buckets not enforcing HTTPS (87 %), ahead of sensitive ports open to the internet (84 %).
- **Agents and MCP opened a new front.** The ingredients were tool-description poisoning, rug-pull server updates, project-defined MCP servers auto-executed by IDEs, and SANDWORM_MODE (Feb 2026), where malicious npm packages installed rogue MCP servers into the configs of AI coding assistants (Cursor, VS Code and others). The OWASP Agentic Top 10 (Dec 2025) codified these risks.

---

## 2. Web applications: OWASP Top 10:2025

### A01 Broken Access Control

| Threat | Status | Rempart |
|---|---|---|
| Missing authorization on a route or object (IDOR / BOLA) | 🟡 | `CODE-IDOR-CANDIDATE` (review queue: lookup by client id with no owner/session reference) |
| Row-level access missing in BaaS (Supabase RLS, Firebase rules) | ✅ | `DATA-SUPABASE-RLS-MISSING`, `DATA-FIREBASE-OPEN-RULES` |
| Mass assignment / over-posting (`role`, `isAdmin`, `credits`) | ✅ | `CODE-MASS-ASSIGNMENT` |
| Server-side request forgery (now part of A01) | ✅ | `CODE-SSRF`, plus the cloud path `TF-EC2-IMDSV1` |
| Path traversal / local file inclusion | ✅ | `CODE-PATH-TRAVERSAL` |
| Open redirect | ✅ | `CODE-OPEN-REDIRECT` |
| CSRF protection disabled | ✅ | `CODE-CSRF-DISABLED` |
| postMessage without origin checks | ✅ | `CODE-POSTMESSAGE-ORIGIN` |
| Function-level authorization (admin endpoints reachable by users), privilege escalation through workflows | 🔭 | Needs runtime role testing |
| Public cloud storage and wildcard resource policies | ✅ | `TF-S3-PUBLIC-ACL`, `TF-POLICY-PUBLIC-PRINCIPAL`, `TF-GCP-PUBLIC-MEMBER`, `TF-AZURE-PUBLIC-BLOB` |

### A02 Security Misconfiguration

| Threat | Status | Rempart |
|---|---|---|
| Debug mode in production (Werkzeug console, Django DEBUG) | ✅ | `CODE-DEBUG-ENABLED` |
| Missing security headers (CSP, HSTS, framing, nosniff, referrer) | ✅ | `WEB-CSP`, `WEB-HSTS`, `WEB-CLICKJACKING`, `WEB-NOSNIFF`, `WEB-REFERRER-POLICY` |
| CORS reflecting any origin with credentials | ✅ | `CODE-CORS-PERMISSIVE`, `WEB-CORS-WILDCARD` |
| XML external entities | ✅ | `CODE-XXE` |
| Version banners | ✅ | `WEB-VERSION-DISCLOSURE` |
| Default credentials, sample apps left deployed | 🔭 | Needs runtime checks |
| Cloud and container misconfiguration | ✅ | sections 6-9 |

### A03 Software Supply Chain Failures

See section 4.

### A04 Cryptographic Failures

| Threat | Status | Rempart |
|---|---|---|
| Broken hashes (MD5, SHA-1) for security | ✅ | `CODE-WEAK-HASH` |
| Passwords stored with fast hashes | ✅ | `CODE-WEAK-PASSWORD-HASH` |
| DES, RC4, ECB, IV-less ciphers | ✅ | `CODE-WEAK-CIPHER` |
| Predictable randomness for tokens, OTPs and resets | ✅ | `CODE-WEAK-RANDOM` |
| TLS verification disabled | ✅ | `CODE-TLS-VERIFY-DISABLED`, `DATA-TLS-INSECURE` |
| Plaintext transport (HTTP, DB without TLS) | ✅ | `WEB-NO-HTTPS-REDIRECT`, `DATA-TLS-DISABLED`, `TF-DATA-NO-TLS` |
| Data at rest unencrypted | ✅ | `TF-DATA-UNENCRYPTED` |
| Legacy TLS and certificate expiry | ✅ | `WEB-TLS-WEAK`, `WEB-CERT-EXPIRY`, `TF-TLS-OUTDATED` |
| Hard-coded keys | ✅ | section 3 |
| Nonce reuse, custom crypto protocols, timing side channels | 🔭 | Needs cryptographic review |

### A05 Injection

| Threat | Status | Rempart |
|---|---|---|
| SQL injection (raw drivers, ORMs' *Unsafe* APIs, string-built queries) | ✅ | `CODE-SQL-INJECTION` (Python AST, JS/TS, Go, Java, PHP, Ruby, C#) |
| NoSQL operator injection, `$where` | ✅ | `CODE-NOSQL-INJECTION` |
| OS command injection | ✅ | `CODE-CMD-INJECTION`, `CODE-SHELL-TRUE` |
| Code injection (`eval`, `new Function`, `vm`) | ✅ | `CODE-EVAL`, `CODE-WEAK-SANDBOX` |
| Cross-site scripting sinks (`innerHTML`, `dangerouslySetInnerHTML`, `{@html}`, `v-html`) | ✅ | `CODE-XSS-SINK` |
| Template injection / auto-escaping disabled | ✅ | `CODE-TEMPLATE-AUTOESCAPE-OFF` |
| Regular expression DoS and regex injection | ✅ | `CODE-REDOS`, `CODE-REGEX-INJECTION` |
| Prototype pollution | 🟡 | `CODE-PROTOTYPE-POLLUTION` (deep merges of request data) |
| Prompt injection into LLM context | 🟡 | `AI-PROMPT-INJECTION-SURFACE` (section 10) |
| LDAP, XPath, header/CRLF, log injection | 🔭 | Roadmap |

### A06 Insecure Design

| Threat | Status | Rempart |
|---|---|---|
| Unrestricted file upload | ✅ | `CODE-UNRESTRICTED-UPLOAD` |
| Missing rate limits, abuse of business flows (OWASP API6) | 🔭 | Needs threat modelling |
| Race conditions on credits, coupons, balances | 🔭 | Needs concurrency testing |
| Security debt left in code | ✅ | `QUAL-SECURITY-TODO` |

### A07 Authentication Failures

| Threat | Status | Rempart |
|---|---|---|
| JWT `none` / unverified signature / ignored expiry | ✅ | `CODE-JWT-UNVERIFIED` |
| Session cookies without Secure/HttpOnly/SameSite | ✅ | `CODE-COOKIE-FLAGS`, `WEB-COOKIE-FLAGS` |
| Tokens in `localStorage` | ✅ | `CODE-TOKEN-LOCALSTORAGE` |
| Secrets with hard-coded fallbacks | ✅ | `CODE-FALLBACK-SECRET` |
| Unauthenticated function URLs and data stores | ✅ | `TF-FUNCTION-URL-PUBLIC`, `DATA-MONGODB-EXPOSED`, `DATA-REDIS-EXPOSED`, `DATA-POSTGRES-TRUST-AUTH` |
| Credential stuffing, MFA bypass, OAuth `redirect_uri`/`state` flaws, reset-token poisoning | 🔭 | Needs runtime testing |

### A08 Software or Data Integrity Failures

| Threat | Status | Rempart |
|---|---|---|
| Unsafe deserialization (pickle, YAML, Java, .NET, PHP, Ruby, `torch.load`) | ✅ | `CODE-UNSAFE-DESERIALIZATION` |
| Unverified downloads (`curl \| sh`, `ADD <url>`) | ✅ | `DOCKER-CURL-PIPE-SHELL`, `DOCKER-ADD-REMOTE`, `CI-CURL-PIPE-SHELL` |
| Trojan Source / invisible characters (CVE-2021-42574) | ✅ | `CODE-TROJAN-SOURCE`, `AI-HIDDEN-INSTRUCTIONS` |
| CI/CD pipeline integrity | ✅ | section 5 |

### A09 Security Logging and Alerting Failures

| Threat | Status | Rempart |
|---|---|---|
| Secrets and personal data written to logs | ✅ | `DATA-SENSITIVE-LOGGED`, `GHA-SECRET-ECHO`, `GITLAB-CI-DEBUG-TRACE` |
| Cloud audit trail incomplete | ✅ | `TF-AUDIT-LOGGING-WEAK` |
| No alerting on security events | 🔭 | Organisational |

### A10 Mishandling of Exceptional Conditions

| Threat | Status | Rempart |
|---|---|---|
| Authorization that fails open on error | ✅ | `QUAL-FAIL-OPEN` |
| Broad exceptions swallowed silently | ✅ | `QUAL-SWALLOWED-EXCEPTION`, `QUAL-BARE-EXCEPT` |
| Security checks with `assert` (stripped under `-O`) | ✅ | `QUAL-ASSERT-SECURITY` |
| Unhandled async work (`forEach(async…)`) | ✅ | `QUAL-FOREACH-ASYNC` |
| Resource exhaustion (no timeouts, no limits, unbounded queries) | ✅ | `PERF-NO-TIMEOUT`, `K8S-NO-RESOURCE-LIMITS`, `PERF-UNBOUNDED-QUERY`, `AI-UNBOUNDED-GENERATION` |

### CWE Top 25 (2025) coverage

| # | CWE | Status | | # | CWE | Status |
|---|---|---|---|---|---|---|
| 1 | 79 XSS | ✅ | | 14 | 121 Stack overflow | 🟡 banned C functions |
| 2 | 89 SQL injection | ✅ | | 15 | 502 Deserialization | ✅ |
| 3 | 352 CSRF | ✅ (disabled protection) | | 16 | 122 Heap overflow | 🟡 banned C functions |
| 4 | 862 Missing authorization | 🟡 RLS/Firebase/IDOR queue | | 17 | 863 Incorrect authorization | 🟡 IDOR queue |
| 5 | 787 Out-of-bounds write | 🟡 banned C functions | | 18 | 20 Input validation | 🔭 |
| 6 | 22 Path traversal | ✅ | | 19 | 284 Access control | ✅ (cloud, BaaS) |
| 7 | 416 Use after free | 🔭 | | 20 | 200 Information exposure | ✅ |
| 8 | 125 Out-of-bounds read | 🔭 | | 21 | 306 Missing authentication | ✅ (data stores, function URLs) |
| 9 | 78 OS command injection | ✅ | | 22 | 918 SSRF | ✅ |
| 10 | 94 Code injection | ✅ | | 23 | 77 Command injection | ✅ |
| 11 | 120 Classic buffer overflow | ✅ banned functions | | 24 | 639 User-controlled key (IDOR) | 🟡 review queue |
| 12 | 434 Unrestricted upload | ✅ | | 25 | 770 Unbounded allocation | ✅ |
| 13 | 476 NULL dereference | 🔭 | | | | |

The memory-safety entries (416, 125, 476) need compiler instrumentation, sanitizers or a real C analyser. They are listed as roadmap work, not claimed.

---

## 3. Secrets and identity

| Threat | Status | Rempart |
|---|---|---|
| Provider tokens in code (25 formats: AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, Hugging Face, npm, PyPI, SendGrid, Resend, Twilio, Mailgun, Discord, Azure Storage, Supabase, DigitalOcean, Shopify, Doppler…) | ✅ | `SEC-*` |
| Private keys and keystores | ✅ | `SEC-PRIVATE-KEY`, `SEC-KEY-FILE` |
| Generic secrets (high-entropy literals in secret-named variables) | ✅ | `SEC-GENERIC` |
| `.env` files committed (gitignored ones are skipped on purpose) | ✅ | `SEC-ENV-COMMITTED` |
| Registry tokens in `.npmrc` / `.pypirc` | ✅ | `SEC-NPMRC-TOKEN` |
| Secrets in Docker layers, Compose, Kubernetes manifests, Terraform, MCP configs, prompts | ✅ | `DOCKER-SECRET-IN-IMAGE`, `COMPOSE-SECRET-LITERAL`, `K8S-SECRET-IN-ENV`, `TF-HARDCODED-PASSWORD`, `TF-TFVARS-SECRET`, `AI-MCP-SECRET-IN-CONFIG`, `AI-SECRET-IN-PROMPT` |
| Secrets in git *history* (deleted but reachable) | 🔭 | Roadmap: `--history` mode over `git log -p` |
| Live validity of a leaked key | 🔭 | Deliberately not done: Rempart never calls third-party APIs with found credentials |

---

## 4. Software supply chain (A03:2025)

| Threat | Real-world reference | Status | Rempart |
|---|---|---|---|
| Known-vulnerable dependency | React2Shell, Next.js middleware bypass (CVE-2025-29927) | ✅ | `DEP-VULNERABLE` with OSV + KEV + EPSS |
| Known-malicious release (worm, account takeover) | Shai-Hulud 1 and 2, Axios 1.14.1, TanStack | ✅ | `DEP-MALICIOUS` (OSV `MAL-` entries from the OpenSSF malicious-packages feed) |
| Install-time code execution in your own package | Worm propagation vector | ✅ | `SUPPLY-INSTALL-SCRIPT` |
| Typosquatting | Recurrent on npm and PyPI | 🟡 | `SUPPLY-TYPOSQUAT` (edit distance 1 from ~190 popular npm and PyPI names) |
| Dependency confusion | Birsan 2021, still common with `--extra-index-url` | ✅ | `SUPPLY-DEPENDENCY-CONFUSION` |
| Mutable versions (`*`, `latest`, git branches, tarball URLs) | n/a | ✅ | `SUPPLY-UNPINNED` |
| No lockfile / non-reproducible installs | n/a | ✅ | `SUPPLY-NO-LOCKFILE`, `DOCKER-NONREPRODUCIBLE-INSTALL` |
| Packages over plain HTTP | n/a | ✅ | `SUPPLY-INSECURE-REGISTRY` |
| Compromised package with *valid* provenance | Mini Shai-Hulud (SLSA L3) | 🔭 | Provenance cannot catch it. Only behavioural analysis or a release delay ("cooldown") policy can. On the roadmap. |
| Malicious code in a not-yet-reported release | Zero-day package compromise | 🔭 | Roadmap: diff-based install-script and network-call heuristics |

---

## 5. CI/CD pipelines (OWASP CICD-SEC-1…10)

| Risk | Threat | Status | Rempart |
|---|---|---|---|
| CICD-SEC-4 Poisoned Pipeline Execution | `pull_request_target` that checks out PR code (pwn request) | ✅ | `GHA-PWN-REQUEST`, `GHA-PULL-REQUEST-TARGET` |
| CICD-SEC-4 | Script injection from issue/PR titles, branch names, commit messages | ✅ | `GHA-SCRIPT-INJECTION` |
| CICD-SEC-4 / 9 | Cache poisoning into a privileged job (TanStack, May 2026) | ✅ | `GHA-CACHE-IN-PRIVILEGED` |
| CICD-SEC-9 | `workflow_run` consuming untrusted artifacts | 🟡 | `GHA-WORKFLOW-RUN-ARTIFACT` |
| CICD-SEC-3 / 8 | Actions pinned to mutable tags (tj-actions, Mar 2025) | ✅ | `GHA-UNPINNED-ACTION` |
| CICD-SEC-2 / 5 | Default or write-all token permissions | ✅ | `GHA-DEFAULT-PERMISSIONS`, `GHA-WRITE-ALL` |
| CICD-SEC-2 / 6 | OIDC `id-token: write` reachable from untrusted triggers | ✅ | `GHA-OIDC-UNTRUSTED` |
| CICD-SEC-6 | Secrets echoed, inherited wholesale, CI debug trace | ✅ | `GHA-SECRET-ECHO`, `GHA-SECRETS-INHERIT`, `GITLAB-CI-DEBUG-TRACE` |
| CICD-SEC-6 | Long-lived publish tokens instead of trusted publishing | 🟡 | `CI-LONG-LIVED-PUBLISH-TOKEN` |
| CICD-SEC-7 | Self-hosted runners exposed to PRs | ✅ | `GHA-SELF-HOSTED-PUBLIC` |
| CICD-SEC-1 | Missing branch protection / required review | 🔭 | Needs the GitHub API; roadmap via `gh` |
| CICD-SEC-10 | Insufficient pipeline logging | 🔭 | Organisational |

---

## 6. Cloud infrastructure (Terraform: AWS, GCP, Azure)

| Threat | Status | Rempart |
|---|---|---|
| Public object storage (ACLs, policies, `allUsers`, anonymous blobs) | ✅ | `TF-S3-PUBLIC-ACL`, `TF-S3-BLOCK-PUBLIC-ACCESS-OFF`, `TF-POLICY-PUBLIC-PRINCIPAL`, `TF-GCP-PUBLIC-MEMBER`, `TF-AZURE-PUBLIC-BLOB` |
| Admin ports (SSH, RDP, WinRM, Docker API, kubelet) open to 0.0.0.0/0 or ::/0 | ✅ | `TF-NET-ADMIN-PORT-OPEN` |
| Database/cache ports open to the internet (20 ports, 17 engines) | ✅ | `TF-NET-DATA-PORT-OPEN`, `TF-NET-ALL-PORTS-OPEN` |
| Wildcard IAM, escalation-capable actions, AdministratorAccess, primitive GCP roles | ✅ | `TF-IAM-WILDCARD`, `TF-IAM-PRIVESC`, `TF-IAM-ADMIN-ATTACHED`, `TF-GCP-PRIMITIVE-ROLE` |
| Long-lived access keys and static provider credentials | ✅ | `TF-IAM-ACCESS-KEY`, `TF-PROVIDER-STATIC-KEYS` |
| IMDSv1: SSRF turns into stolen instance credentials (Capital One 2019) | ✅ | `TF-EC2-IMDSV1` |
| Unencrypted RDS/EBS/EFS/OpenSearch/ElastiCache/SQS/SNS | ✅ | `TF-DATA-UNENCRYPTED` |
| Publicly accessible databases | ✅ | `TF-DB-PUBLIC` |
| No backups, PITR or deletion protection | ✅ | `TF-DATA-NO-BACKUP` |
| TLS not enforced (OpenSearch, Cloud SQL, storage accounts, CloudFront, ALB) | ✅ | `TF-DATA-NO-TLS`, `TF-LB-PLAIN-HTTP`, `TF-TLS-OUTDATED` |
| CloudTrail gaps, KMS rotation off, Key Vault purge protection off | ✅ | `TF-AUDIT-LOGGING-WEAK`, `TF-KMS-NO-ROTATION`, `TF-AZURE-KEYVAULT-PURGE` |
| Public Kubernetes control planes (EKS, GKE, AKS) | ✅ | `TF-K8S-PUBLIC-ENDPOINT` |
| Terraform state and secrets committed; unencrypted remote state | ✅ | `TF-STATE-COMMITTED`, `TF-TFVARS-SECRET`, `TF-BACKEND-UNENCRYPTED` |
| Mutable container registries | ✅ | `TF-REGISTRY-MUTABLE-TAGS` |
| Drift between code and the deployed account | 🔭 | Covered by [cspm-lite](https://github.com/Houssam2510/cspm-lite) (live AWS API, CIS benchmark) |
| CloudFormation, Pulumi, CDK, Bicep | 🔭 | Roadmap |
| Cross-account trust and confused-deputy roles without `ExternalId` | 🟡 | Policies with `Principal "*"` and no condition are caught; account-level trust graphs are not |

---

## 7. Containers

| Threat | Status | Rempart |
|---|---|---|
| Running as root | ✅ | `DOCKER-RUNS-AS-ROOT` |
| Floating base images (`latest`, no digest) | ✅ | `DOCKER-UNPINNED-BASE` |
| Secrets in ENV/ARG layers | ✅ | `DOCKER-SECRET-IN-IMAGE` |
| Build context leaks (`COPY . .` without `.dockerignore`) | ✅ | `DOCKER-NO-DOCKERIGNORE` |
| Remote scripts and unverified downloads | ✅ | `DOCKER-CURL-PIPE-SHELL`, `DOCKER-ADD-REMOTE` |
| Docker socket mounts, privileged/host-network services | ✅ | `COMPOSE-DOCKER-SOCKET`, `COMPOSE-PRIVILEGED` |
| DB ports published on 0.0.0.0 (bypasses ufw) | ✅ | `COMPOSE-DATA-PORT-PUBLISHED` |
| OS-package CVEs inside built images | 🔭 | Use [triage](https://github.com/Houssam2510/triage) (Trivy + KEV + EPSS) |

---

## 8. Kubernetes (OWASP Kubernetes Top 10, 2025)

| Risk | Status | Rempart |
|---|---|---|
| K01 Insecure workload configurations | ✅ | `K8S-PRIVILEGED`, `K8S-PRIV-ESCALATION`, `K8S-RUNS-AS-ROOT`, `K8S-HOST-NAMESPACE`, `K8S-HOSTPATH`, `K8S-DANGEROUS-CAPS`, `K8S-WRITABLE-ROOTFS`, `K8S-NO-SECCOMP`, `K8S-UNPINNED-IMAGE` |
| K02 Overly permissive authorization | ✅ | `K8S-RBAC-WILDCARD`, `K8S-RBAC-ESCALATE`, `K8S-RBAC-SECRETS`, `K8S-CLUSTER-ADMIN-BINDING`, `K8S-SA-TOKEN-AUTOMOUNT` |
| K03 Secrets management failures | ✅ | `K8S-SECRET-COMMITTED`, `K8S-SECRET-IN-ENV` |
| K04 Lack of cluster-level policy enforcement | 🔭 | Needs cluster access (admission controllers) |
| K05 Missing network segmentation | 🟡 | `K8S-SERVICE-EXPOSED`; NetworkPolicy coverage is on the roadmap |
| K06 Overly exposed components | 🟡 | `TF-K8S-PUBLIC-ENDPOINT`, `K8S-SERVICE-EXPOSED` |
| K07 Misconfigured and vulnerable cluster components | 🔭 | Needs cluster version data |
| K08 Cluster-to-cloud lateral movement | 🟡 | `TF-EC2-IMDSV1`, `K8S-HOST-NAMESPACE` |
| K09 Broken authentication | 🟡 | `K8S-CLUSTER-ADMIN-BINDING` (anonymous bindings) |
| K10 Inadequate logging | 🔭 | Needs cluster audit config |
| Reliability: resource limits, probes | ✅ | `K8S-NO-RESOURCE-LIMITS`, `K8S-NO-PROBES` |

Helm templates are skipped until rendered (`helm template . \| rempart` support is on the roadmap).

---

## 9. Data security

This domain mixes security (who can reach the data), integrity (can it be destroyed or ransomed) and privacy (should it be there at all). Rempart tags privacy rules with **Québec Law 25**, **PIPEDA** and **GDPR Art. 32**.

| Threat | Real-world reference | Status | Rempart |
|---|---|---|---|
| Unauthenticated MongoDB on all interfaces | Flare, Feb 2026: ~1,400 servers wiped and ransomed | ✅ | `DATA-MONGODB-EXPOSED` (mongod.conf, `--bind_ip_all`) |
| Redis without protected mode or password | Long-running cryptomining campaigns | ✅ | `DATA-REDIS-EXPOSED` |
| PostgreSQL `trust`/cleartext auth, open `pg_hba`, server TLS off | n/a | ✅ | `DATA-POSTGRES-TRUST-AUTH`, `DATA-POSTGRES-OPEN-HBA`, `DATA-TLS-DISABLED` |
| MySQL `skip-grant-tables`, `local_infile`; Elasticsearch security off; passwordless DB containers | n/a | ✅ | `DATA-SERVER-HARDENING` |
| Supabase tables without Row Level Security | Most common Supabase leak | ✅ | `DATA-SUPABASE-RLS-MISSING` |
| Firebase rules open or in test mode | n/a | ✅ | `DATA-FIREBASE-OPEN-RULES` |
| MongoDB Atlas access list 0.0.0.0/0 | n/a | ✅ | `DATA-ATLAS-OPEN-ACCESS-LIST` |
| Credentials embedded in connection strings | Thousands found on GitHub (Flare 2026) | ✅ | `DATA-CONNECTION-STRING-CREDS` |
| Connections without TLS or accepting any certificate | n/a | ✅ | `DATA-TLS-DISABLED`, `DATA-TLS-INSECURE` |
| Excessive grants (`ALL ON *.*`, `TO PUBLIC`) and passwords in migrations | n/a | ✅ | `DATA-SQL-EXCESSIVE-GRANT`, `DATA-SQL-LITERAL-PASSWORD` |
| Personal data, card numbers, dumps and DB files committed | n/a | ✅ | `DATA-PII-COMMITTED`, `DATA-PAYMENT-CARD`, `DATA-DUMP-COMMITTED` |
| Secrets and PII written to logs | n/a | ✅ | `DATA-SENSITIVE-LOGGED` |
| Unbounded reads that grow with the table | n/a | ✅ | `PERF-UNBOUNDED-QUERY` |
| Public data stores in IaC | n/a | ✅ | section 6 |
| ML model files loaded with pickle (`torch.load`, `joblib`, `read_pickle`) | Malicious models on public hubs | ✅ | `CODE-UNSAFE-DESERIALIZATION` (allows `weights_only=True`) |
| Notebooks committed with data in outputs | n/a | 🔭 | Roadmap |
| Data retention, residency, consent | n/a | 🔭 | Legal review |

---

## 10. AI applications and agents

### OWASP Top 10 for LLM Applications (2025)

| Risk | Status | Rempart |
|---|---|---|
| LLM01 Prompt injection | 🟡 | `AI-PROMPT-INJECTION-SURFACE` (system prompt built from user data), `AI-HIDDEN-INSTRUCTIONS`, `AI-INJECTED-RULE-FILE` |
| LLM02 Sensitive information disclosure | 🟡 | `AI-SECRET-IN-PROMPT` |
| LLM03 Supply chain | ✅ | `AI-MCP-UNPINNED-SERVER`, dependency scanning |
| LLM04 Data and model poisoning | 🔭 | Needs data lineage |
| LLM05 Improper output handling | ✅ | `AI-OUTPUT-TO-SINK` |
| LLM06 Excessive agency | 🟡 | `AI-AGENT-SHELL-TOOL`, `AI-MCP-BROAD-ACCESS` |
| LLM07 System prompt leakage | 🟡 | `AI-SECRET-IN-PROMPT` |
| LLM08 Vector and embedding weaknesses | 🔭 | Roadmap: tenant filters on vector queries |
| LLM09 Misinformation | 🔭 | Out of scope |
| LLM10 Unbounded consumption | 🟡 | `AI-UNBOUNDED-GENERATION` (no `max_tokens`) |

### OWASP Top 10 for Agentic Applications (2026)

| Risk | Status | Rempart |
|---|---|---|
| ASI01 Agent goal hijack | 🟡 | Hidden/injected instructions in rule files |
| ASI02 Tool misuse and exploitation | 🟡 | `AI-AGENT-SHELL-TOOL`, `AI-MCP-BROAD-ACCESS` |
| ASI03 Identity and privilege abuse | 🟡 | `AI-MCP-SECRET-IN-CONFIG`, broad MCP scopes |
| ASI04 Agentic supply chain (MCP servers, rug pulls, SANDWORM_MODE) | ✅ | `AI-MCP-UNPINNED-SERVER`, `AI-MCP-PLAINTEXT-TRANSPORT` |
| ASI05 Unexpected code execution | ✅ | `AI-OUTPUT-TO-SINK`, `AI-AGENT-SHELL-TOOL` |
| ASI06 Memory and context poisoning | 🔭 | Runtime |
| ASI07 Insecure inter-agent communication | 🔭 | Roadmap |
| ASI08 Cascading failures | 🔭 | Architecture review |
| ASI09 Human-agent trust exploitation | 🔭 | Runtime |
| ASI10 Rogue agents | 🔭 | Runtime monitoring |

MCP configuration files are matched by shape, not by product name: any `*mcp*.json`, any `*desktop_config.json`, and `mcp.json` / `settings.json` under an assistant's dot-directory (`.cursor/`, `.vscode/`, `.gemini/`…). Agent instruction files are matched by shape too: `AGENTS.md` and any other upper-case `<NAME>.md` that is not a standard project document, `*rules` dot-files, Copilot instructions, and `rules/`, `instructions/`, `agents/`, `commands/`, `skills/` folders under any dot-directory. New assistants are covered without a rule change.

---

## 11. API-specific risks (OWASP API Security Top 10, 2023)

| Risk | Status | Rempart |
|---|---|---|
| API1 Broken object level authorization | 🟡 | `CODE-IDOR-CANDIDATE` |
| API2 Broken authentication | 🟡 | JWT, cookie and token-storage rules |
| API3 Broken object property level authorization | ✅ | `CODE-MASS-ASSIGNMENT` (write side); response over-exposure is 🔭 |
| API4 Unrestricted resource consumption | 🟡 | Timeouts, limits, unbounded queries, upload limits |
| API5 Broken function level authorization | 🔭 | Runtime role testing |
| API6 Unrestricted access to sensitive business flows | 🔭 | Threat modelling |
| API7 SSRF | ✅ | `CODE-SSRF` |
| API8 Security misconfiguration | ✅ | Headers, CORS, debug, TLS |
| API9 Improper inventory management | 🔭 | Needs an API inventory |
| API10 Unsafe consumption of third-party APIs | 🟡 | `PERF-NO-TIMEOUT`, TLS verification |

GraphQL introspection, query depth and batching limits are on the roadmap.

---

## 12. Quality and performance with security impact

| Issue | Why it matters | Rempart |
|---|---|---|
| High cyclomatic complexity | Untested branches hide checks | `QUAL-COMPLEXITY`, `QUAL-LONG-FUNCTION` |
| N+1 queries, sequential awaits in loops | Latency, then outage under load, then a cheap DoS | `PERF-N-PLUS-ONE` |
| No HTTP timeouts | One slow upstream exhausts every worker | `PERF-NO-TIMEOUT` |
| Blocking I/O in request paths | Event-loop stalls | `PERF-SYNC-IO-IN-SERVER` |
| Heavy imports, JSON deep-clones, image bloat | Bundle size, CPU, cold starts | `PERF-HEAVY-IMPORT`, `PERF-JSON-DEEP-CLONE`, `DOCKER-IMAGE-BLOAT` |
| Slow TTFB, cold starts, no compression | User-facing performance | `PERF-WEB-SLOW-TTFB`, `PERF-WEB-NO-COMPRESSION`, `PERF-WEB-HEAVY-HTML` |

---

## Sources

- OWASP Top 10:2025, introduction: https://owasp.org/Top10/2025/0x00_2025-Introduction/
- MITRE / CISA, 2025 CWE Top 25: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026
- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- OWASP Kubernetes Top 10 (2025): https://owasp.org/www-project-kubernetes-top-ten/
- CISA alert on the Shai-Hulud npm compromise (Sep 2025): https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- Datadog Security Labs on Shai-Hulud 2.0: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- TanStack postmortem (May 2026): https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Trend Micro on the Axios npm compromise (Mar 2026): https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html
- React security advisory for CVE-2025-55182: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- AWS Security Blog on React2Shell exploitation: https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/
- Netlify, Next.js and React security release (May 2026): https://www.netlify.com/changelog/2026-05-08-react-nextjs-security-vulnerabilities/
- Cloud Security Alliance, 2026 cloud security index: https://cloudsecurityalliance.org/blog/2026/09/04/2026-cloud-security-index-how-risk-differs-across-aws-azure-and-google-cloud-csa
- Security Affairs on MongoDB wipe-and-ransom campaigns (2026): https://securityaffairs.com/187548/cyber-crime/hackers-exploit-unsecured-mongodb-instances-to-wipe-data-and-demand-ransom.html
- CSA research note on MCP tool poisoning and IDE auto-execution: https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/
- GitHub Security Lab, preventing pwn requests: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- Trojan Source: https://trojansource.codes/
- Alex Birsan, dependency confusion: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
