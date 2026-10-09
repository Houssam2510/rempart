# Rules

Generated with `rempart rules --markdown`. 268 rules · ai 10, attack-path 9, cicd 16, cloud 30, code 36, containers 12, data 19, dependencies 3, iac 31, image 11, kubernetes 17, performance 12, quality 10, secrets 32, supply-chain 6, web 14.

| Rule | Severity | Domain | Title | CWE | OWASP 2025 | Other frameworks |
|---|---|---|---|---|---|---|
| `AI-AGENT-SHELL-TOOL` | HIGH | ai | Agent tool executes shell commands or code | CWE-78, CWE-94 | A05:2025 | ASI05:2026 Unexpected Code Execution, ASI02:2026 Tool Misuse & Exploitation, LLM06:2025 Excessive Agency |
| `AI-HIDDEN-INSTRUCTIONS` | HIGH | ai | Invisible Unicode in agent instructions or tool metadata | CWE-1007, CWE-451 | A08:2025 | ASI01:2026 Agent Goal Hijack, LLM01:2025 Prompt Injection |
| `AI-INJECTED-RULE-FILE` | HIGH | ai | Agent instruction file contains exfiltration-style directives | CWE-94 | A08:2025 | ASI01:2026 Agent Goal Hijack, LLM01:2025 Prompt Injection |
| `AI-MCP-BROAD-ACCESS` | MEDIUM | ai | MCP server given broad filesystem or shell access | CWE-250 | A07:2025 | ASI02:2026 Tool Misuse & Exploitation, ASI03:2026 Identity & Privilege Abuse, LLM06:2025 Excessive Agency |
| `AI-MCP-PLAINTEXT-TRANSPORT` | MEDIUM | ai | Remote MCP server over plain HTTP | CWE-319 | A08:2025 | ASI04:2026 Agentic Supply Chain |
| `AI-MCP-SECRET-IN-CONFIG` | CRITICAL | ai | Credential written in an MCP config | CWE-798 | A07:2025 | ASI03:2026 Identity & Privilege Abuse |
| `AI-MCP-UNPINNED-SERVER` | HIGH | ai | MCP server launched from an unpinned package | CWE-829, CWE-494 | A03:2025 | ASI04:2026 Agentic Supply Chain, LLM03:2025 Supply Chain |
| `AI-OUTPUT-TO-SINK` | HIGH | ai | Model output flows into a code, shell, HTML or SQL sink | CWE-94, CWE-79, CWE-89 | A05:2025 | LLM05:2025 Improper Output Handling, ASI05:2026 Unexpected Code Execution |
| `AI-PROMPT-INJECTION-SURFACE` | MEDIUM | ai | Untrusted input concatenated into the system prompt | CWE-77 | A05:2025 | LLM01:2025 Prompt Injection, ASI01:2026 Agent Goal Hijack |
| `AI-SECRET-IN-PROMPT` | HIGH | ai | Secret or credential placed in a prompt | CWE-200, CWE-532 | A07:2025 | LLM02:2025 Sensitive Information Disclosure, LLM07:2025 System Prompt Leakage |
| `CHAIN-ADMIN-CREDENTIALS-EXPOSED` | CRITICAL | attack-path | Credentials with full cloud admin can leak |  | A01:2025, A07:2025 |  |
| `CHAIN-BAAS-TABLE-PUBLIC` | CRITICAL | attack-path | Database table readable and writable by any visitor |  | A01:2025 |  |
| `CHAIN-CI-UNTRUSTED-TO-RELEASE` | CRITICAL | attack-path | Untrusted pull-request input can reach release credentials |  | A08:2025, A03:2025 |  |
| `CHAIN-DEBUG-CONSOLE-EXPOSED` | CRITICAL | attack-path | Debug server reachable from the network |  | A02:2025 |  |
| `CHAIN-EXPOSED-DATASTORE` | CRITICAL | attack-path | Internet-reachable data store with weak protection |  | A02:2025, A07:2025 |  |
| `CHAIN-RCE-TO-HOST` | CRITICAL | attack-path | Code execution would escape the container to the host |  | A05:2025, A02:2025 |  |
| `CHAIN-SSRF-TO-CLOUD-CREDENTIALS` | CRITICAL | attack-path | SSRF can reach instance metadata credentials |  | A01:2025 |  |
| `CHAIN-WORM-PROPAGATION` | CRITICAL | attack-path | Install-time code could republish your packages |  | A03:2025, A08:2025 |  |
| `CHAIN-XSS-SESSION-THEFT` | HIGH | attack-path | One XSS steals every user session |  | A05:2025, A07:2025 |  |
| `CI-CURL-PIPE-SHELL` | MEDIUM | cicd | Pipeline downloads and executes a remote script | CWE-494 | A08:2025 | CICD-SEC-3 Dependency Chain Abuse |
| `CI-LONG-LIVED-PUBLISH-TOKEN` | MEDIUM | cicd | Package published with a long-lived token | CWE-798 | A07:2025 | CICD-SEC-6 Insufficient Credential Hygiene |
| `GHA-CACHE-IN-PRIVILEGED` | HIGH | cicd | Cache used in a privileged pull_request_target / release workflow | CWE-349 | A08:2025 | CICD-SEC-4 Poisoned Pipeline Execution, CICD-SEC-9 Improper Artifact Integrity Validation |
| `GHA-DEFAULT-PERMISSIONS` | MEDIUM | cicd | Workflow token permissions not restricted | CWE-250 | A01:2025 | CICD-SEC-2 Inadequate IAM, CICD-SEC-5 Insufficient PBAC |
| `GHA-OIDC-UNTRUSTED` | HIGH | cicd | id-token: write in a workflow triggered by untrusted events | CWE-266 | A07:2025 | CICD-SEC-2 Inadequate IAM, CICD-SEC-6 Insufficient Credential Hygiene |
| `GHA-PULL-REQUEST-TARGET` | MEDIUM | cicd | pull_request_target trigger | CWE-829 | A08:2025 | CICD-SEC-4 Poisoned Pipeline Execution |
| `GHA-PWN-REQUEST` | CRITICAL | cicd | pull_request_target checks out untrusted PR code | CWE-829, CWE-94 | A08:2025, A01:2025 | CICD-SEC-4 Poisoned Pipeline Execution |
| `GHA-SCRIPT-INJECTION` | HIGH | cicd | Untrusted event data interpolated into a shell | CWE-78, CWE-94 | A05:2025 | CICD-SEC-4 Poisoned Pipeline Execution |
| `GHA-SECRET-ECHO` | HIGH | cicd | Secret printed or written by a step | CWE-532 | A07:2025 | CICD-SEC-6 Insufficient Credential Hygiene |
| `GHA-SECRETS-INHERIT` | LOW | cicd | Reusable workflow inherits all secrets | CWE-250 | A07:2025 | CICD-SEC-6 Insufficient Credential Hygiene |
| `GHA-SELF-HOSTED-PUBLIC` | MEDIUM | cicd | Self-hosted runner on pull request events | CWE-668 | A01:2025 | CICD-SEC-7 Insecure System Configuration |
| `GHA-UNPINNED-ACTION` | MEDIUM | cicd | Third-party action not pinned to a commit SHA | CWE-829, CWE-1357 | A03:2025 | CICD-SEC-3 Dependency Chain Abuse, CICD-SEC-8 Ungoverned 3rd Party Services |
| `GHA-UNSECURE-COMMANDS` | HIGH | cicd | ACTIONS_ALLOW_UNSECURE_COMMANDS enabled | CWE-94 | A08:2025 | CICD-SEC-4 Poisoned Pipeline Execution |
| `GHA-WORKFLOW-RUN-ARTIFACT` | MEDIUM | cicd | workflow_run consumes artifacts from an untrusted run | CWE-345 | A08:2025 | CICD-SEC-9 Improper Artifact Integrity Validation |
| `GHA-WRITE-ALL` | HIGH | cicd | Workflow grants write-all permissions | CWE-250 | A01:2025 | CICD-SEC-2 Inadequate IAM, CICD-SEC-5 Insufficient PBAC |
| `GITLAB-CI-DEBUG-TRACE` | HIGH | cicd | CI debug trace enabled | CWE-532 | A07:2025 | CICD-SEC-6 Insufficient Credential Hygiene |
| `AWS-ACCESS-ANALYZER-OFF` | LOW | cloud | IAM Access Analyzer not enabled | CWE-778 | A09:2025 | CIS AWS Foundations Benchmark |
| `AWS-CHECK-SKIPPED` | INFO | cloud | AWS check could not run |  |  |  |
| `AWS-CLOUDTRAIL-GAP` | HIGH | cloud | No complete multi-region CloudTrail | CWE-778 | A09:2025 | CIS AWS Foundations Benchmark |
| `AWS-CONFIG-OFF` | LOW | cloud | AWS Config not recording | CWE-778 | A09:2025 | CIS AWS Foundations Benchmark |
| `AWS-EBS-DEFAULT-ENCRYPTION-OFF` | MEDIUM | cloud | EBS encryption by default is off | CWE-311 | A04:2025 | CIS AWS Foundations Benchmark |
| `AWS-EC2-IMDSV1` | HIGH | cloud | Running instance allows IMDSv1 | CWE-918 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-EKS-PUBLIC-ENDPOINT` | MEDIUM | cloud | EKS API endpoint open to the internet | CWE-668 | A02:2025 | CIS AWS Foundations Benchmark |
| `AWS-GUARDDUTY-OFF` | MEDIUM | cloud | GuardDuty not enabled | CWE-778 | A09:2025 | CIS AWS Foundations Benchmark |
| `AWS-IAM-ADMIN-POLICY` | CRITICAL | cloud | Customer policy grants *:* | CWE-250 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-IAM-OLD-ACCESS-KEY` | MEDIUM | cloud | Access key older than 90 days | CWE-324 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-IAM-UNUSED-CREDENTIAL` | LOW | cloud | Credential unused for 90+ days | CWE-1188 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-IAM-USER-ADMIN` | HIGH | cloud | AdministratorAccess attached to an IAM user | CWE-250 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-IAM-USER-NO-MFA` | HIGH | cloud | Console user without MFA | CWE-308 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-KMS-NO-ROTATION` | LOW | cloud | Customer KMS key without rotation | CWE-320 | A04:2025 | CIS AWS Foundations Benchmark |
| `AWS-LAMBDA-DEPRECATED-RUNTIME` | MEDIUM | cloud | Lambda on a deprecated runtime | CWE-1104 | A06:2025 | CIS AWS Foundations Benchmark |
| `AWS-LAMBDA-URL-PUBLIC` | HIGH | cloud | Lambda function URL without auth | CWE-306 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-PASSWORD-POLICY-WEAK` | MEDIUM | cloud | IAM password policy missing or weak | CWE-521 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-RDS-NO-BACKUPS` | HIGH | cloud | RDS automated backups disabled | CWE-404 | A02:2025 | CIS AWS Foundations Benchmark |
| `AWS-RDS-PUBLIC` | CRITICAL | cloud | RDS instance publicly accessible | CWE-668 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-RDS-UNENCRYPTED` | HIGH | cloud | RDS storage not encrypted | CWE-311 | A04:2025 | CIS AWS Foundations Benchmark |
| `AWS-ROOT-ACCESS-KEYS` | CRITICAL | cloud | Root account has access keys | CWE-250 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-ROOT-NO-MFA` | CRITICAL | cloud | Root account without MFA | CWE-308 | A07:2025 | CIS AWS Foundations Benchmark |
| `AWS-S3-ACCOUNT-PAB-OFF` | HIGH | cloud | Account-level S3 Block Public Access not fully enabled | CWE-284 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-S3-BUCKET-PUBLIC` | CRITICAL | cloud | S3 bucket is public | CWE-284 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-S3-NO-TLS-ENFORCEMENT` | MEDIUM | cloud | S3 bucket does not deny plain HTTP | CWE-319 | A04:2025 | CIS AWS Foundations Benchmark |
| `AWS-SG-ADMIN-PORT-OPEN` | CRITICAL | cloud | Security group opens an admin port to the internet | CWE-668 | A02:2025 | CIS AWS Foundations Benchmark |
| `AWS-SG-ALL-OPEN` | CRITICAL | cloud | Security group allows all traffic from the internet | CWE-668 | A02:2025 | CIS AWS Foundations Benchmark |
| `AWS-SG-DATA-PORT-OPEN` | CRITICAL | cloud | Security group opens a database port to the internet | CWE-668 | A02:2025 | CIS AWS Foundations Benchmark |
| `AWS-SNAPSHOT-PUBLIC` | CRITICAL | cloud | EBS snapshot or AMI shared publicly | CWE-200 | A01:2025 | CIS AWS Foundations Benchmark |
| `AWS-VPC-NO-FLOW-LOGS` | LOW | cloud | VPC without flow logs | CWE-778 | A09:2025 | CIS AWS Foundations Benchmark |
| `CODE-CMD-INJECTION` | CRITICAL | code | OS command built from dynamic input | CWE-78, CWE-77 | A05:2025 |  |
| `CODE-COOKIE-FLAGS` | MEDIUM | code | Session cookie without Secure/HttpOnly | CWE-614, CWE-1004 | A07:2025 |  |
| `CODE-CORS-PERMISSIVE` | HIGH | code | CORS reflects any origin with credentials | CWE-942 | A02:2025 |  |
| `CODE-CSRF-DISABLED` | HIGH | code | CSRF protection disabled | CWE-352 | A01:2025 |  |
| `CODE-DEBUG-ENABLED` | HIGH | code | Debug mode enabled in application code | CWE-489, CWE-215 | A02:2025 |  |
| `CODE-EVAL` | HIGH | code | Dynamic code evaluation | CWE-94 | A05:2025 |  |
| `CODE-FALLBACK-SECRET` | HIGH | code | Secret falls back to a hard-coded default | CWE-798, CWE-1188 | A07:2025, A10:2025 |  |
| `CODE-IDOR-CANDIDATE` | LOW | code | Object fetched by client-supplied ID with no visible ownership check | CWE-639, CWE-862, CWE-863 | A01:2025 | OWASP API1:2023 BOLA |
| `CODE-INSECURE-TEMPFILE` | MEDIUM | code | Predictable temporary file | CWE-377 | A02:2025 |  |
| `CODE-JWT-UNVERIFIED` | CRITICAL | code | JWT accepted without signature or expiry verification | CWE-347, CWE-287 | A07:2025 |  |
| `CODE-MASS-ASSIGNMENT` | MEDIUM | code | Request body written straight into a model | CWE-915 | A01:2025 |  |
| `CODE-NOSQL-INJECTION` | HIGH | code | NoSQL query accepting raw request objects or $where | CWE-943 | A05:2025 |  |
| `CODE-OPEN-REDIRECT` | MEDIUM | code | Redirect target taken from user input | CWE-601 | A01:2025 |  |
| `CODE-PATH-TRAVERSAL` | HIGH | code | File path built from user input | CWE-22 | A01:2025 |  |
| `CODE-POSTMESSAGE-ORIGIN` | MEDIUM | code | postMessage handler without origin check | CWE-346 | A01:2025 |  |
| `CODE-PROTOTYPE-POLLUTION` | MEDIUM | code | Deep merge of untrusted object | CWE-1321 | A08:2025 |  |
| `CODE-REDOS` | MEDIUM | code | Regular expression vulnerable to catastrophic backtracking | CWE-1333, CWE-400 | A06:2025 |  |
| `CODE-REGEX-INJECTION` | MEDIUM | code | Regular expression built from user input | CWE-1333, CWE-625 | A05:2025 |  |
| `CODE-SHELL-TRUE` | MEDIUM | code | Subprocess started through a shell | CWE-78 | A05:2025 |  |
| `CODE-SQL-INJECTION` | CRITICAL | code | SQL query built by string interpolation | CWE-89 | A05:2025 |  |
| `CODE-SSRF` | HIGH | code | Server-side request to a user-supplied URL | CWE-918 | A01:2025 |  |
| `CODE-TEMPLATE-AUTOESCAPE-OFF` | MEDIUM | code | Template auto-escaping disabled or bypassed | CWE-79, CWE-1336 | A05:2025 |  |
| `CODE-TLS-VERIFY-DISABLED` | HIGH | code | TLS certificate verification disabled | CWE-295 | A04:2025 |  |
| `CODE-TOKEN-LOCALSTORAGE` | MEDIUM | code | Auth token stored in localStorage | CWE-922 | A07:2025 |  |
| `CODE-TROJAN-SOURCE` | HIGH | code | Bidirectional or invisible Unicode control characters in source | CWE-1007, CWE-451 | A08:2025 |  |
| `CODE-UNRESTRICTED-UPLOAD` | HIGH | code | File upload without type, name or size restrictions | CWE-434, CWE-770 | A06:2025 |  |
| `CODE-UNSAFE-C-FUNCTION` | HIGH | code | Unbounded C string/memory function | CWE-120, CWE-121, CWE-122, CWE-787 | A06:2025 |  |
| `CODE-UNSAFE-DESERIALIZATION` | HIGH | code | Deserialization of untrusted data | CWE-502 | A08:2025 |  |
| `CODE-WEAK-CIPHER` | HIGH | code | Weak cipher or mode (DES, RC4, ECB, no IV) | CWE-327 | A04:2025 |  |
| `CODE-WEAK-HASH` | MEDIUM | code | Broken hash algorithm (MD5/SHA-1) | CWE-327 | A04:2025 |  |
| `CODE-WEAK-PASSWORD-HASH` | HIGH | code | Password hashed with a fast hash | CWE-916 | A04:2025 |  |
| `CODE-WEAK-RANDOM` | MEDIUM | code | Non-cryptographic RNG used for a security value | CWE-338 | A04:2025 |  |
| `CODE-WEAK-SANDBOX` | HIGH | code | Untrusted code run in a non-isolating sandbox | CWE-94 | A05:2025 |  |
| `CODE-XSS-SINK` | MEDIUM | code | Untrusted HTML written to the DOM | CWE-79 | A05:2025 |  |
| `CODE-XXE` | MEDIUM | code | XML parser without external-entity protection | CWE-611 | A02:2025 |  |
| `CTX-BIND-ALL` | INFO | code | Server binds all interfaces (context) |  |  |  |
| `COMPOSE-DOCKER-SOCKET` | CRITICAL | containers | Docker socket mounted into a container | CWE-250 | A02:2025 | K01:2025 Insecure Workload Configurations |
| `COMPOSE-PRIVILEGED` | HIGH | containers | Compose service with host-level privileges | CWE-250 | A02:2025 | K01:2025 Insecure Workload Configurations |
| `DOCKER-ADD-REMOTE` | MEDIUM | containers | ADD fetches a remote URL without verification | CWE-494 | A08:2025 |  |
| `DOCKER-CURL-PIPE-SHELL` | HIGH | containers | Remote script piped into a shell | CWE-494 | A03:2025, A08:2025 |  |
| `DOCKER-NO-DOCKERIGNORE` | MEDIUM | containers | Whole context copied without a .dockerignore | CWE-538 | A02:2025 |  |
| `DOCKER-NO-HEALTHCHECK` | LOW | containers | No HEALTHCHECK | CWE-1188 | A02:2025 |  |
| `DOCKER-NONREPRODUCIBLE-INSTALL` | LOW | containers | Non-reproducible dependency install in image | CWE-1357 | A03:2025 |  |
| `DOCKER-RUNS-AS-ROOT` | MEDIUM | containers | Container runs as root | CWE-250 | A02:2025 | K01:2025 Insecure Workload Configurations |
| `DOCKER-SECRET-IN-IMAGE` | HIGH | containers | Secret baked into the image | CWE-798, CWE-538 | A07:2025 |  |
| `DOCKER-SSH-EXPOSED` | MEDIUM | containers | SSH server exposed in container | CWE-668 | A02:2025 |  |
| `DOCKER-UNPINNED-BASE` | MEDIUM | containers | Base image not pinned | CWE-1357 | A03:2025, A08:2025 |  |
| `DOCKER-WORLD-WRITABLE` | MEDIUM | containers | World-writable permissions | CWE-732 | A02:2025 |  |
| `COMPOSE-DATA-PORT-PUBLISHED` | HIGH | data | Database port published on all interfaces | CWE-668 | A02:2025 |  |
| `CTX-BAAS-CLIENT` | INFO | data | Front-end BaaS client with public key (context) |  |  |  |
| `DATA-ATLAS-OPEN-ACCESS-LIST` | CRITICAL | data | MongoDB Atlas access list open to the internet | CWE-668 | A02:2025 |  |
| `DATA-CONNECTION-STRING-CREDS` | CRITICAL | data | Database connection string with embedded password | CWE-798 | A07:2025 |  |
| `DATA-DUMP-COMMITTED` | HIGH | data | Database dump or local database file committed | CWE-538 | A02:2025 | Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-FIREBASE-OPEN-RULES` | CRITICAL | data | Firebase rules allow public read/write | CWE-862, CWE-284 | A01:2025 | Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-MONGODB-EXPOSED` | CRITICAL | data | MongoDB listens on all interfaces without authorization | CWE-306, CWE-668 | A07:2025, A02:2025 |  |
| `DATA-PAYMENT-CARD` | CRITICAL | data | Payment card number in repository | CWE-359 | A04:2025 | PCI DSS 3.4, Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-PII-COMMITTED` | HIGH | data | Personal data committed to the repository | CWE-359, CWE-538 | A02:2025 | Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-POSTGRES-OPEN-HBA` | MEDIUM | data | PostgreSQL accepts logins from any address | CWE-668 | A02:2025 |  |
| `DATA-POSTGRES-TRUST-AUTH` | CRITICAL | data | PostgreSQL trust or cleartext authentication | CWE-287, CWE-319 | A07:2025 |  |
| `DATA-REDIS-EXPOSED` | CRITICAL | data | Redis reachable without authentication | CWE-306, CWE-668 | A07:2025, A02:2025 |  |
| `DATA-SENSITIVE-LOGGED` | MEDIUM | data | Sensitive data written to logs | CWE-532, CWE-359 | A09:2025 | Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-SERVER-HARDENING` | HIGH | data | Database server hardening disabled | CWE-1188, CWE-306 | A02:2025 |  |
| `DATA-SQL-EXCESSIVE-GRANT` | HIGH | data | Excessive SQL privileges | CWE-250, CWE-269 | A01:2025 |  |
| `DATA-SQL-LITERAL-PASSWORD` | HIGH | data | Database user created with a literal password | CWE-798 | A07:2025 |  |
| `DATA-SUPABASE-RLS-MISSING` | CRITICAL | data | Supabase table created without Row Level Security | CWE-862, CWE-284 | A01:2025 | Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-TLS-DISABLED` | HIGH | data | Database connection without TLS | CWE-319 | A04:2025 | Québec Law 25, PIPEDA, GDPR Art. 32 |
| `DATA-TLS-INSECURE` | HIGH | data | Database TLS accepts any certificate | CWE-295 | A04:2025 |  |
| `DEP-LOOKUP-SKIPPED` | INFO | dependencies | Vulnerability lookup skipped |  |  |  |
| `DEP-MALICIOUS` | CRITICAL | dependencies | Known malicious package version | CWE-506 | A03:2025 | CICD-SEC-3 Dependency Chain Abuse |
| `DEP-VULNERABLE` | HIGH | dependencies | Dependency with a known vulnerability | CWE-1395 | A03:2025 | CICD-SEC-3 Dependency Chain Abuse |
| `TF-AUDIT-LOGGING-WEAK` | MEDIUM | iac | Audit trail incomplete | CWE-778 | A09:2025 | CIS AWS Foundations 3.1 |
| `TF-AZURE-KEYVAULT-PURGE` | MEDIUM | iac | Key Vault without purge protection | CWE-404 | A02:2025 |  |
| `TF-AZURE-PUBLIC-BLOB` | CRITICAL | iac | Azure storage allows anonymous blob access | CWE-284 | A01:2025 |  |
| `TF-BACKEND-UNENCRYPTED` | MEDIUM | iac | Remote state backend without encryption | CWE-311 | A04:2025 |  |
| `TF-DATA-NO-BACKUP` | MEDIUM | iac | Data store without backups or recovery protection | CWE-404 | A02:2025 |  |
| `TF-DATA-NO-TLS` | HIGH | iac | Data in transit not forced over TLS | CWE-319 | A04:2025 |  |
| `TF-DATA-UNENCRYPTED` | HIGH | iac | Data store without encryption at rest | CWE-311, CWE-312 | A04:2025 |  |
| `TF-DB-PUBLIC` | CRITICAL | iac | Database instance publicly accessible | CWE-668 | A01:2025 |  |
| `TF-EC2-IMDSV1` | HIGH | iac | EC2 instance metadata v1 allowed | CWE-918, CWE-1188 | A01:2025 |  |
| `TF-FUNCTION-URL-PUBLIC` | HIGH | iac | Function URL with no authentication | CWE-306 | A07:2025 |  |
| `TF-GCP-PRIMITIVE-ROLE` | HIGH | iac | Primitive Owner/Editor role granted | CWE-250 | A01:2025 |  |
| `TF-GCP-PUBLIC-MEMBER` | CRITICAL | iac | Resource granted to allUsers / allAuthenticatedUsers | CWE-284 | A01:2025 |  |
| `TF-HARDCODED-PASSWORD` | HIGH | iac | Literal password in a resource | CWE-798 | A07:2025 |  |
| `TF-IAM-ACCESS-KEY` | MEDIUM | iac | Long-lived IAM user access key managed in code | CWE-798 | A07:2025 | CIS AWS Foundations 1.14 |
| `TF-IAM-ADMIN-ATTACHED` | HIGH | iac | AdministratorAccess / Owner granted directly | CWE-250 | A01:2025 |  |
| `TF-IAM-PRIVESC` | HIGH | iac | IAM permission that enables privilege escalation | CWE-269 | A01:2025 |  |
| `TF-IAM-WILDCARD` | CRITICAL | iac | IAM policy allows every action on every resource | CWE-250, CWE-269 | A01:2025 | CIS AWS Foundations 1.16 |
| `TF-K8S-PUBLIC-ENDPOINT` | MEDIUM | iac | Kubernetes API endpoint public to the internet | CWE-668 | A02:2025 | K06:2025 Overly Exposed Kubernetes Components |
| `TF-KMS-NO-ROTATION` | LOW | iac | KMS key rotation disabled | CWE-320 | A04:2025 | CIS AWS Foundations 3.6 |
| `TF-LB-PLAIN-HTTP` | MEDIUM | iac | Load balancer or CDN serves plain HTTP | CWE-319 | A04:2025 |  |
| `TF-NET-ADMIN-PORT-OPEN` | CRITICAL | iac | Admin port open to the internet | CWE-284, CWE-668 | A02:2025 | CIS AWS Foundations 5.2 |
| `TF-NET-ALL-PORTS-OPEN` | CRITICAL | iac | All ports open to the internet | CWE-284 | A02:2025 |  |
| `TF-NET-DATA-PORT-OPEN` | CRITICAL | iac | Database or cache port open to the internet | CWE-284, CWE-668 | A02:2025 |  |
| `TF-POLICY-PUBLIC-PRINCIPAL` | HIGH | iac | Resource policy grants access to any principal | CWE-284 | A01:2025 |  |
| `TF-PROVIDER-STATIC-KEYS` | CRITICAL | iac | Static credentials in a provider block | CWE-798 | A07:2025 |  |
| `TF-REGISTRY-MUTABLE-TAGS` | LOW | iac | Container registry allows tag overwrite / no scan on push | CWE-494 | A08:2025 |  |
| `TF-S3-BLOCK-PUBLIC-ACCESS-OFF` | HIGH | iac | S3 Block Public Access disabled | CWE-284 | A01:2025 | CIS AWS Foundations 2.1.4 |
| `TF-S3-PUBLIC-ACL` | CRITICAL | iac | S3 bucket readable or writable by everyone | CWE-284, CWE-732 | A01:2025 | CIS AWS Foundations 2.1.4 |
| `TF-STATE-COMMITTED` | CRITICAL | iac | Terraform state file committed | CWE-312, CWE-538 | A04:2025 |  |
| `TF-TFVARS-SECRET` | HIGH | iac | Secret value in a committed .tfvars file | CWE-798 | A07:2025 |  |
| `TF-TLS-OUTDATED` | MEDIUM | iac | Outdated TLS version allowed | CWE-326 | A04:2025 |  |
| `IMG-HISTORY-REMOTE-SCRIPT` | MEDIUM | image | Image built by piping a remote script into a shell | CWE-494 | A03:2025 |  |
| `IMG-NO-HEALTHCHECK` | LOW | image | Image has no HEALTHCHECK | CWE-1188 |  |  |
| `IMG-OS-EOL` | HIGH | image | Base OS release is end-of-life | CWE-1104, CWE-1395 | A06:2025 |  |
| `IMG-PACKAGES-NOT-ANALYSED` | INFO | image | Some packages could not be analysed |  |  |  |
| `IMG-RUNS-AS-ROOT` | MEDIUM | image | Image runs as root by default | CWE-250 | A02:2025 |  |
| `IMG-RUNTIME-EOL` | HIGH | image | Language runtime in the image is end-of-life | CWE-1104 | A06:2025 |  |
| `IMG-SECRET-IN-CONFIG` | HIGH | image | Secret in image environment or build history | CWE-798, CWE-538 | A07:2025 |  |
| `IMG-SECRET-IN-FILE` | HIGH | image | Secret file shipped inside the image | CWE-798, CWE-538 | A07:2025 |  |
| `IMG-SSH-EXPOSED` | MEDIUM | image | Image exposes SSH | CWE-668 | A02:2025 |  |
| `IMG-STALE` | MEDIUM | image | Image has not been rebuilt in over a year | CWE-1104 | A06:2025 |  |
| `IMG-VULNERABLE-PACKAGE` | HIGH | image | Image package with a known vulnerability | CWE-1395 | A03:2025 |  |
| `K8S-CLUSTER-ADMIN-BINDING` | HIGH | kubernetes | Binding to cluster-admin or anonymous users | CWE-269 | A01:2025 | K02:2025 Overly Permissive Authorization Configurations, K06:2025 Overly Exposed Kubernetes Components |
| `K8S-DANGEROUS-CAPS` | HIGH | kubernetes | Dangerous Linux capabilities added | CWE-250 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-HOST-NAMESPACE` | HIGH | kubernetes | Pod shares host namespaces | CWE-668 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-HOSTPATH` | HIGH | kubernetes | hostPath volume | CWE-668 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-NO-SECCOMP` | LOW | kubernetes | No seccomp profile | CWE-693 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-PRIV-ESCALATION` | MEDIUM | kubernetes | Privilege escalation not disabled | CWE-269 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-PRIVILEGED` | CRITICAL | kubernetes | Privileged container | CWE-250 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-RBAC-ESCALATE` | HIGH | kubernetes | RBAC allows escalate/bind/impersonate or pod exec | CWE-269 | A01:2025 | K02:2025 Overly Permissive Authorization Configurations |
| `K8S-RBAC-SECRETS` | MEDIUM | kubernetes | RBAC grants read access to Secrets | CWE-269 | A01:2025 | K02:2025 Overly Permissive Authorization Configurations, K03:2025 Secrets Management Failures |
| `K8S-RBAC-WILDCARD` | CRITICAL | kubernetes | RBAC rule grants every verb on every resource | CWE-269 | A01:2025 | K02:2025 Overly Permissive Authorization Configurations |
| `K8S-RUNS-AS-ROOT` | MEDIUM | kubernetes | Container may run as root | CWE-250 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `K8S-SA-TOKEN-AUTOMOUNT` | LOW | kubernetes | Service account token mounted by default | CWE-668 | A01:2025 | K02:2025 Overly Permissive Authorization Configurations |
| `K8S-SECRET-COMMITTED` | HIGH | kubernetes | Kubernetes Secret with data committed | CWE-312 | A07:2025 | K03:2025 Secrets Management Failures |
| `K8S-SECRET-IN-ENV` | HIGH | kubernetes | Secret value written in the manifest | CWE-798 | A07:2025 | K03:2025 Secrets Management Failures |
| `K8S-SERVICE-EXPOSED` | HIGH | kubernetes | Data service exposed outside the cluster | CWE-668 | A02:2025 | K05:2025 Missing Network Segmentation Controls, K06:2025 Overly Exposed Kubernetes Components |
| `K8S-UNPINNED-IMAGE` | MEDIUM | kubernetes | Image not pinned | CWE-1357 | A03:2025 | K01:2025 Insecure Workload Configurations |
| `K8S-WRITABLE-ROOTFS` | LOW | kubernetes | Root filesystem writable | CWE-732 | A02:2025 | K01:2025 Insecure Workload Configurations, Pod Security Standards (restricted) |
| `AI-UNBOUNDED-GENERATION` | LOW | performance | LLM call with no output limit | CWE-770, CWE-400 |  | LLM10:2025 Unbounded Consumption |
| `DOCKER-IMAGE-BLOAT` | LOW | performance | Image build leaves caches or extra packages |  |  |  |
| `K8S-NO-RESOURCE-LIMITS` | MEDIUM | performance | No CPU/memory requests or limits | CWE-770, CWE-400 | A02:2025 | K01:2025 Insecure Workload Configurations |
| `PERF-HEAVY-IMPORT` | LOW | performance | Whole heavy library imported |  |  |  |
| `PERF-JSON-DEEP-CLONE` | LOW | performance | Deep clone through JSON round-trip |  |  |  |
| `PERF-N-PLUS-ONE` | MEDIUM | performance | Database or network call inside a loop | CWE-1050 |  |  |
| `PERF-NO-TIMEOUT` | MEDIUM | performance | Network call without a timeout | CWE-400, CWE-1088 |  |  |
| `PERF-SYNC-IO-IN-SERVER` | LOW | performance | Blocking I/O in a request path | CWE-1050 |  |  |
| `PERF-UNBOUNDED-QUERY` | LOW | performance | Unbounded query loads an entire collection/table | CWE-770, CWE-400 | A02:2025 |  |
| `PERF-WEB-HEAVY-HTML` | LOW | performance | Large HTML document |  |  |  |
| `PERF-WEB-NO-COMPRESSION` | LOW | performance | Response not compressed |  |  |  |
| `PERF-WEB-SLOW-TTFB` | MEDIUM | performance | Slow time to first byte |  |  |  |
| `K8S-NO-PROBES` | LOW | quality | No readiness/liveness probe | CWE-1188 | A02:2025 |  |
| `QUAL-ASSERT-SECURITY` | MEDIUM | quality | assert used for a security check | CWE-617 | A07:2025 |  |
| `QUAL-BARE-EXCEPT` | LOW | quality | Bare except catches everything | CWE-396 | A10:2025 |  |
| `QUAL-COMPLEXITY` | MEDIUM | quality | Function too complex to review reliably | CWE-1121 | A06:2025 |  |
| `QUAL-FAIL-OPEN` | HIGH | quality | Security check fails open on error | CWE-636, CWE-280 | A10:2025, A07:2025 |  |
| `QUAL-FOREACH-ASYNC` | MEDIUM | quality | async callback inside forEach | CWE-755, CWE-362 | A10:2025 |  |
| `QUAL-LONG-FUNCTION` | LOW | quality | Very long function | CWE-1080 |  |  |
| `QUAL-MUTABLE-DEFAULT` | LOW | quality | Mutable default argument | CWE-1188 |  |  |
| `QUAL-SECURITY-TODO` | LOW | quality | Unfinished security work flagged in a comment | CWE-1164 | A06:2025 |  |
| `QUAL-SWALLOWED-EXCEPTION` | MEDIUM | quality | Exception swallowed silently | CWE-390, CWE-755 | A10:2025 |  |
| `COMPOSE-SECRET-LITERAL` | HIGH | secrets | Credential written in docker-compose | CWE-798 | A07:2025 |  |
| `SEC-ANTHROPIC-KEY` | CRITICAL | secrets | Hard-coded Anthropic API key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-AWS-ACCESS-KEY` | CRITICAL | secrets | Hard-coded AWS access key ID | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-AZURE-STORAGE-KEY` | CRITICAL | secrets | Hard-coded Azure storage account key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-DIGITALOCEAN-TOKEN` | CRITICAL | secrets | Hard-coded DigitalOcean token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-DISCORD-WEBHOOK` | MEDIUM | secrets | Hard-coded Discord webhook | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-DOPPLER-TOKEN` | HIGH | secrets | Hard-coded Doppler token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-ENV-COMMITTED` | HIGH | secrets | Environment file committed to the repository | CWE-538, CWE-798 | A02:2025 |  |
| `SEC-GCP-SERVICE-ACCOUNT` | CRITICAL | secrets | Hard-coded GCP service account key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-GENERIC` | HIGH | secrets | Hard-coded secret in assignment | CWE-798 | A07:2025 |  |
| `SEC-GITHUB-TOKEN` | CRITICAL | secrets | Hard-coded GitHub token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-GITLAB-TOKEN` | CRITICAL | secrets | Hard-coded GitLab personal access token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-GOOGLE-API-KEY` | HIGH | secrets | Hard-coded Google API key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-HUGGINGFACE-TOKEN` | HIGH | secrets | Hard-coded Hugging Face token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-JWT` | MEDIUM | secrets | Hard-coded JSON Web Token | CWE-798 | A07:2025 |  |
| `SEC-KEY-FILE` | CRITICAL | secrets | Key or credential file committed | CWE-312, CWE-798 | A04:2025 |  |
| `SEC-MAILGUN-KEY` | HIGH | secrets | Hard-coded Mailgun API key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-NPM-TOKEN` | CRITICAL | secrets | Hard-coded npm access token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-NPMRC-TOKEN` | CRITICAL | secrets | Registry auth token in .npmrc / .pypirc | CWE-798 | A07:2025 |  |
| `SEC-OPENAI-KEY` | CRITICAL | secrets | Hard-coded OpenAI API key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-PRIVATE-KEY` | CRITICAL | secrets | Hard-coded Private key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-PYPI-TOKEN` | CRITICAL | secrets | Hard-coded PyPI upload token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-RESEND-KEY` | HIGH | secrets | Hard-coded Resend API key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-SENDGRID-KEY` | HIGH | secrets | Hard-coded SendGrid API key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-SHOPIFY-TOKEN` | HIGH | secrets | Hard-coded Shopify access token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-SLACK-TOKEN` | HIGH | secrets | Hard-coded Slack token | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-SLACK-WEBHOOK` | MEDIUM | secrets | Hard-coded Slack incoming webhook | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-STRIPE-LIVE` | CRITICAL | secrets | Hard-coded Stripe live secret key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-STRIPE-TEST` | LOW | secrets | Hard-coded Stripe test secret key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-STRIPE-WEBHOOK` | HIGH | secrets | Hard-coded Stripe webhook signing secret | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-SUPABASE-SERVICE` | CRITICAL | secrets | Hard-coded Supabase service-role key | CWE-798 | A07:2025, A04:2025 |  |
| `SEC-TWILIO-KEY` | HIGH | secrets | Hard-coded Twilio API key | CWE-798 | A07:2025, A04:2025 |  |
| `SUPPLY-DEPENDENCY-CONFUSION` | HIGH | supply-chain | Extra package index allows dependency confusion | CWE-427 | A03:2025 |  |
| `SUPPLY-INSECURE-REGISTRY` | HIGH | supply-chain | Packages fetched over plain HTTP | CWE-319, CWE-494 | A03:2025, A08:2025 |  |
| `SUPPLY-INSTALL-SCRIPT` | HIGH | supply-chain | Lifecycle script downloads or executes remote code | CWE-494, CWE-829 | A03:2025, A08:2025 | CICD-SEC-3 Dependency Chain Abuse |
| `SUPPLY-NO-LOCKFILE` | MEDIUM | supply-chain | Manifest without a committed lockfile | CWE-1357 | A03:2025 |  |
| `SUPPLY-TYPOSQUAT` | HIGH | supply-chain | Dependency name one edit away from a popular package | CWE-1357 | A03:2025 |  |
| `SUPPLY-UNPINNED` | MEDIUM | supply-chain | Dependency resolved from a mutable source | CWE-1357, CWE-829 | A03:2025 |  |
| `WEB-CACHE-SENSITIVE` | LOW | web | Authenticated response may be cached by shared caches | CWE-524 | A02:2025 |  |
| `WEB-CERT-EXPIRY` | MEDIUM | web | TLS certificate close to expiry | CWE-298 | A04:2025 |  |
| `WEB-CLICKJACKING` | MEDIUM | web | Page can be framed by any site | CWE-1021 | A02:2025 |  |
| `WEB-COOKIE-FLAGS` | MEDIUM | web | Cookie without Secure / HttpOnly / SameSite | CWE-614, CWE-1004, CWE-1275 | A07:2025 |  |
| `WEB-CORS-WILDCARD` | MEDIUM | web | CORS allows any origin | CWE-942 | A02:2025 |  |
| `WEB-CSP` | MEDIUM | web | Content-Security-Policy missing or permissive | CWE-1021 | A05:2025 |  |
| `WEB-HSTS` | MEDIUM | web | Strict-Transport-Security missing or weak | CWE-319 | A04:2025 |  |
| `WEB-NO-HTTPS-REDIRECT` | HIGH | web | HTTP not redirected to HTTPS | CWE-319 | A04:2025 |  |
| `WEB-NOSNIFF` | LOW | web | X-Content-Type-Options missing | CWE-693 | A02:2025 |  |
| `WEB-PERMISSIONS-POLICY` | INFO | web | Permissions-Policy missing | CWE-693 | A02:2025 |  |
| `WEB-REFERRER-POLICY` | LOW | web | Referrer-Policy missing or leaky | CWE-200 | A02:2025 |  |
| `WEB-SECURITY-TXT` | INFO | web | No security.txt | CWE-1059 | A02:2025 |  |
| `WEB-TLS-WEAK` | HIGH | web | Weak TLS configuration | CWE-326 | A04:2025 |  |
| `WEB-VERSION-DISCLOSURE` | LOW | web | Server software and version disclosed | CWE-200 | A02:2025 |  |
