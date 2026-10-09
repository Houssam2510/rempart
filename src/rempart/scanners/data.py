"""Data-layer security: how databases, data stores and personal data are
configured, connected to and handled.

Exposed, unauthenticated data stores are still compromised within days of
going online (Flare counted ~1,400 wiped-and-ransomed MongoDB servers in early
2026). Backend-as-a-service rules (Supabase RLS, Firebase rules) are the
modern equivalent: one missing policy publishes a table to every visitor.
Privacy tags reference Québec Law 25, PIPEDA and GDPR.
"""

from __future__ import annotations

import os
import re
from typing import Iterator

from rempart.engine import ScanContext, is_comment
from rempart.scanners.secrets import entropy
from rempart.models import Finding, Severity
from rempart.registry import A01, A02, A04, A07, A09, C, H, L, M, rule

PRIVACY = ("Québec Law 25", "PIPEDA", "GDPR Art. 32")

R_CONN = rule("DATA-CONNECTION-STRING-CREDS", "Database connection string with embedded password", C, "data", cwe="CWE-798", owasp=A07,
              fix="Read the URL from the environment / a secret manager, rotate the exposed password, and use a least-privilege database user per service.")
R_NO_TLS = rule("DATA-TLS-DISABLED", "Database connection without TLS", H, "data", cwe="CWE-319", owasp=A04, frameworks=PRIVACY,
                fix="Use sslmode=verify-full (Postgres), tls=true with certificate validation (MongoDB/Redis), useSSL=true&requireSSL=true (MySQL).")
R_TLS_INVALID = rule("DATA-TLS-INSECURE", "Database TLS accepts any certificate", H, "data", cwe="CWE-295", owasp=A04,
                     fix="Remove tlsAllowInvalidCertificates/tlsInsecure and provide the CA file instead.")
R_MONGO = rule("DATA-MONGODB-EXPOSED", "MongoDB listens on all interfaces without authorization", C, "data", cwe=("CWE-306", "CWE-668"), owasp=(A07, A02),
               fix="Set security.authorization: enabled, bind to private interfaces only, and firewall port 27017. Unauthenticated MongoDB is wiped and ransomed automatically.")
R_REDIS = rule("DATA-REDIS-EXPOSED", "Redis reachable without authentication", C, "data", cwe=("CWE-306", "CWE-668"), owasp=(A07, A02),
               fix="Keep protected-mode yes, bind to 127.0.0.1/private IPs, set requirepass or ACL users, and disable CONFIG/MODULE for app users.")
R_PG_TRUST = rule("DATA-POSTGRES-TRUST-AUTH", "PostgreSQL trust or cleartext authentication", C, "data", cwe=("CWE-287", "CWE-319"), owasp=A07,
                  fix="Use scram-sha-256 in pg_hba.conf and restrict address ranges to the application network.")
R_PG_OPEN = rule("DATA-POSTGRES-OPEN-HBA", "PostgreSQL accepts logins from any address", M, "data", cwe="CWE-668", owasp=A02,
                 fix="Restrict pg_hba.conf address ranges to known application subnets and require hostssl.")
R_DB_CONF = rule("DATA-SERVER-HARDENING", "Database server hardening disabled", H, "data", cwe=("CWE-1188", "CWE-306"), owasp=A02,
                 fix="Re-enable the security feature (authentication, grants, TLS) and restrict network binding.")
R_SUPABASE_RLS = rule("DATA-SUPABASE-RLS-MISSING", "Supabase table created without Row Level Security", C, "data", cwe=("CWE-862", "CWE-284"), owasp=A01, frameworks=PRIVACY,
                      fix="Run `alter table <t> enable row level security;` and add explicit policies. Without RLS, the public anon key can read and write the whole table.",
                      confidence=0.75)
R_FIREBASE = rule("DATA-FIREBASE-OPEN-RULES", "Firebase rules allow public read/write", C, "data", cwe=("CWE-862", "CWE-284"), owasp=A01, frameworks=PRIVACY,
                  fix="Require request.auth != null and check ownership (request.auth.uid == resource.data.ownerId) per collection.")
R_ATLAS = rule("DATA-ATLAS-OPEN-ACCESS-LIST", "MongoDB Atlas access list open to the internet", C, "data", cwe="CWE-668", owasp=A02,
               fix="Allow only your application egress IPs or use private endpoints / VPC peering.")
R_SQL_GRANT = rule("DATA-SQL-EXCESSIVE-GRANT", "Excessive SQL privileges", H, "data", cwe=("CWE-250", "CWE-269"), owasp=A01,
                   fix="Grant the application user only SELECT/INSERT/UPDATE/DELETE on its own schema. Never grant to PUBLIC or '%' with ALL.")
R_SQL_PASSWORD = rule("DATA-SQL-LITERAL-PASSWORD", "Database user created with a literal password", H, "data", cwe="CWE-798", owasp=A07,
                      fix="Create users with passwords injected at deploy time, not stored in migrations.")
R_LOG_PII = rule("DATA-SENSITIVE-LOGGED", "Sensitive data written to logs", M, "data", cwe=("CWE-532", "CWE-359"), owasp=A09, frameworks=PRIVACY,
                 fix="Log identifiers, not secrets or personal data. Add a redaction layer (pino redact, structlog processors) for tokens, passwords, emails and card data.",
                 confidence=0.6)
R_PII_FILE = rule("DATA-PII-COMMITTED", "Personal data committed to the repository", H, "data", cwe=("CWE-359", "CWE-538"), owasp=A02, frameworks=PRIVACY,
                  fix="Remove the dataset from git history, use synthetic or anonymised fixtures, and record the exposure as a privacy incident if the data is real.")
R_CARD = rule("DATA-PAYMENT-CARD", "Payment card number in repository", C, "data", cwe="CWE-359", owasp=A04, frameworks=("PCI DSS 3.4",) + PRIVACY,
              fix="Never store PANs. Use your processor's tokens (Stripe PaymentMethod IDs).")
R_DUMP = rule("DATA-DUMP-COMMITTED", "Database dump or local database file committed", H, "data", cwe="CWE-538", owasp=A02, frameworks=PRIVACY,
              fix="Remove it from history and keep dumps in encrypted, access-controlled storage.")
R_UNBOUNDED = rule("PERF-UNBOUNDED-QUERY", "Unbounded query loads an entire collection/table", L, "performance", cwe=("CWE-770", "CWE-400"), owasp=A02,
                   fix="Paginate (limit/cursor) and select only needed columns. Unbounded reads grow linearly with data and become an outage and a DoS vector.",
                   confidence=0.5)

_CONN = re.compile(r"\b(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver|clickhouse|cockroachdb|neo4j(?:\+s)?)://([^:/\s@'\"`]+):([^@\s'\"`]+)@([^/\s'\"`?:]+)")
_PLACEHOLDER = re.compile(r"(?i)^(?:\$\{?.*|<.*>|\[.*\]|\*+|x+|\.{3,}|password|pass|pwd|secret|changeme|example|user|admin|root|test|token|\{.*\}|%s|:\w+|your[\w-]*|my[\w-]*password)$")
# an all-caps word (TOKEN, YOUR_PASSWORD, DB_PASS) is documentation, not a credential
_UPPER_PLACEHOLDER = re.compile(r"^[A-Z][A-Z0-9_\-]{2,}$")
_PLACEHOLDER_HOST = re.compile(r"(?i)x{3,}|example|your[-_]|<|\[|\{")
_LOCAL_HOSTS = re.compile(r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|db|database|postgres|mongo|mongodb|redis|mysql|mariadb|host\.docker\.internal|\w+-db)$")
_LOG_CALL = re.compile(r"\b(?:console\.(?:log|info|warn|error|debug)|logger\.\w+|logging\.\w+|log\.(?:info|debug|warn|warning|error)|print|println!?|fmt\.Print\w*|System\.out\.print\w*)\s*\(")
_SENSITIVE_VAR = re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|access_?token|refresh_?token|authorization|api_?key|apikey|ssn|sin|credit_?card|card_?number|cvv|private_?key)\b|req\.headers|request\.headers|req\.body|request\.body")
_STR = re.compile(r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs", ".md")
# A line that defines a detection pattern is not a connection being made.
_PATTERN_LINE = re.compile(r"""re\.(?:compile|search|match|findall|finditer|sub)\(|new RegExp\(|\bregex\b|\bpattern\b""")
TEST_CARDS = {"4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222", "5200828282828210", "378282246310005", "371449635398431",
              "6011111111111117", "3056930009020004", "36227206271667", "3566002020360505", "6200000000000005", "4111111111111111", "4000000000000002"}


def luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


class DataScanner:
    name = "data"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        supabase_sql: list[str] = []
        for rel in ctx.files:
            base = os.path.basename(rel).lower()
            text = ctx.text(rel)
            if base.endswith((".sqlite", ".sqlite3", ".db", ".dump", ".bak", ".bson")) or re.search(r"\.(?:sql\.gz|dump\.gz|bak\.gz)$", base):
                if ctx.is_committed(rel):
                    yield Finding(R_DUMP, rel, 1, f"{base} is a database file or dump in the repository.", snippet=base)
                continue
            if text is None:
                continue
            if base.endswith(".sql") and re.search(r"(?:^|/)supabase/", rel):
                supabase_sql.append(rel)
            yield from self.connection_strings(ctx, rel)
            if not base.endswith(_SOURCE_SUFFIXES):
                yield from self.server_configs(ctx, rel, base, text)
            if base in ("firestore.rules", "storage.rules", "database.rules.json") or base.endswith(".rules"):
                yield from self.firebase(ctx, rel)
            if base.endswith(".sql"):
                yield from self.sql(ctx, rel)
            if base.endswith(".tf") and "mongodbatlas_project_ip_access_list" in text:
                for i, line in enumerate(ctx.lines(rel), 1):
                    if re.search(r'cidr_block\s*=\s*"0\.0\.0\.0/0"|ip_address\s*=\s*"0\.0\.0\.0"', line):
                        yield Finding(R_ATLAS, rel, i, "Atlas access list allows 0.0.0.0/0.", snippet=line.strip())
            if base.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue", ".py", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs")):
                yield from self.code_data_handling(ctx, rel)
            if base.endswith((".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".sql", ".txt", ".xml", ".yaml", ".yml")) and ctx.is_committed(rel):
                yield from self.pii_in_data(ctx, rel, text)
        if supabase_sql:
            yield from self.supabase_rls(ctx, supabase_sql)

    def connection_strings(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        for i, line in enumerate(ctx.lines(rel), 1):
            if len(line) > 2000 or _PATTERN_LINE.search(line):
                continue
            for m in _CONN.finditer(line):
                scheme, user, pwd, host = m.groups()
                if _PLACEHOLDER.match(pwd) or _UPPER_PLACEHOLDER.match(pwd) or pwd.startswith(("${", "$(", "{{")) \
                        or _PLACEHOLDER_HOST.search(host) or _PLACEHOLDER_HOST.search(user):
                    continue
                local = bool(_LOCAL_HOSTS.match(host.lower()))
                if local and (re.search(r"(?i)\.(?:example|sample|template|dist)$|(?:^|/)docs?/|\.md$|readme|\.github/workflows/|scripts?/|seed|e2e|test", rel)
                              or len(pwd) < 12 or entropy(pwd) < 3.5):
                    continue  # a local database with a local password: not a leaked production credential
                sev = Severity.MEDIUM if local else None
                f = Finding(R_CONN, rel, i, f"{scheme} URL for host `{host}` embeds the password.",
                            snippet=line.strip().replace(pwd, "****")[:200], extra={"anchor": f"{scheme}:{user}@{host}"})
                if sev is not None:
                    f.severity, f.confidence = sev, 0.6
                yield f
            if re.search(r"(?i)sslmode=disable|[?&](?:ssl|tls|useSSL)=false\b|sslmode\s*[:=]\s*['\"]disable['\"]", line):
                yield Finding(R_NO_TLS, rel, i, "Database connection explicitly without TLS.", snippet=_mask(line))
            elif re.search(r"\bssl\s*:\s*false\b", _STR.sub("''", line)) and re.search(r"(?i)db|database|pg|postgres|mysql|mongo|redis|knex|sequelize|typeorm|connection|pool", line):
                yield Finding(R_NO_TLS, rel, i, "Database client configured with ssl: false.", snippet=_mask(line))
            if re.search(r"(?i)tlsAllowInvalid(?:Certificates|Hostnames)\s*[=:]\s*true|tlsInsecure\s*[=:]\s*true|sslValidate\s*[=:]\s*false", line):
                yield Finding(R_TLS_INVALID, rel, i, "TLS certificate validation disabled for the database.", snippet=_mask(line))

    def server_configs(self, ctx: ScanContext, rel: str, base: str, text: str) -> Iterator[Finding]:
        lines = text.splitlines()

        def first(rx: str) -> int:
            return next((i for i, l in enumerate(lines, 1) if re.search(rx, l)), 1)

        if base in ("mongod.conf", "mongodb.conf") or (base.endswith((".conf", ".yaml", ".yml")) and "bindIp" in text and "net:" in text):
            open_bind = re.search(r"bindIp\s*:\s*['\"]?(?:0\.0\.0\.0|::|\*)|bindIpAll\s*:\s*true", text)
            auth_on = re.search(r"authorization\s*:\s*['\"]?enabled", text)
            if open_bind and not auth_on:
                yield Finding(R_MONGO, rel, first(r"bindIp"), "Bound to all interfaces with authorization not enabled.", snippet="bindIp: 0.0.0.0")
        if re.search(r"mongod\b[^\n]*--bind_ip_all", text) and "--auth" not in text and "MONGO_INITDB_ROOT_PASSWORD" not in text:
            yield Finding(R_MONGO, rel, first(r"--bind_ip_all"), "mongod started with --bind_ip_all and no --auth.", snippet="--bind_ip_all")
        if base == "redis.conf" or base.endswith("redis.conf"):
            if re.search(r"(?m)^\s*protected-mode\s+no", text):
                no_pass = not re.search(r"(?m)^\s*requirepass\s+\S+|^\s*user\s+\S+\s+on\s+", text)
                sev = Severity.CRITICAL if no_pass else Severity.HIGH
                f = Finding(R_REDIS, rel, first(r"protected-mode"), "protected-mode no" + (" and no requirepass/ACL." if no_pass else "."), snippet="protected-mode no")
                f.severity = sev
                yield f
            elif re.search(r"(?m)^\s*bind\s+(?:0\.0\.0\.0|\*)", text) and not re.search(r"(?m)^\s*requirepass\s+\S+", text):
                yield Finding(R_REDIS, rel, first(r"^\s*bind"), "Bound to all interfaces without requirepass.", snippet="bind 0.0.0.0")
        if re.search(r"redis-server\b[^\n]*--protected-mode\s+no", text):
            yield Finding(R_REDIS, rel, first(r"--protected-mode"), "redis-server started with --protected-mode no.", snippet="--protected-mode no")
        if base == "pg_hba.conf":
            for i, line in enumerate(lines, 1):
                s = line.split("#", 1)[0].split()
                if len(s) < 4:
                    continue
                method = s[-1] if "=" not in s[-1] else (s[-2] if len(s) > 4 else s[-1])
                conn_type = s[0]
                if method == "trust" and conn_type.startswith("host"):
                    yield Finding(R_PG_TRUST, rel, i, "Network connections accepted with no password (trust).", snippet=line.strip())
                elif method == "password":
                    yield Finding(R_PG_TRUST, rel, i, "Cleartext password authentication.", snippet=line.strip(), severity=Severity.HIGH)
                if conn_type.startswith("host") and any(a in ("0.0.0.0/0", "::/0", "all") for a in s[3:4]):
                    yield Finding(R_PG_OPEN, rel, i, "Address range allows any client.", snippet=line.strip())
                if method == "md5":
                    yield Finding(R_PG_TRUST, rel, i, "md5 auth: prefer scram-sha-256.", snippet=line.strip(), severity=Severity.LOW, confidence=0.6)
        if base == "postgresql.conf" and re.search(r"(?m)^\s*ssl\s*=\s*off", text):
            yield Finding(R_NO_TLS, rel, first(r"^\s*ssl\s*="), "PostgreSQL server TLS off.", snippet="ssl = off")
        if base in ("my.cnf", "mysqld.cnf", "my.ini") or base.endswith(".cnf"):
            if re.search(r"(?m)^\s*skip[-_]grant[-_]tables", text):
                yield Finding(R_DB_CONF, rel, first(r"skip.grant.tables"), "skip-grant-tables disables all authentication.", snippet="skip-grant-tables", severity=Severity.CRITICAL)
            if re.search(r"(?m)^\s*local[-_]infile\s*=\s*(?:1|ON)", text):
                yield Finding(R_DB_CONF, rel, first(r"local.infile"), "local_infile lets clients read server-side files via LOAD DATA.", snippet="local-infile=1", severity=Severity.MEDIUM)
        if base in ("elasticsearch.yml", "opensearch.yml"):
            if re.search(r"xpack\.security\.enabled\s*:\s*false|plugins\.security\.disabled\s*:\s*true", text):
                yield Finding(R_DB_CONF, rel, first(r"security"), "Cluster security plugin disabled.", snippet="security disabled")
        if base.startswith(("docker-compose", "compose")) or base == "dockerfile" or base.endswith((".env.example", ".yml", ".yaml")):
            if re.search(r"xpack\.security\.enabled[=:]\s*['\"]?false", text):
                yield Finding(R_DB_CONF, rel, first(r"xpack\.security\.enabled"), "Elasticsearch started with security disabled.", snippet="xpack.security.enabled=false")
            if re.search(r"ALLOW_EMPTY_PASSWORD[=:]\s*['\"]?yes|MYSQL_ALLOW_EMPTY_PASSWORD[=:]\s*['\"]?(?:yes|true|1)|POSTGRES_HOST_AUTH_METHOD[=:]\s*['\"]?trust", text):
                yield Finding(R_DB_CONF, rel, first(r"EMPTY_PASSWORD|HOST_AUTH_METHOD"), "Database container allows passwordless access.", snippet="empty password / trust")

    def firebase(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        for i, line in enumerate(ctx.lines(rel), 1):
            if re.search(r"allow\s+[\w, ]*(?:read|write|create|update|delete|get|list)[\w, ]*\s*(?::\s*if\s+true\s*;|;)", line) or re.search(r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")", line):
                yield Finding(R_FIREBASE, rel, i, "Rule grants access unconditionally.", snippet=line.strip())
            elif re.search(r"if\s+request\.time\s*<\s*timestamp\.date\(", line):
                yield Finding(R_FIREBASE, rel, i, "Test-mode rule (open until a date).", snippet=line.strip(), severity=Severity.HIGH)

    def sql(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        for i, line in enumerate(ctx.lines(rel), 1):
            if re.search(r"(?i)GRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+(?:\*\.\*|ALL\s+TABLES|DATABASE|SCHEMA)\b|GRANT\s+[^;]*\bTO\s+PUBLIC\b|TO\s+'[^']+'@'%'[^;]*WITH\s+GRANT\s+OPTION", line):
                yield Finding(R_SQL_GRANT, rel, i, "Broad grant.", snippet=line.strip()[:200])
            if re.search(r"(?i)(?:CREATE|ALTER)\s+(?:USER|ROLE)\s+[^;]*(?:IDENTIFIED\s+BY|PASSWORD)\s+'[^']{4,}'", line):
                yield Finding(R_SQL_PASSWORD, rel, i, "Literal password in SQL.", snippet=re.sub(r"'[^']*'\s*;?$", "'****';", line.strip())[:200])

    def supabase_rls(self, ctx: ScanContext, files: list[str]) -> Iterator[Finding]:
        alltext = "\n".join((ctx.text(f) or "") for f in files).lower()
        for rel in files:
            for i, line in enumerate(ctx.lines(rel), 1):
                m = re.search(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?public\"?\.)?\"?([a-z_][\w]*)\"?", line)
                if not m or re.search(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?\"?(?:auth|storage|private|internal|extensions)\"?\.", line):
                    continue
                table = m.group(1).lower()
                if not re.search(rf"alter\s+table\s+(?:only\s+)?(?:\"?public\"?\.)?\"?{re.escape(table)}\"?\s+enable\s+row\s+level\s+security", alltext):
                    yield Finding(R_SUPABASE_RLS, rel, i, f"Table `{table}` has no `enable row level security` in any migration.", snippet=line.strip()[:200])

    def code_data_handling(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        for i, line in enumerate(ctx.lines(rel), 1):
            if len(line) > 1000 or is_comment(line):
                continue
            if _LOG_CALL.search(line):
                code_only = _STR.sub("''", line)
                m = _SENSITIVE_VAR.search(code_only)
                if m:
                    yield Finding(R_LOG_PII, rel, i, f"Log call includes `{m.group(0)}`.", snippet=line.strip()[:200])
            if re.search(r"\.find\(\s*(?:\{\s*\})?\s*\)\s*(?:\.toArray\(\)|;|$)", line) and ".limit(" not in line and "cursor" not in line.lower():
                yield Finding(R_UNBOUNDED, rel, i, "find() with no filter or limit.", snippet=line.strip()[:200])
            elif re.search(r"\.findMany\(\s*\)", line):
                yield Finding(R_UNBOUNDED, rel, i, "findMany() with no take/where.", snippet=line.strip()[:200])
            elif re.search(r"(?i)[\"'`]\s*SELECT\s+\*\s+FROM\s+\w+\s*;?\s*[\"'`]", line):
                yield Finding(R_UNBOUNDED, rel, i, "SELECT * with no WHERE/LIMIT.", snippet=line.strip()[:200])

    def pii_in_data(self, ctx: ScanContext, rel: str, text: str) -> Iterator[Finding]:
        if os.path.basename(rel) in ("package.json", "package-lock.json", "tsconfig.json", "composer.json", "pnpm-lock.yaml") or len(text) < 200:
            return
        emails = {e.lower() for e in _EMAIL.findall(text)}
        emails = {e for e in emails if not re.search(r"@(?:example\.(?:com|org|net)|test\.com|localhost|users\.noreply\.github\.com|email\.com|domain\.com|acme\.\w+)$", e)
                  and not e.endswith((".png", ".jpg", ".svg", ".webp"))}
        if len(emails) >= 25:
            yield Finding(R_PII_FILE, rel, 1, f"{len(emails)} distinct email addresses in a committed data file.", snippet=os.path.basename(rel))
        for i, line in enumerate(text.splitlines(), 1):
            for m in _CARD.finditer(line):
                digits = re.sub(r"\D", "", m.group(0))
                if 13 <= len(digits) <= 19 and luhn(digits) and digits not in TEST_CARDS and re.match(r"^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))", digits) and len(set(digits)) > 3:
                    yield Finding(R_CARD, rel, i, f"Luhn-valid card number ({digits[:4]}…{digits[-4:]}).", snippet=f"{digits[:4]}********{digits[-4:]}")
                    return


def _mask(line: str) -> str:
    return re.sub(r"://([^:/\s@]+):([^@\s]+)@", r"://\1:****@", line.strip())[:200]
