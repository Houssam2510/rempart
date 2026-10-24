"""Terraform misconfiguration checks for AWS, GCP and Azure.

A small brace-matching block reader replaces a full HCL parser: every check
looks at one resource body, which is all these rules need. Rules target the
misconfigurations that dominate real cloud incidents: public storage,
internet-exposed admin and database ports, wildcard IAM, unencrypted data
stores, IMDSv1 (the SSRF-to-credentials path), and missing audit trails.

Values (AUDIT.md R7): before the checks run, `var.x`, `local.x` and, inside a
`dynamic` block, `<iterator>.value.x` are replaced by their value when it is known
in simple cases: a variable's default (merged over `optional(type, default)` in its
object type) or a committed terraform.tfvars / *.auto.tfvars value in the same
directory, a local that is a literal or one of these, `[ref]`, `ref.attr` and
`lookup(ref, "key", default)`. A check that still reads an unresolved value says so
and is capped at MEDIUM with confidence 0.5: an unknown value is never a HIGH.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from rempart.engine import ScanContext, line_of
from rempart.models import Finding, Rule, Severity
from rempart.registry import A01, A02, A04, A07, A08, A09, C, H, L, M, rule

CIS = "CIS AWS Foundations"


def r(id: str, title: str, sev, fix: str, cwe="CWE-16", owasp=A02, fw: tuple[str, ...] = (), conf: float = 0.85) -> Rule:
    return rule(id, title, sev, "iac", cwe=cwe, owasp=owasp, frameworks=fw, fix=fix, confidence=conf)


R_STATE = r("TF-STATE-COMMITTED", "Terraform state file committed", C,
            "State files hold every resource attribute in plaintext, including generated passwords and keys. Remove it from git and its history, store state in an encrypted remote backend, and rotate the secrets it contained.",
            cwe=("CWE-312", "CWE-538"), owasp=A04)
R_TFVARS = r("TF-TFVARS-SECRET", "Secret value in a committed .tfvars file", H,
             "Pass secrets through TF_VAR_* environment variables or a secret manager data source, and mark variables `sensitive = true`.",
             cwe="CWE-798", owasp=A07)
R_PROVIDER_KEYS = r("TF-PROVIDER-STATIC-KEYS", "Static credentials in a provider block", C,
                    "Use the default credential chain, an assumed role, or OIDC workload identity. Never write keys in configuration.",
                    cwe="CWE-798", owasp=A07)
R_BACKEND = r("TF-BACKEND-UNENCRYPTED", "Remote state backend without encryption", M, "Set `encrypt = true` (and a KMS key) on the S3 backend.", cwe="CWE-311", owasp=A04)
R_S3_PUBLIC = r("TF-S3-PUBLIC-ACL", "S3 bucket readable or writable by everyone", C,
                "Remove public ACLs, enable all four Block Public Access settings, and serve public content through CloudFront with origin access control.",
                cwe=("CWE-284", "CWE-732"), owasp=A01, fw=(f"{CIS} 2.1.4",))
R_S3_PAB = r("TF-S3-BLOCK-PUBLIC-ACCESS-OFF", "S3 Block Public Access disabled", H,
             "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.", cwe="CWE-284", owasp=A01, fw=(f"{CIS} 2.1.4",))
R_POLICY_PUBLIC = r("TF-POLICY-PUBLIC-PRINCIPAL", "Resource policy grants access to any principal", H,
                    "Replace Principal \"*\" with specific accounts or roles, or add restrictive conditions (aws:SourceArn, aws:PrincipalOrgID).", cwe="CWE-284", owasp=A01, conf=0.7)
R_OPEN_ADMIN = r("TF-NET-ADMIN-PORT-OPEN", "Admin port open to the internet", C,
                 "Restrict SSH/RDP to a VPN or bastion CIDR, or remove the rule and use SSM Session Manager / IAP.",
                 cwe=("CWE-284", "CWE-668"), owasp=A02, fw=(f"{CIS} 5.2",))
R_OPEN_DB = r("TF-NET-DATA-PORT-OPEN", "Database or cache port open to the internet", C,
              "Data stores must sit in private subnets. Allow only the application's security group as a source.",
              cwe=("CWE-284", "CWE-668"), owasp=A02)
R_OPEN_ALL = r("TF-NET-ALL-PORTS-OPEN", "All ports open to the internet", C, "Open only the ports the service needs, to the sources that need them.", cwe="CWE-284", owasp=A02)
R_IAM_WILDCARD = r("TF-IAM-WILDCARD", "IAM policy allows every action on every resource", C,
                   "Grant the specific actions and resource ARNs the workload uses. Use IAM Access Analyzer to generate a least-privilege policy from activity.",
                   cwe=("CWE-250", "CWE-269"), owasp=A01, fw=(f"{CIS} 1.16",))
R_IAM_ESCALATION = r("TF-IAM-PRIVESC", "IAM permission that enables privilege escalation", H,
                     "Scope iam:PassRole, iam:*Policy*, sts:AssumeRole and lambda/ec2 create-and-pass combinations to named resources and add conditions.",
                     cwe="CWE-269", owasp=A01, conf=0.7)
R_IAM_ADMIN = r("TF-IAM-ADMIN-ATTACHED", "AdministratorAccess / Owner granted directly", H,
                "Grant admin through short-lived, MFA-protected role assumption, not standing attachments to users or workloads.", cwe="CWE-250", owasp=A01)
R_IAM_USER_KEY = r("TF-IAM-ACCESS-KEY", "Long-lived IAM user access key managed in code", M,
                   "Prefer roles and OIDC federation. If a key is unavoidable, rotate it and never output it.", cwe="CWE-798", owasp=A07, fw=(f"{CIS} 1.14",))
R_DB_PUBLIC = r("TF-DB-PUBLIC", "Database instance publicly accessible", C, "Set publicly_accessible = false and reach the database through private networking.", cwe="CWE-668", owasp=A01)
R_DB_UNENCRYPTED = r("TF-DATA-UNENCRYPTED", "Data store without encryption at rest", H,
                     "Enable encryption at rest (storage_encrypted / encrypted / server_side_encryption) with a customer-managed KMS key for sensitive data.",
                     cwe=("CWE-311", "CWE-312"), owasp=A04)
R_DB_BACKUP = r("TF-DATA-NO-BACKUP", "Data store without backups or recovery protection", M,
                "Keep automated backups (retention ≥ 7 days), point-in-time recovery and deletion protection on stateful resources.", cwe="CWE-404", owasp=A02, conf=0.7)
R_TRANSIT = r("TF-DATA-NO-TLS", "Data in transit not forced over TLS", H,
              "Require TLS 1.2+ (require_ssl, enforce_https, https_traffic_only_enabled, aws:SecureTransport deny statement).", cwe="CWE-319", owasp=A04)
R_IMDS = r("TF-EC2-IMDSV1", "EC2 instance metadata v1 allowed", H,
           "Set metadata_options { http_tokens = \"required\" }. IMDSv1 turns any SSRF into stolen instance credentials (the 2019 Capital One path).",
           cwe=("CWE-918", "CWE-1188"), owasp=A01)
R_TRAIL = r("TF-AUDIT-LOGGING-WEAK", "Audit trail incomplete", M, "Enable multi-region CloudTrail with log file validation and KMS encryption; ship logs to a separate account.",
            cwe="CWE-778", owasp=A09, fw=(f"{CIS} 3.1",))
R_KMS_ROTATE = r("TF-KMS-NO-ROTATION", "KMS key rotation disabled", L, "Set enable_key_rotation = true.", cwe="CWE-320", owasp=A04, fw=(f"{CIS} 3.6",))
R_LAMBDA_URL = r("TF-FUNCTION-URL-PUBLIC", "Function URL with no authentication", H, "Use authorization_type = \"AWS_IAM\" or put an authenticated API gateway in front.", cwe="CWE-306", owasp=A07)
R_K8S_PUBLIC = r("TF-K8S-PUBLIC-ENDPOINT", "Kubernetes API endpoint public to the internet", M, "Disable the public endpoint or restrict it to known CIDRs.", cwe="CWE-668", owasp=A02, fw=("K06:2025 Overly Exposed Kubernetes Components",))
R_HTTP_LISTENER = r("TF-LB-PLAIN-HTTP", "Load balancer or CDN serves plain HTTP", M, "Redirect HTTP to HTTPS and use a modern TLS policy.", cwe="CWE-319", owasp=A04)
R_OLD_TLS = r("TF-TLS-OUTDATED", "Outdated TLS version allowed", M, "Require TLS 1.2 or newer.", cwe="CWE-326", owasp=A04)
R_ECR = r("TF-REGISTRY-MUTABLE-TAGS", "Container registry allows tag overwrite / no scan on push", L, "Set image_tag_mutability = \"IMMUTABLE\" and enable scan on push.", cwe="CWE-494", owasp=A08, conf=0.7)
R_GCS_PUBLIC = r("TF-GCP-PUBLIC-MEMBER", "Resource granted to allUsers / allAuthenticatedUsers", C, "Remove public members. allAuthenticatedUsers means any Google account on the internet.", cwe="CWE-284", owasp=A01)
R_GCP_PRIMITIVE = r("TF-GCP-PRIMITIVE-ROLE", "Primitive Owner/Editor role granted", H, "Use predefined or custom roles scoped to the task.", cwe="CWE-250", owasp=A01)
R_AZ_PUBLIC_BLOB = r("TF-AZURE-PUBLIC-BLOB", "Azure storage allows anonymous blob access", C, "Set allow_nested_items_to_be_public = false and container_access_type = \"private\".", cwe="CWE-284", owasp=A01)
R_KEYVAULT = r("TF-AZURE-KEYVAULT-PURGE", "Key Vault without purge protection", M, "Enable purge_protection_enabled so deleted keys cannot be destroyed immediately.", cwe="CWE-404", owasp=A02)
R_HARDCODED_PW = r("TF-HARDCODED-PASSWORD", "Literal password in a resource", H, "Use a random_password resource with a secret manager, or manage_master_user_password = true on RDS.", cwe="CWE-798", owasp=A07)

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 23: "Telnet", 2375: "Docker API", 2376: "Docker API", 6443: "Kubernetes API", 10250: "kubelet"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB", 27018: "MongoDB", 6379: "Redis",
              9200: "Elasticsearch", 9300: "Elasticsearch", 5601: "Kibana", 11211: "Memcached", 9042: "Cassandra", 5984: "CouchDB",
              8086: "InfluxDB", 9092: "Kafka", 2181: "ZooKeeper", 7474: "Neo4j", 8123: "ClickHouse", 5672: "RabbitMQ", 15672: "RabbitMQ"}
WORLD = re.compile(r"[\"'](?:0\.0\.0\.0/0|::/0|\*|Internet|Any)[\"']")


@dataclass
class Block:
    kind: str
    type: str
    name: str
    body: str
    offset: int
    unresolved: dict = field(default_factory=dict)


_HEAD = re.compile(r'^\s*(resource|data|provider|terraform|module|variable|locals)\s*(?:"([^"]+)")?\s*(?:"([^"]+)")?\s*\{', re.M)


def blocks(text: str) -> Iterator[Block]:
    for m in _HEAD.finditer(text):
        depth, i, n = 1, m.end(), len(text)
        in_str = False
        while i < n and depth:
            ch = text[i]
            if in_str:
                if ch == "\\":
                    i += 1
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "#" or (ch == "/" and text[i:i + 2] == "//"):
                nl = text.find("\n", i)
                i = n if nl < 0 else nl
                continue
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        # m.start(1), not m.start(): the leading \s* also matches blank lines above the block
        yield Block(m.group(1), m.group(2) or "", m.group(3) or "", text[m.end():i - 1], m.start(1))


def _close(text: str, i: int) -> int:
    """Index just past the bracket matching the one opened before `i` (strings skipped)."""
    depth, n, in_str = 1, len(text), False
    while i < n and depth:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return i


_ASSIGN = re.compile(r"(?m)^[ \t]*([\w-]+)[ \t]*=[ \t]*")
_REF = re.compile(r"\b(?:var|local)\.[\w-]+|\b[\w-]+\.value\b")
UNRESOLVED = object()


def assignments(body: str) -> dict[str, str]:
    """Top-level `key = expression` of a block body; a multi-line {...} / [...] value is kept whole."""
    out: dict[str, str] = {}
    pos, depth_at = 0, 0
    for m in _ASSIGN.finditer(body):
        if m.start() < pos:
            continue
        # skip assignments nested in sub-blocks
        depth_at = body.count("{", 0, m.start()) - body.count("}", 0, m.start())
        if depth_at:
            continue
        end, depth, in_str = m.end(), 0, False
        # the value runs to the end of the line, or further while a bracket is open
        while end < len(body) and (depth or body[end] != "\n"):
            ch = body[end]
            if in_str:
                in_str = ch != '"' or body[end - 1] == "\\"
            elif ch == '"':
                in_str = True
            elif ch in "{[(":
                depth += 1
            elif ch in "}])":
                depth -= 1
            end += 1
        out[m.group(1)] = body[m.end():end].strip()
        pos = end
    return out


def _split(inner: str) -> list[str]:
    parts, depth, cur, in_str = [], 0, "", False
    for ch in inner:
        if in_str:
            in_str = ch != '"'
        elif ch == '"':
            in_str = True
        elif ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        elif ch in ",\n" and not depth:
            parts.append(cur)
            cur = ""
            continue
        cur += ch
    return [p.strip() for p in parts + [cur] if p.strip()]


def literal(expr: str):
    """A literal HCL value as Python (str, list, dict), or UNRESOLVED."""
    e = expr.strip()
    if re.fullmatch(r'"(?:[^"\\$]|\\.|\$(?!\{))*"', e):
        return e[1:-1]
    if re.fullmatch(r"true|false|null|-?\d+(?:\.\d+)?", e):
        return None if e == "null" else e
    if e.startswith("[") and e.endswith("]"):
        items = [literal(x) for x in _split(e[1:-1])]
        return UNRESOLVED if UNRESOLVED in items else items
    if e.startswith("{") and e.endswith("}"):
        pairs = [re.match(r'\s*"?([\w-]+)"?\s*[=:]\s*(.*)', p, re.S) for p in _split(e[1:-1])]
        if None in pairs:
            return UNRESOLVED
        obj = {m.group(1): literal(m.group(2)) for m in pairs}
        return UNRESOLVED if UNRESOLVED in obj.values() else obj
    return UNRESOLVED


class Values:
    """Variables and locals of one Terraform directory (one module)."""

    def __init__(self, texts: list[str], tfvars: list[str] = ()):
        self.vars: dict[str, object] = {}
        self.local_exprs: dict[str, str] = {}
        for text in texts:
            for b in blocks(text):
                if b.kind == "variable" and b.type:
                    self.vars[b.type] = self._variable(b.body)
                elif b.kind == "locals":
                    self.local_exprs.update(assignments(b.body))
        for text in tfvars:
            for k, v in assignments(text).items():
                value = literal(v)
                if value is not UNRESOLVED:
                    self.vars[k] = value
        self.locals: dict[str, object] = {}

    @staticmethod
    def _variable(body: str):
        a = assignments(body)
        defaults = {m.group(1): literal(m.group(2)) for m in re.finditer(r'([\w-]+)\s*=\s*optional\(\s*\w+\s*,\s*("[^"]*"|\w+)\s*\)', a.get("type", ""))}
        if "default" not in a:
            return UNRESOLVED
        value = literal(a["default"])
        if isinstance(value, dict) and defaults:
            return {**defaults, **{k: v for k, v in value.items() if v is not None}}
        if value is None and defaults:
            return UNRESOLVED
        return value

    def resolve(self, expr: str, env: dict[str, object] | None = None, depth: int = 0):
        e = expr.strip()
        if depth > 8:
            return UNRESOLVED
        value = literal(e)
        if value is not UNRESOLVED:
            return value
        m = re.fullmatch(r"lookup\((.+?),\s*(\"[^\"]+\")\s*(?:,\s*(.+))?\)", e)
        if m:
            obj, key = self.resolve(m.group(1), env, depth + 1), m.group(2)[1:-1]
            if isinstance(obj, dict):
                if obj.get(key) is not None:
                    return obj[key]
                return self.resolve(m.group(3), env, depth + 1) if m.group(3) else UNRESOLVED
            return UNRESOLVED
        if re.fullmatch(r'"[^"]*"', e) and "${" in e:
            # "${...}" interpolation: known only when every placeholder is
            parts = [self.resolve(x, env, depth + 1) for x in re.findall(r"\$\{([^}]*)\}", e)]
            if not all(isinstance(x, str) for x in parts):
                return UNRESOLVED
            it = iter(parts)
            return re.sub(r"\$\{[^}]*\}", lambda _: next(it), e[1:-1])
        if e.startswith("[") and e.endswith("]"):
            items = [self.resolve(x, env, depth + 1) for x in _split(e[1:-1])]
            return UNRESOLVED if UNRESOLVED in items else items
        m = re.fullmatch(r"(var|local|[\w-]+)\.([\w-]+)((?:\.[\w-]+|\[\"[^\"]+\"\])*)", e)
        if not m:
            return UNRESOLVED
        head, name, rest = m.groups()
        if head == "var":
            value = self.vars.get(name, UNRESOLVED)
        elif head == "local":
            if name not in self.locals:
                self.locals[name] = UNRESOLVED  # a cycle stays unresolved
                self.locals[name] = self.resolve(self.local_exprs[name], None, depth + 1) if name in self.local_exprs else UNRESOLVED
            value = self.locals[name]
        elif env is not None and name == "value" and head in env:
            value = env[head]
        else:
            return UNRESOLVED
        for key in re.findall(r'\.([\w-]+)|\["([^"]+)"\]', rest):
            key = key[0] or key[1]
            value = value.get(key, UNRESOLVED) if isinstance(value, dict) else UNRESOLVED
        return UNRESOLVED if value is None and rest else value

    def substitute(self, body: str, env: dict[str, object] | None = None) -> tuple[str, dict[str, str]]:
        """The body with every resolvable reference written as a literal, and the
        attributes left with an unresolved reference (name -> expression)."""
        out, unresolved, i = [], {}, 0
        for d in re.finditer(r'dynamic\s+"([\w-]+)"\s*\{', body):
            if d.start() < i:
                continue
            end = _close(body, d.end())
            inner = body[d.end():end - 1]
            a = assignments(inner)
            iterator = (a.get("iterator") or d.group(1)).strip()
            items = self.resolve(a.get("for_each", ""), env)
            scope = dict(env or {})
            if isinstance(items, list) and len(items) == 1:
                scope[iterator] = items[0]
            elif isinstance(items, dict) and items and all(isinstance(v, dict) for v in items.values()) and len(items) == 1:
                scope[iterator] = next(iter(items.values()))
            done, more = self.substitute(inner, scope)
            unresolved.update(more)
            plain, top = self._line_values(body[i:d.start()], env)
            out += [plain, body[d.start():d.end()], done, "}"]
            unresolved.update(top)
            i = end
        plain, top = self._line_values(body[i:], env)
        unresolved.update(top)
        return "".join(out) + plain, unresolved

    def _line_values(self, text: str, env) -> tuple[str, dict[str, str]]:
        unresolved: dict[str, str] = {}

        def one(m: re.Match) -> str:
            key, expr = m.group(2), m.group(3)
            if not _REF.search(expr):
                return m.group(0)
            value = self.resolve(expr, env)
            if isinstance(value, str):
                return f'{m.group(1)}"{value}"'
            if isinstance(value, list) and all(isinstance(v, str) for v in value):
                return m.group(1) + "[" + ", ".join(f'"{v}"' for v in value) + "]"
            unresolved[key] = expr.strip()
            return m.group(0)

        return re.sub(r"(?m)^([ \t]*([\w-]+)[ \t]*=[ \t]*)([^\n{]*\S)[ \t]*$", one, text), unresolved


def attr(body: str, name: str) -> str | None:
    m = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*(.+?)\s*$", body)
    return m.group(1).strip().strip('"') if m else None


_POLICY_KEYS = re.compile(r'(?<!["\w])(Version|Statement|Sid|Effect|Action|NotAction|Resource|NotResource|Principal|NotPrincipal|Condition|AWS|Service|Federated)\s*=')


def normalize_policy(body: str) -> str:
    """Rewrite HCL `jsonencode({ Action = "*" })` keys into JSON form ("Action": "*")
    so one set of patterns covers both heredoc JSON and jsonencode policies."""
    return _POLICY_KEYS.sub(lambda m: f'"{m.group(1)}":', body)


def is_true(v: str | None) -> bool:
    return v is not None and v.lower() == "true"


def is_false(v: str | None) -> bool:
    return v is not None and v.lower() == "false"


def _ports(body: str) -> tuple[int, int] | None:
    fp, tp = attr(body, "from_port"), attr(body, "to_port")
    try:
        if fp is not None and tp is not None:
            return int(fp), int(tp)
        port = attr(body, "port") or attr(body, "destination_port_range")
        if port and port != "*":
            lo, _, hi = port.partition("-")
            return int(lo), int(hi or lo)
    except ValueError:
        return None
    return None


class TerraformScanner:
    name = "terraform"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        by_dir: dict[str, list[str]] = {}
        for rel in ctx.files:
            if rel.lower().endswith(".tf"):
                by_dir.setdefault(rel.rpartition("/")[0], []).append(rel)
        values: dict[str, Values] = {}
        for d, rels in by_dir.items():
            tfvars = [ctx.text(f) or "" for f in ctx.files if f.rpartition("/")[0] == d
                      and (f.rsplit("/", 1)[-1] == "terraform.tfvars" or f.endswith(".auto.tfvars"))]
            values[d] = Values([ctx.text(f) or "" for f in rels], tfvars)
        for rel in ctx.files:
            low = rel.lower()
            if low.endswith((".tfstate", ".tfstate.backup")) and ctx.is_committed(rel):
                yield Finding(R_STATE, rel, 1, "Terraform state is in the repository.", snippet=rel.rsplit("/", 1)[-1])
            elif low.endswith(".tfvars") and ctx.is_committed(rel):
                for i, line in enumerate(ctx.lines(rel), 1):
                    if re.search(r"(?i)^\s*\w*(?:password|secret|token|api_key|access_key|private_key)\w*\s*=\s*\"[^\"$]{6,}\"", line):
                        yield Finding(R_TFVARS, rel, i, "Secret value in tfvars.", snippet=re.sub(r'=\s*".*"', '= "****"', line.strip()))
            elif low.endswith(".tf"):
                text = ctx.text(rel)
                if text:
                    yield from self.file(rel, text, values.get(rel.rpartition("/")[0]))

    def file(self, rel: str, text: str, values: Values | None = None) -> Iterator[Finding]:
        values = values or Values([text])
        resources = []
        for b in blocks(text):
            if b.kind in ("resource", "data"):
                b.body, b.unresolved = values.substitute(b.body)
            resources.append(b)
        bucket_names = {b.name for b in resources if b.type == "aws_s3_bucket"}
        pab_targets = " ".join(b.body for b in resources if b.type == "aws_s3_bucket_public_access_block")
        for b in resources:
            ln = line_of(text, b.offset)

            def F(rule_: Rule, msg: str, sev=None) -> Finding:
                f = Finding(rule_, rel, ln, f"{b.type}.{b.name}: {msg}" if b.name else msg, snippet=f'{b.kind} "{b.type}" "{b.name}"'.strip())
                if sev is not None:
                    f.severity = sev
                # a check that read a value Terraform only knows at plan time cannot be sure
                unknown = [f"{k} = {v}" for k, v in b.unresolved.items() if re.search(rf"(?<![\w-]){re.escape(k)}(?![\w-])", msg)]
                if unknown:
                    f.severity = min(f.severity, Severity.MEDIUM)
                    f.confidence = min(f.confidence, 0.5)
                    f.message += f" Value not resolved ({'; '.join(unknown)})."
                    f.extra["resolution"] = "unresolved"
                return f

            body, t = b.body, b.type
            policy = normalize_policy(body) if ("jsonencode" in body or "policy" in body.lower()) else body
            # --- provider / backend
            if b.kind == "provider" and re.search(r'(?m)^\s*(?:access_key|secret_key|client_secret|credentials)\s*=\s*"[^"$]{8,}"', body):
                yield F(R_PROVIDER_KEYS, "provider has literal credentials.")
            if b.kind == "terraform" and re.search(r'backend\s+"s3"', body) and not re.search(r"encrypt\s*=\s*true", body):
                yield F(R_BACKEND, "S3 backend without encrypt = true.")
            if b.kind != "resource" and b.kind != "data":
                continue
            # --- literal passwords on any resource
            m = re.search(r'(?m)^\s*(?:master_password|password|admin_password|administrator_login_password|root_password)\s*=\s*"([^"$]{4,})"', body)
            if m:
                yield F(R_HARDCODED_PW, "password set to a literal string.")
            # --- AWS S3
            if t in ("aws_s3_bucket", "aws_s3_bucket_acl") and re.search(r'acl\s*=\s*"(?:public-read|public-read-write|authenticated-read)"', body):
                yield F(R_S3_PUBLIC, f"ACL {attr(body, 'acl')}.")
            if t == "aws_s3_bucket_public_access_block":
                off = [k for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets") if not is_true(attr(body, k))]
                if off:
                    yield F(R_S3_PAB, f"{', '.join(off)} not true.")
            if t == "aws_s3_bucket" and b.name in bucket_names and f"aws_s3_bucket.{b.name}." not in pab_targets and "aws_s3_account_public_access_block" not in text:
                yield F(R_S3_PAB, "no aws_s3_bucket_public_access_block in this file targets the bucket.", sev=L)
            if t in ("aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_s3_bucket", "aws_sqs_queue", "aws_sns_topic", "aws_ecr_repository_policy", "aws_lambda_permission", "aws_secretsmanager_secret_policy", "aws_kms_key"):
                if re.search(r'"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])\s*\})|principals\s*\{[^}]*identifiers\s*=\s*\["\*"\]|principal\s*=\s*"\*"', policy) and "Condition" not in policy and "condition" not in policy:
                    yield F(R_POLICY_PUBLIC, "policy allows Principal \"*\" without a condition.")
            # --- network exposure (AWS SG, GCP firewall, Azure NSG)
            if t in ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "google_compute_firewall", "azurerm_network_security_rule", "azurerm_network_security_group"):
                yield from self._network(b, F)
            # --- IAM
            if t in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy_document"):
                yield from self._iam(policy, F)
            if t in ("aws_iam_user_policy_attachment", "aws_iam_role_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment") and "AdministratorAccess" in body:
                yield F(R_IAM_ADMIN, "AdministratorAccess attached.")
            if t == "aws_iam_access_key":
                yield F(R_IAM_USER_KEY, "access key created for an IAM user.")
            # --- databases & data stores
            if t in ("aws_db_instance", "aws_rds_cluster", "aws_redshift_cluster", "aws_docdb_cluster", "aws_neptune_cluster"):
                if is_true(attr(body, "publicly_accessible")):
                    yield F(R_DB_PUBLIC, "publicly_accessible = true.")
                enc_key = "encrypted" if t == "aws_redshift_cluster" else "storage_encrypted"
                if not is_true(attr(body, enc_key)) and not attr(body, "kms_key_id"):
                    yield F(R_DB_UNENCRYPTED, f"{enc_key} is not true.")
                br = attr(body, "backup_retention_period")
                if br == "0":
                    yield F(R_DB_BACKUP, "backup_retention_period = 0.")
                if t == "aws_db_instance" and not is_true(attr(body, "deletion_protection")):
                    yield F(R_DB_BACKUP, "deletion_protection not enabled.", sev=L)
            if t in ("aws_ebs_volume", "aws_efs_file_system") and not is_true(attr(body, "encrypted")):
                yield F(R_DB_UNENCRYPTED, "encrypted is not true.")
            if t == "aws_ebs_encryption_by_default" and is_false(attr(body, "enabled")):
                yield F(R_DB_UNENCRYPTED, "EBS default encryption disabled.")
            if t in ("aws_elasticsearch_domain", "aws_opensearch_domain"):
                if not re.search(r"encrypt_at_rest\s*\{[^}]*enabled\s*=\s*true", body):
                    yield F(R_DB_UNENCRYPTED, "encrypt_at_rest not enabled.")
                if not re.search(r"enforce_https\s*=\s*true", body):
                    yield F(R_TRANSIT, "enforce_https not set.")
            if t == "aws_elasticache_replication_group":
                if not is_true(attr(body, "at_rest_encryption_enabled")):
                    yield F(R_DB_UNENCRYPTED, "at_rest_encryption_enabled not true.")
                if not is_true(attr(body, "transit_encryption_enabled")):
                    yield F(R_TRANSIT, "transit_encryption_enabled not true.")
            if t == "aws_dynamodb_table" and not re.search(r"point_in_time_recovery\s*\{[^}]*enabled\s*=\s*true", body):
                yield F(R_DB_BACKUP, "point-in-time recovery off.", sev=L)
            if t in ("aws_sqs_queue", "aws_sns_topic") and not (attr(body, "kms_master_key_id") or is_true(attr(body, "sqs_managed_sse_enabled"))):
                yield F(R_DB_UNENCRYPTED, "no server-side encryption.", sev=L)
            # --- compute / functions / k8s
            if t in ("aws_instance", "aws_launch_template") and not re.search(r'http_tokens\s*=\s*"required"', body) \
                    and not re.search(r'http_endpoint\s*=\s*"disabled"', body):
                # with http_endpoint = "disabled" there is no metadata service to reach at all
                yield F(R_IMDS, "metadata_options.http_tokens is not \"required\"" + (" and http_endpoint is not \"disabled\"" if "http_endpoint" in b.unresolved else "") + ".")
            if t in ("aws_instance", "aws_launch_template") and re.search(r"(?:root_block_device|ebs_block_device|ebs)\s*\{[^}]*encrypted\s*=\s*false", body):
                yield F(R_DB_UNENCRYPTED, "block device with encrypted = false.")
            if t == "aws_lambda_function_url" and attr(body, "authorization_type") == "NONE":
                yield F(R_LAMBDA_URL, "authorization_type = NONE.")
            if t == "aws_eks_cluster" and not re.search(r"endpoint_public_access\s*=\s*false", body) and not re.search(r"public_access_cidrs", body):
                yield F(R_K8S_PUBLIC, "public endpoint with no CIDR restriction.")
            if t == "google_container_cluster":
                if is_true(attr(body, "enable_legacy_abac")):
                    yield F(R_K8S_PUBLIC, "legacy ABAC enabled.", sev=H)
                if "master_authorized_networks_config" not in body:
                    yield F(R_K8S_PUBLIC, "no master_authorized_networks_config.")
            # --- logging / keys
            if t == "aws_cloudtrail":
                weak = []
                if not is_true(attr(body, "is_multi_region_trail")):
                    weak.append("not multi-region")
                if not is_true(attr(body, "enable_log_file_validation")):
                    weak.append("no log file validation")
                if not attr(body, "kms_key_id"):
                    weak.append("not KMS-encrypted")
                if weak:
                    yield F(R_TRAIL, ", ".join(weak) + ".")
            if t == "aws_kms_key" and not is_true(attr(body, "enable_key_rotation")):
                yield F(R_KMS_ROTATE, "enable_key_rotation not true.")
            # --- edge / TLS
            if t in ("aws_lb_listener", "aws_alb_listener") and attr(body, "protocol") == "HTTP" and "redirect" not in body:
                yield F(R_HTTP_LISTENER, "HTTP listener without redirect to HTTPS.")
            if t in ("aws_lb_listener", "aws_alb_listener") and re.search(r'ssl_policy\s*=\s*"ELBSecurityPolicy-(?:2015|2016-08|TLS-1-0|TLS-1-1)', body):
                yield F(R_OLD_TLS, f"ssl_policy {attr(body, 'ssl_policy')}.")
            if t == "aws_cloudfront_distribution":
                if re.search(r'viewer_protocol_policy\s*=\s*"allow-all"', body):
                    yield F(R_HTTP_LISTENER, "viewer_protocol_policy = allow-all.")
                if re.search(r'minimum_protocol_version\s*=\s*"(?:SSLv3|TLSv1(?:_2016|\.1_2016)?)"', body):
                    yield F(R_OLD_TLS, "minimum_protocol_version below TLS 1.2.")
            if t == "aws_ecr_repository" and (attr(body, "image_tag_mutability") in (None, "MUTABLE") or not re.search(r"scan_on_push\s*=\s*true", body)):
                yield F(R_ECR, "mutable tags or scan_on_push off.")
            # --- GCP
            if t.startswith("google_") and re.search(r'"(?:allUsers|allAuthenticatedUsers)"', body):
                yield F(R_GCS_PUBLIC, "public member granted.")
            if t in ("google_project_iam_member", "google_project_iam_binding", "google_organization_iam_member") and re.search(r'role\s*=\s*"roles/(?:owner|editor)"', body):
                yield F(R_GCP_PRIMITIVE, f"{attr(body, 'role')} granted.")
            if t == "google_storage_bucket" and is_false(attr(body, "uniform_bucket_level_access")):
                yield F(R_GCS_PUBLIC, "uniform bucket-level access disabled (object ACLs can make data public).", sev=M)
            if t == "google_sql_database_instance":
                if re.search(r'authorized_networks\s*\{[^}]*value\s*=\s*"0\.0\.0\.0/0"', body):
                    yield F(R_DB_PUBLIC, "authorized network 0.0.0.0/0.")
                if not re.search(r'require_ssl\s*=\s*true|ssl_mode\s*=\s*"(?:ENCRYPTED_ONLY|TRUSTED_CLIENT_CERTIFICATE_REQUIRED)"', body):
                    yield F(R_TRANSIT, "SSL not required for connections.")
            # --- Azure
            if t == "azurerm_storage_account":
                if is_true(attr(body, "allow_nested_items_to_be_public")) or is_true(attr(body, "allow_blob_public_access")):
                    yield F(R_AZ_PUBLIC_BLOB, "public blob access allowed.")
                if is_false(attr(body, "https_traffic_only_enabled")) or is_false(attr(body, "enable_https_traffic_only")):
                    yield F(R_TRANSIT, "HTTPS-only traffic disabled.")
                if attr(body, "min_tls_version") in ("TLS1_0", "TLS1_1"):
                    yield F(R_OLD_TLS, f"min_tls_version {attr(body, 'min_tls_version')}.")
            if t == "azurerm_storage_container" and attr(body, "container_access_type") in ("blob", "container"):
                yield F(R_AZ_PUBLIC_BLOB, f"container_access_type = {attr(body, 'container_access_type')}.")
            if t in ("azurerm_sql_firewall_rule", "azurerm_mssql_firewall_rule", "azurerm_postgresql_firewall_rule", "azurerm_mysql_firewall_rule", "azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule"):
                if attr(body, "start_ip_address") == "0.0.0.0" and attr(body, "end_ip_address") == "255.255.255.255":
                    yield F(R_DB_PUBLIC, "firewall rule opens the database to every IPv4 address.")
            if t == "azurerm_key_vault" and not is_true(attr(body, "purge_protection_enabled")):
                yield F(R_KEYVAULT, "purge_protection_enabled not true.")
            if t == "azurerm_kubernetes_cluster" and is_false(attr(body, "role_based_access_control_enabled")):
                yield F(R_K8S_PUBLIC, "RBAC disabled.", sev=H)

    def _network(self, b: Block, F) -> Iterator[Finding]:
        body = b.body
        chunks: list[str] = []
        if b.type == "aws_security_group":
            chunks = [m.group(1) for m in re.finditer(r"ingress\s*\{([^{}]*)\}", body)]
        elif b.type == "aws_security_group_rule":
            chunks = [body] if attr(body, "type") == "ingress" else []
        elif b.type == "google_compute_firewall":
            if attr(body, "direction") in (None, "INGRESS") and re.search(r'source_ranges\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', body):
                allows = re.findall(r"allow\s*\{([^{}]*)\}", body)
                for a in allows:
                    ports = re.findall(r'"(\d+)(?:-(\d+))?"', a.split("ports", 1)[1]) if "ports" in a else []
                    proto = attr(a, "protocol")
                    if not ports and proto in ("all", "tcp", None):
                        yield F(R_OPEN_ALL, "firewall allows all ports from 0.0.0.0/0.")
                    for lo, hi in ports:
                        yield from self._port_findings(int(lo), int(hi or lo), F)
            return
        elif b.type == "azurerm_network_security_rule":
            chunks = [body] if attr(body, "direction") == "Inbound" and attr(body, "access") == "Allow" else []
        elif b.type == "azurerm_network_security_group":
            chunks = [m.group(1) for m in re.finditer(r"security_rule\s*\{([^{}]*)\}", body) if 'Inbound' in m.group(1) and '"Allow"' in m.group(1)]
        else:  # aws_vpc_security_group_ingress_rule
            chunks = [body]
        for c in chunks:
            if not (WORLD.search(c) or re.search(r'cidr_ipv4\s*=\s*"0\.0\.0\.0/0"|source_address_prefix\s*=\s*"(?:\*|Internet|0\.0\.0\.0/0)"', c)):
                continue
            proto = attr(c, "protocol") or attr(c, "ip_protocol")
            ports = _ports(c)
            if proto in ("-1", "all", "*") and ports is None or (ports and ports[0] <= 0 and ports[1] >= 65535) or attr(c, "destination_port_range") == "*":
                yield F(R_OPEN_ALL, "ingress from anywhere on every port.")
                continue
            if ports:
                yield from self._port_findings(ports[0], ports[1], F)

    @staticmethod
    def _port_findings(lo: int, hi: int, F) -> Iterator[Finding]:
        admin = [f"{p}/{n}" for p, n in ADMIN_PORTS.items() if lo <= p <= hi]
        data = [f"{p}/{n}" for p, n in DATA_PORTS.items() if lo <= p <= hi]
        if hi - lo > 1000:
            yield F(R_OPEN_ALL, f"ports {lo}-{hi} open to the internet.")
            return
        if admin:
            yield F(R_OPEN_ADMIN, f"{', '.join(admin)} reachable from anywhere.")
        if data:
            yield F(R_OPEN_DB, f"{', '.join(data)} reachable from anywhere.")

    def _iam(self, body: str, F) -> Iterator[Finding]:
        statements = re.split(r'\{\s*"(?:Sid|Effect)"|statement\s*\{', body)
        if len(statements) > 1:
            statements = statements[1:]
        for st in statements:
            allow = '"Allow"' in st or 'effect = "Allow"' in st or ("Deny" not in st)
            if not allow:
                continue
            action_star = re.search(r'"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])|actions\s*=\s*\[\s*"\*"\s*\]', st)
            resource_star = re.search(r'"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])|resources\s*=\s*\[\s*"\*"\s*\]', st)
            if action_star and resource_star:
                yield F(R_IAM_WILDCARD, "Action \"*\" on Resource \"*\".")
                return
            if re.search(r'"(?:iam:PassRole|iam:\*|iam:(?:Create|Put|Attach)\w*Policy\w*|iam:CreateAccessKey|iam:UpdateAssumeRolePolicy|sts:\*)"', st) and resource_star:
                yield F(R_IAM_ESCALATION, "escalation-capable IAM action on Resource \"*\".")
                return
            if re.search(r'"\w+:\*"', st) and resource_star:
                yield F(R_IAM_ESCALATION, "service-wide wildcard action on Resource \"*\".", sev=M)
                return
