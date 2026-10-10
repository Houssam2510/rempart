"""Live, read-only Google Cloud and Azure posture audits.

Both go through the official CLIs you are already logged into (`gcloud`, `az`)
with JSON output, so there is no SDK to install and no credential handling in
Rempart: whatever the CLI can read, the audit can read. Only list/describe
commands are used. The viewer roles are enough (GCP `roles/viewer` +
`roles/iam.securityReviewer`; Azure `Reader`).

Every command goes through one `Runner` (args -> parsed JSON), which is what
the tests replace with recorded fixtures.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from rempart.models import Finding, Severity
from rempart.registry import A01, A02, A04, A07, A09, C, H, I, L, M, rule

Runner = Callable[[list[str]], Any]

CIS_GCP = "CIS Google Cloud Platform Foundation Benchmark"
CIS_AZ = "CIS Microsoft Azure Foundations Benchmark"
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 2375: "Docker", 6443: "Kubernetes API"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
              9042: "Cassandra", 5984: "CouchDB", 9092: "Kafka"}
OPEN = {"0.0.0.0/0", "::/0", "*", "Internet", "Any", "0.0.0.0"}


def _r(prefix: str, framework: str):
    def make(id, title, sev, fix, cwe="CWE-16", owasp=A02, conf=0.95):
        return rule(f"{prefix}-{id}", title, sev, "cloud", cwe=cwe, owasp=owasp, frameworks=(framework,), fix=fix, confidence=conf)
    return make


def cli_runner(binary: str) -> Runner:
    exe = shutil.which(binary)
    if exe is None:
        raise RuntimeError(f"`{binary}` is not installed or not on PATH")

    def run(args: list[str]) -> Any:
        fmt = ["--format=json"] if binary == "gcloud" else ["-o", "json"]
        out = subprocess.run([exe, *args, *fmt], capture_output=True, text=True, timeout=180)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else f"{binary} exited {out.returncode}")
        return json.loads(out.stdout or "null")
    return run


def _ports(spec: Any) -> set[int]:
    """'22', '8000-8100', 22, '*' -> ports of interest covered by the range."""
    out: set[int] = set()
    interesting = set(ADMIN_PORTS) | set(DATA_PORTS)
    for item in spec if isinstance(spec, list) else [spec]:
        s = str(item).strip()
        if s in ("*", "", "None"):
            return interesting | {0}
        lo, _, hi = s.partition("-")
        try:
            a, b = int(lo), int(hi or lo)
        except ValueError:
            continue
        out |= {p for p in interesting if a <= p <= b}
        if b - a >= 1000:
            out.add(0)
    return out


class _Audit:
    provider = ""
    skipped: Any = None

    def __init__(self, run: Runner, now: datetime | None = None) -> None:
        self.run = run
        self.now = now or datetime.now(timezone.utc)
        self.scope = "unknown"
        self.findings: list[Finding] = []

    def add(self, r_, resource: str, msg: str, sev: Severity | None = None, **extra: Any) -> None:
        f = Finding(r_, f"{self.provider}://{self.scope}/{resource}", 0, msg, snippet=resource, extra={"anchor": f"{r_.id}:{resource}", **extra})
        f.verification = "observed"
        if sev is not None:
            f.severity = sev
        self.findings.append(f)

    def guarded(self, label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # permission denied, API not enabled: report, keep going
            self.add(self.skipped, label, f"{label} skipped: {str(exc)[:200]}")


# ---------------------------------------------------------------- Google Cloud

g = _r("GCP", CIS_GCP)
G_SKIPPED = rule("GCP-CHECK-SKIPPED", "Google Cloud check could not run", I, "cloud",
                 fix="Grant roles/viewer and roles/iam.securityReviewer, and enable the API named in the message.", confidence=1.0)
G_PUBLIC_IAM = g("IAM-PUBLIC-MEMBER", "Project role granted to allUsers or allAuthenticatedUsers", C,
                 "Remove allUsers / allAuthenticatedUsers bindings at project level; grant roles to named principals.", "CWE-284", A01)
G_SA_ADMIN = g("IAM-SA-PRIMITIVE-ROLE", "Service account holds Owner or Editor on the project", H,
               "Replace primitive roles on service accounts with the predefined roles the workload needs.", "CWE-269", A01)
G_SA_KEY_OLD = g("IAM-SA-KEY-OLD", "User-managed service account key older than 90 days", M,
                 "Prefer workload identity federation; otherwise rotate keys every 90 days and delete unused ones.", "CWE-324", A07)
G_BUCKET_PUBLIC = g("STORAGE-PUBLIC", "Cloud Storage bucket readable by anyone", C,
                    "Remove allUsers / allAuthenticatedUsers from the bucket policy and enforce public access prevention.", "CWE-284", A01)
G_BUCKET_PAP = g("STORAGE-NO-PAP", "Bucket without public access prevention or uniform access", M,
                 "Set publicAccessPrevention=enforced and enable uniform bucket-level access.", "CWE-284", A01, 0.8)
G_FW_ADMIN = g("FW-ADMIN-OPEN", "Firewall rule opens an administration port to the internet", H,
               "Restrict sourceRanges to known addresses or use IAP TCP forwarding for SSH/RDP.", "CWE-284", A01)
G_FW_DATA = g("FW-DATA-OPEN", "Firewall rule opens a database port to the internet", C,
              "Remove 0.0.0.0/0 from the rule; reach the database through private IP or the Cloud SQL Auth Proxy.", "CWE-284", A01)
G_SQL_OPEN = g("SQL-AUTHORIZED-ANY", "Cloud SQL instance accepts connections from any address", C,
               "Remove 0.0.0.0/0 from authorized networks; use private IP or the Cloud SQL Auth Proxy.", "CWE-284", A01)
G_SQL_SSL = g("SQL-NO-SSL", "Cloud SQL instance does not require TLS", M,
              "Set sslMode to ENCRYPTED_ONLY or TRUSTED_CLIENT_CERTIFICATE_REQUIRED.", "CWE-319", A04)
G_SQL_BACKUP = g("SQL-NO-BACKUP", "Cloud SQL automated backups disabled", M, "Enable automated backups and point-in-time recovery.", "CWE-404", A02, 0.9)
G_VM_DEFAULT_SA = g("VM-DEFAULT-SA-FULL-SCOPE", "VM runs as the default service account with full API scope", H,
                    "Use a dedicated service account with minimal roles; never cloud-platform scope with the default Editor account.", "CWE-269", A01)
G_VM_SERIAL = g("VM-SERIAL-PORT", "Interactive serial console enabled", L, "Set serial-port-enable=false in instance metadata.", "CWE-16", A02, 0.9)
G_AUDIT_LOGS = g("LOGGING-NO-DATA-ACCESS", "Data access audit logs are not enabled", L,
                 "Enable DATA_READ and DATA_WRITE audit logs for allServices in the project IAM policy.", "CWE-778", A09, 0.8)


class GCPAudit(_Audit):
    provider = "gcp"
    skipped = G_SKIPPED

    def __init__(self, run: Runner, project: str | None = None, now: datetime | None = None) -> None:
        super().__init__(run, now)
        self.project = project

    def gc(self, *args: str) -> Any:
        return self.run([*args, *(["--project", self.project] if self.project else [])])

    def audit(self) -> list[Finding]:
        if not self.project:
            cfg = self.run(["config", "list"]) or {}
            self.project = ((cfg.get("core") or {}).get("project")) if isinstance(cfg, dict) else None
            if not self.project:
                raise RuntimeError("no project: pass --project or run `gcloud config set project ID`")
        self.scope = self.project
        for label, fn in (("iam", self.iam), ("service-account-keys", self.sa_keys), ("storage", self.storage),
                          ("firewall", self.firewall), ("sql", self.sql), ("compute", self.compute)):
            self.guarded(label, fn)
        self.findings.sort(key=lambda f: -f.risk)
        return self.findings

    def iam(self) -> None:
        policy = self.run(["projects", "get-iam-policy", str(self.project)]) or {}
        for b in policy.get("bindings") or []:
            members = b.get("members") or []
            public = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
            if public:
                self.add(G_PUBLIC_IAM, f"iam/{b.get('role')}", f"{b.get('role')} is granted to {', '.join(public)}.")
            if b.get("role") in ("roles/owner", "roles/editor"):
                for m in members:
                    if m.startswith("serviceAccount:"):
                        self.add(G_SA_ADMIN, f"iam/{m[15:]}", f"{m[15:]} has {b['role']}.")
        logged = {(c.get("service"), lt.get("logType")) for c in policy.get("auditConfigs") or [] for lt in c.get("auditLogConfigs") or []}
        if not {("allServices", "DATA_READ"), ("allServices", "DATA_WRITE")} <= logged:
            self.add(G_AUDIT_LOGS, "iam/auditConfigs", "Data access audit logs are not enabled for all services.")

    def sa_keys(self) -> None:
        for sa in self.gc("iam", "service-accounts", "list") or []:
            email = sa.get("email", "")
            for key in self.gc("iam", "service-accounts", "keys", "list", f"--iam-account={email}", "--managed-by=user") or []:
                created = _date(key.get("validAfterTime"))
                if created and (self.now - created).days > 90:
                    self.add(G_SA_KEY_OLD, f"iam/{email}/keys/{str(key.get('name', '')).rsplit('/', 1)[-1][:12]}",
                             f"Key of {email} created {(self.now - created).days} days ago.")

    def storage(self) -> None:
        for b in self.gc("storage", "buckets", "list") or []:
            name = b.get("name") or str(b.get("storage_url", "")).removeprefix("gs://").rstrip("/")
            pap = b.get("public_access_prevention") or (b.get("iamConfiguration") or {}).get("publicAccessPrevention")
            ubla = b.get("uniform_bucket_level_access")
            if ubla is None:
                ubla = ((b.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}).get("enabled")
            policy = self.run(["storage", "buckets", "get-iam-policy", f"gs://{name}"]) or {}
            public = sorted({m for bd in policy.get("bindings") or [] for m in bd.get("members") or [] if m in ("allUsers", "allAuthenticatedUsers")})
            if public:
                self.add(G_BUCKET_PUBLIC, f"storage/{name}", f"gs://{name} grants access to {', '.join(public)}.")
            elif pap != "enforced" and not ubla:
                self.add(G_BUCKET_PAP, f"storage/{name}", f"gs://{name}: public access prevention {pap or 'inherited'}, uniform access off.")

    def firewall(self) -> None:
        for rule_ in self.gc("compute", "firewall-rules", "list") or []:
            if rule_.get("disabled") or rule_.get("direction", "INGRESS") != "INGRESS":
                continue
            if not set(rule_.get("sourceRanges") or []) & OPEN:
                continue
            ports: set[int] = set()
            for allowed in rule_.get("allowed") or []:
                if allowed.get("IPProtocol") in ("tcp", "all", "6"):
                    ports |= _ports(allowed.get("ports") or "*")
            name = rule_.get("name")
            data = sorted(p for p in ports if p in DATA_PORTS)
            admin = sorted(p for p in ports if p in ADMIN_PORTS)
            if data:
                self.add(G_FW_DATA, f"firewall/{name}", f"{name} allows {', '.join(f'{DATA_PORTS[p]} ({p})' for p in data)} from the internet.")
            if admin:
                self.add(G_FW_ADMIN, f"firewall/{name}", f"{name} allows {', '.join(f'{ADMIN_PORTS[p]} ({p})' for p in admin)} from the internet.")

    def sql(self) -> None:
        for inst in self.gc("sql", "instances", "list") or []:
            name = inst.get("name")
            settings = inst.get("settings") or {}
            ip = settings.get("ipConfiguration") or {}
            if any(n.get("value") in ("0.0.0.0/0", "::/0") for n in ip.get("authorizedNetworks") or []) and ip.get("ipv4Enabled", True):
                self.add(G_SQL_OPEN, f"sql/{name}", f"{name} ({inst.get('databaseVersion')}) authorizes 0.0.0.0/0 on its public IP.")
            if ip.get("sslMode") in (None, "ALLOW_UNENCRYPTED_AND_ENCRYPTED") and not ip.get("requireSsl"):
                self.add(G_SQL_SSL, f"sql/{name}", f"{name} accepts unencrypted connections.")
            if not (settings.get("backupConfiguration") or {}).get("enabled"):
                self.add(G_SQL_BACKUP, f"sql/{name}", f"{name} has automated backups disabled.")

    def compute(self) -> None:
        for vm in self.gc("compute", "instances", "list") or []:
            name = vm.get("name")
            for sa in vm.get("serviceAccounts") or []:
                if str(sa.get("email", "")).endswith("-compute@developer.gserviceaccount.com") and \
                        "https://www.googleapis.com/auth/cloud-platform" in (sa.get("scopes") or []):
                    self.add(G_VM_DEFAULT_SA, f"compute/{name}", f"{name} runs as the default compute service account with cloud-platform scope.")
            meta = {i.get("key"): str(i.get("value", "")).lower() for i in (vm.get("metadata") or {}).get("items") or []}
            if meta.get("serial-port-enable") in ("true", "1"):
                self.add(G_VM_SERIAL, f"compute/{name}", f"{name} has the interactive serial console enabled.")


# ---------------------------------------------------------------- Azure

a = _r("AZ", CIS_AZ)
A_SKIPPED = rule("AZ-CHECK-SKIPPED", "Azure check could not run", I, "cloud", fix="Grant the Reader role on the subscription.", confidence=1.0)
A_BLOB_PUBLIC = a("STORAGE-PUBLIC-BLOB", "Storage account allows anonymous blob access", H,
                  "Set allowBlobPublicAccess=false on the account; serve public files through a CDN with SAS or Front Door.", "CWE-284", A01)
A_HTTP = a("STORAGE-HTTP", "Storage account accepts plain HTTP", H, "Set supportsHttpsTrafficOnly=true.", "CWE-319", A04)
A_TLS = a("STORAGE-OLD-TLS", "Storage account accepts TLS below 1.2", M, "Set minimumTlsVersion=TLS1_2.", "CWE-326", A04)
A_STORAGE_NET = a("STORAGE-OPEN-NETWORK", "Storage account reachable from every network", M,
                  "Set the network rule default action to Deny and allow only the VNets and addresses that need it.", "CWE-284", A01, 0.8)
A_NSG_ADMIN = a("NSG-ADMIN-OPEN", "Network security group opens an administration port to the internet", H,
                "Restrict the source to known addresses or use Azure Bastion / just-in-time access.", "CWE-284", A01)
A_NSG_DATA = a("NSG-DATA-OPEN", "Network security group opens a database port to the internet", C,
               "Remove the internet source; use private endpoints for data services.", "CWE-284", A01)
A_SQL_OPEN = a("SQL-FIREWALL-ANY", "Azure SQL server firewall allows every address", C,
               "Delete the 0.0.0.0-255.255.255.255 rule; use private endpoints or named client ranges.", "CWE-284", A01)
A_KV_PURGE = a("KEYVAULT-NO-PURGE-PROTECTION", "Key Vault without purge protection", L,
               "Enable soft delete and purge protection so a compromised identity cannot destroy keys permanently.", "CWE-404", A02, 0.9)
A_OWNER_SP = a("RBAC-SP-OWNER", "Service principal is Owner of the subscription", H,
               "Grant the service principal a narrower built-in role at the resource group that it manages.", "CWE-269", A01)


class AzureAudit(_Audit):
    provider = "azure"
    skipped = A_SKIPPED

    def __init__(self, run: Runner, subscription: str | None = None, now: datetime | None = None) -> None:
        super().__init__(run, now)
        self.subscription = subscription

    def az(self, *args: str) -> Any:
        return self.run([*args, *(["--subscription", self.subscription] if self.subscription else [])])

    def audit(self) -> list[Finding]:
        acct = self.run(["account", "show", *(["--subscription", self.subscription] if self.subscription else [])]) or {}
        self.scope = str(acct.get("id") or self.subscription or "unknown")
        for label, fn in (("storage", self.storage), ("nsg", self.nsg), ("sql", self.sql), ("keyvault", self.keyvault), ("rbac", self.rbac)):
            self.guarded(label, fn)
        self.findings.sort(key=lambda f: -f.risk)
        return self.findings

    def storage(self) -> None:
        for acc in self.az("storage", "account", "list") or []:
            name = acc.get("name")
            if acc.get("allowBlobPublicAccess"):
                self.add(A_BLOB_PUBLIC, f"storage/{name}", f"{name} allows anonymous blob access.")
            if acc.get("enableHttpsTrafficOnly") is False or acc.get("supportsHttpsTrafficOnly") is False:
                self.add(A_HTTP, f"storage/{name}", f"{name} accepts HTTP.")
            if acc.get("minimumTlsVersion") in ("TLS1_0", "TLS1_1"):
                self.add(A_TLS, f"storage/{name}", f"{name} minimum TLS is {acc['minimumTlsVersion']}.")
            if (acc.get("networkRuleSet") or {}).get("defaultAction") == "Allow" and acc.get("publicNetworkAccess", "Enabled") != "Disabled":
                self.add(A_STORAGE_NET, f"storage/{name}", f"{name} accepts traffic from every network.")

    def nsg(self) -> None:
        for nsg in self.az("network", "nsg", "list") or []:
            for rule_ in nsg.get("securityRules") or []:
                if rule_.get("direction") != "Inbound" or rule_.get("access") != "Allow" or rule_.get("protocol") not in ("Tcp", "*"):
                    continue
                sources = {rule_.get("sourceAddressPrefix")} | set(rule_.get("sourceAddressPrefixes") or [])
                if not sources & OPEN:
                    continue
                ports = _ports([rule_.get("destinationPortRange")] + list(rule_.get("destinationPortRanges") or []))
                where = f"nsg/{nsg.get('name')}/{rule_.get('name')}"
                data = sorted(p for p in ports if p in DATA_PORTS)
                admin = sorted(p for p in ports if p in ADMIN_PORTS)
                if data:
                    self.add(A_NSG_DATA, where, f"{nsg.get('name')}/{rule_.get('name')} allows {', '.join(f'{DATA_PORTS[p]} ({p})' for p in data)} from the internet.")
                if admin:
                    self.add(A_NSG_ADMIN, where, f"{nsg.get('name')}/{rule_.get('name')} allows {', '.join(f'{ADMIN_PORTS[p]} ({p})' for p in admin)} from the internet.")

    def sql(self) -> None:
        for srv in self.az("sql", "server", "list") or []:
            if srv.get("publicNetworkAccess") == "Disabled":
                continue
            rules = self.az("sql", "server", "firewall-rule", "list", "-g", str(srv.get("resourceGroup")), "-s", str(srv.get("name"))) or []
            for fr in rules:
                if fr.get("startIpAddress") == "0.0.0.0" and fr.get("endIpAddress") == "255.255.255.255":
                    self.add(A_SQL_OPEN, f"sql/{srv.get('name')}", f"{srv.get('name')} firewall rule {fr.get('name')} allows every IPv4 address.")

    def keyvault(self) -> None:
        for kv in self.az("keyvault", "list") or []:
            props = kv.get("properties") or {}
            if not props.get("enablePurgeProtection"):
                self.add(A_KV_PURGE, f"keyvault/{kv.get('name')}", f"{kv.get('name')} can be purged immediately after deletion.")

    def rbac(self) -> None:
        for ra in self.az("role", "assignment", "list", "--all") or []:
            scope = str(ra.get("scope", ""))
            if ra.get("roleDefinitionName") == "Owner" and ra.get("principalType") == "ServicePrincipal" and scope.count("/") <= 2:
                self.add(A_OWNER_SP, f"rbac/{ra.get('principalName') or ra.get('principalId')}",
                         f"{ra.get('principalName') or ra.get('principalId')} is Owner of {scope}.")


def _date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def audit_gcp(project: str | None = None, run: Runner | None = None) -> Iterator[Finding]:
    yield from GCPAudit(run or cli_runner("gcloud"), project).audit()


def audit_azure(subscription: str | None = None, run: Runner | None = None) -> Iterator[Finding]:
    yield from AzureAudit(run or cli_runner("az"), subscription).audit()
