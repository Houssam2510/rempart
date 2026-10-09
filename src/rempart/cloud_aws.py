"""Live, read-only AWS posture audit.

`rempart cloud aws` uses your existing AWS credentials (profile, SSO, env or
instance role) and only calls Describe/Get/List APIs. The managed policy
`SecurityAudit` is sufficient. Every finding is `observed`: it describes the
account as it is right now, not as the Terraform says it should be.

Requires boto3 (`pip install "rempart[aws]"`).
"""

from __future__ import annotations

import csv
import io
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from rempart.models import Finding, Severity
from rempart.registry import A01, A02, A04, A06, A07, A09, C, H, I, L, M, rule

CIS = "CIS AWS Foundations Benchmark"


def r(id, title, sev, fix, cwe="CWE-16", owasp=A02, conf=0.95):
    return rule(id, title, sev, "cloud", cwe=cwe, owasp=owasp, frameworks=(CIS,), fix=fix, confidence=conf)


R_ROOT_MFA = r("AWS-ROOT-NO-MFA", "Root account without MFA", C, "Enable a hardware or passkey MFA on the root user and lock the credentials away.", "CWE-308", A07)
R_ROOT_KEYS = r("AWS-ROOT-ACCESS-KEYS", "Root account has access keys", C, "Delete root access keys; use IAM roles for every workload.", "CWE-250", A07)
R_PW_POLICY = r("AWS-PASSWORD-POLICY-WEAK", "IAM password policy missing or weak", M, "Require 14+ characters and prevent reuse of the last 24 passwords (or use SSO and no IAM passwords).", "CWE-521", A07)
R_USER_NO_MFA = r("AWS-IAM-USER-NO-MFA", "Console user without MFA", H, "Enforce MFA for every IAM user with a console password, or move humans to IAM Identity Center.", "CWE-308", A07)
R_OLD_KEY = r("AWS-IAM-OLD-ACCESS-KEY", "Access key older than 90 days", M, "Rotate the key, or better, replace it with a role (OIDC for CI, instance/task roles for workloads).", "CWE-324", A07)
R_UNUSED_CRED = r("AWS-IAM-UNUSED-CREDENTIAL", "Credential unused for 90+ days", L, "Disable and delete credentials nobody uses.", "CWE-1188", A07)
R_ADMIN_POLICY = r("AWS-IAM-ADMIN-POLICY", "Customer policy grants *:*", C, "Replace with least-privilege policies (IAM Access Analyzer can generate one from CloudTrail activity).", "CWE-250", A01)
R_USER_ADMIN = r("AWS-IAM-USER-ADMIN", "AdministratorAccess attached to an IAM user", H, "Grant admin through short-lived role assumption with MFA, not standing user attachments.", "CWE-250", A01)
R_ANALYZER = r("AWS-ACCESS-ANALYZER-OFF", "IAM Access Analyzer not enabled", L, "Create an account (or organization) analyzer in each region you use.", "CWE-778", A09, 0.9)
R_S3_ACCOUNT_PAB = r("AWS-S3-ACCOUNT-PAB-OFF", "Account-level S3 Block Public Access not fully enabled", H, "Enable all four account-level Block Public Access settings.", "CWE-284", A01)
R_S3_PUBLIC = r("AWS-S3-BUCKET-PUBLIC", "S3 bucket is public", C, "Remove public ACL grants and policy statements; serve public files through CloudFront with OAC.", "CWE-284", A01)
R_S3_TLS = r("AWS-S3-NO-TLS-ENFORCEMENT", "S3 bucket does not deny plain HTTP", M, "Add a bucket policy statement denying requests where aws:SecureTransport is false.", "CWE-319", A04)
R_SG_ADMIN = r("AWS-SG-ADMIN-PORT-OPEN", "Security group opens an admin port to the internet", C, "Restrict to a VPN/bastion CIDR or use SSM Session Manager.", "CWE-668")
R_SG_DATA = r("AWS-SG-DATA-PORT-OPEN", "Security group opens a database port to the internet", C, "Allow only the application's security group.", "CWE-668")
R_SG_ALL = r("AWS-SG-ALL-OPEN", "Security group allows all traffic from the internet", C, "Open only the required ports.", "CWE-668")
R_IMDS = r("AWS-EC2-IMDSV1", "Running instance allows IMDSv1", H, "Set HttpTokens=required (aws ec2 modify-instance-metadata-options).", "CWE-918", A01)
R_EBS_DEFAULT = r("AWS-EBS-DEFAULT-ENCRYPTION-OFF", "EBS encryption by default is off", M, "Enable EBS encryption by default in every region.", "CWE-311", A04)
R_SNAPSHOT_PUBLIC = r("AWS-SNAPSHOT-PUBLIC", "EBS snapshot or AMI shared publicly", C, "Remove the 'all' create-volume / launch permission.", "CWE-200", A01)
R_FLOW_LOGS = r("AWS-VPC-NO-FLOW-LOGS", "VPC without flow logs", L, "Enable VPC flow logs (at least REJECT traffic) to investigate incidents.", "CWE-778", A09, 0.9)
R_RDS_PUBLIC = r("AWS-RDS-PUBLIC", "RDS instance publicly accessible", C, "Set PubliclyAccessible=false and use private networking.", "CWE-668", A01)
R_RDS_ENC = r("AWS-RDS-UNENCRYPTED", "RDS storage not encrypted", H, "Encryption cannot be enabled in place: snapshot, copy with encryption, restore.", "CWE-311", A04)
R_RDS_BACKUP = r("AWS-RDS-NO-BACKUPS", "RDS automated backups disabled", H, "Set a backup retention period of at least 7 days.", "CWE-404", A02)
R_TRAIL = r("AWS-CLOUDTRAIL-GAP", "No complete multi-region CloudTrail", H, "Create a multi-region trail with log file validation, KMS encryption, delivered to a separate account.", "CWE-778", A09)
R_GUARDDUTY = r("AWS-GUARDDUTY-OFF", "GuardDuty not enabled", M, "Enable GuardDuty in every active region (organization-wide if possible).", "CWE-778", A09)
R_CONFIG = r("AWS-CONFIG-OFF", "AWS Config not recording", L, "Enable an AWS Config recorder for resource history and compliance.", "CWE-778", A09, 0.9)
R_KMS = r("AWS-KMS-NO-ROTATION", "Customer KMS key without rotation", L, "Enable automatic key rotation.", "CWE-320", A04)
R_LAMBDA_URL = r("AWS-LAMBDA-URL-PUBLIC", "Lambda function URL without auth", H, "Use AuthType AWS_IAM or front the function with an authenticated API.", "CWE-306", A07)
R_LAMBDA_RUNTIME = r("AWS-LAMBDA-DEPRECATED-RUNTIME", "Lambda on a deprecated runtime", M, "Upgrade the runtime; deprecated runtimes stop receiving security patches.", "CWE-1104", A06)
R_EKS_PUBLIC = r("AWS-EKS-PUBLIC-ENDPOINT", "EKS API endpoint open to the internet", M, "Disable public access or restrict publicAccessCidrs.", "CWE-668")
R_SKIPPED = rule("AWS-CHECK-SKIPPED", "AWS check could not run", I, "cloud", fix="Grant the SecurityAudit managed policy to the scanning identity.", confidence=1.0)

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 2375: "Docker", 2376: "Docker", 6443: "Kubernetes API", 10250: "kubelet"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
              5601: "Kibana", 11211: "Memcached", 9042: "Cassandra", 5984: "CouchDB", 9092: "Kafka", 2181: "ZooKeeper", 8123: "ClickHouse"}
DEPRECATED_RUNTIMES = {"python2.7", "python3.6", "python3.7", "python3.8", "python3.9", "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10",
                       "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x", "nodejs20.x", "ruby2.5", "ruby2.7", "ruby3.2", "java8",
                       "go1.x", "dotnetcore1.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6", "dotnet7", "provided"}


class AWSAudit:
    """`session` is a boto3.Session (or any object with .client(name, region_name=))."""

    def __init__(self, session: Any, regions: list[str] | None = None, now: datetime | None = None) -> None:
        self.session = session
        self.regions = regions
        self.now = now or datetime.now(timezone.utc)
        self.account = "unknown"
        self.findings: list[Finding] = []

    # ------------------------------------------------------------ plumbing
    def client(self, name: str, region: str = "us-east-1") -> Any:
        return self.session.client(name, region_name=region)

    def add(self, r_, resource: str, msg: str, sev: Severity | None = None, **extra: Any) -> None:
        f = Finding(r_, f"aws://{self.account}/{resource}", 0, msg, snippet=resource, extra={"anchor": f"{r_.id}:{resource}", **extra})
        f.verification = "observed"
        if sev is not None:
            f.severity = sev
        self.findings.append(f)

    def guarded(self, label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # AccessDenied, opt-in regions, throttling: report, keep going
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            self.add(R_SKIPPED, label, f"{label} skipped: {code}")

    def run(self) -> list[Finding]:
        sts = self.client("sts")
        self.account = sts.get_caller_identity()["Account"]
        if self.regions is None:
            ec2 = self.client("ec2")
            self.regions = sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"])
        for label, fn in (("iam/root", self.iam_root), ("iam/password-policy", self.password_policy), ("iam/credential-report", self.credential_report),
                          ("iam/policies", self.iam_policies), ("s3/account", self.s3_account), ("s3/buckets", self.s3_buckets),
                          ("cloudtrail", self.cloudtrail)):
            self.guarded(label, fn)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(self.region, self.regions))
        self.findings.sort(key=lambda f: -f.risk)
        return self.findings

    def region(self, region: str) -> None:
        for label, fn in (("ec2/security-groups", self.security_groups), ("ec2/instances", self.instances), ("ec2/ebs", self.ebs),
                          ("ec2/vpc-flow-logs", self.flow_logs), ("rds", self.rds), ("guardduty", self.guardduty), ("config", self.config),
                          ("kms", self.kms), ("lambda", self.lambdas), ("eks", self.eks), ("access-analyzer", self.access_analyzer)):
            self.guarded(f"{region}/{label}", lambda fn=fn: fn(region))

    # ------------------------------------------------------------ IAM
    def iam_root(self) -> None:
        summary = self.client("iam").get_account_summary()["SummaryMap"]
        if not summary.get("AccountMFAEnabled"):
            self.add(R_ROOT_MFA, "iam/root", "The root user has no MFA device.")
        if summary.get("AccountAccessKeysPresent"):
            self.add(R_ROOT_KEYS, "iam/root", "The root user has active access keys.")

    def password_policy(self) -> None:
        iam = self.client("iam")
        try:
            p = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            self.add(R_PW_POLICY, "iam/password-policy", "No account password policy is set.")
            return
        weak = []
        if p.get("MinimumPasswordLength", 0) < 14:
            weak.append(f"minimum length {p.get('MinimumPasswordLength')}")
        if p.get("PasswordReusePrevention", 0) < 24:
            weak.append("reuse prevention < 24")
        if weak:
            self.add(R_PW_POLICY, "iam/password-policy", "Password policy: " + ", ".join(weak) + ".")

    def credential_report(self) -> None:
        iam = self.client("iam")
        for _ in range(10):
            if iam.generate_credential_report()["State"] == "COMPLETE":
                break
            time.sleep(1)
        content = iam.get_credential_report()["Content"]
        rows = csv.DictReader(io.StringIO(content.decode() if isinstance(content, bytes) else content))
        for row in rows:
            user = row["user"]
            if user == "<root_account>":
                continue
            if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
                self.add(R_USER_NO_MFA, f"iam/user/{user}", f"User {user} can sign in to the console without MFA.")
            for n in ("1", "2"):
                if row.get(f"access_key_{n}_active") != "true":
                    continue
                rotated = _parse(row.get(f"access_key_{n}_last_rotated"))
                used = _parse(row.get(f"access_key_{n}_last_used_date"))
                if rotated and (self.now - rotated).days > 90:
                    self.add(R_OLD_KEY, f"iam/user/{user}/key{n}", f"Access key {n} of {user} is {(self.now - rotated).days} days old.")
                if (used and (self.now - used).days > 90) or (not used and rotated and (self.now - rotated).days > 90):
                    self.add(R_UNUSED_CRED, f"iam/user/{user}/key{n}", f"Access key {n} of {user} has not been used in 90+ days.")

    def iam_policies(self) -> None:
        iam = self.client("iam")
        for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=True):
            for pol in page["Policies"]:
                doc = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
                stmts = doc.get("Statement", [])
                for st in stmts if isinstance(stmts, list) else [stmts]:
                    actions = st.get("Action", [])
                    resources = st.get("Resource", [])
                    actions = [actions] if isinstance(actions, str) else actions
                    resources = [resources] if isinstance(resources, str) else resources
                    if st.get("Effect") == "Allow" and "*" in actions and "*" in resources:
                        self.add(R_ADMIN_POLICY, f"iam/policy/{pol['PolicyName']}", f"Policy {pol['PolicyName']} allows * on *.")
                        break
        admin = "arn:aws:iam::aws:policy/AdministratorAccess"
        for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=admin, EntityFilter="User"):
            for u in page["PolicyUsers"]:
                self.add(R_USER_ADMIN, f"iam/user/{u['UserName']}", f"User {u['UserName']} has AdministratorAccess attached directly.")

    def access_analyzer(self, region: str) -> None:
        aa = self.client("accessanalyzer", region)
        if not [a for a in aa.list_analyzers()["analyzers"] if a.get("status") == "ACTIVE"]:
            self.add(R_ANALYZER, f"{region}/access-analyzer", f"No active IAM Access Analyzer in {region}.")

    # ------------------------------------------------------------ S3
    def s3_account(self) -> None:
        s3c = self.client("s3control")
        try:
            cfg = s3c.get_public_access_block(AccountId=self.account)["PublicAccessBlockConfiguration"]
        except s3c.exceptions.NoSuchPublicAccessBlockConfiguration:
            cfg = {}
        off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not cfg.get(k)]
        if off:
            self.add(R_S3_ACCOUNT_PAB, "s3/account", "Account Block Public Access off: " + ", ".join(off) + ".")

    def s3_buckets(self) -> None:
        s3 = self.client("s3")
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            rs3 = self.client("s3", region)
            public_reason = []
            try:
                if rs3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
                    public_reason.append("bucket policy is public")
            except rs3.exceptions.ClientError:
                pass
            acl = rs3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                uri = (g.get("Grantee") or {}).get("URI", "")
                if uri.endswith(("/global/AllUsers", "/global/AuthenticatedUsers")):
                    public_reason.append(f"ACL grants {g.get('Permission')} to {uri.rsplit('/', 1)[-1]}")
            if public_reason:
                self.add(R_S3_PUBLIC, f"s3/{name}", f"Bucket {name}: " + "; ".join(public_reason) + ".")
            try:
                policy = json.loads(rs3.get_bucket_policy(Bucket=name)["Policy"])
            except rs3.exceptions.ClientError:
                policy = {}
            if "aws:SecureTransport" not in json.dumps(policy):
                self.add(R_S3_TLS, f"s3/{name}", f"Bucket {name} accepts plain-HTTP requests (no aws:SecureTransport deny).")

    # ------------------------------------------------------------ EC2 / VPC
    def security_groups(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    world = [x.get("CidrIp") for x in perm.get("IpRanges", []) if x.get("CidrIp") == "0.0.0.0/0"]
                    world += [x.get("CidrIpv6") for x in perm.get("Ipv6Ranges", []) if x.get("CidrIpv6") == "::/0"]
                    if not world:
                        continue
                    res = f"{region}/ec2/{sg['GroupId']}"
                    if perm.get("IpProtocol") == "-1":
                        self.add(R_SG_ALL, res, f"{sg['GroupId']} ({sg.get('GroupName')}) allows all traffic from {', '.join(world)}.", region=region)
                        continue
                    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                    admin = [f"{p}/{n}" for p, n in ADMIN_PORTS.items() if lo <= p <= hi]
                    data = [f"{p}/{n}" for p, n in DATA_PORTS.items() if lo <= p <= hi]
                    if hi - lo > 1000:
                        self.add(R_SG_ALL, res, f"{sg['GroupId']} opens ports {lo}-{hi} to {', '.join(world)}.", region=region)
                    elif admin:
                        self.add(R_SG_ADMIN, res, f"{sg['GroupId']} opens {', '.join(admin)} to {', '.join(world)}.", region=region)
                    elif data:
                        self.add(R_SG_DATA, res, f"{sg['GroupId']} opens {', '.join(data)} to {', '.join(world)}.", region=region)

    def instances(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        for page in ec2.get_paginator("describe_instances").paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if (inst.get("MetadataOptions") or {}).get("HttpTokens") != "required":
                        self.add(R_IMDS, f"{region}/ec2/{inst['InstanceId']}", f"{inst['InstanceId']} accepts IMDSv1 requests.", region=region)

    def ebs(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            self.add(R_EBS_DEFAULT, f"{region}/ebs", f"EBS encryption by default is off in {region}.", region=region)
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"], RestorableByUserIds=["all"]):
            for snap in page["Snapshots"]:
                self.add(R_SNAPSHOT_PUBLIC, f"{region}/ebs/{snap['SnapshotId']}", f"Snapshot {snap['SnapshotId']} can be restored by any AWS account.", region=region)
        for img in ec2.describe_images(Owners=["self"], ExecutableUsers=["all"]).get("Images", []):
            self.add(R_SNAPSHOT_PUBLIC, f"{region}/ami/{img['ImageId']}", f"AMI {img['ImageId']} is public.", region=region)

    def flow_logs(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        vpcs = {v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"]}
        logged = {fl.get("ResourceId") for fl in ec2.describe_flow_logs()["FlowLogs"]}
        for vpc in sorted(vpcs - logged):
            self.add(R_FLOW_LOGS, f"{region}/vpc/{vpc}", f"VPC {vpc} has no flow logs.", region=region)

    # ------------------------------------------------------------ data
    def rds(self, region: str) -> None:
        rds = self.client("rds", region)
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                rid = f"{region}/rds/{db['DBInstanceIdentifier']}"
                if db.get("PubliclyAccessible"):
                    self.add(R_RDS_PUBLIC, rid, f"{db['DBInstanceIdentifier']} is publicly accessible.", region=region)
                if not db.get("StorageEncrypted"):
                    self.add(R_RDS_ENC, rid, f"{db['DBInstanceIdentifier']} storage is not encrypted.", region=region)
                if db.get("BackupRetentionPeriod", 0) == 0:
                    self.add(R_RDS_BACKUP, rid, f"{db['DBInstanceIdentifier']} has automated backups disabled.", region=region)

    # ------------------------------------------------------------ logging & detection
    def cloudtrail(self) -> None:
        ct = self.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
        good = []
        for t in trails:
            if not t.get("IsMultiRegionTrail"):
                continue
            status = self.client("cloudtrail", t.get("HomeRegion", "us-east-1")).get_trail_status(Name=t["TrailARN"])
            if status.get("IsLogging"):
                good.append(t)
        if not good:
            self.add(R_TRAIL, "cloudtrail", "No multi-region trail is logging.")
            return
        if not any(t.get("LogFileValidationEnabled") for t in good):
            self.add(R_TRAIL, "cloudtrail", "Multi-region trail without log file validation.", sev=Severity.MEDIUM)
        if not any(t.get("KmsKeyId") for t in good):
            self.add(R_TRAIL, "cloudtrail", "Multi-region trail not encrypted with KMS.", sev=Severity.LOW)

    def guardduty(self, region: str) -> None:
        gd = self.client("guardduty", region)
        if not gd.list_detectors()["DetectorIds"]:
            self.add(R_GUARDDUTY, f"{region}/guardduty", f"GuardDuty is not enabled in {region}.", region=region)

    def config(self, region: str) -> None:
        cfg = self.client("config", region)
        statuses = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        if not any(s.get("recording") for s in statuses):
            self.add(R_CONFIG, f"{region}/config", f"AWS Config is not recording in {region}.", region=region)

    def kms(self, region: str) -> None:
        kms = self.client("kms", region)
        for page in kms.get_paginator("list_keys").paginate():
            for k in page["Keys"]:
                meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled" or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue
                if not kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]:
                    self.add(R_KMS, f"{region}/kms/{k['KeyId']}", f"Key {k['KeyId']} has rotation disabled.", region=region)

    # ------------------------------------------------------------ compute
    def lambdas(self, region: str) -> None:
        lam = self.client("lambda", region)
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page["Functions"]:
                name = fn["FunctionName"]
                if fn.get("Runtime") in DEPRECATED_RUNTIMES:
                    self.add(R_LAMBDA_RUNTIME, f"{region}/lambda/{name}", f"{name} runs on {fn.get('Runtime')}.", region=region)
                for url in lam.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", []):
                    if url.get("AuthType") == "NONE":
                        self.add(R_LAMBDA_URL, f"{region}/lambda/{name}", f"{name} has a public function URL without auth ({url.get('FunctionUrl')}).", region=region)

    def eks(self, region: str) -> None:
        eks = self.client("eks", region)
        for name in eks.list_clusters().get("clusters", []):
            vpc = eks.describe_cluster(name=name)["cluster"].get("resourcesVpcConfig", {})
            if vpc.get("endpointPublicAccess") and "0.0.0.0/0" in vpc.get("publicAccessCidrs", ["0.0.0.0/0"]):
                self.add(R_EKS_PUBLIC, f"{region}/eks/{name}", f"EKS cluster {name} API is reachable from any IP.", region=region)


def _parse(value: str | None) -> datetime | None:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def audit(profile: str | None = None, regions: list[str] | None = None) -> Iterator[Finding]:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError('boto3 is required: pip install "rempart[aws]"') from exc
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    yield from AWSAudit(session, regions).run()
