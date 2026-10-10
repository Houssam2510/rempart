import unittest
from datetime import datetime, timezone

from rempart.cloud_multi import AzureAudit, GCPAudit

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def fixtures(table: dict):
    calls = []

    def run(args):
        calls.append(args)
        for key, value in table.items():
            if args[:len(key)] == list(key):
                if isinstance(value, Exception):
                    raise value
                return value
        return []
    run.calls = calls
    return run


GCP = {
    ("projects", "get-iam-policy"): {"bindings": [
        {"role": "roles/viewer", "members": ["allAuthenticatedUsers"]},
        {"role": "roles/editor", "members": ["serviceAccount:ci@demo.iam.gserviceaccount.com", "user:dev@example.org"]}]},
    ("iam", "service-accounts", "list"): [{"email": "ci@demo.iam.gserviceaccount.com"}],
    ("iam", "service-accounts", "keys", "list"): [{"name": "projects/demo/serviceAccounts/ci/keys/abcdef0123456789", "validAfterTime": "2025-01-01T00:00:00Z"}],
    ("storage", "buckets", "list"): [{"name": "public-assets"}, {"name": "invoices", "public_access_prevention": "inherited", "uniform_bucket_level_access": False},
                                     {"name": "locked", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}],
    ("storage", "buckets", "get-iam-policy", "gs://public-assets"): {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
    ("compute", "firewall-rules", "list"): [
        {"name": "allow-ssh", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        {"name": "allow-pg", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["5000-6000"]}]},
        {"name": "office", "direction": "INGRESS", "sourceRanges": ["203.0.113.0/24"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}],
    ("sql", "instances", "list"): [{"name": "main", "databaseVersion": "POSTGRES_15", "settings": {
        "ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"value": "0.0.0.0/0"}]}, "backupConfiguration": {"enabled": False}}}],
    ("compute", "instances", "list"): [{"name": "web-1", "serviceAccounts": [{"email": "123-compute@developer.gserviceaccount.com",
                                                                               "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
                                        "metadata": {"items": [{"key": "serial-port-enable", "value": "TRUE"}]}}],
}

AZURE = {
    ("account", "show"): {"id": "sub-123"},
    ("storage", "account", "list"): [{"name": "files", "allowBlobPublicAccess": True, "enableHttpsTrafficOnly": False, "minimumTlsVersion": "TLS1_0",
                                      "networkRuleSet": {"defaultAction": "Allow"}},
                                     {"name": "safe", "allowBlobPublicAccess": False, "enableHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2",
                                      "networkRuleSet": {"defaultAction": "Deny"}}],
    ("network", "nsg", "list"): [{"name": "web-nsg", "securityRules": [
        {"name": "rdp", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationPortRange": "3389"},
        {"name": "redis", "direction": "Inbound", "access": "Allow", "protocol": "*", "sourceAddressPrefix": "Internet", "destinationPortRange": "6379"},
        {"name": "https", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationPortRange": "443"}]}],
    ("sql", "server", "list"): [{"name": "db1", "resourceGroup": "rg", "publicNetworkAccess": "Enabled"}],
    ("sql", "server", "firewall-rule", "list"): [{"name": "AllowAll", "startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}],
    ("keyvault", "list"): [{"name": "kv1", "properties": {"enablePurgeProtection": None}}],
    ("role", "assignment", "list"): [{"roleDefinitionName": "Owner", "principalType": "ServicePrincipal", "principalName": "deploy-sp",
                                      "scope": "/subscriptions/sub-123"}],
}


class GCPTest(unittest.TestCase):
    def test_fixture_project(self) -> None:
        found = GCPAudit(fixtures(GCP), "demo", now=NOW).audit()
        ids = sorted(f.rule.id for f in found)
        self.assertEqual(ids, sorted([
            "GCP-IAM-PUBLIC-MEMBER", "GCP-IAM-SA-PRIMITIVE-ROLE", "GCP-LOGGING-NO-DATA-ACCESS", "GCP-IAM-SA-KEY-OLD",
            "GCP-STORAGE-PUBLIC", "GCP-STORAGE-NO-PAP", "GCP-FW-ADMIN-OPEN", "GCP-FW-DATA-OPEN",
            "GCP-FW-ADMIN-OPEN",  # 5000-6000 also covers WinRM (5985-5986)
            "GCP-SQL-AUTHORIZED-ANY", "GCP-SQL-NO-SSL", "GCP-SQL-NO-BACKUP", "GCP-VM-DEFAULT-SA-FULL-SCOPE", "GCP-VM-SERIAL-PORT"]))
        self.assertTrue(all(f.path.startswith("gcp://demo/") and f.verification == "observed" for f in found))

    def test_permission_error_is_reported_not_fatal(self) -> None:
        table = dict(GCP)
        table[("sql", "instances", "list")] = RuntimeError("Cloud SQL Admin API has not been used in project demo")
        found = GCPAudit(fixtures(table), "demo", now=NOW).audit()
        self.assertIn("GCP-CHECK-SKIPPED", {f.rule.id for f in found})
        self.assertIn("GCP-FW-DATA-OPEN", {f.rule.id for f in found})


class AzureTest(unittest.TestCase):
    def test_fixture_subscription(self) -> None:
        found = AzureAudit(fixtures(AZURE), now=NOW).audit()
        ids = sorted(f.rule.id for f in found)
        self.assertEqual(ids, sorted(["AZ-STORAGE-PUBLIC-BLOB", "AZ-STORAGE-HTTP", "AZ-STORAGE-OLD-TLS", "AZ-STORAGE-OPEN-NETWORK",
                                      "AZ-NSG-ADMIN-OPEN", "AZ-NSG-DATA-OPEN", "AZ-SQL-FIREWALL-ANY", "AZ-KEYVAULT-NO-PURGE-PROTECTION",
                                      "AZ-RBAC-SP-OWNER"]))
        self.assertTrue(all(f.path.startswith("azure://sub-123/") for f in found))


if __name__ == "__main__":
    unittest.main()
