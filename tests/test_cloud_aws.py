"""AWS audit tests with botocore's Stubber: every request and response is
validated against the real AWS service models, so a wrong operation or
parameter name fails here even without an AWS account."""

import unittest
from datetime import datetime, timezone

try:
    import boto3
    from botocore.stub import Stubber
except ImportError:  # boto3 is an optional extra
    boto3 = None


class StubSession:
    def __init__(self):
        self.clients = {}
        self.stubbers = {}

    def client(self, name, region_name="us-east-1"):
        key = (name, region_name)
        if key not in self.clients:
            c = boto3.client(name, region_name=region_name, aws_access_key_id="AKIATEST", aws_secret_access_key="test")
            self.clients[key] = c
            self.stubbers[key] = Stubber(c)
        return self.clients[key]

    def stub(self, name, region="us-east-1"):
        self.client(name, region)
        return self.stubbers[(name, region)]

    def activate(self):
        for s in self.stubbers.values():
            s.activate()


CRED_REPORT = (
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
    "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,N/A,not_supported,not_supported,false,"
    "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
    "alice,arn:aws:iam::123456789012:user/alice,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,false,"
    "true,2024-01-01T00:00:00+00:00,2024-02-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
)


@unittest.skipIf(boto3 is None, "boto3 not installed")
class AWSAuditTest(unittest.TestCase):
    def test_full_audit_against_service_models(self):
        from rempart.cloud_aws import AWSAudit

        s = StubSession()
        R = "us-east-1"
        s.stub("sts").add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/x", "UserId": "AIDX"})
        iam = s.stub("iam")
        iam.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}})
        iam.add_client_error("get_account_password_policy", service_error_code="NoSuchEntity", http_status_code=404)
        iam.add_response("generate_credential_report", {"State": "COMPLETE"})
        iam.add_response("get_credential_report", {"Content": CRED_REPORT.encode(), "ReportFormat": "text/csv", "GeneratedTime": datetime(2026, 10, 1, tzinfo=timezone.utc)})
        iam.add_response("list_policies", {"Policies": [{"PolicyName": "legacy", "Arn": "arn:aws:iam::123456789012:policy/legacy", "DefaultVersionId": "v1"}], "IsTruncated": False})
        iam.add_response("get_policy_version", {"PolicyVersion": {"Document": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}', "VersionId": "v1"}})
        iam.add_response("list_entities_for_policy", {"PolicyUsers": [{"UserName": "deployer", "UserId": "AIDAEXAMPLEUSER00001"}], "IsTruncated": False})
        s.stub("s3control").add_client_error("get_public_access_block", service_error_code="NoSuchPublicAccessBlockConfiguration", http_status_code=404)
        s3 = s.stub("s3")
        s3.add_response("list_buckets", {"Buckets": [{"Name": "public-assets", "CreationDate": datetime(2024, 1, 1)}]})
        s3.add_response("get_bucket_location", {})
        s3.add_response("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}})
        s3.add_response("get_bucket_acl", {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}], "Owner": {"ID": "o"}})
        s3.add_response("get_bucket_policy", {"Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::public-assets/*"}]}'})
        ct = s.stub("cloudtrail")
        ct.add_response("describe_trails", {"trailList": [{"Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t", "IsMultiRegionTrail": True, "HomeRegion": R, "LogFileValidationEnabled": False}]})
        ct.add_response("get_trail_status", {"IsLogging": True})
        ec2 = s.stub("ec2", R)
        ec2.add_response("describe_security_groups", {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]})
        ec2.add_response("describe_instances", {"Reservations": [{"Instances": [{"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional"}}]}]})
        ec2.add_response("get_ebs_encryption_by_default", {"EbsEncryptionByDefault": False})
        ec2.add_response("describe_snapshots", {"Snapshots": [{"SnapshotId": "snap-1"}]})
        ec2.add_response("describe_images", {"Images": []})
        ec2.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}]})
        ec2.add_response("describe_flow_logs", {"FlowLogs": []})
        s.stub("rds", R).add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "prod", "PubliclyAccessible": True, "StorageEncrypted": False, "BackupRetentionPeriod": 0}]})
        s.stub("guardduty", R).add_response("list_detectors", {"DetectorIds": []})
        s.stub("config", R).add_response("describe_configuration_recorder_status", {"ConfigurationRecordersStatus": []})
        kms = s.stub("kms", R)
        kms.add_response("list_keys", {"Keys": [{"KeyId": "k1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/k1"}], "Truncated": False})
        kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "k1", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT"}})
        kms.add_response("get_key_rotation_status", {"KeyRotationEnabled": False})
        lam = s.stub("lambda", R)
        lam.add_response("list_functions", {"Functions": [{"FunctionName": "api", "Runtime": "nodejs16.x"}]})
        lam.add_response("list_function_url_configs", {"FunctionUrlConfigs": [{"FunctionUrl": "https://abcdefghij.lambda-url.us-east-1.on.aws/", "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:api", "AuthType": "NONE", "CreationTime": "2024", "LastModifiedTime": "2024"}]})
        eks = s.stub("eks", R)
        eks.add_response("list_clusters", {"clusters": ["prod"]})
        eks.add_response("describe_cluster", {"cluster": {"name": "prod", "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}}})
        s.stub("accessanalyzer", R).add_response("list_analyzers", {"analyzers": []})
        s.activate()

        findings = AWSAudit(s, regions=[R], now=datetime(2026, 10, 8, tzinfo=timezone.utc)).run()
        ids = {f.rule.id for f in findings}
        skipped = [f.message for f in findings if f.rule.id == "AWS-CHECK-SKIPPED"]
        self.assertEqual(skipped, [])
        expected = {"AWS-ROOT-NO-MFA", "AWS-ROOT-ACCESS-KEYS", "AWS-PASSWORD-POLICY-WEAK", "AWS-IAM-USER-NO-MFA", "AWS-IAM-OLD-ACCESS-KEY",
                    "AWS-IAM-UNUSED-CREDENTIAL", "AWS-IAM-ADMIN-POLICY", "AWS-IAM-USER-ADMIN", "AWS-S3-ACCOUNT-PAB-OFF", "AWS-S3-BUCKET-PUBLIC",
                    "AWS-S3-NO-TLS-ENFORCEMENT", "AWS-CLOUDTRAIL-GAP", "AWS-SG-ADMIN-PORT-OPEN", "AWS-SG-DATA-PORT-OPEN", "AWS-EC2-IMDSV1",
                    "AWS-EBS-DEFAULT-ENCRYPTION-OFF", "AWS-SNAPSHOT-PUBLIC", "AWS-VPC-NO-FLOW-LOGS", "AWS-RDS-PUBLIC", "AWS-RDS-UNENCRYPTED",
                    "AWS-RDS-NO-BACKUPS", "AWS-GUARDDUTY-OFF", "AWS-CONFIG-OFF", "AWS-KMS-NO-ROTATION", "AWS-LAMBDA-URL-PUBLIC",
                    "AWS-LAMBDA-DEPRECATED-RUNTIME", "AWS-EKS-PUBLIC-ENDPOINT", "AWS-ACCESS-ANALYZER-OFF"}
        self.assertEqual(expected - ids, set())
        self.assertTrue(all(f.verification == "observed" for f in findings))
        self.assertTrue(all(f.path.startswith("aws://123456789012/") for f in findings))
        for stub in s.stubbers.values():
            stub.assert_no_pending_responses()

    def test_access_denied_is_reported_not_fatal(self):
        from rempart.cloud_aws import AWSAudit

        s = StubSession()
        s.stub("sts").add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/x", "UserId": "AIDX"})
        s.stub("iam").add_client_error("get_account_summary", service_error_code="AccessDenied", http_status_code=403)
        s.activate()
        audit = AWSAudit(s, regions=[])
        audit.account = "123456789012"
        audit.guarded("iam/root", audit.iam_root)
        self.assertEqual([f.rule.id for f in audit.findings], ["AWS-CHECK-SKIPPED"])
        self.assertIn("AccessDenied", audit.findings[0].message)


if __name__ == "__main__":
    unittest.main()
