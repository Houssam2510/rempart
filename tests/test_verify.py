import json
import unittest
from datetime import datetime, timezone

from tests.helpers import FAKE_AWS_KEY, FAKE_GH_TOKEN, scan_tree

from rempart import verify as V


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        for prefix, (status, body) in self.responses.items():
            if req.full_url.startswith(prefix):
                return status, body
        return 599, b""


class VerifyTest(unittest.TestCase):
    def setUp(self):
        V._cache.clear()

    def test_github_live_and_revoked(self):
        http = FakeHttp({"https://api.github.com/user": (200, json.dumps({"login": "octo"}).encode())})
        v = V.verify("SEC-GITHUB-TOKEN", FAKE_GH_TOKEN, "", http)
        self.assertEqual((v.status, v.detail), ("live", "GitHub user octo"))
        self.assertEqual(http.requests[0].get_header("Authorization"), "Bearer " + FAKE_GH_TOKEN)
        V._cache.clear()
        v = V.verify("SEC-GITHUB-TOKEN", FAKE_GH_TOKEN, "", FakeHttp({"https://api.github.com/user": (401, b"{}")}))
        self.assertEqual(v.status, "revoked")

    def test_aws_requires_paired_secret(self):
        v = V.verify("SEC-AWS-ACCESS-KEY", FAKE_AWS_KEY, "no secret here", FakeHttp({}))
        self.assertEqual(v.status, "unknown")
        V._cache.clear()
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
        text = f'aws_access_key_id = "{FAKE_AWS_KEY}"\naws_secret_access_key = "{secret}"\n'
        http = FakeHttp({"https://sts.amazonaws.com/": (200, b"<GetCallerIdentityResponse><Arn>arn:aws:iam::111122223333:user/ci</Arn><Account>111122223333</Account></GetCallerIdentityResponse>")})
        v = V.verify("SEC-AWS-ACCESS-KEY", FAKE_AWS_KEY, text, http)
        self.assertEqual(v.status, "live")
        self.assertIn("111122223333", v.detail)
        self.assertTrue(http.requests[0].get_header("Authorization").startswith("AWS4-HMAC-SHA256 Credential=" + FAKE_AWS_KEY))

    def test_sigv4_matches_botocore(self):
        try:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials
        except ImportError:
            self.skipTest("botocore not installed")
        when = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        ours = V.sigv4_headers("AKIDEXAMPLE", "secret", body, when)
        req = AWSRequest(method="POST", url="https://sts.amazonaws.com/", data=body,
                         headers={"Content-Type": ours["Content-Type"], "X-Amz-Date": ours["X-Amz-Date"]})
        signer = SigV4Auth(Credentials("AKIDEXAMPLE", "secret"), "sts", "us-east-1")
        import unittest.mock as m
        with m.patch("botocore.auth.get_current_datetime", return_value=when.replace(tzinfo=None)):
            signer.add_auth(req)
        self.assertEqual(req.headers["X-Amz-Date"], ours["X-Amz-Date"])
        self.assertEqual(req.headers["Authorization"], ours["Authorization"])

    def test_scanner_integration_marks_live_secret(self):
        V._cache.clear()
        V._cache[("SEC-GITHUB-TOKEN", __import__("hashlib").sha256(FAKE_GH_TOKEN.encode()).hexdigest())] = V.Verdict("live", "GitHub user octo")
        from pathlib import Path
        import tempfile
        from rempart.config import Config
        from rempart.engine import run_scan
        from rempart.scanners.secrets import SecretsScanner
        from tests.helpers import write_tree
        root = Path(tempfile.mkdtemp())
        write_tree(root, {"ci.sh": f'export GH="{FAKE_GH_TOKEN}"\n'})
        res = run_scan(root, [SecretsScanner()], Config(), offline=True, verify_secrets=True)
        f = next(f for f in res.findings if f.rule.id == "SEC-GITHUB-TOKEN")
        self.assertEqual((f.verification, f.severity.name, f.confidence), ("live-secret", "CRITICAL", 1.0))
        self.assertNotIn(FAKE_GH_TOKEN, f.message + f.snippet + json.dumps(f.extra))


if __name__ == "__main__":
    unittest.main()
