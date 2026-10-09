import unittest

from tests.helpers import FAKE_AWS_KEY, FAKE_GH_TOKEN, FAKE_PRIVATE_KEY_HEADER, FAKE_STRIPE, rule_ids, scan_tree

from rempart.scanners.secrets import entropy, redact


class SecretsTest(unittest.TestCase):
    def test_provider_tokens_detected_and_redacted(self):
        res = scan_tree({
            "app/config.js": f"""
                const aws = "{FAKE_AWS_KEY}";
                const gh = '{FAKE_GH_TOKEN}';
                const stripe = "{FAKE_STRIPE}";
            """,
            "keys/server.key": FAKE_PRIVATE_KEY_HEADER + "\nMIIEow...\n",
        }, ["secrets"])
        ids = rule_ids(res)
        self.assertTrue({"SEC-AWS-ACCESS-KEY", "SEC-GITHUB-TOKEN", "SEC-STRIPE-LIVE", "SEC-PRIVATE-KEY", "SEC-KEY-FILE"} <= ids, ids)
        for f in res.findings:
            self.assertNotIn(FAKE_AWS_KEY, f.snippet + f.message)
            self.assertNotIn(FAKE_GH_TOKEN, f.snippet + f.message)

    def test_generic_assignment_needs_entropy(self):
        res = scan_tree({
            "settings.py": 'DB_PASSWORD = "Xk92-mQ7z!pR4vT1"\nPASSWORD_FIELD = "password"\nsecret = "changeme"\napi_key = os.environ["API_KEY"]\n',
        }, ["secrets"])
        generic = [f for f in res.findings if f.rule.id == "SEC-GENERIC"]
        self.assertEqual(len(generic), 1)
        self.assertEqual(generic[0].line, 1)

    def test_env_file_committed(self):
        res = scan_tree({".env": "DATABASE_URL=postgres://u:p@h/db\nSECRET=abcdef123\n", ".env.example": "SECRET=\n"}, ["secrets"])
        envs = [f for f in res.findings if f.rule.id == "SEC-ENV-COMMITTED"]
        self.assertEqual([f.path for f in envs], [".env"])

    def test_gitignored_env_is_not_reported(self):
        res = scan_tree({".gitignore": ".env\n", ".env": "SECRET=abcdef123456\n"}, ["secrets"], git=True)
        self.assertNotIn("SEC-ENV-COMMITTED", rule_ids(res))

    def test_test_paths_downgraded(self):
        res = scan_tree({"tests/fixtures/x.js": f'const k = "{FAKE_AWS_KEY}";'}, ["secrets"])
        f = next(f for f in res.findings if f.rule.id == "SEC-AWS-ACCESS-KEY")
        self.assertLess(f.confidence, 0.5)

    def test_inline_suppression(self):
        res = scan_tree({"a.js": f'const k = "{FAKE_AWS_KEY}"; // rempart:ignore[SEC-AWS-ACCESS-KEY]'}, ["secrets"])
        self.assertNotIn("SEC-AWS-ACCESS-KEY", rule_ids(res))
        self.assertEqual(res.suppressed, 1)

    def test_helpers(self):
        self.assertLess(entropy("aaaaaaaa"), 1)
        self.assertGreater(entropy("Xk92mQ7zpR4vT1"), 3.2)
        self.assertEqual(redact("abcdefghijklmnop"), "abcd**********op")


if __name__ == "__main__":
    unittest.main()
