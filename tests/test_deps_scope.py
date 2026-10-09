import json
import unittest

from rempart.models import Finding, Severity
from rempart.reachability import find_symbol_use
from rempart.scanners.deps import R_VULN, upgrade_plan, vulnerable_symbols
from rempart.scanners.lockfiles import Package, parse_package_lock, parse_pnpm_lock, parse_requirements


def vuln(pkg: str, version: str, advisory: str, fixed: list[str], sev: Severity = Severity.HIGH, **extra) -> Finding:
    f = Finding(R_VULN, "package-lock.json", 1, advisory, extra={"package": pkg, "version": version, "ecosystem": "npm",
                                                                  "advisory": advisory, "fixed": fixed, **extra})
    f.severity = sev
    return f


class DevScopeTest(unittest.TestCase):
    def test_package_lock_dev_flags(self) -> None:
        lock = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/next": {"version": "14.2.32"},
            "node_modules/vitest": {"version": "1.0.0", "dev": True},
            "node_modules/fsevents": {"version": "2.3.3", "devOptional": True},
        }})
        pkgs = {p.name: p.dev for p in parse_package_lock("package-lock.json", lock)}
        self.assertEqual(pkgs, {"next": False, "vitest": True, "fsevents": True})

    def test_pnpm_v6_dev_marker(self) -> None:
        lock = "lockfileVersion: '6.0'\npackages:\n  /vite@5.0.0:\n    resolution: {integrity: x}\n    dev: true\n  /react@18.2.0:\n    resolution: {integrity: y}\n    dev: false\n"
        pkgs = {p.name: p.dev for p in parse_pnpm_lock("pnpm-lock.yaml", lock)}
        self.assertEqual(pkgs, {"vite": True, "react": False})

    def test_requirements_dev_file(self) -> None:
        self.assertTrue(all(p.dev for p in parse_requirements("requirements-dev.txt", "pytest==8.0.0\n")))
        self.assertFalse(any(p.dev for p in parse_requirements("requirements.txt", "flask==3.0.0\n")))


class UpgradePlanTest(unittest.TestCase):
    def test_smallest_version_fixing_everything(self) -> None:
        plan = upgrade_plan([
            vuln("next", "14.2.10", "GHSA-a", ["14.2.15", "15.0.1"]),
            vuln("next", "14.2.10", "GHSA-b", ["14.2.25"], Severity.CRITICAL, kev=True),
            vuln("lodash", "4.17.20", "GHSA-c", ["4.17.21"], Severity.MEDIUM),
        ])
        self.assertEqual(plan[0]["package"], "next")
        self.assertEqual(plan[0]["target"], "14.2.25")
        self.assertFalse(plan[0]["major_bump"])
        self.assertEqual(plan[0]["fixes"], 2)
        self.assertEqual(plan[1]["target"], "4.17.21")

    def test_unfixed_advisory_is_reported(self) -> None:
        plan = upgrade_plan([vuln("x", "1.0.0", "GHSA-z", [])])
        self.assertIsNone(plan[0]["target"])
        self.assertEqual(plan[0]["unfixed"], ["GHSA-z"])


class SymbolReachabilityTest(unittest.TestCase):
    def test_symbols_from_osv_record(self) -> None:
        record = {"affected": [{"package": {"name": "golang.org/x/net", "ecosystem": "Go"},
                                "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/html", "symbols": ["Parse", "Tokenizer.Next"]}]}}]}
        pkg = Package("Go", "golang.org/x/net", "v0.1.0", "go.mod", 3)
        self.assertEqual(vulnerable_symbols(record, pkg), ["Parse", "Next"])

    def test_call_site_found_or_not(self) -> None:
        files = {"main.go": 'package main\nimport "golang.org/x/net/html"\nfunc f() { html.Parse(r) }\n', "util.go": "package main\n"}
        self.assertEqual(find_symbol_use(files, files.get, "Go", ["Parse"]), ("main.go", 3, "Parse"))
        self.assertIsNone(find_symbol_use(files, files.get, "Go", ["Render"]))


if __name__ == "__main__":
    unittest.main()
