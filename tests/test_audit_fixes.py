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


if __name__ == "__main__":
    unittest.main()
