import json
import os
import tempfile
import unittest
from pathlib import Path

from tests.helpers import FAKE_AWS_KEY, scan_tree

from rempart.cli import main
from rempart.engine import score
from rempart.history import History
from rempart.models import Finding
from rempart.registry import REGISTRY, load_all_rules
from rempart.reporters import RENDERERS


class RegistryTest(unittest.TestCase):
    def test_rules_are_well_formed(self):
        rules = load_all_rules()
        self.assertGreater(len(rules), 180)
        for r in rules.values():
            self.assertTrue(r.remediation, f"{r.id} has no remediation")
            for cwe in r.cwe:
                self.assertRegex(cwe, r"^CWE-\d+$")


class FingerprintTest(unittest.TestCase):
    def test_fingerprint_ignores_line_moves(self):
        r = REGISTRY["CODE-EVAL"]
        a = Finding(r, "a.py", 10, "m", snippet="eval(x)")
        b = Finding(r, "a.py", 42, "m", snippet="eval(x)   ")
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_score_diminishing_returns(self):
        r = REGISTRY["CODE-EVAL"]
        one = score([Finding(r, "a", 1, "m", snippet="1")])[0]
        many = score([Finding(r, "a", i, "m", snippet=str(i)) for i in range(50)])[0]
        self.assertGreater(many, 20)
        self.assertLess(many, one)


class ReportersTest(unittest.TestCase):
    def test_all_formats(self):
        res = scan_tree({"a.js": f'const k = "{FAKE_AWS_KEY}";\neval(userInput);\n'}, ["secrets", "code"])
        sarif = json.loads(RENDERERS["sarif"](res))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        data = json.loads(RENDERERS["json"](res))
        self.assertIn("grade", data)
        self.assertNotIn(FAKE_AWS_KEY, RENDERERS["html"](res) + RENDERERS["md"](res) + json.dumps(data))


class LearningTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["REMPART_HOME"] = self.home

    def tearDown(self):
        os.environ.pop("REMPART_HOME", None)

    def test_feedback_loop(self):
        res = scan_tree({"a.js": "eval(x);\neval(y);\n"}, ["code"])
        hist = History(Path(self.home) / "t.db")
        project = res.root
        sid = hist.record(project, res)
        self.assertTrue(sid)
        fp_id = res.findings[0].fingerprint
        hist.triage(project, fp_id[:8], "fp")
        kept, suppressed = hist.apply_knowledge(project, list(res.findings))
        self.assertEqual(suppressed, 1)
        self.assertEqual(len(kept), 1)
        self.assertIn("learned precision", kept[0].learned_note)
        self.assertLess(kept[0].confidence, REGISTRY["CODE-EVAL"].confidence)
        hist.close()

    def test_cli_end_to_end(self):
        root = tempfile.mkdtemp()
        Path(root, "app.py").write_text("import os\nfrom flask import request\nos.system('rm ' + request.args['f'])\n")
        out = Path(root, "r.sarif")
        code = main(["scan", root, "--offline", "-f", "sarif", "-o", str(out), "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertTrue(out.read_text().startswith("{"))
        self.assertEqual(main(["history", root]), 0)
        self.assertEqual(main(["rules", "--domain", "data"]), 0)


if __name__ == "__main__":
    unittest.main()


class HistoryDiffTest(unittest.TestCase):
    def test_triaged_findings_are_not_counted_as_fixed(self):
        home = tempfile.mkdtemp()
        res = scan_tree({"a.js": "eval(x);\neval(y);\n"}, ["code"])
        hist = History(Path(home) / "h.db")
        project = res.root
        hist.record(project, res)
        hist.triage(project, res.findings[0].fingerprint, "fp")
        kept, _ = hist.apply_knowledge(project, list(res.findings))
        res.findings = kept
        sid = hist.record(project, res)
        diff = hist.diff_with_previous(project, sid)
        self.assertEqual(diff["fixed"], [])
        self.assertIsNone(hist.mttr_days(project))
        hist.close()


class AIVerdictPolicyTest(unittest.TestCase):
    def test_ai_verdicts_never_close_or_override_human(self):
        home = tempfile.mkdtemp()
        res = scan_tree({"a.js": "eval(x);\neval(y);\n"}, ["code"])
        hist = History(Path(home) / "h.db")
        project = res.root
        hist.record(project, res)
        a, b = res.findings[0].fingerprint, res.findings[1].fingerprint
        hist.triage(project, a, "fp", source="ai")
        kept, suppressed = hist.apply_knowledge(project, list(res.findings))
        self.assertEqual(suppressed, 0)  # AI cannot close
        self.assertAlmostEqual(hist.rule_stats()["CODE-EVAL"].fp, 0.5)  # and counts half
        hist.triage(project, b, "tp")  # human
        hist.triage(project, b, "fp", source="ai")  # ignored: human verdict stands
        verdict = hist.db.execute("SELECT verdict, source FROM verdicts WHERE fingerprint = ?", (b,)).fetchone()
        self.assertEqual(verdict, ("tp", "human"))
        hist.close()
