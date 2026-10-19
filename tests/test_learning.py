import os
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import scan_tree, write_tree

from rempart.cli import main
from rempart.config import Config
from rempart.engine import run_scan
from rempart.history import Calibrator, Evidence, History
from rempart.knowledge import FILE, Knowledge
from rempart.models import Finding, Severity
from rempart.registry import REGISTRY, load_all_rules
from rempart.scanners import ALL_SCANNERS

# The sanitiser delegates to an internal library Rempart cannot see: only a verdict can teach it.
XSS_APP = {
    "app/text.py": "from internal_policy import POLICY\n\n\ndef clean_html(value):\n    return POLICY.apply(value)\n",
    "app/views.py": """
        from flask import Flask, request
        from app.text import clean_html

        app = Flask(__name__)

        @app.get("/")
        def page():
            return "<h1>" + clean_html(request.args["q"]) + "</h1>"
        """,
}


def scan(root: Path, scanners: tuple[str, ...] = ("code",)):
    return run_scan(root, [ALL_SCANNERS[n] for n in scanners], Config(), offline=True)


def project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="rempart-learn-"))
    write_tree(root, files)
    return root


class KnowledgeTest(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("GIT_CEILING_DIRECTORIES", tempfile.gettempdir())

    def test_learned_python_sanitiser_closes_the_whole_class(self):
        root = project(XSS_APP)
        before = [f for f in scan(root).findings if f.rule.id == "CODE-XSS-SINK"]
        self.assertTrue(before, "the custom sanitiser is unknown at first")
        k = Knowledge.load(root)
        self.assertEqual(k.learn("sanitizer", "clean_html", "CODE-XSS-SINK", "app/views.py:5"), "clean_html() sanitises xss")
        k.save(root)
        self.assertFalse([f for f in scan(root).findings if f.rule.id == "CODE-XSS-SINK"])

    def test_category_is_respected(self):
        root = project({"app.py": """
            import os
            from flask import request
            from helpers import clean_html
            def a():
                os.system("echo " + clean_html(request.args["q"]))
            """, "helpers.py": "def clean_html(v):\n    return v\n"})
        k = Knowledge()
        k.learn("sanitizer", "clean_html", "CODE-XSS-SINK", "x")  # xss only
        k.save(root)
        self.assertIn("CODE-CMD-INJECTION", {f.rule.id for f in scan(root).findings})

    def test_learned_js_sanitiser(self):
        files = {"src/app.js": """
            const { exec } = require("child_process");
            app.get("/x", (req, res) => {
              const name = toSafeName(req.query.f);
              exec(`convert ${name} out.png`);
            });
            """}
        root = project(files)
        self.assertIn("CODE-CMD-INJECTION", {f.rule.id for f in scan(root).findings if f.severity >= Severity.HIGH})
        k = Knowledge()
        k.learn("sanitizer", "toSafeName", "CODE-CMD-INJECTION", "src/app.js:4")
        k.save(root)
        self.assertNotIn("CODE-CMD-INJECTION", {f.rule.id for f in scan(root).findings if f.severity >= Severity.HIGH})

    def test_placeholder_is_never_a_secret(self):
        root = project({"config.py": 'api_secret = "dev9Token4Local7Only"\n'})
        self.assertIn("SEC-GENERIC", {f.rule.id for f in scan(root, ("secrets",)).findings})
        k = Knowledge()
        k.learn("placeholder", "dev9Token4Local7Only", "SEC-GENERIC", "config.py:1")
        k.save(root)
        self.assertNotIn("SEC-GENERIC", {f.rule.id for f in scan(root, ("secrets",)).findings})

    def test_proposals_apply_only_once_accepted(self):
        root = project(XSS_APP)
        k = Knowledge.load(root)
        k.learn("sanitizer", "clean_html", "CODE-XSS-SINK", "app/views.py:5", proposed=True)
        k.save(root)
        self.assertTrue([f for f in scan(root).findings if f.rule.id == "CODE-XSS-SINK"])
        self.assertEqual(main(["learn", "--path", str(root), "--accept-proposals"]), 0)
        self.assertFalse([f for f in scan(root).findings if f.rule.id == "CODE-XSS-SINK"])

    def test_round_trip_and_errors(self):
        root = Path(tempfile.mkdtemp())
        k = Knowledge()
        k.learn("sanitizer", "pkg.mod.clean=sql,xss", "CODE-EVAL", "a.py:1")
        k.learn("placeholder", 'quote"d', "SEC-GENERIC", "b.py:2")
        k.save(root)
        again = Knowledge.load(root)
        self.assertEqual(again.sanitizers, {"pkg.mod.clean": frozenset({"sql", "xss"})})
        self.assertEqual(again.placeholders, {'quote"d'})
        self.assertTrue(again.sanitizes("x.pkg.mod.clean", "clean", "sql"))
        self.assertEqual(again.digest(), k.digest())
        with self.assertRaises(ValueError):
            Knowledge().learn("sanitizer", "f", "SEC-GENERIC", "x")  # not a data-flow rule
        with self.assertRaises(ValueError):
            Knowledge().learn("magic", "f", "CODE-EVAL", "x")
        with self.assertRaises(ValueError):
            Knowledge().learn("placeholder", "abcd", "SEC-GENERIC", "x", proposed=True)


class ImplicitSignalsTest(unittest.TestCase):
    def setUp(self):
        self.db = History(Path(tempfile.mkdtemp()) / "h.db")
        os.environ.setdefault("GIT_CEILING_DIRECTORIES", tempfile.gettempdir())

    def tearDown(self):
        self.db.close()

    def cycle(self, root: Path, profile: str = "p"):
        res = scan(root, ("code", "secrets"))
        res.findings, _ = self.db.apply_knowledge(str(root), res.findings)
        self.db.record(str(root), res, profile)
        return res

    def verdicts(self, root: Path):
        return self.db.db.execute("SELECT rule_id, verdict, source FROM verdicts WHERE project = ?", (str(root),)).fetchall()

    def test_a_fix_is_a_true_positive_and_its_return_a_regression(self):
        vulnerable = "import os\nfrom flask import request\ndef a():\n    os.system('ping ' + request.args['h'])\n"
        root = project({"app.py": vulnerable})
        self.cycle(root)
        (root / "app.py").write_text("import subprocess\nfrom flask import request\ndef a():\n    subprocess.run(['ping', request.args['h']])\n")
        self.cycle(root)
        self.assertIn(("CODE-CMD-INJECTION", "tp", "implicit"), self.verdicts(root))
        (root / "app.py").write_text(vulnerable)
        back = [f for f in self.cycle(root).findings if f.rule.id == "CODE-CMD-INJECTION"]
        self.assertTrue(back[0].extra.get("regression"))
        self.assertEqual(back[0].severity, Severity.CRITICAL)
        self.assertIn("regression", back[0].learned_note)

    def test_no_signal_when_the_scan_itself_changed_or_the_file_is_gone(self):
        root = project({"app.py": "import os\nfrom flask import request\nos.system('x ' + request.args['h'])\n", "b.py": "eval(input())\n"})
        self.cycle(root, "p1")
        (root / "app.py").write_text("print(1)\n")
        self.cycle(root, "p2")  # different options: nothing can be concluded
        self.assertEqual(self.verdicts(root), [])
        self.cycle(root, "p2")
        (root / "b.py").unlink()
        self.cycle(root, "p2")  # the file was deleted, not fixed
        self.assertEqual(self.verdicts(root), [])

    def test_inline_ignore_is_weak_false_positive_evidence(self):
        root = project({"app.py": "def f(x):\n    return eval(x)  # rempart:ignore[CODE-EVAL] trusted plugin loader\n"})
        self.cycle(root)
        self.assertEqual(self.verdicts(root), [("CODE-EVAL", "fp", "inline")])

    def test_human_verdict_is_never_overwritten_by_automatic_sources(self):
        root = project({"app.py": "def f(x):\n    return eval(x)\n"})
        res = self.cycle(root)
        fp = res.findings[0].fingerprint
        self.db.triage(str(root), fp, "tp")
        self.db.triage(str(root), fp, "fp", source="ai")
        self.db._put_verdict(str(root), fp, "CODE-EVAL", "fp", "", "implicit", "app.py")
        self.assertEqual(self.verdicts(root), [("CODE-EVAL", "tp", "human")])
        self.db.triage(str(root), fp, "fp")  # a person may change their mind
        self.assertEqual(self.verdicts(root), [("CODE-EVAL", "fp", "human")])


class CalibratorTest(unittest.TestCase):
    def test_older_evidence_and_older_rule_versions_weigh_less(self):
        rules = load_all_rules()
        now = time.time()
        fresh = Calibrator([Evidence("CODE-EVAL", "fp", "human", now, "a.py")], rules, now)
        old = Calibrator([Evidence("CODE-EVAL", "fp", "human", now - 365 * 86400, "a.py")], rules, now)
        self.assertAlmostEqual(fresh.by_rule["CODE-EVAL"].fp, 1.0)
        self.assertAlmostEqual(old.by_rule["CODE-EVAL"].fp, 0.5)
        sqli = REGISTRY["CODE-SQL-INJECTION"]
        self.assertGreater(sqli.version, 1)
        stale = Calibrator([Evidence(sqli.id, "fp", "human", now, "a.py", rule_version=1)], rules, now)
        self.assertAlmostEqual(stale.by_rule[sqli.id].fp, 0.25)

    def test_prior_is_the_scanners_own_confidence(self):
        cal = Calibrator([Evidence("CODE-EVAL", "fp", "human", time.time(), "a.py")], load_all_rules())
        strong = Finding(REGISTRY["CODE-EVAL"], "b.py", 1, "", confidence=0.95)
        weak = Finding(REGISTRY["CODE-EVAL"], "b.py", 1, "", confidence=0.4)
        for f in (strong, weak):
            f.raw = (int(f.severity), f.confidence)
            cal.adjust(f)
        self.assertGreater(strong.confidence, weak.confidence)


class ReplayTest(unittest.TestCase):
    def test_learning_ranks_confirmed_issues_above_repeated_false_alarms(self):
        db = History(Path(tempfile.mkdtemp()) / "r.db")
        noisy, real = REGISTRY["CODE-WEAK-HASH"], REGISTRY["CODE-SSRF"]
        t0 = time.time() - 30 * 86400
        for day in range(12):
            ts = t0 + day * 86400
            sid = db.db.execute("INSERT INTO scans(project, ts, version, profile) VALUES ('p', ?, '0', 'x')", (ts,)).lastrowid
            for rule, verdict, sev, conf in ((noisy, "fp", "HIGH", 0.9), (real, "tp", "MEDIUM", 0.6)):
                fp = f"{rule.id}-{day}"
                db.db.execute("INSERT INTO findings(scan_id, fingerprint, rule_id, severity, path, line, message, base_severity, base_confidence)"
                              " VALUES (?,?,?,?,?,1,'',?,?)", (sid, fp, rule.id, sev, f"f{day}.py", sev, conf))
                db.db.execute("INSERT INTO verdicts(project, fingerprint, rule_id, verdict, ts, source, path) VALUES ('p',?,?,?,?, 'human', ?)",
                              (fp, rule.id, verdict, ts + 3600, f"f{day}.py"))
        db.db.commit()
        r = db.replay("p")
        self.assertEqual(r["labelled"], 24)
        self.assertLess(r["without_learning"]["auc"], 0.5)
        self.assertGreater(r["with_learning"]["auc"], r["without_learning"]["auc"])
        self.assertLess(r["with_learning"]["brier"], r["without_learning"]["brier"])
        self.assertLess(r["with_learning"]["top10"]["false_positives"], r["without_learning"]["top10"]["false_positives"])
        db.close()


class CliTest(unittest.TestCase):
    def test_triage_because_then_rescan(self):
        home = tempfile.mkdtemp()
        os.environ["REMPART_HOME"] = home
        try:
            root = project(XSS_APP)
            self.assertEqual(main(["scan", str(root), "--offline", "--only", "code", "-f", "json", "-o", str(root / "r.json")]), 0)
            import json

            fid = next(f["fingerprint"] for f in json.loads((root / "r.json").read_text())["findings"] if f["rule_id"] == "CODE-XSS-SINK")
            self.assertEqual(main(["triage", fid[:10], "--fp", "--because", "sanitizer:clean_html", "--path", str(root)]), 0)
            self.assertTrue((root / FILE).is_file())
            self.assertEqual(main(["triage", fid[:10], "--tp", "--because", "sanitizer:x", "--path", str(root)]), 2)
            self.assertEqual(main(["learn", "--path", str(root)]), 0)
            self.assertEqual(main(["learn", "--path", str(root), "--eval"]), 0)
            res = scan(root)
            self.assertFalse([f for f in res.findings if f.rule.id == "CODE-XSS-SINK"])
        finally:
            os.environ.pop("REMPART_HOME", None)


class EngineTest(unittest.TestCase):
    def test_scan_result_carries_what_learning_needs(self):
        res = scan_tree({"a.py": "eval(x)  # rempart:ignore\n", "b.py": "print(1)\n"}, ["code"])
        self.assertEqual(sorted(res.files), ["a.py", "b.py"])
        self.assertEqual([f.rule.id for f in res.ignored], ["CODE-EVAL"])
        self.assertTrue(res.knowledge_digest)


if __name__ == "__main__":
    unittest.main()
