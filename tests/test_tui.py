import os
import tempfile
import unittest
from pathlib import Path

from tests.helpers import write_tree

from rempart.history import History
from rempart.knowledge import FILE
from rempart.models import Finding, Severity
from rempart.registry import REGISTRY
from rempart.tui import Session, _fit, _shorten, bar, code_context, describe, describe_chain, domain_counts, domain_worst, fix_first, \
    suggested_reason, visible

try:
    import textual  # noqa: F401
    HAVE_TEXTUAL = True
except ImportError:
    HAVE_TEXTUAL = False

APP = {
    "app/text.py": "from internal_policy import POLICY\n\n\ndef clean_html(value):\n    return POLICY.apply(value)\n",
    "app/views.py": """
        import os
        from flask import Flask, request
        from app.text import clean_html

        app = Flask(__name__)

        @app.get("/a")
        def a():
            return "<p>" + clean_html(request.args["x"]) + "</p>"

        @app.get("/b")
        def b():
            return "<p>" + clean_html(request.args["y"]) + "</p>"

        @app.get("/ping")
        def ping():
            os.system("ping " + request.args["h"])
            return "ok"

        if __name__ == "__main__":
            app.run(host="0.0.0.0", debug=True)
        """,
}


class Isolated(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["REMPART_HOME"] = self.home
        os.environ.setdefault("GIT_CEILING_DIRECTORIES", tempfile.gettempdir())
        self.root = Path(tempfile.mkdtemp(prefix="rempart-tui-"))
        write_tree(self.root, APP)

    def tearDown(self):
        os.environ.pop("REMPART_HOME", None)


class LogicTest(Isolated):
    def test_session_scan_is_the_cli_pipeline_and_records_history(self):
        s = Session(self.root, offline=True)
        steps = []
        res = s.scan(lambda step, done, total: steps.append((step, done, total)))
        self.assertIn("CODE-CMD-INJECTION", {f.rule.id for f in res.findings})
        self.assertEqual(steps[0][1], 0)
        self.assertEqual(steps[-1][0], "learning and attack paths")
        self.assertEqual(len(s.history), 1)
        hist = History()
        self.assertEqual(len(hist.scans(str(self.root.resolve()))), 1)
        hist.close()

    def test_teaching_a_reason_then_rescanning_removes_the_class(self):
        s = Session(self.root, offline=True)
        xss = [f for f in s.scan().findings if f.rule.id == "CODE-XSS-SINK"]
        self.assertEqual(len(xss), 2)
        said = s.triage(xss[0], "fp", because="sanitizer:clean_html")
        self.assertIn("clean_html() sanitises xss", said)
        self.assertTrue((self.root / FILE).is_file())
        self.assertFalse([f for f in s.scan().findings if f.rule.id == "CODE-XSS-SINK"])
        self.assertTrue(s.diff["gone"])  # learned away, not "fixed"

    def test_filters(self):
        r = REGISTRY
        fs = [Finding(r["CODE-EVAL"], "a.py", 1, "eval on input", severity=Severity.HIGH),
              Finding(r["SEC-GENERIC"], "conf/b.py", 2, "secret", severity=Severity.LOW),
              Finding(r["CHAIN-RCE-TO-HOST"], "a.py", 1, "chain", severity=Severity.CRITICAL)]
        self.assertEqual(len(visible(fs)), 3)
        self.assertEqual([f.rule.id for f in visible(fs, domain="code")], ["CODE-EVAL"])
        self.assertEqual(len(visible(fs, min_severity=Severity.HIGH)), 2)
        self.assertEqual([f.path for f in visible(fs, query="CONF/")], ["conf/b.py"])
        self.assertEqual(domain_counts(fs)[0], ("attack-path", 1))  # chains first
        self.assertEqual(domain_worst(fs)["code"], Severity.HIGH)

    def test_fix_first_puts_proven_paths_first_and_does_not_repeat_their_links(self):
        res = Session(self.root, offline=True).scan()
        actions = fix_first(res.findings)
        self.assertTrue(actions)
        self.assertTrue(actions[0].target.startswith("chain:"))
        self.assertIn("break it:", actions[0].detail)
        chain = next(f for f in res.findings if f.fingerprint == actions[0].target[6:])
        members = set(chain.extra["members"])
        self.assertFalse([a for a in actions if a.target.startswith("finding:") and a.target[8:] in members])

    def test_chain_is_drawn_stage_by_stage(self):
        res = Session(self.root, offline=True).scan()
        chain = next(f for f in res.findings if f.rule.domain == "attack-path")
        self.assertTrue(chain.extra["stages"])
        text = " ".join(str(getattr(p, "plain", "")) for p in describe_chain(chain, {f.fingerprint: f for f in res.findings}))
        self.assertIn("attacker", text)
        self.assertIn("impact", text)

    def test_suggested_reason(self):
        self.assertEqual(suggested_reason(Finding(REGISTRY["CODE-XSS-SINK"], "a.py", 1, "")), "sanitizer:")
        self.assertEqual(suggested_reason(Finding(REGISTRY["SEC-GENERIC"], "a.py", 1, "")), "placeholder:")
        self.assertEqual(suggested_reason(Finding(REGISTRY["DOCKER-RUNS-AS-ROOT"], "Dockerfile", 1, "")), "")

    def test_detail_shows_the_code_around_the_finding(self):
        f = next(f for f in Session(self.root, offline=True).scan().findings if f.rule.id == "CODE-CMD-INJECTION")
        code, start = code_context(self.root, f)
        self.assertIn('os.system("ping "', code)
        self.assertLessEqual(start, f.line)
        self.assertIsNone(code_context(self.root, Finding(REGISTRY["AWS-ROOT-NO-MFA"], "aws://123/iam", 0, "")))
        self.assertGreater(len(describe(self.root, f, "tp")), 4)

    def test_text_helpers(self):
        from rich.text import Text

        self.assertEqual(bar(5, 10, 10, "red").cell_len, 10)
        self.assertEqual(bar(0, 0, 6, "red").cell_len, 6)
        fitted = _fit(Text("deep/dir/file.py:12"), 10, left=True).plain
        self.assertEqual((fitted, len(fitted)), ("…ile.py:12", 10))
        self.assertEqual(_fit(Text("abcdefghij"), 6).cell_len, 6)
        self.assertEqual(_shorten("First part. Second part that is long", 20), "First part.")
        self.assertTrue(_shorten("one two three four five six", 12).endswith("…"))


@unittest.skipUnless(HAVE_TEXTUAL, "textual not installed")
class AppTest(Isolated, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from rempart.tui import build_app

        self.app = build_app(self.root, offline=True)

    async def loaded(self, pilot):
        await self.app.workers.wait_for_complete()
        await pilot.pause()
        await pilot.pause()

    async def test_overview_then_jump_to_a_path(self):
        async with self.app.run_test(size=(180, 50)) as pilot:
            await self.loaded(pilot)
            app = self.app
            self.assertEqual(app.query_one("#views").active, "overview")
            self.assertTrue(app.actions)
            await pilot.press("enter")  # first "fix first" action is a proven path
            await pilot.pause()
            self.assertEqual(app.query_one("#views").active, "paths")

    async def test_browse_filter_and_triage(self):
        async with self.app.run_test(size=(180, 50)) as pilot:
            await self.loaded(pilot)
            app = self.app
            await pilot.press("f")  # finding actions are off outside the findings view
            await pilot.pause()
            self.assertEqual(app.verdicts, {})
            await pilot.press("2")
            await pilot.pause()
            await pilot.press("down")
            await pilot.pause()
            self.assertEqual(app.domain, "")
            self.assertEqual(app.query_one("#findings").cursor_row, 1)
            target = app.current()
            await pilot.press("f")
            await pilot.pause()
            self.assertEqual(app.verdicts[target.fingerprint], "fp")
            hist = History()
            row = hist.db.execute("SELECT verdict, source FROM verdicts WHERE fingerprint = ?", (target.fingerprint,)).fetchone()
            hist.close()
            self.assertEqual(row, ("fp", "human"))
            await pilot.press("slash", *"ping")
            await pilot.pause()
            self.assertTrue(app.shown)
            self.assertTrue(all("ping" in f"{f.path} {f.message} {f.rule.id} {f.rule.title}".lower() for f in app.shown))
            await pilot.press("escape", "s", "s", "s")  # low → medium → high → critical
            await pilot.pause()
            self.assertTrue(all(f.severity == Severity.CRITICAL for f in app.shown))

    async def test_teach_a_reason_from_the_interface(self):
        async with self.app.run_test(size=(180, 50)) as pilot:
            await self.loaded(pilot)
            app = self.app
            await pilot.press("2")
            await pilot.pause()
            app.query_text = "XSS"
            app.refresh_table()
            self.assertEqual(len(app.shown), 2)
            await pilot.press("b")
            await pilot.pause()
            await pilot.press("t")  # typed into the dialog, never a triage of what is behind it
            await pilot.pause()
            self.assertEqual(app.verdicts, {})
            await pilot.press("backspace", *"clean_html", "enter")
            await self.loaded(pilot)
            self.assertTrue((self.root / FILE).is_file())
            self.assertEqual(app.shown, [])  # the whole class is gone after the automatic rescan

    async def test_every_view_and_the_report(self):
        async with self.app.run_test(size=(180, 50)) as pilot:
            await self.loaded(pilot)
            for key, pane in (("3", "paths"), ("4", "deps"), ("5", "learning"), ("1", "overview")):
                await pilot.press(key)
                await pilot.pause()
                self.assertEqual(self.app.query_one("#views").active, pane)
            await pilot.press("question_mark")
            await pilot.pause()
            self.assertEqual(type(self.app.screen).__name__, "HelpScreen")
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()
            self.assertTrue((self.root / "rempart-report.html").is_file())


if __name__ == "__main__":
    unittest.main()
