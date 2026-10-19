import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.helpers import FAKE_AWS_KEY, rule_ids, scan_tree

from rempart import bench
from rempart.cli import main


def write_case(root: Path, name: str, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / name / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


class MaterialiseTest(unittest.TestCase):
    def test_labels_point_at_the_next_line_of_the_cleaned_copy(self):
        src, dest = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        write_case(src, "c", {"app.py": """
            import os
            # rempart-expect: CODE-EVAL
            eval(x)
            // rempart-safe: CODE-SSRF, CODE-EVAL
            y = 1
            """, ".env": """
            # rempart-expect-file: SEC-ENV-COMMITTED
            KEY={{FAKE_AWS_KEY}}
            """})
        labels = bench.materialise(src / "c", dest)
        self.assertEqual((dest / "app.py").read_text(), "import os\neval(x)\ny = 1\n")
        self.assertIn(bench.TOKENS["FAKE_AWS_KEY"], (dest / ".env").read_text())
        got = {(lb.path, lb.line, lb.rule, lb.kind) for lb in labels}
        self.assertEqual(got, {("app.py", 2, "CODE-EVAL", "expect"), ("app.py", 3, "CODE-SSRF", "safe"),
                               ("app.py", 3, "CODE-EVAL", "safe"), (".env", 0, "SEC-ENV-COMMITTED", "expect")})

    def test_jsx_comment_markers(self):
        src, dest = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        write_case(src, "c", {"p.tsx": "{/* rempart-expect: CODE-XSS-SINK */}\n<div/>\n"})
        self.assertEqual([lb.line for lb in bench.materialise(src / "c", dest)], [1])


class ScoringTest(unittest.TestCase):
    def corpus(self) -> Path:
        root = Path(tempfile.mkdtemp())
        write_case(root, "flask", {"app.py": """
            import os
            import subprocess
            from flask import request

            def a():
                # rempart-expect: CODE-CMD-INJECTION
                os.system("ping " + request.args["h"])

            def b():
                # rempart-safe: CODE-CMD-INJECTION
                subprocess.run(["ping", "-c", "1", "127.0.0.1"])

            def c():
                # rempart-expect: CODE-SQL-INJECTION
                return "never reported"
            """})
        return root

    def test_tp_fn_and_traps_per_domain(self):
        r = bench.run(self.corpus())
        code = r.domains["code"]
        self.assertEqual((code.tp, code.fn, code.traps, code.traps_fired), (1, 1, 1, 0))
        self.assertEqual(code.precision, 1.0)
        self.assertEqual(code.recall, 0.5)
        self.assertEqual([(m.kind, m.rule) for m in r.misses], [("fn", "CODE-SQL-INJECTION")])

    def test_check_reports_a_drop(self):
        r = bench.run(self.corpus())
        better = {"domains": {"code": {"precision": 1.0, "recall": 1.0}}}
        self.assertEqual(bench.check(r, better), ["code: recall 100.0% → 50.0%"])
        self.assertEqual(bench.check(r, {"domains": {"code": {"precision": 1.0, "recall": 0.5}}}), [])

    def test_alt_location_is_neither_tp_nor_fp(self):
        root = Path(tempfile.mkdtemp())
        write_case(root, "x", {"lib.py": """
            import os

            def run_tool(arg):
                # rempart-alt: CODE-CMD-INJECTION
                return os.system("convert " + arg)
            """, "views.py": """
            from flask import request
            from lib import run_tool

            def v():
                # rempart-expect: CODE-CMD-INJECTION
                run_tool(request.args["f"])
            """})
        c = bench.run(root).domains["code"]
        self.assertEqual((c.tp, c.fp, c.fn), (1, 0, 0))

    def test_bundled_corpus_meets_its_baseline(self):
        baseline = Path(__file__).resolve().parents[1] / "bench" / "baseline.json"
        r = bench.run()
        self.assertGreaterEqual(r.cases, 20)
        self.assertEqual(bench.check(r, json.loads(baseline.read_text())), [])

    def test_cli(self):
        out = Path(tempfile.mkdtemp()) / "b.json"
        self.assertEqual(main(["bench", "--corpus", str(self.corpus()), "--update", str(out)]), 0)
        self.assertEqual(main(["bench", "--corpus", str(self.corpus()), "--check", str(out)]), 0)


class FoundByTheBenchTest(unittest.TestCase):
    """Defects the first bench run exposed; each stays fixed."""

    def test_java_sql_concatenation_with_quote_inside_the_literal(self):
        res = scan_tree({"A.java": 'class A { void f(HttpServletRequest request) { st.executeQuery("SELECT * FROM u WHERE id = \'" + request.getParameter("id") + "\'"); } }\n'})
        self.assertIn("CODE-SQL-INJECTION", rule_ids(res))

    def test_typosquat_checked_on_exactly_pinned_requirements(self):
        res = scan_tree({"requirements.txt": "reqeusts==2.31.0\nflask==3.0.3\n"})
        self.assertIn("SUPPLY-TYPOSQUAT", rule_ids(res))
        self.assertNotIn("SUPPLY-UNPINNED", rule_ids(res))

    def test_env_pointing_at_a_secret_file_is_not_a_secret(self):
        res = scan_tree({"Dockerfile": "FROM python:3.12-slim\nENV API_SECRET_FILE=/run/secrets/api\nUSER app\n"})
        self.assertNotIn("DOCKER-SECRET-IN-IMAGE", rule_ids(res))

    def test_vendor_documented_example_key_is_not_reported(self):
        res = scan_tree({"setup.sh": "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\n", "real.sh": f"KEY={FAKE_AWS_KEY}\n"})
        self.assertEqual({f.path for f in res.findings if f.rule.id == "SEC-AWS-ACCESS-KEY"}, {"real.sh"})

    def test_card_number_in_a_small_file(self):
        res = scan_tree({"payments.csv": "customer,card\nalice,4539148803436467\n"})
        self.assertIn("DATA-PAYMENT-CARD", rule_ids(res))

    def test_model_output_reaching_a_shell_through_variables(self):
        res = scan_tree({"agent.py": """
            import subprocess
            from anthropic import Anthropic
            client = Anthropic()
            def go(task):
                msg = client.messages.create(model="m", max_tokens=10, messages=[])
                command = msg.content[0].text
                return subprocess.run(command, shell=True)
            """})
        self.assertIn("AI-OUTPUT-TO-SINK", rule_ids(res))

    def test_flask_2_shortcut_decorators_are_html_routes(self):
        app = 'from flask import Flask, request\napp = Flask(__name__)\n\n@app.get("/")\ndef page():\n    return "<h1>" + request.args["q"] + "</h1>"\n'
        self.assertIn("CODE-XSS-SINK", rule_ids(scan_tree({"views.py": app}, ["code"])))
        api = app.replace("from flask import Flask, request", "from fastapi import FastAPI, Request\nfrom flask import request")
        self.assertNotIn("CODE-XSS-SINK", rule_ids(scan_tree({"views.py": api}, ["code"])))

    def test_dash_c_is_a_shell_script_only_after_a_shell(self):
        app = "import subprocess\nfrom flask import request\ndef f():\n    subprocess.run([{argv}, request.args['h']])\n"
        self.assertNotIn("CODE-CMD-INJECTION", rule_ids(scan_tree({"a.py": app.format(argv='"ping", "-c", "1"')}, ["code"])))
        self.assertIn("CODE-CMD-INJECTION", rule_ids(scan_tree({"a.py": app.format(argv='"/bin/sh", "-c"')}, ["code"])))

    def test_bound_sql_parameters_through_a_helper_are_not_injection(self):
        res = scan_tree({"db.py": """
            import sqlite3
            def run_params(query, params):
                return sqlite3.connect("a.db").execute(query, params).fetchall()
            """, "views.py": """
            from flask import request
            from db import run_params
            def v():
                return run_params("SELECT * FROM t WHERE id = ?", (request.args["id"],))
            """}, ["code"])
        self.assertNotIn("CODE-SQL-INJECTION", rule_ids(res))

    def test_terraform_line_is_the_resource_header_after_a_blank_line(self):
        res = scan_tree({"main.tf": 'variable "x" {}\n\nresource "aws_s3_bucket_acl" "a" {\n  acl = "public-read"\n}\n'}, ["terraform"])
        self.assertEqual([f.line for f in res.findings if f.rule.id == "TF-S3-PUBLIC-ACL"], [3])


if __name__ == "__main__":
    unittest.main()
