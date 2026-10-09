import unittest

from rempart.models import Severity
from tests.helpers import scan_tree

HELPERS = '''
import subprocess


class RequestWrapper:
    def __init__(self, request):
        self.request = request

    def get_form_parameter(self, name):
        return self.request.form.get(name)

    def get_safe_value(self, name):
        return "bar"


def run_tool(arg):
    subprocess.run("tool " + arg, shell=True)


def quote_sql(value):
    return value.replace("'", "''")
'''


def high(result, rule_id: str, path: str) -> list:
    return [f for f in result.findings if f.rule.id == rule_id and f.path == path and f.severity >= Severity.HIGH]


class InterproceduralTest(unittest.TestCase):
    def test_constant_return_across_files_is_not_user_data(self) -> None:
        result = scan_tree({"helpers/wrap.py": HELPERS, "app.py": '''
            from flask import Flask, request
            import helpers.wrap

            app = Flask(__name__)

            @app.route("/a")
            def a():
                scr = helpers.wrap.RequestWrapper(request)
                param = scr.get_safe_value("x")
                eval(param)
                return "ok"
        '''}, ["code"])
        self.assertEqual(high(result, "CODE-EVAL", "app.py"), [])

    def test_wrapped_request_value_stays_tainted(self) -> None:
        result = scan_tree({"helpers/wrap.py": HELPERS, "app.py": '''
            from flask import Flask, request
            import helpers.wrap

            app = Flask(__name__)

            @app.route("/a")
            def a():
                scr = helpers.wrap.RequestWrapper(request)
                param = scr.get_form_parameter("x")
                eval(param)
                return "ok"
        '''}, ["code"])
        self.assertTrue(high(result, "CODE-EVAL", "app.py"))

    def test_sink_inside_helper_is_reported_at_the_call_site(self) -> None:
        result = scan_tree({"helpers/wrap.py": HELPERS, "app.py": '''
            from flask import Flask, request
            from helpers.wrap import run_tool

            app = Flask(__name__)

            @app.route("/a")
            def a():
                run_tool(request.args["x"])
                return "ok"
        '''}, ["code"])
        hits = high(result, "CODE-CMD-INJECTION", "app.py")
        self.assertTrue(hits)
        self.assertIn("helpers/wrap.py", hits[0].message)

    def test_helper_called_with_constant_is_quiet(self) -> None:
        result = scan_tree({"helpers/wrap.py": HELPERS, "app.py": '''
            from helpers.wrap import run_tool

            def job():
                run_tool("--version")
        '''}, ["code"])
        self.assertEqual(high(result, "CODE-CMD-INJECTION", "app.py"), [])

    def test_sanitiser_summary_is_respected(self) -> None:
        result = scan_tree({"helpers/wrap.py": HELPERS, "app.py": '''
            from flask import Flask, request
            from helpers.wrap import quote_sql

            app = Flask(__name__)

            @app.route("/a")
            def a(cur):
                v = quote_sql(request.args["name"])
                cur.execute("SELECT * FROM t WHERE name = '" + v + "'")
                return "ok"
        '''}, ["code"])
        self.assertEqual(high(result, "CODE-SQL-INJECTION", "app.py"), [])


if __name__ == "__main__":
    unittest.main()
