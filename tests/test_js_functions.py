import unittest

from rempart.models import Severity
from tests.helpers import scan_tree


def hits(files, rule_id):
    res = scan_tree(files, ["code"])
    return [f for f in res.findings if f.rule.id == rule_id and f.severity >= Severity.HIGH]


class JsFunctionFlowTest(unittest.TestCase):
    def test_request_data_through_local_helper_reaches_exec(self) -> None:
        found = hits({"server/git.js": '''
            const { exec } = require("child_process");

            function gitLog(branch) {
              return new Promise((resolve) => exec("git log --oneline " + branch, (e, out) => resolve(out)));
            }

            app.get("/log", async (req, res) => {
              res.send(await gitLog(req.query.branch));
            });
        '''}, "CODE-CMD-INJECTION")
        self.assertEqual(len(found), 1)
        self.assertIn("gitLog()", found[0].message)

    def test_tainted_variable_and_arrow_function(self) -> None:
        found = hits({"api/files.ts": '''
            import { readFile } from "fs/promises";
            import path from "path";

            const load = async (name: string) => {
              return readFile(path.join("/data", name), "utf8");
            };

            export async function GET(request: Request) {
              const url = new URL(request.url);
              const file = url.searchParams.get("f");
              return new Response(await load(file));
            }
        '''}, "CODE-PATH-TRAVERSAL")
        self.assertEqual(len(found), 1)

    def test_constant_or_sanitised_arguments_are_quiet(self) -> None:
        files = {"server/git.js": '''
            const { exec } = require("child_process");
            const quote = require("shell-quote").quote;

            function run(cmd) {
              exec("nice " + cmd);
            }

            run("git gc");
            app.get("/x", (req, res) => run(quote([req.query.a])));
        '''}
        self.assertEqual(hits(files, "CODE-CMD-INJECTION"), [])


if __name__ == "__main__":
    unittest.main()
