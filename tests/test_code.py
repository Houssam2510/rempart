import unittest

from tests.helpers import rule_ids, scan_tree

PY_VULN = '''
import os, pickle, subprocess, yaml, hashlib, random, requests, jwt
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/run")
def run():
    subprocess.run(f"ls {request.args['d']}", shell=True)
    os.system("ping " + request.args["host"])
    eval(request.args["expr"])
    data = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    cur.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")
    requests.get(request.args["url"], verify=False)
    token = random.randint(0, 10**6)
    h = hashlib.md5(password.encode())
    jwt.decode(t, key, options={"verify_signature": False})
    open(request.args["file"])
    return redirect(request.args["next"])

if __name__ == "__main__":
    app.run(debug=True)
'''

PY_SAFE = '''
import subprocess, yaml, secrets, hashlib
from flask import request

def ok(cur, user_id):
    subprocess.run(["ls", "-la"], check=True)
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    cfg = yaml.safe_load(open("c.yml"))
    token = secrets.token_urlsafe(32)
    etag = hashlib.sha256(b"x").hexdigest()
    eval("1 + 1")
'''

JS_VULN = '''
const { exec } = require("child_process");
app.get("/x", async (req, res) => {
  exec(`convert ${req.query.file} out.png`);
  const rows = await db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);
  el.innerHTML = req.query.html;
  const u = await User.findOne(req.body);
  await fetch(req.query.url);
  res.sendFile(req.query.path);
  res.redirect(req.query.next);
  const token = Math.random().toString(36);
  jwt.verify(t, k, { algorithms: ["HS256", "none"] });
  await User.create(req.body);
  localStorage.setItem("accessToken", t);
});
const secret = process.env.JWT_SECRET || "dev-secret";
const agent = new https.Agent({ rejectUnauthorized: false });
app.use(cors({
  origin: true,
  credentials: true,
}));
'''


class CodeTest(unittest.TestCase):
    def test_python_vulnerable(self):
        ids = rule_ids(scan_tree({"app.py": PY_VULN}, ["code"]))
        expected = {"CODE-CMD-INJECTION", "CODE-EVAL", "CODE-UNSAFE-DESERIALIZATION", "CODE-SQL-INJECTION", "CODE-TLS-VERIFY-DISABLED",
                    "CODE-SSRF", "CODE-WEAK-RANDOM", "CODE-WEAK-PASSWORD-HASH", "CODE-JWT-UNVERIFIED", "CODE-PATH-TRAVERSAL",
                    "CODE-OPEN-REDIRECT", "CODE-DEBUG-ENABLED"}
        self.assertTrue(expected <= ids, expected - ids)

    def test_python_safe_has_no_high(self):
        res = scan_tree({"safe.py": PY_SAFE}, ["code"])
        high = [f for f in res.findings if f.severity >= 3]
        self.assertEqual(high, [], [(f.rule.id, f.line) for f in high])

    def test_javascript_vulnerable(self):
        ids = rule_ids(scan_tree({"server.js": JS_VULN}, ["code"]))
        expected = {"CODE-CMD-INJECTION", "CODE-SQL-INJECTION", "CODE-XSS-SINK", "CODE-NOSQL-INJECTION", "CODE-SSRF", "CODE-PATH-TRAVERSAL",
                    "CODE-OPEN-REDIRECT", "CODE-WEAK-RANDOM", "CODE-JWT-UNVERIFIED", "CODE-MASS-ASSIGNMENT", "CODE-TOKEN-LOCALSTORAGE",
                    "CODE-FALLBACK-SECRET", "CODE-TLS-VERIFY-DISABLED", "CODE-CORS-PERMISSIVE"}
        self.assertTrue(expected <= ids, expected - ids)

    def test_svelte_html_with_sanitizer_is_ignored(self):
        res = scan_tree({"A.svelte": "{@html DOMPurify.sanitize(body)}\n", "B.svelte": "{@html body}\n"}, ["code"])
        self.assertEqual([f.path for f in res.findings if f.rule.id == "CODE-XSS-SINK"], ["B.svelte"])

    def test_trojan_source(self):
        res = scan_tree({"a.js": "const isAdmin = false; /* \u202e } \u2066if (isAdmin)\u2069 \u2066 begin admins only */\n"}, ["code"])
        self.assertIn("CODE-TROJAN-SOURCE", rule_ids(res))

    def test_redos(self):
        res = scan_tree({"v.js": "const re = /^(a+)+$/;\n"}, ["code"])
        self.assertIn("CODE-REDOS", rule_ids(res))

    def test_other_languages(self):
        ids = rule_ids(scan_tree({
            "main.go": 'package main\nimport "crypto/tls"\nvar c = &tls.Config{InsecureSkipVerify: true}\nfunc f(){ db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id)) }\n',
            "A.java": 'class A { void f(){ Statement s; s.executeQuery("SELECT * FROM t WHERE id=" + id); new ObjectInputStream(in); Cipher.getInstance("AES"); } }\n',
            "x.php": '<?php system("ls " . $_GET["d"]); $o = unserialize($_COOKIE["o"]); include($_GET["page"]);\n',
            "B.cs": 'var f = new BinaryFormatter();\n',
        }, ["code"]))
        self.assertTrue({"CODE-TLS-VERIFY-DISABLED", "CODE-SQL-INJECTION", "CODE-UNSAFE-DESERIALIZATION", "CODE-WEAK-CIPHER", "CODE-CMD-INJECTION", "CODE-PATH-TRAVERSAL"} <= ids, ids)


if __name__ == "__main__":
    unittest.main()


class PrecisionRegressionTest(unittest.TestCase):
    """False positives found by dogfooding on a real SvelteKit app."""

    def test_non_session_cookie_not_flagged(self):
        res = scan_tree({"hooks.server.ts": "event.cookies.set('ui_lang', lang, {\n  path: '/',\n  sameSite: 'lax',\n  httpOnly: false\n});\n"}, ["code"])
        self.assertNotIn("CODE-COOKIE-FLAGS", rule_ids(res))
        res = scan_tree({"hooks.server.ts": "event.cookies.set('session_token', t, {\n  path: '/',\n  httpOnly: false\n});\n"}, ["code"])
        self.assertIn("CODE-COOKIE-FLAGS", rule_ids(res))

    def test_escaped_json_ld_not_flagged(self):
        src = "<script>const tags = data.map((o) => OPEN + JSON.stringify(o).replace(/</g, '\\\\u003c') + CLOSE);</script>\n{#each tags as t}{@html t}{/each}\n"
        self.assertNotIn("CODE-XSS-SINK", rule_ids(scan_tree({"Seo.svelte": src}, ["code"])))

    def test_unambiguous_or_bounded_regex_not_flagged(self):
        res = scan_tree({"a.ts": "const host = /^[^\\s.]+(\\.[^\\s.]+)+$/;\nconst env = /in\\s+(?:[a-z-]+\\s+){0,3}environments?/i;\n"}, ["code"])
        self.assertNotIn("CODE-REDOS", rule_ids(res))


class CoverageExtensionTest(unittest.TestCase):
    def test_upload_c_and_idor(self):
        ids = rule_ids(scan_tree({
            "src/routes/api/files.js": "const upload = multer({ dest: 'uploads/' });\nrouter.get('/doc/:id', async (req, res) => {\n  const doc = await Doc.findById(req.params.id);\n  res.json(doc);\n});\n",
            "upload.py": "f = request.files['file']\nf.save(os.path.join(UPLOAD_DIR, f.filename))\n",
            "parse.c": "void f(char *in) { char buf[16]; strcpy(buf, in); }\n",
        }, ["code"]))
        self.assertTrue({"CODE-UNRESTRICTED-UPLOAD", "CODE-IDOR-CANDIDATE", "CODE-UNSAFE-C-FUNCTION"} <= ids, ids)

    def test_owner_scoped_lookup_not_flagged(self):
        res = scan_tree({"src/routes/api/x.ts": "const doc = await prisma.doc.findFirst({ where: { id: params.id, ownerId: locals.user.id } });\n"}, ["code"])
        self.assertNotIn("CODE-IDOR-CANDIDATE", rule_ids(res))
