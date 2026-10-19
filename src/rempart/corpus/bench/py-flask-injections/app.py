import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = "/srv/files"
ALLOWED_HOSTS = {"api.partner.example"}


@app.get("/user")
def user():
    db = sqlite3.connect("app.db")
    uid = request.args["id"]
    # rempart-expect: CODE-SQL-INJECTION
    rows = db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()
    # rempart-safe: CODE-SQL-INJECTION
    safe = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()
    return {"rows": rows, "safe": safe}


@app.get("/ping")
def ping():
    host = request.args.get("host", "")
    # rempart-expect: CODE-CMD-INJECTION
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    # rempart-safe: CODE-CMD-INJECTION
    ok = subprocess.run(["ping", "-c", "1", "127.0.0.1"], capture_output=True)
    # rempart-safe: CODE-CMD-INJECTION
    argv = subprocess.run(["ping", "-c", "1", host], capture_output=True)
    # rempart-expect: CODE-CMD-INJECTION
    script = subprocess.run(["sh", "-c", "ping -c 1 " + host], capture_output=True)
    return {"out": out.stdout.decode(), "ok": ok.returncode, "argv": argv.returncode, "script": script.returncode}


@app.get("/fetch")
def fetch():
    url = request.args["url"]
    # rempart-expect: CODE-SSRF
    r = requests.get(url, timeout=5)
    # rempart-safe: CODE-SSRF
    status = requests.get("https://status.partner.example/health", timeout=5)
    return {"body": r.text, "status": status.status_code}


@app.get("/proxy")
def proxy():
    host = request.args["host"]
    if host not in ALLOWED_HOSTS:
        return {"error": "host not allowed"}, 400
    # rempart-safe: CODE-SSRF
    r = requests.get(f"https://{host}/v1/data", timeout=5)
    return r.json()


@app.get("/download")
def download():
    name = request.args["name"]
    # rempart-expect: CODE-PATH-TRAVERSAL
    with open(os.path.join(BASE, name)) as fh:
        data = fh.read()
    # rempart-safe: CODE-PATH-TRAVERSAL
    with open(os.path.join(BASE, secure_filename(name))) as fh:
        clean = fh.read()
    return {"data": data, "clean": clean}


@app.get("/login/done")
def done():
    target = request.args.get("next", "/")
    if request.args.get("internal"):
        # rempart-safe: CODE-OPEN-REDIRECT
        return redirect(url_for("index"))
    # rempart-expect: CODE-OPEN-REDIRECT
    return redirect(target)


@app.post("/import")
def import_data():
    # rempart-expect: CODE-UNSAFE-DESERIALIZATION
    obj = pickle.loads(request.data)
    # rempart-safe: CODE-UNSAFE-DESERIALIZATION
    conf = yaml.safe_load(request.data)
    return {"obj": str(obj), "conf": conf}


@app.post("/calc")
def calc():
    expr = request.form["expr"]
    # rempart-expect: CODE-EVAL
    return {"result": eval(expr)}


@app.get("/hello")
def hello():
    name = request.args.get("name", "")
    if request.args.get("plain"):
        # rempart-safe: CODE-XSS-SINK
        return "<p>Hello " + escape(name) + "</p>"
    # rempart-expect: CODE-XSS-SINK
    return "<p>Hello " + name + "</p>"


@app.get("/")
def index():
    return "ok"
