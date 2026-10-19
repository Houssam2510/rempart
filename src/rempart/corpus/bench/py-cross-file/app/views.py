from flask import Flask, request

from app.helpers.clean import only_digits, pick_column
from app.helpers.db import run, run_params
from app.helpers.shell import run_tool, tool_name

app = Flask(__name__)


@app.get("/order")
def order():
    oid = request.args["id"]
    # rempart-expect: CODE-SQL-INJECTION
    rows = run("SELECT * FROM orders WHERE id = " + oid)
    # rempart-safe: CODE-SQL-INJECTION
    safe = run("SELECT * FROM orders WHERE id = " + str(only_digits(oid)))
    # rempart-safe: CODE-SQL-INJECTION
    param = run_params("SELECT * FROM orders WHERE id = ?", (oid,))
    return {"rows": rows, "safe": safe, "param": param}


@app.get("/sorted")
def sorted_orders():
    col = pick_column(request.args.get("sort", "name"))
    # rempart-safe: CODE-SQL-INJECTION
    return {"rows": run(f"SELECT * FROM orders ORDER BY {col}")}


@app.post("/thumb")
def thumb():
    # rempart-expect: CODE-CMD-INJECTION
    run_tool(request.form["file"])
    # rempart-safe: CODE-CMD-INJECTION
    run_tool(tool_name() + " --version")
    return "ok"
