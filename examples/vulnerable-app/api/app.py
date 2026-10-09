import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/convert")
def convert():
    subprocess.run(f"convert {request.args['file']} out.png", shell=True)
    return "ok"


@app.route("/user")
def user(cursor):
    cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")
    return cursor.fetchone()


@app.route("/import", methods=["POST"])
def import_data():
    return str(pickle.loads(request.data)) + str(yaml.load(request.data))


@app.route("/preview")
def preview():
    return requests.get(request.args["url"], verify=False).text


@app.route("/next")
def go_next():
    return redirect(request.args["next"])


def is_authorized(user):
    try:
        return check_policy(user)
    except Exception:
        return True


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
