import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/preview")
def preview():
    # rempart-safe: CHAIN-SSRF-TO-CLOUD-CREDENTIALS
    return requests.get(request.args["url"], timeout=5).text


if __name__ == "__main__":
    # rempart-safe: CHAIN-DEBUG-CONSOLE-EXPOSED
    app.run(host="127.0.0.1", debug=True)
