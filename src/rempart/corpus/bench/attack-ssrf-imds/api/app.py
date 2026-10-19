import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/preview")
def preview():
    # rempart-expect: CHAIN-SSRF-TO-CLOUD-CREDENTIALS, CODE-SSRF
    return requests.get(request.args["url"], timeout=5).text


if __name__ == "__main__":
    # rempart-expect: CHAIN-DEBUG-CONSOLE-EXPOSED
    app.run(host="0.0.0.0", debug=True)
