import io
import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import write_tree

from rempart.mcp_server import serve


def rpc(*messages, roots=None):
    stdin = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    stdout = io.StringIO()
    serve(stdin, stdout, roots=roots)  # the scanned temporary directory is granted explicitly, as `rempart mcp --root` would
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


class MCPTest(unittest.TestCase):
    def test_handshake_list_and_call(self):
        root = Path(tempfile.mkdtemp())
        write_tree(root, {"app.py": "import os\nfrom flask import request\nos.system('ls ' + request.args['d'])\n"})
        out = rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "rempart_scan", "arguments": {"path": str(root), "offline": True}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rempart_scan", "arguments": {"path": "/definitely/not/here"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "nope"},
            roots=[root],
        )
        self.assertEqual([m["id"] for m in out], [1, 2, 3, 4, 5])  # the notification gets no response
        self.assertEqual(out[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("rempart_scan", {t["name"] for t in out[1]["result"]["tools"]})
        payload = json.loads(out[2]["result"]["content"][0]["text"])
        self.assertIn("CODE-CMD-INJECTION", {f["rule"] for f in payload["findings"]})
        self.assertTrue(out[3]["result"]["isError"])
        self.assertEqual(out[4]["error"]["code"], -32601)

    def test_finding_details_after_scan(self):
        root = Path(tempfile.mkdtemp())
        write_tree(root, {"a.js": "eval(userInput);\n"})
        out = rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rempart_scan", "arguments": {"path": str(root), "offline": True}}},
                  roots=[root])
        fid = json.loads(out[0]["result"]["content"][0]["text"])["findings"][0]["id"]
        out = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "rempart_finding", "arguments": {"id": fid}}})
        self.assertIn("remediation", json.loads(out[0]["result"]["content"][0]["text"]))


if __name__ == "__main__":
    unittest.main()
