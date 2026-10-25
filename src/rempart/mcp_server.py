"""Model Context Protocol server: Rempart as a tool for any AI agent.

`rempart mcp` speaks JSON-RPC 2.0 over stdio (MCP stdio transport), so AI coding
assistants (Cursor, VS Code, Windsurf…) or any MCP client can ask Rempart to scan a repository,
explain a finding, record a triage verdict, audit a site or an image while it
is writing code. Add it to `.mcp.json`:

    {"mcpServers": {"rempart": {"command": "rempart", "args": ["mcp"]}}}

Logs go to stderr; stdout carries protocol messages only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from rempart import __version__

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
_LAST: dict[str, Any] = {}


def _schema(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


TOOLS: list[dict[str, Any]] = [
    {"name": "rempart_scan", "description": "Scan a local repository for security, data, cloud, CI/CD and AI-agent weaknesses. Returns the score and the highest-risk findings with ids.",
     "inputSchema": _schema({"path": {"type": "string", "description": "Directory to scan (absolute or relative to the server's working directory)."},
                             "scanners": {"type": "string", "description": "Optional comma-separated subset, e.g. 'secrets,code'."},
                             "offline": {"type": "boolean", "description": "Skip OSV/KEV/EPSS lookups."},
                             "limit": {"type": "integer", "description": "Max findings returned (default 25)."}}, ["path"])},
    {"name": "rempart_finding", "description": "Full details, remediation and framework mappings for one finding id from the last scan.",
     "inputSchema": _schema({"id": {"type": "string"}}, ["id"])},
    {"name": "rempart_triage", "description": "Record a verdict on a finding so Rempart learns (tp = true positive, fp = false positive, accepted = real but accepted risk).",
     "inputSchema": _schema({"id": {"type": "string"}, "verdict": {"type": "string", "enum": ["tp", "fp", "accepted"]}, "note": {"type": "string"},
                             "because": {"type": "string", "description": "For fp: the reason as sanitizer:FUNCTION_NAME, recorded as a proposal the developer accepts with `rempart learn --accept-proposals`."}},
                            ["id", "verdict"])},
    {"name": "rempart_web_audit", "description": "Passive audit of a website you own: TLS, security headers, cookies, CORS, performance. Sends no attack payloads.",
     "inputSchema": _schema({"url": {"type": "string"}}, ["url"])},
    {"name": "rempart_image_scan", "description": "Scan a container image (registry reference or local docker-save tar) for vulnerable packages, EOL OS/runtime, secrets and config issues.",
     "inputSchema": _schema({"image": {"type": "string"}}, ["image"])},
    {"name": "rempart_rules", "description": "List Rempart rules, optionally for one domain.",
     "inputSchema": _schema({"domain": {"type": "string"}}, [])},
]


def _compact(findings: list[Any], limit: int) -> list[dict[str, Any]]:
    return [{"id": f.fingerprint[:10], "severity": f.severity.name if f.severity else "", "rule": f.rule.id, "title": f.rule.title,
             "location": f"{f.path}:{f.line}" if f.line else f.path, "message": f.message[:400], "verification": f.verification,
             "risk": f.risk} for f in findings[:limit]]


# ------------------------------------------------------------------ boundaries (AUDIT.md F8)
# The assistant chooses paths and URLs. Scans stay inside the roots the developer started
# the server with (`rempart mcp --root DIR`, REMPART_MCP_ROOTS, else the working directory),
# and the web audit only reaches public addresses.

_ROOTS: list[Path] | None = None


def configure_roots(roots: list[Path] | None) -> None:
    global _ROOTS
    _ROOTS = [Path(r).expanduser().resolve() for r in roots] if roots else None


def allowed_roots() -> list[Path]:
    if _ROOTS:
        return _ROOTS
    import os

    env = [p for p in os.environ.get("REMPART_MCP_ROOTS", "").split(os.pathsep) if p.strip()]
    return [Path(p).expanduser().resolve() for p in env] or [Path.cwd().resolve()]


def _inside_roots(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    roots = allowed_roots()
    if not any(p == r or p.is_relative_to(r) for r in roots):
        raise ValueError(f"{p} is outside the directories this server may read ({', '.join(map(str, roots))}); "
                         "start it with `rempart mcp --root DIR` to allow more")
    return p


def tool_scan(args: dict[str, Any]) -> str:
    from rempart.config import Config
    from rempart.engine import run_scan, score
    from rempart.scanners import ALL_SCANNERS, scanner_names, wants_experimental

    root = _inside_roots(str(args["path"]))
    if not root.is_dir():
        raise ValueError(f"{root} is not a directory")
    names = scanner_names(str(args.get("scanners") or "") or None)  # naming an experimental scanner asks for it
    unknown = [n for n in names if n not in ALL_SCANNERS]
    if unknown:
        raise ValueError(f"unknown scanners {unknown}; available: {list(ALL_SCANNERS)}")
    result = run_scan(root, [ALL_SCANNERS[n] for n in names], Config.load(root), offline=bool(args.get("offline", False)),
                      experimental=wants_experimental(names))
    _LAST["result"] = result
    value, grade = score(result.findings) if result.complete else (None, None)
    return json.dumps({"root": str(root), "complete": result.complete, "errors": result.errors, "score": value, "grade": grade,
                       "counts": result.counts(), "files": result.files_scanned,
                       "findings": _compact(result.findings, int(args.get("limit") or 25))}, indent=1)


def _find(fid: str) -> Any:
    result = _LAST.get("result")
    if result is None:
        raise ValueError("run rempart_scan first")
    hits = [f for f in result.findings if f.fingerprint.startswith(fid.strip())]
    if len(hits) != 1:
        raise ValueError(f"unknown or ambiguous id {fid!r}")
    return hits[0]


def tool_finding(args: dict[str, Any]) -> str:
    return json.dumps(_find(str(args["id"])).to_dict(), indent=1, default=str)


def tool_triage(args: dict[str, Any]) -> str:
    from rempart.history import History

    f = _find(str(args["id"]))
    hist = History()
    try:
        project = hist.for_root(Path(_LAST["result"].root))
        if not _LAST.get("recorded"):  # triage needs the finding in history
            hist.record(project, _LAST["result"])
            _LAST["recorded"] = True
        # an assistant's verdict is evidence (weight 0.5), never a decision: it cannot close
        # a finding nor move the severity that --fail-on reads (AUDIT.md F3)
        hist.triage(project, f.fingerprint, str(args["verdict"]), str(args.get("note") or ""), source="ai_assistant")
    finally:
        hist.close()
    out = f"recorded {args['verdict']} for {f.rule.id} at {f.path}:{f.line}"
    because = str(args.get("because") or "")
    if because and args["verdict"] != "tp":
        from rempart.knowledge import Knowledge

        kind, _, value = because.partition(":")
        root = Path(_LAST["result"].root)
        knowledge = Knowledge.load(root)
        try:
            # an assistant's reason is a proposal: only the developer turns it into knowledge
            out += "; " + knowledge.learn(kind.strip(), value.strip(), f.rule.id, f"{f.path}:{f.line} (assistant)", proposed=True)
        except ValueError as exc:
            out += f"; reason not recorded: {exc}"
        else:
            knowledge.save(root)
    return out


def tool_web(args: dict[str, Any]) -> str:
    from rempart.web import PUBLIC_ONLY, audit

    token = PUBLIC_ONLY.set(True)  # an assistant may not use the audit to probe internal addresses
    try:
        findings, meta = audit(str(args["url"]))
    finally:
        PUBLIC_ONLY.reset(token)
    findings.sort(key=lambda f: -f.risk)
    return json.dumps({"meta": meta, "findings": _compact(findings, 40)}, indent=1, default=str)


def tool_image(args: dict[str, Any]) -> str:
    from rempart.images import scan_image

    ref = str(args["image"])
    if ref.endswith(".tar") or ref.startswith((".", "/", "~")):
        ref = str(_inside_roots(ref))  # a local archive: same boundary as a scan
    findings, meta = scan_image(ref)
    findings.sort(key=lambda f: -f.risk)
    return json.dumps({"meta": meta, "findings": _compact(findings, 40)}, indent=1, default=str)


def tool_rules(args: dict[str, Any]) -> str:
    from rempart.registry import load_all_rules

    domain = str(args.get("domain") or "")
    return json.dumps([{"id": r.id, "severity": r.severity.name, "domain": r.domain, "title": r.title}
                       for r in load_all_rules().values() if not domain or r.domain == domain], indent=1)


HANDLERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "rempart_scan": tool_scan, "rempart_finding": tool_finding, "rempart_triage": tool_triage,
    "rempart_web_audit": tool_web, "rempart_image_scan": tool_image, "rempart_rules": tool_rules,
}


def handle(msg: dict[str, Any]) -> dict[str, Any] | None:
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if mid is None:  # notification (e.g. notifications/initialized): no response
        return None

    def ok(result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        return ok({"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "rempart", "version": __version__},
                   "instructions": "Use rempart_scan on a repository path, then rempart_finding for details and rempart_triage to record verdicts."})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
        try:
            text, is_error = handler(params.get("arguments") or {}), False
        except Exception as exc:  # tool errors are results the model can read, not protocol errors
            text, is_error = f"{type(exc).__name__}: {exc}", True
        return ok({"content": [{"type": "text", "text": text}], "isError": is_error})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout, roots: list[Path] | None = None) -> int:
    configure_roots(roots)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            stdout.flush()
            continue
        response = handle(msg)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
    return 0
