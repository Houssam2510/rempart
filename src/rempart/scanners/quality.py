"""Code quality and performance checks that have a security or reliability
consequence. Pure style is out of scope: linters already do that.

The anchor is OWASP A10:2025 Mishandling of Exceptional Conditions: swallowed
errors and authorization checks that fail open when something throws.
"""

from __future__ import annotations

import ast
import re
from typing import Iterator

from rempart.engine import ScanContext, is_comment
from rempart.models import Finding, Severity
from rempart.registry import A06, A07, A10, H, L, M, rule

R_COMPLEX = rule("QUAL-COMPLEXITY", "Function too complex to review reliably", M, "quality", cwe="CWE-1121", owasp=A06,
                 fix="Split the function. Past ~15 independent paths, reviewers and tests stop covering every branch, and security checks hide in the ones nobody reads.",
                 confidence=0.9)
R_LONG = rule("QUAL-LONG-FUNCTION", "Very long function", L, "quality", cwe="CWE-1080", fix="Extract cohesive steps into named helpers.", confidence=0.9)
R_SWALLOW = rule("QUAL-SWALLOWED-EXCEPTION", "Exception swallowed silently", M, "quality", cwe=("CWE-390", "CWE-755"), owasp=A10,
                 fix="Handle the specific exception, or log it with context and re-raise. Silent failures hide attacks and corrupt state.", confidence=0.7)
R_BARE = rule("QUAL-BARE-EXCEPT", "Bare except catches everything", L, "quality", cwe="CWE-396", owasp=A10,
              fix="Catch the specific exceptions you expect; a bare except also traps KeyboardInterrupt and SystemExit.", confidence=0.8)
R_FAIL_OPEN = rule("QUAL-FAIL-OPEN", "Security check fails open on error", H, "quality", cwe=("CWE-636", "CWE-280"), owasp=(A10, A07),
                   fix="On any error in authentication/authorization, deny. Return False / 401 / 403 from the error path, never True or next().", confidence=0.7)
R_ASSERT = rule("QUAL-ASSERT-SECURITY", "assert used for a security check", M, "quality", cwe="CWE-617", owasp=A07,
                fix="Asserts are removed under `python -O`. Use an explicit if/raise.", confidence=0.6)
R_TODO = rule("QUAL-SECURITY-TODO", "Unfinished security work flagged in a comment", L, "quality", cwe="CWE-1164", owasp=A06,
              fix="Track it in an issue and fix it before release; TODOs near auth and validation are where incidents start.", confidence=0.7)
R_MUTABLE_DEFAULT = rule("QUAL-MUTABLE-DEFAULT", "Mutable default argument", L, "quality", cwe="CWE-1188",
                         fix="Default to None and create the list/dict inside the function; the default is shared across calls (and across users).", confidence=0.9)
R_FOREACH_ASYNC = rule("QUAL-FOREACH-ASYNC", "async callback inside forEach", M, "quality", cwe=("CWE-755", "CWE-362"), owasp=A10,
                       fix="forEach ignores returned promises: work runs unawaited and rejections go unhandled. Use for...of with await, or Promise.all(items.map(...)).")
R_N_PLUS_ONE = rule("PERF-N-PLUS-ONE", "Database or network call inside a loop", M, "performance", cwe="CWE-1050",
                    fix="Batch the lookups (WHERE id IN (...), $in, include/join, DataLoader) or run independent calls concurrently with a bounded pool.", confidence=0.6)
R_NO_TIMEOUT = rule("PERF-NO-TIMEOUT", "Network call without a timeout", M, "performance", cwe=("CWE-400", "CWE-1088"),
                    fix="Always pass a timeout (requests: timeout=(3, 30); fetch: AbortSignal.timeout(ms)). Without it one slow upstream exhausts every worker.", confidence=0.8)
R_SYNC_IO = rule("PERF-SYNC-IO-IN-SERVER", "Blocking I/O in a request path", L, "performance", cwe="CWE-1050",
                 fix="Use the async variants (fs.promises, execFile with a callback) so one slow disk call does not block the event loop for every user.", confidence=0.6)
R_DEEP_CLONE = rule("PERF-JSON-DEEP-CLONE", "Deep clone through JSON round-trip", L, "performance",
                    fix="Use structuredClone(), which is faster and keeps Dates, Maps and Sets.", confidence=0.8)
R_HEAVY_IMPORT = rule("PERF-HEAVY-IMPORT", "Whole heavy library imported", L, "performance",
                      fix="Import only the function you need (lodash-es/debounce, date-fns) or drop moment.js (unmaintained, 300 kB) for date-fns/dayjs/Temporal.", confidence=0.7)

AUTHY = re.compile(r"(?i)auth|verify|permission|authori[sz]e|is_?allowed|can_?access|has_?access|check_?access|is_?admin|validate_?token|guard|policy")
# Unambiguous query methods, accepted on any database-looking receiver.
DB_CALLS = {"execute", "executemany", "fetchone", "fetchall", "find", "find_one", "find_many", "aggregate", "scalar", "scalars", "count_documents"}
# Methods that are also dict/list methods: only count on ORM entry points (Model.objects, session, query).
ORM_ONLY_CALLS = {"get", "filter", "first", "one", "all", "query"}
DB_RECEIVER = re.compile(r"(?i)(?:.*[._])?(?:cursor|cur|session|db|conn|connection|collection|coll|client|engine|repo|repository|table|model|objects|query)")
ORM_RECEIVER = re.compile(r"(?i)(?:.*\.)?(?:objects|session|query|db\.session)")
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue")


def complexity(fn: ast.AST) -> int:
    n = 1
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.IfExp, ast.ExceptHandler, ast.With, ast.AsyncWith, ast.Assert, ast.comprehension, ast.match_case)):
            n += 1
        elif isinstance(node, ast.BoolOp):
            n += len(node.values) - 1
    return n


class QualityScanner:
    name = "quality"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.files:
            if rel.endswith(".py"):
                yield from self.python(ctx, rel)
            elif rel.endswith(JS):
                yield from self.javascript(ctx, rel)
            if rel.endswith((".py", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs") + JS):
                yield from self.todos(ctx, rel)

    def todos(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        for i, line in enumerate(ctx.lines(rel), 1):
            if re.search(r"(?:#|//|/\*|\*)\s*(?:TODO|FIXME|HACK|XXX)\b[^\n]*(?i:auth|secur|csrf|xss|sanitiz|validat|permission|encrypt|password|inject|rate.?limit|escape)", line):
                yield Finding(R_TODO, rel, i, "Security-related TODO left in code.", snippet=line.strip()[:200])

    # ------------------------------------------------------------- Python
    def python(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return
        lines = text.splitlines()

        def snip(n: ast.AST) -> str:
            ln = getattr(n, "lineno", 1)
            return lines[ln - 1].strip()[:200] if 0 < ln <= len(lines) else ""

        test_file = bool(re.search(r"(?:^|/)tests?/|test_[^/]*\.py$|_test\.py$", rel))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                c = complexity(node)
                if c > 15 and not test_file:
                    f = Finding(R_COMPLEX, rel, node.lineno, f"{node.name}() has cyclomatic complexity {c}.", snippet=f"def {node.name}(...)", extra={"anchor": f"{node.name}", "complexity": c})
                    if c > 30:
                        f.severity = Severity.HIGH
                    yield f
                length = (getattr(node, "end_lineno", node.lineno) or node.lineno) - node.lineno
                if length > 120 and not test_file:
                    yield Finding(R_LONG, rel, node.lineno, f"{node.name}() spans {length} lines.", snippet=f"def {node.name}(...)", extra={"anchor": node.name})
                for d in node.args.defaults + node.args.kw_defaults:
                    if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                        yield Finding(R_MUTABLE_DEFAULT, rel, node.lineno, f"{node.name}() has a mutable default argument.", snippet=snip(node))
                        break
                if AUTHY.search(node.name):
                    for h in (n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)):
                        for s in ast.walk(h):
                            if isinstance(s, ast.Return) and isinstance(s.value, ast.Constant) and s.value.value is True:
                                yield Finding(R_FAIL_OPEN, rel, s.lineno, f"{node.name}() returns True from an exception handler.", snippet=snip(s))
                                break
            elif isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    yield Finding(R_BARE, rel, node.lineno, "Bare `except:`.", snippet=snip(node))
                # Only broad handlers count: `except ValueError: continue` is a deliberate
                # decision about one failure mode; `except Exception: pass` hides all of them.
                tname = ast.unparse(node.type) if node.type is not None else ""
                broad = node.type is None or re.fullmatch(r"(?:builtins\.)?(?:Exception|BaseException)", tname)
                if broad and all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body):
                    yield Finding(R_SWALLOW, rel, node.lineno, f"`except {tname}`: body only passes.".replace("except :", "except:"), snippet=snip(node))
            elif isinstance(node, ast.Assert) and not test_file:
                src = ast.unparse(node.test)
                if re.search(r"(?i)\b(?:user|auth|admin|permission|role|owner|is_staff|is_superuser|token|logged)", src):
                    yield Finding(R_ASSERT, rel, node.lineno, "Security condition enforced with assert.", snippet=snip(node))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                for sub in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        recv = ast.unparse(sub.func.value)
                        if (sub.func.attr in DB_CALLS and DB_RECEIVER.fullmatch(recv)) or (sub.func.attr in ORM_ONLY_CALLS and ORM_RECEIVER.fullmatch(recv)) \
                                or (recv in ("requests", "httpx") and sub.func.attr in ("get", "post", "put", "delete")):
                            yield Finding(R_N_PLUS_ONE, rel, sub.lineno, f"{recv}.{sub.func.attr}() runs once per loop iteration.", snippet=snip(sub))
                            break
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id in ("requests", "httpx") and node.func.attr in ("get", "post", "put", "patch", "delete", "head", "request") \
                        and not any(k.arg == "timeout" for k in node.keywords) and not test_file:
                    yield Finding(R_NO_TIMEOUT, rel, node.lineno, f"{node.func.value.id}.{node.func.attr}() without timeout=.", snippet=snip(node))

    # ------------------------------------------------------------- JS / TS
    def javascript(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        lines = text.splitlines()
        server_path = not re.search(r"\.(?:test|spec)\.[jt]sx?$|(?:^|/)(?:tests?|__tests__)/", rel) and bool(re.search(r"(?:^|/)(?:api|server|routes?|controllers?|handlers?|middleware)/|\+server\.[jt]s$|\+page\.server\.[jt]s$|route\.[jt]s$", rel))
        for m in re.finditer(r"catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}", text):
            ln = text.count("\n", 0, m.start()) + 1
            yield Finding(R_SWALLOW, rel, ln, "Empty catch block.", snippet=lines[ln - 1].strip()[:200] if ln <= len(lines) else "catch {}")
        for m in re.finditer(r"catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*(?:console\.\w+\([^)]*\);?\s*)?(?:return\s+(?:true|next\(\))|next\(\)\s*;?\s*\})", text):
            before = text[max(0, m.start() - 600): m.start()]
            if AUTHY.search(before):
                ln = text.count("\n", 0, m.start()) + 1
                yield Finding(R_FAIL_OPEN, rel, ln, "Auth/permission code continues (true / next()) after an error.", snippet=lines[ln - 1].strip()[:200])
        for i, line in enumerate(lines, 1):
            if is_comment(line) or len(line) > 1500:
                continue
            if re.search(r"\.forEach\(\s*async\b", line):
                yield Finding(R_FOREACH_ASYNC, rel, i, "forEach(async ...) does not await its callbacks.", snippet=line.strip()[:200])
            if re.search(r"JSON\.parse\(\s*JSON\.stringify\(", line):
                yield Finding(R_DEEP_CLONE, rel, i, "JSON round-trip used to clone.", snippet=line.strip()[:200])
            if re.search(r"""^\s*import\s+(?:\*\s+as\s+)?\w+\s+from\s+['"](?:lodash|moment)['"]|require\(\s*['"](?:lodash|moment)['"]\s*\)""", line):
                yield Finding(R_HEAVY_IMPORT, rel, i, "Whole lodash/moment imported.", snippet=line.strip()[:200])
            if server_path and re.search(r"\b(?:readFileSync|writeFileSync|execSync|spawnSync|readdirSync)\s*\(", line):
                yield Finding(R_SYNC_IO, rel, i, "Synchronous I/O in server code.", snippet=line.strip()[:200])
        # N+1: an awaited DB/HTTP call inside a for loop body
        for m in re.finditer(r"\bfor\s*(?:await\s*)?\(([^)]*)\)\s*\{", text):
            depth, j = 1, m.end()
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            body = text[m.end():j]
            if len(body) > 4000:
                continue
            c = re.search(r"await\s+(?:\w+\.)*(?:prisma|db|knex|sql|pool|client|collection|model|supabase|mongoose|repo|repository|fetch|axios)\b[\w.]*\s*\(|await\s+fetch\s*\(|await\s+\w+\.(?:find(?:One|Many|Unique|First)?|findById|query|execute|get|insertOne|updateOne)\s*\(", body)
            if c:
                ln = text.count("\n", 0, m.end() + c.start()) + 1
                yield Finding(R_N_PLUS_ONE, rel, ln, "Awaited query/request inside a loop runs sequentially once per item.", snippet=lines[ln - 1].strip()[:200] if ln <= len(lines) else "")
