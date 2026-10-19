"""Intra-procedural data-flow engine for Python.

Each function is interpreted once over an abstract state:

* every variable holds a `Val`: which sources reach it (`user` input, `weakrand`
  output), which vulnerability classes it has been sanitised for, its constant
  value when known, the elements of lists and dicts it holds, and the variables
  it was derived from;
* `if` / `match` / ternaries over constants are folded, so only the branch that
  can run is followed; other branches are analysed separately and merged;
* an early-return validation guard (`if "'" in bar: return`) sanitises the
  variables it checks, and those derived from them;
* sinks report through a callback with the vulnerability class, so the scanner
  keeps owning rules, messages and severities.

Precision matters more than cleverness here: a constant stays a constant through
lists, dicts, configparser sections, slicing, f-strings and arithmetic, so the
classic "tainted value overwritten by a constant" traps do not produce alerts.
"""

from __future__ import annotations

import ast
import operator
import re
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from rempart import knowledge

USER, WEAKRAND = "user", "weakrand"
ALL_CATS = frozenset({"sql", "cmd", "code", "path", "redirect", "xss", "xpath", "ldap", "ssrf", "deser", "trust", "regex", "template"})
_NOCONST = object()


@dataclass(frozen=True)
class Val:
    taint: frozenset[str] = frozenset()
    clean: frozenset[str] = frozenset()       # classes this value is safe for
    const: Any = _NOCONST
    items: tuple["Val", ...] | None = None    # list / tuple elements, in order
    keys: tuple[tuple[Any, "Val"], ...] | None = None  # dict or configparser entries
    flags: frozenset[str] = frozenset()       # "dyn" (built by interpolation), "shell", "xxe", "validated"
    derived: frozenset[str] = frozenset()

    def has_const(self) -> bool:
        return self.const is not _NOCONST

    def constant_like(self) -> bool:
        """A single known constant, or one of several constants depending on the branch taken."""
        return self.has_const() or "constlike" in self.flags

    def user(self, cat: str) -> bool:
        return USER in self.taint and cat not in self.clean


CLEAN = Val()


def const(v: Any) -> Val:
    return Val(const=v)


def join(*vals: Val) -> Val:
    vals = tuple(v for v in vals if v is not None)
    if not vals:
        return CLEAN
    if len(vals) == 1:
        return vals[0]
    taint = frozenset().union(*(v.taint for v in vals))
    clean = frozenset.intersection(*(v.clean for v in vals)) if all(v.taint for v in vals) else \
        frozenset.intersection(*(v.clean for v in vals if v.taint)) if any(v.taint for v in vals) else frozenset()
    c = vals[0].const if all(v.has_const() and v.const == vals[0].const for v in vals) else _NOCONST
    items = None
    if all(v.items is not None for v in vals) and len({len(v.items) for v in vals}) == 1:  # type: ignore[arg-type]
        items = tuple(join(*elems) for elems in zip(*(v.items for v in vals)))  # type: ignore[misc]
    keys = None
    if all(v.keys is not None for v in vals):
        merged: dict[Any, list[Val]] = {}
        for v in vals:
            for k, kv in v.keys:  # type: ignore[union-attr]
                merged.setdefault(k, []).append(kv)
        keys = tuple((k, join(*kvs)) for k, kvs in merged.items())
    flags = frozenset().union(*(v.flags for v in vals)) - ({"validated"} if not all("validated" in v.flags for v in vals) else frozenset())
    flags = flags | {"constlike"} if all(v.constant_like() and not v.taint for v in vals) else flags - {"constlike"}
    return Val(taint, clean, c, items, keys, flags, frozenset().union(*(v.derived for v in vals)))


def taint_of(v: Val) -> Val:
    """Collapse a container to the union of what it holds (for opaque uses). When the
    elements are known, they speak for the container, so an escaped element keeps its
    sanitisation inside `"%s" % (escaped, other)`."""
    parts: list[Val] = []
    if v.items is not None:
        parts += list(v.items)
    if v.keys is not None:
        parts += [kv for _, kv in v.keys]
    if not parts:
        parts = [v] if v.items is None and v.keys is None else [CLEAN]
    j = join(*parts)
    return Val(j.taint, j.clean, _NOCONST, None, None, j.flags - {"shell"}, j.derived)


def dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(dotted(node.func) + "()")
    else:
        parts.append("?")
    return ".".join(reversed(parts))


# ------------------------------------------------------------------ knowledge
SANITIZERS: dict[str, frozenset[str]] = {
    "escape": frozenset({"xss"}), "escape_for_html": frozenset({"xss"}), "escape_html": frozenset({"xss"}), "html.escape": frozenset({"xss"}),
    "markupsafe.escape": frozenset({"xss"}), "bleach.clean": frozenset({"xss"}), "jsonify": frozenset({"xss"}), "json.dumps": frozenset({"xss", "sql", "cmd"}),
    "shlex.quote": frozenset({"cmd"}), "pipes.quote": frozenset({"cmd"}),
    "os.path.basename": frozenset({"path"}), "secure_filename": frozenset({"path"}), "werkzeug.utils.secure_filename": frozenset({"path"}),
    "urllib.parse.quote": frozenset({"xss", "path", "redirect"}), "quote": frozenset({"xss", "path", "redirect"}), "urllib.parse.quote_plus": frozenset({"xss", "path", "redirect"}),
    "re.escape": frozenset({"regex"}), "escape_filter_chars": frozenset({"ldap"}), "ldap3.utils.conv.escape_filter_chars": frozenset({"ldap"}),
    "url_for": ALL_CATS, "flask.url_for": ALL_CATS,
}
# Sink categories whose dangerous input is the first positional argument; the rest
# (bound SQL parameters, subprocess options, file modes) cannot carry the attack.
_SUBJECT_IS_FIRST_ARG = frozenset({"sql", "cmd", "code", "path", "redirect", "regex", "template", "deser"})
# Functions whose result carries no user data (numbers, hashes, lengths, booleans).
NEUTRALIZERS = {"render_template", "flask.render_template", "int", "float", "bool", "len", "abs", "round", "hash", "id", "isinstance", "callable", "ord", "uuid.uuid4", "secrets.token_hex",
                "secrets.token_urlsafe", "secrets.randbelow", "secrets.choice", "secrets.token_bytes", "time.time", "datetime.now", "datetime.datetime.now"}
NON_HTML_RESPONSES = {"send_file", "send_from_directory", "jsonify", "abort", "FileResponse", "JSONResponse", "StreamingResponse"}
PROPAGATE_METHODS = {"encode", "decode", "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "swapcase", "replace", "format",
                     "join", "split", "rsplit", "splitlines", "partition", "rpartition", "removeprefix", "removesuffix", "zfill", "center", "ljust", "rjust",
                     "expandtabs", "translate", "read", "readline", "readlines", "getvalue", "copy", "values", "items", "keys", "__str__"}
SHELLS = {"sh", "bash", "zsh", "dash", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "powershell", "pwsh"}
SHELL_SCRIPT_FLAGS = {"-c", "/c", "/C", "-Command", "-command"}


def _shell_argv(elems: tuple["Val", ...]) -> bool:
    """`["sh", "-c", script]`: a shell told to run its argument as a script. A `-c` given
    to another program (`["ping", "-c", "1", host]`) is only an option."""
    consts = [str(e.const) if e.has_const() else None for e in elems]
    return bool(consts) and consts[0] is not None and consts[0].rsplit("/", 1)[-1] in {x.rsplit("/", 1)[-1] for x in SHELLS} \
        and any(c in SHELL_SCRIPT_FLAGS for c in consts[1:])
WEAK_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample", "uniform", "getrandbits", "normalvariate", "gauss", "triangular",
                     "betavariate", "expovariate", "gammavariate", "lognormvariate", "vonmisesvariate", "paretovariate", "weibullvariate", "shuffle", "randbytes"}
SESSION_NAMES = re.compile(r"(?:^|\.)(?:session|mysession|flask\.session|request\.session)$")
DESER_FUNCS = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "_pickle.loads", "dill.loads", "dill.load", "marshal.loads", "marshal.load",
               "jsonpickle.decode", "shelve.open", "yaml.unsafe_load", "yaml.full_load", "pandas.read_pickle", "pd.read_pickle", "joblib.load", "torch.load"}
PATH_SINKS = {"open", "codecs.open", "io.open", "os.open", "pathlib.Path", "Path", "os.remove", "os.unlink", "os.rmdir", "os.listdir", "os.rename", "os.replace",
              "os.makedirs", "os.mkdir", "os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.getsize", "shutil.rmtree", "shutil.copy",
              "shutil.copyfile", "shutil.move", "send_file", "flask.send_file", "FileResponse", "os.scandir", "os.stat", "glob.glob"}
SSRF_SINKS = {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.head", "requests.request",
              "httpx.get", "httpx.post", "httpx.request", "urllib.request.urlopen", "urlopen", "urllib.request.Request", "aiohttp.request"}
REDIRECT_SINKS = {"redirect", "flask.redirect", "RedirectResponse", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "django.shortcuts.redirect"}
CMD_SINKS = {"os.system", "os.popen", "os.popen2", "os.popen3", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput", "os.execl",
             "os.execlp", "os.spawnl", "pty.spawn"}
SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call", "Popen", "check_output", "check_call"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "mogrify", "extra"}
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "exists", "is_file", "is_dir", "stat", "iterdir",
                "touch", "mkdir", "rmdir", "rename", "replace", "glob", "rglob", "lstat", "chmod", "symlink_to", "hardlink_to"}
XPATH_SINKS = {"lxml.etree.XPath", "etree.XPath", "XPath", "elementpath.select", "elementpath.iter_select", "lxml.etree.XPathEvaluator", "etree.XPathEvaluator"}

_BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
           ast.Mod: operator.mod, ast.Pow: operator.pow}
_CMPOPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
           ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b, ast.Is: operator.is_, ast.IsNot: operator.is_not}

Report = Callable[[str, ast.AST, str, dict[str, Any]], None]
SRC = "src"  # direct request source, used only while summarising

# Method names so common in libraries that resolving them by name to a project
# function would be wrong more often than right.
AMBIGUOUS_METHODS = {
    "get", "post", "put", "patch", "delete", "run", "execute", "read", "write", "open", "close", "json", "text", "format", "join", "append",
    "pop", "update", "items", "keys", "values", "search", "find", "query", "send", "load", "loads", "dump", "dumps", "parse", "decode", "encode",
    "replace", "split", "strip", "set", "add", "remove", "call", "filter", "map", "sort", "copy", "start", "stop", "save", "create", "list",
    "fetch", "render", "process", "handle", "validate", "clean", "build", "init", "setup", "connect", "commit", "flush", "lower", "upper",
}


@dataclass
class Summary:
    name: str
    is_method: bool
    ret_params: frozenset[int] = frozenset()
    ret_user: bool = False
    ret_weak: bool = False
    ret_const: Any = _NOCONST
    ret_constlike: bool = False
    ret_clean: frozenset[str] = frozenset()
    sinks: list[tuple[str, frozenset[int], int, str, str]] = field(default_factory=list)  # (cat, params, line, file, message)


class ProjectIndex:
    """Function and method summaries for every Python file of the repository."""

    def __init__(self) -> None:
        self.functions: dict[str, list[Summary]] = {}
        self.classes: set[str] = set()

    def lookup(self, short: str, method_call: bool) -> Summary | None:
        cands = self.functions.get(short) or []
        if not cands:
            return None
        if method_call and (short in AMBIGUOUS_METHODS or len(cands) > 1 and len({c.ret_const for c in cands}) > 1 and not all(c.ret_params for c in cands)):
            if short in AMBIGUOUS_METHODS:
                return None
        if len(cands) == 1:
            return cands[0]
        merged = Summary(short, cands[0].is_method)
        merged.ret_params = frozenset().union(*(c.ret_params for c in cands))
        merged.ret_user = any(c.ret_user for c in cands)
        merged.ret_weak = any(c.ret_weak for c in cands)
        merged.ret_constlike = all(c.ret_constlike or c.ret_const is not _NOCONST for c in cands) and not merged.ret_params and not merged.ret_user
        merged.ret_clean = frozenset.intersection(*(c.ret_clean for c in cands))
        merged.sinks = [s for c in cands for s in c.sinks]
        return merged


@dataclass
class Frame:
    env: dict[str, Val] = field(default_factory=dict)
    terminated: bool = False


def merge_env(a: dict[str, Val], b: dict[str, Val]) -> dict[str, Val]:
    out: dict[str, Val] = {}
    for k in a.keys() | b.keys():
        va, vb = a.get(k), b.get(k)
        out[k] = va if vb is None else vb if va is None else (va if va is vb else join(va, vb))
    return out


class FunctionFlow:
    """Interpret one function (or module body) and report sink hits."""

    def __init__(self, report: Report, *, route: str = "", tainted_params: set[str] | None = None, imports: set[str] | None = None,
                 index: ProjectIndex | None = None, summary_params: list[str] | None = None, local_classes: set[str] | None = None) -> None:
        self.report = report
        self.route = route  # "flask" for HTML-returning routes, "api" for JSON frameworks, "" otherwise
        self.imports = imports or set()
        self.index = index
        self.local_classes = local_classes or set()
        self.summarising = summary_params is not None
        self.returns: list[Val] = []
        self.env: dict[str, Val] = {p: Val(taint=frozenset({USER}), derived=frozenset({p})) for p in (tainted_params or set())}
        for i, p in enumerate(summary_params or []):
            self.env[p] = Val(taint=frozenset({USER, f"p{i}"}), derived=frozenset({p}))
        self.loop_depth = 0

    # ------------------------------------------------------------ expressions
    def fold(self, node: ast.AST) -> Any:
        v = self.ev(node, check=False)
        return v.const if v.has_const() else _NOCONST

    def ev(self, node: ast.AST | None, check: bool = True) -> Val:
        if node is None:
            return CLEAN
        if isinstance(node, ast.Constant):
            return const(node.value)
        if isinstance(node, ast.Name):
            if node.id == "request" and "request" not in self.env:
                return Val(taint=frozenset({USER, SRC} if self.summarising else {USER}), derived=frozenset({"request"}))
            v = self.env.get(node.id)
            if v is None:
                return CLEAN
            return replace(v, derived=v.derived | {node.id})
        if isinstance(node, ast.JoinedStr):
            parts = [self.ev(v.value if isinstance(v, ast.FormattedValue) else v, check) for v in node.values]
            if all(p.has_const() for p in parts):
                try:
                    return const("".join(str(p.const) for p in parts))
                except Exception:  # noqa: BLE001
                    pass
            j = join(*(taint_of(p) for p in parts))
            return replace(j, const=_NOCONST, flags=j.flags | {"dyn"} if any(not p.has_const() for p in parts) else j.flags)
        if isinstance(node, ast.FormattedValue):
            return self.ev(node.value, check)
        if isinstance(node, ast.BinOp):
            left, right = self.ev(node.left, check), self.ev(node.right, check)
            op = _BINOPS.get(type(node.op))
            if op and left.has_const() and right.has_const():
                try:
                    return const(op(left.const, right.const))
                except Exception:  # noqa: BLE001
                    pass
            if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                j = join(left, taint_of(right))
                return replace(j, const=_NOCONST, flags=j.flags | {"dyn"})
            if left.items is not None and right.items is not None and isinstance(node.op, ast.Add):
                return Val(items=left.items + right.items)
            j = join(taint_of(left), taint_of(right))
            return replace(j, const=_NOCONST, flags=j.flags | ({"dyn"} if not (left.has_const() and right.has_const()) else set()))
        if isinstance(node, ast.UnaryOp):
            v = self.ev(node.operand, check)
            if v.has_const():
                try:
                    return const({ast.Not: operator.not_, ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}[type(node.op)](v.const))
                except Exception:  # noqa: BLE001
                    pass
            return CLEAN if isinstance(node.op, ast.Not) else v
        if isinstance(node, ast.BoolOp):
            vals = [self.ev(v, check) for v in node.values]
            if all(v.has_const() for v in vals):
                res = vals[0].const
                for v in vals[1:]:
                    res = (res and v.const) if isinstance(node.op, ast.And) else (res or v.const)
                return const(res)
            return join(*vals)
        if isinstance(node, ast.Compare):
            vals = [self.ev(node.left, check)] + [self.ev(c, check) for c in node.comparators]
            if all(v.has_const() for v in vals):
                ok = True
                try:
                    for op, a, b in zip(node.ops, vals, vals[1:]):
                        ok = ok and _CMPOPS[type(op)](a.const, b.const)
                    return const(bool(ok))
                except Exception:  # noqa: BLE001
                    pass
            return CLEAN
        if isinstance(node, ast.IfExp):
            test = self.fold(node.test)
            if test is not _NOCONST:
                return self.ev(node.body if test else node.orelse, check)
            return join(self.ev(node.body, check), self.ev(node.orelse, check))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elems = tuple(self.ev(e, check) for e in node.elts)
            flags = frozenset({"shell"}) if _shell_argv(elems) else frozenset()
            if all(e.has_const() for e in elems) and not isinstance(node, ast.Set):
                consts = [e.const for e in elems]
                return Val(const=consts if isinstance(node, ast.List) else tuple(consts), items=elems, flags=flags)
            return Val(items=elems, flags=flags, taint=frozenset().union(*(e.taint for e in elems)) if elems else frozenset())
        if isinstance(node, ast.Dict):
            entries = []
            for k, v in zip(node.keys, node.values):
                kv = self.ev(k, check) if k is not None else CLEAN
                entries.append((kv.const if kv.has_const() else ("?", id(k)), self.ev(v, check)))
            return Val(keys=tuple(entries))
        if isinstance(node, ast.Subscript):
            return self._subscript(node, check)
        if isinstance(node, ast.Attribute):
            base = self.ev(node.value, check)
            name = dotted(node)
            # fixed by the platform or by the matched route, not by the client
            if name in ("os.name", "sys.platform") or name in ("request.path", "request.url_rule", "request.endpoint", "request.method",
                                                               "request.blueprint", "request.script_root"):
                return CLEAN
            return Val(taint=base.taint, clean=base.clean, flags=base.flags & {"xxe", "validated"}, derived=base.derived)
        if isinstance(node, ast.Call):
            return self._call(node, check)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            for gen in node.generators:
                it = self.ev(gen.iter, check)
                self._assign(gen.target, taint_of(it))
            return Val(items=None, taint=self.ev(node.elt, check).taint)
        if isinstance(node, ast.DictComp):
            for gen in node.generators:
                self._assign(gen.target, taint_of(self.ev(gen.iter, check)))
            return taint_of(join(self.ev(node.key, check), self.ev(node.value, check)))
        if isinstance(node, ast.NamedExpr):
            v = self.ev(node.value, check)
            self._assign(node.target, v)
            return v
        if isinstance(node, ast.Starred):
            return self.ev(node.value, check)
        if isinstance(node, ast.Await):
            return self.ev(node.value, check)
        if isinstance(node, ast.Lambda):
            return CLEAN
        return CLEAN

    def _subscript(self, node: ast.Subscript, check: bool) -> Val:
        base = self.ev(node.value, check)
        sl = node.slice
        if isinstance(sl, ast.Slice):
            lo, hi, st = (self.fold(x) if x is not None else None for x in (sl.lower, sl.upper, sl.step))
            if base.has_const() and _NOCONST not in (lo, hi, st):
                try:
                    return const(base.const[slice(lo, hi, st)])
                except Exception:  # noqa: BLE001
                    pass
            if base.items is not None and _NOCONST not in (lo, hi, st):
                return Val(items=base.items[slice(lo, hi, st)])
            return taint_of(base)
        idx = self.ev(sl, check)
        if idx.has_const():
            if base.items is not None and isinstance(idx.const, int):
                try:
                    return base.items[idx.const]
                except IndexError:
                    return CLEAN
            if base.keys is not None:
                for k, v in base.keys:
                    if k == idx.const:
                        return v
                return CLEAN if all(not isinstance(k, tuple) for k, _ in base.keys) else taint_of(base)
            if base.has_const():
                try:
                    return const(base.const[idx.const])
                except Exception:  # noqa: BLE001
                    pass
        # unknown index into a known container: any element; into user data: user data
        out = taint_of(base)
        return replace(out, derived=out.derived | idx.derived)

    def _container_call(self, node: ast.Call, recv_name: str, method: str, args: list[Val], check: bool) -> Val | None:
        cur = self.env.get(recv_name)
        if cur is None:
            return None
        if method in ("append", "add") and args:
            if cur.items is not None:
                flags = cur.flags | ({"shell"} if _shell_argv(cur.items + (args[0],)) else set())
                self.env[recv_name] = Val(items=cur.items + (args[0],), flags=frozenset(flags), taint=cur.taint | args[0].taint)
            else:
                self.env[recv_name] = join(cur, taint_of(args[0]))
            return CLEAN
        if method == "insert" and len(args) == 2 and cur.items is not None and args[0].has_const() and isinstance(args[0].const, int):
            items = list(cur.items)
            items.insert(args[0].const, args[1])
            self.env[recv_name] = replace(cur, items=tuple(items), taint=cur.taint | args[1].taint)
            return CLEAN
        if method == "extend" and args:
            other = args[0]
            if cur.items is not None and other.items is not None:
                self.env[recv_name] = replace(cur, items=cur.items + other.items, taint=cur.taint | other.taint, flags=cur.flags | other.flags)
            else:
                self.env[recv_name] = Val(taint=cur.taint | taint_of(other).taint)
            return CLEAN
        if method == "pop":
            if cur.items is not None and cur.items:
                i = args[0].const if args and args[0].has_const() else -1
                items = list(cur.items)
                try:
                    out = items.pop(i)
                except (IndexError, TypeError):
                    return taint_of(cur)
                self.env[recv_name] = replace(cur, items=tuple(items), taint=frozenset().union(*(v.taint for v in items)) if items else frozenset())
                return out
            if cur.keys is not None and args and args[0].has_const():
                found = next((v for k, v in cur.keys if k == args[0].const), CLEAN)
                self.env[recv_name] = replace(cur, keys=tuple((k, v) for k, v in cur.keys if k != args[0].const))
                return found
            return taint_of(cur)
        if method in ("get", "setdefault") and cur.keys is not None:
            if len(args) >= 2 and args[0].has_const() and args[1].has_const() and any(isinstance(k, tuple) and k[0] == "§" for k, _ in cur.keys):
                key = ("§", args[0].const, args[1].const)  # configparser.get(section, option)
            elif args and args[0].has_const():
                key = args[0].const
            else:
                return taint_of(cur)
            for k, v in cur.keys:
                if k == key:
                    return v
            return args[1] if len(args) > 1 and not isinstance(key, tuple) else CLEAN
        if method == "set" and len(args) >= 3 and args[0].has_const() and args[1].has_const():  # configparser.set(section, option, value)
            keys = tuple((k, v) for k, v in (cur.keys or ()) if k != ("§", args[0].const, args[1].const))
            self.env[recv_name] = Val(keys=keys + ((("§", args[0].const, args[1].const), args[2]),), taint=cur.taint | args[2].taint)
            return CLEAN
        if method == "update" and args and cur.keys is not None and args[0].keys is not None:
            self.env[recv_name] = replace(cur, keys=cur.keys + args[0].keys)
            return CLEAN
        if method == "setFeature" and len(args) >= 2 and args[1].has_const() and args[1].const is True:
            feat = dotted(node.args[0]) if node.args else ""
            if "external" in feat:
                self.env[recv_name] = replace(cur, flags=cur.flags | {"xxe"})
            return CLEAN
        if method == "add_section":
            return CLEAN
        if method in ("write", "writelines") and args:  # StringIO / string builders
            j = join(taint_of(cur), taint_of(args[0]))
            self.env[recv_name] = replace(j, const=_NOCONST, flags=j.flags | ({"dyn"} if not args[0].has_const() else set()))
            return CLEAN
        return None

    def _call(self, node: ast.Call, check: bool) -> Val:
        name = dotted(node.func)
        short = name.rsplit(".", 1)[-1]
        args = [self.ev(a, check) for a in node.args]
        kwargs = {k.arg: self.ev(k.value, check) for k in node.keywords if k.arg}
        recv = self.ev(node.func.value, check) if isinstance(node.func, ast.Attribute) else None

        if name in ("configparser.ConfigParser", "ConfigParser", "configparser.RawConfigParser"):
            return Val(keys=())
        if name in ("dict",) and not args:
            return Val(keys=())
        if name in ("list",) and not args:
            return Val(items=())
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            res = self._container_call(node, node.func.value.id, node.func.attr, args, check)
            if res is not None:
                return res

        out = self._sinks(node, name, short, args, kwargs) if check else None
        if out is not None:
            return out

        learned = knowledge.active().categories_of(name, short)
        if learned and "*" in learned:
            learned = ALL_CATS
        if name in SANITIZERS or short in ("escape_for_html", "escape_html", "secure_filename", "escape_filter_chars") or learned:
            cats = (SANITIZERS.get(name) or SANITIZERS.get(short, frozenset())) | learned
            base = join(*(taint_of(a) for a in args)) if args else CLEAN
            return replace(base, clean=base.clean | cats, const=_NOCONST if not base.has_const() else base.const)
        if short in NON_HTML_RESPONSES:
            return CLEAN  # a file, JSON or error response: the value is not written into HTML
        if name in NEUTRALIZERS or (isinstance(node.func, ast.Attribute) and short in ("isdigit", "isalnum", "isnumeric", "startswith", "endswith", "count", "find", "index")):
            return CLEAN
        if "SystemRandom" in name:
            return CLEAN  # os.urandom-backed: cryptographically secure
        if (name.startswith("random.") and short in WEAK_RANDOM_FUNCS) or (name in WEAK_RANDOM_FUNCS and "random" in self.imports):
            return Val(taint=frozenset({WEAKRAND}))
        if name.startswith("secrets.") or name.startswith("os.urandom"):
            return CLEAN
        if name in ("str", "repr", "bytes", "bytearray"):
            if args and args[0].has_const():
                try:
                    return const(str(args[0].const)) if name == "str" else args[0]
                except Exception:  # noqa: BLE001
                    pass
            return taint_of(args[0]) if args else CLEAN
        if name in ("lxml.etree.XMLParser", "etree.XMLParser", "XMLParser") and kwargs.get("resolve_entities", CLEAN).const is True:
            return Val(flags=frozenset({"xxe"}))
        if name in ("xml.sax.make_parser", "make_parser"):
            return Val(keys=())
        if recv is not None and short == "replace" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            removed = node.args[0].value
            cats = {"xpath", "sql"} if removed in ("'", '"') else {"xss"} if removed in ("<", ">", "&") else set()
            j = join(taint_of(recv), *(taint_of(a) for a in args[1:]))
            return replace(j, clean=j.clean | cats) if cats and j.taint else j
        if recv is not None and short in PROPAGATE_METHODS:
            if recv.has_const() and all(a.has_const() for a in args):
                try:
                    return const(getattr(recv.const, short)(*(a.const for a in args)))
                except Exception:  # noqa: BLE001
                    pass
            j = join(taint_of(recv), *(taint_of(a) for a in args)) if short in ("format", "join", "replace") else taint_of(recv)
            return replace(j, flags=j.flags | ({"dyn"} if short == "format" and any(not a.has_const() for a in args) else set()))
        summary = self._resolve(node, name, short)
        if summary is not None:
            return self._apply_summary(node, summary, recv if summary.is_method and isinstance(node.func, ast.Attribute) else None, args)
        # default: the result can carry anything the call was given
        parts = [taint_of(a) for a in args] + [taint_of(v) for v in kwargs.values()]
        if recv is not None:
            parts.append(taint_of(recv))
        j = join(*parts) if parts else CLEAN
        return Val(taint=j.taint, clean=j.clean if j.taint else frozenset(), flags=j.flags & {"validated"}, derived=j.derived)

    # ------------------------------------------------------------ inter-procedural
    def _resolve(self, node: ast.Call, name: str, short: str) -> Summary | None:
        if self.index is None:
            return None
        if isinstance(node.func, ast.Name):
            if short in self.index.classes:
                return None
            return self.index.lookup(short, method_call=False)
        if isinstance(node.func, ast.Attribute):
            root = name.split(".")[0]
            module_call = root in self.imports and root not in self.env
            return self.index.lookup(short, method_call=not module_call)
        return None

    def _apply_summary(self, node: ast.Call, summ: Summary, recv: Val | None, args: list[Val]) -> Val:
        params = ([recv] if summ.is_method and recv is not None else [CLEAN] if summ.is_method else []) + args
        if summ.is_method and recv is None:
            params = [CLEAN] + args
        for cat, pidx, line, file, msg in summ.sinks:
            vals = [taint_of(params[i]) for i in pidx if i < len(params)]
            if any(v.user(cat) for v in vals):
                tainted_src = any(SRC in v.taint for v in vals) or not self.summarising
                self._hit(cat, node, f"{summ.name}() passes request data to {msg} ({file}:{line}).", tainted=True, via=f"{file}:{line}",
                          params=frozenset(i for i in pidx), _src=tainted_src)
        flowing = [taint_of(params[i]) for i in summ.ret_params if i < len(params)]
        if summ.ret_const is not _NOCONST and not flowing and not summ.ret_user:
            return const(summ.ret_const)
        if summ.ret_constlike and not flowing and not summ.ret_user:
            return Val(flags=frozenset({"constlike"}))
        j = join(*flowing) if flowing else CLEAN
        taint = j.taint | ({USER} if summ.ret_user else set()) | ({SRC} if summ.ret_user and self.summarising else set()) | ({WEAKRAND} if summ.ret_weak else set())
        clean = (j.clean if j.taint else ALL_CATS) & summ.ret_clean if summ.ret_user else j.clean | summ.ret_clean
        return Val(taint=frozenset(taint), clean=frozenset(clean) if taint else frozenset(), flags=j.flags & {"dyn", "validated"}, derived=j.derived)

    # ------------------------------------------------------------ sinks
    def _hit(self, cat: str, node: ast.AST, msg: str, **extra: Any) -> None:
        if self.summarising and extra.get("tainted") and "params" not in extra:
            # while summarising, a "tainted" sink means a parameter (or the request) reaches it
            if isinstance(node, ast.Call) and cat in _SUBJECT_IS_FIRST_ARG and node.args:
                # execute(query, params): only the statement is dangerous, the bound parameters are not
                parts = [node.args[0]]
            elif isinstance(node, ast.Call):
                parts = list(node.args) + [k.value for k in node.keywords]
            elif isinstance(node, (ast.Return, ast.Assign, ast.AugAssign, ast.AnnAssign)):
                parts = [node.value] if node.value is not None else []
            else:
                parts = []
            labels: set[str] = set()
            for p in parts:
                labels |= taint_of(self.ev(p)).taint
            extra["params"] = frozenset(int(t[1:]) for t in labels if t.startswith("p") and t[1:].isdigit())
            extra["_src"] = SRC in labels
        if not self.summarising:
            extra.pop("params", None)
            extra.pop("_src", None)
        self.report(cat, node, msg, extra)

    def _sinks(self, node: ast.Call, name: str, short: str, args: list[Val], kwargs: dict[str, Val]) -> Val | None:
        a0 = args[0] if args else kwargs.get("args") or kwargs.get("url") or kwargs.get("sql") or CLEAN
        if name in ("eval", "exec", "compile") and args:
            if a0.user("code"):
                self._hit("code", node, f"{name}() executes request data.", tainted=True)
            elif not a0.constant_like():
                self._hit("code", node, f"{name}() on a non-constant value.", tainted=False, validated="validated" in a0.flags)
        elif name in CMD_SINKS and args:
            if a0.user("cmd"):
                self._hit("cmd", node, f"{name}() runs a command built from request data.", tainted=True)
            elif "dyn" in a0.flags:
                self._hit("cmd", node, f"{name}() runs an interpolated command.", tainted=False)
        elif name in SUBPROCESS or (short in ("run", "call", "Popen", "check_output", "check_call") and name.startswith("subprocess")):
            shell = kwargs.get("shell", CLEAN)
            if shell.has_const() and shell.const:
                if taint_of(a0).user("cmd"):
                    self._hit("cmd", node, "shell=True with a command built from request data.", tainted=True)
                else:
                    self._hit("shell", node, "subprocess call with shell=True.", tainted=False, constant="dyn" not in taint_of(a0).flags)
            elif "shell" in a0.flags and taint_of(a0).user("cmd"):
                self._hit("cmd", node, "a shell (`sh -c` / `cmd /c`) receives request data as its script.", tainted=True)
        elif name in DESER_FUNCS or name in ("yaml.load", "yaml.load_all"):
            loader = kwargs.get("Loader")
            loader_src = ast.unparse(next((k.value for k in node.keywords if k.arg == "Loader"), node.args[1] if len(node.args) > 1 else ast.Constant(None)))
            if name.startswith("yaml.load") and "Safe" in loader_src:
                return None
            if name == "torch.load" and kwargs.get("weights_only", CLEAN).const is True:
                return None
            del loader
            src = taint_of(a0)
            self._hit("deser", node, f"{name}() on request data executes attacker-chosen objects." if src.user("deser") else f"{name}() deserialises data: safe only if it never comes from outside.",
                      tainted=src.user("deser"))
        elif short in SQL_METHODS and isinstance(node.func, ast.Attribute) and args:
            if a0.user("sql") and not a0.has_const():
                self._hit("sql", node, f".{short}() with SQL built from request data.", tainted=True)
            elif "dyn" in a0.flags:
                self._hit("sql", node, f".{short}() with an interpolated SQL string.", tainted=False)
        elif name in ("text", "sqlalchemy.text", "sa.text") and args and ("dyn" in a0.flags or a0.user("sql")):
            self._hit("sql", node, "sqlalchemy text() built by interpolation.", tainted=a0.user("sql"))
        elif name in PATH_SINKS or (short in PATH_METHODS and self.ev(node.func.value, False).user("path")
                                    if isinstance(node.func, ast.Attribute) else False):
            target = a0 if name in PATH_SINKS else self.ev(node.func.value, False)  # type: ignore[union-attr]
            if name == "send_from_directory":
                return None
            if target.user("path"):
                self._hit("path", node, f"{name}() with a path built from request data.", tainted=True)
                if name in ("pathlib.Path", "Path"):
                    return replace(target, clean=target.clean | {"path"})  # reported once, at construction
        elif name in REDIRECT_SINKS:
            if a0.user("redirect"):
                self._hit("redirect", node, f"{name}() to a URL from request data.", tainted=True)
            return CLEAN  # a redirect response carries no HTML body
        elif name in SSRF_SINKS and a0.user("ssrf"):
            self._hit("ssrf", node, f"{name}() fetches a URL taken from the request.", tainted=True)
        elif (name in XPATH_SINKS or short in ("xpath",)) and args:
            q = args[1] if name.startswith("elementpath") and len(args) > 1 else a0
            if q.user("xpath"):
                self._hit("xpath", node, f"{name}() evaluates an XPath query built from request data.", tainted=True)
        elif short in ("find", "findall", "iterfind", "findtext") and isinstance(node.func, ast.Attribute) and args and a0.user("xpath") and "dyn" in a0.flags:
            self._hit("xpath", node, f".{short}() evaluates an ElementPath query built from request data.", tainted=True)
        elif short in ("search", "search_s", "search_st", "search_ext_s") and isinstance(node.func, ast.Attribute) and self._ldap_receiver(node):
            filt = kwargs.get("search_filter") or kwargs.get("filterstr") or (args[1] if len(args) > 1 else CLEAN)
            if filt.user("ldap"):
                self._hit("ldap", node, "LDAP search filter built from request data.", tainted=True)
        elif name in ("render_template_string", "flask.render_template_string", "jinja2.Template", "Template") and a0.user("template"):
            self._hit("template", node, f"{name}() renders a template string controlled by the request (SSTI).", tainted=True)
        elif name in ("re.compile", "re.match", "re.search", "re.fullmatch", "re.findall", "re.sub", "re.split") and a0.user("regex"):
            self._hit("regex", node, f"{name}() compiles a pattern from request data.", tainted=True)
        elif short in ("parseString", "parse", "fromstring", "XML") and any("xxe" in v.flags for v in args[1:] + list(kwargs.values())):
            data = taint_of(a0)
            if USER in data.taint:
                self._hit("xxe", node, f"{name}() parses request data with external entities enabled.", tainted=True)
            elif not a0.constant_like():
                self._hit("xxe", node, f"{name}() parses XML with external entities enabled: safe only for trusted documents.", tainted=False)
        elif short == "set_cookie" and isinstance(node.func, ast.Attribute):
            secure = kwargs.get("secure")
            httponly = kwargs.get("httponly")
            problems = []
            if secure is None or (secure.has_const() and not secure.const):
                problems.append("Secure")
            if httponly is not None and httponly.has_const() and not httponly.const:
                problems.append("HttpOnly")
            if problems:
                self._hit("cookie", node, f"cookie set without {' and '.join(problems)}.", tainted=False)
            value = args[1] if len(args) > 1 else kwargs.get("value", CLEAN)
            if WEAKRAND in taint_of(value).taint:
                self._hit("weakrand", node, "cookie value comes from the non-cryptographic random module.", tainted=False)
        return None

    def _ldap_receiver(self, node: ast.Call) -> bool:
        base = dotted(node.func.value) if isinstance(node.func, ast.Attribute) else ""  # type: ignore[union-attr]
        return bool(re.search(r"(?i)conn|ldap|directory|ad\b", base)) or bool({"ldap3", "ldap"} & self.imports)

    # ------------------------------------------------------------ statements
    def _assign(self, target: ast.AST, v: Val, node: ast.AST | None = None) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = v
        elif isinstance(target, (ast.Tuple, ast.List)):
            elems = v.items if v.items is not None and len(v.items) == len(target.elts) else None
            for i, t in enumerate(target.elts):
                self._assign(t, elems[i] if elems else taint_of(v), node)
        elif isinstance(target, ast.Subscript):
            base_name = dotted(target.value)
            key = self.ev(target.slice)
            if SESSION_NAMES.search(base_name):
                if key.user("trust") or v.user("trust"):
                    self._hit("trust", node or target, f"request data stored in `{base_name}` (trust boundary).", tainted=True)
                if WEAKRAND in taint_of(v).taint:
                    self._hit("weakrand", node or target, f"value stored in `{base_name}` comes from the non-cryptographic random module.", tainted=False)
            if isinstance(target.value, ast.Name):
                cur = self.env.get(target.value.id)
                if cur is not None and cur.keys is not None and key.has_const():
                    keys = tuple((k, kv) for k, kv in cur.keys if k != key.const) + ((key.const, v),)
                    self.env[target.value.id] = replace(cur, keys=keys, taint=cur.taint | v.taint)
                elif cur is not None and cur.items is not None and key.has_const() and isinstance(key.const, int):
                    items = list(cur.items)
                    try:
                        items[key.const] = v
                        self.env[target.value.id] = replace(cur, items=tuple(items), taint=frozenset().union(*(x.taint for x in items)))
                    except IndexError:
                        pass
                elif cur is not None:
                    self.env[target.value.id] = join(cur, Val(taint=v.taint))

    def run(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            if self._terminated:
                return
            self.stmt(stmt)

    _terminated = False

    def _branch(self, body: list[ast.stmt]) -> tuple[dict[str, Val], bool]:
        saved, saved_term = dict(self.env), self._terminated
        self._terminated = False
        self.run(body)
        env, term = self.env, self._terminated
        self.env, self._terminated = saved, saved_term
        return env, term

    def stmt(self, s: ast.stmt) -> None:
        if isinstance(s, ast.Assign):
            v = self.ev(s.value)
            for t in s.targets:
                self._assign(t, v, s)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self._assign(s.target, self.ev(s.value), s)
        elif isinstance(s, ast.AugAssign):
            if isinstance(s.target, ast.Name):
                cur = self.env.get(s.target.id, CLEAN)
                add = self.ev(s.value)
                op = _BINOPS.get(type(s.op))
                if op and cur.has_const() and add.has_const():
                    try:
                        self.env[s.target.id] = const(op(cur.const, add.const))
                        return
                    except Exception:  # noqa: BLE001
                        pass
                j = join(taint_of(cur), taint_of(add))
                self.env[s.target.id] = replace(j, const=_NOCONST, flags=j.flags | ({"dyn"} if not add.has_const() else set()))
            else:
                self._assign(s.target, self.ev(s.value), s)
        elif isinstance(s, ast.Expr):
            self.ev(s.value)
            if isinstance(s.value, ast.Call) and dotted(s.value.func).rsplit(".", 1)[-1] in ("abort", "exit", "_exit"):
                self._terminated = True  # flask.abort / sys.exit never return
        elif isinstance(s, ast.Return):
            v = self.ev(s.value) if s.value is not None else const(None)
            self.returns.append(v)
            if self.route == "flask" and s.value is not None and v.user("xss") and not isinstance(s.value, ast.Constant):
                self._hit("xss", s, "a Flask route returns request data in an HTML response without escaping.", tainted=True)
            self._terminated = True
        elif isinstance(s, ast.Raise):
            self._terminated = True

        elif isinstance(s, ast.If):
            test = self.fold(s.test)
            if test is not _NOCONST:
                self.run(s.body if test else s.orelse)
                return
            self.ev(s.test)
            body_env, body_term = self._branch(s.body)
            else_env, else_term = self._branch(s.orelse)
            if body_term and else_term:
                self._terminated = True
                return
            if body_term:
                self.env = else_env
                if not s.orelse:
                    self._guard(s.test)
            elif else_term:
                self.env = body_env
            else:
                self.env = merge_env(body_env, else_env)
        elif isinstance(s, ast.Match):
            subject = self.ev(s.subject)
            envs = []
            for case in s.cases:
                chosen = self._case_matches(case.pattern, subject)
                if chosen is False:
                    continue
                env, term = self._branch(case.body)
                if not term:
                    envs.append(env)
                if chosen is True:
                    break
            if envs:
                env = envs[0]
                for e in envs[1:]:
                    env = merge_env(env, e)
                self.env = env
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            it = self.ev(s.iter)
            self._assign(s.target, taint_of(it) if it.items is None else join(*it.items) if it.items else CLEAN, s)
            before = dict(self.env)
            for _ in range(2):
                env, _term = self._branch(s.body)
                self.env = merge_env(before, env)
            env, _ = self._branch(s.orelse)
            self.env = merge_env(self.env, env)
        elif isinstance(s, ast.While):
            test = self.fold(s.test)
            if test is not _NOCONST and not test:
                return
            before = dict(self.env)
            for _ in range(2):
                env, _term = self._branch(s.body)
                self.env = merge_env(before, env)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                v = self.ev(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, v, s)
            self.run(s.body)
        elif isinstance(s, ast.Try) or (hasattr(ast, "TryStar") and isinstance(s, getattr(ast, "TryStar"))):
            before = dict(self.env)
            body_env, body_term = self._branch(s.body)
            envs = [] if body_term else [body_env]
            for h in s.handlers:
                self.env = merge_env(before, body_env)
                env, term = self._branch(h.body)
                if not term:
                    envs.append(env)
            self.env = before
            if envs:
                env = envs[0]
                for e in envs[1:]:
                    env = merge_env(env, e)
                self.env = env
            else:
                self._terminated = True
            if s.orelse and not body_term:
                self.run(s.orelse)
            if s.finalbody:
                saved = self._terminated
                self._terminated = False
                self.run(s.finalbody)
                self._terminated = saved or self._terminated
        elif isinstance(s, (ast.Import, ast.ImportFrom)):
            for a in s.names:
                self.imports.add((a.asname or a.name).split(".")[0])
                if isinstance(s, ast.ImportFrom) and s.module:
                    self.imports.add(s.module.split(".")[0])
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # analysed on their own
        elif isinstance(s, (ast.Delete, ast.Pass, ast.Global, ast.Nonlocal, ast.Assert, ast.Break, ast.Continue)):
            return  # break/continue leave the loop body, not the function: assignments before them still flow out
        else:
            for child in ast.iter_child_nodes(s):
                if isinstance(child, ast.expr):
                    self.ev(child)

    def _case_matches(self, pattern: ast.pattern, subject: Val) -> bool | None:
        if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
            return True
        if isinstance(pattern, ast.MatchValue):
            v = self.fold(pattern.value)
            if subject.has_const() and v is not _NOCONST:
                return subject.const == v
            return None
        if isinstance(pattern, ast.MatchOr):
            results = [self._case_matches(p, subject) for p in pattern.patterns]
            if any(r is True for r in results):
                return True
            if all(r is False for r in results):
                return False
            return None
        return None

    _GUARD_SHAPE = re.compile(r"\bin\b|commonpath|is_relative_to|startswith|endswith|isdigit|isalnum|isnumeric|isidentifier|isascii|fullmatch|\.match\(|netloc|scheme|hostname|\bnot\b")

    def _guard(self, test: ast.expr) -> None:
        """`if <check on x>: return` sanitises x (and what x was derived from) for what follows."""
        src = ast.unparse(test)
        if not self._GUARD_SHAPE.search(src) or re.search(r"\blen\(|is None|isinstance\(", src):
            return
        # a presence check (`if not x: return`) proves nothing about the content
        if not any(isinstance(n, (ast.Compare, ast.Call)) for n in ast.walk(test)):
            return
        names = {n.id for n in ast.walk(test) if isinstance(n, ast.Name)}
        derived: set[str] = set()
        for n in names:
            v = self.env.get(n)
            if v is not None:
                derived |= v.derived
        for n in names | derived:
            v = self.env.get(n)
            if v is not None and v.taint:
                self.env[n] = replace(v, clean=ALL_CATS, flags=v.flags | {"validated"})


API_FRAMEWORKS = ("fastapi", "starlette", "litestar", "flask_restx", "flask_smorest", "apiflask")
ROUTE_DECORATOR = re.compile(r"\.(?:route|get|post|put|patch|delete|api_route|websocket)$")


def _imports_of(tree: ast.Module) -> set[str]:
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports |= {(a.asname or a.name).split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
            imports |= {a.asname or a.name for a in node.names}
    return imports


def _defs(tree: ast.Module) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]]:
    out: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node, False))
        elif isinstance(node, ast.ClassDef):
            out += [(m, True) for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return out


def build_index(modules: dict[str, ast.Module], rounds: int = 3) -> ProjectIndex:
    """Summarise every top-level function and method; repeat so summaries can use each other."""
    index = ProjectIndex()
    for tree in modules.values():
        index.classes |= {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
    for _ in range(rounds):
        fresh = ProjectIndex()
        fresh.classes = index.classes
        for rel, tree in modules.items():
            imports = _imports_of(tree)
            for fn, is_method in _defs(tree):
                if fn.name == "__init__":
                    continue
                params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
                sinks: list[tuple[str, frozenset[int], int, str, str]] = []

                def record(cat: str, node: ast.AST, msg: str, extra: dict[str, Any], _sinks=sinks, _rel=rel) -> None:
                    if extra.get("_src"):
                        return  # a direct source inside the helper is reported when the helper itself is analysed
                    vals = extra.get("params")
                    if vals:
                        _sinks.append((cat, vals, getattr(node, "lineno", 0), _rel, msg.split(" (")[0]))

                flow = FunctionFlow(_SinkRecorder(record), imports=set(imports), index=index, summary_params=params)
                flow.run(fn.body)
                ret = join(*flow.returns) if flow.returns else const(None)
                labels = ret.taint
                summ = Summary(fn.name, is_method)
                summ.ret_params = frozenset(int(t[1:]) for t in labels if t.startswith("p") and t[1:].isdigit())
                summ.ret_user = SRC in labels
                summ.ret_weak = WEAKRAND in labels
                summ.ret_const = ret.const if ret.has_const() else _NOCONST
                summ.ret_constlike = ret.constant_like() and not labels
                summ.ret_clean = ret.clean
                summ.sinks = sinks
                fresh.functions.setdefault(fn.name, []).append(summ)
        index = fresh
    return index


class _SinkRecorder:
    """Adapter so sink hits made while summarising carry the parameter indexes they depend on."""

    def __init__(self, record: Callable[[str, ast.AST, str, dict[str, Any]], None]) -> None:
        self.record = record

    def __call__(self, cat: str, node: ast.AST, msg: str, extra: dict[str, Any]) -> None:
        self.record(cat, node, msg, extra)


def analyse_module(tree: ast.Module, report: Callable[[str, ast.AST, str, dict[str, Any]], None], index: ProjectIndex | None = None) -> None:
    imports = _imports_of(tree)
    local_classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
    FunctionFlow(report, imports=set(imports), index=index, local_classes=local_classes).run(
        [s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))])
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [dotted(d.func if isinstance(d, ast.Call) else d) for d in fn.decorator_list]
        route = ""
        params: set[str] = set()
        flask_module = any(str(i).split(".")[0] == "flask" for i in imports) and not any(str(i).split(".")[0] in API_FRAMEWORKS for i in imports)
        if any(d.endswith(".route") for d in decorators) or (flask_module and any(ROUTE_DECORATOR.search(d) for d in decorators)):
            route = "flask"  # Flask 2's @app.get / @bp.post are routes like @app.route
        elif any(ROUTE_DECORATOR.search(d) for d in decorators):
            route = "api"
            params = {a.arg for a in fn.args.args + fn.args.kwonlyargs} - {"self", "cls", "request", "db", "session", "background_tasks", "response"}
        FunctionFlow(report, route=route, tainted_params=params, imports=set(imports), index=index, local_classes=local_classes).run(fn.body)
