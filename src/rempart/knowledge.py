"""Project knowledge learned from triage: `.rempart/knowledge.toml`.

A verdict on one fingerprint fixes one finding. A verdict with a reason fixes the
whole class behind it:

    rempart triage 3f2a91 --fp --because sanitizer:clean_html
    rempart triage 77b0c4 --fp --because placeholder:dev-only-token-123

`clean_html()` then sanitises, in every later scan of this repository, the category
of the rule it was learned from (XSS for CODE-XSS-SINK, SQL for CODE-SQL-INJECTION…),
in the Python data-flow engine and in the JS/TS analysis alike. A placeholder value is
never reported as a secret again. The file is plain TOML and can be committed so
everyone who scans the repository benefits; it can also be edited by hand:

    [sanitizers]
    clean_html = { categories = ["xss"], learned_from = "CODE-XSS-SINK app/views.py:12", date = "2026-10-18" }

    [placeholders]
    "dev-only-token-123" = { learned_from = "SEC-GENERIC config.py:4", date = "2026-10-18" }

    [proposed.sanitizers]       # suggested by the AI agent, applied only once moved up by a person
    normalise_path = { categories = ["path"], learned_from = "agent: CODE-PATH-TRAVERSAL api/files.py:20" }
"""

from __future__ import annotations

import contextvars
import functools
import hashlib
import json
import re
import time
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

FILE = Path(".rempart") / "knowledge.toml"
KINDS = ("sanitizer", "placeholder")

# Rules whose findings depend on a data-flow category, and that category. Built from
# the code scanner's own table so a new flow rule is covered automatically.
_EXTRA_CATEGORIES = {"CODE-NOSQL-INJECTION": "nosql", "AI-OUTPUT-TO-SINK": "code"}


@functools.lru_cache(maxsize=None)
def rule_category(rule_id: str) -> str | None:
    from rempart.scanners import code

    for cat, var in code.PythonAnalyzer._FLOW_RULES.items():
        if getattr(code, var).id == rule_id and cat not in ("shell", "cookie", "weakrand", "trust", "xxe"):
            return cat
    return _EXTRA_CATEGORIES.get(rule_id)


@dataclass
class Knowledge:
    sanitizers: dict[str, frozenset[str]] = field(default_factory=dict)
    placeholders: set[str] = field(default_factory=set)
    meta: dict[str, dict[str, dict[str, object]]] = field(default_factory=dict)  # section -> key -> provenance
    proposed: dict[str, dict[str, dict[str, object]]] = field(default_factory=dict)
    _js_cache: dict[str | None, re.Pattern[str] | None] = field(default_factory=dict, repr=False, compare=False)

    # ---------------------------------------------------------------- queries
    def sanitizes(self, name: str, short: str, category: str) -> bool:
        cats = self.sanitizers.get(name) or self.sanitizers.get(short)
        if cats is None and "." in name:
            cats = next((c for k, c in self.sanitizers.items() if name.endswith("." + k)), None)
        return bool(cats) and (category in cats or "*" in cats)

    def categories_of(self, name: str, short: str) -> frozenset[str]:
        return self.sanitizers.get(name) or self.sanitizers.get(short) or frozenset()

    def js_cleaner(self, category: str | None = None) -> re.Pattern[str] | None:
        """A call to one of the learned sanitisers, for the line-level JS/TS analysis."""
        if category not in self._js_cache:
            names = sorted({n.rsplit(".", 1)[-1] for n, cats in self.sanitizers.items()
                            if category is None or category in cats or "*" in cats})
            self._js_cache[category] = re.compile(r"(?<![\w$])(?:" + "|".join(map(re.escape, names)) + r")\s*\(") if names else None
        return self._js_cache[category]

    def digest(self) -> str:
        """Changes whenever what the scan would learn from changes (part of the scan profile)."""
        raw = json.dumps([sorted((k, sorted(v)) for k, v in self.sanitizers.items()), sorted(self.placeholders)])
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    def is_empty(self) -> bool:
        return not self.sanitizers and not self.placeholders

    # ---------------------------------------------------------------- storage
    @classmethod
    def load(cls, root: Path) -> "Knowledge":
        path = root / FILE
        if not path.is_file():
            return cls()
        try:
            return cls.from_text(path.read_text(encoding="utf-8"))
        except OSError:
            return cls()

    @classmethod
    def from_text(cls, text: str) -> "Knowledge":
        """Parse knowledge that may not be on disk (the target branch's, for a pull request)."""
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return cls()
        k = cls()
        for name, spec in (data.get("sanitizers") or {}).items():
            k.sanitizers[str(name)] = _categories(spec)
            k.meta.setdefault("sanitizers", {})[str(name)] = spec if isinstance(spec, dict) else {}
        for value, spec in (data.get("placeholders") or {}).items():
            k.placeholders.add(str(value))
            k.meta.setdefault("placeholders", {})[str(value)] = spec if isinstance(spec, dict) else {}
        for section, entries in (data.get("proposed") or {}).items():
            if isinstance(entries, dict):
                k.proposed[str(section)] = {str(n): (s if isinstance(s, dict) else {}) for n, s in entries.items()}
        return k

    def save(self, root: Path) -> Path:
        path = root / FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        out = ["# Learned by Rempart from triage verdicts (`rempart triage ID --fp --because KIND:VALUE`).",
               "# Commit this file to share it with everyone who scans this repository. Edit freely.", ""]
        out.append("[sanitizers]")
        for name in sorted(self.sanitizers):
            info = {"categories": sorted(self.sanitizers[name]), **{k: v for k, v in self.meta.get("sanitizers", {}).get(name, {}).items() if k != "categories"}}
            out.append(f"{_key(name)} = {_inline(info)}")
        out += ["", "[placeholders]"]
        for value in sorted(self.placeholders):
            out.append(f"{_key(value)} = {_inline(self.meta.get('placeholders', {}).get(value, {}))}")
        for section in sorted(self.proposed):
            if self.proposed[section]:
                out += ["", f"[proposed.{section}]"]
                for name in sorted(self.proposed[section]):
                    out.append(f"{_key(name)} = {_inline(self.proposed[section][name])}")
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
        return path

    def learn(self, kind: str, value: str, rule_id: str, where: str, proposed: bool = False) -> str:
        """Add one entry; returns a sentence saying what was learned."""
        date = time.strftime("%Y-%m-%d")
        if kind == "sanitizer":
            name, _, cats_text = value.partition("=")
            name = name.strip().removesuffix("()")
            if not re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", name):
                raise ValueError(f"not a function name: {name!r}")
            cats = frozenset(c.strip() for c in cats_text.split(",") if c.strip())
            if not cats:
                cat = rule_category(rule_id)
                if cat is None:
                    raise ValueError(f"{rule_id} is not a data-flow rule: give the categories explicitly, e.g. sanitizer:{name}=xss")
                cats = frozenset({cat})
            info: dict[str, object] = {"categories": sorted(cats), "learned_from": f"{rule_id} {where}", "date": date}
            if proposed:
                self.proposed.setdefault("sanitizers", {})[name] = info
                return f"proposed: {name}() sanitises {', '.join(sorted(cats))} (needs a person to accept it)"
            self.sanitizers[name] = self.sanitizers.get(name, frozenset()) | cats
            self.meta.setdefault("sanitizers", {})[name] = info
            self._js_cache.clear()
            return f"{name}() sanitises {', '.join(sorted(self.sanitizers[name]))}"
        if kind == "placeholder":
            if proposed:
                raise ValueError("only a person can declare a placeholder value")
            if len(value) < 3:
                raise ValueError("a placeholder value needs at least 3 characters")
            self.placeholders.add(value)
            self.meta.setdefault("placeholders", {})[value] = {"learned_from": f"{rule_id} {where}", "date": date}
            return f"`{value}` is a placeholder, never a secret"
        raise ValueError(f"unknown reason kind {kind!r}; use one of: {', '.join(KINDS)}")

    def accept_proposals(self) -> list[str]:
        accepted = []
        for name, info in self.proposed.pop("sanitizers", {}).items():
            cats = _categories(info)
            self.sanitizers[name] = self.sanitizers.get(name, frozenset()) | cats
            self.meta.setdefault("sanitizers", {})[name] = {**info, "accepted": time.strftime("%Y-%m-%d")}
            accepted.append(f"{name}() sanitises {', '.join(sorted(cats))}")
        self._js_cache.clear()
        return accepted


def _categories(spec: object) -> frozenset[str]:
    if isinstance(spec, dict):
        spec = spec.get("categories", ["*"])
    if isinstance(spec, str):
        spec = [spec]
    return frozenset(str(c) for c in (spec or ["*"]))


def _key(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else json.dumps(name)


def _inline(info: dict[str, object]) -> str:
    parts = []
    for k, v in info.items():
        if isinstance(v, (list, tuple)):
            parts.append(f"{k} = [{', '.join(json.dumps(str(x)) for x in v)}]")
        else:
            parts.append(f"{k} = {json.dumps(str(v))}")
    return "{ " + ", ".join(parts) + " }" if parts else "{}"


# ---------------------------------------------------------------- active knowledge during a scan

_ACTIVE: contextvars.ContextVar[Knowledge] = contextvars.ContextVar("rempart_knowledge", default=Knowledge())


def active() -> Knowledge:
    return _ACTIVE.get()


@contextmanager
def using(k: Knowledge) -> Iterator[Knowledge]:
    token = _ACTIVE.set(k)
    try:
        yield k
    finally:
        _ACTIVE.reset(token)
