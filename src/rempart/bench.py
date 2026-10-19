"""Labelled corpus and per-domain detection metrics (`rempart bench`).

A corpus is a directory of cases; each case is a small repository. Labels are
comment lines placed just above the line they describe, in any comment syntax:

    # rempart-expect: CODE-SQL-INJECTION      the next line must be reported by this rule
    // rempart-safe: CODE-SSRF                the next line is a trap: reporting it is a false positive
    # rempart-alt: CODE-CMD-INJECTION         reporting here is acceptable (the sink of a finding labelled
                                              at its call site): neither a true nor a false positive
    # rempart-expect-file: SEC-ENV-COMMITTED  the rule must fire somewhere in this file

Before scanning, each case is copied to a temporary directory with the label
lines removed (so the scanners see ordinary code, and line numbers are those of
the copy) and `{{FAKE_*}}` placeholders replaced by credential-shaped strings
assembled at runtime: the repository itself never contains a literal token.

Within a case, a rule that appears in at least one label is considered fully
labelled there: any other finding of that rule in the case is a false positive.
Rules nobody labelled in a case are not counted for it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS = Path(__file__).parent / "corpus" / "bench"

_MARKER = re.compile(
    r"^\s*(?:#|//|--|;|<!--|\{/\*|/\*|\{#)?\s*rempart-(expect-file|expect|safe|alt)\s*:\s*([A-Z0-9][A-Z0-9, -]*?)\s*(?:-->|\*/\}|\*/|#\})?\s*$")
_TOKEN = re.compile(r"\{\{(FAKE_[A-Z0-9_]+)\}\}")

# Assembled here so no literal credential exists in the repository.
TOKENS = {
    "FAKE_AWS_KEY": "AKIA" + "Z7QXRT2MWPLK4N8J",
    "FAKE_AWS_SECRET": "wJal" + "rXUtnFEMI/K7MDENG/bPxRfiCYzq8Rt2Lx9Q",
    "FAKE_GH_TOKEN": "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5",
    "FAKE_STRIPE_LIVE": "sk_" + "live_" + "51HxQ2bLk9Zt7Rw3Yp4Vn8Mc6Jd",
    "FAKE_SLACK_BOT": "xoxb-" + "2741963580-6193857204816-Qm7RzT4wXk9LpVn2Hs8DcYbF",
    "FAKE_OPENAI": "sk-" + "proj-" + "Tq8Lm2Zr7Wx4Kp9Vn3Hs6Dc1Yb5Fg0JtRk7Qw2Ez5Ux8Ic3Ov6Pa9Sd",
    "FAKE_PRIVATE_KEY_HEADER": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "FAKE_PRIVATE_KEY_FOOTER": "-----END " + "RSA PRIVATE KEY-----",
    "FAKE_GENERIC_SECRET": "q8Zr2" + "Lx7Wm4Tn9Vk3Hp6Dc",
}


@dataclass(frozen=True)
class Label:
    case: str
    path: str
    line: int  # 0: anywhere in the file
    rule: str
    kind: str  # "expect" | "safe" | "alt"


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    traps: int = 0
    traps_fired: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    def to_dict(self) -> dict[str, Any]:
        p, r = self.precision, self.recall
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "traps": self.traps, "traps_fired": self.traps_fired,
                "precision": None if p is None else round(p, 4), "recall": None if r is None else round(r, 4)}


@dataclass
class Miss:
    kind: str  # "fn" | "fp" | "trap"
    case: str
    path: str
    line: int
    rule: str


@dataclass
class BenchResult:
    domains: dict[str, Counts] = field(default_factory=dict)
    misses: list[Miss] = field(default_factory=list)
    cases: int = 0

    def total(self) -> Counts:
        t = Counts()
        for c in self.domains.values():
            t.tp += c.tp
            t.fp += c.fp
            t.fn += c.fn
            t.traps += c.traps
            t.traps_fired += c.traps_fired
        return t

    def to_dict(self) -> dict[str, Any]:
        return {"cases": self.cases, "total": self.total().to_dict(),
                "domains": {d: c.to_dict() for d, c in sorted(self.domains.items())},
                "misses": [m.__dict__ for m in self.misses]}


def materialise(case_dir: Path, dest: Path) -> list[Label]:
    """Copy one case without its label lines, with placeholders filled in."""
    labels: list[Label] = []
    for src in sorted(p for p in case_dir.rglob("*") if p.is_file()):
        rel = src.relative_to(case_dir).as_posix()
        if "__pycache__" in rel:
            continue
        text = src.read_text(encoding="utf-8")
        out: list[str] = []
        pending: list[tuple[str, str]] = []
        for line in text.splitlines():
            m = _MARKER.match(line)
            if m:
                for rule in (r.strip() for r in m.group(2).split(",")):
                    if not rule:
                        continue
                    if m.group(1) == "expect-file":
                        labels.append(Label(case_dir.name, rel, 0, rule, "expect"))
                    else:
                        pending.append((m.group(1), rule))
                continue
            out.append(_TOKEN.sub(lambda t: TOKENS[t.group(1)], line))
            for kind, rule in pending:
                labels.append(Label(case_dir.name, rel, len(out), rule, kind))
            pending = []
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(out) + ("\n" if text.endswith("\n") else ""), encoding="utf-8")
    return labels


def run_case(case_dir: Path, result: BenchResult) -> None:
    from rempart.config import Config
    from rempart.engine import run_scan
    from rempart.registry import load_all_rules
    from rempart.scanners import ALL_SCANNERS

    rules = load_all_rules()
    tmp = Path(tempfile.mkdtemp(prefix=f"rempart-bench-{case_dir.name}-"))
    previous = os.environ.get("GIT_CEILING_DIRECTORIES")
    os.environ["GIT_CEILING_DIRECTORIES"] = str(tmp.parent)  # never read an enclosing repository
    try:
        labels = materialise(case_dir, tmp)
        scan = run_scan(tmp, list(ALL_SCANNERS.values()), Config.load(tmp), offline=True)
    finally:
        if previous is None:
            os.environ.pop("GIT_CEILING_DIRECTORIES", None)
        else:
            os.environ["GIT_CEILING_DIRECTORIES"] = previous
        shutil.rmtree(tmp, ignore_errors=True)
    result.cases += 1
    labelled = {lb.rule for lb in labels}
    got = {(f.path, f.line, f.rule.id) for f in scan.findings if f.rule.id in labelled}
    used: set[tuple[str, int, str]] = set()

    def domain_of(rule_id: str) -> Counts:
        domain = rules[rule_id].domain if rule_id in rules else "unknown"
        return result.domains.setdefault(domain, Counts())

    for lb in labels:
        hits = {g for g in got if g[0] == lb.path and g[2] == lb.rule and (lb.line == 0 or g[1] == lb.line)}
        c = domain_of(lb.rule)
        if lb.kind == "alt":
            pass
        elif lb.kind == "expect":
            if hits:
                c.tp += 1
            else:
                c.fn += 1
                result.misses.append(Miss("fn", lb.case, lb.path, lb.line, lb.rule))
        else:
            c.traps += 1
            if hits:
                c.traps_fired += 1
                c.fp += 1
                result.misses.append(Miss("trap", lb.case, lb.path, lb.line, lb.rule))
        used |= hits
    for path, line, rule_id in sorted(got - used):
        domain_of(rule_id).fp += 1
        result.misses.append(Miss("fp", case_dir.name, path, line, rule_id))


def run(corpus: Path | None = None, only: set[str] | None = None) -> BenchResult:
    root = corpus or CORPUS
    result = BenchResult()
    for case_dir in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith((".", "_"))):
        if only and case_dir.name not in only:
            continue
        run_case(case_dir, result)
    return result


def _pct(v: float | None) -> str:
    return "   –  " if v is None else f"{v:6.1%}"


def render(result: BenchResult, verbose: bool = False) -> str:
    lines = [f"{result.cases} cases\n", f"{'domain':<14} {'TP':>4} {'FP':>4} {'FN':>4}  precision  recall  traps fired"]
    for d, c in sorted(result.domains.items()):
        lines.append(f"{d:<14} {c.tp:>4} {c.fp:>4} {c.fn:>4}     {_pct(c.precision)}  {_pct(c.recall)}  {c.traps_fired}/{c.traps}")
    t = result.total()
    lines.append(f"{'total':<14} {t.tp:>4} {t.fp:>4} {t.fn:>4}     {_pct(t.precision)}  {_pct(t.recall)}  {t.traps_fired}/{t.traps}")
    if verbose and result.misses:
        lines.append("")
        names = {"fn": "missed", "fp": "unexpected", "trap": "trap fired"}
        for m in result.misses:
            where = f"{m.path}:{m.line}" if m.line else m.path
            lines.append(f"  {names[m.kind]:<11} {m.rule:<34} {m.case}/{where}")
    return "\n".join(lines)


def check(result: BenchResult, baseline: dict[str, Any], tolerance: float = 0.0) -> list[str]:
    """Regressions against a recorded baseline: a domain whose precision or recall dropped."""
    problems = []
    now = result.to_dict()["domains"]
    for domain, before in baseline.get("domains", {}).items():
        after = now.get(domain)
        if after is None:
            problems.append(f"{domain}: no longer measured")
            continue
        for metric in ("precision", "recall"):
            b, a = before.get(metric), after.get(metric)
            if b is not None and (a is None or a < b - tolerance):
                problems.append(f"{domain}: {metric} {b:.1%} → {'–' if a is None else f'{a:.1%}'}")
    return problems


def load_baseline(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
