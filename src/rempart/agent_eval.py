"""Measure the verification agent against labelled cases.

Each case is a small repository (files inline in JSON) and the expected truth
for the findings Rempart raises in it, keyed "RULE@path:line" -> "tp" | "fp".
The corpus mixes real vulnerabilities with traps the static layer cannot settle
alone (allow-lists in helpers, sanitisers in other files, literal-only callers).

For every case: scan, run the agent on the labelled findings, compare.

    rempart agent-eval                         # bundled corpus, live model
    rempart agent-eval --corpus my_cases.json  # your own labels

Metrics:
* agreement: verdict matches the label (uncertain counts as a miss);
* false-positive removal: share of "fp" findings the agent rejected;
* true-positive retention: share of "tp" findings it did not reject,
  the number that must stay at 100 % for the agent to be trusted;
* cost and turns.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rempart.config import Config
from rempart.engine import discover, run_scan
from rempart.scanners import ALL_SCANNERS

BUNDLED = Path(__file__).resolve().parent / "corpus" / "agent_cases.json"


@dataclass
class CaseResult:
    name: str
    expected: dict[str, str]
    verdicts: dict[str, str] = field(default_factory=dict)  # key -> confirmed | false_positive | uncertain | missing
    missing_findings: list[str] = field(default_factory=list)  # labelled but not raised by the scanner
    cost: float = 0.0
    turns: int = 0


def finding_key(f: Any) -> str:
    return f"{f.rule.id}@{f.path}:{f.line}"


def load_cases(path: Path | None = None) -> list[dict[str, Any]]:
    return json.loads((path or BUNDLED).read_text(encoding="utf-8"))


def run_case(case: dict[str, Any], *, client: Any = None, model: str | None = None, effort: str = "high", max_turns: int = 30) -> CaseResult:
    from rempart.agent import VerificationAgent

    tmp = Path(tempfile.mkdtemp(prefix="rempart-eval-"))
    try:
        for rel, text in case["files"].items():
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        os.environ.setdefault("GIT_CEILING_DIRECTORIES", str(tmp.parent))
        config = Config()
        result = run_scan(tmp, [ALL_SCANNERS["code"]], config, offline=True)
        by_key = {finding_key(f): f for f in result.findings}
        out = CaseResult(case["name"], dict(case["expect"]))
        targets = [by_key[k] for k in case["expect"] if k in by_key]
        out.missing_findings = [k for k in case["expect"] if k not in by_key]
        if not targets:
            return out
        files, _ = discover(tmp, config)
        agent = VerificationAgent(result, files, client=client, model=model, effort=effort, max_turns=max_turns)
        report = agent.run(targets)
        for k in case["expect"]:
            f = by_key.get(k)
            v = report.verdicts.get(f.fingerprint) if f else None
            out.verdicts[k] = v.verdict if v else "missing"
        out.cost = report.cost_usd() or 0.0
        out.turns = report.turns
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def score(results: list[CaseResult]) -> dict[str, Any]:
    tp = fp = agree = tp_kept = fp_removed = n = 0
    for r in results:
        for k, label in r.expected.items():
            if k in r.missing_findings:
                continue
            v = r.verdicts.get(k, "missing")
            n += 1
            if label == "tp":
                tp += 1
                tp_kept += v != "false_positive"
                agree += v == "confirmed"
            else:
                fp += 1
                fp_removed += v == "false_positive"
                agree += v == "false_positive"
    return {
        "labelled_findings": n, "agreement": round(agree / max(1, n), 3),
        "tp_retention": round(tp_kept / max(1, tp), 3), "fp_removal": round(fp_removed / max(1, fp), 3),
        "cost_usd": round(sum(r.cost for r in results), 4), "turns": sum(r.turns for r in results),
        "scanner_misses": sum(len(r.missing_findings) for r in results),
    }


def render(results: list[CaseResult], summary: dict[str, Any]) -> str:
    lines = [f"{'case':38} {'finding':48} {'label':5} verdict"]
    for r in results:
        for k, label in r.expected.items():
            v = "not raised" if k in r.missing_findings else r.verdicts.get(k, "missing")
            ok = (label == "tp" and v == "confirmed") or (label == "fp" and v == "false_positive")
            lines.append(f"{r.name[:38]:38} {k[:48]:48} {label:5} {v}{'' if ok else '  ✗'}")
    lines += ["", f"agreement {summary['agreement']:.0%} · true positives kept {summary['tp_retention']:.0%} · "
                  f"false positives removed {summary['fp_removal']:.0%} · {summary['turns']} turns · ≈ ${summary['cost_usd']}"]
    return "\n".join(lines)
