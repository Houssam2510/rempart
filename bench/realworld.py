"""Precision on real repositories that Rempart was not tuned on.

    python bench/realworld.py                      # bench/realworld: the audit's repositories, labelled
    python bench/realworld.py --stress             # also the large repositories (time and crashes only)
    python bench/realworld.py --json out.json
    python bench/realworld.py --manifest bench/holdout   # the held-out set (labels written after the fact)

Each repository is cloned once at its pinned commit into a cache, then scanned with the
working tree's Rempart (`python -m rempart scan --offline --no-history -f json`) in a
throw-away REMPART_HOME, so no learning from earlier scans can influence the result.

The metric is the audit's: the top 10 critical/high findings by risk, each compared with a
human label (tp / fp / debatable) from labels.json.

    strict precision = tp / labelled          large precision = (tp + debatable) / labelled

A finding of the top 10 that has no label is reported as UNLABELLED: precision is then
provisional until someone reads the code and labels it. Labels are never inferred.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
TOP = 10


def cache_dir() -> Path:
    base = os.environ.get("REMPART_BENCH_CACHE") or os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "rempart", "realworld")
    return Path(base)


def checkout(repo: dict[str, str], cache: Path) -> Path:
    """The repository at its pinned commit, fetched once (shallow) and reused."""
    dest = cache / repo["name"]
    if dest.is_dir():
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head == repo["commit"]:
            return dest
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    dest.mkdir(parents=True)
    git = ["git", "-C", str(dest)]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["remote", "add", "origin", repo["url"]], check=True)
    subprocess.run(git + ["fetch", "-q", "--depth", "1", "origin", repo["commit"]], check=True, timeout=900)
    subprocess.run(git + ["checkout", "-q", "FETCH_HEAD"], check=True)
    return dest


def scan(path: Path, timeout: int) -> dict[str, Any]:
    """Run the working tree's Rempart on `path`; never raises."""
    with tempfile.TemporaryDirectory(prefix="rempart-rw-") as home:
        out = Path(home) / "out.json"
        env = {**os.environ, "REMPART_HOME": home, "PYTHONPATH": str(SRC) + os.pathsep + os.environ.get("PYTHONPATH", "")}
        start = time.monotonic()
        try:
            proc = subprocess.run([sys.executable, "-m", "rempart", "scan", str(path), "--offline", "--no-history", "-f", "json", "-o", str(out)],
                                  capture_output=True, text=True, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"seconds": round(time.monotonic() - start, 1), "exit": None, "timeout": True, "errors": [f"timeout after {timeout}s"], "findings": []}
        seconds = round(time.monotonic() - start, 1)
        data = json.loads(out.read_text()) if out.is_file() else {}
        errors = list(data.get("errors") or [])
        if not out.is_file():
            errors.append(f"no report (exit {proc.returncode}): {proc.stderr.strip()[-300:]}")
        return {"seconds": seconds, "exit": proc.returncode, "timeout": False, "errors": errors, "findings": data.get("findings") or []}


def top_findings(findings: list[dict[str, Any]], n: int = TOP) -> list[dict[str, Any]]:
    """Critical/high findings by decreasing risk, in the report's own order for ties."""
    hits = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    return sorted(hits, key=lambda f: -float(f.get("risk") or 0))[:n]


def label_of(f: dict[str, Any], labels: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Exact (rule, path, line) match; else the only label of that rule and path, so a
    finding whose reported line moved keeps its label."""
    same = [lb for lb in labels if lb["rule"] == f["rule_id"] and lb["path"] == f["path"]]
    exact = [lb for lb in same if lb["line"] == f["line"]]
    if exact:
        return exact[0]
    return same[0] if len(same) == 1 else None


def evaluate(repo: dict[str, str], findings: list[dict[str, Any]], labels: list[dict[str, Any]]) -> dict[str, Any]:
    mine = [lb for lb in labels if lb["repo"] == repo["name"]]
    rows = []
    for f in top_findings(findings):
        lb = label_of(f, mine)
        rows.append({"severity": f["severity"], "rule": f["rule_id"], "where": f"{f['path']}:{f['line']}",
                     "label": lb["label"] if lb else "UNLABELLED", "reason": lb["reason"] if lb else ""})
    tp = sum(r["label"] == "tp" for r in rows)
    fp = sum(r["label"] == "fp" for r in rows)
    deb = sum(r["label"] == "debatable" for r in rows)
    unl = sum(r["label"] == "UNLABELLED" for r in rows)
    labelled = tp + fp + deb
    counts = {s: sum(f.get("severity") == s for f in findings) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    return {"top": rows, "tp": tp, "fp": fp, "debatable": deb, "unlabelled": unl, "labelled": labelled,
            "strict": round(tp / labelled, 3) if labelled else None, "large": round((tp + deb) / labelled, 3) if labelled else None,
            "counts": counts}


def _pct(v: float | None) -> str:
    return "  n/a" if v is None else f"{v:5.0%}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", default=str(HERE / "realworld"), help="directory holding repos.json and labels.json")
    ap.add_argument("--stress", action="store_true", help="also scan the large repositories listed under 'stress' (time and crashes only)")
    ap.add_argument("--only", action="append", help="scan only this repository (repeatable)")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per repository before it counts as a timeout")
    ap.add_argument("--json", help="write the full results here")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every top-10 finding with its label")
    args = ap.parse_args(argv)

    manifest = Path(args.manifest)
    spec = json.loads((manifest / "repos.json").read_text())
    labels_file = manifest / "labels.json"
    labels = json.loads(labels_file.read_text())["labels"] if labels_file.is_file() else []
    repos = list(spec["repos"]) + (list(spec.get("stress") or []) if args.stress else [])
    if args.only:
        repos = [r for r in repos if r["name"] in set(args.only)]
    stress_names = {r["name"] for r in spec.get("stress") or []}
    cache = cache_dir()
    results: dict[str, Any] = {}
    print(f"{'repository':<22}{'time':>8}  {'crit/high/med/low':<20}{'top':>4}{'tp':>4}{'fp':>4}{'deb':>4}{'unl':>4}   strict  large  crashes")
    tot = {"tp": 0, "fp": 0, "debatable": 0, "unlabelled": 0, "crashes": 0}
    for repo in repos:
        path = checkout(repo, cache)
        res = scan(path, args.timeout)
        crashes = len(res["errors"])
        tot["crashes"] += crashes
        entry: dict[str, Any] = {"commit": repo["commit"], "seconds": res["seconds"], "exit": res["exit"], "timeout": res["timeout"],
                                 "errors": res["errors"], "findings": len(res["findings"])}
        c = {s: sum(f.get("severity") == s for f in res["findings"]) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        counts = f"{c['CRITICAL']}/{c['HIGH']}/{c['MEDIUM']}/{c['LOW']}"
        if repo["name"] in stress_names:
            print(f"{repo['name']:<22}{res['seconds']:>7}s  {counts:<20}{'':>4}{'':>4}{'':>4}{'':>4}{'':>4}   {'':>6}  {'':>5}  {crashes}")
        else:
            ev = evaluate(repo, res["findings"], labels)
            entry.update(ev)
            for k in ("tp", "fp", "debatable", "unlabelled"):
                tot[k] += ev[k]
            print(f"{repo['name']:<22}{res['seconds']:>7}s  {counts:<20}{len(ev['top']):>4}{ev['tp']:>4}{ev['fp']:>4}{ev['debatable']:>4}{ev['unlabelled']:>4}"
                  f"   {_pct(ev['strict']):>6}  {_pct(ev['large']):>5}  {crashes}")
            if args.verbose:
                for r in ev["top"]:
                    print(f"      {r['label']:<10} {r['severity'][:4]} {r['rule']:<32} {r['where']}")
        for e in res["errors"]:
            print(f"      error: {e[:200]}")
        results[repo["name"]] = entry
    labelled = tot["tp"] + tot["fp"] + tot["debatable"]
    strict = tot["tp"] / labelled if labelled else None
    large = (tot["tp"] + tot["debatable"]) / labelled if labelled else None
    print(f"{'total':<22}{'':>8}  {'':<20}{'':>4}{tot['tp']:>4}{tot['fp']:>4}{tot['debatable']:>4}{tot['unlabelled']:>4}   {_pct(strict):>6}  {_pct(large):>5}  {tot['crashes']}")
    if tot["unlabelled"]:
        print(f"\n{tot['unlabelled']} top-10 finding(s) have no label: precision is provisional until they are labelled by reading the code.")
    summary = {**tot, "labelled": labelled, "strict": None if strict is None else round(strict, 3), "large": None if large is None else round(large, 3)}
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "repos": results}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
