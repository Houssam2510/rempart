"""Score Rempart on the OWASP Benchmark for Python (https://github.com/OWASP-Benchmark/BenchmarkPython).

    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git /tmp/bp
    python bench/owasp_python.py /tmp/bp

Each test case is a Flask handler labelled "real vulnerability" or "false positive trap".
The official score per category is the Youden index: true-positive rate minus
false-positive rate (0 = random guessing, 100 = perfect). Categories Rempart has no
rule for count as 0, as in the official scorecards.

Two scores are printed. The first counts alerts (LOW and above), as the console does by
default. The second also counts INFO findings, context notes such as an XML parser whose
safety depends on its configuration: it is lower, and both are reported so neither hides
the other.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rempart.config import Config  # noqa: E402
from rempart.engine import run_scan  # noqa: E402
from rempart.models import Severity  # noqa: E402
from rempart.scanners import ALL_SCANNERS  # noqa: E402

CATEGORY_RULES = {
    "cmdi": {"CODE-CMD-INJECTION"},  # shell=True alone is hygiene, not an injection
    "codeinj": {"CODE-EVAL"},
    "deserialization": {"CODE-UNSAFE-DESERIALIZATION"},
    "hash": {"CODE-WEAK-HASH", "CODE-WEAK-PASSWORD-HASH"},
    "ldapi": {"CODE-LDAP-INJECTION"},
    "pathtraver": {"CODE-PATH-TRAVERSAL"},
    "redirect": {"CODE-OPEN-REDIRECT"},
    "securecookie": {"CODE-COOKIE-FLAGS"},
    "sqli": {"CODE-SQL-INJECTION"},
    "trustbound": {"CODE-TRUST-BOUNDARY"},
    "weakrand": {"CODE-WEAK-RANDOM"},
    "xpathi": {"CODE-XPATH-INJECTION"},
    "xss": {"CODE-XSS-SINK", "CODE-TEMPLATE-AUTOESCAPE-OFF"},
    "xxe": {"CODE-XXE", "CODE-XXE-ENABLED"},
}


def score(findings, expected: dict[str, tuple[str, bool]], threshold: Severity) -> dict[str, dict[str, float]]:
    flagged: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if f.path.startswith("testcode/") and f.severity is not None and f.severity >= threshold:
            flagged[Path(f.path).stem].add(f.rule.id)
    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for test, (cat, real) in expected.items():
        hit = bool(flagged.get(test, set()) & CATEGORY_RULES[cat])
        stats[cat]["tp" if real and hit else "fn" if real else "fp" if hit else "tn"] += 1
    report: dict[str, dict[str, float]] = {}
    for cat in sorted(stats):
        s = stats[cat]
        tpr = s["tp"] / max(1, s["tp"] + s["fn"])
        fpr = s["fp"] / max(1, s["fp"] + s["tn"])
        report[cat] = {"tpr": round(100 * tpr, 1), "fpr": round(100 * fpr, 1), "score": round(100 * (tpr - fpr), 1), **s}
    overall = sum(r["score"] for r in report.values()) / len(report)
    report["_overall"] = {"score": round(overall, 1)}
    return report


def scores(findings, expected: dict[str, tuple[str, bool]]) -> dict[str, dict[str, dict[str, float]]]:
    """Both readings: "alerts" counts LOW and above (an INFO finding is a context note, not an
    alert: the console's default threshold); "with_info" counts every finding."""
    return {"alerts": score(findings, expected, Severity.LOW), "with_info": score(findings, expected, Severity.INFO)}


def main(root: str) -> dict[str, dict[str, dict[str, float]]]:
    bench = Path(root)
    expected: dict[str, tuple[str, bool]] = {}
    with open(bench / "expectedresults-0.1.csv") as fh:
        for row in csv.reader(fh):
            if row and not row[0].startswith("#"):
                expected[row[0]] = (row[1], row[2].strip() == "true")
    # whole project, as a real scan would see it: helpers/ holds functions the test cases call
    result = run_scan(bench, [ALL_SCANNERS["code"]], Config(include_tests=True), offline=True, correlate=False)
    return scores(result.findings, expected)


if __name__ == "__main__":
    both = main(sys.argv[1])
    alerts, info = both["alerts"], both["with_info"]
    print(f"{'category':<16}{'TPR':>7}{'FPR':>7}{'score':>8}   tp fn fp tn   | with INFO: {'FPR':>6}{'score':>8}")
    for cat, r in alerts.items():
        if cat.startswith("_"):
            continue
        i = info[cat]
        print(f"{cat:<16}{r['tpr']:>7}{r['fpr']:>7}{r['score']:>8}   {r['tp']} {r['fn']} {r['fp']} {r['tn']}   |            {i['fpr']:>6}{i['score']:>8}")
    print(f"\nOWASP Benchmark score (all 14 categories), alerts only (LOW and above): {alerts['_overall']['score']}")
    print(f"OWASP Benchmark score (all 14 categories), INFO findings counted too:  {info['_overall']['score']}")
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(both, indent=1))
