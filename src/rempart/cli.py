"""Command-line interface.

    rempart scan [PATH]            static analysis of a repository
    rempart web URL                passive audit of a deployed site you own
    rempart triage ID --fp|--tp|--accept   teach Rempart about a finding
    rempart history [PATH]         score trend, new/fixed, MTTR
    rempart learn                  what the feedback loop has learned per rule
    rempart rules [--domain D]     list every rule and its mappings
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from rempart import __version__
from rempart.config import Config
from rempart.engine import ScanResult, run_scan, score
from rempart.models import Severity
from rempart.registry import OWASP_2025, load_all_rules


def _project_id(root: Path) -> str:
    return str(root.resolve())


def cmd_scan(args: argparse.Namespace) -> int:
    from rempart.history import History
    from rempart.reporters import RENDERERS, render_console
    from rempart.scanners import ALL_SCANNERS

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"rempart: {root} is not a directory", file=sys.stderr)
        return 2
    config = Config.load(root)
    names = list(ALL_SCANNERS)
    if args.only:
        names = [n.strip() for n in args.only.split(",")]
        unknown = [n for n in names if n not in ALL_SCANNERS]
        if unknown:
            print(f"rempart: unknown scanner(s) {unknown}; choose from {list(ALL_SCANNERS)}", file=sys.stderr)
            return 2
    if args.skip:
        names = [n for n in names if n not in {s.strip() for s in args.skip.split(",")}]
    result = run_scan(root, [ALL_SCANNERS[n] for n in names], config, offline=args.offline)

    diff = None
    if not args.no_history:
        hist = History()
        project = _project_id(root)
        result.findings, learned_suppressed = hist.apply_knowledge(project, result.findings)
        result.suppressed += learned_suppressed
        scan_id = hist.record(project, result)
        diff = hist.diff_with_previous(project, scan_id)
        hist.close()

    if args.format == "console":
        print(render_console(result, limit=args.limit, min_severity=Severity.parse(args.min_severity), diff=diff, verbose=args.verbose))
    else:
        out = RENDERERS[args.format](result)
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            v, g = score(result.findings)
            print(f"rempart: {len(result.findings)} findings, grade {g} ({v}/100) → {args.output}", file=sys.stderr)
        else:
            print(out)
    return _exit_code(result, args.fail_on or (config.fail_on.name if config.fail_on else None))


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = Severity.parse(fail_on)
    return 1 if any(f.severity is not None and f.severity >= threshold for f in result.findings) else 0


def cmd_web(args: argparse.Namespace) -> int:
    from rempart.reporters import RENDERERS, render_console
    from rempart.web import audit

    try:
        findings, meta = audit(args.url)
    except Exception as exc:  # network errors of every kind end here
        print(f"rempart: could not reach {args.url}: {exc}", file=sys.stderr)
        return 2
    findings.sort(key=lambda f: -f.risk)
    result = ScanResult(root=str(meta.get("final_url", args.url)), findings=findings, files_scanned=1, duration_s=round(float(meta.get("total_ms", 0)) / 1000, 2), scanners=["web"])
    if args.format == "console":
        tls = meta.get("tls") or {}
        cold = f" (cold {meta['cold_ttfb_ms']} ms)" if meta.get("cold_ttfb_ms") else ""
        print(f"HTTP {meta.get('status')} · TTFB {meta.get('ttfb_ms')} ms{cold} · {meta.get('html_bytes')} bytes" + (f" · {tls.get('version')} · cert {tls.get('days_left')} days left" if isinstance(tls, dict) and tls else ""))
        print(render_console(result, min_severity=Severity.parse(args.min_severity), verbose=args.verbose))
    else:
        print(RENDERERS[args.format](result))
    return _exit_code(result, args.fail_on)


def cmd_triage(args: argparse.Namespace) -> int:
    from rempart.history import History

    verdict = "fp" if args.fp else "tp" if args.tp else "accepted"
    hist = History()
    try:
        rule_id = hist.triage(_project_id(Path(args.path)), args.id, verdict, args.note or "")
    except KeyError as exc:
        print(f"rempart: {exc}", file=sys.stderr)
        return 2
    finally:
        hist.close()
    print(f"Recorded {verdict.upper()} for {args.id} ({rule_id}). Future scans will use it.")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    from rempart.history import History

    hist = History()
    project = _project_id(Path(args.path))
    scans = hist.scans(project, args.limit)
    if not scans:
        print("No scans recorded for this project yet.")
        return 0
    print(f"{'date':<17} {'score':>5} grade  crit high  med  low  files")
    for s in reversed(scans):
        c = s["counts"]
        assert isinstance(c, dict)
        print(f"{datetime.fromtimestamp(float(s['ts'])).strftime('%Y-%m-%d %H:%M'):<17} {s['score']:>5}   {s['grade']}   {c.get('CRITICAL', 0):>4} {c.get('HIGH', 0):>4} {c.get('MEDIUM', 0):>4} {c.get('LOW', 0):>4}  {s['files']:>5}")
    mttr = hist.mttr_days(project)
    if mttr is not None:
        print(f"\nMean time to remediate: {mttr} days")
    hist.close()
    return 0


def cmd_learn(args: argparse.Namespace) -> int:
    from rempart.history import History

    rules = load_all_rules()
    hist = History()
    stats = hist.rule_stats()
    hist.close()
    if not stats:
        print("No feedback yet. Triage findings with `rempart triage <id> --tp/--fp/--accept`.")
        return 0
    print(f"{'rule':<34} {'TP':>4} {'FP':>4} {'acc':>4}  prior  learned")
    for rid, s in sorted(stats.items(), key=lambda kv: kv[1].precision()):
        prior = rules[rid].confidence if rid in rules else 0.8
        print(f"{rid:<34} {s.tp:>4} {s.fp:>4} {s.accepted:>4}  {prior:>5.0%}  {s.precision(prior):>6.0%}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rules = load_all_rules()
    items = [r for r in rules.values() if not args.domain or r.domain == args.domain]
    if args.markdown:
        print("| Rule | Severity | Domain | Title | CWE | OWASP 2025 | Other frameworks |\n|---|---|---|---|---|---|---|")
        for r in sorted(items, key=lambda r: (r.domain, r.id)):
            print(f"| `{r.id}` | {r.severity.name} | {r.domain} | {r.title} | {', '.join(r.cwe)} | {', '.join(o.split(' ')[0] for o in r.owasp)} | {', '.join(r.frameworks)} |")
        return 0
    for r in sorted(items, key=lambda r: (r.domain, -r.severity, r.id)):
        print(f"{r.severity.name:<8} {r.domain:<13} {r.id:<34} {r.title}")
    by_domain = Counter(r.domain for r in items)
    owasp = Counter(o for r in items for o in r.owasp)
    print(f"\n{len(items)} rules · " + ", ".join(f"{d} {n}" for d, n in sorted(by_domain.items())))
    print("OWASP Top 10:2025 rules per category: " + ", ".join(f"{o.split(':')[0]} {owasp.get(o, 0)}" for o in OWASP_2025))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rempart", description="Security, data and cloud posture scanner for your own code and apps.")
    p.add_argument("--version", action="version", version=f"rempart {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-f", "--format", choices=["console", "json", "sarif", "md", "markdown", "html"], default="console")
    s.add_argument("-o", "--output", help="write the report to a file")
    s.add_argument("--only", help="comma-separated scanners to run")
    s.add_argument("--skip", help="comma-separated scanners to skip")
    s.add_argument("--offline", action="store_true", help="no network: skip OSV/KEV/EPSS lookups")
    s.add_argument("--fail-on", choices=[x.name.lower() for x in Severity], help="exit 1 if a finding at or above this severity exists")
    s.add_argument("--min-severity", default="low", choices=[x.name.lower() for x in Severity])
    s.add_argument("--limit", type=int, default=60, help="max findings printed on the console")
    s.add_argument("--no-history", action="store_true", help="do not record this scan or apply learned verdicts")
    s.add_argument("-v", "--verbose", action="store_true", help="show remediation and framework mappings")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("web", help="passive audit of a deployed site you own")
    w.add_argument("url")
    w.add_argument("-f", "--format", choices=["console", "json", "sarif", "md", "markdown", "html"], default="console")
    w.add_argument("--fail-on", choices=[x.name.lower() for x in Severity])
    w.add_argument("--min-severity", default="info", choices=[x.name.lower() for x in Severity])
    w.add_argument("-v", "--verbose", action="store_true")
    w.set_defaults(func=cmd_web)

    t = sub.add_parser("triage", help="record a verdict on a finding")
    t.add_argument("id", help="finding id (prefix of the fingerprint)")
    g = t.add_mutually_exclusive_group(required=True)
    g.add_argument("--fp", action="store_true", help="false positive")
    g.add_argument("--tp", action="store_true", help="true positive")
    g.add_argument("--accept", action="store_true", help="real, but risk accepted")
    t.add_argument("--note")
    t.add_argument("--path", default=".", help="project root (default: current directory)")
    t.set_defaults(func=cmd_triage)

    h = sub.add_parser("history", help="score trend for a project")
    h.add_argument("path", nargs="?", default=".")
    h.add_argument("--limit", type=int, default=20)
    h.set_defaults(func=cmd_history)

    sub.add_parser("learn", help="per-rule precision learned from your verdicts").set_defaults(func=cmd_learn)

    r = sub.add_parser("rules", help="list rules")
    r.add_argument("--domain")
    r.add_argument("--markdown", action="store_true")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
