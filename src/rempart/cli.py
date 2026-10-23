"""Command-line interface.

    rempart scan [PATH]            static analysis of a repository
    rempart tui [PATH]             the same, in an interactive terminal interface
    rempart web URL                passive audit of a deployed site you own
    rempart triage ID --fp|--tp|--accept   teach Rempart about a finding
    rempart history [PATH]         score trend, new/fixed, MTTR
    rempart learn                  what the feedback loop has learned per rule
    rempart bench                  detection metrics per domain on a labelled corpus
    rempart rules [--domain D]     list every rule and its mappings
"""

from __future__ import annotations

import argparse
import json
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


def _scan_profile(root: Path, kind: str, **options: object) -> str:
    """What a scan was run with. Two scans with the same profile only differ by the
    code, so a finding that vanished between them was fixed (an implicit learning signal)."""
    import hashlib

    from rempart.knowledge import Knowledge

    cfg = root / ".rempart.toml"
    cfg_hash = hashlib.sha256(cfg.read_bytes()).hexdigest()[:12] if cfg.is_file() else "-"
    opts = ",".join(f"{k}={v}" for k, v in sorted(options.items()) if v not in (None, False, "", []))
    return f"{kind}|{opts}|config={cfg_hash}|knowledge={Knowledge.load(root).digest()}"


def cmd_scan(args: argparse.Namespace) -> int:
    from rempart.history import History
    from rempart.reporters import RENDERERS, render_console
    from rempart.scanners import ALL_SCANNERS

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"rempart: {root} is not a directory", file=sys.stderr)
        return 2
    config = Config.load(root)
    if getattr(args, "prod_only", False):
        config.prod_only = True
    names = list(ALL_SCANNERS)
    if args.only:
        names = [n.strip() for n in args.only.split(",")]
        unknown = [n for n in names if n not in ALL_SCANNERS]
        if unknown:
            print(f"rempart: unknown scanner(s) {unknown}; choose from {list(ALL_SCANNERS)}", file=sys.stderr)
            return 2
    if args.skip:
        names = [n for n in names if n not in {s.strip() for s in args.skip.split(",")}]
    result = run_scan(root, [ALL_SCANNERS[n] for n in names], config, offline=args.offline, correlate=False,
                      verify_secrets=args.verify_secrets)
    # Optional live sources merged into the same result, so attack paths can span code and production.
    if args.aws:
        from rempart.cloud_aws import audit as aws_audit

        try:
            result.findings += list(aws_audit(profile=None if args.aws == "default" else args.aws))
            result.scanners.append("cloud-aws")
        except Exception as exc:  # credentials, boto3 missing
            result.errors.append(f"aws: {exc}")
    for image in args.image or []:
        from rempart.images import scan_image

        try:
            result.findings += scan_image(image, offline=args.offline)[0]
            result.scanners.append(f"image:{image}")
        except Exception as exc:  # registry/network/archive errors
            result.errors.append(f"image {image}: {exc}")
    if args.git_history:
        from rempart.continuous import scan_git_history

        def current(rel: str) -> str | None:
            try:
                return (root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None

        result.findings += list(scan_git_history(root, current, verify_secrets=args.verify_secrets))
        result.scanners.append("git-history")
    if args.baseline:
        from rempart.continuous import baseline_fingerprints

        scanners = [ALL_SCANNERS[n] for n in names]
        try:
            known = baseline_fingerprints(root, args.baseline, lambda p: run_scan(p, scanners, config, offline=args.offline, correlate=False).findings)
        except Exception as exc:  # unknown ref, not a git repository
            print(f"rempart: cannot scan baseline {args.baseline!r}: {exc}", file=sys.stderr)
            return 2
        inherited = [f for f in result.findings if f.fingerprint in known]
        result.findings = [f for f in result.findings if f.fingerprint not in known]
        result.suppressed += len(inherited)
        print(f"rempart: {len(inherited)} finding(s) already present at {args.baseline} hidden; showing what this change adds.", file=sys.stderr)
    result.findings.sort(key=lambda f: (-f.risk, f.path, f.line))

    diff = None
    if not args.no_history:
        hist = History()
        project = _project_id(root)
        result.findings, learned_suppressed = hist.apply_knowledge(project, result.findings)
        result.suppressed += learned_suppressed
        result.add_attack_paths()
        profile = _scan_profile(root, "scan", only=args.only, skip=args.skip, offline=args.offline, aws=args.aws,
                                image=",".join(args.image or []), git_history=args.git_history, baseline=args.baseline,
                                prod_only=args.prod_only, verify_secrets=args.verify_secrets)
        scan_id = hist.record(project, result, profile)
        diff = hist.diff_with_previous(project, scan_id)
        hist.close()
    else:
        result.add_attack_paths()

    for spec in args.also or []:
        fmt, _, dest = spec.partition(":")
        if fmt not in RENDERERS or not dest:
            print(f"rempart: --also expects FORMAT:PATH with FORMAT in {sorted(RENDERERS)}, got {spec!r}", file=sys.stderr)
            return 2
        Path(dest).write_text(RENDERERS[fmt](result), encoding="utf-8")
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


def _render(findings: list, root: str, args: argparse.Namespace, header: str = "", duration: float = 0.0, scanners: tuple[str, ...] = ()) -> int:
    from rempart.reporters import RENDERERS, render_console

    findings.sort(key=lambda f: -f.risk)
    result = ScanResult(root=root, findings=findings, files_scanned=0, duration_s=duration, scanners=list(scanners))
    if args.format == "console":
        if header:
            print(header)
        print(render_console(result, limit=getattr(args, "limit", 60), min_severity=Severity.parse(args.min_severity), verbose=args.verbose))
    else:
        out = RENDERERS[args.format](result)
        if getattr(args, "output", None):
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"rempart: {len(findings)} findings → {args.output}", file=sys.stderr)
        else:
            print(out)
    return _exit_code(result, args.fail_on)


def cmd_image(args: argparse.Namespace) -> int:
    from rempart.images import scan_image
    from rempart.netcache import NetworkError

    try:
        findings, meta = scan_image(args.image, platform=args.platform, offline=args.offline, max_mb=args.max_mb)
    except (NetworkError, ValueError, OSError) as exc:
        print(f"rempart: {exc}", file=sys.stderr)
        return 2
    header = f"{meta.get('label')} · {meta.get('os')} · {meta.get('packages')} packages · user {meta.get('user')} · built {str(meta.get('created'))[:10]}"
    return _render(findings, f"image:{meta.get('label')}", args, header, scanners=("image",))


def cmd_cloud(args: argparse.Namespace) -> int:
    if args.provider in ("gcp", "azure"):
        from rempart.cloud_multi import audit_azure, audit_gcp

        try:
            findings = list(audit_gcp(args.project) if args.provider == "gcp" else audit_azure(args.subscription))
        except Exception as exc:  # CLI missing, not logged in
            print(f"rempart: {args.provider} audit failed: {exc}", file=sys.stderr)
            return 2
        scope = findings[0].path.split("/")[2] if findings else (args.project or args.subscription or "?")
        return _render(findings, f"{args.provider}:{scope}", args, f"{args.provider} {scope} · read-only via the official CLI", scanners=("cloud",))
    from rempart.cloud_aws import audit

    regions = [r.strip() for r in args.regions.split(",")] if args.regions else None
    try:
        findings = list(audit(profile=args.profile, regions=regions))
    except Exception as exc:  # credentials, boto3 missing, network
        print(f"rempart: AWS audit failed: {exc}", file=sys.stderr)
        return 2
    account = findings[0].path.split("/")[2] if findings else "?"
    return _render(findings, f"aws:{account}", args, f"AWS account {account} · {len(regions) if regions else 'all enabled'} region(s) · read-only", scanners=("cloud",))


def cmd_k8s(args: argparse.Namespace) -> int:
    from rempart.kube_live import audit

    try:
        findings = audit(context=args.context, include_system=args.include_system)
    except (RuntimeError, ValueError) as exc:
        print(f"rempart: {exc}", file=sys.stderr)
        return 2
    return _render(findings, f"k8s:{args.context or 'current-context'}", args, scanners=("kubernetes",))


def cmd_watch(args: argparse.Namespace) -> int:
    from rempart.continuous import watch
    from rempart.scanners import ALL_SCANNERS

    root = Path(args.path).resolve()
    config = Config.load(root)
    names = list(ALL_SCANNERS)
    if args.only:
        names = [n.strip() for n in args.only.split(",")]
    scanners = [ALL_SCANNERS[n] for n in names]
    try:
        watch(root, lambda p: run_scan(p, scanners, config, offline=not args.with_network).findings,
              interval=args.interval, min_severity=Severity.parse(args.min_severity))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_agent_eval(args: argparse.Namespace) -> int:
    from rempart.agent_eval import load_cases, render, run_case, score

    cases = load_cases(Path(args.corpus) if args.corpus else None)
    if args.case:
        cases = [c for c in cases if c["name"] in set(args.case)]
    results = []
    for case in cases:
        print(f"· {case['name']}", file=sys.stderr)
        try:
            results.append(run_case(case, model=args.model, effort=args.effort))
        except RuntimeError as exc:
            print(f"rempart: {exc}", file=sys.stderr)
            return 2
    summary = score(results)
    print(render(results, summary))
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "cases": [r.__dict__ for r in results]}, indent=2), encoding="utf-8")
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from rempart.agent import VerificationAgent, apply_fixes, apply_report, render_report_md, select_targets, write_proofs
    from rempart.engine import discover
    from rempart.history import History
    from rempart.reporters import render_console
    from rempart.scanners import ALL_SCANNERS

    root = Path(args.path).resolve()
    config = Config.load(root)
    result = run_scan(root, list(ALL_SCANNERS.values()), config, offline=args.offline, correlate=False)
    hist = History()
    project = _project_id(root)
    result.findings, _ = hist.apply_knowledge(project, result.findings)
    targets = select_targets(result.findings, Severity.parse(args.min_severity), args.max_findings)
    if not targets:
        print("Nothing for the agent to verify at this severity.")
        return 0
    files, _ = discover(root, config)
    try:
        agent = VerificationAgent(result, files, model=args.model, effort=args.effort, max_turns=args.max_turns,
                                  log=lambda s: print(s, file=sys.stderr))
        print(f"Verifying {len(targets)} finding(s) with {agent.model}…", file=sys.stderr)
        report = agent.run(targets)
    except RuntimeError as exc:
        print(f"rempart: {exc}", file=sys.stderr)
        return 2
    apply_report(result.findings, report)
    result.add_attack_paths()
    hist.record(project, result, _scan_profile(root, "agent", offline=args.offline))
    from rempart.knowledge import Knowledge

    knowledge, proposals = Knowledge.load(root), []
    by_fp = {f.fingerprint: f for f in result.findings}
    for fid, v in report.verdicts.items():
        if v.verdict in ("confirmed", "false_positive"):
            hist.triage(project, fid, "tp" if v.verdict == "confirmed" else "fp", f"AI: {v.reasoning[:300]}", source="ai")
        if v.sanitizer and fid in by_fp and v.sanitizer not in knowledge.sanitizers:
            f = by_fp[fid]
            try:
                proposals.append(knowledge.learn("sanitizer", v.sanitizer, f.rule.id, f"{f.path}:{f.line} (agent)", proposed=True))
            except ValueError:
                pass  # not a data-flow rule, or not a function name
    if proposals:
        knowledge.save(root)
    hist.close()
    md = render_report_md(report, result.findings, root)
    Path(args.report).write_text(md, encoding="utf-8")
    if report.fixes:
        patch = "".join(f.diff(root) for f in report.fixes)
        Path(args.patch).write_text(patch, encoding="utf-8")
    print(render_console(result, limit=args.limit, min_severity=Severity.parse(args.min_severity)))
    cost = report.cost_usd()
    print(f"\nAgent: {sum(v.verdict == 'confirmed' for v in report.verdicts.values())} confirmed, "
          f"{sum(v.verdict == 'false_positive' for v in report.verdicts.values())} false positives, "
          f"{sum(v.verdict == 'uncertain' for v in report.verdicts.values())} uncertain · {report.turns} turns"
          + (f" · ≈ ${cost}" if cost is not None else "") + f" · stop: {report.stop}")
    proofs = write_proofs(report, result.findings, Path(args.proofs))
    print(f"Report: {args.report}" + (f" · fixes: {args.patch} ({len(report.fixes)})" if report.fixes else "")
          + (f" · proof tests: {args.proofs}/ ({len(proofs)}, not executed)" if proofs else ""))
    if report.summary:
        print("\n" + report.summary)
    if proposals:
        print("\nThe agent proposes sanitisers to learn (review, then `rempart learn --accept-proposals`):\n  " + "\n  ".join(proposals))
    if args.apply and report.fixes:
        changed = apply_fixes(report, root)
        print(f"Applied fixes to: {', '.join(changed)}. Review with `git diff` before committing.")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from rempart import bench

    result = bench.run(Path(args.corpus) if args.corpus else None, set(args.case) if args.case else None)
    if not result.cases:
        print("rempart: no bench cases found", file=sys.stderr)
        return 2
    print(bench.render(result, verbose=args.verbose))
    data = result.to_dict()
    if args.json:
        Path(args.json).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if args.update:
        Path(args.update).write_text(json.dumps({"cases": data["cases"], "total": data["total"], "domains": data["domains"]}, indent=2) + "\n", encoding="utf-8")
        print(f"\nBaseline written to {args.update}")
    if args.check:
        problems = bench.check(result, bench.load_baseline(Path(args.check)), args.tolerance)
        if problems:
            print("\nRegressions against " + args.check + ":\n  " + "\n  ".join(problems))
            return 1
        print(f"\nNo regression against {args.check}.")
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"rempart: {root} is not a directory", file=sys.stderr)
        return 2
    try:
        import textual  # noqa: F401
    except ImportError:
        print('rempart: the terminal interface needs Textual: pip install "rempart[tui]" (or textual)', file=sys.stderr)
        return 2
    from rempart.tui import run

    return run(root, offline=args.offline, prod_only=args.prod_only)


def cmd_mcp(args: argparse.Namespace) -> int:
    from rempart.mcp_server import serve

    return serve()


def triage(root: Path, finding_id: str, verdict: str, note: str = "", because: str = "") -> tuple[str, str]:
    """Record a person's verdict, and the reason behind it as project knowledge.
    Returns (rule id, what was learned or ""). Raises KeyError for an unknown finding,
    ValueError for an unusable reason. Shared by the CLI and the terminal interface."""
    from rempart.history import History
    from rempart.knowledge import Knowledge

    if because and verdict == "tp":
        raise ValueError("--because explains why a finding is not a problem; use it with --fp or --accept")
    project = _project_id(root)
    hist = History()
    try:
        learned = ""
        if because:
            kind, _, value = because.partition(":")
            row = hist.finding_row(project, finding_id)
            if row is None:
                raise KeyError(f"unknown fingerprint {finding_id} for {project}; run a scan first")
            knowledge = Knowledge.load(root)
            learned = knowledge.learn(kind.strip(), value.strip(), row["rule_id"], f"{row['path']}:{row['line']}")
            knowledge.save(root)
        note = " · ".join(x for x in (note, f"because {because}" if because else "") if x)
        return hist.triage(project, finding_id, verdict, note), learned
    finally:
        hist.close()


def cmd_triage(args: argparse.Namespace) -> int:
    from rempart.knowledge import FILE

    verdict = "fp" if args.fp else "tp" if args.tp else "accepted"
    try:
        rule_id, learned = triage(Path(args.path).resolve(), args.id, verdict, args.note or "", args.because or "")
    except (KeyError, ValueError) as exc:
        print(f"rempart: {str(exc).strip(chr(39))}", file=sys.stderr)
        return 2
    print(f"Recorded {verdict.upper()} for {args.id} ({rule_id}). Future scans will use it.")
    if learned:
        print(f"Learned: {learned}. Every future scan of this repository applies it ({FILE}; commit it to share).")
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
    from rempart.knowledge import FILE, Knowledge

    root = Path(args.path).resolve()
    if args.accept_proposals:
        knowledge = Knowledge.load(root)
        accepted = knowledge.accept_proposals()
        if not accepted:
            print("No proposals to accept.")
            return 0
        knowledge.save(root)
        print("Accepted:\n  " + "\n  ".join(accepted) + f"\nWritten to {FILE}.")
        return 0
    hist = History()
    if args.eval:
        report = hist.replay(None if args.all_projects else _project_id(root))
        hist.close()
        if args.json:
            print(json.dumps(report, indent=2))
            return 0
        print(_render_replay(report))
        return 0
    stats = hist.rule_stats()
    sources = hist.source_counts()
    hist.close()
    rules = load_all_rules()
    knowledge = Knowledge.load(root)
    if not stats and knowledge.is_empty() and not knowledge.proposed:
        print("No feedback yet. Triage findings with `rempart triage <id> --tp/--fp/--accept`; fixes and inline ignores count too.")
        return 0
    if stats:
        print(f"{'rule':<34} {'TP':>5} {'FP':>5} {'acc':>4}  prior  learned  evidence")
        for rid, s in sorted(stats.items(), key=lambda kv: kv[1].precision()):
            prior = rules[rid].confidence if rid in rules else 0.8
            src = ", ".join(f"{n} {k}" for k, n in sorted(sources.get(rid, {}).items()))
            print(f"{rid:<34} {s.tp:>5.3g} {s.fp:>5.3g} {s.accepted:>4.3g}  {prior:>5.0%}  {s.precision(prior):>6.0%}  {src}")
        print("\nCounts are weighted: human 1, agent / fixed-in-code / inline-ignore 0.5, halved every year, older rule versions 0.25.")
    if not knowledge.is_empty() or knowledge.proposed:
        print(f"\nProject knowledge ({FILE}):")
        for name, cats in sorted(knowledge.sanitizers.items()):
            print(f"  sanitizer    {name}()  {', '.join(sorted(cats))}")
        for value in sorted(knowledge.placeholders):
            print(f"  placeholder  {value}")
        for name, info in sorted(knowledge.proposed.get("sanitizers", {}).items()):
            print(f"  proposed     {name}()  {', '.join(map(str, info.get('categories', [])))}  ({info.get('learned_from', '')})")
        if knowledge.proposed:
            print("  Accept the proposals with `rempart learn --accept-proposals`.")
    return 0


def _render_replay(r: dict) -> str:
    if not r["labelled"]:
        return "Nothing to replay yet: the replay needs findings a person triaged (rempart triage)."
    lines = [f"Replay of {r['labelled']} triaged findings ({r['real']} real, {r['false_alarms']} false alarms), each scored "
             "as it stood the day it first appeared.\n",
             f"{'':<22} {'without learning':>17} {'with learning':>14}"]

    def row(label: str, a: object, b: object) -> None:
        lines.append(f"{label:<22} {str(a):>17} {str(b):>14}")

    w, l = r["without_learning"], r["with_learning"]
    row("ranking AUC", w["auc"] if w["auc"] is not None else "–", l["auc"] if l["auc"] is not None else "–")
    row("Brier score (lower)", w["brier"], l["brier"])
    for key in [k for k in w if k.startswith("top")]:
        row(f"precision in {key}", f"{w[key]['precision']:.0%}", f"{l[key]['precision']:.0%}")
        row(f"false alarms in {key}", w[key]["false_positives"], l[key]["false_positives"])
    return "\n".join(lines)


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
    s.add_argument("--also", action="append", metavar="FORMAT:PATH", help="also write another format from the same scan, e.g. md:report.md (repeatable)")
    s.add_argument("--only", help="comma-separated scanners to run")
    s.add_argument("--skip", help="comma-separated scanners to skip")
    s.add_argument("--offline", action="store_true", help="no network: skip OSV/KEV/EPSS lookups")
    s.add_argument("--aws", nargs="?", const="default", metavar="PROFILE",
                   help="also audit the live AWS account (read-only) and correlate it with the code")
    s.add_argument("--image", action="append", metavar="REF", help="also scan this container image (repeatable)")
    s.add_argument("--git-history", action="store_true", help="also look for secrets removed from the files but still in past commits")
    s.add_argument("--baseline", metavar="REF", help="only report findings that are not already present at this git revision (e.g. origin/main)")
    s.add_argument("--prod-only", action="store_true", help="ignore dependencies only used to build or test (devDependencies, dev groups)")
    s.add_argument("--verify-secrets", action="store_true",
                   help="check whether detected credentials are live by calling each provider's read-only identity endpoint (your own repositories only)")
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
    t.add_argument("--because", metavar="KIND:VALUE",
                   help="teach the reason so it applies to the whole class: sanitizer:NAME[=categories] or placeholder:VALUE")
    t.add_argument("--path", default=".", help="project root (default: current directory)")
    t.set_defaults(func=cmd_triage)

    h = sub.add_parser("history", help="score trend for a project")
    h.add_argument("path", nargs="?", default=".")
    h.add_argument("--limit", type=int, default=20)
    h.set_defaults(func=cmd_history)

    ln = sub.add_parser("learn", help="what Rempart learned: per-rule precision, project knowledge, and whether learning helps")
    ln.add_argument("--path", default=".", help="project root, for its knowledge file and replay (default: current directory)")
    ln.add_argument("--eval", action="store_true", help="replay history in time order: ranking with versus without learning")
    ln.add_argument("--all-projects", action="store_true", help="with --eval: replay every project's history")
    ln.add_argument("--json", action="store_true", help="with --eval: print the replay as JSON")
    ln.add_argument("--accept-proposals", action="store_true", help="apply the sanitisers the AI agent proposed")
    ln.set_defaults(func=cmd_learn)

    def outputs(sp: argparse.ArgumentParser, min_sev: str = "low") -> None:
        sp.add_argument("-f", "--format", choices=["console", "json", "sarif", "md", "markdown", "html"], default="console")
        sp.add_argument("-o", "--output")
        sp.add_argument("--fail-on", choices=[x.name.lower() for x in Severity])
        sp.add_argument("--min-severity", default=min_sev, choices=[x.name.lower() for x in Severity])
        sp.add_argument("--limit", type=int, default=60)
        sp.add_argument("-v", "--verbose", action="store_true")

    im = sub.add_parser("image", help="scan a container image from a registry or a docker-save/OCI tar (no Docker needed)")
    im.add_argument("image", help="e.g. python:3.12-slim, ghcr.io/org/app@sha256:..., or ./image.tar")
    im.add_argument("--platform", default="linux/amd64")
    im.add_argument("--offline", action="store_true")
    im.add_argument("--max-mb", type=int, default=3000, help="refuse images whose layers exceed this size")
    outputs(im)
    im.set_defaults(func=cmd_image)

    cl = sub.add_parser("cloud", help="live read-only audit of a cloud account (AWS)")
    cl.add_argument("provider", choices=["aws", "gcp", "azure"])
    cl.add_argument("--project", help="GCP project id (default: gcloud's configured project)")
    cl.add_argument("--subscription", help="Azure subscription id or name (default: az's current subscription)")
    cl.add_argument("--profile", help="AWS profile name (default: the standard credential chain)")
    cl.add_argument("--regions", help="comma-separated regions (default: every enabled region)")
    outputs(cl)
    cl.set_defaults(func=cmd_cloud)

    k8 = sub.add_parser("k8s", help="live audit of a Kubernetes cluster through kubectl (read-only, never reads Secrets)")
    k8.add_argument("--context")
    k8.add_argument("--include-system", action="store_true", help="also audit kube-system and other system namespaces")
    outputs(k8)
    k8.set_defaults(func=cmd_k8s)

    ag = sub.add_parser("agent", help="AI verification: an LLM reads the code behind each finding, confirms or rejects it and proposes fixes")
    ag.add_argument("path", nargs="?", default=".")
    ag.add_argument("--model", default=None, help="model id (default: $REMPART_MODEL, else the newest Opus-tier model from the Anthropic Models API)")
    ag.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    ag.add_argument("--max-findings", type=int, default=15)
    ag.add_argument("--max-turns", type=int, default=40)
    ag.add_argument("--min-severity", default="medium", choices=[x.name.lower() for x in Severity])
    ag.add_argument("--offline", action="store_true")
    ag.add_argument("--proofs", default="rempart-proofs", metavar="DIR", help="where confirmed findings' proof tests are written (never executed)")
    ag.add_argument("--report", default="rempart-agent-report.md")
    ag.add_argument("--patch", default="rempart-fixes.patch")
    ag.add_argument("--apply", action="store_true", help="write the proposed fixes to the files (review with git diff)")
    ag.add_argument("--limit", type=int, default=40)
    ag.set_defaults(func=cmd_agent)

    wt = sub.add_parser("watch", help="re-scan whenever the repository changes and print only what got better or worse")
    wt.add_argument("path", nargs="?", default=".")
    wt.add_argument("--interval", type=float, default=20.0, help="seconds between change checks")
    wt.add_argument("--min-severity", default="medium", choices=[x.name.lower() for x in Severity])
    wt.add_argument("--only", help="comma-separated scanners to run")
    wt.add_argument("--with-network", action="store_true", help="also query OSV/KEV/EPSS on each change (slower)")
    wt.set_defaults(func=cmd_watch)

    ev = sub.add_parser("agent-eval", help="measure the AI verification agent on labelled cases (needs ANTHROPIC_API_KEY)")
    ev.add_argument("--corpus", help="JSON file of labelled cases (default: the bundled corpus)")
    ev.add_argument("--case", action="append", help="run only this case (repeatable)")
    ev.add_argument("--model", default=None)
    ev.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    ev.add_argument("--json", help="also write the detailed results to this file")
    ev.set_defaults(func=cmd_agent_eval)

    tu = sub.add_parser("tui", help="interactive terminal interface: scan, browse, triage and teach in one screen")
    tu.add_argument("path", nargs="?", default=".")
    tu.add_argument("--offline", action="store_true", help="start without OSV/KEV/EPSS lookups (toggle with o)")
    tu.add_argument("--prod-only", action="store_true", help="ignore dependencies only used to build or test")
    tu.set_defaults(func=cmd_tui)

    bn = sub.add_parser("bench", help="measure detection per domain on a labelled corpus (the bundled one by default)")
    bn.add_argument("--corpus", help="directory of labelled cases (see rempart/bench.py for the label format)")
    bn.add_argument("--case", action="append", help="run only this case (repeatable)")
    bn.add_argument("--check", metavar="BASELINE", help="exit 1 if a domain's precision or recall fell below this baseline JSON")
    bn.add_argument("--tolerance", type=float, default=0.0, help="allowed drop for --check (default 0: the bench is deterministic)")
    bn.add_argument("--update", metavar="BASELINE", help="write the current numbers as the new baseline")
    bn.add_argument("--json", help="also write the full results, misses included")
    bn.add_argument("-v", "--verbose", action="store_true", help="list every miss, unexpected finding and fired trap")
    bn.set_defaults(func=cmd_bench)

    sub.add_parser("mcp", help="run as a Model Context Protocol server over stdio (for AI coding assistants: Cursor, VS Code, Windsurf…)").set_defaults(func=cmd_mcp)

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
