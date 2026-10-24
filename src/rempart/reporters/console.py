from __future__ import annotations

import os
import sys
from typing import Any

from rempart.engine import ScanResult, score
from rempart.models import Severity
from rempart.scanners.deps import upgrade_plan

COLORS = {Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m", Severity.INFO: "\033[2m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def render_console(result: ScanResult, *, limit: int = 60, min_severity: Severity = Severity.LOW, diff: dict[str, Any] | None = None, verbose: bool = False) -> str:
    c = _use_color()

    def col(s: str, code: str) -> str:
        return f"{code}{s}{RESET}" if c else s

    value, grade = score(result.findings)
    counts = result.counts()
    out = [
        col(f"Rempart — {result.root}", BOLD),
        (f"{result.files_scanned} files · " if result.files_scanned else "") + f"{len(result.scanners)} scanner(s) · {result.duration_s}s"
        + (f" · {result.suppressed} suppressed" if result.suppressed else ""),
        "",
        col(f"  Posture score {value}/100  grade {grade}", BOLD) if result.complete else
        col(f"  Posture score: INCOMPLETE — {len(result.errors)} scanner error(s), no grade is given", COLORS[Severity.HIGH]),
        "  " + "  ".join(col(f"{counts[s.name]} {s.name.lower()}", COLORS[s]) for s in sorted(Severity, reverse=True)),
        "",
    ]
    if diff and (diff.get("new") or diff.get("fixed") or diff.get("gone")):
        line = f"  since last scan: {col('+' + str(len(diff['new'])) + ' new', COLORS[Severity.HIGH])}  {col('-' + str(len(diff['fixed'])) + ' fixed', COLORS[Severity.LOW])}"
        if diff.get("gone"):
            line += f"  ({len(diff['gone'])} no longer reported: options, configuration or learned knowledge changed)"
        out.append(line)
        out.append("")
    shown = [f for f in result.findings if f.severity is not None and f.severity >= min_severity]
    by_domain: dict[str, list] = {}
    for f in shown:
        by_domain.setdefault(f.rule.domain, []).append(f)
    printed = 0
    collapsed = 0
    for domain, items in sorted(by_domain.items(), key=lambda kv: (kv[0] != "attack-path", -max(x.risk for x in kv[1]))):
        if printed >= limit:
            break
        out.append(col(f"■ {domain} ({len(items)})", BOLD))
        per_pkg: dict[str, int] = {}
        pkg_total: dict[str, int] = {}
        for f in items:
            if "package" in f.extra:
                key = f"{f.extra['package']}@{f.extra.get('version', '')}"
                pkg_total[key] = pkg_total.get(key, 0) + 1
        for f in items:
            if printed >= limit:
                break
            if "package" in f.extra and not verbose:
                key = f"{f.extra['package']}@{f.extra.get('version', '')}"
                per_pkg[key] = per_pkg.get(key, 0) + 1
                if per_pkg[key] > 3:
                    if per_pkg[key] == 4:
                        out.append(col(f"         … {pkg_total[key] - 3} more advisories for {key} (use -v or --format html)", DIM))
                    collapsed += 1
                    continue
            printed += 1
            assert f.severity is not None
            tag = col(f" {f.severity.name[:4]} ", COLORS[f.severity])
            loc = f"{f.path}:{f.line}" if f.line else f.path
            out.append(f"  {tag} {f.rule.title}  {col(loc, DIM)}")
            route = f.extra.get("route") if f.rule.domain == "attack-path" else None
            if route:
                out.append(f"         {f.message.split(' Connected through:')[0].split(' Links →')[0]}")
                out.append(col(f"         linked: {' ; '.join(route)}", COLORS[Severity.LOW]))
            else:
                out.append(f"         {f.message}")
            if verbose:
                if f.rule.remediation:
                    out.append(col(f"         fix: {f.rule.remediation}", DIM))
                maps = list(f.rule.owasp) + list(f.rule.cwe) + list(f.rule.frameworks)
                if maps:
                    out.append(col(f"         maps: {', '.join(maps)}", DIM))
            out.append(col(f"         id {f.fingerprint[:10]} · {f.rule.id} · risk {f.risk:.0f}" + (f" · {f.learned_note}" if f.learned_note else ""), DIM))
        out.append("")
    plan = upgrade_plan(result.findings)
    if plan:
        out.append(col(f"■ upgrade plan ({len(plan)} package(s), most urgent first)", BOLD))
        for row in plan[:12]:
            target = row["target"] or "no fix published"
            notes = [f"{row['fixes']}/{row['advisories']} advisories fixed"]
            if row["kev"]:
                notes.append("KEV")
            if row["reachable"]:
                notes.append("used by your code")
            if row["major_bump"]:
                notes.append("major version")
            if row["scope"] == "dev":
                notes.append("dev only")
            out.append(f"  {col(row['severity'][:4], COLORS[Severity[row['severity']]])} {row['package']} {row['current']} → {col(target, BOLD)}  "
                       + col(" · ".join(notes), DIM))
        if len(plan) > 12:
            out.append(col(f"  … {len(plan) - 12} more in --format json (upgrade_plan)", DIM))
        out.append("")
    hidden = len(shown) - printed - collapsed
    if hidden > 0:
        out.append(col(f"… {hidden} more. Use --limit, --format html, or --min-severity to see them.", DIM))
    below = len(result.findings) - len(shown)
    if below:
        out.append(col(f"{below} finding(s) below {min_severity.name.lower()} hidden.", DIM))
    for e in result.errors:
        out.append(col(f"scanner error: {e}", COLORS[Severity.HIGH]))
    if result.findings:
        out.append(col("Triage a finding so Rempart learns:  rempart triage <id> --fp | --tp | --accept", DIM))
    return "\n".join(out)
