from __future__ import annotations

import os
import sys
from typing import Any

from rempart.engine import ScanResult, score
from rempart.models import Severity

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
        col(f"  Posture score {value}/100  grade {grade}", BOLD),
        "  " + "  ".join(col(f"{counts[s.name]} {s.name.lower()}", COLORS[s]) for s in sorted(Severity, reverse=True)),
        "",
    ]
    if diff and (diff.get("new") or diff.get("fixed")):
        out.append(f"  since last scan: {col('+' + str(len(diff['new'])) + ' new', COLORS[Severity.HIGH])}  {col('-' + str(len(diff['fixed'])) + ' fixed', COLORS[Severity.LOW])}")
        out.append("")
    shown = [f for f in result.findings if f.severity is not None and f.severity >= min_severity]
    by_domain: dict[str, list] = {}
    for f in shown:
        by_domain.setdefault(f.rule.domain, []).append(f)
    printed = 0
    collapsed = 0
    for domain, items in sorted(by_domain.items(), key=lambda kv: -max(x.risk for x in kv[1])):
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
            out.append(f"         {f.message}")
            if verbose:
                if f.rule.remediation:
                    out.append(col(f"         fix: {f.rule.remediation}", DIM))
                maps = list(f.rule.owasp) + list(f.rule.cwe) + list(f.rule.frameworks)
                if maps:
                    out.append(col(f"         maps: {', '.join(maps)}", DIM))
            out.append(col(f"         id {f.fingerprint[:10]} · {f.rule.id} · risk {f.risk:.0f}" + (f" · {f.learned_note}" if f.learned_note else ""), DIM))
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
