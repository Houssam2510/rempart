from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from rempart import __version__
from rempart.engine import ScanResult, score
from rempart.models import Severity
from rempart.registry import OWASP_2025, REGISTRY
from rempart.scanners.deps import upgrade_plan


def render_json(result: ScanResult) -> str:
    value, grade = score(result.findings)
    return json.dumps({
        "tool": {"name": "rempart", "version": __version__},
        "root": result.root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": value, "grade": grade,
        "counts": result.counts(),
        "files_scanned": result.files_scanned,
        "duration_s": result.duration_s,
        "suppressed": result.suppressed,
        "errors": result.errors,
        "findings": [f.to_dict() for f in result.findings],
        "upgrade_plan": upgrade_plan(result.findings),
    }, indent=2, ensure_ascii=False)


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
_SEC_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.5"}


def render_sarif(result: ScanResult) -> str:
    used = sorted({f.rule.id for f in result.findings})
    rules = []
    for rid in used:
        r = REGISTRY[rid]
        rules.append({
            "id": r.id, "name": r.id.replace("-", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.remediation or r.title},
            "help": {"text": r.remediation, "markdown": r.remediation},
            "helpUri": r.references[0] if r.references else "https://github.com/Houssam2510/rempart/blob/main/docs/RULES.md",
            "properties": {"tags": ["security", r.domain, *r.cwe, *r.owasp], "security-severity": _SEC_SCORE[r.severity], "precision": "high" if r.confidence >= 0.8 else "medium" if r.confidence >= 0.6 else "low"},
        })
    results = []
    for f in result.findings:
        assert f.severity is not None
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path}}}
        if f.line > 0:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule.id, "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [loc],
            "partialFingerprints": {"rempart/v1": f.fingerprint},
            "properties": {"security-severity": _SEC_SCORE[f.severity], "risk": f.risk, **({"epss": f.extra["epss"]} if "epss" in f.extra else {}), **({"kev": True} if f.extra.get("kev") else {})},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "rempart", "version": __version__, "informationUri": "https://github.com/Houssam2510/rempart", "rules": rules}}, "results": results}],
    }, indent=2)


def _owasp_matrix(result: ScanResult) -> Counter[str]:
    c: Counter[str] = Counter()
    for f in result.findings:
        for o in f.rule.owasp:
            c[o] += 1
    return c


def render_markdown(result: ScanResult) -> str:
    value, grade = score(result.findings)
    counts = result.counts()
    lines = [
        f"## Rempart security report — grade **{grade}** ({value}/100)", "",
        "| Critical | High | Medium | Low | Info |", "|---:|---:|---:|---:|---:|",
        f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} |", "",
    ]
    top = [f for f in result.findings if f.severity is not None and f.severity >= Severity.MEDIUM][:25]
    if top:
        lines += ["| Severity | Finding | Location |", "|---|---|---|"]
        for f in top:
            assert f.severity is not None
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity.name} | **{f.rule.title}** — {msg} | `{f.path}:{f.line}` |")
        lines.append("")
    plan = upgrade_plan(result.findings)
    if plan:
        lines += ["### Upgrade plan", "", "| Package | Current | Upgrade to | Advisories fixed | Notes |", "|---|---|---|---:|---|"]
        for row in plan[:20]:
            notes = ", ".join(n for n, on in (("KEV", row["kev"]), ("used by your code", row["reachable"]), ("major version", row["major_bump"]),
                                              ("dev only", row["scope"] == "dev")) if on)
            lines.append(f"| `{row['package']}` | {row['current']} | **{row['target'] or 'no fix yet'}** | {row['fixes']}/{row['advisories']} | {notes} |")
        lines.append("")
    matrix = _owasp_matrix(result)
    if matrix:
        lines += ["<details><summary>OWASP Top 10:2025 coverage of findings</summary>", "", "| Category | Findings |", "|---|---:|"]
        lines += [f"| {cat} | {matrix.get(cat, 0)} |" for cat in OWASP_2025]
        lines += ["", "</details>"]
    return "\n".join(lines)


def render_html(result: ScanResult) -> str:
    value, grade = score(result.findings)
    counts = result.counts()
    esc = html.escape
    rows = []
    for f in result.findings:
        assert f.severity is not None
        maps = ", ".join(list(f.rule.owasp) + list(f.rule.cwe) + list(f.rule.frameworks))
        rows.append(
            f'<tr data-sev="{f.severity.name}" data-domain="{esc(f.rule.domain)}"><td><span class="sev {f.severity.name.lower()}">{f.severity.name}</span></td>'
            f"<td><strong>{esc(f.rule.title)}</strong><div>{esc(f.message)}</div>"
            f'<details><summary>Fix &amp; mappings</summary><p>{esc(f.rule.remediation)}</p><p class="muted">{esc(maps)}</p>'
            f'<p class="muted">{esc(f.rule.id)} · id {f.fingerprint} · risk {f.risk:.0f}{" · " + esc(f.learned_note) if f.learned_note else ""}</p></details></td>'
            f'<td class="loc">{esc(f.path)}{":" + str(f.line) if f.line else ""}</td><td>{esc(f.rule.domain)}</td></tr>'
        )
    domains = sorted({f.rule.domain for f in result.findings})
    matrix = _owasp_matrix(result)
    owasp_rows = "".join(f"<tr><td>{esc(c)}</td><td>{matrix.get(c, 0)}</td></tr>" for c in OWASP_2025)
    options = "".join(f'<option value="{esc(d)}">{esc(d)}</option>' for d in domains)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rempart report</title>
<style>
:root{{--bg:#0f1115;--panel:#171a21;--text:#e7e9ee;--muted:#9aa3b2;--line:#262b36;--crit:#ff4d4f;--high:#ff7a45;--med:#fadb14;--low:#40a9ff;--info:#8c8c8c;--accent:#7c5cff}}
@media (prefers-color-scheme: light){{:root{{--bg:#f6f7f9;--panel:#fff;--text:#14161b;--muted:#5c6370;--line:#e3e6eb}}}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}}
main{{max-width:1200px;margin:0 auto;padding:24px 16px}}h1{{margin:0 0 4px;font-size:22px}}.muted{{color:var(--muted)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:20px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}.card b{{display:block;font-size:26px}}
.grade b{{color:var(--accent)}}table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
td,th{{padding:10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}}.loc{{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}}
.sev{{font-size:11px;font-weight:700;padding:2px 6px;border-radius:4px;color:#000}}.critical{{background:var(--crit);color:#fff}}.high{{background:var(--high)}}.medium{{background:var(--med)}}.low{{background:var(--low)}}.info{{background:var(--info);color:#fff}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}}select,input{{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px}}
details summary{{cursor:pointer;color:var(--muted);margin-top:4px}}.wrap{{overflow-x:auto}}
@media (max-width:640px){{#t{{table-layout:fixed}}#t th:nth-child(4),#t td:nth-child(4){{display:none}}#t th:nth-child(1){{width:82px}}#t th:nth-child(3){{width:92px}}td,th{{padding:8px 6px;overflow-wrap:anywhere}}}}
</style></head><body><main>
<h1>Rempart security report</h1><div class="muted">{esc(result.root)} · {result.files_scanned} files · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · rempart {__version__}</div>
<div class="cards"><div class="card grade"><span class="muted">Grade</span><b>{grade}</b>{value}/100</div>
{''.join(f'<div class="card"><span class="muted">{s.name.title()}</span><b>{counts[s.name]}</b></div>' for s in sorted(Severity, reverse=True))}</div>
<div class="filters"><select id="sev"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
<select id="dom"><option value="">All domains</option>{options}</select><input id="q" placeholder="Filter text…"></div>
<div class="wrap"><table id="t"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Domain</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<h2>OWASP Top 10:2025</h2><div class="wrap"><table><tbody>{owasp_rows}</tbody></table></div>
</main><script>
const f=()=>{{const s=document.getElementById('sev').value,d=document.getElementById('dom').value,q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#t tbody tr').forEach(r=>{{r.style.display=(!s||r.dataset.sev===s)&&(!d||r.dataset.domain===d)&&(!q||r.textContent.toLowerCase().includes(q))?'':'none'}})}};
['sev','dom','q'].forEach(id=>document.getElementById(id).addEventListener('input',f));
</script></body></html>"""
