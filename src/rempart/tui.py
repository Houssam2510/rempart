"""Terminal interface: `rempart tui [PATH]` (needs `pip install "rempart[tui]"`).

Five views, switched with 1–5 or the mouse:

    1 Overview      score, trend, severities, domains, what to fix first, attack paths
    2 Findings      filter / search / triage, with the code around each finding
    3 Attack paths  each chain drawn stage by stage, with the cheapest place to break it
    4 Dependencies  upgrade plan, the smallest version that fixes every advisory
    5 Learning      what Rempart learned, from whom, and whether it helps (replay)

Scans run the same pipeline as `rempart scan` (learned knowledge applied, history
recorded with the same profile), so verdicts and fixes made here teach the CLI too.
Everything the views show is computed by the plain functions of the first half of
this module, which are tested without a terminal.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rempart.config import Config
from rempart.engine import ScanResult, run_scan, score
from rempart.models import Finding, Severity

# ---------------------------------------------------------------- visual language

BRAND = "#8b5cf6"
SEV_COLOR = {Severity.CRITICAL: "#ff4d6d", Severity.HIGH: "#ff8c42", Severity.MEDIUM: "#f7c948",
             Severity.LOW: "#4cc9f0", Severity.INFO: "#6b7280"}
SEV_SHORT = {Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH", Severity.MEDIUM: "MED", Severity.LOW: "LOW", Severity.INFO: "INFO"}
GRADE_COLOR = {"A": "#22c55e", "B": "#84cc16", "C": "#f7c948", "D": "#ff8c42", "F": "#ff4d6d"}
VERDICT_LABEL = {"tp": "TP", "fp": "FP", "accepted": "ACCEPTED"}
PROOF_LABEL = {
    "static": "pattern", "reachable": "reachable", "function-reachable": "called", "imported": "imported",
    "declared": "declared", "not-imported": "unused", "observed": "observed live", "live-secret": "LIVE key",
    "revoked-secret": "revoked", "linked": "linked", "correlated": "correlated", "co-occurrence": "co-occurs",
    "ai-confirmed": "AI confirmed", "ai-rejected": "AI rejected", "ai-uncertain": "AI unsure",
}
STRONG_PROOF = {"linked", "function-reachable", "live-secret", "observed", "ai-confirmed", "reachable"}


def proof_of(f: Finding) -> tuple[str, bool]:
    """How the finding was established, and whether that is strong evidence. A static
    finding whose value was traced from the request is proven by data flow, not a pattern."""
    if f.verification == "static" and (f.extra.get("dataflow") == "tainted" or isinstance(f.extra.get("dataflow"), dict)):
        return "data flow", True
    return PROOF_LABEL.get(f.verification, f.verification), f.verification in STRONG_PROOF


def sev_pill(sev: Severity) -> Any:
    from rich.text import Text

    return Text(f" {SEV_SHORT[sev]:^4} ", style=f"bold #0b0d14 on {SEV_COLOR[sev]}")


def chip(text: str, color: str = "#334155", fg: str = "#e2e8f0") -> Any:
    from rich.text import Text

    return Text(f" {text} ", style=f"{fg} on {color}")


def bar(value: float, total: float, width: int, color: str) -> Any:
    """A horizontal bar with eighth-block resolution."""
    from rich.text import Text

    eighths = 0 if total <= 0 else round(max(0.0, min(1.0, value / total)) * width * 8)
    full, rest = divmod(eighths, 8)
    t = Text("█" * full, style=color)
    if rest:
        t.append(" ▏▎▍▌▋▊▉"[rest], style=color)
    t.append(" " * max(0, width - full - (1 if rest else 0)), style="on #1e2233")
    return t


# ---------------------------------------------------------------- logic (no terminal needed)

@dataclass
class Session:
    root: Path
    offline: bool = False
    prod_only: bool = False
    result: ScanResult | None = None
    diff: dict[str, list[Any]] | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def scan(self, progress: Callable[[str, int, int], None] | None = None) -> ScanResult:
        """Same pipeline as `rempart scan PATH`: learned knowledge, attack paths, history."""
        from rempart.cli import _project_id, _scan_profile
        from rempart.history import History
        from rempart.scanners import ALL_SCANNERS

        config = Config.load(self.root)
        config.prod_only = config.prod_only or self.prod_only
        result = run_scan(self.root, list(ALL_SCANNERS.values()), config, offline=self.offline, correlate=False, progress=progress)
        if progress is not None:
            progress("learning and attack paths", len(ALL_SCANNERS), len(ALL_SCANNERS))
        hist = History()
        try:
            project = _project_id(self.root)
            result.findings, learned = hist.apply_knowledge(project, result.findings)
            result.suppressed += learned
            result.add_attack_paths()
            profile = _scan_profile(self.root, "scan", offline=self.offline, prod_only=self.prod_only)
            self.diff = hist.diff_with_previous(project, hist.record(project, result, profile))
            self.history = list(reversed(hist.scans(project, 30)))
        finally:
            hist.close()
        self.result = result
        return result

    def triage(self, f: Finding, verdict: str, because: str = "", note: str = "") -> str:
        """Record a verdict (and its reason); returns a sentence for the status line."""
        from rempart.cli import triage

        rule_id, learned = triage(self.root, f.fingerprint, verdict, note, because)
        said = f"{VERDICT_LABEL[verdict]} recorded for {rule_id} at {f.path}:{f.line}"
        return said + (f". Learned: {learned}" if learned else "")

    def by_fingerprint(self) -> dict[str, Finding]:
        return {f.fingerprint: f for f in (self.result.findings if self.result else [])}


def visible(findings: list[Finding], domain: str = "", min_severity: Severity = Severity.INFO, query: str = "") -> list[Finding]:
    q = query.lower().strip()
    out = []
    for f in findings:
        if domain and f.rule.domain != domain:
            continue
        if f.severity is not None and f.severity < min_severity:
            continue
        if q and q not in " ".join((f.rule.id, f.rule.title, f.path, f.message, f.rule.domain)).lower():
            continue
        out.append(f)
    return out


def domain_counts(findings: list[Finding]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule.domain] = counts.get(f.rule.domain, 0) + 1
    order = {"attack-path": 0}
    return sorted(counts.items(), key=lambda kv: (order.get(kv[0], 1), -kv[1], kv[0]))


def domain_worst(findings: list[Finding]) -> dict[str, Severity]:
    worst: dict[str, Severity] = {}
    for f in findings:
        sev = f.severity if f.severity is not None else Severity.INFO
        if f.rule.domain not in worst or sev > worst[f.rule.domain]:
            worst[f.rule.domain] = sev
    return worst


@dataclass
class Action:
    """One line of "fix first": what to do, why, and where it leads in the interface."""
    severity: Severity
    title: str
    detail: str
    target: str  # "finding:<fingerprint>" | "chain:<fingerprint>" | "package:<name>@<version>"


def fix_first(findings: list[Finding], limit: int = 7) -> list[Action]:
    """The few actions that remove the most risk: proven attack paths (with the cheapest
    stage to break), dependency upgrades that close exploited, used or critical
    advisories in production, then the riskiest proven findings not already covered."""
    from rempart.scanners.deps import upgrade_plan

    out: list[Action] = []
    covered: set[str] = set()
    for f in findings:
        if f.rule.domain == "attack-path" and f.verification in ("linked", "correlated") and f.severity is not None:
            out.append(Action(f.severity, f.rule.title, "break it: " + _shorten(str(f.extra.get("break_first") or f.rule.remediation), 120),
                              f"chain:{f.fingerprint}"))
            covered |= set(f.extra.get("members") or [])
    for p in upgrade_plan(findings):
        if p["target"] and p["scope"] == "prod" and (p["kev"] or p["reachable"] or Severity[p["severity"]] >= Severity.CRITICAL):
            why = "exploited in the wild (KEV)" if p["kev"] else "your code uses it" if p["reachable"] else "critical advisory"
            out.append(Action(Severity[p["severity"]], f"upgrade {p['package']} {p['current']} → {p['target']}",
                              f"{p['fixes']}/{p['advisories']} advisories · {why}", f"package:{p['package']}@{p['current']}"))
    for f in findings:
        if f.rule.domain in ("attack-path", "dependencies") or f.fingerprint in covered or f.severity is None:
            continue
        if f.severity >= Severity.HIGH and (proof_of(f)[1] or (f.confidence or 0) >= 0.85):
            out.append(Action(f.severity, f.rule.title, f"{f.path}:{f.line}" if f.line else f.path, f"finding:{f.fingerprint}"))
    out.sort(key=lambda a: (-a.severity, {"chain": 0, "package": 1, "finding": 2}[a.target.split(":")[0]]))
    return out[:limit]


def _shorten(text: str, limit: int) -> str:
    """At most `limit` characters, cut at a sentence or word boundary."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    for mark in (". ", "; ", ", "):
        if mark in cut[limit // 2:]:
            return cut[:cut.rindex(mark) + 1].rstrip(",;") + ("" if mark == ". " else "…")
    return cut[:cut.rfind(" ")] + "…"


def suggested_reason(f: Finding) -> str:
    """What `--because` most likely needs for this finding, as a starting point to edit."""
    from rempart.knowledge import rule_category

    if rule_category(f.rule.id):
        return "sanitizer:"
    if f.rule.domain == "secrets":
        return "placeholder:"
    return ""


def code_context(root: Path, f: Finding, around: int = 4) -> tuple[str, int] | None:
    """The lines around a finding, and the number of the first one."""
    if f.line <= 0 or "://" in f.path:
        return None
    try:
        lines = (root / f.path).read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    if f.line > len(lines):
        return None
    start = max(1, f.line - around)
    return "\n".join(line[:220] for line in lines[start - 1:f.line + around]), start


def _lexer(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    name = path.rsplit("/", 1)[-1]
    return {"py": "python", "js": "javascript", "mjs": "javascript", "cjs": "javascript", "jsx": "jsx", "ts": "typescript",
            "tsx": "tsx", "go": "go", "java": "java", "kt": "kotlin", "php": "php", "rb": "ruby", "cs": "csharp", "c": "c",
            "cpp": "cpp", "h": "c", "tf": "terraform", "hcl": "terraform", "yml": "yaml", "yaml": "yaml", "json": "json",
            "toml": "toml", "sql": "sql", "sh": "bash", "md": "markdown", "html": "html", "vue": "vue", "svelte": "html",
            }.get(ext) or ("docker" if name.startswith("Dockerfile") else "text")


def describe(root: Path, f: Finding, verdict: str | None = None) -> list[Any]:
    """Renderables for the finding detail."""
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text

    assert f.severity is not None
    head = Text.assemble(sev_pill(f.severity), "  ", (f.rule.title, "bold #f8fafc"))
    if verdict:
        head.append("  ")
        head.append_text(chip(VERDICT_LABEL[verdict], "#16a34a" if verdict == "tp" else "#7c3aed", "#ffffff"))
    if f.extra.get("regression"):
        head.append("  ")
        head.append_text(chip("REGRESSION", "#b91c1c", "#ffffff"))
    proof, strong = proof_of(f)
    meta = Text.assemble(chip(f.rule.id, "#1e293b", "#a5b4fc"), " ", chip(f"{f.path}{':' + str(f.line) if f.line else ''}", "#1e293b"),
                         " ", chip(f"risk {f.risk:.0f}", "#1e293b"), " ", chip(f"confidence {f.confidence:.0%}", "#1e293b"),
                         " ", chip(proof, "#0e7490" if strong else "#334155", "#ffffff"))
    parts: list[Any] = [head, Text(""), meta, Text(""), Text(f.message, style="#e2e8f0")]
    if f.learned_note:
        parts += [Text(""), Text(f"◆ {f.learned_note}", style="italic #a78bfa")]
    ctx = code_context(root, f)
    if ctx:
        code, start = ctx
        parts += [Text(""), Panel(Syntax(code, _lexer(f.path), line_numbers=True, start_line=start, highlight_lines={f.line},
                                         theme="monokai", word_wrap=True, background_color="#0f1220"),
                                  title=f"[b]{f.path}[/]", title_align="left", border_style="#334155", padding=(0, 1))]
    elif f.snippet:
        parts += [Text(""), Panel(Text(f.snippet), border_style="#334155")]
    extra = {k: v for k, v in f.extra.items() if k not in ("anchor", "members", "stages", "break_first", "route", "regression")
             and v not in (None, "", [], {})}
    if extra:
        rows = Text()
        for k, v in extra.items():
            rows.append(f"{k:<14}", style="#94a3b8")
            rows.append(f"{v}"[:300] + "\n", style="#e2e8f0")
        parts += [Text(""), Panel(rows, title="[b]evidence[/]", title_align="left", border_style="#334155", padding=(0, 1))]
    if f.rule.remediation:
        parts += [Text(""), Panel(Text(f.rule.remediation, style="#dcfce7"), title="[b]how to fix[/]", title_align="left",
                                  border_style="#16a34a", padding=(0, 1))]
    frameworks = list(f.rule.cwe) + [o.split(" ")[0] for o in f.rule.owasp] + list(f.rule.frameworks)
    if frameworks:
        t = Text()
        for fw in frameworks:
            t.append_text(chip(fw, "#1e293b", "#94a3b8"))
            t.append(" ")
        parts += [Text(""), t]
    return parts


def describe_chain(chain: Finding, by_fp: dict[str, Finding]) -> list[Any]:
    """An attack path drawn stage by stage, from the attacker to the impact."""
    from rich.panel import Panel
    from rich.text import Text

    assert chain.severity is not None
    stages = chain.extra.get("stages") or []
    status = (chip("PROVEN PATH", "#0e7490", "#ffffff") if chain.verification == "linked"
              else chip("CO-OCCURRENCE · CHECK THE LINK", "#854d0e", "#ffffff") if chain.verification == "co-occurrence"
              else chip("SAME APPLICATION", "#334155"))
    parts: list[Any] = [Text.assemble(sev_pill(chain.severity), "  ", (chain.rule.title, "bold #f8fafc")), Text(""), status, Text(""),
                        Text("  ◉ attacker", style="bold #ff4d6d")]
    for i, st in enumerate(stages, 1):
        member = by_fp.get(str(st.get("fingerprint")))
        sev = member.severity if member is not None and member.severity is not None else chain.severity
        body = Text.assemble((f"{st.get('title', '')}\n", "bold #f8fafc"), (f"{st.get('rule')}  ", "#a5b4fc"), (str(st.get("where")), "#94a3b8"))
        if st.get("others"):
            body.append(f"   +{st['others']} similar", style="#64748b")
        parts += [Text("  │", style="#475569"), Text("  ▼", style="#475569"),
                  Panel(body, title=f"[b]{i} · {st.get('label', '')}[/]", title_align="left", border_style=SEV_COLOR[sev], padding=(0, 1))]
    parts += [Text("  │", style="#475569"), Text("  ▼", style="#475569"), Text("  ◉ impact", style="bold #ff4d6d"), Text("")]
    for route in chain.extra.get("route") or []:
        parts.append(Text(f"connected through  {route}", style="#67e8f9"))
    parts += [Text(""), Text(chain.message.split(" Links → ")[0], style="#cbd5e1")]
    if chain.extra.get("break_first"):
        parts += [Text(""), Panel(Text(str(chain.extra["break_first"]), style="#dcfce7"), title="[b]cheapest place to break it[/]",
                                  title_align="left", border_style="#16a34a", padding=(0, 1))]
    return parts


def summary_counts(result: ScanResult | None) -> dict[Severity, int]:
    counts = result.counts() if result else {s.name: 0 for s in Severity}
    return {s: counts[s.name] for s in sorted(Severity, reverse=True)}


def _fit(t: Any, width: int, left: bool = False) -> Any:
    """Truncate to `width` cells with an ellipsis, at the end, or at the start for paths
    (the file name matters more than the directories above it)."""
    if t.cell_len <= width:
        return t
    if left:
        t = t[t.cell_len - width + 1:]
        t.pad_left(1, "…")
        return t
    t.truncate(width, overflow="ellipsis")
    return t


# ---------------------------------------------------------------- the application

def build_app(root: Path, offline: bool = False, prod_only: bool = False) -> Any:
    """The Textual application. Imported lazily: textual is an optional dependency."""
    from rich.console import Group
    from rich.text import Text
    from textual import work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.command import Hit, Hits, Provider
    from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
    from textual.screen import ModalScreen
    from textual.theme import Theme
    from textual.widgets import DataTable, Digits, Footer, Input, OptionList, ProgressBar, Sparkline, Static, TabbedContent, TabPane
    from textual.widgets.option_list import Option

    theme = Theme(
        name="rempart", primary=BRAND, secondary="#38bdf8", accent="#f472b6", warning="#f7c948", error="#ff4d6d",
        success="#22c55e", foreground="#e2e8f0", background="#0b0d14", surface="#11141f", panel="#171b2a", dark=True,
        variables={"footer-key-foreground": BRAND, "block-cursor-background": "#2a2350", "block-cursor-foreground": "#ffffff",
                   "block-cursor-text-style": "bold"},
    )

    class ReasonScreen(ModalScreen[str | None]):
        BINDINGS = [Binding("escape", "cancel", "Cancel")]

        def __init__(self, f: Finding) -> None:
            super().__init__()
            self.finding = f

        def compose(self) -> ComposeResult:
            with Vertical(id="dialog"):
                yield Static(Text("Teach Rempart why this is not a problem", style="bold #f8fafc"), classes="dialog-title")
                yield Static(Text.assemble(sev_pill(self.finding.severity or Severity.INFO), "  ",
                                           (f"{self.finding.rule.id} · {self.finding.path}:{self.finding.line}", "#94a3b8")))
                yield Static(Text.assemble(("sanitizer:", "bold #a78bfa"), ("NAME[=categories]", "#cbd5e1"),
                                           ("    a function of yours that makes the value safe\n", "#64748b"),
                                           ("placeholder:", "bold #a78bfa"), ("VALUE", "#cbd5e1"),
                                           ("              a value that is not a real secret", "#64748b")), classes="dialog-help")
                yield Input(value=suggested_reason(self.finding), placeholder="sanitizer:clean_html", id="reason")
                yield Static(Text("Enter: learn it for every finding of this class   Esc: cancel", style="#64748b"))

        def on_mount(self) -> None:
            inp = self.query_one(Input)
            inp.focus()
            inp.cursor_position = len(inp.value)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self.dismiss(event.value.strip() or None)

        def action_cancel(self) -> None:
            self.dismiss(None)

    class HelpScreen(ModalScreen[None]):
        BINDINGS = [Binding("escape,question_mark,q", "close", "Close")]
        KEYS = [
            ("Everywhere", [("1 … 5", "switch view"), ("ctrl+p", "command palette: every action, by name"), ("r", "rescan"),
                            ("o", "offline on/off (no OSV · KEV · EPSS lookups)"), ("e", "write rempart-report.html"),
                            ("?", "this help"), ("q", "quit")]),
            ("Findings", [("↑ ↓  PgUp PgDn", "move"), ("tab", "domain list ↔ table"), ("/", "search rule, path or message"),
                          ("s", "minimum severity"), ("t  f  a", "true positive · false positive · accept the risk"),
                          ("b", "false positive, and why: the whole class goes"),
                          ("x", "open in your editor at the line"), ("y", "copy path:line")]),
            ("Overview", [("enter", "open the selected action")]),
        ]

        def compose(self) -> ComposeResult:
            t = Text()
            for section, keys in self.KEYS:
                t.append(f"{section}\n", style=f"bold {BRAND}")
                for k, what in keys:
                    t.append(f"  {k:<16}", style="bold #f8fafc")
                    t.append(f"{what}\n", style="#94a3b8")
                t.append("\n")
            with Vertical(id="help"):
                yield Static(Text("◆ rempart · keys", style=f"bold {BRAND}"), classes="dialog-title")
                yield Static(t)
                yield Static(Text("Esc to close", style="#64748b"))

        def action_close(self) -> None:
            self.dismiss(None)

    class RempartCommands(Provider):
        """Every action, searchable by name in the command palette (ctrl+p)."""

        async def search(self, query: str) -> Hits:
            app: Any = self.app
            matcher = self.matcher(query)
            commands = [
                ("Rescan the project", app.action_rescan, "run every scanner again"),
                ("Toggle offline mode", app.action_offline, "skip or use OSV / KEV / EPSS"),
                ("Export the HTML report", app.action_export, "rempart-report.html in the project"),
                ("Go to Overview", lambda: app.action_view("overview"), ""),
                ("Go to Findings", lambda: app.action_view("findings"), ""),
                ("Go to Attack paths", lambda: app.action_view("paths"), ""),
                ("Go to Dependencies", lambda: app.action_view("deps"), ""),
                ("Go to Learning", lambda: app.action_view("learning"), ""),
                ("Show only critical and high", lambda: app.set_min_severity(Severity.HIGH), ""),
                ("Show every severity", lambda: app.set_min_severity(Severity.INFO), ""),
                ("Accept the agent's proposed sanitisers", app.action_accept_proposals, "rempart learn --accept-proposals"),
                ("Keyboard help", app.action_help, ""),
            ]
            for name, callback, help_text in commands:
                match = matcher.match(name)
                if match > 0:
                    yield Hit(match, matcher.highlight(name), callback, help=help_text)

    class RempartApp(App[None]):
        TITLE = "rempart"
        COMMANDS = App.COMMANDS | {RempartCommands}
        CSS = f"""
        Screen {{ background: $background; }}
        #brand {{ height: 1; background: #0f1220; padding: 0 1; }}
        #scanbar {{ height: 1; background: #0f1220; padding: 0 1; display: none; }}
        #scanbar.active {{ display: block; }}
        #progress {{ width: 44; }}
        #progress Bar > .bar--bar {{ color: {BRAND}; background: #1e2233; }}
        #progress Bar > .bar--complete {{ color: #22c55e; }}
        #scanlabel {{ width: 1fr; color: #94a3b8; padding-left: 2; }}
        TabbedContent {{ height: 1fr; }}
        Tabs {{ background: #0f1220; }}
        Tab {{ color: #64748b; }}
        Tab.-active {{ color: #f8fafc; text-style: bold; }}
        Tab:hover {{ color: #cbd5e1; }}
        Underline > .underline--bar {{ color: {BRAND}; background: #1e2233; }}
        .card {{ border: round #2a3047; border-title-color: #94a3b8; border-title-style: bold; background: $surface; padding: 0 1; }}
        .card:focus-within {{ border: round {BRAND}; border-title-color: #c4b5fd; }}
        #overview-grid {{ grid-size: 3 2; grid-columns: 1fr 1fr 1fr; grid-rows: 14 1fr; grid-gutter: 0 1; padding: 0 1; }}
        #score-row {{ height: 5; }}
        #score-digits {{ width: auto; color: #f8fafc; text-style: bold; }}
        #grade-digits {{ width: auto; margin-left: 3; text-style: bold; }}
        #grade {{ width: 1fr; height: 5; padding-left: 2; }}
        #trend {{ height: 2; margin-top: 1; }}
        #trend > .sparkline--max-color {{ color: #22c55e; }}
        #trend > .sparkline--min-color {{ color: #ff4d6d; }}
        #score-foot {{ height: auto; }}
        #actions-card {{ column-span: 2; }}
        #actions, #chain-list, #domains {{ background: $surface; border: none; height: 1fr; scrollbar-size-vertical: 1; }}
        #actions > .option-list--option-highlighted, #chain-list > .option-list--option-highlighted,
        #domains > .option-list--option-highlighted {{ background: #2a2350; }}
        #findings-side {{ width: 30; }}
        #severity-filter {{ height: auto; padding-bottom: 1; }}
        #findings-main {{ width: 1fr; }}
        #search {{ display: none; border: tall {BRAND}; background: $surface; }}
        #search.visible {{ display: block; }}
        #findings {{ height: 1fr; background: $surface; border: round #2a3047; border-title-color: #94a3b8; }}
        #findings:focus {{ border: round {BRAND}; }}
        #detail-card {{ height: 55%; }}
        #detail-card, #chain-card, #deps-detail {{ scrollbar-gutter: stable; scrollbar-size-vertical: 1; }}
        #learning-top > .card {{ width: 1fr; height: 100%; }}
        #chain-side {{ width: 48; }}
        #deps-table, #rules-table {{ height: 1fr; background: $surface; border: round #2a3047; border-title-color: #94a3b8; }}
        #deps-table:focus, #rules-table:focus {{ border: round {BRAND}; }}
        #deps-detail {{ height: 40%; }}
        #learning-top {{ height: 10; }}
        DataTable > .datatable--header {{ background: #171b2a; color: #94a3b8; text-style: bold; }}
        DataTable > .datatable--cursor {{ background: #2a2350; }}
        DataTable > .datatable--hover {{ background: #1a1d30; }}
        #status {{ height: 1; background: #0f1220; color: #94a3b8; padding: 0 1; }}
        ReasonScreen, HelpScreen {{ align: center middle; background: #000000 60%; }}
        #dialog, #help {{ width: 100; height: auto; padding: 1 2; border: round {BRAND}; background: $surface; }}
        .dialog-title {{ margin-bottom: 1; }}
        .dialog-help {{ margin: 1 0; }}
        #reason {{ border: tall {BRAND}; }}
        """
        BINDINGS = [
            Binding("1", "view('overview')", "Overview", show=False),
            Binding("2", "view('findings')", "Findings", show=False),
            Binding("3", "view('paths')", "Paths", show=False),
            Binding("4", "view('deps')", "Deps", show=False),
            Binding("5", "view('learning')", "Learning", show=False),
            Binding("t", "triage('tp')", "TP"),
            Binding("f", "triage('fp')", "FP"),
            Binding("a", "triage('accepted')", "Accept"),
            Binding("b", "because", "FP because…"),
            Binding("x", "open_editor", "Open"),
            Binding("y", "copy", "Copy", show=False),
            Binding("slash", "search", "Search"),
            Binding("s", "severity", "Severity"),
            Binding("r", "rescan", "Rescan"),
            Binding("o", "offline", "Offline", show=False),
            Binding("e", "export", "Report", show=False),
            Binding("question_mark", "help", "Help"),
            Binding("escape", "clear", "Clear", show=False),
            Binding("q", "quit", "Quit"),
        ]
        FINDING_ACTIONS = {"triage", "because", "open_editor", "copy", "search", "severity", "clear"}

        def __init__(self) -> None:
            super().__init__()
            self.session = Session(root, offline=offline, prod_only=prod_only)
            self.domain = ""
            self.min_severity = Severity.LOW
            self.query_text = ""
            self.shown: list[Finding] = []
            self.verdicts: dict[str, str] = {}
            self.actions: list[Action] = []
            self.chains: list[Finding] = []
            self.plan: list[dict[str, Any]] = []

        # ======================================================== layout
        def compose(self) -> ComposeResult:
            yield Static(id="brand")
            with Horizontal(id="scanbar"):
                yield ProgressBar(total=100, show_eta=False, show_percentage=True, id="progress")
                yield Static("", id="scanlabel")
            with TabbedContent(initial="overview", id="views"):
                with TabPane("1 Overview", id="overview"):
                    with Grid(id="overview-grid"):
                        with Vertical(id="score-card", classes="card"):
                            with Horizontal(id="score-row"):
                                yield Digits("--", id="score-digits")
                                yield Digits("", id="grade-digits")
                                yield Static("", id="grade")
                            yield Sparkline([], id="trend", summary_function=max)
                            yield Static("", id="score-foot")
                        yield Static("", id="severity-card", classes="card")
                        yield Static("", id="domains-card", classes="card")
                        with Vertical(id="actions-card", classes="card"):
                            yield OptionList(id="actions")
                        yield Static("", id="paths-card", classes="card")
                with TabPane("2 Findings", id="findings-pane"):
                    with Horizontal():
                        with Vertical(id="findings-side", classes="card"):
                            yield Static("", id="severity-filter")
                            yield OptionList(id="domains")
                        with Vertical(id="findings-main"):
                            yield Input(placeholder="search rule, path or message · Enter to keep · Esc to clear", id="search")
                            yield DataTable(id="findings", cursor_type="row")
                            with VerticalScroll(id="detail-card", classes="card"):
                                yield Static("", id="detail")
                with TabPane("3 Attack paths", id="paths"):
                    with Horizontal():
                        with Vertical(id="chain-side", classes="card"):
                            yield OptionList(id="chain-list")
                        with VerticalScroll(id="chain-card", classes="card"):
                            yield Static("", id="chain-detail")
                with TabPane("4 Dependencies", id="deps"):
                    with Vertical():
                        deps: DataTable[Any] = DataTable(id="deps-table", cursor_type="row")
                        for name, w in (("", 6), ("package", None), ("installed", 12), ("upgrade to", 12), ("fixes", 7),
                                        ("used", 6), ("scope", 6), ("", 7), ("lockfile", None)):
                            deps.add_column(name, width=w)
                        yield deps
                        with VerticalScroll(id="deps-detail", classes="card"):
                            yield Static("", id="deps-text")
                with TabPane("5 Learning", id="learning"):
                    with Vertical():
                        with Horizontal(id="learning-top"):
                            yield Static("", id="replay-card", classes="card")
                            yield Static("", id="knowledge-card", classes="card")
                        rules: DataTable[Any] = DataTable(id="rules-table", cursor_type="row")
                        for name in ("rule", "TP", "FP", "accepted", "prior", "learned", "evidence"):
                            rules.add_column(name)
                        yield rules
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            self.register_theme(theme)
            self.theme = "rempart"
            for cid, title in (("score-card", "posture"), ("severity-card", "severity"), ("domains-card", "domains"),
                               ("actions-card", "fix first · enter to open"), ("paths-card", "attack paths"),
                               ("findings-side", "filter"), ("detail-card", "finding"), ("chain-side", "chains"),
                               ("chain-card", "path"), ("deps-detail", "advisories"), ("replay-card", "does learning help?"),
                               ("knowledge-card", "project knowledge")):
                self.query_one(f"#{cid}").border_title = title
            self._brand()
            self.action_rescan()

        # ======================================================== chrome
        def _brand(self, scanning: str = "") -> None:
            t = Text()
            t.append(" ◆ rempart ", style=f"bold #ffffff on {BRAND}")
            t.append(f"  {root}", style="#cbd5e1")
            res = self.session.result
            if res is not None:
                value, grade = score(res.findings)
                t.append("   ")
                t.append(f" {grade} ", style=f"bold #0b0d14 on {GRADE_COLOR[grade]}")
                t.append(f" {value}/100", style="bold #f8fafc")
                t.append(f"   {len(res.findings)} findings · {res.files_scanned} files · {res.duration_s}s", style="#64748b")
            t.append("   " + ("offline" if self.session.offline else "online · OSV KEV EPSS"), style="#64748b")
            if scanning:
                t.append(f"   {scanning}", style=f"bold {BRAND}")
            self.query_one("#brand", Static).update(t)

        def say(self, message: str, style: str = "#94a3b8") -> None:
            self.query_one("#status", Static).update(Text(message, style=style))

        def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
            if len(self.screen_stack) > 1:  # a dialog is open: nothing may act on what is behind it
                return action in ("quit", "help")
            if action in self.FINDING_ACTIONS:
                return self.query_one("#views", TabbedContent).active == "findings-pane"
            return True

        def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
            self.refresh_bindings()
            target = {"overview": "#actions", "findings-pane": "#findings", "paths": "#chain-list", "deps": "#deps-table",
                      "learning": "#rules-table"}.get(str(event.pane.id))
            if target:
                self.query_one(target).focus()
            if event.pane.id == "findings-pane" and self.session.result is not None:
                # the table had no width while hidden: fit its columns now that it is laid out
                self.call_after_refresh(lambda: self.refresh_table(keep=self.current()))

        def action_view(self, view: str) -> None:
            self.query_one("#views", TabbedContent).active = "findings-pane" if view == "findings" else view

        def action_help(self) -> None:
            if len(self.screen_stack) == 1:
                self.push_screen(HelpScreen())

        # ======================================================== scanning
        def action_rescan(self) -> None:
            self.query_one("#scanbar").add_class("active")
            self.query_one("#progress", ProgressBar).update(progress=0)
            self._brand("scanning…")
            self.say("scanning" + (" offline" if self.session.offline else ", looking up dependency advisories") + "…")
            self._scan()

        @work(thread=True, exclusive=True, group="scan")
        def _scan(self) -> None:
            def progress(step: str, done: int, total: int) -> None:
                self.call_from_thread(self._progress, step, done, total)

            try:
                self.session.scan(progress)
            except Exception as exc:  # shown, never fatal: the interface stays usable
                self.call_from_thread(self._scan_failed, exc)
                return
            self.call_from_thread(self._scanned)

        def _progress(self, step: str, done: int, total: int) -> None:
            self.query_one("#progress", ProgressBar).update(progress=round(100 * done / max(1, total + 1)))
            self.query_one("#scanlabel", Static).update(Text.assemble(("scanning ", "#64748b"), (step, "bold #f8fafc"),
                                                                      (f"  {done + 1}/{total + 1}", "#64748b")))

        def _scan_failed(self, exc: Exception) -> None:
            self.query_one("#scanbar").remove_class("active")
            self._brand()
            self.notify(f"scan failed: {exc}", severity="error", timeout=10)

        def _scanned(self) -> None:
            from rempart.scanners.deps import upgrade_plan

            self.query_one("#scanbar").remove_class("active")
            self.verdicts.clear()
            res = self.session.result
            assert res is not None
            self.chains = [f for f in res.findings if f.rule.domain == "attack-path"]
            self.plan = upgrade_plan(res.findings)
            self.actions = fix_first(res.findings)
            self._brand()
            self._overview()
            self._fill_domains()
            self.refresh_table()
            self._fill_chains()
            self._fill_deps()
            self._fill_learning()
            errors = f"   {len(res.errors)} scanner error(s)" if res.errors else ""
            self.say(f"1-5 views · / search · t f a b triage · x open in editor · ctrl+p every command · ? help{errors}")

        # ======================================================== 1 overview
        def _overview(self) -> None:
            res = self.session.result
            assert res is not None
            value, grade = score(res.findings)
            self.query_one("#score-digits", Digits).update(str(value))
            grade_digits = self.query_one("#grade-digits", Digits)
            grade_digits.update(grade)
            grade_digits.styles.color = GRADE_COLOR[grade]
            counts = summary_counts(res)
            urgent = counts[Severity.CRITICAL] + counts[Severity.HIGH]
            self.query_one("#grade", Static).update(Text.assemble(
                ("score / 100\n", "#64748b"), ("grade\n\n", "#64748b"),
                (f"{urgent} critical or high", "bold #ff4d6d" if urgent else "bold #22c55e"), ("\nto handle", "#64748b")))
            scores = [float(s["score"] or 0) for s in self.session.history]
            self.query_one("#trend", Sparkline).data = scores if len(scores) > 1 else [float(value), float(value)]
            d = self.session.diff or {}
            foot = Text()
            if len(scores) > 1:
                delta = scores[-1] - scores[-2]
                foot.append(f"{'▲' if delta > 0 else '▼' if delta < 0 else '■'} {delta:+.0f}  ",
                            style="bold #22c55e" if delta > 0 else "bold #ff4d6d" if delta < 0 else "#64748b")
            foot.append(f"+{len(d.get('new', []))} new", style="#ff8c42" if d.get("new") else "#64748b")
            foot.append("  ")
            foot.append(f"−{len(d.get('fixed', []))} fixed", style="#22c55e" if d.get("fixed") else "#64748b")
            if d.get("gone"):
                foot.append(f"  {len(d['gone'])} learned away", style="#a78bfa")
            foot.append(f"\ntrend over {len(scores)} scan(s)", style="#475569")
            self.query_one("#score-foot", Static).update(foot)

            top = max(counts.values()) or 1
            sev = Text("\n")
            for s, n in counts.items():
                sev.append_text(sev_pill(s))
                sev.append(f" {n:>4}  ", style="bold #f8fafc" if n else "#475569")
                sev.append_text(bar(n, top, 24, SEV_COLOR[s]))
                sev.append("\n\n" if s != Severity.INFO else "")
            self.query_one("#severity-card", Static).update(sev)

            worst = domain_worst(res.findings)
            doms = domain_counts(res.findings)
            top_d = max((n for _, n in doms), default=1)
            dt = Text("\n")
            for name, n in doms[:10]:
                dt.append(f"{name:<13}", style="#cbd5e1")
                dt.append(f"{n:>4} ", style="bold #f8fafc")
                dt.append_text(bar(n, top_d, 18, SEV_COLOR[worst.get(name, Severity.INFO)]))
                dt.append("\n")
            if not doms:
                dt.append("nothing found", style="#22c55e")
            self.query_one("#domains-card", Static).update(dt)

            ol = self.query_one("#actions", OptionList)
            ol.clear_options()
            for a in self.actions:
                kind = {"chain": "PATH", "package": "DEP ", "finding": "FIX "}[a.target.split(":")[0]]
                ol.add_option(Option(Text.assemble(sev_pill(a.severity), " ", chip(kind, "#1e293b", "#a5b4fc"), "  ",
                                                   (a.title, "bold #f8fafc"), "\n              ", (a.detail, "#94a3b8"), "\n"), id=a.target))
            if not self.actions:
                ol.add_option(Option(Text("Nothing urgent: no proven path, no exploited dependency, no proven high finding.", style="#22c55e")))
            ol.highlighted = 0  # Enter acts at once on the most urgent action

            pt = Text("\n")
            if not self.chains:
                pt.append("No attack path: the pieces of a chain\nare not all present.", style="#22c55e")
            for c in self.chains[:7]:
                assert c.severity is not None
                pt.append_text(sev_pill(c.severity))
                pt.append(f" {c.rule.title}\n", style="#f8fafc")
                pt.append(f"       {PROOF_LABEL.get(c.verification, c.verification)}\n", style="#67e8f9" if c.verification == "linked" else "#64748b")
            self.query_one("#paths-card", Static).update(pt)

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            if event.option_list.id == "actions" and event.option.id:
                self.go_to(str(event.option.id))

        def go_to(self, target: str) -> None:
            kind, _, key = target.partition(":")
            if kind == "chain":
                self.action_view("paths")
                self.query_one("#chain-list", OptionList).highlighted = next((i for i, c in enumerate(self.chains) if c.fingerprint == key), 0)
            elif kind == "package":
                self.action_view("deps")
                self.query_one("#deps-table", DataTable).move_cursor(
                    row=next((i for i, p in enumerate(self.plan) if f"{p['package']}@{p['current']}" == key), 0))
            else:
                self.domain, self.query_text, self.min_severity = "", "", Severity.INFO
                self.action_view("findings")
                self.refresh_table()
                self.query_one("#findings", DataTable).move_cursor(row=next((i for i, f in enumerate(self.shown) if f.fingerprint == key), 0))

        # ======================================================== 2 findings
        def _fill_domains(self) -> None:
            res = self.session.result
            findings = res.findings if res else []
            ol = self.query_one("#domains", OptionList)
            ol.clear_options()
            ol.add_option(Option(Text.assemble(("all", "bold #f8fafc"), (f"  {len(findings)}", "#64748b")), id="all"))
            worst = domain_worst(findings)
            for domain, n in domain_counts(findings):
                ol.add_option(Option(Text.assemble(("● ", SEV_COLOR[worst.get(domain, Severity.INFO)]), (domain, "#e2e8f0"), (f"  {n}", "#64748b")), id=domain))
            self._severity_filter()

        def _severity_filter(self) -> None:
            t = Text.assemble(("minimum severity ", "#64748b"), ("s", f"bold {BRAND}"), "\n")
            for s in sorted(Severity, reverse=True):
                on = s >= self.min_severity
                t.append(f"{SEV_SHORT[s]:^5}", style=f"bold #0b0d14 on {SEV_COLOR[s]}" if on else "#475569 on #1e2233")
            self.query_one("#severity-filter", Static).update(t)

        def _column_widths(self) -> tuple[int, int]:
            """(finding, where) widths that fill the table without a horizontal scrollbar."""
            fixed = 6 + 4 + 12 + 9 + 6 * 2 + 4  # sev, risk, proof, verdict, cell padding, border and scrollbar
            room = max(50, self.query_one("#findings", DataTable).size.width - fixed)
            where = max(18, min(48, room * 35 // 100))
            return room - where, where

        def on_resize(self) -> None:
            if self.session.result is not None:
                self.refresh_table(keep=self.current())

        def refresh_table(self, keep: Finding | None = None) -> None:
            res = self.session.result
            table = self.query_one("#findings", DataTable)
            table.clear(columns=True)
            w_title, w_where = self._column_widths()
            for label, key, width in (("", "sev", 6), ("risk", "risk", 4), ("finding", "title", w_title),
                                      ("where", "where", w_where), ("proof", "proof", 12), ("", "verdict", 9)):
                table.add_column(label, key=key, width=width)
            self.shown = visible(res.findings if res else [], self.domain, self.min_severity, self.query_text)
            for i, f in enumerate(self.shown):  # a fingerprint can repeat at several lines: rows are keyed by position
                assert f.severity is not None
                verdict = self.verdicts.get(f.fingerprint, "")
                table.add_row(
                    sev_pill(f.severity),
                    Text(f"{f.risk:.0f}", justify="right", style="bold #f8fafc" if f.risk >= 70 else "#94a3b8"),
                    _fit(Text.assemble((f.rule.title, "#f8fafc" if not verdict else "#64748b"), (f"  {f.rule.id}", "#475569")), w_title),
                    _fit(Text(f"{f.path}:{f.line}" if f.line else f.path, style="#94a3b8"), w_where, left=True),
                    Text(proof_of(f)[0], style="bold #67e8f9" if proof_of(f)[1] else "#64748b"),
                    chip(VERDICT_LABEL[verdict], "#16a34a" if verdict == "tp" else "#7c3aed", "#ffffff") if verdict else Text(""),
                    key=str(i),
                )
            if keep is not None and keep in self.shown:
                table.move_cursor(row=self.shown.index(keep))
            self._show_detail()
            self._severity_filter()
            table.border_title = (f"{len(self.shown)} findings · {self.domain or 'all domains'} · ≥ {self.min_severity.name.lower()}"
                                  + (f" · “{self.query_text}”" if self.query_text else ""))

        def current(self) -> Finding | None:
            table = self.query_one("#findings", DataTable)
            if not self.shown or table.cursor_row is None or not 0 <= table.cursor_row < len(self.shown):
                return None
            return self.shown[table.cursor_row]

        def _show_detail(self) -> None:
            f = self.current()
            detail = self.query_one("#detail", Static)
            if f is None:
                detail.update(Text("No finding matches these filters." if self.session.result else "", style="#64748b"))
                return
            detail.update(Group(*describe(root, f, self.verdicts.get(f.fingerprint))))
            self.query_one("#detail-card", VerticalScroll).scroll_home(animate=False)

        def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
            if event.data_table.id == "findings":
                self._show_detail()
            elif event.data_table.id == "deps-table":
                self._show_package()

        def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
            if event.option_list.id == "domains":
                self.domain = "" if event.option.id == "all" else str(event.option.id)
                self.refresh_table()
            elif event.option_list.id == "chain-list":
                self._show_chain()

        def action_triage(self, verdict: str) -> None:
            f = self.current()
            if f is None:
                return
            try:
                said = self.session.triage(f, verdict)
            except (KeyError, ValueError) as exc:
                self.notify(str(exc).strip("'"), severity="error")
                return
            self.verdicts[f.fingerprint] = verdict
            self.refresh_table(keep=f)
            table = self.query_one("#findings", DataTable)
            if table.cursor_row is not None and table.cursor_row + 1 < len(self.shown):
                table.move_cursor(row=table.cursor_row + 1)  # on to the next one
            self.say(said, "#a78bfa")

        def action_because(self) -> None:
            f = self.current()
            if f is None:
                return

            def done(reason: str | None) -> None:
                if not reason:
                    return
                try:
                    said = self.session.triage(f, "fp", because=reason)
                except (KeyError, ValueError) as exc:
                    self.notify(str(exc).strip("'"), severity="error", timeout=8)
                    return
                self.notify(said, title="learned", timeout=8)
                self.action_rescan()

            self.push_screen(ReasonScreen(f), done)

        def action_open_editor(self) -> None:
            f = self.current()
            if f is None or f.line <= 0 or "://" in f.path:
                return
            path = str(root / f.path)
            editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
            if editor:
                with self.suspend():
                    subprocess.run([*editor.split(), f"+{f.line}", path], check=False)
            elif shutil.which("code"):
                subprocess.Popen(["code", "-g", f"{path}:{f.line}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.say(f"opened {f.path}:{f.line} in VS Code")
            else:
                self.notify("set $EDITOR (or install the `code` command) to open findings", severity="warning")

        def action_copy(self) -> None:
            f = self.current()
            if f is not None:
                self.copy_to_clipboard(f"{f.path}:{f.line}")
                self.say(f"copied {f.path}:{f.line}")

        def action_search(self) -> None:
            box = self.query_one("#search", Input)
            box.add_class("visible")
            box.focus()

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id == "search":
                self.query_text = event.value
                self.refresh_table()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            if event.input.id == "search":
                self.query_one("#findings", DataTable).focus()

        def action_clear(self) -> None:
            box = self.query_one("#search", Input)
            box.value = ""
            box.remove_class("visible")
            self.query_text = ""
            self.refresh_table()
            self.query_one("#findings", DataTable).focus()

        def set_min_severity(self, sev: Severity) -> None:
            self.min_severity = sev
            self.action_view("findings")
            self.refresh_table()

        def action_severity(self) -> None:
            order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            self.min_severity = order[(order.index(self.min_severity) + 1) % len(order)]
            self.refresh_table()

        # ======================================================== 3 attack paths
        def _fill_chains(self) -> None:
            ol = self.query_one("#chain-list", OptionList)
            ol.clear_options()
            for c in self.chains:
                assert c.severity is not None
                ol.add_option(Option(Text.assemble(sev_pill(c.severity), " ", (c.rule.title, "bold #f8fafc"), "\n       ",
                                                   (PROOF_LABEL.get(c.verification, c.verification),
                                                    "#67e8f9" if c.verification == "linked" else "#64748b"), "\n"), id=c.fingerprint))
            if self.chains:
                ol.highlighted = 0
            self._show_chain()

        def _show_chain(self) -> None:
            ol = self.query_one("#chain-list", OptionList)
            box = self.query_one("#chain-detail", Static)
            if not self.chains or ol.highlighted is None:
                box.update(Text("No attack path. Rempart reports a path only when every stage of it is present.", style="#22c55e"))
                return
            box.update(Group(*describe_chain(self.chains[ol.highlighted], self.session.by_fingerprint())))

        # ======================================================== 4 dependencies
        def _fill_deps(self) -> None:
            table = self.query_one("#deps-table", DataTable)
            table.clear()
            for p in self.plan:
                table.add_row(sev_pill(Severity[p["severity"]]), Text(p["package"], style="bold #f8fafc"), Text(p["current"], style="#ff8c42"),
                              Text(p["target"] or "no fix", style="bold #22c55e" if p["target"] else "#ff4d6d"),
                              f"{p['fixes']}/{p['advisories']}", Text("yes", style="bold #67e8f9") if p["reachable"] else "",
                              Text(p["scope"], style="#64748b" if p["scope"] == "dev" else "#f8fafc"),
                              chip("KEV", "#b91c1c", "#ffffff") if p["kev"] else (Text("major", style="#f7c948") if p["major_bump"] else ""),
                              Text(", ".join(p["paths"]), style="#64748b"))
            table.border_title = f"upgrade plan · {len(self.plan)} package(s) · smallest version that fixes every advisory" if self.plan else "no vulnerable dependency"
            self._show_package()

        def _show_package(self) -> None:
            box = self.query_one("#deps-text", Static)
            table = self.query_one("#deps-table", DataTable)
            if not self.plan or table.cursor_row is None or table.cursor_row >= len(self.plan):
                box.update(Text("No vulnerable dependency." + (" The scan is offline: press o to look advisories up." if self.session.offline else ""),
                                style="#64748b"))
                return
            p = self.plan[table.cursor_row]
            res = self.session.result
            items = [f for f in (res.findings if res else []) if f.extra.get("package") == p["package"] and str(f.extra.get("version")) == p["current"]]
            t = Text.assemble((f"{p['package']} ", "bold #f8fafc"), (p["current"], "#ff8c42"), ("  →  ", "#64748b"),
                              (p["target"] or "no fix yet", "bold #22c55e"), (f"   {p['ecosystem']} · {p['scope']}\n\n", "#64748b"))
            for f in sorted(items, key=lambda f: -f.risk):
                assert f.severity is not None
                t.append_text(sev_pill(f.severity))
                parts = f.message.split(" — ")  # "pkg@ver: ID / CVE — title — fixed in … — reachability"
                t.append(f" {f.extra.get('advisory')}  ", style="bold #a5b4fc")
                t.append(f"{parts[1] if len(parts) > 1 else f.message}\n", style="#cbd5e1")
            box.update(t)

        # ======================================================== 5 learning
        def _fill_learning(self) -> None:
            from rempart.cli import _project_id
            from rempart.history import History
            from rempart.knowledge import FILE, Knowledge
            from rempart.registry import load_all_rules

            hist = History()
            try:
                stats, sources = hist.rule_stats(), hist.source_counts()
                replay = hist.replay(_project_id(root))
            finally:
                hist.close()
            rt = Text()
            if not replay["labelled"]:
                rt.append("Not enough history yet.\n\n", style="bold #cbd5e1")
                rt.append("Triage findings (t f a b). The replay then scores each one\nas it stood the day it appeared, with and without learning.",
                          style="#64748b")
            else:
                w, lr = replay["without_learning"], replay["with_learning"]
                rt.append(f"{replay['labelled']} triaged · {replay['real']} real · {replay['false_alarms']} false alarms\n\n", style="#94a3b8")
                rt.append(f"{'':<24}{'without':>9}   {'with':<8}\n", style="#475569")
                for label, a, b, higher_is_better in (("ranking AUC", w["auc"], lr["auc"], True), ("Brier score", w["brier"], lr["brier"], False),
                                                      ("false alarms in top 10", w["top10"]["false_positives"], lr["top10"]["false_positives"], False)):
                    good = a is not None and b is not None and ((b > a) if higher_is_better else (b < a))
                    rt.append(f"{label:<24}", style="#cbd5e1")
                    rt.append(f"{'–' if a is None else a:>9}   ", style="#64748b")
                    rt.append(f"{'–' if b is None else b}\n", style="bold #22c55e" if good else "bold #f8fafc")
            self.query_one("#replay-card", Static).update(rt)
            k = Knowledge.load(root)
            kt = Text()
            for n, c in sorted(k.sanitizers.items()):
                kt.append("sanitizer    ", style="#a78bfa")
                kt.append(f"{n}()", style="bold #f8fafc")
                kt.append(f"  {', '.join(sorted(c))}\n", style="#64748b")
            for v in sorted(k.placeholders):
                kt.append("placeholder  ", style="#a78bfa")
                kt.append(f"{v}\n", style="bold #f8fafc")
            for n in sorted(k.proposed.get("sanitizers", {})):
                kt.append("proposed     ", style="#f7c948")
                kt.append(f"{n}()  ", style="#f8fafc")
                kt.append("ctrl+p → accept\n", style="#64748b")
            if not kt.plain:
                kt.append("Empty.\n\n", style="bold #cbd5e1")
                kt.append(f"Press b on a false positive to teach its reason.\nSaved in {FILE}, commit it for the whole team.", style="#64748b")
            self.query_one("#knowledge-card", Static).update(kt)
            rules = load_all_rules()
            table = self.query_one("#rules-table", DataTable)
            table.clear()
            for rid, s in sorted(stats.items(), key=lambda kv: kv[1].precision()):
                prior = rules[rid].confidence if rid in rules else 0.8
                learned = s.precision(prior)
                table.add_row(Text(rid, style="bold #f8fafc"), f"{s.tp:.3g}", f"{s.fp:.3g}", f"{s.accepted:.3g}", f"{prior:.0%}",
                              Text(f"{learned:.0%}", style="bold #22c55e" if learned >= prior else "bold #ff8c42"),
                              Text(", ".join(f"{n} {src}" for src, n in sorted(sources.get(rid, {}).items())), style="#94a3b8"))
            if not stats:
                table.add_row(Text("no evidence yet: triage findings with t f a b, fixes and rempart:ignore count too", style="#64748b"),
                              "", "", "", "", "", "")
            table.border_title = "precision per rule, learned from your evidence"

        def action_accept_proposals(self) -> None:
            from rempart.knowledge import Knowledge

            k = Knowledge.load(root)
            accepted = k.accept_proposals()
            if not accepted:
                self.notify("no proposal to accept")
                return
            k.save(root)
            self.notify("\n".join(accepted), title="accepted", timeout=8)
            self.action_rescan()

        # ======================================================== other
        def action_offline(self) -> None:
            self.session.offline = not self.session.offline
            self.notify("offline: no OSV / KEV / EPSS lookups" if self.session.offline else "online: dependency advisories looked up")
            self.action_rescan()

        def action_export(self) -> None:
            from rempart.reporters import RENDERERS

            if not self.session.result:
                return
            out = root / "rempart-report.html"
            out.write_text(RENDERERS["html"](self.session.result), encoding="utf-8")
            self.notify(str(out), title="report written", timeout=8)

    return RempartApp()


def run(root: Path, offline: bool = False, prod_only: bool = False) -> int:
    build_app(root, offline=offline, prod_only=prod_only).run()
    return 0
