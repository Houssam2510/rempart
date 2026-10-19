"""File discovery, scanner orchestration, suppressions and scoring."""

from __future__ import annotations

import fnmatch
import math
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

from rempart.config import Config
from rempart.models import DOMAINS, Finding, Rule, Severity

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".svelte-kit", ".next", ".nuxt", ".output", "target", "vendor", ".terraform",
    "coverage", ".rempart", ".mypy_cache", ".pytest_cache", ".tox", ".vercel",
    # build caches and generated bundles: third-party code, not yours
    ".vite", ".turbo", ".cache", ".parcel-cache", ".angular", ".docusaurus", ".expo", ".astro",
    "storybook-static", ".wrangler", ".netlify", ".serverless", "bower_components", "jspm_packages",
}
SKIP_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".pdf", ".zip", ".gz", ".tgz", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3",
    ".lockb", ".wasm", ".so", ".dll", ".exe", ".class", ".jar", ".pyc",
)
MAX_BYTES = 2_000_000

# Test, fixture and mock files: weaknesses there are not reachable in production, so
# code-level domains skip them by default (secrets still apply: a real key in a test leaks too).
TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|e2e|fixtures?|__fixtures__|__mocks__|mocks?|testdata|test-utils)/"
    r"|\.(?:test|spec|e2e)\.[cm]?[jt]sx?$|(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$|(?:^|/)conftest\.py$|\.stories\.[jt]sx?$"
)
TEST_SKIPPED_DOMAINS = {"code", "quality", "performance", "ai"}
TEST_SKIPPED_RULE_PREFIXES = ("DATA-SENSITIVE-LOGGED", "PERF-", "CODE-", "SEC-GENERIC", "SEC-JWT")


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))


_IGNORE = re.compile(r"rempart:ignore(?:\[([A-Z0-9_,\- ]+)\])?")


class Scanner(Protocol):
    name: str

    def scan(self, ctx: "ScanContext") -> Iterable[Finding]: ...


@dataclass
class ScanContext:
    root: Path
    files: list[str]
    tracked: set[str] | None
    config: Config
    offline: bool = False
    verify_secrets: bool = False
    _cache: dict[str, str | None] = field(default_factory=dict)

    def text(self, rel: str) -> str | None:
        if rel not in self._cache:
            self._cache[rel] = _read_text(self.root / rel)
        return self._cache[rel]

    def lines(self, rel: str) -> list[str]:
        t = self.text(rel)
        return t.splitlines() if t is not None else []

    def is_committed(self, rel: str) -> bool:
        """True when the file is (or will be) part of the repository history."""
        return True if self.tracked is None else rel in self.tracked

    def by_suffix(self, *suffixes: str) -> Iterator[str]:
        for f in self.files:
            if f.lower().endswith(suffixes):
                yield f

    def by_name(self, *names: str) -> Iterator[str]:
        for f in self.files:
            if os.path.basename(f) in names:
                yield f


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def discover(root: Path, config: Config) -> tuple[list[str], set[str] | None]:
    """List scannable files. In a git repo, honour .gitignore: what is ignored
    never reaches the remote, so flagging it would be noise."""
    files: list[str]
    tracked: set[str] | None = None
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
            capture_output=True, check=True, timeout=60,
        ).stdout
        files = [p for p in out.decode("utf-8", "replace").split("\0") if p]
        committed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, check=True, timeout=60,
        ).stdout
        tracked = {p for p in committed.decode("utf-8", "replace").split("\0") if p}
        # untracked but not ignored files are about to be committed: count them as tracked
        tracked |= set(files)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                files.append(os.path.relpath(os.path.join(dirpath, name), root))
    result = []
    for f in files:
        f = f.replace(os.sep, "/")
        parts = f.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]):
            continue
        if f.lower().endswith(SKIP_SUFFIXES):
            continue
        if any(fnmatch.fnmatch(f, pat) for pat in config.exclude):
            continue
        if (root / f).is_file():
            result.append(f)
    return sorted(result), tracked


def _suppressed(ctx: ScanContext, finding: Finding) -> bool:
    if finding.line <= 0:
        return False
    lines = ctx.lines(finding.path)
    for idx in (finding.line - 1, finding.line - 2):
        if 0 <= idx < len(lines):
            m = _IGNORE.search(lines[idx])
            if m and (m.group(1) is None or finding.rule.id in {s.strip() for s in m.group(1).split(",")}):
                return True
    return False


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    files_scanned: int
    duration_s: float
    scanners: list[str]
    suppressed: int = 0
    errors: list[str] = field(default_factory=list)
    context: list[Finding] = field(default_factory=list)
    graph: Any = None  # rempart.graph.ResourceGraph, when the scan read the repository
    files: list[str] = field(default_factory=list)  # every file the scan read (learning: "still there?")
    ignored: list[Finding] = field(default_factory=list)  # silenced by an inline `rempart:ignore` (a learning signal)
    knowledge_digest: str = ""  # what .rempart/knowledge.toml held for this scan

    def add_attack_paths(self) -> None:
        """Correlate the (already triaged) findings into attack chains."""
        from rempart.correlate import correlate

        self.findings = [f for f in self.findings if f.rule.domain != "attack-path"]
        self.findings += correlate(self.findings, self.context, self.graph)
        self.findings.sort(key=lambda f: (-f.risk, f.path, f.line))

    def counts(self) -> dict[str, int]:
        c = {s.name: 0 for s in Severity}
        for f in self.findings:
            assert f.severity is not None
            c[f.severity.name] += 1
        return c

    def by_domain(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {d: [] for d in DOMAINS}
        for f in self.findings:
            out[f.rule.domain].append(f)
        return {d: v for d, v in out.items() if v}


WEIGHTS = {Severity.CRITICAL: 25.0, Severity.HIGH: 10.0, Severity.MEDIUM: 4.0, Severity.LOW: 1.0, Severity.INFO: 0.0}


def score(findings: list[Finding]) -> tuple[int, str]:
    """0-100 posture score. Repeats of one rule have diminishing weight, so a
    single noisy rule cannot sink the grade on its own, while many distinct
    problems do."""
    per_rule: dict[str, list[float]] = {}
    for f in findings:
        assert f.severity is not None and f.confidence is not None
        per_rule.setdefault(f.rule.id, []).append(WEIGHTS[f.severity] * f.confidence)
    penalty = 0.0
    for weights in per_rule.values():
        weights.sort(reverse=True)
        penalty += sum(w / (i + 1) for i, w in enumerate(weights))
    value = int(round(100 * math.exp(-penalty / 120)))
    grade = "A" if value >= 90 else "B" if value >= 75 else "C" if value >= 60 else "D" if value >= 40 else "F"
    return value, grade


def run_scan(
    root: Path,
    scanners: list[Scanner],
    config: Config,
    *,
    offline: bool = False,
    correlate: bool = True,
    verify_secrets: bool = False,
) -> ScanResult:
    from rempart.knowledge import Knowledge, using

    with using(Knowledge.load(root)) as knowledge:
        result = _run_scan(root, scanners, config, offline=offline, verify_secrets=verify_secrets)
        result.knowledge_digest = knowledge.digest()
        if correlate:
            result.add_attack_paths()
    return result


def _run_scan(root: Path, scanners: list[Scanner], config: Config, *, offline: bool, verify_secrets: bool) -> ScanResult:
    start = time.monotonic()
    files, tracked = discover(root, config)
    ctx = ScanContext(root=root, files=files, tracked=tracked, config=config, offline=offline, verify_secrets=verify_secrets)
    findings: list[Finding] = []
    errors: list[str] = []
    suppressed = 0
    ignored: list[Finding] = []
    seen: set[str] = set()
    for scanner in scanners:
        try:
            produced = list(scanner.scan(ctx))
        except Exception as exc:  # one broken scanner must not hide the others' results
            errors.append(f"{scanner.name}: {type(exc).__name__}: {exc}")
            continue
        for f in produced:
            if f.rule.id in config.disable:
                continue
            if not config.include_tests and f.line > 0 and is_test_path(f.path) and (
                    f.rule.domain in TEST_SKIPPED_DOMAINS or f.rule.id.startswith(TEST_SKIPPED_RULE_PREFIXES)):
                suppressed += 1
                continue
            if f.rule.id in config.severity_overrides:
                f.severity = config.severity_overrides[f.rule.id]
            if _suppressed(ctx, f):
                suppressed += 1
                ignored.append(f)
                continue
            key = f"{f.fingerprint}:{f.line}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
    findings.sort(key=lambda f: (-f.risk, f.path, f.line))
    from rempart.correlate import context_signals
    from rempart.graph import build_graph

    result = ScanResult(
        root=str(root),
        findings=findings,
        files_scanned=len(files),
        duration_s=round(time.monotonic() - start, 2),
        scanners=[s.name for s in scanners],
        suppressed=suppressed,
        errors=errors,
        context=context_signals(files, ctx.text),
        graph=build_graph(files, ctx.text),
        files=files,
        ignored=ignored,
    )
    return result


# ---------------------------------------------------------------- helpers for scanners

COMMENT_PREFIXES = ("//", "#", "*", "/*", "<!--", "--", ";")


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def regex_findings(
    ctx: ScanContext,
    rel: str,
    rule: Rule,
    pattern: re.Pattern[str],
    message: str,
    *,
    skip_comments: bool = True,
    guard: re.Pattern[str] | None = None,
) -> Iterator[Finding]:
    """Yield one finding per matching line. `guard`, when given, must also match
    the same line (used to require user input or a sensitive context)."""
    for i, line in enumerate(ctx.lines(rel), start=1):
        if len(line) > 1500:
            continue
        if skip_comments and is_comment(line):
            continue
        if pattern.search(line) and (guard is None or guard.search(line)):
            yield Finding(rule, rel, i, message, snippet=line.strip()[:240])


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
