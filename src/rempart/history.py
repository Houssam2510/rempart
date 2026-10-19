"""Scan history and the learning loop.

Every scan is recorded per project. Evidence about findings comes from four sources:

    human      `rempart triage ID --tp | --fp | --accept`             weight 1
    ai         the verification agent's verdicts                       weight 0.5
    implicit   a finding that disappeared while its file was still     weight 0.5
               scanned with the same rules and options: it was fixed
    inline     a finding silenced with `rempart:ignore` in the code    weight 0.5

The evidence feeds a Beta-Bernoulli precision estimate per rule, refined per rule ×
kind of file (code, scripts, tests, infra…):

    precision = (tp + a) / (tp + fp + a + b)      prior a, b from the rule's confidence

Each piece of evidence is also weighted by age (half-life HALF_LIFE_DAYS) and by
whether it judged the current version of the rule (an older version counts
OLD_VERSION_WEIGHT). The estimate adjusts each new finding's confidence and, for
rules that keep being wrong, lowers its severity. A finding that comes back after
being fixed is a regression and is raised one level.

Only a human verdict closes a finding: fingerprints marked false positive or accepted
are suppressed in later scans of the same project. Nothing leaves the machine: the
database lives in REMPART_HOME (default ~/.local/share/rempart).
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from rempart.engine import ScanResult, score
from rempart.models import Finding, Rule, Severity
from rempart.netcache import home

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    ts REAL NOT NULL,
    score INTEGER, grade TEXT,
    counts TEXT, files INTEGER, duration REAL
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT, path TEXT, line INTEGER, message TEXT
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_fp ON findings(fingerprint);
CREATE TABLE IF NOT EXISTS verdicts (
    project TEXT NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('tp', 'fp', 'accepted')),
    note TEXT, ts REAL NOT NULL, source TEXT NOT NULL DEFAULT 'human',
    PRIMARY KEY (project, fingerprint)
);
"""

# Columns added after 0.3, created on older databases on first open.
_MIGRATIONS = {
    "scans": {"version": "TEXT", "profile": "TEXT"},
    "findings": {"base_severity": "TEXT", "base_confidence": "REAL"},
    "verdicts": {"source": "TEXT NOT NULL DEFAULT 'human'", "path": "TEXT", "rule_version": "INTEGER NOT NULL DEFAULT 1"},
}

# An AI verdict is evidence, not a decision: it counts half in calibration and can
# never close a finding. Implicit and inline signals are weaker still in meaning but
# frequent, so they also count half. Only a human verdict suppresses future findings.
AI_WEIGHT = 0.5
SOURCE_WEIGHT = {"human": 1.0, "ai": AI_WEIGHT, "implicit": 0.5, "inline": 0.5}
# Who may overwrite whom: a human verdict always wins; the agent overrides automatic signals.
SOURCE_RANK = {"human": 3, "ai": 2, "implicit": 1, "inline": 1}
HALF_LIFE_DAYS = 365.0
OLD_VERSION_WEIGHT = 0.25
REGRESSION_NOTE = "regression: fixed in an earlier scan, back now"


@dataclass
class RuleStats:
    rule_id: str
    tp: float
    fp: float
    accepted: float

    def precision(self, prior: float = 0.8, strength: float = 4.0) -> float:
        a, b = prior * strength, (1 - prior) * strength
        return (self.tp + a) / (self.tp + self.fp + a + b)


_CONTEXTS = (
    ("test", re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|e2e|fixtures?|mocks?)/|[._-](?:test|spec)\.\w+$|(?:^|/)test_[^/]+\.py$")),
    ("docs", re.compile(r"(?i)(?:^|/)(?:docs?|examples?|samples?|demo)/|\.(?:md|mdx|rst|txt)$")),
    ("scripts", re.compile(r"(?i)(?:^|/)(?:scripts?|tools?|bin|seeds?|migrations?)/")),
    ("ci", re.compile(r"(?i)(?:^|/)\.(?:github|gitlab|circleci)/|(?:^|/)(?:Jenkinsfile|\.gitlab-ci\.yml|azure-pipelines\.yml)$")),
    ("infra", re.compile(r"(?i)\.(?:tf|tfvars|hcl)$|(?:^|/)(?:k8s|kubernetes|helm|charts?|deploy|infra|terraform)/|(?:docker-)?compose[\w.-]*\.ya?ml$|Dockerfile")),
    ("cloud", re.compile(r"^(?:aws|gcp|azure|k8s)://")),
    ("frontend", re.compile(r"(?i)\.(?:jsx|tsx|vue|svelte|astro|html)$|(?:^|/)(?:components|pages|app|public|static|client|frontend|web)/")),
    ("dependencies", re.compile(r"(?i)(?:lock|requirements[\w.-]*\.txt|go\.mod|package\.json)$")),
)


def path_context(path: str) -> str:
    for name, rx in _CONTEXTS:
        if rx.search(path):
            return name
    return "code"


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    verdict: str  # tp | fp | accepted
    source: str
    ts: float
    path: str
    rule_version: int = 1


class Calibrator:
    """Turns evidence into per-rule and per-(rule, kind of file) precision. Pure: built
    from a list of Evidence, so the replay can rebuild it as it stood at any date."""

    def __init__(self, evidence: Iterable[Evidence], rules: dict[str, Rule] | None = None, now: float | None = None) -> None:
        self.now = time.time() if now is None else now
        self.rules = rules or {}
        self.by_rule: dict[str, RuleStats] = {}
        self.by_context: dict[tuple[str, str], RuleStats] = {}
        for e in evidence:
            w = self.weight(e)
            if w <= 0:
                continue
            for st in (self.by_rule.setdefault(e.rule_id, RuleStats(e.rule_id, 0, 0, 0)),
                       self.by_context.setdefault((e.rule_id, path_context(e.path)), RuleStats(e.rule_id, 0, 0, 0))):
                if e.verdict == "tp":
                    st.tp += w
                elif e.verdict == "fp":
                    st.fp += w
                else:
                    st.accepted += w

    def weight(self, e: Evidence) -> float:
        w = SOURCE_WEIGHT.get(e.source, 0.5)
        age_days = max(0, int((self.now - e.ts) // 86400))  # whole days: today's evidence weighs exactly 1
        w *= 0.5 ** (age_days / HALF_LIFE_DAYS)
        rule = self.rules.get(e.rule_id)
        if rule is not None and e.rule_version < rule.version:
            w *= OLD_VERSION_WEIGHT
        return w

    def adjust(self, f: Finding) -> None:
        s = self.by_rule.get(f.rule.id)
        if not s or (s.tp + s.fp) <= 0:
            return
        base = f.raw[1] if f.raw else f.rule.confidence
        p = s.precision(prior=min(0.97, max(0.03, base)))
        ctx = path_context(f.path)
        cs = self.by_context.get((f.rule.id, ctx))
        where = ""
        if cs and (cs.tp + cs.fp) >= 2:
            # the rule-wide estimate is the prior for this kind of file
            p = cs.precision(prior=min(0.97, max(0.03, p)))
            s = cs
            where = f" in {ctx} files"
        f.confidence = round(p, 2)
        f.learned_note = f"learned precision {p:.0%}{where} from {s.tp:g} TP / {s.fp:g} FP"
        if s.fp >= 5 and p < 0.25 and f.severity is not None:
            f.severity = f.severity.lower()
            f.learned_note += ", severity lowered"


class History:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (home() / "rempart.db")
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        for table, columns in _MIGRATIONS.items():
            have = {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}
            for name, decl in columns.items():
                if name not in have:
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------ evidence
    def evidence(self, before: float | None = None) -> list[Evidence]:
        rows = self.db.execute(
            "SELECT v.rule_id, v.verdict, v.source, v.ts, COALESCE(v.path,"
            " (SELECT f.path FROM findings f WHERE f.fingerprint = v.fingerprint ORDER BY f.scan_id DESC LIMIT 1), ''), v.rule_version"
            " FROM verdicts v" + (" WHERE v.ts < ?" if before is not None else ""),
            (before,) if before is not None else (),
        ).fetchall()
        return [Evidence(r[0], r[1], r[2] or "human", r[3], r[4] or "", r[5] or 1) for r in rows]

    def calibrator(self, now: float | None = None, before: float | None = None) -> Calibrator:
        from rempart.registry import load_all_rules

        return Calibrator(self.evidence(before), load_all_rules(), now=now)

    def rule_stats(self) -> dict[str, RuleStats]:
        return self.calibrator().by_rule

    def context_stats(self) -> dict[tuple[str, str], RuleStats]:
        """The same counts split by where the finding was: a rule can be precise in
        application code and noisy in scripts or infrastructure."""
        return self.calibrator().by_context

    def source_counts(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for rule_id, source, n in self.db.execute("SELECT rule_id, source, COUNT(*) FROM verdicts GROUP BY rule_id, source"):
            out.setdefault(rule_id, {})[source] = n
        return out

    # ------------------------------------------------------------ applying what was learned
    def apply_knowledge(self, project: str, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Suppress triaged noise, recalibrate confidence, flag regressions. Returns (kept, suppressed)."""
        closed = self._closed(project)
        fixed = self._fixed(project)
        cal = self.calibrator()
        kept: list[Finding] = []
        for f in findings:
            if f.fingerprint in closed:
                continue
            if f.raw is None and f.severity is not None and f.confidence is not None:
                f.raw = (int(f.severity), float(f.confidence))
            cal.adjust(f)
            if f.fingerprint in fixed and f.severity is not None:
                f.severity = Severity(min(Severity.CRITICAL, f.severity + 1))
                f.extra["regression"] = True
                f.learned_note = (f.learned_note + "; " if f.learned_note else "") + REGRESSION_NOTE
            kept.append(f)
        kept.sort(key=lambda f: (-f.risk, f.path, f.line))
        return kept, len(findings) - len(kept)

    def triage(self, project: str, fingerprint: str, verdict: str, note: str = "", source: str = "human") -> str:
        row = self.db.execute(
            "SELECT f.rule_id, f.fingerprint, f.path FROM findings f JOIN scans s ON s.id = f.scan_id"
            " WHERE s.project = ? AND f.fingerprint LIKE ? ORDER BY s.id DESC LIMIT 1",
            (project, fingerprint + "%"),
        ).fetchone() or self.db.execute(
            "SELECT f.rule_id, f.fingerprint, f.path FROM findings f WHERE f.fingerprint LIKE ? ORDER BY f.scan_id DESC LIMIT 1", (fingerprint + "%",)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown fingerprint {fingerprint} for {project}; run a scan first")
        self._put_verdict(project, row[1], row[0], verdict, note, source, row[2])
        self.db.commit()
        return row[0]

    def finding_row(self, project: str, fingerprint: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT f.rule_id, f.fingerprint, f.path, f.line FROM findings f JOIN scans s ON s.id = f.scan_id"
            " WHERE s.project = ? AND f.fingerprint LIKE ? ORDER BY s.id DESC LIMIT 1", (project, fingerprint + "%")).fetchone()
        return {"rule_id": row[0], "fingerprint": row[1], "path": row[2], "line": row[3]} if row else None

    def _put_verdict(self, project: str, fingerprint: str, rule_id: str, verdict: str, note: str, source: str, path: str) -> None:
        from rempart.registry import REGISTRY

        version = REGISTRY[rule_id].version if rule_id in REGISTRY else 1
        rank = "CASE {col} WHEN 'human' THEN 3 WHEN 'ai' THEN 2 ELSE 1 END"
        # a stronger source always wins; an equal one refreshes (a person changing their mind)
        self.db.execute(
            "INSERT INTO verdicts(project, fingerprint, rule_id, verdict, note, ts, source, path, rule_version) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(project, fingerprint) DO UPDATE SET verdict=excluded.verdict, note=excluded.note, ts=excluded.ts, "
            "source=excluded.source, path=excluded.path, rule_version=excluded.rule_version "
            f"WHERE {rank.format(col='excluded.source')} >= {rank.format(col='verdicts.source')}",
            (project, fingerprint, rule_id, verdict, note, time.time(), source, path, version),
        )

    # ------------------------------------------------------------ history
    def record(self, project: str, result: ScanResult, profile: str = "") -> int:
        """Store one scan, then learn from what changed since the previous comparable one."""
        from rempart import __version__

        value, grade = score(result.findings)
        cur = self.db.execute(
            "INSERT INTO scans(project, ts, score, grade, counts, files, duration, version, profile) VALUES (?,?,?,?,?,?,?,?,?)",
            (project, time.time(), value, grade, json.dumps(result.counts()), result.files_scanned, result.duration_s, __version__, profile),
        )
        scan_id = int(cur.lastrowid or 0)
        rows = []
        for f in result.findings:
            base_sev, base_conf = f.raw if f.raw else (int(f.severity or 0), float(f.confidence or 0))
            rows.append((scan_id, f.fingerprint, f.rule.id, f.severity.name if f.severity else "", f.path, f.line, f.message,
                         Severity(base_sev).name, base_conf))
        self.db.executemany(
            "INSERT INTO findings(scan_id, fingerprint, rule_id, severity, path, line, message, base_severity, base_confidence)"
            " VALUES (?,?,?,?,?,?,?,?,?)", rows)
        if profile:
            self._learn_implicit(project, scan_id, result, profile, __version__)
        for f in result.ignored:
            self._put_verdict(project, f.fingerprint, f.rule.id, "fp", "silenced inline with rempart:ignore", "inline", f.path)
        self.db.commit()
        return scan_id

    def _learn_implicit(self, project: str, scan_id: int, result: ScanResult, profile: str, version: str) -> None:
        """A finding that vanished between two scans with the same version, rules,
        options, configuration and knowledge, while its file was still scanned, can
        only have gone because the code changed: it was fixed. That is a true positive."""
        prev = self.db.execute(
            "SELECT id FROM scans WHERE project = ? AND id < ? AND version = ? AND profile = ? ORDER BY id DESC LIMIT 1",
            (project, scan_id, version, profile)).fetchone()
        if not prev:
            return
        now = {r[0] for r in self.db.execute("SELECT fingerprint FROM findings WHERE scan_id = ?", (scan_id,))}
        files = set(result.files)
        judged = {r[0] for r in self.db.execute("SELECT fingerprint FROM verdicts WHERE project = ?", (project,))}
        ignored = {f.fingerprint for f in result.ignored}
        for fp, rule_id, path in self.db.execute(
                "SELECT fingerprint, rule_id, path FROM findings WHERE scan_id = ?", (prev[0],)).fetchall():
            if fp in now or fp in judged or fp in ignored or path not in files:
                continue
            self._put_verdict(project, fp, rule_id, "tp", "disappeared after a code change", "implicit", path)

    def diff_with_previous(self, project: str, scan_id: int) -> dict[str, list[tuple[str, str, str]]]:
        """New and fixed since the previous scan. When the two scans were not run the same
        way (options, configuration, learned knowledge), what vanished is only `gone`."""
        prev = self.db.execute("SELECT id, profile FROM scans WHERE project = ? AND id < ? ORDER BY id DESC LIMIT 1", (project, scan_id)).fetchone()
        if not prev:
            return {"new": [], "fixed": [], "gone": []}
        profile = self.db.execute("SELECT profile FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]

        def load(sid: int) -> dict[str, tuple[str, str, str]]:
            return {r[0]: (r[1], r[2], r[3]) for r in self.db.execute("SELECT fingerprint, rule_id, path, severity FROM findings WHERE scan_id = ?", (sid,))}

        now, before = load(scan_id), load(prev[0])
        closed = self._closed(project)  # triaged away is not the same as fixed
        vanished = [before[k] for k in before.keys() - now.keys() - closed]
        comparable = not (profile and prev[1]) or profile == prev[1]
        return {"new": [now[k] for k in now.keys() - before.keys()], "fixed": vanished if comparable else [], "gone": [] if comparable else vanished}

    def _closed(self, project: str) -> set[str]:
        return {fp for (fp,) in self.db.execute(
            "SELECT fingerprint FROM verdicts WHERE project = ? AND verdict IN ('fp', 'accepted') AND source = 'human'", (project,))}

    def _fixed(self, project: str) -> set[str]:
        return {fp for (fp,) in self.db.execute(
            "SELECT fingerprint FROM verdicts WHERE project = ? AND source = 'implicit' AND verdict = 'tp'", (project,))}

    def scans(self, project: str, limit: int = 20) -> list[dict[str, object]]:
        rows = self.db.execute(
            "SELECT id, ts, score, grade, counts, files, duration FROM scans WHERE project = ? ORDER BY id DESC LIMIT ?", (project, limit)
        ).fetchall()
        return [{"id": r[0], "ts": r[1], "score": r[2], "grade": r[3], "counts": json.loads(r[4] or "{}"), "files": r[5], "duration": r[6]} for r in rows]

    def mttr_days(self, project: str) -> float | None:
        """Mean time to remediate: first seen -> first scan where it disappeared."""
        rows = self.db.execute(
            "SELECT f.fingerprint, MIN(s.ts), MAX(s.ts) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project = ? GROUP BY f.fingerprint",
            (project,),
        ).fetchall()
        last = self.db.execute("SELECT MAX(ts) FROM scans WHERE project = ?", (project,)).fetchone()[0]
        closed = self._closed(project)
        fixed = [(last_seen - first) / 86400 for fp, first, last_seen in rows if last_seen < last and fp not in closed]
        return round(sum(fixed) / len(fixed), 1) if fixed else None

    # ------------------------------------------------------------ does learning help? (rempart learn --eval)
    def replay(self, project: str | None = None, k_values: tuple[int, ...] = (10, 20)) -> dict[str, Any]:
        """Replay history in time order. Each finding a person eventually judged is
        scored as it stood on the day it first appeared, once with the scanner's own
        confidence and once with what Rempart had learned before that day (evidence
        dated earlier only). Better learning puts confirmed issues above false alarms."""
        from rempart.registry import load_all_rules

        rules = load_all_rules()
        where, params = ("WHERE v.source = 'human'" + (" AND v.project = ?" if project else "")), ((project,) if project else ())
        labelled = self.db.execute(
            "SELECT v.fingerprint, v.verdict, v.project FROM verdicts v " + where, params).fetchall()
        cases = []
        for fp, verdict, proj in labelled:
            first = self.db.execute(
                "SELECT s.ts, f.rule_id, f.path, f.line, COALESCE(f.base_severity, ''), f.base_confidence FROM findings f"
                " JOIN scans s ON s.id = f.scan_id WHERE f.fingerprint = ? AND s.project = ? ORDER BY s.id LIMIT 1", (fp, proj)).fetchone()
            if not first or first[1] not in rules:
                continue
            ts, rule_id, path, line, base_sev, base_conf = first
            rule = rules[rule_id]
            sev = Severity[base_sev] if base_sev in Severity.__members__ else rule.severity
            conf = base_conf if base_conf is not None else rule.confidence
            cases.append((ts, rule, path, line, sev, conf, verdict != "fp"))
        cases.sort(key=lambda c: c[0])
        all_evidence = sorted(self.evidence(), key=lambda e: e.ts)
        scored: list[tuple[float, float, float, float, bool]] = []  # base risk, learned risk, base conf, learned conf, real
        for ts, rule, path, line, sev, conf, real in cases:
            cal = Calibrator([e for e in all_evidence if e.ts < ts], rules, now=ts)
            plain = Finding(rule, path, line, "", severity=sev, confidence=conf)
            learned = Finding(rule, path, line, "", severity=sev, confidence=conf, raw=(int(sev), conf))
            cal.adjust(learned)
            scored.append((plain.risk, learned.risk, conf, float(learned.confidence or 0), real))

        def at_k(idx: int, k: int) -> dict[str, float | int]:
            top = sorted(scored, key=lambda s: -s[idx])[:k]
            return {"k": len(top), "precision": round(sum(s[4] for s in top) / len(top), 3) if top else 0.0,
                    "false_positives": sum(not s[4] for s in top)}

        def brier(idx: int) -> float | None:
            return round(sum((s[idx] - (1.0 if s[4] else 0.0)) ** 2 for s in scored) / len(scored), 4) if scored else None

        def auc(idx: int) -> float | None:
            pos = [s[idx] for s in scored if s[4]]
            neg = [s[idx] for s in scored if not s[4]]
            if not pos or not neg:
                return None
            wins = sum(1.0 if p > n else 0.5 if math.isclose(p, n) else 0.0 for p in pos for n in neg)
            return round(wins / (len(pos) * len(neg)), 3)

        return {
            "labelled": len(scored), "real": sum(s[4] for s in scored), "false_alarms": sum(not s[4] for s in scored),
            "without_learning": {"brier": brier(2), "auc": auc(0), **{f"top{k}": at_k(0, k) for k in k_values}},
            "with_learning": {"brier": brier(3), "auc": auc(1), **{f"top{k}": at_k(1, k) for k in k_values}},
        }

