"""Scan history and the learning loop.

Every scan is recorded per project. You triage findings (true positive,
false positive, accepted risk); the verdicts feed a per-rule Beta-Bernoulli
precision estimate shared across all your projects:

    precision = (tp + a) / (tp + fp + a + b)      prior a, b from the rule's confidence

The estimate then adjusts each new finding's confidence and, for rules that
keep being wrong, its severity. Fingerprints marked false positive or
accepted are suppressed in later scans of the same project. Nothing leaves
the machine: the database lives in REMPART_HOME (default ~/.local/share/rempart).
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from rempart.engine import ScanResult, score
from rempart.models import Finding
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
CREATE TABLE IF NOT EXISTS verdicts (
    project TEXT NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('tp', 'fp', 'accepted')),
    note TEXT, ts REAL NOT NULL,
    PRIMARY KEY (project, fingerprint)
);
"""


@dataclass
class RuleStats:
    rule_id: str
    tp: int
    fp: int
    accepted: int

    def precision(self, prior: float = 0.8, strength: float = 4.0) -> float:
        a, b = prior * strength, (1 - prior) * strength
        return (self.tp + a) / (self.tp + self.fp + a + b)


class History:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (home() / "rempart.db")
        self.db = sqlite3.connect(self.path)
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------ learning
    def rule_stats(self) -> dict[str, RuleStats]:
        rows = self.db.execute(
            "SELECT rule_id, SUM(verdict='tp'), SUM(verdict='fp'), SUM(verdict='accepted') FROM verdicts GROUP BY rule_id"
        ).fetchall()
        return {r[0]: RuleStats(r[0], r[1] or 0, r[2] or 0, r[3] or 0) for r in rows}

    def apply_knowledge(self, project: str, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Suppress triaged noise and recalibrate confidence. Returns (kept, suppressed)."""
        closed = self._closed(project)
        stats = self.rule_stats()
        kept: list[Finding] = []
        for f in findings:
            if f.fingerprint in closed:
                continue
            s = stats.get(f.rule.id)
            if s and (s.tp + s.fp) > 0:
                p = s.precision(prior=f.rule.confidence)
                f.confidence = round(p, 2)
                f.learned_note = f"learned precision {p:.0%} from {s.tp} TP / {s.fp} FP"
                if s.fp >= 5 and p < 0.25 and f.severity is not None:
                    f.severity = f.severity.lower()
                    f.learned_note += ", severity lowered"
            kept.append(f)
        kept.sort(key=lambda f: (-f.risk, f.path, f.line))
        return kept, len(findings) - len(kept)

    def triage(self, project: str, fingerprint: str, verdict: str, note: str = "") -> str:
        row = self.db.execute(
            "SELECT f.rule_id FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project = ? AND f.fingerprint = ? ORDER BY s.id DESC LIMIT 1",
            (project, fingerprint),
        ).fetchone() or self.db.execute(
            "SELECT f.rule_id FROM findings f WHERE f.fingerprint LIKE ? ORDER BY f.scan_id DESC LIMIT 1", (fingerprint + "%",)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown fingerprint {fingerprint} for {project}; run a scan first")
        full = self.db.execute("SELECT fingerprint FROM findings WHERE fingerprint LIKE ? LIMIT 1", (fingerprint + "%",)).fetchone()[0]
        self.db.execute(
            "INSERT INTO verdicts(project, fingerprint, rule_id, verdict, note, ts) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(project, fingerprint) DO UPDATE SET verdict=excluded.verdict, note=excluded.note, ts=excluded.ts",
            (project, full, row[0], verdict, note, time.time()),
        )
        self.db.commit()
        return row[0]

    # ------------------------------------------------------------ history
    def record(self, project: str, result: ScanResult) -> int:
        value, grade = score(result.findings)
        cur = self.db.execute(
            "INSERT INTO scans(project, ts, score, grade, counts, files, duration) VALUES (?,?,?,?,?,?,?)",
            (project, time.time(), value, grade, json.dumps(result.counts()), result.files_scanned, result.duration_s),
        )
        scan_id = int(cur.lastrowid or 0)
        self.db.executemany(
            "INSERT INTO findings(scan_id, fingerprint, rule_id, severity, path, line, message) VALUES (?,?,?,?,?,?,?)",
            [(scan_id, f.fingerprint, f.rule.id, f.severity.name if f.severity else "", f.path, f.line, f.message) for f in result.findings],
        )
        self.db.commit()
        return scan_id

    def diff_with_previous(self, project: str, scan_id: int) -> dict[str, list[tuple[str, str, str]]]:
        prev = self.db.execute("SELECT id FROM scans WHERE project = ? AND id < ? ORDER BY id DESC LIMIT 1", (project, scan_id)).fetchone()
        if not prev:
            return {"new": [], "fixed": []}

        def load(sid: int) -> dict[str, tuple[str, str, str]]:
            return {r[0]: (r[1], r[2], r[3]) for r in self.db.execute("SELECT fingerprint, rule_id, path, severity FROM findings WHERE scan_id = ?", (sid,))}

        now, before = load(scan_id), load(prev[0])
        closed = self._closed(project)  # triaged away is not the same as fixed
        return {"new": [now[k] for k in now.keys() - before.keys()], "fixed": [before[k] for k in before.keys() - now.keys() - closed]}

    def _closed(self, project: str) -> set[str]:
        return {fp for (fp,) in self.db.execute(
            "SELECT fingerprint FROM verdicts WHERE project = ? AND verdict IN ('fp', 'accepted')", (project,))}

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
