"""Core data model: severities, rules and findings.

A Rule is static knowledge (what the weakness is, how to fix it, which
frameworks it maps to). A Finding is one occurrence of a rule in a target.
Fingerprints deliberately ignore the line number, so a finding keeps its
identity when unrelated lines move. That identity is what the learning
loop (history.py) attaches verdicts to.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    def lower(self) -> "Severity":
        return Severity(max(0, self - 1))


# Domains group rules in reports and drive the per-domain score.
DOMAINS = (
    "secrets",
    "code",
    "dependencies",
    "supply-chain",
    "iac",
    "containers",
    "kubernetes",
    "cicd",
    "data",
    "ai",
    "quality",
    "performance",
    "web",
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    domain: str
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    remediation: str = ""
    references: tuple[str, ...] = ()
    confidence: float = 0.8

    def __post_init__(self) -> None:
        if self.domain not in DOMAINS:
            raise ValueError(f"rule {self.id}: unknown domain {self.domain!r}")
        if not 0.0 < self.confidence <= 1.0:
            raise ValueError(f"rule {self.id}: confidence must be in (0, 1]")


_WS = re.compile(r"\s+")


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    message: str
    snippet: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    severity: Severity | None = None
    confidence: float | None = None
    learned_note: str = ""

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = self.rule.severity
        if self.confidence is None:
            self.confidence = self.rule.confidence

    @property
    def fingerprint(self) -> str:
        anchor = self.extra.get("anchor") or _WS.sub(" ", self.snippet).strip()
        raw = f"{self.rule.id}|{self.path}|{anchor}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def risk(self) -> float:
        """0-100 risk used for ordering. Exploitation evidence overrides severity."""
        assert self.severity is not None and self.confidence is not None
        base = {0: 2, 1: 15, 2: 40, 3: 70, 4: 90}[int(self.severity)] * (0.5 + self.confidence / 2)
        epss = self.extra.get("epss")
        if isinstance(epss, (int, float)):
            base = max(base, base * 0.6 + epss * 40)
        if self.extra.get("kev"):
            base = max(base, 95.0)
        return round(min(100.0, base), 1)

    def to_dict(self) -> dict[str, Any]:
        assert self.severity is not None
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "domain": self.rule.domain,
            "severity": self.severity.name,
            "confidence": round(self.confidence or 0, 2),
            "risk": self.risk,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
            "cwe": list(self.rule.cwe),
            "owasp": list(self.rule.owasp),
            "frameworks": list(self.rule.frameworks),
            "remediation": self.rule.remediation,
            "references": list(self.rule.references),
            "learned_note": self.learned_note,
            "extra": {k: v for k, v in self.extra.items() if k != "anchor"},
        }
