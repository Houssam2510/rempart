"""Findings about the scan itself, not about the code: a scan that could not do its
job must say so, loudly, instead of looking clean (AUDIT.md F2)."""

from __future__ import annotations

from rempart.models import Finding, Severity
from rempart.registry import rule

R_SCANNER_ERROR = rule(
    "SCANNER-ERROR", "A scanner failed: the results are incomplete", Severity.HIGH, "scan",
    fix="Read the error, rerun with a fixed version or an exclusion. Until then no score is given and the exit code is 3; "
        "--allow-scanner-errors accepts an incomplete scan on purpose.",
    confidence=1.0)


def scanner_error(name: str, message: str) -> Finding:
    """One HIGH finding per failed scanner (or domain skipped because of an error)."""
    return Finding(R_SCANNER_ERROR, f"scanner:{name}", 0, f"{name}: {message}"[:500], snippet=name,
                   extra={"anchor": f"scanner-error:{name}"}, verification="observed")
