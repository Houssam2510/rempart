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


R_CONFIG_CHANGED = rule(
    "REMPART-CONFIG-CHANGED", "Change set modifies Rempart's own configuration or knowledge", Severity.HIGH, "scan",
    fix="A change under review must not decide how it is reviewed: a person checks this file's diff. Pull-request scans read "
        "these files from the target branch (--trust-config base) unless told otherwise.",
    confidence=1.0)


def config_changed(path: str, ref: str, trusted: str) -> Finding:
    used = f"the version at {ref} was used" if trusted == "base" else "the changed version was used (--trust-config head)"
    return Finding(R_CONFIG_CHANGED, path, 1, f"{path} differs from {ref}; {used}. A person must review this change.",
                   snippet=path, extra={"anchor": f"config-changed:{path}"}, verification="observed")


def scanner_error(name: str, message: str) -> Finding:
    """One HIGH finding per failed scanner (or domain skipped because of an error)."""
    return Finding(R_SCANNER_ERROR, f"scanner:{name}", 0, f"{name}: {message}"[:500], snippet=name,
                   extra={"anchor": f"scanner-error:{name}"}, verification="observed")
