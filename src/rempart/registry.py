"""Global rule registry and the framework vocabulary every rule maps to.

Mappings use the current editions as of 2026:
OWASP Top 10:2025, CWE Top 25 (2025), OWASP Kubernetes Top 10 (2025),
OWASP Top 10 CI/CD Security Risks, OWASP Top 10 for LLM Applications 2025,
OWASP Top 10 for Agentic Applications 2026.
"""

from __future__ import annotations

from rempart.models import Rule, Severity

# OWASP Top 10:2025
A01 = "A01:2025 Broken Access Control"
A02 = "A02:2025 Security Misconfiguration"
A03 = "A03:2025 Software Supply Chain Failures"
A04 = "A04:2025 Cryptographic Failures"
A05 = "A05:2025 Injection"
A06 = "A06:2025 Insecure Design"
A07 = "A07:2025 Authentication Failures"
A08 = "A08:2025 Software or Data Integrity Failures"
A09 = "A09:2025 Security Logging and Alerting Failures"
A10 = "A10:2025 Mishandling of Exceptional Conditions"

OWASP_2025 = (A01, A02, A03, A04, A05, A06, A07, A08, A09, A10)

# CWE Top 25 (2025), rank order. Used to flag findings that hit the list.
CWE_TOP25_2025 = (
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787", "CWE-22", "CWE-416",
    "CWE-125", "CWE-78", "CWE-94", "CWE-120", "CWE-434", "CWE-476", "CWE-121",
    "CWE-502", "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200", "CWE-306",
    "CWE-918", "CWE-77", "CWE-639", "CWE-770",
)

REGISTRY: dict[str, Rule] = {}

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO


def rule(
    id: str,
    title: str,
    severity: Severity,
    domain: str,
    *,
    cwe: tuple[str, ...] | str = (),
    owasp: tuple[str, ...] | str = (),
    frameworks: tuple[str, ...] | str = (),
    fix: str = "",
    refs: tuple[str, ...] | str = (),
    confidence: float = 0.8,
) -> Rule:
    def tup(v: tuple[str, ...] | str) -> tuple[str, ...]:
        return (v,) if isinstance(v, str) else tuple(v)

    if id in REGISTRY:
        raise ValueError(f"duplicate rule id {id}")
    r = Rule(
        id=id,
        title=title,
        severity=severity,
        domain=domain,
        cwe=tup(cwe),
        owasp=tup(owasp),
        frameworks=tup(frameworks),
        remediation=fix,
        references=tup(refs),
        confidence=confidence,
    )
    REGISTRY[id] = r
    return r


def load_all_rules() -> dict[str, Rule]:
    """Import every scanner module so their rules register themselves."""
    from rempart import cloud_aws, cloud_multi, continuous, correlate, images, web  # noqa: F401
    from rempart.scanners import ALL_SCANNERS  # noqa: F401

    return REGISTRY
