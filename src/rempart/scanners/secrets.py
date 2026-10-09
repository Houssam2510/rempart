"""Hard-coded credentials: provider-specific token formats, private keys,
generic secret assignments filtered by entropy, and committed secret files.

Values are always redacted in output: a security report must never become
the leak it describes.
"""

from __future__ import annotations

import math
import os
import re
from typing import Iterator

from rempart.engine import ScanContext, is_comment
from rempart.models import Finding
from rempart.registry import A02, A04, A07, C, H, L, M, rule

_FIX = "Revoke and rotate the credential now, purge it from git history, then load it from a secret manager or an environment variable."
_REF = ("https://cwe.mitre.org/data/definitions/798.html",)

# (rule id, title, severity, regex). Regexes match the token itself.
PROVIDERS = [
    ("SEC-AWS-ACCESS-KEY", "AWS access key ID", C, r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ("SEC-GITHUB-TOKEN", "GitHub token", C, r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("SEC-GITLAB-TOKEN", "GitLab personal access token", C, r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ("SEC-SLACK-TOKEN", "Slack token", H, r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    ("SEC-SLACK-WEBHOOK", "Slack incoming webhook", M, r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SEC-STRIPE-LIVE", "Stripe live secret key", C, r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    ("SEC-STRIPE-TEST", "Stripe test secret key", L, r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b"),
    ("SEC-STRIPE-WEBHOOK", "Stripe webhook signing secret", H, r"\bwhsec_[A-Za-z0-9]{24,}\b"),
    ("SEC-GOOGLE-API-KEY", "Google API key", H, r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("SEC-GCP-SERVICE-ACCOUNT", "GCP service account key", C, r"\"type\"\s*:\s*\"service_account\""),
    ("SEC-OPENAI-KEY", "OpenAI API key", C, r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b|\bsk-proj-[A-Za-z0-9_\-]{40,}\b"),
    ("SEC-ANTHROPIC-KEY", "Anthropic API key", C, r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b"),
    ("SEC-HUGGINGFACE-TOKEN", "Hugging Face token", H, r"\bhf_[A-Za-z0-9]{34,}\b"),
    ("SEC-NPM-TOKEN", "npm access token", C, r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("SEC-PYPI-TOKEN", "PyPI upload token", C, r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
    ("SEC-SENDGRID-KEY", "SendGrid API key", H, r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("SEC-RESEND-KEY", "Resend API key", H, r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,}\b"),
    ("SEC-TWILIO-KEY", "Twilio API key", H, r"\bSK[0-9a-f]{32}\b"),
    ("SEC-MAILGUN-KEY", "Mailgun API key", H, r"\bkey-[0-9a-f]{32}\b"),
    ("SEC-DISCORD-WEBHOOK", "Discord webhook", M, r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,}"),
    ("SEC-AZURE-STORAGE-KEY", "Azure storage account key", C, r"AccountKey=[A-Za-z0-9+/]{86}=="),
    ("SEC-SUPABASE-SERVICE", "Supabase service-role key", C, r"\bsb_secret_[A-Za-z0-9_\-]{20,}\b"),
    ("SEC-DIGITALOCEAN-TOKEN", "DigitalOcean token", C, r"\bdo[opr]_v1_[a-f0-9]{64}\b"),
    ("SEC-SHOPIFY-TOKEN", "Shopify access token", H, r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    ("SEC-DOPPLER-TOKEN", "Doppler token", H, r"\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}\b"),
    ("SEC-PRIVATE-KEY", "Private key", C, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
]

_RULES = {
    rid: rule(
        rid, f"Hard-coded {title}", sev, "secrets",
        cwe=("CWE-798",), owasp=(A07, A04), fix=_FIX, refs=_REF, confidence=0.9,
    )
    for rid, title, sev, _ in PROVIDERS
}
_COMPILED = [(rid, re.compile(rx)) for rid, _, _, rx in PROVIDERS]

R_JWT = rule(
    "SEC-JWT", "Hard-coded JSON Web Token", M, "secrets", cwe="CWE-798", owasp=A07,
    fix="A committed JWT may still be valid. Remove it and rotate the signing key if it was a real token.",
    confidence=0.6,
)
R_GENERIC = rule(
    "SEC-GENERIC", "Hard-coded secret in assignment", H, "secrets", cwe="CWE-798", owasp=A07,
    fix=_FIX, refs=_REF, confidence=0.55,
)
R_ENV_FILE = rule(
    "SEC-ENV-COMMITTED", "Environment file committed to the repository", H, "secrets",
    cwe=("CWE-538", "CWE-798"), owasp=A02,
    fix="Add the file to .gitignore, remove it with `git rm --cached`, rotate every value it held, and commit a `.env.example` with placeholders instead.",
)
R_KEY_FILE = rule(
    "SEC-KEY-FILE", "Key or credential file committed", C, "secrets", cwe=("CWE-312", "CWE-798"), owasp=A04,
    fix="Remove the file from the repository and its history, and reissue the key.",
)
R_NPMRC = rule(
    "SEC-NPMRC-TOKEN", "Registry auth token in .npmrc / .pypirc", C, "secrets", cwe="CWE-798", owasp=A07,
    fix="Reference `${NPM_TOKEN}` instead of a literal, and use short-lived OIDC trusted publishing where possible.",
)

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_ASSIGN = re.compile(
    r"""(?ix)
    (?P<name>[a-z0-9_.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|
        token|private[_\-]?key|client[_\-]?secret|credentials?)[a-z0-9_]*)
    ["']?\s*(?::=|=>|=|:)\s*
    (?P<q>["'`])(?P<value>[^"'`\s]{8,200})(?P=q)
    """
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|\*{3,}|\.{3,}|<[^>]+>|\$\{[^}]*\}|\{\{.*\}\}|%\(.*\)s|changeme|change[_-]?me|example|sample|"
    r"placeholder|your[_-].*|test|dummy|fake|secret|password|redacted|null|none|undefined|todo|xxx.*|.*example.*|"
    r"process\.env.*|os\.environ.*|env\(.*|getenv.*|settings\..*|config\..*|import\.meta.*|true|false)$"
)
_SKIP_NAME = re.compile(r"(?i)(?:_?url|_?path|_?file|_?name|_?type|_?id|_?field|_?header|_?label|_?length|_?min|_?max|_?regex|_?pattern)$")
_KEY_FILES = re.compile(r"(?i)(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx|.*\.jks|.*\.keystore|credentials\.json|service[-_]?account.*\.json|\.htpasswd|.*\.ovpn|\.git-credentials)$")
_KEY_FILE_ALLOW = re.compile(r"(?i)(?:public|\.pub$|example|sample|test|fixture|cert\.pem$|chain\.pem$|ca\.pem$|fullchain)")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * min(12, len(value) - 6) + value[-2:]


def _is_test_path(rel: str) -> bool:
    return bool(re.search(r"(?i)(?:^|/)(?:tests?|__tests__|spec|fixtures?|mocks?|examples?|docs?)(?:/|$)|\.(?:test|spec)\.", rel))


class SecretsScanner:
    name = "secrets"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.files:
            base = os.path.basename(rel)
            committed = ctx.is_committed(rel)
            if committed and re.fullmatch(r"\.env(?:\.(?!example|sample|template|dist|defaults?)[\w.-]+)?", base):
                text = ctx.text(rel) or ""
                if re.search(r"^\s*[A-Z0-9_]+\s*=\s*\S{6,}", text, re.M):
                    yield Finding(R_ENV_FILE, rel, 1, f"{base} with values is part of the repository.", snippet=base)
            if committed and _KEY_FILES.search(rel) and not _KEY_FILE_ALLOW.search(rel):
                text = ctx.text(rel) or ""
                if "PRIVATE KEY" in text or rel.endswith((".p12", ".pfx", ".jks", ".keystore")) or "client_secret" in text or "private_key" in text or base in (".git-credentials", ".htpasswd"):
                    yield Finding(R_KEY_FILE, rel, 1, f"Credential material in {base}.", snippet=base)
            if base in (".npmrc", ".pypirc", ".yarnrc.yml"):
                for i, line in enumerate(ctx.lines(rel), 1):
                    if re.search(r"(?i)(_authToken|password|npmAuthToken)\s*[=:]\s*(?!\$\{)\S{8,}", line):
                        yield Finding(R_NPMRC, rel, i, "Literal registry credential.", snippet=re.sub(r"[=:]\s*\S+", "= ****", line.strip()))
            yield from self._scan_text(ctx, rel)

    def _scan_text(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel)
        if not text:
            return
        test_path = _is_test_path(rel)
        lock = os.path.basename(rel) in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "Cargo.lock", "go.sum", "uv.lock", "composer.lock")
        if lock:
            return
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 4000:
                continue
            hit_provider = False
            for rid, rx in _COMPILED:
                m = rx.search(line)
                if not m:
                    continue
                hit_provider = True
                token = m.group(0)
                f = Finding(
                    _RULES[rid], rel, i, f"{_RULES[rid].title.replace('Hard-coded ', '')} found ({redact(token)}).",
                    snippet=line.strip().replace(token, redact(token))[:200], extra={"anchor": f"{rid}:{redact(token)}"},
                )
                if test_path:
                    f.confidence = 0.4
                    f.severity = f.severity.lower() if f.severity else None
                if getattr(ctx, "verify_secrets", False):
                    _apply_verification(f, rid, token, text)
                yield f
            if hit_provider:
                continue
            m = _JWT.search(line)
            if m and not is_comment(line):
                yield Finding(R_JWT, rel, i, "JWT literal in source.", snippet=line.strip().replace(m.group(0), redact(m.group(0)))[:200],
                              confidence=0.3 if test_path else None)
                continue
            for m in _ASSIGN.finditer(line):
                name, value = m.group("name"), m.group("value")
                if _SKIP_NAME.search(name) or _PLACEHOLDER.match(value) or value.startswith(("$", "{", "%", "/", "http")) \
                        or re.fullmatch(r"[A-Z][A-Z0-9_\-]{2,}", value):
                    continue
                if entropy(value) < 3.2 or not (re.search(r"\d", value) and re.search(r"[A-Za-z]", value)):
                    continue
                f = Finding(R_GENERIC, rel, i, f"`{name}` is assigned a literal that looks like a real secret ({redact(value)}).",
                            snippet=line.strip().replace(value, redact(value))[:200], extra={"anchor": f"{name}:{redact(value)}"})
                if test_path:
                    f.confidence = 0.25
                    f.severity = f.severity.lower() if f.severity else None
                yield f
                break


def _apply_verification(f: Finding, rule_id: str, token: str, file_text: str) -> None:
    from rempart.models import Severity
    from rempart.verify import verify

    v = verify(rule_id, token, file_text)
    f.extra["verification_detail"] = v.detail
    if v.status == "live":
        f.verification = "live-secret"
        f.severity, f.confidence = Severity.CRITICAL, 1.0
        f.message += f" VERIFIED LIVE: {v.detail}. Rotate it now."
    elif v.status == "revoked":
        f.verification = "revoked-secret"
        f.severity, f.confidence = Severity.LOW, 1.0
        f.message += " Provider rejects it (revoked): purge it from git history."
    else:
        f.message += f" (live check inconclusive: {v.detail})"
