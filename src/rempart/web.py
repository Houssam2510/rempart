"""Passive audit of a deployed web application you own.

It sends the same requests a browser would (a GET of the page, the http://
variant to check the redirect, and /.well-known/security.txt) and reads what
comes back: transport security, security headers, cookie flags, information
disclosure and basic performance. It sends no attack payloads and does not
crawl, so it is safe to run against production.
"""

from __future__ import annotations

import contextvars
import gzip
import http.client
import ipaddress
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message

from rempart.models import Finding, Severity
from rempart.registry import A02, A04, A05, A07, H, I, L, M, rule

R_NO_HTTPS = rule("WEB-NO-HTTPS-REDIRECT", "HTTP not redirected to HTTPS", H, "web", cwe="CWE-319", owasp=A04, fix="Redirect every http:// request to https:// with a 301/308.")
R_HSTS = rule("WEB-HSTS", "Strict-Transport-Security missing or weak", M, "web", cwe="CWE-319", owasp=A04,
              fix="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add preload once every subdomain is HTTPS).")
R_CSP = rule("WEB-CSP", "Content-Security-Policy missing or permissive", M, "web", cwe="CWE-1021", owasp=A05,
             fix="Deploy a CSP with nonces or hashes for scripts (`script-src 'nonce-...' 'strict-dynamic'`), `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors`. Avoid 'unsafe-inline' and 'unsafe-eval'.")
R_FRAME = rule("WEB-CLICKJACKING", "Page can be framed by any site", M, "web", cwe="CWE-1021", owasp=A02,
               fix="Send `Content-Security-Policy: frame-ancestors 'self'` (or X-Frame-Options: DENY for old browsers).")
R_NOSNIFF = rule("WEB-NOSNIFF", "X-Content-Type-Options missing", L, "web", cwe="CWE-693", owasp=A02, fix="Send `X-Content-Type-Options: nosniff`.")
R_REFERRER = rule("WEB-REFERRER-POLICY", "Referrer-Policy missing or leaky", L, "web", cwe="CWE-200", owasp=A02,
                  fix="Send `Referrer-Policy: strict-origin-when-cross-origin` (or no-referrer) so URLs with tokens are not leaked to third parties.")
R_PERMS = rule("WEB-PERMISSIONS-POLICY", "Permissions-Policy missing", I, "web", cwe="CWE-693", owasp=A02,
               fix="Disable powerful features you do not use: `Permissions-Policy: camera=(), microphone=(), geolocation=()`.", confidence=0.6)
R_COOKIE = rule("WEB-COOKIE-FLAGS", "Cookie without Secure / HttpOnly / SameSite", M, "web", cwe=("CWE-614", "CWE-1004", "CWE-1275"), owasp=A07,
                fix="Session and auth cookies need Secure, HttpOnly and SameSite=Lax/Strict; prefer the __Host- prefix.")
R_DISCLOSURE = rule("WEB-VERSION-DISCLOSURE", "Server software and version disclosed", L, "web", cwe="CWE-200", owasp=A02,
                    fix="Remove version banners (Server, X-Powered-By, X-AspNet-Version) so scanners cannot match you to CVEs at a glance.")
R_CORS = rule("WEB-CORS-WILDCARD", "CORS allows any origin", M, "web", cwe="CWE-942", owasp=A02,
              fix="Allow-list origins. A wildcard is acceptable only for truly public, unauthenticated resources.", confidence=0.6)
R_TLS_OLD = rule("WEB-TLS-WEAK", "Weak TLS configuration", H, "web", cwe="CWE-326", owasp=A04, fix="Accept TLS 1.2+ only with AEAD cipher suites; TLS 1.3 preferred.")
R_CERT = rule("WEB-CERT-EXPIRY", "TLS certificate close to expiry", M, "web", cwe="CWE-298", owasp=A04, fix="Automate renewal (ACME) and alert at 21 days remaining.")
R_SECURITY_TXT = rule("WEB-SECURITY-TXT", "No security.txt", I, "web", cwe="CWE-1059", owasp=A02,
                      fix="Publish /.well-known/security.txt (RFC 9116) with a Contact and Expires so researchers can report issues to you.", confidence=0.9)
R_SLOW = rule("PERF-WEB-SLOW-TTFB", "Slow time to first byte", M, "performance", fix="Cache at the edge, avoid blocking work before the first byte, check cold starts and database round-trips.", confidence=0.6)
R_NO_COMPRESSION = rule("PERF-WEB-NO-COMPRESSION", "Response not compressed", L, "performance", fix="Enable Brotli or gzip for text responses.", confidence=0.8)
R_HEAVY = rule("PERF-WEB-HEAVY-HTML", "Large HTML document", L, "performance", fix="Keep the initial HTML small: stream, paginate, defer non-critical markup and inline data.", confidence=0.6)
R_CACHE = rule("WEB-CACHE-SENSITIVE", "Authenticated response may be cached by shared caches", L, "web", cwe="CWE-524", owasp=A02,
               fix="Send `Cache-Control: private, no-store` on pages that set or depend on session cookies.", confidence=0.5)

UA = "rempart-web-audit/0.1 (passive; +https://github.com/Houssam2510/rempart)"


@dataclass
class Response:
    url: str
    status: int
    headers: Message
    body: bytes
    ttfb_ms: float
    total_ms: float
    redirects: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ public-only mode (AUDIT.md F8)
# When an AI assistant chooses the URL (MCP), the audit must not become a way to probe the
# machine's own network. Each host is resolved once, every address it resolves to must be
# public, and the connection goes to that checked address (no second resolution, so a DNS
# answer that changes in between cannot redirect it). Redirects are checked hop by hop.

PUBLIC_ONLY: contextvars.ContextVar[bool] = contextvars.ContextVar("rempart_web_public_only", default=False)


class BlockedAddress(ValueError):
    pass


def _is_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                                   or addr.is_reserved or addr.is_unspecified)


def resolve_public(host: str, port: int) -> str:
    """The address to connect to, after checking that every address of `host` is public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedAddress(f"cannot resolve {host}: {exc}") from exc
    addrs = [ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos]
    for a in addrs:
        if not _is_public(a):
            raise BlockedAddress(f"{host} resolves to {a}, which is not a public address (private, loopback, link-local, metadata or reserved)")
    if not addrs:
        raise BlockedAddress(f"{host} has no address")
    return str(addrs[0])


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int | None, ip: str, **kw: object) -> None:
        super().__init__(host, port, **kw)  # type: ignore[arg-type]
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int | None, ip: str, **kw: object) -> None:
        super().__init__(host, port, **kw)  # type: ignore[arg-type]
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


def _connection(parts: urllib.parse.SplitResult, timeout: float) -> http.client.HTTPConnection:
    https = parts.scheme == "https"
    host = parts.hostname or ""
    if not PUBLIC_ONLY.get():
        return (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, parts.port, timeout=timeout)  # type: ignore[arg-type]
    ip = resolve_public(host, parts.port or (443 if https else 80))
    return (_PinnedHTTPS if https else _PinnedHTTP)(host, parts.port, ip, timeout=timeout)


def _socket_to(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((resolve_public(host, port) if PUBLIC_ONLY.get() else host, port), timeout=timeout)


def _request(url: str, timeout: float = 15.0, max_redirects: int = 5, accept_encoding: str = "gzip, br") -> Response:
    redirects: list[str] = []
    for _ in range(max_redirects + 1):
        parts = urllib.parse.urlsplit(url)
        conn = _connection(parts, timeout)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        start = time.monotonic()
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html,*/*", "Accept-Encoding": accept_encoding})
        resp = conn.getresponse()
        ttfb = (time.monotonic() - start) * 1000
        body = resp.read(5_000_000)
        total = (time.monotonic() - start) * 1000
        conn.close()
        if resp.status in (301, 302, 303, 307, 308) and resp.getheader("Location"):
            redirects.append(f"{resp.status} {url}")
            url = urllib.parse.urljoin(url, resp.getheader("Location"))
            continue
        return Response(url, resp.status, resp.msg, body, ttfb, total, redirects)
    raise RuntimeError(f"too many redirects from {url}")


def _tls_info(host: str, port: int = 443) -> dict[str, object]:
    ctx = ssl.create_default_context()
    with _socket_to(host, port, 10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            info: dict[str, object] = {"version": tls.version(), "cipher": (tls.cipher() or ("", "", 0))[0]}
            if cert.get("notAfter"):
                exp = datetime.strptime(str(cert["notAfter"]), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info["days_left"] = (exp - datetime.now(timezone.utc)).days
    # does the server still accept TLS 1.0 / 1.1?
    legacy = []
    for ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = ver
            c.maximum_version = ver
            with _socket_to(host, port, 6) as s, c.wrap_socket(s, server_hostname=host):
                legacy.append(ver.name)
        except (ssl.SSLError, OSError, ValueError):
            continue
    info["legacy_accepted"] = legacy
    return info


def audit(url: str) -> tuple[list[Finding], dict[str, object]]:
    if not re.match(r"^https?://", url):
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    findings: list[Finding] = []
    meta: dict[str, object] = {"url": url}

    def F(r, msg, snippet="", sev=None, conf=None):
        f = Finding(r, url, 0, msg, snippet=snippet, extra={"anchor": f"{host}:{r.id}:{snippet[:60]}"})
        if sev is not None:
            f.severity = sev
        if conf is not None:
            f.confidence = conf
        findings.append(f)

    resp = _request(url)
    cold_ttfb = None
    if resp.ttfb_ms > 800:  # serverless cold starts inflate the first sample: measure again
        cold_ttfb = resp.ttfb_ms
        again = _request(resp.url)
        resp = Response(resp.url, again.status, again.headers, again.body, again.ttfb_ms, again.total_ms, resp.redirects)
    h = resp.headers
    meta.update(status=resp.status, final_url=resp.url, ttfb_ms=round(resp.ttfb_ms), total_ms=round(resp.total_ms), bytes=len(resp.body), redirects=resp.redirects)
    if cold_ttfb is not None:
        meta["cold_ttfb_ms"] = round(cold_ttfb)
    final_https = resp.url.startswith("https://")

    # transport
    try:
        plain = _request(f"http://{host}{parts.path or '/'}", timeout=10)
        if not plain.url.startswith("https://"):
            F(R_NO_HTTPS, "http:// is served without redirecting to https://.", snippet=f"http://{host}")
    except (OSError, http.client.HTTPException, RuntimeError):
        pass
    if final_https:
        try:
            tls = _tls_info(urllib.parse.urlsplit(resp.url).hostname or host)
            meta["tls"] = tls
            if tls.get("legacy_accepted"):
                F(R_TLS_OLD, f"Server still negotiates {', '.join(map(str, tls['legacy_accepted']))}.", snippet="legacy TLS")
            days = tls.get("days_left")
            if isinstance(days, int) and days < 21:
                F(R_CERT, f"Certificate expires in {days} days.", snippet=f"{days} days", sev=Severity.HIGH if days < 7 else None)
        except (OSError, ssl.SSLError, ValueError) as exc:
            F(R_TLS_OLD, f"TLS handshake failed with default verification: {exc}", snippet="handshake")
        hsts = h.get("Strict-Transport-Security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if not hsts:
            F(R_HSTS, "No Strict-Transport-Security header.", snippet="HSTS (missing)")
        elif not m or int(m.group(1)) < 15_552_000:
            F(R_HSTS, f"HSTS max-age too short: {hsts}", snippet=hsts[:120], sev=Severity.LOW)
    else:
        F(R_NO_HTTPS, "The final page is served over plain HTTP.", snippet=resp.url)

    # headers
    csp = h.get("Content-Security-Policy", "")
    if not csp:
        ro = h.get("Content-Security-Policy-Report-Only")
        F(R_CSP, "No Content-Security-Policy" + (" (report-only is set, not enforced)." if ro else "."), snippet="CSP (missing)")
    else:
        weak = []
        script_src = re.search(r"script-src([^;]*)", csp) or re.search(r"default-src([^;]*)", csp)
        src = script_src.group(1) if script_src else ""
        if "'unsafe-inline'" in src and "'nonce-" not in src and "'sha256-" not in src and "'strict-dynamic'" not in src:
            weak.append("'unsafe-inline' scripts")
        if "'unsafe-eval'" in src:
            weak.append("'unsafe-eval'")
        if re.search(r"(?:^|\s)(?:\*|https:|http:)(?:\s|$)", src):
            weak.append("wildcard script source")
        if "object-src" not in csp and "default-src 'none'" not in csp:
            weak.append("no object-src")
        if weak:
            F(R_CSP, "CSP present but weak: " + ", ".join(weak) + ".", snippet=csp[:160], sev=Severity.LOW if weak == ["no object-src"] else None)
    if "frame-ancestors" not in csp and not h.get("X-Frame-Options"):
        F(R_FRAME, "Neither frame-ancestors nor X-Frame-Options is set.", snippet="framing allowed")
    if (h.get("X-Content-Type-Options") or "").lower() != "nosniff":
        F(R_NOSNIFF, "X-Content-Type-Options: nosniff missing.", snippet="nosniff (missing)")
    rp = (h.get("Referrer-Policy") or "").lower()
    if not rp or rp in ("unsafe-url", "no-referrer-when-downgrade"):
        F(R_REFERRER, f"Referrer-Policy {'missing' if not rp else rp}.", snippet=rp or "Referrer-Policy (missing)")
    if not h.get("Permissions-Policy"):
        F(R_PERMS, "Permissions-Policy missing.", snippet="Permissions-Policy (missing)")
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        v = h.get(name)
        if v and re.search(r"\d", v):
            F(R_DISCLOSURE, f"{name}: {v}", snippet=f"{name}: {v}"[:120])
    acao = h.get("Access-Control-Allow-Origin")
    if acao == "*":
        has_cookies = bool(h.get_all("Set-Cookie"))
        F(R_CORS, "Access-Control-Allow-Origin: * on the main document" + ("" if has_cookies else " (no cookies set, so impact is limited to readable public content)") + ".",
          snippet="ACAO: *", sev=None if has_cookies else Severity.LOW)

    # cookies
    session_cookie = False
    for raw in h.get_all("Set-Cookie") or []:
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        missing = [flag for flag, present in (("Secure", "; secure" in attrs), ("HttpOnly", "; httponly" in attrs), ("SameSite", "samesite=" in attrs)) if not present]
        sensitive = bool(re.search(r"(?i)sess|auth|token|sid|jwt|login|remember", name))
        session_cookie = session_cookie or sensitive
        if missing and (sensitive or "Secure" in missing):
            F(R_COOKIE, f"Cookie `{name}` missing {', '.join(missing)}.", snippet=name, sev=None if sensitive else Severity.LOW)
    if session_cookie and not re.search(r"no-store|private", h.get("Cache-Control", "")):
        F(R_CACHE, "Session cookie set on a response without Cache-Control: private/no-store.", snippet=h.get("Cache-Control", "(none)"))

    # security.txt
    try:
        st = _request(f"{parts.scheme}://{host}/.well-known/security.txt", timeout=8)
        if st.status != 200 or b"contact:" not in st.body.lower():
            F(R_SECURITY_TXT, "No valid /.well-known/security.txt.", snippet="security.txt")
    except (OSError, http.client.HTTPException, RuntimeError):
        F(R_SECURITY_TXT, "No valid /.well-known/security.txt.", snippet="security.txt")

    # performance
    if resp.ttfb_ms > 800:
        F(R_SLOW, f"TTFB {resp.ttfb_ms:.0f} ms on a warm request.", snippet="slow TTFB", sev=Severity.HIGH if resp.ttfb_ms > 2000 else None)
    elif cold_ttfb is not None and cold_ttfb > 2000:
        F(R_SLOW, f"Cold start: first request took {cold_ttfb:.0f} ms, warm {resp.ttfb_ms:.0f} ms.", snippet="cold start", sev=Severity.LOW)
    ctype = h.get("Content-Type", "")
    enc = h.get("Content-Encoding", "")
    if re.search(r"text/|json|javascript|xml", ctype) and not enc and len(resp.body) > 1500:
        F(R_NO_COMPRESSION, f"{len(resp.body)} bytes sent uncompressed.", snippet=ctype)
    size = len(gzip.decompress(resp.body)) if enc == "gzip" else len(resp.body)
    meta["html_bytes"] = size
    if "html" in ctype and size > 500_000:
        F(R_HEAVY, f"HTML document is {size // 1024} kB.", snippet=f"{size // 1024} kB")
    return findings, meta
