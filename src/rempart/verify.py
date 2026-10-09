"""Live verification of detected credentials (opt-in: `--verify-secrets`).

A leaked key that the provider has already revoked is a history-cleanup task;
a leaked key that still works is an incident. For each supported provider,
Rempart calls one **read-only identity endpoint** (who am I / list models)
with the found credential and classifies it:

    live      the provider accepted it  -> CRITICAL, rotate now
    revoked   the provider rejected it  -> LOW, still purge it from history
    unknown   network error, rate limit, or no endpoint for this provider

Only run this on repositories you own. Nothing is written with the key, and
the key never appears in output; only the identity the provider returns
(account id, login) is reported.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from rempart.netcache import USER_AGENT

Http = Callable[[urllib.request.Request], tuple[int, bytes]]


def default_http(req: urllib.request.Request) -> tuple[int, bytes]:
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed provider endpoints
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536) if exc.fp else b""


@dataclass
class Verdict:
    status: str  # live | revoked | unknown
    detail: str = ""


def _bearer(url: str, token: str, identity: Callable[[dict], str] = lambda d: "", header: str = "Authorization", prefix: str = "Bearer ") -> Callable[[Http], Verdict]:
    def run(http: Http) -> Verdict:
        req = urllib.request.Request(url, headers={header: prefix + token, "Accept": "application/json"})
        status, body = http(req)
        if status in (200, 403):  # 403: valid key without this scope, still live
            try:
                who = identity(json.loads(body or b"{}"))
            except ValueError:
                who = ""
            return Verdict("live", who)
        if status == 401:
            return Verdict("revoked", "rejected by provider (401)")
        return Verdict("unknown", f"HTTP {status}")
    return run


def _slack(token: str) -> Callable[[Http], Verdict]:
    def run(http: Http) -> Verdict:
        status, body = http(urllib.request.Request("https://slack.com/api/auth.test", data=b"", headers={"Authorization": f"Bearer {token}"}))
        try:
            data = json.loads(body)
        except ValueError:
            return Verdict("unknown", f"HTTP {status}")
        if data.get("ok"):
            return Verdict("live", f"team {data.get('team', '?')}, user {data.get('user', '?')}")
        return Verdict("revoked" if data.get("error") in ("invalid_auth", "token_revoked", "account_inactive", "token_expired") else "unknown", str(data.get("error")))
    return run


def _stripe(token: str) -> Callable[[Http], Verdict]:
    basic = base64.b64encode(f"{token}:".encode()).decode()
    return _bearer("https://api.stripe.com/v1/account", basic, lambda d: f"account {d.get('id', '?')}", prefix="Basic ")


# ---------------------------------------------------------------- AWS SigV4 (stdlib)

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_headers(access_key: str, secret_key: str, body: str, when: datetime, host: str = "sts.amazonaws.com",
                  region: str = "us-east-1", service: str = "sts") -> dict[str, str]:
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    day = when.strftime("%Y%m%d")
    content_type = "application/x-www-form-urlencoded; charset=utf-8"
    canonical_headers = f"content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\n"
    signed = "content-type;host;x-amz-date"
    canonical = "\n".join(["POST", "/", "", canonical_headers, signed, hashlib.sha256(body.encode()).hexdigest()])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + secret_key).encode(), day), region), service), "aws4_request")
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Content-Type": content_type,
        "X-Amz-Date": amz_date,
        "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}",
    }


_AWS_SECRET = re.compile(r"(?i)(?:secret[_\-]?(?:access[_\-]?)?key|aws_secret)[\"'\s]*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")


def _aws(access_key: str, file_text: str) -> Callable[[Http], Verdict]:
    def run(http: Http) -> Verdict:
        m = _AWS_SECRET.search(file_text)
        if not m:
            return Verdict("unknown", "no secret access key next to the key ID; cannot verify")
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        headers = sigv4_headers(access_key, m.group(1), body, datetime.now(timezone.utc))
        status, resp = http(urllib.request.Request("https://sts.amazonaws.com/", data=body.encode(), headers=headers, method="POST"))
        text = resp.decode("utf-8", "replace")
        if status == 200:
            acct = re.search(r"<Account>(\d+)</Account>", text)
            arn = re.search(r"<Arn>([^<]+)</Arn>", text)
            return Verdict("live", f"account {acct.group(1) if acct else '?'} ({arn.group(1) if arn else '?'})")
        if re.search(r"InvalidClientTokenId|SignatureDoesNotMatch|ExpiredToken", text):
            return Verdict("revoked", "rejected by AWS STS")
        return Verdict("unknown", f"HTTP {status}")
    return run


def checker(rule_id: str, token: str, file_text: str) -> Callable[[Http], Verdict] | None:
    table: dict[str, Callable[[], Callable[[Http], Verdict]]] = {
        "SEC-AWS-ACCESS-KEY": lambda: _aws(token, file_text),
        "SEC-GITHUB-TOKEN": lambda: _bearer("https://api.github.com/user", token, lambda d: f"GitHub user {d.get('login', '?')}"),
        "SEC-GITLAB-TOKEN": lambda: _bearer("https://gitlab.com/api/v4/personal_access_tokens/self", token, lambda d: f"token '{d.get('name', '?')}' scopes {d.get('scopes')}", header="PRIVATE-TOKEN", prefix=""),
        "SEC-SLACK-TOKEN": lambda: _slack(token),
        "SEC-STRIPE-LIVE": lambda: _stripe(token),
        "SEC-STRIPE-TEST": lambda: _stripe(token),
        "SEC-OPENAI-KEY": lambda: _bearer("https://api.openai.com/v1/models", token, lambda d: "OpenAI key accepted"),
        "SEC-ANTHROPIC-KEY": lambda: _bearer("https://api.anthropic.com/v1/models", token, lambda d: "Anthropic key accepted", header="x-api-key", prefix=""),
        "SEC-HUGGINGFACE-TOKEN": lambda: _bearer("https://huggingface.co/api/whoami-v2", token, lambda d: f"Hugging Face user {d.get('name', '?')}"),
        "SEC-NPM-TOKEN": lambda: _bearer("https://registry.npmjs.org/-/whoami", token, lambda d: f"npm user {d.get('username', '?')}"),
        "SEC-SENDGRID-KEY": lambda: _bearer("https://api.sendgrid.com/v3/scopes", token, lambda d: f"{len(d.get('scopes', []))} scopes"),
        "SEC-DIGITALOCEAN-TOKEN": lambda: _bearer("https://api.digitalocean.com/v2/account", token, lambda d: f"account {(d.get('account') or {}).get('email', '?')}"),
        "SEC-RESEND-KEY": lambda: _bearer("https://api.resend.com/domains", token, lambda d: "Resend key accepted"),
    }
    make = table.get(rule_id)
    return make() if make else None


_cache: dict[tuple[str, str], Verdict] = {}


def verify(rule_id: str, token: str, file_text: str, http: Http = default_http) -> Verdict:
    key = (rule_id, hashlib.sha256(token.encode()).hexdigest())
    if key in _cache:
        return _cache[key]
    run = checker(rule_id, token, file_text)
    if run is None:
        verdict = Verdict("unknown", "no verification endpoint for this provider")
    else:
        try:
            verdict = run(http)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            verdict = Verdict("unknown", f"network error: {exc}")
    _cache[key] = verdict
    return verdict
