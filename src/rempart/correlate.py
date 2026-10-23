"""Attack-path correlation.

Single findings are rated in isolation. Real incidents are chains: an SSRF is
"high", IMDSv1 is "high", but SSRF *plus* IMDSv1 in the same deployment is how
the 2019 Capital One breach reached 100 million records. This module looks for
combinations of findings across domains that form a known path to impact and
emits one CRITICAL `attack-path` finding per chain, naming every link and the
cheapest one to break.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from rempart.models import Finding, Severity
from rempart.registry import A01, A02, A03, A05, A07, A08, I, rule


@dataclass(frozen=True)
class Chain:
    rule_id: str
    title: str
    severity: Severity
    narrative: str
    stages: tuple[tuple[str, Callable[[Finding], bool]], ...]  # (stage label, predicate)
    break_first: str
    owasp: tuple[str, ...] = ()
    # "graph": the pieces must be connected through infrastructure (same service, a
    # Terraform reference, a compose dependency) to be a path; "repo": being in the
    # same application is already the link (one front-end, one CI configuration).
    scope: str = "graph"


def ids(*rule_ids: str) -> Callable[[Finding], bool]:
    s = set(rule_ids)
    return lambda f: f.rule.id in s


def prefix(*prefixes: str) -> Callable[[Finding], bool]:
    return lambda f: f.rule.id.startswith(prefixes)


def kev_or_rce(f: Finding) -> bool:
    if f.rule.id == "DEP-VULNERABLE" and (f.extra.get("kev") or (f.extra.get("epss") or 0) >= 0.5):
        return True
    return f.rule.id in ("CODE-CMD-INJECTION", "CODE-EVAL", "CODE-UNSAFE-DESERIALIZATION", "AI-OUTPUT-TO-SINK", "AI-AGENT-SHELL-TOOL", "CODE-TEMPLATE-AUTOESCAPE-OFF")


CHAINS: tuple[Chain, ...] = (
    Chain("CHAIN-SSRF-TO-CLOUD-CREDENTIALS", "SSRF can reach instance metadata credentials", Severity.CRITICAL,
          "Server-side request to a user-supplied URL, on compute where IMDSv1 is allowed: one request returns the instance role's temporary credentials.",
          (("request forgery", ids("CODE-SSRF")), ("metadata v1 reachable", ids("TF-EC2-IMDSV1", "AWS-EC2-IMDSV1"))),
          "Require IMDSv2 (http_tokens = required); it is a one-line change and breaks the chain even before the SSRF is fixed.", (A01,)),
    Chain("CHAIN-EXPOSED-DATASTORE", "Internet-reachable data store with weak protection", Severity.CRITICAL,
          "A database or cache is reachable from the internet and does not enforce authentication or encryption: automated scanners find, copy and wipe such stores within days.",
          (("reachable from the internet", ids("TF-NET-DATA-PORT-OPEN", "COMPOSE-DATA-PORT-PUBLISHED", "K8S-SERVICE-EXPOSED", "TF-DB-PUBLIC", "TF-NET-ALL-PORTS-OPEN", "DATA-ATLAS-OPEN-ACCESS-LIST", "AWS-SG-DATA-PORT-OPEN", "AWS-RDS-PUBLIC", "GCP-FW-DATA-OPEN", "GCP-SQL-AUTHORIZED-ANY", "AZ-NSG-DATA-OPEN", "AZ-SQL-FIREWALL-ANY")),
           ("weak authentication or encryption", ids("DATA-MONGODB-EXPOSED", "DATA-REDIS-EXPOSED", "DATA-POSTGRES-TRUST-AUTH", "DATA-SERVER-HARDENING", "DATA-TLS-DISABLED", "TF-DATA-UNENCRYPTED", "TF-DATA-NO-TLS", "DATA-CONNECTION-STRING-CREDS", "AWS-RDS-UNENCRYPTED", "GCP-SQL-NO-SSL"))),
          "Remove the public exposure first (private subnet, bind to localhost, no published port), then enforce authentication.", (A02, A07)),
    Chain("CHAIN-CI-UNTRUSTED-TO-RELEASE", "Untrusted pull-request input can reach release credentials", Severity.CRITICAL,
          "A workflow runs attacker-controlled code or text with privileges, and the same repository holds publishing power (write token, OIDC, cache shared with a release job, or a stored publish token). This is the TanStack (May 2026) and Shai-Hulud pattern.",
          (("untrusted code or text executes", ids("GHA-PWN-REQUEST", "GHA-SCRIPT-INJECTION")),
           ("publishing power reachable", ids("GHA-WRITE-ALL", "GHA-OIDC-UNTRUSTED", "GHA-CACHE-IN-PRIVILEGED", "CI-LONG-LIVED-PUBLISH-TOKEN", "SEC-NPM-TOKEN", "SEC-PYPI-TOKEN", "SEC-GITHUB-TOKEN"))),
          "Stop checking out PR code in pull_request_target workflows and pass event text through env variables; then move publishing to OIDC trusted publishing behind a protected environment.", (A08, A03), "repo"),
    Chain("CHAIN-RCE-TO-HOST", "Code execution would escape the container to the host", Severity.CRITICAL,
          "A remote-code-execution class weakness exists, and the workload runs privileged, mounts the Docker socket or host paths: a single exploit becomes root on the node and every container on it.",
          (("code execution", kev_or_rce), ("container isolation disabled", ids("K8S-PRIVILEGED", "K8S-HOSTPATH", "COMPOSE-DOCKER-SOCKET", "COMPOSE-PRIVILEGED", "K8S-HOST-NAMESPACE", "K8S-DANGEROUS-CAPS"))),
          "Drop privileged mode, socket and hostPath mounts; then fix the code execution bug.", (A05, A02)),
    Chain("CHAIN-BAAS-TABLE-PUBLIC", "Database table readable and writable by any visitor", Severity.CRITICAL,
          "Row-level security or Firebase rules are missing while the client ships the public key to every browser: anyone can query the table directly, bypassing the app.",
          (("access rules missing", ids("DATA-SUPABASE-RLS-MISSING", "DATA-FIREBASE-OPEN-RULES")), ("public client key in front-end", ids("CTX-BAAS-CLIENT"))),
          "Enable RLS (or lock the Firebase rules) and add explicit per-user policies.", (A01,), "repo"),
    Chain("CHAIN-DEBUG-CONSOLE-EXPOSED", "Debug server reachable from the network", Severity.CRITICAL,
          "Debug mode is on and the server binds every interface: the Werkzeug/Django debug pages leak settings and, for Werkzeug, offer an interactive Python console.",
          (("debug on", ids("CODE-DEBUG-ENABLED")), ("listening on all interfaces", ids("CTX-BIND-ALL"))),
          "Turn debug off outside local development.", (A02,), "repo"),
    Chain("CHAIN-XSS-SESSION-THEFT", "One XSS steals every user session", Severity.HIGH,
          "HTML is written to the DOM from dynamic data while session tokens live in localStorage, readable by any script on the page.",
          (("XSS sink", ids("CODE-XSS-SINK", "CODE-TEMPLATE-AUTOESCAPE-OFF", "AI-OUTPUT-TO-SINK")), ("token readable by scripts", ids("CODE-TOKEN-LOCALSTORAGE", "CODE-COOKIE-FLAGS", "WEB-COOKIE-FLAGS"))),
          "Move tokens to HttpOnly cookies; sanitize the sink; deploy a nonce-based CSP.", (A05, A07), "repo"),
    Chain("CHAIN-ADMIN-CREDENTIALS-EXPOSED", "Credentials with full cloud admin can leak", Severity.CRITICAL,
          "An identity is granted every action on every resource, and a path exists to its credentials (static access key, secret in the repository, metadata endpoint, or OIDC on untrusted triggers).",
          (("full admin", ids("TF-IAM-WILDCARD", "TF-IAM-ADMIN-ATTACHED", "AWS-IAM-ADMIN-POLICY", "AWS-IAM-USER-ADMIN", "GCP-IAM-SA-PRIMITIVE-ROLE", "AZ-RBAC-SP-OWNER")),
           ("credential exposure path", ids("TF-IAM-ACCESS-KEY", "SEC-AWS-ACCESS-KEY", "GHA-OIDC-UNTRUSTED", "TF-EC2-IMDSV1", "TF-PROVIDER-STATIC-KEYS", "AWS-IAM-OLD-ACCESS-KEY", "AWS-EC2-IMDSV1", "GCP-IAM-SA-KEY-OLD", "SEC-GCP-SERVICE-ACCOUNT"))),
          "Scope the policy to the actions actually used (IAM Access Analyzer can generate it), then remove long-lived keys.", (A01, A07)),
    Chain("CHAIN-WORM-PROPAGATION", "Install-time code could republish your packages", Severity.CRITICAL,
          "Code that runs at install time (malicious dependency or remote install script) sits next to a publish token: this is how the Shai-Hulud worms spread from one maintainer to every package they owned.",
          (("install-time execution", ids("DEP-MALICIOUS", "SUPPLY-INSTALL-SCRIPT")), ("publish credential", ids("SEC-NPM-TOKEN", "SEC-PYPI-TOKEN", "SEC-NPMRC-TOKEN", "CI-LONG-LIVED-PUBLISH-TOKEN", "SEC-GITHUB-TOKEN"))),
          "Remove the install-time execution and rotate every token on machines that installed it; switch to trusted publishing.", (A03, A08), "repo"),
)

R_CHAIN = {c.rule_id: rule(c.rule_id, c.title, c.severity, "attack-path", owasp=c.owasp,
                          fix=c.break_first, confidence=0.9) for c in CHAINS}

# Context signals: facts that are not weaknesses on their own but complete a chain.
R_CTX_BAAS = rule("CTX-BAAS-CLIENT", "Front-end BaaS client with public key (context)", I, "data", fix="Context signal used to build attack paths; never reported alone.", confidence=1.0)
R_CTX_BIND = rule("CTX-BIND-ALL", "Server binds all interfaces (context)", I, "code", fix="Context signal used to build attack paths; never reported alone.", confidence=1.0)
_BAAS_CLIENT = re.compile(r"createClient\(\s*[^)]*(?:SUPABASE|supabase)|initializeApp\(\s*\{[^}]*apiKey|PUBLIC_SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE")
_BIND_ALL = re.compile(r"""host\s*=\s*["']0\.0\.0\.0["']|--host[ =]0\.0\.0\.0|\.listen\([^)]*["']0\.0\.0\.0["']|runserver\s+0\.0\.0\.0""")


def context_signals(files: Iterable[str], read: Callable[[str], str | None]) -> list[Finding]:
    """Cheap repository facts used as chain links (never reported on their own)."""
    ctx_rules = {"CTX-BAAS-CLIENT": R_CTX_BAAS, "CTX-BIND-ALL": R_CTX_BIND}
    out: list[Finding] = []
    for rel in files:
        if not rel.endswith((".js", ".jsx", ".ts", ".tsx", ".svelte", ".vue", ".py", ".env.example", ".json", "Dockerfile", ".yml", ".yaml")):
            continue
        text = read(rel) or ""
        for rid, rx in (("CTX-BAAS-CLIENT", _BAAS_CLIENT), ("CTX-BIND-ALL", _BIND_ALL)):
            m = rx.search(text)
            if m:
                out.append(Finding(ctx_rules[rid], rel, text.count("\n", 0, m.start()) + 1, ctx_rules[rid].title, snippet=m.group(0)[:120]))
    return out


def _linked_pair(graph: Any, links: list[tuple[str, list[Finding]]]) -> tuple[list[Finding], list[list[str]]] | None:
    """Pick one finding per stage so that consecutive stages are connected in the resource graph."""
    def walk(stage: int, chosen: list[Finding], paths: list[list[str]]) -> tuple[list[Finding], list[list[str]]] | None:
        if stage == len(links):
            return chosen, paths
        for f in sorted(links[stage][1], key=lambda x: -x.risk)[:40]:
            if chosen:
                p = graph.link(chosen[-1], f)
                if p is None:
                    continue
                found = walk(stage + 1, chosen + [f], paths + [p])
            else:
                found = walk(stage + 1, [f], paths)
            if found:
                return found
        return None

    return walk(0, [], [])


def correlate(findings: list[Finding], context: list[Finding] | None = None, graph: Any = None) -> list[Finding]:
    pool = list(findings) + list(context or [])
    chains: list[Finding] = []
    for chain in CHAINS:
        links: list[tuple[str, list[Finding]]] = []
        for label, pred in chain.stages:
            matched = [f for f in pool if pred(f)]
            if not matched:
                break
            links.append((label, matched))
        else:
            linked = _linked_pair(graph, links) if graph is not None and chain.scope == "graph" else None
            parts = []
            stages: list[dict[str, Any]] = []
            members: list[str] = []
            for idx, (label, matched) in enumerate(links):
                best = linked[0][idx] if linked else sorted(matched, key=lambda f: -f.risk)[0]
                where = f"{best.path}:{best.line}" if best.line else best.path
                more = f" (+{len(matched) - 1} more)" if len(matched) > 1 and not linked else ""
                parts.append(f"{label}: {best.rule.id} at {where}{more}")
                stages.append({"label": label, "rule": best.rule.id, "title": best.rule.title, "where": where,
                               "fingerprint": best.fingerprint, "others": 0 if linked else len(matched) - 1})
                members += [f.fingerprint for f in ([best] if linked else matched) if not f.rule.id.startswith("CTX-")]
            first = linked[0][0] if linked else links[0][1][0]
            narrative = chain.narrative
            if linked:
                route = " ; ".join(graph.describe(p) for p in linked[1])
                narrative += f" Connected through: {route}."
            elif graph is not None and chain.scope == "graph":
                narrative = "Both pieces are in this project but no infrastructure link between them was found, so this is a co-occurrence to check, not a proven path. " + narrative
            f = Finding(R_CHAIN[chain.rule_id], first.path, first.line, narrative + " Links → " + " | ".join(parts),
                        snippet=chain.title, extra={"anchor": chain.rule_id + ":" + ",".join(sorted(set(members))[:6]), "members": members,
                                                    "stages": stages, "break_first": chain.break_first})
            if linked:
                f.verification = "linked"
                f.extra["route"] = [graph.describe(p) for p in linked[1]]
            elif graph is not None and chain.scope == "graph":
                f.verification = "co-occurrence"
                f.severity = Severity(max(Severity.MEDIUM, chain.severity - 1))
                f.confidence = 0.5
            else:
                f.verification = "correlated"
            chains.append(f)
    return chains
