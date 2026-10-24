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


def untrusted_ci_input(f: Finding) -> bool:
    return f.rule.id == "GHA-PWN-REQUEST" or (f.rule.id == "GHA-SCRIPT-INJECTION" and not f.extra.get("trusted_input"))


def werkzeug_debug(f: Finding) -> bool:
    """Only the Werkzeug (Flask) debugger offers a console; Django's DEBUG pages do not."""
    return f.rule.id == "CODE-DEBUG-ENABLED" and f.extra.get("framework") == "flask"


# What each piece of evidence means, so a chain's story says only what was found (AUDIT.md R5).
PHRASES = {
    "CODE-TOKEN-LOCALSTORAGE": "auth tokens are stored in localStorage, where any script on the page can read them",
    "CODE-COOKIE-FLAGS": "the session cookie lacks HttpOnly or Secure, so a script or a plain-HTTP request can obtain it",
    "WEB-COOKIE-FLAGS": "the site's session cookie lacks HttpOnly or Secure",
    "K8S-PRIVILEGED": "the workload runs privileged", "COMPOSE-PRIVILEGED": "the container runs privileged",
    "K8S-HOSTPATH": "the workload mounts host paths", "COMPOSE-DOCKER-SOCKET": "the container mounts the Docker socket",
    "K8S-HOST-NAMESPACE": "the workload shares the host's namespaces", "K8S-DANGEROUS-CAPS": "the workload holds dangerous capabilities",
    "GHA-OIDC-UNTRUSTED": "the workflow can mint a cloud OIDC token", "GHA-WRITE-ALL": "the workflow token can write everywhere",
    "GHA-CACHE-IN-PRIVILEGED": "a cache is shared with a privileged job", "GHA-ENV-INJECTION": "untrusted content is written to GITHUB_ENV, which sets the environment of every later step",
    "CI-LONG-LIVED-PUBLISH-TOKEN": "a stored publish token is used", "SEC-NPM-TOKEN": "an npm token is committed",
    "SEC-PYPI-TOKEN": "a PyPI token is committed", "SEC-GITHUB-TOKEN": "a GitHub token is committed",
    "GHA-PWN-REQUEST": "the workflow checks out and runs untrusted pull-request code", "GHA-SCRIPT-INJECTION": "untrusted event text is expanded inside a shell script",
    "TF-IAM-ACCESS-KEY": "a static access key is created for it", "SEC-AWS-ACCESS-KEY": "an AWS access key is committed",
    "TF-EC2-IMDSV1": "its instance metadata answers IMDSv1 requests", "AWS-EC2-IMDSV1": "its instance metadata answers IMDSv1 requests",
    "TF-PROVIDER-STATIC-KEYS": "the provider is configured with static keys",
}


def phrase(f: Finding) -> str:
    return PHRASES.get(f.rule.id) or f.rule.title[:1].lower() + f.rule.title[1:]


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
          "A workflow runs attacker-controlled input with privileges: {0}, and {1}. This is the TanStack (May 2026) and Shai-Hulud pattern.",
          (("untrusted code or text executes", untrusted_ci_input),
           ("privileged effect", ids("GHA-WRITE-ALL", "GHA-OIDC-UNTRUSTED", "GHA-CACHE-IN-PRIVILEGED", "GHA-ENV-INJECTION", "CI-LONG-LIVED-PUBLISH-TOKEN", "SEC-NPM-TOKEN", "SEC-PYPI-TOKEN", "SEC-GITHUB-TOKEN"))),
          "Do not check out or run the triggering pull request's code in a privileged workflow (pull_request_target, workflow_run); pass event text and artifact content through validated step outputs, never GITHUB_ENV; publish with OIDC behind a protected environment.", (A08, A03), "workflow"),
    Chain("CHAIN-RCE-TO-HOST", "Code execution would escape the container to the host", Severity.CRITICAL,
          "A remote-code-execution class weakness exists ({0}), and {1}: a single exploit becomes root on the node and every container on it.",
          (("code execution", kev_or_rce), ("container isolation disabled", ids("K8S-PRIVILEGED", "K8S-HOSTPATH", "COMPOSE-DOCKER-SOCKET", "COMPOSE-PRIVILEGED", "K8S-HOST-NAMESPACE", "K8S-DANGEROUS-CAPS"))),
          "Drop privileged mode, socket and hostPath mounts; then fix the code execution bug.", (A05, A02)),
    Chain("CHAIN-BAAS-TABLE-PUBLIC", "Database table readable and writable by any visitor", Severity.CRITICAL,
          "Row-level security or Firebase rules are missing while the client ships the public key to every browser: anyone can query the table directly, bypassing the app.",
          (("access rules missing", ids("DATA-SUPABASE-RLS-MISSING", "DATA-FIREBASE-OPEN-RULES")), ("public client key in front-end", ids("CTX-BAAS-CLIENT"))),
          "Enable RLS (or lock the Firebase rules) and add explicit per-user policies.", (A01,), "repo"),
    Chain("CHAIN-DEBUG-CONSOLE-EXPOSED", "Debug server reachable from the network", Severity.CRITICAL,
          "The Flask app runs with the Werkzeug debugger on and the server binds every interface: anyone who reaches it gets the debugger's interactive Python console.",
          (("Werkzeug debugger on", werkzeug_debug), ("listening on all interfaces", ids("CTX-BIND-ALL"))),
          "Turn debug off outside local development.", (A02,), "repo"),
    Chain("CHAIN-XSS-SESSION-THEFT", "One XSS steals every user session", Severity.HIGH,
          "HTML is written to the page from dynamic data, and {1}: one injected script is enough to take over sessions.",
          (("XSS sink", ids("CODE-XSS-SINK", "CODE-TEMPLATE-AUTOESCAPE-OFF", "AI-OUTPUT-TO-SINK")), ("token readable by scripts", ids("CODE-TOKEN-LOCALSTORAGE", "CODE-COOKIE-FLAGS", "WEB-COOKIE-FLAGS"))),
          "Move tokens to HttpOnly cookies; sanitize the sink; deploy a nonce-based CSP.", (A05, A07), "repo"),
    Chain("CHAIN-ADMIN-CREDENTIALS-EXPOSED", "Credentials with full cloud admin can leak", Severity.CRITICAL,
          "An identity is granted every action on every resource, and a path exists to its credentials: {1}.",
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


def _same_file(links: list[tuple[str, list[Finding]]]) -> tuple[list[Finding], list[list[str]]] | None:
    """For CI chains: every stage found in one workflow file is one path."""
    paths = set.intersection(*({f.path for f in matched} for _, matched in links))
    for path in sorted(paths):
        chosen = [sorted((f for f in matched if f.path == path), key=lambda f: -f.risk)[0] for _, matched in links]
        return chosen, [[f"same workflow {path}", f"{chosen[i].rule.id}:{chosen[i].line} → {chosen[i + 1].rule.id}:{chosen[i + 1].line}"]
                        for i in range(len(chosen) - 1)]
    return None


def correlate(findings: list[Finding], context: list[Finding] | None = None, graph: Any = None) -> list[Finding]:
    from rempart.filekind import chainable

    # development, example, test, vendored and documentation files cannot be a stage (AUDIT.md R4)
    pool = [f for f in list(findings) + list(context or []) if chainable(f)]
    chains: list[Finding] = []
    for chain in CHAINS:
        links: list[tuple[str, list[Finding]]] = []
        for label, pred in chain.stages:
            matched = [f for f in pool if pred(f)]
            if not matched:
                break
            links.append((label, matched))
        else:
            linked = (_linked_pair(graph, links) if graph is not None and chain.scope == "graph"
                      else _same_file(links) if chain.scope == "workflow" else None)
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
            chosen = linked[0] if linked else [sorted(m, key=lambda f: -f.risk)[0] for _, m in links]
            narrative = chain.narrative.format(*(phrase(f) for f in chosen)) if "{" in chain.narrative else chain.narrative
            if linked:
                route = " ; ".join(graph.describe(p) if chain.scope == "graph" else " → ".join(p) for p in linked[1])
                narrative += f" Connected through: {route}."
            elif graph is not None and chain.scope == "graph":
                narrative = "Both pieces are in this project but no infrastructure link between them was found, so this is a co-occurrence to check, not a proven path. " + narrative
            f = Finding(R_CHAIN[chain.rule_id], first.path, first.line, narrative + " Links → " + " | ".join(parts),
                        snippet=chain.title, extra={"anchor": chain.rule_id + ":" + ",".join(sorted(set(members))[:6]), "members": members,
                                                    "stages": stages, "break_first": chain.break_first})
            if linked:
                f.verification = "linked"
                f.extra["route"] = [graph.describe(p) for p in linked[1]] if chain.scope == "graph" else [" → ".join(p) for p in linked[1]]
            elif graph is not None and chain.scope == "graph":
                f.verification = "co-occurrence"
                f.severity = Severity(max(Severity.MEDIUM, chain.severity - 1))
                f.confidence = 0.5
            elif chain.scope == "workflow":
                f.verification = "co-occurrence"  # the pieces are in different workflows: not one path
                f.severity = Severity(max(Severity.MEDIUM, chain.severity - 1))
                f.confidence = 0.5
            else:
                f.verification = "correlated"
            if f.verification != "linked" and f.severity is not None:
                f.severity = Severity(min(f.severity, Severity.HIGH))  # CRITICAL needs a proven path (AUDIT.md R5)
            chains.append(f)
    return chains
