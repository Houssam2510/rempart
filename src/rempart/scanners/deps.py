"""Software composition analysis and supply-chain hygiene.

Known vulnerabilities come from OSV.dev (which aggregates GitHub advisories,
PyPA, Go, RustSec, and the OpenSSF malicious-packages feed). Each CVE is then
enriched with exploitation evidence: CISA KEV (confirmed exploited) and FIRST
EPSS (predicted probability of exploitation in the next 30 days). The same
approach as Houssam2510/triage, applied to application dependencies.
"""

from __future__ import annotations

import json
import math
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterator

from rempart.engine import ScanContext
from rempart.models import Finding, Severity
from rempart.netcache import NetworkError, safe_get_json
from rempart.registry import A03, A08, C, H, I, M, rule
from rempart.scanners.lockfiles import Package, parser_for

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"

R_VULN = rule("DEP-VULNERABLE", "Dependency with a known vulnerability", H, "dependencies", cwe="CWE-1395", owasp=A03,
              frameworks=("CICD-SEC-3 Dependency Chain Abuse",),
              fix="Upgrade to a fixed version. Prioritise by exploitation evidence: KEV-listed first, then high EPSS, then CVSS.",
              confidence=0.95)
R_MALICIOUS = rule("DEP-MALICIOUS", "Known malicious package version", C, "dependencies", cwe="CWE-506", owasp=A03,
                   frameworks=("CICD-SEC-3 Dependency Chain Abuse",),
                   fix="Remove the package, rotate every credential that was present on machines and CI runners that installed it, and audit for persistence.",
                   confidence=0.99)
R_INSTALL_SCRIPT = rule("SUPPLY-INSTALL-SCRIPT", "Lifecycle script downloads or executes remote code", H, "supply-chain", cwe=("CWE-494", "CWE-829"), owasp=(A03, A08),
                        frameworks=("CICD-SEC-3 Dependency Chain Abuse",),
                        fix="Do not fetch-and-run code from install hooks. Vendor the asset with a checksum, or move the step to an explicit, reviewed build script.")
R_UNPINNED = rule("SUPPLY-UNPINNED", "Dependency resolved from a mutable source", M, "supply-chain", cwe=("CWE-1357", "CWE-829"), owasp=A03,
                  fix="Pin exact versions in a committed lockfile. Avoid '*', 'latest', branch URLs and tarball links that can change under you.")
R_NO_LOCK = rule("SUPPLY-NO-LOCKFILE", "Manifest without a committed lockfile", M, "supply-chain", cwe="CWE-1357", owasp=A03,
                 fix="Commit the lockfile and install with `npm ci` / `pnpm install --frozen-lockfile` so every build gets the exact versions you reviewed.")
R_CONFUSION = rule("SUPPLY-DEPENDENCY-CONFUSION", "Extra package index allows dependency confusion", H, "supply-chain", cwe="CWE-427", owasp=A03,
                   fix="Use a single index (a proxy that serves both private and public packages) or pin private names to their index; never mix --extra-index-url with private package names.",
                   refs=("https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",))
R_INSECURE_REGISTRY = rule("SUPPLY-INSECURE-REGISTRY", "Packages fetched over plain HTTP", H, "supply-chain", cwe=("CWE-319", "CWE-494"), owasp=(A03, A08),
                           fix="Use https:// registry URLs and keep integrity hashes in the lockfile.")
R_TYPOSQUAT = rule("SUPPLY-TYPOSQUAT", "Dependency name one edit away from a popular package", H, "supply-chain", cwe="CWE-1357", owasp=A03,
                   fix="Check the name character by character. If it is not the package you meant, remove it and treat the machine as compromised.",
                   confidence=0.45)
R_OSV_DOWN = rule("DEP-LOOKUP-SKIPPED", "Vulnerability lookup skipped", I, "dependencies",
                  fix="Run again with network access to query OSV.dev.", confidence=1.0)

# Popular package names used for typosquat distance checks.
POPULAR_NPM = """react react-dom next vue svelte @sveltejs/kit express lodash axios moment dayjs chalk commander
debug request typescript webpack vite rollup esbuild babel-core @babel/core eslint prettier jest mocha vitest
dotenv cors body-parser jsonwebtoken bcrypt bcryptjs mongoose mongodb pg mysql mysql2 redis ioredis sequelize
prisma @prisma/client knex uuid nanoid zod yup joi socket.io ws node-fetch cross-env rimraf glob minimist yargs
inquirer ora colors underscore async bluebird rxjs tslib core-js classnames styled-components tailwindcss
postcss autoprefixer sass less nodemon pm2 helmet passport multer sharp puppeteer playwright cheerio jquery
bootstrap three d3 chart.js stripe openai @anthropic-ai/sdk aws-sdk @aws-sdk/client-s3 firebase firebase-admin
@supabase/supabase-js graphql apollo-server @apollo/client redux @reduxjs/toolkit zustand immer date-fns
luxon validator qs semver fs-extra mkdirp chokidar ethers web3 electron better-auth resend nodemailer
@tanstack/react-query @tanstack/query-core tanstack""".split()
POPULAR_PYPI = """requests numpy pandas scipy matplotlib django flask fastapi uvicorn gunicorn pydantic sqlalchemy
psycopg2 psycopg2-binary pymongo redis celery boto3 botocore urllib3 certifi idna charset-normalizer
setuptools wheel pip six python-dateutil pytz pyyaml jinja2 markupsafe click colorama tqdm pillow
cryptography pyjwt bcrypt paramiko scikit-learn tensorflow torch transformers openai anthropic langchain
httpx aiohttp beautifulsoup4 lxml selenium pytest black ruff mypy rich typer dotenv python-dotenv
attrs packaging virtualenv docker kubernetes google-cloud-storage azure-storage-blob litellm""".split()


def _dl1(a: str, b: str) -> bool:
    """True when a and b are within Damerau-Levenshtein distance 1 (and differ)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    s, t = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == t[i]:
        i += 1
    return s[i:] == t[i + 1:]


# ---------------------------------------------------------------- CVSS v3.x base score

_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_base(vector: str) -> float | None:
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        cia = [_CVSS_W["C"][m[k]] for k in ("C", "I", "A")]
        iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _CVSS_W["AV"][m["AV"]] * _CVSS_W["AC"][m["AC"]] * pr * _CVSS_W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return math.ceil(raw * 10 - 1e-9) / 10
    except (KeyError, ValueError, IndexError):
        return None


def _sev_from_score(score: float) -> Severity:
    return Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else Severity.MEDIUM if score >= 4 else Severity.LOW if score > 0 else Severity.INFO


def vuln_severity(v: dict[str, Any]) -> tuple[Severity, float | None]:
    label = str((v.get("database_specific") or {}).get("severity", "")).upper()
    score = None
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base(str(s.get("score", "")))
            if score is not None:
                break
    if label in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}[label], score
    if score is not None:
        return _sev_from_score(score), score
    return Severity.MEDIUM, None


def fixed_versions(v: dict[str, Any], pkg: Package) -> list[str]:
    out: list[str] = []
    for aff in v.get("affected") or []:
        p = aff.get("package") or {}
        if str(p.get("name", "")).lower() != pkg.name.lower():
            continue
        if p.get("ecosystem") and str(p["ecosystem"]) != pkg.ecosystem:
            continue  # a fix for Debian 12 says nothing about the Debian 13 package
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in out:
                    out.append(str(ev["fixed"]))
    return out


# ---------------------------------------------------------------- scanner

class DependencyScanner:
    name = "dependencies"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        packages = self.collect(ctx)
        yield from self.hygiene(ctx, packages)
        if not packages:
            return
        if ctx.offline:
            yield Finding(R_OSV_DOWN, packages[0].path, 0, f"{len(packages)} packages not checked (offline mode).", extra={"anchor": "offline"})
            return
        try:
            yield from self.with_reachability(ctx, self.vulnerabilities(packages))
        except NetworkError as exc:
            yield Finding(R_OSV_DOWN, packages[0].path, 0, f"OSV.dev unreachable: {exc}", extra={"anchor": "network"})

    @staticmethod
    def with_reachability(ctx: ScanContext, findings: Iterator[Finding]) -> Iterator[Finding]:
        from rempart.reachability import classify, direct_dependencies, imported_names

        imported = imported_names(ctx.files, ctx.text)
        direct = direct_dependencies(ctx.files, ctx.text)
        for f in findings:
            eco, name = f.extra.get("ecosystem"), f.extra.get("package")
            if eco and name and f.rule is R_VULN:
                is_direct, is_imported = classify(str(eco), str(name), imported, direct)
                if is_imported is not None:
                    f.extra["direct"], f.extra["imported"] = is_direct, is_imported
                    if is_imported:
                        f.verification = "reachable"
                        f.message += " — imported by your code"
                    elif is_direct:
                        f.verification = "declared"
                    else:
                        f.verification = "not-imported"
                        f.confidence = round((f.confidence or 0.9) * 0.6, 2)
                        f.message += " — transitive, not imported directly"
            yield f

    @staticmethod
    def collect(ctx: ScanContext) -> list[Package]:
        seen: dict[tuple[str, str, str], Package] = {}
        for rel in ctx.files:
            parser = parser_for(os.path.basename(rel))
            if parser is None:
                continue
            text = ctx.text(rel)
            if not text:
                continue
            try:
                for p in parser(rel, text):
                    seen.setdefault((p.ecosystem, p.name.lower() if p.ecosystem == "PyPI" else p.name, p.version), p)
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
        return list(seen.values())

    def vulnerabilities(self, packages: list[Package]) -> Iterator[Finding]:
        hits: list[tuple[Package, str]] = []
        for start in range(0, len(packages), 500):
            chunk = packages[start:start + 500]
            payload = {"queries": [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk]}
            res = safe_get_json(OSV_BATCH, data=payload, ttl=6 * 3600)
            for pkg, r in zip(chunk, res.get("results", [])):
                for v in r.get("vulns") or []:
                    hits.append((pkg, v["id"]))
        if not hits:
            return
        ids = sorted({vid for _, vid in hits})
        with ThreadPoolExecutor(max_workers=8) as pool:
            details = dict(zip(ids, pool.map(lambda i: _try(lambda: safe_get_json(OSV_VULN.format(i), ttl=3 * 86400)), ids)))
        cves = sorted({c for d in details.values() if d for a in (d.get("aliases") or []) + (d.get("upstream") or []) + [d.get("id", "")]
                       for c in re.findall(r"CVE-\d{4}-\d{4,}", str(a))})
        kev = _load_kev()
        epss = _load_epss(cves)
        # Collapse advisories that are aliases of each other (GHSA + PYSEC for one CVE).
        emitted: set[tuple[str, str, str]] = set()
        for pkg, vid in hits:
            d = details.get(vid) or {"id": vid}
            aliases = [a for a in (d.get("aliases") or []) + (d.get("upstream") or []) if a]
            cve_ids = [a for a in aliases + [vid] if a.startswith("CVE-")]
            cve_ids += [c for c in re.findall(r"CVE-\d{4}-\d{4,}", vid) if c not in cve_ids]  # DEBIAN-CVE-…, UBUNTU-CVE-…
            key = (pkg.name, pkg.version, cve_ids[0] if cve_ids else vid)
            if key in emitted:
                continue
            emitted.add(key)
            if vid.startswith("MAL-"):
                yield Finding(R_MALICIOUS, pkg.path, pkg.line, f"{pkg.name}@{pkg.version} is a known malicious release ({vid}).",
                              snippet=f"{pkg.name}@{pkg.version}", extra={"anchor": f"{pkg.ecosystem}:{pkg.name}:{pkg.version}:{vid}", "package": pkg.name,
                                                                          "version": pkg.version, "ecosystem": pkg.ecosystem, "advisory": vid})
                continue
            sev, cvss = vuln_severity(d)
            in_kev = any(c in kev for c in cve_ids)
            e = max((epss.get(c, 0.0) for c in cve_ids), default=0.0)
            if in_kev:
                sev = Severity.CRITICAL
            fixes = fixed_versions(d, pkg)
            summary = (d.get("summary") or d.get("details") or "").strip().splitlines()[0][:140] if (d.get("summary") or d.get("details")) else ""
            label = vid + (f" / {cve_ids[0]}" if cve_ids and cve_ids[0] != vid else "")
            parts = [f"{pkg.name}@{pkg.version}: {label}"]
            if summary:
                parts.append(summary)
            if fixes:
                parts.append(f"fixed in {', '.join(fixes[:3])}")
            if in_kev:
                parts.append("exploited in the wild (CISA KEV)")
            elif e >= 0.1:
                parts.append(f"EPSS {e:.0%}")
            f = Finding(R_VULN, pkg.path, pkg.line, " — ".join(parts), snippet=f"{pkg.name}@{pkg.version}",
                        extra={"anchor": f"{pkg.ecosystem}:{pkg.name}:{pkg.version}:{key[2]}", "package": pkg.name, "version": pkg.version,
                               "ecosystem": pkg.ecosystem, "advisory": vid, "aliases": aliases, "fixed": fixes, "cvss": cvss,
                               "epss": round(e, 4), "kev": in_kev, "published": str(d.get("published", ""))[:10]})
            f.severity = sev
            yield f

    # ------------------------------------------------------------ offline hygiene
    def hygiene(self, ctx: ScanContext, packages: list[Package]) -> Iterator[Finding]:
        for rel in ctx.by_name("package.json"):
            if "node_modules/" in rel:
                continue
            text = ctx.text(rel) or ""
            try:
                manifest = json.loads(text)
            except ValueError:
                continue
            lines = text.splitlines()

            def ln(needle: str) -> int:
                for i, l in enumerate(lines, 1):
                    if needle in l:
                        return i
                return 1

            for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
                cmd = str((manifest.get("scripts") or {}).get(hook, ""))
                if re.search(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64\s+-d|\|\s*(?:sh|bash)\b", cmd):
                    yield Finding(R_INSTALL_SCRIPT, rel, ln(f'"{hook}"'), f"`{hook}` script runs: {cmd[:120]}", snippet=f'"{hook}": "{cmd[:120]}"')
            dirname = os.path.dirname(rel)
            has_lock = any(os.path.join(dirname, lf).lstrip("/") in ctx.files for lf in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "npm-shrinkwrap.json"))
            deps = {**(manifest.get("dependencies") or {}), **(manifest.get("devDependencies") or {}), **(manifest.get("optionalDependencies") or {})}
            if deps and not has_lock and not manifest.get("workspaces") and not _has_ancestor_lock(ctx, dirname):
                yield Finding(R_NO_LOCK, rel, 1, "Dependencies declared but no lockfile is committed next to this package.json.", snippet="package.json")
            for name, spec in deps.items():
                spec = str(spec)
                if spec in ("*", "latest", "x", "") or re.match(r"^(?:git(?:\+\w+)?://|git@|https?://|github:|[\w.-]+/[\w.-]+(?:#.*)?$)", spec):
                    f = Finding(R_UNPINNED, rel, ln(f'"{name}"'), f"{name} → {spec!r} can change without a code change.", snippet=f'"{name}": "{spec}"')
                    if has_lock:
                        f.severity = Severity.LOW
                    yield f
                if name not in POPULAR_NPM and not name.startswith("@types/"):
                    for pop in POPULAR_NPM:
                        if _dl1(name.lower(), pop):
                            yield Finding(R_TYPOSQUAT, rel, ln(f'"{name}"'), f"`{name}` is one edit away from the popular package `{pop}`.", snippet=f'"{name}"')
                            break
        for rel in ctx.files:
            base = os.path.basename(rel)
            if parser_for(base) is not None and base.startswith(("requirements", "constraints")) or base in ("pip.conf", ".pip.conf", "pip.ini"):
                for i, line in enumerate(ctx.lines(rel), 1):
                    if re.search(r"--extra-index-url|^\s*extra-index-url\s*=", line):
                        yield Finding(R_CONFUSION, rel, i, "--extra-index-url lets a public package shadow a private one with the same name.", snippet=line.strip())
                    if re.search(r"--(?:index-url|extra-index-url|trusted-host)\s+http://|index-url\s*=\s*http://", line):
                        yield Finding(R_INSECURE_REGISTRY, rel, i, "Python packages fetched over HTTP.", snippet=line.strip())
                    if base.startswith("requirements") and (m := re.match(r"^\s*([A-Za-z0-9][\w.\-]*)\s*(?:$|[<>~!]=?|\[)", line)):
                        name = m.group(1).lower()
                        if name not in POPULAR_PYPI:
                            for pop in POPULAR_PYPI:
                                if _dl1(name, pop):
                                    yield Finding(R_TYPOSQUAT, rel, i, f"`{name}` is one edit away from the popular package `{pop}`.", snippet=line.strip())
                                    break
                        yield Finding(R_UNPINNED, rel, i, f"{m.group(1)} has no exact version pin.", snippet=line.strip(), severity=Severity.LOW)
            if base in (".npmrc", ".yarnrc", ".yarnrc.yml"):
                for i, line in enumerate(ctx.lines(rel), 1):
                    if re.search(r"registry\s*[=:]\s*[\"']?http://|npmRegistryServer\s*:\s*[\"']?http://", line):
                        yield Finding(R_INSECURE_REGISTRY, rel, i, "npm registry over HTTP.", snippet=line.strip())
            if base == "package-lock.json":
                for i, line in enumerate(ctx.lines(rel), 1):
                    if '"resolved": "http://' in line:
                        yield Finding(R_INSECURE_REGISTRY, rel, i, "Package tarball resolved over HTTP.", snippet=line.strip()[:200])
                        break


def _has_ancestor_lock(ctx: ScanContext, dirname: str) -> bool:
    parts = dirname.split("/") if dirname else []
    while parts:
        parts.pop()
        prefix = "/".join(parts)
        for lf in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"):
            if (f"{prefix}/{lf}" if prefix else lf) in ctx.files:
                return True
    return False


def _try(fn: Any) -> Any:
    try:
        return fn()
    except NetworkError:
        return None


def _load_kev() -> set[str]:
    try:
        data = safe_get_json(KEV_URL, ttl=12 * 3600, timeout=60)
    except NetworkError:
        return set()
    return {v.get("cveID", "") for v in data.get("vulnerabilities", [])}


def _load_epss(cves: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for start in range(0, len(cves), 80):
        chunk = cves[start:start + 80]
        try:
            data = safe_get_json(EPSS_URL.format(",".join(chunk)), ttl=24 * 3600)
        except NetworkError:
            continue
        for row in data.get("data", []):
            try:
                out[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError):
                continue
    return out
