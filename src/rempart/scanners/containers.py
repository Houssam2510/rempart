"""Dockerfile and docker-compose checks."""

from __future__ import annotations

import os
import re
from typing import Any, Iterator

import yaml

from rempart.engine import ScanContext
from rempart.models import Finding, Severity
from rempart.registry import A02, A03, A07, A08, C, H, L, M, rule

K01 = "K01:2025 Insecure Workload Configurations"

R_ROOT = rule("DOCKER-RUNS-AS-ROOT", "Container runs as root", M, "containers", cwe="CWE-250", owasp=A02, frameworks=(K01,),
              fix="Create an unprivileged user and add `USER app` (or a numeric UID) after installing packages.")
R_LATEST = rule("DOCKER-UNPINNED-BASE", "Base image not pinned", M, "containers", cwe="CWE-1357", owasp=(A03, A08),
                fix="Pin a specific tag and, for reproducibility and tamper-resistance, a digest: `FROM node:22.11-alpine@sha256:...`.")
R_PIPE_SHELL = rule("DOCKER-CURL-PIPE-SHELL", "Remote script piped into a shell", H, "containers", cwe="CWE-494", owasp=(A03, A08),
                    fix="Download to a file, verify a pinned checksum or signature, then execute.")
R_ADD_URL = rule("DOCKER-ADD-REMOTE", "ADD fetches a remote URL without verification", M, "containers", cwe="CWE-494", owasp=A08,
                 fix="Use `ADD --checksum=sha256:...` or download with curl and verify the hash.")
R_SECRET_ENV = rule("DOCKER-SECRET-IN-IMAGE", "Secret baked into the image", H, "containers", cwe=("CWE-798", "CWE-538"), owasp=A07,
                    fix="ENV and ARG values persist in image layers and `docker history`. Use BuildKit secrets (`RUN --mount=type=secret`) or inject at runtime.")
R_CHMOD = rule("DOCKER-WORLD-WRITABLE", "World-writable permissions", M, "containers", cwe="CWE-732", owasp=A02, fix="Grant the minimum permissions needed (e.g. 755/644) to the owning user.")
R_SSH = rule("DOCKER-SSH-EXPOSED", "SSH server exposed in container", M, "containers", cwe="CWE-668", owasp=A02, fix="Do not run sshd in containers; use `docker exec` / `kubectl exec` with RBAC.")
R_NO_DOCKERIGNORE = rule("DOCKER-NO-DOCKERIGNORE", "Whole context copied without a .dockerignore", M, "containers", cwe="CWE-538", owasp=A02,
                         fix="Add a .dockerignore excluding .git, .env*, node_modules, keys and local data so they never land in an image layer.")
R_NO_HEALTH = rule("DOCKER-NO-HEALTHCHECK", "No HEALTHCHECK", L, "containers", cwe="CWE-1188", owasp=A02,
                   fix="Add a HEALTHCHECK so orchestrators restart hung containers instead of routing traffic to them.", confidence=0.5)
R_BUILD_PERF = rule("DOCKER-IMAGE-BLOAT", "Image build leaves caches or extra packages", L, "performance",
                    fix="Use --no-install-recommends, clean apt lists in the same layer, pip --no-cache-dir, and `npm ci --omit=dev` in a multi-stage build.",
                    confidence=0.6)
R_NPM_INSTALL = rule("DOCKER-NONREPRODUCIBLE-INSTALL", "Non-reproducible dependency install in image", L, "containers", cwe="CWE-1357", owasp=A03,
                     fix="Use `npm ci` / `pnpm install --frozen-lockfile` / `pip install -r requirements.txt --require-hashes`.", confidence=0.6)
R_COMPOSE_PRIV = rule("COMPOSE-PRIVILEGED", "Compose service with host-level privileges", H, "containers", cwe="CWE-250", owasp=A02, frameworks=(K01,),
                      fix="Remove privileged/host network/host PID and the Docker socket mount; add only the capabilities the service needs.")
R_COMPOSE_SOCK = rule("COMPOSE-DOCKER-SOCKET", "Docker socket mounted into a container", C, "containers", cwe="CWE-250", owasp=A02, frameworks=(K01,),
                      fix="Access to /var/run/docker.sock is root on the host. Use a socket proxy with an allow-list, or remove it.")
R_COMPOSE_DB_PORT = rule("COMPOSE-DATA-PORT-PUBLISHED", "Database port published on all interfaces", H, "data", cwe="CWE-668", owasp=A02,
                         fix="Bind to localhost (`127.0.0.1:5432:5432`) or do not publish the port; services on the compose network reach each other by name. Docker-published ports bypass host firewalls such as ufw.")
R_COMPOSE_SECRET = rule("COMPOSE-SECRET-LITERAL", "Credential written in docker-compose", H, "secrets", cwe="CWE-798", owasp=A07,
                        fix="Use an env_file that is git-ignored, `${VAR}` substitution, or compose secrets.")

_SECRET_NAME = re.compile(r"(?i)(?:password|passwd|secret|token|api_?key|access_?key|private_?key|credentials?)")
_DEV_DEFAULTS = {"postgres", "password", "example", "secret", "root", "admin", "changeme", "mysql", "mongo", "redis", "test", "dev", "local", "pass", "guest"}
_DATA_PORTS = {"3306", "5432", "27017", "6379", "9200", "11211", "1433", "5984", "9042", "8086", "7474", "5672", "9092", "2181", "8123"}


class ContainerScanner:
    name = "containers"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.files:
            base = os.path.basename(rel)
            if base == "Dockerfile" or base.startswith("Dockerfile.") or base.endswith((".Dockerfile", ".dockerfile")) or base == "Containerfile":
                yield from self.dockerfile(ctx, rel)
            elif re.fullmatch(r"(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml", base):
                yield from self.compose(ctx, rel)

    def dockerfile(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        raw_lines = ctx.lines(rel)
        # join continuation lines, remembering the first line number
        instrs: list[tuple[int, str]] = []
        buf, start = "", 0
        for i, line in enumerate(raw_lines, 1):
            s = line.strip()
            if not buf and (not s or s.startswith("#")):
                continue
            if not buf:
                start = i
            buf += " " + s.rstrip("\\")
            if not s.endswith("\\"):
                instrs.append((start, buf.strip()))
                buf = ""
        if buf:
            instrs.append((start, buf.strip()))
        stages = [n for n, ins in instrs if ins.upper().startswith("FROM ")]
        last_stage_start = stages[-1] if stages else 0
        user_after_last_from = None
        has_health = False
        stage_aliases = set()
        for n, ins in instrs:
            op, _, arg = ins.partition(" ")
            op = op.upper()
            arg = arg.strip()
            if op == "FROM":
                m = re.match(r"(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", arg, re.I)
                if m:
                    image = m.group(1)
                    if m.group(2):
                        stage_aliases.add(m.group(2).lower())
                    if image.lower() in stage_aliases or image == "scratch" or image.startswith("$"):
                        continue
                    if "@sha256:" in image:
                        continue
                    name_tag = image.rsplit("/", 1)[-1]
                    if ":" not in name_tag or name_tag.endswith(":latest"):
                        yield Finding(R_LATEST, rel, n, f"`{image}` floats to whatever `latest` points at.", snippet=ins[:200])
                    else:
                        yield Finding(R_LATEST, rel, n, f"`{image}` is tag-pinned but not digest-pinned.", snippet=ins[:200], severity=Severity.INFO, confidence=0.5)
            elif op == "USER" and n >= last_stage_start:
                user_after_last_from = arg
            elif op == "HEALTHCHECK":
                has_health = True
            elif op in ("ENV", "ARG"):
                for m in re.finditer(r"([A-Za-z_][\w]*)(?:\s*=\s*|\s+)(\"[^\"]*\"|'[^']*'|\S+)?", arg):
                    key, val = m.group(1), (m.group(2) or "").strip("\"'")
                    if _SECRET_NAME.search(key) and val and not val.startswith("$") and len(val) >= 4:
                        yield Finding(R_SECRET_ENV, rel, n, f"{op} {key} has a literal value.", snippet=f"{op} {key}=****")
            elif op == "ADD" and re.search(r"https?://", arg) and "--checksum" not in arg:
                yield Finding(R_ADD_URL, rel, n, "ADD downloads a URL with no checksum.", snippet=ins[:200])
            elif op == "EXPOSE" and re.search(r"\b22\b", arg):
                yield Finding(R_SSH, rel, n, "Port 22 exposed.", snippet=ins[:200])
            if op == "RUN":
                if re.search(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", arg):
                    yield Finding(R_PIPE_SHELL, rel, n, "Download piped straight into a shell.", snippet=ins[:200])
                if re.search(r"chmod\s+(?:-R\s+)?(?:0?777|a\+rwx|o\+w)", arg):
                    yield Finding(R_CHMOD, rel, n, "chmod 777 / o+w.", snippet=ins[:200])
                bloat = []
                if "apt-get install" in arg and "--no-install-recommends" not in arg:
                    bloat.append("apt-get without --no-install-recommends")
                if "apt-get install" in arg and "rm -rf /var/lib/apt/lists" not in arg:
                    bloat.append("apt lists not cleaned in the same layer")
                if re.search(r"\bpip3?\s+install\b", arg) and "--no-cache-dir" not in arg:
                    bloat.append("pip cache kept")
                if re.search(r"\bapk\s+add\b", arg) and "--no-cache" not in arg:
                    bloat.append("apk cache kept")
                if bloat:
                    yield Finding(R_BUILD_PERF, rel, n, "; ".join(bloat) + ".", snippet=ins[:200])
                if re.search(r"\bnpm\s+install\b(?!\s+-g)", arg) or re.search(r"\byarn\s+install\b(?!.*--(?:frozen-lockfile|immutable))", arg):
                    yield Finding(R_NPM_INSTALL, rel, n, "Install not locked to the lockfile.", snippet=ins[:200])
            if op == "COPY" and re.match(r"(?:--\S+\s+)*\.\s+\S+", arg):
                d = os.path.dirname(rel)
                if not any(x in ctx.files for x in (os.path.join(d, ".dockerignore").lstrip("/"), ".dockerignore", rel + ".dockerignore")):
                    yield Finding(R_NO_DOCKERIGNORE, rel, n, "`COPY . ...` with no .dockerignore: .git, .env and local files end up in the image.", snippet=ins[:200])
        if instrs and (user_after_last_from is None or user_after_last_from.split(":")[0] in ("root", "0")):
            if not any(re.match(r"FROM\s+\S*(?:distroless|chainguard)\S*(?::nonroot|-nonroot)", ins, re.I) for _, ins in instrs):
                yield Finding(R_ROOT, rel, last_stage_start or 1, "Final stage has no non-root USER.", snippet="USER (missing)" if user_after_last_from is None else f"USER {user_after_last_from}")
        if instrs and not has_health:
            yield Finding(R_NO_HEALTH, rel, 1, "Image defines no HEALTHCHECK.", snippet="HEALTHCHECK (missing)")

    def compose(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return
        if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
            return
        lines = text.splitlines()

        def ln(needle: str, after: int = 0) -> int:
            for i in range(after, len(lines)):
                if needle in lines[i]:
                    return i + 1
            return 1

        for name, svc in doc["services"].items():
            if not isinstance(svc, dict):
                continue
            base = ln(f"{name}:")
            if svc.get("privileged") is True:
                yield Finding(R_COMPOSE_PRIV, rel, ln("privileged", base - 1), f"service `{name}` is privileged.", snippet="privileged: true")
            for key in ("network_mode", "pid", "ipc"):
                if svc.get(key) == "host":
                    yield Finding(R_COMPOSE_PRIV, rel, ln(key, base - 1), f"service `{name}` shares the host {key}.", snippet=f"{key}: host")
            for cap in svc.get("cap_add") or []:
                if str(cap).upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"):
                    yield Finding(R_COMPOSE_PRIV, rel, ln(str(cap), base - 1), f"service `{name}` adds {cap}.", snippet=f"cap_add: {cap}")
            for vol in svc.get("volumes") or []:
                v = vol if isinstance(vol, str) else str((vol or {}).get("source", ""))
                if "docker.sock" in v:
                    yield Finding(R_COMPOSE_SOCK, rel, ln("docker.sock", base - 1), f"service `{name}` mounts the Docker socket.", snippet=v)
            for port in svc.get("ports") or []:
                p = str(port if not isinstance(port, dict) else f"{port.get('published')}:{port.get('target')}")
                parts = p.split(":")
                target = parts[-1].split("/")[0]
                bound_local = len(parts) == 3 and parts[0] in ("127.0.0.1", "localhost", "::1")
                if target in _DATA_PORTS and not bound_local:
                    yield Finding(R_COMPOSE_DB_PORT, rel, ln(p, base - 1),
                                  f"service `{name}` publishes {target} on 0.0.0.0 (on a server, Docker bypasses ufw/iptables rules).", snippet=p,
                                  extra={"resource": f"compose:{name}"}, severity=Severity.MEDIUM)
            env = svc.get("environment") or {}
            items: list[tuple[str, Any]] = list(env.items()) if isinstance(env, dict) else [tuple(e.split("=", 1)) if "=" in e else (e, None) for e in env]  # type: ignore[misc]
            for key, val in items:
                if _SECRET_NAME.search(str(key)) and val not in (None, "") and not str(val).startswith("$"):
                    f = Finding(R_COMPOSE_SECRET, rel, ln(str(key), base - 1), f"service `{name}`: {key} is a literal.", snippet=f"{key}: ****",
                                extra={"resource": f"compose:{name}"})
                    if str(val).lower() in _DEV_DEFAULTS:
                        f.severity, f.confidence = Severity.LOW, 0.6
                        f.message += " It is a well-known default: fine for a local dev stack, never deploy this file as-is."
                    yield f
            image = str(svc.get("image") or "")
            if image and "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                yield Finding(R_LATEST, rel, ln(image, base - 1), f"service `{name}` image `{image}` is not pinned.", snippet=f"image: {image}")
