"""CI/CD pipeline checks (GitHub Actions, GitLab CI), mapped to the OWASP
Top 10 CI/CD Security Risks.

The rules follow the attack chains actually used in 2025-2026:
tj-actions/changed-files (mutable tag repointed to a credential-dumping
commit), TanStack (pull_request_target + cache poisoning + OIDC token theft),
and the Shai-Hulud worms (stolen tokens republishing packages from CI).
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterator

import yaml

from rempart.engine import ScanContext
from rempart.models import Finding, Severity
from rempart.registry import A01, A03, A05, A07, A08, C, H, L, M, rule

S1 = "CICD-SEC-1 Insufficient Flow Control"
S2 = "CICD-SEC-2 Inadequate IAM"
S3 = "CICD-SEC-3 Dependency Chain Abuse"
S4 = "CICD-SEC-4 Poisoned Pipeline Execution"
S5 = "CICD-SEC-5 Insufficient PBAC"
S6 = "CICD-SEC-6 Insufficient Credential Hygiene"
S7 = "CICD-SEC-7 Insecure System Configuration"
S8 = "CICD-SEC-8 Ungoverned 3rd Party Services"
S9 = "CICD-SEC-9 Improper Artifact Integrity Validation"

R_PWN = rule("GHA-PWN-REQUEST", "Privileged workflow checks out untrusted pull-request code", C, "cicd", cwe=("CWE-829", "CWE-94"), owasp=(A08, A01), frameworks=(S4,),
             fix="Use `pull_request` for anything that builds PR code. If pull_request_target is required, never check out the PR head, and keep secrets, write tokens and caches out of that job.",
             refs=("https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",))
R_PRT = rule("GHA-PULL-REQUEST-TARGET", "pull_request_target trigger", M, "cicd", cwe="CWE-829", owasp=A08, frameworks=(S4,),
             fix="pull_request_target runs with repository secrets on forks' events. Prefer `pull_request`; if you keep it, avoid checkout of PR code, caches and id-token.",
             confidence=0.6)
R_INJECT = rule("GHA-SCRIPT-INJECTION", "Untrusted event data interpolated into a shell", H, "cicd", cwe=("CWE-78", "CWE-94"), owasp=A05, frameworks=(S4,),
                fix="Pass the value through an environment variable (`env: TITLE: ${{ github.event.issue.title }}` then `\"$TITLE\"`). `${{ }}` is substituted before the shell parses the script.")
R_UNPINNED = rule("GHA-UNPINNED-ACTION", "Third-party action not pinned to a commit SHA", M, "cicd", cwe=("CWE-829", "CWE-1357"), owasp=A03, frameworks=(S3, S8),
                  fix="Pin to a full 40-character commit SHA with the version in a comment (`uses: owner/action@<sha> # v4.2.0`) and let Dependabot/Renovate bump it. Tags are mutable: that is how tj-actions/changed-files leaked secrets in March 2025.")
R_PERMS = rule("GHA-DEFAULT-PERMISSIONS", "Workflow token permissions not restricted", M, "cicd", cwe="CWE-250", owasp=A01, frameworks=(S2, S5),
               fix="Add `permissions: contents: read` at the workflow level and grant extra scopes per job.", confidence=0.7)
R_WRITE_ALL = rule("GHA-WRITE-ALL", "Workflow grants write-all permissions", H, "cicd", cwe="CWE-250", owasp=A01, frameworks=(S2, S5),
                   fix="Replace write-all with the specific scopes each job needs.")
R_SECRET_ECHO = rule("GHA-SECRET-ECHO", "Secret printed or written by a step", H, "cicd", cwe="CWE-532", owasp=A07, frameworks=(S6,),
                     fix="Never echo secrets or write them to files/artifacts. Pass them as env vars to the tool that needs them.")
R_CACHE_POISON = rule("GHA-CACHE-IN-PRIVILEGED", "Cache used in a privileged pull_request_target / release workflow", H, "cicd", cwe="CWE-349", owasp=A08, frameworks=(S4, S9),
                      fix="Do not restore caches in jobs that hold publish credentials or run on pull_request_target; a poisoned cache entry runs inside the privileged job (TanStack, May 2026).")
R_OIDC_PRT = rule("GHA-OIDC-UNTRUSTED", "id-token: write in a workflow triggered by untrusted events", H, "cicd", cwe="CWE-266", owasp=A07, frameworks=(S2, S6),
                  fix="Grant id-token: write only to release jobs triggered by protected branches/tags, behind an environment with required reviewers.")
R_UNSECURE_CMDS = rule("GHA-UNSECURE-COMMANDS", "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled", H, "cicd", cwe="CWE-94", owasp=A08, frameworks=(S4,),
                       fix="Remove it; the deprecated set-env/add-path commands let log output inject environment variables.")
R_ARTIFACT = rule("GHA-WORKFLOW-RUN-ARTIFACT", "workflow_run consumes artifacts from an untrusted run", M, "cicd", cwe="CWE-345", owasp=A08, frameworks=(S9,),
                  fix="Treat artifacts from PR-triggered runs as untrusted data: never execute them, extract to a temp dir, validate content.", confidence=0.6)
R_ENV_INJECT = rule("GHA-ENV-INJECTION", "Untrusted content written to GITHUB_ENV or GITHUB_PATH", H, "cicd", cwe=("CWE-94", "CWE-78"), owasp=(A08, A05),
                    frameworks=(S4,),
                    fix="Never write artifact or event content to $GITHUB_ENV / $GITHUB_PATH in a workflow triggered by untrusted runs: a crafted "
                        "value sets LD_PRELOAD, NODE_OPTIONS or PATH for every later step. Validate it strictly or pass it through step outputs.",
                    confidence=0.7)
R_SELF_HOSTED = rule("GHA-SELF-HOSTED-PUBLIC", "Self-hosted runner on pull request events", M, "cicd", cwe="CWE-668", owasp=A01, frameworks=(S7,),
                     fix="Use ephemeral, isolated runners for PR builds. A persistent self-hosted runner lets a PR plant malware for the next job.", confidence=0.6)
R_CURL_SH = rule("CI-CURL-PIPE-SHELL", "Pipeline downloads and executes a remote script", M, "cicd", cwe="CWE-494", owasp=A08, frameworks=(S3,),
                 fix="Pin the script by checksum or use a versioned, pinned action/image instead.")
R_INHERIT = rule("GHA-SECRETS-INHERIT", "Reusable workflow inherits all secrets", L, "cicd", cwe="CWE-250", owasp=A07, frameworks=(S6,),
                 fix="Pass only the secrets the called workflow needs.", confidence=0.6)
R_NPM_TOKEN_PUBLISH = rule("CI-LONG-LIVED-PUBLISH-TOKEN", "Package published with a long-lived token", M, "cicd", cwe="CWE-798", owasp=A07, frameworks=(S6,),
                           fix="Use npm/PyPI trusted publishing (OIDC) so no reusable publish token exists to steal; the 2025-2026 npm worms spread with stolen tokens.",
                           confidence=0.6)
R_GITLAB_DEBUG = rule("GITLAB-CI-DEBUG-TRACE", "CI debug trace enabled", H, "cicd", cwe="CWE-532", owasp=A07, frameworks=(S6,),
                      fix="CI_DEBUG_TRACE prints every variable, including masked secrets, to the job log. Remove it.")

UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|"
    r"comment\.body|review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.(?:message|author\.(?:email|name))|"
    r"head_commit\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|head_commit\.message|display_title)|discussion\.(?:title|body))|"
    r"github\.head_ref|inputs\.[\w-]+|steps\.[\w-]+\.outputs\.[\w-]+)\s*\}\}"
)
PR_HEAD = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/")
# the code of the run that triggered a workflow_run workflow: a fork's, for pull-request CI
RUN_HEAD = re.compile(r"github\.event\.workflow_run\.(?:head_sha|head_branch|head_repository|head_commit\.id)")
# triggers whose inputs come only from people with write access; workflow_call is excluded:
# its caller may forward untrusted data
TRUSTED_TRIGGERS = {"workflow_dispatch", "push", "schedule", "release", "create", "delete", "merge_group", "repository_dispatch"}


def _triggers(doc: dict[str, Any]) -> set[str]:
    on = doc.get("on", doc.get(True))  # PyYAML parses bare `on:` as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(map(str, on))
    if isinstance(on, dict):
        return set(map(str, on.keys()))
    return set()


class CICDScanner:
    name = "cicd"

    def scan(self, ctx: ScanContext) -> Iterator[Finding]:
        for rel in ctx.files:
            if re.match(r"(?:.*/)?\.github/workflows/[^/]+\.ya?ml$", rel):
                yield from self.github(ctx, rel)
            elif re.match(r"(?:.*/)?action\.ya?ml$", rel):
                yield from self.composite_action(ctx, rel)
            elif os.path.basename(rel) == ".gitlab-ci.yml":
                yield from self.gitlab(ctx, rel)

    def _uses(self, rel: str, lines: list[str]) -> Iterator[Finding]:
        for i, line in enumerate(lines, 1):
            m = re.search(r"uses:\s*['\"]?([^'\"\s#]+)", line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith(("./", "docker://")):
                if ref.startswith("docker://") and "@sha256:" not in ref:
                    yield Finding(R_UNPINNED, rel, i, f"{ref} not digest-pinned.", snippet=line.strip(), severity=Severity.LOW)
                continue
            if "@" not in ref:
                continue
            owner_repo, version = ref.split("@", 1)
            if re.fullmatch(r"[0-9a-f]{40}", version):
                continue
            first_party = owner_repo.split("/")[0] in ("actions", "github")
            f = Finding(R_UNPINNED, rel, i, f"{owner_repo}@{version} uses a mutable ref.", snippet=line.strip())
            if first_party:
                f.severity, f.confidence = Severity.LOW, 0.5
            yield f

    def _run_steps(self, rel: str, lines: list[str], trusted_inputs: bool = False, untrusted_trigger: bool = False,
                   downloads_artifacts: bool = False) -> Iterator[Finding]:
        in_run, run_indent = False, 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
            if m:
                in_run, run_indent = True, len(m.group(1))
                content = m.group(2)
            elif in_run and (indent > run_indent or not stripped):
                content = line
            else:
                in_run = False
                content = ""
            if not content:
                continue
            for um in UNTRUSTED.finditer(content):
                expr = um.group(0)
                maintainer_input = trusted_inputs and "inputs." in expr
                sev = Severity.LOW if maintainer_input else Severity.MEDIUM if ("inputs." in expr or "steps." in expr) else None
                f = Finding(R_INJECT, rel, i, f"{expr} is expanded inside a shell script"
                            + (" (only maintainers can trigger this workflow: hygiene, not an untrusted input)." if maintainer_input else "."),
                            snippet=stripped[:200], extra={"anchor": f"{expr}:{stripped[:80]}"})
                if maintainer_input:
                    f.extra["trusted_input"] = True
                if sev is not None:
                    f.severity, f.confidence = sev, 0.5
                yield f
            if untrusted_trigger and re.search(r"GITHUB_(?:ENV|PATH)", content) and (
                    re.search(r"\$\(\s*cat\b|\$\(<|<\s*[\w./-]+|\$\{\{\s*github\.event", content) or downloads_artifacts):
                yield Finding(R_ENV_INJECT, rel, i, "Content from an untrusted run or event is written to GITHUB_ENV/GITHUB_PATH.", snippet=stripped[:200])
            if re.search(r"(?:echo|printf|tee|>>?)\s[^\n]*\$\{\{\s*secrets\.", content) and "GITHUB_ENV" not in content and "add-mask" not in content:
                yield Finding(R_SECRET_ECHO, rel, i, "A secret is echoed or written out.", snippet=re.sub(r"secrets\.\w+", "secrets.****", stripped)[:200])
            if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", content):
                yield Finding(R_CURL_SH, rel, i, "curl | sh in a pipeline step.", snippet=stripped[:200])
            if re.search(r"npm\s+publish|twine\s+upload|yarn\s+npm\s+publish|pnpm\s+publish", content) and "--provenance" not in content:
                window = "\n".join(lines[max(0, i - 15): i + 5])
                if re.search(r"NODE_AUTH_TOKEN|NPM_TOKEN|TWINE_PASSWORD|PYPI_TOKEN", window):
                    yield Finding(R_NPM_TOKEN_PUBLISH, rel, i, "publish step authenticated with a stored token.", snippet=stripped[:200])

    def github(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        text = ctx.text(rel) or ""
        lines = text.splitlines()
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            doc = None
        if not isinstance(doc, dict):
            # Invalid YAML still deserves the line-level checks: never fail silent.
            yield from self._uses(rel, lines)
            yield from self._run_steps(rel, lines)
            return
        trig = _triggers(doc)
        jobs = doc.get("jobs") or {}

        def ln(needle: str) -> int:
            return next((i for i, l in enumerate(lines, 1) if needle in l), 1)

        untrusted_trigger = bool(trig & {"pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment", "workflow_run", "pull_request_review", "pull_request_review_comment"})
        if "pull_request_target" in trig:
            checks_out_head = bool(PR_HEAD.search(text)) and "actions/checkout" in text
            if checks_out_head:
                yield Finding(R_PWN, rel, ln("ref:") if "ref:" in text else ln("pull_request_target"), "pull_request_target workflow checks out the PR head with repository privileges.", snippet="pull_request_target + checkout of PR head")
            else:
                yield Finding(R_PRT, rel, ln("pull_request_target"), "Runs in the base repository's privileged context on fork events.", snippet="on: pull_request_target")
        privileged = "pull_request_target" in trig or bool(re.search(r"npm\s+publish|twine\s+upload|id-token:\s*write|release", text))
        if privileged and re.search(r"actions/cache@|cache:\s*['\"]?(?:npm|pnpm|yarn|pip|poetry|gradle|maven)", text) and ("pull_request_target" in trig or re.search(r"npm\s+publish|twine\s+upload", text)):
            yield Finding(R_CACHE_POISON, rel, ln("cache"), "Cache restored in a job that can publish or runs on pull_request_target.", snippet="actions/cache / setup-* cache")
        if untrusted_trigger and re.search(r"id-token:\s*write", text):
            yield Finding(R_OIDC_PRT, rel, ln("id-token"), f"OIDC token mintable from {sorted(trig & {'pull_request_target', 'issue_comment', 'issues', 'workflow_run'})}.", snippet="id-token: write")
        perms = doc.get("permissions")
        if perms == "write-all" or re.search(r"permissions:\s*write-all", text):
            yield Finding(R_WRITE_ALL, rel, ln("write-all"), "permissions: write-all.", snippet="permissions: write-all")
        elif perms is None and isinstance(jobs, dict) and not all(isinstance(j, dict) and "permissions" in j for j in jobs.values()):
            yield Finding(R_PERMS, rel, 1, "No top-level `permissions:`; jobs get the repository default token scope.", snippet="permissions (missing)")
        if "ACTIONS_ALLOW_UNSECURE_COMMANDS" in text and re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*['\"]?true", text):
            yield Finding(R_UNSECURE_CMDS, rel, ln("ACTIONS_ALLOW_UNSECURE_COMMANDS"), "Unsecure workflow commands enabled.", snippet="ACTIONS_ALLOW_UNSECURE_COMMANDS: true")
        downloads = "workflow_run" in trig and bool(re.search(r"download-artifact|actions/github-script[^\n]*\n[^\n]*listWorkflowRunArtifacts", text))
        if downloads:
            yield Finding(R_ARTIFACT, rel, ln("download-artifact"), "Artifacts from a triggering (possibly fork) run are downloaded.", snippet="workflow_run + download-artifact")
        if "workflow_run" in trig and "actions/checkout" in text:
            head = next((i for i, l in enumerate(lines, 1) if RUN_HEAD.search(l) and re.search(r"\b(?:ref|repository):", l)), 0)
            if head:
                yield Finding(R_PWN, rel, head, "workflow_run workflow checks out the triggering run's code (a fork's, for pull requests) with "
                              "repository privileges.", snippet="workflow_run + checkout of the triggering head")
        if trig & {"pull_request", "pull_request_target"} and re.search(r"runs-on:\s*\[?[^\n]*self-hosted", text):
            yield Finding(R_SELF_HOSTED, rel, ln("self-hosted"), "Self-hosted runner reachable from pull requests.", snippet="runs-on: self-hosted")
        if re.search(r"secrets:\s*inherit", text):
            yield Finding(R_INHERIT, rel, ln("secrets: inherit"), "secrets: inherit forwards every secret.", snippet="secrets: inherit")
        yield from self._uses(rel, lines)
        yield from self._run_steps(rel, lines, trusted_inputs=bool(trig) and trig <= TRUSTED_TRIGGERS, untrusted_trigger=untrusted_trigger,
                                   downloads_artifacts=downloads)

    def composite_action(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        lines = ctx.lines(rel)
        yield from self._uses(rel, lines)
        yield from self._run_steps(rel, lines)

    def gitlab(self, ctx: ScanContext, rel: str) -> Iterator[Finding]:
        for i, line in enumerate(ctx.lines(rel), 1):
            if re.search(r"CI_DEBUG_TRACE:\s*['\"]?true", line):
                yield Finding(R_GITLAB_DEBUG, rel, i, "CI_DEBUG_TRACE leaks variables to logs.", snippet=line.strip())
            if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", line):
                yield Finding(R_CURL_SH, rel, i, "curl | sh in a pipeline job.", snippet=line.strip()[:200])
            m = re.search(r"^\s*image:\s*['\"]?([^'\"\s]+)", line)
            if m and "@sha256:" not in m.group(1) and (":" not in m.group(1).rsplit("/", 1)[-1] or m.group(1).endswith(":latest")):
                yield Finding(R_UNPINNED, rel, i, f"CI image {m.group(1)} not pinned.", snippet=line.strip())
