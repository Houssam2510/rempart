"""Continuous security: what changed, what is new, what never left.

* `scan_git_history`: a secret deleted from the working tree is still in every
  clone and fork. This walks the added lines of every commit (all branches)
  and reports provider-format credentials that are no longer in the current
  files, with the commit that introduced them.
* `baseline_fingerprints`: scan another git revision in a temporary worktree,
  so a pull request is judged on what it adds, not on the backlog it inherits.
* `watch`: re-scan when the repository changes and print only the difference.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterator

from rempart.models import Finding, Severity
from rempart.registry import A02, A07, H, rule

R_HISTORY = rule("SEC-GIT-HISTORY", "Secret still reachable in git history", H, "secrets", cwe="CWE-798", owasp=(A07, A02),
                 fix="Rotate the credential first (deleting the line does not revoke it). Then rewrite history with git filter-repo, force-push every branch, "
                     "and ask the host to purge cached views; forks and clones keep their copy, which is why rotation comes first.",
                 refs=("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",),
                 confidence=0.85)


def _git(root: Path, *args: str, timeout: int = 300) -> str:
    out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=timeout, check=True)
    return out.stdout.decode("utf-8", "replace")


def scan_git_history(root: Path, current_text: Callable[[str], str | None] | None = None, max_commits: int = 5000,
                     verify_secrets: bool = False) -> Iterator[Finding]:
    from rempart.scanners.secrets import _COMPILED, _RULES, redact

    try:
        log = _git(root, "log", "--all", f"--max-count={max_commits}", "-p", "--no-color", "--unified=0", "--no-renames",
                   "--format=%x00%H%x09%aI%x09%an", timeout=600)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return
    present: dict[str, str] = {}
    seen: set[str] = set()
    commit = date = author = path = ""
    for line in log.splitlines():
        if line.startswith("\0"):
            commit, date, author = (line[1:].split("\t") + ["", "", ""])[:3]
            continue
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
            continue
        if not line.startswith("+") or line.startswith("+++") or not path or len(line) > 4000:
            continue
        for rid, rx in _COMPILED:
            m = rx.search(line)
            if not m:
                continue
            token = m.group(0)
            key = hashlib.sha256(token.encode()).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            if current_text is not None:
                if path not in present:
                    present[path] = current_text(path) or ""
                if token in present[path]:
                    continue  # still in the working tree: the regular scan already reports it
            f = Finding(R_HISTORY, path, 0,
                        f"{_RULES[rid].title} ({redact(token)}) was added in commit {commit[:10]} ({date[:10]}) and is still in the history.",
                        snippet=f"{commit[:10]} {path}", extra={"anchor": f"history:{rid}:{redact(token)}", "commit": commit, "date": date,
                                                              "provider_rule": rid})
            f.severity = _RULES[rid].severity if _RULES[rid].severity >= Severity.HIGH else Severity.MEDIUM
            if verify_secrets:
                from rempart.verify import verify

                v = verify(rid, token, "")
                f.extra["verification_detail"] = v.detail
                if v.status == "live":
                    f.verification, f.severity, f.confidence = "live-secret", Severity.CRITICAL, 1.0
                    f.message += f" VERIFIED LIVE: {v.detail}. Rotate it now."
                elif v.status == "revoked":
                    f.verification, f.severity = "revoked-secret", Severity.LOW
                    f.message += " Provider rejects it (revoked)."
            yield f


def baseline_fingerprints(root: Path, ref: str, run: Callable[[Path], list[Finding]]) -> set[str]:
    """Fingerprints of the findings at `ref`, scanned in a throwaway worktree."""
    tmp = Path(tempfile.mkdtemp(prefix="rempart-baseline-"))
    target = tmp / "tree"
    try:
        _git(root, "worktree", "add", "--detach", str(target), ref, timeout=120)
        try:
            return {f.fingerprint for f in run(target)}
        finally:
            subprocess.run(["git", "-C", str(root), "worktree", "remove", "--force", str(target)], capture_output=True, timeout=60)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def tree_signature(root: Path) -> str:
    """Changes whenever a commit lands or a tracked/untracked file is edited."""
    h = hashlib.sha256()
    try:
        h.update(_git(root, "rev-parse", "HEAD", timeout=30).encode())
        h.update(_git(root, "status", "--porcelain", "-z", timeout=60).encode())
        for rel in _git(root, "ls-files", "-m", "-o", "--exclude-standard", "-z", timeout=60).split("\0"):
            p = root / rel
            if rel and p.is_file():
                st = p.stat()
                h.update(f"{rel}:{st.st_mtime_ns}:{st.st_size}".encode())
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        for p in sorted(root.rglob("*")):
            if p.is_file() and ".git" not in p.parts:
                st = p.stat()
                h.update(f"{p}:{st.st_mtime_ns}".encode())
    return h.hexdigest()


def diff_findings(before: dict[str, Finding], after: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    now = {f.fingerprint: f for f in after}
    new = [f for k, f in now.items() if k not in before]
    fixed = [f for k, f in before.items() if k not in now]
    return new, fixed


def watch(root: Path, scan: Callable[[Path], list[Finding]], *, interval: float = 20.0, min_severity: Severity = Severity.MEDIUM,
          emit: Callable[[str], None] = print, iterations: int | None = None) -> None:
    previous: dict[str, Finding] | None = None
    signature = ""
    done = 0
    while iterations is None or done < iterations:
        sig = tree_signature(root)
        if sig != signature:
            signature = sig
            findings = [f for f in scan(root) if f.severity is not None and f.severity >= min_severity]
            stamp = time.strftime("%H:%M:%S")
            if previous is None:
                emit(f"[{stamp}] watching {root} · {len(findings)} finding(s) at {min_severity.name.lower()} or above")
            else:
                new, fixed = diff_findings(previous, findings)
                for f in sorted(new, key=lambda x: -x.risk):
                    emit(f"[{stamp}] + {f.severity.name if f.severity else ''} {f.rule.id} {f.path}:{f.line} {f.message[:140]}")
                for f in fixed:
                    emit(f"[{stamp}] - fixed {f.rule.id} {f.path}:{f.line}")
                if not new and not fixed:
                    emit(f"[{stamp}] change detected · no security difference")
            previous = {f.fingerprint: f for f in findings}
        done += 1
        if iterations is None or done < iterations:
            time.sleep(interval)
