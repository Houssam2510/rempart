from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
from pathlib import Path

from rempart.config import Config
from rempart.engine import ScanResult, run_scan
from rempart.scanners import ALL_SCANNERS

# Credential-shaped strings are assembled at runtime so this repository never
# contains a literal token (and GitHub push protection stays happy).
FAKE_AWS_KEY = "AKIA" + "Z7QXRT2MWPLK4N8J"
FAKE_GH_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
FAKE_STRIPE = "sk_" + "live_" + "51HxQ2bLk9Zt7Rw3Yp4Vn8Mc6Jd"
FAKE_PRIVATE_KEY_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def scan_tree(files: dict[str, str], scanners: list[str] | None = None, git: bool = False) -> ScanResult:
    tmp = Path(tempfile.mkdtemp(prefix="rempart-test-"))
    write_tree(tmp, files)
    if git:
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
    else:
        os.environ.setdefault("GIT_CEILING_DIRECTORIES", str(tmp.parent))
    selected = [ALL_SCANNERS[n] for n in (scanners or list(ALL_SCANNERS))]
    return run_scan(tmp, selected, Config(), offline=True)


def rule_ids(result: ScanResult) -> set[str]:
    return {f.rule.id for f in result.findings}
