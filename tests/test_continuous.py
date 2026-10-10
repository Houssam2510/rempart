import subprocess
import tempfile
import unittest
from pathlib import Path

from rempart.config import Config
from rempart.continuous import baseline_fingerprints, scan_git_history, watch
from rempart.engine import run_scan
from rempart.scanners import ALL_SCANNERS
from tests.helpers import FAKE_GH_TOKEN


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@example.org", "PATH": "/usr/bin:/bin", "HOME": str(root)})


def repo() -> Path:
    root = Path(tempfile.mkdtemp(prefix="rempart-git-"))
    git(root, "init", "-q", "-b", "main")
    return root


class GitHistoryTest(unittest.TestCase):
    def test_removed_secret_is_found_in_history(self) -> None:
        root = repo()
        (root / "deploy.sh").write_text(f"export GH={FAKE_GH_TOKEN}\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "add deploy")
        (root / "deploy.sh").write_text("export GH=$GH_TOKEN\n")
        git(root, "commit", "-qam", "use env")
        found = list(scan_git_history(root, lambda rel: (root / rel).read_text()))
        self.assertEqual([f.rule.id for f in found], ["SEC-GIT-HISTORY"])
        self.assertNotIn(FAKE_GH_TOKEN, found[0].message)
        self.assertEqual(found[0].extra["provider_rule"], "SEC-GITHUB-TOKEN")

    def test_secret_still_in_tree_is_left_to_the_regular_scan(self) -> None:
        root = repo()
        (root / "app.env.sh").write_text(f"GH={FAKE_GH_TOKEN}\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "x")
        self.assertEqual(list(scan_git_history(root, lambda rel: (root / rel).read_text())), [])


class BaselineTest(unittest.TestCase):
    def test_only_new_findings_survive(self) -> None:
        root = repo()
        (root / "old.py").write_text("import os\nos.system('ls ' + os.environ['D'])\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "old")
        (root / "new.py").write_text("import yaml\ncfg = yaml.load(open('x'), Loader=yaml.Loader)\nimport subprocess\nsubprocess.run(input(), shell=True)\n")
        scan = lambda p: run_scan(p, [ALL_SCANNERS["code"]], Config(), offline=True, correlate=False).findings
        known = baseline_fingerprints(root, "HEAD", scan)
        now = scan(root)
        self.assertTrue(any(f.path == "old.py" for f in now))
        self.assertFalse(any(f.path == "old.py" and f.fingerprint not in known for f in now))
        self.assertTrue(any(f.path == "new.py" and f.fingerprint not in known for f in now))
        out = subprocess.run(["git", "-C", str(root), "worktree", "list"], capture_output=True, text=True).stdout
        self.assertEqual(len(out.strip().splitlines()), 1)


class WatchTest(unittest.TestCase):
    def test_prints_difference_only(self) -> None:
        root = repo()
        (root / "a.py").write_text("x = 1\n")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "a")
        lines: list[str] = []
        passes = {"n": 0}

        def scan(p):
            passes["n"] += 1
            found = run_scan(p, [ALL_SCANNERS["code"]], Config(), offline=True, correlate=False).findings
            if passes["n"] == 1:  # the developer edits the file while the first scan runs
                (root / "a.py").write_text("import os\nos.system('rm ' + input())\n")
            return found

        watch(root, scan, interval=0, emit=lines.append, iterations=2)
        self.assertIn("watching", lines[0])
        self.assertTrue(any("] + " in l and "a.py" in l for l in lines[1:]), lines)


if __name__ == "__main__":
    unittest.main()
