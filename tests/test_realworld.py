import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("realworld", ROOT / "bench" / "realworld.py")
rw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rw)


def finding(rule, path, line, severity="HIGH", risk=70.0):
    return {"rule_id": rule, "path": path, "line": line, "severity": severity, "risk": risk}


class ScoringTest(unittest.TestCase):
    def test_top_ten_critical_high_by_risk(self):
        fs = [finding("A", "a", i, risk=float(i)) for i in range(15)] + [finding("M", "m", 1, "MEDIUM", 99.0)]
        top = rw.top_findings(fs)
        self.assertEqual(len(top), 10)
        self.assertEqual(top[0]["line"], 14)
        self.assertNotIn("M", {f["rule_id"] for f in top})

    def test_labels_strict_large_and_unlabelled(self):
        labels = [
            {"repo": "r", "rule": "A", "path": "a.py", "line": 1, "label": "tp", "reason": ""},
            {"repo": "r", "rule": "B", "path": "b.py", "line": 2, "label": "fp", "reason": ""},
            {"repo": "r", "rule": "C", "path": "c.py", "line": 3, "label": "debatable", "reason": ""},
            {"repo": "other", "rule": "D", "path": "d.py", "line": 4, "label": "tp", "reason": ""},
        ]
        fs = [finding("A", "a.py", 1, risk=90), finding("B", "b.py", 2, risk=80), finding("C", "c.py", 9, risk=70),
              finding("D", "d.py", 4, risk=60)]
        ev = rw.evaluate({"name": "r"}, fs, labels)
        self.assertEqual((ev["tp"], ev["fp"], ev["debatable"], ev["unlabelled"]), (1, 1, 1, 1))
        self.assertEqual(ev["strict"], round(1 / 3, 3))
        self.assertEqual(ev["large"], round(2 / 3, 3))

    def test_moved_line_keeps_its_label_only_when_unambiguous(self):
        labels = [{"repo": "r", "rule": "A", "path": "a.py", "line": 1, "label": "fp", "reason": ""},
                  {"repo": "r", "rule": "A", "path": "a.py", "line": 5, "label": "tp", "reason": ""}]
        self.assertIsNone(rw.label_of(finding("A", "a.py", 3), labels))
        self.assertEqual(rw.label_of(finding("A", "a.py", 5), labels)["label"], "tp")
        self.assertEqual(rw.label_of(finding("A", "a.py", 7), labels[:1])["label"], "fp")

    def test_manifests_are_pinned_and_labels_well_formed(self):
        for manifest in ("realworld", "holdout"):
            spec = json.loads((ROOT / "bench" / manifest / "repos.json").read_text())
            for repo in spec["repos"] + spec.get("stress", []):
                self.assertRegex(repo["commit"], r"^[0-9a-f]{40}$", repo["name"])
        labels = json.loads((ROOT / "bench" / "realworld" / "labels.json").read_text())["labels"]
        names = {r["name"] for r in json.loads((ROOT / "bench" / "realworld" / "repos.json").read_text())["repos"]}
        for lb in labels:
            self.assertIn(lb["repo"], names)
            self.assertIn(lb["label"], ("tp", "fp", "debatable"))
            self.assertTrue(lb["reason"])
        # The holdout labels were forbidden until phase 5 (written only at the end). Now that they exist,
        # they must name the code commit they were made against, and no source may change after it
        # because of them: checked whenever that commit is in the local history.
        held = ROOT / "bench" / "holdout" / "labels.json"
        if held.exists():
            doc = json.loads(held.read_text())
            self.assertRegex(doc["labelled_at"], r"^[0-9a-f]{40}$")
            self.assertIn("Nothing was fixed", doc["protocol"])
            hnames = {r["name"] for r in json.loads((ROOT / "bench" / "holdout" / "repos.json").read_text())["repos"]}
            for lb in doc["labels"]:
                self.assertIn(lb["repo"], hnames)
                self.assertIn(lb["label"], ("tp", "fp", "debatable"))
                self.assertTrue(lb["reason"])
            import subprocess

            known = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", doc["labelled_at"] + "^{commit}"], capture_output=True)
            if known.returncode == 0:
                changed = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", doc["labelled_at"], "HEAD", "--", "src"],
                                         capture_output=True, text=True).stdout.split()
                self.assertEqual(changed, [], "source changed after the holdout was labelled: re-measure it, do not tune on it")


class RegressionCheckTest(unittest.TestCase):
    BASE = {"summary": {"strict": 0.5, "large": 0.75, "crashes": 0},
            "repos": {"r": {"strict": 0.5, "large": 1.0, "errors": [], "timeout": False,
                            "top": [{"rule": "A", "where": "a.py:1", "label": "tp"}, {"rule": "B", "where": "b.py:2", "label": "fp"}]}}}

    def run_with(self, **repo):
        import copy

        now = copy.deepcopy(self.BASE)
        now["repos"]["r"].update(repo)
        return rw.regressions(self.BASE, now)

    def test_same_results_pass(self):
        self.assertEqual(rw.regressions(self.BASE, self.BASE), [])

    def test_lower_precision_a_lost_true_positive_a_crash_or_an_unlabelled_entry_fail(self):
        self.assertTrue(self.run_with(strict=0.25))
        self.assertTrue(self.run_with(large=0.5))
        self.assertTrue(self.run_with(top=[{"rule": "B", "where": "b.py:2", "label": "fp"}]))
        self.assertTrue(self.run_with(errors=["code: TypeError"]))
        self.assertTrue(self.run_with(timeout=True))
        unlabelled = self.BASE["repos"]["r"]["top"] + [{"rule": "C", "where": "c.py:3", "label": "UNLABELLED"}]
        self.assertTrue(any("UNLABELLED" in r or "label" in r for r in self.run_with(top=unlabelled)))

    def test_better_results_pass(self):
        self.assertEqual(self.run_with(strict=1.0, top=[{"rule": "A", "where": "a.py:1", "label": "tp"}]), [])


if __name__ == "__main__":
    unittest.main()
