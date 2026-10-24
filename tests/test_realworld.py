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
        self.assertFalse((ROOT / "bench" / "holdout" / "labels.json").exists(), "holdout labels are written only at the end")


if __name__ == "__main__":
    unittest.main()
