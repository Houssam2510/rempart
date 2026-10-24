import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

from rempart.models import Severity

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("owasp_python", ROOT / "bench" / "owasp_python.py")
ow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ow)


def finding(test, rule, severity):
    return SimpleNamespace(path=f"testcode/{test}.py", rule=SimpleNamespace(id=rule), severity=severity)


class BothScoresTest(unittest.TestCase):
    def test_score_with_and_without_info_findings(self):
        # an INFO context note on a trap is not an alert, but a reader must see what counting it costs
        expected = {"T1": ("xxe", True), "T2": ("xxe", False)}
        findings = [finding("T1", "CODE-XXE", Severity.HIGH), finding("T2", "CODE-XXE", Severity.INFO)]
        both = ow.scores(findings, expected)
        self.assertEqual(both["alerts"]["xxe"]["score"], 100.0)
        self.assertEqual(both["with_info"]["xxe"]["score"], 0.0)
        self.assertEqual((both["alerts"]["_overall"]["score"], both["with_info"]["_overall"]["score"]), (100.0, 0.0))


if __name__ == "__main__":
    unittest.main()
