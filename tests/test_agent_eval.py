import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

from rempart.agent import write_proofs
from rempart.agent_eval import load_cases, run_case, score


class ScriptedClient:
    """Stands in for the API: decides every listed finding with `oracle`, writes one proof, then finishes."""

    def __init__(self, oracle):
        self.oracle = oracle
        self.beta = NS(messages=NS(create=self.create))

    def create(self, **kw):
        first = kw["messages"][0]["content"]
        if len(kw["messages"]) > 1:
            return NS(content=[NS(type="text", text="done")], stop_reason="end_turn", usage=None)
        blocks = []
        for i, m in enumerate(re.finditer(r"^- (\w{10}) \w+ ([\w-]+) at ([^\s:]+):", first, re.M)):
            fid, rule, path = m.groups()
            verdict = self.oracle(rule, path)
            blocks.append(NS(type="tool_use", id=f"t{i}", name="record_verdict",
                             input={"id": fid, "verdict": verdict, "confidence": "high", "reasoning": "scripted", "evidence": path}))
            if verdict == "confirmed":
                blocks.append(NS(type="tool_use", id=f"p{i}", name="write_proof",
                                 input={"id": fid, "filename": f"test_proof_{i}.py", "content": "def test_x():\n    assert True\n", "run_with": "pytest"}))
        blocks.append(NS(type="tool_use", id="f", name="finish", input={"summary": "scripted"}))
        return NS(content=blocks, stop_reason="tool_use", usage=None)


class AgentEvalTest(unittest.TestCase):
    def test_bundled_corpus_is_raised_by_the_scanner(self) -> None:
        cases = load_cases()
        self.assertGreaterEqual(len(cases), 8)
        results = [run_case(c, client=ScriptedClient(lambda r, p: "confirmed"), model="acme-opus-9") for c in cases]
        s = score(results)
        self.assertEqual(s["scanner_misses"], 0, [r.missing_findings for r in results])
        self.assertEqual(s["tp_retention"], 1.0)
        self.assertEqual(s["fp_removal"], 0.0)

    def test_perfect_oracle_scores_full_agreement(self) -> None:
        cases = load_cases()
        truth = {}
        for c in cases:
            for key, label in c["expect"].items():
                rule, rest = key.split("@", 1)
                truth[(rule, rest.rsplit(":", 1)[0])] = label
        oracle = lambda r, p: "confirmed" if truth.get((r, p)) == "tp" else "false_positive"
        s = score([run_case(c, client=ScriptedClient(oracle), model="acme-opus-9") for c in cases])
        self.assertEqual(s["agreement"], 1.0)

    def test_proofs_are_written_for_confirmed_findings_only(self) -> None:
        from rempart.agent import VerificationAgent
        from rempart.config import Config
        from rempart.engine import discover, run_scan
        from rempart.scanners import ALL_SCANNERS

        case = next(c for c in load_cases() if c["name"] == "py-path-traversal")
        tmp = Path(tempfile.mkdtemp(prefix="rempart-proof-"))
        for rel, text in case["files"].items():
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp / rel).write_text(text)
        result = run_scan(tmp, [ALL_SCANNERS["code"]], Config(), offline=True)
        files, _ = discover(tmp, Config())
        targets = [f for f in result.findings if f.rule.id == "CODE-PATH-TRAVERSAL"]
        agent = VerificationAgent(result, files, client=ScriptedClient(lambda r, p: "confirmed"), model="acme-opus-9")
        report = agent.run(targets)
        written = write_proofs(report, result.findings, tmp / "rempart-proofs")
        self.assertEqual([p.name for p in written], ["test_proof_0.py"])
        self.assertIn("never runs them", (tmp / "rempart-proofs" / "README.md").read_text())


if __name__ == "__main__":
    unittest.main()
