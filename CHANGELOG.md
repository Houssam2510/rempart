# Changelog

## 0.2.0 (2026-10-08)

Rempart becomes standalone and verifies what it reports.

- **Attack paths**: 9 cross-domain chain patterns (`CHAIN-*`), including live AWS findings.
- **Data flow**: per-function taint in the Python analyzer (request data, FastAPI parameters, interpolated strings); variable tracking for JS/TS.
- **Reachability** of vulnerable dependencies: imported, declared, or transitive-only.
- **Verification level** on every finding (static, reachable, observed, live-secret, correlated, ai-confirmed…).
- `--verify-secrets`: live check of leaked credentials for 13 providers through read-only identity endpoints; stdlib AWS SigV4 verified against botocore.
- `rempart image`: registry pull without Docker, OS and language packages, EOL OS and runtimes, secrets and config checks.
- `rempart cloud aws`: 28 live read-only checks, validated against AWS service models with botocore's Stubber.
- `rempart k8s`: live cluster audit through kubectl.
- `rempart agent`: LLM verification agent with read-only tools, evidence-backed verdicts and proposed fixes; AI verdicts count half and never close findings.
- `rempart mcp`: Model Context Protocol server for AI coding assistants (Cursor, VS Code, Windsurf…).
- `rempart scan --aws --image`: merge live sources into one correlated scan.
- 268 rules, 77 tests. False positives fixed from dogfooding: `RegExp.exec()` as command execution, `dict.get()` as N+1.

## 0.1.0 (2026-10-08)

First release.

- 216 rules across 13 domains: secrets, code, dependencies, supply chain, IaC, containers, Kubernetes, CI/CD, data, AI/agents, quality, performance, web.
- Dependency vulnerabilities from OSV.dev, ranked with CISA KEV and FIRST EPSS; malicious-package detection.
- Passive web audit (`rempart web`).
- Local learning loop: scan history, new/fixed diff, MTTR, triage verdicts and per-rule precision calibration.
- Console, JSON, SARIF 2.1.0, Markdown and HTML reports; composite GitHub Action.
- Precision tuned on real repositories; each false positive found became a regression test (54 tests).
