# Changelog

## 0.3.0 (2026-10-09)

Depth, proof and continuity.

- **Inter-procedural data flow (Python)**: every function and method is summarised (parameter → return, parameter → sink, constant return) across files; values carry sanitisation, constants and container contents; guards (`abort()`, `commonpath`, allow-lists) clean what follows.
- **JS/TS**: functions of the same file are summarised; request data passed to a helper that reaches `exec`, `eval`, raw SQL, `fetch`, the file system or `innerHTML` is reported at the call site. An interpolated `exec` with no traced request data is MEDIUM.
- **OWASP Benchmark for Python: 99.4** (`bench/owasp_python.py`), up from 14.2 at the start of the release work.
- **Precision on 10 real repositories**: 8 % → 80 % strict on critical/high findings, all true positives kept.
- **Dependencies**: dev/prod scope (`--prod-only`), vulnerable-function reachability from OSV symbols, consolidated upgrade plan (console, JSON, Markdown).
- **Resource graph**: Terraform references, compose services, Kubernetes objects and the images the repository builds; chains are `linked` (with their route) or a `co-occurrence` one level lower.
- **Agent**: proof-of-exploitability tests for confirmed findings (`rempart-proofs/`, never executed); `rempart agent-eval` with a bundled labelled corpus.
- **Continuous**: `--git-history` secrets, `--baseline REF` through a temporary worktree, `rempart watch`, scheduled workflow template.
- **Coverage**: `rempart cloud gcp|azure` (22 checks through the official CLIs), RPM / Go binaries / JAR in images, 20 more secret formats and 11 more live verifiers.
- **DX**: per-context learning, action with baseline and pull-request comment, `--also FORMAT:PATH`, pre-commit hooks, release workflow with PyPI trusted publishing.
- 316 rules, 116 tests.

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
