# Changelog

## 0.1.0 (2026-10-08)

First release.

- 216 rules across 13 domains: secrets, code, dependencies, supply chain, IaC, containers, Kubernetes, CI/CD, data, AI/agents, quality, performance, web.
- Dependency vulnerabilities from OSV.dev, ranked with CISA KEV and FIRST EPSS; malicious-package detection.
- Passive web audit (`rempart web`).
- Local learning loop: scan history, new/fixed diff, MTTR, triage verdicts and per-rule precision calibration.
- Console, JSON, SARIF 2.1.0, Markdown and HTML reports; composite GitHub Action.
- Precision tuned on real repositories; each false positive found became a regression test (54 tests).
