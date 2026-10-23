# Changelog

## Unreleased

Measure everything, learn from everything.

- **`rempart bench`**: a labelled corpus of 22 small repositories covering every file-reading domain (90 issues, 73 traps), per-domain precision and recall, `--check` against `bench/baseline.json` in CI so no domain can regress, `--corpus DIR` for external labelled sets. Labels are comments (`rempart-expect`, `rempart-safe`, `rempart-alt`, `rempart-expect-file`); credentials are filled in at run time, so the repository holds no literal token.
- **Learning v2**:
  - `rempart triage ID --fp --because sanitizer:NAME[=categories]` or `placeholder:VALUE` writes `.rempart/knowledge.toml`. A learned sanitiser is applied by the Python data-flow engine and the JS/TS analysis, for the triaged rule's category, so one verdict removes a whole class. Placeholders are never reported as secrets.
  - The agent (`record_verdict.sanitizer`) and MCP assistants (`rempart_triage.because`) can only propose a sanitiser; `rempart learn --accept-proposals` applies them.
  - Implicit evidence: a finding that disappears between two scans run the same way (version, options, configuration, knowledge) while its file is still scanned counts as a fix (true positive, weight 0.5); if it comes back it is a regression, raised one level. `rempart:ignore` counts as false-positive evidence (0.5).
  - Evidence decays with age (half-life one year) and counts 0.25 when it judged an older version of the rule (`Rule.version`). The calibration prior is the finding's own confidence, not only the rule's.
  - `rempart learn --eval` replays the history in time order: ranking AUC, Brier score and false alarms in the top 10 / 20, with versus without learning. `rempart learn` shows evidence by source and the project knowledge.
  - The scan header separates "fixed" from "no longer reported" when the scan options or learned knowledge changed.
- **Defects found while building the bench**, each with a regression test and a bench case:
  - Java: JDBC concatenation was missed when the SQL literal contained a quote.
  - Typosquats were never checked on exactly pinned requirements (`reqeusts==2.31.0`).
  - `ENV API_SECRET_FILE=/run/secrets/api` was reported as a baked-in secret.
  - The AWS documentation key `AKIAIOSFODNN7EXAMPLE` was reported as a live key.
  - Payment card numbers in files under 200 bytes were skipped.
  - Model output was only tracked to a sink on the same line; it now follows variables (`msg = client.messages.create(...)`, `cmd = msg.content[0].text`, `subprocess.run(cmd, shell=True)`).
  - Python: bound parameters passed through a helper (`execute(query, params)`) counted as SQL injection; a Python-specific copy of the line-level SQL rule duplicated the data-flow engine and fired on values it had proven clean.
  - Flask 2 shortcut decorators (`@app.get`, `@bp.post`) were treated as JSON APIs, so XSS in their HTML responses was missed.
  - `["ping", "-c", "1", host]` was reported as a shell script (`-c` alone was taken for `sh -c`).
  - Terraform findings pointed one line above the resource when a blank line preceded it.
- **`rempart tui`** (`[tui]` extra, Textual): five views (overview with "fix first", findings, attack paths drawn stage by stage, dependencies, learning), scan progress, command palette, help, triage (`t` / `f` / `a`), teach a reason (`b`, then an automatic rescan), open in the editor (`x`), export HTML (`e`). Same pipeline and history as the CLI. Attack-path findings now carry their `stages` and `break_first`; `run_scan` takes a `progress` callback.
- OWASP Benchmark for Python unchanged at 99.4. 160 tests.

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
