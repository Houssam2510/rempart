# Architecture

## Design goals

1. **Zero setup.** Python 3.11+ and PyYAML. No database server, no account, no API key.
2. **One pass, many domains.** A single file walk feeds every scanner, so adding a domain does not add a pass over the repository.
3. **Precision over volume.** Rules need a dangerous sink *and* an untrusted or dynamic argument. Every false positive found in real repositories becomes a regression test.
4. **Explainable ranking.** Every number in a report can be recomputed by hand from the formula in the README.
5. **Local learning.** Feedback stays on the machine and improves the next scan.

## Data flow

```
discover()            git ls-files -co --exclude-standard (honours .gitignore), or os.walk
   │                  skips vendored/build dirs, binaries, files > 2 MB, .rempart.toml excludes
   ▼
ScanContext           lazy, cached text per file; is_committed() for "is this in the repo?"
   │
   ▼
scanners[*].scan(ctx) → Iterable[Finding]       (a crashing scanner is reported, not fatal)
   │
   ▼
run_scan()            config.disable, severity overrides, inline `rempart:ignore`, de-duplication
   │
   ▼
--baseline REF        scan REF in a throwaway git worktree, keep only findings it does not have
   │
   ▼
History.apply_knowledge()   drop fingerprints marked FP/accepted, recalibrate confidence per rule × kind of file
   │
   ▼
build_graph() + correlate()   resource graph → CHAIN-* findings, linked (with route) or co-occurrence
   │
   ▼
reporters             console · JSON · SARIF 2.1.0 · Markdown · HTML
```

## Beyond the repository

```
rempart image REF|tar   images.py      registry v2 client (token auth) → layers streamed → whiteout-aware ImageFS
                                        → os-release, dpkg/status(.d), apk db, dist-info, node_modules, lockfiles
                                        → DependencyScanner.vulnerabilities() (OSV + KEV + EPSS) + EOL + config + secrets
rempart cloud aws       cloud_aws.py   AWSAudit(session): global IAM/S3/CloudTrail, then regions in parallel;
                                        every API error becomes an AWS-CHECK-SKIPPED finding, never a crash
rempart cloud gcp|azure cloud_multi.py GCPAudit / AzureAudit over a Runner (gcloud / az JSON); fixtures in tests replace the Runner
rempart k8s             kube_live.py   kubectl get … -o json → KubernetesScanner.document() on live objects
scan --git-history      continuous.py  git log -p --all: added lines × provider regexes, minus what is still in the tree
rempart watch           continuous.py  tree signature (HEAD + status + mtimes) → re-scan → new / fixed
rempart scan --aws/--image             merges those findings before correlation
```

## Intelligence layers

| Layer | Module | Effect on a finding |
|---|---|---|
| Data flow | `pyflow.py` (`FunctionFlow`, `build_index` summaries), `scanners/code.py` (`js_tracked_names`, `js_function_summaries`) | Python: values carry taint/sanitisation/constants through branches, loops and guards; every function and method is summarised over 3 rounds so taint and constants cross functions and files. JS/TS: variables and functions within a file |
| Reachability | `reachability.py`, `scanners/deps.py` | `verification` = function-reachable (call site of an OSV-listed symbol) / reachable / imported / declared / not-imported; dev-only packages one level lower; `upgrade_plan()` per package |
| Live verification | `verify.py` | `live-secret` → CRITICAL, confidence 1.0; `revoked-secret` → LOW |
| Resource graph | `graph.py` | nodes: Terraform blocks, compose services, k8s objects, image build contexts; edges: references, depends_on/networks, selectors/service accounts/bindings, image built here → workload or `user_data` that runs it |
| Correlation | `correlate.py` | adds `CHAIN-*` findings (domain `attack-path`) after triage; infrastructure chains are `linked` only through a graph path, otherwise `co-occurrence` one level lower |
| AI review | `agent.py`, `agent_eval.py` | `ai-confirmed` / `ai-rejected` / `ai-uncertain`, reasoning and evidence in `extra`, proposed patches, proof tests (written, never run); `agent-eval` scores it on `corpus/agent_cases.json` |
| Learning | `history.py`, `knowledge.py` | Beta posterior per rule, then per rule × kind of file (code, scripts, tests, infra, CI, frontend, docs) with the rule-wide value as prior. Evidence from people, the agent, fixes and inline ignores, weighted by source, age and rule version; regressions raised one level. Project knowledge (learned sanitisers and placeholders) feeds the data-flow engines and the secrets scanner during the scan |

## Agent loop (`agent.py`)

Manual tool-use loop on the Anthropic Messages API (`client.beta.messages.create`): the newest Opus-tier model from the Models API unless `REMPART_MODEL` is set (adaptive thinking, effort `high`), strict tool schemas, automatic prompt caching, server-side refusal fallback (`fallbacks="default"`). History is append-only. Every `tool_use` gets a `tool_result` in the next user message, and errors come back as `is_error` results. Stops on `finish` once every target has a verdict, on refusal, or at the turn budget. The `Workspace` class is the agent's only access to the repository: read and search on files the scan discovered, nothing else.

## Terminal interface (`tui.py`)

Two layers. `Session` runs the `rempart scan` pipeline (knowledge, attack paths, history with the CLI's profile, `progress` callback) and records verdicts through `cli.triage`, the function `rempart triage` uses; `visible`, `domain_counts`, `fix_first`, `describe`, `describe_chain` and `code_context` are plain functions. `build_app` wraps them in a Textual application, imported lazily so the core keeps its single dependency. Scans run in a worker thread; table rows are keyed by position because a fingerprint can repeat at several lines; actions on findings are disabled (`check_action`) while a secondary screen is open. Tests drive the application headlessly with Textual's pilot.

## MCP server (`mcp_server.py`)

JSON-RPC 2.0 over stdio, newline-delimited. It implements `initialize` (protocol version negotiation), `ping`, `tools/list` and `tools/call`. Tool failures are returned as `isError: true` results, not protocol errors, so the calling model can read and recover.

## Core types (`models.py`)

- **Rule**: static knowledge. It holds the id, title, default severity, domain, CWE, OWASP 2025 category, other frameworks, remediation and a prior confidence.
- **Finding**: one occurrence. It holds the rule, path, line, message, snippet, `extra` (EPSS, KEV, package, data flow, AI reasoning…), a severity and confidence that can be adjusted, the learned note, and a **verification** level stating how the finding was established.
- **Fingerprint** = `sha256(rule_id | path | anchor)`, where the anchor is the normalised snippet (or a scanner-provided key). Line numbers are excluded on purpose, so triage verdicts survive unrelated edits.

## Scanners

| Module | Technique |
|---|---|
| `secrets.py` | Provider regexes, then entropy + placeholder filtering for generic assignments. Values are redacted before they reach a Finding. |
| `code.py` | Python: `ast.NodeVisitor` that distinguishes constant strings from f-strings/concatenation and request-derived values. Other languages: `LineRule` tables (sink pattern, `unless` sanitizer pattern, `file_unless`). File-level checks for multi-line constructs (CORS objects, postMessage, XXE factories, ReDoS, IDOR windows). |
| `deps.py` + `lockfiles.py` | 12 lockfile parsers, then OSV `querybatch`, then `/v1/vulns/{id}` details (8 threads), then KEV + EPSS. Alias collapsing (GHSA/PYSEC/CVE), a CVSS v3.1 base-score calculator, fixed-version extraction. Offline hygiene checks. |
| `terraform.py` | Brace-matching block reader (strings and comments aware). `jsonencode()` policies normalised to JSON keys before matching. |
| `containers.py` | Dockerfile instruction parser (continuations, stages); Compose through PyYAML. |
| `kubernetes.py` | Multi-document YAML, pod-spec extraction for all workload kinds, RBAC and bindings. |
| `cicd.py` | YAML-aware trigger and permission analysis plus line scanning of `run:` blocks; falls back to line checks on invalid YAML. |
| `data.py` | Connection strings, server configs (mongod, redis, pg_hba, postgresql.conf, my.cnf, elasticsearch.yml), BaaS rules, SQL migrations, PII/card detection with Luhn. |
| `ai.py` | MCP config parsing, invisible-Unicode and directive detection in agent rule files, output-to-sink and tool-execution heuristics. |
| `quality.py` | AST complexity, fail-open handlers, N+1 detection inside loop bodies. |
| `web.py` | `http.client` + `ssl`: redirects, headers, cookies, legacy TLS probes, certificate expiry, security.txt, warm/cold TTFB. |

## File kinds (`filekind.py`)

After the scanners run, every finding's file is classified from its path (and, for JavaScript/CSS, whether its lines are minified): `app`, `test`, `dev` (settings/dev*, *.local.*, compose files that run a development server or mount the source tree, `*initdb.d/`, seeds), `example` (examples/, samples/, demo/, docs/ code), `vendored` (vendor/, third_party/, static/**/lib/, bundles, minified files) or `docs` (prose). Vendored files lose their code, data, quality, performance and AI findings; prose loses code, data, quality and performance findings; dev and example findings drop one level (provider-format credentials in dev files keep theirs; secrets in example paths are lowered once, by the secrets scanner). Only `app` findings can be a stage of an attack path. The heuristics are listed in the module docstring (AUDIT.md R4).

## Network and caching

`netcache.py` wraps `urllib` with an on-disk JSON cache under `REMPART_HOME/cache` (OSV batch 6 h, advisory details 3 days, KEV 12 h, EPSS 24 h). An unwritable cache never blocks a lookup. `--offline` skips every network call and emits one INFO finding saying so.

## Learning store

SQLite at `REMPART_HOME/rempart.db` (older databases gain the new columns on first open):

- `scans(id, project, ts, score, grade, counts, files, duration, version, profile)`
- `findings(scan_id, fingerprint, rule_id, severity, path, line, message, base_severity, base_confidence)`
- `verdicts(project, fingerprint, rule_id, verdict ∈ {tp, fp, accepted}, note, ts, source ∈ {human, ai, implicit, inline}, path, rule_version, scope ∈ {project, global})`

`Calibrator` is a pure function of a list of `Evidence`: precision per rule is a Beta posterior (strength 4) whose prior is the finding's own confidence as the scanner produced it (`Finding.raw`), so a tainted data-flow hit and a bare pattern keep their difference. Each piece of evidence weighs `source × 0.5^(age/365 d) × (0.25 if rule_version < Rule.version)`. Severity changes (the input of `--fail-on`) are computed from human verdicts alone (`Calibrator.human_rule` / `human_context`); agent (`ai`), assistant (`ai_assistant`, from MCP), implicit and inline evidence only adjust confidence (AUDIT.md F3). A stronger source overwrites a weaker one (human > ai > implicit/inline), never the reverse. Suppression is per project and human-only. Calibration is per project too: a project is the root commit of its git history (plus the directory inside the repository), else its canonical path (`project_identity`), and older databases keyed by path are adopted on first use (`History.for_root`). Only a human verdict recorded with `--global` calibrates every project. `rempart:ignore` evidence is capped at `INLINE_CAP` per rule and project. This closes the poisoning shown in AUDIT.md (F1): scanning a third-party repository can no longer change how another project is judged.

**Implicit evidence.** The CLI stores a *profile* with every scan: kind, options, a hash of `.rempart.toml` and of the knowledge file. When two consecutive scans share version and profile, a finding of the earlier one that is absent from the later one, whose file was still scanned and that nobody judged, can only have gone because the code changed: an `implicit` true positive. If the same fingerprint comes back, it is a regression (`extra.regression`, severity +1). `rempart:ignore` lines produce `inline` false-positive evidence. When profiles differ, vanished findings are reported as "no longer reported", not fixed.

**Project knowledge** (`knowledge.py`, `.rempart/knowledge.toml`). `rempart triage ID --fp --because sanitizer:NAME[=categories]` records a sanitiser whose default category is the triaged rule's data-flow category (`rule_category`); `placeholder:VALUE` records a non-secret value. `run_scan` loads the file and exposes it through a context variable (`knowledge.active()`): `pyflow` treats the function as a sanitiser of those categories, the JS/TS analysis as a cleaner for the matching rules, the secrets scanner skips the values. The agent's `record_verdict` and the MCP `rempart_triage` can only *propose* a sanitiser (`[proposed.sanitizers]`); `rempart learn --accept-proposals` applies them.

**Replay** (`History.replay`, `rempart learn --eval`). Every finding a person judged is scored as it stood the day it first appeared, with the scanner's confidence and with a `Calibrator` built only from evidence dated earlier. The report gives ranking AUC, Brier score and precision / false alarms in the top 10 and 20, with and without learning.

## Bench

`bench.py` and `corpus/bench/`: each case is a small repository whose lines are labelled with comments (`rempart-expect`, `rempart-safe`, `rempart-alt`, `rempart-expect-file`). Cases are copied to a temporary directory with the labels removed and `{{FAKE_*}}` placeholders filled with credential-shaped strings built at runtime, then scanned offline with every scanner. A rule labelled anywhere in a case is fully labelled there, so any other finding of it is a false positive. `rempart bench --check bench/baseline.json` fails CI on any drop of precision or recall in any domain; `--corpus DIR` runs the same scoring on an external labelled set.

## Adding a rule

1. Declare it with `rule(...)` next to the scanner that detects it (id, severity, domain, CWE, OWASP 2025, remediation, prior confidence).
2. Emit `Finding(rule, path, line, message, snippet=...)` from the scanner.
3. Add a positive test and, whenever there is a plausible look-alike, a negative test.
4. Label a realistic occurrence and a look-alike in a bench case (`src/rempart/corpus/bench/`), then `rempart bench --update bench/baseline.json`.
5. When you change an existing rule's detection logic, bump its `version=` so older verdicts weigh less.
6. Run `rempart rules --markdown > docs/RULES.md`.
