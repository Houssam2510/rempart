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
History.apply_knowledge()   drop fingerprints marked FP/accepted, recalibrate confidence per rule
   │
   ▼
reporters             console · JSON · SARIF 2.1.0 · Markdown · HTML
```

## Core types (`models.py`)

- **Rule**: static knowledge. It holds the id, title, default severity, domain, CWE, OWASP 2025 category, other frameworks, remediation and a prior confidence.
- **Finding**: one occurrence. It holds the rule, path, line, message, snippet, `extra` (EPSS, KEV, package…), a severity and confidence that can be adjusted, and the learned note.
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

## Network and caching

`netcache.py` wraps `urllib` with an on-disk JSON cache under `REMPART_HOME/cache` (OSV batch 6 h, advisory details 3 days, KEV 12 h, EPSS 24 h). An unwritable cache never blocks a lookup. `--offline` skips every network call and emits one INFO finding saying so.

## Learning store

SQLite at `REMPART_HOME/rempart.db`:

- `scans(id, project, ts, score, grade, counts, files, duration)`
- `findings(scan_id, fingerprint, rule_id, severity, path, line, message)`
- `verdicts(project, fingerprint, rule_id, verdict ∈ {tp, fp, accepted}, note, ts)`

Precision per rule is a Beta posterior whose prior is the rule's declared confidence (strength 4). Suppression is per project, while calibration is global, which is how one project's feedback improves scans of the next one.

## Adding a rule

1. Declare it with `rule(...)` next to the scanner that detects it (id, severity, domain, CWE, OWASP 2025, remediation, prior confidence).
2. Emit `Finding(rule, path, line, message, snippet=...)` from the scanner.
3. Add a positive test and, whenever there is a plausible look-alike, a negative test.
4. Run `rempart rules --markdown > docs/RULES.md`.
