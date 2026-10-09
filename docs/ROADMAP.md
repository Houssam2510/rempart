# Roadmap

The goal is breadth first, then depth where real scans show it is needed. Each item lists the signal that will justify it.

## 0.2: depth where it pays

- **Intra-file taint tracking for JS/TS** (source to variable to sink within a function) using a lightweight tokenizer, to catch values laundered through one or two assignments. Signal: misses found while triaging.
- **Git history secrets** (`rempart scan --history`): scan `git log -p` for secrets that were deleted but remain reachable.
- **Baseline mode** (`--baseline main`): report only findings introduced by a branch, for PR gating on legacy repos.
- **Helm and Kustomize**: render, then scan.
- **CloudFormation / CDK synth output** through the same IaC rule set.

## 0.3: data and AI depth

- Notebook scanning (outputs containing data, credentials in cells).
- Vector database queries without tenant filters (OWASP LLM08).
- GraphQL: introspection, depth and complexity limits.
- dbt / Airflow / Spark configs: credentials, public buckets in data pipelines.

## 0.4: closing the loop with the other two tools

- Import [cspm-lite](https://github.com/Houssam2510/cspm-lite) results so code-level and live-account findings share one score.
- Use the [triage](https://github.com/Houssam2510/triage) KEV/EPSS cache as a shared threat-intel store.
- Package-release cooldown policy: flag dependencies published less than N days ago, the main defence against worms shipping with valid provenance.

## Learning loop

- Per-project rule calibration on top of the global one, once a project has enough verdicts.
- Export and import anonymised rule statistics, so a team shares calibration without sharing code.
- Precision dashboard in the HTML report (rules ranked by learned precision and volume).

## Distribution

- Publish to PyPI as `rempart`.
- Pre-commit hook.
- VS Code task / problem matcher using the JSON output.
- Docker image (distroless, non-root, digest-pinned).
