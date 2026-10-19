# Roadmap

Direction: no new domains, no public release for now. Every existing domain goes
deeper, the attack-path idea stays the centre, and the learning loop becomes the
backbone: Rempart should be measurably better on a project after a month of use
than on day one.

Each item lists the signal that justifies it and how it is measured. Shipped items
move to the changelog.

## Principles for every item

1. **Measured before and after.** No depth work without a labelled corpus for its
   domain and a number in `rempart bench`. A change that lowers a number is a regression.
2. **Learnable.** Knowledge a rule depends on (sources, sinks, sanitisers, safe
   wrappers, placeholders, trusted actions) lives in data the learning loop can
   extend per project, not only in Python code.
3. **Explainable.** Every learned adjustment says which verdicts produced it.
4. **Local.** Learning stays on the machine; sharing is an explicit file, never a service.

---

## Status

| Lot | State |
|---|---|
| 1 Measure | `rempart bench` (bundled regression corpus, CI gate) and `rempart learn --eval` shipped. **Missing:** held-out external sets. |
| 2 Learning v2 | Implicit signals, regressions, project knowledge with `--because`, agent/assistant proposals, rule versions, time decay, replay shipped. **Missing:** multi-factor calibration, fingerprints that follow renames, agent few-shot from team verdicts, `rempart corpus add`. |
| 3–5 | Not started. The bench already names their first targets: `var.*` in Terraform, JS across modules. |

## Lot 1: measure everything (foundation)

Today only Python code (OWASP Benchmark) and the agent (9 cases) are measured, and
the Python score was tuned on the benchmark it reports.

- **`rempart bench`**: one command, one labelled corpus per domain (code per
  language, secrets, deps reachability, Terraform, Kubernetes, CI/CD, data, AI,
  attack paths). Output: precision, recall, Youden per domain, JSON for CI.
- **Held-out sets.** Corpora never used while tuning: OWASP Benchmark Java (for the
  JVM rules), Juice Shop and NodeGoat (JS/TS), TerraGoat and kubernetes-goat (IaC),
  vulnerable GitHub Actions labs (CI/CD). Report them separately from tuning sets.
- **Learning replay.** `rempart learn --eval` replays the history in time order:
  calibrate on verdicts before day *t*, score findings after *t*. Report
  precision@10 and false positives in the top 20, with and without learning.
  This is the proof that "it learns" is true.
- **CI gate**: bench numbers checked in; a drop beyond tolerance fails the build.

## Lot 2: learning v2 (the backbone)

Today: a Beta posterior per rule and per rule × kind of file, exact-fingerprint
suppression, severity can only go down, only explicit verdicts count.

- **Implicit signals.** A finding that disappears because the lines it points to
  were edited counts as a likely true positive (weight 0.5). A whole file deleted
  does not count. An inline `rempart:ignore` counts as a false positive or accepted risk
  for that project. A finding that comes back after being fixed is a regression and is
  raised one level.
- **Project knowledge base** (`.rempart/knowledge.toml`, committable): learned
  sanitisers, validators, safe wrappers, trusted internal hosts, placeholder secret
  values, trusted actions. Filled from verdict reasons
  (`rempart triage <id> --fp --because sanitizer:clean_html`) and from the agent's
  evidence, then fed back into the data-flow engines as real sanitisers. One
  verdict fixes a whole class of findings, not one fingerprint.
- **Richer calibration.** Move from rule × context to a hierarchical model over
  rule, kind of file, language, framework, verification level and data-flow depth
  (hops between source and sink). Each factor's effect is shown in the note. Severity can go up
  when a rule is repeatedly confirmed in a context, not only down.
- **Rule versions.** Each rule carries a version; when its logic changes, older
  verdicts are down-weighted instead of mis-calibrating the new logic.
- **Fingerprints that follow code.** Use git rename detection and a fuzzy anchor
  (normalised AST or token shingle) so verdicts survive moves and refactors.
- **Agent learns from the team.** The agent prompt gets the most similar human
  verdicts from the same project (rule, file, reasoning). `rempart corpus add <id>`
  turns a human verdict into an `agent-eval` case, so the corpus grows with use.
- **Time decay**: old verdicts weigh less than recent ones, so a project that
  changes its stack is not judged on its past.

## Lot 3: understand the infrastructure as it really is

Today: Terraform is read block by block with regexes, values like `var.x` are not
resolved, Kubernetes charts are not rendered, exposure is decided per resource.

- **Terraform evaluation**: variables with defaults and `.tfvars`, `locals`, local
  modules, `count` / `for_each`, `dynamic` blocks. Accept `terraform show -json`
  plans as the most precise input when present.
- **Effective exposure.** A security group is "internet-exposed" only if it is
  attached to something with a public IP or load balancer in a subnet routed to an
  internet gateway. An S3 bucket is public from the combination of policy, ACL and
  public-access block. Same reasoning for GCP firewall + external IP and Azure NSG + public IP.
- **IAM reasoning, offline**: parse policies into effective permissions, then the
  known privilege-escalation techniques (`iam:PassRole` + `lambda:CreateFunction`,
  `iam:CreatePolicyVersion`, `sts:AssumeRole` chains, GCP `iam.serviceAccounts.actAs`,
  Azure role assignment write). Applies to Terraform and to the live audits.
- **Kubernetes rendered**: `helm template` / `kustomize build` when the CLIs exist;
  effective Pod Security level per namespace; NetworkPolicy coverage per pod; RBAC
  escalation graph (who can create pods → mount a service account → reach
  cluster-admin); Ingress → Service → Pod exposure.
- **Compose and Dockerfile**: published ports bound to all interfaces, secrets
  copied in one stage and left in the final one, build args leaked to layers.
- **Live cloud ↔ repository links**: tags, state outputs and ARNs tie a live
  resource to the Terraform block and the image that made it, so live chains can be `linked`.
- **Images**: attribute each vulnerable package to the layer and Dockerfile
  instruction that introduced it; recommend the base-image tag that fixes the most;
  BerkeleyDB rpmdb (RHEL 7/8) and the Red Hat advisory feed.

## Lot 4: code and pipelines at the same depth as Python

Today: Python is inter-procedural; JS/TS stops at the file; Go, Java, PHP, Ruby,
C# are line rules; CI/CD is checked step by step.

- **JS/TS across modules**: resolve `import` / `require` / path aliases from
  `tsconfig.json`, summaries cross files as in Python. Framework models for Express,
  Fastify, NestJS, Next.js route handlers and server actions.
- **Sources, sinks and sanitisers as data** (YAML catalogues per language and
  framework), shared by the static engines, the learning loop (Lot 2) and the agent.
- **Go and Java with real parsing** (optional `[parse]` extra on tree-sitter, line
  rules remain the zero-dependency fallback): intra-procedural taint first, then
  summaries. Measured on the held-out sets of Lot 1.
- **Authorization logic**: a route inventory per framework; a route without the
  auth decorator, middleware or check its neighbours have is ranked high in the IDOR
  queue, with the neighbours as evidence.
- **Dependencies through the call graph**: a vulnerable function is "reachable"
  only if a route or entry point reaches the call site, using the Python (then JS)
  summaries instead of a text search. Explain the transitive path (which direct
  dependency brings it). Flag major-version upgrades in the plan as breaking.
- **Secrets with blast radius**: for a live AWS/GCP key, what it can do (attached
  policies, read-only calls); link the key to its Terraform `aws_iam_access_key` or
  service account; for git history, the commit that introduced it and whether it
  reached a pushed branch.
- **CI/CD data flow**: untrusted expressions followed through `env`, step and job
  `outputs`, `GITHUB_ENV` / `GITHUB_OUTPUT`, reusable workflows and local composite
  actions; effective token permissions per job; environments and required reviewers
  as mitigations.
- **Data**: PII fields followed to logs, analytics and third-party calls through
  the flow engines; Supabase RLS policies evaluated (`using (true)` is open, `auth.uid()`
  checks are not); code that reads a sensitive table linked to the data store node.
- **AI and agents**: LLM output as a taint source in the flow engines; the
  "untrusted content + private data + outbound channel" combination in one agent
  reported as a chain; MCP tools graded by what they can touch.

## Lot 5: attack paths as reasoning, not a list

Today: 9 hand-written chain patterns, a BFS of at most 5 hops in the resource graph.

- **Capabilities, not patterns.** Each rule declares what an attacker needs and
  what they gain (network reach to X, code execution in workload Y, credentials of
  role Z, read on store S). Chains are found by search over the graph, so a new
  rule automatically joins every chain it fits. The 9 current patterns become test cases.
- **Cheapest fix.** A minimum cut over all chains: the smallest set of changes that
  breaks the most paths, ranked first in every report.
- **Agent-confirmed chains.** The agent receives each chain and has to prove or break
  every link, with file:line evidence and a proof test where possible.
- **Chains learn too.** A verdict on a chain propagates to its links and the
  reverse; a confirmed link raises the confidence of chains that share it.
- **Interactive graph** in the HTML report: nodes, routes, and the fix that cuts them.

---

## Order and exit criteria

| Lot | Done when |
|---|---|
| 1 Measure | `rempart bench` covers every domain; held-out numbers published in the README, even when low |
| 2 Learning v2 | Learning replay shows fewer false positives in the top 20 on real history; one `--because` verdict removes a class of findings |
| 3 Infrastructure | TerraGoat / kubernetes-goat recall up with no precision loss; privilege-escalation paths found on the cspm-lite lab |
| 4 Code and pipelines | JS held-out score within reach of Python; deps "reachable" only from entry points |
| 5 Attack paths | Current 9 chains reproduced by the generic engine; minimum-cut fix shown on the demo app |

## Deferred (decided, not forgotten)

PyPI release, Docker image, public repository, team server. Revisit after Lot 2.
