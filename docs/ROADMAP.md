# Roadmap

Each item lists the signal that justifies it. Shipped items move to the changelog.

## Shipped in 0.3

Inter-procedural Python data flow, JS/TS function summaries, resource-level attack graph, dev/prod and function-level dependency reachability with an upgrade plan, git-history secrets, baseline mode, watch mode, live GCP and Azure, RPM/Go/JAR in images, agent proof tests and evaluation corpus, per-context learning, PR comments, pre-commit hooks, release workflow.

## Shipped in 0.2

Attack-path correlation, intra-procedural data flow (Python, JS/TS), dependency reachability, live secret verification, container image scanning without Docker, live AWS and Kubernetes audits, the AI verification agent, and the MCP server.

## Next: depth

- **Cross-module JS/TS data flow.** Resolve imports so summaries cross files, as Python already does. Signal: the agent corpus case where a sanitiser lives in another module.
- **Live cloud ↔ repository links.** Tie an observed security group or instance to the Terraform resource and image that created it (tags, ARNs in state outputs), so live chains can be `linked`.
- **Agent-confirmed attack paths.** Give the agent each `CHAIN-*` and ask it to prove or break the link, with a proof test where possible.
- **RHEL BerkeleyDB rpmdb** and the Red Hat advisory feed.

## Next: breadth

- Kubernetes admission-policy inventory (K04), NetworkPolicy coverage (K05).
- GraphQL depth/complexity limits, vector-store tenant filters (LLM08), notebooks with data in outputs.
- More live cloud checks for GCP and Azure (logging sinks, KMS rotation, AKS/GKE).

## Agent

- Publish agent-eval results per model in the README once measured with a live key.
- Batch mode through the Message Batches API for nightly runs at half price.

## Distribution

- PyPI release (the workflow is ready: push a `v0.3.0` tag and approve the `pypi` environment), Docker image (distroless, non-root, digest-pinned), VS Code problem matcher.
