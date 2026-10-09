# Roadmap

Each item lists the signal that justifies it. Shipped items move to the changelog.

## Shipped in 0.2

Attack-path correlation, intra-procedural data flow (Python, JS/TS), dependency reachability, live secret verification, container image scanning without Docker, live AWS and Kubernetes audits, the AI verification agent, and the MCP server.

## Next: depth

- **Resource-level attack graph.** Link findings by resource (this security group protects that instance, which runs this image built from this repo) instead of repository co-occurrence. Signal: chains whose links concern different resources.
- **Inter-procedural data flow.** Summaries per function (parameter → sink) so taint crosses function boundaries in Python first, then JS/TS.
- **Git history secrets** (`rempart scan --history`).
- **Baseline mode** (`--baseline main`) for PR gating on legacy repositories.
- **Images:** RPM (rpmdb.sqlite), Go build info, Java JARs.

## Next: breadth

- Live GCP and Azure audits with the same `observed` model as AWS.
- Kubernetes admission-policy inventory (K04), NetworkPolicy coverage (K05).
- GraphQL depth/complexity limits, vector-store tenant filters (LLM08), notebooks with data in outputs.

## Agent

- Agent-assisted chain confirmation: give the agent each `CHAIN-*` finding and ask it to prove or break the link at resource level.
- Batch mode through the Message Batches API for nightly runs at half price.
- Evaluation set: a labelled corpus of true and false positives to measure agent precision per rule and catch regressions when the model or prompt changes.

## Distribution

- PyPI release, pre-commit hook, Docker image (distroless, non-root, digest-pinned), VS Code problem matcher.
