# Open Source Publishing Guide

Use this guide before making the repository public. AgentGuard Graph is ready to publish as a local-first AI agent security analyzer, but it should be positioned precisely.

## Positioning

Recommended description:

> AgentGuard Graph is a local-first, read-only analyzer for AI agent security evidence, attack paths, missing controls, and remediation planning.

Good claims:

- Reviews local evidence without connecting to production systems.
- Maps agents, tools, identities, data, approval policies, and runtime exports into a graph.
- Produces JSON, Markdown, and self-contained HTML security review reports.
- Finds missing evidence and likely control gaps.
- Creates owner-routed remediation plans.

Avoid claims:

- Runtime enforcement.
- Breach prevention.
- Complete coverage of all AI platforms.
- Proof that controls are enforced unless exported evidence proves them.
- Safety from absence of findings.

## Pre-Publish Checklist

1. Confirm `.gitignore` excludes generated artifacts, local evidence packs, caches, wheels, build outputs, and runtime session outputs.
2. Review `README.md` as the public landing page.
3. Review `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and `LICENSE`.
4. Run a local secret scan over evidence, samples, docs, and generated reports before publishing.
5. Run the release gates in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
6. Install from a clean checkout and run `agentguard-graph demo`.
7. Inspect the source tree for private prompts, customer data, credentials, internal hostnames, proprietary descriptors, or workspace-only artifacts.

## Repository Hygiene

Keep these out of source control:

- `build/`, `dist/`, `*.egg-info/`, `.wheels/`
- `__pycache__/`, `*.pyc`, coverage caches, test caches
- `outputs/`
- `agent-evidence/`, `*-evidence/`
- `.env`, `.env.*`
- `.vibeskills-work/` and other local runtime/session artifacts

Sanitized samples under `samples/`, `schemas/examples/`, and `src/agentguard_graph/sample_packs/` are intended to be published.

## Release Language

For the first public release, prefer:

- `v1 preview`
- `beta`
- `local-first offline analyzer`

Do not imply that AgentGuard Graph replaces policy gateways, sandboxing, approval brokers, runtime telemetry, or production authorization checks. It helps reviewers determine whether those controls are represented by evidence and where the gaps are.
