# Release Checklist

Use this checklist before publishing an AgentGuard Graph package or tag.

## Scope

- `CHANGELOG.md` matches the implementation.
- `docs/ROADMAP.md` reflects closed work and future backlog.
- User-facing CLI changes are documented in `README.md` and `docs/E2E_WORKFLOW.md`.
- Unsupported live crawling, enforcement, telemetry, YAML OpenAPI parsing, and remote fetch behavior are explicit.
- `docs/V1_READINESS.md`, `schemas/v1/manifest.json`, and `docs/RELEASE_PROVENANCE.md` match the release.
- `docs/OPEN_SOURCE_PUBLISHING.md` has been reviewed for public positioning and hygiene.

## Safety

- Scanner and evidence strings are escaped in HTML.
- Reports are self-contained: no external JavaScript, CSS, fonts, images, or CDNs.
- Evidence files are never executed.
- Offline importers read local files only.
- Malformed JSON and JSONL produce clear errors.
- Missing evidence produces visibility gaps, not safety claims.
- `doctor` detects likely secrets before packaging.

## Quality Gates

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
coverage run --source=src/agentguard_graph -m unittest discover -s tests
coverage report -m --fail-under=85
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
PYTHONPATH=src python -m agentguard_graph.cli demo
```

## Artifact Checks

- Inspect `dist/agentguard_graph-*.whl`.
- Install the wheel in a clean virtual environment.
- Run `agentguard-graph demo`.
- Run `agentguard-graph init --sample support-agent`.
- Run `agentguard-graph validate --json --evidence-dir <sample-dir>`.
- Confirm package data includes sample packs.

## Repository Hygiene

- Keep generated `build/`, `*.egg-info`, `outputs/`, `.coverage`, `.coverage-deps`, `.wheels`, and `__pycache__/` out of source control.
- Keep local `agent-evidence/`, `*-evidence/`, `.env*`, `.vibeskills/`, and `.vibeskills-work/` out of source control.
- Do not publish evidence containing secrets, tokens, private keys, raw customer data, raw prompts, or proprietary descriptors.
- Use sanitized fixtures that still exercise real parser shapes.

## Versioning

The 1.0 release freezes:

- CLI command contract
- JSON report schema
- evidence schema versioning rules
- rule ids
- scoring dimension names and tier thresholds

Product version is `1.0.0`; evidence and report payloads retain `schema_version: "0.1"`.
