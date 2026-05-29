# Contributing

AgentGuard Graph has a narrow contract: normalize local evidence, build an agent security graph, analyze attack paths, and report unknowns. Contributions must preserve the local-first, read-only, no-telemetry boundary.

## Setup

```bash
pip install -e ".[dev]"
python -m compileall -q src tests
python -m unittest discover -s tests -v
coverage run --source=src/agentguard_graph -m unittest discover -s tests
coverage report -m --fail-under=85
```

The scanner runtime should stay standard-library-only unless the project explicitly accepts a new dependency.

## Rules

- Do not add network calls to the core scan path.
- Do not execute commands, code, prompts, tool descriptors, or evidence fields.
- Treat all evidence strings as untrusted.
- Escape HTML output.
- Keep reports self-contained.
- Report missing information as visibility gaps.
- Keep scoring explainable with named dimensions, controls, and caps.
- Add tests for parser, rule, report, and CLI changes.

## Evidence Adapters

Adapters import offline exports or static local config.

Expected behavior:

- accept JSON first
- preserve source metadata
- assign confidence explicitly
- keep inferred mappings conservative
- emit warnings for incomplete exports
- avoid secrets in samples and docs
- include fixture tests and an E2E path when `collect` behavior changes

## Findings And Scoring

New rules need:

- stable rule id
- graph node and edge references
- evidence summary
- unknowns and visibility gaps
- recommended next evidence
- remediation
- score dimensions and controls
- tests for positive and controlled cases

## Documentation

Update `README.md`, `docs/E2E_WORKFLOW.md`, `docs/ROADMAP.md`, and `CHANGELOG.md` when changing user-facing commands, evidence formats, report fields, or supported workflows.
