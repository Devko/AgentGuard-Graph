# Release Provenance

Release provenance makes AgentGuard Graph artifacts traceable without adding network behavior to the scanner.

## Model

Each release should have:

- versioned source tree
- local quality gate results
- clean package build
- SHA-256 checksums for built artifacts
- annotated signed tag when signing keys are available
- release notes linking the tag, checksums, and quality gate summary

The scanner remains local-first. Provenance work happens around publication.

## Steps

1. Confirm `pyproject.toml` and `src/agentguard_graph/__init__.py` contain the intended version.
2. Run the gates in `docs/RELEASE_CHECKLIST.md`.
3. Build the wheel from a clean checkout or equivalent source export.
4. Generate SHA-256 checksums for each artifact in `dist/`.
5. Create an annotated signed tag when signing keys are available:

```bash
git tag -s v1.0.0 -m "AgentGuard Graph 1.0.0"
```

6. If signed tags are unavailable, create an annotated tag and publish checksums with release notes explaining the constraint.
7. Link `docs/V1_READINESS.md`, `schemas/v1/manifest.json`, and the quality gate summary from release notes.

## Checksum Command

```bash
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python - <<'PY'
from hashlib import sha256
from pathlib import Path

for path in sorted(Path("dist").glob("*")):
    if path.is_file():
        print(f"{sha256(path.read_bytes()).hexdigest()}  {path.name}")
PY
```

## Retention

Keep:

- quality gate output
- wheel filename and checksum
- source commit or source archive hash
- signed or annotated tag name
- release notes
- checklist deviations

This is sufficient documented provenance for v1 when signed tags are not available. Signed tags remain preferred.
