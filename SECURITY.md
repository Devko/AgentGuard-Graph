# Security Policy

AgentGuard Graph is a local-first, read-only analyzer. It parses local evidence and writes local reports. It must not execute evidence, call remote APIs in the core scan path, upload telemetry, or claim runtime enforcement.

## Supported Versions

Security fixes target the latest `main` branch and the latest `1.x` release.

## Reporting A Vulnerability

Report suspected vulnerabilities privately to the maintainers. If no private contact is configured, open a minimal public issue stating that a private report is needed. Do not publish exploit details or sensitive evidence in the issue.

Useful report details:

- affected command and version
- minimal redacted evidence file
- expected behavior
- actual behavior
- whether the issue involves HTML escaping, unsafe parsing, unexpected file access, command execution, or report data leakage

Do not include secrets, tokens, private keys, raw customer data, raw prompts, or proprietary agent evidence in public issues.

## Security Boundaries

- Evidence files are untrusted input.
- JSON and JSONL are parsed with standard-library parsers.
- Scanner input is never executed.
- HTML reports are self-contained and escape untrusted strings.
- Missing evidence remains a visibility gap.
- Offline importers read local files only.
- `doctor` detects likely secrets before evidence handoff.

## Out Of Scope

- Conservative findings caused by missing evidence.
- Possible paths that do not prove exploitability.
- Lack of live cloud/SaaS crawling.
- Lack of runtime enforcement.
- Unsupported YAML input in the dependency-free core path.
