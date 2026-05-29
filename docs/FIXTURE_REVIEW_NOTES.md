# Fixture Review Notes

The fixture set is sanitized, local, and designed to exercise parser shapes and report semantics without live enterprise access.

## Reviewed Fixtures

- `samples/support-agent`: Salesforce contact read, Gmail send, untrusted Zendesk input, approval gaps, and runtime observations.
- `samples/coding-agent`: repository operations, command-execution risk, source-code data classes, and IAM visibility gaps.
- `samples/demo-enterprise`: support, coding, release, finance, knowledge-assistant, and Microsoft 365 Copilot sales workflows.
- `tests/fixtures/adapters/openclaw_enterprise.json`: OpenClaw tool groups.
- `tests/fixtures/adapters/langchain_custom_manifest.json`: LangChain/custom manifest normalization.
- `tests/fixtures/adapters/github_app_manifest.json`: GitHub App permissions.
- `tests/fixtures/adapters/slack_oauth_manifest.json` and `google_oauth_tokeninfo.json`: OAuth scopes.
- `tests/fixtures/adapters/salesforce_profile_permissions.json`: Salesforce object permissions.
- `tests/fixtures/adapters/aws_policy_document.json`: AWS IAM actions.
- `tests/fixtures/adapters/kubernetes_rbac_list.json`: Kubernetes Role and ClusterRole rules.

## False-Positive Calibration

The scanner is conservative when identity, data classification, policy, or runtime evidence is missing.

- `weak` and `incomplete` findings use possible-path language.
- Missing IAM and classification evidence becomes a visibility gap.
- Runtime events increase confidence only for observed actions or correlated sequences.
- A single event is not treated as a full observed path unless the related sequence is present.

Accepted v1 shape: a sensitive-looking tool plus an external-send tool may produce a low or medium finding when identity evidence is absent. The report should request the next evidence instead of suppressing the path.

## False-Negative Calibration

Known limits:

- Weak tool descriptions can hide sensitive or dangerous behavior.
- OpenAPI field classification is heuristic and can miss organization-specific names.
- Approval policy matching uses the local normalized model. OPA/Rego and Cedar files are imported as evidence; the scanner does not execute external policy engines.
- Runtime reconstruction depends on session ids or equivalent event correlation.

These limits are surfaced through evidence quality labels and visibility gaps where possible.

## Coverage Decision

The fixture corpus is sufficient for the v1 local-first baseline because it covers:

- static evidence
- identity-backed supported paths
- missing identity and permission gaps
- partial and full runtime observations
- allowed and blocked runtime actions
- external send, production write, financial action, command execution, and memory retention rules
- adapter imports for common config and admin export shapes

More partner-specific admin exports remain calibration work, not an open v1 blocker.
