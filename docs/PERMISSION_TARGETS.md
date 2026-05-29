# Permission Parser Targets

AgentGuard Graph prioritizes systems that commonly sit on agent attack paths: code, cloud, collaboration, identity, customer data, finance, production operations, and analytics.

## Top 20 Targets

1. GitHub
2. Google Workspace
3. Slack
4. Salesforce
5. AWS IAM
6. Kubernetes RBAC
7. Microsoft 365 / Microsoft Graph
8. Azure RBAC
9. Google Cloud IAM
10. Dataverse
11. Power Platform
12. Okta
13. Jira
14. Confluence
15. Zendesk
16. ServiceNow
17. Snowflake
18. Databricks
19. Stripe
20. NetSuite

## Collector Flags

- `--github-app-export`
- `--oauth-scopes-export`
- `--salesforce-permissions-export`
- `--aws-iam-policy`
- `--kubernetes-rbac`
- `--microsoft-365-permissions`
- `--azure-rbac`
- `--gcp-iam-policy`
- `--dataverse-permissions`
- `--power-platform-permissions`
- `--okta-permissions`
- `--jira-permissions`
- `--confluence-permissions`
- `--zendesk-permissions`
- `--servicenow-permissions`
- `--snowflake-grants`
- `--databricks-permissions`
- `--stripe-permissions`
- `--netsuite-permissions`

## Normalized Output

Each parser writes `identity.json` entries with:

- `target_system`
- `scopes`
- `permissions`
- `resource`
- `actions`
- `data_classes`
- `confidence`

Parsers are offline. Malformed rows produce collector warnings instead of silent drops.

## Least-Privilege Review

`scan` writes `iam_analysis` into the JSON report and the Markdown/HTML outputs. It reports:

- tools with explicit `tool_identity_bindings`
- tools inferred to one same-target identity
- tools with ambiguous same-target identities
- identities that no covered tool uses
- permissions that no covered tool explains
- least-privilege suggestions for GitHub, Google Workspace, Slack, Salesforce, AWS IAM, Kubernetes RBAC, Microsoft 365 / Microsoft Graph, Azure RBAC, Google Cloud IAM, and Okta

Use explicit bindings when one agent has multiple identities for the same target system. Without them, same-target credentials are reported as ambiguous.
