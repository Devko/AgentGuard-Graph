"""Offline importers for target-system identity permission exports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import load_json_file, source_name, string_list


def parse_github_app_export(path: str | Path) -> dict[str, Any]:
    data = load_json_file(path)
    source = source_name(path)
    warnings: list[str] = []
    app_name = str(data.get("slug") or data.get("name") or data.get("app_slug") or Path(path).stem)
    identity_id = str(data.get("identity_id") or data.get("id") or f"github:{app_name}")
    permissions = _github_permissions(data, source, warnings)
    normalized_permissions = []
    for name, level in sorted(permissions.items()):
        actions = _github_permission_actions(level)
        if not actions:
            continue
        normalized_permissions.append(
            {
                "resource": f"github.{name}",
                "actions": actions,
                "data_classes": _github_data_classes(name),
                "confidence": str(data.get("confidence", "high")),
                "raw": {"permission": name, "level": level},
            }
        )
    if not normalized_permissions:
        warnings.append(f"{source}: no GitHub App permissions found")
    return {
        "identities": [
            {
                "id": identity_id,
                "type": str(data.get("type", "github_app")),
                "target_system": "github",
                "scopes": [],
                "permissions": normalized_permissions,
                "confidence": str(data.get("confidence", "high")),
                "raw_source": source,
                "source_file": source,
                "raw": data,
            }
        ],
        "warnings": warnings,
    }


def parse_oauth_scope_export(path: str | Path) -> dict[str, Any]:
    data = load_json_file(path)
    source = source_name(path)
    warnings: list[str] = []
    scopes = _oauth_scopes(data, source, warnings)
    target_system = str(data.get("target_system") or _target_from_oauth_export(data, scopes) or "unknown")
    identity_id = str(data.get("identity_id") or data.get("id") or f"{target_system}:{Path(path).stem}")
    permissions = []
    for scope in scopes:
        permissions.append(
            {
                "resource": _oauth_scope_resource(target_system, scope),
                "actions": _oauth_scope_actions(scope),
                "data_classes": _oauth_scope_data_classes(target_system, scope),
                "confidence": str(data.get("confidence", "medium")),
                "raw": {"scope": scope},
            }
        )
    if not scopes:
        warnings.append(f"{source}: no OAuth scopes found")
    return {
        "identities": [
            {
                "id": identity_id,
                "type": str(data.get("type", "oauth_client")),
                "target_system": target_system,
                "scopes": scopes,
                "permissions": permissions,
                "confidence": str(data.get("confidence", "medium")),
                "raw_source": source,
                "source_file": source,
                "raw": data,
            }
        ],
        "warnings": warnings,
    }


def parse_salesforce_permissions_export(path: str | Path) -> dict[str, Any]:
    data = load_json_file(path)
    source = source_name(path)
    warnings: list[str] = []
    identity_id = str(data.get("identity_id") or data.get("id") or f"salesforce:{Path(path).stem}")
    object_permissions = (
        data.get("object_permissions")
        or data.get("objectPermissions")
        or data.get("ObjectPermissions")
        or data.get("objects")
        or data.get("records")
        or []
    )
    permissions = []
    if isinstance(object_permissions, dict):
        object_permissions = [
            {"object": object_name, **details} if isinstance(details, dict) else {"object": object_name, "actions": details}
            for object_name, details in object_permissions.items()
        ]
    elif object_permissions is None:
        object_permissions = []
    elif not isinstance(object_permissions, list):
        warnings.append(f"{source}: Salesforce object permissions must be a list or object")
        object_permissions = []
    for index, item in enumerate(object_permissions, start=1):
        if not isinstance(item, dict):
            warnings.append(f"{source}: Salesforce object_permissions[{index}] must be an object")
            continue
        object_name = str(item.get("object") or item.get("sobject") or item.get("name") or item.get("resource") or "")
        if not object_name:
            warnings.append(f"{source}: Salesforce object_permissions[{index}] is missing object/resource name")
            continue
        actions = _salesforce_actions(item)
        if not actions:
            warnings.append(f"{source}: Salesforce object_permissions[{index}] for {object_name} has no read/write actions")
            continue
        data_classes = string_list(item.get("data_classes")) or _salesforce_data_classes(object_name)
        permissions.append(
            {
                "resource": object_name if object_name.startswith("salesforce.") else f"salesforce.{object_name}",
                "actions": actions,
                "data_classes": data_classes,
                "confidence": str(item.get("confidence", data.get("confidence", "high"))),
                "raw": item,
            }
        )
    if not permissions:
        warnings.append(f"{source}: no Salesforce object permissions found")
    return {
        "identities": [
            {
                "id": identity_id,
                "type": str(data.get("type", "salesforce_connected_app")),
                "target_system": "salesforce",
                "scopes": string_list(data.get("scopes")),
                "permissions": permissions,
                "confidence": str(data.get("confidence", "high")),
                "raw_source": source,
                "source_file": source,
                "raw": data,
            }
        ],
        "warnings": warnings,
    }


def parse_aws_iam_policy_export(path: str | Path) -> dict[str, Any]:
    data = load_json_file(path)
    source = source_name(path)
    warnings: list[str] = []
    identity_id = _aws_identity_id(data, path)
    policy = _aws_policy_document(data)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif statements is None:
        statements = []
    elif not isinstance(statements, list):
        warnings.append(f"{source}: AWS IAM Statement must be an object or list")
        statements = []
    permissions = []
    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            warnings.append(f"{source}: AWS IAM Statement[{index}] must be an object")
            continue
        if str(statement.get("Effect", statement.get("effect", "Allow"))).lower() != "allow":
            continue
        raw_actions = statement.get("Action") or statement.get("action") or statement.get("NotAction") or statement.get("notAction")
        if not raw_actions:
            warnings.append(f"{source}: AWS IAM Statement[{index}] is missing Action")
            continue
        actions = string_list(raw_actions)
        raw_resources = statement.get("Resource") or statement.get("resource") or statement.get("NotResource") or statement.get("notResource")
        if not raw_resources:
            warnings.append(f"{source}: AWS IAM Statement[{index}] is missing Resource; using '*'")
        resources = string_list(raw_resources or "*") or ["*"]
        for resource in resources:
            normalized_actions = _aws_actions(actions)
            permissions.append(
                {
                    "resource": str(resource),
                    "actions": normalized_actions,
                    "data_classes": _aws_data_classes(actions, resource),
                    "confidence": str(data.get("confidence", "high")),
                    "raw": {"statement_index": index, **statement},
                }
            )
    if not permissions:
        warnings.append(f"{source}: no AWS IAM Allow statements found")
    return {
        "identities": [
            {
                "id": identity_id if str(identity_id).startswith("aws:") else f"aws:{identity_id}",
                "type": str(data.get("type", "aws_iam_role")),
                "target_system": "aws",
                "scopes": [],
                "permissions": permissions,
                "confidence": str(data.get("confidence", "high")),
                "raw_source": source,
                "source_file": source,
                "raw": data,
            }
        ],
        "warnings": warnings,
    }


def parse_kubernetes_rbac_export(path: str | Path) -> dict[str, Any]:
    data = load_json_file(path)
    source = source_name(path)
    warnings = []
    items_value = data.get("items")
    if items_value is None:
        items = [data]
    elif isinstance(items_value, list):
        items = items_value
    else:
        warnings.append(f"{source}: Kubernetes items must be a list")
        items = []
    identities = []
    for item_index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            warnings.append(f"{source}: Kubernetes items[{item_index}] must be an object")
            continue
        kind = str(item.get("kind", "Role"))
        if kind not in {"Role", "ClusterRole"}:
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        name = str(item.get("identity_id") or item.get("id") or metadata.get("name") or Path(path).stem)
        permissions = []
        raw_rules = item.get("rules", [])
        if raw_rules is None:
            raw_rules = []
        elif not isinstance(raw_rules, list):
            warnings.append(f"{source}: Kubernetes {kind} {name} rules must be a list")
            raw_rules = []
        for index, rule in enumerate(raw_rules, start=1):
            if not isinstance(rule, dict):
                warnings.append(f"{source}: Kubernetes {kind} {name} rules[{index}] must be an object")
                continue
            verbs = string_list(rule.get("verbs"))
            if not verbs:
                warnings.append(f"{source}: Kubernetes {kind} {name} rules[{index}] is missing verbs")
                continue
            if not rule.get("resources"):
                warnings.append(f"{source}: Kubernetes {kind} {name} rules[{index}] is missing resources; using '*'")
            resources = string_list(rule.get("resources")) or ["*"]
            api_groups = string_list(rule.get("apiGroups")) or [""]
            for resource in resources:
                permissions.append(
                    {
                        "resource": _kubernetes_resource(api_groups, resource),
                        "actions": verbs,
                        "data_classes": _kubernetes_data_classes(resource),
                        "confidence": str(item.get("confidence", data.get("confidence", "high"))),
                        "raw": {"rule_index": index, **rule},
                    }
                )
        identity_id = name if name.startswith("kubernetes:") else f"kubernetes:{name}"
        identities.append(
            {
                "id": identity_id,
                "type": str(item.get("type", kind.lower())),
                "target_system": "kubernetes",
                "scopes": [],
                "permissions": permissions,
                "confidence": str(item.get("confidence", data.get("confidence", "high"))),
                "raw_source": source,
                "source_file": source,
                "raw": item,
            }
        )
        if not permissions:
            warnings.append(f"{source}: no Kubernetes RBAC rules found for {identity_id}")
    if not identities:
        warnings.append(f"{source}: no Kubernetes Role or ClusterRole objects found")
    return {"identities": identities, "warnings": warnings}


def parse_microsoft_365_permission_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="microsoft_365",
        identity_prefix="microsoft365",
        default_type="microsoft_365_app",
        label="Microsoft 365",
        record_keys=[
            "permissions",
            "graph_permissions",
            "delegated_permissions",
            "application_permissions",
            "appRoles",
            "oauth2PermissionGrants",
            "roles",
            "items",
        ],
    )


def parse_azure_rbac_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="azure",
        identity_prefix="azure",
        default_type="azure_managed_identity",
        label="Azure RBAC",
        record_keys=["roleAssignments", "role_assignments", "assignments", "permissions", "roles", "items"],
    )


def parse_gcp_iam_policy_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="gcp",
        identity_prefix="gcp",
        default_type="gcp_service_account",
        label="GCP IAM",
        record_keys=["bindings", "iam_bindings", "policy_bindings", "permissions", "roles", "items"],
    )


def parse_dataverse_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="dataverse",
        identity_prefix="dataverse",
        default_type="dataverse_application_user",
        label="Dataverse",
        record_keys=["table_permissions", "tables", "privileges", "permissions", "roles", "items"],
    )


def parse_power_platform_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="power_platform",
        identity_prefix="powerplatform",
        default_type="power_platform_application_user",
        label="Power Platform",
        record_keys=["environment_permissions", "flows", "apps", "permissions", "roles", "items"],
    )


def parse_okta_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="okta",
        identity_prefix="okta",
        default_type="okta_service_app",
        label="Okta",
        record_keys=["roles", "admin_roles", "app_permissions", "permissions", "grants", "items"],
    )


def parse_jira_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="jira",
        identity_prefix="jira",
        default_type="jira_app",
        label="Jira",
        record_keys=["project_permissions", "permissions", "roles", "groups", "items"],
    )


def parse_confluence_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="confluence",
        identity_prefix="confluence",
        default_type="confluence_app",
        label="Confluence",
        record_keys=["space_permissions", "permissions", "roles", "groups", "items"],
    )


def parse_zendesk_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="zendesk",
        identity_prefix="zendesk",
        default_type="zendesk_integration",
        label="Zendesk",
        record_keys=["role_permissions", "permissions", "scopes", "roles", "items"],
    )


def parse_servicenow_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="servicenow",
        identity_prefix="servicenow",
        default_type="servicenow_integration",
        label="ServiceNow",
        record_keys=["acl_permissions", "table_permissions", "roles", "permissions", "items"],
    )


def parse_snowflake_grants_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="snowflake",
        identity_prefix="snowflake",
        default_type="snowflake_role",
        label="Snowflake",
        record_keys=["grants", "role_grants", "permissions", "privileges", "items"],
    )


def parse_databricks_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="databricks",
        identity_prefix="databricks",
        default_type="databricks_service_principal",
        label="Databricks",
        record_keys=["object_permissions", "permissions", "workspace_permissions", "grants", "items"],
    )


def parse_stripe_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="stripe",
        identity_prefix="stripe",
        default_type="stripe_restricted_key",
        label="Stripe",
        record_keys=["restricted_key_permissions", "permissions", "scopes", "resources", "items"],
    )


def parse_netsuite_permissions_export(path: str | Path) -> dict[str, Any]:
    return _parse_permission_records_export(
        path,
        target_system="netsuite",
        identity_prefix="netsuite",
        default_type="netsuite_role",
        label="NetSuite",
        record_keys=["role_permissions", "record_permissions", "permissions", "roles", "items"],
    )


def _parse_permission_records_export(
    path: str | Path,
    *,
    target_system: str,
    identity_prefix: str,
    default_type: str,
    label: str,
    record_keys: list[str],
) -> dict[str, Any]:
    data = load_json_file(path)
    source = source_name(path)
    warnings: list[str] = []
    identity_id = _prefixed_identity_id(
        str(
            data.get("identity_id")
            or data.get("principal_id")
            or data.get("principalId")
            or data.get("client_id")
            or data.get("app_id")
            or data.get("service_account")
            or data.get("role")
            or data.get("name")
            or Path(path).stem
        ),
        identity_prefix,
    )
    raw_records = _permission_records(data, record_keys, source, label, warnings)
    permissions = []
    for index, record in enumerate(raw_records, start=1):
        normalized = _normalize_permission_record(record, target_system, source, label, index, warnings)
        if normalized:
            permissions.append(normalized)
    if not permissions:
        warnings.append(f"{source}: no {label} permissions found")
    return {
        "identities": [
            {
                "id": identity_id,
                "type": str(data.get("type", default_type)),
                "target_system": target_system,
                "scopes": string_list(data.get("scopes") or data.get("oauth_scopes") or data.get("roles")),
                "permissions": permissions,
                "confidence": str(data.get("confidence", "medium")),
                "raw_source": source,
                "source_file": source,
                "raw": data,
            }
        ],
        "warnings": warnings,
    }


def _prefixed_identity_id(value: str, prefix: str) -> str:
    identity_id = value.strip() or prefix
    return identity_id if identity_id.startswith(f"{prefix}:") else f"{prefix}:{identity_id}"


def _permission_records(
    data: dict[str, Any],
    record_keys: list[str],
    source: str,
    label: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in record_keys:
        if key not in data:
            continue
        value = data.get(key)
        records.extend(_records_from_value(value, source, label, key, warnings))
    if not records:
        records.extend(_records_from_value(data, source, label, "root", warnings, allow_root_object=True))
    return records


def _records_from_value(
    value: Any,
    source: str,
    label: str,
    key: str,
    warnings: list[str],
    *,
    allow_root_object: bool = False,
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        if allow_root_object and any(field in value for field in _RESOURCE_KEYS + _ACTION_KEYS + _BOOLEAN_ACTION_KEYS):
            return [value]
        if not allow_root_object:
            records = []
            for resource, details in value.items():
                if isinstance(details, dict):
                    records.append({"resource": resource, **details})
                else:
                    records.append({"resource": resource, "actions": details})
            return records
        return []
    if isinstance(value, list):
        records = []
        for index, item in enumerate(value, start=1):
            if isinstance(item, dict):
                records.append(item)
            elif isinstance(item, str):
                records.append({"resource": item, "actions": ["use"], "raw_value": item})
            else:
                warnings.append(f"{source}: {label} {key}[{index}] must be an object or string")
        return records
    warnings.append(f"{source}: {label} {key} must be an object or list")
    return []


_RESOURCE_KEYS = [
    "resource",
    "resource_id",
    "resourceId",
    "resource_name",
    "resourceName",
    "scope",
    "scope_id",
    "object",
    "object_name",
    "objectName",
    "table",
    "table_name",
    "database",
    "schema",
    "collection",
    "project",
    "project_id",
    "service",
    "serviceName",
    "path",
    "name",
    "role",
    "role_name",
    "roleName",
    "roleDefinitionName",
    "permission",
]
_ACTION_KEYS = [
    "actions",
    "action",
    "verbs",
    "verb",
    "privileges",
    "privilege",
    "permissions",
    "permission",
    "scopes",
    "scope",
    "access",
    "level",
    "role",
    "role_name",
    "roleName",
    "roleDefinitionName",
]
_BOOLEAN_ACTION_KEYS = [
    "read",
    "view",
    "select",
    "list",
    "get",
    "write",
    "create",
    "update",
    "edit",
    "delete",
    "send",
    "execute",
    "run",
    "admin",
    "manage",
    "owner",
    "approve",
]


def _normalize_permission_record(
    record: dict[str, Any],
    target_system: str,
    source: str,
    label: str,
    index: int,
    warnings: list[str],
) -> dict[str, Any] | None:
    resource = _record_resource(record)
    if not resource:
        warnings.append(f"{source}: {label} permission[{index}] is missing resource")
        return None
    actions = _record_actions(record)
    if not actions:
        warnings.append(f"{source}: {label} permission[{index}] for {resource} has no actions")
        return None
    data_classes = string_list(record.get("data_classes")) or _target_data_classes(target_system, resource, actions)
    return {
        "resource": _prefixed_resource(target_system, resource),
        "actions": actions,
        "data_classes": data_classes,
        "confidence": str(record.get("confidence", "medium")),
        "raw": record,
    }


def _record_resource(record: dict[str, Any]) -> str:
    for key in _RESOURCE_KEYS:
        value = record.get(key)
        if value:
            return str(value)
    return ""


def _record_actions(record: dict[str, Any]) -> list[str]:
    explicit: list[str] = []
    for key in _ACTION_KEYS:
        if record.get(key):
            explicit.extend(string_list(record.get(key)))
    actions = set(_generic_actions(explicit))
    for key in _BOOLEAN_ACTION_KEYS:
        if record.get(key):
            actions.update(_generic_actions([key]))
    if not actions and record.get("raw_value"):
        actions.add("use")
    return sorted(actions)


def _generic_actions(values: list[str]) -> list[str]:
    actions: set[str] = set()
    for value in values:
        lowered = value.lower()
        if any(token in lowered for token in ["owner", "admin", "manage", "all", "*", "full"]):
            actions.update({"read", "write", "delete", "admin"})
        if any(token in lowered for token in ["read", "reader", "view", "viewer", "get", "list", "select", "monitor"]):
            actions.add("read")
        if any(
            token in lowered
            for token in ["write", "contribute", "contributor", "developer", "create", "update", "edit", "modify", "insert", "patch"]
        ):
            actions.add("write")
        if "delete" in lowered or "remove" in lowered or "drop" in lowered:
            actions.add("delete")
        if "send" in lowered or "message" in lowered or "mail" in lowered:
            actions.add("send")
        if "approve" in lowered or "approval" in lowered:
            actions.add("approve")
        if "execute" in lowered or "run" in lowered or "invoke" in lowered:
            actions.add("execute")
    return sorted(actions) or (["use"] if values else [])


def _prefixed_resource(target_system: str, resource: str) -> str:
    prefixes = {
        "microsoft_365": "microsoft365",
        "power_platform": "powerplatform",
    }
    prefix = prefixes.get(target_system, target_system)
    return resource if resource.startswith(f"{prefix}.") else f"{prefix}.{resource}"


def _target_data_classes(target_system: str, resource: str, actions: list[str]) -> list[str]:
    text = f"{target_system} {resource} {' '.join(actions)}".lower()
    classes: set[str] = set()
    if any(token in text for token in ["secret", "credential", "token", "keyvault", "key_vault", "password"]):
        classes.add("secrets")
    if any(token in text for token in ["user", "employee", "people", "profile", "directory", "member", "group"]):
        classes.add("employee_pii")
    if any(token in text for token in ["customer", "contact", "account", "lead", "opportunity", "ticket", "case"]):
        classes.add("customer_pii")
    if any(token in text for token in ["payment", "invoice", "billing", "charge", "refund", "payout", "discount", "vendor"]):
        classes.update({"billing_data", "financial_data"})
    if any(token in text for token in ["repo", "repository", "source", "code", "pull_request", "merge"]):
        classes.add("source_code")
    if any(
        token in text
        for token in [
            "production",
            "deploy",
            "cluster",
            "lambda",
            "function",
            "vm",
            "compute",
            "pipeline",
            "workflow",
            "environment",
            "infrastructure",
            "role assignment",
            "subscription",
            "resourcegroup",
            "resource group",
        ]
    ):
        classes.add("production_config")
    if any(token in text for token in ["log", "audit", "incident", "alert", "monitor", "security", "event"]):
        classes.add("security_logs")
    if target_system in {"snowflake", "databricks"} and any(token in text for token in ["table", "schema", "database", "warehouse"]):
        classes.add("internal")
    if target_system in {"microsoft_365", "google_workspace", "confluence", "jira", "zendesk", "servicenow", "okta"}:
        classes.add("internal")
    if target_system in {"stripe", "netsuite"}:
        classes.add("financial_data")
    return sorted(classes) or ["internal"]


def _github_permissions(data: dict[str, Any], source: str, warnings: list[str]) -> dict[str, Any]:
    permissions: dict[str, Any] = {}
    for key in [
        "permissions",
        "default_permissions",
        "repository_permissions",
        "organization_permissions",
        "account_permissions",
    ]:
        permissions.update(_permission_map(data.get(key), source, key, warnings))
    return permissions


def _permission_map(value: Any, source: str, label: str, warnings: list[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(name): level for name, level in value.items()}
    if not isinstance(value, list):
        warnings.append(f"{source}: GitHub {label} must be an object or list")
        return {}
    permissions: dict[str, Any] = {}
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            warnings.append(f"{source}: GitHub {label}[{index}] must be an object")
            continue
        name = item.get("name") or item.get("permission") or item.get("resource")
        if not name:
            warnings.append(f"{source}: GitHub {label}[{index}] is missing name/permission/resource")
            continue
        level = item.get("level") or item.get("access") or item.get("value") or item.get("permission")
        permissions[str(name)] = "read" if level is None else level
    return permissions


def _github_permission_actions(level: Any) -> list[str]:
    if isinstance(level, bool):
        return ["read", "write"] if level else []
    lowered = str(level).lower()
    if lowered in {"none", "false"}:
        return []
    if lowered in {"admin", "write", "true"}:
        return ["read", "write"]
    if lowered == "read":
        return ["read"]
    return [lowered]


def _github_data_classes(permission_name: str) -> list[str]:
    lowered = permission_name.lower()
    if lowered in {"contents", "pull_requests", "repository_projects"}:
        return ["source_code"]
    if lowered in {"actions", "workflows", "deployments", "environments", "administration"}:
        return ["production_config", "source_code"]
    if lowered in {"secrets", "codespaces_secrets"}:
        return ["secrets"]
    if lowered in {"security_events", "secret_scanning_alerts", "dependabot_alerts"}:
        return ["security_logs"]
    return ["internal"]


def _target_from_oauth_export(data: dict[str, Any], scopes: Any) -> str:
    scope_values = [scope.lower() for scope in string_list(scopes)]
    metadata_values = [
        data.get("issuer"),
        data.get("issuer_uri"),
        data.get("auth_uri"),
        data.get("authorization_uri"),
        data.get("token_uri"),
        data.get("audience"),
        data.get("resource"),
        data.get("client_uri"),
    ]
    metadata = " ".join(str(value) for value in metadata_values if value).lower()
    scope_text = " ".join(string_list(scopes)).lower()
    combined = f"{metadata} {scope_text}"
    if "gmail" in scope_text or "drive" in scope_text or "calendar" in scope_text or "googleapis" in scope_text:
        return "google_workspace"
    if "chat:" in scope_text or "channels:" in scope_text or "users:" in scope_text or "files:" in scope_text:
        return "slack"
    if "graph.microsoft.com" in combined or "microsoftonline.com" in combined:
        return "microsoft_365"
    if any(token in scope_text for token in ["mail.", "files.", "sites.", "calendars.", "directory.", "user.read", "chat.read", "team.read"]):
        return "microsoft_365"
    if any(
        scope in {"repo", "workflow", "gist"}
        or scope.startswith(
            (
                "repo:",
                "admin:org",
                "read:org",
                "write:org",
                "read:user",
                "user:",
                "read:packages",
                "write:packages",
                "delete:packages",
                "admin:repo_hook",
                "admin:public_key",
                "codespace",
                "copilot",
            )
        )
        for scope in scope_values
    ):
        return "github"
    if "okta." in scope_text or "okta.com" in combined:
        return "okta"
    if "jira" in scope_text:
        return "jira"
    if "confluence" in scope_text:
        return "confluence"
    if "salesforce.com" in combined:
        return "salesforce"
    return "unknown"


def _oauth_scopes(data: dict[str, Any], source: str, warnings: list[str]) -> list[str]:
    candidates = [
        ("scopes", data.get("scopes")),
        ("oauth_scopes", data.get("oauth_scopes")),
        ("granted_scopes", data.get("granted_scopes")),
        ("scope", data.get("scope")),
    ]
    oauth_config = data.get("oauth_config") if isinstance(data.get("oauth_config"), dict) else {}
    scope_config = oauth_config.get("scopes") if isinstance(oauth_config.get("scopes"), dict) else {}
    for key in ["bot", "user", "admin"]:
        candidates.append((f"oauth_config.scopes.{key}", scope_config.get(key)))
    for client_key in ["installed", "web"]:
        client_config = data.get(client_key) if isinstance(data.get(client_key), dict) else {}
        candidates.extend(
            [
                (f"{client_key}.scopes", client_config.get("scopes")),
                (f"{client_key}.oauthScopes", client_config.get("oauthScopes")),
                (f"{client_key}.scope", client_config.get("scope")),
            ]
        )

    scopes: list[str] = []
    seen: set[str] = set()
    for label, candidate in candidates:
        for scope in _split_scopes(candidate, source, label, warnings):
            if scope in seen:
                continue
            scopes.append(scope)
            seen.add(scope)
    return scopes


def _split_scopes(value: Any, source: str, label: str, warnings: list[str]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part for part in value.replace(",", " ").split() if part]
    if isinstance(value, list):
        scopes: list[str] = []
        for index, item in enumerate(value, start=1):
            scopes.extend(_split_scopes(item, source, f"{label}[{index}]", warnings))
        return scopes
    warnings.append(f"{source}: OAuth {label} must be a string or list of strings")
    return []


def _oauth_scope_resource(target_system: str, scope: str) -> str:
    cleaned = _normalized_oauth_scope(scope)
    namespace = _oauth_scope_namespace(target_system)
    if target_system in {"jira", "confluence"} and ":" in cleaned:
        resource = cleaned.split(":", 1)[1].split(".", 1)[0]
    elif target_system == "github" and ":" in cleaned:
        resource = cleaned.split(":", 1)[1]
    elif target_system == "okta" and cleaned.lower().startswith("okta."):
        parts = cleaned.split(".")
        resource = parts[1] if len(parts) > 1 else cleaned
    elif ":" in cleaned and not cleaned.startswith(("http://", "https://")):
        resource = cleaned.split(":", 1)[0]
    else:
        resource = cleaned.split(".", 1)[0]
    return f"{namespace}.{resource or 'scope'}"


def _oauth_scope_actions(scope: str) -> list[str]:
    lowered = scope.lower()
    actions: set[str] = set()
    if any(token in lowered for token in ["admin", "manage", "owner", "full_access"]):
        actions.update({"read", "write", "delete", "admin"})
    if any(token in lowered for token in ["readwrite", "read.write"]):
        actions.update({"read", "write"})
    if any(token in lowered for token in ["send", "write", "create", "update", "delete", "modify", "chat:write", "workflow"]):
        actions.add("write")
    if lowered == "repo" or lowered.startswith("repo:"):
        actions.add("write")
    if any(token in lowered for token in ["delete", "remove"]):
        actions.add("delete")
    if any(token in lowered for token in ["read", "readonly", "metadata", "users:", "channels:", "profile", "openid"]):
        actions.add("read")
    return sorted(actions) or ["use"]


def _oauth_scope_data_classes(target_system: str, scope: str) -> list[str]:
    lowered = scope.lower()
    if "gmail" in lowered or "mail" in lowered:
        return ["customer_pii", "internal"]
    if "drive" in lowered or "files" in lowered:
        return ["internal"]
    if "users" in lowered or "profile" in lowered:
        return ["employee_pii"]
    if target_system in {"slack", "google_workspace"}:
        return ["internal"]
    return []


def _normalized_oauth_scope(scope: str) -> str:
    cleaned = scope.strip()
    for prefix in [
        "https://www.googleapis.com/auth/",
        "https://graph.microsoft.com/",
        "https://outlook.office.com/",
    ]:
        if cleaned.lower().startswith(prefix):
            return cleaned[len(prefix) :]
    return cleaned


def _oauth_scope_namespace(target_system: str) -> str:
    namespaces = {
        "microsoft_365": "microsoft365",
        "google_workspace": "google_workspace",
    }
    return namespaces.get(target_system, target_system if target_system != "unknown" else "oauth")


def _salesforce_actions(item: dict[str, Any]) -> list[str]:
    explicit = string_list(item.get("actions"))
    if explicit:
        return explicit
    actions = []
    if _truthy(item, "read", "allowRead", "permissionsRead", "PermissionsRead"):
        actions.append("read")
    if _truthy(item, "create", "allowCreate", "permissionsCreate", "PermissionsCreate"):
        actions.append("write")
    if _truthy(item, "update", "edit", "allowEdit", "permissionsEdit", "PermissionsEdit"):
        actions.append("write")
    if _truthy(item, "delete", "allowDelete", "permissionsDelete", "PermissionsDelete"):
        actions.append("delete")
    if _truthy(item, "viewAllRecords", "ViewAllRecords"):
        actions.append("read")
    if _truthy(item, "modifyAllRecords", "ModifyAllRecords"):
        actions.extend(["read", "write", "delete"])
    return sorted(set(actions))


def _truthy(item: dict[str, Any], *keys: str) -> bool:
    return any(bool(item.get(key)) for key in keys)


def _aws_identity_id(data: dict[str, Any], path: str | Path) -> str:
    role = data.get("Role") if isinstance(data.get("Role"), dict) else data.get("role") if isinstance(data.get("role"), dict) else {}
    return str(
        data.get("identity_id")
        or data.get("id")
        or data.get("RoleName")
        or data.get("role_name")
        or role.get("RoleName")
        or role.get("role_name")
        or f"aws:{Path(path).stem}"
    )


def _aws_policy_document(data: dict[str, Any]) -> dict[str, Any]:
    for key in ["policy", "PolicyDocument", "policy_document", "Document", "document"]:
        value = data.get(key)
        if isinstance(value, dict):
            return value
    policy = data.get("Policy") if isinstance(data.get("Policy"), dict) else {}
    policy_document = policy.get("PolicyDocument") or policy.get("policy_document")
    if isinstance(policy_document, dict):
        return policy_document
    return data


def _salesforce_data_classes(object_name: str) -> list[str]:
    lowered = object_name.lower()
    if any(token in lowered for token in ["contact", "lead", "user", "person", "account"]):
        return ["customer_pii"]
    if "case" in lowered:
        return ["support_history", "customer_pii"]
    if any(token in lowered for token in ["payment", "invoice", "billing"]):
        return ["billing_data", "financial_data"]
    return ["internal"]


def _aws_actions(actions: list[str]) -> list[str]:
    normalized = set()
    for action in actions:
        lowered = action.lower()
        if any(token in lowered for token in ["get", "list", "describe", "read"]):
            normalized.add("read")
        if any(token in lowered for token in ["put", "create", "update", "delete", "write", "start", "stop", "run", "*"]):
            normalized.add("write")
    return sorted(normalized) or ["use"]


def _aws_data_classes(actions: list[str], resource: str) -> list[str]:
    text = " ".join(actions + [resource]).lower()
    classes = set()
    if any(token in text for token in ["secret", "ssm:getparameter", "kms:decrypt", "credential"]):
        classes.add("secrets")
    if any(token in text for token in ["iam:", "cloudformation", "eks:", "ecs:", "ec2:", "lambda:", "apigateway"]):
        classes.add("production_config")
    if any(token in text for token in ["s3:", "rds:", "dynamodb:", "redshift"]):
        classes.add("internal")
    if "codecommit" in text:
        classes.add("source_code")
    return sorted(classes)


def _kubernetes_resource(api_groups: list[str], resource: str) -> str:
    group = api_groups[0] if api_groups else ""
    return f"kubernetes.{group + '.' if group else ''}{resource}"


def _kubernetes_data_classes(resource: str) -> list[str]:
    lowered = resource.lower()
    if lowered == "secrets":
        return ["secrets"]
    if lowered in {"configmaps", "deployments", "statefulsets", "daemonsets", "pods", "services", "ingresses"}:
        return ["production_config"]
    if lowered in {"events", "logs"}:
        return ["security_logs"]
    return ["internal"]
