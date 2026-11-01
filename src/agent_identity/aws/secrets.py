"""Secret metadata only. Nothing here can read a secret value."""

from __future__ import annotations

import json
from typing import Any

from agent_identity.analysis.permissions import parse_policy
from agent_identity.aws.base import CoverageLog, attempt, quiet
from agent_identity.aws.session import client
from agent_identity.models import Secret

_VENDORS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "github": "GitHub",
    "gitlab": "GitLab",
    "slack": "Slack",
    "salesforce": "Salesforce",
    "zendesk": "Zendesk",
    "stripe": "Stripe",
    "jira": "Atlassian",
    "confluence": "Atlassian",
    "atlassian": "Atlassian",
    "notion": "Notion",
    "hubspot": "HubSpot",
    "google": "Google",
    "gemini": "Google Gemini",
    "okta": "Okta",
    "microsoft": "Microsoft",
    "azure": "Microsoft",
    "snowflake": "Snowflake",
    "datadog": "Datadog",
    "twilio": "Twilio",
    "sendgrid": "SendGrid",
    "mistral": "Mistral",
}


def vendor_for(name: str) -> str | None:
    lowered = name.lower()
    return next((vendor for key, vendor in _VENDORS.items() if key in lowered), None)


def collect_secrets(session: Any, region: str, coverage: CoverageLog) -> list[Secret]:
    api = client(session, "secretsmanager", region)

    def list_all() -> list[dict]:
        return [
            s
            for page in api.get_paginator("list_secrets").paginate()
            for s in page.get("SecretList", [])
        ]

    secrets = []
    items, _ = attempt(coverage, "Secrets Manager", region, list_all, [])
    for item in items:
        policy_text = quiet(
            lambda s=item: api.get_resource_policy(SecretId=s["ARN"]).get("ResourcePolicy")
        )
        secrets.append(
            Secret(
                arn=item["ARN"],
                name=item["Name"],
                kind="Secrets Manager",
                region=region,
                vendor=vendor_for(item["Name"]),
                rotation_enabled=bool(item.get("RotationEnabled")),
                last_rotated=item.get("LastRotatedDate"),
                last_accessed=item.get("LastAccessedDate"),
                created=item.get("CreatedDate"),
                kms_key_arn=item.get("KmsKeyId"),
                resource_policy=parse_policy("Resource policy", json.loads(policy_text))
                if policy_text
                else None,
            )
        )
    return secrets


def collect_parameters(
    session: Any, region: str, account_id: str, coverage: CoverageLog
) -> list[Secret]:
    api = client(session, "ssm", region)

    def list_all() -> list[dict]:
        pages = api.get_paginator("describe_parameters").paginate(
            ParameterFilters=[{"Key": "Type", "Values": ["SecureString"]}]
        )
        return [p for page in pages for p in page.get("Parameters", [])]

    items, _ = attempt(coverage, "SSM Parameter Store", region, list_all, [])
    secrets = []
    for item in items:
        name = item["Name"]
        arn = item.get("ARN") or (f"arn:aws:ssm:{region}:{account_id}:parameter/{name.lstrip('/')}")
        secrets.append(
            Secret(
                arn=arn,
                name=name,
                kind="SSM SecureString",
                region=region,
                vendor=vendor_for(name),
                last_rotated=item.get("LastModifiedDate"),
                kms_key_arn=item.get("KeyId"),
            )
        )
    return secrets
