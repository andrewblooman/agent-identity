"""IAM roles and users, with their policy documents."""

from __future__ import annotations

import time
from typing import Any

from agent_identity.analysis.permissions import parse_policy
from agent_identity.analysis.redaction import mask_key_id
from agent_identity.aws.base import quiet
from agent_identity.aws.session import client
from agent_identity.models import AccessKey, Identity, Policy

WORKLOAD_SERVICES = {
    "lambda.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "ec2.amazonaws.com",
    "bedrock.amazonaws.com",
    "bedrock-agentcore.amazonaws.com",
    "pods.eks.amazonaws.com",
}


def _trust(document: dict[str, Any] | None) -> tuple[list[str], bool]:
    principals: list[str] = []
    broad = False
    statements = (document or {}).get("Statement", [])
    for stmt in [statements] if isinstance(statements, dict) else statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            principals.append("*")
            broad = broad or not stmt.get("Condition")
            continue
        for values in principal.values():
            for value in [values] if isinstance(values, str) else values:
                principals.append(value)
                if value == "*" or (value.endswith(":root") and not stmt.get("Condition")):
                    broad = True
    return principals, broad


def _policy_index(details: dict[str, Any]) -> dict[str, Policy]:
    index: dict[str, Policy] = {}
    for item in details["Policies"]:
        version = next((v for v in item["PolicyVersionList"] if v.get("IsDefaultVersion")), None)
        arn = item["Arn"]
        index[arn] = parse_policy(
            item["PolicyName"],
            version["Document"] if version else None,
            arn=arn,
            managed_by_aws=arn.startswith("arn:aws:iam::aws:"),
        )
    return index


def _attached(item: dict[str, Any], index: dict[str, Policy], inline_key: str) -> list[Policy]:
    policies = [
        index.get(p["PolicyArn"]) or Policy(name=p["PolicyName"], arn=p["PolicyArn"])
        for p in item.get("AttachedManagedPolicies", [])
    ]
    policies += [
        parse_policy(p["PolicyName"], p.get("PolicyDocument")) for p in item.get(inline_key, [])
    ]
    return policies


def collect_identities(session: Any, account_id: str) -> tuple[list[Identity], dict[str, str]]:
    """Return identities and a map of instance profile ARN to role ARN."""
    iam = client(session, "iam")
    details: dict[str, list] = {"RoleDetailList": [], "UserDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
        Filter=["Role", "User", "LocalManagedPolicy", "AWSManagedPolicy"]
    ):
        for key in details:
            details[key].extend(page.get(key, []))
    index = _policy_index(details)
    identities: list[Identity] = []
    profiles: dict[str, str] = {}
    for role in details["RoleDetailList"]:
        for profile in role.get("InstanceProfileList", []):
            profiles[profile["Arn"]] = role["Arn"]
        if role.get("Path", "").startswith("/aws-service-role/"):
            continue  # AWS owns these, and they can't run an agent.
        principals, broad = _trust(role.get("AssumeRolePolicyDocument"))
        boundary_arn = (role.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        identities.append(
            Identity(
                arn=role["Arn"],
                name=role["RoleName"],
                kind="role",
                account_id=account_id,
                created=role.get("CreateDate"),
                last_used=(role.get("RoleLastUsed") or {}).get("LastUsedDate"),
                trusted_principals=principals,
                trust_is_broad=broad,
                policies=_attached(role, index, "RolePolicyList"),
                boundary=index.get(boundary_arn) if boundary_arn else None,
            )
        )
    for user in details["UserDetailList"]:
        boundary_arn = (user.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        identities.append(
            Identity(
                arn=user["Arn"],
                name=user["UserName"],
                kind="user",
                account_id=account_id,
                created=user.get("CreateDate"),
                policies=_attached(user, index, "UserPolicyList"),
                boundary=index.get(boundary_arn) if boundary_arn else None,
            )
        )
    return identities, profiles


def add_access_keys(session: Any, identity: Identity) -> None:
    iam = client(session, "iam")
    response = quiet(lambda: iam.list_access_keys(UserName=identity.name))
    if response is None:
        return
    for key in response.get("AccessKeyMetadata", []):
        used = quiet(lambda k=key: iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]), {})
        last = (used or {}).get("AccessKeyLastUsed", {})
        identity.access_keys.append(
            AccessKey(
                key_id=mask_key_id(key["AccessKeyId"]),
                status=key.get("Status", "Unknown"),
                created=key.get("CreateDate"),
                last_used=last.get("LastUsedDate"),
                last_service=last.get("ServiceName"),
                last_region=last.get("Region"),
            )
        )


def add_last_accessed(session: Any, identities: list[Identity], timeout: float = 30) -> None:
    """IAM last-accessed reports take seconds to build, so start them all, then collect them."""
    iam = client(session, "iam")
    jobs = {}
    for identity in identities:
        job = quiet(lambda i=identity: iam.generate_service_last_accessed_details(Arn=i.arn))
        if job:
            jobs[identity.arn] = (identity, job["JobId"])
    deadline = time.monotonic() + timeout
    while jobs and time.monotonic() < deadline:
        for arn, (identity, job_id) in list(jobs.items()):
            result = quiet(lambda j=job_id: iam.get_service_last_accessed_details(JobId=j))
            if result is None or result.get("JobStatus") == "FAILED":
                del jobs[arn]
            elif result.get("JobStatus") == "COMPLETED":
                identity.service_last_used = {
                    s["ServiceNamespace"]: s.get("LastAuthenticated")
                    for s in result.get("ServicesLastAccessed", [])
                }
                del jobs[arn]
        if jobs:
            time.sleep(1)


def simulate(
    session: Any, identity: Identity, checks: list[tuple[str, str]], results: dict[str, bool]
) -> None:
    """Confirm (action, resource) pairs for one identity with SimulatePrincipalPolicy."""
    iam = client(session, "iam")
    by_resource: dict[str, list[str]] = {}
    for action, resource in checks:
        by_resource.setdefault(resource, []).append(action)
    for resource, actions in by_resource.items():
        response = iam.simulate_principal_policy(
            PolicySourceArn=identity.arn,
            ActionNames=sorted(set(actions)),
            ResourceArns=[resource],
        )
        for item in response.get("EvaluationResults", []):
            allowed = item.get("EvalDecision") == "allowed"
            results[f"{identity.arn}|{item['EvalActionName']}|{resource}"] = allowed
