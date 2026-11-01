"""S3, DynamoDB and RDS stores, with what's known about how sensitive they are."""

from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import ClientError

from agent_identity.analysis.permissions import parse_policy
from agent_identity.aws.base import CALL_FAILURES, CoverageLog, attempt, quiet
from agent_identity.aws.session import client
from agent_identity.models import CoverageStatus, DataStore, Domain, Sensitivity

_MAX_BUCKETS = 200
_CLASSIFICATION_TAGS = (
    "data-classification",
    "dataclassification",
    "classification",
    "sensitivity",
    "data-sensitivity",
    "data_classification",
)
_TAG_VALUES = {
    "restricted": Sensitivity.RESTRICTED,
    "secret": Sensitivity.RESTRICTED,
    "highly-confidential": Sensitivity.RESTRICTED,
    "pii": Sensitivity.RESTRICTED,
    "phi": Sensitivity.RESTRICTED,
    "pci": Sensitivity.RESTRICTED,
    "confidential": Sensitivity.CONFIDENTIAL,
    "sensitive": Sensitivity.CONFIDENTIAL,
    "internal": Sensitivity.INTERNAL,
    "private": Sensitivity.INTERNAL,
    "public": Sensitivity.PUBLIC,
}
_SENSITIVE_NAME = re.compile(
    r"customer|pii|payroll|finance|invoice|billing|medical|patient|claims|salary|tax|\bhr\b|-hr-"
    r"|credential|passport|ssn",
    re.IGNORECASE,
)


def classify(name: str, tags: dict[str, str]) -> tuple[Sensitivity, str]:
    lowered = {k.lower(): v.lower() for k, v in tags.items()}
    for key in _CLASSIFICATION_TAGS:
        if key in lowered and lowered[key] in _TAG_VALUES:
            return _TAG_VALUES[lowered[key]], "classification tag"
    if _SENSITIVE_NAME.search(name):
        return Sensitivity.CONFIDENTIAL, "name (inferred)"
    return Sensitivity.UNKNOWN, "not classified"


def _other_accounts(document: dict | None, account_id: str) -> list[str]:
    principals = []
    statements = (document or {}).get("Statement", [])
    for stmt in [statements] if isinstance(statements, dict) else statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        values = principal.get("AWS", []) if isinstance(principal, dict) else [principal]
        for value in [values] if isinstance(values, str) else values:
            if value == "*":
                principals.append("anyone")
            elif re.fullmatch(r"\d{12}", value) and value != account_id:
                principals.append(value)
            elif value.startswith("arn:aws:iam::") and f"::{account_id}:" not in value:
                principals.append(value.split(":")[4])
    return sorted(set(principals))


def _bucket_policy_read(call: Any) -> tuple[Any, bool]:
    """Return (value, known). Having no policy is an answer. Being refused one is not."""
    try:
        return call(), True
    except CALL_FAILURES as error:
        missing = (
            isinstance(error, ClientError)
            and error.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy"
        )
        return None, missing


def collect_s3(
    session: Any, account_id: str, data_events: set[str] | None, coverage: CoverageLog
) -> list[DataStore]:
    default = client(session, "s3", "us-east-1")
    buckets, _ = attempt(
        coverage, "S3", "global", lambda: default.list_buckets().get("Buckets", []), []
    )
    if len(buckets) > _MAX_BUCKETS:
        coverage.gap(
            "S3",
            "global",
            CoverageStatus.ERROR,
            f"Only the first {_MAX_BUCKETS} of {len(buckets)} buckets were checked",
            [Domain.DATA],
        )
    stores = []
    for bucket in buckets[:_MAX_BUCKETS]:
        name = bucket["Name"]
        location = quiet(lambda n=name: default.get_bucket_location(Bucket=n))
        region = (location or {}).get("LocationConstraint") or "us-east-1"
        api = client(session, "s3", region)
        tags_response = quiet(lambda n=name, api=api: api.get_bucket_tagging(Bucket=n), {})
        tags = {t["Key"]: t["Value"] for t in (tags_response or {}).get("TagSet", [])}
        sensitivity, source = classify(name, tags)
        encryption = quiet(
            lambda n=name, api=api: api.get_bucket_encryption(Bucket=n)[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
        )
        kms_key = None
        for rule in encryption or []:
            default_rule = rule.get("ApplyServerSideEncryptionByDefault") or {}
            kms_key = default_rule.get("KMSMasterKeyID") or kms_key
        status, status_known = _bucket_policy_read(
            lambda n=name, api=api: api.get_bucket_policy_status(Bucket=n)["PolicyStatus"]
        )
        policy_text, policy_known = _bucket_policy_read(
            lambda n=name, api=api: api.get_bucket_policy(Bucket=n)["Policy"]
        )
        document = json.loads(policy_text) if policy_text else None
        arn = f"arn:aws:s3:::{name}"
        logged = None
        if data_events is not None:
            logged = "*" in data_events or arn in data_events
        stores.append(
            DataStore(
                arn=arn,
                name=name,
                type="S3",
                region=region,
                sensitivity=sensitivity,
                sensitivity_source=source,
                encrypted=True if encryption else None,
                kms_key_arn=kms_key if kms_key and kms_key.startswith("arn:") else None,
                public=(status or {}).get("IsPublic", False) if status_known else None,
                cross_account_principals=(
                    _other_accounts(document, account_id) if policy_known else None
                ),
                resource_policy=parse_policy("Bucket policy", document) if document else None,
                logs_data_access=logged,
            )
        )
    return stores


def collect_dynamodb(session: Any, region: str, coverage: CoverageLog) -> list[DataStore]:
    api = client(session, "dynamodb", region)

    def list_all() -> list[str]:
        return [
            t
            for page in api.get_paginator("list_tables").paginate()
            for t in page.get("TableNames", [])
        ]

    stores = []
    tables, _ = attempt(coverage, "DynamoDB", region, list_all, [])
    for table in tables:
        info = quiet(lambda t=table: api.describe_table(TableName=t)["Table"])
        if info is None:
            coverage.gap(
                "DynamoDB",
                region,
                CoverageStatus.ERROR,
                f"Couldn't describe table {table}",
                [Domain.DATA],
            )
            continue
        tags_response = quiet(
            lambda a=info["TableArn"]: api.list_tags_of_resource(ResourceArn=a), {}
        )
        tags = {t["Key"]: t["Value"] for t in (tags_response or {}).get("Tags", [])}
        sensitivity, source = classify(table, tags)
        sse = info.get("SSEDescription") or {}
        stores.append(
            DataStore(
                arn=info["TableArn"],
                name=table,
                type="DynamoDB",
                region=region,
                sensitivity=sensitivity,
                sensitivity_source=source,
                encrypted=True,  # DynamoDB always encrypts at rest.
                kms_key_arn=sse.get("KMSMasterKeyArn"),
                public=False,
            )
        )
    return stores


def collect_rds(session: Any, region: str, coverage: CoverageLog) -> list[DataStore]:
    api = client(session, "rds", region)

    def list_all() -> tuple[list[dict], list[dict]]:
        instances = [
            i
            for page in api.get_paginator("describe_db_instances").paginate()
            for i in page.get("DBInstances", [])
        ]
        clusters = [
            c
            for page in api.get_paginator("describe_db_clusters").paginate()
            for c in page.get("DBClusters", [])
        ]
        return instances, clusters

    (instances, clusters), _ = attempt(coverage, "RDS", region, list_all, ([], []))
    stores = []
    for cluster in clusters:
        name = cluster["DBClusterIdentifier"]
        tags = {t["Key"]: t["Value"] for t in cluster.get("TagList", [])}
        sensitivity, source = classify(name, tags)
        stores.append(
            DataStore(
                arn=cluster["DBClusterArn"],
                name=name,
                type="RDS",
                region=region,
                sensitivity=sensitivity,
                sensitivity_source=source,
                db_resource_id=cluster.get("DbClusterResourceId"),
                encrypted=cluster.get("StorageEncrypted"),
                kms_key_arn=cluster.get("KmsKeyId"),
                public=cluster.get("PubliclyAccessible"),
            )
        )
    for instance in instances:
        if instance.get("DBClusterIdentifier"):
            continue  # Counted through its cluster.
        name = instance["DBInstanceIdentifier"]
        tags = {t["Key"]: t["Value"] for t in instance.get("TagList", [])}
        sensitivity, source = classify(name, tags)
        stores.append(
            DataStore(
                arn=instance["DBInstanceArn"],
                name=name,
                type="RDS",
                region=region,
                sensitivity=sensitivity,
                sensitivity_source=source,
                db_resource_id=instance.get("DbiResourceId"),
                encrypted=instance.get("StorageEncrypted"),
                kms_key_arn=instance.get("KmsKeyId"),
                public=instance.get("PubliclyAccessible"),
            )
        )
    return stores
