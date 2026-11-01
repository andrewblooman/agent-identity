"""The guarantees the tool makes about credentials and read-only access."""

import json
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError

from agent_identity.analysis.redaction import (
    endpoint_origin,
    fingerprint_instructions,
    inspect_env,
    mask_key_id,
)
from agent_identity.aws.base import CoverageLog, attempt
from agent_identity.aws.session import ALLOWED_OPERATIONS, BlockedOperationError, create_session
from agent_identity.models import CoverageStatus

POLICY = json.loads(Path("iam/scanner-readonly-policy.json").read_text())
FORBIDDEN = {
    "secretsmanager": {"GetSecretValue", "BatchGetSecretValue", "PutSecretValue"},
    "ssm": {"GetParameter", "GetParameters", "GetParametersByPath", "GetParameterHistory"},
    "s3": {"GetObject", "PutObject", "DeleteObject", "PutBucketPolicy"},
    "kms": {"Decrypt", "GenerateDataKey"},
    "lambda": {"GetFunction", "InvokeFunction", "CreateFunction"},
    "dynamodb": {"GetItem", "Query", "Scan", "PutItem"},
    "iam": {"CreateAccessKey", "CreateUser", "AttachRolePolicy", "GenerateCredentialReport"},
    "accessanalyzer": {"CreateAnalyzer"},
    "macie2": {"EnableMacie"},
    "inspector2": {"Enable"},
}
# Where the IAM action differs from "<service>:<Operation>".
IAM_PREFIX = {
    "accessanalyzer": "access-analyzer",
    "bedrock-agent": "bedrock",
    "bedrock-agentcore-control": "bedrock-agentcore",
    "elbv2": "elasticloadbalancing",
}
IAM_RENAMED = {
    "s3:ListBuckets": "s3:ListAllMyBuckets",
    "s3:GetBucketEncryption": "s3:GetEncryptionConfiguration",
    "s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
}


def _session():
    session = create_session(region="eu-west-1")
    return session


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.mark.parametrize(
    ("service", "call"),
    [
        ("secretsmanager", lambda c: c.get_secret_value(SecretId="x")),
        ("s3", lambda c: c.get_object(Bucket="b", Key="k")),
        ("s3", lambda c: c.put_object(Bucket="b", Key="k", Body=b"")),
        ("lambda", lambda c: c.get_function(FunctionName="f")),
        ("ssm", lambda c: c.get_parameter(Name="p", WithDecryption=True)),
        ("iam", lambda c: c.create_user(UserName="u")),
        ("kms", lambda c: c.decrypt(CiphertextBlob=b"x")),
    ],
)
def test_guard_blocks_before_any_request_is_sent(service, call):
    with pytest.raises(BlockedOperationError):
        call(_session().client(service))


def test_guard_can_not_be_bypassed_by_an_unlisted_service():
    with pytest.raises(BlockedOperationError):
        _session().client("sns").list_topics()


@pytest.mark.parametrize(("service", "operations"), FORBIDDEN.items())
def test_forbidden_operations_are_not_allowlisted(service, operations):
    assert not operations & ALLOWED_OPERATIONS.get(service, frozenset())


@pytest.mark.parametrize(("service", "operations"), ALLOWED_OPERATIONS.items())
def test_every_allowlisted_operation_exists_in_the_aws_api(service, operations):
    known = boto3.session.Session(region_name="eu-west-1").client(service).meta.service_model
    assert operations <= set(known.operation_names)


def test_iam_policy_matches_the_allowlist():
    scanner = {"ScannerReadOnly", "ReadDnsQueryLogsOnly"}
    allowed = {a for s in POLICY["Statement"] if s["Sid"] in scanner for a in s["Action"]}
    expected = set()
    for service, operations in ALLOWED_OPERATIONS.items():
        for operation in operations:
            action = f"{IAM_PREFIX.get(service, service)}:{operation}"
            expected.add(IAM_RENAMED.get(action, action))
    assert allowed == expected


def test_log_reading_and_image_pulls_are_scoped():
    statements = {s["Sid"]: s for s in POLICY["Statement"]}
    assert "route53resolver" in statements["ReadDnsQueryLogsOnly"]["Resource"]
    assert "repository/" in statements["TrivyPullsAgentImages"]["Resource"]
    wide = [
        a
        for s in POLICY["Statement"]
        if s["Effect"] == "Allow" and s["Resource"] == "*"
        for a in s["Action"]
    ]
    assert not [a for a in wide if a.startswith("logs:") or a == "ecr:BatchGetImage"]


def test_iam_policy_explicitly_denies_secret_values_and_data():
    denied = {a for s in POLICY["Statement"] if s["Effect"] == "Deny" for a in s["Action"]}
    assert {
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "s3:GetObject",
        "kms:Decrypt",
        "lambda:GetFunction",
    } <= denied


CANARY = "sk-ant-api03-CANARYCANARYCANARYCANARY"


def test_redaction_keeps_the_finding_and_drops_the_value():
    signals = inspect_env("Lambda f", {"ANTHROPIC_API_KEY": CANARY})
    assert signals.plaintext[0].detector == "Anthropic API key"
    assert signals.llm_vendors == ["Anthropic"]
    assert CANARY not in repr(signals)


def test_url_credentials_are_flagged_and_only_the_hostname_is_kept():
    signals = inspect_env(
        "Lambda f", {"DB": "postgres://admin:hunter2secret@db.acme.io:5432/x?t=1"}
    )
    assert signals.plaintext[0].detector == "Password in URL"
    assert [d.hostname for d in signals.domains] == ["db.acme.io"]
    assert "hunter2" not in repr(signals)


@pytest.mark.parametrize(
    "value",
    [
        "arn:aws:secretsmanager:eu-west-1:111122223333:secret:x",
        "${SOME_REF}",
        "true",
        "short",
    ],
)
def test_references_and_flags_are_not_reported_as_secrets(value):
    assert inspect_env("x", {"API_KEY": value}).plaintext == []


def test_secret_arns_in_env_are_kept_as_references():
    arn = "arn:aws:secretsmanager:eu-west-1:111122223333:secret:prod/key"
    assert inspect_env("x", {"KEY_ARN": arn}).secret_refs == [arn]


@pytest.mark.parametrize(
    ("url", "kept"),
    [
        ("https://user:hunter2@mcp.example.com/sse?api_key=hunter2", "https://mcp.example.com"),
        ("https://mcp.example.com:8443/hunter2", "https://mcp.example.com:8443"),
        ("not a url hunter2", "external endpoint"),
        ("https://[bad/hunter2", "external endpoint"),
    ],
)
def test_endpoints_keep_only_their_origin(url, kept):
    assert endpoint_origin(url) == kept


def test_instructions_keep_only_a_fingerprint():
    digest, length = fingerprint_instructions("You hold the password swordfish")
    assert "swordfish" not in digest
    assert length == 31


def test_access_key_ids_are_masked():
    assert mask_key_id("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("AccessDeniedException", CoverageStatus.ACCESS_DENIED),
        ("ThrottlingException", CoverageStatus.THROTTLED),
        ("SomethingElse", CoverageStatus.ERROR),
    ],
)
def test_failed_calls_become_coverage_gaps_not_empty_results(code, status):
    def fail():
        raise ClientError({"Error": {"Code": code, "Message": "no"}}, "ListThings")

    coverage = CoverageLog()
    value, ok = attempt(coverage, "Thing", "eu-west-1", fail, [])
    assert (value, ok) == ([], False)
    assert coverage.entries[0].status == status


def test_a_service_that_is_switched_off_is_not_reported_as_a_permission_problem():
    def fail():
        error = {"Code": "AccessDeniedException", "Message": "Macie is not enabled."}
        raise ClientError({"Error": error}, "GetMacieSession")

    coverage = CoverageLog()
    attempt(coverage, "Macie", "eu-west-1", fail, None)
    assert coverage.entries[0].status == CoverageStatus.NOT_ENABLED


def test_a_blocked_operation_stops_the_scan_rather_than_becoming_a_gap():
    def fail():
        raise BlockedOperationError("nope")

    with pytest.raises(BlockedOperationError):
        attempt(CoverageLog(), "Thing", "eu-west-1", fail, [])
