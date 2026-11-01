"""Collectors against mocked AWS. moto has no AgentCore support, so that uses a botocore Stubber."""

import json

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from agent_identity import db
from agent_identity.analysis.engine import analyse
from agent_identity.aws import agentcore, base, vulns
from agent_identity.aws.base import CoverageLog
from agent_identity.aws.collect import collect_snapshot
from agent_identity.aws.data_stores import classify
from agent_identity.aws.network import RegionNetwork
from agent_identity.config import Settings
from agent_identity.models import AgentKind, Confidence, CoverageStatus, Platform, Sensitivity

REGION = "eu-west-1"
CANARY = "sk-ant-api03-CANARYCANARYCANARYCANARY"
SECRET_CANARY = "CANARYSECRETVALUE1234567"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    # moto raises this for APIs it hasn't implemented. Real AWS never does.
    monkeypatch.setattr(base, "CALL_FAILURES", (*base.CALL_FAILURES, NotImplementedError))
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(name, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _settings(tmp_path):
    return Settings(
        _env_file=None,
        aws_profile=None,
        scan_regions=[REGION],
        trivy_enabled=False,
        database_path=tmp_path / "t.sqlite3",
    )


def _role(name, *actions):
    iam = boto3.client("iam")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(TRUST))["Role"]["Arn"]
    if actions:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="p",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}],
                }
            ),
        )
    return arn


def _function(name, role, env=None):
    boto3.client("lambda", region_name=REGION).create_function(
        FunctionName=name,
        Runtime="python3.13",
        Role=role,
        Handler="a.b",
        Code={"ZipFile": b"PK\x05\x06" + b"\x00" * 18},
        Environment={"Variables": env or {}},
    )


@mock_aws
def test_live_scan_finds_agents_and_ignores_plain_lambdas(tmp_path):
    plain = _role("plain-role", "logs:PutLogEvents")
    _function("resize-images", plain)
    agent_role = _role("agent-role", "bedrock:InvokeModel", "s3:PutObject")
    _function("triage", agent_role, {"ANTHROPIC_API_KEY": CANARY})

    snapshot = collect_snapshot(_settings(tmp_path))
    agents = {a.name: a for a in snapshot.agents}
    assert "resize-images" not in agents
    assert agents["triage"].platform == Platform.LAMBDA

    analyse(snapshot)
    triage = next(a for a in snapshot.agents if a.name == "triage")
    assert triage.kind == AgentKind.AGENT
    assert triage.confidence == Confidence.LIKELY
    assert triage.plaintext_secrets[0].variable == "ANTHROPIC_API_KEY"
    assert triage.network.internet_egress is True


@mock_aws
def test_secret_values_never_reach_the_database(tmp_path):
    role = _role("agent-role", "bedrock:InvokeModel", "secretsmanager:GetSecretValue")
    _function(
        "triage",
        role,
        {
            "ANTHROPIC_API_KEY": CANARY,
            "DB_URL": f"postgres://admin:{SECRET_CANARY}@db.acme.io/x",
            "SOME_PASSWORD": SECRET_CANARY,
        },
    )
    boto3.client("secretsmanager", region_name=REGION).create_secret(
        Name="prod/thing", SecretString=SECRET_CANARY
    )

    settings = _settings(tmp_path)
    snapshot = collect_snapshot(settings)
    result = analyse(snapshot)
    engine = db.create_db(settings.database_path)
    db.finish_scan(engine, db.start_scan(engine, "live"), snapshot, result)
    engine.dispose()

    assert any(a.name == "triage" and a.plaintext_secrets for a in snapshot.agents)
    stored = settings.database_path.read_bytes()
    assert CANARY.encode() not in stored
    assert SECRET_CANARY.encode() not in stored
    assert b"db.acme.io" in stored


@mock_aws
def test_scan_of_an_empty_account_is_not_a_failure(tmp_path):
    snapshot = collect_snapshot(_settings(tmp_path))
    assert snapshot.agents == []
    assert snapshot.coverage


@mock_aws
def test_role_with_explicit_model_permission_and_no_workload_is_possible(tmp_path):
    _role("orphan-role", "bedrock:InvokeModel")
    _role("admin-role", "*")
    snapshot = collect_snapshot(_settings(tmp_path))
    analyse(snapshot)
    names = {a.name: a for a in snapshot.agents}
    assert names["orphan-role"].confidence == Confidence.POSSIBLE
    assert names["orphan-role"].platform == Platform.IAM_ONLY
    assert "admin-role" not in names


@mock_aws
def test_s3_buckets_are_collected_with_their_classification(tmp_path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="acme-payroll")
    s3.create_bucket(Bucket="tagged")
    s3.put_bucket_tagging(
        Bucket="tagged", Tagging={"TagSet": [{"Key": "data-classification", "Value": "restricted"}]}
    )
    s3.create_bucket(Bucket="logs-archive")
    stores = {s.name: s for s in collect_snapshot(_settings(tmp_path)).stores}
    assert stores["tagged"].sensitivity == Sensitivity.RESTRICTED
    assert stores["acme-payroll"].sensitivity_source == "name (inferred)"
    assert stores["logs-archive"].sensitivity == Sensitivity.UNKNOWN


def test_classification_tag_beats_the_name():
    assert classify("customer-data", {"Classification": "Public"})[0] == Sensitivity.PUBLIC


@mock_aws
def test_private_subnet_has_no_internet_route():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    net = RegionNetwork(boto3.session.Session(region_name=REGION), REGION)
    assert net.internet_route([subnet])[0] is False
    assert net.vpc_of(subnet) == vpc


@mock_aws
def test_subnet_with_internet_gateway_route_has_egress():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    table = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)
    net = RegionNetwork(boto3.session.Session(region_name=REGION), REGION)
    assert net.internet_route([subnet])[0] is True


RUNTIME_ARN = "arn:aws:bedrock-agentcore:eu-west-1:111122223333:runtime/r-1234567890"
ROLE_ARN = "arn:aws:iam::111122223333:role/runtime-role"


def _stubbed(monkeypatch):
    session = boto3.session.Session(region_name=REGION)
    api = session.client("bedrock-agentcore-control")
    monkeypatch.setattr(agentcore, "client", lambda *_a, **_k: api)
    return session, api, Stubber(api)


def test_agentcore_runtime_is_parsed_and_its_env_redacted(monkeypatch):
    session, _, stub = _stubbed(monkeypatch)
    stub.add_response(
        "list_agent_runtimes",
        {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": RUNTIME_ARN,
                    "agentRuntimeId": "r-1234567890",
                    "agentRuntimeVersion": "1",
                    "agentRuntimeName": "reconciler",
                    "description": "d",
                    "lastUpdatedAt": "2026-10-01T00:00:00Z",
                    "status": "READY",
                }
            ]
        },
    )
    stub.add_response(
        "get_agent_runtime",
        {
            "agentRuntimeArn": RUNTIME_ARN,
            "agentRuntimeName": "reconciler",
            "agentRuntimeId": "r-1234567890",
            "agentRuntimeVersion": "1",
            "createdAt": "2026-10-01T00:00:00Z",
            "lastUpdatedAt": "2026-10-01T00:00:00Z",
            "roleArn": ROLE_ARN,
            "networkConfiguration": {"networkMode": "PUBLIC"},
            "status": "READY",
            "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 900, "maxLifetime": 3600},
            "environmentVariables": {"OPENAI_API_KEY": "sk-" + "A" * 40},
            "agentRuntimeArtifact": {
                "containerConfiguration": {
                    "containerUri": "111122223333.dkr.ecr.eu-west-1.amazonaws.com/r:latest"
                }
            },
            "workloadIdentityDetails": {
                "workloadIdentityArn": "arn:aws:bedrock-agentcore:eu-west-1:1:workload-identity/r"
            },
        },
    )
    coverage = CoverageLog()
    with stub:
        agents = agentcore.collect_runtimes(session, REGION, "111122223333", None, coverage)
    agent = agents[0]
    assert agent.platform == Platform.AGENTCORE
    assert agent.identity_arn == ROLE_ARN
    assert agent.network.internet_egress is True
    assert agent.network.inbound[0].authenticated is True
    assert agent.runtime.image_pinned is False
    assert agent.plaintext_secrets[0].detector == "OpenAI API key"
    assert "AAAA" not in agent.model_dump_json()


def test_agentcore_access_denied_is_a_gap_not_an_empty_estate(monkeypatch):
    session, _, stub = _stubbed(monkeypatch)
    stub.add_client_error("list_agent_runtimes", "AccessDeniedException")
    coverage = CoverageLog()
    with stub:
        assert agentcore.collect_runtimes(session, REGION, "1", None, coverage) == []
    assert coverage.entries[0].status == CoverageStatus.ACCESS_DENIED


def test_trivy_report_is_parsed_and_frameworks_found():
    found, frameworks = vulns._parse_trivy(
        {
            "Results": [
                {
                    "Packages": [{"Name": "LangChain"}, {"Name": "requests"}],
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "openssl",
                            "InstalledVersion": "3",
                            "FixedVersion": "3.1",
                            "Severity": "CRITICAL",
                        },
                        {"VulnerabilityID": "CVE-2", "PkgName": "x", "Severity": "UNKNOWN"},
                    ],
                }
            ]
        }
    )
    assert [v.cve for v in found] == ["CVE-1"]
    assert frameworks == ["LangChain"]


@pytest.mark.parametrize(
    "image",
    [
        "111122223333.dkr.ecr.eu-west-1.amazonaws.com/app:latest",
        "111122223333.dkr.ecr.eu-west-1.amazonaws.com/team/app@sha256:" + "a" * 64,
    ],
)
def test_ecr_images_are_accepted_for_scanning(image):
    assert vulns._ECR_IMAGE.match(image)


@pytest.mark.parametrize(
    "image",
    [
        "--config=/etc/passwd",
        "docker.io/library/python:3",
        "111122223333.dkr.ecr.eu-west-1.amazonaws.com/app:latest --exit-code 1",
        "111122223333.dkr.ecr.eu-west-1.amazonaws.com/app;rm -rf /",
    ],
)
def test_other_image_references_are_refused(image):
    assert not vulns._ECR_IMAGE.match(image)
