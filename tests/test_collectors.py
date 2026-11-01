"""Collectors against mocked AWS. moto has no AgentCore support, so that uses a botocore Stubber."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from moto import mock_aws

from agent_identity import db
from agent_identity.analysis.engine import analyse
from agent_identity.aws import agentcore, base, bedrock, collect, data_stores, iam, optional, vulns
from agent_identity.aws.base import CoverageLog
from agent_identity.aws.collect import collect_snapshot
from agent_identity.aws.data_stores import classify
from agent_identity.aws.network import RegionNetwork
from agent_identity.config import Settings
from agent_identity.models import (
    Agent,
    AgentKind,
    Confidence,
    CoverageStatus,
    DomainRef,
    Identity,
    NetworkProfile,
    Platform,
    RuntimeProfile,
    Secret,
    Sensitivity,
)

REGION = "eu-west-1"
NOW = datetime(2026, 11, 1, tzinfo=UTC)
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
    assert net.internet_route([subnet], public_ipv4=True)[0] is True
    assert net.internet_route([subnet], public_ipv4=None)[0] is None
    # A VPC Lambda has no public address, so the same route doesn't get it out.
    assert net.internet_route([subnet], public_ipv4=False)[0] is False


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


def _denied(operation="Call", code="AccessDenied"):
    return ClientError({"Error": {"Code": code, "Message": "no"}}, operation)


class _FakeEc2:
    """Answers with fixed data, so routes moto can't create can be tested."""

    def __init__(self, tables, subnets=("subnet-a",), groups_error=None):
        self.tables, self.subnets, self.groups_error = tables, subnets, groups_error

    def describe_route_tables(self):
        return {"RouteTables": self.tables}

    def describe_subnets(self):
        return {"Subnets": [{"SubnetId": s, "VpcId": "vpc-1"} for s in self.subnets]}

    def describe_security_groups(self, GroupIds):  # noqa: N803
        if self.groups_error:
            raise self.groups_error
        return {"SecurityGroups": []}

    def describe_vpc_endpoints(self):
        return {"VpcEndpoints": []}


def _net(ec2):
    net = RegionNetwork(boto3.session.Session(region_name=REGION), REGION, CoverageLog())
    net.ec2 = ec2
    return net


def _table(subnet, *routes):
    return {"VpcId": "vpc-1", "Associations": [{"SubnetId": subnet}], "Routes": list(routes)}


@pytest.mark.parametrize(
    "route",
    [
        {"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1"},
        {"DestinationIpv6CidrBlock": "::/0", "EgressOnlyInternetGatewayId": "eigw-1"},
    ],
)
def test_ipv6_default_routes_count_as_egress(route):
    net = _net(_FakeEc2([_table("subnet-a", route)]))
    assert net.internet_route(["subnet-a"], public_ipv4=False)[0] is True
    assert net.internet_route(["subnet-a"], public_ipv4=False, ipv6=False)[0] is False


def test_unread_subnet_keeps_egress_unknown_instead_of_no():
    net = _net(_FakeEc2([_table("subnet-a")], subnets=("subnet-a", "subnet-b")))
    assert net.internet_route(["subnet-a"])[0] is False
    assert net.internet_route(["subnet-a", "subnet-b"])[0] is None


def test_a_later_subnet_can_still_prove_egress_after_an_unknown_one():
    device = {"DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": "tgw-1"}
    nat = {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}
    tables = [_table("subnet-a", device), _table("subnet-b", nat)]
    net = _net(_FakeEc2(tables, subnets=("subnet-a", "subnet-b")))
    assert net.internet_route(["subnet-a", "subnet-b"])[0] is True


def test_denied_security_group_read_is_unknown_and_recorded():
    net = _net(_FakeEc2([], groups_error=_denied("DescribeSecurityGroups")))
    profile = net.profile(["subnet-a"], ["sg-1"])
    assert profile.open_security_groups is None
    assert net.coverage.entries[-1].status == CoverageStatus.ACCESS_DENIED


def test_inspector_account_status_reads_overall_and_per_resource_state(monkeypatch):
    def status(body):
        fake = SimpleNamespace(batch_get_account_status=lambda: {"accounts": [body]})
        monkeypatch.setattr(vulns, "client", lambda *_a, **_k: fake)
        return vulns.inspector_enabled(None, REGION, CoverageLog())

    assert status({"state": {"status": "ENABLED"}}) is True
    assert status(
        {"state": {"status": "DISABLED"}, "resourceState": {"ecr": {"status": "ENABLED"}}}
    )
    off = {"state": {"status": "DISABLED"}, "resourceState": {"ecr": {"status": "DISABLED"}}}
    assert status(off) is False


REGISTRY = "111122223333"
REPOSITORY = "agent"
DIGEST_OLD = "sha256:" + "a" * 64
DIGEST_NEW = "sha256:" + "b" * 64
IMAGE_HOST = f"{REGISTRY}.dkr.ecr.{REGION}.amazonaws.com/{REPOSITORY}"


def _image_agent(image):
    return Agent(
        id=image,
        name="a",
        account_id=REGISTRY,
        region=REGION,
        platform=Platform.ECS,
        resource_arn="arn:aws:ecs:eu-west-1:1:service/c/s",
        runtime=RuntimeProfile(image=image),
    )


def _finding(digest, tags=()):
    return {
        "severity": "CRITICAL",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": "CVE-1",
            "vulnerablePackages": [{"name": "openssl", "version": "3"}],
        },
        "resources": [
            {
                "id": f"arn:aws:ecr:{REGION}:{REGISTRY}:repository/{REPOSITORY}/{digest}",
                "details": {
                    "awsEcrContainerImage": {
                        "registry": REGISTRY,
                        "repositoryName": REPOSITORY,
                        "imageHash": digest,
                        "imageTags": list(tags),
                    }
                },
            }
        ],
    }


def _covered(digest, tags=(), status="ACTIVE"):
    return {
        "resourceType": "AWS_ECR_CONTAINER_IMAGE",
        "resourceId": f"arn:aws:ecr:{REGION}:{REGISTRY}:repository/{REPOSITORY}/{digest}",
        "scanStatus": {"statusCode": status},
        "resourceMetadata": {"ecrImage": {"imageTags": list(tags)}},
    }


def _fake_inspector(monkeypatch, findings, covered):
    pages = {
        "list_findings": [{"findings": findings}],
        "list_coverage": [{"coveredResources": covered}],
    }

    def get_paginator(name):
        return SimpleNamespace(paginate=lambda **_k: pages[name])

    fake = SimpleNamespace(get_paginator=get_paginator)
    monkeypatch.setattr(vulns, "client", lambda *_a, **_k: fake)


def test_findings_join_on_the_deployed_image_not_just_the_repository(monkeypatch):
    _fake_inspector(
        monkeypatch,
        [_finding(DIGEST_OLD, ["old"])],
        [_covered(DIGEST_OLD, ["old"]), _covered(DIGEST_NEW, ["new"])],
    )
    patched = _image_agent(f"{IMAGE_HOST}@{DIGEST_NEW}")
    tagged = _image_agent(f"{IMAGE_HOST}:old")
    vulns.apply_inspector(None, REGION, [patched, tagged], CoverageLog())
    assert patched.runtime.vulns_assessed and patched.runtime.vulnerabilities == []
    assert [v.cve for v in tagged.runtime.vulnerabilities] == ["CVE-1"]


def test_image_inspector_does_not_scan_stays_unassessed_for_trivy(monkeypatch):
    _fake_inspector(monkeypatch, [], [_covered(DIGEST_NEW, status="INACTIVE")])
    agent = _image_agent(f"{IMAGE_HOST}@{DIGEST_NEW}")
    lambda_agent = Agent(
        id="l",
        name="l",
        account_id=REGISTRY,
        region=REGION,
        platform=Platform.LAMBDA,
        resource_arn="arn:aws:lambda:eu-west-1:1:function:l",
    )
    vulns.apply_inspector(None, REGION, [agent, lambda_agent], CoverageLog())
    assert not agent.runtime.vulns_assessed
    assert not lambda_agent.runtime.vulns_assessed


def _s3_session(monkeypatch, policy_error, status_error):
    def fail_with(error):
        def call(**_k):
            raise error

        return call

    fake = SimpleNamespace(
        list_buckets=lambda: {"Buckets": [{"Name": "b"}]},
        get_bucket_location=lambda **_k: {"LocationConstraint": REGION},
        get_bucket_tagging=fail_with(_denied()),
        get_bucket_encryption=fail_with(_denied()),
        get_bucket_policy=fail_with(policy_error),
        get_bucket_policy_status=fail_with(status_error),
    )
    monkeypatch.setattr(data_stores, "client", lambda *_a, **_k: fake)


def test_denied_bucket_policy_is_unknown_rather_than_private(monkeypatch):
    _s3_session(monkeypatch, _denied(), _denied())
    store = data_stores.collect_s3(None, REGISTRY, None, CoverageLog())[0]
    assert store.public is None
    assert store.cross_account_principals is None


def test_bucket_without_a_policy_is_assessed_as_not_public(monkeypatch):
    missing = _denied(code="NoSuchBucketPolicy")
    _s3_session(monkeypatch, missing, missing)
    store = data_stores.collect_s3(None, REGISTRY, None, CoverageLog())[0]
    assert store.public is False
    assert store.cross_account_principals == []


@mock_aws
def test_users_inherit_their_groups_policies():
    api = boto3.client("iam")
    api.create_user(UserName="svc")
    api.create_group(GroupName="agents")
    api.add_user_to_group(GroupName="agents", UserName="svc")
    api.put_group_policy(
        GroupName="agents",
        PolicyName="models",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}
                ],
            }
        ),
    )
    identities, _ = iam.collect_identities(boto3.session.Session(region_name=REGION), "1")
    user = next(i for i in identities if i.name == "svc")
    assert [p.name for p in user.policies] == ["models (group agents)"]


class _LastAccessed:
    def __init__(self, later_page_error=None):
        self.later_page_error = later_page_error

    def generate_service_last_accessed_details(self, Arn):  # noqa: N803
        return {"JobId": "j"}

    def get_service_last_accessed_details(self, JobId, Marker=None):  # noqa: N803
        if Marker is None:
            return {
                "JobStatus": "COMPLETED",
                "IsTruncated": True,
                "Marker": "m",
                "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
            }
        if self.later_page_error:
            raise self.later_page_error
        return {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "kms"}]}


def _user():
    return Identity(arn="arn:aws:iam::1:user/u", name="u", kind="user", account_id="1")


def test_last_accessed_reads_every_page(monkeypatch):
    monkeypatch.setattr(iam, "client", lambda *_a, **_k: _LastAccessed())
    user = _user()
    iam.add_last_accessed(None, [user])
    assert set(user.service_last_used) == {"s3", "kms"}


def test_partial_last_accessed_report_is_discarded(monkeypatch):
    monkeypatch.setattr(iam, "client", lambda *_a, **_k: _LastAccessed(_denied()))
    user = _user()
    iam.add_last_accessed(None, [user])
    assert user.service_last_used is None


def test_simulator_denial_that_lacked_context_stays_unresolved(monkeypatch):
    response = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalDecision": "implicitDeny",
                "MissingContextValues": ["aws:SecureTransport"],
            },
            {"EvalActionName": "s3:PutObject", "EvalDecision": "implicitDeny"},
        ]
    }
    fake = SimpleNamespace(simulate_principal_policy=lambda **_k: response)
    monkeypatch.setattr(iam, "client", lambda *_a, **_k: fake)
    results = {}
    user = _user()
    iam.simulate(None, user, [("s3:GetObject", "r"), ("s3:PutObject", "r")], results)
    assert results == {f"{user.arn}|s3:PutObject|r": False}


def test_gateway_targets_keep_only_the_endpoint_origin():
    agent = Agent(
        id="a",
        name="a",
        account_id="1",
        region=REGION,
        platform=Platform.AGENTCORE,
        resource_arn="r",
    )
    endpoint = f"https://user:{SECRET_CANARY}@mcp.example.com:8443/sse/{SECRET_CANARY}?api_key=x"
    config = {"targetConfiguration": {"mcp": {"mcpServer": {"endpoint": endpoint}}}}
    agentcore._apply_target(config, {"targetId": "t", "name": "t"}, [agent], {}, "arn:role")
    assert agent.tools[0].target == "https://mcp.example.com:8443"
    assert agent.tools[0].role_arn == "arn:role"
    assert SECRET_CANARY not in agent.model_dump_json()


def _action_group(group):
    fake = SimpleNamespace(get_agent_action_group=lambda **_k: {"agentActionGroup": group})
    return bedrock._tool(fake, "agent", {"actionGroupId": "g"})


def test_return_control_is_not_treated_as_human_approval():
    returned = {"customControl": "RETURN_CONTROL"}
    assert _action_group({"actionGroupExecutor": returned}).requires_approval is None
    confirmed = [{"name": "f", "requireConfirmation": "ENABLED"}]
    group = {"actionGroupExecutor": returned, "functionSchema": {"functions": confirmed}}
    assert _action_group(group).requires_approval is True
    unconfirmed = [{"name": "f", "requireConfirmation": "DISABLED"}]
    group = {"actionGroupExecutor": returned, "functionSchema": {"functions": unconfirmed}}
    assert _action_group(group).requires_approval is False


def test_a_role_and_a_user_with_the_same_name_get_different_agent_ids():
    role = Identity(arn="arn:aws:iam::1:role/x", name="x", kind="role", account_id="1")
    user = Identity(arn="arn:aws:iam::1:user/x", name="x", kind="user", account_id="1")
    assert collect._identity_agent(role, []).id != collect._identity_agent(user, []).id


def test_parameter_names_link_to_ssm_secrets_in_the_same_region():
    agent = Agent(
        id="a",
        name="a",
        account_id="1",
        region=REGION,
        platform=Platform.ECS,
        resource_arn="r",
        secret_arns=["/prod/api-key"],
    )
    here = Secret(
        arn=f"arn:aws:ssm:{REGION}:1:parameter/prod/api-key",
        name="/prod/api-key",
        kind="SSM SecureString",
        region=REGION,
    )
    elsewhere = here.model_copy(
        update={"arn": "arn:aws:ssm:us-east-1:1:parameter/prod/api-key", "region": "us-east-1"}
    )
    collect._link_secret_refs([agent], [elsewhere, here])
    assert agent.secret_arns == [here.arn]


def test_dns_search_is_limited_to_the_agents_vpc(monkeypatch):
    patterns = []

    def filter_log_events(**kwargs):
        patterns.append(kwargs["filterPattern"])
        return {"events": [{"message": "hit"}]}

    resolver = SimpleNamespace(
        list_resolver_query_log_configs=lambda: {
            "ResolverQueryLogConfigs": [
                {"DestinationArn": "arn:aws:logs:eu-west-1:1:log-group:/aws/route53resolver/q"}
            ]
        }
    )
    fake_logs = SimpleNamespace(filter_log_events=filter_log_events)
    monkeypatch.setattr(
        optional,
        "client",
        lambda _s, service, _r=None: resolver if "route53" in service else fake_logs,
    )

    def agent(network):
        return Agent(
            id="a",
            name="a",
            account_id="1",
            region=REGION,
            platform=Platform.ECS,
            resource_arn="r",
            network=network,
            domains=[DomainRef(hostname="api.example.com", source="env")],
        )

    in_vpc = agent(NetworkProfile(vpc_id="vpc-1"))
    outside = agent(NetworkProfile(in_vpc=False))
    optional.apply_dns_logs(None, REGION, [in_vpc, outside], NOW, CoverageLog())
    assert in_vpc.domains[0].observed
    assert not outside.domains[0].observed
    assert patterns == ['{ $.query_name = "api.example.com." && $.vpc_id = "vpc-1" }']
