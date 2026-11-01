"""A synthetic estate for demos and tests. Every name, ARN and date here is made up.

IAM policies are real documents, so the permissions engine and rules work out the results the same
way they do on a live scan. Nothing is hard-coded as a finding. Account 111122223333 is the example
account ID from the AWS documentation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agent_identity.analysis.permissions import parse_policy
from agent_identity.models import (
    AccessKey,
    AccountSignals,
    Agent,
    Coverage,
    CoverageStatus,
    DataStore,
    Domain,
    DomainRef,
    Evidence,
    Exposure,
    Identity,
    NetworkProfile,
    PlaintextSecret,
    Platform,
    RuntimeProfile,
    SaasConnection,
    Secret,
    Sensitivity,
    Severity,
    Snapshot,
    Tool,
    Vulnerability,
)

ACCOUNT = "111122223333"
REGION = "eu-west-1"


def _role_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def _s3(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _ddb(name: str) -> str:
    return f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}"


def _secret(name: str) -> str:
    return f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:{name}"


def _kb(name: str) -> str:
    return f"arn:aws:bedrock:{REGION}:{ACCOUNT}:knowledge-base/{name}"


def _memory(name: str) -> str:
    return f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:memory/{name}"


def _policy(name: str, *statements: tuple[list[str], list[str]], **kwargs) -> object:
    document = {
        "Statement": [{"Effect": "Allow", "Action": a, "Resource": r} for a, r in statements]
    }
    return parse_policy(name, document, **kwargs)


LOGS = (["logs:CreateLogStream", "logs:PutLogEvents"], ["*"])
MODEL = (
    ["bedrock:InvokeModel", "bedrock:Converse"],
    [f"arn:aws:bedrock:{REGION}::foundation-model/*"],
)


def _identities(now: datetime) -> list[Identity]:
    d = lambda days: now - timedelta(days=days)  # noqa: E731
    return [
        Identity(
            arn=_role_arn("support-copilot-role"),
            name="support-copilot-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(240),
            last_used=d(0),
            trusted_principals=["bedrock.amazonaws.com"],
            policies=[
                _policy(
                    "support-copilot-access",
                    MODEL,
                    LOGS,
                    (
                        ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
                        [_ddb("customer-profiles"), _ddb("support-tickets")],
                    ),
                    (["dynamodb:PutItem", "dynamodb:UpdateItem"], [_ddb("support-tickets")]),
                    (["s3:GetObject"], [f"{_s3('acme-support-attachments')}/*"]),
                    (
                        ["secretsmanager:GetSecretValue"],
                        [
                            _secret("prod/zendesk/oauth-AbCdEf"),
                            _secret("prod/stripe/api-key-GhIjKl"),
                        ],
                    ),
                    (["bedrock:Retrieve"], [_kb("support-articles")]),
                ),
            ],
            service_last_used={
                "bedrock": d(0),
                "dynamodb": d(0),
                "s3": d(1),
                "secretsmanager": d(0),
                "logs": d(0),
            },
        ),
        Identity(
            arn=_role_arn("ops-autopilot-role"),
            name="ops-autopilot-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(420),
            last_used=d(0),
            trusted_principals=["lambda.amazonaws.com", _role_arn("finance-reconciler-role")],
            policies=[
                parse_policy(
                    "AdministratorAccess",
                    {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                    arn="arn:aws:iam::aws:policy/AdministratorAccess",
                    managed_by_aws=True,
                )
            ],
            service_last_used={
                "bedrock": d(0),
                "ec2": d(1),
                "logs": d(0),
                "cloudwatch": d(0),
                "ecs": d(1),
                "iam": None,
                "rds": None,
                "s3": None,
                "dynamodb": None,
                "kms": None,
                "secretsmanager": None,
                "sns": None,
            },
        ),
        Identity(
            arn=_role_arn("invoice-worker-task"),
            name="invoice-worker-task",
            kind="role",
            account_id=ACCOUNT,
            created=d(610),
            last_used=d(0),
            trusted_principals=["ecs-tasks.amazonaws.com"],
            policies=[
                _policy(
                    "invoice-worker-data",
                    LOGS,
                    (
                        ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                        [f"{_s3('acme-finance-records')}/*"],
                    ),
                    (["s3:GetObject"], ["arn:aws:s3:::*/*"]),
                    (["dynamodb:*"], [_ddb("invoices")]),
                ),
            ],
            service_last_used={"s3": d(0), "dynamodb": d(0), "logs": d(0)},
        ),
        Identity(
            arn=_role_arn("finance-reconciler-role"),
            name="finance-reconciler-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(120),
            last_used=d(1),
            trusted_principals=["bedrock-agentcore.amazonaws.com"],
            policies=[
                _policy(
                    "finance-reconciler-access",
                    MODEL,
                    LOGS,
                    (["s3:GetObject", "s3:PutObject"], [f"{_s3('acme-finance-records')}/*"]),
                    (
                        ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem"],
                        [_ddb("invoices")],
                    ),
                    (["kms:Decrypt"], [f"arn:aws:kms:{REGION}:{ACCOUNT}:key/finance"]),
                    (["sts:AssumeRole"], [_role_arn("ops-autopilot-role")]),
                ),
            ],
            service_last_used={
                "bedrock": d(1),
                "s3": d(1),
                "dynamodb": d(1),
                "kms": d(1),
                "sts": None,
            },
        ),
        Identity(
            arn=_role_arn("dev-assistant-shared"),
            name="dev-assistant-shared",
            kind="role",
            account_id=ACCOUNT,
            created=d(300),
            last_used=d(0),
            trusted_principals=["lambda.amazonaws.com"],
            policies=[
                _policy(
                    "dev-assistant-access",
                    MODEL,
                    LOGS,
                    (["iam:PassRole", "lambda:CreateFunction", "lambda:UpdateFunctionCode"], ["*"]),
                    (["s3:GetObject", "s3:ListBucket"], [f"{_s3('acme-engineering-docs')}/*"]),
                    (["secretsmanager:GetSecretValue"], [_secret("prod/github/app-key-MnOpQr")]),
                ),
            ],
            service_last_used={
                "bedrock": d(0),
                "lambda": d(30),
                "iam": d(30),
                "s3": d(2),
                "secretsmanager": d(2),
                "logs": d(0),
            },
        ),
        Identity(
            arn=_role_arn("hr-policy-bot-role"),
            name="hr-policy-bot-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(90),
            last_used=d(0),
            trusted_principals=["bedrock.amazonaws.com"],
            policies=[
                _policy(
                    "hr-policy-bot-access",
                    MODEL,
                    LOGS,
                    (["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"], [_kb("hr-policies")]),
                ),
            ],
            service_last_used={"bedrock": d(0), "logs": d(0)},
        ),
        Identity(
            arn=_role_arn("content-sync-role"),
            name="content-sync-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(95),
            last_used=d(0),
            trusted_principals=["lambda.amazonaws.com"],
            policies=[
                _policy(
                    "content-sync-access",
                    MODEL,
                    LOGS,
                    (["s3:GetObject", "s3:PutObject"], [f"{_s3('acme-hr-documents')}/*"]),
                    (["bedrock:StartIngestionJob"], [_kb("hr-policies")]),
                ),
            ],
            service_last_used={"bedrock": d(0), "s3": d(0), "logs": d(0)},
        ),
        Identity(
            arn=f"arn:aws:iam::{ACCOUNT}:user/svc-code-review",
            name="svc-code-review",
            kind="user",
            account_id=ACCOUNT,
            created=d(780),
            last_used=d(0),
            policies=[
                _policy(
                    "code-review-access",
                    (["bedrock:InvokeModel", "bedrock:Converse"], ["*"]),
                    (["s3:GetObject", "s3:PutObject"], [f"{_s3('acme-engineering-docs')}/*"]),
                    (["secretsmanager:GetSecretValue"], [_secret("prod/github/app-key-MnOpQr")]),
                ),
            ],
            access_keys=[
                AccessKey(
                    key_id="AKIA…7Q2X",
                    status="Active",
                    created=d(780),
                    last_used=d(0),
                    last_service="bedrock",
                    last_region=REGION,
                    human_use_signal=(
                        "Key used from a residential network and the AWS CLI on 3 days in "
                        "the last 2 weeks"
                    ),
                )
            ],
            service_last_used={"bedrock": d(0), "s3": d(0), "secretsmanager": d(0)},
        ),
        Identity(
            arn=_role_arn("summariser-role"),
            name="summariser-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(60),
            last_used=d(0),
            trusted_principals=["lambda.amazonaws.com"],
            policies=[_policy("summariser-access", MODEL, LOGS)],
            service_last_used={"bedrock": d(0), "logs": d(0)},
        ),
        Identity(
            arn=_role_arn("research-sandbox-role"),
            name="research-sandbox-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(200),
            last_used=d(130),
            trusted_principals=[f"arn:aws:iam::{ACCOUNT}:root"],
            trust_is_broad=True,
            human_session_signal="Assumed through the console by 4 different people",
            policies=[
                _policy(
                    "research-sandbox-access",
                    (["bedrock:*"], ["*"]),
                    (["s3:GetObject", "s3:ListBucket"], [f"{_s3('acme-research-datasets')}/*"]),
                ),
            ],
            service_last_used={"bedrock": d(130), "s3": None},
        ),
        Identity(
            arn=_role_arn("claims-assistant-role"),
            name="claims-assistant-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(45),
            last_used=d(0),
            trusted_principals=["bedrock-agentcore.amazonaws.com"],
            boundary=parse_policy(
                "agent-boundary",
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "bedrock:*",
                                "bedrock-agentcore:*",
                                "logs:*",
                                "dynamodb:GetItem",
                                "dynamodb:Query",
                                "kms:Decrypt",
                                "secretsmanager:GetSecretValue",
                            ],
                            "Resource": "*",
                        }
                    ]
                },
            ),
            policies=[
                _policy(
                    "claims-assistant-access",
                    MODEL,
                    LOGS,
                    (["dynamodb:GetItem", "dynamodb:Query"], [_ddb("claims")]),
                    (["kms:Decrypt"], [f"arn:aws:kms:{REGION}:{ACCOUNT}:key/claims"]),
                    (["secretsmanager:GetSecretValue"], [_secret("prod/claims/policy-api-StUvWx")]),
                    (
                        [
                            "bedrock-agentcore:RetrieveMemoryRecords",
                            "bedrock-agentcore:ListEvents",
                            "bedrock-agentcore:CreateEvent",
                        ],
                        [_memory("claims-session")],
                    ),
                ),
            ],
            service_last_used={
                "bedrock": d(0),
                "dynamodb": d(0),
                "kms": d(0),
                "secretsmanager": d(0),
                "bedrock-agentcore": d(0),
                "logs": d(0),
            },
        ),
        Identity(
            arn=_role_arn("ml-pipeline-pod-role"),
            name="ml-pipeline-pod-role",
            kind="role",
            account_id=ACCOUNT,
            created=d(150),
            last_used=d(3),
            trusted_principals=["pods.eks.amazonaws.com"],
            policies=[
                _policy(
                    "ml-pipeline-access",
                    MODEL,
                    (["s3:*"], ["arn:aws:s3:::acme-research-*", "arn:aws:s3:::acme-research-*/*"]),
                    (["dynamodb:Scan", "dynamodb:Query"], [_ddb("customer-profiles")]),
                ),
            ],
        ),
    ]


def _stores() -> list[DataStore]:
    return [
        DataStore(
            arn=_ddb("customer-profiles"),
            name="customer-profiles",
            type="DynamoDB",
            region=REGION,
            sensitivity=Sensitivity.RESTRICTED,
            sensitivity_source="classification tag",
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_ddb("support-tickets"),
            name="support-tickets",
            type="DynamoDB",
            region=REGION,
            sensitivity=Sensitivity.CONFIDENTIAL,
            sensitivity_source="classification tag",
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_ddb("invoices"),
            name="invoices",
            type="DynamoDB",
            region=REGION,
            sensitivity=Sensitivity.RESTRICTED,
            sensitivity_source="classification tag",
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=True,
        ),
        DataStore(
            arn=_ddb("claims"),
            name="claims",
            type="DynamoDB",
            region=REGION,
            sensitivity=Sensitivity.RESTRICTED,
            sensitivity_source="classification tag",
            encrypted=True,
            kms_key_arn=f"arn:aws:kms:{REGION}:{ACCOUNT}:key/claims",
            public=False,
            cross_account_principals=[],
            logs_data_access=True,
        ),
        DataStore(
            arn=_s3("acme-finance-records"),
            name="acme-finance-records",
            type="S3",
            region=REGION,
            sensitivity=Sensitivity.RESTRICTED,
            sensitivity_source="Macie",
            encrypted=True,
            kms_key_arn=f"arn:aws:kms:{REGION}:{ACCOUNT}:key/finance",
            public=False,
            cross_account_principals=["444455556666 (auditor)"],
            logs_data_access=True,
        ),
        DataStore(
            arn=_s3("acme-support-attachments"),
            name="acme-support-attachments",
            type="S3",
            region=REGION,
            sensitivity=Sensitivity.CONFIDENTIAL,
            sensitivity_source="Macie",
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_s3("acme-hr-documents"),
            name="acme-hr-documents",
            type="S3",
            region=REGION,
            sensitivity=Sensitivity.CONFIDENTIAL,
            sensitivity_source="name (inferred)",
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_s3("acme-engineering-docs"),
            name="acme-engineering-docs",
            type="S3",
            region=REGION,
            sensitivity=Sensitivity.INTERNAL,
            sensitivity_source="classification tag",
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_s3("acme-research-datasets"),
            name="acme-research-datasets",
            type="S3",
            region=REGION,
            encrypted=True,
            public=False,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_s3("acme-marketing-assets"),
            name="acme-marketing-assets",
            type="S3",
            region=REGION,
            sensitivity=Sensitivity.PUBLIC,
            sensitivity_source="classification tag",
            encrypted=True,
            public=True,
            cross_account_principals=[],
            logs_data_access=False,
        ),
        DataStore(
            arn=_kb("hr-policies"),
            name="hr-policies",
            type="Knowledge base",
            region=REGION,
            sensitivity=Sensitivity.CONFIDENTIAL,
            sensitivity_source="source bucket",
            encrypted=True,
            source_store_arns=[_s3("acme-hr-documents")],
        ),
        DataStore(
            arn=_kb("support-articles"),
            name="support-articles",
            type="Knowledge base",
            region=REGION,
            sensitivity=Sensitivity.INTERNAL,
            sensitivity_source="classification tag",
            encrypted=True,
            source_store_arns=[_s3("acme-engineering-docs")],
        ),
        DataStore(
            arn=_memory("claims-session"),
            name="claims-session",
            type="Agent memory",
            region=REGION,
            sensitivity=Sensitivity.RESTRICTED,
            sensitivity_source="classification tag",
            encrypted=True,
            public=False,
        ),
    ]


def _secrets(now: datetime) -> list[Secret]:
    d = lambda days: now - timedelta(days=days)  # noqa: E731
    return [
        Secret(
            arn=_secret("prod/zendesk/oauth-AbCdEf"),
            name="prod/zendesk/oauth",
            kind="Secrets Manager",
            region=REGION,
            vendor="Zendesk",
            rotation_enabled=False,
            created=d(240),
            last_accessed=d(0),
        ),
        Secret(
            arn=_secret("prod/stripe/api-key-GhIjKl"),
            name="prod/stripe/api-key",
            kind="Secrets Manager",
            region=REGION,
            vendor="Stripe",
            rotation_enabled=False,
            created=d(510),
            last_accessed=d(120),
        ),
        Secret(
            arn=_secret("prod/github/app-key-MnOpQr"),
            name="prod/github/app-key",
            kind="Secrets Manager",
            region=REGION,
            vendor="GitHub",
            rotation_enabled=True,
            last_rotated=d(200),
            created=d(600),
            last_accessed=d(0),
        ),
        Secret(
            arn=_secret("prod/claims/policy-api-StUvWx"),
            name="prod/claims/policy-api",
            kind="Secrets Manager",
            region=REGION,
            rotation_enabled=True,
            last_rotated=d(12),
            created=d(45),
            last_accessed=d(0),
            kms_key_arn=f"arn:aws:kms:{REGION}:{ACCOUNT}:key/claims",
        ),
        Secret(
            arn=_secret("prod/db/admin-YzAbCd"),
            name="prod/db/admin",
            kind="Secrets Manager",
            region=REGION,
            rotation_enabled=True,
            last_rotated=d(20),
            created=d(700),
            last_accessed=d(20),
        ),
        Secret(
            arn=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:token-vault/default/"
            "oauth2credentialprovider/salesforce-crm",
            name="salesforce-crm",
            kind="OAuth provider",
            region=REGION,
            vendor="Salesforce",
            created=d(110),
        ),
    ]


def _agents(now: datetime) -> list[Agent]:
    d = lambda days: now - timedelta(days=days)  # noqa: E731
    return [
        Agent(
            id="support-copilot",
            name="support-copilot",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.BEDROCK_AGENT,
            resource_arn=f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/SUPPORT1",
            description="Answers customer tickets and updates them in Zendesk",
            evidence=[
                Evidence(signal="managed", source="Bedrock Agents", detail="Registered agent"),
                Evidence(
                    signal="behaviour", source="CloudTrail", detail="412 model calls in 14 days"
                ),
            ],
            identity_arn=_role_arn("support-copilot-role"),
            owner="customer-experience",
            environment="prod",
            triggers=["http"],
            untrusted_inputs=["customer ticket text", "ticket attachments"],
            tools=[
                Tool(
                    name="update_ticket",
                    type="action group",
                    target="Zendesk API",
                    requires_approval=False,
                    external=True,
                    writes=True,
                ),
                Tool(
                    name="issue_refund",
                    type="action group",
                    target="Stripe API",
                    requires_approval=False,
                    external=True,
                    writes=True,
                ),
                Tool(
                    name="lookup_customer",
                    type="action group",
                    target="customer-profiles",
                    requires_approval=False,
                    writes=False,
                ),
            ],
            knowledge_base_arns=[_kb("support-articles")],
            secret_arns=[_secret("prod/zendesk/oauth-AbCdEf")],
            domains=[
                DomainRef(hostname="acme.zendesk.com", source="action group schema"),
                DomainRef(hostname="api.stripe.com", source="action group schema"),
            ],
            saas=[
                SaasConnection(
                    vendor="Zendesk",
                    source="action group",
                    credential_type="OAuth",
                    credential_ref="prod/zendesk/oauth",
                    scopes=["tickets:read", "tickets:write", "users:read"],
                    can_write=True,
                ),
                SaasConnection(
                    vendor="Stripe",
                    source="action group",
                    credential_type="API key",
                    credential_ref="prod/stripe/api-key",
                    can_write=True,
                ),
            ],
            network=NetworkProfile(
                inbound=[
                    Exposure(
                        kind="API Gateway",
                        detail="support-copilot-api",
                        internet=True,
                        authenticated=True,
                        auth_detail="JWT authoriser",
                    )
                ],
                internet_egress=True,
                egress_detail="Managed service with outbound access to action group APIs",
                in_vpc=False,
            ),
            runtime=RuntimeProfile(
                platform_detail="Bedrock managed runtime",
                vulns_assessed=False,
                vulns_source="Managed by AWS",
            ),
            guardrail=False,
            model_ids=["anthropic.claude-sonnet"],
            instructions_sha256="0" * 64,
            instructions_length=1840,
            last_model_call=d(0),
        ),
        Agent(
            id="ops-autopilot",
            name="ops-autopilot",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.LAMBDA,
            resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:ops-autopilot",
            description="Restarts and resizes services when alarms fire",
            evidence=[
                Evidence(
                    signal="behaviour", source="CloudTrail", detail="88 Converse calls in 14 days"
                ),
                Evidence(signal="config", source="Lambda", detail="BEDROCK_MODEL_ID env var"),
            ],
            identity_arn=_role_arn("ops-autopilot-role"),
            owner="platform-sre",
            environment="prod",
            triggers=["schedule", "event"],
            untrusted_inputs=[],
            tools=[
                Tool(
                    name="restart_service",
                    type="function",
                    target="ECS",
                    writes=True,
                    requires_approval=False,
                ),
                Tool(
                    name="scale_database",
                    type="function",
                    target="RDS",
                    writes=True,
                    requires_approval=False,
                ),
            ],
            network=NetworkProfile(
                inbound=[],
                internet_egress=True,
                egress_detail="Lambda with no VPC has outbound internet",
                in_vpc=False,
            ),
            runtime=RuntimeProfile(
                platform_detail="Lambda zip",
                language_runtime="python3.9",
                runtime_deprecated=True,
                vulns_assessed=True,
                vulns_source="Inspector",
                frameworks=["LangChain"],
                vulnerabilities=[
                    Vulnerability(
                        cve="CVE-2099-0101",
                        severity=Severity.HIGH,
                        package="langchain-core 0.1.0",
                        fixed_in="0.3.0",
                        source="Inspector",
                    ),
                ],
            ),
            guardrail=False,
            model_ids=["anthropic.claude-haiku"],
            last_model_call=d(0),
        ),
        Agent(
            id="invoice-triage-worker",
            name="invoice-triage-worker",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.ECS,
            resource_arn=f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/ops/invoice-triage",
            description="Not in any inventory. Found from its config and OpenAI key",
            evidence=[
                Evidence(
                    signal="config",
                    source="ECS task definition",
                    detail="OPENAI_API_KEY env var; image name contains 'langchain'",
                ),
            ],
            identity_arn=_role_arn("invoice-worker-task"),
            environment="prod",
            triggers=None,
            untrusted_inputs=["inbound invoice PDFs from suppliers"],
            plaintext_secrets=[
                PlaintextSecret(
                    location="ECS task definition invoice-triage:14",
                    variable="OPENAI_API_KEY",
                    detector="OpenAI API key",
                ),
            ],
            domains=[
                DomainRef(hostname="api.openai.com", source="env var OPENAI_BASE_URL"),
                DomainRef(hostname="ocr.quickparse-tools.io", source="env var OCR_ENDPOINT"),
            ],
            saas=[
                SaasConnection(
                    vendor="OpenAI",
                    source="env var",
                    credential_type="API key",
                    credential_ref="plain text in task definition",
                    can_write=None,
                )
            ],
            network=NetworkProfile(
                inbound=[
                    Exposure(
                        kind="Load balancer",
                        detail="invoice-triage-alb",
                        internet=True,
                        authenticated=False,
                        auth_detail="No listener authentication",
                    )
                ],
                internet_egress=True,
                egress_detail="Route to a NAT gateway, all ports open outbound",
                vpc_id="vpc-0a1b2c3d",
                in_vpc=True,
                open_security_groups=["sg-0invoice"],
                vpc_endpoints=["com.amazonaws.eu-west-1.s3"],
            ),
            runtime=RuntimeProfile(
                platform_detail="Fargate",
                image=f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/langchain-invoice:latest",
                image_pinned=False,
                privileged=False,
                runs_as_root=True,
                read_only_root=False,
                vulns_assessed=True,
                vulns_source="Trivy",
                frameworks=["LangChain", "Unstructured"],
                vulnerabilities=[
                    Vulnerability(
                        cve="CVE-2099-1001",
                        severity=Severity.CRITICAL,
                        package="langchain-community 0.0.20",
                        fixed_in="0.3.5",
                        exploit_available=True,
                        source="Trivy",
                    ),
                    Vulnerability(
                        cve="CVE-2099-1002",
                        severity=Severity.CRITICAL,
                        package="pillow 9.0.0",
                        fixed_in="11.0.0",
                        exploit_available=False,
                        source="Trivy",
                    ),
                    Vulnerability(
                        cve="CVE-2099-1003",
                        severity=Severity.HIGH,
                        package="openssl 3.0.2",
                        fixed_in="3.0.15",
                        source="Trivy",
                    ),
                    Vulnerability(
                        cve="CVE-2099-1004",
                        severity=Severity.HIGH,
                        package="pypdf 3.1.0",
                        fixed_in="4.0.0",
                        source="Trivy",
                    ),
                    Vulnerability(
                        cve="CVE-2099-1005",
                        severity=Severity.MEDIUM,
                        package="requests 2.28.0",
                        fixed_in="2.32.0",
                        source="Trivy",
                    ),
                ],
            ),
            guardrail=False,
        ),
        Agent(
            id="finance-reconciler",
            name="finance-reconciler",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.AGENTCORE,
            resource_arn=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/finance-reconciler",
            description="Matches payments to invoices each night",
            evidence=[Evidence(signal="managed", source="AgentCore", detail="Registered runtime")],
            identity_arn=_role_arn("finance-reconciler-role"),
            owner="finance-systems",
            environment="prod",
            triggers=["schedule"],
            untrusted_inputs=[],
            saas=[
                SaasConnection(
                    vendor="Salesforce",
                    source="AgentCore credential provider",
                    credential_type="OAuth",
                    credential_ref="salesforce-crm",
                    scopes=["api", "refresh_token"],
                    can_write=True,
                )
            ],
            secret_arns=[],
            tools=[
                Tool(
                    name="salesforce-crm",
                    type="gateway target",
                    target="Salesforce",
                    requires_approval=False,
                    external=True,
                    writes=True,
                )
            ],
            domains=[DomainRef(hostname="acme.my.salesforce.com", source="gateway target")],
            network=NetworkProfile(
                inbound=[],
                internet_egress=False,
                egress_detail="Private subnets with no NAT route",
                vpc_id="vpc-0e5f6a7b",
                in_vpc=True,
                vpc_endpoints=[
                    "com.amazonaws.eu-west-1.bedrock-runtime",
                    "com.amazonaws.eu-west-1.s3",
                ],
            ),
            runtime=RuntimeProfile(
                platform_detail="AgentCore container",
                image=f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/finance-reconciler@sha256:ab12",
                image_pinned=True,
                vulns_assessed=True,
                vulns_source="Inspector",
                frameworks=["Strands"],
                vulnerabilities=[
                    Vulnerability(
                        cve="CVE-2099-2001",
                        severity=Severity.HIGH,
                        package="urllib3 1.26.0",
                        fixed_in="2.2.0",
                        source="Inspector",
                    ),
                ],
            ),
            guardrail=True,
            last_model_call=d(1),
        ),
        Agent(
            id="dev-assistant-prod",
            name="dev-assistant-prod",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.LAMBDA,
            resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:dev-assistant-prod",
            description="Slack assistant that can deploy Lambda functions",
            evidence=[
                Evidence(
                    signal="behaviour", source="CloudTrail", detail="207 model calls in 14 days"
                ),
                Evidence(
                    signal="config", source="Lambda", detail="Function URL and MODEL_ID env var"
                ),
            ],
            identity_arn=_role_arn("dev-assistant-shared"),
            owner="developer-experience",
            environment="prod",
            triggers=["http"],
            untrusted_inputs=["Slack messages"],
            secret_arns=[_secret("prod/github/app-key-MnOpQr")],
            domains=[DomainRef(hostname="slack.com", source="env var SLACK_API_URL")],
            saas=[
                SaasConnection(
                    vendor="GitHub",
                    source="secret name",
                    credential_type="App key",
                    credential_ref="prod/github/app-key",
                    can_write=None,
                ),
                SaasConnection(
                    vendor="Slack", source="env var", credential_type="unknown", can_write=True
                ),
            ],
            network=NetworkProfile(
                inbound=[
                    Exposure(
                        kind="Lambda function URL",
                        detail="dev-assistant-prod URL",
                        internet=True,
                        authenticated=False,
                        auth_detail="AuthType NONE",
                    )
                ],
                internet_egress=True,
                egress_detail="Lambda with no VPC has outbound internet",
                in_vpc=False,
            ),
            runtime=RuntimeProfile(
                platform_detail="Lambda zip",
                language_runtime="python3.13",
                runtime_deprecated=False,
                vulns_assessed=False,
                vulns_source="Inspector not covering Lambda",
            ),
            guardrail=False,
            last_model_call=d(0),
        ),
        Agent(
            id="dev-assistant-dev",
            name="dev-assistant-dev",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.LAMBDA,
            resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:dev-assistant-dev",
            description="Test copy of the Slack assistant, using the production role",
            evidence=[
                Evidence(signal="config", source="Lambda", detail="MODEL_ID env var"),
            ],
            identity_arn=_role_arn("dev-assistant-shared"),
            owner="developer-experience",
            environment="dev",
            triggers=["human"],
            untrusted_inputs=[],
            network=NetworkProfile(
                inbound=[],
                internet_egress=True,
                egress_detail="Lambda with no VPC has outbound internet",
                in_vpc=False,
            ),
            runtime=RuntimeProfile(
                platform_detail="Lambda zip",
                language_runtime="python3.13",
                runtime_deprecated=False,
                vulns_assessed=False,
                vulns_source="Inspector not covering Lambda",
            ),
            guardrail=False,
            last_model_call=d(18),
        ),
        Agent(
            id="hr-policy-bot",
            name="hr-policy-bot",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.BEDROCK_AGENT,
            resource_arn=f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/HRBOT001",
            description="Answers staff questions about HR policy",
            evidence=[
                Evidence(signal="managed", source="Bedrock Agents", detail="Registered agent")
            ],
            identity_arn=_role_arn("hr-policy-bot-role"),
            owner="people-team",
            environment="prod",
            triggers=["human"],
            untrusted_inputs=[],
            knowledge_base_arns=[_kb("hr-policies")],
            network=NetworkProfile(
                inbound=[],
                internet_egress=False,
                egress_detail="No action groups or outbound tools",
                in_vpc=False,
            ),
            runtime=RuntimeProfile(
                platform_detail="Bedrock managed runtime",
                vulns_assessed=False,
                vulns_source="Managed by AWS",
            ),
            guardrail=True,
            last_model_call=d(0),
        ),
        Agent(
            id="content-sync-agent",
            name="content-sync-agent",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.LAMBDA,
            resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:content-sync",
            description="Pulls policy pages from the web and adds them to the HR knowledge base",
            evidence=[
                Evidence(
                    signal="behaviour", source="CloudTrail", detail="61 model calls in 14 days"
                ),
            ],
            identity_arn=_role_arn("content-sync-role"),
            environment="prod",
            triggers=["schedule"],
            untrusted_inputs=["web pages fetched from external sites"],
            tools=[
                Tool(
                    name="fetch_url",
                    type="function",
                    target="any public URL",
                    external=True,
                    requires_approval=False,
                    writes=False,
                )
            ],
            domains=[
                DomainRef(hostname="policy-updates.hrnewsfeed.example", source="env var FEED_URL")
            ],
            network=NetworkProfile(
                inbound=[],
                internet_egress=True,
                egress_detail="Lambda with no VPC has outbound internet",
                in_vpc=False,
            ),
            runtime=RuntimeProfile(
                platform_detail="Lambda zip",
                language_runtime="python3.12",
                runtime_deprecated=False,
                vulns_assessed=True,
                vulns_source="Inspector",
            ),
            guardrail=False,
            last_model_call=d(0),
        ),
        Agent(
            id="code-review-agent",
            name="code-review-agent",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.EC2,
            resource_arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0codereview",
            description="Reviews pull requests from a long-running instance",
            evidence=[
                Evidence(
                    signal="behaviour",
                    source="CloudTrail",
                    detail="1,120 InvokeModel calls from a long-lived key",
                ),
                Evidence(signal="config", source="EC2 tags", detail="Tag purpose=ai-code-review"),
            ],
            identity_arn=f"arn:aws:iam::{ACCOUNT}:user/svc-code-review",
            owner="developer-experience",
            environment="prod",
            triggers=["event"],
            untrusted_inputs=["pull request contents from outside contributors"],
            secret_arns=[_secret("prod/github/app-key-MnOpQr")],
            tools=[
                Tool(
                    name="github-mcp",
                    type="MCP server",
                    target="mcp.gh-tools.example",
                    external=True,
                    writes=True,
                    requires_approval=False,
                )
            ],
            domains=[
                DomainRef(hostname="api.github.com", source="env var GITHUB_API"),
                DomainRef(hostname="mcp.gh-tools.example", source="MCP config tag"),
            ],
            saas=[
                SaasConnection(
                    vendor="GitHub",
                    source="secret name",
                    credential_type="App key",
                    credential_ref="prod/github/app-key",
                    scopes=["contents:write", "pull_requests:write"],
                    can_write=True,
                )
            ],
            network=NetworkProfile(
                inbound=[],
                internet_egress=True,
                egress_detail="Public IP on an instance with open outbound rules",
                vpc_id="vpc-0a1b2c3d",
                in_vpc=True,
                open_security_groups=["sg-0reviewssh"],
                vpc_endpoints=["com.amazonaws.eu-west-1.s3"],
            ),
            runtime=RuntimeProfile(
                platform_detail="t3.large, Amazon Linux 2",
                imdsv2_required=False,
                code_execution_tool=True,
                vulns_assessed=True,
                vulns_source="Inspector",
                vulnerabilities=[
                    Vulnerability(
                        cve="CVE-2099-3001",
                        severity=Severity.HIGH,
                        package="sudo 1.8.0",
                        fixed_in="1.9.15",
                        source="Inspector",
                    ),
                ],
            ),
            guardrail=False,
            last_model_call=d(0),
        ),
        Agent(
            id="ticket-summariser",
            name="ticket-summariser",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.LAMBDA,
            resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:ticket-summariser",
            description="Summarises text it is given. It has no tools and no data access",
            evidence=[
                Evidence(
                    signal="behaviour", source="CloudTrail", detail="1,903 model calls in 14 days"
                )
            ],
            identity_arn=_role_arn("summariser-role"),
            owner="customer-experience",
            environment="prod",
            triggers=["http"],
            untrusted_inputs=["ticket text passed by the caller"],
            network=NetworkProfile(
                inbound=[],
                internet_egress=False,
                egress_detail="VPC with only a Bedrock endpoint",
                vpc_id="vpc-0e5f6a7b",
                in_vpc=True,
                vpc_endpoints=["com.amazonaws.eu-west-1.bedrock-runtime"],
            ),
            runtime=RuntimeProfile(
                platform_detail="Lambda zip",
                language_runtime="python3.13",
                runtime_deprecated=False,
                vulns_assessed=True,
                vulns_source="Inspector",
            ),
            guardrail=True,
            last_model_call=d(0),
        ),
        Agent(
            id="research-sandbox",
            name="research-sandbox-role",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.IAM_ONLY,
            resource_arn=_role_arn("research-sandbox-role"),
            description="A role that can use models, with no workload found behind it",
            evidence=[Evidence(signal="iam", source="IAM", detail="Policy allows bedrock:*")],
            identity_arn=_role_arn("research-sandbox-role"),
            last_model_call=d(130),
        ),
        Agent(
            id="ml-pipeline",
            name="ml-pipeline",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.EKS,
            resource_arn=f"arn:aws:eks:{REGION}:{ACCOUNT}:podidentityassociation/data/ml-pipeline",
            description="Workload inside EKS. Pods can't be inspected from AWS APIs",
            evidence=[
                Evidence(
                    signal="behaviour",
                    source="CloudTrail",
                    detail="34 model calls through a pod identity role",
                )
            ],
            identity_arn=_role_arn("ml-pipeline-pod-role"),
            owner="data-science",
            environment="prod",
            network=NetworkProfile(vpc_id="vpc-0c9d8e7f", in_vpc=True),
            last_model_call=d(3),
        ),
        Agent(
            id="claims-assistant",
            name="claims-assistant",
            account_id=ACCOUNT,
            region=REGION,
            platform=Platform.AGENTCORE,
            resource_arn=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/claims-assistant",
            description="Helps staff look up claims. Set up with least privilege",
            evidence=[Evidence(signal="managed", source="AgentCore", detail="Registered runtime")],
            identity_arn=_role_arn("claims-assistant-role"),
            owner="claims-operations",
            environment="prod",
            triggers=["human"],
            untrusted_inputs=[],
            memory_arns=[_memory("claims-session")],
            secret_arns=[_secret("prod/claims/policy-api-StUvWx")],
            tools=[
                Tool(
                    name="get_policy",
                    type="gateway target",
                    target="internal policy API",
                    requires_approval=True,
                    writes=False,
                )
            ],
            domains=[DomainRef(hostname="policy-api.claims.internal", source="gateway target")],
            network=NetworkProfile(
                inbound=[
                    Exposure(
                        kind="AgentCore endpoint",
                        detail="claims-assistant-endpoint",
                        internet=False,
                        authenticated=True,
                        auth_detail="Custom JWT authoriser",
                    )
                ],
                internet_egress=False,
                egress_detail="Private subnets with no NAT route",
                vpc_id="vpc-0e5f6a7b",
                in_vpc=True,
                vpc_endpoints=[
                    "com.amazonaws.eu-west-1.bedrock-runtime",
                    "com.amazonaws.eu-west-1.dynamodb",
                ],
            ),
            runtime=RuntimeProfile(
                platform_detail="AgentCore container",
                image=f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/claims-assistant@sha256:cd34",
                image_pinned=True,
                vulns_assessed=True,
                vulns_source="Inspector",
                frameworks=["Strands"],
            ),
            guardrail=True,
            last_model_call=d(0),
        ),
    ]


_COVERAGE = [
    Coverage(source="Bedrock Agents", region=REGION, status=CoverageStatus.OK),
    Coverage(source="AgentCore", region=REGION, status=CoverageStatus.OK),
    Coverage(source="IAM", status=CoverageStatus.OK),
    Coverage(source="CloudTrail", region=REGION, status=CoverageStatus.OK),
    Coverage(
        source="Inspector",
        region=REGION,
        status=CoverageStatus.OK,
        detail="Scanning ECR and EC2, with partial Lambda coverage",
    ),
    Coverage(
        source="Macie",
        region=REGION,
        status=CoverageStatus.OK,
        detail="Scanning two buckets",
        affects=[Domain.DATA],
    ),
    Coverage(
        source="Access Analyzer (unused access)",
        status=CoverageStatus.NOT_ENABLED,
        detail="Using IAM last-accessed data instead",
        affects=[Domain.IDENTITY],
    ),
    Coverage(
        source="CloudTrail data events",
        region=REGION,
        status=CoverageStatus.NOT_ENABLED,
        detail="On for three stores only, so per-resource use is mostly unknown",
        affects=[Domain.DATA],
    ),
    Coverage(
        source="Route 53 Resolver query logs",
        region=REGION,
        status=CoverageStatus.NOT_ENABLED,
        detail="Domains show what is configured, not what was contacted",
        affects=[Domain.NETWORK],
    ),
    Coverage(
        source="EKS pods",
        region=REGION,
        status=CoverageStatus.NOT_AVAILABLE,
        detail="Needs Kubernetes API access, which this version doesn't use",
        affects=[Domain.RUNTIME, Domain.NETWORK],
    ),
]

# Older scans have fewer agents, so the history shows the estate growing over time.
_INTRODUCED_DAYS_AGO = {
    "support-copilot": 56,
    "ops-autopilot": 56,
    "invoice-triage-worker": 42,
    "finance-reconciler": 42,
    "hr-policy-bot": 56,
    "ticket-summariser": 56,
    "dev-assistant-prod": 28,
    "dev-assistant-dev": 14,
    "content-sync-agent": 0,
    "code-review-agent": 7,
    "research-sandbox": 42,
    "ml-pipeline": 28,
    "claims-assistant": 42,
}
HISTORY_DAYS_AGO = (56, 42, 28, 14, 7, 0)


def build_snapshot(days_ago: int = 0, now: datetime | None = None) -> Snapshot:
    now = (now or datetime.now(UTC)) - timedelta(days=days_ago)
    agents = [a for a in _agents(now) if _INTRODUCED_DAYS_AGO[a.id] >= days_ago]
    return Snapshot(
        mode="demo",
        account_id=ACCOUNT,
        regions=[REGION],
        taken_at=now,
        agents=agents,
        identities=_identities(now),
        stores=_stores(),
        secrets=_secrets(now),
        coverage=_COVERAGE,
        signals=AccountSignals(
            model_invocation_logging={REGION: False},
            access_analyzer_unused=False,
            access_analyzer_internal=False,
            macie_enabled=True,
            inspector_enabled=True,
            cloudtrail_data_events=True,
        ),
        observed_data_use={
            _s3("acme-finance-records"): {
                _role_arn("finance-reconciler-role"): now - timedelta(days=1),
                _role_arn("invoice-worker-task"): now - timedelta(days=0),
            },
            _ddb("invoices"): {_role_arn("invoice-worker-task"): now},
            _ddb("claims"): {_role_arn("claims-assistant-role"): now},
        },
    )
