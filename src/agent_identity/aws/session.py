"""AWS session whose clients can only make allowlisted, read-only calls.

The guard runs before signing, so a blocked call never leaves the process. Add operations here
only if they cannot change a resource or return a secret value. `lambda.GetFunction`,
`secretsmanager.GetSecretValue`, `ssm.GetParameter*`, `s3.GetObject` and `kms.Decrypt` must stay
out.
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config

ALLOWED_OPERATIONS: dict[str, frozenset[str]] = {
    "sts": frozenset({"GetCallerIdentity"}),
    "iam": frozenset(
        {
            "GetAccountAuthorizationDetails",
            "ListAccessKeys",
            "GetAccessKeyLastUsed",
            "SimulatePrincipalPolicy",
            # Starts a read-only report job. The only "Generate" call the scanner makes.
            "GenerateServiceLastAccessedDetails",
            "GetServiceLastAccessedDetails",
        }
    ),
    "bedrock": frozenset({"GetModelInvocationLoggingConfiguration"}),
    "bedrock-agent": frozenset(
        {
            "ListAgents",
            "GetAgent",
            "ListAgentActionGroups",
            "GetAgentActionGroup",
            "ListAgentKnowledgeBases",
            "ListKnowledgeBases",
            "GetKnowledgeBase",
            "ListDataSources",
            "GetDataSource",
        }
    ),
    "bedrock-agentcore-control": frozenset(
        {
            "ListAgentRuntimes",
            "GetAgentRuntime",
            "ListGateways",
            "GetGateway",
            "ListGatewayTargets",
            "GetGatewayTarget",
            "ListApiKeyCredentialProviders",
            "ListOauth2CredentialProviders",
            "ListMemories",
        }
    ),
    "lambda": frozenset(
        {"ListFunctions", "ListFunctionUrlConfigs", "ListEventSourceMappings", "GetPolicy"}
    ),
    "ecs": frozenset(
        {
            "ListClusters",
            "ListServices",
            "DescribeServices",
            "DescribeTaskDefinition",
        }
    ),
    "eks": frozenset(
        {
            "ListClusters",
            "DescribeCluster",
            "ListPodIdentityAssociations",
            "DescribePodIdentityAssociation",
        }
    ),
    "ec2": frozenset(
        {
            "DescribeInstances",
            "DescribeSecurityGroups",
            "DescribeRouteTables",
            "DescribeSubnets",
            "DescribeVpcEndpoints",
        }
    ),
    "elbv2": frozenset({"DescribeLoadBalancers", "DescribeTargetGroups", "DescribeListeners"}),
    "cloudtrail": frozenset({"LookupEvents", "DescribeTrails", "GetEventSelectors"}),
    "secretsmanager": frozenset({"ListSecrets", "GetResourcePolicy"}),
    "ssm": frozenset({"DescribeParameters"}),
    "s3": frozenset(
        {
            "ListBuckets",
            "GetBucketLocation",
            "GetBucketTagging",
            "GetBucketEncryption",
            "GetBucketPolicy",
            "GetBucketPolicyStatus",
        }
    ),
    "dynamodb": frozenset({"ListTables", "DescribeTable", "ListTagsOfResource"}),
    "rds": frozenset({"DescribeDBInstances", "DescribeDBClusters"}),
    "accessanalyzer": frozenset({"ListAnalyzers"}),
    "macie2": frozenset({"GetMacieSession", "DescribeBuckets"}),
    "inspector2": frozenset({"BatchGetAccountStatus", "ListFindings"}),
    "route53resolver": frozenset({"ListResolverQueryLogConfigs"}),
    "logs": frozenset({"FilterLogEvents"}),
}


class BlockedOperationError(RuntimeError):
    """The scanner tried to call an AWS operation that is not on the read-only allowlist."""


def _guard(model: Any, **_: Any) -> None:
    service = model.service_model.service_name
    if model.name not in ALLOWED_OPERATIONS.get(service, frozenset()):
        raise BlockedOperationError(f"Blocked {service}.{model.name}: not on the read-only list")


def create_session(profile: str | None = None, region: str | None = None) -> boto3.session.Session:
    session = boto3.session.Session(profile_name=profile or None, region_name=region)
    session.events.register("before-call", _guard)
    return session


RETRY_CONFIG = Config(
    retries={"max_attempts": 6, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra="agent-identity-scanner/0.1",
)


def client(session: boto3.session.Session, service: str, region: str | None = None) -> Any:
    return session.client(service, region_name=region, config=RETRY_CONFIG)
