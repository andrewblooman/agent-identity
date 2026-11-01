"""Lambda, ECS, EKS and EC2 workloads. Each becomes a candidate if a signal points to a model."""

from __future__ import annotations

import json
import re
from typing import Any

from agent_identity.analysis.redaction import EnvSignals, inspect_env
from agent_identity.aws.base import CoverageLog, attempt, quiet
from agent_identity.aws.network import RegionNetwork
from agent_identity.aws.session import client
from agent_identity.models import (
    Agent,
    CoverageStatus,
    Evidence,
    Exposure,
    NetworkProfile,
    Platform,
    RuntimeProfile,
    SaasConnection,
)

_AI_NAME = re.compile(
    r"langchain|langgraph|crewai|autogen|llama[-_]?index|strands[-_]agents|mcp[-_]server"
    r"|openai|anthropic|claude|bedrock[-_]agent|ai[-_]agent|llm",
    re.IGNORECASE,
)
_DEPRECATED_RUNTIMES = re.compile(
    r"^(python2\.7|python3\.[0-9]$|nodejs(4|6|8|10|12|14|16|18)|ruby2|dotnetcore|dotnet[56]$"
    r"|java8$|go1\.x)"
)
_NON_EXTERNAL = {"Amazon Bedrock", "Unspecified model"}
_OWNER_TAGS = ("owner", "team", "Owner", "Team", "owner:team")
_ENV_TAGS = ("environment", "Environment", "env", "Env", "stage", "Stage")


def _tag(tags: dict[str, str], names: tuple[str, ...]) -> str | None:
    return next((tags[n] for n in names if tags.get(n)), None)


def apply_env(agent: Agent, signals: EnvSignals, source: str) -> None:
    agent.plaintext_secrets += signals.plaintext
    agent.domains += signals.domains
    agent.secret_arns += signals.secret_refs
    agent.runtime.frameworks = sorted({*agent.runtime.frameworks, *signals.frameworks})
    vendors = sorted(set(signals.llm_vendors))
    if vendors or signals.frameworks:
        named = [*vendors, *sorted(set(signals.frameworks))]
        agent.evidence.append(
            Evidence(
                signal="config",
                source=source,
                detail=f"Environment variables point to: {', '.join(named)}",
            )
        )
    for vendor in vendors:
        if vendor not in _NON_EXTERNAL:
            agent.saas.append(
                SaasConnection(vendor=vendor, source="env var", credential_type="API key")
            )


def _lambda_exposure(policy: dict[str, Any] | None, url_configs: list[dict]) -> list[Exposure]:
    exposures = [
        Exposure(
            kind="Lambda function URL",
            detail=c.get("FunctionUrl", "function URL"),
            internet=True,
            authenticated=c.get("AuthType") != "NONE",
            auth_detail=f"AuthType {c.get('AuthType')}",
        )
        for c in url_configs
    ]
    for stmt in (policy or {}).get("Statement", []):
        principal = stmt.get("Principal", {})
        service = principal.get("Service") if isinstance(principal, dict) else None
        if service == "apigateway.amazonaws.com":
            exposures.append(
                Exposure(
                    kind="API Gateway",
                    detail="Invoked through API Gateway",
                    internet=True,
                    authenticated=None,
                    auth_detail="Check the route's authoriser",
                )
            )
    return exposures


def _lambda_triggers(
    policy: dict[str, Any] | None, mappings: list[dict], url_configs: list[dict]
) -> list[str]:
    triggers = set()
    if url_configs:
        triggers.add("http")
    if mappings:
        triggers.add("queue")
    for stmt in (policy or {}).get("Statement", []):
        principal = stmt.get("Principal", {})
        service = principal.get("Service") if isinstance(principal, dict) else None
        if service == "events.amazonaws.com":
            triggers.add("schedule")
        elif service in {"sns.amazonaws.com", "s3.amazonaws.com", "sqs.amazonaws.com"}:
            triggers.add("event")
        elif service == "apigateway.amazonaws.com":
            triggers.add("http")
    return sorted(triggers)


def collect_lambda(
    session: Any, region: str, account_id: str, net: RegionNetwork, coverage: CoverageLog
) -> list[Agent]:
    api = client(session, "lambda", region)

    def list_all() -> list[dict]:
        return [
            f
            for page in api.get_paginator("list_functions").paginate()
            for f in page.get("Functions", [])
        ]

    functions, _ = attempt(coverage, "Lambda", region, list_all, [])
    agents = []
    for fn in functions:
        name, arn = fn["FunctionName"], fn["FunctionArn"]
        vpc = fn.get("VpcConfig") or {}
        subnets, groups = vpc.get("SubnetIds") or [], vpc.get("SecurityGroupIds") or []
        if subnets:
            # Lambda's network interfaces never get a public IPv4 address, even in a public subnet.
            network = net.profile(
                subnets,
                groups,
                public_ipv4=False,
                ipv6=bool(vpc.get("Ipv6AllowedForDualStack")),
            )
        else:
            network = NetworkProfile(
                inbound=[],
                internet_egress=True,
                in_vpc=False,
                egress_detail="Lambda outside a VPC has outbound internet",
            )
        runtime_name = fn.get("Runtime")
        agent = Agent(
            id=f"lambda-{region}-{name}",
            name=name,
            account_id=account_id,
            region=region,
            platform=Platform.LAMBDA,
            resource_arn=arn,
            identity_arn=fn.get("Role"),
            network=network,
            description=(fn.get("Description") or "")[:200],
            runtime=RuntimeProfile(
                platform_detail=f"Lambda {fn.get('PackageType', 'Zip').lower()}",
                language_runtime=runtime_name,
                runtime_deprecated=(
                    bool(_DEPRECATED_RUNTIMES.match(runtime_name)) if runtime_name else None
                ),
            ),
        )
        apply_env(
            agent,
            inspect_env(f"Lambda {name}", (fn.get("Environment") or {}).get("Variables")),
            "Lambda configuration",
        )
        layers = [layer["Arn"] for layer in fn.get("Layers") or [] if _AI_NAME.search(layer["Arn"])]
        if layers:
            agent.evidence.append(
                Evidence(
                    signal="config",
                    source="Lambda layers",
                    detail=f"Layer name suggests AI use: {layers[0]}",
                )
            )
        if _AI_NAME.search(name):
            agent.evidence.append(
                Evidence(
                    signal="config",
                    source="Lambda name",
                    detail="The function name suggests AI use",
                )
            )
        agents.append(agent)
    return agents


def enrich_lambda(session: Any, agent: Agent) -> None:
    """Triggers and entry points. These take one call per function, so only run them on agents."""
    api = client(session, "lambda", agent.region)
    name = agent.name
    policy_text = quiet(lambda: api.get_policy(FunctionName=name).get("Policy"))
    policy = json.loads(policy_text) if policy_text else None
    urls = quiet(
        lambda: api.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", []), None
    )
    maps = quiet(
        lambda: api.list_event_source_mappings(FunctionName=name).get("EventSourceMappings", []),
        None,
    )
    agent.network.inbound = None if urls is None else _lambda_exposure(policy, urls)
    if urls is not None and maps is not None:
        agent.triggers = _lambda_triggers(policy, maps, urls)


def _image_pinned(image: str) -> bool:
    return "@sha256:" in image


def _ecs_load_balancers(session: Any, region: str, service: dict) -> list[Exposure]:
    elb = client(session, "elbv2", region)
    exposures = []
    for entry in service.get("loadBalancers", []):
        target_group = entry.get("targetGroupArn")
        if not target_group:
            continue
        groups = quiet(
            lambda t=target_group: elb.describe_target_groups(TargetGroupArns=[t]).get(
                "TargetGroups", []
            ),
            [],
        )
        for group in groups:
            for lb_arn in group.get("LoadBalancerArns", []):
                lbs = quiet(
                    lambda a=lb_arn: elb.describe_load_balancers(LoadBalancerArns=[a]).get(
                        "LoadBalancers", []
                    ),
                    [],
                )
                listeners = quiet(
                    lambda a=lb_arn: elb.describe_listeners(LoadBalancerArn=a).get("Listeners", [])
                )
                for lb in lbs:
                    has_auth = (
                        None
                        if listeners is None
                        else any(
                            action.get("Type", "").startswith("authenticate")
                            for listener in listeners
                            for action in listener.get("DefaultActions", [])
                        )
                    )
                    exposures.append(
                        Exposure(
                            kind="Load balancer",
                            detail=lb.get("LoadBalancerName", "load balancer"),
                            internet=lb.get("Scheme") == "internet-facing",
                            authenticated=has_auth,
                            auth_detail=(
                                "Listener authentication"
                                if has_auth
                                else "No listener authentication"
                                if has_auth is False
                                else ""
                            ),
                        )
                    )
    return exposures


def collect_ecs(
    session: Any, region: str, account_id: str, net: RegionNetwork, coverage: CoverageLog
) -> list[Agent]:
    ecs = client(session, "ecs", region)

    def clusters() -> list[str]:
        return [
            c
            for page in ecs.get_paginator("list_clusters").paginate()
            for c in page.get("clusterArns", [])
        ]

    agents = []
    arns, _ = attempt(coverage, "ECS", region, clusters, [])
    for cluster in arns:
        service_arns = [
            s
            for page in ecs.get_paginator("list_services").paginate(cluster=cluster)
            for s in page.get("serviceArns", [])
        ]
        for start in range(0, len(service_arns), 10):
            described = ecs.describe_services(
                cluster=cluster, services=service_arns[start : start + 10]
            )
            for service in described.get("services", []):
                agent = _ecs_agent(session, ecs, service, region, account_id, net)
                if agent is not None:
                    agents.append(agent)
    return agents


def _ecs_agent(
    session: Any, ecs: Any, service: dict, region: str, account_id: str, net: RegionNetwork
) -> Agent | None:
    response = quiet(
        lambda: ecs.describe_task_definition(
            taskDefinition=service["taskDefinition"], include=["TAGS"]
        )
    )
    if response is None:
        return None
    task = response["taskDefinition"]
    tags = {t["key"]: t["value"] for t in response.get("tags", [])}
    containers = task.get("containerDefinitions", [])
    vpc = (service.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
    subnets, groups = vpc.get("subnets", []), vpc.get("securityGroups", [])
    public_ip = vpc.get("assignPublicIp") == "ENABLED"
    network = (
        net.profile(subnets, groups, public_ipv4=public_ip)
        if subnets
        else NetworkProfile(inbound=None)
    )
    network.inbound = _ecs_load_balancers(session, region, service)
    first_image = containers[0].get("image") if containers else None
    runs_as_root = (
        any(c.get("user") in (None, "root", "0") for c in containers) if containers else None
    )
    # A missing "user" means the image decides, so root is only known when it's explicit.
    if containers and all(c.get("user") is None for c in containers):
        runs_as_root = None
    agent = Agent(
        id=f"ecs-{region}-{service['serviceName']}",
        name=service["serviceName"],
        account_id=account_id,
        region=region,
        platform=Platform.ECS,
        resource_arn=service["serviceArn"],
        identity_arn=task.get("taskRoleArn"),
        secret_fetch_role_arns=[task["executionRoleArn"]] if task.get("executionRoleArn") else [],
        owner=_tag(tags, _OWNER_TAGS),
        environment=_tag(tags, _ENV_TAGS),
        network=network,
        runtime=RuntimeProfile(
            platform_detail=service.get("launchType") or "ECS",
            image=first_image,
            image_pinned=all(_image_pinned(c.get("image", "")) for c in containers),
            privileged=any(c.get("privileged") for c in containers),
            runs_as_root=runs_as_root,
            read_only_root=all(c.get("readonlyRootFilesystem") for c in containers),
        ),
    )
    family = f"{task.get('family')}:{task.get('revision')}"
    for container in containers:
        env = {e["name"]: e.get("value", "") for e in container.get("environment", [])}
        apply_env(agent, inspect_env(f"ECS task definition {family}", env), "ECS task definition")
        agent.secret_arns += [s["valueFrom"] for s in container.get("secrets", [])]
        if _AI_NAME.search(container.get("image", "")):
            agent.evidence.append(
                Evidence(
                    signal="config",
                    source="Container image",
                    detail="The image name suggests AI use",
                )
            )
    return agent


def collect_eks(session: Any, region: str, account_id: str, coverage: CoverageLog) -> list[Agent]:
    eks = client(session, "eks", region)

    def clusters() -> list[str]:
        return [
            c
            for page in eks.get_paginator("list_clusters").paginate()
            for c in page.get("clusters", [])
        ]

    agents = []
    names, _ = attempt(coverage, "EKS", region, clusters, [])
    for cluster in names:
        info = quiet(lambda c=cluster: eks.describe_cluster(name=c).get("cluster", {}), {})
        associations = quiet(
            lambda c=cluster: eks.list_pod_identity_associations(clusterName=c).get(
                "associations", []
            ),
            [],
        )
        public = (info.get("resourcesVpcConfig") or {}).get("endpointPublicAccess")
        for assoc in associations:
            detail = quiet(
                lambda a=assoc, c=cluster: eks.describe_pod_identity_association(
                    clusterName=c, associationId=a["associationId"]
                ).get("association", {}),
                {},
            )
            account = assoc.get("namespace", "default")
            service_account = assoc.get("serviceAccount", "unknown")
            agents.append(
                Agent(
                    id=f"eks-{region}-{cluster}-{account}-{service_account}",
                    name=f"{cluster}/{account}/{service_account}",
                    account_id=account_id,
                    region=region,
                    platform=Platform.EKS,
                    resource_arn=assoc.get("associationArn", cluster),
                    identity_arn=detail.get("roleArn"),
                    network=NetworkProfile(
                        in_vpc=True, vpc_id=(info.get("resourcesVpcConfig") or {}).get("vpcId")
                    ),
                    runtime=RuntimeProfile(
                        platform_detail=f"EKS cluster {cluster}"
                        + (", public API endpoint" if public else ""),
                        vulns_source="Pods can't be inspected through AWS APIs",
                    ),
                )
            )
    if names:
        coverage.gap(
            "EKS pods",
            region,
            CoverageStatus.NOT_AVAILABLE,
            "Needs Kubernetes API access, which this version doesn't use",
        )
    return agents


def collect_ec2(
    session: Any,
    region: str,
    account_id: str,
    net: RegionNetwork,
    profiles: dict[str, str],
    coverage: CoverageLog,
) -> list[Agent]:
    ec2 = client(session, "ec2", region)

    def instances() -> list[dict]:
        pages = ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
        return [
            i
            for page in pages
            for r in page.get("Reservations", [])
            for i in r.get("Instances", [])
        ]

    found, _ = attempt(coverage, "EC2", region, instances, [])
    agents = []
    for instance in found:
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        profile_arn = (instance.get("IamInstanceProfile") or {}).get("Arn")
        subnets = [instance["SubnetId"]] if instance.get("SubnetId") else []
        groups = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
        public_ip = bool(instance.get("PublicIpAddress"))
        network = (
            net.profile(subnets, groups, public_ipv4=public_ip) if subnets else NetworkProfile()
        )
        if public_ip and network.open_security_groups is None:
            network.inbound = None
        if public_ip:
            network.internet_egress = (
                True if network.internet_egress is None else network.internet_egress
            )
            if network.open_security_groups:
                network.inbound = [
                    Exposure(
                        kind="Public IP",
                        detail=instance["InstanceId"],
                        internet=True,
                        authenticated=None,
                        auth_detail="Security group open to the internet",
                    )
                ]
        instance_id = instance["InstanceId"]
        agent = Agent(
            id=f"ec2-{region}-{instance_id}",
            name=tags.get("Name", instance_id),
            account_id=account_id,
            region=region,
            platform=Platform.EC2,
            resource_arn=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
            identity_arn=profiles.get(profile_arn or ""),
            owner=_tag(tags, _OWNER_TAGS),
            environment=_tag(tags, _ENV_TAGS),
            network=network,
            runtime=RuntimeProfile(
                platform_detail=instance.get("InstanceType", "EC2"),
                imdsv2_required=(instance.get("MetadataOptions") or {}).get("HttpTokens")
                == "required",
            ),
        )
        ai_tags = [k for k, v in tags.items() if _AI_NAME.search(f"{k}={v}")]
        if ai_tags:
            agent.evidence.append(
                Evidence(
                    signal="config", source="EC2 tags", detail=f"Tag {ai_tags[0]} suggests AI use"
                )
            )
        agents.append(agent)
    return agents
