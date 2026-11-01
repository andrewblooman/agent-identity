"""Bedrock AgentCore: runtimes, gateways, credential providers and memory."""

from __future__ import annotations

from typing import Any

from agent_identity.analysis.redaction import hostnames_in, inspect_env
from agent_identity.aws.base import CoverageLog, attempt, quiet
from agent_identity.aws.compute import apply_env
from agent_identity.aws.network import RegionNetwork
from agent_identity.aws.session import client
from agent_identity.models import (
    Agent,
    CoverageStatus,
    DataStore,
    DomainRef,
    Evidence,
    Exposure,
    NetworkProfile,
    Platform,
    RuntimeProfile,
    SaasConnection,
    Secret,
    Tool,
)

_SERVICE = "bedrock-agentcore-control"


def _pages(call: Any, key: str, **kwargs: Any) -> list[dict]:
    items, token = [], None
    while True:
        response = call(**kwargs, **({"nextToken": token} if token else {}))
        items += response.get(key, [])
        token = response.get("nextToken")
        if not token:
            return items


def collect_runtimes(
    session: Any, region: str, account_id: str, net: RegionNetwork, coverage: CoverageLog
) -> list[Agent]:
    api = client(session, _SERVICE, region)
    summaries, _ = attempt(
        coverage, "AgentCore", region, lambda: _pages(api.list_agent_runtimes, "agentRuntimes"), []
    )
    agents = []
    for summary in summaries:
        runtime_id = summary["agentRuntimeId"]
        detail = quiet(lambda r=runtime_id: api.get_agent_runtime(agentRuntimeId=r), {})
        config = detail.get("networkConfiguration") or {}
        mode = config.get("networkMode")
        vpc = config.get("networkModeConfig") or {}
        if mode == "VPC":
            network = net.profile(vpc.get("subnets", []), vpc.get("securityGroups", []))
        elif mode == "PUBLIC":
            network = NetworkProfile(
                in_vpc=False, internet_egress=True, egress_detail="Runtime uses public network mode"
            )
        else:
            network = NetworkProfile()
        has_jwt = bool((detail.get("authorizerConfiguration") or {}).get("customJWTAuthorizer"))
        if detail:
            network.inbound = [
                Exposure(
                    kind="AgentCore endpoint",
                    detail=summary.get("agentRuntimeName", runtime_id),
                    internet=mode == "PUBLIC",
                    authenticated=True,
                    auth_detail="Custom JWT authoriser" if has_jwt else "AWS IAM (SigV4)",
                )
            ]
        container = (
            (detail.get("agentRuntimeArtifact") or {}).get("containerConfiguration") or {}
        ).get("containerUri")
        agent = Agent(
            id=f"agentcore-{region}-{runtime_id}",
            name=summary.get("agentRuntimeName", runtime_id),
            account_id=account_id,
            region=region,
            platform=Platform.AGENTCORE,
            resource_arn=summary.get("agentRuntimeArn", runtime_id),
            description=(summary.get("description") or "")[:200],
            evidence=[Evidence(signal="managed", source="AgentCore", detail="Registered runtime")],
            identity_arn=detail.get("roleArn"),
            network=network,
            runtime=RuntimeProfile(
                platform_detail="AgentCore container" if container else "AgentCore code",
                image=container,
                image_pinned=("@sha256:" in container) if container else None,
            ),
        )
        apply_env(
            agent,
            inspect_env(f"AgentCore runtime {agent.name}", detail.get("environmentVariables")),
            "AgentCore runtime",
        )
        agents.append(agent)
    return agents


def collect_memories(session: Any, region: str, coverage: CoverageLog) -> list[DataStore]:
    api = client(session, _SERVICE, region)
    memories, _ = attempt(
        coverage,
        "AgentCore memory",
        region,
        lambda: _pages(api.list_memories, "memories"),
        [],
        record_ok=False,
    )
    return [
        DataStore(arn=m["arn"], name=m.get("id", m["arn"]), type="Agent memory", region=region)
        for m in memories
        if m.get("arn")
    ]


def _vendor_name(raw: str | None) -> str | None:
    return raw.removesuffix("Oauth2") if raw else None


def collect_credential_providers(session: Any, region: str, coverage: CoverageLog) -> list[Secret]:
    api = client(session, _SERVICE, region)
    secrets = []
    oauth, _ = attempt(
        coverage,
        "AgentCore OAuth providers",
        region,
        lambda: _pages(api.list_oauth2_credential_providers, "credentialProviders"),
        [],
        record_ok=False,
    )
    for provider in oauth:
        secrets.append(
            Secret(
                arn=provider["credentialProviderArn"],
                name=provider["name"],
                kind="OAuth provider",
                region=region,
                vendor=_vendor_name(provider.get("credentialProviderVendor")),
                created=provider.get("createdTime"),
            )
        )
    keys, _ = attempt(
        coverage,
        "AgentCore API key providers",
        region,
        lambda: _pages(api.list_api_key_credential_providers, "credentialProviders"),
        [],
        record_ok=False,
    )
    for provider in keys:
        secrets.append(
            Secret(
                arn=provider["credentialProviderArn"],
                name=provider["name"],
                kind="API key provider",
                region=region,
                created=provider.get("createdTime"),
            )
        )
    return secrets


def link_gateways(
    session: Any, region: str, agents: list[Agent], providers: list[Secret], coverage: CoverageLog
) -> None:
    """Attach gateway targets to runtimes whose config names the gateway's hostname.

    AWS doesn't record which runtime uses which gateway, so a gateway with no match stays
    unlinked and is reported as a coverage note.
    """
    api = client(session, _SERVICE, region)
    gateways, _ = attempt(
        coverage,
        "AgentCore gateways",
        region,
        lambda: _pages(api.list_gateways, "items"),
        [],
        record_ok=False,
    )
    by_arn = {p.arn: p for p in providers}
    unlinked = []
    for summary in gateways:
        gateway_id = summary["gatewayId"]
        detail = quiet(lambda g=gateway_id: api.get_gateway(gatewayIdentifier=g), {})
        hosts = hostnames_in(detail.get("gatewayUrl") or "")
        users = [a for a in agents if {d.hostname for d in a.domains} & set(hosts)]
        if not users:
            unlinked.append(summary.get("name", gateway_id))
            continue
        targets = quiet(
            lambda g=gateway_id: _pages(api.list_gateway_targets, "items", gatewayIdentifier=g), []
        )
        for target in targets:
            config = quiet(
                lambda g=gateway_id, t=target["targetId"]: api.get_gateway_target(
                    gatewayIdentifier=g, targetId=t
                ),
                {},
            )
            _apply_target(config, target, users, by_arn)
    if unlinked:
        coverage.gap(
            "AgentCore gateway links",
            region,
            CoverageStatus.NOT_AVAILABLE,
            f"Can't tell which agents use: {', '.join(unlinked)}",
        )


def _apply_target(
    config: dict, target: dict, users: list[Agent], by_arn: dict[str, Secret]
) -> None:
    mcp = (config.get("targetConfiguration") or {}).get("mcp") or {}
    endpoint = (mcp.get("mcpServer") or {}).get("endpoint", "")
    lambda_arn = (mcp.get("lambda") or {}).get("lambdaArn", "")
    external = bool(endpoint)
    for credential in config.get("credentialProviderConfigurations") or []:
        provider = credential.get("credentialProvider") or {}
        oauth = provider.get("oauthCredentialProvider") or {}
        key = provider.get("apiKeyCredentialProvider") or {}
        arn = oauth.get("providerArn") or key.get("providerArn")
        secret = by_arn.get(arn or "")
        if secret is None:
            continue
        external = True
        for agent in users:
            agent.secret_arns.append(secret.arn)
            agent.saas.append(
                SaasConnection(
                    vendor=secret.vendor or secret.name,
                    source="AgentCore credential provider",
                    credential_ref=secret.name,
                    credential_type="OAuth" if oauth else "API key",
                    scopes=oauth.get("scopes"),
                )
            )
    for agent in users:
        agent.tools.append(
            Tool(
                name=target.get("name", target["targetId"]),
                type="gateway target",
                target=endpoint or lambda_arn or "gateway target",
                external=external,
            )
        )
        agent.domains += [
            DomainRef(hostname=host, source="gateway target") for host in hostnames_in(endpoint)
        ]
