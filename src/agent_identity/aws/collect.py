"""Run every collector and put together a snapshot."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from agent_identity.analysis import data_access, discovery, permissions
from agent_identity.aws import (
    agentcore,
    bedrock,
    cloudtrail,
    compute,
    data_stores,
    iam,
    network,
    optional,
    secrets,
    vulns,
)
from agent_identity.aws.base import CoverageLog, attempt
from agent_identity.aws.session import client, create_session
from agent_identity.config import Settings
from agent_identity.models import (
    AccountSignals,
    Agent,
    CoverageStatus,
    DataStore,
    Domain,
    Evidence,
    Identity,
    Platform,
    SaasConnection,
    Secret,
    Snapshot,
)

log = logging.getLogger(__name__)

_MAX_SIMULATED_IDENTITIES = 40
_MAX_LAST_ACCESSED = 40
_NOT_SCANNED_NOTE = (
    "Calls to the bedrock-mantle endpoint and to models outside AWS don't show up in this signal"
)


def _merge_behaviour(
    agents: list[Agent],
    identities: dict[str, Identity],
    usage: dict[str, cloudtrail.ModelUse],
    lookback_days: int,
) -> list[Agent]:
    """Link model calls to workloads through their role, and flag roles with no workload."""
    by_identity: dict[str, list[Agent]] = {}
    for agent in agents:
        if agent.identity_arn:
            by_identity.setdefault(agent.identity_arn, []).append(agent)

    extras: list[Agent] = []
    for principal, use in usage.items():
        identity = identities.get(principal)
        if identity is None:
            continue
        evidence = Evidence(
            signal="behaviour",
            source="CloudTrail",
            detail=f"{use.calls} model calls in {lookback_days} days",
        )
        if use.human_agents:
            identity.human_session_signal = (
                f"Model calls made through: {', '.join(sorted(use.human_agents))}"
            )
        linked = by_identity.get(principal, [])
        for agent in linked:
            agent.evidence.append(evidence)
            agent.last_model_call = use.last_call
        if not linked:
            extras.append(_identity_agent(identity, [evidence], use))
    return extras


def _identity_agent(
    identity: Identity, evidence: list[Evidence], use: cloudtrail.ModelUse | None = None
) -> Agent:
    return Agent(
        id=f"iam-{identity.kind}-{identity.name}",
        name=identity.name,
        account_id=identity.account_id,
        region="global",
        platform=Platform.IAM_ONLY,
        resource_arn=identity.arn,
        description="An identity that uses or can use models, with no workload found behind it",
        evidence=evidence,
        identity_arn=identity.arn,
        last_model_call=use.last_call if use else None,
    )


def _permission_candidates(identities: list[Identity], agents: list[Agent]) -> list[Agent]:
    """Add IAM evidence, and list service roles and key-holding users that have no workload."""
    used = {a.identity_arn for a in agents}
    extras = []
    for identity in identities:
        if not discovery.has_explicit_model_access(identity):
            continue
        evidence = Evidence(
            signal="iam", source="IAM", detail="A policy names bedrock model invocation"
        )
        if identity.arn in used:
            for agent in agents:
                if agent.identity_arn == identity.arn:
                    agent.evidence.append(evidence)
            continue
        is_service_role = identity.kind == "role" and bool(
            set(identity.trusted_principals) & iam.WORKLOAD_SERVICES
        )
        if is_service_role or (identity.kind == "user" and identity.access_keys):
            extras.append(_identity_agent(identity, [evidence]))
    return extras


def _simulate(
    session,
    agents: list[Agent],
    identities: dict[str, Identity],
    stores: list[DataStore],
    secret_list: list[Secret],
    snapshot_identities,
    coverage: CoverageLog,
) -> dict[str, bool]:
    results: dict[str, bool] = {}
    interim = Snapshot(
        mode="live",
        account_id="",
        regions=[],
        taken_at=datetime.now(UTC),
        agents=agents,
        identities=snapshot_identities,
        stores=stores,
        secrets=secret_list,
    )
    reachable: dict[str, Identity] = {}
    for agent in agents:
        for route in data_access.identity_routes(agent, interim):
            reachable[route.identity.arn] = route.identity

    def run() -> None:
        for identity in list(reachable.values())[:_MAX_SIMULATED_IDENTITIES]:
            checks = []
            for store in stores:
                for actions in data_access.STORE_ACTIONS.get(store.type, {}).values():
                    for action in actions:
                        for resource in data_access.resources_to_check(identity, store, action):
                            if permissions.evaluate(
                                identity, action, resource, store.resource_policy
                            ).allowed:
                                checks.append((action, resource))
            for secret in secret_list:
                action = data_access.SECRET_ACTIONS.get(secret.kind)
                if (
                    action
                    and permissions.evaluate(
                        identity, action, secret.arn, secret.resource_policy
                    ).allowed
                ):
                    checks.append((action, secret.arn))
            if checks:
                iam.simulate(session, identity, checks, results)

    attempt(coverage, "IAM policy simulator", "global", run, None, [Domain.DATA, Domain.SECRETS])
    return results


def _secret_matches(secret: Secret, ref: str, region: str) -> bool:
    if secret.arn == ref or secret.arn.startswith(ref) or ref.startswith(secret.arn):
        return True
    return secret.kind == "SSM SecureString" and secret.name == ref and secret.region == region


def _link_secret_refs(agents: list[Agent], secret_list: list[Secret]) -> None:
    """Config can name a secret by a partial ARN or a parameter path. Match it to the real one."""
    for agent in agents:
        resolved = []
        for ref in agent.secret_arns:
            match = next((s for s in secret_list if _secret_matches(s, ref, agent.region)), None)
            if match is None:
                continue
            resolved.append(match.arn)
            if match.vendor and not any(c.credential_ref == match.name for c in agent.saas):
                agent.saas.append(
                    SaasConnection(
                        vendor=match.vendor,
                        source="secret name",
                        credential_type="Stored secret",
                        credential_ref=match.name,
                    )
                )
        agent.secret_arns = sorted(set(resolved))


def _link_tool_roles(agents: list[Agent], workloads: list[Agent]) -> None:
    """An action group runs as its Lambda's role, so that role is part of the agent's reach."""
    roles = {w.resource_arn: w.identity_arn for w in workloads}
    for agent in agents:
        for tool in agent.tools:
            if tool.target in roles:
                tool.role_arn = roles[tool.target]


def collect_snapshot(settings: Settings) -> Snapshot:
    now = datetime.now(UTC)
    session = create_session(settings.aws_profile, settings.scan_regions[0])
    account_id = client(session, "sts").get_caller_identity()["Account"]
    coverage = CoverageLog()

    (identity_list, profiles), identities_ok = attempt(
        coverage,
        "IAM",
        "global",
        lambda: iam.collect_identities(session, account_id),
        ([], {}),
        [Domain.IDENTITY, Domain.DATA, Domain.SECRETS],
    )
    identities = {i.arn: i for i in identity_list}
    for identity in identity_list:
        if identity.kind == "user" and discovery.has_explicit_model_access(identity):
            iam.add_access_keys(session, identity)

    workloads: list[Agent] = []
    managed: list[Agent] = []
    stores: list[DataStore] = []
    secret_list: list[Secret] = []
    signals = AccountSignals()
    usage: dict[str, cloudtrail.ModelUse] = {}
    data_events: set[str] | None = None

    for region in settings.scan_regions:
        net = network.RegionNetwork(session, region, coverage)
        workloads += compute.collect_lambda(session, region, account_id, net, coverage)
        workloads += compute.collect_ecs(session, region, account_id, net, coverage)
        workloads += compute.collect_eks(session, region, account_id, coverage)
        workloads += compute.collect_ec2(session, region, account_id, net, profiles, coverage)
        managed += bedrock.collect_agents(session, region, account_id, coverage)
        runtimes = agentcore.collect_runtimes(session, region, account_id, net, coverage)
        managed += runtimes
        stores += bedrock.collect_knowledge_bases(session, region, coverage)
        stores += agentcore.collect_memories(session, region, coverage)
        stores += data_stores.collect_dynamodb(session, region, coverage)
        stores += data_stores.collect_rds(session, region, coverage)
        providers = agentcore.collect_credential_providers(session, region, coverage)
        agentcore.link_gateways(session, region, runtimes, providers, coverage)
        secret_list += providers
        secret_list += secrets.collect_secrets(session, region, coverage)
        secret_list += secrets.collect_parameters(session, region, account_id, coverage)
        signals.model_invocation_logging[region] = bedrock.invocation_logging(
            session, region, coverage
        )
        for principal, use in cloudtrail.collect_model_use(
            session, region, now, settings.cloudtrail_lookback_days, coverage
        ).items():
            merged = usage.setdefault(principal, cloudtrail.ModelUse())
            merged.calls += use.calls
            merged.human_agents |= use.human_agents
            if use.last_call and (not merged.last_call or use.last_call > merged.last_call):
                merged.last_call = use.last_call
        trail_buckets = cloudtrail.data_event_buckets(session, region, coverage)
        if trail_buckets is not None:
            data_events = (data_events or set()) | trail_buckets

    stores += data_stores.collect_s3(session, account_id, data_events, coverage)
    primary = settings.scan_regions[0]
    signals.cloudtrail_data_events = bool(data_events) if data_events is not None else None
    if data_events is not None and not data_events:
        coverage.gap(
            "CloudTrail data events",
            primary,
            CoverageStatus.NOT_ENABLED,
            "Which agent used which store is mostly unknown",
            [Domain.DATA],
        )
    coverage.gap(
        "Model calls outside this signal",
        primary,
        CoverageStatus.NOT_AVAILABLE,
        _NOT_SCANNED_NOTE,
        [Domain.GOVERNANCE],
    )
    unused, internal = optional.access_analyzers(session, primary, coverage)
    signals.access_analyzer_unused, signals.access_analyzer_internal = unused, internal
    for region in settings.scan_regions:
        state = optional.apply_macie(session, region, stores, coverage)
        signals.macie_enabled = (
            bool(signals.macie_enabled or state) if state is not None else signals.macie_enabled
        )

    extras = _merge_behaviour(
        [*workloads, *managed], identities, usage, settings.cloudtrail_lookback_days
    )
    extras += _permission_candidates(identity_list, [*workloads, *managed, *extras])
    agents = [*managed, *(w for w in workloads if w.evidence), *extras]
    _link_tool_roles(agents, workloads)
    _link_secret_refs(agents, secret_list)
    for agent in agents:
        if agent.platform == Platform.LAMBDA:
            compute.enrich_lambda(session, agent)
    for region in settings.scan_regions:
        regional = [a for a in agents if a.region == region]
        enabled = vulns.inspector_enabled(session, region, coverage)
        signals.inspector_enabled = bool(signals.inspector_enabled or enabled)
        if enabled:
            vulns.apply_inspector(session, region, regional, coverage)
        elif enabled is False:
            coverage.gap(
                "Inspector",
                region,
                CoverageStatus.NOT_ENABLED,
                "Only ECR images can be scanned, using Trivy",
                [Domain.RUNTIME],
            )
        vulns.scan_with_trivy(regional, settings, coverage, region)
        optional.apply_dns_logs(session, region, regional, now, coverage)

    agent_identities = [identities[a.identity_arn] for a in agents if a.identity_arn in identities]
    if agent_identities:
        iam.add_last_accessed(session, agent_identities[:_MAX_LAST_ACCESSED])
    if len(agent_identities) > _MAX_LAST_ACCESSED:
        coverage.gap(
            "IAM last-accessed",
            "global",
            CoverageStatus.ERROR,
            f"Only the first {_MAX_LAST_ACCESSED} identities were checked",
            [Domain.IDENTITY],
        )
    simulated = _simulate(session, agents, identities, stores, secret_list, identity_list, coverage)
    log.info("Live scan found %s agents across %s regions", len(agents), len(settings.scan_regions))
    return Snapshot(
        mode="live",
        account_id=account_id,
        regions=settings.scan_regions,
        taken_at=now,
        agents=agents,
        identities=identity_list,
        stores=stores,
        secrets=secret_list,
        coverage=coverage.entries,
        signals=signals,
        simulated=simulated,
    )
