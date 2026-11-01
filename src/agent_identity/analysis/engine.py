"""Turn a snapshot into findings, scores and everything the pages show."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_identity.analysis import autonomy, data_access, discovery, domains, permissions
from agent_identity.models import (
    AccessLevel,
    Agent,
    AgentResult,
    CoverageStatus,
    DataGrant,
    Domain,
    DomainScore,
    Finding,
    Result,
    Severity,
    Snapshot,
    Trifecta,
    TrifectaLeg,
)
from agent_identity.rules import checks  # noqa: F401  (registers the rules)
from agent_identity.rules.catalog import RULES, SENSITIVE, Context

SEVERITY_PENALTY = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 22,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}
DOMAIN_WEIGHT = {
    Domain.DATA: 30,
    Domain.IDENTITY: 25,
    Domain.SECRETS: 15,
    Domain.NETWORK: 15,
    Domain.RUNTIME: 10,
    Domain.GOVERNANCE: 5,
}
CRITICAL_CAP = 40
HIGH_CAP = 70

# If one of these lists fails, finding nothing in that domain doesn't mean there's nothing to find.
_INVENTORY_SOURCES = {
    Domain.IDENTITY: {"IAM"},
    Domain.DATA: {"IAM", "S3", "DynamoDB", "RDS", "Bedrock knowledge bases", "AgentCore memory"},
    Domain.SECRETS: {
        "IAM",
        "Secrets Manager",
        "SSM Parameter Store",
        "AgentCore OAuth providers",
        "AgentCore API key providers",
    },
}
_INCOMPLETE = {CoverageStatus.ACCESS_DENIED, CoverageStatus.THROTTLED, CoverageStatus.ERROR}


def incomplete_domains(snapshot: Snapshot) -> set[Domain]:
    failed = {c.source for c in snapshot.coverage if c.status in _INCOMPLETE}
    return {domain for domain, sources in _INVENTORY_SOURCES.items() if sources & failed}


def compute_trifecta(
    agent: Agent, grants: list[DataGrant], stores: dict, data_complete: bool = True
) -> Trifecta:
    readable = [g for g in grants if AccessLevel.READ in g.levels or AccessLevel.ADMIN in g.levels]
    sensitive = [g for g in readable if stores[g.store_arn].sensitivity in SENSITIVE]
    unclassified = [g for g in readable if stores[g.store_arn].sensitivity.value == "unknown"]
    if sensitive:
        data = TrifectaLeg(
            state=True,
            reasons=[
                f"Can read {stores[g.store_arn].name} ({stores[g.store_arn].sensitivity.value})"
                for g in sensitive
            ],
        )
    elif unclassified:
        data = TrifectaLeg(
            state=None,
            reasons=[f"{stores[g.store_arn].name} has no classification" for g in unclassified],
        )
    elif agent.identity_arn is None:
        data = TrifectaLeg(state=None, reasons=["Its identity could not be determined"])
    elif not data_complete:
        data = TrifectaLeg(state=None, reasons=["Some data stores or roles could not be listed"])
    else:
        data = TrifectaLeg(state=False, reasons=["No sensitive data found within reach"])

    inputs = [f"Reads untrusted content: {i}" for i in agent.untrusted_inputs or []]
    inputs += [f"Open to the internet: {e.kind}" for e in agent.network.inbound or [] if e.internet]
    if inputs:
        untrusted = TrifectaLeg(state=True, reasons=inputs)
    elif agent.untrusted_inputs is None and agent.network.inbound is None:
        untrusted = TrifectaLeg(state=None, reasons=["Inputs could not be determined"])
    elif agent.untrusted_inputs is None:
        untrusted = TrifectaLeg(
            state=None, reasons=["Not exposed to the internet, but other inputs are unknown"]
        )
    else:
        untrusted = TrifectaLeg(state=False, reasons=["No untrusted input found"])

    outbound_reasons = []
    if agent.network.internet_egress:
        outbound_reasons.append(agent.network.egress_detail or "Has outbound internet access")
    outbound_reasons += [f"External tool: {t.name}" for t in agent.tools if t.external]
    outbound_reasons += [f"Can write to {s.vendor}" for s in agent.saas if s.can_write]
    if outbound_reasons:
        outbound = TrifectaLeg(state=True, reasons=outbound_reasons)
    elif agent.network.internet_egress is None:
        outbound = TrifectaLeg(state=None, reasons=["Outbound access could not be determined"])
    else:
        outbound = TrifectaLeg(state=False, reasons=["No outbound path found"])
    return Trifecta(sensitive_data=data, untrusted_input=untrusted, outbound_path=outbound)


def _score_domain(findings: list[Finding]) -> int:
    return max(0, 100 - sum(SEVERITY_PENALTY[f.severity] for f in findings))


def _score_agent(
    domain_scores: list[DomainScore], findings: list[Finding]
) -> tuple[int | None, int | None, str]:
    scored = [d for d in domain_scores if d.score is not None]
    if not scored:
        return None, None, ""
    weight = sum(DOMAIN_WEIGHT[d.domain] for d in scored)
    uncapped = round(sum(d.score * DOMAIN_WEIGHT[d.domain] for d in scored) / weight)
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities and uncapped > CRITICAL_CAP:
        return CRITICAL_CAP, uncapped, "Limited to 40 by a critical finding"
    if Severity.HIGH in severities and uncapped > HIGH_CAP:
        return HIGH_CAP, uncapped, "Limited to 70 by a high finding"
    return uncapped, uncapped, ""


def estate_score(scores: list[int]) -> int | None:
    """The mean, pulled towards the worst quarter so one bad agent can't be averaged away."""
    if not scores:
        return None
    ordered = sorted(scores)
    worst = ordered[: max(1, len(ordered) // 4)]
    return round((sum(ordered) / len(ordered) + sum(worst) / len(worst)) / 2)


def analyse(snapshot: Snapshot, now: datetime | None = None) -> Result:
    now = now or datetime.now(UTC)
    identities = {i.arn: i for i in snapshot.identities}
    stores = {s.arn: s for s in snapshot.stores}
    secrets = {s.arn: s for s in snapshot.secrets}
    agents_by_id = {a.id: a for a in snapshot.agents}

    for agent in snapshot.agents:
        discovery.classify(agent, identities.get(agent.identity_arn or ""))

    grants = data_access.build_data_grants(snapshot)
    secret_grants = data_access.build_secret_grants(snapshot)
    domain_info = domains.build_domains(snapshot.agents)
    incomplete = incomplete_domains(snapshot)
    unknown_hosts = {d.hostname for d in domain_info if d.category == "Unknown"}

    agent_results: list[AgentResult] = []
    findings: list[Finding] = []
    total_runs = assessed_runs = 0

    for agent in snapshot.agents:
        identity = identities.get(agent.identity_arn or "")
        own_grants = [g for g in grants if g.agent_id == agent.id]
        own_secret_grants = [g for g in secret_grants if g.agent_id == agent.id]
        trifecta = compute_trifecta(agent, own_grants, stores, Domain.DATA not in incomplete)
        scope, scope_reasons = autonomy.estimate_scope(agent, own_grants)
        admin = identity is not None and permissions.is_admin_equivalent(identity)
        privesc = permissions.privilege_escalation_paths(identity) if identity else []
        routes = data_access.identity_routes(agent, snapshot)
        indirect_admin = [
            route.identity.name
            for route in routes
            if route.identity.arn != agent.identity_arn
            and permissions.is_admin_equivalent(route.identity)
        ]
        shared = [
            other
            for other in snapshot.agents
            if other.id != agent.id
            and other.identity_arn == agent.identity_arn
            and agent.identity_arn
        ]
        ctx = Context(
            agent=agent,
            snapshot=snapshot,
            now=now,
            identity=identity,
            identities=identities,
            stores=stores,
            secrets=secrets,
            grants=own_grants,
            secret_grants=own_secret_grants,
            all_grants=grants,
            all_secret_grants=secret_grants,
            trifecta=trifecta,
            autonomy_scope=scope,
            admin_equivalent=admin,
            privesc_paths=privesc,
            indirect_admin=indirect_admin,
            shared_with=shared,
            unknown_domains=[d.hostname for d in agent.domains if d.hostname in unknown_hosts],
            agents_by_id=agents_by_id,
        )

        per_domain: dict[Domain, dict[str, list | int]] = {
            d: {"findings": [], "assessed": 0, "total": 0} for d in Domain
        }
        own_findings: list[Finding] = []
        for rule in RULES:
            bucket = per_domain[rule.domain]
            bucket["total"] += 1
            total_runs += 1
            hits = rule.fn(ctx)
            if hits is None or (not hits and rule.domain in incomplete):
                continue
            bucket["assessed"] += 1
            assessed_runs += 1
            for hit in hits:
                finding = Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=hit.severity or rule.severity,
                    domain=rule.domain,
                    agent_id=agent.id,
                    subject=hit.subject,
                    evidence=hit.evidence,
                    remediation=rule.remediation,
                    nhi=list(rule.nhi),
                    asi=list(rule.asi),
                    aws_dimension=list(rule.aws),
                )
                bucket["findings"].append(finding)
                own_findings.append(finding)

        domain_scores = [
            DomainScore(
                domain=domain,
                score=_score_domain(bucket["findings"]) if bucket["assessed"] else None,
                assessed=bucket["assessed"],
                total=bucket["total"],
            )
            for domain, bucket in per_domain.items()
        ]
        score, uncapped, cap_reason = _score_agent(domain_scores, own_findings)
        assessed = sum(d.assessed for d in domain_scores)
        total = sum(d.total for d in domain_scores)
        agent_results.append(
            AgentResult(
                agent_id=agent.id,
                score=score,
                uncapped_score=uncapped,
                cap_reason=cap_reason,
                coverage_pct=round(100 * assessed / total) if total else 0,
                domains=domain_scores,
                autonomy_scope=scope,
                autonomy_reasons=scope_reasons,
                trifecta=trifecta,
                admin_equivalent=admin,
                privesc_paths=privesc,
                shared_identity_with=[a.id for a in shared],
            )
        )
        findings.extend(own_findings)

    order = list(Severity)
    findings.sort(key=lambda f: (order.index(f.severity), f.rule_id, f.agent_id or ""))
    not_assessed = [
        {"source": c.source, "region": c.region, "status": c.status.value, "detail": c.detail}
        for c in snapshot.coverage
        if c.status != CoverageStatus.OK
    ]
    return Result(
        score=estate_score([r.score for r in agent_results if r.score is not None]),
        coverage_pct=round(100 * assessed_runs / total_runs) if total_runs else 0,
        agents=agent_results,
        grants=grants,
        secret_grants=secret_grants,
        findings=findings,
        domains=domain_info,
        not_assessed=not_assessed,
    )
