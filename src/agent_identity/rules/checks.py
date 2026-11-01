"""Every posture check. Importing this module registers them."""

from __future__ import annotations

from agent_identity.models import AccessLevel, Domain, Platform, Sensitivity, Severity
from agent_identity.rules.catalog import SENSITIVE, WRITE_LEVELS, Context, Hit, rule

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
IDENTITY_CTX = "Identity context"
DATA_CTX = "Data, memory and state protection"
AUDIT = "Audit and logging"
CONTROLS = "Agent and LLM controls"
PERIMETER = "Agency perimeters and policies"
ORCHESTRATION = "Orchestration"


def _age_days(ctx: Context, when) -> int:
    return (ctx.now - when).days


def _store(ctx: Context, grant):
    return ctx.stores[grant.store_arn]


# ---- Identity ---------------------------------------------------------------------------------


@rule(
    "AIP-101",
    "Agent has administrator-level access",
    C,
    Domain.IDENTITY,
    "Replace the policy with one listing only the actions and resources this agent uses.",
    nhi=("NHI5",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX, PERIMETER),
)
def admin_equivalent(ctx: Context):
    if ctx.identity is None:
        return None
    if not ctx.admin_equivalent:
        return []
    names = ", ".join(p.name for p in ctx.identity.policies)
    return [Hit(f"{ctx.identity.name} allows all actions through: {names}", ctx.identity.arn)]


@rule(
    "AIP-102",
    "Agent can raise its own privileges",
    H,
    Domain.IDENTITY,
    "Remove IAM write and iam:PassRole permissions, or scope PassRole to named roles.",
    nhi=("NHI5",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX,),
)
def privesc(ctx: Context):
    if ctx.identity is None:
        return None
    if ctx.admin_equivalent or not ctx.privesc_paths:
        return []
    return [Hit(path, path) for path in ctx.privesc_paths]


@rule(
    "AIP-103",
    "Anyone in a wide group can assume this agent's role",
    H,
    Domain.IDENTITY,
    "Limit the trust policy to the one service or principal that runs this agent.",
    nhi=("NHI4", "NHI6"),
    asi=("ASI03",),
    aws=(IDENTITY_CTX,),
)
def broad_trust(ctx: Context):
    if ctx.identity is None or ctx.identity.kind != "role":
        return None if ctx.identity is None else []
    if not ctx.identity.trust_is_broad:
        return []
    who = ", ".join(ctx.identity.trusted_principals) or "a wildcard principal"
    return [Hit(f"Trust policy allows: {who}", ctx.identity.arn)]


@rule(
    "AIP-104",
    "Agent uses a long-lived access key",
    H,
    Domain.IDENTITY,
    "Run the agent under an IAM role so it gets short-lived credentials, then delete the key.",
    nhi=("NHI7",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX,),
)
def static_key(ctx: Context):
    if ctx.identity is None:
        return None
    return [
        Hit(f"{key.key_id} on user {ctx.identity.name} is {key.status.lower()}", key.key_id)
        for key in ctx.identity.access_keys
    ]


@rule(
    "AIP-105",
    "Access key hasn't been rotated in 90 days",
    M,
    Domain.IDENTITY,
    "Rotate the key now. Better still, replace it with a role.",
    nhi=("NHI7",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX,),
)
def old_key(ctx: Context):
    if ctx.identity is None:
        return None
    hits = []
    for key in ctx.identity.access_keys:
        if key.created and _age_days(ctx, key.created) > 90:
            age = _age_days(ctx, key.created)
            hits.append(
                Hit(f"{key.key_id} is {age} days old", key.key_id, H if age > 365 else None)
            )
    return hits


@rule(
    "AIP-106",
    "Identity is shared with other agents",
    M,
    Domain.IDENTITY,
    "Give each agent its own role, so a compromise and its audit trail stay separate.",
    nhi=("NHI9",),
    asi=("ASI03", "ASI08"),
    aws=(IDENTITY_CTX,),
)
def shared_identity(ctx: Context):
    if ctx.identity is None:
        return None
    if not ctx.shared_with:
        return []
    names = ", ".join(a.name for a in ctx.shared_with)
    return [Hit(f"{ctx.identity.name} is also used by {names}", ctx.identity.arn)]


@rule(
    "AIP-107",
    "Identity is shared across environments",
    H,
    Domain.IDENTITY,
    "Use separate roles for each environment, ideally in separate accounts.",
    nhi=("NHI8",),
    asi=("ASI03", "ASI08"),
    aws=(IDENTITY_CTX, PERIMETER),
)
def cross_environment(ctx: Context):
    if ctx.identity is None:
        return None
    envs = {a.environment for a in ctx.shared_with if a.environment}
    if ctx.agent.environment:
        envs.add(ctx.agent.environment)
    if len(envs) < 2:
        return []
    return [Hit(f"{ctx.identity.name} runs in: {', '.join(sorted(envs))}", ctx.identity.arn)]


@rule(
    "AIP-108",
    "People appear to be using this agent's identity",
    M,
    Domain.IDENTITY,
    "Give people their own federated access, and restrict the trust policy to the workload.",
    nhi=("NHI10",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX, AUDIT),
)
def human_use(ctx: Context):
    if ctx.identity is None:
        return None
    signals = [ctx.identity.human_session_signal] if ctx.identity.human_session_signal else []
    signals += [k.human_use_signal for k in ctx.identity.access_keys if k.human_use_signal]
    return [Hit(signal, ctx.identity.arn) for signal in signals]


@rule(
    "AIP-109",
    "Agent holds permissions for services it never uses",
    L,
    Domain.IDENTITY,
    "Remove unused services from the policy. IAM Access Analyzer can generate a tighter one.",
    nhi=("NHI5",),
    asi=("ASI03",),
    aws=(PERIMETER,),
)
def unused_services(ctx: Context):
    if ctx.identity is None or ctx.identity.service_last_used is None:
        return None
    unused = sorted(s for s, last in ctx.identity.service_last_used.items() if last is None)
    if not unused:
        return []
    severity = M if len(unused) >= 5 else None
    return [Hit(f"No recorded use of: {', '.join(unused[:12])}", ctx.identity.arn, severity)]


@rule(
    "AIP-110",
    "Agent can assume a role with administrator access",
    C,
    Domain.IDENTITY,
    "Remove sts:AssumeRole on the stronger role, or tighten who that role trusts.",
    nhi=("NHI5",),
    asi=("ASI03", "ASI08"),
    aws=(IDENTITY_CTX, PERIMETER),
)
def assume_admin(ctx: Context):
    if ctx.identity is None:
        return None
    return [Hit(f"Reaches admin-level role {name}", name) for name in ctx.indirect_admin]


# ---- Data -------------------------------------------------------------------------------------


@rule(
    "AIP-201",
    "Lethal trifecta: sensitive data, untrusted input and a way out",
    C,
    Domain.DATA,
    "Break one leg. Remove outbound access, stop reading untrusted input, or narrow the data.",
    asi=("ASI01", "ASI02"),
    aws=(DATA_CTX, PERIMETER, CONTROLS),
)
def trifecta(ctx: Context):
    t = ctx.trifecta
    if t.complete:
        reasons = [
            t.sensitive_data.reasons[0],
            t.untrusted_input.reasons[0],
            t.outbound_path.reasons[0],
        ]
        return [Hit("; ".join(reasons), "trifecta")]
    if t.possible:
        return None
    return []


@rule(
    "AIP-202",
    "Agent can change or delete sensitive data",
    H,
    Domain.DATA,
    "Remove write and delete access, or route changes through a tool that requires approval.",
    nhi=("NHI5",),
    asi=("ASI02", "ASI03"),
    aws=(DATA_CTX, PERIMETER),
)
def write_sensitive(ctx: Context):
    if ctx.identity is None:
        return None
    hits = []
    for grant in ctx.grants:
        store = _store(ctx, grant)
        changes = sorted(WRITE_LEVELS & set(grant.levels))
        if store.arn in ctx.agent.memory_arns:
            continue  # An agent writing to its own attached memory is how memory works.
        if store.sensitivity in SENSITIVE and changes:
            severity = (
                C
                if store.sensitivity == Sensitivity.RESTRICTED
                and (AccessLevel.DELETE in changes or AccessLevel.ADMIN in changes)
                else None
            )
            hits.append(
                Hit(
                    f"{', '.join(changes)} on {store.name} ({store.sensitivity.value})",
                    store.arn,
                    severity,
                )
            )
    return hits


@rule(
    "AIP-203",
    "Agent can read sensitive data it hasn't used",
    M,
    Domain.DATA,
    "Remove this access. It adds risk without being needed.",
    nhi=("NHI5",),
    asi=("ASI03",),
    aws=(DATA_CTX,),
)
def unused_sensitive(ctx: Context):
    if ctx.identity is None:
        return None
    usage_known = any(g.use != "unknown" for g in ctx.grants)
    if ctx.grants and not usage_known:
        return None
    return [
        Hit(f"{_store(ctx, g).name}: {g.use_detail}", g.store_arn)
        for g in ctx.grants
        if g.use == "unused" and _store(ctx, g).sensitivity in SENSITIVE
    ]


@rule(
    "AIP-204",
    "Agent can reach most of the account's data",
    H,
    Domain.DATA,
    "Replace wildcard resources with the specific stores this agent needs.",
    nhi=("NHI5",),
    asi=("ASI03", "ASI08"),
    aws=(PERIMETER,),
)
def broad_reach(ctx: Context):
    if ctx.identity is None:
        return None
    total = len(ctx.stores)
    if total < 4 or len(ctx.grants) < total * 0.6:
        return []
    return [Hit(f"Reaches {len(ctx.grants)} of {total} data stores", "reach")]


@rule(
    "AIP-205",
    "Agent can reach a public data store",
    H,
    Domain.DATA,
    "Turn on S3 Block Public Access, and check nothing sensitive was already exposed.",
    asi=("ASI06",),
    aws=(DATA_CTX,),
)
def public_store(ctx: Context):
    stores = [_store(ctx, g) for g in ctx.grants]
    if stores and all(s.public is None for s in stores):
        return None
    return [Hit(f"{s.name} is publicly accessible", s.arn) for s in stores if s.public]


@rule(
    "AIP-206",
    "Agent reaches data nobody has classified",
    L,
    Domain.DATA,
    "Classify the store with a data-classification tag or scan it with Macie.",
    aws=(DATA_CTX,),
)
def unclassified(ctx: Context):
    return [
        Hit(f"{_store(ctx, g).name} has no classification", g.store_arn)
        for g in ctx.grants
        if _store(ctx, g).sensitivity == Sensitivity.UNKNOWN
    ]


@rule(
    "AIP-207",
    "Agent can poison what other agents read",
    H,
    Domain.DATA,
    "Separate write access from the agents that read this store, and review what gets ingested.",
    asi=("ASI06", "ASI08"),
    aws=(DATA_CTX, ORCHESTRATION),
)
def context_poisoning(ctx: Context):
    hits = []
    for grant in ctx.grants:
        if not WRITE_LEVELS & set(grant.levels):
            continue
        store = _store(ctx, grant)
        consumers = {
            other.id: other
            for other in ctx.agents_by_id.values()
            if other.id != ctx.agent.id
            and any(
                arn == store.arn or store.arn in ctx.stores[arn].source_store_arns
                for arn in [*other.knowledge_base_arns, *other.memory_arns]
                if arn in ctx.stores
            )
        }
        if consumers:
            names = ", ".join(a.name for a in consumers.values())
            hits.append(Hit(f"Writes to {store.name}, which feeds {names}", store.arn))
    return hits


@rule(
    "AIP-211",
    "Another agent can change what this agent reads",
    M,
    Domain.DATA,
    "Review what gets ingested, and limit write access to this store's sources.",
    asi=("ASI06", "ASI08"),
    aws=(DATA_CTX, ORCHESTRATION),
)
def poisonable_context(ctx: Context):
    hits = []
    for arn in [*ctx.agent.knowledge_base_arns, *ctx.agent.memory_arns]:
        store = ctx.stores.get(arn)
        if store is None:
            continue
        targets = {arn, *store.source_store_arns}
        writers = sorted(
            {
                ctx.agents_by_id[g.agent_id].name
                for g in ctx.all_grants
                if g.store_arn in targets
                and g.agent_id != ctx.agent.id
                and WRITE_LEVELS & set(g.levels)
            }
        )
        if writers:
            hits.append(Hit(f"{store.name} can be changed by {', '.join(writers)}", arn))
    return hits


@rule(
    "AIP-208",
    "Access to sensitive data isn't being logged",
    M,
    Domain.DATA,
    "Turn on CloudTrail data events or the store's own audit logging.",
    asi=("ASI10",),
    aws=(AUDIT,),
)
def data_not_logged(ctx: Context):
    sensitive = [_store(ctx, g) for g in ctx.grants if _store(ctx, g).sensitivity in SENSITIVE]
    if sensitive and all(s.logs_data_access is None for s in sensitive):
        return None
    return [
        Hit(f"{s.name} has no data access logging", s.arn)
        for s in sensitive
        if s.logs_data_access is False
    ]


@rule(
    "AIP-209",
    "Sensitive store isn't encrypted with a managed key",
    M,
    Domain.DATA,
    "Encrypt with KMS so key policy adds a second check on access.",
    aws=(DATA_CTX,),
)
def unencrypted(ctx: Context):
    return [
        Hit(f"{_store(ctx, g).name} is unencrypted", g.store_arn)
        for g in ctx.grants
        if _store(ctx, g).sensitivity in SENSITIVE and _store(ctx, g).encrypted is False
    ]


@rule(
    "AIP-210",
    "Other accounts can also reach this sensitive store",
    M,
    Domain.DATA,
    "Check whether the outside access is intended, and remove it if not.",
    nhi=("NHI3",),
    aws=(DATA_CTX, PERIMETER),
)
def cross_account(ctx: Context):
    hits = []
    for grant in ctx.grants:
        store = _store(ctx, grant)
        if store.sensitivity in SENSITIVE and store.cross_account_principals:
            who = ", ".join(store.cross_account_principals)
            hits.append(Hit(f"{store.name} is shared with {who}", store.arn))
    return hits


# ---- Secrets ----------------------------------------------------------------------------------


@rule(
    "AIP-301",
    "Credential stored in plain text in agent config",
    C,
    Domain.SECRETS,
    "Revoke this credential, issue a new one in Secrets Manager, and read it at runtime.",
    nhi=("NHI2",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX, DATA_CTX),
)
def plaintext(ctx: Context):
    return [
        Hit(f"{p.detector} in {p.variable} ({p.location})", f"{p.location}/{p.variable}")
        for p in ctx.agent.plaintext_secrets
    ]


@rule(
    "AIP-302",
    "Agent can read secrets it doesn't reference",
    H,
    Domain.SECRETS,
    "Limit secretsmanager:GetSecretValue to the secrets named in this agent's config.",
    nhi=("NHI5",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX,),
)
def overscoped_secrets(ctx: Context):
    if ctx.identity is None:
        return None
    return [
        Hit(f"Can read {ctx.secrets[g.secret_arn].name}", g.secret_arn)
        for g in ctx.secret_grants
        if not g.referenced
    ]


@rule(
    "AIP-303",
    "Reachable secret isn't being rotated",
    M,
    Domain.SECRETS,
    "Turn on automatic rotation, or replace it with a short-lived credential.",
    nhi=("NHI7",),
    asi=("ASI03",),
    aws=(IDENTITY_CTX,),
)
def unrotated(ctx: Context):
    hits = []
    for grant in ctx.secret_grants:
        secret = ctx.secrets[grant.secret_arn]
        if secret.rotation_enabled is False:
            hits.append(Hit(f"{secret.name} has rotation turned off", secret.arn))
        elif secret.last_rotated and _age_days(ctx, secret.last_rotated) > 90:
            days = _age_days(ctx, secret.last_rotated)
            hits.append(Hit(f"{secret.name} was last rotated {days} days ago", secret.arn))
    return hits


@rule(
    "AIP-304",
    "Secret is shared between agents",
    M,
    Domain.SECRETS,
    "Issue each agent its own credential, so one can be revoked without affecting the others.",
    nhi=("NHI9",),
    asi=("ASI08",),
    aws=(IDENTITY_CTX,),
)
def shared_secret(ctx: Context):
    hits = []
    for grant in ctx.secret_grants:
        if not grant.referenced:
            continue
        others = [
            ctx.agents_by_id[g.agent_id].name
            for g in ctx.all_secret_grants
            if g.secret_arn == grant.secret_arn and g.agent_id != ctx.agent.id and g.referenced
        ]
        if others:
            hits.append(
                Hit(
                    f"{ctx.secrets[grant.secret_arn].name} is also used by {', '.join(others)}",
                    grant.secret_arn,
                )
            )
    return hits


@rule(
    "AIP-305",
    "Agent can read a secret nobody has used in 90 days",
    L,
    Domain.SECRETS,
    "Confirm it's unneeded, then remove access and delete the secret.",
    nhi=("NHI1",),
    aws=(IDENTITY_CTX,),
)
def dormant_secret(ctx: Context):
    hits = []
    for grant in ctx.secret_grants:
        secret = ctx.secrets[grant.secret_arn]
        if secret.last_accessed and _age_days(ctx, secret.last_accessed) > 90:
            days = _age_days(ctx, secret.last_accessed)
            hits.append(Hit(f"{secret.name} was last read {days} days ago", secret.arn))
    return hits


# ---- Network ----------------------------------------------------------------------------------


@rule(
    "AIP-401",
    "Agent can be reached from the internet without authentication",
    C,
    Domain.NETWORK,
    "Add authentication at the entry point, or move it behind a private endpoint.",
    nhi=("NHI4",),
    asi=("ASI01",),
    aws=(PERIMETER, CONTROLS),
)
def open_inbound(ctx: Context):
    if ctx.agent.network.inbound is None:
        return None
    return [
        Hit(f"{e.kind}: {e.detail}", e.detail)
        for e in ctx.agent.network.inbound
        if e.internet and e.authenticated is False
    ]


@rule(
    "AIP-402",
    "Agent is reachable from the internet",
    L,
    Domain.NETWORK,
    "Confirm this is intended. Add a WAF and rate limits to public entry points.",
    asi=("ASI01",),
    aws=(PERIMETER,),
)
def inbound_auth(ctx: Context):
    if ctx.agent.network.inbound is None:
        return None
    return [
        Hit(f"{e.kind}: {e.detail} ({e.auth_detail or 'authentication not determined'})", e.detail)
        for e in ctx.agent.network.inbound
        if e.internet and e.authenticated is not False
    ]


@rule(
    "AIP-403",
    "Agent has unrestricted outbound internet access",
    M,
    Domain.NETWORK,
    "Send outbound traffic through an allowlisting proxy or Network Firewall.",
    asi=("ASI02",),
    aws=(PERIMETER,),
)
def open_egress(ctx: Context):
    if ctx.agent.network.internet_egress is None:
        return None
    if not ctx.agent.network.internet_egress:
        return []
    detail = ctx.agent.network.egress_detail or "Outbound internet access is available"
    return [Hit(detail, "egress")]


@rule(
    "AIP-404",
    "Security group is open to the whole internet",
    H,
    Domain.NETWORK,
    "Restrict inbound rules to the load balancer or specific source ranges.",
    aws=(PERIMETER,),
)
def open_sg(ctx: Context):
    if ctx.agent.network.in_vpc is None:
        return None
    return [
        Hit(f"{sg} allows inbound from 0.0.0.0/0", sg)
        for sg in ctx.agent.network.open_security_groups
    ]


@rule(
    "AIP-405",
    "Model traffic doesn't use a private endpoint",
    L,
    Domain.NETWORK,
    "Add a VPC endpoint for Bedrock so model calls stay on the AWS network.",
    aws=(PERIMETER,),
)
def no_vpc_endpoint(ctx: Context):
    network = ctx.agent.network
    if not network.in_vpc:
        return [] if network.in_vpc is False else None
    if network.vpc_endpoints is None:
        return None
    if any("bedrock" in endpoint for endpoint in network.vpc_endpoints):
        return []
    return [Hit(f"{network.vpc_id} has no Bedrock VPC endpoint", network.vpc_id or "vpc")]


@rule(
    "AIP-406",
    "Agent is configured to call an unrecognised domain",
    M,
    Domain.NETWORK,
    "Find out what this domain is and who runs it. Remove it if nobody can say.",
    nhi=("NHI3",),
    asi=("ASI02", "ASI04"),
    aws=(PERIMETER,),
)
def unknown_domain(ctx: Context):
    return [Hit(f"{host} isn't a recognised service", host) for host in ctx.unknown_domains]


# ---- Runtime ----------------------------------------------------------------------------------


@rule(
    "AIP-501",
    "Critical vulnerability with a known exploit",
    H,
    Domain.RUNTIME,
    "Update the package and redeploy. Do this first if the agent is internet-facing.",
    asi=("ASI04", "ASI05"),
    aws=(CONTROLS,),
)
def exploitable(ctx: Context):
    if not ctx.agent.runtime.vulns_assessed:
        return None
    internet = any(e.internet for e in ctx.agent.network.inbound or [])
    return [
        Hit(
            f"{v.cve} in {v.package}" + (f", fixed in {v.fixed_in}" if v.fixed_in else ""),
            v.cve,
            C if internet else None,
        )
        for v in ctx.agent.runtime.vulnerabilities
        if v.severity == C and v.exploit_available
    ]


@rule(
    "AIP-502",
    "Serious vulnerabilities with a fix available",
    M,
    Domain.RUNTIME,
    "Update the affected packages and rebuild the image.",
    asi=("ASI04",),
    aws=(CONTROLS,),
)
def fixable(ctx: Context):
    if not ctx.agent.runtime.vulns_assessed:
        return None
    vulns = [
        v
        for v in ctx.agent.runtime.vulnerabilities
        if v.severity in (C, H) and v.fixed_in and not (v.severity == C and v.exploit_available)
    ]
    if not vulns:
        return []
    packages = ", ".join(sorted({v.package for v in vulns})[:6])
    return [Hit(f"{len(vulns)} fixable in: {packages}", "fixable")]


@rule(
    "AIP-503",
    "Container runs in privileged mode",
    H,
    Domain.RUNTIME,
    "Remove privileged mode. Agents shouldn't need host-level access.",
    asi=("ASI05",),
    aws=(CONTROLS,),
)
def privileged(ctx: Context):
    if ctx.agent.runtime.privileged is None:
        return None
    return (
        [Hit("privileged is true in the task definition", "privileged")]
        if ctx.agent.runtime.privileged
        else []
    )


@rule(
    "AIP-504",
    "Container runs as root",
    M,
    Domain.RUNTIME,
    "Set a non-root user in the image or task definition.",
    asi=("ASI05",),
    aws=(CONTROLS,),
)
def root_user(ctx: Context):
    if ctx.agent.runtime.runs_as_root is None:
        return None
    return [Hit("No non-root user is configured", "root")] if ctx.agent.runtime.runs_as_root else []


@rule(
    "AIP-505",
    "Container filesystem is writable",
    L,
    Domain.RUNTIME,
    "Set readonlyRootFilesystem, and mount a temporary directory if one is needed.",
    asi=("ASI05",),
    aws=(CONTROLS,),
)
def writable_fs(ctx: Context):
    if ctx.agent.runtime.read_only_root is None:
        return None
    return (
        [] if ctx.agent.runtime.read_only_root else [Hit("Root filesystem is writable", "rootfs")]
    )


@rule(
    "AIP-506",
    "Image isn't pinned to a digest",
    L,
    Domain.RUNTIME,
    "Deploy by image digest, so what runs is exactly what was scanned.",
    nhi=("NHI3",),
    asi=("ASI04",),
    aws=(CONTROLS,),
)
def unpinned(ctx: Context):
    if ctx.agent.runtime.image_pinned is None:
        return None
    return (
        []
        if ctx.agent.runtime.image_pinned
        else [Hit(f"{ctx.agent.runtime.image} uses a mutable tag", "image")]
    )


@rule(
    "AIP-507",
    "Runtime is past end of support",
    M,
    Domain.RUNTIME,
    "Move to a supported language runtime.",
    asi=("ASI04",),
    aws=(CONTROLS,),
)
def deprecated_runtime(ctx: Context):
    if ctx.agent.runtime.runtime_deprecated is None:
        return None
    return (
        [Hit(f"{ctx.agent.runtime.language_runtime} no longer gets security updates", "runtime")]
        if ctx.agent.runtime.runtime_deprecated
        else []
    )


@rule(
    "AIP-508",
    "Instance allows IMDSv1",
    H,
    Domain.RUNTIME,
    "Require IMDSv2, so a request forged through the agent can't fetch its credentials.",
    asi=("ASI02",),
    aws=(IDENTITY_CTX, CONTROLS),
)
def imdsv1(ctx: Context):
    if ctx.agent.platform != Platform.EC2:
        return []
    if ctx.agent.runtime.imdsv2_required is None:
        return None
    return (
        []
        if ctx.agent.runtime.imdsv2_required
        else [Hit("HttpTokens is optional on this instance", "imds")]
    )


@rule(
    "AIP-509",
    "Agent can run generated code and reach the internet",
    H,
    Domain.RUNTIME,
    "Run generated code in a sandbox with no network access.",
    asi=("ASI05",),
    aws=(CONTROLS, PERIMETER),
)
def code_exec(ctx: Context):
    if not ctx.agent.runtime.code_execution_tool:
        return []
    if ctx.agent.network.internet_egress is None:
        return None
    return (
        [Hit("Has a code execution tool and outbound internet", "code-exec")]
        if ctx.agent.network.internet_egress
        else []
    )


# ---- Governance -------------------------------------------------------------------------------


@rule(
    "AIP-601",
    "Nobody is named as this agent's owner",
    M,
    Domain.GOVERNANCE,
    "Add an owner tag, so someone is accountable and it gets offboarded when no longer needed.",
    nhi=("NHI1",),
    asi=("ASI10",),
    aws=(AUDIT,),
)
def no_owner(ctx: Context):
    return [] if ctx.agent.owner else [Hit("No owner tag on the workload or its role", "owner")]


@rule(
    "AIP-602",
    "Agent isn't running on a managed agent service",
    L,
    Domain.GOVERNANCE,
    "Register it in your inventory and consider moving it to Bedrock AgentCore.",
    asi=("ASI10",),
    aws=(ORCHESTRATION,),
)
def shadow(ctx: Context):
    if ctx.agent.platform in (Platform.BEDROCK_AGENT, Platform.AGENTCORE):
        return []
    return [
        Hit(
            f"Found through {', '.join(sorted({e.signal for e in ctx.agent.evidence}))} "
            "signals, not a registry",
            "unmanaged",
        )
    ]


@rule(
    "AIP-603",
    "No guardrail on model calls",
    M,
    Domain.GOVERNANCE,
    "Attach a Bedrock guardrail. It reduces harm but won't stop every prompt injection.",
    asi=("ASI01", "ASI09"),
    aws=(CONTROLS,),
)
def no_guardrail(ctx: Context):
    if ctx.agent.guardrail is None:
        return None
    return [] if ctx.agent.guardrail else [Hit("No guardrail is configured", "guardrail")]


@rule(
    "AIP-604",
    "Agent acts on its own with no human approval",
    H,
    Domain.GOVERNANCE,
    "Require approval for changes that can't be undone, and add a way to shut it off.",
    asi=("ASI02", "ASI10"),
    aws=(ORCHESTRATION, PERIMETER),
)
def unsupervised(ctx: Context):
    if ctx.autonomy_scope is None:
        return None
    if ctx.autonomy_scope < 4:
        return []
    return [Hit("Estimated scope 4: starts on its own and can make changes", "autonomy")]


@rule(
    "AIP-605",
    "Model invocation logging is off in this region",
    M,
    Domain.GOVERNANCE,
    "Turn on Bedrock model invocation logging, so prompts and responses can be investigated.",
    asi=("ASI10",),
    aws=(AUDIT,),
)
def no_invocation_logging(ctx: Context):
    state = ctx.snapshot.signals.model_invocation_logging.get(ctx.agent.region)
    if state is None:
        return None
    return [] if state else [Hit(f"Logging is off in {ctx.agent.region}", ctx.agent.region)]


@rule(
    "AIP-606",
    "External tool can act without human approval",
    M,
    Domain.GOVERNANCE,
    "Pin and review the tool, and require approval for its change-making actions.",
    nhi=("NHI3",),
    asi=("ASI02", "ASI04"),
    aws=(ORCHESTRATION,),
)
def unapproved_tool(ctx: Context):
    return [
        Hit(f"{t.name} ({t.type}) at {t.target}", t.name)
        for t in ctx.agent.tools
        if t.external and t.requires_approval is not True
    ]


@rule(
    "AIP-607",
    "Idle agent still holds its permissions",
    L,
    Domain.GOVERNANCE,
    "If it's no longer needed, remove the role and delete the workload.",
    nhi=("NHI1",),
    asi=("ASI10",),
    aws=(AUDIT,),
)
def dormant(ctx: Context):
    if ctx.agent.last_model_call is None:
        return None
    days = _age_days(ctx, ctx.agent.last_model_call)
    return [Hit(f"Last model call was {days} days ago", "dormant")] if days > 90 else []


@rule(
    "AIP-608",
    "Agent can write to a SaaS product",
    M,
    Domain.GOVERNANCE,
    "Narrow the OAuth scopes to read-only where possible, and review them regularly.",
    nhi=("NHI3",),
    asi=("ASI02", "ASI03"),
    aws=(IDENTITY_CTX, PERIMETER),
)
def saas_write(ctx: Context):
    return [
        Hit(f"{s.vendor}" + (f" with scopes {', '.join(s.scopes)}" if s.scopes else ""), s.vendor)
        for s in ctx.agent.saas
        if s.can_write
    ]
