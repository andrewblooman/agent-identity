"""Work out which agent can reach which data store or secret, and by what route."""

from __future__ import annotations

from dataclasses import dataclass

from agent_identity.analysis import permissions
from agent_identity.models import (
    AccessLevel,
    Agent,
    DataGrant,
    DataStore,
    GrantRoute,
    Identity,
    Policy,
    Secret,
    SecretGrant,
    Snapshot,
)

# Actions that define each level. A store is reached at a level if any action is allowed.
STORE_ACTIONS: dict[str, dict[AccessLevel, list[str]]] = {
    "S3": {
        AccessLevel.READ: ["s3:GetObject"],
        AccessLevel.WRITE: ["s3:PutObject"],
        AccessLevel.DELETE: ["s3:DeleteObject", "s3:DeleteBucket"],
        AccessLevel.ADMIN: ["s3:PutBucketPolicy"],
    },
    "DynamoDB": {
        AccessLevel.READ: ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
        AccessLevel.WRITE: ["dynamodb:PutItem", "dynamodb:UpdateItem"],
        AccessLevel.DELETE: ["dynamodb:DeleteItem", "dynamodb:DeleteTable"],
        AccessLevel.ADMIN: ["dynamodb:PutResourcePolicy"],
    },
    "RDS": {
        AccessLevel.READ: ["rds-db:connect", "rds-data:ExecuteStatement"],
        AccessLevel.WRITE: ["rds-data:ExecuteStatement"],
        AccessLevel.DELETE: ["rds:DeleteDBInstance", "rds:DeleteDBCluster"],
        AccessLevel.ADMIN: ["rds:ModifyDBInstance", "rds:ModifyDBCluster"],
    },
    "Knowledge base": {
        AccessLevel.READ: ["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"],
        AccessLevel.WRITE: ["bedrock:IngestKnowledgeBaseDocuments", "bedrock:StartIngestionJob"],
        AccessLevel.DELETE: ["bedrock:DeleteKnowledgeBase", "bedrock:DeleteKnowledgeBaseDocuments"],
        AccessLevel.ADMIN: ["bedrock:UpdateKnowledgeBase"],
    },
    "Agent memory": {
        AccessLevel.READ: [
            "bedrock-agentcore:RetrieveMemoryRecords",
            "bedrock-agentcore:ListEvents",
        ],
        AccessLevel.WRITE: [
            "bedrock-agentcore:CreateEvent",
            "bedrock-agentcore:BatchCreateMemoryRecords",
        ],
        AccessLevel.DELETE: ["bedrock-agentcore:DeleteMemory"],
        AccessLevel.ADMIN: ["bedrock-agentcore:UpdateMemory"],
    },
}

SECRET_ACTIONS = {
    "Secrets Manager": "secretsmanager:GetSecretValue",
    "SSM SecureString": "ssm:GetParameter",
    "API key provider": "bedrock-agentcore:GetResourceApiKey",
    "OAuth provider": "bedrock-agentcore:GetResourceOauth2Token",
}

_SERVICE_NAMESPACE = {
    "S3": "s3",
    "DynamoDB": "dynamodb",
    "RDS": "rds",
    "Knowledge base": "bedrock",
    "Agent memory": "bedrock-agentcore",
}


_S3_BUCKET_ACTIONS = {"s3:DeleteBucket", "s3:PutBucketPolicy"}
_USE_RANK = {"used": 0, "unknown": 1, "unused": 2}


def _whole_store(store: DataStore, action: str) -> str:
    """The resource an action applies to when it covers the whole store."""
    if store.type == "S3" and action not in _S3_BUCKET_ACTIONS:
        return f"{store.arn}/*"
    if action == "rds-db:connect" and store.db_resource_id:
        _, _, _, region, account, *_ = store.arn.split(":")
        return f"arn:aws:rds-db:{region}:{account}:dbuser:{store.db_resource_id}/*"
    return store.arn


def resources_to_check(identity: Identity, store: DataStore, action: str) -> list[str]:
    """The whole store, then any narrower grants on it, such as one S3 prefix or one DB user."""
    whole = _whole_store(store, action)
    narrower = permissions.narrower_resources(identity, action, whole, store.resource_policy)
    return [whole, *narrower]


def _check(
    snapshot: Snapshot,
    identity: Identity,
    action: str,
    resource: str,
    resource_policy: Policy | None,
) -> tuple[bool, bool, bool]:
    """Return (allowed, conditional, verified). Simulator answers override the local evaluator."""
    local = permissions.evaluate(identity, action, resource, resource_policy)
    simulated = snapshot.simulated.get(f"{identity.arn}|{action}|{resource}")
    if simulated is None:
        return local.allowed, local.conditional, False
    # The simulator only saw identity policies. Simulating a resource policy for a role needs an
    # IAM user as the caller, so resource policies are still judged locally.
    if resource_policy is None:
        return simulated, local.conditional and simulated, True
    alone = permissions.evaluate(identity, action, resource)
    granted_by_resource = local.allowed and not alone.allowed
    denied_by_resource = alone.allowed and not local.allowed
    allowed = (simulated or granted_by_resource) and not denied_by_resource
    return allowed, local.conditional and allowed, True


@dataclass
class _Reach:
    levels: list[AccessLevel]
    conditional: bool = False
    verified: bool = False
    limited_to: list[str] | None = None


def _levels(snapshot: Snapshot, identity: Identity, store: DataStore) -> _Reach:
    reach = _Reach(levels=[])
    whole_store = False
    limited: set[str] = set()
    for level, actions in STORE_ACTIONS.get(store.type, {}).items():
        for action in actions:
            whole, *narrower = resources_to_check(identity, store, action)
            for resource in [whole, *narrower]:
                ok, cond, ver = _check(snapshot, identity, action, resource, store.resource_policy)
                reach.verified = reach.verified or ver
                if not ok:
                    continue
                if level not in reach.levels:
                    reach.levels.append(level)
                reach.conditional = reach.conditional or cond
                if resource == whole:
                    whole_store = True
                    break
                limited.add(resource)
    reach.limited_to = [] if whole_store else sorted(limited)
    return reach


def _kms_blocked(snapshot: Snapshot, identity: Identity, store: DataStore) -> bool:
    if not store.kms_key_arn:
        return False
    return not permissions.evaluate(identity, "kms:Decrypt", store.kms_key_arn).allowed


@dataclass
class _Route:
    identity: Identity
    path: list[str]
    indirect: bool


def identity_routes(agent: Agent, snapshot: Snapshot) -> list[_Route]:
    """Every identity the agent can act as: its own, roles it can assume, and tool roles."""
    by_arn = {i.arn: i for i in snapshot.identities}
    routes: list[_Route] = []
    seen: set[str] = set()

    def add(identity: Identity, path: list[str], indirect: bool) -> None:
        if identity.arn in seen:
            return
        seen.add(identity.arn)
        routes.append(_Route(identity, path, indirect))
        for target in permissions.assumable_roles(identity, snapshot.identities):
            add(target, [*path, f"assumes {target.name}"], True)

    for arn in [agent.identity_arn, *agent.extra_identity_arns]:
        if arn and arn in by_arn:
            add(by_arn[arn], [by_arn[arn].name], arn != agent.identity_arn)
    for tool in agent.tools:
        if tool.role_arn and tool.role_arn in by_arn:
            role = by_arn[tool.role_arn]
            add(role, [f"tool {tool.name}", role.name], True)
    return routes


def _use(snapshot: Snapshot, identity: Identity, store: DataStore) -> tuple[str, str]:
    observed = snapshot.observed_data_use.get(store.arn, {}).get(identity.arn)
    if observed:
        return "used", f"Data events show use on {observed:%d %b %Y}"
    if store.logs_data_access and snapshot.observed_data_use.get(store.arn) is not None:
        return "unused", "Data events are on for this store and show no use by this identity"
    if identity.service_last_used is None:
        return "unknown", "No usage data available"
    namespace = _SERVICE_NAMESPACE.get(store.type, "")
    last = identity.service_last_used.get(namespace)
    if last is None:
        return "unused", f"IAM shows no {namespace} activity by this identity in the last 400 days"
    return "unknown", f"IAM shows {namespace} use on {last:%d %b %Y}, but not on which resource"


def _summarise(grant: DataGrant) -> None:
    """Describe a grant from its routes, without implying one route allows everything."""
    routes = grant.routes
    main = next((r for r in routes if not r.indirect), routes[0])
    direct = {level for r in routes if not r.indirect for level in r.levels}
    every = {level for r in routes for level in r.levels}
    best_use = min(routes, key=lambda r: _USE_RANK.get(r.use, 1))
    grant.identity_arn, grant.path, grant.indirect = main.identity_arn, main.path, main.indirect
    grant.levels = [level for level in AccessLevel if level in every]
    grant.indirect_levels = [level for level in grant.levels if level not in direct]
    grant.conditional = all(r.conditional for r in routes)
    grant.verified = any(r.verified for r in routes)
    grant.blocked_by_kms = all(r.blocked_by_kms for r in routes)
    grant.limited_to = (
        sorted({p for r in routes for p in r.limited_to})
        if all(r.limited_to for r in routes)
        else []
    )
    grant.use, grant.use_detail = best_use.use, best_use.use_detail


def build_data_grants(snapshot: Snapshot) -> list[DataGrant]:
    grants: dict[tuple[str, str], DataGrant] = {}
    stores = {s.arn: s for s in snapshot.stores}

    def merge(agent_id: str, store_arn: str, route: GrantRoute) -> None:
        grant = grants.setdefault(
            (agent_id, store_arn),
            DataGrant(
                agent_id=agent_id,
                identity_arn=route.identity_arn,
                store_arn=store_arn,
                levels=route.levels,
            ),
        )
        grant.routes.append(route)
        _summarise(grant)

    for agent in snapshot.agents:
        routes = identity_routes(agent, snapshot)
        for route in routes:
            for store in snapshot.stores:
                reach = _levels(snapshot, route.identity, store)
                if not reach.levels:
                    continue
                use, detail = _use(snapshot, route.identity, store)
                merge(
                    agent.id,
                    store.arn,
                    GrantRoute(
                        identity_arn=route.identity.arn,
                        levels=reach.levels,
                        conditional=reach.conditional,
                        verified=reach.verified,
                        blocked_by_kms=_kms_blocked(snapshot, route.identity, store),
                        limited_to=reach.limited_to or [],
                        indirect=route.indirect,
                        path=[*route.path, store.name],
                        use=use,
                        use_detail=detail,
                    ),
                )
        # A knowledge base attached to the agent exposes its content and its source buckets,
        # because the service reads them on the agent's behalf with the KB's own role.
        for kb_arn in agent.knowledge_base_arns:
            kb = stores.get(kb_arn)
            if kb is None:
                continue
            merge(
                agent.id,
                kb.arn,
                GrantRoute(
                    identity_arn=agent.identity_arn or "",
                    levels=[AccessLevel.READ],
                    indirect=False,
                    path=[agent.name, "attached knowledge base", kb.name],
                    use_detail="Attached in the agent's configuration",
                ),
            )
            for source_arn in kb.source_store_arns:
                source = stores.get(source_arn)
                if source is None:
                    continue
                merge(
                    agent.id,
                    source.arn,
                    GrantRoute(
                        identity_arn=agent.identity_arn or "",
                        levels=[AccessLevel.READ],
                        indirect=True,
                        path=[agent.name, kb.name, f"indexed from {source.name}"],
                        use_detail="Content reaches the agent through the knowledge base",
                    ),
                )
        for memory_arn in agent.memory_arns:
            memory = stores.get(memory_arn)
            if memory is not None:
                merge(
                    agent.id,
                    memory.arn,
                    GrantRoute(
                        identity_arn=agent.identity_arn or "",
                        levels=[AccessLevel.READ, AccessLevel.WRITE],
                        path=[agent.name, "attached memory", memory.name],
                        use_detail="Attached in the agent's configuration",
                    ),
                )
    return list(grants.values())


def build_secret_grants(snapshot: Snapshot) -> list[SecretGrant]:
    grants: dict[tuple[str, str], SecretGrant] = {}
    secrets: dict[str, Secret] = {s.arn: s for s in snapshot.secrets}
    identities = {i.arn: i for i in snapshot.identities}
    for agent in snapshot.agents:
        routes = identity_routes(agent, snapshot)
        for route in routes:
            for secret in snapshot.secrets:
                action = SECRET_ACTIONS.get(secret.kind)
                if action is None:
                    continue
                allowed, conditional, _ = _check(
                    snapshot, route.identity, action, secret.arn, secret.resource_policy
                )
                if not allowed:
                    continue
                key = (agent.id, secret.arn)
                if key not in grants or (grants[key].indirect and not route.indirect):
                    grants[key] = SecretGrant(
                        agent_id=agent.id,
                        identity_arn=route.identity.arn,
                        secret_arn=secret.arn,
                        conditional=conditional,
                        indirect=route.indirect,
                        referenced=secret.arn in agent.secret_arns,
                        path=[*route.path, secret.name],
                    )
        for arn in agent.secret_arns:
            if arn in secrets and (agent.id, arn) not in grants:
                grants[(agent.id, arn)] = _referenced_grant(
                    snapshot, agent, secrets[arn], identities, bool(routes)
                )
    return list(grants.values())


def _referenced_grant(
    snapshot: Snapshot,
    agent: Agent,
    secret: Secret,
    identities: dict[str, Identity],
    identity_known: bool,
) -> SecretGrant:
    """Config naming a secret isn't permission to read it, unless a fetching role can."""
    action = SECRET_ACTIONS.get(secret.kind)
    for arn in agent.secret_fetch_role_arns:
        role = identities.get(arn)
        if role is None or action is None:
            continue
        allowed, conditional, _ = _check(snapshot, role, action, secret.arn, secret.resource_policy)
        if allowed:
            return SecretGrant(
                agent_id=agent.id,
                identity_arn=role.arn,
                secret_arn=secret.arn,
                conditional=conditional,
                indirect=True,
                referenced=True,
                path=[agent.name, f"fetched at start by {role.name}", secret.name],
            )
    return SecretGrant(
        agent_id=agent.id,
        identity_arn=agent.identity_arn or "",
        secret_arn=secret.arn,
        referenced=True,
        authorized=False if identity_known else None,
        path=[agent.name, "referenced in config", secret.name],
    )
